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

/// Extract the docker-compose YAML from an app-compose JSON document.
pub fn docker_compose_file(app_compose: &str) -> Result<String, ComposeError> {
    let v: serde_json::Value =
        serde_json::from_str(app_compose).map_err(|e| ComposeError::Json(e.to_string()))?;
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
    let v: serde_json::Value =
        serde_json::from_str(app_compose).map_err(|e| ComposeError::Json(e.to_string()))?;
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
    if text("init_script")?.is_some() {
        out.push("app-compose has a non-empty `init_script`".into());
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
    let v: serde_json::Value = serde_json::from_str(app_compose).ok()?;
    let s = v.get("pre_launch_script")?.as_str()?;
    if s.trim().is_empty() {
        return None;
    }
    Some(hex::encode(Sha256::digest(s.as_bytes())))
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
