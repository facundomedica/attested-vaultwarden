//! Intel TDX (dstack) evidence verification.
//!
//! * Quote signature chain, collateral validity and TCB status: `dcap-qvl`
//!   (`QuoteVerifier::new_prod().verify_with_policy`), against collateral
//!   fetched from Intel PCS (or recorded, in tests) and an explicit time.
//! * TD attributes: debug must be off (checked here as well as in dcap-qvl).
//! * RTMR3: replayed from the dstack event log; every runtime event digest
//!   is **recomputed** from its name and payload (the log's `digest` field is
//!   only cross-checked), and the replayed value must equal the quoted RTMR3.
//!
//! Event digest (dstack `cc-eventlog/src/runtime_events.rs`, V1):
//! `SHA-384(u32_le(0x08000001) ‖ ":" ‖ name ‖ ":" ‖ payload)`, and
//! `RTMR3 = fold(0^48, |mr, d| SHA-384(mr ‖ d))`.

use dcap_qvl::verify::QuoteVerifier;
use dcap_qvl::{QuoteCollateralV3, QuotePolicy, TcbStatus};
use serde::Deserialize;
use sha2::{Digest, Sha384};

/// dstack runtime event type.
pub const DSTACK_RUNTIME_EVENT_TYPE: u32 = 0x0800_0001;

/// RTMR3 events a dstack OS emits during boot. Anything else (including
/// application events emitted later through the guest agent) is rejected,
/// because the published compose does not emit any.
pub const KNOWN_RTMR3_EVENTS: &[&str] = &[
    "system-preparing",
    "app-id",
    "compose-hash",
    "init-script-hash",
    "gpu-policy-hash",
    "instance-id",
    "boot-mr-done",
    "gpu-attestation",
    "os-image-hash",
    "key-provider",
    "storage-fs",
    // dstack 0.6.5+: `1` if the data disk is LUKS-encrypted, `0` if not
    // (dstack docs/tutorials/attestation-verification.md, system_setup.rs).
    "storage-encrypted",
    "system-ready",
];

#[derive(Debug, thiserror::Error)]
pub enum TdxError {
    #[error(
        "quote verification failed (signature, certificate chain, collateral or TCB policy): {0}"
    )]
    Quote(String),
    #[error("quote is not a TDX TD report")]
    NotTd,
    #[error("TD debug attribute is set: the TD's memory is readable by the host")]
    Debug,
    #[error("policy lists unknown TCB status `{0}`")]
    BadPolicyStatus(String),
    #[error("TCB status is {status}, policy accepts only {accepted}")]
    TcbStatus { status: String, accepted: String },
    #[error("event log is not valid JSON: {0}")]
    EventLogJson(String),
    #[error("event log entry {index}: {reason}")]
    EventLogEntry { index: usize, reason: String },
    #[error(
        "RTMR3 replay gives {replayed} but the quote says {quoted}: the event log does not describe this TD"
    )]
    Rtmr3Mismatch { replayed: String, quoted: String },
    #[error("RTMR3 events: {0}")]
    Events(String),
}

/// What a successfully verified quote tells us.
#[derive(Debug, Clone)]
pub struct VerifiedQuote {
    pub tcb_status: String,
    /// Lower of the TCB info and QE identity `tcbEvaluationDataNumber`.
    pub tcb_eval_data_number: u32,
    pub advisory_ids: Vec<String>,
    /// Launch-time fields chosen by the host (see [`check_launch_fields`]).
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub xfam: [u8; 8],
    pub mr_td: [u8; 48],
    pub rt_mr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
    pub td_attributes: [u8; 8],
    /// PCK certificate flags that are explicitly true (`smt`,
    /// `dynamic_platform`, `cached_keys`), for the report and policy drafts.
    pub pck_flags_set: Vec<&'static str>,
}

/// PCK platform flags the policy is willing to accept (all default false).
#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformFlags {
    pub smt: bool,
    pub dynamic_platform: bool,
    pub cached_keys: bool,
}

impl PlatformFlags {
    pub fn from_policy(p: &attested_vw_common::policy::TdxPolicy) -> Self {
        Self {
            smt: p.allow_smt,
            dynamic_platform: p.allow_dynamic_platform,
            cached_keys: p.allow_cached_keys,
        }
    }
}

fn parse_status(s: &str) -> Result<TcbStatus, TdxError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| TdxError::BadPolicyStatus(s.to_owned()))
}

/// Verify a raw TDX quote against collateral at time `now_secs`.
///
/// * `accepted_tcb_status` is the EXACT set of acceptable statuses.
///   dcap-qvl's `QuotePolicy::strict` always includes `UpToDate`, so the set
///   is enforced again here on the verified claims.
/// * `min_tcb_eval_data_number`: the collateral (TCB info and QE identity)
///   must be at least this recent. Collateral is Intel-signed, but Intel
///   keeps signing and serving older evaluation data sets for months, so
///   without this floor the collateral *source* could pick a set in which a
///   platform with a since-fixed vulnerability still counts as `UpToDate`.
pub fn verify_quote(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    accepted_tcb_status: &[String],
    min_tcb_eval_data_number: u32,
    flags: PlatformFlags,
) -> Result<VerifiedQuote, TdxError> {
    let mut qp = QuotePolicy::strict(now_secs)
        .min_tcb_eval_data_number(min_tcb_eval_data_number)
        .allow_smt(flags.smt)
        .allow_dynamic_platform(flags.dynamic_platform)
        .allow_cached_keys(flags.cached_keys);
    let mut accepted = Vec::new();
    for s in accepted_tcb_status {
        let status = parse_status(s)?;
        accepted.push(status.to_string());
        qp = qp.allow_status(status);
    }
    let claims = QuoteVerifier::new_prod()
        .verify_with_policy(quote, collateral.clone(), now_secs, &qp)
        .map_err(|e| TdxError::Quote(format!("{e:#}")))?;
    let status = claims.tcb.status.to_string();
    if !accepted.contains(&status) {
        return Err(TdxError::TcbStatus {
            status,
            accepted: accepted.join(", "),
        });
    }
    // Belt and braces: dcap-qvl enforced the floor through the policy above.
    if claims.tcb.eval_data_number < min_tcb_eval_data_number {
        return Err(TdxError::Quote(format!(
            "collateral tcbEvaluationDataNumber {} is below the policy minimum {min_tcb_eval_data_number}",
            claims.tcb.eval_data_number
        )));
    }
    let td = claims.report.as_td10().ok_or(TdxError::NotTd)?;
    check_td_attributes(&td.td_attributes)?;
    let pck = &claims.platform.pck;
    let mut pck_flags_set = Vec::new();
    for (name, flag) in [
        ("smt", pck.smt_enabled),
        ("dynamic_platform", pck.dynamic_platform),
        ("cached_keys", pck.cached_keys),
    ] {
        if flag == dcap_qvl::PckCertFlag::True {
            pck_flags_set.push(name);
        }
    }
    Ok(VerifiedQuote {
        pck_flags_set,
        tcb_status: claims.tcb.status.to_string(),
        tcb_eval_data_number: claims.tcb.eval_data_number,
        advisory_ids: claims.tcb.advisory_ids.clone(),
        mr_config_id: td.mr_config_id,
        mr_owner: td.mr_owner,
        mr_owner_config: td.mr_owner_config,
        xfam: td.xfam,
        mr_td: td.mr_td,
        rt_mr: [td.rt_mr0, td.rt_mr1, td.rt_mr2, td.rt_mr3],
        report_data: td.report_data,
        td_attributes: td.td_attributes,
    })
}

/// TDATTRIBUTES byte 0 bit 0 is DEBUG (Intel TDX module spec, TDATTRIBUTES
/// "TUD" group). dcap-qvl rejects it by default too; this is belt and braces.
pub fn check_td_attributes(attrs: &[u8; 8]) -> Result<(), TdxError> {
    if attrs[0] & 0x01 != 0 {
        return Err(TdxError::Debug);
    }
    Ok(())
}

/// MRCONFIGID, MROWNER and MROWNERCONFIG are set by the host when it
/// launches the TD and are part of the signed report, but not of MRTD or the
/// RTMRs. Returns the problems found and, possibly, a note for the report.
///
/// * A field the policy pins must equal the pin.
/// * MROWNER / MROWNERCONFIG, unpinned: must be all-zero (dstack never sets
///   them).
/// * MRCONFIGID, unpinned: all-zero, or a dstack config id (dstack
///   `dstack-types/src/mr_config.rs`; first byte = format version, 32-byte
///   hash, 15 zero bytes). Version 1 is `0x01 ‖ compose_hash` and is
///   recomputed here. Versions 2 (Keccak-256 over compose hash, app id, key
///   provider) and 3 (SHA-256 over a host-generated JSON document) are
///   accepted by shape only, with a note: the measured dstack OS itself
///   refuses to boot if they disagree with the compose hash, app id and key
///   provider it measured into RTMR3, which this verifier checks directly.
///   Pin `tdx.mr_config_id` to make it exact.
pub fn check_launch_fields(
    q: &VerifiedQuote,
    tp: &attested_vw_common::policy::TdxPolicy,
    compose_hash: &[u8; 32],
) -> (Vec<String>, Option<String>) {
    let mut problems = Vec::new();
    let mut note = None;
    let eq = |want: &str, got: &[u8; 48]| want.eq_ignore_ascii_case(&hex::encode(got));
    for (name, pin, got) in [
        ("MROWNER", &tp.mr_owner, &q.mr_owner),
        ("MROWNERCONFIG", &tp.mr_owner_config, &q.mr_owner_config),
    ] {
        match pin {
            Some(want) if eq(want, got) => {}
            Some(want) => problems.push(format!("{name} is {} (policy: {want})", hex::encode(got))),
            None if got == &[0u8; 48] => {}
            None => problems.push(format!(
                "{name} is {}, not zero, and the policy does not pin it",
                hex::encode(got)
            )),
        }
    }
    let got = &q.mr_config_id;
    let mut v1 = [0u8; 48];
    v1[0] = 1;
    v1[1..33].copy_from_slice(compose_hash);
    match &tp.mr_config_id {
        Some(want) if eq(want, got) => {}
        Some(want) => problems.push(format!(
            "MRCONFIGID is {} (policy: {want})",
            hex::encode(got)
        )),
        None if got == &[0u8; 48] || got == &v1 => {}
        None if matches!(got[0], 2 | 3) && got[33..] == [0u8; 15] => {
            note = Some(format!(
                "MRCONFIGID {} is a dstack v{} config id; accepted by shape, not recomputed (pin tdx.mr_config_id to make it exact)",
                hex::encode(got),
                got[0]
            ));
        }
        None => problems.push(format!(
            "MRCONFIGID is {}: neither zero nor a dstack config id for this compose, and the policy does not pin it",
            hex::encode(got)
        )),
    }
    (problems, note)
}

/// One dstack event log entry as served by the guest agent.
#[derive(Debug, Deserialize)]
struct RawEvent {
    imr: u32,
    event_type: u32,
    digest: String,
    #[serde(default)]
    event: String,
    #[serde(default)]
    event_payload: String,
    /// Present on V2 logs. We support V1 only and refuse V2 explicitly.
    #[serde(default)]
    version: Option<serde_json::Value>,
}

/// A replayed RTMR3 runtime event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub name: String,
    pub payload: Vec<u8>,
}

/// V1 digest of a runtime event.
pub fn runtime_event_digest(name: &str, payload: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(DSTACK_RUNTIME_EVENT_TYPE.to_le_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    h.update(b":");
    h.update(payload);
    h.finalize().into()
}

fn extend(mr: &[u8; 48], digest: &[u8; 48]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(mr);
    h.update(digest);
    h.finalize().into()
}

/// Replay RTMR3 from a dstack event log (JSON array string).
pub fn replay_rtmr3(event_log_json: &str) -> Result<([u8; 48], Vec<RuntimeEvent>), TdxError> {
    let raw: Vec<RawEvent> =
        serde_json::from_str(event_log_json).map_err(|e| TdxError::EventLogJson(e.to_string()))?;
    let mut mr = [0u8; 48];
    let mut events = Vec::new();
    for (index, e) in raw.iter().enumerate() {
        if e.imr != 3 {
            continue;
        }
        let bad = |reason: String| TdxError::EventLogEntry { index, reason };
        if e.version
            .as_ref()
            .is_some_and(|v| v != &serde_json::json!(1))
        {
            return Err(bad("event log version 2 is not supported yet".into()));
        }
        if e.event_type != DSTACK_RUNTIME_EVENT_TYPE {
            return Err(bad(format!(
                "unexpected RTMR3 event type {:#x}",
                e.event_type
            )));
        }
        if !KNOWN_RTMR3_EVENTS.contains(&e.event.as_str()) {
            return Err(bad(format!("unknown RTMR3 event `{}`", e.event)));
        }
        let payload =
            hex::decode(&e.event_payload).map_err(|_| bad("payload is not hex".into()))?;
        let digest = runtime_event_digest(&e.event, &payload);
        if !e.digest.eq_ignore_ascii_case(&hex::encode(digest)) {
            return Err(bad(format!(
                "digest field does not match SHA-384 of event `{}`",
                e.event
            )));
        }
        mr = extend(&mr, &digest);
        events.push(RuntimeEvent {
            name: e.event.clone(),
            payload,
        });
    }
    Ok((mr, events))
}

/// Replay RTMR3 and require it to equal the quoted value.
pub fn check_rtmr3(event_log_json: &str, quoted: &[u8; 48]) -> Result<Vec<RuntimeEvent>, TdxError> {
    let (replayed, events) = replay_rtmr3(event_log_json)?;
    if &replayed != quoted {
        return Err(TdxError::Rtmr3Mismatch {
            replayed: hex::encode(replayed),
            quoted: hex::encode(quoted),
        });
    }
    Ok(events)
}

/// Facts extracted from a verified RTMR3 event sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rtmr3Facts {
    pub compose_hash: [u8; 32],
    pub app_id: Vec<u8>,
    pub key_provider: String,
    /// `Some(true)` if the OS measured an encrypted data disk; `None` on
    /// images that predate the `storage-encrypted` event.
    pub storage_encrypted: Option<bool>,
}

/// Boot events up to and including `boot-mr-done`, in dstack's order
/// (`dstack-util/src/system_setup.rs`); `true` = required.
const RTMR3_BOOT: &[(&str, bool)] = &[
    ("system-preparing", true),
    ("app-id", true),
    ("compose-hash", true),
    ("gpu-policy-hash", false),
    ("instance-id", true),
    ("boot-mr-done", true),
];
/// After `boot-mr-done` the key provider is recorded; with a KMS the OS
/// image hash the KMS saw is recorded next to it. Either order is accepted.
const RTMR3_KEYS: &[&str] = &["os-image-hash", "key-provider"];
/// Storage setup, then the end of the OS's own measurements.
const RTMR3_TAIL: &[(&str, bool)] = &[
    ("storage-fs", true),
    ("storage-encrypted", false),
    ("system-ready", true),
];
/// Known dstack events this release must not contain.
const RTMR3_REFUSED: &[(&str, &str)] = &[
    (
        "init-script-hash",
        "the OS ran an init script, and the policy pins none",
    ),
    (
        "gpu-attestation",
        "GPU attestation, and this release has no GPU",
    ),
];

fn take_in_order<'a>(
    rest: &mut &'a [RuntimeEvent],
    spec: &[(&str, bool)],
    position: &mut usize,
) -> Result<Vec<&'a RuntimeEvent>, TdxError> {
    let mut taken = Vec::new();
    for (name, required) in spec {
        match rest.first() {
            Some(e) if e.name == *name => {
                taken.push(e);
                *rest = &rest[1..];
                *position += 1;
            }
            _ if !required => {}
            Some(e) => {
                return Err(TdxError::Events(format!(
                    "event {} is `{}` where `{name}` is expected (not the dstack boot sequence)",
                    *position, e.name
                )));
            }
            None => {
                return Err(TdxError::Events(format!(
                    "log ends before `{name}` (boot did not complete)"
                )));
            }
        }
    }
    Ok(taken)
}

fn find<'a>(events: &[&'a RuntimeEvent], name: &str) -> Option<&'a RuntimeEvent> {
    events.iter().find(|e| e.name == name).copied()
}

/// Structural checks on the replayed RTMR3 events. The log must be exactly
/// the sequence a dstack OS emits while booting this release, nothing more:
///
/// ```text
/// system-preparing, app-id, compose-hash, [gpu-policy-hash], instance-id,
/// boot-mr-done, {[os-image-hash], key-provider}, storage-fs,
/// [storage-encrypted], system-ready
/// ```
///
/// * no event appears twice;
/// * nothing follows `system-ready`: whatever comes later was emitted after
///   boot (a container can extend RTMR3 through the guest agent), and the
///   published compose emits nothing;
/// * `init-script-hash` and `gpu-attestation` are refused: the policy pins
///   no init script and the release has no GPU;
/// * the marker events (`system-preparing`, `boot-mr-done`, `system-ready`)
///   carry no payload.
pub fn rtmr3_facts(events: &[RuntimeEvent]) -> Result<Rtmr3Facts, TdxError> {
    let bad = |m: String| Err(TdxError::Events(m));
    for (i, e) in events.iter().enumerate() {
        if let Some((_, why)) = RTMR3_REFUSED.iter().find(|(n, _)| *n == e.name) {
            return bad(format!("`{}` event: {why}", e.name));
        }
        if events[..i].iter().any(|p| p.name == e.name) {
            return bad(format!("more than one `{}` event", e.name));
        }
    }
    if let Some(end) = events.iter().position(|e| e.name == "system-ready")
        && end + 1 != events.len()
    {
        return bad(format!(
            "{} event(s) after `system-ready`: something extended RTMR3 after boot",
            events.len() - end - 1
        ));
    }

    let mut rest = events;
    let mut position = 0;
    let mut seen = take_in_order(&mut rest, RTMR3_BOOT, &mut position)?;
    while let Some(e) = rest
        .first()
        .filter(|e| RTMR3_KEYS.contains(&e.name.as_str()))
    {
        seen.push(e);
        rest = &rest[1..];
        position += 1;
    }
    let Some(kp) = find(&seen, "key-provider") else {
        return bad("no `key-provider` event after `boot-mr-done`".into());
    };
    seen.extend(take_in_order(&mut rest, RTMR3_TAIL, &mut position)?);
    if let Some(e) = rest.first() {
        return bad(format!(
            "unexpected event `{}` at position {position}",
            e.name
        ));
    }

    for marker in ["system-preparing", "boot-mr-done", "system-ready"] {
        if find(&seen, marker).is_some_and(|e| !e.payload.is_empty()) {
            return bad(format!("`{marker}` carries a payload"));
        }
    }
    let payload = |name: &str| find(&seen, name).map(|e| e.payload.as_slice());
    let compose_hash: [u8; 32] = payload("compose-hash")
        .and_then(|p| p.try_into().ok())
        .ok_or_else(|| TdxError::Events("`compose-hash` payload is not 32 bytes".into()))?;
    let app_id = payload("app-id").unwrap_or_default().to_vec();
    let key_provider = String::from_utf8(kp.payload.clone())
        .map_err(|_| TdxError::Events("`key-provider` payload is not UTF-8".into()))?;
    let storage_encrypted = match payload("storage-encrypted") {
        None => None,
        Some(b"1") => Some(true),
        Some(b"0") => {
            return bad(
                "`storage-encrypted` is 0: the data disk is NOT encrypted, the host can read it"
                    .into(),
            );
        }
        Some(_) => return bad("`storage-encrypted` payload is not 0 or 1".into()),
    };
    Ok(Rtmr3Facts {
        compose_hash,
        app_id,
        key_provider,
        storage_encrypted,
    })
}
