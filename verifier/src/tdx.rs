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
    pub advisory_ids: Vec<String>,
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
pub fn verify_quote(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_secs: u64,
    accepted_tcb_status: &[String],
    flags: PlatformFlags,
) -> Result<VerifiedQuote, TdxError> {
    let mut qp = QuotePolicy::strict(now_secs)
        .allow_smt(flags.smt)
        .allow_dynamic_platform(flags.dynamic_platform)
        .allow_cached_keys(flags.cached_keys);
    for s in accepted_tcb_status {
        qp = qp.allow_status(parse_status(s)?);
    }
    let claims = QuoteVerifier::new_prod()
        .verify_with_policy(quote, collateral.clone(), now_secs, &qp)
        .map_err(|e| TdxError::Quote(format!("{e:#}")))?;
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
        advisory_ids: claims.tcb.advisory_ids.clone(),
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

fn single<'a>(events: &'a [RuntimeEvent], name: &str) -> Result<&'a RuntimeEvent, TdxError> {
    let mut it = events.iter().filter(|e| e.name == name);
    let first = it
        .next()
        .ok_or_else(|| TdxError::Events(format!("no `{name}` event")))?;
    if it.next().is_some() {
        return Err(TdxError::Events(format!("more than one `{name}` event")));
    }
    Ok(first)
}

/// Structural checks: exactly one `compose-hash`, `app-id`, `key-provider`,
/// `boot-mr-done`, and `compose-hash` measured before `boot-mr-done` (i.e.
/// by the OS during boot, not by a container afterwards).
pub fn rtmr3_facts(events: &[RuntimeEvent]) -> Result<Rtmr3Facts, TdxError> {
    let pos = |n: &str| events.iter().position(|e| e.name == n);
    let ch = single(events, "compose-hash")?;
    single(events, "boot-mr-done")?;
    if pos("compose-hash") > pos("boot-mr-done") {
        return Err(TdxError::Events(
            "`compose-hash` measured after `boot-mr-done`".into(),
        ));
    }
    let compose_hash: [u8; 32] = ch
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| TdxError::Events("`compose-hash` payload is not 32 bytes".into()))?;
    let app_id = single(events, "app-id")?.payload.clone();
    let kp = single(events, "key-provider")?;
    let key_provider = String::from_utf8(kp.payload.clone())
        .map_err(|_| TdxError::Events("`key-provider` payload is not UTF-8".into()))?;
    let storage_encrypted = match events
        .iter()
        .filter(|e| e.name == "storage-encrypted")
        .count()
    {
        0 => None,
        1 => match single(events, "storage-encrypted")?.payload.as_slice() {
            b"1" => Some(true),
            b"0" => {
                return Err(TdxError::Events(
                    "`storage-encrypted` is 0: the data disk is NOT encrypted, the host can read it".into(),
                ));
            }
            _ => {
                return Err(TdxError::Events(
                    "`storage-encrypted` payload is not 0 or 1".into(),
                ));
            }
        },
        _ => {
            return Err(TdxError::Events(
                "more than one `storage-encrypted` event".into(),
            ));
        }
    };
    Ok(Rtmr3Facts {
        compose_hash,
        app_id,
        key_provider,
        storage_encrypted,
    })
}
