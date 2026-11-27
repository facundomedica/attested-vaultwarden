//! Certificate Transparency check (browser mode, THREAT_MODEL R2).
//!
//! A web page cannot see the TLS certificate of its own connection, so it
//! cannot bind *this connection* to the attestation the way the CLI does.
//! What it can do is ask a CT monitor for **every** certificate that is
//! currently valid for the name and require each one's public key to be a
//! key that was attested inside the VM: the one attested just now
//! ([`crate::Report::attested_spki`]) or one from a list of previously
//! attested keys supplied by the caller.
//!
//! If that holds, a client that enforces CT (current browsers) can only
//! complete a handshake for the name with a key that lives in an attested
//! VM. Limits, which callers must show to the user:
//!
//! * detection, not prevention: a certificate issued a moment ago may not
//!   be in the logs or in the monitor's index yet;
//! * the monitor (Cert Spotter) is trusted to return every issuance; this
//!   code cannot check completeness;
//! * a previously attested key keeps counting for as long as its
//!   certificate is valid, even if the VM that held it is gone;
//! * revocation is ignored (a revoked certificate still has to be attested).
//!
//! Pure and synchronous: the caller does the HTTP requests (Cert Spotter
//! `GET /v1/issuances?domain=<name>&expand=dns_names&expand=issuer`, paged
//! with `after=<last id>`) and passes the JSON pages in. The exact-name
//! query does not return wildcard certificates, so the caller also queries
//! the parent ([`wildcard_parent`]) and this module keeps the issuances
//! naming `*.parent` (same logic as `demo/live/ct-check.sh`).

use serde::{Deserialize, Serialize};

use crate::report::{CheckId, Report};

/// One Cert Spotter issuance object (the fields we use).
#[derive(Debug, Deserialize)]
struct Issuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
    pubkey_sha256: String,
    #[serde(default)]
    not_before: String,
    #[serde(default)]
    not_after: String,
    #[serde(default)]
    issuer: Option<Issuer>,
}

#[derive(Debug, Deserialize)]
struct Issuer {
    #[serde(default)]
    friendly_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

/// Why a logged certificate is or is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CtStatus {
    /// Key attested in this run.
    AttestedNow,
    /// Key in the caller's list of previously attested keys.
    AttestedBefore,
    /// Valid certificate whose key was never attested: FAIL.
    NeverAttested,
    /// Past `not_after`; ignored.
    Expired,
}

/// A logged certificate valid for the name (or expired), for display.
#[derive(Debug, Clone, Serialize)]
pub struct CtCert {
    pub id: String,
    pub not_before: String,
    pub not_after: String,
    pub issuer: String,
    pub pubkey_sha256: String,
    pub dns_names: Vec<String>,
    /// Matched through `*.parent` rather than the exact name.
    pub wildcard: bool,
    pub status: CtStatus,
}

/// Inputs to [`check`]. Everything here comes from the caller's own
/// requests and bundled data, never from the attestation document.
#[derive(Debug, Clone)]
pub struct CtQuery<'a> {
    /// DNS name being verified.
    pub host: &'a str,
    /// Cert Spotter response bodies (JSON arrays) for `domain=<host>`.
    pub exact_pages: &'a [String],
    /// Response bodies for `domain=<wildcard_parent(host)>`. Required when
    /// [`wildcard_parent`] returns a name.
    pub parent_pages: Option<&'a [String]>,
    /// Current time (unix seconds), to drop expired certificates.
    pub now_secs: u64,
    /// SPKI SHA-256 hashes (hex) attested in earlier verifier runs.
    pub known_spkis: &'a [String],
}

/// Lower-case `host` without a trailing dot, if it looks like a DNS name.
pub fn normalize_host(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    ok.then_some(h)
}

/// The name whose wildcard certificate (`*.<parent>`) would also be valid
/// for `host`: `host` minus its first label, if at least two labels remain
/// (no CA issues `*.com`).
pub fn wildcard_parent(host: &str) -> Option<String> {
    let h = normalize_host(host)?;
    let (_, parent) = h.split_once('.')?;
    parent.contains('.').then(|| parent.to_owned())
}

/// Seconds since the unix epoch for an RFC 3339 timestamp
/// (`2026-11-27T09:00:00Z`, optional fraction, `Z` or `±hh:mm`).
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        let n = frac.bytes().take_while(u8::is_ascii_digit).count();
        if n == 0 {
            return None;
        }
        rest = &frac[n..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ => {
            let sign = match rest.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                return None;
            }
            let oh = rest.get(1..3)?.parse::<i64>().ok()?;
            let om = rest.get(4..6)?.parse::<i64>().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    // Days from civil (Howard Hinnant's algorithm), proleptic Gregorian.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec - offset).ok()
}

fn parse_pages(pages: &[String], what: &str) -> Result<Vec<Issuance>, String> {
    let mut out = Vec::new();
    for (i, p) in pages.iter().enumerate() {
        let page: Vec<Issuance> = serde_json::from_str(p).map_err(|e| {
            format!(
                "CT response for {what} (page {}) is not a list of issuances: {e}",
                i + 1
            )
        })?;
        out.extend(page);
    }
    Ok(out)
}

fn is_spki_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Run the CT check and record exactly one `CtBinding` check on `report`.
/// Returns the certificates considered, for display.
///
/// Fail-closed: no attested key on the report, a missing or malformed
/// response, a wildcard parent that was not queried, a certificate with an
/// unreadable expiry (treated as valid), no valid certificate carrying the
/// key attested now, or any valid certificate with a key that is neither
/// attested now nor in `known_spkis`.
pub fn check(q: &CtQuery<'_>, report: &mut Report) -> Vec<CtCert> {
    match check_inner(q, report.attested_spki.as_deref()) {
        Ok((detail, certs)) => {
            report.pass(CheckId::CtBinding, detail);
            certs
        }
        Err((detail, certs)) => {
            report.fail(CheckId::CtBinding, detail);
            certs
        }
    }
}

type Outcome = (String, Vec<CtCert>);

fn check_inner(q: &CtQuery<'_>, attested: Option<&str>) -> Result<Outcome, Outcome> {
    let fail = |m: String| (m, Vec::new());
    let host =
        normalize_host(q.host).ok_or_else(|| fail(format!("`{}` is not a DNS name", q.host)))?;
    let parent = wildcard_parent(&host);
    let mut all = parse_pages(q.exact_pages, &host).map_err(fail)?;
    if q.exact_pages.is_empty() {
        return Err(fail(format!("no CT response for {host}")));
    }
    let wildcard_name = parent.as_ref().map(|p| format!("*.{p}"));
    if let Some(p) = &parent {
        let pages = q
            .parent_pages
            .filter(|p| !p.is_empty())
            .ok_or_else(|| fail(format!("no CT response for {p} (needed to find *.{p} wildcard certificates, which are valid for {host})")))?;
        all.extend(parse_pages(pages, p).map_err(fail)?);
    }

    let mut certs: Vec<CtCert> = Vec::new();
    for i in all {
        let names: Vec<String> = i.dns_names.iter().map(|n| n.to_ascii_lowercase()).collect();
        let exact = names.contains(&host);
        let wild = wildcard_name.as_ref().is_some_and(|w| names.contains(w));
        // The parent query also returns certificates for the parent itself
        // and its other names; only those covering `host` matter. An
        // exact-name response that does not name the host is ignored too.
        if !(exact || wild) || certs.iter().any(|c| c.id == i.id) {
            continue;
        }
        let spki = i.pubkey_sha256.to_ascii_lowercase();
        let expired = parse_rfc3339(&i.not_after).is_some_and(|t| t <= q.now_secs);
        let status = if expired {
            CtStatus::Expired
        } else if !is_spki_hex(&spki) {
            CtStatus::NeverAttested
        } else if attested.is_some_and(|a| a.eq_ignore_ascii_case(&spki)) {
            CtStatus::AttestedNow
        } else if q.known_spkis.iter().any(|k| k.eq_ignore_ascii_case(&spki)) {
            CtStatus::AttestedBefore
        } else {
            CtStatus::NeverAttested
        };
        certs.push(CtCert {
            id: i.id,
            not_before: i.not_before,
            not_after: i.not_after,
            issuer: i
                .issuer
                .and_then(|x| x.friendly_name.or(x.name))
                .unwrap_or_default(),
            pubkey_sha256: spki,
            dns_names: i.dns_names,
            wildcard: wild && !exact,
            status,
        });
    }

    let count = |s: CtStatus| certs.iter().filter(|c| c.status == s).count();
    let (now, before, never, expired) = (
        count(CtStatus::AttestedNow),
        count(CtStatus::AttestedBefore),
        count(CtStatus::NeverAttested),
        count(CtStatus::Expired),
    );
    let valid = now + before + never;
    let scope = match &wildcard_name {
        Some(w) => format!("{host} or {w}"),
        None => host.clone(),
    };
    if never > 0 {
        let bad: Vec<String> = certs
            .iter()
            .filter(|c| c.status == CtStatus::NeverAttested)
            .map(|c| {
                format!(
                    "{} from {} (issuer {}, key {})",
                    c.dns_names.join(","),
                    c.not_before,
                    c.issuer,
                    c.pubkey_sha256
                )
            })
            .collect();
        return Err((
            format!(
                "{never} of {valid} currently valid logged certificate(s) for {scope} have a key that was never attested: a server outside the attested VM can hold that key and serve this name: {}",
                bad.join("; ")
            ),
            certs,
        ));
    }
    let Some(attested) = attested else {
        return Err((
            "the attestation checks did not establish an attested TLS key, so there is nothing to compare the logged certificates with".to_owned(),
            certs,
        ));
    };
    if now == 0 {
        return Err((
            format!(
                "no currently valid logged certificate for {scope} has the key attested now ({attested}); {valid} valid, {expired} expired found. The server's certificate may be too new for the CT monitor: try again in a few minutes"
            ),
            certs,
        ));
    }
    Ok((
        format!(
            "{valid} currently valid logged certificate(s) for {scope}: {now} with the key attested now, {before} with a previously attested key; {expired} expired ignored (source: Cert Spotter)"
        ),
        certs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const NOW: u64 = 1_795_767_600; // 2026-11-27T08:20:00Z

    fn iss(id: &str, names: &[&str], spki: &str, not_after: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id, "dns_names": names, "pubkey_sha256": spki,
            "not_before": "2026-11-01T00:00:00Z", "not_after": not_after,
            "issuer": {"friendly_name": "Test CA", "name": "CN=Test CA"},
            "tbs_sha256": "00", "cert_sha256": "00", "revoked": false,
        })
    }

    fn page(v: &[serde_json::Value]) -> Vec<String> {
        vec![serde_json::Value::Array(v.to_vec()).to_string()]
    }

    fn run(
        host: &str,
        exact: &[String],
        parent: Option<&[String]>,
        attested: Option<&str>,
        known: &[String],
    ) -> (Report, Vec<CtCert>) {
        let mut r = Report::new(host);
        r.browser_mode = true;
        r.attested_spki = attested.map(str::to_owned);
        let certs = check(
            &CtQuery {
                host,
                exact_pages: exact,
                parent_pages: parent,
                now_secs: NOW,
                known_spkis: known,
            },
            &mut r,
        );
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].id, CheckId::CtBinding);
        (r, certs)
    }

    const LATER: &str = "2027-02-01T00:00:00Z";
    const EARLIER: &str = "2026-11-20T00:00:00Z";
    const H: &str = "vault.warden.example.org";

    #[test]
    fn rfc3339() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-27T08:20:00Z"), Some(NOW));
        assert_eq!(parse_rfc3339("2026-11-27T08:20:00.123Z"), Some(NOW));
        assert_eq!(parse_rfc3339("2026-11-27T10:20:00+02:00"), Some(NOW));
        assert_eq!(parse_rfc3339("2026-11-27T08:20:00-00:00"), Some(NOW));
        assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for bad in [
            "",
            "2026-11-27",
            "2026-11-27T08:20:00",
            "2026-13-01T00:00:00Z",
            "x026-11-27T08:20:00Z",
            "2026-11-27T08:20:00.Z",
            "2026-11-27T08:20:00+0200",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn parents() {
        assert_eq!(wildcard_parent(H).as_deref(), Some("warden.example.org"));
        assert_eq!(
            wildcard_parent("Vault.Example.org.").as_deref(),
            Some("example.org")
        );
        assert_eq!(wildcard_parent("example.org"), None);
        assert_eq!(wildcard_parent("localhost"), None);
        assert_eq!(normalize_host("a b.example"), None);
        assert_eq!(normalize_host("https://x.example"), None);
    }

    #[test]
    fn all_attested_passes() {
        let exact = page(&[
            iss("1", &[H], A, LATER),
            iss("2", &[H], B, LATER),
            iss("3", &[H], C, EARLIER), // expired, never attested: ignored
        ]);
        let parent = page(&[iss("9", &["warden.example.org"], C, LATER)]); // not valid for H
        let (r, certs) = run(H, &exact, Some(&parent), Some(A), &[B.to_uppercase()]);
        assert!(r.checks[0].passed, "{}", r.checks[0].detail);
        assert!(r.passed());
        assert!(
            r.to_string()
                .ends_with("Result:  PASS (browser mode: CT-based binding)")
        );
        let st: Vec<CtStatus> = certs.iter().map(|c| c.status).collect();
        assert_eq!(
            st,
            [
                CtStatus::AttestedNow,
                CtStatus::AttestedBefore,
                CtStatus::Expired
            ]
        );
    }

    #[test]
    fn unattested_certificate_fails() {
        let exact = page(&[iss("1", &[H], A, LATER), iss("2", &[H], C, LATER)]);
        let parent = page(&[]);
        let (r, _) = run(H, &exact, Some(&parent), Some(A), &[]);
        assert!(!r.checks[0].passed);
        assert!(r.checks[0].detail.contains(C));
        assert!(r.to_string().ends_with("Result:  FAIL"));
    }

    #[test]
    fn unattested_wildcard_fails() {
        let exact = page(&[iss("1", &[H], A, LATER)]);
        let parent = page(&[iss(
            "7",
            &["*.WARDEN.example.org", "warden.example.org"],
            C,
            LATER,
        )]);
        let (r, certs) = run(H, &exact, Some(&parent), Some(A), &[]);
        assert!(!r.checks[0].passed);
        assert!(
            certs
                .iter()
                .any(|c| c.wildcard && c.status == CtStatus::NeverAttested)
        );
    }

    #[test]
    fn deeper_wildcard_does_not_cover() {
        // *.example.org is not valid for vault.warden.example.org.
        let exact = page(&[iss("1", &[H], A, LATER)]);
        let parent = page(&[iss("7", &["*.example.org"], C, LATER)]);
        let (r, certs) = run(H, &exact, Some(&parent), Some(A), &[]);
        assert!(r.checks[0].passed);
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn missing_parent_query_fails() {
        let exact = page(&[iss("1", &[H], A, LATER)]);
        let (r, _) = run(H, &exact, None, Some(A), &[]);
        assert!(!r.checks[0].passed);
        assert!(r.checks[0].detail.contains("*.warden.example.org"));
        // A two-label name has no wildcard parent to query.
        let exact = page(&[iss("1", &["example.org"], A, LATER)]);
        let (r, _) = run("example.org", &exact, None, Some(A), &[]);
        assert!(r.checks[0].passed, "{}", r.checks[0].detail);
    }

    #[test]
    fn nothing_attested_fails() {
        let exact = page(&[iss("1", &[H], A, LATER)]);
        let parent = page(&[]);
        // Even if every key is in the known list.
        let (r, _) = run(H, &exact, Some(&parent), None, &[A.to_owned()]);
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn attested_key_not_logged_fails() {
        // Empty log: must not pass vacuously.
        let (r, _) = run(H, &page(&[]), Some(&page(&[])), Some(A), &[]);
        assert!(!r.checks[0].passed);
        // Only a previously attested key is logged.
        let exact = page(&[iss("1", &[H], B, LATER)]);
        let (r, _) = run(H, &exact, Some(&page(&[])), Some(A), &[B.to_owned()]);
        assert!(!r.checks[0].passed);
        assert!(r.checks[0].detail.contains("too new"));
        // The current key's only certificate has expired.
        let exact = page(&[iss("1", &[H], A, EARLIER)]);
        let (r, _) = run(H, &exact, Some(&page(&[])), Some(A), &[]);
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn malformed_input_fails() {
        let ok = page(&[iss("1", &[H], A, LATER)]);
        for bad in ["", "{}", "{\"code\":\"rate_limited\"}", "[{\"id\":\"1\"}]"] {
            let (r, _) = run(H, &[bad.to_owned()], Some(&page(&[])), Some(A), &[]);
            assert!(!r.checks[0].passed, "{bad}");
            let (r, _) = run(H, &ok, Some(&[bad.to_owned()]), Some(A), &[]);
            assert!(!r.checks[0].passed, "{bad}");
        }
        let (r, _) = run(H, &[], Some(&page(&[])), Some(A), &[]);
        assert!(!r.checks[0].passed);
        let (r, _) = run("not a host", &ok, None, Some(A), &[]);
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn unreadable_expiry_counts_as_valid() {
        let exact = page(&[iss("1", &[H], A, LATER), iss("2", &[H], C, "soon")]);
        let (r, _) = run(H, &exact, Some(&page(&[])), Some(A), &[]);
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn pages_are_concatenated_and_deduplicated() {
        let mut exact = page(&[iss("1", &[H], A, LATER)]);
        exact.extend(page(&[iss("1", &[H], A, LATER), iss("2", &[H], C, LATER)]));
        let (r, certs) = run(H, &exact, Some(&page(&[])), Some(A), &[]);
        assert_eq!(certs.len(), 2);
        assert!(!r.checks[0].passed);
    }

    #[test]
    fn browser_report_without_ct_check_is_not_pass() {
        let mut r = Report::new("x");
        r.browser_mode = true;
        r.pass(CheckId::Fetch, "ok");
        assert!(!r.passed());
        assert_eq!(r.exit_code(), 1);
        assert!(r.to_string().ends_with("Result:  FAIL"));
    }
}
