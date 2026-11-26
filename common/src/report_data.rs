//! `report_data` construction.
//!
//! ```text
//! report_data = SHA-512( "attested-vaultwarden/v1" || nonce || spki_sha256 )
//! ```
//!
//! * `nonce`: 32 random bytes chosen by the verifier (sent as 64 hex chars).
//! * `spki_sha256`: SHA-256 of the DER-encoded `SubjectPublicKeyInfo` of the
//!   TLS leaf certificate the proxy serves.
//!
//! The 64-byte output fills the whole `report_data` field of both a TDX
//! TDREPORT and an SEV-SNP attestation report. The domain-separation tag
//! prevents a quote produced for some other protocol from being replayed here.
//! All inputs are fixed length, so plain concatenation is unambiguous.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Domain-separation tag; bump the version suffix on any change to the
/// construction.
pub const DOMAIN_TAG: &[u8] = b"attested-vaultwarden/v1";

/// Human-readable description returned in the attestation document so that a
/// verifier can detect a construction mismatch with a clear message.
pub const CONSTRUCTION: &str =
    "SHA-512(\"attested-vaultwarden/v1\" || nonce[32] || spki_sha256[32])";

/// Errors parsing fixed-size hex values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HexError {
    #[error("expected {expected} hex characters, got {got}")]
    Length { expected: usize, got: usize },
    #[error("invalid hex: {0}")]
    Invalid(String),
}

fn parse_fixed_hex<const N: usize>(s: &str) -> Result<[u8; N], HexError> {
    if s.len() != N * 2 {
        return Err(HexError::Length {
            expected: N * 2,
            got: s.len(),
        });
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|e| HexError::Invalid(e.to_string()))?;
    Ok(out)
}

macro_rules! fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = HexError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_fixed_hex::<$len>(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_bytes!(
    /// 32-byte verifier-chosen freshness nonce.
    Nonce,
    32
);
fixed_bytes!(
    /// SHA-256 of a DER-encoded `SubjectPublicKeyInfo`.
    SpkiSha256,
    32
);
fixed_bytes!(
    /// The 64-byte value placed in the TEE report's `report_data` field.
    ReportData,
    64
);

impl SpkiSha256 {
    /// Hash a DER-encoded `SubjectPublicKeyInfo`.
    pub fn of_spki_der(spki_der: &[u8]) -> Self {
        Self(Sha256::digest(spki_der).into())
    }
}

/// Compute `report_data` for a nonce and TLS key.
pub fn compute(nonce: &Nonce, spki: &SpkiSha256) -> ReportData {
    let mut h = Sha512::new();
    h.update(DOMAIN_TAG);
    h.update(nonce.0);
    h.update(spki.0);
    ReportData(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer() {
        // Independent computation:
        //   printf 'attested-vaultwarden/v1' > m; head -c32 /dev/zero >> m;
        //   head -c32 /dev/zero | tr '\0' '\377' >> m; sha512sum m
        let nonce = Nonce([0u8; 32]);
        let spki = SpkiSha256([0xffu8; 32]);
        let rd = compute(&nonce, &spki);
        assert_eq!(rd.to_hex(), KAT_ZERO_FF);
    }

    // Filled in from the shell command in `known_answer`; see DECISIONS.md.
    const KAT_ZERO_FF: &str = include_str!("../testdata/report_data_kat.hex").trim_ascii();

    #[test]
    fn nonce_and_spki_are_both_bound() {
        let n1 = Nonce([1u8; 32]);
        let n2 = Nonce([2u8; 32]);
        let s1 = SpkiSha256([1u8; 32]);
        let s2 = SpkiSha256([2u8; 32]);
        assert_ne!(compute(&n1, &s1), compute(&n2, &s1));
        assert_ne!(compute(&n1, &s1), compute(&n1, &s2));
    }

    #[test]
    fn nonce_parsing_is_strict() {
        assert!("00".repeat(32).parse::<Nonce>().is_ok());
        assert_eq!(
            "00".repeat(31).parse::<Nonce>(),
            Err(HexError::Length {
                expected: 64,
                got: 62
            })
        );
        assert!(matches!(
            "zz".repeat(32).parse::<Nonce>(),
            Err(HexError::Invalid(_))
        ));
        // A 0x prefix is not accepted.
        assert!(format!("0x{}", "00".repeat(31)).parse::<Nonce>().is_err());
    }

    #[test]
    fn serde_roundtrip_hex() {
        let n = Nonce([0xabu8; 32]);
        let j = serde_json::to_string(&n).unwrap_or_default();
        assert_eq!(j, format!("\"{}\"", "ab".repeat(32)));
        let back: Nonce = serde_json::from_str(&j).unwrap_or(Nonce([0; 32]));
        assert_eq!(back, n);
    }
}
