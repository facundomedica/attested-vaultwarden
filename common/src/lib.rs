//! Shared types for Attested Vaultwarden.
//!
//! This crate is deliberately small and dependency-light: both the sidecar
//! (which runs inside the TEE) and the verifier (which runs on users'
//! machines) depend on it, so everything here is part of the trusted surface.
//!
//! * [`report_data`]: the exact construction binding a verifier nonce and the
//!   TLS leaf SPKI hash into the 64-byte TEE `report_data` field.
//! * [`schema`]: the JSON document served at `/.well-known/tee-attestation`.
//! * [`policy`]: the per-release policy file format (`policy/<release>.toml`).
//! * [`provider`]: the `QuoteProvider` trait implemented by the sidecar.

#![forbid(unsafe_code)]

pub mod policy;
pub mod provider;
pub mod report_data;
pub mod schema;

/// Path at which the sidecar's attestation endpoint is served.
pub const ATTESTATION_PATH: &str = "/.well-known/tee-attestation";

/// Banner printed wherever the insecure mock platform appears.
pub const INSECURE_MOCK_BANNER: &str = "INSECURE MOCK: this evidence is NOT produced by TEE hardware and proves NOTHING about the server";
