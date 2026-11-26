//! TLS certificate helpers shared by the sidecar and the verifier, so both
//! compute `spki_sha256` with exactly the same code.

use crate::report_data::SpkiSha256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CertError {
    #[error("no PEM CERTIFICATE block found")]
    NoPem,
    #[error("invalid PEM: {0}")]
    Pem(String),
    #[error("invalid X.509 certificate: {0}")]
    X509(String),
}

/// SHA-256 over the DER `SubjectPublicKeyInfo` of a DER certificate.
pub fn spki_sha256_from_der(cert_der: &[u8]) -> Result<SpkiSha256, CertError> {
    let (rest, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| CertError::X509(e.to_string()))?;
    if !rest.is_empty() {
        return Err(CertError::X509("trailing data after certificate".into()));
    }
    Ok(SpkiSha256::of_spki_der(cert.public_key().raw))
}

/// DER of the first `CERTIFICATE` block in a PEM file (the leaf, in Caddy's
/// `<domain>.crt` bundle).
pub fn first_cert_der_from_pem(pem: &[u8]) -> Result<Vec<u8>, CertError> {
    for item in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let item = item.map_err(|e| CertError::Pem(e.to_string()))?;
        if item.label == "CERTIFICATE" {
            return Ok(item.contents);
        }
    }
    Err(CertError::NoPem)
}

/// DER of every `CERTIFICATE` block in a PEM file. Errors if there is none.
pub fn all_cert_ders_from_pem(pem: &[u8]) -> Result<Vec<Vec<u8>>, CertError> {
    let mut out = Vec::new();
    for item in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let item = item.map_err(|e| CertError::Pem(e.to_string()))?;
        if item.label == "CERTIFICATE" {
            out.push(item.contents);
        }
    }
    if out.is_empty() {
        return Err(CertError::NoPem);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Self-signed P-256 test certificate generated with:
    //   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    //     -keyout /dev/null -subj /CN=test -days 1 -out cert.pem
    // Expected SPKI hash computed with:
    //   openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER \
    //     | shasum -a 256
    const PEM: &[u8] = include_bytes!("../testdata/test-cert.pem");
    const SPKI_SHA256: &str = include_str!("../testdata/test-cert.spki-sha256.hex");

    #[test]
    fn spki_hash_matches_openssl() {
        let der = first_cert_der_from_pem(PEM).unwrap_or_default();
        let h = spki_sha256_from_der(&der)
            .map(|h| h.to_hex())
            .unwrap_or_default();
        assert_eq!(h, SPKI_SHA256.trim());
    }

    #[test]
    fn garbage_rejected() {
        assert_eq!(first_cert_der_from_pem(b"hello"), Err(CertError::NoPem));
        assert!(spki_sha256_from_der(b"\x30\x00").is_err());
    }
}
