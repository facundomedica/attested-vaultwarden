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
