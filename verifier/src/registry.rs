//! Display-only enrichment of the image list: which tags point at a pinned
//! digest right now.
//!
//! **Never part of the verdict.** The verifier trusts digests, which are
//! content hashes; a tag is a mutable pointer that the registry (or whoever
//! controls the repository) can move at any time. The lookup only helps a
//! human recognise a digest ("that is vaultwarden/server 1.37.5"). A failed
//! or slow lookup prints "lookup failed" and changes nothing else.
//!
//! This module is pure: it builds the request URL and formats the answer.
//! The CLI (`online`) and the web page do the HTTP request themselves.

/// Tags requested from Docker Hub (one page, newest first).
pub const HUB_PAGE_SIZE: u32 = 100;

/// Note printed for images on ghcr.io, which this project publishes
/// privately: nobody else can ask the registry, but anyone can rebuild.
pub const GHCR_NOTE: &str = "(private registry: rebuild with attest-sidecar/reproducible-build.sh <commit from policy header>)";

/// A digest-pinned image reference split into its parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// Registry host, `docker.io` if the reference names none.
    pub registry: String,
    /// Repository path; Docker Hub official images get `library/`.
    pub repository: String,
    /// `sha256:<64 hex>`.
    pub digest: String,
}

/// Parse `[registry/]repo[:tag]@sha256:<hex>`. `None` if not digest-pinned.
pub fn parse(image: &str) -> Option<ImageRef> {
    let (name, digest) = image.split_once('@')?;
    let hex = digest.strip_prefix("sha256:")?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let (first, rest) = name.split_once('/').unwrap_or(("", name));
    // Docker's rule: the first component is a registry if it has a dot or a
    // port, or is `localhost`.
    let (registry, path) = if first.contains('.') || first.contains(':') || first == "localhost" {
        (first, rest)
    } else {
        ("docker.io", name)
    };
    // Drop a tag, if any (`repo:tag@sha256:…`).
    let path = path.split_once(':').map_or(path, |(p, _)| p);
    let registry = match registry {
        "index.docker.io" | "registry-1.docker.io" => "docker.io",
        r => r,
    };
    let repository = if registry == "docker.io" && !path.contains('/') {
        format!("library/{path}")
    } else {
        path.to_owned()
    };
    let ok = !repository.is_empty()
        && repository.split('/').all(|c| {
            !c.is_empty()
                && !c.starts_with(".")
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        });
    ok.then(|| ImageRef {
        registry: registry.to_ascii_lowercase(),
        repository,
        digest: digest.to_ascii_lowercase(),
    })
}

impl ImageRef {
    /// Name as users write it: `caddy`, `vaultwarden/server`.
    pub fn short_name(&self) -> &str {
        match (
            self.registry.as_str(),
            self.repository.strip_prefix("library/"),
        ) {
            ("docker.io", Some(n)) => n,
            _ => &self.repository,
        }
    }
}

/// Docker Hub API URL listing the newest tags of the image's repository,
/// if the image is on Docker Hub.
pub fn hub_tags_url(image: &str) -> Option<String> {
    let r = parse(image)?;
    (r.registry == "docker.io").then(|| {
        format!(
            "https://hub.docker.com/v2/repositories/{}/tags?page_size={HUB_PAGE_SIZE}&ordering=last_updated",
            r.repository
        )
    })
}

/// Tag names in a Docker Hub tags response whose manifest (multi-arch index
/// or any per-platform image) has `digest`.
pub fn hub_tags_for_digest(body: &str, digest: &str) -> Result<Vec<String>, String> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("response is not JSON: {e}"))?;
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .ok_or("response has no `results` list")?;
    let is = |d: Option<&serde_json::Value>| {
        d.and_then(|d| d.as_str())
            .is_some_and(|d| d.eq_ignore_ascii_case(digest))
    };
    let mut tags = Vec::new();
    for t in results {
        let Some(name) = t.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        let hit = is(t.get("digest"))
            || t.get("images")
                .and_then(|i| i.as_array())
                .is_some_and(|imgs| imgs.iter().any(|i| is(i.get("digest"))));
        // Tag names come from the network: keep only the registry's own
        // alphabet so nothing odd reaches a terminal.
        let clean = !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if hit && clean {
            tags.push(name.to_owned());
        }
    }
    Ok(tags)
}

/// The annotation line for one image, or `None` if there is nothing to say.
///
/// `hub` is the outcome of the Docker Hub request for [`hub_tags_url`]:
/// `None` if no lookup was attempted, `Some(Ok(body))` or `Some(Err(why))`.
pub fn annotation(image: &str, hub: Option<Result<&str, &str>>) -> Option<String> {
    let r = parse(image)?;
    match r.registry.as_str() {
        "ghcr.io" => Some(GHCR_NOTE.to_owned()),
        "docker.io" => {
            let failed = |why: &str| {
                let why: String = why.chars().filter(|c| !c.is_control()).take(120).collect();
                format!("(Docker Hub tag lookup failed: {why})")
            };
            Some(match hub? {
                Err(why) => failed(why),
                Ok(body) => match hub_tags_for_digest(body, &r.digest) {
                    Err(why) => failed(&why),
                    Ok(tags) if tags.is_empty() => format!(
                        "(Docker Hub: none of the {HUB_PAGE_SIZE} most recently updated tags points at this digest)"
                    ),
                    Ok(tags) => {
                        let names: Vec<String> = tags
                            .iter()
                            .map(|t| format!("{}:{t}", r.short_name()))
                            .collect();
                        format!(
                            "= {} (Docker Hub, as of now; tags can move)",
                            names.join(", ")
                        )
                    }
                },
            })
        }
        _ => None,
    }
}

/// Sub-lines of the `Images` check: one `<service>  <image>` line per
/// service (full digest), each followed by its annotation, if any.
/// `notes` is parallel to `images`; missing entries mean "no annotation".
pub fn sub_lines(images: &[(String, String)], notes: &[Option<String>]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, (service, image)) in images.iter().enumerate() {
        out.push(format!("{service}  {image}"));
        if let Some(Some(n)) = notes.get(i) {
            out.push(format!("  {n}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const D3: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    fn hub_body() -> String {
        serde_json::json!({"count": 3, "results": [
            {"name": "1.37.5", "digest": D1, "images": [{"digest": D2, "architecture": "amd64"}]},
            {"name": "latest", "digest": D1, "images": [{"digest": D2}]},
            {"name": "testing", "digest": D3, "images": []},
            {"name": "evil\u{1b}[31m", "digest": D1},
            {"digest": D1},
        ]})
        .to_string()
    }

    #[test]
    fn parses_references() {
        let p = |s: &str| parse(s).map(|r| (r.registry, r.repository));
        let v = format!("docker.io/vaultwarden/server@{D1}");
        assert_eq!(
            p(&v),
            Some(("docker.io".into(), "vaultwarden/server".into()))
        );
        assert_eq!(
            p(&format!("docker.io/library/caddy@{D1}")),
            Some(("docker.io".into(), "library/caddy".into()))
        );
        assert_eq!(
            p(&format!("caddy:2@{D1}")),
            Some(("docker.io".into(), "library/caddy".into()))
        );
        assert_eq!(
            p(&format!("vaultwarden/server@{D1}")),
            Some(("docker.io".into(), "vaultwarden/server".into()))
        );
        assert_eq!(
            p(&format!("ghcr.io/someone/attest-sidecar@{D1}")),
            Some(("ghcr.io".into(), "someone/attest-sidecar".into()))
        );
        assert_eq!(
            p(&format!("localhost:5000/x@{D1}")),
            Some(("localhost:5000".into(), "x".into()))
        );
        for bad in [
            "caddy:2",
            "caddy@sha256:abc",
            "caddy@md5:1111",
            &format!("docker.io/a/../b@{D1}") as &str,
            &format!("docker.io/a?x=1@{D1}"),
            &format!("@{D1}"),
        ] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn hub_url_only_for_docker_hub() {
        assert_eq!(
            hub_tags_url(&format!("docker.io/library/caddy@{D1}")).as_deref(),
            Some(
                "https://hub.docker.com/v2/repositories/library/caddy/tags?page_size=100&ordering=last_updated"
            )
        );
        assert_eq!(hub_tags_url(&format!("ghcr.io/a/b@{D1}")), None);
        assert_eq!(hub_tags_url("caddy:latest"), None);
    }

    #[test]
    fn finds_tags_by_index_or_platform_digest() {
        let b = hub_body();
        assert_eq!(hub_tags_for_digest(&b, D1).unwrap(), ["1.37.5", "latest"]);
        assert_eq!(
            hub_tags_for_digest(&b, &D2.to_uppercase().replace("SHA256", "sha256"))
                .unwrap()
                .len(),
            2
        );
        assert!(hub_tags_for_digest(&b, "sha256:00").unwrap().is_empty());
        assert!(hub_tags_for_digest("<html>", D1).is_err());
        assert!(hub_tags_for_digest("{}", D1).is_err());
    }

    #[test]
    fn annotations() {
        let b = hub_body();
        let vw = format!("docker.io/vaultwarden/server@{D1}");
        assert_eq!(
            annotation(&vw, Some(Ok(&b))).unwrap(),
            "= vaultwarden/server:1.37.5, vaultwarden/server:latest (Docker Hub, as of now; tags can move)"
        );
        assert_eq!(
            annotation(&format!("docker.io/library/caddy@{D3}"), Some(Ok(&b))).unwrap(),
            "= caddy:testing (Docker Hub, as of now; tags can move)"
        );
        assert_eq!(
            annotation(
                &format!("docker.io/library/caddy@sha256:{}", "9".repeat(64)),
                Some(Ok(&b))
            )
            .unwrap(),
            "(Docker Hub: none of the 100 most recently updated tags points at this digest)"
        );
        assert_eq!(
            annotation(&vw, Some(Err("timed out\nafter 5 s"))).unwrap(),
            "(Docker Hub tag lookup failed: timed outafter 5 s)"
        );
        assert!(
            annotation(&vw, Some(Ok("not json")))
                .unwrap()
                .starts_with("(Docker Hub tag lookup failed: ")
        );
        // No lookup attempted: nothing to say about a Docker Hub image.
        assert_eq!(annotation(&vw, None), None);
        // ghcr.io: static note, with or without a lookup.
        assert_eq!(
            annotation(&format!("ghcr.io/a/b@{D1}"), None).unwrap(),
            GHCR_NOTE
        );
        assert_eq!(
            annotation(&format!("quay.io/a/b@{D1}"), Some(Err("x"))),
            None
        );
        assert_eq!(annotation("caddy:latest", Some(Ok(&b))), None);
    }

    #[test]
    fn sub_lines_format() {
        let images = vec![
            ("attest".to_owned(), format!("ghcr.io/a/b@{D1}")),
            ("proxy".to_owned(), format!("docker.io/library/caddy@{D2}")),
        ];
        assert_eq!(
            sub_lines(&images, &[]),
            [
                format!("attest  ghcr.io/a/b@{D1}"),
                format!("proxy  docker.io/library/caddy@{D2}")
            ]
        );
        let notes = vec![Some(GHCR_NOTE.to_owned()), None];
        assert_eq!(
            sub_lines(&images, &notes),
            [
                format!("attest  ghcr.io/a/b@{D1}"),
                format!("  {GHCR_NOTE}"),
                format!("proxy  docker.io/library/caddy@{D2}")
            ]
        );
    }
}
