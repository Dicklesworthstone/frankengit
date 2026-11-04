//! Static artifact custody inspector. Its independent native artifact-read
//! endpoints retain authorization; enabling source or issues is unnecessary.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/artifacts/" => Some(("text/html; charset=utf-8", include_str!("artifacts.html"))),
        b"/ui/artifacts/artifacts.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("artifacts.mjs"),
        )),
        b"/ui/artifacts/artifacts-protocol.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("artifacts-protocol.mjs"),
        )),
        b"/ui/artifacts/artifacts-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("artifacts-view.mjs"),
        )),
        b"/ui/artifacts/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        // An artifact-only gateway need not enable the source/issue CSS route.
        b"/ui/artifacts/browser.css" => {
            Some(("text/css; charset=utf-8", include_str!("browser.css")))
        }
        _ => None,
    }
}

fn checked_asset(
    route: &[u8],
    enabled: bool,
    maximum: u64,
    request: &Envelope<'_>,
    trailing: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else {
        return Ok(None);
    };
    if !enabled {
        return Err(Status::NotFound);
    }
    if request.method != "GET" {
        return Err(Status::Method);
    }
    if request.target.contains('?')
        || request.git_protocol.is_some()
        || request.expect_continue
        || trailing
        || !matches!(
            request.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        )
    {
        return Err(Status::BadRequest);
    }
    if body.len() as u64 > maximum {
        return Err(Status::TooLarge);
    }
    Ok(Some(found))
}

pub(super) fn serve(
    profile: &Profile,
    request: &Envelope<'_>,
    trailing: &[u8],
    writer: &mut impl Write,
) -> Result<bool, Status> {
    let Some((media, body)) = checked_asset(
        &profile.route,
        profile.config.workflow_artifact_root().is_some(),
        profile.maximum_response_bytes,
        request,
        !trailing.is_empty(),
    )?
    else {
        return Ok(false);
    };
    let version = match request.version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    write!(
        writer,
        "{version} 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{SECURITY}Connection: close\r\n\r\n",
        body.len()
    )?;
    writer.write_all(body.as_bytes())?;
    writer.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn artifact_shell_has_exact_independently_enabled_routes_and_all_relative_assets() {
        for suffix in [
            "",
            "artifacts.mjs",
            "artifacts-protocol.mjs",
            "artifacts-view.mjs",
            "pulls-core.mjs",
            "browser.css",
        ] {
            let target = format!("/repo.git/ui/artifacts/{suffix}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(
                checked_asset(b"/repo.git", true, u64::MAX, &request, false)
                    .unwrap()
                    .is_some()
            );
            assert!(matches!(
                checked_asset(b"/repo.git", false, u64::MAX, &request, false),
                Err(Status::NotFound)
            ));
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in [
            "/repo.git-more/ui/artifacts/",
            "/repo.git/ui/artifacts/../private",
            "/repo.git/ui/artifacts/%2e%2e",
            "/repo.git/ui/artifacts/root",
            "/repo.git/api/v1/artifacts/",
            "/repo.git/ui/pulls/",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }

    #[test]
    fn static_artifact_profile_refuses_queries_bodies_protocols_and_over_budget_assets() {
        for (method, query, headers, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX),
            ("GET", "?token=secret", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Transfer-Encoding: chunked\r\n", false, u64::MAX),
            ("GET", "", "Expect: 100-continue\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX),
            ("GET", "", "", false, 1),
        ] {
            let bytes = format!(
                "{method} /repo.git/ui/artifacts/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }

    #[test]
    fn artifact_shell_uses_inert_text_and_ephemeral_credentials() {
        assert!(!include_str!("artifacts.html").contains("<script>"));
        for script in [
            include_str!("artifacts.mjs"),
            include_str!("artifacts-protocol.mjs"),
            include_str!("artifacts-view.mjs"),
        ] {
            for forbidden in [
                "innerHTML",
                "outerHTML",
                "localStorage",
                "sessionStorage",
                "document.cookie",
                "eval(",
            ] {
                assert!(!script.contains(forbidden), "unexpected {forbidden}");
            }
        }
        assert!(SECURITY.contains("connect-src 'self'"));
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(include_str!("artifacts-view.mjs").contains("revokeObjectURL"));
        assert!(include_str!("artifacts-view.mjs").contains("'pagehide'"));
    }

    #[test]
    fn browser_vectors_match_native_artifact_and_scope_commitments() {
        use crate::workflow_artifacts::parse_artifact_id;
        use fgit_object_fabric::artifact::storage::ArtifactScope;
        use fgit_object_fabric::{
            ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile,
        };
        use fgit_schema::json::{self, Value};
        use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};

        fn bytes(text: &str) -> Vec<u8> {
            assert_eq!(text.len() % 2, 0);
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
                .collect()
        }
        let Value::Array(vectors) = json::parse(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/browser/artifacts-native-vectors.json"
        )))
        .unwrap() else {
            panic!("native artifact vectors must be an array");
        };
        assert_eq!(vectors.len(), 4);
        for vector in vectors {
            let row = vector.object().unwrap();
            let metadata = row["metadata"].object().unwrap();
            let text = |key: &str| metadata[key].text().unwrap();
            let optional = |key: &str| {
                metadata[key]
                    .text()
                    .map(|value| parse_artifact_id(value).unwrap())
            };
            let payload = bytes(row["payload_hex"].text().unwrap());
            let kind = match text("kind") {
                "ci_artifact" => ArtifactPayloadKind::CiArtifact,
                "build_log" => ArtifactPayloadKind::BuildLog,
                "release_asset" => ArtifactPayloadKind::ReleaseAsset,
                "provenance" => ArtifactPayloadKind::Provenance,
                other => panic!("unexpected vector kind {other}"),
            };
            let identity = ArtifactIdentity::new(
                parse_artifact_id(text("payload_sha256")).unwrap(),
                metadata["payload_bytes"].unsigned().unwrap(),
                MediaType::parse(text("media_type")).unwrap(),
                kind,
                optional("build_capsule_sha256"),
                optional("check_receipt_sha256"),
                optional("source_rcr_sha256"),
                RetentionProfile::decode_canonical(&bytes(text("retention_canonical_hex")))
                    .unwrap(),
            );
            assert_eq!(
                identity.artifact_id(),
                &parse_artifact_id(text("artifact_id")).unwrap()
            );
            assert_eq!(identity.payload_len(), payload.len() as u64);
            assert_eq!(
                identity.payload_digest().bytes().as_bytes(),
                &fgit_crypto::sha256_digest(&payload)
            );
            assert_eq!(text("trust_domain"), crate::TRUSTED_WORKFLOW_ARTIFACT_TRUST);
            let scope = ArtifactScope::new(
                TenantId::from_bytes(bytes(text("tenant_id")).try_into().unwrap()),
                RepositoryId::from_bytes(bytes(text("repository_id")).try_into().unwrap()),
                RepositoryIncarnationId::from_bytes(
                    bytes(text("repository_incarnation_id")).try_into().unwrap(),
                ),
                text("trust_domain"),
            )
            .unwrap();
            assert_eq!(
                scope.commitment(),
                parse_artifact_id(text("scope_sha256")).unwrap()
            );
        }
    }
}
