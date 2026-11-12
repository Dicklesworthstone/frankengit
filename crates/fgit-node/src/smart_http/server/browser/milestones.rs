//! The milestone page composes the existing issue-granted native API.
//! Its complete flat module graph shares the ordinary issue transport,
//! renderer and stylesheet; the parent dispatcher preserves their existing
//! profile ceilings and applies the same bounded static-response policy.

pub(super) fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/milestones/" => Some(("text/html; charset=utf-8", include_str!("milestones.html"))),
        b"/ui/milestones.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("milestones.mjs"),
        )),
        b"/ui/milestones-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("milestones-view.mjs"),
        )),
        b"/ui/issues.mjs" => Some(("text/javascript; charset=utf-8", include_str!("issues.mjs"))),
        b"/ui/markdown.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("markdown.mjs"),
        )),
        b"/ui/browser.css" => Some(("text/css; charset=utf-8", include_str!("browser.css"))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        CredentialSource, GitDaemonSessionTimeout, NodeConfig, NodeLanes, Profile, PushQuota,
        RepositoryHttpService, RepositoryHttpServices, Status, WriterGate,
    };
    use super::super::{SECURITY, serve};
    use super::*;
    use fgit_crypto::sha256_digest;
    use fgit_types::{PrincipalId, RepositoryId, TenantId};
    use fgit_wire::smart_http::{HttpLimits, head};
    use std::sync::Arc;

    fn profile(source: bool, issues: bool, pulls: bool) -> Profile {
        let config = NodeConfig::new(
            "unused-milestone-shell".into(),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        );
        Profile {
            config: config.clone(),
            route: b"/repo.git".to_vec(),
            credentials: CredentialSource::Static {
                digest: sha256_digest(&[b'a'; 64]),
                principal: PrincipalId::from_bytes([3; 16]),
            },
            services: RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Source, source)
                .with(RepositoryHttpService::Issues, issues)
                .with(RepositoryHttpService::Pulls, pulls),
            #[cfg(unix)]
            lfs: None,
            http: HttpLimits::default(),
            maximum_response_bytes: u64::MAX,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()),
            outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()),
            writers: Arc::new(WriterGate::new(1)),
            nodes: Arc::new(NodeLanes::new(config, 1, "milestone shell test")),
        }
    }

    fn get(profile: &Profile, target: &str, version: &str) -> Result<Vec<u8>, Status> {
        let bytes = format!("GET {target} {version}\r\nHost: local\r\nContent-Length: 0\r\n\r\n");
        let request = head::parse(bytes.as_bytes(), HttpLimits::default())
            .unwrap()
            .unwrap();
        let mut wire = Vec::new();
        assert!(serve(profile, &request, &[], &mut wire)?);
        Ok(wire)
    }

    #[test]
    fn milestone_shell_and_entire_module_graph_serve_with_issues_only() {
        let profile = profile(false, true, false);
        for suffix in [
            "/ui/milestones/",
            "/ui/milestones.mjs",
            "/ui/milestones-view.mjs",
            "/ui/issues.mjs",
            "/ui/markdown.mjs",
            "/ui/browser.css",
        ] {
            let target = format!("/repo.git{suffix}");
            let (media, body) = asset(b"/repo.git", &target).unwrap();
            assert!(!body.is_empty());
            for version in ["HTTP/1.0", "HTTP/1.1"] {
                let wire = get(&profile, &target, version).unwrap();
                let wire = std::str::from_utf8(&wire).unwrap();
                let (headers, served) = wire.split_once("\r\n\r\n").unwrap();
                assert!(headers.starts_with(&format!("{version} 200 OK\r\n")));
                assert!(headers.contains(&format!("Content-Type: {media}\r\n")));
                assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
                assert!(headers.contains(SECURITY));
                assert!(headers.contains("Cache-Control: no-store\r\n"));
                assert!(headers.contains("script-src 'self'"));
                assert!(headers.contains("frame-ancestors 'none'"));
                assert!(!headers.contains("unsafe-inline"));
                assert_eq!(served, body);
            }
        }
    }

    #[test]
    fn milestone_assets_require_issues_even_with_source_or_pulls_enabled() {
        for source in [false, true] {
            for issues in [false, true] {
                for pulls in [false, true] {
                    let mut profile = profile(source, issues, pulls);
                    for suffix in [
                        "/ui/milestones/",
                        "/ui/milestones.mjs",
                        "/ui/milestones-view.mjs",
                    ] {
                        let target = format!("/repo.git{suffix}");
                        let (_, body) = asset(b"/repo.git", &target).unwrap();
                        profile.maximum_response_bytes = body.len() as u64;
                        let result = get(&profile, &target, "HTTP/1.1");
                        if issues {
                            assert!(result.is_ok());
                            profile.maximum_response_bytes -= 1;
                            assert_eq!(get(&profile, &target, "HTTP/1.1"), Err(Status::TooLarge));
                        } else {
                            assert_eq!(result, Err(Status::NotFound));
                        }
                    }
                }
            }
        }
        // Sharing the flat stylesheet does not enable the milestone profile.
        assert!(
            get(
                &profile(true, false, false),
                "/repo.git/ui/browser.css",
                "HTTP/1.1"
            )
            .is_ok()
        );
        assert!(
            get(
                &profile(false, false, true),
                "/repo.git/ui/markdown.mjs",
                "HTTP/1.1"
            )
            .is_ok()
        );
    }

    #[test]
    fn milestone_assets_never_match_route_prefixes_or_native_api_requests() {
        let profile = profile(true, true, true);
        for target in [
            "/other.git/ui/milestones/",
            "/repo.git-more/ui/milestones/",
            "/repo.git/ui/milestones",
            "/repo.git/ui/milestones.html",
            "/repo.git/ui/milestones/../private",
            "/repo.git/ui/milestones/%2e%2e",
            "/repo.git/ui/%6dilestones/",
            "/repo.git/ui/milestones/unknown.mjs",
            "/repo.git/ui/milestones.mjs/extra",
            "/repo.git/api/v1/milestones",
            "/repo.git/api/v1/milestones/7/open",
        ] {
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let mut wire = Vec::new();
            assert_eq!(
                serve(&profile, &request, &[], &mut wire),
                Ok(false),
                "{target}"
            );
            assert!(wire.is_empty());
        }
    }

    #[test]
    fn milestone_shell_refuses_mutation_methods_queries_and_body_smuggling() {
        let profile = profile(false, true, false);
        for (method, query, headers, trailing, expected) in [
            ("POST", "", "", false, Status::Method),
            ("HEAD", "", "", false, Status::Method),
            ("GET", "?token=secret", "", false, Status::BadRequest),
            (
                "GET",
                "",
                "Content-Length: 1\r\n",
                false,
                Status::BadRequest,
            ),
            (
                "GET",
                "",
                "Transfer-Encoding: chunked\r\n",
                false,
                Status::BadRequest,
            ),
            (
                "GET",
                "",
                "Expect: 100-continue\r\n",
                false,
                Status::BadRequest,
            ),
            (
                "GET",
                "",
                "Git-Protocol: version=2\r\n",
                false,
                Status::BadRequest,
            ),
            ("GET", "", "", true, Status::BadRequest),
        ] {
            let bytes = format!(
                "{method} /repo.git/ui/milestones/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let mut wire = Vec::new();
            let trailing = if trailing {
                b"x".as_slice()
            } else {
                b"".as_slice()
            };
            assert_eq!(
                serve(&profile, &request, trailing, &mut wire),
                Err(expected)
            );
            assert!(wire.is_empty());
        }
        let page = include_str!("milestones.html");
        assert!(page.contains("src=\"../milestones-view.mjs\""));
        assert!(page.contains("href=\"../browser.css\""));
        assert!(!page.contains("<script>"));
    }
}
