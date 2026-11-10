use super::super::credentials::{Binding, CredentialSource};
use super::super::{RepositoryHttpService, RepositoryHttpServices};
use super::*;
use crate::node_lanes::NodeLanes;
use crate::{GitDaemonSessionTimeout, MAX_CONCURRENT_WRITERS, NodeConfig, PushQuota, WriterGate};
use fgit_crypto::sha256_digest;
use fgit_types::{
    GitHashAlgorithm, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId,
};
use fgit_wire::smart_http::{HttpLimits, head};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

fn raw(method: &str, target: &str, headers: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: local\r\n{headers}\r\n").into_bytes()
}
#[test]
fn strict_get_route_query_and_exact_cursor_have_permitted_twins() {
    for target in [
        "/repo.git/api/v1/events",
        "/repo.git/api/v1/events?after=0",
        "/repo.git/api/v1/events?after=1%3A0&limit=1",
        "/repo.git/api/v1/events?profile=issues-pulls-v1",
        "/repo.git/api/v1/events?profile=collaboration-v2&after=0&limit=100",
    ] {
        assert!(is_route(target));
        let bytes = raw("GET", target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        let query = Request::parse(&envelope).unwrap();
        assert_eq!(query.repository_route, "/repo.git");
    }
    let bytes = raw(
        "GET",
        "/repo.git/api/v1/events?after=18446744073709551615:4294967295&limit=100",
        "",
    );
    let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    assert_eq!(query.after, Some((u64::MAX, u32::MAX)));
    assert_eq!(query.limit, 100);
    assert!(query.expected_head.is_none());
    assert_eq!(
        query.disclosure_profile,
        ForgeEventDisclosureProfile::IssuesPullsV1
    );
    for target in [
        "/repo.git/api/v1/events/1",
        "/repo.git/api/v1/events-evil",
        "/repo.git/api/v1/events?after=1:00",
        "/repo.git/api/v1/events?after=0:0",
        "/repo.git/api/v1/events?after=1:4294967296",
        "/repo.git/api/v1/events?limit=0",
        "/repo.git/api/v1/events?limit=101",
        "/repo.git/api/v1/events?limit=01",
        "/repo.git/api/v1/events?limit=1&limit=2",
        "/repo.git/api/v1/events?limit=1&%6cimit=2",
        "/repo.git/api/v1/events?principal=admin",
        "/repo.git/api/v1/events?issues_read=true",
        "/repo.git/api/v1/events?expected_head=garbage",
        "/repo.git/api/v1/events?after=%ff",
        "/repo.git/api/v1/events?profile=collaboration-v3",
        "/repo.git/api/v1/events?profile=COLLABORATION-v2",
        "/repo.git/api/v1/events?profile=",
        "/repo.git/api/v1/events?profile=issues-pulls-v1&%70rofile=collaboration-v2",
        "/repo.git/api/v1/events?profile=collaboration-v2&reviews_read=true",
        "/repo.git/api/v1/events?profile=collaboration-v2&discussions_read=true",
    ] {
        let bytes = raw("GET", target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&envelope).is_err(), "{target}");
    }
    assert!(!is_route("/repo.git/api/v1/issues?query=/api/v1/events"));
    let oversized = format!(
        "/repo.git/api/v1/events?{}",
        "a".repeat(MAX_QUERY_BYTES + 1)
    );
    let bytes = raw("GET", &oversized, "");
    let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    assert!(Request::parse(&envelope).is_err());
}

#[test]
fn body_expectations_protocol_and_non_get_methods_refuse_without_reading_a_body() {
    for (method, headers) in [
        ("POST", ""),
        ("HEAD", ""),
        ("PUT", ""),
        ("GET", "Content-Length: 1\r\n"),
        ("GET", "Transfer-Encoding: chunked\r\n"),
        ("GET", "Expect: 100-continue\r\n"),
        ("GET", "Git-Protocol: version=2\r\n"),
    ] {
        let bytes = raw(method, "/repo.git/api/v1/events", headers);
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&envelope).is_err(), "{method} {headers}");
    }
    let bytes = raw("GET", "/repo.git/api/v1/events", "Content-Length: 0\r\n");
    let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    assert!(Request::parse(&envelope).is_ok());
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-event-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
    fn profile(
        &self,
        config: NodeConfig,
        incarnation: RepositoryIncarnationId,
        scopes: &str,
    ) -> Profile {
        let binding = Binding {
            tenant: TenantId::from_bytes([0xc1; 16]),
            repository: RepositoryId::from_bytes([0xc2; 16]),
            incarnation,
        };
        let path = self.0.join("credentials");
        self.credentials(binding, scopes);
        Profile {
            config: config.clone(),
            route: b"/repo.git".to_vec(),
            credentials: CredentialSource::File { path, binding },
            services: RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Receive, false)
                .with(RepositoryHttpService::Issues, true)
                .with(RepositoryHttpService::Outcomes, false)
                .with(RepositoryHttpService::Pulls, true)
                .with(RepositoryHttpService::Source, false),
            #[cfg(target_os = "linux")]
            lfs: None,
            http: HttpLimits::default(),
            maximum_response_bytes: 2 * 1024 * 1024,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()),
            outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()),
            writers: Arc::new(WriterGate::new(MAX_CONCURRENT_WRITERS)),
            nodes: Arc::new(NodeLanes::new(config, 1, "event HTTP test")),
        }
    }
    fn credentials(&self, binding: Binding, scopes: &str) {
        let digest: String = sha256_digest(&[b'a'; 64])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let header = format!(
            "frankengit-http-credentials-v1 {} {} {}\n",
            binding.tenant, binding.repository, binding.incarnation
        );
        let body = if scopes.is_empty() {
            header
        } else {
            format!(
                "{header}{digest} {} {scopes}\n",
                PrincipalId::from_bytes([0xc3; 16])
            )
        };
        let temporary = self.0.join("credentials.next");
        fs::write(&temporary, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::rename(temporary, self.0.join("credentials")).unwrap();
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn bearer() -> String {
    format!("Authorization: Bearer {}\r\n", "a".repeat(64))
}

#[test]
fn credentials_and_endpoint_ceilings_cannot_be_widened_by_other_grants_or_request_fields() {
    let scratch = Scratch::new();
    let incarnation = RepositoryIncarnationId::from_bytes([0xc4; 16]);
    let binding = Binding {
        tenant: TenantId::from_bytes([0xc1; 16]),
        repository: RepositoryId::from_bytes([0xc2; 16]),
        incarnation,
    };
    let mut profile = scratch.profile(
        scratch.config(GitHashAlgorithm::Sha1),
        incarnation,
        "issues-read,pulls-read",
    );
    let bytes = raw("GET", "/repo.git/api/v1/events", &bearer());
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(grant.issues && grant.pulls);
    profile.services = profile.services.with(RepositoryHttpService::Issues, false);
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(!grant.issues && grant.pulls);
    profile.services = profile.services.with(RepositoryHttpService::Pulls, false);
    assert_eq!(
        authenticate(&profile, &envelope, &query)
            .unwrap_err()
            .status,
        Status::Forbidden
    );
    profile.services = profile.services.with(RepositoryHttpService::Issues, true);
    profile.services = profile.services.with(RepositoryHttpService::Pulls, true);
    for scopes in [
        "read,receive",
        "issues-write,pulls-write",
        "reviews-read,reviews-write,merges-write",
        "outcomes-read",
    ] {
        scratch.credentials(binding, scopes);
        assert_eq!(
            authenticate(&profile, &envelope, &query)
                .unwrap_err()
                .status,
            Status::Forbidden,
            "{scopes}"
        );
    }
    scratch.credentials(binding, "issues-read");
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(grant.issues && !grant.pulls);
    scratch.credentials(binding, "pulls-read");
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(!grant.issues && grant.pulls);
    scratch.credentials(binding, "");
    assert_eq!(
        authenticate(&profile, &envelope, &query)
            .unwrap_err()
            .status,
        Status::Unauthorized
    );
    scratch.credentials(binding, "issues-read");
    assert!(authenticate(&profile, &envelope, &query).is_ok());
    profile.route = b"/other.git".to_vec();
    assert_eq!(
        authenticate(&profile, &envelope, &query)
            .unwrap_err()
            .status,
        Status::NotFound
    );
}

#[test]
fn collaboration_profile_intersects_each_read_scope_with_its_endpoint_ceiling() {
    let scratch = Scratch::new();
    let incarnation = RepositoryIncarnationId::from_bytes([0xc4; 16]);
    let binding = Binding {
        tenant: TenantId::from_bytes([0xc1; 16]),
        repository: RepositoryId::from_bytes([0xc2; 16]),
        incarnation,
    };
    let mut profile = scratch.profile(scratch.config(GitHashAlgorithm::Sha1), incarnation, "read");
    let bytes = raw(
        "GET",
        "/repo.git/api/v1/events?profile=collaboration-v2",
        &bearer(),
    );
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    let legacy_bytes = raw(
        "GET",
        "/repo.git/api/v1/events?profile=issues-pulls-v1",
        &bearer(),
    );
    let legacy_envelope = head::parse(&legacy_bytes, profile.http).unwrap().unwrap();
    let legacy = Request::parse(&legacy_envelope).unwrap();
    for permissions in 0_u8..16 {
        let mut scopes = vec![
            "read",
            "issues-write",
            "pulls-write",
            "discussions-write",
            "reviews-write",
        ];
        for (bit, scope) in [
            "issues-read",
            "pulls-read",
            "discussions-read",
            "reviews-read",
        ]
        .into_iter()
        .enumerate()
        {
            if permissions & (1 << bit) != 0 {
                scopes.push(scope);
            }
        }
        scratch.credentials(binding, &scopes.join(","));
        for ceilings in 0_u8..8 {
            profile.services = RepositoryHttpServices::NONE
                .with(RepositoryHttpService::Issues, ceilings & 1 != 0)
                .with(RepositoryHttpService::Pulls, ceilings & 2 != 0);
            profile.config = if ceilings & 4 != 0 {
                scratch
                    .config(GitHashAlgorithm::Sha1)
                    .with_http_discussions()
            } else {
                scratch.config(GitHashAlgorithm::Sha1)
            };
            let expected = (
                permissions & 1 != 0 && ceilings & 1 != 0,
                permissions & 2 != 0 && ceilings & 2 != 0,
                permissions & 4 != 0 && ceilings & 4 != 0,
                permissions & 8 != 0 && ceilings & 2 != 0,
            );
            let actual = authenticate(&profile, &envelope, &query);
            if expected.0 || expected.1 || expected.2 || expected.3 {
                let grant = actual.unwrap();
                assert_eq!(
                    (grant.issues, grant.pulls, grant.discussions, grant.reviews),
                    expected
                );
            } else {
                assert_eq!(actual.unwrap_err().status, Status::Forbidden);
            }
            let actual = authenticate(&profile, &legacy_envelope, &legacy);
            if expected.0 || expected.1 {
                let grant = actual.unwrap();
                assert_eq!(
                    (grant.issues, grant.pulls, grant.discussions, grant.reviews),
                    (expected.0, expected.1, false, false)
                );
            } else {
                assert_eq!(actual.unwrap_err().status, Status::Forbidden);
            }
        }
    }
    assert!(!scratch.0.join("node").exists());
}

#[test]
fn refused_http_responses_are_typed_bearer_only_and_never_open_a_missing_repository() {
    let scratch = Scratch::new();
    let profile = scratch.profile(
        scratch.config(GitHashAlgorithm::Sha1),
        RepositoryIncarnationId::from_bytes([0xc4; 16]),
        "issues-read",
    );
    for headers in [
        String::new(),
        "X-Forwarded-User: admin\r\n".to_owned(),
        "Authorization: Basic Z2l0OmFhYQ==\r\n".to_owned(),
        format!("Authorization: Bearer {}\r\n", "b".repeat(64)),
    ] {
        let bytes = raw("GET", "/repo.git/api/v1/events", &headers);
        let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
        let mut output = Vec::new();
        assert_eq!(
            serve(&profile, &envelope, &[], &mut output),
            Err(Status::Unauthorized)
        );
        let response = String::from_utf8(output).unwrap();
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 401"));
        assert!(head.contains("WWW-Authenticate: Bearer"));
        assert!(!head.contains("WWW-Authenticate: Basic"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(body.contains("\"type\":\"event_error\""));
        assert!(body.contains("\"read_only\":true"));
        assert!(!body.contains("admin"));
    }
    let bytes = raw("GET", "/repo.git/api/v1/events", &bearer());
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    assert!(authenticate(&profile, &envelope, &Request::parse(&envelope).unwrap()).is_ok());
    assert_eq!(
        prepare(&profile, &envelope, b"smuggled")
            .err()
            .unwrap()
            .status,
        Status::BadRequest
    );
    assert!(!scratch.0.join("node").exists());
}

#[test]
fn real_node_http_reads_exact_frames_and_closes_failed_output_before_retry() {
    use crate::LoopbackReceiveSession;
    use fgit_authority::IdempotencyKey;
    use fgit_forge::{
        ExpectedVersion, IssueNumber,
        event::issue::{IssueAction, IssueCommand},
    };
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(
            PrincipalId::from_bytes([0xc3; 16]),
            IdempotencyKey::new(b"http-event-seed".to_vec()).unwrap(),
        );
        let command = IssueCommand {
            number: IssueNumber::try_new(1).unwrap(),
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "fixture".into(),
                body: "Exact event body".into(),
                labels: vec![],
            },
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default()))
            .unwrap();
        assert!(matches!(
            terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let page = node
            .runtime()
            .block_on(node.read_scoped_forge_events_in(&request, None, 20, None, true, false))
            .unwrap();
        assert_eq!(
            page.events().len(),
            1,
            "the successful twin must expose a real canonical event"
        );
        let expected = page.to_json().unwrap();
        node.shutdown().unwrap();
        let mut profile = scratch.profile(config, incarnation, "issues-read");
        let bytes = raw("GET", "/repo.git/api/v1/events", &bearer());
        let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
        let mut response = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut response), Ok(()));
        let response = String::from_utf8(response).unwrap();
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, expected);
        // Endpoint deployment switches are independent ceilings. Exercise the
        // real credential reader and canonical event response for every profile,
        // including profiles that expose unrelated Git/recovery/source services.
        for switches in 0_u8..32 {
            let mut selected = profile.clone();
            selected.services = selected
                .services
                .with(RepositoryHttpService::Receive, switches & 1 != 0);
            selected.services = selected
                .services
                .with(RepositoryHttpService::Issues, switches & 2 != 0);
            selected.services = selected
                .services
                .with(RepositoryHttpService::Outcomes, switches & 4 != 0);
            selected.services = selected
                .services
                .with(RepositoryHttpService::Pulls, switches & 8 != 0);
            selected.services = selected
                .services
                .with(RepositoryHttpService::Source, switches & 16 != 0);
            let mut selected_response = Vec::new();
            let outcome = serve(&selected, &envelope, &[], &mut selected_response);
            let selected_response = String::from_utf8(selected_response).unwrap();
            if switches & 2 != 0 {
                assert_eq!(outcome, Ok(()), "profile {switches}");
                assert_eq!(
                    selected_response.split_once("\r\n\r\n").unwrap().1,
                    expected,
                    "profile {switches}"
                );
            } else {
                assert_eq!(outcome, Err(Status::Forbidden), "profile {switches}");
                assert!(
                    !selected_response.contains("Exact event body"),
                    "profile {switches} disclosed a disabled issue event"
                );
            }
        }
        struct LostOutput(usize);
        impl Write for LostOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut lost = LostOutput(0);
        assert_eq!(
            serve(&profile, &envelope, &[], &mut lost),
            Err(Status::Unavailable)
        );
        assert_eq!(
            lost.0, 1,
            "no second HTTP error response after a failed success write"
        );
        let mut retried = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut retried), Ok(()));
        assert_eq!(String::from_utf8(retried).unwrap(), response);
        profile.maximum_response_bytes = 1;
        let mut refused = Vec::new();
        assert_eq!(
            serve(&profile, &envelope, &[], &mut refused),
            Err(Status::TooLarge)
        );
        assert!(
            !String::from_utf8(refused)
                .unwrap()
                .contains("Exact event body")
        );
        profile.maximum_response_bytes = 2 * 1024 * 1024;
        let mut twin = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut twin), Ok(()));
        assert_eq!(String::from_utf8(twin).unwrap(), response);
        profile.nodes.close().unwrap();
    }
}

#[test]
fn persisted_collaboration_http_feed_keeps_legacy_bytes_and_rotates_family_grants() {
    use crate::LoopbackReceiveSession;
    use fgit_authority::IdempotencyKey;
    use fgit_forge::event::discussion::{DiscussionAction, DiscussionCommand};
    use fgit_forge::event::milestone::{MilestoneAction, MilestoneCommand};
    use fgit_forge::{DiscussionNumber, ExpectedVersion, MilestoneNumber};

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format).with_http_discussions();
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        let request = node.request_context();
        let session = |key: &[u8]| {
            LoopbackReceiveSession::authenticated(
                PrincipalId::from_bytes([0xc3; 16]),
                IdempotencyKey::new(key.to_vec()).unwrap(),
            )
        };
        let (_, milestone) = node
            .runtime()
            .block_on(node.admit_milestone_durable_in(
                &request,
                &session(b"event-milestone"),
                &MilestoneCommand {
                    number: MilestoneNumber::try_new(1).unwrap(),
                    expected_version: ExpectedVersion::NewStream,
                    action: MilestoneAction::Open {
                        title: "Release".into(),
                        body: "Milestone event".into(),
                        due_at: None,
                    },
                },
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            milestone.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let (_, discussion) = node
            .runtime()
            .block_on(node.admit_discussion_durable_in(
                &request,
                &session(b"event-discussion"),
                &DiscussionCommand {
                    number: DiscussionNumber::try_new(1).unwrap(),
                    expected_version: ExpectedVersion::NewStream,
                    action: DiscussionAction::Open {
                        title: "Design".into(),
                        body: "Discussion event".into(),
                    },
                },
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            discussion.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        let legacy = node
            .runtime()
            .block_on(node.read_scoped_forge_events_in(&request, None, 20, None, true, false))
            .unwrap()
            .to_json()
            .unwrap();
        let page = node
            .runtime()
            .block_on(node.read_profiled_forge_events_in(
                &request,
                None,
                20,
                None,
                ForgeEventDisclosureProfile::CollaborationV2,
                ForgeEventReadGrants {
                    issues: true,
                    discussions: true,
                    ..Default::default()
                },
            ))
            .unwrap();
        assert_eq!(page.events().len(), 2);
        let expected = page.to_json().unwrap();
        let discussion_only = node
            .runtime()
            .block_on(node.read_profiled_forge_events_in(
                &request,
                None,
                20,
                None,
                ForgeEventDisclosureProfile::CollaborationV2,
                ForgeEventReadGrants {
                    discussions: true,
                    ..Default::default()
                },
            ))
            .unwrap();
        assert_eq!(discussion_only.events().len(), 1);
        let discussion_only = discussion_only.to_json().unwrap();
        node.shutdown().unwrap();

        let profile = scratch.profile(config, incarnation, "issues-read,discussions-read");
        let read = |target: &str| {
            let bytes = raw("GET", target, &bearer());
            let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
            let mut response = Vec::new();
            let outcome = serve(&profile, &envelope, &[], &mut response);
            let body = String::from_utf8(response)
                .unwrap()
                .split_once("\r\n\r\n")
                .unwrap()
                .1
                .to_owned();
            (outcome, body)
        };
        assert_eq!(read("/repo.git/api/v1/events"), (Ok(()), legacy.clone()));
        assert_eq!(
            read("/repo.git/api/v1/events?profile=issues-pulls-v1"),
            (Ok(()), legacy)
        );
        assert_eq!(
            read("/repo.git/api/v1/events?profile=collaboration-v2"),
            (Ok(()), expected)
        );
        let binding = Binding {
            tenant: TenantId::from_bytes([0xc1; 16]),
            repository: RepositoryId::from_bytes([0xc2; 16]),
            incarnation,
        };
        scratch.credentials(binding, "discussions-read");
        assert_eq!(
            read("/repo.git/api/v1/events?profile=collaboration-v2"),
            (Ok(()), discussion_only)
        );
        assert_eq!(read("/repo.git/api/v1/events").0, Err(Status::Forbidden));
        scratch.credentials(binding, "discussions-write,reviews-write,issues-write");
        assert_eq!(
            read("/repo.git/api/v1/events?profile=collaboration-v2").0,
            Err(Status::Forbidden)
        );
        profile.nodes.close().unwrap();
    }
}

#[test]
fn status_mapping_and_headers_preserve_read_only_refusal_semantics() {
    for (code, status) in [
        ("invalid_event_cursor", Status::BadRequest),
        ("snapshot_moved", Status::Conflict),
        ("events_not_granted", Status::Forbidden),
        ("event_response_limit", Status::TooLarge),
        ("event_read_cancelled", Status::Timeout),
        ("internal-storage-path", Status::Unavailable),
    ] {
        let error = read_error(code);
        assert_eq!(error.status, status);
        assert_ne!(error.code, "internal-storage-path");
    }
    for (version, prefix) in [
        (HttpVersion::Http10, "HTTP/1.0"),
        (HttpVersion::Http11, "HTTP/1.1"),
    ] {
        for status in [Status::Success, Status::Method, Status::RateLimited] {
            let mut out = Vec::new();
            send(&mut out, version, status, "{}").unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.starts_with(prefix));
            assert!(out.contains("Content-Length: 2\r\n"));
            assert!(out.contains("Vary: Authorization\r\n"));
            assert!(out.contains("Cache-Control: no-store\r\n"));
            assert_eq!(out.contains("Allow: GET\r\n"), status == Status::Method);
            assert_eq!(
                out.contains("Retry-After: 60\r\n"),
                status == Status::RateLimited
            );
        }
    }
}
