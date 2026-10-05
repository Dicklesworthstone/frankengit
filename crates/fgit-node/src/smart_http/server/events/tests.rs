use super::*;
use super::super::credentials::{Binding, CredentialSource};
use crate::node_lanes::NodeLanes;
use crate::{GitDaemonSessionTimeout, NodeConfig, PushQuota, WriterGate, MAX_CONCURRENT_WRITERS};
use fgit_crypto::sha256_digest;
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::smart_http::{HttpLimits, head};
use std::{fs, path::PathBuf, sync::{Arc, atomic::{AtomicU64, Ordering}}};

fn raw(method: &str, target: &str, headers: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: local\r\n{headers}\r\n").into_bytes()
}
#[test]
fn strict_get_route_query_and_exact_cursor_have_permitted_twins() {
    for target in ["/repo.git/api/v1/events", "/repo.git/api/v1/events?after=0", "/repo.git/api/v1/events?after=1%3A0&limit=1"] {
        assert!(is_route(target));
        let bytes = raw("GET", target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        let query = Request::parse(&envelope).unwrap();
        assert_eq!(query.repository_route, "/repo.git");
    }
    let bytes = raw("GET", "/repo.git/api/v1/events?after=18446744073709551615:4294967295&limit=100", "");
    let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    assert_eq!(query.after, Some((u64::MAX, u32::MAX)));
    assert_eq!(query.limit, 100);
    assert!(query.expected_head.is_none());
    for target in ["/repo.git/api/v1/events/1", "/repo.git/api/v1/events-evil",
        "/repo.git/api/v1/events?after=1:00", "/repo.git/api/v1/events?after=0:0",
        "/repo.git/api/v1/events?after=1:4294967296", "/repo.git/api/v1/events?limit=0",
        "/repo.git/api/v1/events?limit=101", "/repo.git/api/v1/events?limit=01",
        "/repo.git/api/v1/events?limit=1&limit=2", "/repo.git/api/v1/events?limit=1&%6cimit=2",
        "/repo.git/api/v1/events?principal=admin", "/repo.git/api/v1/events?issues_read=true",
        "/repo.git/api/v1/events?expected_head=garbage", "/repo.git/api/v1/events?after=%ff"]
    {
        let bytes = raw("GET", target, "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&envelope).is_err(), "{target}");
    }
    assert!(!is_route("/repo.git/api/v1/issues?query=/api/v1/events"));
    let oversized = format!("/repo.git/api/v1/events?{}", "a".repeat(MAX_QUERY_BYTES + 1));
    let bytes = raw("GET", &oversized, "");
    let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
    assert!(Request::parse(&envelope).is_err());
}

#[test]
fn body_expectations_protocol_and_non_get_methods_refuse_without_reading_a_body() {
    for (method, headers) in [("POST", ""), ("HEAD", ""), ("PUT", ""),
        ("GET", "Content-Length: 1\r\n"), ("GET", "Transfer-Encoding: chunked\r\n"),
        ("GET", "Expect: 100-continue\r\n"), ("GET", "Git-Protocol: version=2\r\n")]
    {
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
        let path = std::env::temp_dir().join(format!("fg-event-http-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xc1; 16]), RepositoryId::from_bytes([0xc2; 16]))
            .with_object_format(format).with_worker_threads(2)
    }
    fn profile(&self, config: NodeConfig, incarnation: RepositoryIncarnationId, scopes: &str) -> Profile {
        let binding = Binding {
            tenant: TenantId::from_bytes([0xc1; 16]), repository: RepositoryId::from_bytes([0xc2; 16]), incarnation,
        };
        let path = self.0.join("credentials");
        self.credentials(binding, scopes);
        Profile {
            config: config.clone(), route: b"/repo.git".to_vec(),
            credentials: CredentialSource::File { path, binding },
            allow_receive: false, allow_issues: true, allow_outcomes: false, allow_pulls: true, allow_source: false,
            http: HttpLimits::default(), maximum_response_bytes: 2 * 1024 * 1024,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()), outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()), writers: Arc::new(WriterGate::new(MAX_CONCURRENT_WRITERS)),
            nodes: Arc::new(NodeLanes::new(config, 1, "event HTTP test")),
        }
    }
    fn credentials(&self, binding: Binding, scopes: &str) {
        let digest: String = sha256_digest(&[b'a'; 64]).iter().map(|b| format!("{b:02x}")).collect();
        let header = format!("frankengit-http-credentials-v1 {} {} {}\n", binding.tenant, binding.repository, binding.incarnation);
        let body = if scopes.is_empty() { header } else {
            format!("{header}{digest} {} {scopes}\n", PrincipalId::from_bytes([0xc3; 16]))
        };
        let temporary = self.0.join("credentials.next");
        fs::write(&temporary, body).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::rename(temporary, self.0.join("credentials")).unwrap();
    }
}
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn bearer() -> String { format!("Authorization: Bearer {}\r\n", "a".repeat(64)) }

#[test]
fn credentials_and_endpoint_ceilings_cannot_be_widened_by_other_grants_or_request_fields() {
    let scratch = Scratch::new();
    let incarnation = RepositoryIncarnationId::from_bytes([0xc4; 16]);
    let binding = Binding { tenant: TenantId::from_bytes([0xc1; 16]), repository: RepositoryId::from_bytes([0xc2; 16]), incarnation };
    let mut profile = scratch.profile(scratch.config(GitHashAlgorithm::Sha1), incarnation, "issues-read,pulls-read");
    let bytes = raw("GET", "/repo.git/api/v1/events", &bearer());
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let query = Request::parse(&envelope).unwrap();
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(grant.issues && grant.pulls);
    profile.allow_issues = false;
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(!grant.issues && grant.pulls);
    profile.allow_pulls = false;
    assert_eq!(authenticate(&profile, &envelope, &query).unwrap_err().status, Status::Forbidden);
    profile.allow_issues = true;
    profile.allow_pulls = true;
    for scopes in ["read,receive", "issues-write,pulls-write", "reviews-read,reviews-write,merges-write", "outcomes-read"] {
        scratch.credentials(binding, scopes);
        assert_eq!(authenticate(&profile, &envelope, &query).unwrap_err().status, Status::Forbidden, "{scopes}");
    }
    scratch.credentials(binding, "issues-read");
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(grant.issues && !grant.pulls);
    scratch.credentials(binding, "pulls-read");
    let grant = authenticate(&profile, &envelope, &query).unwrap();
    assert!(!grant.issues && grant.pulls);
    scratch.credentials(binding, "");
    assert_eq!(authenticate(&profile, &envelope, &query).unwrap_err().status, Status::Unauthorized);
    scratch.credentials(binding, "issues-read");
    assert!(authenticate(&profile, &envelope, &query).is_ok());
    profile.route = b"/other.git".to_vec();
    assert_eq!(authenticate(&profile, &envelope, &query).unwrap_err().status, Status::NotFound);
}

#[test]
fn refused_http_responses_are_typed_bearer_only_and_never_open_a_missing_repository() {
    let scratch = Scratch::new();
    let profile = scratch.profile(scratch.config(GitHashAlgorithm::Sha1), RepositoryIncarnationId::from_bytes([0xc4; 16]), "issues-read");
    for headers in ["".to_owned(), "X-Forwarded-User: admin\r\n".to_owned(),
        "Authorization: Basic Z2l0OmFhYQ==\r\n".to_owned(),
        format!("Authorization: Bearer {}\r\n", "b".repeat(64))]
    {
        let bytes = raw("GET", "/repo.git/api/v1/events", &headers);
        let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
        let mut output = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut output), Err(Status::Unauthorized));
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
    assert_eq!(prepare(&profile, &envelope, b"smuggled").err().unwrap().status, Status::BadRequest);
    assert!(!scratch.0.join("node").exists());
}

#[test]
fn real_node_http_reads_exact_frames_and_closes_failed_output_before_retry() {
    use fgit_authority::IdempotencyKey;
    use fgit_forge::{ExpectedVersion, IssueNumber, event::issue::{IssueAction, IssueCommand}};
    use crate::LoopbackReceiveSession;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        let request = node.request_context();
        let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0xc3; 16]), IdempotencyKey::new(b"http-event-seed".to_vec()).unwrap());
        let command = IssueCommand { number: IssueNumber::try_new(1).unwrap(), expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open { title: "fixture".into(), body: "Exact event body".into(), labels: vec![] } };
        let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default())).unwrap();
        assert!(matches!(terminal.outcome, fgit_types::DecisionOutcome::Committed { .. }));
        let page = node.runtime().block_on(node.read_scoped_forge_events_in(&request, None, 20, None, true, false)).unwrap();
        assert_eq!(page.events().len(), 1, "the successful twin must expose a real canonical event");
        let expected = page.to_json().unwrap();
        node.shutdown().unwrap();
        let mut profile = scratch.profile(config, incarnation, "issues-read");
        let bytes = raw("GET", "/repo.git/api/v1/events", &bearer());
        let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
        let mut response = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut response), Ok(()));
        let response = String::from_utf8(response).unwrap();
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, expected);
        struct LostOutput(usize);
        impl Write for LostOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> { self.0 += 1; Err(io::Error::from(io::ErrorKind::BrokenPipe)) }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let mut lost = LostOutput(0);
        assert_eq!(serve(&profile, &envelope, &[], &mut lost), Err(Status::Unavailable));
        assert_eq!(lost.0, 1, "no second HTTP error response after a failed success write");
        let mut retried = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut retried), Ok(()));
        assert_eq!(String::from_utf8(retried).unwrap(), response);
        profile.maximum_response_bytes = 1;
        let mut refused = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut refused), Err(Status::TooLarge));
        assert!(!String::from_utf8(refused).unwrap().contains("Exact event body"));
        profile.maximum_response_bytes = 2 * 1024 * 1024;
        let mut twin = Vec::new();
        assert_eq!(serve(&profile, &envelope, &[], &mut twin), Ok(()));
        assert_eq!(String::from_utf8(twin).unwrap(), response);
        profile.nodes.close().unwrap();
    }
}

#[test]
fn status_mapping_and_headers_preserve_read_only_refusal_semantics() {
    for (code, status) in [("invalid_event_cursor", Status::BadRequest), ("snapshot_moved", Status::Conflict),
        ("events_not_granted", Status::Forbidden), ("event_response_limit", Status::TooLarge),
        ("event_read_cancelled", Status::Timeout), ("internal-storage-path", Status::Unavailable)]
    {
        let error = read_error(code);
        assert_eq!(error.status, status);
        assert_ne!(error.code, "internal-storage-path");
    }
    for (version, prefix) in [(HttpVersion::Http10, "HTTP/1.0"), (HttpVersion::Http11, "HTTP/1.1")] {
        for status in [Status::Success, Status::Method, Status::RateLimited] {
            let mut out = Vec::new();
            send(&mut out, version, status, "{}").unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.starts_with(prefix));
            assert!(out.contains("Content-Length: 2\r\n"));
            assert!(out.contains("Vary: Authorization\r\n"));
            assert!(out.contains("Cache-Control: no-store\r\n"));
            assert_eq!(out.contains("Allow: GET\r\n"), status == Status::Method);
            assert_eq!(out.contains("Retry-After: 60\r\n"), status == Status::RateLimited);
        }
    }
}
