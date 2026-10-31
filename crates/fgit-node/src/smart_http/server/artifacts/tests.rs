use super::super::RepositoryHttpServices;
use super::super::credentials::{Binding, CredentialSource};
use super::*;
use crate::node_lanes::NodeLanes;
use crate::{
    GitDaemonSessionTimeout, GitDaemonSessionWorkScaling, MAX_CONCURRENT_WRITERS, NodeConfig,
    PushQuota, WriterGate,
};
use fgit_crypto::sha256_digest;
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactScope, ArtifactStorageError, LocalArtifactStore,
};
use fgit_object_fabric::{ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    DigestAlgorithmId, DigestBytes, HeadGeneration, RepositoryId, RepositoryIncarnationId, TenantId,
};
use fgit_wire::smart_http::{HttpLimits, head};
use std::fmt::Write as _;
use std::{
    fs,
    io::Cursor,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
fn raw(method: &str, target: &str, headers: &str) -> Vec<u8> {
    format!("{method} {target} HTTP/1.1\r\nHost: local\r\n{headers}\r\n").into_bytes()
}
fn bearer() -> String {
    format!("Authorization: Bearer {}\r\n", "a".repeat(64))
}
fn deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    )
}
#[test]
fn only_exact_lowercase_artifact_selectors_and_bodyless_get_are_admitted() {
    for (suffix, content) in [("", false), ("/content", true)] {
        let target = format!("/repo.git/api/v1/artifacts/{ID}{suffix}");
        assert!(is_route(&target));
        let bytes = raw("GET", &target, "Content-Length: 0\r\n");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        let query = Request::parse(&envelope, &bytes, &[]).unwrap();
        assert_eq!(query.id_hex, ID);
        assert_eq!(query.repository_route, "/repo.git");
        assert_eq!(query.content, content);
        assert!(Request::parse(&envelope, &bytes, b"smuggled").is_err());
    }
    for suffix in [
        String::new(),
        format!("{ID}/"),
        format!("{ID}/content/"),
        format!("{ID}/content/other"),
        format!("{ID}?path=private"),
        format!("{ID}?trust=other"),
        ID.to_uppercase(),
        ID[..63].to_owned(),
        format!("%30{}", &ID[1..]),
        format!("../{ID}"),
    ] {
        let bytes = raw("GET", &format!("/repo.git/api/v1/artifacts/{suffix}"), "");
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(Request::parse(&envelope, &bytes, &[]).is_err(), "{suffix}");
    }
    assert!(!is_route("/repo.git/api/v1/issues?query=/api/v1/artifacts"));
    for (method, headers) in [
        ("POST", ""),
        ("HEAD", ""),
        ("PUT", ""),
        ("DELETE", ""),
        ("GET", "Content-Length: 1\r\n"),
        ("GET", "Transfer-Encoding: chunked\r\n"),
        ("GET", "Expect: 100-continue\r\n"),
        ("GET", "Git-Protocol: version=2\r\n"),
        ("GET", "Idempotency-Key: no-artifact-writes\r\n"),
    ] {
        let bytes = raw(method, &format!("/repo.git/api/v1/artifacts/{ID}"), headers);
        let envelope = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        assert!(
            Request::parse(&envelope, &bytes, &[]).is_err(),
            "{method} {headers}"
        );
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-artifact-http-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("artifacts")).unwrap();
        fs::set_permissions(root.join("artifacts"), fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn config(&self) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16]),
        )
        .with_worker_threads(2)
        .with_workflow_artifact_root(self.0.join("artifacts"))
    }
    fn binding(incarnation: RepositoryIncarnationId) -> Binding {
        Binding {
            tenant: TenantId::from_bytes([0xd1; 16]),
            repository: RepositoryId::from_bytes([0xd2; 16]),
            incarnation,
        }
    }
    fn credentials(&self, binding: Binding, scopes: &str) {
        let digest: String = sha256_digest(&[b'a'; 64])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut body = format!(
            "frankengit-http-credentials-v1 {} {} {}\n",
            binding.tenant, binding.repository, binding.incarnation
        );
        if !scopes.is_empty() {
            writeln!(
                body,
                "{digest} {} {scopes}",
                PrincipalId::from_bytes([0xd3; 16])
            )
            .expect("writing to a String cannot fail");
        }
        let temp = self.0.join("credentials.next");
        fs::write(&temp, body).unwrap();
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(temp, self.0.join("credentials")).unwrap();
    }
    fn profile(&self, incarnation: RepositoryIncarnationId, scopes: &str) -> Profile {
        let config = self.config();
        let binding = Self::binding(incarnation);
        self.credentials(binding, scopes);
        Profile {
            config: config.clone(),
            route: b"/repo.git".to_vec(),
            credentials: CredentialSource::File {
                path: self.0.join("credentials"),
                binding,
            },
            services: RepositoryHttpServices::NONE,
            lfs: None,
            http: HttpLimits::default(),
            maximum_response_bytes: 2 * 1024 * 1024,
            timeout: GitDaemonSessionTimeout::DEFAULT,
            quota: Arc::new(PushQuota::default()),
            outcome_quota: Arc::new(PushQuota::default()),
            source_quota: Arc::new(PushQuota::default()),
            writers: Arc::new(WriterGate::new(MAX_CONCURRENT_WRITERS)),
            nodes: Arc::new(NodeLanes::new(config, 1, "artifact HTTP test")),
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn independent_scope_profile_and_live_revocation_gate_all_reads_before_node_open() {
    let scratch = Scratch::new();
    let incarnation = RepositoryIncarnationId::from_bytes([0xd4; 16]);
    let binding = Scratch::binding(incarnation);
    let mut profile = scratch.profile(incarnation, "artifact-read");
    let bytes = raw(
        "GET",
        &format!("/repo.git/api/v1/artifacts/{ID}"),
        &bearer(),
    );
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let query = Request::parse(&envelope, &bytes, &[]).unwrap();
    assert_eq!(
        authenticate(&profile, &envelope, &query).unwrap(),
        PrincipalId::from_bytes([0xd3; 16])
    );
    for scopes in [
        "read,receive",
        "issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write",
        "protection-read,protection-write,lfs-read,lfs-write",
    ] {
        scratch.credentials(binding, scopes);
        let mut response = Vec::new();
        assert_eq!(
            serve(&profile, &envelope, &bytes, &[], &mut response, &deadline()),
            Err(Status::Forbidden)
        );
        let text = String::from_utf8(response).unwrap();
        assert!(text.contains("artifact_read_not_granted"));
        assert!(text.contains("\"outcome_unknown\":false"));
        assert!(!scratch.0.join("node").exists());
    }
    scratch.credentials(binding, "");
    assert_eq!(
        authenticate(&profile, &envelope, &query)
            .unwrap_err()
            .status,
        Status::Unauthorized
    );
    scratch.credentials(binding, "artifact-read");
    assert!(authenticate(&profile, &envelope, &query).is_ok());
    profile.config = NodeConfig::new(scratch.0.join("node"), binding.tenant, binding.repository);
    assert_eq!(
        authenticate(&profile, &envelope, &query)
            .unwrap_err()
            .status,
        Status::Forbidden
    );
    profile.config = scratch.config();
    profile.route = b"/other.git".to_vec();
    assert_eq!(
        authenticate(&profile, &envelope, &query)
            .unwrap_err()
            .status,
        Status::NotFound
    );
    assert!(!scratch.0.join("node").exists());
}

#[test]
fn bearer_only_authentication_and_read_quota_refuse_without_opening_a_node() {
    let scratch = Scratch::new();
    let profile = scratch.profile(
        RepositoryIncarnationId::from_bytes([0xd4; 16]),
        "artifact-read",
    );
    for headers in [
        String::new(),
        "X-Forwarded-User: admin\r\n".into(),
        "Authorization: Basic Z2l0OmFhYQ==\r\n".into(),
        format!("Authorization: Bearer {}\r\n", "b".repeat(64)),
    ] {
        let bytes = raw("GET", &format!("/repo.git/api/v1/artifacts/{ID}"), &headers);
        let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
        let mut response = Vec::new();
        assert_eq!(
            serve(&profile, &envelope, &bytes, &[], &mut response, &deadline()),
            Err(Status::Unauthorized)
        );
        let text = String::from_utf8(response).unwrap();
        assert!(text.contains("WWW-Authenticate: Bearer"));
        assert!(!text.contains("WWW-Authenticate: Basic"));
        assert!(!text.contains("admin"));
    }
    for _ in 0..120 {
        profile
            .source_quota
            .evaluate(&PrincipalId::from_bytes([0xd3; 16]))
            .unwrap();
    }
    let bytes = raw(
        "GET",
        &format!("/repo.git/api/v1/artifacts/{ID}/content"),
        &bearer(),
    );
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let mut response = Vec::new();
    assert_eq!(
        serve(&profile, &envelope, &bytes, &[], &mut response, &deadline()),
        Err(Status::RateLimited)
    );
    assert!(
        String::from_utf8(response)
            .unwrap()
            .contains("Retry-After: 60\r\n")
    );
    assert!(!scratch.0.join("node").exists());
}

#[test]
fn verified_binary_reads_bound_responses_and_retire_lost_response_lanes() {
    let scratch = Scratch::new();
    let (mut node, _) = OneNode::init(scratch.config()).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let incarnation = node.repository_incarnation_id();
    let payload = b"<html>untrusted\0\xffartifact</html>";
    let identity = ArtifactIdentity::new(
        Digest::new(
            DigestAlgorithmId::try_new(2).unwrap(),
            DigestBytes::try_new(&sha256_digest(payload)).unwrap(),
        ),
        payload.len() as u64,
        MediaType::parse("text/html").unwrap(),
        ArtifactPayloadKind::CiArtifact,
        None,
        None,
        None,
        RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
    );
    let scope = ArtifactScope::new(
        TenantId::from_bytes([0xd1; 16]),
        RepositoryId::from_bytes([0xd2; 16]),
        incarnation,
        crate::TRUSTED_WORKFLOW_ARTIFACT_TRUST,
    )
    .unwrap();
    let store = LocalArtifactStore::open(&scratch.0.join("artifacts"), scope).unwrap();
    store
        .put_reader(
            &identity,
            &mut Cursor::new(payload),
            &ArtifactOperation::new(4096, Duration::from_secs(10), &|| true).unwrap(),
        )
        .unwrap();
    node.shutdown().unwrap();
    let mut profile = scratch.profile(incarnation, "artifact-read");
    let id: String = identity
        .artifact_id()
        .bytes()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let bytes = raw(
        "GET",
        &format!("/repo.git/api/v1/artifacts/{id}/content"),
        &bearer(),
    );
    let envelope = head::parse(&bytes, profile.http).unwrap().unwrap();
    let mut response = Vec::new();
    assert_eq!(
        serve(&profile, &envelope, &bytes, &[], &mut response, &deadline()),
        Ok(())
    );
    assert!(response.ends_with(payload));
    let header = String::from_utf8_lossy(&response[..response.len() - payload.len()]);
    assert!(header.contains("Content-Type: application/octet-stream\r\n"));
    assert!(header.contains(&format!(
        "Content-Disposition: attachment; filename=\"artifact-{id}\"\r\n"
    )));
    assert!(header.contains("X-Content-Type-Options: nosniff\r\n"));
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
        serve(&profile, &envelope, &bytes, &[], &mut lost, &deadline()),
        Err(Status::Unavailable)
    );
    assert_eq!(
        lost.0, 1,
        "no second HTTP response after a failed success write"
    );
    let mut retried = Vec::new();
    assert_eq!(
        serve(&profile, &envelope, &bytes, &[], &mut retried, &deadline()),
        Ok(())
    );
    assert_eq!(retried, response);
    profile.maximum_response_bytes = 1;
    let mut refused = Vec::new();
    assert_eq!(
        serve(&profile, &envelope, &bytes, &[], &mut refused, &deadline()),
        Err(Status::TooLarge)
    );
    assert!(
        !refused
            .windows(payload.len())
            .any(|window| window == payload)
    );
    profile.maximum_response_bytes = 2 * 1024 * 1024;
    let mut expired = deadline();
    expired.started -= expired.timeout.duration() + Duration::from_secs(1);
    let mut refused = Vec::new();
    assert_eq!(
        serve(&profile, &envelope, &bytes, &[], &mut refused, &expired),
        Err(Status::Timeout)
    );
    assert!(
        !refused
            .windows(payload.len())
            .any(|window| window == payload)
    );
    let mut twin = Vec::new();
    assert_eq!(
        serve(&profile, &envelope, &bytes, &[], &mut twin, &deadline()),
        Ok(())
    );
    assert_eq!(twin, response);
    profile.nodes.close().unwrap();
}

#[test]
fn error_mapping_and_response_headers_keep_custody_failures_read_only() {
    for (refusal, status) in [
        (WorkflowArtifactReadRefusal::Disabled, Status::Forbidden),
        (WorkflowArtifactReadRefusal::InvalidId, Status::BadRequest),
        (
            WorkflowArtifactReadRefusal::Storage(ArtifactStorageError::NotFound),
            Status::NotFound,
        ),
        (
            WorkflowArtifactReadRefusal::Storage(ArtifactStorageError::PayloadLimit),
            Status::TooLarge,
        ),
        (
            WorkflowArtifactReadRefusal::Storage(ArtifactStorageError::Cancelled),
            Status::Timeout,
        ),
        (
            WorkflowArtifactReadRefusal::Storage(ArtifactStorageError::Deadline),
            Status::Timeout,
        ),
        (
            WorkflowArtifactReadRefusal::InvalidScope,
            Status::Unavailable,
        ),
    ] {
        let error = read_error(refusal);
        assert_eq!(error.status, status);
        assert!(!error.outcome_unknown);
    }
    for version in [HttpVersion::Http10, HttpVersion::Http11] {
        for status in [Status::Success, Status::Method, Status::RateLimited] {
            let mut output = Vec::new();
            send(&mut output, version, status, b"{}", None).unwrap();
            let output = String::from_utf8(output).unwrap();
            assert!(output.contains("Content-Length: 2\r\n"));
            assert!(output.contains("Vary: Authorization\r\n"));
            assert!(output.contains("Cache-Control: no-store\r\n"));
            assert_eq!(output.contains("Allow: GET\r\n"), status == Status::Method);
            assert_eq!(
                output.contains("Retry-After: 60\r\n"),
                status == Status::RateLimited
            );
        }
    }
}
