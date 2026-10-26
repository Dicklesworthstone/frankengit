#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Exact workflow custody downloads through a real authenticated TCP listener.
use fgit_crypto::sha256_digest;
use fgit_node::{
    GitDaemonServerLimits, GitDaemonServerReceipt, NodeConfig, OneNode,
    TRUSTED_WORKFLOW_ARTIFACT_TRUST,
};
use fgit_object_fabric::artifact::storage::{ArtifactOperation, ArtifactScope, LocalArtifactStore};
use fgit_object_fabric::{ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, HeadGeneration, PrincipalId,
    RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::{
    fs,
    io::{Cursor, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::Duration,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const PAYLOAD: &[u8] = b"<html>retained-build\0\xffpayload</html>";
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-artifact-http-tcp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("artifacts")).unwrap();
        fs::set_permissions(root.join("artifacts"), fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), tenant(), repository())
            .with_worker_threads(2)
            .with_object_format(format)
            .with_workflow_artifact_root(self.0.join("artifacts"))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn tenant() -> TenantId {
    TenantId::from_bytes([0xe1; 16])
}
fn repository() -> RepositoryId {
    RepositoryId::from_bytes([0xe2; 16])
}
fn hex(digest: &Digest) -> String {
    digest
        .bytes()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn scope(incarnation: RepositoryIncarnationId) -> ArtifactScope {
    ArtifactScope::new(
        tenant(),
        repository(),
        incarnation,
        TRUSTED_WORKFLOW_ARTIFACT_TRUST,
    )
    .unwrap()
}
fn put(root: &Path, scope: ArtifactScope, payload: &[u8]) -> (ArtifactIdentity, PathBuf) {
    let store = LocalArtifactStore::open(root, scope).unwrap();
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
    store
        .put_reader(
            &identity,
            &mut Cursor::new(payload),
            &ArtifactOperation::new(4096, Duration::from_secs(10), &|| true).unwrap(),
        )
        .unwrap();
    let path = root
        .join(format!("scope-{}", hex(&store.scope().commitment())))
        .join(hex(identity.artifact_id()));
    (identity, path)
}
fn credentials(path: &Path, incarnation: RepositoryIncarnationId, artifact_scope: Option<&str>) {
    let mut body = format!(
        "frankengit-http-credentials-v1 {} {} {incarnation}\n",
        tenant(),
        repository()
    );
    for (token, scopes) in [('a', artifact_scope), ('b', Some("read,lfs-read"))] {
        if let Some(scopes) = scopes {
            let hash: String = sha256_digest(token.to_string().repeat(64).as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            body.push_str(&format!(
                "{hash} {} {scopes}\n",
                PrincipalId::from_bytes([token as u8; 16])
            ));
        }
    }
    let temp = path.with_extension("next");
    fs::write(&temp, body).unwrap();
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(temp, path).unwrap();
}
struct Server {
    address: SocketAddr,
    route: String,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
}
impl Server {
    fn start(node: OneNode, credentials: PathBuf, sessions: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let route =
            String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let worker = thread::spawn(move || {
            let result = node.serve_smart_http_with_credentials_file_bounded(
                &listener,
                GitDaemonServerLimits::try_new(sessions, 2).unwrap(),
                &credentials,
                false,
                Duration::from_secs(15),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            address,
            route,
            worker: Some(worker),
        }
    }
    fn exchange(&self, method: &str, suffix: &str, token: Option<char>, headers: &str) -> Vec<u8> {
        let auth = token.map_or_else(String::new, |token| {
            format!("Authorization: Bearer {}\r\n", token.to_string().repeat(64))
        });
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        write!(
            stream,
            "{method} {}{suffix} HTTP/1.1\r\nHost: loopback\r\n{auth}{headers}\r\n",
            self.route
        )
        .unwrap();
        let mut response = Vec::new();
        stream.take(1024 * 1024).read_to_end(&mut response).unwrap();
        response
    }
    fn finish(mut self) -> GitDaemonServerReceipt {
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn response(bytes: &[u8], expected: u16) -> (&str, &[u8]) {
    assert!(
        bytes.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()),
        "{}",
        String::from_utf8_lossy(bytes)
    );
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&bytes[..split]).unwrap();
    let body = &bytes[split + 4..];
    assert!(head.contains(&format!("Content-Length: {}", body.len())));
    (head, body)
}
fn refused(bytes: &[u8], expected: u16) {
    let (_, body) = response(bytes, expected);
    assert!(!body.windows(PAYLOAD.len()).any(|window| window == PAYLOAD));
    let body = std::str::from_utf8(body).unwrap();
    assert!(body.contains("\"read_only\":true"));
    assert!(body.contains("\"outcome_unknown\":false"));
}

#[test]
fn verified_downloads_survive_restart_and_live_grants_never_cross_artifact_namespaces() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let config = scratch.config(format);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let incarnation = node.repository_incarnation_id();
        let before = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap()
            .receipt()
            .generation();
        let root = scratch.0.join("artifacts");
        let (identity, saved) = put(&root, scope(incarnation), PAYLOAD);
        let original = fs::read(&saved).unwrap();
        let id = hex(identity.artifact_id());
        let metadata_route = format!("/api/v1/artifacts/{id}");
        let content_route = format!("{metadata_route}/content");
        let expected_metadata = node
            .runtime()
            .block_on(
                node.inspect_workflow_artifact_in(&node.request_context(), identity.artifact_id()),
            )
            .unwrap()
            .to_json()
            .unwrap();
        let foreign = [
            ArtifactScope::new(
                TenantId::from_bytes([0xe5; 16]),
                repository(),
                incarnation,
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
            ArtifactScope::new(
                tenant(),
                RepositoryId::from_bytes([0xe6; 16]),
                incarnation,
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
            ArtifactScope::new(
                tenant(),
                repository(),
                RepositoryIncarnationId::from_bytes([0xe7; 16]),
                TRUSTED_WORKFLOW_ARTIFACT_TRUST,
            )
            .unwrap(),
            ArtifactScope::new(tenant(), repository(), incarnation, "another-trust-domain")
                .unwrap(),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, scope)| {
            let (identity, _) = put(&root, scope, format!("foreign-only-{index}").as_bytes());
            hex(identity.artifact_id())
        })
        .collect::<Vec<_>>();
        let grants = scratch.0.join("credentials");
        credentials(&grants, incarnation, Some("artifact-read"));
        let server = Server::start(node, grants.clone(), 22);
        // Missing/unknown credentials and an ordinary Git/LFS reader are separate failures.
        refused(&server.exchange("GET", &content_route, None, ""), 401);
        refused(&server.exchange("GET", &content_route, Some('c'), ""), 401);
        refused(&server.exchange("GET", &content_route, Some('b'), ""), 403);
        let download = server.exchange("GET", &content_route, Some('a'), "");
        let (head, body) = response(&download, 200);
        assert_eq!(body, PAYLOAD);
        assert!(head.contains("Content-Type: application/octet-stream"));
        assert!(head.contains(&format!(
            "Content-Disposition: attachment; filename=\"artifact-{id}\""
        )));
        assert!(head.contains("X-Content-Type-Options: nosniff"));
        assert!(head.contains("Cache-Control: no-store"));
        assert!(head.contains("Vary: Authorization"));
        let metadata = server.exchange("GET", &metadata_route, Some('a'), "");
        assert_eq!(response(&metadata, 200).1, expected_metadata.as_bytes());
        response(
            &server.exchange("GET", "/info/refs?service=git-upload-pack", Some('a'), ""),
            403,
        );
        refused(&server.exchange("POST", &content_route, Some('a'), ""), 405);
        refused(
            &server.exchange(
                "GET",
                &format!("{metadata_route}?trust=another-trust-domain"),
                Some('a'),
                "",
            ),
            400,
        );
        refused(
            &server.exchange(
                "GET",
                &content_route,
                Some('a'),
                "Idempotency-Key: never-write\r\n",
            ),
            400,
        );
        refused(
            &server.exchange(
                "GET",
                &format!("/api/v1/artifacts/{}/content", "0".repeat(64)),
                Some('a'),
                "",
            ),
            404,
        );
        credentials(&grants, incarnation, None);
        refused(&server.exchange("GET", &content_route, Some('a'), ""), 401);
        credentials(&grants, incarnation, Some("read"));
        refused(&server.exchange("GET", &content_route, Some('a'), ""), 403);
        credentials(&grants, incarnation, Some("artifact-read"));
        assert_eq!(
            response(&server.exchange("GET", &content_route, Some('a'), ""), 200).1,
            PAYLOAD
        );
        let mut corrupt = original.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        fs::write(&saved, &corrupt).unwrap();
        refused(&server.exchange("GET", &content_route, Some('a'), ""), 503);
        refused(&server.exchange("GET", &metadata_route, Some('a'), ""), 503);
        fs::write(&saved, &original).unwrap();
        assert_eq!(
            response(&server.exchange("GET", &content_route, Some('a'), ""), 200).1,
            PAYLOAD
        );
        for foreign_id in foreign {
            refused(
                &server.exchange(
                    "GET",
                    &format!("/api/v1/artifacts/{foreign_id}/content"),
                    Some('a'),
                    "",
                ),
                404,
            );
        }
        credentials(
            &grants,
            RepositoryIncarnationId::from_bytes([0xe8; 16]),
            Some("artifact-read"),
        );
        refused(&server.exchange("GET", &content_route, Some('a'), ""), 503);
        credentials(&grants, incarnation, Some("artifact-read"));
        assert_eq!(
            response(&server.exchange("GET", &metadata_route, Some('a'), ""), 200).1,
            expected_metadata.as_bytes()
        );
        let receipt = server.finish();
        assert_eq!(receipt.accepted_sessions(), 22);
        assert_eq!(
            receipt.completed_sessions() + receipt.refused_sessions(),
            22
        );
        let mut reopened = OneNode::open_existing(config).unwrap();
        let head = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        assert_eq!(
            head.receipt().generation(),
            before,
            "custody reads never publish repository state"
        );
        reopened
            .bring_into_service(head.receipt().generation())
            .unwrap();
        let server = Server::start(reopened, grants, 2);
        assert_eq!(
            response(&server.exchange("GET", &metadata_route, Some('a'), ""), 200).1,
            expected_metadata.as_bytes()
        );
        assert_eq!(
            response(&server.exchange("GET", &content_route, Some('a'), ""), 200).1,
            PAYLOAD
        );
        assert_eq!(server.finish().completed_sessions(), 2);
    }
}
