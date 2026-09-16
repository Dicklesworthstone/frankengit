#![forbid(unsafe_code)]
//! Two real HTTP editors of one exact version; no racing fixture projection.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use fgit_crypto::sha256_digest;
use fgit_forge::IssueNumber;
use fgit_node::{GitDaemonServerLimits, GitDaemonSessionTimeout, NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-issue-http-race-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn private_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn request(address: SocketAddr, route: &str, token: &str, action: &str, key: &str, body: &str) -> (u16, String) {
    let mut socket = TcpStream::connect(address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    write!(socket, "POST {route}/api/v1/issues/1/{action} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {token}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: {key}\r\n\r\n{body}", body.len()).unwrap();
    let mut bytes = Vec::new();
    (&mut socket).take(1024 * 1024).read_to_end(&mut bytes).unwrap();
    let response = String::from_utf8(bytes).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    assert_eq!(length, body.len());
    (status, body.to_owned())
}

#[test]
fn competing_editors_and_their_retries_do_not_overwrite_the_winners_issue() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let tenant = TenantId::from_bytes([0x71; 16]);
        let repository = RepositoryId::from_bytes([0x72; 16]);
        let config = NodeConfig::new(scratch.0.join("node"), tenant, repository)
            .with_object_format(format)
            .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(30)).unwrap());
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let before = node.runtime().block_on(node.materialize_admission()).unwrap().basis().generation();
        let token = "a".repeat(64);
        let digest: String = sha256_digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        let credentials = scratch.0.join("credentials");
        private_file(&credentials, format!("frankengit-http-credentials-v1 {tenant} {repository} {}\n{digest} {} issues-write\n",
            node.repository_incarnation_id(), PrincipalId::from_bytes([0x73; 16])).as_bytes());
        let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let result = node.serve_git_and_issue_http_with_credentials_file_bounded(&listener,
                GitDaemonServerLimits::try_new(5, 2).unwrap(), &credentials, false, Duration::from_secs(5));
            node.shutdown().unwrap();
            result.unwrap()
        });
        let opened = request(address, &route, &token, "open", "open", "expected_version=0&title=Before&body=immutable");
        assert_eq!(opened.0, 200, "{}", opened.1);
        let barrier = Arc::new(Barrier::new(3));
        let mut editors = Vec::new();
        for title in ["Left", "Right"] {
            let barrier = Arc::clone(&barrier);
            let route = route.clone();
            let token = token.clone();
            editors.push(thread::spawn(move || {
                barrier.wait();
                let body = format!("expected_version=1&title={title}");
                (title, request(address, &route, &token, "edit", title, &body))
            }));
        }
        barrier.wait();
        let replies: Vec<_> = editors.into_iter().map(|editor| editor.join().unwrap()).collect();
        let mut statuses = replies.iter().map(|(_, reply)| reply.0).collect::<Vec<_>>();
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 409], "{replies:?}");
        let winner = replies.iter().find(|(_, reply)| reply.0 == 200).unwrap().0;
        for (title, reply) in &replies {
            assert!(reply.1.contains(if reply.0 == 200 { "\"outcome\":\"committed\"" } else { "\"outcome\":\"refused\"" }));
            let retry = request(address, &route, &token, "edit", title, &format!("expected_version=1&title={title}"));
            assert_eq!(&retry, reply, "each key retains its actual winning or refused terminal result");
        }
        assert_eq!(server.join().unwrap().accepted_sessions(), 5);
        let mut node = OneNode::open_existing(config).unwrap();
        let generation = node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().generation();
        node.bring_into_service(generation).unwrap();
        let state = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(state.basis().generation().get(), before.get() + 3, "open, winning edit and losing refusal, never retry decisions");
        let page = node.runtime().block_on(node.read_issue_history_in(&node.request_context(),
            IssueNumber::try_new(1).unwrap(), 0, 10, None)).unwrap();
        let issue = page.issue.unwrap();
        assert_eq!(issue.title, winner);
        assert_eq!(issue.body, "immutable");
        assert_eq!(issue.version.get(), 2);
        assert_eq!(page.events.len(), 2);
        assert!(state.snapshot().refs.is_empty());
        node.shutdown().unwrap();
    }
}
