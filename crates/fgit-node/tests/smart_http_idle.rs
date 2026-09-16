#![forbid(unsafe_code)]
//! A request longer than listener idleness must not retire its follow-up route.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use fgit_crypto::sha256_digest;
use fgit_node::{GitDaemonServerLimits, GitDaemonSessionTimeout, NodeConfig, OneNode};
use fgit_types::{HeadGeneration, PrincipalId, RepositoryId, TenantId};
use fgit_wire::{Packet, WireLimits, encode_packets};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}

#[test]
fn slow_authenticated_request_keeps_the_follow_up_accept_window_open() {
    let scratch = Scratch(std::env::temp_dir().join(format!("fg-http-idle-{}", std::process::id())));
    let configuration = NodeConfig::new(scratch.0.clone(), TenantId::from_bytes([0xd1; 16]), RepositoryId::from_bytes([0xd2; 16]))
        .with_git_daemon_session_timeout(GitDaemonSessionTimeout::try_new(Duration::from_secs(10)).unwrap());
    let (mut node, _) = OneNode::init(configuration).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let route = String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let token = "b".repeat(64);
    let digest = sha256_digest(token.as_bytes());
    // Connect before starting the listener loop so startup scheduling cannot
    // consume the idle interval before any test client exists.
    let mut first = TcpStream::connect(address).unwrap();
    first.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    first.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    let worker = std::thread::spawn(move || {
        let result = node.serve_smart_http_bounded(&listener, GitDaemonServerLimits::try_new(2, 1).unwrap(),
            digest, PrincipalId::from_bytes([0xd3; 16]), false, Duration::from_millis(100));
        let cleanup = node.shutdown();
        (result, cleanup)
    });
    let body = encode_packets(&[
        Packet::Data(b"command=ls-refs\n".to_vec()), Packet::Delimiter, Packet::Flush,
    ], &WireLimits::default()).unwrap();
    let request = format!("POST {route}/git-upload-pack HTTP/1.1\r\nHost: loopback\r\nAuthorization: Bearer {token}\r\nGit-Protocol: version=2\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {}\r\nExpect: 100-continue\r\n\r\n", body.len());
    first.write_all(request.as_bytes()).unwrap();
    let mut interim = [0_u8; 25];
    first.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    // The interim reply proves the request is accepted and authenticated. The
    // following delay exceeds the listener idle window, not its ingress limit.
    std::thread::sleep(Duration::from_millis(300));
    first.write_all(&body).unwrap();
    let mut first_response = Vec::new();
    first.read_to_end(&mut first_response).unwrap();
    drop(first);

    let follow_up = (|| -> std::io::Result<Vec<u8>> {
        let mut second = TcpStream::connect(address)?;
        second.set_read_timeout(Some(Duration::from_secs(15)))?;
        second.set_write_timeout(Some(Duration::from_secs(15)))?;
        // A fresh anonymous connection must be accepted then independently
        // refused, rather than inheriting authentication or seeing a dead port.
        write!(second, "GET {route}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: loopback\r\n\r\n")?;
        let mut response = Vec::new();
        second.read_to_end(&mut response)?;
        Ok(response)
    })();
    let (result, cleanup) = worker.join().unwrap();
    cleanup.expect("HTTP node and its children drain");
    let receipt = result.expect("bounded listener succeeds");
    assert!(first_response.starts_with(b"HTTP/1.1 200"));
    assert!(follow_up.expect("follow-up connection remains available").starts_with(b"HTTP/1.1 401"));
    assert_eq!(receipt.accepted_sessions(), 2);
    assert_eq!(receipt.completed_sessions(), 1);
    assert_eq!(receipt.refused_sessions(), 1);
}
