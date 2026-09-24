#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_authority::IdempotencyKey;
use fgit_node::{LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::PrincipalId;
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, RepositoryId, TenantId};
use fgit_wire::smart_http::{HttpLimits, ProtocolVersion, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "frankengit-smart-http-node-{}-{n}",
            std::process::id()
        )))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config(root: PathBuf) -> NodeConfig {
    NodeConfig::new(
        root,
        TenantId::from_bytes([0x81; 16]),
        RepositoryId::from_bytes([0x82; 16]),
    )
}

fn serving_node(scratch: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(config(scratch.0.clone()).with_object_format(format))
        .expect("node initializes");
    node.bring_into_service(HeadGeneration::FIRST)
        .expect("node enters service");
    node
}

fn request(route: &str, protocol: Option<&str>) -> Vec<u8> {
    let protocol = protocol.map_or(String::new(), |value| format!("Git-Protocol: {value}\r\n"));
    format!(
        "GET {route}/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: loopback\r\n{protocol}\r\n"
    )
    .into_bytes()
}

#[test]
fn discovery_v2_comes_from_the_real_empty_authority_view() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
        .expect("canonical route is UTF-8");
    let bytes = request(route, Some("version=2"));
    let head = parse_head(&bytes, Default::default())
        .expect("head parses")
        .expect("head complete");
    let response = node
        .smart_http_upload_discovery_in(&head, WireLimits::default())
        .expect("authority-backed v2 discovery serves");
    assert_eq!(response.version(), ProtocolVersion::V2);
    assert!(response.head().starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(
        response
            .head()
            .contains("application/x-git-upload-pack-advertisement")
    );
    assert!(response.body().starts_with(b"000eversion 2\n"));
    assert!(
        response
            .body()
            .windows(b"object-format=sha1".len())
            .any(|w| w == b"object-format=sha1")
    );
    node.shutdown().expect("node shuts down");
}

#[test]
fn discovery_sha256_retains_the_authenticated_object_domain() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha256);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = request(route, None);
    let head = parse_head(&bytes, Default::default()).unwrap().unwrap();
    let response = node
        .smart_http_upload_discovery_in(&head, WireLimits::default())
        .unwrap();
    assert_eq!(response.version(), ProtocolVersion::V0);
    assert!(
        response
            .body()
            .starts_with(b"001e# service=git-upload-pack\n0000")
    );
    assert!(
        response
            .body()
            .windows(b"object-format=sha256".len())
            .any(|w| w == b"object-format=sha256")
    );
    node.shutdown().unwrap();
}

#[test]
fn mismatched_route_refuses_before_repository_service() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let bytes = request("/not-this-repository.git", None);
    let head = parse_head(&bytes, Default::default()).unwrap().unwrap();
    assert!(matches!(
        node.smart_http_upload_discovery_in(&head, WireLimits::default()),
        Err(NodeSmartHttpRefusal::RepositoryRouteMismatch)
    ));
    node.shutdown().unwrap();
}

fn upload_request(route: &str, body_len: usize) -> Vec<u8> {
    format!(
        "POST {route}/git-upload-pack HTTP/1.1\r\nHost: loopback\r\nGit-Protocol: version=2\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: {body_len}\r\n\r\n"
    )
    .into_bytes()
}

fn ls_refs_body() -> Vec<u8> {
    encode_packets(
        &[
            Packet::Data(b"command=ls-refs\n".to_vec()),
            Packet::Delimiter,
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .expect("fixed v2 ls-refs body encodes")
}

#[test]
fn stateless_v2_ls_refs_runs_against_the_same_empty_authority_view() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let body = ls_refs_body();
    let head_bytes = upload_request(route, body.len());
    let head = parse_head(&head_bytes, HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut live = || true;
    let mut output = Vec::new();
    let receipt = node
        .smart_http_upload_rpc_in(
            &head,
            &body,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut live,
            &mut output,
        )
        .expect("v2 ls-refs serves from authenticated empty state");
    assert_eq!(receipt.version(), ProtocolVersion::V2);
    assert!(!receipt.pack_requested());
    assert!(output.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(
        output
            .windows(b"Transfer-Encoding: chunked".len())
            .any(|w| w == b"Transfer-Encoding: chunked")
    );
    assert!(output.ends_with(b"4\r\n0000\r\n0\r\n\r\n"));
    node.shutdown().unwrap();
}

#[test]
fn rpc_refuses_pipelined_suffix_before_writing_any_response() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let body = ls_refs_body();
    let head_bytes = upload_request(route, body.len());
    let head = parse_head(&head_bytes, HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut offered = body;
    offered.extend_from_slice(b"NEXT");
    let mut live = || true;
    let mut output = Vec::new();
    assert!(matches!(
        node.smart_http_upload_rpc_in(
            &head,
            &offered,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut live,
            &mut output,
        ),
        Err(NodeSmartHttpRefusal::TrailingRequestBytes { count: 4 })
    ));
    assert!(output.is_empty());
    node.shutdown().unwrap();
}

#[test]
fn rpc_cancellation_precedes_authority_work_and_response_bytes() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let body = ls_refs_body();
    let head_bytes = upload_request(route, body.len());
    let head = parse_head(&head_bytes, HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut cancelled = || false;
    let mut output = Vec::new();
    assert!(
        node.smart_http_upload_rpc_in(
            &head,
            &body,
            WireLimits::default(),
            HttpLimits::default(),
            1024 * 1024,
            &mut cancelled,
            &mut output,
        )
        .is_err()
    );
    assert!(output.is_empty());
    node.shutdown().unwrap();
}

fn receive_discovery_request(route: &str, protocol: Option<&str>) -> Vec<u8> {
    let protocol = protocol.map_or(String::new(), |value| format!("Git-Protocol: {value}\r\n"));
    format!(
        "GET {route}/info/refs?service=git-receive-pack HTTP/1.1\r\nHost: loopback\r\n{protocol}\r\n"
    )
    .into_bytes()
}

fn authenticated_receive() -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0x77; 16]),
        IdempotencyKey::new(b"smart-http-receive-discovery".to_vec())
            .expect("fixed retry key is bounded"),
    )
}

#[test]
fn authenticated_receive_discovery_uses_authority_visible_refs() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = receive_discovery_request(route, None);
    let head = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    let response = node
        .smart_http_receive_discovery_in(&head, &authenticated_receive(), WireLimits::default())
        .expect("authenticated receive discovery serves");
    assert_eq!(response.version(), ProtocolVersion::V0);
    assert!(
        response
            .head()
            .contains("application/x-git-receive-pack-advertisement")
    );
    assert!(
        response
            .body()
            .starts_with(b"001f# service=git-receive-pack\n0000")
    );
    assert!(
        response
            .body()
            .windows(b"report-status".len())
            .any(|w| w == b"report-status")
    );
    assert!(
        response
            .body()
            .windows(b"object-format=sha1".len())
            .any(|w| w == b"object-format=sha1")
    );
    node.shutdown().unwrap();
}

#[test]
fn receive_discovery_refuses_anonymous_and_protocol_v2() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha1);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let anonymous_bytes = receive_discovery_request(route, None);
    let anonymous_head = parse_head(&anonymous_bytes, HttpLimits::default())
        .unwrap()
        .unwrap();
    assert!(matches!(
        node.smart_http_receive_discovery_in(
            &anonymous_head,
            &LoopbackReceiveSession::Anonymous,
            WireLimits::default(),
        ),
        Err(NodeSmartHttpRefusal::UnauthenticatedReceive)
    ));
    let v2_bytes = receive_discovery_request(route, Some("version=2"));
    let v2_head = parse_head(&v2_bytes, HttpLimits::default())
        .unwrap()
        .unwrap();
    assert!(
        node.smart_http_receive_discovery_in(
            &v2_head,
            &authenticated_receive(),
            WireLimits::default(),
        )
        .is_err()
    );
    node.shutdown().unwrap();
}

#[test]
fn receive_discovery_sha256_retains_authenticated_object_domain() {
    let scratch = Scratch::new();
    let node = serving_node(&scratch, GitHashAlgorithm::Sha256);
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let bytes = receive_discovery_request(route, None);
    let head = parse_head(&bytes, HttpLimits::default()).unwrap().unwrap();
    let response = node
        .smart_http_receive_discovery_in(&head, &authenticated_receive(), WireLimits::default())
        .unwrap();
    assert!(
        response
            .body()
            .windows(b"object-format=sha256".len())
            .any(|w| w == b"object-format=sha256")
    );
    node.shutdown().unwrap();
}
