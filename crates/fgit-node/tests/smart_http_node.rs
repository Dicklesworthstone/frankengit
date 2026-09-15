#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_node::{NodeConfig, NodeSmartHttpRefusal, OneNode};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{GitHashAlgorithm, RepositoryId, TenantId};
use fgit_wire::WireLimits;
use fgit_wire::smart_http::{ProtocolVersion, parse_head};

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
