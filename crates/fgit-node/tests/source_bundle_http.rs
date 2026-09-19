#![forbid(unsafe_code)]
//! Real native bundle export through authenticated HTTP, exact snapshot replay
//! and reopened embedded nodes. These tests do not invoke an external Git engine.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;
use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::sha256_digest;
use fgit_node::LoopbackReceiveSession;
use fgit_pack::full_bundle::FullBundleInput;
use fgit_types::GitHashAlgorithm;
use fgit_wire::visibility::RefVisibility;

struct BinaryReply { status: u16, head: String, body: Vec<u8> }
impl BinaryReply {
    fn header(&self, name: &str) -> &str {
        self.head.split("\r\n").filter_map(|line| line.split_once(": "))
            .find(|(key, _)| key.eq_ignore_ascii_case(name)).unwrap().1
    }
}
fn binary_exchange(client: &Endpoint, bytes: &[u8]) -> BinaryReply {
    let mut socket = TcpStream::connect(client.address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.write_all(bytes).unwrap(); socket.shutdown(Shutdown::Write).unwrap();
    let mut raw = Vec::new();
    (&mut socket).take(129 * 1024 * 1024).read_to_end(&mut raw).unwrap();
    let at = raw.windows(4).position(|part| part == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..at].to_vec()).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let reply = BinaryReply { status, head, body: raw[at + 4..].to_vec() };
    assert_eq!(reply.head.matches("HTTP/1.1 ").count(), 1);
    assert_eq!(reply.header("Content-Length").parse::<usize>().unwrap(), reply.body.len());
    reply
}
fn export(client: &Endpoint, token: char, form: &str, extra: &str, chunked: bool) -> BinaryReply {
    let (body, framing) = if chunked {
        let mut bytes = Vec::new();
        for part in form.as_bytes().chunks(7) {
            bytes.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            bytes.extend_from_slice(part); bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n"); (bytes, "Transfer-Encoding: chunked\r\n".into())
    } else { (form.as_bytes().to_vec(), format!("Content-Length: {}\r\n", form.len())) };
    binary_exchange(client, &request(client, "/api/v1/source/bundle/export", token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}{extra}"), &body))
}

#[test]
fn complete_native_bundle_bytes_and_snapshot_survive_http_and_reopen_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, main) = fixture(&root, format); let before = generation(&node);
        let (_, native) = node.runtime().block_on(node.export_full_git_bundle_in(
            &node.request_context(), &RefVisibility::new(), None)).unwrap();
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 3, true, false);
        let browse = post(&server.client, "tree", 'a', &common(format), false);
        status(&browse, 200);
        assert_eq!(text(&browse.body, "source_commit"), main.to_string());
        assert_eq!(number(&browse.body, "limit"), 100);
        let form = format!("object_format={}", format.as_str());
        let first = export(&server.client, 'a', &form, "", false);
        assert_eq!(first.status, 200, "{}", first.head);
        assert_eq!(first.body, native.bytes());
        assert_eq!(first.header("X-Fgit-Snapshot"), token(&browse));
        assert_eq!(first.header("Content-Type"), "application/x-git-bundle");
        assert_eq!(first.header("X-Fgit-Artifact-Sha256"), hex(&sha256_digest(&first.body)));
        assert_eq!(first.header("X-Fgit-Object-Format"), format.as_str());
        assert_eq!(first.header("X-Fgit-Read-Only"), "true");
        assert_eq!(first.header("Cache-Control"), "no-store");
        assert!(!first.head.to_ascii_lowercase().contains("set-cookie"));
        let parsed = FullBundleInput::parse(&first.body, Default::default(), &mut || true).unwrap();
        assert_eq!(parsed.format(), format);
        assert_eq!(parsed.references().len(), 1);
        assert_eq!(parsed.references()[0].name().as_bytes(), b"refs/heads/main");
        assert_eq!(*parsed.references()[0].target(), main);
        assert!(parsed.prerequisites().is_empty());
        let pinned = format!("{form}&expected_head={}", first.header("X-Fgit-Snapshot"));
        let again = export(&server.client, 'a', &pinned, "", true);
        assert_eq!(again.status, 200); assert_eq!(again.body, first.body); assert_eq!(again.head, first.head);
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config); assert_eq!(generation(&node), before);
        let session = LoopbackReceiveSession::authenticated(OWNER,
            IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap());
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(
            &node.request_context(), &session)).unwrap(), RequestRecovery::KeyNotObserved));
        let server = Server::start(node, &path, 1, true, false);
        let reopened = export(&server.client, 'a', &pinned, "", false);
        assert_eq!(reopened.status, 200); assert_eq!(reopened.body, first.body); assert_eq!(reopened.head, first.head);
        assert_eq!(server.finish().accepted_sessions(), 1);
    }
}

#[test]
fn export_pins_the_whole_authority_snapshot_even_when_only_forge_state_changes() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 4, true, true);
    let first = export(&server.client, 'a', "object_format=sha1", "", false);
    assert_eq!(first.status, 200);
    let body = b"expected_version=0&title=Intervening+issue&body=";
    let changed = exchange(&server.client, &request(&server.client, "/api/v1/issues/1/open", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: bundle-pin-change\r\n", body.len()), body), true);
    status(&changed, 200);
    let stale = export(&server.client, 'a', &format!("object_format=sha1&expected_head={}", first.header("X-Fgit-Snapshot")), "", false);
    assert_eq!(stale.status, 409);
    assert!(String::from_utf8(stale.body).unwrap().contains("source_snapshot_moved"));
    let current = export(&server.client, 'a', "object_format=sha1", "", false);
    assert_eq!(current.status, 200); assert_eq!(current.body, first.body);
    assert_ne!(current.header("X-Fgit-Snapshot"), first.header("X-Fgit-Snapshot"));
    assert_eq!(server.finish().accepted_sessions(), 4);
    let node = reopen(&config); node.shutdown().unwrap();
}

#[test]
fn export_requires_source_enablement_and_read_scope_before_continue_or_disclosure() {
    let root = Scratch::new(); let config = root.config(GitHashAlgorithm::Sha1);
    let (node, _) = fixture(&root, GitHashAlgorithm::Sha1); let before = generation(&node);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 6, true, false);
    for (token, extra, expected) in [('b', "", 403), ('f', "", 401),
        ('a', "Idempotency-Key: forbidden-read-key\r\n", 400)] {
        let reply = export(&server.client, token, "object_format=sha1", extra, false);
        assert_eq!(reply.status, expected); assert!(!reply.body.starts_with(b"# v2 git bundle"));
        assert!(!reply.head.contains("X-Fgit-Source-Head"));
    }
    let denied = binary_exchange(&server.client, &request(&server.client, "/api/v1/source/bundle/export", 'b',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 999\r\nExpect: 100-continue\r\n", &[]));
    assert_eq!(denied.status, 403); assert!(!denied.head.contains("100 Continue"));
    let foreign = Endpoint { address: server.client.address, route: format!("{}/other", server.client.route) };
    assert_eq!(export(&foreign, 'a', "object_format=sha1", "", false).status, 404);
    assert_eq!(export(&server.client, 'a', "object_format=sha256", "", false).status, 400);
    assert_eq!(server.finish().accepted_sessions(), 6);
    let node = reopen(&config); assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, false, false);
    assert_eq!(export(&server.client, 'a', "object_format=sha1", "", false).status, 403);
    assert_eq!(server.finish().accepted_sessions(), 1);
}
