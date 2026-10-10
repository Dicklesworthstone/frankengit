#![forbid(unsafe_code)]
//! Real persisted native objects and the authenticated TCP source endpoint.

#[path = "source_http/support.rs"]
mod support;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use fgit_authority::authority_head_identity;
use fgit_types::{GitHashAlgorithm, RefName, RepositoryAuthorityHeadId, RootLayoutVersion};
use fgit_verified_read::blob::{
    MAX_VERIFIED_BLOB_FRAME_BYTES, decode_verified_blob_envelope, verify_blob_against_head,
};
use support::*;

fn pin(node: &fgit_node::OneNode) -> RepositoryAuthorityHeadId {
    let selected = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    authority_head_identity(&selected.body().unwrap()).unwrap()
}
fn token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn query(head: RepositoryAuthorityHeadId, path: &[u8]) -> String {
    format!(
        "/api/v1/source/verified-blob?ref_hex={}&path_hex={}&expected_head={}",
        hex(b"refs/heads/main"),
        hex(path),
        token(head)
    )
}
fn get(
    client: &Endpoint,
    target: &str,
    credential: char,
    extra: &str,
    method: &str,
) -> (u16, String, Vec<u8>) {
    let mut socket = TcpStream::connect(client.address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    write!(socket, "{method} {}{target} HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\nConnection: close\r\n{extra}\r\n",
        client.route, credential.to_string().repeat(64)).unwrap();
    let mut bytes = Vec::new();
    socket
        .take(MAX_VERIFIED_BLOB_FRAME_BYTES as u64 + 16 * 1024)
        .read_to_end(&mut bytes)
        .unwrap();
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let headers = String::from_utf8(bytes[..split].to_vec()).unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    let length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(length, bytes.len() - split);
    (status, headers, bytes[split..].to_vec())
}

#[test]
fn actual_http_blob_proofs_bind_independent_head_ref_path_bytes_and_source_grant() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root
            .config(format)
            .with_root_layout(RootLayoutVersion::RefStateMerkleV1);
        let (node, commit) = fixture_with_config(&root, format, config.clone());
        let trusted = pin(&node);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 11, true, false);
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        for (path, expected, kind) in [
            (b"alpha.txt".as_slice(), TEXT, "file"),
            (BINARY_PATH, BINARY, "file"),
            (b"link", LINK, "symlink"),
            (b"dir/nested.txt", b"needle in nested\n", "file"),
            (b"empty", b"", "file"),
            (b"run", b"#!/bin/sh\nneedle\n", "executable"),
        ] {
            let (status, headers, bytes) =
                get(&server.client, &query(trusted, path), 'a', "", "GET");
            assert_eq!(status, 200, "{headers} {}", String::from_utf8_lossy(&bytes));
            assert!(headers.contains("Content-Type: application/vnd.frankengit.verified-blob\r\n"));
            let envelope = decode_verified_blob_envelope(&bytes).unwrap();
            let verified = verify_blob_against_head(trusted, &reference, path, &envelope).unwrap();
            assert_eq!(verified.bytes, expected);
            assert_eq!(verified.kind.as_str(), kind);
            assert_eq!(verified.source_commit, commit);
            assert!(verify_blob_against_head(trusted, &reference, b"other", &envelope).is_err());
            let mut changed = bytes;
            *changed.last_mut().unwrap() ^= 1;
            assert!(
                decode_verified_blob_envelope(&changed)
                    .and_then(
                        |proof| verify_blob_against_head(trusted, &reference, path, &proof)
                            .map(|_| ())
                    )
                    .is_err()
            );
        }
        let target = query(trusted, b"alpha.txt");
        assert_eq!(get(&server.client, &target, 'b', "", "GET").0, 403);
        let wrong = target.replace(
            &token(trusted),
            &format!(
                "alg:{}:{}",
                trusted.as_internal_object_id().algorithm().code_point(),
                "00".repeat(32)
            ),
        );
        assert_eq!(get(&server.client, &wrong, 'a', "", "GET").0, 409);
        assert_eq!(
            get(
                &server.client,
                &target,
                'a',
                "Idempotency-Key: cannot-write\r\n",
                "GET"
            )
            .0,
            400
        );
        assert_eq!(
            get(&server.client, &query(trusted, b"module"), 'a', "", "GET").0,
            404
        );
        assert_eq!(get(&server.client, &target, 'a', "", "POST").0, 405);
        server.finish();
        let node = reopen(&config);
        assert_eq!(
            generation(&node),
            before,
            "proof reads publish no transactions"
        );
        assert_eq!(pin(&node), trusted);
        node.shutdown().unwrap();
    }
}

#[test]
fn legacy_layout_and_disabled_source_api_refuse_without_silent_migration() {
    for enabled in [true, false] {
        let root = Scratch::new();
        let (node, _) = fixture(&root, GitHashAlgorithm::Sha1);
        let trusted = pin(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 1, enabled, false);
        let (status, _, body) = get(
            &server.client,
            &query(trusted, b"alpha.txt"),
            'a',
            "",
            "GET",
        );
        assert_eq!(status, if enabled { 409 } else { 403 });
        assert!(decode_verified_blob_envelope(&body).is_err());
        server.finish();
    }
}
