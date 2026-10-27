#![forbid(unsafe_code)]
//! Authentication-selected ref ceilings across real TCP and native authority.
//! The same service credential can prepare/read repository-wide data while
//! publishing only its explicit refs. No fake admission or substitute store.
#[allow(
    dead_code,
    reason = "reuse the production TCP fixture without copying it"
)]
#[path = "source_http/support.rs"]
mod support;

use fgit_crypto::{GitObjectKind, git_object_id, sha1_digest, sha256_digest};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::{Packet, WireLimits, encode_packets};
use std::net::TcpListener;
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use support::*;

struct ScopedServer {
    client: Endpoint,
    worker: Option<JoinHandle<GitDaemonServerReceipt>>,
    requests: usize,
}
impl ScopedServer {
    fn start(node: OneNode, path: &Path, requests: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint {
            address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec())
                .unwrap(),
        };
        let path = path.to_owned();
        let worker = thread::spawn(move || {
            let result = node.serve_repository_http_with_source_bounded(
                &listener,
                GitDaemonServerLimits::try_new(requests, 2).unwrap(),
                &path,
                true,
                false,
                true,
                true,
                Duration::from_secs(5),
            );
            node.shutdown().unwrap();
            result.unwrap()
        });
        Self {
            client,
            worker: Some(worker),
            requests,
        }
    }
    fn finish(mut self) {
        assert_eq!(
            self.worker
                .take()
                .unwrap()
                .join()
                .unwrap()
                .accepted_sessions(),
            self.requests
        );
    }
}
impl Drop for ScopedServer {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn scoped_row(token: char, services: &str, refs: &str) -> String {
    format!("{} {refs}\n", row(token, OWNER, services).trim_end())
}
fn scoped_header(node: &OneNode, path: &Path) -> String {
    credentials(node, path).replacen("credentials-v1", "credentials-v2", 1)
}
fn configure(path: &Path, header: &str, scope: &str) {
    replace(
        path,
        &(header.to_owned()
            + &scoped_row('a', "read,outcomes-read", "none")
            + &scoped_row('b', "read,receive,outcomes-read,merges-write", scope)),
    );
}
fn mutation(client: &Endpoint, route: &str, key: &str, form: &str) -> Reply {
    exchange(
        client,
        &request(
            client,
            route,
            'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\n",
                form.len()
            ),
            form.as_bytes(),
        ),
        true,
    )
}
fn recover(client: &Endpoint, key: &str) -> Reply {
    exchange(
        client,
        &request(
            client,
            "/api/v1/outcomes",
            'b',
            &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"),
            &[],
        ),
        true,
    )
}
fn list(client: &Endpoint, format: GitHashAlgorithm, token: char) -> Reply {
    post(
        client,
        "refs",
        token,
        &format!("object_format={}", format.as_str()),
        false,
    )
}
fn denied(reply: &Reply) {
    status(reply, 403);
    assert!(
        reply.body.contains("ref_write_scope_denied"),
        "{}",
        reply.raw
    );
}
fn committed(reply: &Reply) {
    status(reply, 200);
    assert!(
        reply.body.contains("\"outcome\":\"committed\""),
        "{}",
        reply.raw
    );
}
fn snapshot(node: &OneNode) -> std::collections::BTreeMap<RefName, GitOid> {
    node.runtime()
        .block_on(node.materialize_admission())
        .unwrap()
        .snapshot()
        .refs
        .clone()
}

#[test]
fn scoped_native_refs_and_tags_enforce_full_transactions_and_reload_without_filtering_reads() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, tip) = fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        let header = scoped_header(&node, &path);
        let raw_tag = b"refs/tags/release-\xff";
        configure(
            &path,
            &header,
            &format!(
                "prefix:{},exact:{}",
                hex(b"refs/heads/agent/"),
                hex(raw_tag)
            ),
        );
        let server = ScopedServer::start(node, &path, 15);
        let client = &server.client;
        let common = format!("object_format={}", format.as_str());
        let visible = list(client, format, 'a'); // 1
        status(&visible, 200);
        assert!(visible.body.contains("refs/heads/main"));
        let create = format!("{common}&ref=refs/heads/agent/work&new_commit={tip}");
        committed(&mutation(
            client,
            "/api/v1/source/branches/create",
            "native-create",
            &create,
        )); // 2
        for (key, reference) in [
            ("collision", "refs/heads/agents/escape"),
            ("root", "refs/heads/agent"),
        ] {
            denied(&mutation(
                client,
                "/api/v1/source/branches/create",
                key,
                &format!("{common}&ref={reference}&new_commit={tip}"),
            )); // 3,4
        }
        denied(&mutation(
            client,
            "/api/v1/source/branches/rename",
            "rename",
            &format!(
                "{common}&ref=refs/heads/agent/work&expected_commit={tip}&new_ref=refs/heads/escape"
            ),
        )); // 5
        denied(&mutation(
            client,
            "/api/v1/source/branches/transaction",
            "mixed",
            &format!(
                "{common}&create={}:{tip}&delete={}:{tip}",
                hex(b"refs/heads/agent/never-partial"),
                hex(b"refs/heads/main")
            ),
        )); // 6
        denied(&mutation(
            client,
            "/api/v1/source/branches/delete",
            "delete-main",
            &format!("{common}&ref=refs/heads/main&expected_commit={tip}"),
        )); // 7
        committed(&mutation(
            client,
            "/api/v1/source/tags/lightweight",
            "tag-create",
            &format!("{common}&ref_hex={}&target={tip}", hex(raw_tag)),
        )); // 8
        denied(&mutation(
            client,
            "/api/v1/source/tags/lightweight",
            "tag-escape",
            &format!("{common}&ref=refs/tags/release-other&target={tip}"),
        )); // 9
        let visible = list(client, format, 'a'); // 10
        status(&visible, 200);
        assert!(visible.body.contains("refs/heads/main"));
        assert!(visible.body.contains("refs/heads/agent/work"));
        assert!(visible.body.contains(&hex(raw_tag)));
        assert!(!visible.body.contains("never-partial") && !visible.body.contains("escape"));
        configure(&path, &header, "none");
        denied(&mutation(
            client,
            "/api/v1/source/branches/delete",
            "withdrawn",
            &format!("{common}&ref=refs/heads/agent/work&expected_commit={tip}"),
        )); // 11
        denied(&mutation(
            client,
            "/api/v1/source/branches/create",
            "native-create",
            &create,
        )); // 12
        status(&list(client, format, 'b'), 200); // 13
        let recovered = recover(client, "native-create"); // 14
        status(&recovered, 200);
        assert!(recovered.body.contains("committed"));
        replace(&path, &header);
        status(&list(client, format, 'b'), 401); // 15
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 2);
        let refs = snapshot(&node);
        assert_eq!(refs.len(), 3);
        for name in [
            b"refs/heads/main".as_slice(),
            b"refs/heads/agent/work",
            raw_tag,
        ] {
            assert_eq!(refs[&RefName::try_new(name).unwrap()], tip);
        }
        node.shutdown().unwrap();
    }
}

fn blob_pack(format: GitHashAlgorithm) -> (GitOid, Vec<u8>) {
    let oid = git_object_id(format, GitObjectKind::Blob, b"x");
    let mut bytes = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
    bytes.extend_from_slice(&[
        0x31, 0x78, 0x01, 0x01, 1, 0, 0xfe, 0xff, b'x', 0, 121, 0, 121,
    ]);
    let trailer = match format {
        GitHashAlgorithm::Sha1 => sha1_digest(&bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(&bytes).to_vec(),
    };
    bytes.extend(trailer);
    (oid, bytes)
}
fn receive_body(
    format: GitHashAlgorithm,
    atomic: bool,
    commands: &[(&str, GitOid, GitOid)],
    pack: &[u8],
) -> Vec<u8> {
    let mut packets = Vec::new();
    for (index, (name, old, new)) in commands.iter().enumerate() {
        let mut command = format!("{old} {new} {name}");
        if index == 0 {
            command.push_str(&format!(
                "\0report-status delete-refs object-format={}{}",
                format.as_str(),
                if atomic { " atomic" } else { "" }
            ));
        }
        packets.push(Packet::Data(command.into_bytes()));
    }
    packets.push(Packet::Flush);
    let mut body = encode_packets(&packets, &WireLimits::default()).unwrap();
    body.extend_from_slice(pack);
    body
}
fn push(client: &Endpoint, key: &str, body: &[u8]) -> Reply {
    exchange(
        client,
        &request(
            client,
            "/git-receive-pack",
            'b',
            &format!(
                "Content-Type: application/x-git-receive-pack-request\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\n",
                body.len()
            ),
            body,
        ),
        true,
    )
}
fn git_scope_denied(reply: &Reply) {
    status(reply, 200);
    assert!(
        reply.body.contains("ERR ") && reply.body.contains("credential does not permit"),
        "{}",
        reply.raw
    );
    assert!(!reply.body.contains("unpack ok") && !reply.body.contains("\nok refs/"));
}

#[test]
fn atomic_and_non_atomic_git_pushes_check_every_original_ref_before_any_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for atomic in [false, true] {
            let root = Scratch::new();
            let config = root.config(format);
            let (node, _) = fixture(&root, format);
            let path = root.0.join("credentials");
            let header = scoped_header(&node, &path);
            let narrow = format!("exact:{}", hex(b"refs/tags/first"));
            configure(&path, &header, &narrow);
            let server = ScopedServer::start(node, &path, 9);
            let client = &server.client;
            let (oid, pack) = blob_pack(format);
            let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
            let body = receive_body(
                format,
                atomic,
                &[
                    ("refs/tags/first", zero, oid),
                    ("refs/tags/second", zero, oid),
                ],
                &pack,
            );
            git_scope_denied(&push(client, "mixed-git", &body)); // 1
            let unknown = recover(client, "mixed-git"); // 2
            status(&unknown, 200);
            assert!(unknown.body.contains("key_not_observed"));
            let refs = list(client, format, 'a'); // 3
            status(&refs, 200);
            assert!(
                !refs.body.contains("refs/tags/first") && !refs.body.contains("refs/tags/second")
            );
            // Exactly the same original retry key can succeed after an operator
            // expands the ceiling: the denied attempt never claimed it.
            configure(&path, &header, "all");
            let accepted = push(client, "mixed-git", &body); // 4
            status(&accepted, 200);
            assert!(accepted.body.contains("unpack ok"), "{}", accepted.raw);
            assert!(
                accepted.body.contains("ok refs/tags/first")
                    && accepted.body.contains("ok refs/tags/second")
            );
            configure(&path, &header, &narrow);
            let replay = push(client, "mixed-git", &body); // 5
            git_scope_denied(&replay);
            assert!(
                replay
                    .body
                    .contains("any prior outcome remains recoverable")
            );
            let mixed_delete = receive_body(
                format,
                atomic,
                &[
                    ("refs/tags/first", oid, zero),
                    ("refs/tags/second", oid, zero),
                ],
                &[],
            );
            git_scope_denied(&push(client, "mixed-delete", &mixed_delete)); // 6
            let allowed_delete =
                receive_body(format, atomic, &[("refs/tags/first", oid, zero)], &[]);
            let accepted = push(client, "allowed-delete", &allowed_delete); // 7
            status(&accepted, 200);
            assert!(
                accepted.body.contains("ok refs/tags/first"),
                "{}",
                accepted.raw
            );
            let visible = list(client, format, 'a'); // 8
            status(&visible, 200);
            assert!(!visible.body.contains("refs/tags/first"));
            assert!(visible.body.contains("refs/tags/second"));
            replace(&path, &header);
            status(&push(client, "revoked", &body), 401); // 9
            server.finish();
            let node = reopen(&config);
            let refs = snapshot(&node);
            assert_eq!(refs.len(), 2);
            assert!(!refs.contains_key(&RefName::try_new(b"refs/tags/first").unwrap()));
            assert_eq!(refs[&RefName::try_new(b"refs/tags/second").unwrap()], oid);
            node.shutdown().unwrap();
        }
    }
}
