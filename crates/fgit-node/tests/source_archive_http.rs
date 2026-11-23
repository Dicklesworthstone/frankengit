//! Complete source archives through the production TCP listener and authority.
//! Independent format readers check byte paths, metadata and exact framing.
#![forbid(unsafe_code)]

#[path = "source_http/support.rs"]
mod support;

#[path = "source_archive_http/zip_tests.rs"]
mod zip_tests;

use fgit_authority::{IdempotencyKey, key_recovery::RequestRecovery};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::time::Duration;
use support::*;

struct BinaryReply {
    status: u16,
    head: String,
    body: Vec<u8>,
}
impl BinaryReply {
    fn header(&self, name: &str) -> &str {
        self.head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .unwrap()
            .1
            .trim()
    }
    fn error(&self, expected: u16, code: &str) {
        assert_eq!(self.status, expected, "{}", self.head);
        let body = std::str::from_utf8(&self.body).unwrap();
        assert!(body.contains(code), "{body}");
        assert!(!self.head.contains("application/x-tar"));
        assert!(!self.head.contains("application/zip"));
        assert!(!self.head.contains("Content-Disposition:"));
        assert!(!self.head.contains("X-FrankenGit-Source-Commit:"));
    }
}
fn binary_exchange(client: &Endpoint, bytes: &[u8], half_close: bool) -> BinaryReply {
    let mut socket = TcpStream::connect(client.address).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(60))).unwrap();
    socket.write_all(bytes).unwrap();
    if half_close {
        socket.shutdown(Shutdown::Write).unwrap();
    }
    let mut response = Vec::new();
    (&mut socket)
        .take(2 * 1024 * 1024)
        .read_to_end(&mut response)
        .unwrap();
    let boundary = response.windows(4).position(|part| part == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(response[..boundary].to_vec()).unwrap();
    assert_eq!(head.matches("HTTP/1.1 ").count(), 1, "{head}");
    assert!(!head.contains("100 Continue"));
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = response[boundary + 4..].to_vec();
    let reply = BinaryReply { status, head, body };
    assert_eq!(
        reply.header("Content-Length").parse::<usize>().unwrap(),
        reply.body.len()
    );
    reply
}
fn archive(client: &Endpoint, token: char, form: &str, chunked: bool) -> BinaryReply {
    let (body, framing) = if chunked {
        let mut bytes = Vec::new();
        for chunk in form.as_bytes().chunks(11) {
            bytes.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            bytes.extend_from_slice(chunk);
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n");
        (bytes, "Transfer-Encoding: chunked\r\n".to_owned())
    } else {
        (
            form.as_bytes().to_vec(),
            format!("Content-Length: {}\r\n", form.len()),
        )
    };
    binary_exchange(
        client,
        &request(
            client,
            "/api/v1/source/archive",
            token,
            &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"),
            &body,
        ),
        true,
    )
}

#[derive(Debug)]
struct Member {
    mode: u64,
    kind: u8,
    data: Vec<u8>,
    link: Vec<u8>,
}
fn field(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len())]
}
fn octal(bytes: &[u8]) -> u64 {
    let text = std::str::from_utf8(field(bytes)).unwrap().trim();
    u64::from_str_radix(text, 8).unwrap()
}
fn members(bytes: &[u8]) -> BTreeMap<Vec<u8>, Member> {
    let mut result = BTreeMap::new();
    let mut offset = 0;
    loop {
        let header = bytes.get(offset..offset + 512).unwrap();
        if header.iter().all(|byte| *byte == 0) {
            assert_eq!(bytes.len() - offset, 1024);
            assert!(bytes[offset..].iter().all(|byte| *byte == 0));
            return result;
        }
        assert_eq!(&header[257..263], b"ustar\0");
        assert_eq!(&header[263..265], b"00");
        let checksum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, byte)| if (148..156).contains(&i) { 32 } else { u64::from(*byte) })
            .sum();
        assert_eq!(octal(&header[148..156]), checksum);
        for range in [108..116, 116..124, 136..148] {
            assert_eq!(octal(&header[range]), 0);
        }
        let mut name = field(&header[345..500]).to_vec();
        if !name.is_empty() {
            name.push(b'/');
        }
        name.extend_from_slice(field(&header[..100]));
        assert!(name.starts_with(b"source/"), "{name:?}");
        let size = usize::try_from(octal(&header[124..136])).unwrap();
        let start = offset + 512;
        let end = start.checked_add(size).unwrap();
        let next = end.div_ceil(512) * 512;
        assert!(bytes[end..next].iter().all(|byte| *byte == 0));
        let member = Member {
            mode: octal(&header[100..108]),
            kind: header[156],
            data: bytes[start..end].to_vec(),
            link: field(&header[157..257]).to_vec(),
        };
        assert!(result.insert(name, member).is_none());
        offset = next;
    }
}

fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let name = match kind {
        GitObjectKind::Blob => "blob",
        GitObjectKind::Tree => "tree",
        GitObjectKind::Commit => "commit",
        GitObjectKind::Tag => "tag",
    };
    let id = git_object_id(format, kind, body);
    let raw = [format!("{name} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut compressed = vec![0x78, 0x01, 0x01];
    compressed.extend(length.to_le_bytes());
    compressed.extend((!length).to_le_bytes());
    compressed.extend_from_slice(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    compressed.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let directory = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&text[2..]), compressed).unwrap();
    id
}
fn safe_fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid, GitOid) {
    safe_fixture_with_name(root, format, BINARY_PATH)
}
fn safe_fixture_with_name(
    root: &Scratch,
    format: GitHashAlgorithm,
    binary_name: &[u8],
) -> (OneNode, GitOid, GitOid) {
    let git = root.0.join("archive-source");
    fs::create_dir_all(git.join("refs/heads")).unwrap();
    fs::write(git.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(git.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = |bytes: &[u8]| loose(&git, format, GitObjectKind::Blob, bytes);
    let executable = blob(b"#!/bin/sh\nprintf hello\n");
    let nested = loose(
        &git,
        format,
        GitObjectKind::Tree,
        &[b"100755 run\0".as_slice(), executable.as_bytes()].concat(),
    );
    // This target is deliberately absent: exporting a gitlink cannot follow it.
    let missing = GitOid::from_hex(format, &"ab".repeat(format.digest_len())).unwrap();
    let mut entries = Vec::new();
    for (mode, name, oid) in [
        ("100644", binary_name, blob(BINARY)),
        ("40000", b"dir".as_slice(), nested),
        ("100644", b"empty".as_slice(), blob(&[])),
        ("120000", b"link".as_slice(), blob(b"dir/run")),
        ("160000", b"module".as_slice(), missing),
    ] {
        entries.extend_from_slice(mode.as_bytes());
        entries.push(b' ');
        entries.extend_from_slice(name);
        entries.push(0);
        entries.extend_from_slice(oid.as_bytes());
    }
    let tree = loose(&git, format, GitObjectKind::Tree, &entries);
    let body = format!(
        "tree {tree}\nauthor Archive <fixture@example.invalid> 1 +0000\ncommitter Archive <fixture@example.invalid> 1 +0000\n\narchive fixture\n"
    );
    let commit = loose(&git, format, GitObjectKind::Commit, body.as_bytes());
    fs::write(git.join("refs/heads/main"), format!("{commit}\n")).unwrap();
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    let selected = node.runtime().block_on(node.authenticate_authority_head()).unwrap();
    node.bring_into_service(selected.receipt().generation()).unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &git,
            OWNER,
            b"source-archive-http-fixture",
        ))
        .unwrap();
    assert!(
        imported.commands.iter().all(|command|
            matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (node, commit, tree)
}

#[test]
fn complete_native_archives_preserve_bytes_and_modes_in_both_domains_and_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, commit, tree) = safe_fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 3, true, false);
        let form = common(format);
        let first = archive(&server.client, 'a', &form, false);
        assert_eq!(first.status, 200, "{}", first.head);
        for (name, value) in [
            ("Content-Type", "application/x-tar"),
            ("Content-Disposition", "attachment; filename=\"source.tar\""),
            ("Cache-Control", "no-store"),
            ("Vary", "Authorization"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-FrankenGit-Archive-Profile", "ustar-source-v1"),
            ("X-FrankenGit-Archive-Gitlinks", "1"),
            ("X-FrankenGit-Archive-Entries", "7"),
        ] {
            assert_eq!(first.header(name), value);
        }
        assert_eq!(first.header("X-FrankenGit-Source-Commit"), commit.to_string());
        assert_eq!(first.header("X-FrankenGit-Root-Tree"), tree.to_string());
        assert_eq!(first.header("X-FrankenGit-Selected-Tree"), tree.to_string());
        let files = members(&first.body);
        assert_eq!(files.len(), 7);
        let raw_path = [b"source/".as_slice(), BINARY_PATH].concat();
        assert_eq!(files[&raw_path].data, BINARY);
        assert_eq!(files[&raw_path].mode, 0o644);
        let run = &files[b"source/dir/run".as_slice()];
        assert_eq!(run.mode, 0o755);
        assert_eq!(run.data, b"#!/bin/sh\nprintf hello\n");
        assert!(files[b"source/empty".as_slice()].data.is_empty());
        let link = &files[b"source/link".as_slice()];
        assert_eq!(link.kind, b'2');
        assert_eq!(link.link, b"dir/run");
        assert!(link.data.is_empty());
        let module = &files[b"source/module/".as_slice()];
        assert_eq!(module.kind, b'5');
        assert!(module.data.is_empty());
        let pinned = format!(
            "{form}&expected_head={}&expected_commit={commit}",
            first.header("X-FrankenGit-Snapshot-Token")
        );
        let repeated = archive(&server.client, 'a', &pinned, true);
        assert_eq!(repeated.status, 200);
        assert_eq!(repeated.body, first.body);
        assert_eq!(repeated.head, first.head);
        let subtree = archive(&server.client, 'a', &(pinned.clone() + "&path_hex=646972"), false);
        assert_eq!(subtree.status, 200);
        assert_eq!(subtree.header("X-FrankenGit-Root-Tree"), tree.to_string());
        assert_ne!(subtree.header("X-FrankenGit-Selected-Tree"), tree.to_string());
        let selected = members(&subtree.body);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[b"source/run".as_slice()].mode, 0o755);
        assert_eq!(server.finish().accepted_sessions(), 3);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        let session = LoopbackReceiveSession::authenticated(
            OWNER,
            IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap(),
        );
        assert!(matches!(
            node.runtime()
                .block_on(node.recover_transaction_in(&node.request_context(), &session))
                .unwrap(),
            RequestRecovery::KeyNotObserved
        ));
        let server = Server::start(node, &path, 1, true, false);
        let restarted = archive(&server.client, 'a', &pinned, false);
        assert_eq!(restarted.status, 200);
        assert_eq!(restarted.body, first.body);
        assert_eq!(restarted.head, first.head);
        assert_eq!(server.finish().accepted_sessions(), 1);
    }
}

#[test]
fn unsafe_symlink_refuses_the_whole_export_without_hiding_its_safe_subtree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, _) = fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        credentials(&node, &path);
        let server = Server::start(node, &path, 2, true, false);
        let refused = archive(&server.client, 'a', &common(format), false);
        refused.error(409, "source_archive_profile_refused");
        let message = std::str::from_utf8(&refused.body).unwrap();
        assert!(!message.contains("outside-secret") && !message.contains("../../"));
        let permitted = archive(
            &server.client, 'a', &(common(format) + "&path_hex=646972"), true,
        );
        assert_eq!(permitted.status, 200);
        assert_eq!(
            members(&permitted.body)[b"source/nested.txt".as_slice()].data,
            b"needle in nested\n"
        );
        assert_eq!(server.finish().accepted_sessions(), 2);
        let node = reopen(&config);
        assert_eq!(generation(&node), before);
        node.shutdown().unwrap();
    }
}

#[test]
fn archive_authentication_precedes_body_intake_and_read_scope_never_grants_mutation() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha1;
    let config = root.config(format);
    let (node, _, _) = safe_fixture(&root, format);
    let before = generation(&node);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 1, false, false);
    archive(&server.client, 'a', &common(format), false).error(403, "forbidden");
    assert_eq!(server.finish().accepted_sessions(), 1);
    let server = Server::start(reopen(&config), &path, 8, true, true);
    for (token, extra, expected, code) in [
        ('b', "", 403, "forbidden"),
        ('c', "", 403, "forbidden"),
        ('a', "Idempotency-Key: forbidden-read-key\r\n", 400, "source_read_has_no_transaction_key"),
    ] {
        let wire = request(
            &server.client, "/api/v1/source/archive", token,
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n{extra}"
            ),
            &[],
        );
        binary_exchange(&server.client, &wire, false).error(expected, code);
    }
    for extra in ["&principal=admin", "&after_hex=61"] {
        archive(&server.client, 'a', &(common(format) + extra), false)
            .error(400, "unknown_or_inapplicable_field");
    }
    let form = common(format);
    let incomplete = request(
        &server.client, "/api/v1/source/archive", 'a',
        &format!(
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n",
            form.len() + 1
        ),
        form.as_bytes(),
    );
    let refused = binary_exchange(&server.client, &incomplete, true);
    assert_eq!(refused.status, 400);
    assert!(!refused.head.contains("application/x-tar"));
    let body = b"expected_version=0&title=Denied&body=";
    let mutation = exchange(
        &server.client,
        &request(
            &server.client, "/api/v1/issues/1/open", 'a',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: source-cannot-write\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&mutation, 403);
    assert_eq!(archive(&server.client, 'a', &form, false).status, 200);
    assert_eq!(server.finish().accepted_sessions(), 8);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

#[test]
fn archive_head_preconditions_reject_intervening_forge_writes_and_wrong_commits() {
    let root = Scratch::new();
    let format = GitHashAlgorithm::Sha256;
    let (node, commit, _) = safe_fixture(&root, format);
    let path = root.0.join("credentials");
    credentials(&node, &path);
    let server = Server::start(node, &path, 5, true, true);
    let form = common(format);
    let first = archive(&server.client, 'a', &form, false);
    assert_eq!(first.status, 200);
    let body = b"expected_version=0&title=Intervening+issue&body=";
    let changed = exchange(
        &server.client,
        &request(
            &server.client, "/api/v1/issues/1/open", 'b',
            &format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: source-archive-pin-change\r\n",
                body.len()
            ),
            body,
        ),
        true,
    );
    status(&changed, 200);
    let stale = archive(
        &server.client, 'a',
        &format!(
            "{form}&expected_head={}&expected_commit={commit}",
            first.header("X-FrankenGit-Snapshot-Token")
        ),
        false,
    );
    stale.error(409, "source_snapshot_moved");
    let wrong = archive(
        &server.client, 'a',
        &format!("{form}&expected_commit={}", "ab".repeat(format.digest_len())),
        false,
    );
    wrong.error(409, "source_commit_moved");
    let fresh = archive(
        &server.client, 'a', &format!("{form}&expected_commit={commit}"), true,
    );
    assert_eq!(fresh.status, 200);
    assert_eq!(fresh.body, first.body);
    assert_ne!(
        fresh.header("X-FrankenGit-Snapshot-Token"),
        first.header("X-FrankenGit-Snapshot-Token")
    );
    assert_eq!(server.finish().accepted_sessions(), 5);
}
