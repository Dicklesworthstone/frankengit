#![forbid(unsafe_code)]
//! End-to-end source editing through real HTTP/native objects/authority.
//! Preparation never invokes a local planner in place of the remote endpoint.
#[path = "source_change_http/support.rs"]
mod support;
use support::*;

use std::io::Write;
use std::net::Shutdown;
use std::sync::{Arc, Barrier};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, RefName};

#[test]
fn remote_multi_file_patch_inspects_and_publishes_exactly_once_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, base) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = Server::start(node, &path, 4, true, true);
        let original_file = blob(&server.client, format, b"alpha.txt"); // 1
        status(&original_file, 200); assert_eq!(text(&original_file.body, "content_hex"), hex(TEXT));
        let response = prepare(&server.client, base, &patch(), "Remote+exact+edit", false); // 2
        let artifact = extract(&response, format);
        assert_eq!(prepare(&server.client, base, &patch(), "Remote+exact+edit", true), response); // 3
        let inspection = inspect(&server.client, base, &artifact); // 4
        status(&inspection, 200);
        assert!(inspection.body.contains("\"type\":\"source_inspection\""));
        assert!(inspection.body.contains("\"all_changed_paths\":true"));
        assert!(inspection.body.contains("\"publication_authorized\":false"));
        assert!(inspection.body.contains(&hex(b"Edited needle\r\nababa\n")));
        assert!(inspection.body.contains(&hex(b"no final newline")));
        assert!(inspection.body.contains("\"kind\":\"deleted\""));
        assert!(inspection.body.contains("\"kind\":\"mode_changed\""));
        let commit = unhex(text(&inspection.body, "candidate_commit_body_hex"));
        assert_eq!(git_object_id(format, GitObjectKind::Commit, &commit), artifact.commit);
        assert!(commit.ends_with(b"Remote exact edit\n"));
        assert_eq!(server.finish().accepted_sessions(), 4);
        let node = reopen(&config); assert_eq!(generation(&node), before);
        assert!(node.read_git_object(artifact.commit).is_err(), "preparation and inspection must not stage the commit");
        let new_blob = git_object_id(format, GitObjectKind::Blob, b"no final newline");
        assert!(node.read_git_object(new_blob).is_err());
        assert!(artifact.metadata.contains("\"transaction_created\":false"));
        let server = Server::start(node, &path, 10, true, true);
        assert_eq!(prepare(&server.client, base, &patch(), "Remote+exact+edit", false), response); // 1
        assert_eq!(inspect(&server.client, base, &artifact), inspection); // 2
        // Receive-only credential can publish but cannot inspect source.
        let accepted = apply(&server.client, base, &artifact, "source-edit-1", false); // 3
        committed(&accepted);
        assert_eq!(apply(&server.client, base, &artifact, "source-edit-1", true), accepted); // 4
        let edited = blob(&server.client, format, b"alpha.txt"); // 5
        status(&edited, 200); assert_eq!(text(&edited.body, "content_hex"), hex(b"Edited needle\r\nababa\n"));
        let new_file = blob(&server.client, format, b"new.txt"); // 6
        status(&new_file, 200); assert_eq!(text(&new_file.body, "content_hex"), hex(b"no final newline"));
        status(&blob(&server.client, format, b"empty"), 404); // 7
        let mode = blob(&server.client, format, b"run"); // 8
        status(&mode, 200); assert_eq!(text(&mode.body, "kind"), "file");
        assert_eq!(text(&mode.body, "content_hex"), hex(b"#!/bin/sh\nneedle\n"));
        let sibling = blob(&server.client, format, BINARY_PATH); // 9
        status(&sibling, 200); assert_eq!(text(&sibling.body, "content_hex"), hex(BINARY));
        let recovered = recover(&server.client, 'c', "source-edit-1"); // 10
        status(&recovered, 200); assert_eq!(text(&recovered.body, "state"), "committed");
        assert_eq!(text(&recovered.body, "tx_id"), text(&accepted.body, "tx_id"));
        assert_eq!(server.finish().accepted_sessions(), 10);
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()], artifact.commit);
        assert!(node.read_git_object(new_blob).is_ok());
        node.shutdown().unwrap();
    }
}

#[test]
fn competing_remote_edits_keep_expected_old_and_stable_terminal_retries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, base) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); configure(&node, &path);
        let server = Server::start(node, &path, 2, true, true);
        let left = extract(&prepare(&server.client, base, &patch(), "Left+editor", false), format);
        let right_patch = String::from_utf8(patch()).unwrap().replace("Edited needle", "Other needle");
        let right = extract(&prepare(&server.client, base, right_patch.as_bytes(), "Right+editor", true), format);
        assert_ne!(left.commit, right.commit); server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before);
        let server = Server::start(node, &path, 8, true, true);
        let barrier = Arc::new(Barrier::new(2));
        let (a, b) = std::thread::scope(|scope| {
            let first = Arc::clone(&barrier); let second = Arc::clone(&barrier);
            let client = &server.client;
            let a = scope.spawn(|| { first.wait(); apply(client, base, &left, "editor-left", false) });
            let b = scope.spawn(|| { second.wait(); apply(client, base, &right, "editor-right", true) });
            (a.join().unwrap(), b.join().unwrap())
        }); // 1, 2
        let (winner, winner_key, winner_reply, loser) = match (a.status, b.status) {
            (200, 409) => (&left, "editor-left", &a, &b),
            (409, 200) => (&right, "editor-right", &b, &a),
            _ => panic!("one native commit and one native refusal expected: {a:?}; {b:?}"),
        };
        committed(winner_reply); assert_eq!(text(&loser.body, "outcome"), "refused");
        assert_eq!(apply(&server.client, base, &left, "editor-left", true), a); // 3
        assert_eq!(apply(&server.client, base, &right, "editor-right", false), b); // 4
        let recovered_a = recover(&server.client, 'c', "editor-left"); // 5
        let recovered_b = recover(&server.client, 'c', "editor-right"); // 6
        assert_eq!(text(&recovered_a.body, "tx_id"), text(&a.body, "tx_id"));
        assert_eq!(text(&recovered_b.body, "tx_id"), text(&b.body, "tx_id"));
        let current = blob(&server.client, format, b"alpha.txt"); // 7
        status(&current, 200); assert_eq!(text(&current.body, "source_commit"), winner.commit.to_string());
        let changed = if winner.commit == left.commit { &right } else { &left };
        let reuse = apply(&server.client, base, changed, winner_key, false); // 8
        status(&reuse, 409); assert!(reuse.body.contains("idempotency_key_reuse"));
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config); assert_eq!(generation(&node), before + 2, "commit and refusal only; retries and key conflicts publish nothing");
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()], winner.commit);
        node.shutdown().unwrap();
    }
}

fn withheld(client: &Endpoint, action: &str, token: char, headers: &str, length: usize) -> Reply {
    let reply = exchange(client, &request(client, &format!("/api/v1/source/{action}"), token,
        &format!("Content-Type: multipart/form-data; boundary=source-edit\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{headers}"), &[]), false);
    assert!(!reply.raw.contains("100 Continue")); reply
}
#[test]
fn source_reads_and_writes_keep_independent_gates_and_refuse_partial_inputs() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new(); let config = root.config(format);
    let (node, base) = fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); configure(&node, &path);
    let disabled = Server::start(node, &path, 2, false, true);
    status(&withheld(&disabled.client, "prepare", 'a', "", 100), 403);
    status(&withheld(&disabled.client, "apply", 'b', "Idempotency-Key: disabled\r\n", 100), 403);
    disabled.finish();
    let node = reopen(&config);
    let read_only = Server::start(node, &path, 3, true, false);
    let response = prepare(&read_only.client, base, &patch(), "Bounded+edit", false);
    let artifact = extract(&response, format);
    status(&withheld(&read_only.client, "apply", 'b', "Idempotency-Key: read-only\r\n", 100), 403);
    status(&withheld(&read_only.client, "inspect", 'b', "", 100), 403);
    read_only.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 13, true, true);
    status(&withheld(&server.client, "apply", 'a', "Idempotency-Key: no-write\r\n", 100), 403); // 1
    status(&withheld(&server.client, "prepare", 'b', "", 100), 403); // 2
    status(&withheld(&server.client, "inspect", 'b', "", 100), 403); // 3
    status(&withheld(&server.client, "prepare", 'a', "Idempotency-Key: no-read-key\r\n", 100), 400); // 4
    status(&withheld(&server.client, "apply", 'b', "", 100), 400); // 5
    status(&withheld(&server.client, "apply", 'b', "Idempotency-Key: a\r\nIdempotency-Key: b\r\n", 100), 400); // 6
    status(&withheld(&server.client, "prepare", 'a', "", 17 * 1024 * 1024), 413); // 7
    let wrong_context = String::from_utf8(patch()).unwrap().replace("-Needle needle", "-Wrong context");
    let refused = prepare(&server.client, base, wrong_context.as_bytes(), "Bad+context", false); // 8
    assert_eq!(refused.status, 409); assert!(String::from_utf8(refused.body).unwrap().contains("patch_context_mismatch"));
    let invalid_path = String::from_utf8(patch()).unwrap().replace("alpha.txt", "../outside-secret");
    assert_eq!(prepare(&server.client, base, invalid_path.as_bytes(), "Bad+path", false).status, 400); // 9
    let mut truncated = change_bytes(&server.client, "prepare", 'a', None, &metadata(base, "Truncated"), &patch(), false);
    truncated.pop();
    status(&exchange(&server.client, &truncated, true), 400); // 10
    let mut incomplete_apply = change_bytes(&server.client, "apply", 'b', Some("incomplete"),
        &candidate_form(base, artifact.commit), &artifact.bundle, true);
    incomplete_apply.truncate(incomplete_apply.len() - 2);
    status(&exchange(&server.client, &incomplete_apply, true), 400); // 11
    let mut corrupt = artifact.clone(); let last = corrupt.bundle.last_mut().unwrap(); *last ^= 1;
    let inspected = inspect(&server.client, base, &corrupt); // 12
    status(&inspected, 503); assert!(!inspected.body.contains("candidate_commit_body_hex"));
    status(&inspect(&server.client, base, &artifact), 200); // 13, permitted twin
    assert_eq!(server.finish().accepted_sessions(), 13);
    let node = reopen(&config); assert_eq!(generation(&node), before);
    assert!(node.read_git_object(artifact.commit).is_err()); node.shutdown().unwrap();
}

#[test]
fn lost_source_receipt_recovers_after_restart_with_write_permission_revoked() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, base) = fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); let header = configure(&node, &path);
        let server = Server::start(node, &path, 1, true, true);
        let artifact = extract(&prepare(&server.client, base, &patch(), "Lost+reply", false), format);
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before);
        let server = Server::start(node, &path, 1, true, true);
        let bytes = change_bytes(&server.client, "apply", 'b', Some("lost-source-edit"),
            &candidate_form(base, artifact.commit), &artifact.bundle, false);
        let mut socket = connect(&server.client);
        socket.write_all(&bytes).unwrap(); socket.shutdown(Shutdown::Write).unwrap();
        drop(socket); // Intentionally discard the receipt; do not infer rollback.
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        replace(&path, &(header + &row('9', OWNER, "outcomes-read") + &row('d', FOREIGN, "outcomes-read")));
        let server = Server::start(node, &path, 5, false, false);
        let recovered = recover(&server.client, '9', "lost-source-edit"); // 1
        status(&recovered, 200); assert_eq!(text(&recovered.body, "state"), "committed");
        assert_eq!(recover(&server.client, '9', "lost-source-edit"), recovered); // 2
        let foreign = recover(&server.client, 'd', "lost-source-edit"); // 3
        status(&foreign, 200); assert_eq!(text(&foreign.body, "state"), "key_not_observed");
        status(&apply(&server.client, base, &artifact, "lost-source-edit", false), 401); // 4, old write token gone
        let missing = recover(&server.client, '9', "unobserved-edit"); // 5
        status(&missing, 200); assert_eq!(text(&missing.body, "state"), "key_not_observed");
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 1);
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()], artifact.commit);
        node.shutdown().unwrap();
    }
}
