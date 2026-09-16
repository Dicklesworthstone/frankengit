#![forbid(unsafe_code)]
//! Real TCP -> authenticated native PR handlers -> embedded authority -> reopen.
//! These tests do not replace the node, projection, or Git object validator.

#[path = "pull_request_http/support.rs"]
mod support;

use std::io::{Read, Write};
use std::sync::{Arc, Barrier};
use std::thread;

use fgit_authority::{IdempotencyKey, OutcomeLookup};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm};
use fgit_wire::visibility::RefVisibility;
use support::*;

#[test]
fn native_pr_lifecycle_keeps_retained_pages_retry_outcomes_and_git_refs_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let before = generation(&node);
        let (refs, outbox) = {
            let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
            (selected.snapshot().refs.clone(), selected.snapshot().outbox.len())
        };
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, &path, 18, true, false);
        let client = &server.client;
        let original = post(client, 7, "open", 'b', "open-seven", &form(&data, 0), false); // 1
        committed(&original);
        assert!(original.body.contains(&OWNER.to_string()));
        assert_eq!(post(client, 7, "open", 'b', "open-seven", &form(&data, 0), true), original); // 2
        committed(&post(client, 9, "open", 'b', "open-nine", &form(&data, 0), true)); // 3
        let first = get(client, "/api/v1/pulls?limit=1", 'a'); // 4
        status(&first, 200);
        assert!(first.body.contains("\"number\":7"));
        assert!(first.body.contains("\"next_after\":7"));
        let snapshot = token(&first);
        let mut updated = data.clone();
        updated.title = "Updated title".into();
        updated.body.clear();
        committed(&post(client, 7, "update", 'b', "update-seven", &form(&updated, 1), false)); // 5
        let stale = post(client, 7, "update", 'b', "stale-seven", &form(&data, 1), false); // 6
        status(&stale, 409);
        assert!(stale.body.contains("\"outcome\":\"refused\""));
        assert_eq!(post(client, 7, "update", 'b', "stale-seven", &form(&data, 1), true), stale); // 7
        let reused = post(client, 7, "open", 'b', "open-seven", &form(&updated, 0), false); // 8
        status(&reused, 409);
        assert!(reused.body.contains("\"type\":\"pull_request_error\""));
        assert!(reused.body.contains("\"code\":\"idempotency_key_reuse\""));
        assert!(!reused.body.contains("\"outcome\":\"refused\""));
        committed(&post(client, 8, "open", 'b', "open-eight", &form(&data, 0), false)); // 9
        let next = get(client, &format!("/api/v1/pulls?after=7&limit=1&expected_head={snapshot}"), 'a'); // 10
        status(&next, 200);
        assert_eq!(token(&next), snapshot);
        assert!(next.body.contains("\"number\":9"));
        assert!(!next.body.contains("\"number\":8"));
        assert!(next.body.contains("\"next_after\":null"));
        let old = get(client, &format!("/api/v1/pulls/7?expected_head={snapshot}"), 'a'); // 11
        status(&old, 200);
        assert!(old.body.contains("\"title\":\"Original 🦀\""));
        assert!(old.body.contains("\"version\":1"));
        let current = get(client, "/api/v1/pulls/7", 'a'); // 12
        status(&current, 200);
        assert!(current.body.contains("\"title\":\"Updated title\""));
        assert!(current.body.contains("\"version\":2"));
        let missing = get(client, "/api/v1/pulls/6", 'a'); // 13
        status(&missing, 404);
        assert!(missing.body.contains("\"found\":false,\"pull_request\":null"));
        assert!(!missing.body.contains("source_ref"), "a missing-number lookup must not disclose the next visible PR");
        let closed = post(client, 7, "close", 'b', "close-seven", &form(&updated, 2), true); // 14
        committed(&closed);
        assert_eq!(post(client, 7, "close", 'b', "close-seven", &form(&updated, 2), false), closed); // 15
        let current = get(client, "/api/v1/pulls/7", 'a'); // 16
        status(&current, 200);
        assert!(current.body.contains("\"version\":3,\"state\":\"closed\""));
        assert_eq!(get(client, &format!("/api/v1/pulls/7?expected_head={snapshot}"), 'a'), old); // 17
        let fresh = get(client, "/api/v1/pulls", 'a'); // 18
        status(&fresh, 200);
        assert!(fresh.body.contains("\"number\":8"));
        assert_eq!(server.finish().accepted_sessions(), 18);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 6, "five PR commits and one canonical refusal, no retry decisions");
        let selected = node.runtime().block_on(node.materialize_admission()).unwrap();
        assert_eq!(selected.snapshot().refs, refs, "metadata operations cannot change either branch");
        assert_eq!(selected.snapshot().outbox.len(), outbox + 5, "each committed PR event has its delivery obligation");
        node.shutdown().unwrap();
    }
}

fn withheld(client: &Endpoint, token: char, key: bool, length: usize) -> Reply {
    let key = if key { "Idempotency-Key: withheld\r\n" } else { "" };
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {length}\r\nExpect: 100-continue\r\n{key}");
    let result = exchange(client, &request(client, "POST", "/api/v1/pulls/1/open", token, &headers, &[]), false);
    assert!(!result.raw.contains("100 Continue"));
    result
}

#[test]
fn unrelated_scopes_forged_identity_and_incomplete_bodies_cannot_publish_pr_state() {
    let root = Scratch::new();
    let config = root.config(GitHashAlgorithm::Sha1);
    let (node, data) = fixture(&root, GitHashAlgorithm::Sha1);
    let before = generation(&node);
    let path = root.0.join("credentials");
    grants(&node, &path);
    let server = Server::start(node, &path, 17, true, true);
    let client = &server.client;
    status(&withheld(client, 'a', true, 64), 403); // 1: a PR reader cannot mutate.
    status(&get(client, "/api/v1/pulls", 'b'), 403); // 2: PR write does not imply read.
    status(&get(client, "/api/v1/pulls", 'd'), 403); // 3: no old service scope implies PR access.
    status(&get(client, "/info/refs?service=git-upload-pack", 'b'), 403); // 4
    status(&get(client, "/api/v1/issues", 'a'), 403); // 5
    status(&exchange(client, &request(client, "POST", "/api/v1/outcomes", 'b',
        "Content-Length: 0\r\nIdempotency-Key: no-recovery-grant\r\n", &[]), true), 403); // 6
    let forged = format!("POST {}/api/v1/pulls/1/open HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 64\r\nX-Forwarded-User: owner\r\nIdempotency-Key: forged\r\nExpect: 100-continue\r\n\r\n", client.route);
    let denied = exchange(client, forged.as_bytes(), false); // 7
    status(&denied, 401);
    assert!(!denied.raw.contains("100 Continue"));
    status(&withheld(client, 'b', false, 64), 400); // 8
    let body = form(&data, 0);
    status(&post(client, 1, "open", 'b', "wrong-format", &body.replace("object_format=sha1", "object_format=sha256"), false), 400); // 9
    let invalid_utf8 = body.rsplit_once("&body=").unwrap().0.to_owned() + "&body=%FF";
    status(&post(client, 1, "open", 'b', "bad-text", &invalid_utf8, false), 400); // 10
    let duplicate = post(client, 1, "open", 'b', "duplicate", &(body.clone() + "&title=another"), false); // 11
    assert!(matches!(duplicate.status, 400 | 413));
    let headers = format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: truncated\r\n", body.len() + 1);
    status(&exchange(client, &request(client, "POST", "/api/v1/pulls/1/open", 'b', &headers, body.as_bytes()), true), 400); // 12
    let wire = format!("{:x}\r\n{body}\r\n0\r\n", body.len());
    status(&exchange(client, &request(client, "POST", "/api/v1/pulls/1/open", 'b',
        "Content-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nIdempotency-Key: incomplete-chunks\r\n", wire.as_bytes()), true), 400); // 13
    status(&withheld(client, 'b', true, 256 * 1024 + 1), 413); // 14
    let wrong_route = format!("GET /other.git/api/v1/pulls HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer {}\r\n\r\n", "a".repeat(64));
    status(&exchange(client, wrong_route.as_bytes(), true), 404); // 15
    let empty = get(client, "/api/v1/pulls", 'a'); // 16
    status(&empty, 200);
    assert!(empty.body.contains("\"pull_requests\":[]"));
    status(&get(client, "/api/v1/pulls/1", 'a'), 404); // 17
    assert_eq!(server.finish().accepted_sessions(), 17);
    let node = reopen(&config);
    assert_eq!(generation(&node), before);
    node.shutdown().unwrap();
}

fn lookup(client: &Endpoint, token: char, key: &str) -> Reply {
    exchange(client, &request(client, "POST", "/api/v1/outcomes", token,
        &format!("Content-Length: 0\r\nIdempotency-Key: {key}\r\n"), &[]), true)
}

#[test]
fn a_lost_pr_reply_is_recovered_after_restart_and_write_revocation_without_reexecution() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        let header = grants(&node, &path);
        let server = Server::start(node, &path, 1, true, false);
        let body = form(&data, 0);
        let bytes = request(&server.client, "POST", "/api/v1/pulls/1/open", 'b',
            &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: lost-pr-reply\r\n", body.len()), body.as_bytes());
        let mut socket = connection(&server.client);
        socket.write_all(&bytes).unwrap();
        let mut first = [0; 1];
        socket.read_exact(&mut first).unwrap();
        assert_eq!(first, [b'H']); // Client has no JSON receipt and no transaction ID.
        drop(socket);
        server.finish();
        let node = reopen(&config);
        let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"lost-pr-reply".to_vec()).unwrap());
        let known = node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &session)).unwrap();
        let fgit_authority::key_recovery::RequestRecovery::Recovered(known) = known else { panic!("real PR seal must exist") };
        let OutcomeLookup::Decided(terminal) = known.outcome() else { panic!("real PR must be terminal") };
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        replace(&path, &(header + &row('f', OWNER, "outcomes-read") + &row('e', FOREIGN, "outcomes-read")));
        let server = Server::start(node, &path, 5, false, true);
        let recovered = lookup(&server.client, 'f', "lost-pr-reply"); // 1
        status(&recovered, 200);
        assert!(recovered.body.contains("\"state\":\"committed\""));
        assert!(recovered.body.contains(&format!("\"tx_id\":\"{}\"", known.tx_id())));
        assert!(recovered.body.contains("\"request_reexecuted\":false"));
        assert!(!recovered.body.contains("lost-pr-reply"));
        assert_eq!(lookup(&server.client, 'f', "lost-pr-reply"), recovered); // 2
        status(&get(&server.client, "/api/v1/pulls/1", 'f'), 403); // 3
        status(&lookup(&server.client, 'b', "lost-pr-reply"), 401); // 4: original token revoked.
        let foreign = lookup(&server.client, 'e', "lost-pr-reply"); // 5
        status(&foreign, 200);
        assert!(foreign.body.contains("\"state\":\"key_not_observed\""));
        assert!(!foreign.body.contains(&known.tx_id().to_string()));
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1, "lookups cannot repeat the original PR mutation");
        let page = node.runtime().block_on(node.read_pull_requests_in(&node.request_context(),
            &RefVisibility::new(), 0, 10, None)).unwrap();
        assert_eq!(page.pull_requests.len(), 1);
        assert_eq!(page.pull_requests[0].data, Some(data));
        node.shutdown().unwrap();
    }
}

#[test]
fn competing_http_editors_keep_one_winner_and_each_exact_retry_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, data) = fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        grants(&node, &path);
        let server = Server::start(node, &path, 6, true, false);
        committed(&post(&server.client, 1, "open", 'b', "open", &form(&data, 0), false));
        let barrier = Arc::new(Barrier::new(3));
        let mut editors = Vec::new();
        for title in ["Left", "Right"] {
            let client = server.client.clone();
            let barrier = Arc::clone(&barrier);
            let mut change = data.clone();
            change.title = title.into();
            editors.push(thread::spawn(move || {
                barrier.wait();
                (title, post(&client, 1, "update", 'b', title, &form(&change, 1), false))
            }));
        }
        barrier.wait();
        let replies: Vec<_> = editors.into_iter().map(|worker| worker.join().unwrap()).collect();
        let mut statuses: Vec<_> = replies.iter().map(|(_, reply)| reply.status).collect();
        statuses.sort_unstable();
        assert_eq!(statuses, [200, 409], "{replies:?}");
        let winner = replies.iter().find(|(_, reply)| reply.status == 200).unwrap().0;
        for (title, reply) in &replies {
            let mut change = data.clone();
            change.title = (*title).into();
            assert_eq!(&post(&server.client, 1, "update", 'b', title, &form(&change, 1), true), reply);
        }
        let current = get(&server.client, "/api/v1/pulls/1", 'a');
        status(&current, 200);
        assert!(current.body.contains(&format!("\"title\":\"{winner}\"")));
        assert!(current.body.contains("\"version\":2"));
        assert_eq!(server.finish().accepted_sessions(), 6);
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 3, "open, winning edit, refused competitor; no retry decisions");
        let page = node.runtime().block_on(node.read_pull_requests_in(&node.request_context(),
            &RefVisibility::new(), 0, 10, None)).unwrap();
        assert_eq!(page.pull_requests[0].data.as_ref().unwrap().title, winner);
        assert_eq!(page.pull_requests[0].event.version.get(), 2);
        node.shutdown().unwrap();
    }
}

#[test]
fn a_well_formed_but_stale_source_tip_is_a_canonical_refusal_not_a_silent_refresh() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let config = root.config(format);
        let (node, mut data) = fixture(&root, format);
        let before = generation(&node);
        let path = root.0.join("credentials");
        grants(&node, &path);
        // This is a real admitted commit, but not the current source branch tip.
        data.source_tip = data.target_tip;
        let server = Server::start(node, &path, 3, true, false);
        let refused = post(&server.client, 1, "open", 'b', "stale-tip", &form(&data, 0), false);
        status(&refused, 409);
        assert!(refused.body.contains("\"outcome\":\"refused\""));
        assert!(refused.body.contains("\"refusal_code\":\"TargetRefMoved\""));
        assert_eq!(post(&server.client, 1, "open", 'b', "stale-tip", &form(&data, 0), true), refused);
        status(&get(&server.client, "/api/v1/pulls/1", 'a'), 404);
        server.finish();
        let node = reopen(&config);
        assert_eq!(generation(&node), before + 1);
        node.shutdown().unwrap();
    }
}
