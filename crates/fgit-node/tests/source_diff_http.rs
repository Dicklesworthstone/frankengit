#![forbid(unsafe_code)]
//! Production TCP listener -> native source review -> embedded authority.
//! Tests do not invoke Git, a worktree, or a replacement comparison engine.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, key_recovery::RequestRecovery};
use fgit_forge::history::LogOptions;
use fgit_node::{LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};

fn comparison_fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid, GitOid) {
    let (node, main) = fixture(root, format);
    let request = node.request_context();
    let (_, page) = node.runtime().block_on(node.read_commit_history_in(&request,
        &RefName::try_new(b"refs/heads/main").unwrap(), &Default::default(), None, LogOptions::default())).unwrap();
    let base = page.commits[1].id;
    let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"diff-base-branch".to_vec()).unwrap());
    let commands = [RefCommand { name: RefName::try_new(b"refs/heads/base").unwrap(),
        expected_old: ExpectedOld::Absent, proposed_new: ProposedNew::Update(base), force: false }];
    let result = node.runtime().block_on(node.admit_branch_updates_durable_in(&request, &session, &commands, Default::default())).unwrap();
    assert!(result.commands.iter().all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. })));
    (node, base, main)
}
fn query(format: GitHashAlgorithm) -> String {
    format!("object_format={}&before_ref=refs/heads/base&after_ref=refs/heads/main", format.as_str())
}
fn assert_no_read_transaction(node: &OneNode) {
    let session = LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(b"read-only-source-query".to_vec()).unwrap());
    assert!(matches!(node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &session)).unwrap(), RequestRecovery::KeyNotObserved));
}

#[test]
fn both_formats_return_exact_changed_entries_context_and_pins_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, base, main) = comparison_fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); credentials(&node, &path);
        let server = Server::start(node, &path, 8, true, false);
        let query = query(format);
        let first = post(&server.client, "diff", 'a', &query, false); // 1
        status(&first, 200);
        assert_eq!(text(&first.body, "requested_before"), base.to_string());
        assert_eq!(text(&first.body, "requested_after"), main.to_string());
        assert_eq!(text(&first.body, "compared_before"), base.to_string());
        assert_eq!(number(&first.body, "entry_count"), 8);
        assert!(first.body.contains("\"complete\":true"));
        assert!(first.body.contains("\"approval_created\":false"));
        assert!(first.body.contains(&format!("\"after_hex\":\"{}\"", hex(TEXT))));
        assert!(first.body.contains(&format!("\"path_hex\":\"{}\"", hex(BINARY_PATH))));
        assert!(first.body.contains(&format!("\"kind\":\"binary\",\"before_bytes\":0,\"after_bytes\":{}", BINARY.len())));
        assert!(first.body.contains("\"kind\":\"object_only\""));
        assert!(first.body.contains("\"mode\":\"100755\""));
        assert!(first.body.contains("\"mode\":\"120000\""));
        assert!(first.body.contains("\"mode\":\"160000\""));
        let pin = token(&first);
        let pinned = format!("{query}&expected_head={pin}&expected_before={base}&expected_after={main}");
        assert_eq!(post(&server.client, "diff", 'a', &pinned, true), first); // 2
        let merge_base = post(&server.client, "diff", 'a', &(query.clone() + "&mode=merge-base"), true); // 3
        status(&merge_base, 200); assert_eq!(text(&merge_base.body, "compared_before"), base.to_string());
        let selected = post(&server.client, "diff", 'a', &(query.clone() + "&path_prefix_hex=646972&context_lines=0"), false); // 4
        status(&selected, 200); assert_eq!(number(&selected.body, "entry_count"), 2);
        assert!(!selected.body.contains(&hex(TEXT))); assert!(!selected.body.contains(&hex(BINARY_PATH)));
        let empty = post(&server.client, "diff", 'a', &(query.clone() + "&path_prefix_hex=6469"), false); // 5
        status(&empty, 200); assert_eq!(number(&empty.body, "entry_count"), 0);
        let reverse = post(&server.client, "diff", 'a', &query.replace("before_ref=refs/heads/base&after_ref=refs/heads/main",
            "before_ref=refs/heads/main&after_ref=refs/heads/base"), false); // 6
        status(&reverse, 200); assert!(reverse.body.contains("\"kind\":\"deleted\""));
        assert!(reverse.body.contains(&format!("\"before_hex\":\"{}\"", hex(TEXT))));
        let unchanged = post(&server.client, "diff", 'a', &query.replace("before_ref=refs/heads/base", "before_ref=refs/heads/main"), false); // 7
        status(&unchanged, 200); assert_eq!(number(&unchanged.body, "entry_count"), 0);
        status(&post(&server.client, "diff", 'a', &(query.clone() + "&expected_before=" + &main.to_string()), false), 409); // 8
        assert_eq!(server.finish().accepted_sessions(), 8);
        let node = reopen(&config); assert_eq!(generation(&node), before); assert_no_read_transaction(&node);
        let server = Server::start(node, &path, 1, true, false);
        assert_eq!(post(&server.client, "diff", 'a', &pinned, true), first);
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before); node.shutdown().unwrap();
    }
}

#[test]
fn credentials_and_budgets_refuse_without_a_successful_partial_diff() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new(); let config = root.config(format);
    let (node, _, _) = comparison_fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); let header = credentials(&node, &path);
    let server = Server::start(node, &path, 9, true, false);
    let query = query(format);
    for (token, extra, expected) in [('b', "", 403), ('f', "", 401),
        ('a', "&max_changes=1", 413), ('a', "&max_blob_bytes=1", 413),
        ('a', "&max_output_bytes=1", 413), ('a', "&force=true", 400)] {
        let reply = post(&server.client, "diff", token, &(query.clone() + extra), false);
        status(&reply, expected);
        assert!(!reply.body.contains("\"entries\":[]")); assert!(!reply.body.contains("\"complete\":true"));
    }
    // Refuse a transaction key before consuming a withheld body/100-continue.
    let bytes = request(&server.client, "/api/v1/source/diff", 'a',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\nIdempotency-Key: forbidden-read-key\r\n", b"");
    status(&exchange(&server.client, &bytes, false), 400); // 7
    status(&post(&server.client, "diff", 'a', &query.replace("refs/heads/base", "refs/heads/absent"), false), 404); // 8
    status(&post(&server.client, "diff", 'a', &query, true), 200); // 9
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before); assert_no_read_transaction(&node);
    replace(&path, &(header + &row('9', OWNER, "read")));
    let server = Server::start(node, &path, 2, true, false);
    status(&post(&server.client, "diff", 'a', &query, false), 401);
    status(&post(&server.client, "diff", '9', &query, false), 200);
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, false, false);
    status(&post(&server.client, "diff", '9', &query, false), 403);
    server.finish();
}

#[test]
fn an_intervening_metadata_write_invalidates_the_exact_comparison_snapshot() {
    let format = GitHashAlgorithm::Sha256;
    let root = Scratch::new(); let config = root.config(format);
    let (node, _, _) = comparison_fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); credentials(&node, &path);
    let server = Server::start(node, &path, 4, true, true);
    let query = query(format);
    let original = post(&server.client, "diff", 'a', &query, false); status(&original, 200);
    let body = b"expected_version=0&title=Intervening+write&body=";
    let written = exchange(&server.client, &request(&server.client, "/api/v1/issues/1/open", 'b',
        &format!("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nIdempotency-Key: diff-pin-write\r\n", body.len()), body), true);
    status(&written, 200); assert!(written.body.contains("\"outcome\":\"committed\""));
    let stale = post(&server.client, "diff", 'a', &format!("{query}&expected_head={}", token(&original)), true);
    status(&stale, 409); assert!(stale.body.contains("source_snapshot_moved"));
    let fresh = post(&server.client, "diff", 'a', &query, false); status(&fresh, 200);
    assert_ne!(token(&fresh), token(&original));
    assert_eq!(number(&fresh.body, "entry_count"), number(&original.body, "entry_count"));
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before + 1); assert_no_read_transaction(&node); node.shutdown().unwrap();
}
