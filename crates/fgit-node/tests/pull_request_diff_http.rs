#![forbid(unsafe_code)]
//! Real PR diffs through the production listener and canonical PR/ref engines.
#[path = "source_http/support.rs"]
mod support;
use support::*;

use std::net::TcpListener;
use std::path::Path;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, key_recovery::RequestRecovery};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::history::LogOptions;
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{GitDaemonServerLimits, GitDaemonServerReceipt, LoopbackReceiveSession, OneNode};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};

fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(key.to_vec()).unwrap())
}
fn branch(node: &OneNode, name: &[u8], old: ExpectedOld, new: ProposedNew, key: &[u8]) {
    let command = RefCommand { name: RefName::try_new(name).unwrap(), expected_old: old, proposed_new: new, force: false };
    let result = node.runtime().block_on(node.admit_branch_updates_durable_in(&node.request_context(),
        &session(key), &[command], Default::default())).unwrap();
    assert!(result.commands.iter().all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })));
}
fn pr_fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, PullRequestData) {
    let (node, main) = fixture(root, format);
    let (_, page) = node.runtime().block_on(node.read_commit_history_in(&node.request_context(),
        &RefName::try_new(b"refs/heads/main").unwrap(), &Default::default(), None, LogOptions::default())).unwrap();
    let base: GitOid = page.commits[1].id;
    branch(&node, b"refs/heads/base", ExpectedOld::Absent, ProposedNew::Update(base), b"pr-diff-base");
    branch(&node, b"refs/heads/topic", ExpectedOld::Absent, ProposedNew::Update(main), b"pr-diff-topic");
    let data = PullRequestData { source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/base").unwrap(), source_tip: main, target_tip: base,
        title: "Review original bytes".into(), body: "metadata is not source authorization".into() };
    let command = PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open, data: data.clone() };
    let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(&node.request_context(),
        &session(b"pr-diff-open"), &command, Default::default())).unwrap();
    assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
    (node, data)
}
fn grants(node: &OneNode, path: &Path) -> String {
    let header = credentials(node, path);
    replace(path, &(header.clone() + &row('a', OWNER, "read") + &row('b', OWNER, "pulls-read")
        + &row('d', OWNER, "read,pulls-read") + &row('e', OWNER, "read,pulls-write")));
    header
}
struct PullServer { client: Endpoint, worker: Option<JoinHandle<GitDaemonServerReceipt>> }
impl PullServer {
    fn start(node: OneNode, path: &Path, count: usize, source: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = Endpoint { address: listener.local_addr().unwrap(),
            route: String::from_utf8(node.git_daemon_repository_path().as_bytes().to_vec()).unwrap() };
        let path = path.to_path_buf();
        let worker = thread::spawn(move || {
            let limits = GitDaemonServerLimits::try_new(count, 2).unwrap();
            let result = if source {
                node.serve_repository_http_with_source_bounded(&listener, limits, &path,
                    false, false, true, true, Duration::from_secs(5))
            } else {
                node.serve_repository_http_with_pull_requests_bounded(&listener, limits, &path,
                    false, false, true, Duration::from_secs(5))
            };
            node.shutdown().unwrap(); result.unwrap()
        });
        Self { client, worker: Some(worker) }
    }
    fn finish(mut self) { self.worker.take().unwrap().join().unwrap(); }
}
impl Drop for PullServer {
    fn drop(&mut self) { if let Some(worker) = self.worker.take() { let _ = worker.join(); } }
}
fn diff(client: &Endpoint, number: u64, token: char, form: &str, chunked: bool) -> Reply {
    let (body, framing) = if chunked {
        let mut bytes = Vec::new();
        for chunk in form.as_bytes().chunks(11) {
            bytes.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            bytes.extend_from_slice(chunk); bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"0\r\n\r\n"); (bytes, "Transfer-Encoding: chunked\r\n".into())
    } else { (form.as_bytes().to_vec(), format!("Content-Length: {}\r\n", form.len())) };
    exchange(client, &request(client, &format!("/api/v1/pulls/{number}/diff"), token,
        &format!("Content-Type: application/x-www-form-urlencoded\r\n{framing}"), &body), true)
}
fn no_read_transaction(node: &OneNode) {
    for key in [b"read-only-pull-request-diff".as_slice(), b"read-only-source-query".as_slice()] {
        assert!(matches!(node.runtime().block_on(node.recover_transaction_in(&node.request_context(), &session(key))).unwrap(), RequestRecovery::KeyNotObserved));
    }
}

#[test]
fn recorded_pr_diff_survives_close_branch_advance_delete_and_restart_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new(); let config = root.config(format);
        let (node, data) = pr_fixture(&root, format); let before = generation(&node);
        let path = root.0.join("credentials"); grants(&node, &path);
        let server = PullServer::start(node, &path, 3, false);
        let query = format!("object_format={}", format.as_str());
        let original = diff(&server.client, 1, 'd', &query, false); status(&original, 200); // 1
        assert_eq!(text(&original.body, "mode"), "merge-base");
        assert!(original.body.contains("\"pull_request\":{\"number\":1,\"version\":1}"));
        assert_eq!(text(&original.body, "requested_before"), data.target_tip.to_string());
        assert_eq!(text(&original.body, "requested_after"), data.source_tip.to_string());
        assert_eq!(number(&original.body, "entry_count"), 8);
        assert!(original.body.contains(&format!("\"after_hex\":\"{}\"", hex(TEXT))));
        let pinned = format!("{query}&expected_version=1&expected_head={}", token(&original));
        assert_eq!(diff(&server.client, 1, 'd', &pinned, true), original); // 2
        let direct = diff(&server.client, 1, 'd', &(query.clone() + "&mode=direct"), false); // 3
        status(&direct, 200); assert_eq!(text(&direct.body, "compared_before"), data.target_tip.to_string());
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before); no_read_transaction(&node);
        let close = PullRequestCommand { number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: PullRequestAction::Close, data: data.clone() };
        let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(&node.request_context(),
            &session(b"pr-diff-close"), &close, Default::default())).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        branch(&node, b"refs/heads/base", ExpectedOld::Exactly(data.target_tip), ProposedNew::Update(data.source_tip), b"pr-diff-advance");
        branch(&node, b"refs/heads/topic", ExpectedOld::Exactly(data.source_tip), ProposedNew::Delete, b"pr-diff-delete");
        assert_eq!(generation(&node), before + 3);
        let server = PullServer::start(node, &path, 8, true);
        let stale = diff(&server.client, 1, 'd', &pinned, false); status(&stale, 409); // 1
        assert!(stale.body.contains("source_snapshot_moved"));
        let stale_version = diff(&server.client, 1, 'd', &(query.clone() + "&expected_version=1"), false); // 2
        status(&stale_version, 409); assert!(stale_version.body.contains("pull_request_version_moved"));
        let current_query = query.clone() + "&expected_version=2";
        let current = diff(&server.client, 1, 'd', &current_query, true); status(&current, 200); // 3
        assert_ne!(token(&current), token(&original));
        for key in ["requested_before", "requested_after", "compared_before", "before_tree", "after_tree"] {
            assert_eq!(text(&current.body, key), text(&original.body, key));
        }
        assert_eq!(number(&current.body, "entry_count"), 8);
        assert!(current.body.contains("\"version\":2"));
        let live_refs = format!("object_format={}&before_ref=refs/heads/base&after_ref=refs/heads/main", format.as_str());
        let live_diff = post(&server.client, "diff", 'd', &live_refs, false); status(&live_diff, 200); // 4
        assert_eq!(number(&live_diff.body, "entry_count"), 0, "live refs moved; PR tips must not float");
        status(&post(&server.client, "diff", 'd', &live_refs.replace("after_ref=refs/heads/main", "after_ref=refs/heads/topic"), false), 404); // 5
        status(&diff(&server.client, 1, 'd', &format!("{query}&expected_after={}", data.target_tip), false), 409); // 6
        status(&diff(&server.client, 2, 'd', &query, false), 404); // 7
        let selected = diff(&server.client, 1, 'd', &(query + "&path_prefix_hex=616c7068612e747874"), true); // 8
        status(&selected, 200); assert_eq!(number(&selected.body, "entry_count"), 1);
        server.finish();
        let node = reopen(&config); assert_eq!(generation(&node), before + 3); no_read_transaction(&node);
        let server = PullServer::start(node, &path, 1, false);
        assert_eq!(diff(&server.client, 1, 'd', &current_query, false), current);
        server.finish();
    }
}

#[test]
fn both_grants_are_required_before_body_intake_and_reads_never_create_reviews() {
    let format = GitHashAlgorithm::Sha1;
    let root = Scratch::new(); let config = root.config(format);
    let (node, _) = pr_fixture(&root, format); let before = generation(&node);
    let path = root.0.join("credentials"); let header = grants(&node, &path);
    let server = PullServer::start(node, &path, 8, false);
    let query = "object_format=sha1";
    for token in ['a', 'b', 'e'] {
        let bytes = request(&server.client, "/api/v1/pulls/1/diff", token,
            "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\n", b"");
        status(&exchange(&server.client, &bytes, false), 403); // 1, 2, 3
    }
    let bytes = request(&server.client, "/api/v1/pulls/1/diff", 'd',
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\nExpect: 100-continue\r\nIdempotency-Key: not-a-review\r\n", b"");
    status(&exchange(&server.client, &bytes, false), 400); // 4
    status(&diff(&server.client, 1, 'd', "object_format=sha1&before_ref=refs/heads/main", false), 400); // 5
    let exhausted = diff(&server.client, 1, 'd', "object_format=sha1&max_changes=1", true); // 6
    status(&exhausted, 413); assert!(!exhausted.body.contains("\"entries\":[]"));
    status(&diff(&server.client, 1, 'f', query, false), 401); // 7
    let successful = diff(&server.client, 1, 'd', query, false); status(&successful, 200); // 8
    assert!(successful.body.contains("\"transaction_created\":false"));
    assert!(successful.body.contains("\"approval_created\":false"));
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before); no_read_transaction(&node);
    replace(&path, &(header + &row('9', OWNER, "read,pulls-read")));
    let server = PullServer::start(node, &path, 2, false);
    status(&diff(&server.client, 1, 'd', query, false), 401);
    assert_eq!(diff(&server.client, 1, '9', query, true), successful);
    server.finish();
    let node = reopen(&config); assert_eq!(generation(&node), before);
    let server = Server::start(node, &path, 1, true, false); // source on, PR API off
    status(&diff(&server.client, 1, '9', query, false), 403);
    server.finish();
}
