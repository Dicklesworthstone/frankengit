//! Persisted native publication is test setup only. Review tools expose no write path.
use super::*;
use super::super::super::protocol::Server;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::MergeMetadata;
use fgit_forge::ExpectedVersion;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fg-mcp-review-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap(); Self(root)
    }
    fn options(&self, format: GitHashAlgorithm) -> Options {
        Options { storage: self.0.join("node"), tenant: TenantId::from_bytes([0xd1; 16]),
            repository: RepositoryId::from_bytes([0xd2; 16]), format, incarnation: None,
            issues: false, pulls: true, source: true, issue_writes: false, outcomes: false, principal: None, max_messages: 32 }
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xd3; 16]) }
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap())
}
fn metadata(time: u64) -> MergeMetadata {
    MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(),
        timestamp: time, message: b"native review test\n".to_vec() }
}
fn authority(node: &OneNode) -> RepositoryAuthorityHeadId {
    let request = node.request_context();
    node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis().id()
}
fn edit(node: &OneNode, branch: &RefName, before: GitOid, old: &str, new: &str, time: u64) -> GitOid {
    let patch = format!("diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-{old}\n+{new}\n");
    let request = node.request_context();
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(
        &request, branch, before, [0xd4; 16], patch.as_bytes(), &metadata(time), Default::default(),
    )).unwrap();
    let result = node.runtime().block_on(node.apply_workspace_bundle_durable_in(
        &request, principal(), format!("edit-{time}").as_bytes(), branch,
        before, candidate.candidate_commit, candidate.bundle_bytes(),
    )).unwrap();
    assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    candidate.candidate_commit
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, name: &str, arguments: Value) -> Value {
    let request = object([("jsonrpc", text("2.0")), ("id", json::number(id)), ("method", text("tools/call")),
        ("params", object([("name", text(name)), ("arguments", arguments)]))]);
    server.receive(backend, request.encode(8192).unwrap().as_bytes()).unwrap()
}
fn result(response: &Value) -> &Object {
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{response:?}");
    result["structuredContent"].object().unwrap()
}
fn tool_error(response: &Value) {
    assert_eq!(response.object().unwrap()["result"].object().unwrap()["isError"], Value::Bool(true));
}

#[test]
fn reopened_nodes_review_real_changes_and_recorded_pr_tips_without_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut options = scratch.options(format);
        let (mut node, _) = OneNode::init(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(format).with_worker_threads(2)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let main = RefName::try_new(b"refs/heads/main").unwrap();
        let topic = RefName::try_new(b"refs/heads/topic").unwrap();
        let patch = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+old\n";
        let request = node.request_context();
        let (_, root, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &main, patch, &metadata(1), Default::default(), None,
        )).unwrap();
        let published = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session("initial"), &main, root.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let branch = RefCommand { name: topic.clone(), expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(root.commit), force: false };
        let published = node.runtime().block_on(node.admit_branch_updates_durable_in(
            &request, &session("branch"), &[branch], Default::default(),
        )).unwrap();
        assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let tip = edit(&node, &topic, root.commit, "old", "new", 2);
        let command = PullRequestCommand { number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream, action: PullRequestAction::Open,
            data: PullRequestData { source_ref: topic.clone(), target_ref: main.clone(), source_tip: tip,
                target_tip: root.commit, title: "Review source".into(), body: "not an approval".into() } };
        let request = node.request_context();
        let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(
            &request, &session("pr"), &command, Default::default(),
        )).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let original_head = authority(&node);
        options.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"review-test","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let compared = invoke(&mut server, &mut backend, 2, COMPARE, object([
            ("before_ref", text("refs/heads/main")), ("after_ref", text("refs/heads/topic")),
            ("expected_before", text(root.commit.to_string())), ("expected_after", text(tip.to_string())),
        ]));
        assert_eq!(result(&compared)["snapshot_token"].text(), Some(head_token(original_head).as_str()));
        assert_eq!(result(&compared)["entry_count"].text(), Some("1"));
        let Value::Array(entries) = &result(&compared)["entries"] else { panic!("entries") };
        let Value::Array(hunks) = &entries[0].object().unwrap()["content"].object().unwrap()["hunks"] else { panic!("hunks") };
        assert_eq!(hunks[0].object().unwrap()["before_hex"].text(), Some("6f6c640a"));
        assert_eq!(hunks[0].object().unwrap()["after_hex"].text(), Some("6e65770a"));
        let pr = invoke(&mut server, &mut backend, 3, PULL_DIFF, object([
            ("number", text("1")), ("expected_version", text("1")),
        ]));
        assert_eq!(result(&pr)["comparison"].text(), Some("merge-base"));
        assert_eq!(result(&pr)["compared_before"].text(), Some(root.commit.to_string().as_str()));
        assert_eq!(result(&pr)["merge_permission"], Value::Null);
        let stale_version = invoke(&mut server, &mut backend, 4, PULL_DIFF, object([
            ("number", text("1")), ("expected_version", text("2")),
        ]));
        tool_error(&stale_version);
        let tiny = invoke(&mut server, &mut backend, 5, COMPARE, object([
            ("before_ref", text("refs/heads/main")), ("after_ref", text("refs/heads/topic")),
            ("max_blob_bytes", json::number(1)),
        ]));
        tool_error(&tiny);
        assert_eq!(authority(&backend.node), original_head);

        // A later test-only branch publication must not rewrite recorded PR tips.
        let later = edit(&backend.node, &topic, tip, "new", "later", 3);
        let current_head = authority(&backend.node);
        assert_ne!(current_head, original_head);
        let stale_head = invoke(&mut server, &mut backend, 6, PULL_DIFF, object([
            ("number", text("1")), ("expected_version", text("1")),
            ("expected_head", text(head_token(original_head))),
        ]));
        tool_error(&stale_head);
        let recorded = invoke(&mut server, &mut backend, 7, PULL_DIFF, object([
            ("number", text("1")), ("expected_version", text("1")),
        ]));
        assert_eq!(result(&recorded)["requested_after"].text(), Some(tip.to_string().as_str()));
        assert_ne!(tip, later);
        for (source, pulls) in [(false, true), (true, false), (false, false)] {
            backend.options.source = source; backend.options.pulls = pulls;
            assert!(!backend.tools().iter().any(|tool| tool.name == PULL_DIFF));
            assert!(backend.call(PULL_DIFF, &object([("number", text("1")), ("expected_version", text("1"))]).object().unwrap().clone()).is_err());
        }
        assert_eq!(authority(&backend.node), current_head);
        backend.close().unwrap();
    }
}

#[test]
fn history_and_blame_page_reopened_native_nodes_with_exact_line_origins() {
    use super::super::history::{BLAME, LOG};
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut options = scratch.options(format); options.pulls = false;
        let (mut node, _) = OneNode::init(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(format).with_worker_threads(2)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let patch = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1,2 @@\n+old\n+stable\n";
        let request = node.request_context();
        let (_, root, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &reference, patch, &metadata(1), Default::default(), None,
        )).unwrap();
        let published = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session("initial"), &reference, root.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let tip = edit(&node, &reference, root.commit, "old", "new", 2);
        let original = authority(&node); options.incarnation = Some(node.repository_incarnation_id());
        node.shutdown().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"history-test","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let first = invoke(&mut server, &mut backend, 2, LOG, object([
            ("reference", text("refs/heads/main")), ("limit", json::number(1)),
        ]));
        assert_eq!(result(&first)["total_commits"].text(), Some("2"));
        assert_eq!(result(&first)["next_after"].text(), Some("1"));
        let Value::Array(rows) = &result(&first)["commits"] else { panic!("commits") };
        assert_eq!(rows[0].object().unwrap()["id"].text(), Some(tip.to_string().as_str()));
        let tail = invoke(&mut server, &mut backend, 3, LOG, object([
            ("reference", text("refs/heads/main")), ("after", text("1")),
            ("expected_head", result(&first)["snapshot_token"].clone()),
        ]));
        let Value::Array(rows) = &result(&tail)["commits"] else { panic!("commits") };
        assert_eq!(rows[0].object().unwrap()["id"].text(), Some(root.commit.to_string().as_str()));
        assert_eq!(result(&tail)["complete"], Value::Bool(true));
        let first_line = invoke(&mut server, &mut backend, 4, BLAME, object([
            ("reference", text("refs/heads/main")), ("path_hex", text("66696c65")), ("limit", json::number(1)),
        ]));
        assert_eq!(result(&first_line)["total_lines"].text(), Some("2"));
        assert_eq!(result(&first_line)["bytes_hex"].text(), Some("6e65770a"));
        assert_eq!(result(&first_line)["next_first_line"].text(), Some("1"));
        let Value::Array(lines) = &result(&first_line)["lines"] else { panic!("lines") };
        assert_eq!(lines[0].object().unwrap()["origin_commit"].text(), Some(tip.to_string().as_str()));
        // Default 100-line page clamps at EOF rather than refusing a short file.
        let last_line = invoke(&mut server, &mut backend, 5, BLAME, object([
            ("reference", text("refs/heads/main")), ("path_hex", text("66696c65")), ("first_line", text("1")),
            ("expected_head", result(&first_line)["snapshot_token"].clone()),
        ]));
        assert_eq!(result(&last_line)["bytes_hex"].text(), Some("737461626c650a"));
        assert_eq!(result(&last_line)["complete"], Value::Bool(true));
        let Value::Array(lines) = &result(&last_line)["lines"] else { panic!("lines") };
        assert_eq!(lines[0].object().unwrap()["origin_commit"].text(), Some(root.commit.to_string().as_str()));
        assert_eq!(result(&last_line)["human_authorship_proven"], Value::Bool(false));
        assert_eq!(authority(&backend.node), original);
        let _later = edit(&backend.node, &reference, tip, "new", "later", 3);
        let current = authority(&backend.node);
        let stale = invoke(&mut server, &mut backend, 6, BLAME, object([
            ("reference", text("refs/heads/main")), ("path_hex", text("66696c65")), ("first_line", text("1")),
            ("expected_head", result(&first_line)["snapshot_token"].clone()),
        ]));
        tool_error(&stale);
        backend.options.source = false; backend.options.pulls = true;
        for name in [LOG, BLAME] {
            assert!(!backend.tools().iter().any(|tool| tool.name == name));
            assert!(backend.call(name, &Object::new()).is_err());
        }
        assert_eq!(authority(&backend.node), current);
        backend.close().unwrap();
    }
}
