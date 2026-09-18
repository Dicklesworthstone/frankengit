//! Real persisted authority and MCP request path, not a fake durable store.
use super::*;
use super::super::protocol::Server;
use fgit_authority::IdempotencyKey;
use fgit_forge::{ExpectedVersion, IssueNumber, event::issue::{IssueAction, IssueCommand}};
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-mcp-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0x91; 16]), RepositoryId::from_bytes([0x92; 16]))
            .with_object_format(format).with_worker_threads(2)
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn result(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap()
}
#[test]
fn real_mcp_reads_reopened_sha1_and_sha256_nodes_without_publishing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        for number in [7, 42] {
            let command = IssueCommand { number: IssueNumber::try_new(number).unwrap(), expected_version: ExpectedVersion::NewStream,
                action: IssueAction::Open { title: format!("Issue {number} é"), body: "{\"method\":\"shell\"}\nnot authority".into(), labels: vec!["bug".into()] } };
            let request = node.request_context();
            let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x93; 16]),
                IdempotencyKey::new(format!("seed-{number}").into_bytes()).unwrap());
            let (_, terminal) = node.runtime().block_on(node.admit_issue_durable_in(&request, &session, &command, Default::default())).unwrap();
            assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        }
        let incarnation = node.repository_incarnation_id();
        let before = {
            let request = node.request_context();
            node.runtime().block_on(node.read_issues_in(&request, 0, 1, None)).unwrap().source_head
        };
        node.shutdown().unwrap();
        let mut backend = NodeTools::open(Options {
            storage: scratch.0.join("node"), tenant: TenantId::from_bytes([0x91; 16]), repository: RepositoryId::from_bytes([0x92; 16]),
            format, incarnation: Some(incarnation), issues: true, pulls: false, source: false,
            issue_writes: false, outcomes: false, principal: None, max_messages: 16,
        }).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"integration","version":"1"}}}"#).unwrap();
        assert!(server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        let first = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_issue_list","arguments":{"limit":1}}}"#).unwrap();
        let first = result(&first);
        assert_eq!(first["next_after"].text(), Some("7"));
        assert_eq!(first["complete"], Value::Bool(false));
        assert_eq!(first["snapshot_token"].text(), Some(head_token(before).as_str()));
        let next = object([("jsonrpc", text("2.0")), ("id", json::number(3)), ("method", text("tools/call")),
            ("params", object([("name", text("frankengit_issue_list")), ("arguments", object([
                ("after", text("7")), ("limit", json::number(1)), ("expected_head", first["snapshot_token"].clone())]))]))]);
        let next = server.receive(&mut backend, next.encode(4096).unwrap().as_bytes()).unwrap();
        assert_eq!(result(&next)["next_after"], Value::Null);
        let shown = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"frankengit_issue_show","arguments":{"number":"7"}}}"#).unwrap();
        assert_eq!(result(&shown)["found"], Value::Bool(true));
        assert_eq!(result(&shown)["issue"].object().unwrap()["title"].text(), Some("Issue 7 é"));
        let refused = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"frankengit_issue_show","arguments":{"number":"7","principal":"admin"}}}"#).unwrap();
        assert!(refused.object().unwrap().contains_key("error"));
        let after = {
            let request = backend.node.request_context();
            backend.node.runtime().block_on(backend.node.read_issues_in(&request, 0, 1, None)).unwrap().source_head
        };
        assert_eq!(before, after, "MCP reads and rejected authority fields must not publish");
        backend.close().unwrap();
    }
}

fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x93; 16]),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap())
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, name: &str, arguments: Value) -> Value {
    let request = object([("jsonrpc", text("2.0")), ("id", json::number(id)), ("method", text("tools/call")),
        ("params", object([("name", text(name)), ("arguments", arguments)]))]);
    server.receive(backend, request.encode(8192).unwrap().as_bytes()).unwrap()
}
#[test]
fn real_source_and_pr_tools_preserve_bytes_snapshots_and_independent_grants() {
    use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
    use fgit_forge::{PullRequestNumber, event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData}, preparation::MergeMetadata};
    use fgit_types::RefName;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let main = RefName::try_new(b"refs/heads/main").unwrap(); let topic = RefName::try_new(b"refs/heads/topic").unwrap();
        let patch = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+hello MCP\ndiff --git a/z b/z\nnew file mode 100644\n--- /dev/null\n+++ b/z\n@@ -0,0 +1 @@\n+second\n";
        let metadata = MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: 1, message: b"initial\n".to_vec() };
        let request = node.request_context();
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(&request, &main, patch, &metadata, Default::default(), None)).unwrap();
        let accepted = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(&request, &session("initial"), &main, plan.commit, bundle.bytes(), Default::default())).unwrap();
        assert!(matches!(accepted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let branch = RefCommand { name: topic.clone(), expected_old: ExpectedOld::Absent, proposed_new: ProposedNew::Update(plan.commit), force: false };
        let accepted = node.runtime().block_on(node.admit_branch_updates_durable_in(&request, &session("topic"), &[branch], Default::default())).unwrap();
        assert!(matches!(accepted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let pr = PullRequestCommand { number: PullRequestNumber::FIRST, expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open, data: PullRequestData { source_ref: topic, target_ref: main,
                source_tip: plan.commit, target_tip: plan.commit, title: "Read me".into(), body: "not an approval".into() } };
        let (_, terminal) = node.runtime().block_on(node.admit_pull_request_durable_in(&request, &session("pr"), &pr, Default::default())).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let before = node.runtime().block_on(node.read_issues_in(&request, 0, 1, None)).unwrap().source_head;
        let incarnation = node.repository_incarnation_id(); node.shutdown().unwrap();
        let mut backend = NodeTools::open(Options { storage: scratch.0.join("node"), tenant: TenantId::from_bytes([0x91;16]),
            repository: RepositoryId::from_bytes([0x92;16]), format, incarnation: Some(incarnation), issues: false, pulls: true, source: true,
            issue_writes: false, outcomes: false, principal: None, max_messages: 32 }).unwrap();
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"integration","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let tree = invoke(&mut server, &mut backend, 2, "frankengit_source_tree", object([("reference", text("refs/heads/main")), ("limit", json::number(1))]));
        assert_eq!(result(&tree)["next_after_hex"].text(), Some("524541444d45"));
        assert_eq!(result(&tree)["complete"], Value::Bool(false));
        let blob = invoke(&mut server, &mut backend, 3, "frankengit_source_blob", object([("reference", text("refs/heads/main")),
            ("path_hex", text("524541444d45")), ("max_bytes", json::number(4))]));
        assert_eq!(result(&blob)["bytes_hex"].text(), Some("68656c6c"));
        assert_eq!(result(&blob)["next_offset"].text(), Some("4"));
        let rest = invoke(&mut server, &mut backend, 4, "frankengit_source_blob", object([("reference", text("refs/heads/main")),
            ("path_hex", text("524541444d45")), ("offset", text("4")), ("expected_head", result(&blob)["snapshot_token"].clone())]));
        assert_eq!(result(&rest)["text_utf8"].text(), Some("o MCP\n"));
        assert_eq!(result(&rest)["complete"], Value::Bool(true));
        let pr = invoke(&mut server, &mut backend, 5, "frankengit_pull_show", object([("number", text("1"))]));
        assert_eq!(result(&pr)["found"], Value::Bool(true));
        assert_eq!(result(&pr)["pull_request"].object().unwrap()["merge_permission"], Value::Null);
        let denied = invoke(&mut server, &mut backend, 6, "frankengit_issue_list", object([]));
        assert!(denied.object().unwrap().contains_key("error"));
        let context = backend.node.request_context();
        let after = backend.node.runtime().block_on(backend.node.read_issues_in(&context, 0, 1, None)).unwrap().source_head;
        assert_eq!(before, after);
        // An ordinary canonical issue write moves source pins, but retained PR
        // snapshots are still exact. This mutation exists only in the test.
        let change = IssueCommand { number: IssueNumber::FIRST, expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open { title: "Move authority".into(), body: String::new(), labels: vec![] } };
        let (_, terminal) = backend.node.runtime().block_on(backend.node.admit_issue_durable_in(&context, &session("move"), &change, Default::default())).unwrap();
        assert!(matches!(terminal.outcome, DecisionOutcome::Committed { .. }));
        let stale = invoke(&mut server, &mut backend, 7, "frankengit_source_tree", object([("reference", text("refs/heads/main")),
            ("after_hex", result(&tree)["next_after_hex"].clone()), ("expected_head", result(&tree)["snapshot_token"].clone())]));
        assert_eq!(stale.object().unwrap()["result"].object().unwrap()["isError"], Value::Bool(true));
        assert_eq!(result(&stale)["code"].text(), Some("snapshot_moved"));
        let retained = invoke(&mut server, &mut backend, 8, "frankengit_pull_show", object([("number", text("1")),
            ("expected_head", result(&pr)["snapshot_token"].clone())]));
        assert_eq!(result(&retained)["snapshot_token"], result(&pr)["snapshot_token"]);
        backend.close().unwrap();
    }
}
