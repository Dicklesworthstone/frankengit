//! The real embedded authority owns every mutation, refusal and recovered key.
use super::*;
use super::super::{Options, NodeTools};
use super::super::super::{WriteGrants, protocol::{ReadTools, Server}};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture { root: PathBuf, options: Options, commit: GitOid }
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-mcp-pr-writes-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let mut options = Options { storage: root.join("node"), tenant: TenantId::from_bytes([0x81; 16]),
            repository: RepositoryId::from_bytes([0x82; 16]), format, incarnation: None,
            issues: false, pulls: false, source: false, writes: WriteGrants { pulls: true, ..Default::default() },
            outcomes: true, principal: Some(actor()), max_messages: 64 };
        let (mut node, _) = OneNode::init(config(&options)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context(); let main = reference("refs/heads/main");
        let patch = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+base\n";
        let metadata = MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: 1, message: b"root\n".to_vec() };
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &main, patch, &metadata, Default::default(), None,
        )).unwrap();
        let result = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session("seed"), &main, plan.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let create = RefCommand { name: reference("refs/heads/topic"), expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(plan.commit), force: false };
        let result = node.runtime().block_on(node.admit_branch_updates_durable_in(&request, &session("topic"), &[create], Default::default())).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        options.incarnation = Some(node.repository_incarnation_id()); node.shutdown().unwrap();
        Self { root, options, commit: plan.commit }
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.root).unwrap(); } }
fn config(options: &Options) -> NodeConfig {
    NodeConfig::new(options.storage.clone(), options.tenant, options.repository).with_object_format(options.format).with_worker_threads(2)
}
fn actor() -> PrincipalId { PrincipalId::from_bytes([0x83; 16]) }
fn reference(name: &str) -> RefName { RefName::try_new(name.as_bytes()).unwrap() }
fn session(key: &str) -> LoopbackReceiveSession { LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.as_bytes().to_vec()).unwrap()) }
fn args(commit: GitOid, version: &str, key: &str, title: &str) -> Value {
    object([("number", text("7")), ("expected_version", text(version)), ("idempotency_key", text(key)),
        ("source_reference", text("refs/heads/topic")), ("target_reference", text("refs/heads/main")),
        ("expected_source", text(commit.to_string())), ("expected_target", text(commit.to_string())),
        ("title", text(title)), ("body", text("literal é\r\nnot a policy"))])
}
fn start(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"pr-writes","version":"1"}}}"#).unwrap();
    assert!(server.receive(backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none()); server
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, name: &str, args: Value) -> Value {
    let message = object([("jsonrpc", text("2.0")), ("id", json::number(id)), ("method", text("tools/call")),
        ("params", object([("name", text(name)), ("arguments", args)]))]);
    server.receive(backend, message.encode(16384).unwrap().as_bytes()).unwrap()
}
fn result(value: &Value) -> &Object { value.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap() }
fn head(node: &OneNode) -> RepositoryAuthorityHeadId {
    let request = node.request_context(); node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis().id()
}

#[test]
fn native_pr_lifecycle_is_versioned_read_independent_and_recoverable_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap(); let mut server = start(&mut backend);
        let first = invoke(&mut server, &mut backend, 2, OPEN, args(fixture.commit, "0", "open-pr", "Original"));
        assert_eq!(result(&first)["outcome"].text(), Some("committed"));
        let held = head(&backend.node);
        let retry = invoke(&mut server, &mut backend, 3, OPEN, args(fixture.commit, "0", "open-pr", "Original"));
        assert_eq!(result(&retry), result(&first)); assert_eq!(head(&backend.node), held);
        for (index, name) in ["frankengit_pull_show", "frankengit_issue_open", "frankengit_source_blob", "frankengit_pull_merge"].into_iter().enumerate() {
            let denied = invoke(&mut server, &mut backend, 4 + index as u64, name, object([]));
            assert!(denied.object().unwrap().contains_key("error"));
        }
        let updated = invoke(&mut server, &mut backend, 8, UPDATE, args(fixture.commit, "1", "update-pr", "Updated"));
        assert_eq!(result(&updated)["outcome"].text(), Some("committed"));
        let stale = invoke(&mut server, &mut backend, 9, UPDATE, args(fixture.commit, "1", "stale-pr", "Stale"));
        assert_eq!(result(&stale)["outcome"].text(), Some("refused"));
        assert_eq!(stale.object().unwrap()["result"].object().unwrap()["isError"], Value::Bool(true));
        assert_eq!(result(&stale)["outcome_unknown"], Value::Bool(false));
        // Closing must preserve the complete recorded metadata, including after deletion.
        let request = backend.node.request_context();
        let delete = RefCommand { name: reference("refs/heads/topic"), expected_old: ExpectedOld::Exactly(fixture.commit), proposed_new: ProposedNew::Delete, force: false };
        let deleted = backend.node.runtime().block_on(backend.node.admit_branch_updates_durable_in(&request, &session("delete-topic"), &[delete], Default::default())).unwrap();
        assert!(matches!(deleted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let bad_close = invoke(&mut server, &mut backend, 10, CLOSE, args(fixture.commit, "2", "bad-close", "Changed on close"));
        assert_eq!(result(&bad_close)["outcome"].text(), Some("refused"));
        let closed = invoke(&mut server, &mut backend, 11, CLOSE, args(fixture.commit, "2", "close-pr", "Updated"));
        assert_eq!(result(&closed)["outcome"].text(), Some("committed"));
        assert_eq!(result(&closed)["refs_changed"], Value::Bool(false));
        let held = head(&backend.node); let config = config(&backend.options);
        let NodeTools { node, options } = backend; node.shutdown().unwrap();
        // No bring-into-service: terminal recovery must precede fresh-write intake.
        let mut stopped = NodeTools { node: OneNode::open_existing(config).unwrap(), options };
        let mut server = start(&mut stopped);
        let retry = invoke(&mut server, &mut stopped, 2, OPEN, args(fixture.commit, "0", "open-pr", "Original"));
        assert_eq!(result(&retry), result(&first));
        let recovered = invoke(&mut server, &mut stopped, 3, super::super::outcomes::NAME,
            object([("idempotency_key", text("close-pr"))]));
        assert_eq!(result(&recovered)["tx_id"], result(&closed)["tx_id"]);
        let fresh = invoke(&mut server, &mut stopped, 5, UPDATE, args(fixture.commit, "3", "new-stopped", "No"));
        assert_eq!(result(&fresh)["outcome_unknown"], Value::Bool(true));
        stopped.node.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(head(&stopped.node), held);
        stopped.close().unwrap();
    }
}

#[test]
fn pull_write_grants_do_not_imply_reads_issues_or_recovery_and_descriptors_are_mutating() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut options = fixture.options.clone(); options.outcomes = false;
    let mut backend = NodeTools::open(options).unwrap();
    assert_eq!(backend.tools().len(), 3);
    for tool in backend.tools() { assert!(is_tool(tool.name)); assert!(backend.is_mutation(tool.name)); }
    let mut server = start(&mut backend);
    let list = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
    let Value::Array(tools) = &list.object().unwrap()["result"].object().unwrap()["tools"] else { panic!("tools") };
    for tool in tools {
        let annotations = tool.object().unwrap()["annotations"].object().unwrap();
        assert_eq!(annotations["readOnlyHint"], Value::Bool(false));
    }
    let mut injected = args(fixture.commit, "0", "injected", "No");
    let Value::Object(fields) = &mut injected else { unreachable!() }; fields.insert("principal".into(), text("admin"));
    let before = head(&backend.node);
    assert!(invoke(&mut server, &mut backend, 3, OPEN, injected).object().unwrap().contains_key("error"));
    let Value::Object(fields) = args(fixture.commit, "0", "denied", "No") else { unreachable!() };
    assert!(super::super::issue_writes::call(&backend, "frankengit_issue_open", &fields).unwrap_err().invalid);
    assert_eq!(head(&backend.node), before);
    backend.close().unwrap();
    let mut options = fixture.options.clone(); options.writes.pulls = false; options.pulls = true; options.outcomes = false; options.principal = None;
    let mut reader = NodeTools::open(options).unwrap();
    assert!(reader.call(OPEN, &fields).unwrap_err().invalid);
    // Direct adapter dispatch has the same denial as discovery/protocol dispatch.
    assert!(call(&reader, OPEN, &fields).unwrap_err().invalid);
    reader.close().unwrap();
}
