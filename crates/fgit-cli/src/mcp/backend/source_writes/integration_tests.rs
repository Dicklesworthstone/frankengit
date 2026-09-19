//! Real native source -> publication -> PR -> diff, plus lost-reply recovery.
//! Candidate construction is native test setup, not a newly granted MCP tool.
use super::*;
use super::super::{NodeTools, Options, pull_writes, outcomes};
use super::super::super::{WriteGrants, protocol::{self, ReadTools, Server}};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{NodeConfig, OneNode};
use fgit_authority::IdempotencyKey;
use fgit_types::{GitOid, HeadGeneration, PrincipalId, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use std::{collections::BTreeMap, fs, io::{self, Cursor, Write}, path::PathBuf,
    sync::atomic::{AtomicU64, Ordering}};
static NEXT: AtomicU64 = AtomicU64::new(0);
const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"source-writes","version":"1"}}}"#;
const READY: &str = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
struct Fixture { root: PathBuf, options: Options, commit: GitOid }
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-mcp-source-writes-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let mut options = Options { storage: root.join("node"), tenant: TenantId::from_bytes([0x61; 16]),
            repository: RepositoryId::from_bytes([0x62; 16]), format, incarnation: None,
            issues: false, pulls: true, source: true,
            writes: WriteGrants { source: true, pulls: true, ..Default::default() },
            outcomes: true, principal: Some(actor()), max_messages: 128 };
        let (mut node, _) = OneNode::init(config(&options)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context(); let main = reference("refs/heads/main");
        let patch = b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+before\n";
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &main, patch, &metadata(1), Default::default(), None,
        )).unwrap();
        let session = fgit_node::LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(b"seed".to_vec()).unwrap());
        let result = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session, &main, plan.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        options.incarnation = Some(node.repository_incarnation_id()); node.shutdown().unwrap();
        Self { root, options, commit: plan.commit }
    }
}
impl Drop for Fixture { fn drop(&mut self) { fs::remove_dir_all(&self.root).unwrap(); } }
fn config(options: &Options) -> NodeConfig {
    NodeConfig::new(options.storage.clone(), options.tenant, options.repository).with_object_format(options.format).with_worker_threads(2)
}
fn actor() -> PrincipalId { PrincipalId::from_bytes([0x63; 16]) }
fn reference(name: &str) -> RefName { RefName::try_new(name.as_bytes()).unwrap() }
fn metadata(time: u64) -> MergeMetadata {
    MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: time, message: b"native candidate\n".to_vec() }
}
fn state(node: &OneNode) -> (RepositoryAuthorityHeadId, BTreeMap<RefName, GitOid>) {
    let request = node.request_context(); let selected = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
    (selected.basis().id(), selected.snapshot().refs.clone())
}
fn prepare(node: &OneNode, branch: &str, base: GitOid, content: &str, time: u64) -> (GitOid, Vec<u8>) {
    let patch = format!("diff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-before\n+{content}\n");
    let request = node.request_context(); let before = state(node).0;
    let candidate = node.runtime().block_on(node.prepare_trusted_patch_in(&request, &reference(branch), base,
        [0x64; 16], patch.as_bytes(), &metadata(time), Default::default())).unwrap();
    assert_eq!(state(node).0, before, "preparing test inputs must not publish");
    assert!(candidate.bundle_bytes().len() <= MAX_BUNDLE_BYTES);
    (candidate.candidate_commit, candidate.bundle_bytes().to_vec())
}
fn command(branch: &str, key: &str, fields: &[(&str, Value)]) -> Value {
    let Value::Object(mut args) = object([("reference", text(branch)), ("idempotency_key", text(key))]) else { unreachable!() };
    for (name, value) in fields { args.insert((*name).into(), value.clone()); } Value::Object(args)
}
fn publishing(branch: &str, key: &str, base: GitOid, tip: GitOid, bytes: &[u8]) -> Value {
    command(branch, key, &[("expected_base", text(base.to_string())), ("expected_candidate", text(tip.to_string())),
        ("bundle_hex_chunks", Value::Array(bytes.chunks(CHUNK_BYTES).map(|chunk| text(hex(chunk))).collect()))])
}
fn message(id: u64, name: &str, args: Value) -> String {
    object([("jsonrpc", text("2.0")), ("id", json::number(id)), ("method", text("tools/call")),
        ("params", object([("name", text(name)), ("arguments", args)]))]).encode(json::MAX_INPUT).unwrap()
}
fn start(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap(); server.receive(backend, INIT.as_bytes()).unwrap();
    assert!(server.receive(backend, READY.as_bytes()).is_none()); server
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, name: &str, args: Value) -> Value {
    server.receive(backend, message(id, name, args).as_bytes()).unwrap()
}
fn result(value: &Value) -> &Object { value.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap() }
fn committed(value: &Value) {
    assert_eq!(value.object().unwrap()["result"].object().unwrap()["isError"], Value::Bool(false), "{value:?}");
    assert_eq!(result(value)["outcome"].text(), Some("committed"));
    assert_eq!(result(value)["terminal"], Value::Bool(true));
}
fn refused(value: &Value) {
    // Both pre-admission uncertainty and canonical refusal are errors. Neither
    // may report a successful mutation or silently refresh the expected old tip.
    assert_eq!(value.object().unwrap()["result"].object().unwrap()["isError"], Value::Bool(true), "{value:?}");
    assert_ne!(result(value).get("outcome").and_then(Value::text), Some("committed"));
}

#[test]
fn source_publish_pr_review_and_atomic_branch_lifecycle_compose_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = Fixture::new(format); let mut backend = NodeTools::open(f.options.clone()).unwrap(); let mut server = start(&mut backend);
        let create = command("refs/heads/topic", "topic", &[("target", text(f.commit.to_string()))]);
        let created = invoke(&mut server, &mut backend, 2, CREATE, create.clone()); committed(&created);
        let held = state(&backend.node).0;
        let replay = invoke(&mut server, &mut backend, 3, CREATE, create); assert_eq!(result(&created), result(&replay)); assert_eq!(state(&backend.node).0, held);
        let (tip, bundle) = prepare(&backend.node, "refs/heads/topic", f.commit, "after", 2);
        let (alternate, competing) = prepare(&backend.node, "refs/heads/topic", f.commit, "competing", 3);
        let published = invoke(&mut server, &mut backend, 4, PUBLISH, publishing("refs/heads/topic", "publish", f.commit, tip, &bundle)); committed(&published);
        assert_eq!(state(&backend.node).1[&reference("refs/heads/topic")], tip);
        assert_eq!(result(&published)["current_refs_asserted"], Value::Bool(false));
        assert_eq!(result(&published)["bundle_validation_receipt"], Value::Null);
        let pr = object([("number", text("7")), ("expected_version", text("0")), ("idempotency_key", text("pr")),
            ("source_reference", text("refs/heads/topic")), ("target_reference", text("refs/heads/main")),
            ("expected_source", text(tip.to_string())), ("expected_target", text(f.commit.to_string())),
            ("title", text("Source written through MCP")), ("body", text("Ready for review, not approved"))]);
        let opened = invoke(&mut server, &mut backend, 5, pull_writes::OPEN, pr); committed(&opened);
        let diff = invoke(&mut server, &mut backend, 6, super::super::review::PULL_DIFF,
            object([("number", text("7")), ("expected_version", text("1"))]));
        assert_eq!(result(&diff)["entry_count"].text(), Some("1"));
        assert_eq!(result(&diff)["requested_after"].text(), Some(tip.to_string().as_str()));
        assert_eq!(result(&diff)["merge_permission"], Value::Null);
        let before = state(&backend.node).1;
        refused(&invoke(&mut server, &mut backend, 7, PUBLISH, publishing("refs/heads/topic", "stale", f.commit, alternate, &competing)));
        assert_eq!(state(&backend.node).1, before);
        let mut corrupt = bundle.clone(); *corrupt.last_mut().unwrap() ^= 1;
        refused(&invoke(&mut server, &mut backend, 8, PUBLISH, publishing("refs/heads/topic", "corrupt", f.commit, tip, &corrupt)));
        assert_eq!(state(&backend.node).1, before);
        let occupied = command("refs/heads/topic", "occupied", &[("expected_old", text(tip.to_string())), ("destination", text("refs/heads/main"))]);
        refused(&invoke(&mut server, &mut backend, 9, RENAME, occupied)); assert_eq!(state(&backend.node).1, before);
        refused(&invoke(&mut server, &mut backend, 10, DELETE, command("refs/heads/main", "delete-default", &[("expected_old", text(f.commit.to_string()))])));
        assert_eq!(state(&backend.node).1, before);
        let rename = command("refs/heads/topic", "rename", &[("expected_old", text(tip.to_string())), ("destination", text("refs/heads/renamed"))]);
        let renamed = invoke(&mut server, &mut backend, 11, RENAME, rename.clone()); committed(&renamed);
        assert_eq!(result(&renamed)["atomic"], Value::Bool(true));
        let renamed_refs = state(&backend.node).1;
        assert!(!renamed_refs.contains_key(&reference("refs/heads/topic")));
        assert_eq!(renamed_refs[&reference("refs/heads/renamed")], tip);
        refused(&invoke(&mut server, &mut backend, 12, UPDATE, command("refs/heads/renamed", "non-ff", &[("expected_old", text(tip.to_string())), ("target", text(f.commit.to_string()))])));
        assert_eq!(state(&backend.node).1, renamed_refs);
        let deleted = invoke(&mut server, &mut backend, 13, DELETE, command("refs/heads/renamed", "delete", &[("expected_old", text(tip.to_string()))])); committed(&deleted);
        let held = state(&backend.node); assert!(!held.1.contains_key(&reference("refs/heads/renamed")));
        let NodeTools { node, options } = backend; node.shutdown().unwrap();
        let mut stopped = NodeTools { node: OneNode::open_existing(config(&options)).unwrap(), options }; let mut server = start(&mut stopped);
        let retried = invoke(&mut server, &mut stopped, 2, RENAME, rename); assert_eq!(result(&retried), result(&renamed));
        let recovered = invoke(&mut server, &mut stopped, 3, outcomes::NAME, object([("idempotency_key", text("publish"))]));
        assert_eq!(result(&recovered)["tx_id"], result(&published)["tx_id"]);
        let retry = invoke(&mut server, &mut stopped, 4, PUBLISH, publishing("refs/heads/topic", "publish", f.commit, tip, &bundle));
        assert_eq!(result(&retry), result(&published));
        refused(&invoke(&mut server, &mut stopped, 5, CREATE, command("refs/heads/new", "new-stopped", &[("target", text(f.commit.to_string()))])));
        stopped.node.bring_into_service(HeadGeneration::FIRST).unwrap(); assert_eq!(state(&stopped.node), held);
        stopped.close().unwrap();
    }
}

#[test]
fn lost_published_reply_is_recoverable_and_no_following_request_runs() {
    struct Lost { flushed: bool }
    impl Write for Lost {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.flushed { Err(io::ErrorKind::BrokenPipe.into()) } else { Ok(bytes.len()) }
        }
        fn flush(&mut self) -> io::Result<()> { self.flushed = true; Ok(()) }
    }
    let f = Fixture::new(GitHashAlgorithm::Sha256); let mut backend = NodeTools::open(f.options.clone()).unwrap();
    let (tip, bundle) = prepare(&backend.node, "refs/heads/main", f.commit, "after", 2);
    let publish = publishing("refs/heads/main", "lost-publish", f.commit, tip, &bundle);
    let first = message(2, PUBLISH, publish.clone());
    let second = message(3, CREATE, command("refs/heads/must-not-run", "unread-key", &[("target", text(tip.to_string()))]));
    let transcript = format!("{INIT}\n{READY}\n{first}\n{second}\n");
    assert!(protocol::serve(&mut Cursor::new(transcript), &mut Lost { flushed: false }, &mut backend, 10).is_err());
    backend.close().unwrap();
    let mut backend = NodeTools::open(f.options.clone()).unwrap(); let mut server = start(&mut backend);
    let held = state(&backend.node);
    assert_eq!(held.1[&reference("refs/heads/main")], tip);
    assert!(!held.1.contains_key(&reference("refs/heads/must-not-run")));
    let recovered = invoke(&mut server, &mut backend, 2, outcomes::NAME, object([("idempotency_key", text("lost-publish"))]));
    assert_eq!(result(&recovered)["outcome"].text(), Some("committed"));
    let unread = invoke(&mut server, &mut backend, 3, outcomes::NAME, object([("idempotency_key", text("unread-key"))]));
    assert_eq!(result(&unread)["observation"].text(), Some("key_not_observed"));
    let retried = invoke(&mut server, &mut backend, 4, PUBLISH, publish); committed(&retried);
    assert_eq!(result(&retried)["tx_id"], result(&recovered)["tx_id"]);
    assert_eq!(state(&backend.node), held); backend.close().unwrap();
}

#[test]
fn source_write_grant_never_implies_other_tools_and_denial_precedes_body_intake() {
    let f = Fixture::new(GitHashAlgorithm::Sha1); let mut options = f.options.clone();
    options.source = false; options.pulls = false; options.outcomes = false; options.writes.pulls = false;
    let mut writer = NodeTools::open(options).unwrap();
    assert_eq!(writer.tools().len(), 5);
    for tool in writer.tools() { assert!(is_tool(tool.name)); assert!(writer.is_mutation(tool.name)); }
    for name in ["frankengit_source_blob", "frankengit_pull_open", "frankengit_issue_open", outcomes::NAME] {
        assert!(writer.call(name, &Object::new()).unwrap_err().invalid);
    }
    writer.close().unwrap();
    let mut options = f.options.clone(); options.writes = WriteGrants::default(); options.outcomes = false; options.principal = None;
    let mut reader = NodeTools::open(options).unwrap(); let held = state(&reader.node);
    for name in [CREATE, UPDATE, DELETE, RENAME, PUBLISH] {
        assert!(!reader.tools().iter().any(|tool| tool.name == name));
        assert!(reader.call(name, &Object::new()).unwrap_err().invalid);
        assert_eq!(call(&reader, name, &Object::new()).unwrap_err().code, "tool_not_granted");
    }
    assert_eq!(state(&reader.node), held); reader.close().unwrap();
}
