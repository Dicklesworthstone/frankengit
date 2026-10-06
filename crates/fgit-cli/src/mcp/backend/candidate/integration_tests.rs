//! Real persisted-node calls through the MCP protocol, not a fake Git engine.
use super::*;
use super::super::super::protocol::{ReadTools, Server};
use super::super::Options;
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
const PATCH: &str = "diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-before\n+after\n";
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn fields<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(values) else { unreachable!() };
    fields
}
fn sponsor() -> PrincipalId { PrincipalId::from_bytes([0xb3; 16]) }
fn setup(format: GitHashAlgorithm) -> (Scratch, NodeTools, GitOid) {
    let scratch = Scratch(std::env::temp_dir().join(format!("fg-mcp-candidate-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xb1; 16]);
    let repository = RepositoryId::from_bytes([0xb2; 16]);
    let config = NodeConfig::new(scratch.0.join("node"), tenant, repository).with_object_format(format).with_worker_threads(2);
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let initial = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+before\ndiff --git a/sibling b/sibling\nnew file mode 100644\n--- /dev/null\n+++ b/sibling\n@@ -0,0 +1 @@\n+untouched\n";
    let metadata = MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: 1, message: b"initial\n".to_vec() };
    let request = node.request_context();
    let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(&request, &reference, initial, &metadata, Default::default(), None)).unwrap();
    let session = LoopbackReceiveSession::authenticated(sponsor(), IdempotencyKey::new(b"seed".to_vec()).unwrap());
    let outcome = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(&request, &session, &reference, plan.commit, bundle.bytes(), Default::default())).unwrap();
    assert!(matches!(outcome.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"), tenant, repository, format, incarnation: Some(incarnation),
        issues: false, pulls: false, source: true, writes: Default::default(), outcomes: false,
        principal: None, max_messages: 32,
    }).unwrap();
    (scratch, backend, plan.commit)
}
fn input(base: GitOid) -> Object {
    fields([
        ("operation", text("prepare_patch")), ("reference", text("refs/heads/main")),
        ("expected_base", text(raw_oid(base))), ("patch", text(PATCH)),
        ("author", text("Author <author@example.invalid>")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("2")), ("message_hex", text(hex(b"edit through MCP\n"))),
    ])
}
fn head_bytes(backend: &NodeTools) -> Vec<u8> {
    backend.node.runtime().block_on(backend.node.authenticate_authority_head()).unwrap().receipt().body().to_vec()
}
fn server(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"candidate-test","version":"1"}}}"#).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    server
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, name: &str, args: Object) -> Value {
    let wire = object([
        ("jsonrpc", text("2.0")), ("id", json::number(id)), ("method", text("tools/call")),
        ("params", object([("name", text(name)), ("arguments", Value::Object(args))])),
    ]).encode(json::MAX_INPUT).unwrap();
    server.receive(backend, wire.as_bytes()).unwrap()
}
fn content(response: &Value) -> &Object {
    response.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap()
}
#[test]
fn prepare_over_mcp_is_reproducible_unstaged_and_refuses_without_side_effects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, base) = setup(format);
        let before = head_bytes(&backend);
        let mut server = server(&mut backend);
        let response = invoke(&mut server, &mut backend, 2, NAME, input(base));
        let prepared = content(&response);
        assert_eq!(prepared["published"], Value::Bool(false));
        assert_eq!(prepared["approval_granted"], Value::Bool(false));
        assert_eq!(prepared["snapshot_token"], Value::Null);
        assert_eq!(prepared["source_commit"].text(), Some(raw_oid(base).as_str()));
        let publication = prepared["publication_arguments"].object().unwrap();
        let candidate = oid(publication, "expected_candidate", format).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err(), "preparation must not stage uploaded objects");
        assert_eq!(backend.call(NAME, &input(base)).unwrap().object().unwrap(), prepared);
        let Value::Array(paths) = &prepared["paths"] else { unreachable!() };
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].object().unwrap()["path_hex"].text(), Some(hex(b"README").as_str()));
        assert_eq!(backend.call("frankengit_source_publish", publication).unwrap_err().code, "tool_not_granted");
        let mut stale = input(base);
        stale.insert("expected_base".into(), text("ab".repeat(format.digest_len())));
        assert_eq!(backend.call(NAME, &stale).unwrap_err().code, "source_commit_moved");
        let mut mismatch = input(base);
        mismatch.insert("patch".into(), text(PATCH.replace("-before", "-different")));
        assert_eq!(backend.call(NAME, &mismatch).unwrap_err().code, "patch_context_mismatch");
        let mut missing = input(base);
        missing.insert("reference".into(), text("refs/heads/absent"));
        assert_eq!(backend.call(NAME, &missing).unwrap_err().code, "reference_unavailable");
        assert_eq!(head_bytes(&backend), before);
        backend.options.source = false;
        backend.options.writes.source = true;
        assert!(!backend.tools().iter().any(|tool| tool.name == NAME));
        assert_eq!(backend.call(NAME, &input(base)).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(&backend, &input(base)).unwrap_err().code, "tool_not_granted");
        backend.close().unwrap();
    }
}
#[test]
fn candidate_fits_the_existing_full_registry_without_gaining_mutation_annotations() {
    let (_scratch, mut backend, base) = setup(GitHashAlgorithm::Sha1);
    backend.options.issues = true;
    backend.options.pulls = true;
    backend.options.writes.issues = true;
    backend.options.writes.pulls = true;
    backend.options.writes.source = true;
    backend.options.writes.reviews = true;
    backend.options.writes.merges = true;
    backend.options.outcomes = true;
    backend.options.principal = Some(sponsor());
    backend.options.validate_access().unwrap();
    assert_eq!(backend.tools().len(), 32);
    let mut server = server(&mut backend);
    let tools = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
    let Value::Array(tools) = &tools.object().unwrap()["result"].object().unwrap()["tools"] else { unreachable!() };
    let tool = tools.iter().find(|value| value.object().unwrap()["name"].text() == Some(NAME)).unwrap().object().unwrap();
    assert_eq!(tool["annotations"].object().unwrap()["readOnlyHint"], Value::Bool(true));
    assert!(!backend.is_mutation(NAME));
    assert!(backend.call(NAME, &input(base)).is_ok());
    backend.close().unwrap();
}
