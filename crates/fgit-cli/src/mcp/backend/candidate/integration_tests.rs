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

fn inspection(prepared: &Object) -> Object {
    let mut args = prepared["publication_arguments"].object().unwrap().clone();
    args.insert("operation".into(), text("inspect"));
    args.insert("expected_bundle_sha256".into(), prepared["bundle_sha256"].clone());
    args
}
fn blob(backend: &mut NodeTools, path: &[u8]) -> Value {
    backend.call("frankengit_source_blob", &fields([
        ("reference", text("refs/heads/main")), ("path_hex", text(hex(path))),
    ])).unwrap()
}
#[test]
fn prepare_inspect_publish_and_lost_reply_retry_preserve_exact_bytes_and_siblings() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, base) = setup(format);
        let before = head_bytes(&backend);
        let original = blob(&mut backend, b"README");
        let prepared = backend.call(NAME, &input(base)).unwrap();
        let mut arguments = inspection(prepared.object().unwrap());
        arguments.insert("expected_head".into(), original.object().unwrap()["snapshot_token"].clone());
        let mut server = server(&mut backend);
        let response = invoke(&mut server, &mut backend, 2, NAME, arguments.clone());
        let inspected = content(&response);
        assert_eq!(inspected["snapshot_token"], original.object().unwrap()["snapshot_token"]);
        assert_eq!(inspected["published"], Value::Bool(false));
        assert_eq!(inspected["approval_granted"], Value::Bool(false));
        assert_eq!(inspected["bundle_sha256"], prepared.object().unwrap()["bundle_sha256"]);
        let review = inspected["review"].object().unwrap();
        assert_eq!(review["entry_count"].text(), Some("1"));
        assert_eq!(review["completion_scope"].text(), Some("entire_candidate_tree"));
        let Value::Array(entries) = &review["entries"] else { unreachable!() };
        let entry = entries[0].object().unwrap();
        assert_eq!(entry["path_hex"].text(), Some(hex(b"README").as_str()));
        let Value::Array(hunks) = &entry["content"].object().unwrap()["hunks"] else { unreachable!() };
        assert!(hunks.iter().any(|h| h.object().unwrap()["before_hex"].text() == Some(hex(b"before\n").as_str())));
        assert!(hunks.iter().any(|h| h.object().unwrap()["after_hex"].text() == Some(hex(b"after\n").as_str())));
        let body = inspected["candidate_commit_text_utf8"].text().unwrap();
        assert!(body.contains("author Author <author@example.invalid> 2 +0000\n"));
        assert!(body.ends_with("edit through MCP\n"));
        let candidate = oid(&arguments, "expected_candidate", format).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err());
        let mut publication = inspected["publication_arguments"].object().unwrap().clone();
        publication.insert("idempotency_key".into(), text("explicit-inspected-publication"));
        assert_eq!(backend.call("frankengit_source_publish", &publication).unwrap_err().code, "tool_not_granted");
        assert_eq!(head_bytes(&backend), before);

        // A separately launched operator grant, not tool arguments or mutable
        // repository text, enables publication as the sponsor principal.
        let mut options = backend.options.clone();
        options.writes.source = true;
        options.principal = Some(sponsor());
        backend.close().unwrap();
        let mut backend = NodeTools::open(options.clone()).unwrap();
        let mut server = self::server(&mut backend);
        let response = invoke(&mut server, &mut backend, 2, "frankengit_source_publish", publication.clone());
        let committed = content(&response);
        assert_eq!(committed["outcome"].text(), Some("committed"));
        let after = head_bytes(&backend);
        assert_ne!(after, before);
        let retry = invoke(&mut server, &mut backend, 3, "frankengit_source_publish", publication);
        assert_eq!(content(&retry), committed);
        assert_eq!(head_bytes(&backend), after, "lost replies do not duplicate publication");
        assert_eq!(blob(&mut backend, b"README").object().unwrap()["bytes_hex"].text(), Some(hex(b"after\n").as_str()));
        assert_eq!(blob(&mut backend, b"sibling").object().unwrap()["bytes_hex"].text(), Some(hex(b"untouched\n").as_str()));
        assert!(backend.call(NAME, &arguments).is_err(), "old inspection pins cannot survive a ref move");
        backend.close().unwrap();
        options.writes.source = false;
        options.principal = None;
        let mut backend = NodeTools::open(options).unwrap();
        assert_eq!(head_bytes(&backend), after);
        assert_eq!(blob(&mut backend, b"README").object().unwrap()["bytes_hex"].text(), Some(hex(b"after\n").as_str()));
        backend.close().unwrap();
    }
}
#[test]
fn corrupt_candidates_stale_pins_and_incomplete_diffs_never_disclose_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, base) = setup(format);
        let before = head_bytes(&backend);
        let mut command = input(base);
        command.insert("patch".into(), text(format!("{PATCH}diff --git a/sibling b/sibling\n--- a/sibling\n+++ b/sibling\n@@ -1 +1 @@\n-untouched\n+also changed\n")));
        let prepared = backend.call(NAME, &command).unwrap();
        let arguments = inspection(prepared.object().unwrap());
        let full = backend.call(NAME, &arguments).unwrap();
        assert_eq!(full.object().unwrap()["review"].object().unwrap()["entry_count"].text(), Some("2"));
        let mut budget = arguments.clone();
        budget.insert("max_changes".into(), json::number(1));
        assert_eq!(backend.call(NAME, &budget).unwrap_err().code, "candidate_inspection_failed");
        budget = arguments.clone();
        budget.insert("max_output_bytes".into(), json::number(1));
        assert!(backend.call(NAME, &budget).is_err());
        let mut corrupt = arguments.clone();
        let mut bytes = chunks(&corrupt, "bundle_hex_chunks").unwrap();
        let last = bytes.last_mut().unwrap(); *last ^= 1;
        corrupt.remove("expected_bundle_sha256");
        corrupt.insert("bundle_hex_chunks".into(), encoded_chunks(&bytes).unwrap());
        assert_eq!(backend.call(NAME, &corrupt).unwrap_err().code, "candidate_inspection_failed");
        let mut wrong = arguments.clone();
        wrong.insert("expected_candidate".into(), text("ef".repeat(format.digest_len())));
        assert!(backend.call(NAME, &wrong).is_err());
        wrong = arguments.clone();
        wrong.insert("expected_head".into(), text(format!("alg:1:{}", "ef".repeat(32))));
        assert!(backend.call(NAME, &wrong).is_err());
        assert_eq!(backend.call(NAME, &arguments).unwrap(), full);
        assert_eq!(head_bytes(&backend), before);
        backend.options.source = false;
        backend.options.writes.source = true;
        assert_eq!(call(&backend, &arguments).unwrap_err().code, "tool_not_granted");
        backend.close().unwrap();
    }
}
#[test]
fn candidate_review_reuses_ref_snapshot_and_span_validation_without_a_filtered_escape() {
    use fgit_forge::review::{ComparisonMode, ReviewOptions};
    let (_scratch, mut backend, base) = setup(GitHashAlgorithm::Sha1);
    let prepared = backend.call(NAME, &input(base)).unwrap();
    let args = inspection(prepared.object().unwrap());
    let reference = branch(&args, "reference", "reference_hex").unwrap();
    let candidate = oid(&args, "expected_candidate", GitHashAlgorithm::Sha1).unwrap();
    let bytes = chunks(&args, "bundle_hex_chunks").unwrap();
    let request = backend.node.request_context();
    let options = || ReviewOptions { mode: ComparisonMode::Direct, ..ReviewOptions::default() };
    let mut native = backend.node.runtime().block_on(backend.node.inspect_workspace_bundle_in(
        &request, &reference, base, candidate, &bytes, &Default::default(), None, &options(),
    )).unwrap();
    assert!(super::super::review::render_candidate(&backend, &reference, base, candidate, None, options(), &native.review).is_ok());
    let mut filtered = options(); filtered.paths.push(b"README".to_vec());
    assert!(super::super::review::render_candidate(&backend, &reference, base, candidate, None, filtered, &native.review).is_err());
    native.review.comparison.requested_after = base;
    assert!(super::super::review::render_candidate(&backend, &reference, base, candidate, None, options(), &native.review).is_err());
    native.review.comparison.requested_after = candidate;
    native.review.before_reference = RefName::try_new(b"refs/heads/wrong").unwrap();
    assert!(super::super::review::render_candidate(&backend, &reference, base, candidate, None, options(), &native.review).is_err());
    backend.close().unwrap();
}
