//! Real native initial publication and restart through the MCP adapter.
use super::*;
use super::super::super::super::protocol::{ReadTools, Server};
use super::super::super::{Options, candidate};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

fn fields<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(values) else { unreachable!() };
    fields
}
fn command(format: GitHashAlgorithm) -> Object {
    fields([
        ("initial", Value::Bool(true)), ("reference", text("refs/heads/main")),
        ("expected_candidate", text("11".repeat(format.digest_len()))),
        ("bundle_hex_chunks", Value::Array(vec![text("00")])),
        ("idempotency_key", text("explicit-original-key")),
    ])
}
#[test]
fn initial_publish_never_infers_absence_or_ignores_conflicting_preconditions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let args = command(format);
        let input = parse(&args, format).unwrap();
        assert_eq!(input.reference.as_bytes(), b"refs/heads/main");
        assert_eq!(input.bytes, [0]);
        for value in [Value::Bool(false), Value::Null, text("true"), json::number(1)] {
            let mut bad = args.clone(); bad.insert("initial".into(), value);
            assert_eq!(parse(&bad, format).unwrap_err().code, "initial_must_be_true");
        }
        let mut bad = args.clone(); bad.remove("initial");
        assert!(parse(&bad, format).is_err());
        for (name, value) in [
            ("expected_base", text("22".repeat(format.digest_len()))),
            ("expected_head", text("must-not-refresh")), ("principal", text("33".repeat(16))),
            ("force", Value::Bool(true)), ("bundle_path", text("/tmp/bundle")),
        ] {
            let mut bad = args.clone(); bad.insert(name.into(), value);
            assert_eq!(parse(&bad, format).unwrap_err().code, "unknown_argument");
        }
        let mut bad = args.clone(); bad.insert("expected_candidate".into(), text("00".repeat(format.digest_len())));
        assert!(parse(&bad, format).is_err());
        bad = args.clone(); bad.insert("expected_candidate".into(), text("11".repeat(if format == GitHashAlgorithm::Sha1 { 32 } else { 20 })));
        assert!(parse(&bad, format).is_err());
        bad = args.clone(); bad.insert("reference_hex".into(), text(hex(b"refs/heads/main")));
        assert!(parse(&bad, format).is_err());
        assert!(super::super::parse(PUBLISH, &args, format).is_err(), "legacy input cannot silently ignore initial");
    }
}
#[test]
fn initial_publication_keeps_the_closed_bundle_envelope() {
    let mut args = command(GitHashAlgorithm::Sha1);
    for chunks in [
        vec![], vec![text("")], vec![text("0")], vec![text("AB")],
        vec![text("aa".repeat(CHUNK_BYTES + 1))], vec![text("00"); MAX_CHUNKS + 1],
    ] {
        args.insert("bundle_hex_chunks".into(), Value::Array(chunks));
        assert!(parse(&args, GitHashAlgorithm::Sha1).is_err());
    }
    args.insert("bundle_hex_chunks".into(), Value::Array(vec![text("ab".repeat(CHUNK_BYTES)); MAX_CHUNKS]));
    assert_eq!(parse(&args, GitHashAlgorithm::Sha1).unwrap().bytes.len(), MAX_BUNDLE_BYTES);
    args.remove("idempotency_key");
    assert!(common::key(&args).is_err());
}
#[test]
fn schema_keeps_creation_and_incremental_predecessors_disjoint_in_one_tool() {
    let combined = super::super::schema(PUBLISH);
    let schema = combined.object().unwrap();
    let properties = schema["properties"].object().unwrap();
    assert_eq!(properties["initial"].object().unwrap()["const"], Value::Bool(true));
    assert!(properties.contains_key("expected_base"));
    let Value::Array(common) = &schema["required"] else { unreachable!() };
    assert!(!common.contains(&text("expected_base")));
    assert!(!common.contains(&text("initial")));
    for name in ["idempotency_key", "expected_candidate", "bundle_hex_chunks"] {
        assert!(common.contains(&text(name)));
    }
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let Value::Array(variants) = &schema["oneOf"] else { unreachable!() };
    assert_eq!(variants.len(), 2);
    for (index, variant) in variants.iter().enumerate() {
        let fields = variant.object().unwrap();
        let required = if index == 0 { "expected_base" } else { "initial" };
        let forbidden = if index == 0 { "initial" } else { "expected_base" };
        assert_eq!(fields["required"], Value::Array(vec![text(required)]));
        assert_eq!(fields["not"].object().unwrap()["required"], Value::Array(vec![text(forbidden)]));
    }
    assert_eq!(tools().len(), 5);
    assert!(super::super::schema(CREATE).object().unwrap().get("oneOf").is_none());
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn actor() -> PrincipalId { PrincipalId::from_bytes([0xd3; 16]) }
fn empty(format: GitHashAlgorithm) -> (Scratch, NodeTools) {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fg-mcp-initial-publish-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xd1; 16]);
    let repository = RepositoryId::from_bytes([0xd2; 16]);
    let (node, _) = OneNode::init(NodeConfig::new(scratch.0.join("node"), tenant, repository)
        .with_object_format(format).with_worker_threads(2)).unwrap();
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"), tenant, repository, format,
        incarnation: Some(incarnation), issues: false, pulls: false, source: true,
        writes: Default::default(), outcomes: false, principal: None, max_messages: 32,
    }).unwrap();
    (scratch, backend)
}
fn preparation(reference: &str, content: &str) -> Object {
    fields([
        ("operation", text("prepare_initial")), ("reference", text(reference)),
        ("patch", text(format!("diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+{content}\ndiff --git a/empty b/empty\nnew file mode 100755\n--- /dev/null\n+++ b/empty\n"))),
        ("author", text("Author <a@example.invalid>")), ("committer", text("Committer <c@example.invalid>")),
        ("timestamp", text("1")), ("message_hex", text(hex(b"initial over MCP\n"))),
    ])
}
fn prepared(backend: &mut NodeTools, reference: &str, content: &str) -> Value {
    backend.call(candidate::NAME, &preparation(reference, content)).unwrap()
}
fn publication(prepared: &Value, key: &str) -> Object {
    let mut args = prepared.object().unwrap()["publication_arguments"].object().unwrap().clone();
    args.insert("idempotency_key".into(), text(key));
    args
}
fn writer(backend: NodeTools, reads: bool) -> NodeTools {
    let mut options = backend.options.clone();
    options.source = reads;
    options.writes.source = true;
    options.principal = Some(actor());
    backend.close().unwrap();
    NodeTools::open(options).unwrap()
}
fn head(backend: &NodeTools) -> Vec<u8> {
    backend.node.runtime().block_on(backend.node.authenticate_authority_head())
        .unwrap().receipt().body().to_vec()
}
fn blob(backend: &mut NodeTools, reference: &str, path: &[u8]) -> Value {
    backend.call("frankengit_source_blob", &fields([
        ("reference", text(reference)), ("path_hex", text(hex(path))),
    ])).unwrap()
}
fn server(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"initial-publish-test","version":"1"}}}"#).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    server
}
fn invoke(server: &mut Server, backend: &mut NodeTools, id: u64, args: &Object) -> Value {
    let wire = object([
        ("jsonrpc", text("2.0")), ("id", json::number(id)), ("method", text("tools/call")),
        ("params", object([("name", text(PUBLISH)), ("arguments", Value::Object(args.clone()))])),
    ]).encode(json::MAX_INPUT).unwrap();
    server.receive(backend, wire.as_bytes()).unwrap()
}
fn content(response: &Value) -> &Object {
    response.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap()
}

#[test]
fn empty_repo_prepare_publish_retry_and_reopen_preserve_exact_native_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let initial = prepared(&mut backend, "refs/heads/main", "first");
        let args = publication(&initial, "original-initial");
        let before = head(&backend);
        assert_eq!(backend.call(PUBLISH, &args).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(&backend, &args).unwrap_err().code, "tool_not_granted");
        assert_eq!(head(&backend), before);
        // A write-only launch can submit offered bytes but cannot prepare/read.
        let mut backend = writer(backend, false);
        assert_eq!(backend.call(candidate::NAME, &preparation("refs/heads/main", "first")).unwrap_err().code, "tool_not_granted");
        let mut server = server(&mut backend);
        let response = invoke(&mut server, &mut backend, 2, &args);
        let committed = content(&response);
        assert_eq!(committed["outcome"].text(), Some("committed"));
        assert_eq!(committed["action"].text(), Some("publish_initial"));
        assert_eq!(committed["current_refs_asserted"], Value::Bool(false));
        assert_eq!(committed["bundle_validation_receipt"], Value::Null);
        let after = head(&backend);
        assert_ne!(before, after);
        let retry = invoke(&mut server, &mut backend, 3, &args);
        assert_eq!(content(&retry), committed);
        assert_eq!(head(&backend), after);
        assert!(backend.is_mutation(PUBLISH));
        let committed = Value::Object(committed.clone());
        let mut backend = writer(backend, true);
        assert_eq!(backend.call(PUBLISH, &args).unwrap(), committed);
        assert_eq!(head(&backend), after);
        assert_eq!(blob(&mut backend, "refs/heads/main", b"README").object().unwrap()["bytes_hex"].text(), Some(hex(b"first\n").as_str()));
        assert_eq!(blob(&mut backend, "refs/heads/main", b"empty").object().unwrap()["bytes_hex"].text(), Some(""));
        let id = oid(&args, "expected_candidate", format).unwrap();
        let commit = backend.node.read_git_object(id).unwrap();
        assert_eq!(hex(commit.payload()), initial.object().unwrap()["candidate_commit_body_hex"].text().unwrap());
        assert!(!commit.payload().windows(8).any(|bytes| bytes == b"\nparent "));
        backend.close().unwrap();
    }
}

#[test]
fn competing_initial_candidates_terminalize_once_and_never_overwrite_the_winner() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let first = prepared(&mut backend, "refs/heads/main", "winner");
        let second = prepared(&mut backend, "refs/heads/main", "loser");
        let a = publication(&first, "winner-key");
        let b = publication(&second, "loser-key");
        let mut backend = writer(backend, true);
        let won = backend.call(PUBLISH, &a).unwrap();
        assert_eq!(won.object().unwrap()["outcome"].text(), Some("committed"));
        let mut server = server(&mut backend);
        let reply = invoke(&mut server, &mut backend, 2, &b);
        assert_eq!(reply.object().unwrap()["result"].object().unwrap()["isError"], Value::Bool(true));
        let lost = Value::Object(content(&reply).clone());
        assert_eq!(lost.object().unwrap()["outcome"].text(), Some("refused"));
        let after = head(&backend);
        assert_eq!(backend.call(PUBLISH, &b).unwrap(), lost);
        assert_eq!(backend.call(PUBLISH, &a).unwrap(), won);
        let mut reused = b.clone(); reused.insert("idempotency_key".into(), text("winner-key"));
        assert!(backend.call(PUBLISH, &reused).is_err());
        assert_eq!(head(&backend), after);
        assert_eq!(blob(&mut backend, "refs/heads/main", b"README").object().unwrap()["bytes_hex"].text(), Some(hex(b"winner\n").as_str()));
        assert!(backend.call(candidate::NAME, &preparation("refs/heads/main", "replacement")).is_err());
        let mut other = preparation("refs/heads/other", "independent");
        other.insert("expected_head".into(), first.object().unwrap()["snapshot_token"].clone());
        assert!(backend.call(candidate::NAME, &other).is_err());
        other.remove("expected_head");
        let independent = backend.call(candidate::NAME, &other).unwrap();
        assert_eq!(backend.call(PUBLISH, &publication(&independent, "other-key")).unwrap().object().unwrap()["outcome"].text(), Some("committed"));
        assert_eq!(blob(&mut backend, "refs/heads/main", b"README").object().unwrap()["bytes_hex"].text(), Some(hex(b"winner\n").as_str()));
        backend.close().unwrap();
    }
}

#[test]
fn invalid_initial_bundles_and_coordinates_do_not_publish_and_valid_twins_do() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let initial = prepared(&mut backend, "refs/heads/main", "verified");
        let args = publication(&initial, "valid-key");
        let mut backend = writer(backend, true);
        let before = head(&backend);
        let mut corrupt = args.clone();
        let mut bytes = bundle(&args).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        corrupt.insert("bundle_hex_chunks".into(), Value::Array(bytes.chunks(CHUNK_BYTES).map(|chunk| text(hex(chunk))).collect()));
        assert!(backend.call(PUBLISH, &corrupt).is_err());
        let mut wrong = args.clone(); wrong.insert("expected_candidate".into(), text("ee".repeat(format.digest_len())));
        assert!(backend.call(PUBLISH, &wrong).is_err());
        wrong = args.clone(); wrong.insert("reference_hex".into(), text(hex(b"refs/heads/wrong")));
        assert!(backend.call(PUBLISH, &wrong).is_err());
        assert_eq!(head(&backend), before);
        let id = oid(&args, "expected_candidate", format).unwrap();
        assert!(backend.node.read_git_object(id).is_err());
        let accepted = backend.call(PUBLISH, &args).unwrap();
        assert_eq!(accepted.object().unwrap()["outcome"].text(), Some("committed"));
        backend.close().unwrap();
    }
}

#[test]
fn ordinary_incremental_publication_still_extends_initial_history_without_a_flag() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let initial = prepared(&mut backend, "refs/heads/main", "before");
        let initial_args = publication(&initial, "initial-key");
        let mut backend = writer(backend, true);
        let original = backend.call(PUBLISH, &initial_args).unwrap();
        let mut patch = preparation("refs/heads/main", "unused");
        patch.insert("operation".into(), text("prepare_patch"));
        patch.insert("expected_base".into(), initial.object().unwrap()["candidate_commit"].clone());
        patch.insert("patch".into(), text("diff --git a/README b/README\n--- a/README\n+++ b/README\n@@ -1 +1 @@\n-before\n+after\n"));
        patch.insert("timestamp".into(), text("2"));
        let incremental = backend.call(candidate::NAME, &patch).unwrap();
        let args = publication(&incremental, "incremental-key");
        assert!(!args.contains_key("initial"));
        let accepted = backend.call(PUBLISH, &args).unwrap();
        assert_eq!(accepted.object().unwrap()["action"].text(), Some("publish"));
        assert_eq!(accepted.object().unwrap()["outcome"].text(), Some("committed"));
        let after = head(&backend);
        // Historical initial recovery must not require the branch to be absent
        // or still equal the first tip, and must not restore its old source.
        assert_eq!(backend.call(PUBLISH, &initial_args).unwrap(), original);
        assert_eq!(head(&backend), after);
        assert_eq!(blob(&mut backend, "refs/heads/main", b"README").object().unwrap()["bytes_hex"].text(), Some(hex(b"after\n").as_str()));
        assert_eq!(blob(&mut backend, "refs/heads/main", b"empty").object().unwrap()["bytes_hex"].text(), Some(""));
        backend.close().unwrap();
    }
}
