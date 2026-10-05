//! Persisted-node regressions; no substitute search engine or Git subprocess.
use super::*;
use super::super::super::protocol::Server;
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-mcp-search-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fields<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(values) else { unreachable!() };
    value
}
fn open(format: GitHashAlgorithm) -> (Scratch, NodeTools) {
    let scratch = Scratch::new();
    let tenant = TenantId::from_bytes([0xa1; 16]);
    let repository = RepositoryId::from_bytes([0xa2; 16]);
    let (mut node, _) = OneNode::init(NodeConfig::new(scratch.0.join("node"), tenant, repository)
        .with_object_format(format).with_worker_threads(2)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let patch = b"diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1,2 @@\n+hello MCP\n+hello MCP again\ndiff --git a/z b/z\nnew file mode 100644\n--- /dev/null\n+++ b/z\n@@ -0,0 +1 @@\n+second\n";
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 1,
        message: b"initial\n".to_vec(),
    };
    let request = node.request_context();
    let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
        &request, &reference, patch, &metadata, Default::default(), None,
    )).unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xa3; 16]),
        IdempotencyKey::new(b"search-initial".to_vec()).unwrap(),
    );
    let accepted = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
        &request, &session, &reference, plan.commit, bundle.bytes(), Default::default(),
    )).unwrap();
    assert!(matches!(accepted.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"), tenant, repository, format,
        incarnation: Some(incarnation), issues: false, pulls: false, source: true,
        writes: Default::default(), outcomes: false, principal: None, max_messages: 16,
    }).unwrap();
    (scratch, backend)
}
fn request() -> Object {
    fields([("reference", text("refs/heads/main")), ("needle_hex", text(hex(b"MCP")))])
}
fn result(value: &Value) -> &Object {
    value.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap()
}

#[test]
fn reopened_sha1_and_sha256_search_is_pinned_complete_and_read_only() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = open(format);
        assert!(!backend.is_mutation(NAME));
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"search-test","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let first = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_source_search","arguments":{"reference":"refs/heads/main","needle_hex":"4d4350","max_matches":1}}}"#).unwrap();
        let first = result(&first);
        assert_eq!(first["complete"], Value::Bool(false));
        assert_eq!(first["truncated_reason"].text(), Some("match_limit"));
        assert_eq!(first["match_count"].text(), Some("1"));
        let mut pinned = request();
        pinned.insert("expected_head".into(), first["snapshot_token"].clone());
        pinned.insert("expected_commit".into(), first["source_commit"].clone());
        let full = backend.call(NAME, &pinned).unwrap();
        let full = full.object().unwrap();
        assert_eq!(full["snapshot_token"], first["snapshot_token"]);
        assert_eq!(full["source_commit"], first["source_commit"]);
        assert_eq!(full["source_tree"], first["source_tree"]);
        assert_eq!(full["complete"], Value::Bool(true));
        assert_eq!(full["match_count"].text(), Some("2"));
        assert_eq!(full["read_only"], Value::Bool(true));
        let mut absent = pinned.clone();
        absent.insert("needle_hex".into(), text(hex(b"absent")));
        assert_eq!(backend.call(NAME, &absent).unwrap().object().unwrap()["match_count"].text(), Some("0"));
        let mut narrow = pinned.clone();
        narrow.insert("path_prefixes_hex".into(), Value::Array(vec![text(hex(b"z"))]));
        assert_eq!(backend.call(NAME, &narrow).unwrap().object().unwrap()["match_count"].text(), Some("0"));
        let mut moved = pinned.clone();
        moved.insert("expected_commit".into(), text("ab".repeat(format.digest_len())));
        assert_eq!(backend.call(NAME, &moved).unwrap_err().code, "source_commit_moved");
        let mut stale = pinned.clone();
        stale.insert("expected_head".into(), text(head_token(parse_head(&format!("alg:1:{}", "ef".repeat(32))).unwrap())));
        assert_eq!(backend.call(NAME, &stale).unwrap_err().code, "snapshot_moved");
        let mut missing = request();
        missing.insert("reference".into(), text("refs/heads/missing"));
        assert_eq!(backend.call(NAME, &missing).unwrap_err().code, "reference_unavailable");
        let mut budget = pinned.clone();
        budget.insert("max_total_bytes".into(), json::number(1));
        assert_eq!(backend.call(NAME, &budget).unwrap_err().code, "resource_limit");
        // A final pinned read succeeding proves these calls did not publish a
        // new authority head, including refusal paths and truncated searches.
        assert!(backend.call(NAME, &pinned).is_ok());
        backend.options.source = false;
        backend.options.issues = true;
        assert!(backend.tools().iter().all(|tool| tool.name != NAME));
        assert_eq!(backend.call(NAME, &request()).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(&backend, &request()).unwrap_err().code, "tool_not_granted");
        backend.close().unwrap();
    }
}
