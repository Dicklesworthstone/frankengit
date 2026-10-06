//! Native persisted repositories and the actual MCP protocol; no mock matcher.
use super::*;
use super::super::super::super::Options;
use super::super::super::super::protocol::{ReadTools, Server};
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn args(pattern: &str) -> Object {
    let Value::Object(args) = object([("operation", text("regex")), ("reference", text("refs/heads/main")),
        ("pattern", text(pattern))]) else { unreachable!() }; args
}
struct Fixture { root: PathBuf, backend: Option<NodeTools>, commit: GitOid }
impl Fixture {
    fn new(format: GitHashAlgorithm) -> Self {
        let root = std::env::temp_dir().join(format!("fg-mcp-regex-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&root).unwrap();
        let tenant = TenantId::from_bytes([0x91; 16]);
        let repository = RepositoryId::from_bytes([0x92; 16]);
        let (mut node, _) = OneNode::init(NodeConfig::new(root.join("node"), tenant, repository)
            .with_object_format(format).with_worker_threads(2)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let mut patch = b"diff --git a/src/matches b/src/matches\nnew file mode 100644\n--- /dev/null\n+++ b/src/matches\n@@ -0,0 +1,4 @@\n+abbb ab\n+AB\r\n+\n+last\n\\ No newline at end of file\ndiff --git a/src-old/matches b/src-old/matches\nnew file mode 100644\n--- /dev/null\n+++ b/src-old/matches\n@@ -0,0 +1 @@\n+ab\n".to_vec();
        patch.extend_from_slice(format!("diff --git a/long b/long\nnew file mode 100644\n--- /dev/null\n+++ b/long\n@@ -0,0 +1 @@\n+{}\n", "x".repeat(1000)).as_bytes());
        let metadata = MergeMetadata { author: "A <a@example.invalid>".into(), committer: "C <c@example.invalid>".into(), timestamp: 1, message: b"regex fixture\n".to_vec() };
        let request = node.request_context();
        let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
            &request, &reference, &patch, &metadata, Default::default(), None,
        )).unwrap();
        let session = LoopbackReceiveSession::authenticated(PrincipalId::from_bytes([0x93; 16]), IdempotencyKey::new(b"seed-regex".to_vec()).unwrap());
        let published = node.runtime().block_on(node.apply_initial_patch_bundle_durable_in(
            &request, &session, &reference, plan.commit, bundle.bytes(), Default::default(),
        )).unwrap();
        assert!(matches!(published.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let incarnation = node.repository_incarnation_id();
        node.shutdown().unwrap();
        let backend = NodeTools::open(Options { storage: root.join("node"), tenant, repository, format,
            incarnation: Some(incarnation), source: true, issues: false, pulls: false,
            writes: Default::default(), outcomes: false, principal: None, max_messages: 64 }).unwrap();
        Self { root, backend: Some(backend), commit: plan.commit }
    }
    fn backend(&self) -> &NodeTools { self.backend.as_ref().unwrap() }
    fn call(&mut self, args: &Object) -> Result<Value, ToolError> { self.backend.as_mut().unwrap().call(NAME, args) }
    fn head(&self) -> Vec<u8> {
        let node = &self.backend().node;
        node.runtime().block_on(node.authenticate_authority_head()).unwrap().receipt().body().to_vec()
    }
    fn reopen(&mut self) {
        let options = self.backend().options.clone();
        self.backend.take().unwrap().close().unwrap();
        self.backend = Some(NodeTools::open(options).unwrap());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() { backend.close().unwrap(); }
        fs::remove_dir_all(&self.root).unwrap();
    }
}
fn rows(value: &Value) -> &[Value] {
    let Value::Array(rows) = &value.object().unwrap()["matches"] else { unreachable!() }; rows
}

#[test]
fn native_regex_preserves_leftmost_longest_crlf_empty_lines_and_reopen_parity() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let before = f.head();
        let mut query = args("ab+");
        query.insert("path_prefixes_hex".into(), Value::Array(vec![text(hex(b"src"))]));
        query.insert("ignore_ascii_case".into(), Value::Bool(true));
        let result = f.call(&query).unwrap();
        assert_eq!(rows(&result).len(), 2);
        assert_eq!(rows(&result)[0].object().unwrap()["match_bytes_hex"].text(), Some(hex(b"abbb").as_str()));
        assert_eq!(rows(&result)[1].object().unwrap()["byte_offset"].text(), Some("8"));
        assert_eq!(rows(&result)[1].object().unwrap()["excerpt_hex"].text(), Some(hex(b"AB\r").as_str()));
        query.insert("expected_head".into(), result.object().unwrap()["snapshot_token"].clone());
        query.insert("expected_commit".into(), text(f.commit.to_string()));
        f.reopen();
        assert_eq!(f.call(&query).unwrap(), result);
        query.insert("pattern".into(), text("^$"));
        let blank = f.call(&query).unwrap();
        assert_eq!(rows(&blank).len(), 1);
        assert_eq!(rows(&blank)[0].object().unwrap()["line"].text(), Some("3"));
        assert_eq!(rows(&blank)[0].object().unwrap()["match_length"].text(), Some("0"));
        query.insert("pattern".into(), text("last$"));
        assert_eq!(rows(&f.call(&query).unwrap()).len(), 1);
        let long = f.call(&args("^x+$")).unwrap();
        assert_eq!(rows(&long).len(), 1);
        assert_eq!(rows(&long)[0].object().unwrap()["match_fully_in_excerpt"], Value::Bool(false));
        assert_eq!(rows(&long)[0].object().unwrap()["match_length"].text(), Some("1000"));
        assert_eq!(f.head(), before);
    }
}

#[test]
fn native_match_ceiling_differs_from_work_exhaustion_and_pins_never_refresh() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format);
        let before = f.head();
        let mut query = args("ab+"); query.insert("max_matches".into(), json::number(1));
        let partial = f.call(&query).unwrap();
        assert_eq!(partial.object().unwrap()["complete"], Value::Bool(false));
        assert_eq!(rows(&partial).len(), 1);
        query.insert("max_regex_steps".into(), json::number(1));
        assert_eq!(f.call(&query).unwrap_err().code, "resource_limit");
        query.remove("max_regex_steps"); query.insert("expected_commit".into(), text("ab".repeat(format.digest_len())));
        assert!(f.call(&query).is_err());
        query.remove("expected_commit"); query.insert("reference".into(), text("refs/heads/missing"));
        assert_eq!(f.call(&query).unwrap_err().code, "reference_unavailable");
        let node = &f.backend().node;
        let request = fgit_cli::command_request_context(node); request.cancel();
        let query = RegexQuery::new(b"ab+", SearchCase::Exact, &[], MAX_REGEX_STEPS).unwrap();
        assert!(node.runtime().block_on(node.search_source_regex_snapshot_local_in(
            &request, &RefName::try_new(b"refs/heads/main").unwrap(), None, None, &query, Default::default(),
        )).is_err());
        assert_eq!(f.head(), before);
    }
}

#[test]
fn actual_protocol_returns_regex_results_and_write_permission_cannot_grant_reads() {
    let mut f = Fixture::new(GitHashAlgorithm::Sha256);
    let before = f.head();
    let backend = f.backend.as_mut().unwrap();
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"regex-test","version":"1"}}}"#).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    let wire = object([("jsonrpc", text("2.0")), ("id", json::number(2)), ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(args("last$")))]))])
        .encode(json::MAX_INPUT).unwrap();
    let response = server.receive(backend, wire.as_bytes()).unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false));
    assert_eq!(rows(&result["structuredContent"]).len(), 1);
    backend.options.source = false; backend.options.writes.source = true;
    assert_eq!(call(backend, &Object::new()).unwrap_err().code, "tool_not_granted");
    assert_eq!(backend.call(NAME, &args(".*")).unwrap_err().code, "tool_not_granted");
    assert_eq!(f.head(), before);
}
