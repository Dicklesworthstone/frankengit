//! Parser and native persisted-node regressions, not a substitute repository.
use super::*;
use super::super::super::super::protocol::{ReadTools, Server};
use super::super::super::Options;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

const PATCH: &str = "diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+first\ndiff --git a/src/run b/src/run\nnew file mode 100755\n--- /dev/null\n+++ b/src/run\n@@ -0,0 +1 @@\n+last\n\\ No newline at end of file\n";
fn arguments() -> Object {
    let Value::Object(fields) = object([
        ("operation", text("prepare_initial")),
        ("reference", text("refs/heads/main")), ("patch", text(PATCH)),
        ("author", text("Author <author@example.invalid>")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("1")), ("message_hex", text(hex(b"first commit\n"))),
    ]) else { unreachable!() };
    fields
}

#[test]
fn initial_parser_requires_explicit_creation_without_synthetic_base_or_authority() {
    let args = arguments();
    let input = parse(&args).unwrap();
    assert_eq!(input.patch, PATCH.as_bytes());
    assert!(input.expected_head.is_none());
    for (name, value) in [
        ("expected_base", text("11".repeat(20))), ("principal", text("22".repeat(16))),
        ("idempotency_key", text("must-not-publish")), ("force", Value::Bool(true)),
        ("paths_hex", Value::Array(vec![])),
    ] {
        let mut bad = args.clone(); bad.insert(name.into(), value);
        assert_eq!(parse(&bad).err().unwrap().code, "unknown_argument");
    }
    for name in ["operation", "author", "committer", "timestamp", "message_hex"] {
        let mut bad = args.clone(); bad.remove(name);
        assert!(parse(&bad).is_err(), "missing {name}");
    }
    let mut bad = args.clone(); bad.insert("operation".into(), text("prepare_patch"));
    assert!(parse(&bad).is_err());
    bad = args.clone(); bad.insert("timestamp".into(), text("0"));
    assert!(parse(&bad).is_err());
    bad = args.clone(); bad.insert("expected_head".into(), text("not-a-head"));
    assert!(parse(&bad).is_err());
}

#[test]
fn initial_byte_input_uses_the_existing_closed_chunk_and_metadata_bounds() {
    let mut args = arguments();
    args.remove("patch");
    let bytes = [b'\xff', b'\r', b'\n'];
    args.insert("patch_hex_chunks".into(), encoded_chunks(&bytes).unwrap());
    assert_eq!(parse(&args).unwrap().patch, bytes);
    args.insert("patch".into(), text(PATCH));
    assert!(parse(&args).is_err());
    args.remove("patch");
    args.insert("patch_hex_chunks".into(), Value::Array(vec![text("aa".repeat(CHUNK_BYTES + 1))]));
    assert!(parse(&args).is_err());
    let mut args = arguments();
    args.insert("message_hex".into(), text("aa".repeat(4097)));
    assert!(parse(&args).is_err());
}

#[test]
fn initial_preview_comes_from_verified_native_file_and_commit_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = parse(&arguments()).unwrap();
        let plan = fgit_forge::initial_commit::prepare_initial_commit(
            format, &input.patch, &input.metadata, PatchLimits::default(), &|| false,
        ).unwrap();
        let (Value::Array(files), commit) = preview(&plan).unwrap() else { unreachable!() };
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].object().unwrap()["bytes_hex"].text(), Some(hex(b"first\n").as_str()));
        assert_eq!(files[1].object().unwrap()["bytes_hex"].text(), Some(hex(b"last").as_str()));
        assert_eq!(files[1].object().unwrap()["mode"].text(), Some("100755"));
        assert!(!commit.split(|byte| *byte == b'\n').any(|line| line.starts_with(b"parent ")));
        assert_eq!(git_object_id(format, GitObjectKind::Commit, commit), plan.commit);
        let mut bad = plan.clone(); bad.files[0].bytes += 1;
        assert!(preview(&bad).is_err());
        bad = plan.clone(); bad.files[0].mode = 0o120000;
        assert!(preview(&bad).is_err());
        bad = plan.clone(); bad.files.swap(0, 1);
        assert!(preview(&bad).is_err());
        bad = plan.clone(); bad.objects.iter_mut().find(|o| o.id == plan.files[0].blob).unwrap().body.push(0);
        assert!(preview(&bad).is_err());
        assert!(preview(&plan).is_ok());
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn empty(format: GitHashAlgorithm) -> (Scratch, NodeTools) {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fg-mcp-initial-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xc1; 16]);
    let repository = RepositoryId::from_bytes([0xc2; 16]);
    let (node, _) = OneNode::init(NodeConfig::new(scratch.0.join("node"), tenant, repository)
        .with_object_format(format).with_worker_threads(2)).unwrap();
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"), tenant, repository, format,
        incarnation: Some(incarnation), source: true, issues: false, pulls: false,
        writes: Default::default(), outcomes: false, principal: None, max_messages: 32,
    }).unwrap();
    (scratch, backend)
}
fn head(backend: &NodeTools) -> Vec<u8> {
    backend.node.runtime().block_on(backend.node.authenticate_authority_head())
        .unwrap().receipt().body().to_vec()
}

#[test]
fn empty_repository_prepares_over_mcp_without_staging_or_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let before = head(&backend);
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"initial-test","version":"1"}}}"#).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let wire = object([
            ("jsonrpc", text("2.0")), ("id", json::number(2)), ("method", text("tools/call")),
            ("params", object([("name", text(NAME)), ("arguments", Value::Object(arguments()))])),
        ]).encode(json::MAX_INPUT).unwrap();
        let response = server.receive(&mut backend, wire.as_bytes()).unwrap();
        let result = response.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap();
        assert_eq!(result["source_commit"], Value::Null);
        assert_eq!(result["parents"], Value::Array(Vec::new()));
        assert_eq!(result["published"], Value::Bool(false));
        assert_eq!(result["file_count"].text(), Some("2"));
        let mut pinned = arguments(); pinned.insert("expected_head".into(), result["snapshot_token"].clone());
        assert_eq!(backend.call(NAME, &pinned).unwrap().object().unwrap(), result);
        let candidate = GitOid::from_hex(format, result["candidate_commit"].text().unwrap()).unwrap();
        assert!(backend.node.read_git_object(candidate).is_err());
        assert_eq!(head(&backend), before);
        assert!(!backend.is_mutation(NAME));
        // Writing does not implicitly authorize preparation, even for empty repos.
        backend.options.source = false;
        backend.options.writes.source = true;
        backend.options.principal = Some(PrincipalId::from_bytes([0xc3; 16]));
        assert_eq!(backend.call(NAME, &arguments()).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(&backend, &arguments()).unwrap_err().code, "tool_not_granted");
        assert_eq!(head(&backend), before);
        backend.close().unwrap();
    }
}
