//! Transport tests plus actual native calls through the persisted MCP backend.
use super::*;
use super::super::super::super::protocol::{ReadTools, Server};
use super::super::super::Options;
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{PrincipalId, RepositoryId, TenantId};
use std::{fs, path::PathBuf, sync::atomic::{AtomicU64, Ordering}};

fn fields<const N: usize>(input: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(input) else { unreachable!() };
    fields
}
fn arguments(format: GitHashAlgorithm) -> Object {
    fields([
        ("operation", text("inspect_initial")), ("initial", Value::Bool(true)),
        ("reference", text("refs/heads/main")),
        ("expected_candidate", text("ab".repeat(format.digest_len()))),
        ("bundle_hex_chunks", encoded_chunks(b"transport parser only").unwrap()),
    ])
}

#[test]
fn root_inspection_requires_independent_coordinates_and_never_accepts_publication_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let args = arguments(format);
        assert_eq!(parse(&args, format).unwrap().bytes, b"transport parser only");
        let mut no_flag = args.clone(); no_flag.remove("initial");
        assert!(parse(&no_flag, format).is_ok());
        for name in ["operation", "expected_candidate", "bundle_hex_chunks", "reference"] {
            let mut bad = args.clone(); bad.remove(name);
            assert!(parse(&bad, format).is_err(), "{name}");
        }
        for name in ["expected_base", "paths_hex", "author", "principal", "force", "idempotency_key", "bundle_path", "patch"] {
            let mut bad = args.clone(); bad.insert(name.into(), text("not authority"));
            assert_eq!(parse(&bad, format).err().unwrap().code, "unknown_argument");
        }
        for value in [Value::Bool(false), Value::Null, text("true"), json::number(1)] {
            let mut bad = args.clone(); bad.insert("initial".into(), value);
            assert!(parse(&bad, format).is_err());
        }
        let mut raw = args.clone(); raw.remove("reference");
        raw.insert("reference_hex".into(), text(hex(b"refs/heads/raw-\xff")));
        assert_eq!(parse(&raw, format).unwrap().reference.as_bytes(), b"refs/heads/raw-\xff");
        raw.insert("reference".into(), text("refs/heads/main"));
        assert!(parse(&raw, format).is_err());
        for candidate in ["0".repeat(format.digest_len() * 2), "latest".into(), "AB".repeat(format.digest_len())] {
            let mut bad = args.clone(); bad.insert("expected_candidate".into(), text(candidate));
            assert!(parse(&bad, format).is_err());
        }
    }
}

#[test]
fn exact_transport_pins_and_work_limits_are_checked_before_native_selection() {
    let args = arguments(GitHashAlgorithm::Sha256);
    let mut pinned = args.clone();
    pinned.insert("expected_bundle_sha256".into(), text(hex(&sha256_digest(b"transport parser only"))));
    assert!(parse(&pinned, GitHashAlgorithm::Sha256).is_ok());
    for wrong in ["ff".repeat(32), "ab".repeat(31), "not a hash".into()] {
        let mut bad = args.clone(); bad.insert("expected_bundle_sha256".into(), text(wrong));
        assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err());
    }
    for &(name, maximum) in LIMITS {
        let mut exact = args.clone(); exact.insert(name.into(), json::number(maximum as u64));
        assert!(parse(&exact, GitHashAlgorithm::Sha256).is_ok());
        for value in [json::number(0), json::number(maximum as u64 + 1), text("1"), Value::Bool(true)] {
            let mut bad = args.clone(); bad.insert(name.into(), value);
            assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err(), "{name}");
        }
    }
    for fragments in [Value::Array(vec![]), Value::Array(vec![text("aa"); 4]),
        Value::Array(vec![text("aa".repeat(CHUNK_BYTES + 1))])]
    {
        let mut bad = args.clone(); bad.insert("bundle_hex_chunks".into(), fragments);
        assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err());
    }
}

#[test]
fn discovery_and_maximum_input_retain_the_existing_registry_and_json_envelope() {
    let descriptor = schema();
    let properties = descriptor.object().unwrap()["properties"].object().unwrap();
    for forbidden in ["expected_base", "principal", "idempotency_key", "force", "paths_hex"] {
        assert!(!properties.contains_key(forbidden));
    }
    let Value::Array(required) = &descriptor.object().unwrap()["required"] else { unreachable!() };
    assert!(required.contains(&text("expected_candidate")));
    assert!(required.contains(&text("bundle_hex_chunks")));
    let mut input = arguments(GitHashAlgorithm::Sha256);
    input.remove("reference");
    input.insert("reference_hex".into(), text("ab".repeat(4096)));
    input.insert("bundle_hex_chunks".into(), encoded_chunks(&vec![0xab; MAX_BUNDLE_BYTES]).unwrap());
    input.insert("expected_bundle_sha256".into(), text("ff".repeat(32)));
    let request = object([
        ("jsonrpc", text("2.0")), ("id", text("i".repeat(128))), ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(input))])),
    ]);
    let encoded = request.encode(json::MAX_INPUT).unwrap();
    assert_eq!(json::parse(encoded.as_bytes()).unwrap(), request);
    assert!(super::super::tool().schema.encode(MAX_TOOL_RESULT).is_ok());
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn empty(format: GitHashAlgorithm) -> (Scratch, NodeTools) {
    let scratch = Scratch(std::env::temp_dir().join(format!("fg-mcp-root-inspect-{}-{}",
        std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xd1; 16]);
    let repository = RepositoryId::from_bytes([0xd2; 16]);
    let (node, _) = OneNode::init(NodeConfig::new(scratch.0.join("node"), tenant, repository)
        .with_object_format(format).with_worker_threads(2)).unwrap();
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"), tenant, repository, format, incarnation: Some(incarnation),
        source: true, issues: false, pulls: false, writes: Default::default(), outcomes: false,
        principal: None, max_messages: 32,
    }).unwrap();
    (scratch, backend)
}
fn head(backend: &NodeTools) -> Vec<u8> {
    backend.node.runtime().block_on(backend.node.authenticate_authority_head())
        .unwrap().receipt().body().to_vec()
}
fn prepare(backend: &mut NodeTools) -> Value {
    backend.call(NAME, &fields([
        ("operation", text("prepare_initial")), ("reference", text("refs/heads/main")),
        ("patch", text("diff --git a/README b/README\nnew file mode 100644\n--- /dev/null\n+++ b/README\n@@ -0,0 +1 @@\n+first\ndiff --git a/src/run b/src/run\nnew file mode 100755\n--- /dev/null\n+++ b/src/run\n@@ -0,0 +1 @@\n+last\n\\ No newline at end of file\n")),
        ("author", text("Author <author@example.invalid>")),
        ("committer", text("Committer <committer@example.invalid>")),
        ("timestamp", text("1")), ("message_hex", text(hex(b"root commit\n"))),
    ])).unwrap()
}
fn inspection(prepared: &Value) -> Object {
    let prepared = prepared.object().unwrap();
    let mut args = prepared["publication_arguments"].object().unwrap().clone();
    args.insert("operation".into(), text("inspect_initial"));
    args.insert("expected_head".into(), prepared["snapshot_token"].clone());
    args.insert("expected_bundle_sha256".into(), prepared["bundle_sha256"].clone());
    args
}
fn server(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"root-inspection","version":"1"}}}"#).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    server
}
fn invoke(server: &mut Server, backend: &mut NodeTools, args: &Object) -> Value {
    let bytes = object([
        ("jsonrpc", text("2.0")), ("id", json::number(2)), ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(args.clone()))])),
    ]).encode(json::MAX_INPUT).unwrap();
    server.receive(backend, bytes.as_bytes()).unwrap()
}

#[test]
fn root_prepare_inspect_separately_publish_retry_and_reopen_preserve_exact_contents() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let before = head(&backend);
        let prepared = prepare(&mut backend);
        let args = inspection(&prepared);
        let mut server = server(&mut backend);
        let response = invoke(&mut server, &mut backend, &args);
        let report = response.object().unwrap()["result"].object().unwrap()["structuredContent"].object().unwrap();
        assert_eq!(report["files"], prepared.object().unwrap()["files"]);
        assert_eq!(report["snapshot_token"], prepared.object().unwrap()["snapshot_token"]);
        assert_eq!(report["candidate_commit_body_hex"], prepared.object().unwrap()["candidate_commit_body_hex"]);
        assert_eq!(report["directory_count"].text(), Some("2"));
        assert_eq!(report["parents"], Value::Array(vec![]));
        assert_eq!(report["published"], Value::Bool(false));
        assert_eq!(report["approval_granted"], Value::Bool(false));
        assert!(!backend.is_mutation(NAME));
        let id = oid(&args, "expected_candidate", format).unwrap();
        assert!(backend.node.read_git_object(id).is_err());
        assert_eq!(head(&backend), before);
        let mut publication = report["publication_arguments"].object().unwrap().clone();
        assert!(!publication.contains_key("idempotency_key"));
        publication.insert("idempotency_key".into(), text("reviewed-initial"));
        assert_eq!(backend.call("frankengit_source_publish", &publication).unwrap_err().code, "tool_not_granted");
        let mut options = backend.options.clone();
        options.source = false; options.writes.source = true;
        options.principal = Some(PrincipalId::from_bytes([0xd3; 16]));
        backend.close().unwrap();
        let mut backend = NodeTools::open(options.clone()).unwrap();
        assert_eq!(backend.call(NAME, &args).unwrap_err().code, "tool_not_granted");
        assert_eq!(call(&backend, &args).unwrap_err().code, "tool_not_granted");
        let result = backend.call("frankengit_source_publish", &publication).unwrap();
        assert_eq!(result.object().unwrap()["outcome"].text(), Some("committed"));
        let after = head(&backend);
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        assert_eq!(backend.call("frankengit_source_publish", &publication).unwrap(), result);
        assert_eq!(head(&backend), after);
        let mut options = backend.options.clone();
        options.source = true; options.writes.source = false; options.principal = None;
        backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        for (path, expected) in [(b"README".as_slice(), b"first\n".as_slice()), (b"src/run", b"last")] {
            let blob = backend.call("frankengit_source_blob", &fields([
                ("reference", text("refs/heads/main")), ("path_hex", text(hex(path))),
            ])).unwrap();
            assert_eq!(blob.object().unwrap()["bytes_hex"].text(), Some(hex(expected).as_str()));
        }
        assert!(backend.call(NAME, &args).is_err());
        backend.close().unwrap();
    }
}

#[test]
fn invalid_transport_pins_and_truncated_preview_budgets_never_return_a_partial_inspection() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = empty(format);
        let prepared = prepare(&mut backend);
        let args = inspection(&prepared);
        let before = head(&backend);
        let good = backend.call(NAME, &args).unwrap();
        for name in ["max_files", "max_tree_entries", "max_file_bytes", "max_output_bytes"] {
            let mut bad = args.clone(); bad.insert(name.into(), json::number(1));
            assert_eq!(backend.call(NAME, &bad).unwrap_err().code, "initial_candidate_inspection_failed");
        }
        let mut corrupt = args.clone(); corrupt.remove("expected_bundle_sha256");
        let mut bytes = chunks(&corrupt, "bundle_hex_chunks").unwrap(); *bytes.last_mut().unwrap() ^= 1;
        corrupt.insert("bundle_hex_chunks".into(), encoded_chunks(&bytes).unwrap());
        assert_eq!(backend.call(NAME, &corrupt).unwrap_err().code, "initial_candidate_inspection_failed");
        let mut wrong_digest = args.clone(); wrong_digest.insert("expected_bundle_sha256".into(), text("ff".repeat(32)));
        assert_eq!(backend.call(NAME, &wrong_digest).unwrap_err().code, "bundle_digest_mismatch");
        assert_eq!(head(&backend), before);
        assert_eq!(backend.call(NAME, &args).unwrap(), good);
        assert!(backend.node.read_git_object(oid(&args, "expected_candidate", format).unwrap()).is_err());
        backend.close().unwrap();
    }
}

#[test]
fn adapter_rechecks_native_report_bindings_before_encoding_review_data() {
    let (_scratch, mut backend) = empty(GitHashAlgorithm::Sha256);
    let prepared = prepare(&mut backend);
    let args = inspection(&prepared);
    let input = parse(&args, GitHashAlgorithm::Sha256).unwrap();
    let request = backend.node.request_context();
    let (head, report) = backend.node.runtime().block_on(backend.node.inspect_initial_patch_bundle_in(
        &request, &input.reference, input.candidate, &input.bytes, &Default::default(), input.head, input.limits,
    )).unwrap();
    validate(&input, head, &report).unwrap();
    let mut changed = report.clone(); changed.bundle_sha256[0] ^= 1;
    assert!(validate(&input, head, &changed).is_err());
    changed = report.clone(); changed.files[0].content.push(0);
    assert!(validate(&input, head, &changed).is_err());
    changed = report.clone(); changed.directories.remove(0);
    assert!(validate(&input, head, &changed).is_err());
    changed = report.clone(); changed.files.swap(0, 1);
    assert!(validate(&input, head, &changed).is_err());
    changed = report.clone(); changed.candidate_commit = report.root_tree;
    assert!(validate(&input, head, &changed).is_err());
    validate(&input, head, &report).unwrap();
    backend.close().unwrap();
}
