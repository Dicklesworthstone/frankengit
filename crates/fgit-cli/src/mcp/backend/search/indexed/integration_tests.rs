//! Real persisted lexical indexes and MCP pages. No replacement search engine,
//! foreign Git, fabricated result documents or execution claims.
use super::super::super::super::protocol::{ReadTools, Server};
use super::*;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::MergeMetadata;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RefName, RepositoryId,
    TenantId,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fields<const N: usize>(pairs: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(pairs) else {
        unreachable!()
    };
    value
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xe3; 16])
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(principal(), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn seeded(format: GitHashAlgorithm, build: bool) -> (Scratch, NodeTools, GitOid) {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fg-mcp-index-page-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    )));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xe1; 16]);
    let repository = RepositoryId::from_bytes([0xe2; 16]);
    let (mut node, _) = OneNode::init(
        NodeConfig::new(scratch.0.join("node"), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let mut patch = String::new();
    for (path, bytes) in [
        ("README", "unrelated"),
        ("src/Needle-a.rs", "needle common"),
        ("src/Needle-b.rs", "needle common"),
        ("src/Needle-c.rs", "needle common"),
        ("src/Other.rs", "unrelated"),
        ("src2/Needle-d.rs", "needle common"),
    ] {
        patch.push_str(&format!(
            "diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+{bytes}\n"
        ));
    }
    let metadata = MergeMetadata {
        author: "Index <index@example.invalid>".into(),
        committer: "Index <index@example.invalid>".into(),
        timestamp: 1,
        message: b"persisted paginated search corpus\n".to_vec(),
    };
    let request = node.request_context();
    let (_, plan, bundle) = node
        .runtime()
        .block_on(node.prepare_trusted_initial_patch_in(
            &request,
            &reference,
            patch.as_bytes(),
            &metadata,
            Default::default(),
            None,
        ))
        .unwrap();
    let commit = plan.commit;
    let accepted = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &session(b"indexed-corpus"),
            &reference,
            commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        accepted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    if build {
        node.runtime()
            .block_on(node.build_source_index_local_in(
                &node.outbox_delivery_context(),
                &reference,
                None,
                None,
                None,
                Default::default(),
            ))
            .unwrap();
    }
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let backend = NodeTools::open(Options {
        storage: scratch.0.join("node"),
        tenant,
        repository,
        format,
        incarnation: Some(incarnation),
        issues: false,
        discussions: false,
        pulls: false,
        source: true,
        writes: Default::default(),
        outcomes: false,
        principal: None,
        queues: Default::default(),
        agent_context: false,
        artifacts: false,
        artifact_root: None,
        agent_token_file: None,
        max_messages: 32,
        index_maintenance: None,
    })
    .unwrap();
    (scratch, backend, commit)
}
fn query(channel: &str) -> Object {
    fields([
        ("reference", text("refs/heads/main")),
        ("terms_hex", Value::Array(vec![text(hex(b"Needle"))])),
        ("channel", text(channel)),
        ("limit", json::number(2)),
    ])
}
fn head_bytes(backend: &NodeTools) -> Vec<u8> {
    backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap()
        .receipt()
        .body()
        .to_vec()
}
fn rows(value: &Value) -> &[Value] {
    let Value::Array(rows) = value else {
        panic!("expected array")
    };
    rows
}
fn continuation(original: &Object, page: &Object) -> Object {
    let mut next = original.clone();
    for (input, output) in [
        ("expected_head", "snapshot_token"),
        ("expected_commit", "source_commit"),
        ("index_token", "index_token"),
        ("index_number", "index_number"),
        ("after", "next_after"),
    ] {
        next.insert(input.into(), page[output].clone());
    }
    next
}
fn protocol_call(backend: &mut NodeTools, args: Object) -> Value {
    let mut server = Server::new(backend).unwrap();
    server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"indexed-page-test","version":"1"}}}"#).unwrap();
    server.receive(
        backend,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    let wire = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(2)),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(NAME)), ("arguments", Value::Object(args))]),
        ),
    ])
    .encode(json::MAX_INPUT)
    .unwrap();
    let response = server.receive(backend, wire.as_bytes()).unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(false), "{response:?}");
    result["structuredContent"].clone()
}

#[test]
fn persisted_content_and_path_pages_are_pinned_complete_and_lossless_in_both_native_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, commit) = seeded(format, true);
        let before = head_bytes(&backend);
        assert!(backend.tools().iter().any(|tool| tool.name == NAME));
        assert!(!backend.is_mutation(NAME));
        for channel in ["content", "path"] {
            for mode in ["revalidated", "exact"] {
                let mut args = query(channel);
                args.insert("source_mode".into(), text(mode));
                let first = protocol_call(&mut backend, args.clone());
                let first = first.object().unwrap();
                assert_eq!(
                    first["source_commit"].text(),
                    Some(commit.to_string().as_str())
                );
                assert_eq!(first["source_mode"].text(), Some(mode));
                assert_eq!(first["counter_encoding"].text(), Some("decimal-strings-v1"));
                assert_eq!(first["terms_hex"], Value::Array(vec![text(hex(b"needle"))]));
                assert_eq!(first["complete"], Value::Bool(false));
                assert_eq!(first["coverage_complete"], Value::Bool(true));
                assert!(rows(&first["omissions"]).is_empty());
                assert_eq!(first["returned_hits"].text(), Some("2"));
                assert_eq!(first["read_only"], Value::Bool(true));
                assert_eq!(first["transaction_created"], Value::Bool(false));
                assert_eq!(first["published"], Value::Bool(false));
                for name in [
                    "index_number",
                    "selected_index_number",
                    "limit",
                    "indexed_documents",
                    "work_units",
                ] {
                    assert!(first[name].text().is_some(), "{mode} {name}");
                }
                let pinned = continuation(&args, first);
                for missing in [
                    "expected_head",
                    "expected_commit",
                    "index_token",
                    "index_number",
                ] {
                    let mut bad = pinned.clone();
                    bad.remove(missing);
                    assert!(backend.call(NAME, &bad).is_err(), "missing {missing}");
                }
                let second = backend.call(NAME, &pinned).unwrap();
                let second = second.object().unwrap();
                for name in [
                    "snapshot_token",
                    "source_commit",
                    "index_token",
                    "index_number",
                ] {
                    assert_eq!(second[name], first[name], "{name}");
                }
                assert_eq!(second["after"], first["next_after"]);
                assert_eq!(second["complete"], Value::Bool(true));
                assert_eq!(second["next_after"], Value::Null);
                assert_eq!(second["returned_hits"].text(), Some("2"));
                let hits: Vec<_> = rows(&first["hits"])
                    .iter()
                    .chain(rows(&second["hits"]))
                    .collect();
                let paths: Vec<_> = hits
                    .iter()
                    .map(|hit| hit.object().unwrap()["path_hex"].text().unwrap().to_owned())
                    .collect();
                assert_eq!(
                    paths,
                    vec![
                        hex(b"src/Needle-a.rs"),
                        hex(b"src/Needle-b.rs"),
                        hex(b"src/Needle-c.rs"),
                        hex(b"src2/Needle-d.rs"),
                    ]
                );
                let ids: Vec<u64> = hits
                    .iter()
                    .map(|hit| {
                        hit.object().unwrap()["document_id"]
                            .text()
                            .unwrap()
                            .parse()
                            .unwrap()
                    })
                    .collect();
                assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
                for hit in hits {
                    let row = hit.object().unwrap();
                    let spans = rows(&row["spans"]);
                    assert_eq!(spans.len(), 1);
                    assert_eq!(spans[0].object().unwrap()["query_index"].text(), Some("0"));
                    assert_eq!(spans[0].object().unwrap()["byte_length"].text(), Some("6"));
                    let offset = spans[0].object().unwrap()["byte_offset"]
                        .text()
                        .unwrap()
                        .parse::<u64>()
                        .unwrap();
                    if channel == "content" {
                        assert_eq!(offset, 0);
                    } else {
                        assert!(offset >= 4);
                    }
                }
                let mut scoped = args;
                scoped.insert("limit".into(), json::number(10));
                scoped.insert(
                    "path_prefixes_hex".into(),
                    Value::Array(vec![text(hex(b"src"))]),
                );
                let scoped = backend.call(NAME, &scoped).unwrap();
                let scoped = scoped.object().unwrap();
                assert_eq!(scoped["returned_hits"].text(), Some("3"));
                assert_eq!(scoped["complete"], Value::Bool(true));
                assert!(rows(&scoped["hits"]).iter().all(|hit| {
                    hit.object().unwrap()["path_hex"]
                        .text()
                        .unwrap()
                        .starts_with(&hex(b"src/"))
                }));
            }
        }
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}

#[test]
fn current_source_mode_keeps_original_index_provenance_after_an_unrelated_ref_update() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, commit) = seeded(format, true);
        let args = query("content");
        let first = backend.call(NAME, &args).unwrap();
        let first = first.object().unwrap();
        assert_eq!(first["distinct_provenance"], Value::Bool(false));
        let original_continuation = continuation(&args, first);
        let reference = RefName::try_new(b"refs/heads/unrelated").unwrap();
        let request = backend.node.request_context();
        let changed = backend
            .node
            .runtime()
            .block_on(backend.node.admit_branch_updates_durable_in(
                &request,
                &session(b"advance-other-ref"),
                &[RefCommand {
                    name: reference,
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(commit),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            changed.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let changed_head = head_bytes(&backend);
        assert!(
            backend.call(NAME, &original_continuation).is_err(),
            "an old source pin cannot continue after authority moves"
        );
        let mut strict = args.clone();
        strict.insert("source_mode".into(), text("exact"));
        assert_eq!(
            backend.call(NAME, &strict).unwrap_err().code,
            "source_index_stale"
        );
        let current = backend.call(NAME, &args).unwrap();
        let current = current.object().unwrap();
        assert_eq!(current["source_commit"], first["source_commit"]);
        assert_eq!(current["root_tree"], first["root_tree"]);
        assert_eq!(current["index_token"], first["index_token"]);
        assert_eq!(current["index_number"], first["index_number"]);
        assert_ne!(current["snapshot_token"], first["snapshot_token"]);
        assert_eq!(current["distinct_provenance"], Value::Bool(true));
        let indexed = current["indexed_source"].object().unwrap();
        let selected = current["current_source"].object().unwrap();
        assert_eq!(indexed["snapshot_token"], first["snapshot_token"]);
        assert_eq!(selected["snapshot_token"], current["snapshot_token"]);
        assert_eq!(indexed["source_commit"], selected["source_commit"]);
        let last = backend.call(NAME, &continuation(&args, current)).unwrap();
        assert_eq!(last.object().unwrap()["complete"], Value::Bool(true));
        assert_eq!(head_bytes(&backend), changed_head);
        backend.close().unwrap();
    }
}

#[test]
fn absent_index_and_work_or_payload_exhaustion_refuse_without_rebuilding_or_partial_success() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend, _) = seeded(format, false);
        let before = head_bytes(&backend);
        for _ in 0..2 {
            let error = backend.call(NAME, &query("content")).unwrap_err();
            assert_eq!(error.code, "source_index_uninitialized");
            assert!(!error.invalid);
        }
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();

        let (_indexed_scratch, mut backend, _) = seeded(format, true);
        let before = head_bytes(&backend);
        for name in ["max_work", "max_payload_bytes"] {
            let mut tiny = query("content");
            tiny.insert(name.into(), json::number(1));
            let error = backend.call(NAME, &tiny).unwrap_err();
            assert!(
                !error.invalid,
                "valid narrow budget must refuse work, not reinterpret the query"
            );
            assert_eq!(head_bytes(&backend), before);
        }
        let mut missing = query("content");
        missing.insert("reference".into(), text("refs/heads/missing"));
        assert!(backend.call(NAME, &missing).is_err());
        let mut mismatched = query("content");
        mismatched.insert(
            "expected_commit".into(),
            text("ab".repeat(format.digest_len())),
        );
        assert!(backend.call(NAME, &mismatched).is_err());
        assert!(backend.call(NAME, &query("content")).is_ok());
        assert_eq!(head_bytes(&backend), before);
        backend.close().unwrap();
    }
}

#[test]
fn source_write_or_unverified_agent_context_never_enables_the_indexed_read_handler() {
    let (_scratch, mut backend, _) = seeded(GitHashAlgorithm::Sha1, true);
    let before = head_bytes(&backend);
    let hostile = Object::new();
    backend.options.source = false;
    backend.options.writes.source = true;
    backend.options.principal = Some(principal());
    assert!(backend.tools().iter().all(|tool| tool.name != NAME));
    assert_eq!(
        backend.call(NAME, &hostile).unwrap_err().code,
        "tool_not_granted"
    );
    assert_eq!(
        super::call(&backend, &hostile).unwrap_err().code,
        "tool_not_granted"
    );
    backend.options.source = true;
    backend.options.agent_token_file = Some(PathBuf::from("must-not-open"));
    assert_eq!(
        super::call(&backend, &hostile).unwrap_err().code,
        "agent_request_required"
    );
    backend.options.agent_token_file = None;
    backend.options.writes.source = false;
    backend.options.principal = None;
    assert_eq!(head_bytes(&backend), before);
    backend.close().unwrap();
}
