//! Argument mapping, plus persisted nodes with real lexical and symbol indexes.
//! The node's shared entrypoint is the one HTTP search-initial/context-initial use.
use super::*;
use fgit_authority::IdempotencyKey;
use fgit_forge::preparation::MergeMetadata;
use fgit_node::LoopbackReceiveSession;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

fn args<const N: usize>(values: [(&str, Value); N]) -> Object {
    let Value::Object(value) = object(values) else {
        unreachable!()
    };
    value
}
fn hexes(values: &[&[u8]]) -> Value {
    Value::Array(values.iter().map(|v| text(hex(v))).collect())
}
fn base() -> Object {
    args([
        ("reference", text("refs/heads/main")),
        ("terms_hex", hexes(&[b"Thing"])),
    ])
}

#[test]
fn arguments_map_one_to_one_onto_route_fields() {
    let mut full = base();
    full.insert("path_prefixes_hex".into(), hexes(&[b"src", b"lib"]));
    full.insert("symbol_name_hex".into(), text(hex(b"Thing")));
    full.insert("symbol_kinds".into(), Value::Array(vec![text("function")]));
    full.insert("max_results_per_channel".into(), json::number(3));
    let mapped = fields(&full, false).unwrap();
    assert_eq!(mapped[0], ("ref".into(), "refs/heads/main".into()));
    for expected in [
        ("term_hex", hex(b"Thing")),
        ("path_prefix_hex", hex(b"src")),
        ("path_prefix_hex", hex(b"lib")),
        ("symbol_kind", "function".to_owned()),
        ("symbol_name_hex", hex(b"Thing")),
        ("max_results_per_channel", "3".to_owned()),
    ] {
        assert!(
            mapped.contains(&(expected.0.to_owned(), expected.1.clone())),
            "{expected:?} in {mapped:?}"
        );
    }
    // object_format is never caller-supplied; the node adds its own.
    assert!(mapped.iter().all(|(name, _)| name != "object_format"));
    let mut context = base();
    context.insert("context_max_files".into(), json::number(2));
    context.insert(
        "context_selection".into(),
        text("context-weighted-rrf-q16-v1"),
    );
    let mapped = fields(&context, true).unwrap();
    assert!(mapped.contains(&("context_max_files".into(), "2".into())));
    assert!(mapped.contains(&(
        "context_selection".into(),
        "context-weighted-rrf-q16-v1".into()
    )));
}

#[test]
fn shapes_are_refused_before_node_work_with_permitted_twins() {
    for (field, value) in [
        ("object_format", text("sha1")),
        ("ref", text("refs/heads/main")),
        ("force", Value::Bool(true)),
        ("context_max_files", json::number(2)),
        ("context_selection", text("raw-path-prefix")),
    ] {
        let mut bad = base();
        bad.insert(field.into(), value);
        assert_eq!(
            fields(&bad, false).unwrap_err().code,
            "unknown_argument",
            "{field}"
        );
    }
    let mut bad = base();
    bad.insert("terms_hex".into(), text(hex(b"Thing")));
    assert_eq!(fields(&bad, false).unwrap_err().code, "expected_array");
    let mut bad = base();
    bad.insert("terms_hex".into(), Value::Array(vec![json::number(1)]));
    assert_eq!(fields(&bad, false).unwrap_err().code, "expected_string");
    let mut bad = base();
    bad.insert("terms_hex".into(), hexes(&[b"x".as_slice(); 33]));
    assert_eq!(fields(&bad, false).unwrap_err().code, "too_many_values");
    let mut ok = base();
    ok.insert("terms_hex".into(), hexes(&[b"x".as_slice(); 32]));
    assert!(fields(&ok, false).is_ok());
    let mut bad = base();
    bad.insert("max_work".into(), text("5"));
    assert_eq!(fields(&bad, false).unwrap_err().code, "invalid_limit");
    let mut missing = base();
    missing.remove("reference");
    assert_eq!(
        fields(&missing, false).unwrap_err().code,
        "reference_required"
    );
}

#[test]
fn route_codes_keep_request_errors_distinct_from_state_failures() {
    for code in [
        "invalid_initial_query",
        "unknown_initial_field",
        "unsupported_symbol_match",
        "symbol_options_without_name",
        "duplicate_field",
    ] {
        assert!(refusal(code).invalid, "{code}");
    }
    for code in [
        "source_index_uninitialized",
        "source_index_stale",
        "source_snapshot_mismatch",
        "index_generation_mismatch",
        "unavailable",
    ] {
        assert!(!refusal(code).invalid, "{code}");
    }
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

const CORPUS: &[u8] = b"diff --git a/src/Thing.rs b/src/Thing.rs
new file mode 100644
--- /dev/null
+++ b/src/Thing.rs
@@ -0,0 +1 @@
+pub fn Thing() {}
diff --git a/src/comment.rs b/src/comment.rs
new file mode 100644
--- /dev/null
+++ b/src/comment.rs
@@ -0,0 +1,2 @@
+// Thing
+pub struct Other;
diff --git a/src2/Thing.rs b/src2/Thing.rs
new file mode 100644
--- /dev/null
+++ b/src2/Thing.rs
@@ -0,0 +1 @@
+pub fn Thing() {}
";

fn seeded(format: GitHashAlgorithm, indexes: bool) -> (Scratch, NodeTools) {
    let scratch = Scratch(std::env::temp_dir().join(format!(
        "fg-mcp-retrieval-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    fs::create_dir(&scratch.0).unwrap();
    let tenant = TenantId::from_bytes([0xc1; 16]);
    let repository = RepositoryId::from_bytes([0xc2; 16]);
    let (mut node, _) = OneNode::init(
        NodeConfig::new(scratch.0.join("node"), tenant, repository)
            .with_object_format(format)
            .with_worker_threads(2),
    )
    .unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 1,
        message: b"retrieval corpus\n".to_vec(),
    };
    let request = node.request_context();
    let (_, plan, bundle) = node
        .runtime()
        .block_on(node.prepare_trusted_initial_patch_in(
            &request,
            &reference,
            CORPUS,
            &metadata,
            Default::default(),
            None,
        ))
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xc3; 16]),
        IdempotencyKey::new(b"retrieval-initial".to_vec()).unwrap(),
    );
    let accepted = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &session,
            &reference,
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        accepted.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    if indexes {
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
        node.runtime()
            .block_on(node.build_source_symbol_index_local_in(
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
        pulls: false,
        source: true,
        writes: Default::default(),
        outcomes: false,
        principal: None,
        agent_context: false,
        artifacts: false,
        artifact_root: None,
        max_messages: 16,
    })
    .unwrap();
    (scratch, backend)
}

fn array(value: &Value) -> &[Value] {
    match value {
        Value::Array(rows) => rows,
        other => panic!("expected result array, got {other:?}"),
    }
}

fn field<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    path.iter()
        .fold(value, |value, key| &value.object().unwrap()[*key])
}

#[test]
fn persisted_indexes_answer_initial_and_context_in_both_formats_through_the_shared_entrypoint() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = seeded(format, true);
        assert!(!backend.is_mutation(INITIAL) && !backend.is_mutation(CONTEXT));
        let names: Vec<_> = backend.tools().iter().map(|tool| tool.name).collect();
        assert!(names.contains(&INITIAL) && names.contains(&CONTEXT));

        let mut request = base();
        request.insert("symbol_name_hex".into(), text(hex(b"Thing")));
        request.insert("symbol_policy".into(), text("required"));
        let initial = backend.call(INITIAL, &request).unwrap();
        assert_eq!(
            field(&initial, &["type"]).text(),
            Some("source_search_initial")
        );
        assert_eq!(field(&initial, &["complete"]), &Value::Bool(true));
        assert_eq!(field(&initial, &["read_only"]), &Value::Bool(true));
        assert_eq!(
            field(&initial, &["authorization", "host"]).text(),
            Some("trusted-local-mcp")
        );
        assert_eq!(
            field(&initial, &["authorization", "scope"]).text(),
            Some("whole-repository")
        );
        assert_eq!(
            field(&initial, &["authorization", "reusable_capability"]),
            &Value::Bool(false)
        );
        for (channel, rows, domain) in [
            ("content", "hits", "source-blob-bytes"),
            ("path", "hits", "raw-path-bytes"),
        ] {
            let hits = array(field(&initial, &[channel, rows]));
            assert!(!hits.is_empty());
            for hit in hits {
                let row = hit.object().unwrap();
                let label = row["authorization_label"].text().unwrap();
                assert_eq!(label.len(), 64);
                assert!(
                    label
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                );
                assert_eq!(row["position_domain"].text(), Some(domain));
            }
        }
        for hit in array(field(&initial, &["symbols", "result", "matches"])) {
            let row = hit.object().unwrap();
            assert_eq!(row["authorization_label"].text().unwrap().len(), 64);
            assert_eq!(
                row["position_domain"].text(),
                Some("source-declaration-bytes")
            );
        }
        assert_eq!(
            field(&initial, &["symbols", "state"]).text(),
            Some("available")
        );
        // The same fields through the node entrypoint HTTP uses: one document.
        let routed = fgit_node::source_retrieval_json(
            &backend.node,
            &fgit_node::source_retrieval::authorization::SourceReadContext::trusted_local_mcp(
                &backend.node,
            ),
            fields(&request, false).unwrap(),
            false,
            MAX_RESULT_BYTES,
        )
        .unwrap();
        assert_eq!(
            json::parse_with(routed.as_bytes(), DOCUMENT_LIMITS).unwrap(),
            initial
        );

        // Scope and per-channel limits are the route's own.
        let mut scoped = request.clone();
        scoped.insert("path_prefixes_hex".into(), hexes(&[b"src2"]));
        let scoped = backend.call(INITIAL, &scoped).unwrap();
        assert!(!format!("{scoped:?}").contains(&hex(b"src/comment.rs")));
        let mut limited = request.clone();
        limited.insert("max_results_per_channel".into(), json::number(1));
        assert_eq!(
            field(&backend.call(INITIAL, &limited).unwrap(), &["complete"]),
            &Value::Bool(false)
        );
        // A pinned snapshot is accepted; a foreign pin is refused, not answered.
        let mut pinned = request.clone();
        pinned.insert(
            "expected_head".into(),
            field(&initial, &["snapshot_token"]).clone(),
        );
        assert_eq!(
            field(
                &backend.call(INITIAL, &pinned).unwrap(),
                &["snapshot_token"]
            ),
            field(&initial, &["snapshot_token"])
        );
        let mut foreign = request.clone();
        foreign.insert(
            "expected_head".into(),
            text(format!("alg:2:{}", "05".repeat(32))),
        );
        assert!(backend.call(INITIAL, &foreign).is_err());

        // Context packets: raw-path and ranked selections over the same retrieval.
        for selection in [None, Some("context-weighted-rrf-q16-v1")] {
            let mut context = base();
            if let Some(selection) = selection {
                context.insert("context_selection".into(), text(selection));
            }
            let packet = backend.call(CONTEXT, &context).unwrap();
            assert_eq!(
                field(&packet, &["type"]).text(),
                Some("source_context_initial")
            );
            assert_eq!(
                field(&packet, &["source_material_untrusted"]),
                &Value::Bool(true)
            );
            assert_eq!(
                field(&packet, &["retrieval", "type"]).text(),
                Some("source_search_initial")
            );
            let Value::Array(files) = field(&packet, &["files"]) else {
                panic!("files")
            };
            assert!(!files.is_empty());
            assert!(files.iter().any(|file| {
                file.object().unwrap()["path_hex"].text() == Some(hex(b"src/Thing.rs").as_str())
            }));
            let retrieval = field(&packet, &["retrieval"]);
            for file in files {
                let path = field(file, &["path_hex"]);
                let commitment = field(file, &["lineage_commitment"]).text().unwrap();
                assert_eq!(commitment.len(), 64);
                let mut originals = Vec::new();
                for channel in ["content", "path"] {
                    for row in array(field(retrieval, &[channel, "hits"])) {
                        if field(row, &["path_hex"]) == path {
                            let label = field(row, &["authorization_label"]).clone();
                            if !originals.contains(&label) {
                                originals.push(label);
                            }
                        }
                    }
                }
                let origins = array(field(file, &["authorization_labels"]));
                assert!(!origins.is_empty());
                assert_eq!(origins, originals);
                for anchor in array(field(file, &["anchors"])) {
                    assert!(origins.contains(field(anchor, &["authorization_label"])));
                }
                for excerpt in array(field(file, &["excerpts"])) {
                    assert_eq!(
                        field(excerpt, &["lineage_commitment"]).text(),
                        Some(commitment)
                    );
                    assert_eq!(
                        field(excerpt, &["position_domain"]).text(),
                        Some("source-blob-bytes")
                    );
                }
            }
        }
        // Detached symbol options and malformed terms are request errors.
        let mut detached = base();
        detached.insert("symbol_policy".into(), text("required"));
        assert!(backend.call(INITIAL, &detached).unwrap_err().invalid);
        let mut odd = base();
        odd.insert("terms_hex".into(), Value::Array(vec![text("abc")]));
        assert!(backend.call(INITIAL, &odd).unwrap_err().invalid);
    }
}

#[test]
fn missing_indexes_fail_typed_instead_of_answering_empty() {
    let (_scratch, mut backend) = seeded(GitHashAlgorithm::Sha1, false);
    let error = backend.call(INITIAL, &base()).unwrap_err();
    assert!(!error.invalid);
    assert_eq!(error.code, "source_index_uninitialized");
    assert!(!backend.call(CONTEXT, &base()).unwrap_err().invalid);
}

#[test]
fn agent_context_uses_the_real_native_packet_with_launch_sponsorship_in_both_formats() {
    use super::super::agent_context;
    use crate::mcp::protocol::Server;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut source_backend) = seeded(format, true);
        assert_eq!(
            source_backend
                .call(agent_context::NAME, &base())
                .unwrap_err()
                .code,
            "tool_not_granted"
        );
        let mut options = source_backend.options.clone();
        options.source = false;
        options.agent_context = true;
        options.principal = Some(PrincipalId::from_bytes([0xc8; 16]));
        source_backend.close().unwrap();
        let mut backend = NodeTools::open(options).unwrap();
        let before = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        assert_eq!(backend.tools().len(), 1);
        assert!(!backend.is_mutation(agent_context::NAME));
        assert_eq!(
            backend.call(INITIAL, &base()).unwrap_err().code,
            "tool_not_granted"
        );

        let document = backend.call(agent_context::NAME, &base()).unwrap();
        assert_eq!(field(&document, &["type"]).text(), Some("agent_context"));
        assert_eq!(field(&document, &["read_only"]), &Value::Bool(true));
        assert_eq!(
            field(&document, &["publication_authorized"]),
            &Value::Bool(false)
        );
        assert_eq!(
            field(&document, &["sponsor", "principal_id"]).text(),
            Some(PrincipalId::from_bytes([0xc8; 16]).to_string().as_str())
        );
        assert_eq!(
            field(&document, &["sponsor", "authentication"]).text(),
            Some("operator-asserted")
        );
        assert_eq!(
            field(&document, &["sponsor", "authorization_host"]).text(),
            Some("trusted-local-mcp")
        );
        assert_eq!(
            field(
                &document,
                &["retrieval_evidence", "source", "object_format"]
            )
            .text(),
            Some(format.as_str())
        );
        let sources = array(field(&document, &["untrusted_sources"]));
        assert!(!sources.is_empty());
        assert!(sources.iter().any(|source| {
            field(source, &["untrusted_utf8"])
                .text()
                .is_some_and(|bytes| bytes.contains("pub fn Thing() {}"))
        }));
        assert!(sources.iter().all(|source| {
            !field(source, &["untrusted_bytes_hex"])
                .text()
                .unwrap()
                .is_empty()
        }));
        assert!(
            !field(&document, &["context_packet", "packet_id"])
                .text()
                .unwrap()
                .is_empty()
        );
        let mut pinned = base();
        pinned.insert(
            "expected_head".into(),
            field(&document, &["authority_receipt", "head"]).clone(),
        );
        assert!(backend.call(agent_context::NAME, &pinned).is_ok());
        pinned.insert(
            "expected_head".into(),
            text(format!("alg:2:{}", "05".repeat(32))),
        );
        assert_eq!(
            backend.call(agent_context::NAME, &pinned).unwrap_err().code,
            "source_snapshot_moved"
        );
        let mut too_small = base();
        too_small.insert("max_output_bytes".into(), json::number(128));
        assert_eq!(
            backend
                .call(agent_context::NAME, &too_small)
                .unwrap_err()
                .code,
            "resource_limit"
        );
        let mut injected = base();
        injected.insert("principal".into(), text("00".repeat(16)));
        assert_eq!(
            backend
                .call(agent_context::NAME, &injected)
                .unwrap_err()
                .code,
            "unknown_argument"
        );

        // Real MCP request lifecycle: partial native evidence is usable data,
        // never a mutation receipt or permission to hide the omission.
        let mut server = Server::new(&backend).unwrap();
        server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"agent-context-test","version":"1"}}}"#).unwrap();
        assert!(
            server
                .receive(
                    &mut backend,
                    br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
                )
                .is_none()
        );
        let response = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_agent_context","arguments":{"reference":"refs/heads/main","terms_hex":["5468696e67"],"context_max_files":1}}}"#).unwrap();
        let result = response.object().unwrap()["result"].object().unwrap();
        assert_eq!(result["isError"], Value::Bool(false));
        let partial = &result["structuredContent"];
        assert_eq!(field(partial, &["complete"]), &Value::Bool(false));
        assert!(!array(field(partial, &["untrusted_sources"])).is_empty());
        assert_eq!(
            field(partial, &["publication_authorized"]),
            &Value::Bool(false)
        );
        let after = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        assert_eq!(before.receipt(), after.receipt());
        backend.close().unwrap();
    }
}

#[test]
fn agent_context_missing_index_refuses_without_rebuilding_or_moving_authority() {
    use super::super::agent_context;
    let (_scratch, source_backend) = seeded(GitHashAlgorithm::Sha1, false);
    let mut options = source_backend.options.clone();
    options.source = false;
    options.agent_context = true;
    options.principal = Some(PrincipalId::from_bytes([0xc8; 16]));
    source_backend.close().unwrap();
    let mut backend = NodeTools::open(options).unwrap();
    let before = backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            backend.call(agent_context::NAME, &base()).unwrap_err().code,
            "source_index_uninitialized"
        );
    }
    let after = backend
        .node
        .runtime()
        .block_on(backend.node.authenticate_authority_head())
        .unwrap();
    assert_eq!(before.receipt(), after.receipt());
    backend.close().unwrap();
}
