//! Real persisted indexes and native objects through the actual MCP adapter.
use super::super::progressive as adapter;
use super::*;
use crate::mcp::protocol::Server;
use fgit_node::source_retrieval::authorization::SourceReadContext;

fn query() -> Object {
    let mut args = base();
    args.insert("operation".into(), text("progressive"));
    args
}

fn phases(value: &Value) -> &[Value] {
    array(field(value, &["phases"]))
}

fn native(backend: &NodeTools, args: &Object) -> (Result<bool, &'static str>, Vec<Value>) {
    let mut ordinary = args.clone();
    ordinary.remove("operation");
    let mut bytes = Vec::new();
    let outcome = backend.node.write_progressive_source_context(
        &SourceReadContext::trusted_local_mcp(&backend.node),
        fields(&ordinary, true).unwrap(),
        MAX_RESULT_BYTES,
        &mut bytes,
    );
    let records = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| json::parse_with(line, DOCUMENT_LIMITS).unwrap())
        .collect();
    (outcome, records)
}

#[test]
fn buffered_progressive_preserves_native_phases_scope_and_raw_default_in_both_hash_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, mut backend) = seeded(format, true);
        let before = backend
            .node
            .runtime()
            .block_on(backend.node.authenticate_authority_head())
            .unwrap();
        let ordinary = backend.call(CONTEXT, &base()).unwrap();
        assert_eq!(
            field(&ordinary, &["selection"]).text(),
            Some("raw-path-prefix")
        );
        assert!(!ordinary.object().unwrap().contains_key("phases"));
        for current in [false, true] {
            let mut args = query();
            args.insert("path_prefixes_hex".into(), hexes(&[b"src2"]));
            args.insert("symbol_name_hex".into(), text(hex(b"Thing")));
            args.insert("symbol_policy".into(), text("required"));
            if current {
                args.insert("index_source".into(), text("current-native-v1"));
            }
            let (outcome, original) = native(&backend, &args);
            assert_eq!(outcome, Ok(true));
            let result = backend.call(CONTEXT, &args).unwrap();
            assert!(!backend.is_mutation(CONTEXT));
            assert!(!backend.result_is_error(CONTEXT, &result));
            assert_eq!(
                field(&result, &["profile"]).text(),
                Some("source-context-progressive-mcp-v1")
            );
            assert_eq!(field(&result, &["delivery"]).text(), Some("buffered"));
            assert_eq!(
                field(&result, &["refinement_succeeded"]),
                &Value::Bool(true)
            );
            assert_eq!(field(&result, &["complete"]), &Value::Bool(true));
            assert_eq!(phases(&result), original);
            let initial = field(&phases(&result)[0], &["answer"]);
            let refined = field(&phases(&result)[1], &["answer"]);
            assert!(!array(field(initial, &["content", "hits"])).is_empty());
            assert_eq!(field(refined, &["retrieval"]), initial);
            assert_eq!(
                field(initial, &["object_format"]).text(),
                Some(format.as_str())
            );
            assert_eq!(
                field(initial, &["authorization", "host"]).text(),
                Some("trusted-local-mcp")
            );
            let files = array(field(refined, &["files"]));
            assert_eq!(files.len(), 1);
            assert_eq!(
                field(&files[0], &["path_hex"]),
                &text(hex(b"src2/Thing.rs"))
            );
            assert_eq!(
                field(refined, &["source_material_untrusted"]),
                &Value::Bool(true)
            );
            assert_eq!(
                field(refined, &["ranking", "profile"]).text(),
                Some("context-weighted-rrf-q16-v1")
            );
            assert!(result.encode(MAX_RESULT_BYTES).unwrap().len() <= MAX_RESULT_BYTES);
        }
        assert_eq!(backend.call(CONTEXT, &base()).unwrap(), ordinary);
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
fn refinement_source_and_output_exhaustion_keep_the_exact_nonempty_initial() {
    let (_scratch, mut backend) = seeded(GitHashAlgorithm::Sha256, true);
    let args = query();
    let (outcome, original) = native(&backend, &args);
    assert_eq!(outcome, Ok(true));
    let initial = field(&original[0], &["answer"]);
    let mut source_limited = args.clone();
    source_limited.insert("context_max_source_bytes".into(), json::number(1));
    let (outcome, original_failure) = native(&backend, &source_limited);
    assert_eq!(outcome, Err("resource_limit"));
    let failed = backend.call(CONTEXT, &source_limited).unwrap();
    assert_eq!(phases(&failed), original_failure);
    assert_eq!(field(&phases(&failed)[0], &["answer"]), initial);
    assert!(!array(field(initial, &["content", "hits"])).is_empty());
    assert!(backend.result_is_error(CONTEXT, &failed));
    assert!(!backend.result_is_error(INITIAL, &failed));
    assert_eq!(field(&failed, &["complete"]), &Value::Bool(false));
    assert_eq!(
        field(&failed, &["refinement_succeeded"]),
        &Value::Bool(false)
    );

    // Enough for the entire original Initial, terminal refusal and fixed wrapper,
    // but not a second full report. The native writer reserves its failure row.
    let allowance = original[0].encode(MAX_RESULT_BYTES).unwrap().len() + 1 + 256 + 512;
    let bounded = adapter::call_with_maximum(&backend, &args, allowance).unwrap();
    assert_eq!(field(&phases(&bounded)[0], &["answer"]), initial);
    assert_eq!(
        field(&phases(&bounded)[1], &["phase"]).text(),
        Some("RefinementFailed")
    );
    assert_eq!(
        field(&phases(&bounded)[1], &["code"]).text(),
        Some("resource_limit")
    );
    assert!(backend.result_is_error(CONTEXT, &bounded));
    assert!(bounded.encode(allowance).unwrap().len() <= allowance);
    for allowance in [0, 511, 512, 1024] {
        assert_eq!(
            adapter::call_with_maximum(&backend, &args, allowance)
                .unwrap_err()
                .code,
            "resource_limit"
        );
    }

    // MCP must emit the retained Initial as structured content and as error
    // data, rather than replacing it with the generic empty tool failure body.
    let mut server = Server::new(&backend).unwrap();
    server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"progressive-test","version":"1"}}}"#).unwrap();
    assert!(
        server
            .receive(
                &mut backend,
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
    );
    let response = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_source_context","arguments":{"operation":"progressive","reference":"refs/heads/main","terms_hex":["5468696e67"],"context_max_source_bytes":1}}}"#).unwrap();
    assert_eq!(field(&response, &["result", "isError"]), &Value::Bool(true));
    assert_eq!(field(&response, &["result", "structuredContent"]), &failed);
    let response = server.receive(&mut backend, br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"frankengit_source_context","arguments":{"operation":"progressive","reference":"refs/heads/main","terms_hex":["5468696e67"],"context_max_files":1}}}"#).unwrap();
    assert_eq!(
        field(&response, &["result", "isError"]),
        &Value::Bool(false)
    );
    let partial = field(&response, &["result", "structuredContent"]);
    assert_eq!(field(partial, &["complete"]), &Value::Bool(false));
    assert_eq!(
        field(partial, &["refinement_succeeded"]),
        &Value::Bool(true)
    );
    assert_eq!(
        array(field(&phases(partial)[1], &["answer", "files"])).len(),
        1
    );
    backend.close().unwrap();
}

#[test]
fn missing_indexes_and_invalid_or_ungranted_initial_requests_expose_no_phases() {
    let (_scratch, mut backend) = seeded(GitHashAlgorithm::Sha1, false);
    assert_eq!(
        backend.call(CONTEXT, &query()).unwrap_err().code,
        "source_index_uninitialized"
    );
    for (name, value, code) in [
        ("operation", text("stream"), "unsupported_context_operation"),
        (
            "context_selection",
            text("raw-path-prefix"),
            "unsupported_context_selection",
        ),
        ("context_selection", Value::Bool(true), "expected_string"),
        ("principal", text("00".repeat(16)), "unknown_argument"),
        ("terms_hex", text("5468696e67"), "expected_array"),
        (
            "index_source",
            text("current-native-v2"),
            "unsupported_index_source",
        ),
    ] {
        let mut invalid = query();
        invalid.insert(name.into(), value);
        let error = backend.call(CONTEXT, &invalid).unwrap_err();
        assert!(error.invalid, "{name}: {error:?}");
        assert_eq!(error.code, code);
    }
    assert_eq!(
        backend.call(INITIAL, &query()).unwrap_err().code,
        "unknown_argument"
    );
    backend.options.source = false;
    assert_eq!(
        backend.call(CONTEXT, &query()).unwrap_err().code,
        "tool_not_granted"
    );
    backend.close().unwrap();
}
