use super::*;
use fgit_schema::mcp::{IdempotencyRequirement, ReadMutationClass};
use std::collections::BTreeSet;

fn args(format: GitHashAlgorithm) -> Object {
    let width = format.digest_len() * 2;
    let Value::Object(fields) = object([
        ("reference", text("refs/heads/topic")),
        ("expected_source", text("a".repeat(width))),
        ("onto", text("b".repeat(width))),
        ("expected_candidate", text("c".repeat(width))),
        ("bundle_hex_chunks", Value::Array(vec![text("0001"), text("ff")])),
        ("idempotency_key", text("original-rebase-request")),
    ]) else { unreachable!() };
    fields
}

#[test]
fn old_source_and_onto_are_distinct_exact_operands_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let original = args(format);
        let input = parse(&original, format).unwrap();
        assert_eq!(input.expected_source.to_string(), "a".repeat(format.digest_len() * 2));
        assert_eq!(input.onto.to_string(), "b".repeat(format.digest_len() * 2));
        assert_eq!(input.expected_candidate.to_string(), "c".repeat(format.digest_len() * 2));
        assert_eq!(input.bytes, [0, 1, 255]);
        let mut raw = original.clone();
        raw.remove("reference");
        raw.insert("reference_hex".into(), text(hex(b"refs/heads/topic-\xff")));
        assert_eq!(parse(&raw, format).unwrap().reference.as_bytes(), b"refs/heads/topic-\xff");

        // A complete series may contain zero commits; native validation still
        // verifies the complete bundle and the separate old-source lease.
        let mut empty = original;
        empty.insert("expected_candidate".into(), empty["onto"].clone());
        let empty = parse(&empty, format).unwrap();
        assert_eq!(empty.expected_candidate, empty.onto);
        assert_ne!(empty.expected_source, empty.onto);
    }
}

#[test]
fn publication_cannot_invent_authority_force_a_ref_or_substitute_a_latest_source() {
    let original = args(GitHashAlgorithm::Sha1);
    for name in ["principal", "storage", "tenant", "repository", "force", "approved", "expected_head", "expected_base", "initial", "command", "bundle_path", "onto_reference"] {
        let mut bad = original.clone();
        bad.insert(name.into(), text("injected"));
        assert_eq!(parse(&bad, GitHashAlgorithm::Sha1).unwrap_err().code, "unknown_argument", "{name}");
    }
    for name in ["reference", "expected_source", "onto", "expected_candidate", "bundle_hex_chunks"] {
        let mut missing = original.clone();
        missing.remove(name);
        assert!(parse(&missing, GitHashAlgorithm::Sha1).is_err(), "{name}");
    }
    let mut both = original.clone();
    both.insert("reference_hex".into(), text(hex(b"refs/heads/topic")));
    assert!(parse(&both, GitHashAlgorithm::Sha1).is_err());
    for reference in ["main", "refs/tags/tag", "refs/heads/../main"] {
        let mut bad = original.clone();
        bad.insert("reference".into(), text(reference));
        assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err(), "{reference}");
    }
    for name in ["expected_source", "onto", "expected_candidate"] {
        for value in [Value::Null, json::number(0), text("latest"), text("0".repeat(40)), text("A".repeat(40)), text("b".repeat(64))] {
            let mut bad = original.clone();
            bad.insert(name.into(), value);
            assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err(), "{name}");
        }
    }
}

#[test]
fn complete_bundle_transport_has_exact_accepted_and_refused_boundaries() {
    let mut input = args(GitHashAlgorithm::Sha256);
    input.insert("bundle_hex_chunks".into(), Value::Array(vec![text("ab".repeat(CHUNK_BYTES)); MAX_CHUNKS]));
    assert_eq!(parse(&input, GitHashAlgorithm::Sha256).unwrap().bytes, vec![0xab; MAX_BUNDLE_BYTES]);
    for chunks in [
        Value::Array(vec![]),
        Value::Array(vec![text("ab"); MAX_CHUNKS + 1]),
        Value::Array(vec![text("ab".repeat(CHUNK_BYTES + 1))]),
        Value::Array(vec![text("AB")]),
        Value::Array(vec![text("a")]),
        Value::Array(vec![Value::Null]),
        text("https://external.invalid/bundle"),
    ] {
        input.insert("bundle_hex_chunks".into(), chunks);
        assert!(parse(&input, GitHashAlgorithm::Sha256).is_err());
    }
}

#[test]
fn maximum_inputs_fit_the_unchanged_mcp_request_envelope() {
    let mut input = args(GitHashAlgorithm::Sha256);
    input.remove("reference");
    let reference = format!("refs/heads/{}", "x".repeat(MAX_REF_NAME_LEN - 11));
    assert_eq!(reference.len(), MAX_REF_NAME_LEN);
    input.insert("reference_hex".into(), text(hex(reference.as_bytes())));
    input.insert("bundle_hex_chunks".into(), Value::Array(vec![text("ab".repeat(CHUNK_BYTES)); MAX_CHUNKS]));
    input.insert("idempotency_key".into(), text("k".repeat(common::MAX_KEY_BYTES)));
    assert!(parse(&input, GitHashAlgorithm::Sha256).is_ok());
    assert!(common::key(&input).is_ok());
    let request = object([
        ("jsonrpc", text("2.0")),
        ("id", json::number(1)),
        ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(input))])),
    ]).encode(json::MAX_INPUT).unwrap();
    assert!(json::parse(request.as_bytes()).is_ok());
}

#[test]
fn served_contract_is_closed_and_classifies_durable_rebase_publication() {
    let tools = super::super::tools();
    let tool = tools.iter().find(|tool| tool.name == NAME).unwrap();
    assert!(super::super::is_tool(NAME));
    let contract = fgit_schema::mcp::find_tool(NAME).unwrap();
    assert_eq!(contract.read_mutation, ReadMutationClass::Mutation);
    assert_eq!(contract.idempotency, IdempotencyRequirement::RequiredDurableKey);
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    let expected: BTreeSet<_> = FIELDS.iter().copied().collect();
    assert_eq!(expected, properties.keys().map(String::as_str).collect());
    assert_eq!(expected, contract.input_fields.iter().map(|field| field.name).collect());
    let required: BTreeSet<_> = contract.input_fields.iter().filter(|field| field.required).map(|field| field.name).collect();
    assert_eq!(required, ["expected_source", "onto", "expected_candidate", "bundle_hex_chunks", "idempotency_key"].into_iter().collect());
    assert!(contract.output_fields.iter().any(|field| field.name == "submitted_onto"));
    assert!(contract.output_fields.iter().any(|field| field.name == "replay_equivalence_verified"));
}
