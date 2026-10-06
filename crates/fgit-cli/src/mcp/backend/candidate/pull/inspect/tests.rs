use super::*;

fn args(format: GitHashAlgorithm) -> Object {
    let Value::Object(fields) = object([
        ("operation", text(INSPECT)),
        ("number", text("1")), ("expected_version", text("1")),
        ("source_reference", text("refs/heads/topic")),
        ("target_reference", text("refs/heads/main")),
        ("expected_source", text("11".repeat(format.digest_len()))),
        ("expected_target", text("22".repeat(format.digest_len()))),
        ("merge_base", text("33".repeat(format.digest_len()))),
        ("candidate_commit", text("44".repeat(format.digest_len()))),
        ("policy_epoch", text("1")),
        ("bundle_hex_chunks", Value::Array(vec![text("0001"), text("ff")])),
    ]) else { unreachable!() };
    fields
}

#[test]
fn inspection_reuses_exact_consumer_subjects_and_lossless_reference_bytes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut args = args(format);
        let input = parse(&args, format).unwrap();
        assert_eq!(input.bundle, [0, 1, 255]);
        assert_eq!(reviews::subject(&args, format).unwrap(), (input.selection.subject, input.candidate));
        assert_eq!(input.options.mode, ComparisonMode::Direct);
        assert!(input.options.paths.is_empty());
        assert!(input.selection.expected_head.is_none());
        args.remove("source_reference");
        args.insert("source_reference_hex".into(), text(hex(b"refs/heads/raw-\xff")));
        let input = parse(&args, format).unwrap();
        assert_eq!(input.selection.subject.source_ref.as_bytes(), b"refs/heads/raw-\xff");
        args.insert("expected_bundle_sha256".into(), text(hex(&input.digest)));
        assert_eq!(parse(&args, format).unwrap().digest, input.digest);
    }
}

#[test]
fn no_missing_coordinates_authority_metadata_or_filtered_inspection_is_accepted() {
    let original = args(GitHashAlgorithm::Sha1);
    for name in ["operation", "number", "expected_version", "policy_epoch", "source_reference",
        "target_reference", "expected_source", "expected_target", "candidate_commit", "merge_base", "bundle_hex_chunks"]
    {
        let mut bad = original.clone(); bad.remove(name);
        assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err(), "missing {name}");
    }
    for name in ["idempotency_key", "principal", "reviewer", "review_version", "decision", "reason",
        "force", "expected_base", "paths_hex", "comparison", "author", "committer", "timestamp",
        "message_hex", "merge_profile", "storage", "bundle_path", "bundle_url", "approved"]
    {
        let mut bad = original.clone(); bad.insert(name.into(), Value::Null);
        assert_eq!(parse(&bad, GitHashAlgorithm::Sha1).err().unwrap().code, "unknown_argument", "{name}");
    }
    for name in ["expected_source", "expected_target", "merge_base", "candidate_commit"] {
        for value in [Value::Null, text("latest"), text("00".repeat(20)), text("AA".repeat(20)), text("11".repeat(32))] {
            let mut bad = original.clone(); bad.insert(name.into(), value);
            assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err(), "{name}");
        }
    }
    for name in ["number", "expected_version", "policy_epoch"] {
        for value in [json::number(1), text("0"), text("01"), text("18446744073709551616")] {
            let mut bad = original.clone(); bad.insert(name.into(), value);
            assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err(), "{name}");
        }
    }
    let mut bad = original.clone(); bad.insert("operation".into(), text(PREPARE));
    assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err());
    bad = original; bad.insert("source_reference_hex".into(), text(hex(b"refs/heads/topic")));
    assert!(parse(&bad, GitHashAlgorithm::Sha1).is_err());
}

#[test]
fn exact_transport_and_per_request_work_limits_cannot_be_widened_or_ignored() {
    let original = args(GitHashAlgorithm::Sha256);
    for value in [Value::Null, text("00".repeat(32)), text("a"), text("AA".repeat(32))] {
        let mut bad = original.clone(); bad.insert("expected_bundle_sha256".into(), value);
        assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err());
    }
    for &(name, _, minimum, maximum) in LIMITS {
        for value in [Value::Null, text("1"), json::number((maximum + 1) as u64)] {
            let mut bad = original.clone(); bad.insert(name.into(), value);
            assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err(), "{name}");
        }
        for value in [minimum, maximum] {
            let mut valid = original.clone(); valid.insert(name.into(), json::number(value as u64));
            assert!(parse(&valid, GitHashAlgorithm::Sha256).is_ok(), "{name}");
        }
    }
    let mut bad = original;
    bad.insert("bundle_hex_chunks".into(), Value::Array(vec![text("00"); MAX_CHUNKS + 1]));
    assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err());
    bad.insert("bundle_hex_chunks".into(), Value::Array(vec![text("00".repeat(CHUNK_BYTES + 1))]));
    assert!(parse(&bad, GitHashAlgorithm::Sha256).is_err());
}

#[test]
fn discovery_requires_the_complete_native_subject_and_has_no_mutation_fields() {
    let schema = schema();
    let body = schema.object().unwrap();
    assert_eq!(body["additionalProperties"], Value::Bool(false));
    let properties = body["properties"].object().unwrap();
    assert_eq!(properties["operation"].object().unwrap()["const"].text(), Some(INSPECT));
    for name in ["candidate_commit", "merge_base", "expected_source", "expected_target", "bundle_hex_chunks", "policy_epoch"] {
        assert!(properties.contains_key(name));
        let Value::Array(required) = &body["required"] else { unreachable!() };
        assert!(required.contains(&text(name)));
    }
    for name in ["paths_hex", "comparison", "idempotency_key", "principal", "decision", "force"] {
        assert!(!properties.contains_key(name));
    }
    assert!(schema.encode(16 * 1024).is_ok());
    let mut args = args(GitHashAlgorithm::Sha256);
    args.insert("bundle_hex_chunks".into(), Value::Array(vec![text("ab".repeat(CHUNK_BYTES)); MAX_CHUNKS]));
    let wire = object([
        ("jsonrpc", text("2.0")), ("id", json::number(1)), ("method", text("tools/call")),
        ("params", object([("name", text(NAME)), ("arguments", Value::Object(args))])),
    ]).encode(json::MAX_INPUT).unwrap();
    assert!(json::parse(wire.as_bytes()).is_ok());
}
