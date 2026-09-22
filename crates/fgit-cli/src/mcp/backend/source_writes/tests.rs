use super::*;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, DigestAlgorithmId, DigestBytes, RefusalCode,
    RefusalRecordId, RepositoryCommitId,
};
fn args(name: &str, format: GitHashAlgorithm) -> Object {
    let Value::Object(mut args) = object([
        ("reference", text("refs/heads/topic")),
        ("idempotency_key", text("original")),
    ]) else {
        unreachable!()
    };
    let old = text("a".repeat(format.digest_len() * 2));
    let new = text("b".repeat(format.digest_len() * 2));
    match name {
        CREATE => {
            args.insert("target".into(), new);
        }
        UPDATE => {
            args.insert("expected_old".into(), old);
            args.insert("target".into(), new);
        }
        DELETE => {
            args.insert("expected_old".into(), old);
        }
        RENAME => {
            args.insert("expected_old".into(), old);
            args.insert("destination".into(), text("refs/heads/renamed"));
        }
        PUBLISH => {
            args.insert("expected_base".into(), old);
            args.insert("expected_candidate".into(), new);
            args.insert(
                "bundle_hex_chunks".into(),
                Value::Array(vec![text("00"), text("01ff")]),
            );
        }
        _ => unreachable!(),
    }
    args
}
#[test]
fn operations_are_exact_nonforced_and_rename_is_one_same_tip_transaction() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let created = parse(CREATE, &args(CREATE, format), format).unwrap();
        assert_eq!(created.commands.len(), 1);
        assert_eq!(created.commands[0].expected_old, ExpectedOld::Absent);
        for name in [CREATE, UPDATE, DELETE, RENAME, PUBLISH] {
            let input = parse(name, &args(name, format), format).unwrap();
            assert!(input.commands.iter().all(|command| !command.force));
            assert_eq!(input.commands.len(), if name == RENAME { 2 } else { 1 });
            assert_eq!(input.bundle.is_some(), name == PUBLISH);
            if name == RENAME {
                let ExpectedOld::Exactly(tip) = input.commands[0].expected_old else {
                    panic!("lease")
                };
                assert_eq!(input.commands[0].proposed_new, ProposedNew::Delete);
                assert_eq!(input.commands[1].expected_old, ExpectedOld::Absent);
                assert_eq!(input.commands[1].proposed_new, ProposedNew::Update(tip));
            }
            let mut raw = args(name, format);
            raw.remove("reference");
            raw.insert(
                "reference_hex".into(),
                text(hex(b"refs/heads/nonutf8-\xff")),
            );
            assert_eq!(
                parse(name, &raw, format).unwrap().commands[0]
                    .name
                    .as_bytes(),
                b"refs/heads/nonutf8-\xff"
            );
        }
    }
}
#[test]
fn mutation_arguments_cannot_smuggle_authority_force_or_an_implicit_lease() {
    for name in [CREATE, UPDATE, DELETE, RENAME, PUBLISH] {
        let format = GitHashAlgorithm::Sha256;
        let original = args(name, format);
        for field in [
            "principal",
            "storage",
            "tenant",
            "repository",
            "force",
            "expected_head",
            "approved",
            "command",
            "bundle_path",
        ] {
            let mut bad = original.clone();
            bad.insert(field.into(), text("injected"));
            assert!(parse(name, &bad, format).is_err(), "{name} {field}");
        }
        let mut missing = original.clone();
        missing.remove("reference");
        assert!(parse(name, &missing, format).is_err());
        let mut doubled = original;
        doubled.insert("reference_hex".into(), text(hex(b"refs/heads/topic")));
        assert!(parse(name, &doubled, format).is_err());
    }
    for (name, field) in [
        (CREATE, "target"),
        (UPDATE, "expected_old"),
        (DELETE, "expected_old"),
        (RENAME, "expected_old"),
        (PUBLISH, "expected_base"),
        (PUBLISH, "expected_candidate"),
    ] {
        for value in [
            Value::Null,
            json::number(0),
            text("latest"),
            text("0".repeat(40)),
            text("A".repeat(40)),
            text("a".repeat(64)),
        ] {
            let mut bad = args(name, GitHashAlgorithm::Sha1);
            bad.insert(field.into(), value);
            assert!(parse(name, &bad, GitHashAlgorithm::Sha1).is_err());
        }
    }
    let mut rename = args(RENAME, GitHashAlgorithm::Sha1);
    rename.insert("destination".into(), text("refs/heads/topic"));
    assert!(parse(RENAME, &rename, GitHashAlgorithm::Sha1).is_err());
    for (name, new) in [(UPDATE, "target"), (PUBLISH, "expected_candidate")] {
        let mut no_op = args(name, GitHashAlgorithm::Sha1);
        no_op.insert(new.into(), text("a".repeat(40)));
        assert!(parse(name, &no_op, GitHashAlgorithm::Sha1).is_err());
    }
}
#[test]
fn complete_bundle_chunks_are_bounded_and_byte_exact_before_any_native_work() {
    let mut input = args(PUBLISH, GitHashAlgorithm::Sha1);
    assert_eq!(bundle(&input).unwrap(), [0, 1, 255]);
    for invalid in [
        Value::Null,
        text("/tmp/bundle"),
        Value::Array(vec![]),
        Value::Array(vec![text("00"); MAX_CHUNKS + 1]),
        Value::Array(vec![json::number(1)]),
        Value::Array(vec![text("")]),
        Value::Array(vec![text("0")]),
        Value::Array(vec![text("FF")]),
        Value::Array(vec![text("zz")]),
        Value::Array(vec![text("00".repeat(CHUNK_BYTES + 1))]),
    ] {
        input.insert("bundle_hex_chunks".into(), invalid);
        assert!(bundle(&input).is_err());
    }
    input.insert(
        "bundle_hex_chunks".into(),
        Value::Array(vec![text("ab".repeat(CHUNK_BYTES)); MAX_CHUNKS]),
    );
    assert_eq!(bundle(&input).unwrap(), vec![0xab; MAX_BUNDLE_BYTES]);
}
#[test]
fn maximum_bundle_and_reference_fit_the_existing_json_transport_without_new_global_limits() {
    let mut input = args(PUBLISH, GitHashAlgorithm::Sha256);
    input.remove("reference");
    input.insert("reference_hex".into(), text("ab".repeat(4096)));
    input.insert(
        "bundle_hex_chunks".into(),
        Value::Array(vec![text("00".repeat(CHUNK_BYTES)); MAX_CHUNKS]),
    );
    input.insert(
        "idempotency_key".into(),
        text("k".repeat(common::MAX_KEY_BYTES)),
    );
    let message = object([
        ("jsonrpc", text("2.0")),
        ("id", text("i".repeat(128))),
        ("method", text("tools/call")),
        (
            "params",
            object([("name", text(PUBLISH)), ("arguments", Value::Object(input))]),
        ),
    ]);
    let encoded = message.encode(json::MAX_INPUT).unwrap();
    assert_eq!(json::parse(encoded.as_bytes()).unwrap(), message);
    assert!(encoded.len() < json::MAX_INPUT);
}
fn terminal(committed: bool) -> (TxId, TerminalOutcome) {
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let digest = |seed| DigestBytes::try_new(&[seed; 32]).unwrap();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest(1));
    let outcome = if committed {
        DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest(2),
            ),
        }
    } else {
        DecisionOutcome::Refused {
            code: RefusalCode::EvidenceStale,
            refusal_record_id: RefusalRecordId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest(3),
            ),
        }
    };
    (
        tx,
        TerminalOutcome {
            decision_sequence: DecisionSequence::FIRST,
            outcome,
        },
    )
}
#[test]
fn partial_or_contradictory_atomic_outcomes_never_become_a_successful_rename() {
    for committed in [false, true] {
        let first = terminal(committed);
        let other = terminal(!committed);
        assert_eq!(
            atomic_terminal(true, &[first.0], &[first, first], 2).unwrap(),
            first
        );
        assert_eq!(
            atomic_terminal(true, &[first.0], &[first], 1).unwrap(),
            first
        );
        for (atomic, ids, rows, count) in [
            (false, vec![first.0], vec![first, first], 2),
            (true, vec![first.0], vec![first], 2),
            (true, vec![first.0], vec![first, other], 2),
            (true, vec![], vec![first], 1),
            (true, vec![first.0, first.0], vec![first, first], 2),
            (true, vec![first.0], vec![], 1),
            (true, vec![first.0], vec![first], 0),
        ] {
            assert!(
                !atomic_terminal(atomic, &ids, &rows, count)
                    .unwrap_err()
                    .invalid
            );
        }
    }
}
#[test]
fn discovery_requires_each_semantic_pin_and_has_no_force_or_host_path_field() {
    assert_eq!(tools().len(), 5);
    for tool in tools() {
        assert!(is_tool(tool.name));
        let schema = tool.schema.object().unwrap();
        assert_eq!(schema["additionalProperties"], Value::Bool(false));
        let properties = schema["properties"].object().unwrap();
        assert!(properties.contains_key("idempotency_key"));
        for denied in ["principal", "force", "bundle_path", "storage"] {
            assert!(!properties.contains_key(denied));
        }
        assert!(tool.schema.encode(16384).is_ok());
    }
    assert!(!is_tool("frankengit_source_merge"));
}
