use super::*;
use fgit_schema::json;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, DigestAlgorithmId, DigestBytes, RefusalCode,
    RefusalRecordId, RepositoryCommitId,
};

fn args(write: bool, format: &str) -> Vec<String> {
    let mut result = vec![
        if write { "set-default" } else { "default" }.into(),
        "unopened".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--trusted-local".into(),
        "--object-format".into(),
        format.into(),
    ];
    if write {
        result.extend([
            "--principal".into(),
            "33".repeat(16),
            "--idempotency-key".into(),
            "private-default-key".into(),
            "--expected-default".into(),
            "refs/heads/main".into(),
            "--ref".into(),
            "refs/heads/trunk".into(),
            "--expected-tip".into(),
            "ab".repeat(if format == "sha256" { 32 } else { 20 }),
        ]);
    }
    result
}

fn replace(values: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut changed = values.to_vec();
    let at = changed.iter().position(|item| item == flag).unwrap();
    changed[at + 1] = value.into();
    changed
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
            code: RefusalCode::ProtectedRefTransitionDenied,
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

fn document(bytes: &[u8]) -> Value {
    json::parse(bytes).unwrap()
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    &value.object().unwrap()[name]
}

#[test]
fn exact_named_absent_and_non_utf8_head_expectations_are_distinct() {
    for format in ["sha1", "sha256"] {
        let named = args(true, format);
        let parsed = options::parse(&named).unwrap();
        let Operation::Set { command, .. } = parsed.operation else {
            panic!()
        };
        assert_eq!(
            command.expected_head.unwrap().as_bytes(),
            b"refs/heads/main"
        );
        assert_eq!(command.target.as_bytes(), b"refs/heads/trunk");
        assert_eq!(command.expected_target_tip.algorithm().as_str(), format);

        let mut absent = named.clone();
        let at = absent
            .iter()
            .position(|value| value == "--expected-default")
            .unwrap();
        absent.splice(at..at + 2, ["--expect-no-default".into()]);
        let parsed = options::parse(&absent).unwrap();
        let Operation::Set { command, .. } = parsed.operation else {
            panic!()
        };
        assert!(command.expected_head.is_none());
        absent.extend(["--expected-default".into(), "refs/heads/main".into()]);
        assert!(options::parse(&absent).is_err());

        let mut bytes = named;
        let at = bytes
            .iter()
            .position(|value| value == "--expected-default")
            .unwrap();
        bytes[at] = "--expected-default-hex".into();
        bytes[at + 1] = hex(b"refs/heads/\xff");
        let at = bytes.iter().position(|value| value == "--ref").unwrap();
        bytes[at] = "--ref-hex".into();
        bytes[at + 1] = hex(b"refs/heads/\xfe");
        let parsed = options::parse(&bytes).unwrap();
        let Operation::Set { command, .. } = parsed.operation else {
            panic!()
        };
        assert_eq!(
            command.expected_head.unwrap().as_bytes(),
            b"refs/heads/\xff"
        );
        assert_eq!(command.target.as_bytes(), b"refs/heads/\xfe");
    }
}

#[test]
fn write_requires_every_original_precondition_and_never_promotes_read_flags() {
    let values = args(true, "sha1");
    for flag in [
        "--principal",
        "--idempotency-key",
        "--expected-default",
        "--ref",
        "--expected-tip",
    ] {
        let mut missing = values.clone();
        let at = missing.iter().position(|value| value == flag).unwrap();
        missing.drain(at..at + 2);
        assert!(options::parse(&missing).is_err(), "{flag}");
    }
    let mut untrusted = values.clone();
    untrusted.retain(|value| value != "--trusted-local");
    assert!(options::parse(&untrusted).is_err());
    for (flag, value) in [
        ("--force", "true"),
        ("--expected-head", "latest"),
        ("--unset", "true"),
        ("--expected-tip", ""),
        ("--ref", "HEAD"),
    ] {
        let mut duplicate = values.clone();
        duplicate.extend([flag.into(), value.into()]);
        assert!(options::parse(&duplicate).is_err());
    }
    for invalid in ["refs/tags/tag", "HEAD", "main", "refs/heads/../bad", ""] {
        assert!(options::parse(&replace(&values, "--ref", invalid)).is_err());
        assert!(options::parse(&replace(&values, "--expected-default", invalid)).is_err());
    }
    for invalid in ["0".repeat(40), "1".repeat(64), "Z".repeat(40)] {
        assert!(options::parse(&replace(&values, "--expected-tip", &invalid)).is_err());
    }
    for flag in [
        "--principal",
        "--ref",
        "--idempotency-key",
        "--expected-default",
    ] {
        let mut read = args(false, "sha1");
        read.extend([flag.into(), "unwanted".into()]);
        assert!(options::parse(&read).is_err());
    }
    let mut duplicate_key = values.clone();
    duplicate_key.push("--key-stdin".into());
    assert!(options::parse(&duplicate_key).is_err());
    assert!(options::parse(&replace(&values, "--idempotency-key", &"k".repeat(257))).is_err());
    let mut oversized = args(false, "sha1");
    oversized[1] = "x".repeat(4097);
    assert!(options::parse(&oversized).is_err());
}

#[test]
fn absent_unborn_and_resolved_reads_never_invent_a_default() {
    let options = options::parse(&args(false, "sha1")).unwrap();
    let head = RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[7; 32]).unwrap(),
    );
    let target = RefName::try_new(b"refs/heads/\xff").unwrap();
    let tip = GitOid::from_hex(options.format, &"12".repeat(20)).unwrap();
    for (target, tip, unborn) in [
        (None, None, false),
        (Some(&target), None, true),
        (Some(&target), Some(tip), false),
    ] {
        let receipt = document(
            read_receipt(&options, head, target, tip)
                .unwrap()
                .as_bytes(),
        );
        assert_eq!(field(&receipt, "default_reference_hex"), &reference(target));
        assert_eq!(field(&receipt, "unborn"), &Value::Bool(unborn));
        assert_eq!(field(&receipt, "read_only"), &Value::Bool(true));
        assert_eq!(field(&receipt, "node_closed"), &Value::Bool(true));
    }
    assert!(read_receipt(&options, head, None, Some(tip)).is_err());
}

#[test]
fn receipt_failure_preserves_the_canonical_outcome_and_original_identity() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("lost output"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let options = options::parse(&args(true, "sha1")).unwrap();
    for committed in [false, true] {
        let (tx, terminal) = terminal(committed);
        let mut output = Vec::new();
        assert_eq!(
            finish_publication(&mut output, &options, tx, &terminal, None).unwrap(),
            if committed { 0 } else { 3 }
        );
        let receipt = document(&output);
        assert_eq!(
            field(&receipt, "command_committed"),
            &Value::Bool(committed)
        );
        assert_eq!(
            field(&receipt, "head_changed_by_transaction"),
            &Value::Bool(committed)
        );
        assert_eq!(field(&receipt, "direct_refs_changed"), &Value::Bool(false));
        assert!(
            !String::from_utf8(output)
                .unwrap()
                .contains("private-default-key")
        );
        let error = finish_publication(&mut Broken, &options, tx, &terminal, Some("close failed"))
            .unwrap_err();
        assert!(error.contains(&tx.to_string()) && error.contains("close failed"));
        assert!(error.contains(if committed {
            "is committed"
        } else {
            "canonical refusal"
        }));
        let mut output = Vec::new();
        assert!(
            finish_publication(&mut output, &options, tx, &terminal, Some("close failed")).is_err()
        );
        let receipt = document(&output);
        assert_eq!(
            field(&receipt, "command_committed"),
            &Value::Bool(committed)
        );
        assert_eq!(field(&receipt, "node_closed"), &Value::Bool(false));
    }
    let same = options::parse(&replace(&args(true, "sha1"), "--ref", "refs/heads/main")).unwrap();
    let (tx, terminal) = terminal(true);
    let receipt = document(
        publication_receipt(&same, tx, &terminal, None)
            .unwrap()
            .0
            .as_bytes(),
    );
    assert_eq!(
        field(&receipt, "head_changed_by_transaction"),
        &Value::Bool(false)
    );
    assert_eq!(field(&receipt, "command_committed"), &Value::Bool(true));
}
