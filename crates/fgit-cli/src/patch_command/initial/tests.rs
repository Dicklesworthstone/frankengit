use super::*;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, RefusalCode, RefusalRecordId, RepositoryCommitId,
    hash::{DigestAlgorithmId, DigestBytes},
};
fn prepare_args(format: &str) -> Vec<String> {
    [
        "prepare-initial",
        "node",
        &"11".repeat(16),
        &"22".repeat(16),
        "refs/heads/main",
        "new.patch",
        "initial.bundle",
        "--trusted-local",
        "--profile",
        "exact-v1",
        "--object-format",
        format,
        "--author",
        "Author <a@example.invalid>",
        "--timestamp",
        "1",
        "--message",
        "Initial\n",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn apply_args(width: usize) -> Vec<String> {
    [
        "apply-initial",
        "node",
        &"11".repeat(16),
        &"22".repeat(16),
        "refs/heads/main",
        "saved.bundle",
        "--trusted-local",
        "--principal",
        &"33".repeat(16),
        "--idempotency-key",
        "do-not-print-this-key",
        "--expected-commit",
        &"a".repeat(width),
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn set(args: &mut [String], flag: &str, value: &str) {
    let at = args.iter().position(|s| s == flag).unwrap();
    args[at + 1] = value.into();
}
fn identity() -> (DigestAlgorithmId, DigestBytes) {
    (
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&[7; 32]).unwrap(),
    )
}

#[test]
fn explicit_root_commands_and_exact_keys_support_both_domains() {
    for (fmt, width) in [("sha1", 40), ("sha256", 64)] {
        let prepared = options::parse(&prepare_args(fmt)).unwrap();
        assert_eq!(prepared.format.as_str(), fmt);
        let Operation::Prepare { metadata, .. } = prepared.operation else {
            panic!()
        };
        assert_eq!(metadata.author, metadata.committer);
        let applied = options::parse(&apply_args(width)).unwrap();
        assert_eq!(applied.format.as_str(), fmt);
        let Operation::Apply { key, candidate, .. } = applied.operation else {
            panic!()
        };
        assert_eq!(candidate.to_string(), "a".repeat(width));
        assert_eq!(
            key_bytes(&key, &mut &b"ignored"[..]).unwrap(),
            b"do-not-print-this-key"
        );
    }
    assert_eq!(
        key_bytes(&options::Key::Stdin, &mut &b"private\n"[..]).unwrap(),
        b"private\n"
    );
    assert!(key_bytes(&options::Key::Stdin, &mut &b""[..]).is_err());
    assert!(key_bytes(&options::Key::Stdin, &mut &vec![1; 257][..]).is_err());
    assert_eq!(
        key_bytes(&options::Key::Stdin, &mut &vec![1; 256][..])
            .unwrap()
            .len(),
        256
    );
}
#[test]
fn cross_operation_implicit_base_force_and_duplicate_fields_refuse() {
    for args in [prepare_args("sha1"), apply_args(40)] {
        let mut no_trust = args.clone();
        no_trust.retain(|a| a != "--trusted-local");
        assert!(options::parse(&no_trust).is_err());
        for flag in ["--force", "--expected-base", "--workspace-id", "--latest"] {
            let mut bad = args.clone();
            bad.extend([flag.into(), "ignored".into()]);
            assert!(options::parse(&bad).is_err());
        }
        let mut duplicate = args;
        duplicate.push("--trusted-local".into());
        assert!(options::parse(&duplicate).is_err());
    }
    let mut bad = prepare_args("sha1");
    bad.extend(["--principal".into(), "33".repeat(16)]);
    assert!(options::parse(&bad).is_err());
    let mut bad = apply_args(40);
    bad.extend(["--profile".into(), "exact-v1".into()]);
    assert!(options::parse(&bad).is_err());
    let mut stdin = apply_args(40);
    stdin.push("--key-stdin".into());
    assert!(options::parse(&stdin).is_err());
    let at = stdin.iter().position(|a| a == "--idempotency-key").unwrap();
    stdin.drain(at..at + 2);
    assert!(matches!(
        options::parse(&stdin).unwrap().operation,
        Operation::Apply {
            key: options::Key::Stdin,
            ..
        }
    ));
}
#[test]
fn raw_refs_metadata_and_limits_are_validated_without_repository_io() {
    let mut raw = prepare_args("sha256");
    raw[4] = hex(b"refs/heads/\xff");
    raw.push("--ref-hex".into());
    assert_eq!(
        options::parse(&raw).unwrap().reference.as_bytes(),
        b"refs/heads/\xff"
    );
    raw[4] = "fF".into();
    assert!(options::parse(&raw).is_err());
    for (flag, value) in [
        ("--profile", "fuzzy"),
        ("--timestamp", "0"),
        ("--timestamp", "01"),
        ("--timestamp", "18446744073709551616"),
        ("--author", "A <a@example.invalid>\nparent injected"),
        ("--message", ""),
    ] {
        let mut bad = prepare_args("sha1");
        set(&mut bad, flag, value);
        assert!(options::parse(&bad).is_err(), "{flag}");
    }
    for (flag, value) in [
        ("--max-files", "0"),
        ("--max-hunks", "4097"),
        ("--max-output-bytes", "33554433"),
    ] {
        let mut bad = prepare_args("sha1");
        bad.extend([flag.into(), value.into()]);
        assert!(options::parse(&bad).is_err());
    }
    for value in ["0".repeat(40), "x".repeat(40), "1".repeat(41)] {
        let mut bad = apply_args(40);
        set(&mut bad, "--expected-commit", &value);
        assert!(options::parse(&bad).is_err());
    }
    let mut bad = prepare_args("sha1");
    bad[4] = "refs/tags/main".into();
    assert!(options::parse(&bad).is_err());
}
#[test]
fn preparation_receipts_bind_the_complete_zero_parent_candidate() {
    for fmt in ["sha1", "sha256"] {
        let options = options::parse(&prepare_args(fmt)).unwrap();
        let Operation::Prepare {
            metadata, limits, ..
        } = &options.operation
        else {
            panic!()
        };
        let patch=b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+hello\n";
        let plan = fgit_forge::initial_commit::prepare_initial_commit(
            options.format,
            patch,
            metadata,
            *limits,
            &|| false,
        )
        .unwrap();
        let (algorithm, digest) = identity();
        let head =
            RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
        let receipt = prepared_receipt(
            &options,
            head,
            &plan,
            b"receipt-unit-input",
            plan.objects.len() as u32,
        )
        .unwrap();
        assert!(receipt.contains("\"parent_count\":0"));
        assert!(receipt.contains("\"published_to_repository\":false"));
        assert!(receipt.contains(&plan.commit.to_string()));
        assert!(receipt.contains(&hex(&plan.patch_sha256)));
        assert!(receipt.contains(&hex(&fgit_crypto::sha256_digest(b"receipt-unit-input"))));
        assert!(prepared_receipt(&options, head, &plan, b"", plan.objects.len() as u32).is_err());
        assert!(prepared_receipt(&options, head, &plan, b"bytes", 0).is_err());
    }
}
#[test]
fn terminal_receipts_preserve_commit_and_refusal_across_output_and_cleanup_failures() {
    let options = options::parse(&apply_args(40)).unwrap();
    let (algorithm, digest) = identity();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest);
    let commit = TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(2).unwrap(),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest,
            ),
        },
    };
    let mut bytes = Vec::new();
    assert_eq!(
        finish_applied(&mut bytes, &options, tx, &commit, None).unwrap(),
        0
    );
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"atomic\":true"));
    assert!(text.contains("\"expected_absent\":true"));
    assert!(!text.contains("do-not-print-this-key"));
    assert!(text.contains("\"outcome\":\"committed\""));
    let mut bytes = Vec::new();
    assert!(finish_applied(&mut bytes, &options, tx, &commit, Some("close failed")).is_err());
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"node_closed\":false"));
    assert!(text.contains("\"published_to_repository\":true"));
    struct Broken(bool);
    impl Write for Broken {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.0 {
                Ok(b.len())
            } else {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }
    for flush in [false, true] {
        let error = finish_applied(
            &mut Broken(flush),
            &options,
            tx,
            &commit,
            Some("close failed"),
        )
        .unwrap_err();
        assert!(error.contains("is committed as"));
        assert!(error.contains("close failed"));
    }
    let refused = TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(3).unwrap(),
        outcome: DecisionOutcome::Refused {
            code: RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id: RefusalRecordId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                digest,
            ),
        },
    };
    let mut bytes = Vec::new();
    assert_eq!(
        finish_applied(&mut bytes, &options, tx, &refused, None).unwrap(),
        3
    );
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("ExpectedOldRefMismatch")
    );
}
