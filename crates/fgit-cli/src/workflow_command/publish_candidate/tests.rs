use super::*;
use fgit_forge::event::workflow_check::candidate::CandidateWorkflowCheckRecord;
use fgit_forge::event::workflow_check::{WorkflowCheckConclusion, WorkflowCheckRecord};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, DigestAlgorithmId, GitHashAlgorithm, PrincipalId,
    RefusalCode, RefusalRecordId, RepositoryCommitId,
};

fn arguments(format: GitHashAlgorithm) -> Vec<String> {
    let oid = |part: &str| part.repeat(format.digest_len());
    [
        "publish-candidate".into(),
        "/absent/storage".into(),
        "11".repeat(16),
        "22".repeat(16),
        "refs/heads/main".into(),
        "--trusted-local".into(),
        "--run-directory".into(),
        "/absent/private-run".into(),
        "--journal-id".into(),
        "aa".repeat(32),
        "--batch".into(),
        "bb".repeat(32),
        "--fact-index".into(),
        "0".into(),
        "--principal-id".into(),
        "33".repeat(16),
        "--idempotency-key".into(),
        "original-candidate-key".into(),
        "--expected-incarnation".into(),
        "44".repeat(16),
        "--object-format".into(),
        format.as_str().into(),
        "--pull-request".into(),
        "7".into(),
        "--expected-pull-request-version".into(),
        "3".into(),
        "--expected-policy-epoch".into(),
        "5".into(),
        "--source-ref".into(),
        "refs/heads/topic".into(),
        "--expected-source-tip".into(),
        oid("11"),
        "--expected-target-tip".into(),
        oid("22"),
        "--merge-base".into(),
        oid("33"),
        "--candidate-commit".into(),
        oid("44"),
        "--bundle".into(),
        "/absent/candidate.bundle".into(),
        "--bundle-sha256".into(),
        "55".repeat(32),
    ]
    .into_iter()
    .collect()
}
fn replace(arguments: &mut [String], flag: &str, value: &str) {
    let index = arguments.iter().position(|part| part == flag).unwrap();
    arguments[index + 1] = value.to_owned();
}
fn remove(arguments: &mut Vec<String>, flag: &str) {
    let index = arguments.iter().position(|part| part == flag).unwrap();
    arguments.drain(index..index + 2);
}

#[test]
fn complete_candidate_selection_parses_without_touching_paths_in_both_hash_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = arguments(format);
        let options = parse(&input).unwrap();
        assert_eq!(options.publication.format, format);
        assert_eq!(options.publication.reference.as_bytes(), b"refs/heads/main");
        assert_eq!(
            options.publication.directory,
            PathBuf::from("/absent/private-run")
        );
        assert_eq!(options.subject.pull_request.get(), 7);
        assert_eq!(options.subject.pull_request_version.get(), 3);
        assert_eq!(options.subject.policy_epoch.get(), 5);
        assert_eq!(options.subject.source_ref.as_bytes(), b"refs/heads/topic");
        assert_eq!(options.subject.source_tip.algorithm(), format);
        assert_eq!(options.candidate.commit.algorithm(), format);
        assert_eq!(options.bundle_sha256, [0x55; 32]);
        assert_eq!(options.bundle, PathBuf::from("/absent/candidate.bundle"));
        assert_eq!(
            options.publication.key.as_bytes(),
            b"original-candidate-key"
        );
        assert_eq!(
            options.publication.incarnation,
            Some(RepositoryIncarnationId::from_bytes([0x44; 16]))
        );
        assert!(!options.candidate.is_fast_forward(&options.subject));

        let mut fast_forward = input;
        replace(
            &mut fast_forward,
            "--merge-base",
            &"22".repeat(format.digest_len()),
        );
        replace(
            &mut fast_forward,
            "--candidate-commit",
            &"11".repeat(format.digest_len()),
        );
        let selected = parse(&fast_forward).unwrap();
        assert!(selected.candidate.is_fast_forward(&selected.subject));
    }
}

#[test]
fn exact_byte_refs_and_journal_pins_remain_explicit_and_source_encodings_are_exclusive() {
    let mut args = arguments(GitHashAlgorithm::Sha256);
    args[4] = hex(b"refs/heads/main-\xff");
    args.push("--ref-hex".into());
    let at = args.iter().position(|part| part == "--source-ref").unwrap();
    args[at] = "--source-ref-hex".into();
    args[at + 1] = hex(b"refs/heads/topic-\xfe");
    args.extend(["--minimum-pin".into(), format!("72:{}", "66".repeat(32))]);
    let selected = parse(&args).unwrap();
    assert_eq!(
        selected.subject.source_ref.as_bytes(),
        b"refs/heads/topic-\xfe"
    );
    assert_eq!(
        selected.subject.target_ref.as_bytes(),
        b"refs/heads/main-\xff"
    );
    assert_eq!(selected.publication.minimum.unwrap().0, 72);
    args.extend(["--source-ref".into(), "refs/heads/other".into()]);
    assert!(parse(&args).is_err());
}

#[test]
fn required_original_subject_digest_and_execution_selectors_cannot_be_omitted_or_replaced_by_claims()
 {
    for flag in [
        "--run-directory",
        "--journal-id",
        "--batch",
        "--fact-index",
        "--principal-id",
        "--idempotency-key",
        "--expected-incarnation",
        "--pull-request",
        "--expected-pull-request-version",
        "--expected-policy-epoch",
        "--source-ref",
        "--expected-source-tip",
        "--expected-target-tip",
        "--merge-base",
        "--candidate-commit",
        "--bundle",
        "--bundle-sha256",
    ] {
        let mut args = arguments(GitHashAlgorithm::Sha1);
        remove(&mut args, flag);
        assert!(parse(&args).is_err(), "{flag}");
    }
    for (flag, value) in [
        ("--conclusion", "success"),
        ("--evidence", "claimed"),
        ("--graph-root", "claimed"),
        ("--job", "claimed"),
        ("--actor", "claimed"),
        ("--method", "auto"),
        ("--expected-head", "latest"),
        ("--force", "true"),
    ] {
        let mut args = arguments(GitHashAlgorithm::Sha1);
        args.extend([flag.into(), value.into()]);
        assert!(parse(&args).is_err(), "{flag}");
    }
    let mut args = arguments(GitHashAlgorithm::Sha1);
    args.retain(|part| part != "--trusted-local");
    assert!(parse(&args).is_err());
    args.push("--trusted-local".into());
    assert!(parse(&args).is_ok());
}

#[test]
fn stale_shape_shortcuts_and_ambiguous_or_unbounded_values_refuse_before_io() {
    for flag in [
        "--pull-request",
        "--expected-pull-request-version",
        "--expected-policy-epoch",
    ] {
        for value in ["", "0", "01", "-1", "+1", "1e0", "18446744073709551616"] {
            let mut args = arguments(GitHashAlgorithm::Sha1);
            replace(&mut args, flag, value);
            assert!(parse(&args).is_err(), "{flag}={value}");
        }
    }
    for flag in [
        "--expected-source-tip",
        "--expected-target-tip",
        "--merge-base",
        "--candidate-commit",
    ] {
        for value in [
            "00".repeat(20),
            "11".repeat(32),
            "AA".repeat(20),
            "1".repeat(39),
        ] {
            let mut args = arguments(GitHashAlgorithm::Sha1);
            replace(&mut args, flag, &value);
            assert!(parse(&args).is_err(), "{flag}");
        }
    }
    for (flag, value) in [
        ("--source-ref", "refs/heads/main".to_owned()),
        ("--source-ref", "refs/tags/topic".to_owned()),
        ("--candidate-commit", "22".repeat(20)),
        ("--candidate-commit", "11".repeat(20)), // Invalid fast-forward base.
        ("--expected-source-tip", "22".repeat(20)),
        ("--bundle", String::new()),
        ("--bundle-sha256", "55".repeat(31)),
        ("--bundle-sha256", "AA".repeat(32)),
    ] {
        let mut args = arguments(GitHashAlgorithm::Sha1);
        replace(&mut args, flag, &value);
        assert!(parse(&args).is_err(), "{flag}");
    }
    let mut duplicate = arguments(GitHashAlgorithm::Sha1);
    duplicate.extend(["--bundle-sha256".into(), "55".repeat(32)]);
    assert!(parse(&duplicate).is_err());
    let mut excessive = arguments(GitHashAlgorithm::Sha1);
    replace(&mut excessive, "--bundle", &"x".repeat(4097));
    assert!(parse(&excessive).is_err());
    let mut nul = arguments(GitHashAlgorithm::Sha1);
    replace(&mut nul, "--bundle", "candidate\0.bundle");
    assert!(parse(&nul).is_err());
}

#[test]
fn artifact_digest_is_independent_exact_and_checkpointed_without_running_work() {
    let bytes = vec![0x77; 3 * 16 * 1024 + 1];
    let expected = fgit_crypto::sha256_digest(&bytes);
    assert!(verify_bundle_digest(&bytes, expected, &|| true).is_ok());
    let mut wrong = expected;
    wrong[0] ^= 1;
    assert!(verify_bundle_digest(&bytes, wrong, &|| true).is_err());
    assert!(
        verify_bundle_digest(&bytes, expected, &|| false)
            .unwrap_err()
            .contains("timed out")
    );
    let visits = std::cell::Cell::new(0);
    assert!(
        verify_bundle_digest(&bytes, expected, &|| {
            visits.set(visits.get() + 1);
            visits.get() < 3
        })
        .is_err()
    );
    assert_eq!(visits.get(), 3);
}

fn terminal(committed: bool) -> (TxId, TerminalOutcome) {
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let bytes = |seed| fgit_types::DigestBytes::try_new(&[seed; 32]).unwrap();
    let tx = TxId::from_digest(algorithm, CANONICAL_CODEC_VERSION, bytes(1));
    let outcome = if committed {
        DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                bytes(2),
            ),
        }
    } else {
        DecisionOutcome::Refused {
            code: RefusalCode::TargetRefMoved,
            refusal_record_id: RefusalRecordId::from_digest(
                algorithm,
                CANONICAL_CODEC_VERSION,
                bytes(3),
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
fn observation(options: &Options) -> NativeCandidateWorkflowCheck {
    NativeCandidateWorkflowCheck {
        actor: PrincipalId::from_bytes([0x33; 16]),
        record: CandidateWorkflowCheckRecord {
            subject: options.subject.clone(),
            candidate: options.candidate,
            bundle_sha256: options.bundle_sha256,
            check: WorkflowCheckRecord {
                source_ref: options.subject.target_ref.clone(),
                source_commit: options.candidate.commit,
                run_id: [1; 32],
                attempt_id: [2; 32],
                graph_root: [3; 32],
                job: "build/é\"".into(),
                conclusion: WorkflowCheckConclusion::Success,
                evidence: b"private original evidence".to_vec(),
            },
        },
    }
}

#[test]
fn historical_receipts_bind_original_subject_and_digest_without_claiming_fresh_eligibility() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let options = parse(&arguments(format)).unwrap();
        let observation = observation(&options);
        for committed in [true, false] {
            let (tx, terminal) = terminal(committed);
            let incarnation = options.publication.incarnation.unwrap();
            let mut output = Vec::new();
            assert_eq!(
                finish(
                    &mut output,
                    &options,
                    incarnation,
                    &observation,
                    tx,
                    &terminal,
                    true,
                    None
                )
                .unwrap(),
                if committed { 0 } else { 3 }
            );
            let rendered = String::from_utf8(output).unwrap();
            for expected in [
                "\"type\":\"candidate_workflow_check_publication\"",
                "\"subject_kind\":\"unpublished_pr_candidate\"",
                "\"outcome_recovered\":true",
                "\"objects_staged\":false",
                "\"refs_changed\":false",
                "\"execution_retried\":false",
                "\"current_refs_asserted\":false",
                "\"journal_acknowledged\":false",
                "\"merge_permission\":null",
                "\"node_closed\":true",
                "\"pull_request\":7",
                "\"pull_request_version\":3",
                "\"policy_epoch\":5",
            ] {
                assert!(rendered.contains(expected), "{expected}");
            }
            assert!(rendered.contains(&format!("\"bundle_sha256\":\"{}\"", "55".repeat(32))));
            assert!(rendered.contains(&quote(&observation.id().to_string())));
            assert!(rendered.contains(&quote(&options.candidate.commit.to_string())));
            assert!(rendered.contains(&quote(&observation.record.check.job)));
            assert!(!rendered.contains("private original evidence"));
            assert!(!rendered.contains("original-candidate-key"));
        }
    }
}

struct FailedOutput;
impl Write for FailedOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("output unavailable"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_or_cleanup_failure_keeps_the_known_candidate_terminal() {
    let options = parse(&arguments(GitHashAlgorithm::Sha1)).unwrap();
    let observation = observation(&options);
    let incarnation = options.publication.incarnation.unwrap();
    for committed in [true, false] {
        let (tx, terminal) = terminal(committed);
        let error = finish(
            &mut FailedOutput,
            &options,
            incarnation,
            &observation,
            tx,
            &terminal,
            false,
            None,
        )
        .unwrap_err();
        assert!(error.contains(&describe(tx, &terminal)));
        assert!(error.contains("receipt output failed"));
        let mut output = Vec::new();
        let error = finish(
            &mut output,
            &options,
            incarnation,
            &observation,
            tx,
            &terminal,
            false,
            Some("close failed"),
        )
        .unwrap_err();
        assert!(error.contains(&describe(tx, &terminal)));
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("\"node_closed\":false")
        );
    }
}
#[test]
fn help_requires_no_custody_and_names_original_bundle_pin_recovery() {
    let mut out = Vec::new();
    assert_eq!(
        run(&["publish-candidate".into(), "--help".into()], &mut out).unwrap(),
        0
    );
    let help = String::from_utf8(out).unwrap();
    assert!(help.contains("--bundle-sha256"));
    assert!(help.contains("before\nopening the bundle file"));
    assert!(help.contains("does not run scripts"));
}
