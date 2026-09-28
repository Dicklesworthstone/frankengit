use super::*;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, DigestAlgorithmId, GitOid, RefusalCode,
    RefusalRecordId, RepositoryCommitId,
};

fn arguments() -> Vec<String> {
    [
        "publish",
        "/absent/storage",
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
        "refs/heads/topic",
        "--trusted-local",
        "--run-directory",
        "/absent/private-run",
        "--journal-id",
        &"a".repeat(64),
        "--batch",
        &"b".repeat(64),
        "--fact-index",
        "0",
        "--principal-id",
        "33333333333333333333333333333333",
        "--idempotency-key",
        "original-key",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn replace(arguments: &mut [String], flag: &str, value: &str) {
    let index = arguments.iter().position(|part| part == flag).unwrap();
    arguments[index + 1] = value.to_owned();
}

#[test]
fn complete_publication_parses_without_opening_any_path() {
    let options = parse(&arguments()).unwrap();
    assert_eq!(options.storage, PathBuf::from("/absent/storage"));
    assert_eq!(options.directory, PathBuf::from("/absent/private-run"));
    assert_eq!(options.reference.as_bytes(), b"refs/heads/topic");
    assert_eq!(options.format, GitHashAlgorithm::Sha1);
    assert_eq!(options.fact_index, 0);
    assert_eq!(options.journal, digest(&"a".repeat(64)).unwrap());
    assert_eq!(options.batch, digest(&"b".repeat(64)).unwrap());
    assert_eq!(options.principal, PrincipalId::from_bytes([0x33; 16]));
    assert_eq!(options.key.as_bytes(), b"original-key");
    assert_eq!(options.timeout_ms, 30_000);
    assert!(options.minimum.is_none());
    assert!(options.incarnation.is_none());
}

#[test]
fn optional_scope_pins_and_non_utf8_ref_bytes_are_exact() {
    let mut input = arguments();
    input[4] = hex(b"refs/heads/topic-\xff");
    input.extend([
        "--ref-hex".to_owned(),
        "--object-format".to_owned(),
        "sha256".to_owned(),
        "--minimum-pin".to_owned(),
        format!("72:{}", "c".repeat(64)),
        "--expected-incarnation".to_owned(),
        "d".repeat(32),
        "--timeout-ms".to_owned(),
        "60000".to_owned(),
    ]);
    replace(&mut input, "--fact-index", "127");
    let options = parse(&input).unwrap();
    assert_eq!(options.reference.as_bytes(), b"refs/heads/topic-\xff");
    assert_eq!(options.format, GitHashAlgorithm::Sha256);
    assert_eq!(
        options.minimum,
        Some((72, digest(&"c".repeat(64)).unwrap()))
    );
    assert_eq!(
        options.incarnation,
        Some(RepositoryIncarnationId::from_bytes([0xdd; 16]))
    );
    assert_eq!(options.fact_index, 127);
    assert_eq!(options.timeout_ms, 60_000);
}

#[test]
fn trust_scope_and_exact_fact_selectors_are_all_mandatory() {
    for flag in [
        "--trusted-local",
        "--run-directory",
        "--journal-id",
        "--batch",
        "--fact-index",
        "--principal-id",
        "--idempotency-key",
    ] {
        let mut input = arguments();
        let index = input.iter().position(|part| part == flag).unwrap();
        let count = if flag == "--trusted-local" { 1 } else { 2 };
        input.drain(index..index + count);
        assert!(parse(&input).is_err(), "accepted missing {flag}");
    }
    assert!(parse(&arguments()).is_ok());
}

#[test]
fn duplicate_unknown_and_execution_options_refuse_before_io() {
    for flag in [
        "--trusted-local",
        "--batch",
        "--principal-id",
        "--idempotency-key",
    ] {
        let mut input = arguments();
        input.push(flag.to_owned());
        if flag != "--trusted-local" {
            input.push("value".to_owned());
        }
        assert!(parse(&input).unwrap_err().contains("duplicate"));
    }
    for flag in [
        "--run-id",
        "--workflow",
        "--input",
        "--output",
        "--evidence",
        "--force",
    ] {
        let mut input = arguments();
        input.extend([flag.to_owned(), "value".to_owned()]);
        assert!(parse(&input).unwrap_err().contains("unknown"));
    }
    let mut missing = arguments();
    missing.push("--minimum-pin".to_owned());
    assert!(parse(&missing).unwrap_err().contains("missing value"));
    assert!(parse(&arguments()).is_ok());
}

#[test]
fn decimal_indices_and_timeouts_have_exact_bounded_twins() {
    for value in [
        "",
        "-1",
        "+1",
        "00",
        "01",
        " 1",
        "1 ",
        "1.0",
        "128",
        "18446744073709551616",
        "١",
    ] {
        let mut input = arguments();
        replace(&mut input, "--fact-index", value);
        assert!(parse(&input).is_err(), "accepted fact index {value:?}");
    }
    for value in ["0", "1", "127"] {
        let mut input = arguments();
        replace(&mut input, "--fact-index", value);
        assert_eq!(parse(&input).unwrap().fact_index.to_string(), value);
    }
    for value in ["0", "01", "60001", "18446744073709551616"] {
        let mut input = arguments();
        input.extend(["--timeout-ms".to_owned(), value.to_owned()]);
        assert!(parse(&input).is_err());
    }
    for value in ["1", "60000"] {
        let mut input = arguments();
        input.extend(["--timeout-ms".to_owned(), value.to_owned()]);
        assert_eq!(parse(&input).unwrap().timeout_ms.to_string(), value);
    }
}

#[test]
fn exact_scope_hex_and_anti_rollback_pin_shapes_are_checked() {
    for flag in ["--journal-id", "--batch"] {
        for value in [
            "a".repeat(63),
            "a".repeat(66),
            "A".repeat(64),
            "z".repeat(64),
        ] {
            let mut input = arguments();
            replace(&mut input, flag, &value);
            assert!(parse(&input).is_err(), "accepted malformed {flag}");
        }
    }
    for flag in ["--principal-id", "--expected-incarnation"] {
        let mut input = arguments();
        if flag == "--expected-incarnation" {
            input.extend([flag.to_owned(), "d".repeat(32)]);
        }
        for value in ["1".repeat(30), "1".repeat(34), "A".repeat(32)] {
            replace(&mut input, flag, &value);
            assert!(parse(&input).is_err());
        }
    }
    for value in [
        format!("71:{}", "c".repeat(64)),
        format!("4294967297:{}", "c".repeat(64)),
        format!("072:{}", "c".repeat(64)),
        format!("72:{}", "c".repeat(63)),
        format!("72:{}:extra", "c".repeat(64)),
    ] {
        let mut input = arguments();
        input.extend(["--minimum-pin".to_owned(), value]);
        assert!(parse(&input).is_err());
    }
    for length in [72, 4_294_967_296_u64] {
        let mut input = arguments();
        input.extend([
            "--minimum-pin".to_owned(),
            format!("{length}:{}", "c".repeat(64)),
        ]);
        assert_eq!(parse(&input).unwrap().minimum.unwrap().0, length);
    }
    assert!(parse(&arguments()).is_ok());
}

#[test]
fn paths_branches_keys_and_total_arguments_refuse_unsafe_or_unbounded_input() {
    for path in ["", "relative/run", "/private/../run", "/private/run/", "/"] {
        let mut input = arguments();
        replace(&mut input, "--run-directory", path);
        assert!(parse(&input).is_err());
    }
    for name in [
        "HEAD",
        "refs/tags/release",
        "refs/heads/../topic",
        "refs/heads/topic.lock",
    ] {
        let mut input = arguments();
        input[4] = name.to_owned();
        assert!(parse(&input).is_err());
    }
    for key in [String::new(), "a".repeat(257), "embedded\0nul".to_owned()] {
        let mut input = arguments();
        replace(&mut input, "--idempotency-key", &key);
        assert!(parse(&input).is_err());
    }
    let mut bounded = arguments();
    replace(&mut bounded, "--idempotency-key", &"a".repeat(256));
    assert_eq!(parse(&bounded).unwrap().key.as_bytes().len(), 256);
    let mut too_large = arguments();
    too_large[1] = "x".repeat(4097);
    assert!(parse(&too_large).is_err());
    let mut too_many = arguments();
    too_many.extend(vec!["--trusted-local".to_owned(); 41]);
    assert!(parse(&too_many).is_err());
    let mut nul = arguments();
    nul[1] = "/root\0other".to_owned();
    assert!(parse(&nul).is_err());
    assert!(parse(&arguments()).is_ok());
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

fn observation(format: GitHashAlgorithm) -> NativeWorkflowCheck {
    NativeWorkflowCheck {
        actor: PrincipalId::from_bytes([0x33; 16]),
        record: fgit_forge::event::workflow_check::WorkflowCheckRecord {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_commit: GitOid::from_hex(format, &"c".repeat(format.digest_len() * 2)).unwrap(),
            run_id: [4; 32],
            attempt_id: [5; 32],
            graph_root: [6; 32],
            job: "build/é\"\\\u{202e}".to_owned(),
            conclusion: WorkflowCheckConclusion::ActionRequired,
            evidence: b"private raw execution output".to_vec(),
        },
    }
}

#[test]
fn receipts_preserve_exact_check_identity_and_never_grant_success() {
    let incarnation = RepositoryIncarnationId::from_bytes([0xdd; 16]);
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut options = parse(&arguments()).unwrap();
        options.format = format;
        let mut check = observation(format);
        for (conclusion, name) in [
            (WorkflowCheckConclusion::ActionRequired, "action_required"),
            (WorkflowCheckConclusion::Failure, "failure"),
            (WorkflowCheckConclusion::Cancelled, "cancelled"),
            (WorkflowCheckConclusion::TimedOut, "timed_out"),
        ] {
            check.record.conclusion = conclusion;
            let (tx, terminal) = terminal(true);
            let rendered = receipt(&options, incarnation, &check, tx, &terminal, None);
            assert_eq!(
                rendered,
                receipt(&options, incarnation, &check, tx, &terminal, None)
            );
            assert!(rendered.contains(&format!("\"check_id\":{}", quote(&check.id().to_string()))));
            assert!(rendered.contains(&format!("\"job\":{}", quote(&check.record.job))));
            assert!(rendered.contains(&format!(
                "\"source_commit\":{}",
                quote(&check.record.source_commit.to_string())
            )));
            assert!(rendered.contains(&format!("\"conclusion\":\"{name}\"")));
            assert!(rendered.contains("\"merge_permission\":null"));
            assert!(rendered.contains("\"authoritative_check\":false"));
            assert!(rendered.contains("\"execution_retried\":false"));
            assert!(rendered.contains("\"journal_acknowledged\":false"));
            assert!(rendered.contains("\"decision_sequence\":\"1\""));
            assert!(rendered.contains("\"current_refs_asserted\":false"));
            assert!(!rendered.contains("private raw execution output"));
            assert!(!rendered.contains("original-key"));
            assert!(!rendered.contains('\u{202e}'));
        }
    }
}

#[test]
fn terminal_receipts_distinguish_canonical_refusal_from_committed_observation() {
    let options = parse(&arguments()).unwrap();
    let incarnation = RepositoryIncarnationId::from_bytes([0xdd; 16]);
    let check = observation(options.format);
    for (committed, exit) in [(true, 0), (false, 3)] {
        let (tx, terminal) = terminal(committed);
        let mut out = Vec::new();
        assert_eq!(
            finish(&mut out, &options, incarnation, &check, tx, &terminal, None).unwrap(),
            exit
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains(&format!("\"command_committed\":{committed}")));
        assert!(out.contains("\"node_closed\":true"));
        if committed {
            assert!(out.contains("\"outcome\":\"committed\""));
            assert!(out.contains("\"refusal_code\":null"));
        } else {
            assert!(out.contains("\"outcome\":\"refused\""));
            assert!(out.contains("\"refusal_code\":\"TargetRefMoved\""));
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
fn output_or_shutdown_failure_never_erases_the_known_terminal_decision() {
    let options = parse(&arguments()).unwrap();
    let incarnation = RepositoryIncarnationId::from_bytes([0xdd; 16]);
    let check = observation(options.format);
    for committed in [true, false] {
        let (tx, terminal) = terminal(committed);
        let error = finish(
            &mut FailedOutput,
            &options,
            incarnation,
            &check,
            tx,
            &terminal,
            None,
        )
        .unwrap_err();
        assert!(error.contains(&describe(tx, &terminal)));
        assert!(error.contains("receipt output failed"));
        let mut out = Vec::new();
        let error = finish(
            &mut out,
            &options,
            incarnation,
            &check,
            tx,
            &terminal,
            Some("close failed"),
        )
        .unwrap_err();
        assert!(error.contains(&describe(tx, &terminal)));
        assert!(error.contains("node shutdown failed"));
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("\"node_closed\":false")
        );
    }
}

#[test]
fn unknown_outcomes_require_identical_reconciliation_without_execution_retry() {
    let before = operation_error("open failed", false, Some("close failed"));
    assert!(before.contains("this invocation submitted no observation"));
    assert!(before.contains("does not determine any earlier invocation's outcome"));
    let entered = operation_error("response lost", true, None);
    assert!(entered.contains("not evidence of non-commit"));
    assert!(entered.contains(
        "identical principal, idempotency key, branch bytes, journal ID, batch and fact"
    ));
    assert!(entered.contains("do not rerun the workflow"));
}

#[test]
fn help_needs_no_saved_workflow_or_repository_and_explains_conclusions() {
    let mut out = Vec::new();
    assert_eq!(
        run(&["publish".to_owned(), "--help".to_owned()], &mut out).unwrap(),
        0
    );
    let help = String::from_utf8(out).unwrap();
    assert!(help.contains("fg workflow publish"));
    assert!(help.contains("Local success remains action_required"));
    assert!(help.contains("does not run scripts") || help.contains("does\nnot run scripts"));
}
