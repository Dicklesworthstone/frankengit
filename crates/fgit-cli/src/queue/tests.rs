use super::*;
use fgit_forge::merge_queue::{MergeQueueSnapshot, QueueCommand, QueueCommandAction, QueueEntry};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{
    CANONICAL_CODEC_VERSION, DecisionSequence, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    GitOid, PrincipalId, RefName, RefusalCode, RefusalRecordId, RepositoryAuthorityHeadId,
    RepositoryCommitId,
};

fn input(action: &str) -> Vec<String> {
    let mut args = vec![
        action.into(),
        "unopened-queue-node".into(),
        "11".repeat(16),
        "22".repeat(16),
    ];
    if action != "list" {
        args.push("7".into());
    }
    args.push("--trusted-local".into());
    if !matches!(action, "show" | "list") {
        args.extend([
            "--principal".into(),
            "33".repeat(16),
            "--expected-incarnation".into(),
            "44".repeat(16),
            "--idempotency-key".into(),
            "private-stable-queue-key".into(),
            "--expected-version".into(),
            if action == "enqueue" {
                "0".into()
            } else {
                "2".into()
            },
            "--target-ref".into(),
            "refs/heads/main".into(),
        ]);
    }
    match action {
        "enqueue" | "land" => args.extend([
            "--pull-request".into(),
            "42".into(),
            "--source-ref".into(),
            "refs/heads/topic".into(),
            "--expected-source-tip".into(),
            "aa".repeat(20),
            "--expected-target-tip".into(),
            "bb".repeat(20),
            "--expected-pull-version".into(),
            "3".into(),
        ]),
        "dequeue" => {
            args.extend(["--pull-request", "42", "--reason", "withdrawn"].map(str::to_owned))
        }
        "reorder" => args.extend(["--entry", "42", "--entry", "11"].map(str::to_owned)),
        _ => {}
    }
    if action == "land" {
        args.extend(["--expected-policy-epoch", "1"].map(str::to_owned));
    }
    args
}

fn replace(args: &mut [String], flag: &str, value: &str) {
    let position = args.iter().position(|arg| arg == flag).unwrap();
    args[position + 1] = value.into();
}

fn remove(args: &mut Vec<String>, flag: &str) {
    let position = args.iter().position(|arg| arg == flag).unwrap();
    args.remove(position);
    if flag != "--trusted-local" {
        args.remove(position);
    }
}

fn mutation(options: &Options) -> &QueueCommand {
    let Operation::Mutate { command, .. } = &options.operation else {
        panic!("mutation fixture");
    };
    command
}

fn incarnation() -> RepositoryIncarnationId {
    RepositoryIncarnationId::from_bytes([4; 16])
}

fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_digest(
        DigestAlgorithmId::try_new(1).unwrap(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[6; 32]).unwrap(),
    )
}

fn terminal(committed: bool) -> (TxId, TerminalOutcome) {
    let algorithm = DigestAlgorithmId::try_new(1).unwrap();
    let digest = |byte| DigestBytes::try_new(&[byte; 32]).unwrap();
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

fn snapshot() -> MergeQueueSnapshot {
    let mut snapshot = MergeQueueSnapshot::new(
        QueueNumber::try_new(7).unwrap(),
        RefName::try_new(b"refs/heads/main").unwrap(),
    );
    snapshot.version = AggregateVersion::try_new(4).unwrap();
    snapshot.entries = [42, 11]
        .into_iter()
        .map(|number| QueueEntry {
            pull_request: PullRequestNumber::try_new(number).unwrap(),
            source_ref: RefName::try_new(format!("refs/heads/topic-{number}").as_bytes()).unwrap(),
            head_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"aa".repeat(20)).unwrap(),
            enqueued_by: PrincipalId::from_bytes([3; 16]),
            priority: if number == 42 { 0 } else { 10 },
            enqueued_version: AggregateVersion::FIRST,
        })
        .collect();
    snapshot
}

#[test]
fn enqueue_binds_exact_queue_pr_tips_scope_and_both_hash_formats() {
    for (format, bytes) in [("sha1", 20), ("sha256", 32)] {
        let mut args = input("enqueue");
        args.extend([
            "--object-format".into(),
            format.into(),
            "--priority".into(),
            "4294967295".into(),
        ]);
        replace(&mut args, "--expected-source-tip", &"aa".repeat(bytes));
        replace(&mut args, "--expected-target-tip", &"bb".repeat(bytes));
        let parsed = options::parse(&args).unwrap();
        let command = mutation(&parsed);
        assert_eq!(
            parsed.incarnation,
            Some(RepositoryIncarnationId::from_hex(&"44".repeat(16)).unwrap())
        );
        assert_eq!(command.expected_version, ExpectedVersion::NewStream);
        assert_eq!(command.number.get(), 7);
        let QueueCommandAction::Enqueue {
            pull_request,
            source_ref,
            head_tip,
            priority,
            expected_pull_request_version,
            expected_target_tip,
        } = &command.action
        else {
            panic!()
        };
        assert_eq!(pull_request.get(), 42);
        assert_eq!(source_ref.as_bytes(), b"refs/heads/topic");
        assert_eq!(head_tip.to_string(), "aa".repeat(bytes));
        assert_eq!(expected_target_tip.to_string(), "bb".repeat(bytes));
        assert_eq!(expected_pull_request_version.get(), 3);
        assert_eq!(*priority, u32::MAX);
        assert_eq!(head_tip.algorithm(), parsed.format);
    }
}

#[test]
fn every_write_requires_operator_scope_original_key_and_exact_predecessor() {
    for action in ["enqueue", "dequeue", "reorder", "land"] {
        for flag in [
            "--trusted-local",
            "--principal",
            "--expected-incarnation",
            "--idempotency-key",
            "--expected-version",
            "--target-ref",
        ] {
            let mut args = input(action);
            remove(&mut args, flag);
            assert!(
                options::parse(&args).is_err(),
                "{action} accepted missing {flag}"
            );
        }
        let mut args = input(action);
        replace(&mut args, "--expected-version", "18446744073709551615");
        assert!(options::parse(&args).is_err());
        replace(&mut args, "--expected-version", "01");
        assert!(options::parse(&args).is_err());
    }
    for flag in [
        "--pull-request",
        "--source-ref",
        "--expected-source-tip",
        "--expected-target-tip",
        "--expected-pull-version",
    ] {
        let mut args = input("enqueue");
        remove(&mut args, flag);
        assert!(
            options::parse(&args).is_err(),
            "enqueue accepted missing {flag}"
        );
    }
    for action in ["dequeue", "reorder", "land"] {
        let mut args = input(action);
        replace(&mut args, "--expected-version", "0");
        assert!(options::parse(&args).is_err());
    }
}

#[test]
fn malformed_native_coordinates_and_ambiguous_options_refuse_before_io() {
    for (flag, value) in [
        ("--source-ref", "refs/heads/main"),
        ("--source-ref", "refs/tags/topic"),
        ("--target-ref", "main"),
        ("--expected-pull-version", "0"),
        ("--pull-request", "0"),
        ("--expected-source-tip", "not-an-oid"),
        (
            "--expected-target-tip",
            "0000000000000000000000000000000000000000",
        ),
    ] {
        let mut args = input("enqueue");
        replace(&mut args, flag, value);
        assert!(options::parse(&args).is_err(), "accepted invalid {flag}");
    }
    let mut args = input("enqueue");
    args.extend(["--object-format", "sha256"].map(str::to_owned));
    assert!(options::parse(&args).is_err());
    for action in ["enqueue", "dequeue", "reorder", "land", "show", "list"] {
        let mut args = input(action);
        args.push("--trusted-local".into());
        assert!(options::parse(&args).is_err());
        let mut args = input(action);
        args.extend(["--force", "true"].map(str::to_owned));
        assert!(options::parse(&args).is_err());
    }
    for action in ["show", "list"] {
        let mut args = input(action);
        args.extend(["--principal".into(), "33".repeat(16)]);
        assert!(options::parse(&args).is_err());
    }
}

#[test]
fn reorder_preserves_full_explicit_order_and_refuses_duplicates_or_excess() {
    let parsed = options::parse(&input("reorder")).unwrap();
    let QueueCommandAction::Reorder { order } = &mutation(&parsed).action else {
        panic!()
    };
    assert_eq!(
        order.iter().map(|number| number.get()).collect::<Vec<_>>(),
        [42, 11]
    );
    let mut args = input("reorder");
    args.extend(["--entry", "42"].map(str::to_owned));
    assert!(options::parse(&args).is_err());
    let mut args = input("reorder");
    args.truncate(args.len() - 4);
    assert!(options::parse(&args).is_err());
    for number in 1..=1024 {
        args.extend(["--entry".into(), number.to_string()]);
    }
    assert!(options::parse(&args).is_ok());
    args.extend(["--entry", "1025"].map(str::to_owned));
    assert!(options::parse(&args).is_err());
}

#[test]
fn dequeue_reason_is_explicit_and_round_trips_into_the_receipt() {
    let (tx, terminal) = terminal(true);
    for value in [
        "withdrawn",
        "conflict",
        "check-failed",
        "base-moved",
        "evicted",
        "admin-override",
    ] {
        let mut args = input("dequeue");
        replace(&mut args, "--reason", value);
        let parsed = options::parse(&args).unwrap();
        let report = output::publication(&parsed, incarnation(), tx, &terminal, None).unwrap();
        assert!(report.contains(&format!("\"reason\":\"{value}\"")));
    }
    let mut args = input("dequeue");
    replace(&mut args, "--reason", "unknown");
    assert!(options::parse(&args).is_err());
}

#[test]
fn list_continuation_requires_the_exact_algorithm_qualified_head() {
    let mut args = input("list");
    args.extend(["--after", "7", "--limit", "1"].map(str::to_owned));
    assert!(options::parse(&args).is_err());
    args.extend(["--expected-head".into(), options::head_token(head())]);
    let parsed = options::parse(&args).unwrap();
    let Operation::List {
        after,
        limit,
        expected_head,
    } = parsed.operation
    else {
        panic!()
    };
    assert_eq!(after, 7);
    assert_eq!(limit, 1);
    assert_eq!(expected_head, Some(head()));
    for limit in ["0", "101", "-1", "01"] {
        replace(&mut args, "--limit", limit);
        assert!(options::parse(&args).is_err());
    }
    let mut show = input("show");
    show.extend([
        "--expected-head".into(),
        format!("head:{}", options::head_token(head())),
    ]);
    assert!(options::parse(&show).is_ok());
    replace(&mut show, "--expected-head", &"aa".repeat(32));
    assert!(options::parse(&show).is_err());
}

#[test]
fn read_receipts_preserve_authority_order_and_non_utf8_reference_bytes() {
    let options = options::parse(&input("show")).unwrap();
    let mut queue = snapshot();
    queue.entries[0].source_ref = RefName::try_new(b"refs/heads/non-utf8-\xff").unwrap();
    let report = output::show(
        &options,
        incarnation(),
        queue.queue_number,
        head(),
        Some(&queue),
    )
    .unwrap();
    assert!(report.contains("\"order\":[42,11]"));
    assert!(report.contains("\"source_ref\":null"));
    assert!(report.contains(&options::hex(queue.entries[0].source_ref.as_bytes())));
    assert!(report.contains(&options::head_token(head())));
    assert!(report.contains("\"version\":4"));
    let missing = output::show(&options, incarnation(), queue.queue_number, head(), None).unwrap();
    assert!(missing.contains("\"found\":false,\"version\":0,\"queue\":null"));
    assert!(missing.contains(&options::head_token(head())));
    queue.entries.push(queue.entries[0].clone());
    assert!(
        output::show(
            &options,
            incarnation(),
            queue.queue_number,
            head(),
            Some(&queue)
        )
        .is_err()
    );
}

#[test]
fn list_renderer_refuses_cursor_or_order_substitution() {
    let options = options::parse(&input("list")).unwrap();
    let first = snapshot();
    let mut second = snapshot();
    second.queue_number = QueueNumber::try_new(8).unwrap();
    let report = output::list(
        &options,
        incarnation(),
        head(),
        &[first.clone(), second.clone()],
        Some(8),
    )
    .unwrap();
    assert!(report.contains("\"next_after\":8"));
    assert!(
        output::list(
            &options,
            incarnation(),
            head(),
            &[second, first.clone()],
            None
        )
        .is_err()
    );
    assert!(output::list(&options, incarnation(), head(), &[first], Some(99)).is_err());
    assert!(output::list(&options, incarnation(), head(), &[], Some(7)).is_err());
}

#[test]
fn terminal_receipts_bind_guards_and_never_echo_the_retry_key() {
    for action in ["enqueue", "land"] {
        let options = options::parse(&input(action)).unwrap();
        for committed in [true, false] {
            let (tx, terminal) = terminal(committed);
            let mut bytes = Vec::new();
            let exit = finish(&mut bytes, &options, incarnation(), tx, &terminal, None).unwrap();
            assert_eq!(exit, if committed { 0 } else { 3 });
            let report = String::from_utf8(bytes).unwrap();
            assert!(report.contains(&tx.to_string()));
            assert!(report.contains("\"expected_pull_request_version\":3"));
            assert!(report.contains(&format!("\"expected_target_tip\":\"{}\"", "bb".repeat(20))));
            assert!(report.contains(&format!(
                "\"refs_changed\":{}",
                action == "land" && committed
            )));
            if action == "land" {
                assert!(report.contains("\"expected_policy_epoch\":1"));
                assert!(report.contains("\"method\":\"fast-forward-only\""));
            }
            assert!(!report.contains("private-stable-queue-key"));
            assert!(!report.contains("idempotency_key"));
            let mut bytes = Vec::new();
            let error = finish(
                &mut bytes,
                &options,
                incarnation(),
                tx,
                &terminal,
                Some("drain failed"),
            )
            .unwrap_err();
            assert!(error.contains(&tx.to_string()));
            assert!(
                String::from_utf8(bytes)
                    .unwrap()
                    .contains("\"node_closed\":false")
            );
        }
    }
}

struct BrokenOutput;
impl Write for BrokenOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn failed_receipt_output_retains_the_known_terminal_decision() {
    for action in ["dequeue", "land"] {
        let options = options::parse(&input(action)).unwrap();
        for committed in [true, false] {
            let (tx, terminal) = terminal(committed);
            let error = finish(
                &mut BrokenOutput,
                &options,
                incarnation(),
                tx,
                &terminal,
                None,
            )
            .unwrap_err();
            assert!(error.contains(&tx.to_string()));
            assert!(error.contains(if committed {
                "is committed"
            } else {
                "canonical refusal"
            }));
            assert!(error.contains("receipt output failed"));
        }
    }
}

#[test]
fn command_help_is_available_without_opening_a_repository() {
    for action in ["show", "list", "enqueue", "dequeue", "reorder", "land"] {
        let mut bytes = Vec::new();
        assert_eq!(
            run_to(&[action.into(), "--help".into()], &mut bytes).unwrap(),
            0
        );
        let help = String::from_utf8(bytes).unwrap();
        assert!(help.contains("--expected-incarnation"));
        assert!(help.contains("--expected-pull-version"));
        assert!(help.contains("--expected-policy-epoch"));
        assert!(help.contains("FastForwardOnly"));
        assert!(help.contains("publish atomically"));
    }
}

#[test]
fn landing_requires_exact_protection_scope_and_available_successor_versions() {
    for flag in [
        "--pull-request",
        "--source-ref",
        "--expected-source-tip",
        "--expected-target-tip",
        "--expected-pull-version",
        "--expected-policy-epoch",
    ] {
        let mut args = input("land");
        remove(&mut args, flag);
        assert!(
            options::parse(&args).is_err(),
            "land accepted missing {flag}"
        );
    }
    for (flag, value) in [
        ("--expected-version", "18446744073709551614"),
        ("--expected-pull-version", "18446744073709551615"),
        ("--expected-policy-epoch", "0"),
        ("--source-ref", "refs/heads/main"),
        (
            "--expected-target-tip",
            "0000000000000000000000000000000000000000",
        ),
    ] {
        let mut args = input("land");
        replace(&mut args, flag, value);
        assert!(
            options::parse(&args).is_err(),
            "land accepted invalid {flag}"
        );
    }
    for flag in [
        "--priority",
        "--entry",
        "--reason",
        "--batch-passed",
        "--force",
    ] {
        let mut args = input("land");
        args.extend([flag.into(), "1".into()]);
        assert!(
            options::parse(&args).is_err(),
            "land accepted inapplicable {flag}"
        );
    }
    for (format, bytes) in [("sha1", 20), ("sha256", 32)] {
        let mut args = input("land");
        args.extend(["--object-format".into(), format.into()]);
        replace(&mut args, "--expected-source-tip", &"aa".repeat(bytes));
        replace(&mut args, "--expected-target-tip", &"bb".repeat(bytes));
        let parsed = options::parse(&args).unwrap();
        let Operation::Land { command, .. } = parsed.operation else {
            panic!()
        };
        assert_eq!(command.expected_version.get(), 2);
        assert_eq!(command.expected_pull_request_version.get(), 3);
        assert_eq!(command.expected_policy_epoch.get(), 1);
        assert_eq!(command.head_tip.algorithm(), parsed.format);
        assert_eq!(command.expected_target_tip.algorithm(), parsed.format);
    }
}

#[test]
fn equal_tip_landing_refuses_before_node_io() {
    let mut args = input("land");
    replace(&mut args, "--expected-target-tip", &"aa".repeat(20));
    assert!(options::parse(&args).is_err());
}
