use super::*;
fn args() -> Vec<String> {
    [
        "watch",
        "/not-opened",
        &"11".repeat(16),
        &"22".repeat(16),
        "refs/heads/main",
        "--trusted-local",
        "--workflow",
        "ci",
        "--input",
        "ci",
        "--run-parent",
        "/private",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn merge_args() -> Vec<String> {
    [
        args(),
        [
            "--pull-request",
            "7",
            "--expected-incarnation",
            &"44".repeat(16),
            "--merge-candidate-ref",
            "refs/heads/ci/pr-7",
            "--merge-principal",
            &"33".repeat(16),
            "--merge-author",
            "CI <ci@example.test>",
            "--merge-committer",
            "CI <ci@example.test>",
            "--merge-timestamp",
            "1700000000",
            "--merge-message",
            "Test the combined tree\n",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    ]
    .concat()
}

fn queue_args() -> Vec<String> {
    let mut input = merge_args();
    let index = input
        .iter()
        .position(|value| value == "--pull-request")
        .unwrap();
    input[index] = "--merge-queue".into();
    input
}

#[test]
fn queue_watch_selects_target_and_current_head_without_implicit_check_publication() {
    let mut input = queue_args();
    let parsed = options(&input).unwrap();
    assert_eq!(parsed.merge_queue, Some(7));
    assert!(parsed.pull_request.is_none());
    assert!(parsed.publisher.is_none());
    assert_eq!(parsed.execution.reference.as_bytes(), b"refs/heads/main");
    assert_eq!(
        parsed.merge_candidate.unwrap().style,
        fgit_forge::preparation::MergeCommitStyle::TwoParent
    );
    input.extend([
        "--publish-checks".into(),
        "--principal-id".into(),
        "55".repeat(16),
        "--merge-profile".into(),
        "exact-renames".into(),
        "--continuous".into(),
        "--stop-file".into(),
        "/private/queue.stop".into(),
        "--attempt-timeout-secs".into(),
        "120".into(),
    ]);
    let parsed = options(&input).unwrap();
    assert_eq!(parsed.merge_queue, Some(7));
    assert_ne!(
        parsed.publisher.unwrap(),
        parsed.merge_candidate.as_ref().unwrap().principal
    );
    assert_eq!(
        parsed.merge_candidate.unwrap().profile,
        fgit_forge::preparation::MergeProfile::ExactRenamesV1
    );
    assert_eq!(parsed.attempt_timeout, Duration::from_secs(120));
}

#[test]
fn queue_watch_requires_exact_exclusive_selection_complete_identity_and_two_parents() {
    for flag in [
        "--expected-incarnation",
        "--merge-candidate-ref",
        "--merge-principal",
        "--merge-author",
        "--merge-committer",
        "--merge-timestamp",
        "--merge-message",
    ] {
        let mut input = queue_args();
        let at = input.iter().position(|value| value == flag).unwrap();
        input.drain(at..at + 2);
        assert!(options(&input).is_err(), "{flag}");
    }
    assert!(options(&[args(), vec!["--merge-queue".into(), "7".into()]].concat()).is_err());
    for extra in [
        vec!["--pull-request", "7"],
        vec!["--merge-queue", "7"],
        vec!["--merge-method", "squash"],
    ] {
        let mut input = queue_args();
        input.extend(extra.into_iter().map(str::to_owned));
        assert!(options(&input).is_err());
    }
    let mut input = queue_args();
    let at = input
        .iter()
        .position(|value| value == "--merge-candidate-ref")
        .unwrap();
    input[at + 1] = input[4].clone();
    assert!(options(&input).is_err());
    for invalid in [
        "0",
        "01",
        "-1",
        "+1",
        "1.0",
        "18446744073709551616",
        "",
        "7\n",
    ] {
        let mut input = queue_args();
        let at = input
            .iter()
            .position(|value| value == "--merge-queue")
            .unwrap();
        input[at + 1] = invalid.into();
        assert!(options(&input).is_err(), "{invalid:?}");
    }
    let mut input = queue_args();
    let at = input
        .iter()
        .position(|value| value == "--merge-queue")
        .unwrap();
    input[at + 1] = u64::MAX.to_string();
    assert_eq!(options(&input).unwrap().merge_queue, Some(u64::MAX));
}

#[test]
fn queue_watch_keeps_raw_target_bytes_and_flag_looking_values_exact() {
    let mut input = queue_args();
    input[4] = "726566732f68656164732fff".into();
    input.push("--ref-hex".into());
    let at = input
        .iter()
        .position(|value| value == "--merge-message")
        .unwrap();
    input[at + 1] = "--merge-queue".into();
    let parsed = options(&input).unwrap();
    assert_eq!(parsed.execution.reference.as_bytes(), b"refs/heads/\xff");
    assert_eq!(parsed.merge_queue, Some(7));
    assert_eq!(
        parsed.merge_candidate.unwrap().metadata.message,
        b"--merge-queue"
    );
    let mut input = args();
    input[7] = "--merge-queue".into();
    input[9] = "--merge-queue".into();
    assert!(options(&input).unwrap().merge_queue.is_none());
}

#[test]
fn merge_watch_is_explicit_and_does_not_implicitly_publish_checks() {
    let options = options(&merge_args()).unwrap();
    assert_eq!(options.pull_request, Some(7));
    assert!(options.publisher.is_none());
    let merge = options.merge_candidate.unwrap();
    assert_eq!(merge.reference.as_bytes(), b"refs/heads/ci/pr-7");
    assert_eq!(merge.metadata.message, b"Test the combined tree\n");
    assert_eq!(
        merge.style,
        fgit_forge::preparation::MergeCommitStyle::TwoParent
    );

    let mut input = merge_args();
    input.extend([
        "--publish-checks".into(),
        "--principal-id".into(),
        "55".repeat(16),
        "--merge-method".into(),
        "squash".into(),
        "--merge-profile".into(),
        "exact-renames".into(),
    ]);
    let options = self::options(&input).unwrap();
    assert_eq!(
        options.publisher.unwrap(),
        fgit_types::PrincipalId::from_bytes([0x55; 16])
    );
    assert_eq!(
        options.merge_candidate.unwrap().style,
        fgit_forge::preparation::MergeCommitStyle::Squash
    );
    assert!(self::options(&args()).unwrap().merge_candidate.is_none());
}

#[test]
fn merge_watch_requires_complete_identity_pr_and_incarnation_without_io() {
    for flag in [
        "--pull-request",
        "--expected-incarnation",
        "--merge-candidate-ref",
        "--merge-principal",
        "--merge-author",
        "--merge-committer",
        "--merge-timestamp",
        "--merge-message",
    ] {
        let mut input = merge_args();
        let index = input.iter().position(|v| v == flag).unwrap();
        input.drain(index..index + 2);
        assert!(options(&input).is_err(), "{flag}");
    }
    let mut input = merge_args();
    input.extend(["--merge-principal".into(), "66".repeat(16)]);
    assert!(options(&input).is_err());
    let mut input = merge_args();
    let index = input
        .iter()
        .position(|v| v == "--merge-candidate-ref")
        .unwrap();
    input[index + 1] = input[4].clone();
    assert!(options(&input).is_err());
}

#[test]
fn merge_option_values_cannot_inject_another_option() {
    let mut input = merge_args();
    let index = input.iter().position(|v| v == "--merge-message").unwrap();
    input[index + 1] = "--merge-method".into();
    let options = options(&input).unwrap();
    let merge = options.merge_candidate.unwrap();
    assert_eq!(merge.metadata.message, b"--merge-method");
    assert_eq!(
        merge.style,
        fgit_forge::preparation::MergeCommitStyle::TwoParent
    );
}
#[test]
fn defaults_and_finite_polling_options_parse_without_io() {
    let opts = options(&args()).unwrap();
    assert_eq!(opts.polls, 1);
    assert_eq!(opts.interval, Duration::from_secs(1));
    assert!(opts.stop_file.is_none());
    assert_eq!(opts.execution.workflow, b"ci");
    let mut input = args();
    input.extend([
        "--polls".into(),
        "10000".into(),
        "--interval-ms".into(),
        "10".into(),
    ]);
    let opts = options(&input).unwrap();
    assert_eq!(opts.polls, 10000);
    assert_eq!(opts.interval, Duration::from_millis(10));
}
#[test]
fn continuous_lifetime_requires_explicit_control_and_preserves_finite_attempts() {
    let input = [
        args(),
        vec![
            "--continuous".into(),
            "--stop-file".into(),
            "watch.stop".into(),
        ],
    ]
    .concat();
    let opts = options(&input).unwrap();
    assert_eq!(opts.stop_file, Some(PathBuf::from("watch.stop")));
    assert_eq!(opts.attempt_timeout, Duration::from_secs(300));
    let mut configured = input.clone();
    configured.extend(["--attempt-timeout-secs".into(), "3600".into()]);
    assert_eq!(
        options(&configured).unwrap().attempt_timeout,
        Duration::from_secs(3600)
    );
    for flags in [
        vec!["--continuous"],
        vec!["--stop-file", "watch.stop"],
        vec!["--continuous", "--stop-file", ""],
        vec!["--attempt-timeout-secs", "2"],
    ] {
        let mut bad = args();
        bad.extend(flags.into_iter().map(str::to_owned));
        assert!(options(&bad).is_err(), "{bad:?}");
    }
    for flags in [
        vec!["--polls", "1"],
        vec!["--continuous"],
        vec!["--stop-file", "another.stop"],
        vec!["--attempt-timeout-secs", "0"],
        vec!["--attempt-timeout-secs", "3601"],
        vec!["--attempt-timeout-secs", "01"],
        vec!["--attempt-timeout-secs", "1.5"],
        vec!["--attempt-timeout-secs", "2", "--attempt-timeout-secs", "3"],
    ] {
        let mut bad = input.clone();
        bad.extend(flags.into_iter().map(str::to_owned));
        assert!(options(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn idle_operator_stop_is_success_but_never_hides_failed_or_unresolved_work() {
    let mut summary = Summary {
        continuous: true,
        operator_stopped: true,
        stopped: true,
        ..Default::default()
    };
    let mut output = Vec::new();
    assert_eq!(finish(&mut output, &summary, None, None).unwrap(), 0);
    let text = String::from_utf8(output).unwrap();
    assert!(text.contains("\"continuous\":true"));
    assert!(text.contains("\"operator_stopped\":true"));
    summary.reconcile = true;
    assert_eq!(finish(&mut Vec::new(), &summary, None, None).unwrap(), 1);
    summary.reconcile = false;
    summary.non_green = true;
    assert_eq!(finish(&mut Vec::new(), &summary, None, None).unwrap(), 1);
    summary.non_green = false;
    summary.lifetime_expired = true;
    assert_eq!(finish(&mut Vec::new(), &summary, None, None).unwrap(), 1);
    assert_eq!(
        finish(&mut Vec::new(), &summary, Some("stop control lost"), None).unwrap(),
        2
    );
}
#[test]
fn user_supplied_event_and_execution_identity_cannot_override_history() {
    for (flag, value) in [
        ("--run-id", "33".repeat(16)),
        ("--expected-head", format!("alg:2:{}", "aa".repeat(32))),
        ("--expected-commit", "aa".repeat(20)),
        ("--event", "push".into()),
        ("--bundle", "/tmp/bundle".into()),
    ] {
        let mut input = args();
        input.extend([flag.into(), value]);
        assert!(options(&input).is_err(), "{flag}");
    }
    assert!(options(&args()).is_ok());
}
#[test]
fn trust_namespace_count_and_interval_bounds_are_mandatory() {
    let mut input = args();
    input.retain(|a| a != "--trusted-local");
    assert!(options(&input).is_err());
    let mut input = args();
    input[4] = "refs/tags/v1".into();
    assert!(options(&input).is_err());
    for (flag, values) in [
        ("--polls", vec!["0", "10001", "01", "-1", "4294967296"]),
        ("--interval-ms", vec!["0", "9", "60001", "NaN", "1.0"]),
    ] {
        for value in values {
            let mut input = args();
            input.extend([flag.into(), value.into()]);
            assert!(options(&input).is_err(), "{flag} {value}");
        }
    }
    let mut duplicate = args();
    duplicate.extend(["--polls".into(), "2".into(), "--polls".into(), "3".into()]);
    assert!(options(&duplicate).is_err());
}
#[test]
fn flag_looking_values_and_byte_names_are_not_reinterpreted() {
    let mut input = args();
    input[7] = "--polls".into();
    input[9] = "--polls".into();
    let opts = options(&input).unwrap();
    assert_eq!(opts.polls, 1);
    assert_eq!(opts.execution.workflow, b"--polls");
    let mut input = args();
    input[4] = "726566732f68656164732fff".into();
    input.push("--ref-hex".into());
    input[6] = "--workflow-hex".into();
    input[7] = "ff".into();
    input[8] = "--input-hex".into();
    input[9] = "ff".into();
    let opts = options(&input).unwrap();
    assert_eq!(opts.execution.reference.as_bytes(), b"refs/heads/\xff");
    assert_eq!(opts.execution.workflow, b"\xff");
}
#[test]
fn idle_wait_obeys_stop_without_waiting_for_interval() {
    let start = Instant::now();
    assert!(!wait_interval(Duration::from_secs(60), &|| false));
    assert!(start.elapsed() < Duration::from_secs(1));
    let count = std::cell::Cell::new(0);
    assert!(!wait_interval(Duration::from_secs(60), &|| {
        count.set(count.get() + 1);
        count.get() < 3
    }));
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(wait_interval(Duration::from_millis(1), &|| true));
}
#[test]
fn summary_preserves_nonpass_and_both_cleanup_and_operation_errors() {
    for (summary, operation, cleanup, expected) in [
        (Summary::default(), None, None, 0),
        (
            Summary {
                non_green: true,
                ..Default::default()
            },
            None,
            None,
            1,
        ),
        (
            Summary {
                stopped: true,
                ..Default::default()
            },
            None,
            None,
            1,
        ),
        (
            Summary {
                reconcile: true,
                ..Default::default()
            },
            None,
            None,
            1,
        ),
        (
            Summary::default(),
            Some("operation\nerror"),
            Some("close error"),
            2,
        ),
        (Summary::default(), None, Some("close error"), 2),
    ] {
        let mut out = Vec::new();
        assert_eq!(
            finish(&mut out, &summary, operation, cleanup).unwrap(),
            expected
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.ends_with("\n"));
        if operation.is_some() {
            assert!(text.contains("operation\\nerror") || text.contains("operation\\u000aerror"));
        }
        if cleanup.is_some() {
            assert!(text.contains("close error") && text.contains("\"node_closed\":false"));
        }
    }
}
#[test]
fn broken_receipt_output_never_reports_success() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(finish(&mut Broken, &Summary::default(), None, None).is_err());
}

#[test]
fn check_reporting_requires_explicit_opt_in_publisher_and_incarnation_together() {
    let original = args();
    assert!(options(&original).unwrap().publisher.is_none());
    let complete = [
        original.clone(),
        vec![
            "--publish-checks".into(),
            "--principal-id".into(),
            "77".repeat(16),
            "--expected-incarnation".into(),
            "88".repeat(16),
        ],
    ]
    .concat();
    assert!(options(&complete).unwrap().publisher.is_some());
    for flag in [
        "--publish-checks",
        "--principal-id",
        "--expected-incarnation",
    ] {
        let mut bad = complete.clone();
        let index = bad.iter().position(|s| s == flag).unwrap();
        let count = if flag == "--publish-checks" { 1 } else { 2 };
        bad.drain(index..index + count);
        assert!(options(&bad).is_err(), "{flag}");
    }
    for extra in [
        vec!["--publish-checks".into()],
        vec!["--principal-id".into(), "77".repeat(16)],
    ] {
        assert!(options(&[complete.clone(), extra].concat()).is_err());
    }
}
#[test]
fn publisher_is_not_parsed_from_an_option_value_or_workflow_name() {
    let mut input = args();
    input[7] = "ci/--publish-checks".into();
    assert!(options(&input).unwrap().publisher.is_none());
    let mut full = args();
    full.extend([
        "--publish-checks".into(),
        "--principal-id".into(),
        "ZZ".repeat(16),
        "--expected-incarnation".into(),
        "88".repeat(16),
    ]);
    assert!(options(&full).is_err());
}
#[test]
fn publication_decisions_and_incomplete_admission_survive_the_summary() {
    let mut output = Vec::new();
    let summary = Summary {
        publication_enabled: true,
        checks_committed: 3,
        checks_refused: 1,
        non_green: true,
        reconcile: true,
        ..Summary::default()
    };
    assert_eq!(
        finish(
            &mut output,
            &summary,
            Some("saved result requires reconciliation"),
            None
        )
        .unwrap(),
        2
    );
    let text = String::from_utf8(output).unwrap();
    for expected in [
        "\"committed_check_decisions\":3",
        "\"refused_check_decisions\":1",
        "\"requires_reconciliation\":true",
        "\"node_closed\":true",
    ] {
        assert!(text.contains(expected));
    }
}

#[test]
fn pull_request_selector_is_explicit_exact_and_bounded_before_io() {
    assert!(options(&args()).unwrap().pull_request.is_none());
    for valid in ["1", "7", "18446744073709551615"] {
        let input = [args(), vec!["--pull-request".into(), valid.into()]].concat();
        assert_eq!(
            options(&input).unwrap().pull_request,
            Some(valid.parse().unwrap())
        );
    }
    for invalid in [
        "0",
        "01",
        "-1",
        "+1",
        "1.0",
        "18446744073709551616",
        "",
        "7\n",
    ] {
        assert!(
            options(&[args(), vec!["--pull-request".into(), invalid.into()]].concat()).is_err()
        );
    }
    assert!(options(&[args(), vec!["--pull-request".into()]].concat()).is_err());
    assert!(
        options(
            &[
                args(),
                vec![
                    "--pull-request".into(),
                    "7".into(),
                    "--pull-request".into(),
                    "7".into()
                ]
            ]
            .concat()
        )
        .is_err()
    );
}
#[test]
fn pull_request_flag_looking_paths_remain_values_not_trigger_authority() {
    let mut input = args();
    input[7] = "--pull-request".into();
    input[9] = "--pull-request".into();
    let parsed = options(&input).unwrap();
    assert!(parsed.pull_request.is_none());
    assert_eq!(parsed.execution.workflow, b"--pull-request");
    let mut input = args();
    input.extend([
        "--pull-request".into(),
        "7".into(),
        "--event".into(),
        "pull_request".into(),
    ]);
    assert!(options(&input).is_err());
}
#[test]
fn pull_request_reporting_preserves_the_original_explicit_publisher_contract() {
    let mut input = args();
    input.extend([
        "--pull-request".into(),
        "7".into(),
        "--publish-checks".into(),
        "--principal-id".into(),
        "77".repeat(16),
        "--expected-incarnation".into(),
        "88".repeat(16),
    ]);
    let parsed = options(&input).unwrap();
    assert_eq!(parsed.pull_request, Some(7));
    assert!(parsed.publisher.is_some());
    let index = input
        .iter()
        .position(|s| s == "--expected-incarnation")
        .unwrap();
    input.drain(index..index + 2);
    assert!(options(&input).is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn watch_log_only_capture_preserves_poll_options_and_derived_execution_identity() {
    let mut input = args();
    input.extend([
        "--artifact-logs".into(),
        "--polls".into(),
        "3".into(),
        "--artifact-root".into(),
        "/not-opened-watch-logs".into(),
    ]);
    let parsed = options(&input).unwrap();
    assert_eq!(parsed.polls, 3);
    assert!(parsed.execution.head.is_none());
    assert!(parsed.execution.commit.is_none());
    let config = parsed.execution.artifacts.unwrap().node_config().unwrap();
    assert!(config.capture_logs());
    assert!(config.selections().is_empty());
    input.push("--artifact-logs".into());
    assert!(options(&input).is_err());
}
