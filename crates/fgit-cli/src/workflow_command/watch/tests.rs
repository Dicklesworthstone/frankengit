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
#[test]
fn defaults_and_finite_polling_options_parse_without_io() {
    let opts = options(&args()).unwrap();
    assert_eq!(opts.polls, 1);
    assert_eq!(opts.interval, Duration::from_secs(1));
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
