//! The HTTP parser must make collection authority and bounds explicit before I/O.

use super::*;

fn collection_arguments() -> Vec<String> {
    let mut arguments = server_arguments();
    arguments.extend([
        "--expected-incarnation".into(),
        "44".repeat(16),
        "--workflow-pull-requests".into(),
    ]);
    arguments
}

#[test]
fn collection_selects_a_fixed_target_without_enabling_network_or_check_writes() {
    let options = parse_server(&collection_arguments()).unwrap();
    assert!(matches!(
        options.credentials,
        CredentialInput::Reloadable(_)
    ));
    assert!(!options.allow_receive);
    assert!(!options.allow_pulls);
    assert!(!options.allow_source);
    assert!(!options.allow_outcomes);
    assert!(!options.allow_protection);
    assert!(!options.allow_queues);
    assert!(!options.allow_queue_landings);
    let config = options.workflow_service.unwrap();
    assert_eq!(config.pull_requests(), Some(64));
    assert_eq!(config.reference().as_bytes(), b"refs/heads/main");
    assert_eq!(config.format(), GitHashAlgorithm::Sha256);
    assert_eq!(config.inputs(), &[b"ci".to_vec()]);
    assert_eq!(config.interval(), Duration::from_secs(1));
    assert_eq!(config.attempt_timeout(), Duration::from_secs(300));
    assert!(config.pull_request().is_none());
    assert!(config.merge_queue().is_none());
    assert!(config.merge_candidate().is_none());
    assert!(config.publisher().is_none());
}

#[test]
fn collection_capacity_and_attempt_budget_are_explicit_and_bounded() {
    for capacity in ["1", "17", "64"] {
        let mut arguments = collection_arguments();
        arguments.extend([
            "--workflow-max-pull-requests".into(),
            capacity.into(),
            "--workflow-interval-ms".into(),
            "10".into(),
            "--workflow-attempt-timeout-secs".into(),
            "30".into(),
        ]);
        let config = parse_server(&arguments).unwrap().workflow_service.unwrap();
        assert_eq!(config.pull_requests(), Some(capacity.parse().unwrap()));
        assert_eq!(config.interval(), Duration::from_millis(10));
        assert_eq!(config.attempt_timeout(), Duration::from_secs(30));
    }
    for invalid in [
        "0",
        "65",
        "01",
        "-1",
        "+1",
        "1.0",
        "18446744073709551616",
        "",
    ] {
        let mut arguments = collection_arguments();
        arguments.extend(["--workflow-max-pull-requests".into(), invalid.into()]);
        assert!(parse_server(&arguments).is_err(), "{invalid:?}");
    }
}

#[test]
fn collection_requires_incarnation_and_separate_execution_trust_without_a_publisher() {
    for missing in [
        "--expected-incarnation",
        "--workflow-trusted-local",
        "--credentials-file",
        "--continuous",
        "--stop-file",
    ] {
        let mut arguments = collection_arguments();
        let at = arguments.iter().position(|value| value == missing).unwrap();
        let count = if matches!(missing, "--workflow-trusted-local" | "--continuous") {
            1
        } else {
            2
        };
        arguments.drain(at..at + count);
        assert!(parse_server(&arguments).is_err(), "{missing}");
    }
    let mut arguments = collection_arguments();
    let at = arguments
        .iter()
        .position(|value| value == "--expected-incarnation")
        .unwrap();
    arguments[at + 1] = "invalid-incarnation".into();
    assert!(parse_server(&arguments).is_err());
}

#[test]
fn capacity_alone_does_not_enable_discovery_and_duplicate_selectors_refuse() {
    let mut arguments = server_arguments();
    arguments.extend(["--workflow-max-pull-requests".into(), "4".into()]);
    assert!(
        parse_server(&arguments)
            .err()
            .unwrap()
            .contains("requires --workflow-pull-requests")
    );
    for extra in [
        vec!["--workflow-pull-requests"],
        vec!["--workflow-pull-request", "7"],
        vec!["--workflow-merge-queue", "7"],
    ] {
        let mut arguments = collection_arguments();
        arguments.extend(extra.into_iter().map(str::to_owned));
        assert!(parse_server(&arguments).is_err());
    }
    let mut arguments = collection_arguments();
    arguments.extend(
        [
            "--workflow-max-pull-requests",
            "2",
            "--workflow-max-pull-requests",
            "3",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    assert!(parse_server(&arguments).is_err());
}

#[test]
fn collection_refuses_even_a_partial_merge_candidate_contract() {
    for (name, value) in [
        ("--workflow-merge-candidate-ref", "refs/heads/ci/prs"),
        (
            "--workflow-merge-candidate-ref-hex",
            "726566732f68656164732f6369",
        ),
        (
            "--workflow-merge-principal",
            "33333333333333333333333333333333",
        ),
        ("--workflow-merge-author", "CI <ci@example.test>"),
        ("--workflow-merge-committer", "CI <ci@example.test>"),
        ("--workflow-merge-timestamp", "1700000000"),
        ("--workflow-merge-message", "Check all PRs"),
        ("--workflow-merge-profile", "path"),
        ("--workflow-merge-method", "merge-commit"),
    ] {
        let mut arguments = collection_arguments();
        arguments.extend([name.into(), value.into()]);
        assert!(
            parse_server(&arguments)
                .err()
                .unwrap()
                .contains("selects source heads"),
            "{name}"
        );
    }
}

#[test]
fn collection_uses_existing_explicit_check_and_artifact_contracts() {
    let mut arguments = collection_arguments();
    arguments.extend(
        [
            "--workflow-publish-checks",
            "--workflow-principal",
            "55555555555555555555555555555555",
            "--artifact-root",
            "/private/artifacts",
            "--workflow-artifact-logs",
            "--workflow-artifact",
            "ci/build.yml:build:package.bin",
            "--workflow-artifact-input",
            "ci/build.yml:test:build:package.bin:package.bin",
            "--allow-outcomes",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    let options = parse_server(&arguments).unwrap();
    assert!(options.allow_outcomes);
    assert!(!options.allow_receive);
    assert!(!options.allow_pulls);
    let config = options.workflow_service.unwrap();
    assert_eq!(config.pull_requests(), Some(64));
    assert_eq!(
        config.publisher(),
        Some(PrincipalId::from_hex(&"55".repeat(16)).unwrap())
    );
    assert!(config.artifacts().is_some());
}
