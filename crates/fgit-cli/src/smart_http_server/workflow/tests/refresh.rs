use super::*;

fn refresh_arguments() -> Vec<String> {
    let mut arguments = landing_arguments();
    arguments.extend([
        "--workflow-refresh-queue-head".into(),
        "--workflow-refresh-principal".into(),
        "77".repeat(16),
    ]);
    arguments
}

#[test]
fn refresh_service_grant_is_separate_from_landing_checks_and_http_endpoints() {
    for arguments in [server_arguments(), merge_arguments(), queue_arguments(), landing_arguments()] {
        assert!(parse_server(&arguments).unwrap().workflow_service.unwrap()
            .queue_refresh_principal().is_none());
    }
    let mut endpoints = landing_arguments();
    endpoints.extend([
        "--allow-pulls".into(), "--allow-queues".into(), "--allow-queue-landings".into(),
    ]);
    assert!(parse_server(&endpoints).unwrap().workflow_service.unwrap()
        .queue_refresh_principal().is_none());
    let options = parse_server(&refresh_arguments()).unwrap();
    assert!(!options.allow_queue_landings);
    assert!(!options.allow_queues);
    assert!(!options.allow_pulls);
    assert!(!options.allow_receive);
    assert!(!options.allow_source);
    let config = options.workflow_service.unwrap();
    assert_eq!(config.merge_queue(), Some(7));
    assert_eq!(config.queue_refresh_principal(), Some(PrincipalId::from_bytes([0x77; 16])));
    assert_eq!(config.landing_principal(), Some(PrincipalId::from_bytes([0x66; 16])));
    assert_eq!(config.publisher(), Some(PrincipalId::from_bytes([0x55; 16])));
    assert_eq!(config.merge_candidate().unwrap().principal(), PrincipalId::from_bytes([0x33; 16]));
    assert!(config.validate().is_ok());

    let mut same = refresh_arguments();
    let at = same.iter().position(|value| value == "--workflow-refresh-principal").unwrap();
    same[at + 1] = "66".repeat(16);
    let config = parse_server(&same).unwrap().workflow_service.unwrap();
    assert_eq!(config.queue_refresh_principal(), config.landing_principal());
}

#[test]
fn refresh_service_requires_the_full_paired_operator_configuration_before_io() {
    for (flag, width) in [
        ("--workflow-refresh-queue-head", 1), ("--workflow-refresh-principal", 2),
        ("--workflow-land-queue-head", 1), ("--workflow-landing-principal", 2),
        ("--workflow-publish-checks", 1), ("--workflow-principal", 2),
        ("--expected-incarnation", 2), ("--workflow-merge-queue", 2),
        ("--workflow-merge-candidate-ref", 2), ("--workflow-merge-principal", 2),
        ("--workflow-merge-author", 2), ("--workflow-merge-committer", 2),
        ("--workflow-merge-timestamp", 2), ("--workflow-merge-message", 2),
        ("--workflow-trusted-local", 1), ("--credentials-file", 2),
        ("--continuous", 1), ("--stop-file", 2),
    ] {
        let mut arguments = refresh_arguments();
        let at = arguments.iter().position(|value| value == flag).unwrap();
        arguments.drain(at..at + width);
        assert!(parse_server(&arguments).is_err(), "{flag}");
    }
    let mut no_landing = refresh_arguments();
    for (flag, width) in [
        ("--workflow-land-queue-head", 1), ("--workflow-landing-principal", 2),
    ] {
        let at = no_landing.iter().position(|value| value == flag).unwrap();
        no_landing.drain(at..at + width);
    }
    assert!(parse_server(&no_landing).is_err());
    for extra in [
        vec!["--workflow-refresh-queue-head"],
        vec!["--workflow-refresh-principal", "77777777777777777777777777777777"],
        vec!["--workflow-refresh-principal"],
        vec!["--workflow-pull-request", "7"],
        vec!["--workflow-pull-requests"],
        vec!["--workflow-merge-method", "squash"],
    ] {
        let mut arguments = refresh_arguments();
        arguments.extend(extra.into_iter().map(str::to_owned));
        assert!(parse_server(&arguments).is_err(), "{arguments:?}");
    }
    for invalid in ["", "77", "not-a-principal", "--workflow-publish-checks", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        let mut arguments = refresh_arguments();
        let at = arguments.iter().position(|value| value == "--workflow-refresh-principal").unwrap();
        arguments[at + 1] = invalid.into();
        assert!(parse_server(&arguments).is_err(), "{invalid:?}");
    }
    let mut pr = refresh_arguments();
    let at = pr.iter().position(|value| value == "--workflow-merge-queue").unwrap();
    pr[at] = "--workflow-pull-request".into();
    assert!(parse_server(&pr).is_err());
    let mut tag = refresh_arguments();
    let at = tag.iter().position(|value| value == "--workflow-ref").unwrap();
    tag[at + 1] = "refs/tags/v1".into();
    assert!(parse_server(&tag).is_err());
}

#[test]
fn refresh_switches_in_literal_merge_metadata_grant_no_metadata_authority() {
    for literal in ["--workflow-refresh-queue-head", "--workflow-refresh-principal"] {
        let mut arguments = landing_arguments();
        let at = arguments.iter().position(|value| value == "--workflow-merge-message").unwrap();
        arguments[at + 1] = literal.into();
        let config = parse_server(&arguments).unwrap().workflow_service.unwrap();
        assert!(config.queue_refresh_principal().is_none());
        assert_eq!(config.merge_candidate().unwrap().metadata().message, literal.as_bytes());
    }
}
