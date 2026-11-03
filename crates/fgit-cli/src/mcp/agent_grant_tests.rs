use super::*;

fn args() -> Vec<String> {
    vec![
        "/unused".into(),
        "11".repeat(16),
        "22".repeat(16),
        "--agent-token-file".into(),
        "/private/agent.token".into(),
        "--expected-incarnation".into(),
        "33".repeat(16),
        "--allow-issues".into(),
    ]
}

#[test]
fn agent_profile_requires_its_own_credential_and_incarnation_without_operator_identity() {
    let options = parse_options(&args()).unwrap();
    assert!(options.principal.is_none());
    assert_eq!(
        options.agent_token_file,
        Some("/private/agent.token".into())
    );
    for extra in [
        vec!["--trusted-local".into()],
        vec!["--principal".into(), "44".repeat(16)],
        vec!["--agent-token-file".into(), "/private/other.token".into()],
    ] {
        let mut input = args();
        input.extend(extra);
        assert!(parse_options(&input).is_err());
    }
    let mut missing_incarnation = args();
    missing_incarnation.drain(5..7);
    assert!(parse_options(&missing_incarnation).is_err());
    let mut empty_file = args();
    empty_file[4].clear();
    assert!(parse_options(&empty_file).is_err());
    let mut no_grant = args();
    no_grant.pop();
    assert!(parse_options(&no_grant).is_err());
}

#[test]
fn agent_profile_rejects_every_operator_only_group_and_keeps_metadata_grants_independent() {
    for flag in [
        "--allow-source",
        "--allow-source-writes",
        "--allow-review-writes",
        "--allow-reviewed-merges",
        "--allow-notification-writes",
        "--allow-queues",
        "--allow-queue-writes",
        "--allow-queue-landings",
        "--allow-agent-context",
        "--allow-artifacts",
    ] {
        let mut input = args();
        input.push(flag.into());
        assert!(parse_options(&input).is_err(), "{flag}");
    }
    for flag in [
        "--allow-issues",
        "--allow-issue-writes",
        "--allow-discussions",
        "--allow-discussion-writes",
        "--allow-pulls",
        "--allow-pull-writes",
        "--allow-outcomes",
    ] {
        let mut input = args();
        *input.last_mut().unwrap() = flag.into();
        let options = parse_options(&input).unwrap();
        assert_eq!(options.issues, flag == "--allow-issues");
        assert_eq!(options.discussions, flag == "--allow-discussions");
        assert_eq!(options.pulls, flag == "--allow-pulls");
        assert_eq!(options.writes.issues, flag == "--allow-issue-writes");
        assert_eq!(
            options.writes.discussions,
            flag == "--allow-discussion-writes"
        );
        assert_eq!(options.writes.pulls, flag == "--allow-pull-writes");
        assert_eq!(options.outcomes, flag == "--allow-outcomes");
        assert!(options.principal.is_none());
    }
}
