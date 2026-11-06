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
fn agent_profile_rejects_every_operator_only_group_and_keeps_grants_independent() {
    for flag in [
        "--allow-source-writes",
        "--allow-review-writes",
        "--allow-reviewed-merges",
        "--allow-notification-writes",
        "--allow-queues",
        "--allow-queue-writes",
        "--allow-queue-landings",
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
        "--allow-source",
        "--allow-agent-context",
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
        assert_eq!(options.source, flag == "--allow-source");
        assert_eq!(options.agent_context, flag == "--allow-agent-context");
        assert!(options.principal.is_none());
    }
}

#[test]
fn agent_source_and_context_grants_have_independent_closed_tool_inventories() {
    use std::collections::BTreeSet;

    let source_tools = BTreeSet::from([
        "frankengit_source_tree",
        "frankengit_source_blob",
        "frankengit_source_search",
        "frankengit_source_search_batch",
        "frankengit_source_search_index",
        "frankengit_source_symbols",
        "frankengit_ref_list",
        "frankengit_source_initial",
        "frankengit_source_context",
        "frankengit_source_log",
        "frankengit_source_blame",
        "frankengit_source_historical_tree",
        "frankengit_source_historical_blob",
        "frankengit_source_compare",
    ]);
    for (flags, expected) in [
        (vec!["--allow-source"], source_tools.clone()),
        (
            vec!["--allow-agent-context"],
            BTreeSet::from(["frankengit_agent_context"]),
        ),
        (
            vec!["--allow-source", "--allow-agent-context"],
            source_tools
                .iter()
                .copied()
                .chain(["frankengit_agent_context"])
                .collect(),
        ),
    ] {
        let mut input = args();
        input.pop();
        input.extend(flags.iter().map(|flag| (*flag).to_owned()));
        let options = parse_options(&input).unwrap();
        assert_eq!(options.source, flags.contains(&"--allow-source"));
        assert_eq!(
            options.agent_context,
            flags.contains(&"--allow-agent-context")
        );
        assert!(!options.issues && !options.discussions && !options.pulls);
        assert!(!options.writes.any() && !options.outcomes);
        let observed: BTreeSet<_> = backend::tools_for_options(&options)
            .iter()
            .map(|tool| tool.name)
            .collect();
        assert_eq!(observed, expected);

        let mut missing_pin = input.clone();
        missing_pin.drain(5..7);
        assert!(parse_options(&missing_pin).is_err());
        for forbidden in [
            vec!["--principal".into(), "44".repeat(16)],
            vec!["--trusted-local".into()],
            vec!["--allow-source-writes".into()],
            vec!["--allow-review-writes".into()],
        ] {
            let mut widened = input.clone();
            widened.extend(forbidden);
            assert!(parse_options(&widened).is_err());
        }
    }
}
