use super::*;

fn launch() -> Vec<String> {
    [
        "/unused",
        &"11".repeat(16),
        &"22".repeat(16),
        "--trusted-local",
        "--allow-agent-context",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn sponsored_context_requires_its_own_grant_principal_and_incarnation() {
    let mut arguments = launch();
    assert!(parse_options(&arguments).is_err());
    arguments.extend(["--principal".into(), "33".repeat(16)]);
    assert!(parse_options(&arguments).is_err());
    arguments.extend(["--expected-incarnation".into(), "44".repeat(16)]);
    let options = parse_options(&arguments).unwrap();
    assert!(options.agent_context);
    assert!(!options.source && !options.issues && !options.pulls && !options.artifacts);
    assert!(!options.writes.any() && !options.outcomes);
    let tools = backend::tools_for_options(&options);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "frankengit_agent_context");

    for missing in ["--trusted-local", "--allow-agent-context"] {
        let mut forbidden = arguments.clone();
        forbidden.retain(|argument| argument != missing);
        assert!(parse_options(&forbidden).is_err(), "{missing}");
    }
    let mut without_context = arguments;
    without_context.retain(|argument| argument != "--allow-agent-context");
    without_context.push("--allow-source".into());
    // A source grant does not make a launch principal meaningful on its own.
    assert!(parse_options(&without_context).is_err());
    without_context.push("--allow-outcomes".into());
    let read_and_recovery = parse_options(&without_context).unwrap();
    assert!(!read_and_recovery.agent_context);
    assert!(
        backend::tools_for_options(&read_and_recovery)
            .iter()
            .all(|tool| tool.name != "frankengit_agent_context")
    );
}

#[test]
fn declared_agent_context_inputs_match_the_served_schema() {
    let mut arguments = launch();
    arguments.extend([
        "--principal".into(),
        "33".repeat(16),
        "--expected-incarnation".into(),
        "44".repeat(16),
    ]);
    let tools = backend::tools_for_options(&parse_options(&arguments).unwrap());
    let contract = fgit_schema::mcp::find_tool(tools[0].name).unwrap();
    let declared: std::collections::BTreeSet<_> = contract
        .input_fields
        .iter()
        .map(|field| field.name)
        .collect();
    let properties = tools[0].schema.object().unwrap()["properties"]
        .object()
        .unwrap();
    let served: std::collections::BTreeSet<_> = properties.keys().map(String::as_str).collect();
    assert_eq!(served, declared);
    assert_eq!(
        contract.principal,
        fgit_schema::mcp::PrincipalRequirement::OperatorBound
    );
    assert_eq!(
        contract.capability,
        fgit_schema::mcp::CapabilityRequirement::READ_AGENT_CONTEXT
    );
}
