use super::*;

fn args(values: impl IntoIterator<Item = (&'static str, Value)>) -> Object {
    values
        .into_iter()
        .map(|(key, value)| (key.into(), value))
        .collect()
}

#[test]
fn issue_search_preserves_exact_filters_and_lossless_candidate_cursors() {
    let assignee = PrincipalId::from_bytes([3; 16]);
    let opener = PrincipalId::from_bytes([4; 16]);
    let (query, request) = parse(&args([
        ("query", text("[a].*é")),
        ("state", text("closed")),
        ("opened_by", text(opener.to_string())),
        ("assignee", text(assignee.to_string())),
        ("labels", Value::Array(vec![text("z"), text("a")])),
        ("milestone", text(u64::MAX.to_string())),
        ("case_sensitive", Value::Bool(true)),
        ("limit", json::number(2)),
        ("max_scan", json::number(3)),
    ]))
    .unwrap();
    assert_eq!(query.query().text.as_deref(), Some("[a].*é"));
    assert_eq!(query.query().state, Some(IssueState::Closed));
    assert_eq!(query.query().opened_by, Some(opener));
    assert_eq!(
        query.query().assignee,
        Some(AssigneeFilter::Principal(assignee))
    );
    assert_eq!(query.query().labels, ["a", "z"]);
    assert_eq!(
        query.query().milestone,
        Some(MilestoneFilter::Number(
            MilestoneNumber::try_new(u64::MAX).unwrap()
        ))
    );
    assert!(query.query().case_sensitive);
    assert_eq!((request.limit, request.max_scan), (2, 3));
    let token = format!("alg:1:{}", "ab".repeat(32));
    let (query, request) = parse(&args([
        ("assignee", text("none")),
        ("milestone", text("none")),
        ("after", text(u64::MAX.to_string())),
        ("expected_head", text(token)),
    ]))
    .unwrap();
    assert_eq!(request.after, u64::MAX);
    assert_eq!(query.query().assignee, Some(AssigneeFilter::Unassigned));
    assert_eq!(query.query().milestone, Some(MilestoneFilter::Unassigned));
    let (query, request) = parse(&Object::new()).unwrap();
    assert_eq!(query.query(), &IssueQuery::default());
    assert_eq!((request.limit, request.max_scan), (5, 1000));
}

#[test]
fn issue_search_refuses_authority_fields_ambiguous_filters_and_unbounded_work() {
    for values in [
        vec![("principal", text("admin"))],
        vec![("idempotency_key", text("write"))],
        vec![("expected_version", text("1"))],
        vec![("tenant", text("other"))],
        vec![("repository", text("other"))],
        vec![("case_sensitive", Value::Bool(true))],
        vec![("case_sensitive", text("false"))],
        vec![("query", Value::Null)],
        vec![("query", text(""))],
        vec![("query", text("a\0b"))],
        vec![("after", json::number(1))],
        vec![("after", text("1"))],
        vec![("after", text("01"))],
        vec![("max_scan", json::number(0))],
        vec![("max_scan", json::number(1001))],
        vec![("max_scan", text("5"))],
        vec![("limit", json::number(21))],
        vec![("state", text("merged"))],
        vec![("opened_by", text("bad"))],
        vec![("assignee", text("all"))],
        vec![("assignee", text(""))],
        vec![("assignee", Value::Null)],
        vec![("milestone", text("0"))],
        vec![("milestone", text("01"))],
        vec![("milestone", json::number(7))],
        vec![("labels", text("bug"))],
        vec![("labels", Value::Array(vec![text("bug"), text("bug")]))],
        vec![("labels", Value::Array(vec![text(" ")]))],
        vec![("labels", Value::Array(vec![json::number(1)]))],
        vec![("labels", Value::Array(vec![text("a\nb")]))],
    ] {
        assert!(parse(&args(values.clone())).is_err(), "{values:?}");
    }
    assert!(parse(&args([("query", text("é".repeat(129)))])).is_err());
    assert!(
        parse(&args([(
            "labels",
            Value::Array(vec![text("é".repeat(33))])
        )]))
        .is_err()
    );
    assert!(
        parse(&args([(
            "labels",
            Value::Array((0..33).map(|n| text(format!("label-{n}"))).collect())
        )]))
        .is_err()
    );
}

#[test]
fn issue_search_discovery_and_registry_declare_the_same_bounded_read() {
    let tool = tool();
    let entry = fgit_schema::mcp::find_tool(tool.name).unwrap();
    let schema = tool.schema.object().unwrap();
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    let properties = schema["properties"].object().unwrap();
    let served: std::collections::BTreeSet<_> = properties.keys().map(String::as_str).collect();
    let declared: std::collections::BTreeSet<_> =
        entry.input_fields.iter().map(|field| field.name).collect();
    assert_eq!(served, declared);
    assert_eq!(
        properties["max_scan"].object().unwrap()["maximum"],
        json::number(1000)
    );
    assert_eq!(
        properties["limit"].object().unwrap()["maximum"],
        json::number(20)
    );
    assert_eq!(
        properties["labels"].object().unwrap()["uniqueItems"],
        Value::Bool(true)
    );
    assert!(!properties.contains_key("principal"));
    assert!(!properties.contains_key("idempotency_key"));
    assert_eq!(
        entry.read_mutation,
        fgit_schema::mcp::ReadMutationClass::ReadOnly
    );
    assert_eq!(
        entry.capability,
        fgit_schema::mcp::find_tool("frankengit_issue_list")
            .unwrap()
            .capability
    );
}
