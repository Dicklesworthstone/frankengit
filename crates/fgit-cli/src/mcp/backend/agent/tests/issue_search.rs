//! Search shares the existing current canonical issue-read grant, not a filter.
use super::*;

const SEARCH: &str = "frankengit_issue_search";

#[test]
fn sponsored_issue_search_rechecks_read_scope_launch_ceiling_and_revocation() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut admin = NodeTools::open(fixture.options.clone()).unwrap();
    committed(
        &admin
            .call("frankengit_issue_open", &opening(7, "search-subject"))
            .unwrap(),
    );
    let reader_id = issue(
        &admin.node,
        &token(0x81),
        grant(&admin.node, ISSUES_READ),
        "search-reader",
    );
    issue(
        &admin.node,
        &token(0x82),
        grant(&admin.node, ISSUES_WRITE),
        "search-writer",
    );
    issue(
        &admin.node,
        &token(0x83),
        grant(&admin.node, PULLS_READ),
        "search-pull-reader",
    );
    admin.close().unwrap();

    let mut query = object([
        ("opened_by", text(AGENT.to_string())),
        ("assignee", text("none")),
    ])
    .object()
    .unwrap()
    .clone();
    let reader_options = fixture.replacement(0x81);
    let mut reader = NodeTools::open(reader_options.clone()).unwrap();
    assert!(reader.tools().iter().any(|tool| tool.name == SEARCH));
    let page = reader.call(SEARCH, &query).unwrap();
    let fields = page.object().unwrap();
    assert_eq!(fields["count"], super::super::super::json::number(1));
    assert_eq!(fields["read_only"], Value::Bool(true));
    assert_eq!(fields["complete"], Value::Bool(true));
    assert!(!page.encode(MAX_RESPONSE).unwrap().contains(&token(0x81)));
    assert_eq!(
        reader
            .call("frankengit_issue_open", &opening(8, "search-cannot-write"))
            .unwrap_err()
            .code,
        "agent_operation_not_granted"
    );
    assert!(reader.agent.as_ref().unwrap().request.is_none());
    reader.close().unwrap();

    let mut writer = NodeTools::open(fixture.replacement(0x82)).unwrap();
    // Authorship, assignment filters and the issue-write scope cannot confer
    // the independent read capability, even at a retained authority snapshot.
    query.insert("expected_head".into(), fields["snapshot_token"].clone());
    assert_eq!(
        writer.call(SEARCH, &query).unwrap_err().code,
        "agent_operation_not_granted"
    );
    writer.close().unwrap();
    let mut pull_reader = NodeTools::open(fixture.replacement(0x83)).unwrap();
    assert_eq!(
        pull_reader.call(SEARCH, &query).unwrap_err().code,
        "agent_operation_not_granted"
    );
    pull_reader.close().unwrap();

    let mut narrow = reader_options.clone();
    narrow.issues = false;
    let mut backend = NodeTools::open(narrow).unwrap();
    assert!(!backend.tools().iter().any(|tool| tool.name == SEARCH));
    assert_eq!(
        backend.call(SEARCH, &query).unwrap_err().code,
        "tool_not_granted"
    );
    backend.close().unwrap();

    let mut reader = NodeTools::open(reader_options).unwrap();
    assert!(reader.call(SEARCH, &query).is_ok());
    revoke(&reader.node, reader_id, "revoke-search-reader");
    assert!(
        reader.call(SEARCH, &query).is_err(),
        "a retained head cannot revive revoked disclosure authority"
    );
    assert!(reader.agent.as_ref().unwrap().request.is_none());
    reader.close().unwrap();
}
