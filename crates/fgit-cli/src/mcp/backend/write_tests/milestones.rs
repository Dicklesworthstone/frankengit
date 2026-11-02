//! MCP -> native admission -> original terminal outcomes -> cold authority reads.
use super::*;

fn array(value: &Value) -> &[Value] {
    let Value::Array(values) = value else {
        panic!("Expected array: {value:?}")
    };
    values
}

fn call(
    server: &mut Server,
    backend: &mut NodeTools,
    next: &mut u64,
    name: &str,
    args: Value,
) -> Value {
    let id = *next;
    *next += 1;
    invoke(server, backend, id, name, args)
}
fn list(server: &mut Server, backend: &mut NodeTools, next: &mut u64, pin: Option<Value>) -> Value {
    call(
        server,
        backend,
        next,
        "frankengit_milestone_list",
        pin.map_or_else(|| object([]), |head| object([("expected_head", head)])),
    )
}
fn show(server: &mut Server, backend: &mut NodeTools, next: &mut u64, name: &str) -> Value {
    call(
        server,
        backend,
        next,
        name,
        object([("number", text("7")), ("limit", json::number(20))]),
    )
}
fn counts(reply: &Value, open: &str, closed: &str) {
    assert!(!failed(reply), "{reply:?}");
    let row = array(&structured(reply)["milestones"])[0].object().unwrap();
    assert_eq!(row["open_issues"], text(open));
    assert_eq!(row["closed_issues"], text(closed));
}
fn committed(reply: &Value) {
    assert!(!failed(reply), "{reply:?}");
    assert_eq!(structured(reply)["outcome"], text("committed"));
    assert_eq!(structured(reply)["refs_changed"], Value::Bool(false));
}
fn membership(version: &str, milestone_version: &str, key: &str) -> Value {
    command(
        "7",
        version,
        key,
        &[
            ("milestone", text("7")),
            ("expected_milestone_version", text(milestone_version)),
        ],
    )
}

#[test]
fn milestone_dates_membership_history_and_exact_retry_keys_survive_mcp_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        let opening_milestone = command(
            "7",
            "0",
            "milestone-open",
            &[
                ("title", text("Release é")),
                ("body", text("Literal <script>")),
                ("due_at", text("0")),
            ],
        );
        let original = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_milestone_open",
            opening_milestone.clone(),
        );
        committed(&original);
        assert_eq!(structured(&original)["type"], text("milestone_publication"));
        assert_eq!(
            structured(&original)["principal_id"],
            text(PrincipalId::from_bytes([0xa3; 16]).to_string())
        );
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_open",
            opening(),
        ));
        let assignment = membership("1", "1", "set-original");
        let assigned = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_set_milestone",
            assignment.clone(),
        );
        committed(&assigned);
        let before = list(&mut server, &mut backend, &mut next, None);
        counts(&before, "1", "0");
        let pin = structured(&before)["snapshot_token"].clone();
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_milestone_edit",
            command("7", "1", "clear-date", &[("due_at", Value::Null)]),
        ));
        let stale = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_set_milestone",
            membership("2", "1", "stale-milestone"),
        );
        assert!(failed(&stale));
        assert_eq!(structured(&stale)["outcome"], text("refused"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_set_milestone",
            membership("2", "2", "set-repeat"),
        ));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_milestone_close",
            command("7", "2", "close-milestone", &[]),
        ));
        let closed = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_set_milestone",
            membership("3", "3", "closed-milestone"),
        );
        assert!(failed(&closed));
        assert_eq!(structured(&closed)["outcome"], text("refused"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_close",
            command("7", "3", "close-issue", &[]),
        ));
        counts(&list(&mut server, &mut backend, &mut next, None), "0", "1");
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_clear_milestone",
            command("7", "4", "clear-membership", &[]),
        ));
        let historical = list(&mut server, &mut backend, &mut next, Some(pin));
        assert_eq!(structured(&historical), structured(&before));
        let issue = show(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_show",
        );
        let issue_row = structured(&issue)["issue"].object().unwrap();
        assert_eq!(issue_row["version"], text("5"));
        assert_eq!(issue_row["milestone"], Value::Null);
        let actions = array(&structured(&issue)["events"]);
        assert_eq!(
            actions[1].object().unwrap()["action"].object().unwrap()["milestone"],
            text("7")
        );
        assert_eq!(
            actions[2].object().unwrap()["action"].object().unwrap()["expected_milestone_version"],
            text("2")
        );
        assert_eq!(
            actions[4].object().unwrap()["action"].object().unwrap()["name"],
            text("clear-milestone")
        );
        let milestone = show(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_milestone_show",
        );
        let row = structured(&milestone)["milestone"].object().unwrap();
        assert_eq!(row["due_at"], Value::Null);
        assert_eq!(row["state"], text("closed"));
        let events = array(&structured(&milestone)["events"]);
        assert_eq!(
            events[0].object().unwrap()["action"].object().unwrap()["due_at"],
            text("0")
        );
        assert_eq!(
            events[1].object().unwrap()["action"].object().unwrap()["due_at"],
            Value::Null
        );
        assert!(
            !events[2].object().unwrap()["action"]
                .object()
                .unwrap()
                .contains_key("due_at")
        );
        let selected = current_head(&backend);
        backend.close().unwrap();

        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        assert_eq!(
            structured(&show(
                &mut server,
                &mut backend,
                &mut next,
                "frankengit_issue_show"
            )),
            structured(&issue)
        );
        assert_eq!(
            structured(&show(
                &mut server,
                &mut backend,
                &mut next,
                "frankengit_milestone_show"
            )),
            structured(&milestone)
        );
        let retry = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_milestone_open",
            opening_milestone,
        );
        assert_eq!(structured(&retry), structured(&original));
        let retry = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_set_milestone",
            assignment,
        );
        assert_eq!(structured(&retry), structured(&assigned));
        let recovered = recover(&mut server, &mut backend, next, "milestone-open");
        next += 1;
        assert_eq!(
            structured(&recovered)["tx_id"],
            structured(&original)["tx_id"]
        );
        assert_eq!(current_head(&backend), selected);
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_milestone_reopen",
            command("7", "3", "reopen-milestone", &[]),
        ));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_set_milestone",
            membership("5", "4", "assign-closed-issue"),
        ));
        counts(&list(&mut server, &mut backend, &mut next, None), "0", "1");
        assert!(
            backend
                .node
                .runtime()
                .block_on(backend.node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs
                .is_empty()
        );
        backend.close().unwrap();
    }
}

#[test]
fn milestone_tools_preserve_independent_issue_read_write_and_outcome_grants() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut backend = NodeTools::open(fixture.options(false, false, true, 0xa3)).unwrap();
    assert!(
        backend
            .tools()
            .iter()
            .any(|tool| tool.name == "frankengit_milestone_list")
    );
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| !super::super::milestones::is_write(tool.name))
    );
    let mut server = initialized(&mut backend);
    let refused = invoke(
        &mut server,
        &mut backend,
        2,
        "frankengit_milestone_open",
        command(
            "7",
            "0",
            "no-write",
            &[("title", text("Denied")), ("body", text("Denied"))],
        ),
    );
    assert!(refused.object().unwrap().contains_key("error"));
    backend.close().unwrap();
    let mut backend = NodeTools::open(fixture.options(true, false, false, 0xa3)).unwrap();
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| !super::super::milestones::is_read(tool.name))
    );
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| tool.name != outcomes::NAME)
    );
    let mut server = initialized(&mut backend);
    let write = invoke(
        &mut server,
        &mut backend,
        2,
        "frankengit_milestone_open",
        command(
            "7",
            "0",
            "write-only",
            &[("title", text("Allowed")), ("body", text("Literal"))],
        ),
    );
    committed(&write);
    let refused = invoke(
        &mut server,
        &mut backend,
        3,
        "frankengit_milestone_list",
        object([]),
    );
    assert!(refused.object().unwrap().contains_key("error"));
    backend.close().unwrap();
}
