//! Actual MCP dispatch, native publication, retained reads and cold recovery.
use super::*;

mod append;

const NUMBER: &str = "9007199254740993";

fn options(fixture: &Fixture, reads: bool, writes: bool, outcomes: bool) -> Options {
    let mut options = fixture.options(false, outcomes, false, 0xa3);
    options.discussions = reads;
    options.writes.discussions = writes;
    options.principal = (writes || outcomes).then_some(PrincipalId::from_bytes([0xa3; 16]));
    options
}
fn array(value: &Value) -> &[Value] {
    let Value::Array(values) = value else {
        panic!("expected array: {value:?}")
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
fn committed(reply: &Value) {
    assert!(!failed(reply), "{reply:?}");
    assert_eq!(structured(reply)["outcome"], text("committed"));
    assert_eq!(structured(reply)["refs_changed"], Value::Bool(false));
}
fn read(server: &mut Server, backend: &mut NodeTools, next: &mut u64) -> Value {
    call(
        server,
        backend,
        next,
        "frankengit_discussion_show",
        object([
            ("number", text(NUMBER)),
            ("limit", json::number(20)),
            ("render", text("html_safe")),
        ]),
    )
}
fn opening_discussion() -> Value {
    command(
        NUMBER,
        "0",
        "discussion-open",
        &[
            ("title", text("Independent design é")),
            (
                "body",
                text("Literal <script>hostile()</script>\r\n**document**"),
            ),
        ],
    )
}

#[test]
fn discussion_lifecycle_locking_pinned_history_and_exact_retries_survive_mcp_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(options(&fixture, true, true, true)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        let opened = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_open",
            opening_discussion(),
        );
        committed(&opened);
        assert_eq!(structured(&opened)["type"], text("discussion_publication"));
        assert_eq!(structured(&opened)["number"], text(NUMBER));
        assert_eq!(structured(&opened)["expected_version"], text("0"));
        assert_eq!(
            structured(&opened)["principal_id"],
            text(PrincipalId::from_bytes([0xa3; 16]).to_string())
        );
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_comment",
            command(
                NUMBER,
                "1",
                "discussion-comment",
                &[("body", text("Exact é\r\nreply"))],
            ),
        ));
        let before = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_show",
            object([("number", text(NUMBER)), ("limit", json::number(1))]),
        );
        assert!(!failed(&before));
        assert_eq!(structured(&before)["next_after_version"], text("1"));
        let pin = structured(&before)["snapshot_token"].clone();
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_lock",
            command(NUMBER, "2", "discussion-lock", &[]),
        ));
        let locked_command = command(
            NUMBER,
            "3",
            "locked-comment",
            &[("body", text("Must remain refused"))],
        );
        let locked = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_comment",
            locked_command.clone(),
        );
        assert!(failed(&locked));
        assert_eq!(structured(&locked)["outcome"], text("refused"));
        for (name, version, key, fields) in [
            (
                "frankengit_discussion_edit",
                "3",
                "rename-discussion",
                vec![("title", text("Renamed"))],
            ),
            (
                "frankengit_discussion_close",
                "4",
                "close-discussion",
                vec![],
            ),
            (
                "frankengit_discussion_unlock",
                "5",
                "unlock-discussion",
                vec![],
            ),
            (
                "frankengit_discussion_comment",
                "6",
                "closed-comment",
                vec![("body", text("Closed discussions still accept replies"))],
            ),
            (
                "frankengit_discussion_reopen",
                "7",
                "reopen-discussion",
                vec![],
            ),
        ] {
            committed(&call(
                &mut server,
                &mut backend,
                &mut next,
                name,
                command(NUMBER, version, key, &fields),
            ));
        }
        let stale = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_edit",
            command(
                NUMBER,
                "2",
                "stale-discussion",
                &[("title", text("Must not overwrite"))],
            ),
        );
        assert!(failed(&stale));
        assert_eq!(structured(&stale)["outcome"], text("refused"));
        let historical = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_show",
            object([
                ("number", text(NUMBER)),
                ("after_version", text("1")),
                ("limit", json::number(1)),
                ("expected_head", pin),
            ]),
        );
        assert!(!failed(&historical));
        let old_row = structured(&historical)["discussion"].object().unwrap();
        assert_eq!(old_row["version"], text("2"));
        assert_eq!(old_row["title"], text("Independent design é"));
        assert_eq!(old_row["comments"], text("1"));
        assert_eq!(structured(&historical)["next_after_version"], Value::Null);
        let old_events = array(&structured(&historical)["events"]);
        assert_eq!(old_events.len(), 1);
        assert_eq!(
            old_events[0].object().unwrap()["action"].object().unwrap()["body"],
            text("Exact é\r\nreply")
        );
        let unpinned = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_show",
            object([("number", text(NUMBER)), ("after_version", text("1"))]),
        );
        assert!(unpinned.object().unwrap().contains_key("error"));
        let shown = read(&mut server, &mut backend, &mut next);
        assert!(!failed(&shown), "{shown:?}");
        let row = structured(&shown)["discussion"].object().unwrap();
        assert_eq!(row["number"], text(NUMBER));
        assert_eq!(row["version"], text("8"));
        assert_eq!(row["comments"], text("2"));
        assert_eq!(row["state"], text("open"));
        assert_eq!(row["locked"], Value::Bool(false));
        assert_eq!(row["title"], text("Renamed"));
        assert_eq!(
            row["body"],
            text("Literal <script>hostile()</script>\r\n**document**")
        );
        let rendered = row["body_rendered"].object().unwrap();
        assert!(!rendered["html"].text().unwrap().contains("<script>"));
        let events = array(&structured(&shown)["events"]);
        assert_eq!(events.len(), 8);
        for (event, name) in events.iter().zip([
            "open", "comment", "lock", "edit", "close", "unlock", "comment", "reopen",
        ]) {
            let event = event.object().unwrap();
            assert_eq!(
                event["actor"],
                text(PrincipalId::from_bytes([0xa3; 16]).to_string())
            );
            assert_eq!(event["action"].object().unwrap()["name"], text(name));
        }
        let selected = current_head(&backend);
        backend.close().unwrap();

        let mut backend = NodeTools::open(options(&fixture, true, true, true)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        assert_eq!(
            structured(&read(&mut server, &mut backend, &mut next)),
            structured(&shown)
        );
        let retried = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_open",
            opening_discussion(),
        );
        assert_eq!(structured(&retried), structured(&opened));
        let refused_again = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_comment",
            locked_command,
        );
        assert_eq!(structured(&refused_again), structured(&locked));
        let recovered = recover(&mut server, &mut backend, next, "discussion-open");
        assert_eq!(
            structured(&recovered)["tx_id"],
            structured(&opened)["tx_id"]
        );
        assert_eq!(current_head(&backend), selected);
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
fn discussion_read_write_and_issue_grants_are_independent_in_native_dispatch() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| !tool.name.starts_with("frankengit_discussion_"))
    );
    let mut server = initialized(&mut backend);
    let denied = invoke(
        &mut server,
        &mut backend,
        2,
        "frankengit_discussion_open",
        opening_discussion(),
    );
    assert!(denied.object().unwrap().contains_key("error"));
    backend.close().unwrap();

    let mut backend = NodeTools::open(options(&fixture, true, false, false)).unwrap();
    assert_eq!(backend.tools().len(), 2);
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| super::super::discussions::is_read(tool.name))
    );
    let mut server = initialized(&mut backend);
    let empty = invoke(
        &mut server,
        &mut backend,
        2,
        "frankengit_discussion_list",
        object([]),
    );
    assert!(!failed(&empty));
    assert!(array(&structured(&empty)["discussions"]).is_empty());
    let denied = invoke(
        &mut server,
        &mut backend,
        3,
        "frankengit_discussion_open",
        opening_discussion(),
    );
    assert!(denied.object().unwrap().contains_key("error"));
    backend.close().unwrap();

    let mut backend = NodeTools::open(options(&fixture, false, true, false)).unwrap();
    assert_eq!(backend.tools().len(), 8);
    assert!(
        backend
            .tools()
            .iter()
            .all(|tool| super::super::discussions::is_write(tool.name))
    );
    let mut server = initialized(&mut backend);
    committed(&invoke(
        &mut server,
        &mut backend,
        2,
        "frankengit_discussion_open",
        opening_discussion(),
    ));
    for (id, name, args) in [
        (3, "frankengit_discussion_list", object([])),
        (4, "frankengit_issue_list", object([])),
        (
            5,
            outcomes::NAME,
            object([("idempotency_key", text("discussion-open"))]),
        ),
    ] {
        let denied = invoke(&mut server, &mut backend, id, name, args);
        assert!(denied.object().unwrap().contains_key("error"));
    }
    backend.close().unwrap();
}
