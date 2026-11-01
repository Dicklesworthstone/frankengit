//! Real protocol dispatch, native admission, historical outcomes and cold reads.
use super::*;

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
fn append(key: &str, body: &str) -> Value {
    object([
        ("number", text("7")),
        ("idempotency_key", text(key)),
        ("body", text(body)),
    ])
}
fn show(server: &mut Server, backend: &mut NodeTools, next: &mut u64) -> Value {
    call(
        server,
        backend,
        next,
        "frankengit_issue_show",
        object([("number", text("7")), ("limit", json::number(20))]),
    )
}
fn assert_issue(reply: &Value, version: &str, locked: bool, comments: &str) {
    assert!(!failed(reply), "{reply:?}");
    let issue = structured(reply)["issue"].object().unwrap();
    assert_eq!(issue["version"], text(version));
    assert_eq!(issue["locked"], Value::Bool(locked));
    assert_eq!(issue["comments"], text(comments));
}
fn assert_refusal(reply: &Value, code: &str) {
    assert!(failed(reply), "{reply:?}");
    assert_eq!(structured(reply)["outcome"], text("refused"));
    assert_eq!(structured(reply)["refusal_code"], text(code));
}

#[test]
fn locked_comments_and_historical_retries_survive_restart_through_mcp() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        assert!(!failed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_open",
            opening()
        )));
        let before_args = append("before-lock", "Accepted before locking");
        let before = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_append_comment",
            before_args.clone(),
        );
        assert!(!failed(&before));
        let lock_args = command("7", "2", "lock-original", &[]);
        let locked = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_lock",
            lock_args.clone(),
        );
        assert!(!failed(&locked));
        assert_eq!(structured(&locked)["action"], text("lock"));
        assert_issue(&show(&mut server, &mut backend, &mut next), "3", true, "1");

        let strict = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_comment",
            command("7", "3", "locked-strict", &[("body", text("Must refuse"))]),
        );
        assert_refusal(&strict, "ProtectedRefTransitionDenied");
        let blocked_args = append("locked-append", "Must stay refused under this key");
        let blocked = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_append_comment",
            blocked_args.clone(),
        );
        assert_refusal(&blocked, "ProtectedRefTransitionDenied");

        for (name, version, key, fields) in [
            ("frankengit_issue_close", "3", "close-locked", vec![]),
            (
                "frankengit_issue_edit",
                "4",
                "edit-locked",
                vec![("title", text("Edited while locked"))],
            ),
            ("frankengit_issue_reopen", "5", "reopen-locked", vec![]),
        ] {
            let result = call(
                &mut server,
                &mut backend,
                &mut next,
                name,
                command("7", version, key, &fields),
            );
            assert!(!failed(&result), "{result:?}");
        }
        let duplicate = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_lock",
            command("7", "6", "lock-again", &[]),
        );
        assert_refusal(&duplicate, "ProtectedRefTransitionDenied");
        let stale = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_unlock",
            command("7", "3", "stale-unlock", &[]),
        );
        assert_refusal(&stale, "EvidenceStale");
        let state = show(&mut server, &mut backend, &mut next);
        assert_issue(&state, "6", true, "1");
        let selected = current_head(&backend);
        backend.close().unwrap();

        let mut backend = NodeTools::open(fixture.options(true, true, true, 0xa3)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        let reopened = show(&mut server, &mut backend, &mut next);
        assert_eq!(structured(&reopened), structured(&state));
        let lock_retry = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_lock",
            lock_args,
        );
        assert_eq!(structured(&lock_retry), structured(&locked));
        let before_retry = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_append_comment",
            before_args,
        );
        assert_eq!(structured(&before_retry), structured(&before));
        assert_eq!(current_head(&backend), selected);

        let unlocked = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_unlock",
            command("7", "6", "unlock-original", &[]),
        );
        assert!(!failed(&unlocked));
        assert_eq!(structured(&unlocked)["action"], text("unlock"));
        let selected = current_head(&backend);
        let blocked_retry = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_append_comment",
            blocked_args,
        );
        assert_eq!(structured(&blocked_retry), structured(&blocked));
        assert_eq!(current_head(&backend), selected);
        let allowed = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_append_comment",
            append("after-unlock", "Accepted after unlocking"),
        );
        assert!(!failed(&allowed));
        let final_state = show(&mut server, &mut backend, &mut next);
        assert_issue(&final_state, "8", false, "2");
        let Value::Array(events) = &structured(&final_state)["events"] else {
            panic!("events");
        };
        let actions: Vec<_> = events
            .iter()
            .map(|event| {
                event.object().unwrap()["action"].object().unwrap()["name"]
                    .text()
                    .unwrap()
            })
            .collect();
        assert_eq!(
            actions,
            [
                "open", "comment", "lock", "close", "edit", "reopen", "unlock", "comment"
            ]
        );
        let listed = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_issue_list",
            object([]),
        );
        let Value::Array(issues) = &structured(&listed)["issues"] else {
            panic!("issues");
        };
        assert_eq!(issues[0].object().unwrap()["locked"], Value::Bool(false));
        backend.close().unwrap();
    }
}
