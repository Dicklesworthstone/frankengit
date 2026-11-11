//! Version-independent publication through actual MCP grants and native storage.
use super::*;

const APPEND: &str = "frankengit_discussion_append_comment";

fn append_args(key: &str, body: &str) -> Value {
    object([
        ("number", text(NUMBER)),
        ("idempotency_key", text(key)),
        ("body", text(body)),
    ])
}

#[test]
fn discussion_append_preserves_intervening_edits_and_recovers_original_results_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(options(&fixture, true, true, true)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_open",
            opening_discussion(),
        ));
        let original = append_args("append-original", "Exact é\r\n<script>untrusted</script>");
        let first = call(
            &mut server,
            &mut backend,
            &mut next,
            APPEND,
            original.clone(),
        );
        committed(&first);
        assert_eq!(structured(&first)["action"], text("append-comment"));
        assert_eq!(structured(&first)["expected_version"], Value::Null);
        assert_eq!(structured(&first)["number"], text(NUMBER));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_edit",
            command(
                NUMBER,
                "2",
                "edit-between-appends",
                &[("title", text("Preserved edit"))],
            ),
        ));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            APPEND,
            append_args("append-second", "Independent contribution"),
        ));
        let shown = read(&mut server, &mut backend, &mut next);
        assert!(!failed(&shown));
        let row = structured(&shown)["discussion"].object().unwrap();
        assert_eq!(row["title"], text("Preserved edit"));
        assert_eq!(row["version"], text("4"));
        assert_eq!(row["comments"], text("2"));
        let events = array(&structured(&shown)["events"]);
        assert_eq!(
            events[1].object().unwrap()["action"].object().unwrap()["name"],
            text("comment")
        );
        assert_eq!(
            events[1].object().unwrap()["action"].object().unwrap()["body"],
            text("Exact é\r\n<script>untrusted</script>")
        );

        let strict = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_comment",
            command(
                NUMBER,
                "1",
                "strict-stale-comment",
                &[("body", text("Must remain strict"))],
            ),
        );
        assert!(!failed(&strict));
        assert_eq!(structured(&strict)["refusal_code"], text("EvidenceStale"));
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_lock",
            command(NUMBER, "4", "lock-appends", &[]),
        ));
        let refused_args = append_args("append-locked", "Cannot publish while locked");
        let refused = call(
            &mut server,
            &mut backend,
            &mut next,
            APPEND,
            refused_args.clone(),
        );
        assert!(!failed(&refused));
        assert_eq!(
            structured(&refused)["refusal_code"],
            text("ProtectedRefTransitionDenied")
        );
        let before_retry = current_head(&backend);
        let replay = call(
            &mut server,
            &mut backend,
            &mut next,
            APPEND,
            original.clone(),
        );
        assert_eq!(structured(&replay), structured(&first));
        assert_eq!(current_head(&backend), before_retry);
        backend.close().unwrap();

        let mut backend = NodeTools::open(options(&fixture, true, true, true)).unwrap();
        let mut server = initialized(&mut backend);
        let mut next = 2;
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_unlock",
            command(NUMBER, "5", "unlock-appends", &[]),
        ));
        let before_retry = current_head(&backend);
        let replay = call(&mut server, &mut backend, &mut next, APPEND, original);
        assert_eq!(structured(&replay), structured(&first));
        let replay = call(&mut server, &mut backend, &mut next, APPEND, refused_args);
        assert_eq!(structured(&replay), structured(&refused));
        let changed = call(
            &mut server,
            &mut backend,
            &mut next,
            APPEND,
            append_args("append-original", "Changed body under original key"),
        );
        assert!(failed(&changed));
        let changed_profile = call(
            &mut server,
            &mut backend,
            &mut next,
            "frankengit_discussion_comment",
            command(
                NUMBER,
                "1",
                "append-original",
                &[("body", text("Exact é\r\n<script>untrusted</script>"))],
            ),
        );
        assert!(failed(&changed_profile));
        assert_eq!(current_head(&backend), before_retry);
        committed(&call(
            &mut server,
            &mut backend,
            &mut next,
            APPEND,
            append_args("append-after-unlock", "Fresh permitted reply"),
        ));
        let shown = read(&mut server, &mut backend, &mut next);
        let row = structured(&shown)["discussion"].object().unwrap();
        assert_eq!(row["comments"], text("3"));
        assert_eq!(row["version"], text("7"));
        assert_eq!(row["title"], text("Preserved edit"));
        backend.close().unwrap();

        // Knowing an old key does not widen a subsequent process's grant.
        let mut backend = NodeTools::open(options(&fixture, true, false, true)).unwrap();
        let mut server = initialized(&mut backend);
        let denied = invoke(
            &mut server,
            &mut backend,
            2,
            APPEND,
            append_args("append-original", "Exact é\r\n<script>untrusted</script>"),
        );
        assert!(denied.object().unwrap().contains_key("error"));
        backend.close().unwrap();
    }
}
