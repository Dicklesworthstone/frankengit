use super::*;

fn initialized(backend: &mut NodeTools) -> Server {
    let mut server = Server::new(backend).unwrap();
    let response = server.receive(backend, br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"canonical-agent","version":"1"}}}"#).unwrap();
    assert!(response.object().unwrap().contains_key("result"));
    assert!(
        server
            .receive(
                backend,
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
            )
            .is_none()
    );
    server
}
fn invoke(
    server: &mut Server,
    backend: &mut NodeTools,
    id: u64,
    name: &str,
    args: &Object,
) -> Value {
    let request = object([
        ("jsonrpc", text("2.0")),
        ("id", super::super::super::super::json::number(id)),
        ("method", text("tools/call")),
        (
            "params",
            object([
                ("name", text(name)),
                ("arguments", Value::Object(args.clone())),
            ]),
        ),
    ]);
    server
        .receive(backend, request.encode(64 * 1024).unwrap().as_bytes())
        .unwrap()
}
fn result(response: &Value) -> &Value {
    &response.object().unwrap()["result"].object().unwrap()["structuredContent"]
}
fn failed(response: &Value) -> bool {
    response.object().unwrap()["result"].object().unwrap()["isError"] == Value::Bool(true)
}

#[test]
fn mcp_agent_publishes_metadata_and_recovers_original_sponsored_evidence_after_rotation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let mut server = initialized(&mut backend);
        let issue_args = opening(7, "agent-issue-original");
        let first = invoke(
            &mut server,
            &mut backend,
            2,
            "frankengit_issue_open",
            &issue_args,
        );
        assert!(!failed(&first), "{first:?}");
        committed(result(&first));
        let pr_args = pull_opening(&fixture, 7, "agent-pull-original");
        let pull = invoke(
            &mut server,
            &mut backend,
            3,
            "frankengit_pull_open",
            &pr_args,
        );
        assert!(!failed(&pull), "{pull:?}");
        committed(result(&pull));
        let mut comment = recovery("agent-pull-comment");
        comment.insert("number".into(), text("7"));
        comment.insert("body".into(), text("Agent conversation, not an approval"));
        let comment_response = invoke(
            &mut server,
            &mut backend,
            4,
            "frankengit_pull_append_comment",
            &comment,
        );
        assert!(!failed(&comment_response), "{comment_response:?}");
        committed(result(&comment_response));
        let discussion = invoke(
            &mut server,
            &mut backend,
            5,
            "frankengit_discussion_open",
            &opening(7, "agent-discussion-original"),
        );
        assert!(!failed(&discussion), "{discussion:?}");
        committed(result(&discussion));
        let mut discussion_comment = recovery("agent-discussion-comment");
        discussion_comment.insert("number".into(), text("7"));
        discussion_comment.insert("body".into(), text("Sponsored discussion reply"));
        let discussion_reply = invoke(
            &mut server,
            &mut backend,
            14,
            "frankengit_discussion_append_comment",
            &discussion_comment,
        );
        assert!(!failed(&discussion_reply), "{discussion_reply:?}");
        committed(result(&discussion_reply));
        assert_eq!(
            result(&discussion_reply).object().unwrap()["expected_version"],
            Value::Null
        );
        assert_eq!(
            result(&discussion_reply).object().unwrap()["action"],
            text("append-comment")
        );

        for (id, tool, entity) in [
            (6, "frankengit_issue_show", Some("issue")),
            (7, "frankengit_discussion_show", Some("discussion")),
            (8, "frankengit_pull_show", None),
            (9, "frankengit_pull_comments", None),
        ] {
            let args = object([("number", text("7"))]).object().unwrap().clone();
            let shown = invoke(&mut server, &mut backend, id, tool, &args);
            assert!(!failed(&shown), "{tool}: {shown:?}");
            if let Some(entity) = entity {
                assert_eq!(
                    result(&shown).object().unwrap()[entity].object().unwrap()["opened_by"],
                    text(AGENT.to_string())
                );
            }
        }
        // A new transport ID uses the exact original durable key and command.
        let repeated = invoke(
            &mut server,
            &mut backend,
            10,
            "frankengit_issue_open",
            &issue_args,
        );
        assert_eq!(result(&repeated), result(&first));
        let recovered = invoke(
            &mut server,
            &mut backend,
            11,
            "frankengit_transaction_outcome",
            &recovery("agent-issue-original"),
        );
        assert_eq!(
            result(&recovered).object().unwrap()["tx_id"],
            result(&first).object().unwrap()["tx_id"]
        );
        let mut changed = issue_args.clone();
        changed.insert("title".into(), text("Changed under the old key"));
        let conflict = invoke(
            &mut server,
            &mut backend,
            12,
            "frankengit_issue_open",
            &changed,
        );
        assert!(failed(&conflict));
        assert_eq!(
            result(&conflict).object().unwrap()["outcome_unknown"],
            Value::Bool(true)
        );
        let mut injected = opening(8, "injected-identity");
        injected.insert("principal".into(), text(SPONSOR.to_string()));
        let rejected = invoke(
            &mut server,
            &mut backend,
            13,
            "frankengit_issue_open",
            &injected,
        );
        assert!(rejected.object().unwrap().contains_key("error"));

        // The response schemas are unchanged; sponsor evidence comes from the
        // authenticated original principal snapshot selected by each decision.
        let original = provenance(&backend, "agent-issue-original");
        for retry in [
            "agent-issue-original",
            "agent-pull-original",
            "agent-pull-comment",
            "agent-discussion-original",
            "agent-discussion-comment",
        ] {
            let snapshot = provenance(&backend, retry);
            let witness = snapshot.agent_provenance().unwrap();
            assert_eq!(witness.agent(), AGENT);
            assert_eq!(witness.sponsor(), SPONSOR);
            assert_eq!(witness.credential_id(), fixture.credential_id);
            assert_ne!(*witness.run_commitment(), [0; 32]);
        }
        assert!(!first.encode(MAX_RESPONSE).unwrap().contains(&token(0xaa)));
        backend.close().unwrap();

        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(
            backend.call("frankengit_issue_open", &issue_args).unwrap(),
            *result(&first)
        );
        assert_eq!(provenance(&backend, "agent-issue-original"), original);
        let discussion_provenance = provenance(&backend, "agent-discussion-comment");
        assert_eq!(
            backend
                .call("frankengit_discussion_append_comment", &discussion_comment)
                .unwrap(),
            *result(&discussion_reply)
        );
        // A live process must consult a new canonical frontier on its next call.
        revoke(&backend.node, fixture.credential_id, "revoke-primary");
        for (name, args) in [
            ("frankengit_issue_list", Object::new()),
            ("frankengit_issue_open", opening(9, "after-revocation")),
            (
                "frankengit_discussion_append_comment",
                discussion_comment.clone(),
            ),
            (
                "frankengit_transaction_outcome",
                recovery("agent-issue-original"),
            ),
        ] {
            assert_eq!(
                backend.call(name, &args).unwrap_err().code,
                "agent_credential_unavailable"
            );
        }
        let replacement_id = issue(
            &backend.node,
            &token(0xbb),
            grant(&backend.node, ALL_OPERATIONS),
            "issue-replacement",
        );
        let mut foreign = grant(&backend.node, OUTCOMES_READ);
        foreign.agent = fgit_types::PrincipalId::from_bytes([0xd5; 16]);
        issue(&backend.node, &token(0xcc), foreign, "issue-other-agent");
        backend.close().unwrap();

        let mut replacement = NodeTools::open(fixture.replacement(0xbb)).unwrap();
        let recovered = replacement
            .call(
                "frankengit_transaction_outcome",
                &recovery("agent-issue-original"),
            )
            .unwrap();
        assert_eq!(
            recovered.object().unwrap()["tx_id"],
            result(&first).object().unwrap()["tx_id"]
        );
        assert_eq!(
            replacement
                .call("frankengit_issue_open", &issue_args)
                .unwrap(),
            *result(&first)
        );
        assert_eq!(provenance(&replacement, "agent-issue-original"), original);
        assert_eq!(
            replacement
                .call("frankengit_discussion_append_comment", &discussion_comment)
                .unwrap(),
            *result(&discussion_reply)
        );
        assert_eq!(
            provenance(&replacement, "agent-discussion-comment"),
            discussion_provenance
        );
        assert_ne!(
            original.agent_provenance().unwrap().credential_id(),
            replacement_id
        );
        let shown = replacement
            .call(
                "frankengit_issue_show",
                object([("number", text("7"))]).object().unwrap(),
            )
            .unwrap();
        assert_eq!(
            shown.object().unwrap()["issue"].object().unwrap()["version"].text(),
            Some("1")
        );
        replacement.close().unwrap();

        let mut another = NodeTools::open(fixture.replacement(0xcc)).unwrap();
        let hidden = another
            .call(
                "frankengit_transaction_outcome",
                &recovery("agent-issue-original"),
            )
            .unwrap();
        assert_eq!(
            hidden.object().unwrap()["observation"].text(),
            Some("key_not_observed")
        );
        assert_eq!(hidden.object().unwrap()["tx_id"], Value::Null);
        assert_eq!(
            hidden.object().unwrap()["absence_proves_non_commit"],
            Value::Bool(false)
        );
        another.close().unwrap();
    }
}
