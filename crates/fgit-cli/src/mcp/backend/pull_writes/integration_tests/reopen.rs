use super::*;

fn changed(mut value: Value, field: &str, replacement: Value) -> Value {
    let Value::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert(field.into(), replacement);
    value
}

fn replace_topic(node: &OneNode) -> GitOid {
    let request = node.request_context();
    let branch = reference("refs/heads/topic");
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 2,
        message: b"recreated topic\n".to_vec(),
    };
    let (_, plan, bundle) = node.runtime().block_on(node.prepare_trusted_initial_patch_in(
        &request,
        &branch,
        b"diff --git a/file b/file\nnew file mode 100644\n--- /dev/null\n+++ b/file\n@@ -0,0 +1 @@\n+revised\n",
        &metadata,
        Default::default(),
        None,
    )).unwrap();
    let published = node
        .runtime()
        .block_on(node.apply_initial_patch_bundle_durable_in(
            &request,
            &session("recreate-topic"),
            &branch,
            plan.commit,
            bundle.bytes(),
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        published.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    plan.commit
}

#[test]
fn reopening_refreshes_explicit_tips_and_metadata_without_moving_refs_and_retries_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut options = fixture.options.clone();
        options.pulls = true;
        let mut backend = NodeTools::open(options).unwrap();
        let mut server = start(&mut backend);
        for (id, action, version, key) in [(2, OPEN, "0", "opening"), (3, CLOSE, "1", "closing")] {
            let response = invoke(
                &mut server,
                &mut backend,
                id,
                action,
                args(fixture.commit, version, key, "Original"),
            );
            assert_eq!(
                result(&response)["outcome"].text(),
                Some("committed"),
                "{response:?}"
            );
        }

        let request = backend.node.request_context();
        let deleted = backend
            .node
            .runtime()
            .block_on(backend.node.admit_branch_updates_durable_in(
                &request,
                &session("remove-topic"),
                &[RefCommand {
                    name: reference("refs/heads/topic"),
                    expected_old: ExpectedOld::Exactly(fixture.commit),
                    proposed_new: ProposedNew::Delete,
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            deleted.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let missing = invoke(
            &mut server,
            &mut backend,
            4,
            REOPEN,
            args(fixture.commit, "2", "missing-source", "Revised"),
        );
        assert_eq!(result(&missing)["outcome"].text(), Some("refused"));
        assert_eq!(result(&missing)["outcome_unknown"], Value::Bool(false));
        let new_source = replace_topic(&backend.node);
        assert_ne!(new_source, fixture.commit);
        let reopening = changed(
            changed(
                args(fixture.commit, "2", "reopen-exact", "Revised"),
                "expected_source",
                text(new_source.to_string()),
            ),
            "body",
            text("Refreshed é\r\nmetadata remains literal"),
        );

        // A closed PR cannot be updated, retargeted, or reopened with stale tips/version.
        for (id, action, key, field, value) in [
            (5, UPDATE, "update-closed", "title", text("Revised")),
            (6, REOPEN, "stale-version", "expected_version", text("1")),
            (
                7,
                REOPEN,
                "stale-source",
                "expected_source",
                text(fixture.commit.to_string()),
            ),
            (
                8,
                REOPEN,
                "retarget",
                "target_reference",
                text("refs/heads/elsewhere"),
            ),
        ] {
            let input = changed(
                changed(reopening.clone(), "idempotency_key", text(key)),
                field,
                value,
            );
            let response = invoke(&mut server, &mut backend, id, action, input);
            assert_eq!(
                result(&response)["outcome"].text(),
                Some("refused"),
                "{key}: {response:?}"
            );
            assert_eq!(result(&response)["outcome_unknown"], Value::Bool(false));
        }
        let before = backend
            .node
            .runtime()
            .block_on(backend.node.materialize_admission_in(&request))
            .unwrap();
        let reopened = invoke(&mut server, &mut backend, 9, REOPEN, reopening.clone());
        assert_eq!(
            result(&reopened)["outcome"].text(),
            Some("committed"),
            "{reopened:?}"
        );
        assert_eq!(result(&reopened)["action"].text(), Some("reopen"));
        assert_eq!(result(&reopened)["expected_version"].text(), Some("2"));
        assert_eq!(result(&reopened)["refs_changed"], Value::Bool(false));
        let contract = fgit_schema::mcp::find_tool(REOPEN).unwrap();
        let declared: std::collections::BTreeSet<_> = contract
            .output_fields
            .iter()
            .map(|field| field.name)
            .collect();
        let observed: std::collections::BTreeSet<_> =
            result(&reopened).keys().map(String::as_str).collect();
        assert_eq!(declared, observed);
        let after = backend
            .node
            .runtime()
            .block_on(backend.node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(before.snapshot().refs, after.snapshot().refs);
        assert_eq!(
            before.basis().body().ref_root,
            after.basis().body().ref_root
        );
        let shown = invoke(
            &mut server,
            &mut backend,
            10,
            "frankengit_pull_show",
            object([("number", text("7"))]),
        );
        let pull = result(&shown)["pull_request"].object().unwrap();
        assert_eq!(pull["state"].text(), Some("open"));
        assert_eq!(pull["last_action"].text(), Some("reopen"));
        assert_eq!(pull["version"].text(), Some("3"));
        assert_eq!(pull["opened_by"], text(actor().to_string()));
        assert_eq!(
            pull["data"].object().unwrap()["source_tip"],
            text(new_source.to_string())
        );
        assert_eq!(pull["data"].object().unwrap()["title"], text("Revised"));
        assert_eq!(
            pull["data"].object().unwrap()["body"],
            text("Refreshed é\r\nmetadata remains literal")
        );

        let held = head(&backend.node);
        let repeated = invoke(&mut server, &mut backend, 11, REOPEN, reopening.clone());
        assert_eq!(result(&repeated), result(&reopened));
        assert_eq!(head(&backend.node), held);
        // The durable key also binds the action; an update cannot alias this reopen.
        let conflict = invoke(&mut server, &mut backend, 12, UPDATE, reopening.clone());
        assert_eq!(result(&conflict)["outcome_unknown"], Value::Bool(true));
        assert_eq!(head(&backend.node), held);
        let open_again = invoke(
            &mut server,
            &mut backend,
            13,
            REOPEN,
            changed(
                changed(reopening.clone(), "expected_version", text("3")),
                "idempotency_key",
                text("already-open"),
            ),
        );
        assert_eq!(result(&open_again)["outcome"].text(), Some("refused"));

        let config = config(&backend.options);
        let NodeTools { node, options, .. } = backend;
        node.shutdown().unwrap();
        let mut stopped = NodeTools {
            agent: None,
            maintenance: None,
            node: OneNode::open_existing(config).unwrap(),
            options,
        };
        let mut server = start(&mut stopped);
        let repeated = invoke(&mut server, &mut stopped, 2, REOPEN, reopening);
        assert_eq!(result(&repeated), result(&reopened));
        let recovered = invoke(
            &mut server,
            &mut stopped,
            3,
            super::super::super::outcomes::NAME,
            object([("idempotency_key", text("reopen-exact"))]),
        );
        assert_eq!(result(&recovered)["tx_id"], result(&reopened)["tx_id"]);
        stopped.close().unwrap();
    }
}
