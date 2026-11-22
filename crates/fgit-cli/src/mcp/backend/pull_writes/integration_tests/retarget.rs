//! Complete stdio dispatch through real native metadata admission and recovery.
use super::*;

fn change(mut value: Value, field: &str, replacement: Value) -> Value {
    let Value::Object(fields) = &mut value else {
        unreachable!()
    };
    fields.insert(field.into(), replacement);
    value
}

#[test]
fn mcp_retargets_existing_pr_and_recovers_original_action_without_read_or_ref_write_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        let request = backend.node.request_context();
        let created = backend
            .node
            .runtime()
            .block_on(backend.node.admit_branch_updates_durable_in(
                &request,
                &session("release"),
                &[RefCommand {
                    name: reference("refs/heads/release"),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(fixture.commit),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let mut server = start(&mut backend);
        let opened = invoke(
            &mut server,
            &mut backend,
            2,
            OPEN,
            args(fixture.commit, "0", "open", "Original"),
        );
        assert_eq!(result(&opened)["outcome"].text(), Some("committed"));
        let input = change(
            args(fixture.commit, "1", "retarget", "Original"),
            "target_reference",
            text("refs/heads/release"),
        );
        let denied_update = invoke(
            &mut server,
            &mut backend,
            3,
            UPDATE,
            change(input.clone(), "idempotency_key", text("implicit-update")),
        );
        assert_eq!(result(&denied_update)["outcome"].text(), Some("refused"));
        let moved = invoke(&mut server, &mut backend, 4, RETARGET, input.clone());
        assert_eq!(result(&moved)["outcome"].text(), Some("committed"));
        assert_eq!(result(&moved)["action"].text(), Some("retarget"));
        assert_eq!(result(&moved)["refs_changed"], Value::Bool(false));
        let contract = fgit_schema::mcp::find_tool(RETARGET).unwrap();
        let declared: std::collections::BTreeSet<_> =
            contract.output_fields.iter().map(|f| f.name).collect();
        let served: std::collections::BTreeSet<_> =
            result(&moved).keys().map(String::as_str).collect();
        assert_eq!(declared, served);
        let held = head(&backend.node);
        let repeated = invoke(&mut server, &mut backend, 5, RETARGET, input.clone());
        assert_eq!(result(&repeated), result(&moved));
        assert_eq!(head(&backend.node), held);
        // Retarget does not create a read grant. Enable the independent ceiling
        // only for checking the resulting public representation.
        assert!(
            invoke(
                &mut server,
                &mut backend,
                6,
                "frankengit_pull_show",
                object([("number", text("7"))])
            )
            .object()
            .unwrap()
            .contains_key("error")
        );
        backend.options.pulls = true;
        let shown = backend
            .call(
                "frankengit_pull_show",
                &object([("number", text("7"))]).object().unwrap().clone(),
            )
            .unwrap();
        let row = shown.object().unwrap()["pull_request"].object().unwrap();
        assert_eq!(row["state"].text(), Some("open"));
        assert_eq!(row["last_action"].text(), Some("retarget"));
        assert_eq!(row["version"].text(), Some("2"));
        assert_eq!(row["opened_by"], text(actor().to_string()));
        assert_eq!(
            row["data"].object().unwrap()["target_ref_hex"],
            text(super::super::super::hex(b"refs/heads/release"))
        );
        let closed = invoke(
            &mut server,
            &mut backend,
            7,
            CLOSE,
            change(
                change(input.clone(), "expected_version", text("2")),
                "idempotency_key",
                text("close-after-retarget"),
            ),
        );
        assert_eq!(result(&closed)["outcome"].text(), Some("committed"));
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
        let recovered = invoke(&mut server, &mut stopped, 2, RETARGET, input);
        assert_eq!(result(&recovered), result(&moved));
        stopped.close().unwrap();
    }
}
