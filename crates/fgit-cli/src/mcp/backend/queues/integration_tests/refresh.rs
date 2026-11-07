//! Exact refresh through the real MCP envelope, native authority and durable replay.
use super::*;
use fgit_forge::ForgeEventPayload;
use fgit_forge::event::pull_request::PullRequestAction;
use fgit_forge::preparation::MergeMetadata;
use fgit_types::GitOid;

fn refresh_options(fixture: &Fixture) -> Options {
    let mut options = fixture.options.clone();
    options.writes.pulls = true;
    options.queues.land = false;
    options
}

fn advance_target(backend: &NodeTools, fixture: &Fixture) -> GitOid {
    let request = fgit_cli::command_request_context(&backend.node);
    let target_ref = reference("refs/heads/main");
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 3,
        message: b"Advance target after enqueue\n".to_vec(),
    };
    let patch = b"diff --git a/target-side b/target-side\nnew file mode 100644\n--- /dev/null\n+++ b/target-side\n@@ -0,0 +1 @@\n+advanced target\n";
    let prepared = backend
        .node
        .runtime()
        .block_on(backend.node.prepare_trusted_patch_in(
            &request,
            &target_ref,
            fixture.target,
            [0x97; 16],
            patch,
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let next = prepared.candidate_commit;
    let published = backend
        .node
        .runtime()
        .block_on(backend.node.apply_workspace_bundle_durable_in(
            &request,
            actor(),
            b"refresh-advance-target",
            &target_ref,
            fixture.target,
            next,
            prepared.bundle_bytes(),
        ))
        .unwrap();
    assert!(matches!(
        published.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
    next
}

fn offered(fixture: &Fixture, next: GitOid, version: u64, key: &str) -> Object {
    let mut args = fixture.command(ENQUEUE, 1, version, 7, key);
    args.extend([
        ("expected_policy_epoch".into(), text("1")),
        ("expected_target".into(), text(next.to_string())),
        ("expected_recorded_target".into(), text(fixture.target.to_string())),
        ("title".into(), text("Native queue PR 7")),
        ("body".into(), text("Literal repository text, not authority")),
    ]);
    args
}

fn enqueue_pair(backend: &mut NodeTools, fixture: &Fixture) {
    let mut first = fixture.command(ENQUEUE, 1, 0, 7, "refresh-enqueue-head");
    first.insert("priority".into(), text("42"));
    invoke(backend, ENQUEUE, first);
    let mut second = fixture.command(ENQUEUE, 1, 1, 9, "refresh-enqueue-tail");
    second.insert("priority".into(), text("1"));
    invoke(backend, ENQUEUE, second);
    assert_queue(&show(backend, 1), 2, &[7, 9]);
}

#[test]
fn refresh_moves_only_the_recorded_target_and_replays_after_queue_changes_and_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let options = refresh_options(&fixture);
        let mut backend = NodeTools::open(options.clone()).unwrap();
        enqueue_pair(&mut backend, &fixture);
        let next = advance_target(&backend, &fixture);
        let before_queue = show(&mut backend, 1).object().unwrap()["queue"].clone();
        let before_refs = refs(&backend);
        let before = backend
            .node
            .runtime()
            .block_on(backend.node.materialize_admission())
            .unwrap();
        let original = offered(&fixture, next, 2, "original-refresh");
        let receipt = invoke(&mut backend, REFRESH, original.clone());
        assert_eq!(value(&receipt, "outcome"), "committed");
        assert_eq!(value(&receipt, "action"), "refresh");
        assert_eq!(value(&receipt, "principal_id"), actor().to_string());
        assert_eq!(receipt.object().unwrap()["refs_changed"], Value::Bool(false));
        assert_eq!(receipt.object().unwrap()["historical_outcome"], Value::Bool(true));
        assert_eq!(receipt.object().unwrap()["delivery_acknowledged"], Value::Null);
        let proposed = &receipt.object().unwrap()["proposed_action"];
        assert_eq!(value(proposed, "expected_recorded_target"), fixture.target.to_string());
        assert_eq!(value(proposed, "expected_target"), next.to_string());
        assert_eq!(value(proposed, "expected_source"), fixture.source.to_string());
        assert_eq!(value(proposed, "expected_pull_request_version"), "1");
        assert!(!proposed.object().unwrap().contains_key("body"));
        assert!(!proposed.object().unwrap().contains_key("title"));
        assert!(!receipt.encode(MAX_RESPONSE).unwrap().contains("original-refresh"));
        assert_eq!(refs(&backend), before_refs);
        let current = show(&mut backend, 1);
        assert_queue(&current, 2, &[7, 9]);
        assert_eq!(current.object().unwrap()["queue"], before_queue);
        let after = backend
            .node
            .runtime()
            .block_on(backend.node.materialize_admission())
            .unwrap();
        assert_eq!(after.snapshot().outbox.len(), before.snapshot().outbox.len() + 1);

        let context = fgit_cli::command_request_context(&backend.node);
        let history = backend
            .node
            .runtime()
            .block_on(backend.node.snapshot_history_in(&context))
            .unwrap();
        let decision = history.last().unwrap();
        assert_eq!(decision.batch.decisions.len(), 1);
        assert_eq!(decision.batch.committed_rcrs.len(), 1);
        assert_eq!(decision.forge_events.len(), 1);
        assert_eq!(decision.forge_events[0].version.get(), 2);
        let ForgeEventPayload::PullRequestChangedNative(event) =
            &decision.forge_events[0].payload
        else {
            panic!("refresh must publish the sole PR Update")
        };
        assert_eq!(event.action, PullRequestAction::Update);
        assert_eq!(event.actor, actor());
        assert_eq!(event.data.source_ref, reference("refs/heads/topic"));
        assert_eq!(event.data.target_ref, reference("refs/heads/main"));
        assert_eq!(event.data.source_tip, fixture.source);
        assert_eq!(event.data.target_tip, next);
        assert_eq!(event.data.title, "Native queue PR 7");
        assert_eq!(event.data.body, "Literal repository text, not authority");
        let pulls = backend
            .node
            .runtime()
            .block_on(backend.node.read_pull_requests_in(
                &context,
                &Default::default(),
                0,
                10,
                None,
            ))
            .unwrap();
        assert_eq!(
            pulls
                .pull_requests
                .iter()
                .find(|row| row.number.get() == 7)
                .unwrap()
                .event
                .version
                .get(),
            2
        );
        assert_eq!(
            pulls
                .pull_requests
                .iter()
                .find(|row| row.number.get() == 9)
                .unwrap()
                .event
                .version
                .get(),
            1
        );

        invoke(
            &mut backend,
            DEQUEUE,
            fixture.command(DEQUEUE, 1, 2, 9, "refresh-remove-tail"),
        );
        assert_queue(&show(&mut backend, 1), 3, &[7]);
        let held = selected_head(&backend);
        assert_eq!(invoke(&mut backend, REFRESH, original.clone()), receipt);
        assert_eq!(selected_head(&backend), held);
        backend.close().unwrap();

        // Replay resolves the original sealed command even with intake stopped
        // and both the PR version and queue version now beyond its guards.
        let mut backend = NodeTools {
            agent: None,
            maintenance: None,
            node: fgit_node::OneNode::open_existing(fixture.config()).unwrap(),
            options,
        };
        assert_eq!(invoke(&mut backend, REFRESH, original.clone()), receipt);
        let recovered = invoke(
            &mut backend,
            "frankengit_transaction_outcome",
            fields([("idempotency_key", text("original-refresh"))]),
        );
        assert_eq!(
            recovered.object().unwrap()["tx_id"],
            receipt.object().unwrap()["tx_id"]
        );
        for (field, replacement) in [
            ("title", text("Changed title")),
            ("body", text("Changed body")),
            ("expected_version", text("3")),
            ("expected_target", text(fixture.source.to_string())),
        ] {
            let mut changed = original.clone();
            changed.insert(field.into(), replacement);
            assert!(!backend.call(REFRESH, &changed).unwrap_err().invalid);
        }
        assert_eq!(selected_head(&backend), held);
        assert_eq!(refs(&backend), before_refs);
        backend.close().unwrap();
    }
}

#[test]
fn refresh_cannot_use_one_grant_or_modify_metadata_outside_the_exact_head() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let mut backend = NodeTools::open(refresh_options(&fixture)).unwrap();
    let held = selected_head(&backend);
    for (queue_write, pull_write) in [(false, false), (true, false), (false, true)] {
        backend.options.queues.write = queue_write;
        backend.options.writes.pulls = pull_write;
        backend.options.queues.land = true;
        assert!(!backend.tools().iter().any(|tool| tool.name == REFRESH));
        assert!(!backend.is_mutation(REFRESH));
        assert_eq!(
            backend.call(REFRESH, &Object::new()).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(selected_head(&backend), held);
    }
    backend.options.queues.write = true;
    backend.options.writes.pulls = true;
    backend.options.queues.land = false;
    assert!(backend.tools().iter().any(|tool| tool.name == REFRESH));
    assert!(backend.is_mutation(REFRESH));
    enqueue_pair(&mut backend, &fixture);
    let next = advance_target(&backend, &fixture);
    let before_refs = refs(&backend);
    let before_queue = show(&mut backend, 1).object().unwrap()["queue"].clone();
    let original = offered(&fixture, next, 2, "unused");
    for (field, replacement, refusal) in [
        ("title", text("Changed title"), "EvidenceStale"),
        ("body", text("Changed body"), "EvidenceStale"),
        ("expected_version", text("1"), "EvidenceStale"),
        ("expected_pull_request_version", text("2"), "EvidenceStale"),
        ("expected_policy_epoch", text("2"), "EvidenceStale"),
        ("expected_recorded_target", text(fixture.source.to_string()), "EvidenceStale"),
        ("expected_source", text(fixture.target.to_string()), "EvidenceStale"),
        ("expected_target", text(fixture.source.to_string()), "TargetRefMoved"),
        ("pull_request", text("9"), "ProtectedRefTransitionDenied"),
    ] {
        let mut changed = original.clone();
        changed.insert(field.into(), replacement);
        changed.insert("idempotency_key".into(), text(format!("refresh-refuse-{field}")));
        let receipt = invoke(&mut backend, REFRESH, changed);
        assert_eq!(value(&receipt, "outcome"), "refused", "{field}");
        assert_eq!(value(&receipt, "refusal_code"), refusal, "{field}");
        assert_eq!(receipt.object().unwrap()["refs_changed"], Value::Bool(false));
        assert_eq!(refs(&backend), before_refs);
        assert_eq!(show(&mut backend, 1).object().unwrap()["queue"], before_queue);
    }
    let valid = offered(&fixture, next, 2, "refresh-after-refusals");
    assert_eq!(value(&invoke(&mut backend, REFRESH, valid), "outcome"), "committed");
    assert_queue(&show(&mut backend, 1), 2, &[7, 9]);
    backend.close().unwrap();
}

#[test]
fn lost_refresh_stdout_recovers_the_original_update_and_stops_the_next_tool() {
    struct LoseAfterInitialize {
        flushed: bool,
    }
    impl Write for LoseAfterInitialize {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.flushed {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushed = true;
            Ok(())
        }
    }
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let options = refresh_options(&fixture);
    let mut backend = NodeTools::open(options.clone()).unwrap();
    enqueue_pair(&mut backend, &fixture);
    let next = advance_target(&backend, &fixture);
    let original = offered(&fixture, next, 2, "lost-refresh");
    let first = message(2, REFRESH, original.clone());
    let second = message(
        3,
        DEQUEUE,
        fixture.command(DEQUEUE, 1, 2, 7, "refresh-followup-must-not-run"),
    );
    let wire = format!("{INIT}\n{READY}\n{first}\n{second}\n");
    assert!(
        protocol::serve(
            &mut Cursor::new(wire),
            &mut LoseAfterInitialize { flushed: false },
            &mut backend,
            8
        )
        .is_err()
    );
    backend.close().unwrap();
    let mut backend = NodeTools::open(options).unwrap();
    assert_queue(&show(&mut backend, 1), 2, &[7, 9]);
    let held = selected_head(&backend);
    let receipt = invoke(&mut backend, REFRESH, original);
    assert_eq!(value(&receipt, "outcome"), "committed");
    assert_eq!(receipt.object().unwrap()["refs_changed"], Value::Bool(false));
    let recovered = invoke(
        &mut backend,
        "frankengit_transaction_outcome",
        fields([("idempotency_key", text("lost-refresh"))]),
    );
    assert_eq!(
        receipt.object().unwrap()["tx_id"],
        recovered.object().unwrap()["tx_id"]
    );
    let absent = invoke(
        &mut backend,
        "frankengit_transaction_outcome",
        fields([("idempotency_key", text("refresh-followup-must-not-run"))]),
    );
    assert_eq!(value(&absent, "observation"), "key_not_observed");
    assert_eq!(selected_head(&backend), held);
    backend.close().unwrap();
}
