//! The MCP envelope reaches real native candidate admission and durable replay.
use super::*;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{MergeMetadata, MergePreparation};
use fgit_forge::{PullRequestNumber, QueueNumber};
use fgit_types::GitOid;

fn protect(backend: &NodeTools, version: u64, epoch: u64, approvals: bool) {
    let command = ProtectionCommand {
        expected_version: if version == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
        },
        expected_epoch: PolicyEpoch::try_new(epoch).unwrap(),
        protection: ReviewProtection {
            administrators: vec![actor()],
            ref_policy: None,
            branches: vec![ProtectedBranch {
                path_reviews: Vec::new(),
                required_candidate_checks: Vec::new(),
                require_merge_queue: true,
                name: reference("refs/heads/main"),
                reviewers: if approvals {
                    vec![fgit_types::PrincipalId::from_bytes([0x44; 16])]
                } else {
                    Vec::new()
                },
                required_approvals: u16::from(approvals),
                required_checks: Vec::new(),
            }],
        },
    };
    let request = fgit_cli::command_request_context(&backend.node);
    let (_, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_review_protection_durable_in(
            &request,
            &session(&format!("candidate-policy-{epoch}")),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn prepare(backend: &NodeTools, fixture: &Fixture, epoch: u64, key: &str) -> (Object, GitOid) {
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::try_new(7).unwrap(),
        pull_request_version: AggregateVersion::FIRST,
        source_ref: reference("refs/heads/topic"),
        target_ref: reference("refs/heads/main"),
        source_tip: fixture.source,
        target_tip: fixture.target,
        policy_epoch: PolicyEpoch::try_new(epoch).unwrap(),
    };
    let metadata = MergeMetadata {
        author: "A <a@example.invalid>".into(),
        committer: "C <c@example.invalid>".into(),
        timestamp: 2,
        message: b"Land exact divergent queue head\n".to_vec(),
    };
    let held = selected_head(backend);
    let request = fgit_cli::command_request_context(&backend.node);
    let prepared = backend
        .node
        .runtime()
        .block_on(backend.node.prepare_queue_head_bundle_in(
            &request,
            QueueNumber::FIRST,
            AggregateVersion::FIRST,
            &subject,
            &Default::default(),
            &metadata,
            Default::default(),
        ))
        .unwrap();
    let MergePreparation::Clean(plan) = prepared.outcome else {
        panic!("divergent native merge should be clean")
    };
    assert_ne!(plan.base, fixture.target);
    assert_ne!(plan.base, fixture.source);
    assert_eq!(selected_head(backend), held);
    let mut offered = fixture.command(LAND_CANDIDATE, 1, 1, 7, key);
    offered.insert("expected_policy_epoch".into(), text(epoch.to_string()));
    offered.insert("merge_base".into(), text(plan.base.to_string()));
    offered.insert("candidate_commit".into(), text(plan.commit.to_string()));
    let bundle = prepared.bundle.unwrap();
    assert!(bundle.len() <= 24 * 1024);
    offered.insert(
        "bundle_hex_chunks".into(),
        Value::Array(
            bundle
                .chunks(8192)
                .map(|chunk| text(super::super::super::hex(chunk)))
                .collect(),
        ),
    );
    (offered, plan.commit)
}

fn uncertain(backend: &mut NodeTools, args: Object) {
    let mut server = protocol::Server::new(backend).unwrap();
    server.receive(backend, INIT.as_bytes()).unwrap();
    assert!(server.receive(backend, READY.as_bytes()).is_none());
    let response = server
        .receive(backend, message(2, LAND_CANDIDATE, args).as_bytes())
        .unwrap();
    let result = response.object().unwrap()["result"].object().unwrap();
    assert_eq!(result["isError"], Value::Bool(true));
    let content = result["structuredContent"].object().unwrap();
    assert_eq!(content["code"], text("queue_mutation_outcome_unknown"));
    assert_eq!(content["terminal"], Value::Bool(false));
    assert_eq!(content["outcome_unknown"], Value::Bool(true));
}

#[test]
fn divergent_candidate_lands_atomically_and_replays_without_upload_or_current_intake() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::divergent(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        invoke(
            &mut backend,
            ENQUEUE,
            fixture.command(ENQUEUE, 1, 0, 7, "enqueue-candidate"),
        );
        protect(&backend, 0, 1, false);
        let (offered, candidate) = prepare(&backend, &fixture, 2, "land-native-candidate");
        assert!(backend.node.read_git_object(candidate).is_err());
        let before_refs = refs(&backend);

        // The established fast-forward profile refuses this actual divergence.
        let mut fast_forward = fixture.command(LAND, 1, 1, 7, "ff-cannot-land-divergence");
        fast_forward.insert("expected_policy_epoch".into(), text("2"));
        assert_eq!(
            value(&invoke(&mut backend, LAND, fast_forward), "outcome"),
            "refused"
        );
        assert_eq!(refs(&backend), before_refs);

        let held = selected_head(&backend);
        backend.options.queues.land = false;
        assert_eq!(
            backend.call(LAND_CANDIDATE, &offered).unwrap_err().code,
            "tool_not_granted"
        );
        assert_eq!(selected_head(&backend), held);
        backend.options.queues.land = true;
        backend.options.queues.write = false;
        backend.options.queues.read = false;
        assert!(!backend.options.pulls && !backend.options.source);

        // Framed but invalid bytes carry no terminal claim. The identical
        // original command/key may still be retried with its actual artifact.
        let mut bad = offered.clone();
        bad.insert("bundle_hex_chunks".into(), Value::Array(vec![text("00ff")]));
        uncertain(&mut backend, bad);
        let mut absent = offered.clone();
        absent.remove("bundle_hex_chunks");
        uncertain(&mut backend, absent.clone());
        assert_eq!(refs(&backend), before_refs);
        let before = backend
            .node
            .runtime()
            .block_on(backend.node.materialize_admission())
            .unwrap();
        let landed = invoke(&mut backend, LAND_CANDIDATE, offered.clone());
        assert_eq!(value(&landed, "outcome"), "committed");
        assert_eq!(value(&landed, "action"), "land-candidate");
        assert_eq!(landed.object().unwrap()["refs_changed"], Value::Bool(true));
        let action = landed.object().unwrap()["proposed_action"]
            .object()
            .unwrap();
        assert_eq!(action["method"], text("merge-commit"));
        assert_eq!(action["candidate_commit"], text(candidate.to_string()));
        assert_eq!(action["merge_base"], offered["merge_base"]);
        assert!(!action.contains_key("bundle_hex_chunks"));
        assert!(
            !landed
                .encode(MAX_RESPONSE)
                .unwrap()
                .contains("land-native-candidate")
        );
        let after = backend
            .node
            .runtime()
            .block_on(backend.node.materialize_admission())
            .unwrap();
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        let mut expected_refs = before_refs;
        expected_refs.insert(reference("refs/heads/main"), candidate);
        assert_eq!(after.snapshot().refs, expected_refs);
        let context = fgit_cli::command_request_context(&backend.node);
        let history = backend
            .node
            .runtime()
            .block_on(backend.node.snapshot_history_in(&context))
            .unwrap();
        let decision = history.last().unwrap();
        assert_eq!(decision.batch.decisions.len(), 1);
        assert_eq!(decision.batch.committed_rcrs.len(), 1);
        assert_eq!(decision.forge_events.len(), 3);
        assert_eq!(
            decision
                .forge_events
                .iter()
                .map(|event| event.version.get())
                .collect::<Vec<_>>(),
            [2, 2, 3]
        );
        backend.options.queues.read = true;
        assert_queue(&show(&mut backend, 1), 3, &[]);
        let commit = backend.node.read_git_object(candidate).unwrap();
        let parents: Vec<_> = std::str::from_utf8(commit.payload())
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("parent "))
            .map(str::to_owned)
            .collect();
        assert_eq!(
            parents,
            [
                format!("parent {}", fixture.target),
                format!("parent {}", fixture.source)
            ]
        );

        // New protection cannot reinterpret the sealed historical request.
        protect(&backend, 1, 2, true);
        let held = selected_head(&backend);
        assert_eq!(invoke(&mut backend, LAND_CANDIDATE, absent.clone()), landed);
        backend.close().unwrap();
        let mut backend = NodeTools {
            agent: None,
            maintenance: None,
            node: fgit_node::OneNode::open_existing(fixture.config()).unwrap(),
            options: fixture.options.clone(),
        };
        assert_eq!(invoke(&mut backend, LAND_CANDIDATE, absent), landed);
        for chunks in [vec![], vec![text("00ff")]] {
            let mut retry = offered.clone();
            retry.insert("bundle_hex_chunks".into(), Value::Array(chunks));
            assert_eq!(invoke(&mut backend, LAND_CANDIDATE, retry), landed);
        }
        let recovered = invoke(
            &mut backend,
            "frankengit_transaction_outcome",
            fields([("idempotency_key", text("land-native-candidate"))]),
        );
        assert_eq!(
            recovered.object().unwrap()["tx_id"],
            landed.object().unwrap()["tx_id"]
        );
        let mut changed = offered;
        changed.insert("expected_policy_epoch".into(), text("3"));
        uncertain(&mut backend, changed);
        assert_eq!(selected_head(&backend), held);
        assert_eq!(refs(&backend), expected_refs);
        backend.close().unwrap();
    }
}

#[test]
fn candidate_queue_landing_preserves_current_reviews_and_original_terminal_refusal() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::divergent(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        invoke(
            &mut backend,
            ENQUEUE,
            fixture.command(ENQUEUE, 1, 0, 7, "enqueue-review-bound-candidate"),
        );
        protect(&backend, 0, 1, true);
        let (offered, _) = prepare(&backend, &fixture, 2, "candidate-review-required");
        let before = refs(&backend);
        let refused = invoke(&mut backend, LAND_CANDIDATE, offered.clone());
        assert_eq!(value(&refused, "outcome"), "refused");
        assert_eq!(value(&refused, "refusal_code"), "EvidenceMissing");
        assert_eq!(
            refused.object().unwrap()["refs_changed"],
            Value::Bool(false)
        );
        assert_eq!(refs(&backend), before);
        assert_queue(&show(&mut backend, 1), 1, &[7]);
        protect(&backend, 1, 2, false);
        let mut recovery = offered;
        recovery.remove("bundle_hex_chunks");
        assert_eq!(invoke(&mut backend, LAND_CANDIDATE, recovery), refused);
        let (fresh, _) = prepare(&backend, &fixture, 3, "candidate-current-policy");
        assert_eq!(
            value(&invoke(&mut backend, LAND_CANDIDATE, fresh), "outcome"),
            "committed"
        );
        assert_queue(&show(&mut backend, 1), 3, &[]);
        backend.close().unwrap();
    }
}
