//! Real protocol calls, persisted native objects and original terminal recovery.
mod support;
use super::super::super::json::{self, object, text};
use super::super::super::{
    Options,
    protocol::{self, ReadTools},
};
use super::*;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::{AggregateVersion, ExpectedVersion};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PolicyEpoch};
use std::io::{self, Cursor, Write};
use support::*;

#[test]
fn native_queue_lifecycle_and_atomic_landing_cross_real_mcp_without_other_grants() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format);
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        for forbidden in [
            "frankengit_pull_show",
            "frankengit_pull_review",
            "frankengit_pull_fast_forward",
            "frankengit_branch_update",
        ] {
            assert_eq!(
                backend.call(forbidden, &Object::new()).unwrap_err().code,
                "tool_not_granted"
            );
        }
        let before_refs = refs(&backend);
        let original_args = fixture.command(ENQUEUE, 1, 0, 7, "original-enqueue");
        let original = invoke(&mut backend, ENQUEUE, original_args.clone());
        assert_eq!(value(&original, "outcome"), "committed");
        assert_eq!(value(&original, "principal_id"), actor().to_string());
        assert_eq!(
            original.object().unwrap()["refs_changed"],
            Value::Bool(false)
        );
        let mut priority = fixture.command(ENQUEUE, 1, 1, 9, "second");
        priority.insert("priority".into(), text("10"));
        invoke(&mut backend, ENQUEUE, priority);
        invoke(
            &mut backend,
            ENQUEUE,
            fixture.command(ENQUEUE, 2, 0, 7, "other-queue"),
        );
        let page = invoke(&mut backend, LIST, fields([("limit", json::number(1))]));
        assert_eq!(value(&page, "next_after"), "1");
        let pinned = value(&page, "snapshot_token").to_owned();
        let previous = show(&mut backend, 1);
        assert_queue(&previous, 2, &[9, 7]);
        let nonhead = invoke(
            &mut backend,
            LAND,
            fixture.command(LAND, 1, 2, 7, "nonhead"),
        );
        assert_eq!(
            value(&nonhead, "refusal_code"),
            "ProtectedRefTransitionDenied"
        );
        let mut order = fixture.command(REORDER, 1, 2, 0, "reorder");
        order.insert("order".into(), Value::Array(vec![text("7"), text("9")]));
        invoke(&mut backend, REORDER, order);
        assert_queue(&show(&mut backend, 1), 3, &[7, 9]);
        let historical = invoke(
            &mut backend,
            SHOW,
            fields([("number", text("1")), ("expected_head", text(&pinned))]),
        );
        assert_eq!(historical, previous);
        let next = invoke(
            &mut backend,
            LIST,
            fields([
                ("after", text("1")),
                ("limit", json::number(1)),
                ("expected_head", text(&pinned)),
            ]),
        );
        assert_eq!(value(&next, "snapshot_token"), pinned);
        let Value::Array(rows) = &next.object().unwrap()["queues"] else {
            panic!()
        };
        assert_eq!(value(&rows[0], "number"), "2");
        assert!(
            backend
                .call(LIST, &fields([("after", text("1"))]))
                .unwrap_err()
                .invalid
        );
        let stale_args = fixture.command(LAND, 1, 2, 7, "stale-queue");
        let stale = invoke(&mut backend, LAND, stale_args.clone());
        assert_eq!(value(&stale, "refusal_code"), "EvidenceStale");
        for guard in ["expected_pull_request_version", "expected_policy_epoch"] {
            let mut bad = fixture.command(LAND, 1, 3, 7, guard);
            bad.insert(guard.into(), text("2"));
            assert_eq!(
                value(&invoke(&mut backend, LAND, bad), "refusal_code"),
                "EvidenceStale"
            );
        }
        assert_eq!(refs(&backend), before_refs);
        let offered = fixture.command(LAND, 1, 3, 7, "land-original");
        let landed = invoke(&mut backend, LAND, offered.clone());
        assert_eq!(value(&landed, "outcome"), "committed");
        assert_eq!(landed.object().unwrap()["refs_changed"], Value::Bool(true));
        assert_eq!(
            landed.object().unwrap()["delivery_acknowledged"],
            Value::Null
        );
        assert!(
            !landed
                .encode(MAX_RESPONSE)
                .unwrap()
                .contains("land-original")
        );
        assert_queue(&show(&mut backend, 1), 5, &[9]);
        let mut expected_refs = before_refs;
        expected_refs.insert(reference("refs/heads/main"), fixture.source);
        assert_eq!(refs(&backend), expected_refs);
        let context = fgit_cli::command_request_context(&backend.node);
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
        let merged = pulls
            .pull_requests
            .iter()
            .find(|row| row.number.get() == 7)
            .unwrap();
        assert_eq!(merged.event.version.get(), 2);
        assert!(matches!(
            merged.event.payload,
            fgit_forge::ForgeEventPayload::MergeCommittedNative(_)
        ));
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
            fixture.command(DEQUEUE, 1, 5, 9, "dequeue-survivor"),
        );
        let current = show(&mut backend, 1);
        assert_queue(&current, 6, &[]);
        let held = selected_head(&backend);
        assert_eq!(
            invoke(&mut backend, ENQUEUE, original_args.clone()),
            original
        );
        assert_eq!(invoke(&mut backend, LAND, offered.clone()), landed);
        assert_eq!(invoke(&mut backend, LAND, stale_args.clone()), stale);
        assert_eq!(selected_head(&backend), held);
        backend.close().unwrap();

        // Reopen with no new-publication intake transition. Historical retries
        // and outcome recovery still resolve before the native intake gate.
        let mut backend = NodeTools {
            node: fgit_node::OneNode::open_existing(fixture.config()).unwrap(),
            options: fixture.options.clone(),
        };
        assert_eq!(invoke(&mut backend, LAND, offered.clone()), landed);
        let recovered = invoke(
            &mut backend,
            "frankengit_transaction_outcome",
            fields([("idempotency_key", text("land-original"))]),
        );
        assert_eq!(
            recovered.object().unwrap()["tx_id"],
            landed.object().unwrap()["tx_id"]
        );
        let mut changed = offered.clone();
        changed.insert("expected_policy_epoch".into(), text("2"));
        assert!(backend.call(LAND, &changed).is_err());
        let mut fresh = fixture.command(ENQUEUE, 3, 0, 9, "stopped-new-work");
        fresh.insert("expected_target".into(), text(fixture.source.to_string()));
        assert!(!backend.call(ENQUEUE, &fresh).unwrap_err().invalid);
        assert_eq!(selected_head(&backend), held);
        backend.close().unwrap();
        let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
        assert_eq!(show(&mut backend, 1), current);
        assert_eq!(refs(&backend), expected_refs);
        backend.close().unwrap();
    }
}

#[test]
fn grant_removal_and_invalid_scope_cannot_acquire_a_queue_identity() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1);
    let mut options = fixture.options.clone();
    options.queues.land = false;
    let mut backend = NodeTools::open(options.clone()).unwrap();
    let original = fixture.command(ENQUEUE, 1, 0, 7, "input-key");
    let held = selected_head(&backend);
    for (field, value) in [
        ("principal", text("ff".repeat(16))),
        ("expected_incarnation", text("ef".repeat(16))),
        ("object_format", text("sha256")),
    ] {
        let mut bad = original.clone();
        bad.insert(field.into(), value);
        assert!(backend.call(ENQUEUE, &bad).unwrap_err().invalid);
        assert_eq!(selected_head(&backend), held);
    }
    invoke(&mut backend, ENQUEUE, original.clone());
    assert_eq!(
        backend
            .call(LAND, &fixture.command(LAND, 1, 1, 7, "no-landing-grant"))
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    backend.close().unwrap();
    options.queues.write = false;
    options.queues.land = true;
    let mut backend = NodeTools::open(options.clone()).unwrap();
    assert_eq!(
        backend.call(ENQUEUE, &original).unwrap_err().code,
        "tool_not_granted"
    );
    assert_eq!(
        value(
            &invoke(
                &mut backend,
                LAND,
                fixture.command(LAND, 1, 1, 7, "landing-granted")
            ),
            "outcome"
        ),
        "committed"
    );
    backend.close().unwrap();
    options.queues.land = false;
    options.outcomes = false;
    options.principal = None;
    let mut reader = NodeTools::open(options).unwrap();
    assert_eq!(reader.tools().len(), 2);
    assert_eq!(
        reader
            .call(
                "frankengit_transaction_outcome",
                &fields([("idempotency_key", text("landing-granted"))])
            )
            .unwrap_err()
            .code,
        "tool_not_granted"
    );
    assert_queue(&show(&mut reader, 1), 3, &[]);
    reader.close().unwrap();
}

#[test]
fn queue_landing_cannot_bypass_required_review_and_original_refusal_stays_final() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256);
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    invoke(
        &mut backend,
        ENQUEUE,
        fixture.command(ENQUEUE, 1, 0, 7, "enqueue"),
    );
    let mut protection = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![actor()],
            ref_policy: None,
            branches: vec![ProtectedBranch {
                name: reference("refs/heads/main"),
                reviewers: vec![fgit_types::PrincipalId::from_bytes([0x44; 16])],
                required_approvals: 1,
                required_checks: Vec::new(),
            }],
        },
    };
    let install = |backend: &NodeTools, command: &ProtectionCommand, key: &str| {
        let request = fgit_cli::command_request_context(&backend.node);
        let (_, outcome) = backend
            .node
            .runtime()
            .block_on(backend.node.admit_review_protection_durable_in(
                &request,
                &session(key),
                command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    };
    install(&backend, &protection, "protect");
    let mut offered = fixture.command(LAND, 1, 1, 7, "review-required");
    offered.insert("expected_policy_epoch".into(), text("2"));
    let before = refs(&backend);
    let refused = invoke(&mut backend, LAND, offered.clone());
    assert_eq!(value(&refused, "outcome"), "refused");
    assert_eq!(value(&refused, "refusal_code"), "EvidenceMissing");
    assert_eq!(refs(&backend), before);
    assert_queue(&show(&mut backend, 1), 1, &[7]);
    protection.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    protection.expected_epoch = PolicyEpoch::try_new(2).unwrap();
    protection.protection.branches.clear();
    install(&backend, &protection, "clear");
    assert_eq!(invoke(&mut backend, LAND, offered.clone()), refused);
    offered.insert("expected_policy_epoch".into(), text("3"));
    offered.insert("idempotency_key".into(), text("current-policy-landing"));
    assert_eq!(
        value(&invoke(&mut backend, LAND, offered), "outcome"),
        "committed"
    );
    assert_queue(&show(&mut backend, 1), 3, &[]);
    backend.close().unwrap();
}

#[test]
fn lost_landing_stdout_recovers_the_original_decision_and_stops_next_tool() {
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
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    invoke(
        &mut backend,
        ENQUEUE,
        fixture.command(ENQUEUE, 1, 0, 7, "enqueue"),
    );
    let offered = fixture.command(LAND, 1, 1, 7, "lost-landing");
    let first = message(2, LAND, offered.clone());
    let second = message(
        3,
        ENQUEUE,
        fixture.command(ENQUEUE, 1, 3, 9, "must-not-run"),
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
    let mut backend = NodeTools::open(fixture.options.clone()).unwrap();
    assert_queue(&show(&mut backend, 1), 3, &[]);
    let recovered = invoke(
        &mut backend,
        "frankengit_transaction_outcome",
        fields([("idempotency_key", text("lost-landing"))]),
    );
    let original = invoke(&mut backend, LAND, offered);
    assert_eq!(value(&original, "outcome"), "committed");
    assert_eq!(
        original.object().unwrap()["tx_id"],
        recovered.object().unwrap()["tx_id"]
    );
    let absent = invoke(
        &mut backend,
        "frankengit_transaction_outcome",
        fields([("idempotency_key", text("must-not-run"))]),
    );
    assert_eq!(value(&absent, "observation"), "key_not_observed");
    backend.close().unwrap();
}
