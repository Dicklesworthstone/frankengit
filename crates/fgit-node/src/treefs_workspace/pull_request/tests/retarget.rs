//! Real native source objects, file-backed authority, metadata/outbox coupling,
//! retained conversation and original-key recovery across target changes.
use super::*;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand};
use fgit_forge::event::pull_request_comment::PullRequestAppendCommentCommand;

fn release() -> RefName {
    RefName::try_new(b"refs/heads/release").unwrap()
}
fn create_release(node: &OneNode, tip: GitOid) {
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &request,
            &session("release-branch"),
            &[RefCommand {
                name: release(),
                expected_old: ExpectedOld::Absent,
                proposed_new: ProposedNew::Update(tip),
                force: false,
            }],
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn retarget(open: &PullRequestCommand) -> PullRequestCommand {
    let mut next = open.clone();
    next.action = PullRequestAction::Retarget;
    next.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    next.data.target_ref = release();
    next
}
fn unchanged_forge(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    unchanged_code(before, after);
    assert_eq!(
        before.basis().body().forge_position_root,
        after.basis().body().forge_position_root
    );
    assert_eq!(
        before.basis().body().outbox_root,
        after.basis().body().outbox_root
    );
}

#[test]
fn retarget_keeps_conversation_opener_and_original_outcome_after_later_change_and_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let f = fixture(&node, &scratch, format);
        create_release(&node, f.data.target_tip);
        let open = command(&f, 1);
        accepted(apply(&node, &open, "open"));
        let comment = PullRequestAppendCommentCommand {
            number: open.number,
            body: "Keep the original conversation é\r\n".into(),
            anchor: None,
        };
        accepted(
            node.runtime()
                .block_on(node.admit_pull_request_append_comment_durable_in(
                    &node.request_context(),
                    &session("comment-before"),
                    &comment,
                    Default::default(),
                )),
        );
        let before = snapshot(&node);
        let change = retarget(&open);
        let original = accepted(apply(&node, &change, "retarget-original"));
        let after = snapshot(&node);
        unchanged_code(&before, &after);
        assert_ne!(
            before.basis().body().forge_position_root,
            after.basis().body().forge_position_root
        );
        assert_ne!(
            before.basis().body().outbox_root,
            after.basis().body().outbox_root
        );
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        let row = page(&node, 0, 1, None).unwrap().pull_requests.remove(0);
        assert_eq!(row.event.version.get(), 2);
        assert_eq!(row.opened_by, Some(principal()));
        assert_eq!(row.data, Some(change.data.clone()));
        assert!(
            matches!(row.event.payload, ForgeEventPayload::PullRequestChangedNative(event)
            if event.action == PullRequestAction::Retarget)
        );
        let comments = node
            .runtime()
            .block_on(node.read_pull_request_comments_in(
                &node.request_context(),
                &RefVisibility::new(),
                open.number,
                0,
                100,
                None,
            ))
            .unwrap()
            .unwrap();
        assert_eq!(comments.discussion_version.unwrap().get(), 1);
        assert_eq!(comments.comments.len(), 1);
        assert_eq!(comments.comments[0].body, comment.body);
        let old = page(&node, 0, 1, Some(before.basis().id()))
            .unwrap()
            .pull_requests
            .remove(0);
        assert_eq!(old.data, Some(open.data.clone()));
        assert_eq!(
            apply(&node, &change, "retarget-original").unwrap(),
            original
        );
        assert_eq!(snapshot(&node).basis(), after.basis());
        let mut changed = change.clone();
        changed.data.title.push('!');
        assert!(apply(&node, &changed, "retarget-original").is_err());
        assert_eq!(snapshot(&node).basis(), after.basis());
        let mut back = change.clone();
        back.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        back.data.target_ref = target();
        accepted(apply(&node, &back, "retarget-back"));
        let later = snapshot(&node);
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        // Retry recovery precedes service intake and may not retarget a later PR.
        assert_eq!(
            apply(&reopened, &change, "retarget-original").unwrap(),
            original
        );
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(snapshot(&reopened).basis(), later.basis());
        let current = page(&reopened, 0, 1, None).unwrap().pull_requests.remove(0);
        assert_eq!(current.event.version.get(), 3);
        assert_eq!(current.data, Some(back.data));
        reopened.shutdown().unwrap();
    }
}

#[test]
fn retarget_refusals_cannot_change_forge_and_permitted_twin_publishes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let f = fixture(&node, &scratch, format);
        create_release(&node, f.data.target_tip);
        let open = command(&f, 1);
        accepted(apply(&node, &open, "open"));
        let change = retarget(&open);
        let mut cases = Vec::new();
        let mut same = change.clone();
        same.data.target_ref = target();
        cases.push((
            "same-target",
            same,
            RefusalCode::ProtectedRefTransitionDenied,
        ));
        let mut source = change.clone();
        source.data.source_ref = target();
        cases.push((
            "changed-source",
            source,
            RefusalCode::ProtectedRefTransitionDenied,
        ));
        let mut implicit = change.clone();
        implicit.action = PullRequestAction::Update;
        cases.push((
            "implicit-update",
            implicit,
            RefusalCode::ProtectedRefTransitionDenied,
        ));
        let mut missing = change.clone();
        missing.data.target_ref = RefName::try_new(b"refs/heads/missing").unwrap();
        cases.push(("missing-target", missing, RefusalCode::TargetRefMoved));
        let mut source_tip = change.clone();
        source_tip.data.source_tip = f.data.target_tip;
        cases.push(("moved-source", source_tip, RefusalCode::TargetRefMoved));
        let mut target_tip = change.clone();
        target_tip.data.target_tip = f.data.source_tip;
        cases.push(("moved-target", target_tip, RefusalCode::TargetRefMoved));
        for (key, invalid, expected) in cases {
            let before = snapshot(&node);
            let refused = apply(&node, &invalid, key).unwrap();
            assert!(
                matches!(refused.1.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
                "{key}: {refused:?}"
            );
            let after = snapshot(&node);
            unchanged_forge(&before, &after);
            assert_eq!(apply(&node, &invalid, key).unwrap(), refused);
            assert_eq!(snapshot(&node).basis(), after.basis());
        }
        let cancelled = node.request_context();
        cancelled.cancel();
        let before = snapshot(&node);
        assert!(
            node.runtime()
                .block_on(node.admit_pull_request_durable_in(
                    &cancelled,
                    &session("cancelled-retarget"),
                    &change,
                    Default::default()
                ))
                .is_err()
        );
        assert_eq!(snapshot(&node).basis(), before.basis());
        accepted(apply(&node, &change, "permitted"));
        let before = snapshot(&node);
        let stale = apply(&node, &change, "stale-version").unwrap();
        assert!(matches!(
            stale.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::EvidenceStale,
                ..
            }
        ));
        unchanged_forge(&before, &snapshot(&node));
        let mut close = change.clone();
        close.action = PullRequestAction::Close;
        close.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        accepted(apply(&node, &close, "close"));
        let mut closed = change;
        closed.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap());
        closed.data.target_ref = target();
        let before = snapshot(&node);
        let refused = apply(&node, &closed, "retarget-closed").unwrap();
        assert!(matches!(
            refused.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        unchanged_forge(&before, &snapshot(&node));
        node.shutdown().unwrap();
    }
}

#[test]
fn retarget_checks_current_visibility_of_source_old_target_and_new_target() {
    for hidden in [source_ref(), target(), release()] {
        let scratch = Scratch::new();
        let node = node(&scratch, GitHashAlgorithm::Sha256);
        let f = fixture(&node, &scratch, GitHashAlgorithm::Sha256);
        create_release(&node, f.data.target_tip);
        let open = command(&f, 1);
        accepted(apply(&node, &open, "open"));
        let mut change = retarget(&open);
        accepted(apply(&node, &change, "visible-twin"));
        // Return to the original pair, then hide one of the three relevant refs.
        change.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        change.data.target_ref = target();
        accepted(apply(&node, &change, "return"));
        super::notifications::hide(&node, &hidden);
        change.expected_version = ExpectedVersion::Exactly(AggregateVersion::try_new(3).unwrap());
        change.data.target_ref = release();
        let before = snapshot(&node);
        let refused = apply(&node, &change, "hidden-retarget").unwrap();
        assert!(
            matches!(
                refused.1.outcome,
                DecisionOutcome::Refused {
                    code: RefusalCode::HiddenRefUnauthorized,
                    ..
                }
            ),
            "{hidden}: {refused:?}"
        );
        unchanged_forge(&before, &snapshot(&node));
        node.shutdown().unwrap();
    }
}
