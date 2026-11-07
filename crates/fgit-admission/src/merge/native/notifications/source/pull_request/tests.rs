use super::*;
use fgit_forge::event::notification::{
    NotificationAction, NotificationCommand, NotificationMode, NotificationTarget,
};
use fgit_forge::event::pull_request::{NativePullRequestEvent, PullRequestData};
use fgit_forge::event::pull_request_comment::NativePullRequestComment;
use fgit_forge::event::review::{NativeReviewEvent, ReviewDecision, ReviewSubject};
use fgit_forge::{ExpectedVersion, ForgeEvent};
use fgit_types::{GitHashAlgorithm, GitOid, PolicyEpoch, RefName};
use std::sync::atomic::{AtomicUsize, Ordering};
mod support;
use support::{Fixture, actor, run};

fn version(value: u64) -> AggregateVersion {
    AggregateVersion::try_new(value).unwrap()
}
fn data(format: GitHashAlgorithm) -> PullRequestData {
    let width = format.digest_len() * 2;
    PullRequestData {
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: GitOid::from_hex(format, &"a".repeat(width)).unwrap(),
        target_tip: GitOid::from_hex(format, &"b".repeat(width)).unwrap(),
        title: "Original pull request".into(),
        body: "untrusted source text".into(),
    }
}
fn lifecycle(format: GitHashAlgorithm, v: u64, who: u8, action: PullRequestAction) -> ForgeEvent {
    ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: version(v),
        payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
            action,
            actor: actor(who),
            data: data(format),
        }),
    }
}
fn comment(v: u64, who: u8) -> ForgeEvent {
    ForgeEvent {
        aggregate: AggregateId::PullRequestConversation(PullRequestNumber::FIRST),
        version: version(v),
        payload: ForgeEventPayload::PullRequestCommentedNative(NativePullRequestComment {
            actor: actor(who),
            body: format!("Comment {v}"),
            anchor: None,
        }),
    }
}
fn review(format: GitHashAlgorithm, who: u8, v: u64, lifecycle_version: u64) -> ForgeEvent {
    let data = data(format);
    ForgeEvent {
        aggregate: AggregateId::PullRequestReview {
            pull_request: PullRequestNumber::FIRST,
            reviewer: actor(who),
        },
        version: version(v),
        payload: ForgeEventPayload::PullRequestReviewedNative(NativeReviewEvent {
            reviewer: actor(who),
            subject: ReviewSubject {
                pull_request: PullRequestNumber::FIRST,
                pull_request_version: version(lifecycle_version),
                source_ref: data.source_ref,
                target_ref: data.target_ref,
                source_tip: data.source_tip,
                target_tip: data.target_tip,
                policy_epoch: PolicyEpoch::FIRST,
            },
            decision: ReviewDecision::Approve,
            candidate: None,
            reason: String::new(),
        }),
    }
}
fn preference(who: u8, before: u64, action: NotificationAction) -> ForgeEvent {
    NotificationCommand {
        target: NotificationTarget::PullRequest(PullRequestNumber::FIRST),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(version(before))
        },
        action,
    }
    .proposed_event(actor(who))
    .unwrap()
}
fn merge(format: GitHashAlgorithm, v: u64) -> ForgeEvent {
    let data = data(format);
    ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: version(v),
        payload: ForgeEventPayload::MergeCommittedNative(fgit_forge::event::NativeMerge {
            source_ref: data.source_ref,
            source_tip: data.source_tip,
            base_tip: data.target_tip,
            target_ref: data.target_ref,
            target_tip_before: data.target_tip,
            merge_commit: GitOid::from_hex(format, &"c".repeat(format.digest_len() * 2)).unwrap(),
        }),
    }
}

#[test]
fn independent_streams_form_one_append_stable_activity_prefix_in_repository_order() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new();
        f.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
        // Deliberately interleave aggregates so aggregate sorting would create
        // a different latest-other prefix and fail the assertions below.
        f.append(vec![comment(1, 2)], 2);
        f.append(vec![lifecycle(format, 2, 1, PullRequestAction::Update)], 1);
        f.append(vec![review(format, 3, 1, 2)], 3);
        let observed = f.basis.body().clone();
        f.append(vec![comment(2, 1)], 1);
        f.append(
            vec![preference(
                2,
                0,
                NotificationAction::SetReadThrough(Some(version(4))),
            )],
            2,
        );
        let before_own = f.source(2).unwrap().remove(0);
        assert_eq!(before_own.subject.version(), version(5));
        assert_eq!(before_own.latest_other_version, Some(version(5)));
        assert_eq!(
            before_own.preference.as_ref().unwrap().read_through,
            Some(version(4))
        );
        assert!(before_own.participated);

        // A new reviewer's FIRST aggregate version is activity six, not one.
        f.append(vec![review(format, 2, 1, 2)], 2);
        let after_own = f.source(2).unwrap().remove(0);
        assert_eq!(after_own.subject.version(), version(6));
        assert_eq!(
            after_own.latest_other_version,
            before_own.latest_other_version
        );
        assert_eq!(after_own.preference, before_own.preference);
        f.append(
            vec![preference(
                1,
                0,
                NotificationAction::SetMode(NotificationMode::Muted),
            )],
            1,
        );
        assert_eq!(
            f.source(2).unwrap()[0],
            after_own,
            "other recipients' preferences are private and are not activity"
        );
        f.append(vec![lifecycle(format, 3, 4, PullRequestAction::Close)], 4);
        let closed = f.source(2).unwrap().remove(0);
        assert_eq!(closed.subject.version(), version(7));
        assert_eq!(closed.latest_other_version, Some(version(7)));
        assert!(closed.subject.is_closed());
        assert!(!closed.subject.is_merged());
        assert!(
            !f.source(4).unwrap()[0].participated,
            "closing alone is not participation"
        );
        assert_eq!(f.source(3).unwrap()[0].preference, None);
        assert!(
            f.source(3).unwrap()[0].participated,
            "reviewing establishes participation"
        );
        assert_eq!(closed.subject.opened_by(), actor(1));
        assert_eq!(
            closed.subject.pull_request_refs(),
            Some((&data(format).source_ref, &data(format).target_ref))
        );

        let retained = f.selected_head(&observed, 2).unwrap().threads.remove(0);
        assert_eq!(retained.subject.version(), version(4));
        assert_eq!(retained.latest_other_version, Some(version(4)));
        assert_eq!(retained.preference, None);
        assert!(!retained.subject.is_closed());
        assert_eq!(
            f.source(2).unwrap(),
            f.source(2).unwrap(),
            "fresh replay is deterministic"
        );
    }
}

#[test]
fn exact_rcr_and_intra_batch_order_survives_multiple_records_in_one_cas() {
    let format = GitHashAlgorithm::Sha1;
    let mut grouped = Fixture::new();
    grouped.append_records(vec![
        (
            vec![
                lifecycle(format, 1, 1, PullRequestAction::Open),
                comment(1, 2),
            ],
            2,
        ),
        (vec![review(format, 3, 1, 1), comment(2, 1)], 1),
    ]);
    let mut separate = Fixture::new();
    for (event, who) in [
        (lifecycle(format, 1, 1, PullRequestAction::Open), 1),
        (comment(1, 2), 2),
        (review(format, 3, 1, 1), 3),
        (comment(2, 1), 1),
    ] {
        separate.append(vec![event], who);
    }
    let thread = grouped.source(1).unwrap().remove(0);
    assert_eq!(thread.subject.version(), version(4));
    assert_eq!(thread.latest_other_version, Some(version(3)));
    assert_eq!(grouped.source(1).unwrap(), separate.source(1).unwrap());
    // A preference in a later RCR does not alter the previously observed prefix.
    grouped.append(
        vec![preference(
            1,
            0,
            NotificationAction::SetReadThrough(Some(version(4))),
        )],
        1,
    );
    assert_eq!(grouped.source(1).unwrap()[0].subject.version(), version(4));
}

#[test]
fn merge_activity_uses_the_committed_principal_snapshot_and_preserves_native_metadata() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new();
        f.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
        f.append(vec![comment(1, 2)], 2);
        f.append(vec![merge(format, 2)], 1);
        let own = f.source(1).unwrap().remove(0);
        assert_eq!(own.subject.version(), version(3));
        assert_eq!(
            own.latest_other_version,
            Some(version(2)),
            "own merge is not another actor's activity"
        );
        assert_eq!(own.subject.title(), "Original pull request");
        assert!(own.subject.is_closed());
        assert!(own.subject.is_merged());
        assert_eq!(
            f.source(2).unwrap()[0].latest_other_version,
            Some(version(3))
        );
        assert!(!f.source(3).unwrap()[0].participated);
        let key = f.principal_keys.last().unwrap().clone();
        for corrupt in [false, true] {
            *f.store.fault.lock().unwrap() = Some((key.clone(), corrupt));
            assert!(
                f.source(1).is_err(),
                "missing/corrupt merge actor must not be invented"
            );
        }
        *f.store.fault.lock().unwrap() = None;
        assert_eq!(f.source(1).unwrap()[0], own);
    }
}

#[test]
fn read_acknowledges_only_the_observed_activity_prefix_and_modes_are_independent() {
    let format = GitHashAlgorithm::Sha1;
    let mut f = Fixture::new();
    f.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
    f.append(vec![comment(1, 2)], 2);
    f.append(
        vec![preference(
            1,
            0,
            NotificationAction::SetReadThrough(Some(version(2))),
        )],
        1,
    );
    f.append(vec![review(format, 3, 1, 1)], 3);
    let unread = f.source(1).unwrap().remove(0);
    assert_eq!(unread.latest_other_version, Some(version(3)));
    assert_eq!(
        unread.preference.as_ref().unwrap().read_through,
        Some(version(2))
    );
    f.append(
        vec![preference(
            1,
            1,
            NotificationAction::SetMode(NotificationMode::Muted),
        )],
        1,
    );
    let muted = f.source(1).unwrap().remove(0);
    assert_eq!(muted.subject.version(), version(3));
    assert_eq!(
        muted.preference.as_ref().unwrap().read_through,
        Some(version(2))
    );
    f.append(
        vec![preference(1, 2, NotificationAction::SetReadThrough(None))],
        1,
    );
    let cleared = f.source(1).unwrap().remove(0);
    assert_eq!(
        cleared.preference.as_ref().unwrap().mode,
        NotificationMode::Muted
    );
    assert_eq!(cleared.preference.as_ref().unwrap().read_through, None);
    assert_eq!(cleared.latest_other_version, Some(version(3)));
    let beyond = preference(1, 3, NotificationAction::SetReadThrough(Some(version(4))));
    assert_eq!(
        super::super::super::validate_current_thread(Some(&cleared), &beyond),
        Err(RefusalCode::EvidenceStale)
    );
    let permitted = preference(1, 3, NotificationAction::SetReadThrough(Some(version(3))));
    assert_eq!(
        super::super::super::validate_current_thread(Some(&cleared), &permitted),
        Ok(())
    );

    let mut forged = Fixture::new();
    forged.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
    forged.append(
        vec![preference(
            1,
            0,
            NotificationAction::SetReadThrough(Some(version(2))),
        )],
        1,
    );
    forged.append(vec![comment(1, 2)], 2);
    assert!(
        forged.source(1).is_err(),
        "later activity cannot validate an originally future acknowledgement"
    );
}

#[test]
fn native_open_is_required_and_terminal_streams_cannot_be_resurrected() {
    let format = GitHashAlgorithm::Sha1;
    let mut standalone = Fixture::new();
    standalone.append(vec![merge(format, 1)], 1);
    assert!(
        standalone.source(1).unwrap().is_empty(),
        "standalone merge receipts have no invented opener/title"
    );
    let mut incomplete = Fixture::new();
    incomplete.append(vec![comment(1, 2)], 2);
    assert!(
        incomplete.source(1).is_err(),
        "a native conversation without its PR is incomplete"
    );
    let mut f = Fixture::new();
    f.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
    f.append(vec![lifecycle(format, 2, 2, PullRequestAction::Close)], 2);
    f.append(vec![lifecycle(format, 3, 3, PullRequestAction::Reopen)], 3);
    assert!(!f.source(1).unwrap()[0].subject.is_closed());
    f.append(vec![merge(format, 4)], 3);
    assert!(f.source(1).unwrap()[0].subject.is_merged());
    f.append(vec![lifecycle(format, 5, 1, PullRequestAction::Reopen)], 1);
    assert!(f.source(1).is_err());
}

#[test]
fn source_work_is_bounded_cancellable_and_verifies_every_selected_history_link() {
    let format = GitHashAlgorithm::Sha1;
    let mut f = Fixture::new();
    f.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
    for index in 1..=8 {
        f.append(vec![comment(index, 2)], 2);
    }
    f.store.reads.lock().unwrap().clear();
    let expected = f.source(1).unwrap();
    let reads = f.store.reads.lock().unwrap().clone();
    for key in &f.event_keys {
        assert_eq!(
            reads.iter().filter(|observed| *observed == key).count(),
            1,
            "one event read per RCR; no paginated replays"
        );
    }
    let calls = AtomicUsize::new(0);
    let stopped = run(read_threads(
        &f.store,
        &(),
        &f.basis,
        &f.forge,
        actor(1),
        &|| calls.fetch_add(1, Ordering::SeqCst) >= 5,
    ));
    assert!(matches!(
        stopped,
        Err(AdmissionError::AsyncProjectionUnavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    assert_eq!(f.source(1).unwrap(), expected);
    let key = f.event_keys[0].clone();
    for corrupt in [false, true] {
        *f.store.fault.lock().unwrap() = Some((key.clone(), corrupt));
        assert!(
            f.source(1).is_err(),
            "no fabricated empty prefix for missing/corrupt history"
        );
    }
    *f.store.fault.lock().unwrap() = None;
    let original = f.forge.clone();
    f.forge = CanonicalForgePositionState::try_new(
        f.basis.body().repository_id,
        original
            .entries()
            .iter()
            .copied()
            .filter(|entry| !entry.stream().as_str().starts_with("conversation/"))
            .collect(),
    )
    .unwrap();
    assert!(
        f.source(1).is_err(),
        "history absent from the authenticated frontier is not complete"
    );
    f.forge = original;
    assert_eq!(f.source(1).unwrap(), expected);

    let selected = |event: &ForgeEvent| relevant(event.aggregate, actor(1));
    for limits in [
        feed::SelectedHistoryLimits {
            events: 8,
            ..feed::SelectedHistoryLimits::DEFAULT
        },
        feed::SelectedHistoryLimits {
            scan_bytes: 1,
            ..feed::SelectedHistoryLimits::DEFAULT
        },
        feed::SelectedHistoryLimits {
            retained_bytes: 1,
            ..feed::SelectedHistoryLimits::DEFAULT
        },
    ] {
        assert!(
            run(feed::read_selected_at(
                &f.store,
                &(),
                &f.basis,
                limits,
                &selected,
                &|| false
            ))
            .is_err()
        );
    }
    let kept = run(feed::read_selected_at(
        &f.store,
        &(),
        &f.basis,
        feed::SelectedHistoryLimits {
            events: 9,
            ..feed::SelectedHistoryLimits::DEFAULT
        },
        &selected,
        &|| false,
    ))
    .unwrap();
    assert_eq!(kept.events.len(), 9);
    assert!(
        kept.events
            .windows(2)
            .all(|pair| pair[0].cursor < pair[1].cursor)
    );
}

#[test]
fn publication_revalidation_requires_both_current_refs_and_keeps_preferences_self_owned() {
    let mut f = Fixture::new();
    f.append(
        vec![lifecycle(
            GitHashAlgorithm::Sha1,
            1,
            1,
            PullRequestAction::Open,
        )],
        1,
    );
    f.append(
        vec![preference(
            1,
            0,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        )],
        1,
    );
    let thread = f.source(1).unwrap().remove(0);
    let command = preference(1, 1, NotificationAction::SetReadThrough(Some(version(1))));
    let check = |snapshot: &crate::AdmissionSnapshot, event: &ForgeEvent| {
        super::super::super::validate_current_thread_disclosure(Some(&thread), snapshot, event)
    };
    assert_eq!(
        check(&crate::AdmissionSnapshot::default(), &command),
        Ok(())
    );
    for hidden in [
        b"refs/heads/topic".as_slice(),
        b"refs/heads/main".as_slice(),
    ] {
        let mut current = crate::AdmissionSnapshot::default();
        current
            .hidden_refs
            .push_rule(hidden, &fgit_wire::WireLimits::default())
            .unwrap();
        assert_eq!(
            check(&current, &command),
            Err(RefusalCode::HiddenRefUnauthorized)
        );
        let mut unhide = b"!".to_vec();
        unhide.extend_from_slice(hidden);
        current
            .hidden_refs
            .push_rule(&unhide, &fgit_wire::WireLimits::default())
            .unwrap();
        assert_eq!(check(&current, &command), Ok(()), "current permitted twin");
    }
    let other = preference(2, 1, NotificationAction::SetReadThrough(Some(version(1))));
    assert!(check(&crate::AdmissionSnapshot::default(), &other).is_err());
    assert!(f.source(2).unwrap()[0].preference.is_none());
    assert_eq!(
        f.source(1).unwrap()[0],
        thread,
        "validation cannot publish or change a preference"
    );
}

#[test]
fn shared_preparation_accepts_the_complete_activity_prefix_but_not_unrelated_stream_positions() {
    use crate::merge::prepare::{NativeMergeBasis, prepare_event};
    let format = GitHashAlgorithm::Sha1;
    let mut f = Fixture::new();
    for (event, who) in [
        (lifecycle(format, 1, 1, PullRequestAction::Open), 1),
        (comment(1, 2), 2),
        (review(format, 3, 1, 1), 3),
        (review(format, 3, 2, 1), 3),
        (review(format, 4, 1, 1), 4),
        (
            preference(1, 0, NotificationAction::SetMode(NotificationMode::Muted)),
            1,
        ),
    ] {
        f.append(vec![event], who);
    }
    let mut unrelated = lifecycle(format, 1, 1, PullRequestAction::Open);
    unrelated.aggregate = AggregateId::PullRequest(PullRequestNumber::try_new(2).unwrap());
    f.append(vec![unrelated], 1);
    let mut unrelated = comment(1, 2);
    unrelated.aggregate =
        AggregateId::PullRequestConversation(PullRequestNumber::try_new(2).unwrap());
    f.append(vec![unrelated], 2);
    assert_eq!(f.source(1).unwrap()[0].subject.version(), version(5));
    let context = f.context(1);
    let resolved = NativeMergeBasis {
        refs: crate::CanonicalRefState::default(),
        root_layout: fgit_types::RootLayoutVersion::LegacyWholeBody,
        forge: f.forge.clone(),
        outbox: f.outbox.clone(),
    };
    let closure = crate::ValidatedClosure {
        object_closure_root: crate::permitted_object_closure_root(
            &crate::PermittedObjectClosure::default(),
        )
        .unwrap(),
        objects: BTreeSet::new(),
    };
    let prepare = |through| {
        let command = NotificationCommand {
            target: NotificationTarget::PullRequest(PullRequestNumber::FIRST),
            expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
            action: NotificationAction::SetReadThrough(Some(version(through))),
        };
        let (event, attempt) = super::super::super::proposal(&context, &command).unwrap();
        let tx = attempt.derive().unwrap().0;
        prepare_event(
            &context, &event, &closure, tx, &attempt, &f.basis, &resolved,
        )
    };
    let prepared = prepare(5).unwrap();
    assert_eq!(prepared.refs, resolved.refs);
    assert_eq!(prepared.event.events.len(), 1);
    assert_eq!(prepared.event.events[0].version, version(2));
    assert_eq!(
        prepared.materialization.record.resulting_ref_root,
        f.basis.body().ref_root
    );
    assert!(matches!(prepare(6), Err(RefusalCode::EvidenceStale)));
}

#[test]
fn anchored_comment_activity_requires_both_retained_refs_to_match_the_native_pr() {
    use fgit_forge::event::pull_request_comment::{
        SourceCommentAnchor, SourceCommentComparison, SourceCommentSide,
    };
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for wrong_source in [true, false] {
            let mut f = Fixture::new();
            f.append(vec![lifecycle(format, 1, 1, PullRequestAction::Open)], 1);
            let basis = data(format);
            let anchor = SourceCommentAnchor {
                pull_request_version: AggregateVersion::FIRST,
                source_ref: basis.source_ref,
                target_ref: basis.target_ref,
                source_tip: basis.source_tip,
                target_tip: basis.target_tip,
                compared_base: basis.target_tip,
                comparison: SourceCommentComparison::Direct,
                path: b"file.rs".to_vec(),
                side: SourceCommentSide::After,
                blob: GitOid::from_hex(format, &"c".repeat(format.digest_len() * 2)).unwrap(),
                mode: 0o100644,
                byte_start: 0,
                byte_end: 4,
                line_start: 0,
                line_count: 1,
            };
            let mut permitted = comment(1, 2);
            let ForgeEventPayload::PullRequestCommentedNative(change) = &mut permitted.payload
            else {
                unreachable!()
            };
            change.anchor = Some(anchor);
            f.append(vec![permitted.clone()], 2);
            assert_eq!(f.source(1).unwrap()[0].subject.version(), version(2));
            assert!(f.source(2).unwrap()[0].participated);

            let mut forged = permitted;
            forged.version = version(2);
            let ForgeEventPayload::PullRequestCommentedNative(change) = &mut forged.payload else {
                unreachable!()
            };
            let anchor = change.anchor.as_mut().unwrap();
            let foreign = RefName::try_new(b"refs/heads/foreign").unwrap();
            if wrong_source {
                anchor.source_ref = foreign;
            } else {
                anchor.target_ref = foreign;
            }
            // The standalone anchor remains well formed; the reader must
            // independently enforce its relationship to the native PR.
            anchor.validate().unwrap();
            f.append(vec![forged], 2);
            assert!(matches!(
                f.source(1),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceInvalid
                ))
            ));
        }
    }
}
