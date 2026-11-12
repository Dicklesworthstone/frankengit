//! Same-number subjects and owners remain separate at the canonical source.
use super::*;
use fgit_forge::DiscussionNumber;
use fgit_forge::event::discussion::{DiscussionAction, DiscussionCommand, DiscussionEdit};

fn discussion(number: u64, before: u64, who: u8, action: DiscussionAction) -> ForgeEvent {
    DiscussionCommand {
        number: DiscussionNumber::try_new(number).unwrap(),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(before).unwrap())
        },
        action,
    }
    .proposed_event(actor(who))
    .unwrap()
}
fn opened(number: u64, who: u8) -> ForgeEvent {
    discussion(
        number,
        0,
        who,
        DiscussionAction::Open {
            title: format!("Discussion {number}"),
            body: String::new(),
        },
    )
}
fn preference(number: u64, before: u64, who: u8, action: NotificationAction) -> ForgeEvent {
    NotificationCommand {
        target: NotificationTarget::Discussion(DiscussionNumber::try_new(number).unwrap()),
        expected_version: if before == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(AggregateVersion::try_new(before).unwrap())
        },
        action,
    }
    .proposed_event(actor(who))
    .unwrap()
}

#[test]
fn kind_and_owner_select_independent_preferences_and_complete_other_activity() {
    let events = vec![
        super::opened(2, 1),
        opened(10, 1),
        opened(2, 2),
        discussion(
            2,
            1,
            1,
            DiscussionAction::Comment {
                body: "Participating".into(),
            },
        ),
        discussion(
            2,
            2,
            2,
            DiscussionAction::Edit(DiscussionEdit {
                title: Some("Latest discussion title".into()),
                ..Default::default()
            }),
        ),
        discussion(2, 3, 3, DiscussionAction::Close),
        super::preference(
            2,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Muted),
        ),
        preference(
            2,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        ),
        preference(
            2,
            1,
            1,
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(3).unwrap())),
        ),
        preference(
            2,
            0,
            3,
            NotificationAction::SetMode(NotificationMode::Muted),
        ),
    ];
    let grouped = Fixture::new(vec![ForgeEventBatch {
        events: events.clone(),
    }]);
    let fixture = Fixture::new(events.into_iter().map(ForgeEventBatch::of_one).collect());
    let source = fixture
        .source_kind(1, NotificationTargetKind::Discussion)
        .unwrap();
    assert_eq!(source.kind, NotificationTargetKind::Discussion);
    assert_eq!(source.principal, actor(1));
    assert_eq!(source.source_head, fixture.basis.id());
    assert_eq!(source.forge_root, fixture.basis.body().forge_position_root);
    assert_eq!(source.outbox_root, fixture.basis.body().outbox_root);
    assert_eq!(
        grouped.source_kind(1, source.kind).unwrap().threads,
        source.threads
    );
    assert_eq!(
        source
            .threads
            .iter()
            .map(|thread| thread.subject.target().number())
            .collect::<Vec<_>>(),
        [2, 10]
    );
    let thread = &source.threads[0];
    assert_eq!(
        thread.subject.target(),
        NotificationTarget::Discussion(DiscussionNumber::try_new(2).unwrap())
    );
    assert_eq!(thread.subject.title(), "Latest discussion title");
    assert_eq!(thread.subject.opened_by(), actor(2));
    assert!(thread.subject.is_closed());
    assert!(!thread.subject.assigned_to(actor(1)));
    assert!(thread.participated);
    assert_eq!(thread.latest_other_version.unwrap().get(), 4);
    let preference = thread.preference.as_ref().unwrap();
    assert_eq!(preference.target, thread.subject.target());
    assert_eq!(preference.principal, actor(1));
    assert_eq!(preference.mode, NotificationMode::Subscribed);
    assert_eq!(preference.read_through.unwrap().get(), 3);
    assert!(source.threads[1].participated);
    assert_eq!(source.threads[1].latest_other_version, None);
    let issues = fixture.source(1).unwrap();
    assert_eq!(issues.kind, NotificationTargetKind::Issue);
    assert_eq!(issues.threads.len(), 1);
    assert_eq!(
        issues.threads[0].preference.as_ref().unwrap().mode,
        NotificationMode::Muted
    );
    assert_eq!(issues.threads[0].subject.title(), "Issue 2");
    let author = fixture.source_kind(2, source.kind).unwrap();
    assert!(author.threads[0].participated);
    assert!(author.threads[0].preference.is_none());
    let other = fixture.source_kind(3, source.kind).unwrap();
    assert!(!other.threads[0].participated);
    assert_eq!(other.threads[0].latest_other_version.unwrap().get(), 3);
    assert_eq!(
        other.threads[0].preference.as_ref().unwrap().mode,
        NotificationMode::Muted
    );
}

#[test]
fn exact_subject_and_preference_prefix_refuse_stale_cross_kind_and_cross_owner_updates() {
    let fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(opened(1, 1)),
        ForgeEventBatch::of_one(discussion(
            1,
            1,
            2,
            DiscussionAction::Comment {
                body: "Reply".into(),
            },
        )),
        ForgeEventBatch::of_one(preference(
            1,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        )),
    ]);
    let source = fixture
        .source_kind(1, NotificationTargetKind::Discussion)
        .unwrap();
    let thread = &source.threads[0];
    let validate =
        |event: ForgeEvent| super::super::super::validate_current_thread(Some(thread), &event);
    assert_eq!(
        validate(preference(
            1,
            1,
            1,
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(2).unwrap()))
        )),
        Ok(())
    );
    assert_eq!(
        validate(preference(
            1,
            1,
            1,
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(3).unwrap()))
        )),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        validate(preference(
            1,
            0,
            1,
            NotificationAction::SetReadThrough(None)
        )),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        validate(preference(
            1,
            1,
            2,
            NotificationAction::SetReadThrough(None)
        )),
        Err(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        validate(super::preference(
            1,
            1,
            1,
            NotificationAction::SetReadThrough(None)
        )),
        Err(RefusalCode::EvidenceInvalid)
    );
    assert_eq!(
        validate(preference(
            2,
            1,
            1,
            NotificationAction::SetReadThrough(None)
        )),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn discussion_replay_refuses_conflicting_or_missing_history_and_future_or_orphan_prefixes() {
    let first = opened(1, 2);
    let second = discussion(
        1,
        1,
        1,
        DiscussionAction::Comment {
            body: "reply".into(),
        },
    );
    let kind = NotificationTargetKind::Discussion;
    let mut fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(first.clone()),
        ForgeEventBatch::of_one(second.clone()),
    ]);
    let original = fixture.replay_kind(1, kind).unwrap();
    fixture.extra_payload(ForgeEventBatch {
        events: vec![first.clone(), second.clone()],
    });
    assert_eq!(fixture.replay_kind(1, kind).unwrap(), original);
    let mut conflict = first.clone();
    let ForgeEventPayload::DiscussionChangedNative(change) = &mut conflict.payload else {
        unreachable!()
    };
    let DiscussionAction::Open { title, .. } = &mut change.action else {
        unreachable!()
    };
    *title = "Different canonical history".into();
    fixture.extra_payload(ForgeEventBatch::of_one(conflict));
    assert!(fixture.replay_kind(1, kind).is_err());
    for (remove, recoverable) in [(first.clone(), false), (second.clone(), true)] {
        let mut fixture = Fixture::new(vec![
            ForgeEventBatch::of_one(first.clone()),
            ForgeEventBatch::of_one(second.clone()),
        ]);
        let root = storage::root(&ForgeEventBatch::of_one(remove)).unwrap();
        let entries = fixture
            .outbox
            .entries()
            .iter()
            .copied()
            .filter(|entry| entry.payload_root() != root)
            .collect();
        fixture.select_outbox(entries);
        if recoverable {
            assert_eq!(fixture.source_kind(1, kind).unwrap().threads, original);
        } else {
            assert!(matches!(
                fixture.source_kind(1, kind),
                Err(AdmissionError::AsyncProjectionUnavailable(
                    RefusalCode::EvidenceMissing
                ))
            ));
        }
    }
    for event in [
        preference(
            2,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        ),
        preference(
            1,
            0,
            1,
            NotificationAction::SetReadThrough(Some(AggregateVersion::try_new(2).unwrap())),
        ),
    ] {
        let fixture = Fixture::new(vec![
            ForgeEventBatch::of_one(super::opened(2, 1)),
            ForgeEventBatch::of_one(first.clone()),
            ForgeEventBatch::of_one(event),
        ]);
        assert!(fixture.source_kind(1, kind).is_err());
        // An issue with the same number cannot satisfy a discussion preference.
        // A valid issue-only read retains neither the discussion nor its preferences.
        assert_eq!(fixture.source(1).unwrap().threads.len(), 1);
    }
}

#[test]
fn cancellation_at_every_discussion_source_checkpoint_returns_no_partial_snapshot() {
    let fixture = Fixture::new(vec![
        ForgeEventBatch::of_one(opened(1, 2)),
        ForgeEventBatch::of_one(preference(
            1,
            0,
            1,
            NotificationAction::SetMode(NotificationMode::Subscribed),
        )),
    ]);
    use std::sync::atomic::{AtomicUsize, Ordering};
    let visits = AtomicUsize::new(0);
    run(read_source_for_kind_at(
        &fixture.store,
        &(),
        &fixture.basis,
        actor(1),
        NotificationTargetKind::Discussion,
        &|| {
            visits.fetch_add(1, Ordering::Relaxed);
            false
        },
    ))
    .unwrap();
    for stop in 1..=visits.load(Ordering::Relaxed) {
        let seen = AtomicUsize::new(0);
        assert!(
            run(read_source_for_kind_at(
                &fixture.store,
                &(),
                &fixture.basis,
                actor(1),
                NotificationTargetKind::Discussion,
                &|| { seen.fetch_add(1, Ordering::Relaxed) + 1 == stop }
            ))
            .is_err()
        );
    }
}
