//! Real-driver tests of the notification read-model boundary. These are
//! mechanism tests; node/HTTP suites own end-to-end authentication evidence.

use std::future::Future;
use std::time::Duration;

use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, InternalObjectId};

use super::*;

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered digest code point"),
        DigestBytes::try_new(&[byte; 32]).expect("digest width"),
    )
}

fn head(byte: u8) -> RepositoryAuthorityHeadId {
    let digest = digest(byte);
    RepositoryAuthorityHeadId::from_internal_object_id(InternalObjectId::new(
        digest.algorithm(),
        RepositoryAuthorityHeadId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION,
        *digest.bytes(),
    ))
    .expect("head identity")
}

fn binding() -> InboxSnapshotBinding {
    InboxSnapshotBinding {
        kind: InboxKind::Issue,
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        authority_head: head(4),
        authority_head_generation: 7,
        forge_position_root: digest(5),
        outbox_root: digest(6),
        principal: PrincipalId::from_bytes([7; 16]),
    }
}

fn row(issue: u64) -> InboxRow {
    InboxRow {
        thread_number: issue,
        thread_version: 8,
        preference_version: None,
        read_through: None,
        latest_other_version: Some(7),
        reasons: vec![InboxReason::Author],
        muted: false,
    }
}

fn snapshot() -> InboxSnapshot {
    let mut authored = row(1);
    authored.reasons = vec![InboxReason::Participant, InboxReason::Author];
    let mut read = row(2);
    read.preference_version = Some(3);
    read.read_through = Some(7);
    read.reasons = vec![InboxReason::Assignee];
    let mut muted = row(3);
    muted.preference_version = Some(1);
    muted.reasons.clear();
    muted.muted = true;
    let mut subscribed = row(4);
    subscribed.preference_version = Some(2);
    subscribed.latest_other_version = None;
    subscribed.reasons = vec![InboxReason::Subscribed];
    InboxSnapshot {
        binding: binding(),
        rows: vec![subscribed, muted, read, authored],
    }
}

fn query(limit: u16) -> InboxQuery {
    InboxQuery {
        after_thread: None,
        limit: NonZeroU16::new(limit).expect("positive page"),
        unread_only: false,
        include_muted: false,
    }
}

fn run_case<F: Future<Output = Result<(), InboxError>>>(case: impl FnOnce(Cx) -> F) {
    let node = fgit_runtime::boot::RuntimeProfile::deterministic()
        .build()
        .expect("node");
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("runtime");
    let cx = node.request_cx(fgit_runtime::meter::BudgetClass::Request);
    runtime
        .block_on(case(cx))
        .expect("real SQLite inbox mechanism");
    assert!(
        runtime.shutdown_timeout(Duration::from_secs(5)),
        "runtime drains"
    );
}

fn thread_numbers(page: &InboxPage) -> Vec<u64> {
    page.rows.iter().map(|row| row.thread_number).collect()
}

#[test]
fn typed_snapshot_pages_reasons_read_state_and_mute_are_coherent() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        let first = session.read_page(&cx, &binding(), query(2)).await?;
        assert_eq!(thread_numbers(&first), [1, 2]);
        assert_eq!(first.next_thread, Some(2));
        assert_eq!(
            first.rows[0].reasons,
            [InboxReason::Author, InboxReason::Participant]
        );
        assert!(first.rows[0].unread());
        assert!(!first.rows[1].unread());
        assert_eq!(first.rows[1].preference_version, Some(3));
        assert_eq!(first.rows[1].thread_version, 8);

        let second = session
            .read_page(
                &cx,
                &binding(),
                InboxQuery {
                    after_thread: first.next_thread,
                    ..query(2)
                },
            )
            .await?;
        assert_eq!(thread_numbers(&second), [4]);
        assert_eq!(second.next_thread, None);
        assert!(!second.rows[0].unread(), "only own activity is not unread");

        let unread = session
            .read_page(
                &cx,
                &binding(),
                InboxQuery {
                    unread_only: true,
                    ..query(100)
                },
            )
            .await?;
        assert_eq!(thread_numbers(&unread), [1]);
        let with_muted = session
            .read_page(
                &cx,
                &binding(),
                InboxQuery {
                    unread_only: true,
                    include_muted: true,
                    ..query(100)
                },
            )
            .await?;
        assert_eq!(thread_numbers(&with_muted), [1, 3]);
        assert!(with_muted.rows[1].muted);
        assert!(with_muted.rows[1].reasons.is_empty());
        session.close(&cx).await
    });
}

#[test]
fn every_source_coordinate_and_the_recipient_must_match() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        let original = binding();
        let twins = [
            InboxSnapshotBinding {
                tenant: TenantId::from_bytes([21; 16]),
                ..original
            },
            InboxSnapshotBinding {
                repository: RepositoryId::from_bytes([22; 16]),
                ..original
            },
            InboxSnapshotBinding {
                incarnation: RepositoryIncarnationId::from_bytes([23; 16]),
                ..original
            },
            InboxSnapshotBinding {
                authority_head: head(24),
                ..original
            },
            InboxSnapshotBinding {
                authority_head_generation: 8,
                ..original
            },
            InboxSnapshotBinding {
                forge_position_root: digest(25),
                ..original
            },
            InboxSnapshotBinding {
                outbox_root: digest(26),
                ..original
            },
            InboxSnapshotBinding {
                principal: PrincipalId::from_bytes([27; 16]),
                ..original
            },
        ];
        for twin in twins {
            assert!(matches!(
                session.read_page(&cx, &twin, query(100)).await,
                Err(InboxError::Refusal(InboxRefusal::SourceMismatch))
            ));
            assert_eq!(
                thread_numbers(&session.read_page(&cx, &original, query(100)).await?),
                [1, 2, 4]
            );
        }
        session.close(&cx).await
    });
}

#[test]
fn identical_replay_and_fresh_rebuild_produce_the_same_complete_page() {
    run_case(|cx| async move {
        let mut first = InboxSession::open_memory()?;
        first.install_snapshot(&cx, snapshot()).await?;
        let all = InboxQuery {
            include_muted: true,
            ..query(100)
        };
        let expected = first.read_page(&cx, &binding(), all).await?;
        let mut reordered = snapshot();
        reordered.rows.reverse();
        first.install_snapshot(&cx, reordered.clone()).await?;
        assert_eq!(first.read_page(&cx, &binding(), all).await?, expected);
        first.close(&cx).await?;

        // The whole disposable database is gone. Only the verified source
        // input survives; rebuilding it restores precisely the same page.
        let mut rebuilt = InboxSession::open_memory()?;
        rebuilt.install_snapshot(&cx, reordered).await?;
        assert_eq!(rebuilt.read_page(&cx, &binding(), all).await?, expected);
        rebuilt.close(&cx).await
    });
}

#[test]
fn refused_input_or_conflicting_replay_preserves_the_installed_generation() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        let expected = session.read_page(&cx, &binding(), query(100)).await?;

        let mut duplicate = snapshot();
        duplicate.rows.push(row(1));
        assert!(matches!(
            session.install_snapshot(&cx, duplicate).await,
            Err(InboxError::Refusal(InboxRefusal::DuplicateThread(1)))
        ));

        let mut changed = snapshot();
        changed.rows[3].latest_other_version = Some(6);
        assert!(matches!(
            session.install_snapshot(&cx, changed).await,
            Err(InboxError::Refusal(InboxRefusal::SnapshotConflict))
        ));

        let mut unrelated = row(99);
        unrelated.reasons.clear();
        assert!(matches!(
            session
                .install_snapshot(
                    &cx,
                    InboxSnapshot {
                        binding: binding(),
                        rows: vec![unrelated]
                    }
                )
                .await,
            Err(InboxError::Refusal(InboxRefusal::InvalidField(
                "unrelated_thread"
            )))
        ));
        assert_eq!(
            session.read_page(&cx, &binding(), query(100)).await?,
            expected
        );
        session.close(&cx).await
    });
}

#[test]
fn missing_rows_or_a_stored_foreign_recipient_never_pass_the_complete_gate() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        // Simulate local derived-state loss. The complete marker is retained.
        flatten(
            session
                .connection
                .execute(&cx, &store::delete::<StoredThread>(), &[])
                .await,
            "test_inbox_row_loss",
        )?;
        assert!(matches!(
            session.read_page(&cx, &binding(), query(100)).await,
            Err(InboxError::Refusal(InboxRefusal::IncompleteSnapshot))
        ));
        session.close(&cx).await?;

        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        let mut foreign = snapshot();
        foreign.binding.principal = PrincipalId::from_bytes([99; 16]);
        let foreign = StoredInbox::from_snapshot(&foreign)?;
        let (statement, params) = store::insert(&foreign);
        flatten(
            session
                .connection
                .execute(&cx, &store::delete::<StoredInbox>(), &[])
                .await,
            "test_remove_inbox_marker",
        )?;
        flatten(
            session.connection.execute(&cx, &statement, &params).await,
            "test_foreign_inbox_marker",
        )?;
        assert!(matches!(
            session.read_page(&cx, &binding(), query(100)).await,
            Err(InboxError::Refusal(InboxRefusal::SourceMismatch))
        ));
        session.close(&cx).await
    });
}

#[test]
fn empty_snapshot_has_a_real_marker_and_limits_refuse_before_disclosure() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        assert!(matches!(
            session.read_page(&cx, &binding(), query(100)).await,
            Err(InboxError::Refusal(InboxRefusal::SnapshotMissing))
        ));
        session
            .install_snapshot(
                &cx,
                InboxSnapshot {
                    binding: binding(),
                    rows: Vec::new(),
                },
            )
            .await?;
        let page = session.read_page(&cx, &binding(), query(100)).await?;
        assert!(page.rows.is_empty());
        assert_eq!(page.binding, binding());
        assert_eq!(page.next_thread, None);
        assert!(matches!(
            session.read_page(&cx, &binding(), query(101)).await,
            Err(InboxError::Refusal(InboxRefusal::PageLimit { .. }))
        ));
        assert!(matches!(
            session
                .read_page(
                    &cx,
                    &binding(),
                    InboxQuery {
                        after_thread: Some(u64::MAX),
                        ..query(1)
                    }
                )
                .await,
            Err(InboxError::Storage(ProjectionError::OutOfRange {
                field: "after_thread",
                ..
            }))
        ));
        session.close(&cx).await
    });
}

#[test]
fn cancelled_request_returns_no_page_and_explicitly_closes_its_worker() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        cx.set_cancel_requested(true);
        assert!(matches!(
            session.read_page(&cx, &binding(), query(100)).await,
            Err(InboxError::Storage(ProjectionError::Cancelled {
                step: "inbox_begin_read",
                ..
            }))
        ));
        // Closing is still awaited under the cancelled request context. The
        // driver closes its worker rather than starting another query.
        session.close(&cx).await
    });
}

#[test]
fn future_or_fabricated_preference_cursors_and_reason_sets_are_refused() {
    let mut offered = row(1);
    offered.latest_other_version = Some(9);
    assert!(matches!(
        offered.normalize(),
        Err(InboxError::Refusal(InboxRefusal::InvalidField(
            "latest_other_version"
        )))
    ));
    let mut offered = row(1);
    offered.read_through = Some(7);
    assert!(matches!(
        offered.normalize(),
        Err(InboxError::Refusal(InboxRefusal::InvalidField(
            "preference_version"
        )))
    ));
    let mut offered = row(1);
    offered.reasons.push(InboxReason::Author);
    assert!(matches!(
        offered.normalize(),
        Err(InboxError::Refusal(InboxRefusal::InvalidField(
            "duplicate_reason"
        )))
    ));
    let mut offered = row(1);
    offered.preference_version = Some(1);
    offered.muted = true;
    offered.reasons = vec![InboxReason::Subscribed];
    assert!(matches!(
        offered.normalize(),
        Err(InboxError::Refusal(InboxRefusal::InvalidField(
            "muted_subscription"
        )))
    ));
    let mut offered = row(1);
    offered.preference_version = Some(1);
    offered.read_through = Some(7);
    assert!(!offered.unread());
    offered.read_through = None;
    assert!(
        offered.unread(),
        "clearing the canonical cursor restores unread state"
    );
}

#[test]
fn identical_numbers_and_source_roots_cannot_cross_inbox_kinds() {
    run_case(|cx| async move {
        let mut session = InboxSession::open_memory()?;
        session.install_snapshot(&cx, snapshot()).await?;
        let mut discussion = binding();
        discussion.kind = InboxKind::Discussion;
        assert!(matches!(
            session.read_page(&cx, &discussion, query(10)).await,
            Err(InboxError::Refusal(InboxRefusal::SourceMismatch))
        ));
        let mut other = snapshot();
        other.binding = discussion;
        assert!(matches!(
            session.install_snapshot(&cx, other).await,
            Err(InboxError::Refusal(InboxRefusal::SourceMismatch))
        ));
        session.close(&cx).await?;
        let mut session = InboxSession::open_memory()?;
        let mut discussion_rows = snapshot();
        discussion_rows.binding = discussion;
        session.install_snapshot(&cx, discussion_rows).await?;
        let page = session.read_page(&cx, &discussion, query(10)).await?;
        assert_eq!(page.binding.kind, InboxKind::Discussion);
        assert_eq!(page.rows[0].thread_number, 1);
        assert!(page.rows[0].unread());
        session.close(&cx).await
    });
}

#[test]
fn pull_request_activity_prefix_is_kind_bound_and_rebuilds_with_the_same_unread_state() {
    run_case(|cx| async move {
        let mut pull_binding = binding();
        pull_binding.kind = InboxKind::PullRequest;
        let mut pull_rows = snapshot();
        pull_rows.binding = pull_binding;
        // Independent native lifecycle/comment/reviewer versions have already
        // been folded by the canonical reader into this observed activity prefix.
        pull_rows.rows[0].thread_version = 14;
        pull_rows.rows[0].latest_other_version = Some(13);
        pull_rows.rows[0].read_through = Some(12);
        let mut first = InboxSession::open_memory()?;
        first.install_snapshot(&cx, pull_rows.clone()).await?;
        let page = first.read_page(&cx, &pull_binding, query(100)).await?;
        for kind in [InboxKind::Issue, InboxKind::Discussion] {
            let other = InboxSnapshotBinding {
                kind,
                ..pull_binding
            };
            assert!(matches!(
                first.read_page(&cx, &other, query(100)).await,
                Err(InboxError::Refusal(InboxRefusal::SourceMismatch))
            ));
        }
        first.close(&cx).await?;
        let mut rebuilt = InboxSession::open_memory()?;
        rebuilt.install_snapshot(&cx, pull_rows).await?;
        assert_eq!(
            rebuilt.read_page(&cx, &pull_binding, query(100)).await?,
            page
        );
        assert_eq!(page.binding.kind.name(), "pull_request");
        let activity = page.rows.iter().find(|row| row.thread_number == 4).unwrap();
        assert_eq!(activity.thread_version, 14);
        assert_eq!(activity.read_through, Some(12));
        assert!(activity.unread());
        rebuilt.close(&cx).await
    });
}
