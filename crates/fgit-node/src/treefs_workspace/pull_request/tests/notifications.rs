//! Real canonical hidden-ref policy reaches fresh and retained PR inbox reads.
use super::*;
use crate::treefs_workspace::{InboxSyncOutcome, NotificationInboxPage, NotificationReadRefusal};
use fgit_admission::merge::native::protection::publish_hidden_ref_policy_async;
use fgit_authority::read_repository_incarnation_configuration_async;
use fgit_codec::{DecodeLimits, HiddenRefPolicyBody, RepositoryAuthorityHeadBody, decode_body};
use fgit_forge::IssueNumber;
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::event::notification::{
    NotificationAction, NotificationCommand, NotificationTarget, NotificationTargetKind,
};

fn inbox(
    node: &OneNode,
    expected: Option<RepositoryAuthorityHeadId>,
    single: bool,
) -> Result<NotificationInboxPage, NotificationReadRefusal> {
    let request = node.request_context();
    let reader = session("notification-read");
    if single {
        node.runtime().block_on(node.read_notification_target_in(
            &request,
            &reader,
            NotificationTarget::PullRequest(PullRequestNumber::FIRST),
            expected,
        ))
    } else {
        node.runtime()
            .block_on(node.read_notification_inbox_for_kind_in(
                &request,
                &reader,
                NotificationTargetKind::PullRequest,
                0,
                100,
                expected,
                false,
                false,
            ))
    }
}

/// Like hidden_ref_policy_end_to_end, stage actual canonical bodies and select
/// the configuration with an authenticated 1-decision policy-epoch advance.
/// All existing committed source/forge roots are carried forward unchanged.
pub(super) fn hide(node: &OneNode, reference: &RefName) -> RepositoryAuthorityHeadId {
    let request = node.request_context();
    node.runtime().block_on(async {
        let authenticated = node.authenticate_authority_head_in(&request).await.unwrap();
        let receipt = authenticated.receipt();
        let prior: RepositoryAuthorityHeadBody =
            decode_body(receipt.body(), DecodeLimits::DEFAULT).unwrap();
        let original = read_repository_incarnation_configuration_async(
            &node.authority,
            request.authority(),
            &prior.configuration_root,
        )
        .await
        .unwrap();
        assert!(original.policy_root.is_none());
        let policy = HiddenRefPolicyBody {
            rules: vec![reference.as_bytes().to_vec()],
        };
        let head_id = publish_hidden_ref_policy_async(
            &node.authority,
            request.authority(),
            &node.head_key,
            node.tenant_id,
            Some(&policy),
            fgit_codec::harness::tx_id(),
        )
        .await
        .unwrap();
        let selected = node.materialize_admission_in(&request).await.unwrap();
        assert_eq!(selected.basis().id(), head_id);
        assert!(selected.snapshot().hidden_refs.hides(reference.as_bytes()));
        selected.basis().id()
    })
}

fn advance_with_issue(node: &OneNode) {
    let request = node.request_context();
    accepted(node.runtime().block_on(node.admit_issue_durable_in(
        &request,
        &session("advance-hidden-inbox"),
        &IssueCommand {
            number: IssueNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: IssueAction::Open {
                title: "Independent visible issue".into(),
                body: String::new(),
                labels: Vec::new(),
            },
        },
        AdmissionLimits::default(),
    )));
}

fn assert_hidden(
    node: &OneNode,
    visible_head: RepositoryAuthorityHeadId,
    retained_hidden_head: RepositoryAuthorityHeadId,
) {
    let before = snapshot(node);
    for single in [false, true] {
        let fresh = inbox(node, None, single).unwrap();
        assert!(fresh.threads.is_empty());
        assert_eq!(fresh.next_after, None);
        assert_eq!(fresh.binding.authority_head, before.basis().id());
        let retained = inbox(node, Some(retained_hidden_head), single).unwrap();
        assert!(retained.threads.is_empty());
        assert_eq!(retained.next_after, None);
        assert_eq!(retained.binding.authority_head, retained_hidden_head);
        assert!(matches!(
            inbox(node, Some(visible_head), single),
            Err(NotificationReadRefusal::SnapshotMoved)
        ));
    }
    assert_eq!(
        snapshot(node).basis(),
        before.basis(),
        "reads cannot publish"
    );
}

#[test]
fn current_source_or_target_policy_hides_fresh_and_retained_pull_request_notifications() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for hidden in [source_ref(), target()] {
            let scratch = Scratch::new();
            let node = node(&scratch, format);
            let fixture = fixture(&node, &scratch, format);
            accepted(apply(&node, &command(&fixture, 1), "open-inbox-subject"));
            let visible = inbox(&node, None, false).unwrap();
            assert_eq!(visible.threads.len(), 1, "visible positive twin");
            assert_eq!(visible.threads[0].title, fixture.data.title);
            assert_eq!(inbox(&node, None, true).unwrap().threads.len(), 1);
            let original = snapshot(&node);
            let hidden_head = hide(&node, &hidden);
            assert_ne!(hidden_head, visible.binding.authority_head);
            let hidden_snapshot = snapshot(&node);
            assert_eq!(hidden_snapshot.snapshot().refs, original.snapshot().refs);
            assert_eq!(
                hidden_snapshot.basis().body().forge_position_root,
                original.basis().body().forge_position_root,
                "the PR still exists at exactly its original frontier"
            );
            assert_hidden(&node, visible.binding.authority_head, hidden_head);
            advance_with_issue(&node);
            let current = snapshot(&node).basis().id();
            assert_ne!(current, hidden_head);
            assert_hidden(&node, visible.binding.authority_head, hidden_head);
            node.shutdown().unwrap();

            let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
            let head = reopened
                .runtime()
                .block_on(reopened.authenticate_authority_head())
                .unwrap();
            reopened
                .bring_into_service(head.receipt().generation())
                .unwrap();
            assert_hidden(&reopened, visible.binding.authority_head, hidden_head);
            assert_eq!(snapshot(&reopened).basis().id(), current);
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn retarget_keeps_old_target_disclosure_on_inbox_reads_and_preferences() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let node = node(&scratch, format);
        let fixture = fixture(&node, &scratch, format);
        let request = node.request_context();
        let release = RefName::try_new(b"refs/heads/release").unwrap();
        let created = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &request,
                &session("inbox-release-branch"),
                &[fgit_authority::RefCommand {
                    name: release.clone(),
                    expected_old: fgit_authority::ExpectedOld::Absent,
                    proposed_new: fgit_authority::ProposedNew::Update(fixture.data.target_tip),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            created.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let open = command(&fixture, 1);
        accepted(apply(&node, &open, "open-retarget-inbox"));
        let mut changed = open.clone();
        changed.action = PullRequestAction::Retarget;
        changed.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        changed.data.target_ref = release.clone();
        accepted(apply(&node, &changed, "change-inbox-target"));
        let visible = inbox(&node, None, false).unwrap();
        assert_eq!(visible.threads.len(), 1, "visible retargeted positive twin");
        assert_eq!(visible.threads[0].thread_version.get(), 2);
        let hidden_head = hide(&node, &target());
        let before = snapshot(&node);
        assert!(!before.snapshot().hidden_refs.hides(source_ref().as_bytes()));
        assert!(!before.snapshot().hidden_refs.hides(release.as_bytes()));
        assert_hidden(&node, visible.binding.authority_head, hidden_head);
        let refused = node
            .runtime()
            .block_on(node.admit_notification_durable_in(
                &request,
                &session("mark-hidden-retarget-inbox"),
                &NotificationCommand {
                    target: NotificationTarget::PullRequest(open.number),
                    expected_version: ExpectedVersion::NewStream,
                    action: NotificationAction::SetReadThrough(Some(
                        AggregateVersion::try_new(2).unwrap(),
                    )),
                },
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            refused.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::HiddenRefUnauthorized,
                ..
            }
        ));
        assert_eq!(before.snapshot().refs, snapshot(&node).snapshot().refs);
        assert_eq!(
            before.basis().body().forge_position_root,
            snapshot(&node).basis().body().forge_position_root
        );
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        let head = reopened
            .runtime()
            .block_on(reopened.authenticate_authority_head())
            .unwrap();
        reopened
            .bring_into_service(head.receipt().generation())
            .unwrap();
        assert_hidden(&reopened, visible.binding.authority_head, hidden_head);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn persisted_inbox_projection_reuses_watermark_invalidates_on_advance_and_rebuilds_after_corruption()
 {
    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1);
    for raw_number in 1..=3 {
        let number = IssueNumber::try_new(raw_number).unwrap();
        let request = node.request_context();
        accepted(node.runtime().block_on(node.admit_issue_durable_in(
            &request,
            &session(&format!("open-issue-{raw_number}")),
            &IssueCommand {
                number,
                expected_version: ExpectedVersion::NewStream,
                action: IssueAction::Open {
                    title: format!("Issue #{raw_number}"),
                    body: String::new(),
                    labels: Vec::new(),
                },
            },
            AdmissionLimits::default(),
        )));
    }

    let reader = session("inbox-reader-page-1");
    let principal = reader.authenticated_session().unwrap().principal_id();
    let projection_path =
        node.notification_inbox_projection_path(principal, NotificationTargetKind::Issue);
    assert!(
        projection_path.starts_with(node.storage_root().join("projections").join("inbox")),
        "projection file lives under <storage-root>/projections/inbox"
    );

    let request = node.request_context();
    let page_one = node
        .runtime()
        .block_on(node.read_notification_inbox_in(&request, &reader, 0, 2, None, false, false))
        .unwrap();
    assert_eq!(
        page_one.sync_outcome,
        Some(InboxSyncOutcome::InstalledGeneration)
    );
    assert_eq!(page_one.threads.len(), 2);
    assert_eq!(page_one.next_after, Some(2));
    assert!(projection_path.is_file(), "SQLite projection persisted");

    // Second page at the same head reuses the persisted watermark without rewriting rows.
    let page_two = node
        .runtime()
        .block_on(node.read_notification_inbox_in(
            &request,
            &reader,
            page_one.next_after.unwrap(),
            2,
            Some(page_one.binding.authority_head),
            false,
            false,
        ))
        .unwrap();
    assert_eq!(
        page_two.sync_outcome,
        Some(InboxSyncOutcome::ReusedWatermark)
    );
    assert_eq!(page_two.threads.len(), 1);
    assert_eq!(page_two.threads[0].target.number(), 3);
    assert_eq!(page_two.next_after, None);
    node.shutdown().unwrap();

    // Across node restart, the persisted watermark is still reused cleanly.
    let mut reopened = OneNode::open_existing(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    let head = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap();
    reopened
        .bring_into_service(head.receipt().generation())
        .unwrap();
    let request = reopened.request_context();
    let reused_after_restart = reopened
        .runtime()
        .block_on(reopened.read_notification_inbox_in(&request, &reader, 0, 10, None, false, false))
        .unwrap();
    assert_eq!(
        reused_after_restart.sync_outcome,
        Some(InboxSyncOutcome::ReusedWatermark)
    );
    assert_eq!(reused_after_restart.threads.len(), 3);

    // Advancing preference/forge state invalidates the watermark immediately.
    accepted(
        reopened
            .runtime()
            .block_on(reopened.admit_notification_durable_in(
                &request,
                &session("mark-issue-1-read"),
                &NotificationCommand {
                    target: NotificationTarget::Issue(IssueNumber::FIRST),
                    expected_version: ExpectedVersion::NewStream,
                    action: NotificationAction::SetReadThrough(Some(AggregateVersion::FIRST)),
                },
                AdmissionLimits::default(),
            )),
    );
    let after_preference = reopened
        .runtime()
        .block_on(reopened.read_notification_inbox_in(&request, &reader, 0, 10, None, false, false))
        .unwrap();
    assert_eq!(
        after_preference.sync_outcome,
        Some(InboxSyncOutcome::InstalledGeneration)
    );
    assert_eq!(
        after_preference.threads[0].read_through,
        Some(AggregateVersion::FIRST)
    );

    // Corrupting the on-disk SQLite file rebuilds cleanly from canonical authority.
    fs::write(&projection_path, b"corrupt-non-sqlite-projection-bytes").unwrap();
    let rebuilt = reopened
        .runtime()
        .block_on(reopened.read_notification_inbox_in(&request, &reader, 0, 10, None, false, false))
        .unwrap();
    assert_eq!(
        rebuilt.sync_outcome,
        Some(InboxSyncOutcome::InstalledGeneration)
    );
    assert_eq!(rebuilt.threads.len(), 3);
    assert_eq!(
        rebuilt.threads[0].read_through,
        Some(AggregateVersion::FIRST)
    );

    let reused_again = reopened
        .runtime()
        .block_on(reopened.read_notification_inbox_in(&request, &reader, 0, 10, None, false, false))
        .unwrap();
    assert_eq!(
        reused_again.sync_outcome,
        Some(InboxSyncOutcome::ReusedWatermark)
    );
    reopened.shutdown().unwrap();
}

#[test]
fn completed_recipient_and_kind_reads_leave_no_process_gates() {
    use crate::treefs_workspace::notifications::projection_gate_count_under;

    let scratch = Scratch::new();
    let node = node(&scratch, GitHashAlgorithm::Sha1);
    advance_with_issue(&node);
    let head = snapshot(&node).basis().id();
    for id in 1..=8 {
        let recipient = PrincipalId::from_bytes([id; 16]);
        let reader = LoopbackReceiveSession::authenticated(
            recipient,
            IdempotencyKey::new(b"read-inbox".to_vec()).unwrap(),
        );
        for kind in [
            NotificationTargetKind::Issue,
            NotificationTargetKind::Discussion,
            NotificationTargetKind::PullRequest,
        ] {
            let page = node
                .runtime()
                .block_on(node.read_notification_inbox_for_kind_in(
                    &node.request_context(),
                    &reader,
                    kind,
                    0,
                    10,
                    None,
                    false,
                    false,
                ))
                .unwrap();
            assert_eq!(page.binding.principal, recipient);
            assert_eq!(page.binding.authority_head, head);
            assert!(
                page.threads.is_empty(),
                "the issue belongs to a different principal"
            );
            assert!(
                node.notification_inbox_projection_path(recipient, kind)
                    .is_file()
            );
            assert_eq!(projection_gate_count_under(node.storage_root()), 0);
        }
    }
    assert_eq!(snapshot(&node).basis().id(), head);
    node.shutdown().unwrap();
}

#[test]
fn queued_reader_cancels_while_a_reopened_reader_rebuilds_the_same_file() {
    use crate::treefs_workspace::notifications::{
        projection_file_gate, projection_gate_count_under,
    };
    use std::time::{Duration, Instant};

    let scratch = Scratch::new();
    let first = node(&scratch, GitHashAlgorithm::Sha1);
    advance_with_issue(&first);
    let reader = session("read-shared-inbox");
    let read = |node: &OneNode, request: &crate::NodeRequestContext| {
        node.runtime()
            .block_on(node.read_notification_inbox_in(request, &reader, 0, 10, None, false, false))
    };
    let original = read(&first, &first.request_context()).unwrap();
    assert_eq!(original.threads.len(), 1);
    let mut reopened = OneNode::open_existing(scratch.config(GitHashAlgorithm::Sha1)).unwrap();
    let head = reopened
        .runtime()
        .block_on(reopened.authenticate_authority_head())
        .unwrap();
    reopened
        .bring_into_service(head.receipt().generation())
        .unwrap();

    let path = first.notification_inbox_projection_path(principal(), NotificationTargetKind::Issue);
    fs::write(&path, b"corrupt projection to rebuild").unwrap();
    let gate = projection_file_gate(&path);
    let cancelled = first.request_context();
    let rebuilt = std::thread::scope(|threads| {
        // Drop the holder before scoped joins, including on assertion failure.
        let holder = gate.try_lock_owned().unwrap();
        let cancelled_read = threads.spawn(|| read(&first, &cancelled));
        let next_read = threads.spawn(|| read(&reopened, &reopened.request_context()));
        let wait_for = |count| {
            let until = Instant::now() + Duration::from_secs(10);
            while gate.waiters() != count {
                assert!(
                    Instant::now() < until,
                    "expected {count} queued readers, observed {}",
                    gate.waiters()
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        wait_for(2);
        cancelled.cancel();
        wait_for(1);
        assert!(
            matches!(cancelled_read.join().unwrap(), Err(NotificationReadRefusal::Projection(error))
            if matches!(*error, fgit_projection::inbox::InboxError::Storage(fgit_projection::ProjectionError::Interrupted("inbox_acquire_projection_gate"))))
        );
        drop(holder);
        next_read.join().unwrap().unwrap()
    });
    drop(gate);
    assert_eq!(projection_gate_count_under(first.storage_root()), 0);
    assert_eq!(rebuilt.binding, original.binding);
    assert_eq!(rebuilt.threads[0].title, original.threads[0].title);
    assert_eq!(
        rebuilt.sync_outcome,
        Some(InboxSyncOutcome::InstalledGeneration)
    );
    let reused = read(&first, &first.request_context()).unwrap();
    assert_eq!(reused.binding, rebuilt.binding);
    assert_eq!(reused.sync_outcome, Some(InboxSyncOutcome::ReusedWatermark));
    assert_eq!(projection_gate_count_under(first.storage_root()), 0);
    assert_eq!(
        snapshot(&first).basis().id(),
        original.binding.authority_head
    );
    reopened.shutdown().unwrap();
    first.shutdown().unwrap();
}
