use super::*;
use crate::merge::prepare::{NativeMergeBasis, prepare_event};
use crate::{CanonicalRefState, permitted_object_closure_root};
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry,
    RepositoryAuthorityHeadBody,
};
use fgit_forge::{PullRequestNumber, QueueNumber};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, HeadGeneration, PolicyEpoch,
    PrincipalId, RefName, RegistryEpoch, RepositoryId, RootLayoutVersion, TenantId,
};
use std::collections::BTreeMap;

fn fixture() -> (AdmissionContext, QueueCommand) {
    let context = AdmissionContext {
        head_key: HeadKey::new(b"queue/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"queue-command".to_vec()).unwrap(),
        object_format: GitHashAlgorithm::Sha1,
    };
    let command = QueueCommand {
        number: QueueNumber::FIRST,
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        expected_version: ExpectedVersion::NewStream,
        action: QueueCommandAction::Enqueue {
            pull_request: PullRequestNumber::FIRST,
            expected_pull_request_version: AggregateVersion::FIRST,
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            head_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"11".repeat(20)).unwrap(),
            expected_target_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"22".repeat(20))
                .unwrap(),
            priority: 0,
        },
    };
    (context, command)
}

#[test]
fn queue_guards_are_sealed_even_when_canonical_event_bytes_are_identical() {
    let (context, command) = fixture();
    let (event, seal) = proposal(&context, &command).unwrap();
    assert_eq!(verify_event_seal(&context, &event, &seal).unwrap(), command);
    assert!(seal.request.ref_commands().is_empty());
    assert!(seal.request.atomic());
    let tx = seal.derive().unwrap().0;
    for change in 0..2 {
        let mut different = command.clone();
        let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            expected_target_tip,
            ..
        } = &mut different.action
        else {
            unreachable!()
        };
        if change == 0 {
            *expected_pull_request_version = AggregateVersion::try_new(2).unwrap();
        } else {
            *expected_target_tip =
                GitOid::from_hex(GitHashAlgorithm::Sha1, &"33".repeat(20)).unwrap();
        }
        let (same_event, different_seal) = proposal(&context, &different).unwrap();
        assert_eq!(same_event, event);
        assert_ne!(different_seal.derive().unwrap().0, tx);
        assert_eq!(
            verify_event_seal(&context, &event, &different_seal).unwrap(),
            different
        );
    }
    let mut actor = context.clone();
    actor.principal_id = PrincipalId::from_bytes([9; 16]);
    assert_ne!(
        proposal(&actor, &command).unwrap().1.derive().unwrap().0,
        tx
    );
    assert_eq!(
        verify_event_seal(&actor, &event, &seal),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn fold_boundary_refuses_extra_or_missing_guards_and_batch_event_substitution() {
    let (context, command) = fixture();
    let (event, original) = proposal(&context, &command).unwrap();
    for remove in [true, false] {
        let mut seal = original.clone();
        let mut entries = seal.request.scoped_entries().to_vec();
        if remove {
            entries.pop();
        } else {
            entries.push(
                ScopedEntry::new(
                    AsciiSlug::from_static("forge"),
                    AsciiSlug::from_static("queue.extra"),
                    vec![1],
                )
                .unwrap(),
            );
        }
        seal.request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            vec![],
            vec![],
            entries,
        )
        .unwrap();
        assert_eq!(
            verify_event_seal(&context, &event, &seal),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
    let mut changed = event.clone();
    let ForgeEventPayload::MergeQueueChangedNative(change) = &mut changed.payload else {
        unreachable!()
    };
    change.action = fgit_forge::event::queue::QueueAction::BatchFormed {
        batch_id: storage::root(&event).unwrap(),
        entries: vec![PullRequestNumber::FIRST],
    };
    assert_eq!(
        verify_event_seal(&context, &changed, &original),
        Err(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn malformed_new_stream_and_reorder_requests_never_become_seals() {
    let (context, mut command) = fixture();
    command.action = QueueCommandAction::Reorder { order: vec![] };
    assert!(proposal(&context, &command).is_err());
    command.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
    command.action = QueueCommandAction::Reorder {
        order: vec![PullRequestNumber::FIRST, PullRequestNumber::FIRST],
    };
    assert!(proposal(&context, &command).is_err());
    command.action = QueueCommandAction::Reorder {
        order: vec![PullRequestNumber::FIRST],
    };
    let (event, seal) = proposal(&context, &command).unwrap();
    assert_eq!(verify_event_seal(&context, &event, &seal).unwrap(), command);
}

// These are pure preparation fixtures. Native node tests authenticate the
// selected event bodies, PR lifecycle, caller capabilities and visibility.
fn fold_fixture(
    format: GitHashAlgorithm,
) -> (
    AdmissionContext,
    QueueCommand,
    NativeMergeBasis,
    PublicationBasis,
    ValidatedClosure,
) {
    let (mut context, mut command) = fixture();
    context.object_format = format;
    let QueueCommandAction::Enqueue {
        source_ref,
        head_tip,
        expected_target_tip,
        ..
    } = &mut command.action
    else {
        unreachable!()
    };
    *head_tip = GitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap();
    *expected_target_tip = GitOid::from_hex(format, &"22".repeat(format.digest_len())).unwrap();
    let digest = |value| {
        Digest::new(
            DigestAlgorithmId::try_new(2).unwrap(),
            DigestBytes::try_new(&[value; 32]).unwrap(),
        )
    };
    let resolved = NativeMergeBasis {
        refs: CanonicalRefState::new(BTreeMap::from([
            (source_ref.clone(), *head_tip),
            (command.target_ref.clone(), *expected_target_tip),
        ])),
        root_layout: RootLayoutVersion::LegacyWholeBody,
        forge: CanonicalForgePositionState::try_new(
            context.repository_id,
            vec![
                ForgePositionStateEntry::try_new(
                    AsciiSlug::from_static("pull-request/1"),
                    0,
                    1,
                    digest(9),
                )
                .unwrap(),
            ],
        )
        .unwrap(),
        outbox: CanonicalOutboxState::try_new(context.repository_id, Vec::new()).unwrap(),
    };
    let head = RepositoryAuthorityHeadBody {
        repository_id: context.repository_id,
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: crate::ref_state_root(resolved.root_layout, &resolved.refs).unwrap(),
        forge_position_root: storage::root(&resolved.forge).unwrap(),
        outcome_index_root: digest(10),
        retention_root: digest(11),
        outbox_root: storage::root(&resolved.outbox).unwrap(),
        configuration_root: digest(12),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    );
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::default())
            .unwrap(),
        objects: BTreeSet::new(),
    };
    (context, command, resolved, basis, closure)
}

#[test]
fn actual_queue_fold_advances_only_its_stream_and_outbox_in_both_native_hash_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, resolved, basis, closure) = fold_fixture(format);
        let (event, seal) = proposal(&context, &command).unwrap();
        let tx = seal.derive().unwrap().0;
        let prepared =
            prepare_event(&context, &event, &closure, tx, &seal, &basis, &resolved).unwrap();
        assert_eq!(prepared.refs, resolved.refs);
        assert_eq!(
            prepared.materialization.roots.ref_root,
            basis.body().ref_root
        );
        assert_eq!(
            prepared.materialization.roots.retention_root,
            basis.body().retention_root
        );
        assert_eq!(
            prepared.materialization.roots.policy_epoch,
            basis.body().policy_epoch
        );
        let effects = prepared.fold.effects().unwrap();
        assert!(effects.refs.is_empty() && effects.retention.is_empty());
        assert_eq!(effects.forge.len(), 1);
        let kind = effects.forge.values().next().unwrap();
        assert!(
            matches!(kind.as_slice(), [fgit_reference::intent::ForgeEventKind::MergeQueueChanged { queue, target }]
            if queue.label().as_str() == "queue/1" && target == &command.target_ref)
        );
        assert_eq!(
            prepared
                .forge
                .entry(AsciiSlug::from_static("pull-request/1")),
            resolved
                .forge
                .entry(AsciiSlug::from_static("pull-request/1"))
        );
        assert_eq!(prepared.event.events, vec![event]);
        assert_eq!(prepared.outbox.entries().len(), 1);
        let delivery = &prepared.outbox.entries()[0];
        assert_eq!(delivery.tx_id(), tx);
        assert_eq!(
            delivery.payload_root(),
            storage::root(&prepared.event).unwrap()
        );
        assert_eq!(
            prepared.materialization.record.forge_event_batch_root,
            delivery.payload_root()
        );
        assert!(prepared.closure.objects().is_empty());
    }
}

#[test]
fn actual_fold_independently_checks_frozen_pr_and_target_guards() {
    let (context, command, resolved, basis, closure) = fold_fixture(GitHashAlgorithm::Sha1);
    let (original_event, _) = proposal(&context, &command).unwrap();
    for (change, expected) in [
        (0, RefusalCode::EvidenceStale),
        (1, RefusalCode::TargetRefMoved),
    ] {
        let mut command = command.clone();
        let QueueCommandAction::Enqueue {
            expected_pull_request_version,
            expected_target_tip,
            ..
        } = &mut command.action
        else {
            unreachable!()
        };
        if change == 0 {
            *expected_pull_request_version = AggregateVersion::try_new(2).unwrap();
        } else {
            *expected_target_tip =
                GitOid::from_hex(context.object_format, &"33".repeat(20)).unwrap();
        }
        let (event, seal) = proposal(&context, &command).unwrap();
        assert_eq!(event, original_event);
        assert_eq!(
            prepare_event(
                &context,
                &event,
                &closure,
                seal.derive().unwrap().0,
                &seal,
                &basis,
                &resolved,
            )
            .err(),
            Some(expected)
        );
    }
}

#[test]
fn actual_fold_refuses_forged_actor_landing_and_omitted_guard_even_with_recomputed_identity() {
    let (context, command, resolved, basis, closure) = fold_fixture(GitHashAlgorithm::Sha1);
    let (original_event, original_seal) = proposal(&context, &command).unwrap();
    for change in 0..3 {
        let mut event = original_event.clone();
        let mut seal = original_seal.clone();
        let ForgeEventPayload::MergeQueueChangedNative(queue) = &mut event.payload else {
            unreachable!()
        };
        match change {
            0 => {
                let fgit_forge::event::queue::QueueAction::Enqueue { enqueued_by, .. } =
                    &mut queue.action
                else {
                    unreachable!()
                };
                *enqueued_by = PrincipalId::from_bytes([99; 16]);
            }
            1 => {
                queue.action = fgit_forge::event::queue::QueueAction::BatchLanded {
                    batch_id: storage::root(&ForgeEventBatch::of_one(original_event.clone()))
                        .unwrap(),
                    entries: vec![PullRequestNumber::FIRST],
                    target_tip: GitOid::from_hex(context.object_format, &"33".repeat(20)).unwrap(),
                };
            }
            _ => {}
        }
        let event_root = storage::root(&ForgeEventBatch::of_one(event.clone())).unwrap();
        let mut guards = seal.request.scoped_entries().to_vec();
        for guard in &mut guards {
            if guard.key.as_str() == "queue.event-batch-root" {
                guard.value = event_root.bytes().as_bytes().to_vec();
            }
        }
        if change == 2 {
            guards.retain(|guard| guard.key.as_str() != "queue.expected-target-tip");
        }
        seal.request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            vec![],
            vec![],
            guards,
        )
        .unwrap();
        assert_eq!(
            prepare_event(
                &context,
                &event,
                &closure,
                seal.derive().unwrap().0,
                &seal,
                &basis,
                &resolved,
            )
            .err(),
            Some(RefusalCode::EvidenceInvalid)
        );
    }
}

#[test]
fn candidate_refusals_hide_legacy_versions_and_check_actual_native_visibility_first() {
    use fgit_forge::event::NativeMerge;
    use fgit_forge::event::pull_request::NativePullRequestEvent;
    let (context, command) = fixture();
    let QueueCommandAction::Enqueue {
        source_ref,
        head_tip,
        expected_target_tip,
        ..
    } = &command.action
    else {
        unreachable!()
    };
    let data = PullRequestData {
        source_ref: source_ref.clone(),
        target_ref: command.target_ref.clone(),
        source_tip: *head_tip,
        target_tip: *expected_target_tip,
        title: "candidate".into(),
        body: String::new(),
    };
    let legacy_digest = storage::root(&proposal(&context, &command).unwrap().0).unwrap();
    let legacy = ForgeEventPayload::PullRequestOpened {
        source_ref: source_ref.as_bytes().to_vec(),
        target_ref: command.target_ref.as_bytes().to_vec(),
        source_tip: legacy_digest,
        target_tip: legacy_digest,
    };
    let closed = ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
        action: PullRequestAction::Close,
        actor: context.principal_id,
        data: data.clone(),
    });
    let merged = ForgeEventPayload::MergeCommittedNative(NativeMerge {
        source_ref: source_ref.clone(),
        source_tip: *head_tip,
        base_tip: *expected_target_tip,
        target_ref: command.target_ref.clone(),
        target_tip_before: *expected_target_tip,
        merge_commit: GitOid::from_hex(context.object_format, &"33".repeat(20)).unwrap(),
    });
    for (payload, native) in [(legacy, false), (closed, true), (merged, true)] {
        let selected = ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
            version: AggregateVersion::try_new(2).unwrap(),
            payload,
        };
        for expected in [AggregateVersion::FIRST, selected.version] {
            assert_eq!(
                candidate_data(&selected, expected, &|_| false).err(),
                Some(RefusalCode::ProtectedRefTransitionDenied)
            );
            assert_eq!(
                candidate_data(&selected, expected, &|_| true).err(),
                Some(if native {
                    RefusalCode::HiddenRefUnauthorized
                } else {
                    RefusalCode::ProtectedRefTransitionDenied
                })
            );
        }
    }
    let opened = ForgeEvent {
        aggregate: AggregateId::PullRequest(PullRequestNumber::FIRST),
        version: AggregateVersion::FIRST,
        payload: ForgeEventPayload::PullRequestChangedNative(NativePullRequestEvent {
            action: PullRequestAction::Open,
            actor: context.principal_id,
            data: data.clone(),
        }),
    };
    assert_eq!(
        candidate_data(&opened, opened.version, &|_| false).unwrap(),
        &data
    );
    assert_eq!(
        candidate_data(&opened, AggregateVersion::try_new(2).unwrap(), &|_| false).err(),
        Some(RefusalCode::EvidenceStale)
    );
    assert_eq!(
        candidate_data(&opened, AggregateVersion::try_new(2).unwrap(), &|name| {
            name == source_ref
        })
        .err(),
        Some(RefusalCode::HiddenRefUnauthorized)
    );
}
