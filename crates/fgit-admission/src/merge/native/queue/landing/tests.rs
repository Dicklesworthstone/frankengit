use super::*;
use crate::{CanonicalRefState, PermittedObjectClosure, permitted_object_closure_root};
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry,
    RepositoryAuthorityHeadBody,
};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, HeadGeneration, PrincipalId,
    RegistryEpoch, RepositoryId, RootLayoutVersion, TenantId,
};

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

fn fixture(
    format: GitHashAlgorithm,
) -> (
    AdmissionContext,
    QueueLandingCommand,
    NativeMergeBasis,
    PublicationBasis,
    ValidatedClosure,
) {
    let context = AdmissionContext {
        head_key: HeadKey::new(b"queue/landing/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"land-head".to_vec()).unwrap(),
        object_format: format,
    };
    let command = QueueLandingCommand {
        number: QueueNumber::FIRST,
        expected_version: AggregateVersion::try_new(5).unwrap(),
        expected_policy_epoch: PolicyEpoch::FIRST,
        pull_request: PullRequestNumber::FIRST,
        expected_pull_request_version: AggregateVersion::try_new(3).unwrap(),
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        head_tip: GitOid::from_hex(format, &"11".repeat(format.digest_len())).unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        expected_target_tip: GitOid::from_hex(format, &"22".repeat(format.digest_len())).unwrap(),
    };
    let resolved = NativeMergeBasis {
        refs: CanonicalRefState::new(BTreeMap::from([
            (command.source_ref.clone(), command.head_tip),
            (command.target_ref.clone(), command.expected_target_tip),
        ])),
        root_layout: RootLayoutVersion::LegacyWholeBody,
        forge: CanonicalForgePositionState::try_new(
            context.repository_id,
            vec![
                ForgePositionStateEntry::try_new(
                    AsciiSlug::from_static("queue/1"),
                    4,
                    1,
                    digest(8),
                )
                .unwrap(),
                ForgePositionStateEntry::try_new(
                    AsciiSlug::from_static("pull-request/1"),
                    2,
                    1,
                    digest(9),
                )
                .unwrap(),
            ],
        )
        .unwrap(),
        outbox: CanonicalOutboxState::try_new(context.repository_id, vec![]).unwrap(),
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
        policy_epoch: command.expected_policy_epoch,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    };
    let basis = PublicationBasis::new(
        fgit_authority::authority_head_identity(&head).unwrap(),
        head,
    );
    let objects = BTreeSet::from([command.head_tip, command.expected_target_tip]);
    let closure = ValidatedClosure {
        object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
            objects.clone(),
        ))
        .unwrap(),
        objects,
    };
    (context, command, resolved, basis, closure)
}

#[test]
fn landing_seal_freezes_both_streams_policy_candidate_actor_and_method() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, ..) = fixture(format);
        let (events, seal) = landing_proposal(&context, &command).unwrap();
        assert_eq!(
            events
                .events
                .iter()
                .map(|event| event.version.get())
                .collect::<Vec<_>>(),
            [6, 4, 7]
        );
        assert_eq!(validate_landing_shape(&events).unwrap(), &events.events[1]);
        assert_eq!(seal.request.ref_commands().len(), 1);
        assert!(!seal.request.ref_commands()[0].force);
        assert!(seal.request.atomic());
        let tx = seal.derive().unwrap().0;
        assert_ne!(
            command
                .intent()
                .unwrap()
                .seal_attempt(&context)
                .unwrap()
                .derive()
                .unwrap()
                .0,
            tx
        );
        for change in 0..8 {
            let mut changed = command.clone();
            match change {
                0 => changed.expected_version = changed.expected_version.next().unwrap(),
                1 => {
                    changed.expected_pull_request_version =
                        changed.expected_pull_request_version.next().unwrap()
                }
                2 => changed.expected_policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                3 => changed.number = QueueNumber::try_new(2).unwrap(),
                4 => changed.pull_request = PullRequestNumber::try_new(2).unwrap(),
                5 => changed.source_ref = RefName::try_new(b"refs/heads/other").unwrap(),
                6 => {
                    changed.head_tip =
                        GitOid::from_hex(format, &"33".repeat(format.digest_len())).unwrap()
                }
                _ => {
                    changed.expected_target_tip =
                        GitOid::from_hex(format, &"44".repeat(format.digest_len())).unwrap()
                }
            }
            assert_ne!(
                landing_proposal(&context, &changed)
                    .unwrap()
                    .1
                    .derive()
                    .unwrap()
                    .0,
                tx
            );
        }
        let mut actor = context;
        actor.principal_id = PrincipalId::from_bytes([9; 16]);
        assert_ne!(
            landing_proposal(&actor, &command)
                .unwrap()
                .1
                .derive()
                .unwrap()
                .0,
            tx
        );
    }
}

#[test]
fn landing_shared_fold_moves_one_ref_advances_both_streams_and_stages_one_delivery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, resolved, basis, closure) = fixture(format);
        let (events, seal) = landing_proposal(&context, &command).unwrap();
        let tx = seal.derive().unwrap().0;
        let prepared = prepare_landing(
            &context, &command, &events, &closure, tx, &seal, &basis, &resolved,
        )
        .unwrap();
        crate::merge::staging::validate_prepared(&prepared).unwrap();
        assert_eq!(
            prepared.refs.refs().get(&command.target_ref),
            Some(&command.head_tip)
        );
        assert_eq!(
            prepared.refs.refs().get(&command.source_ref),
            Some(&command.head_tip)
        );
        assert_eq!(
            prepared.fold.effects().unwrap().refs,
            BTreeMap::from([(command.target_ref.clone(), RefEffect::Set(command.head_tip))])
        );
        assert_eq!(prepared.fold.effects().unwrap().forge.len(), 2);
        assert!(prepared.fold.effects().unwrap().retention.is_empty());
        let root = storage::root(&events).unwrap();
        for (name, predecessor, count, successor) in
            [("queue/1", 5, 2, 7), ("pull-request/1", 3, 1, 4)]
        {
            let position = prepared.forge.entry(AsciiSlug::from_static(name)).unwrap();
            assert_eq!(position.predecessor_position(), predecessor);
            assert_eq!(position.event_count(), count);
            assert_eq!(position.successor_position(), successor);
            assert_eq!(position.event_batch_root(), root);
        }
        assert_eq!(prepared.outbox.entries().len(), 1);
        assert_eq!(prepared.outbox.entries()[0].payload_root(), root);
        assert_eq!(prepared.outbox.entries()[0].tx_id(), tx);
        assert_eq!(prepared.materialization.record.forge_event_batch_root, root);
        assert_eq!(
            prepared.materialization.roots.policy_epoch,
            basis.body().policy_epoch
        );
        assert_eq!(
            prepared.materialization.roots.retention_root,
            basis.body().retention_root
        );
        let mut evidence = prepared.evidence.clone();
        evidence
            .record_activated_policy(
                &context,
                &basis,
                &resolved.refs,
                resolved.root_layout,
                &prepared.fold,
                vec![],
                fgit_forge::event::protection::compile_ref_policy("policy p { default allow }")
                    .unwrap(),
                crate::evidence::RefPolicyPublication::NativeMerge,
            )
            .unwrap();
        evidence
            .verify_decision(&context, &basis, &prepared.request, &prepared.fold)
            .unwrap();
    }
}

#[test]
fn landing_shared_fold_rejects_changed_or_omitted_guards_and_event_substitution() {
    let (context, command, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha1);
    let (events, seal) = landing_proposal(&context, &command).unwrap();
    for change in 0..7 {
        let mut altered = events.clone();
        match change {
            0 => {
                altered.events.swap(0, 2);
            }
            1 => {
                altered.events.pop();
            }
            2 => {
                altered.events.push(events.events[1].clone());
            }
            3 => altered.events[2].version = altered.events[0].version,
            4 => altered.events[1].version = AggregateVersion::FIRST,
            5 => {
                let ForgeEventPayload::MergeQueueChangedNative(event) =
                    &mut altered.events[2].payload
                else {
                    unreachable!()
                };
                let QueueAction::BatchLanded { batch_id, .. } = &mut event.action else {
                    unreachable!()
                };
                *batch_id = digest(37);
            }
            _ => {
                let ForgeEventPayload::MergeQueueChangedNative(event) =
                    &mut altered.events[0].payload
                else {
                    unreachable!()
                };
                event.target_ref = RefName::try_new(b"refs/heads/other").unwrap();
            }
        }
        assert_eq!(
            validate_landing_shape(&altered).err(),
            Some(RefusalCode::EvidenceInvalid)
        );
        assert_eq!(
            prepare_landing(
                &context,
                &command,
                &altered,
                &closure,
                seal.derive().unwrap().0,
                &seal,
                &basis,
                &resolved
            )
            .err(),
            Some(RefusalCode::EvidenceInvalid)
        );
    }
    for remove in [false, true] {
        let mut altered = seal.clone();
        let mut entries = seal.request.scoped_entries().to_vec();
        if remove {
            entries.pop();
        } else {
            entries.push(
                ScopedEntry::new(
                    AsciiSlug::from_static("forge"),
                    AsciiSlug::from_static("queue.extra"),
                    b"1",
                )
                .unwrap(),
            );
        }
        altered.request = SemanticRequest::build(
            fgit_authority::RECEIVE_ADMISSION_SCHEMA,
            context.object_format,
            true,
            seal.request.ref_commands().to_vec(),
            vec![],
            entries,
        )
        .unwrap();
        assert_eq!(
            prepare_landing(
                &context,
                &command,
                &events,
                &closure,
                altered.derive().unwrap().0,
                &altered,
                &basis,
                &resolved
            )
            .err(),
            Some(RefusalCode::EvidenceInvalid)
        );
    }
    let mut actor = context.clone();
    actor.principal_id = PrincipalId::from_bytes([8; 16]);
    assert_eq!(
        prepare_landing(
            &actor,
            &command,
            &events,
            &closure,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        )
        .err(),
        Some(RefusalCode::EvidenceInvalid)
    );
}

#[test]
fn landing_shared_fold_checks_frozen_versions_policy_tips_and_object_closure() {
    let (context, command, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha256);
    for change in 0..5 {
        let mut altered = command.clone();
        match change {
            0 => altered.expected_version = AggregateVersion::try_new(6).unwrap(),
            1 => altered.expected_pull_request_version = AggregateVersion::try_new(4).unwrap(),
            2 => altered.expected_policy_epoch = PolicyEpoch::try_new(2).unwrap(),
            3 => {
                altered.head_tip =
                    GitOid::from_hex(context.object_format, &"33".repeat(32)).unwrap()
            }
            _ => {
                altered.expected_target_tip =
                    GitOid::from_hex(context.object_format, &"44".repeat(32)).unwrap()
            }
        }
        let (events, seal) = landing_proposal(&context, &altered).unwrap();
        assert_eq!(
            prepare_landing(
                &context,
                &altered,
                &events,
                &closure,
                seal.derive().unwrap().0,
                &seal,
                &basis,
                &resolved
            )
            .err(),
            Some(if change < 3 {
                RefusalCode::EvidenceStale
            } else {
                RefusalCode::TargetRefMoved
            })
        );
    }
    let (events, seal) = landing_proposal(&context, &command).unwrap();
    let mut missing = closure;
    missing.objects.remove(&command.expected_target_tip);
    missing.object_closure_root =
        permitted_object_closure_root(&PermittedObjectClosure::new(missing.objects.clone()))
            .unwrap();
    assert_eq!(
        prepare_landing(
            &context,
            &command,
            &events,
            &missing,
            seal.derive().unwrap().0,
            &seal,
            &basis,
            &resolved
        )
        .err(),
        Some(RefusalCode::ObjectClosureIncomplete)
    );
}

#[test]
fn staging_rejects_truncated_stream_ranges_and_policy_advances_in_a_landing() {
    let (context, command, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha1);
    let (events, seal) = landing_proposal(&context, &command).unwrap();
    let prepared = prepare_landing(
        &context,
        &command,
        &events,
        &closure,
        seal.derive().unwrap().0,
        &seal,
        &basis,
        &resolved,
    )
    .unwrap();
    for change in 0..4 {
        let mut invalid = prepared.clone();
        if change == 3 {
            invalid.materialization.roots.policy_epoch = PolicyEpoch::try_new(2).unwrap();
        } else {
            let mut positions = invalid.forge.entries().to_vec();
            if change == 0 {
                positions.retain(|position| position.stream().as_str() != "pull-request/1");
            } else {
                let position = positions
                    .iter_mut()
                    .find(|position| position.stream().as_str() == "queue/1")
                    .unwrap();
                *position = ForgePositionStateEntry::try_new(
                    position.stream(),
                    if change == 1 { 6 } else { 4 },
                    if change == 1 { 1 } else { 3 },
                    position.event_batch_root(),
                )
                .unwrap();
            }
            invalid.forge =
                CanonicalForgePositionState::try_new(context.repository_id, positions).unwrap();
            let root = storage::root(&invalid.forge).unwrap();
            invalid.materialization.roots.forge_position_root = root;
            invalid.materialization.record.resulting_forge_position_root = root;
        }
        assert!(crate::merge::staging::validate_prepared(&invalid).is_err());
    }
}

#[test]
fn landing_rejects_exhausted_queue_or_pr_versions_and_nonmoving_candidates() {
    let (context, command, ..) = fixture(GitHashAlgorithm::Sha1);
    for change in 0..4 {
        let mut changed = command.clone();
        match change {
            0 => changed.expected_version = AggregateVersion::try_new(u64::MAX - 1).unwrap(),
            1 => changed.expected_version = AggregateVersion::try_new(u64::MAX).unwrap(),
            2 => {
                changed.expected_pull_request_version = AggregateVersion::try_new(u64::MAX).unwrap()
            }
            _ => changed.head_tip = changed.expected_target_tip,
        }
        assert!(landing_proposal(&context, &changed).is_err());
    }
}
