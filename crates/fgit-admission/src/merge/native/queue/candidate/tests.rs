use super::*;
use crate::merge::native::NativeMergeMethod;
use crate::{CanonicalRefState, PermittedObjectClosure, permitted_object_closure_root};
use fgit_authority::{HeadKey, IdempotencyKey};
use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxState, ForgePositionStateEntry,
    RepositoryAuthorityHeadBody,
};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId,
    RefName, RegistryEpoch, RepositoryId, RootLayoutVersion, TenantId,
};
use std::collections::BTreeSet;

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

fn oid(format: GitHashAlgorithm, byte: u8) -> GitOid {
    GitOid::from_hex(format, &format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}

fn fixture(
    format: GitHashAlgorithm,
) -> (
    AdmissionContext,
    QueueCandidateLandingCommand,
    NativeMergeBasis,
    PublicationBasis,
    ValidatedClosure,
) {
    let context = AdmissionContext {
        head_key: HeadKey::new(b"queue/candidate/head".to_vec()).unwrap(),
        tenant_id: TenantId::from_bytes([1; 16]),
        repository_id: RepositoryId::from_bytes([2; 16]),
        principal_id: PrincipalId::from_bytes([3; 16]),
        idempotency_key: IdempotencyKey::new(b"land-exact-candidate".to_vec()).unwrap(),
        object_format: format,
    };
    let command = QueueCandidateLandingCommand {
        number: QueueNumber::FIRST,
        expected_version: AggregateVersion::try_new(5).unwrap(),
        expected_policy_epoch: PolicyEpoch::FIRST,
        pull_request: PullRequestNumber::FIRST,
        expected_pull_request_version: AggregateVersion::try_new(3).unwrap(),
        merge: NativeMerge {
            source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
            source_tip: oid(format, 0x11),
            base_tip: oid(format, 0x22),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            target_tip_before: oid(format, 0x33),
            merge_commit: oid(format, 0x44),
        },
    };
    let resolved = NativeMergeBasis {
        refs: CanonicalRefState::new(BTreeMap::from([
            (command.merge.source_ref.clone(), command.merge.source_tip),
            (
                command.merge.target_ref.clone(),
                command.merge.target_tip_before,
            ),
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
    let objects = BTreeSet::from([
        command.merge.source_tip,
        command.merge.base_tip,
        command.merge.target_tip_before,
        command.merge.merge_commit,
    ]);
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
fn candidate_seal_binds_every_guard_native_coordinate_actor_scope_and_method() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, ..) = fixture(format);
        let (events, seal) = candidate_landing_proposal(&context, &command).unwrap();
        let tx = seal.derive().unwrap().0;
        assert_eq!(
            command.intent().unwrap().method(),
            NativeMergeMethod::MergeCommit
        );
        assert_eq!(
            events
                .events
                .iter()
                .map(|event| event.version.get())
                .collect::<Vec<_>>(),
            [6, 4, 7]
        );
        assert_eq!(
            validate_candidate_landing_shape(&events).unwrap(),
            &events.events[1]
        );
        assert!(super::super::landing::validate_landing_shape(&events).is_err());
        assert_eq!(
            seal.request.ref_commands(),
            &[RefCommand {
                name: command.merge.target_ref.clone(),
                expected_old: ExpectedOld::Exactly(command.merge.target_tip_before),
                proposed_new: ProposedNew::Update(command.merge.merge_commit),
                force: false,
            }]
        );
        assert!(seal.request.atomic());
        assert!(
            seal.request
                .scoped_entries()
                .iter()
                .any(|entry| entry.key.as_str() == "queue.landing-profile"
                    && entry.value == b"two-parent-head/v1")
        );
        assert!(
            seal.request
                .scoped_entries()
                .iter()
                .any(|entry| entry.key.as_str() == "queue.landing-method"
                    && entry.value == b"merge-commit/v1")
        );
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
        for field in 0..11 {
            let mut changed = command.clone();
            match field {
                0 => changed.number = QueueNumber::try_new(2).unwrap(),
                1 => changed.expected_version = changed.expected_version.next().unwrap(),
                2 => changed.expected_policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                3 => changed.pull_request = PullRequestNumber::try_new(2).unwrap(),
                4 => {
                    changed.expected_pull_request_version =
                        changed.expected_pull_request_version.next().unwrap()
                }
                5 => {
                    changed.merge.source_ref = RefName::try_new(b"refs/heads/other-source").unwrap()
                }
                6 => changed.merge.source_tip = oid(format, 0x55),
                7 => changed.merge.base_tip = oid(format, 0x66),
                8 => {
                    changed.merge.target_ref = RefName::try_new(b"refs/heads/other-target").unwrap()
                }
                9 => changed.merge.target_tip_before = oid(format, 0x77),
                _ => changed.merge.merge_commit = oid(format, 0x88),
            }
            assert_ne!(
                candidate_landing_proposal(&context, &changed)
                    .unwrap()
                    .1
                    .derive()
                    .unwrap()
                    .0,
                tx,
                "field {field}"
            );
        }
        for field in 0..4 {
            let mut changed = context.clone();
            match field {
                0 => changed.principal_id = PrincipalId::from_bytes([9; 16]),
                1 => changed.tenant_id = TenantId::from_bytes([9; 16]),
                2 => changed.repository_id = RepositoryId::from_bytes([9; 16]),
                _ => {
                    changed.idempotency_key =
                        IdempotencyKey::new(b"different-request".to_vec()).unwrap()
                }
            }
            assert_ne!(
                candidate_landing_proposal(&changed, &command)
                    .unwrap()
                    .1
                    .derive()
                    .unwrap()
                    .0,
                tx
            );
        }
    }
}

#[test]
fn fast_forward_keeps_its_original_seal_without_candidate_profile_entries() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, candidate, ..) = fixture(format);
        let command = candidate.guards();
        let (events, actual) = super::super::landing_proposal(&context, &command).unwrap();
        let root = storage::root(&events).unwrap();
        // Freeze the complete historical semantic envelope: one non-force move,
        // no push options and precisely its original three required forge keys.
        let expected = SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request: SemanticRequest::build(
                fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                format,
                true,
                vec![RefCommand {
                    name: command.target_ref.clone(),
                    expected_old: ExpectedOld::Exactly(command.expected_target_tip),
                    proposed_new: ProposedNew::Update(command.head_tip),
                    force: false,
                }],
                vec![],
                vec![
                    ScopedEntry::new(
                        AsciiSlug::from_static("forge"),
                        AsciiSlug::from_static("queue.landing-event-batch-root"),
                        root.bytes().as_bytes(),
                    )
                    .unwrap(),
                    ScopedEntry::new(
                        AsciiSlug::from_static("forge"),
                        AsciiSlug::from_static("queue.landing-policy-epoch"),
                        command.expected_policy_epoch.get().to_be_bytes(),
                    )
                    .unwrap(),
                    ScopedEntry::new(
                        AsciiSlug::from_static("forge"),
                        AsciiSlug::from_static("queue.landing-profile"),
                        b"fast-forward-head/v1",
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        };
        assert_eq!(actual, expected);
        assert_eq!(actual.derive().unwrap(), expected.derive().unwrap());
        assert!(validate_candidate_landing_shape(&events).is_err());
        assert_ne!(
            candidate_landing_proposal(&context, &candidate)
                .unwrap()
                .1
                .derive()
                .unwrap()
                .0,
            actual.derive().unwrap().0
        );
    }
}

#[test]
fn candidate_fold_has_one_target_move_two_stream_advances_and_one_delivery() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, resolved, basis, closure) = fixture(format);
        let (events, seal) = candidate_landing_proposal(&context, &command).unwrap();
        let tx = seal.derive().unwrap().0;
        let prepared = prepare_candidate_landing(
            &context, &command, &events, &closure, tx, &seal, &basis, &resolved,
        )
        .unwrap();
        crate::merge::staging::validate_prepared(&prepared).unwrap();
        let root = storage::root(&events).unwrap();
        assert_eq!(
            prepared.refs.refs().get(&command.merge.target_ref),
            Some(&command.merge.merge_commit)
        );
        assert_eq!(
            prepared.refs.refs().get(&command.merge.source_ref),
            Some(&command.merge.source_tip)
        );
        assert_eq!(
            prepared.fold.effects().unwrap().refs,
            BTreeMap::from([(
                command.merge.target_ref.clone(),
                RefEffect::Set(command.merge.merge_commit)
            )])
        );
        assert_eq!(prepared.fold.effects().unwrap().forge.len(), 2);
        assert!(prepared.fold.effects().unwrap().retention.is_empty());
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
        assert_eq!(prepared.outbox.entries()[0].tx_id(), tx);
        assert_eq!(prepared.outbox.entries()[0].payload_root(), root);
        assert_eq!(prepared.materialization.record.forge_event_batch_root, root);
        assert_eq!(
            prepared.materialization.roots.policy_epoch,
            basis.body().policy_epoch
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
fn candidate_rejects_wrong_shape_extra_members_and_cross_profile_aliases() {
    let (context, command, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha1);
    let (events, seal) = candidate_landing_proposal(&context, &command).unwrap();
    for change in 0..12 {
        let mut altered = events.clone();
        match change {
            0 => altered.events.swap(0, 2),
            1 => {
                altered.events.pop();
            }
            2 => altered.events.push(events.events[1].clone()),
            3 => altered.events[1].version = AggregateVersion::FIRST,
            4 => altered.events[2].version = altered.events[0].version,
            5 => {
                altered.events[1].aggregate =
                    AggregateId::PullRequest(PullRequestNumber::try_new(2).unwrap())
            }
            6 => {
                let ForgeEventPayload::MergeQueueChangedNative(change) =
                    &mut altered.events[0].payload
                else {
                    unreachable!()
                };
                let QueueAction::BatchFormed { entries, .. } = &mut change.action else {
                    unreachable!()
                };
                entries.push(PullRequestNumber::try_new(2).unwrap());
            }
            7 => {
                let ForgeEventPayload::MergeQueueChangedNative(change) =
                    &mut altered.events[0].payload
                else {
                    unreachable!()
                };
                change.target_ref = RefName::try_new(b"refs/heads/other").unwrap();
            }
            8 => {
                let ForgeEventPayload::MergeQueueChangedNative(change) =
                    &mut altered.events[2].payload
                else {
                    unreachable!()
                };
                let QueueAction::BatchLanded { target_tip, .. } = &mut change.action else {
                    unreachable!()
                };
                *target_tip = command.merge.source_tip;
            }
            9 => {
                let ForgeEventPayload::MergeQueueChangedNative(change) =
                    &mut altered.events[2].payload
                else {
                    unreachable!()
                };
                let QueueAction::BatchLanded { batch_id, .. } = &mut change.action else {
                    unreachable!()
                };
                *batch_id = digest(30);
            }
            _ => {
                let ForgeEventPayload::MergeCommittedNative(merge) = &mut altered.events[1].payload
                else {
                    unreachable!()
                };
                if change == 10 {
                    merge.merge_commit = merge.source_tip;
                } else {
                    merge.base_tip = merge.merge_commit;
                }
            }
        }
        assert_eq!(
            validate_candidate_landing_shape(&altered).err(),
            Some(RefusalCode::EvidenceInvalid),
            "shape {change}"
        );
        assert_eq!(
            super::super::validate_publication_shape(&altered).err(),
            Some(RefusalCode::EvidenceInvalid),
            "staging shape {change}"
        );
        assert_eq!(
            prepare_candidate_landing(
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
}

#[test]
fn candidate_fold_refuses_every_changed_or_missing_seal_entry_and_ref_command() {
    let (context, command, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha256);
    let (events, seal) = candidate_landing_proposal(&context, &command).unwrap();
    for index in 0..seal.request.scoped_entries().len() {
        for remove in [false, true] {
            let mut entries = seal.request.scoped_entries().to_vec();
            if remove {
                entries.remove(index);
            } else {
                entries[index].value.push(0);
            }
            let mut altered = seal.clone();
            altered.request = SemanticRequest::build(
                seal.request.request_schema(),
                context.object_format,
                true,
                seal.request.ref_commands().to_vec(),
                vec![],
                entries,
            )
            .unwrap();
            assert_eq!(
                prepare_candidate_landing(
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
    }
    for change in 0..3 {
        let mut refs = seal.request.ref_commands().to_vec();
        match change {
            0 => refs[0].force = true,
            1 => refs[0].proposed_new = ProposedNew::Update(command.merge.source_tip),
            _ => refs[0].expected_old = ExpectedOld::Exactly(command.merge.base_tip),
        }
        let mut altered = seal.clone();
        altered.request = SemanticRequest::build(
            seal.request.request_schema(),
            context.object_format,
            true,
            refs,
            vec![],
            seal.request.scoped_entries().to_vec(),
        )
        .unwrap();
        assert_eq!(
            prepare_candidate_landing(
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
}

#[test]
fn candidate_fold_rechecks_stream_versions_policy_live_tips_and_all_native_roots() {
    let (context, command, resolved, basis, closure) = fixture(GitHashAlgorithm::Sha256);
    for change in 0..5 {
        let mut changed = command.clone();
        match change {
            0 => changed.expected_version = changed.expected_version.next().unwrap(),
            1 => {
                changed.expected_pull_request_version =
                    changed.expected_pull_request_version.next().unwrap()
            }
            2 => changed.expected_policy_epoch = PolicyEpoch::try_new(2).unwrap(),
            3 => changed.merge.source_tip = oid(context.object_format, 0x55),
            _ => changed.merge.target_tip_before = oid(context.object_format, 0x66),
        }
        let (events, seal) = candidate_landing_proposal(&context, &changed).unwrap();
        assert_eq!(
            prepare_candidate_landing(
                &context,
                &changed,
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
    let (events, seal) = candidate_landing_proposal(&context, &command).unwrap();
    for root in &closure.objects {
        let mut missing = closure.clone();
        missing.objects.remove(root);
        missing.object_closure_root =
            permitted_object_closure_root(&PermittedObjectClosure::new(missing.objects.clone()))
                .unwrap();
        assert_eq!(
            prepare_candidate_landing(
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
}

#[test]
fn candidate_proposal_refuses_aliases_exhaustion_zero_and_mixed_hashes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, ..) = fixture(format);
        for change in 0..10 {
            let mut changed = command.clone();
            match change {
                0 => changed.expected_version = AggregateVersion::try_new(u64::MAX - 1).unwrap(),
                1 => changed.expected_version = AggregateVersion::try_new(u64::MAX).unwrap(),
                2 => {
                    changed.expected_pull_request_version =
                        AggregateVersion::try_new(u64::MAX).unwrap()
                }
                3 => changed.merge.source_ref = changed.merge.target_ref.clone(),
                4 => changed.merge.source_tip = changed.merge.target_tip_before,
                5 => changed.merge.merge_commit = changed.merge.source_tip,
                6 => changed.merge.merge_commit = changed.merge.target_tip_before,
                7 => changed.merge.merge_commit = changed.merge.base_tip,
                8 => changed.merge.base_tip = oid(format, 0),
                _ => {
                    changed.merge.base_tip = oid(
                        if format == GitHashAlgorithm::Sha1 {
                            GitHashAlgorithm::Sha256
                        } else {
                            GitHashAlgorithm::Sha1
                        },
                        0x55,
                    )
                }
            }
            assert!(
                candidate_landing_proposal(&context, &changed).is_err(),
                "invalid coordinates {change}"
            );
        }
        let mut other = context;
        other.object_format = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert!(candidate_landing_proposal(&other, &command).is_err());
    }
}
