//! Proof-boundary tests use a private constructed value to mutate every guard.
//! Actual queue replay and native publication are covered by the node campaign;
//! these tests make no durable-store or object-validation claim.

use super::*;
use crate::merge::native::metadata_read_tests::{Store, run};
use crate::merge::native::protection;
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};

fn proof(
    context: &AdmissionContext,
    basis: &PublicationBasis,
    command: &QueueLandingCommand,
) -> ValidatedQueueLanding {
    let (events, attempt) = landing_proposal(context, command).unwrap();
    ValidatedQueueLanding {
        context: context.clone(),
        basis: basis.clone(),
        intent: command.intent().unwrap(),
        attempt,
        event_root: storage::root(&events).unwrap(),
    }
}

#[test]
fn queue_proof_cannot_move_across_basis_actor_method_intent_or_prepared_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, command, resolved, basis, closure) = fixture(format);
        let (events, attempt) = landing_proposal(&context, &command).unwrap();
        let intent = command.intent().unwrap();
        let proof = proof(&context, &basis, &command);
        let prepared = prepare_landing(
            &context,
            &command,
            &events,
            &closure,
            attempt.derive().unwrap().0,
            &attempt,
            &basis,
            &resolved,
        )
        .unwrap();
        proof
            .verify_intent(&basis, &intent, context.principal_id)
            .unwrap();
        proof.verify_prepared(&context, &basis, &prepared).unwrap();
        assert_eq!(
            proof.verify_intent(&basis, &intent, PrincipalId::from_bytes([8; 16])),
            Err(RefusalCode::EvidenceInvalid)
        );
        let other_method = NativeMergeIntent::new(
            command.pull_request,
            fgit_forge::ExpectedVersion::Exactly(command.expected_pull_request_version),
            intent.merge().unwrap().clone(),
        )
        .unwrap();
        assert_eq!(
            proof.verify_intent(&basis, &other_method, context.principal_id),
            Err(RefusalCode::EvidenceInvalid)
        );
        for alter in 0..4 {
            let mut body = basis.body().clone();
            match alter {
                0 => body.policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                1 => body.generation = basis.successor_generation().unwrap(),
                2 => body.ref_root = digest(0x91),
                _ => body.forge_position_root = digest(0x92),
            }
            // Even a mismatched body claiming the same ID cannot reuse proof.
            let changed = PublicationBasis::new(basis.id(), body);
            assert_eq!(
                proof.verify_intent(&changed, &intent, context.principal_id),
                Err(RefusalCode::EvidenceInvalid)
            );
        }
        for alter in 0..3 {
            let mut changed = context.clone();
            match alter {
                0 => changed.principal_id = PrincipalId::from_bytes([8; 16]),
                1 => {
                    changed.idempotency_key =
                        IdempotencyKey::new(b"different-request".to_vec()).unwrap()
                }
                _ => changed.head_key = HeadKey::new(b"different-authority".to_vec()).unwrap(),
            }
            assert_eq!(
                proof.verify_prepared(&changed, &basis, &prepared),
                Err(RefusalCode::EvidenceInvalid)
            );
        }
        for alter in 0..5 {
            let mut changed = prepared.clone();
            match alter {
                0 => changed.event.events.swap(0, 2),
                1 => {
                    changed.event.events.pop();
                }
                2 => changed.request.canonical_request_digest = digest(0x93),
                3 => changed.materialization.record.forge_event_batch_root = digest(0x94),
                _ => changed.materialization.record.policy_epoch = PolicyEpoch::try_new(2).unwrap(),
            }
            assert_eq!(
                proof.verify_prepared(&context, &basis, &changed),
                Err(RefusalCode::EvidenceInvalid)
            );
        }
    }
}

#[test]
fn public_native_policy_attachment_cannot_grant_queue_privilege_from_batch_shape() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (context, mut command, mut resolved, basis, closure) = fixture(format);
        let store = Store::new();
        let policy = ProtectionCommand {
            expected_version: fgit_forge::ExpectedVersion::NewStream,
            expected_epoch: basis.body().policy_epoch,
            protection: ReviewProtection {
                administrators: vec![context.principal_id],
                branches: vec![ProtectedBranch {
                    name: command.target_ref.clone(),
                    reviewers: Vec::new(),
                    required_approvals: 0,
                    required_checks: Vec::new(),
                    require_merge_queue: true,
                }],
                ref_policy: Some(
                    fgit_forge::event::protection::compile_ref_policy(
                        "policy permissive { default allow }",
                    )
                    .unwrap(),
                ),
            },
        };
        let policy_event =
            ForgeEventBatch::of_one(policy.proposed_event(context.principal_id).unwrap());
        let event_root = run(storage::stage_body(
            &store,
            &(),
            context.repository_id,
            storage::EVENT_NAMESPACE,
            &policy_event,
        ))
        .unwrap();
        resolved.forge =
            storage::advance_positions(&resolved.forge, &policy_event, event_root).unwrap();
        let mut head = basis.body().clone();
        head.forge_position_root = run(storage::stage_body(
            &store,
            &(),
            context.repository_id,
            storage::POSITION_NAMESPACE,
            &resolved.forge,
        ))
        .unwrap();
        head.policy_epoch = head.policy_epoch.next().unwrap();
        command.expected_policy_epoch = head.policy_epoch;
        let basis = PublicationBasis::new(
            fgit_authority::authority_head_identity(&head).unwrap(),
            head,
        );
        let (events, attempt) = landing_proposal(&context, &command).unwrap();
        let mut prepared = prepare_landing(
            &context,
            &command,
            &events,
            &closure,
            attempt.derive().unwrap().0,
            &attempt,
            &basis,
            &resolved,
        )
        .unwrap();
        // A complete valid triple and a permissive activated DSL do not turn
        // this public publication enum into authenticated queue selection.
        for publication in [
            crate::evidence::RefPolicyPublication::Direct,
            crate::evidence::RefPolicyPublication::NativeMerge,
        ] {
            assert!(matches!(
                run(protection::attach_prepared_policy_at(
                    &store,
                    &(),
                    &context,
                    &basis,
                    &resolved,
                    &mut prepared,
                    publication,
                    &|| false,
                )),
                Err(ProjectionFailure::Refuse(
                    RefusalCode::ProtectedRefTransitionDenied
                ))
            ));
        }
        let proof = proof(&context, &basis, &command);
        run(protection::attach_prepared_policy_selected_at(
            &store,
            &(),
            &context,
            &basis,
            &resolved,
            &mut prepared,
            crate::evidence::RefPolicyPublication::NativeMerge,
            None,
            Some(&proof),
            &|| false,
        ))
        .unwrap();
        prepared
            .evidence
            .verify_decision(&context, &basis, &prepared.request, &prepared.fold)
            .unwrap();
        assert!(matches!(
            run(protection::attach_prepared_policy_selected_at(
                &store,
                &(),
                &context,
                &basis,
                &resolved,
                &mut prepared,
                crate::evidence::RefPolicyPublication::NativeMerge,
                None,
                Some(&proof),
                &|| true,
            )),
            Err(ProjectionFailure::Unavailable(
                RefusalCode::CancellationInProgress
            ))
        ));
    }
}
