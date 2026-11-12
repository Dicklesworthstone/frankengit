//! Existing approvals cannot outlive the reviewer's canonical agent declaration.
//! These reference-store fixtures exercise the production consumer gate, not
//! credential issuance, durable-node recovery or an executed human review.

use super::*;
use fgit_forge::event::agent_credential::{
    AgentCredentialAction, AgentCredentialCommand, AgentCredentialGrant, AgentCredentialId,
    PULLS_READ, SponsorKind,
};
use fgit_types::{RepositoryIncarnationId, TenantId};

fn declaration(reviewer: u8, revoked: bool) -> ForgeEvent {
    let grant = AgentCredentialGrant {
        agent: principal(reviewer),
        sponsor: principal(50),
        sponsor_kind: SponsorKind::Human,
        tenant: TenantId::from_bytes([0x41; 16]),
        repository: RepositoryId::from_bytes([0x42; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([0x43; 16]),
        issued_at: 1,
        expires_at: 100,
        operations: PULLS_READ,
    };
    AgentCredentialCommand {
        id: AgentCredentialId::try_new([reviewer; 32]).unwrap(),
        expected_version: if revoked {
            ExpectedVersion::Exactly(AggregateVersion::FIRST)
        } else {
            ExpectedVersion::NewStream
        },
        action: if revoked {
            AgentCredentialAction::Revoke(grant)
        } else {
            AgentCredentialAction::Issue(grant)
        },
    }
    .proposed_event(grant.sponsor)
    .unwrap()
}

/// Advance only this canonical-body fixture's head. The same stored approvals,
/// PR version, tips and policy epoch survive the later identity declaration.
fn append(fixture: &mut Fixture, event: ForgeEvent) -> ImmutableKey {
    let state = run(delivery::read_roots_in(
        &fixture.store,
        &(),
        &fixture.basis,
        &|| false,
    ))
    .unwrap();
    let repository = fixture.basis.body().repository_id;
    let batch = ForgeEventBatch::of_one(event);
    let payload = stage(&fixture.store, repository, storage::EVENT_NAMESPACE, &batch);
    fixture.positions = storage::advance_positions(&fixture.positions, &batch, payload).unwrap();
    let class = AsciiSlug::from_static("forge-event");
    let destination = AsciiSlug::from_static("forge-projection");
    let delivery_key =
        fgit_codec::derive_outbox_delivery_key(fgit_codec::OutboxDeliveryIdentityInput::new(
            repository,
            class,
            destination,
            payload,
            tx_id(),
            None,
        ))
        .unwrap();
    let effect = CanonicalOutboxEffectState::committed(repository, delivery_key, tx_id(), payload);
    let effect_root = stage(
        &fixture.store,
        repository,
        delivery::EFFECT_NAMESPACE,
        &effect,
    );
    let mut entries = state.outbox.entries().to_vec();
    entries.push(CanonicalOutboxStateEntry::new(
        delivery_key,
        class,
        destination,
        payload,
        tx_id(),
        None,
        effect_root,
        None,
    ));
    let outbox = CanonicalOutboxState::try_new(repository, entries).unwrap();
    let mut head = fixture.basis.body().clone();
    head.generation = fixture.basis.successor_generation().unwrap();
    head.predecessor_head_id = Some(fixture.basis.id());
    head.forge_position_root = stage(
        &fixture.store,
        repository,
        storage::POSITION_NAMESPACE,
        &fixture.positions,
    );
    head.outbox_root = stage(
        &fixture.store,
        repository,
        delivery::OUTBOX_NAMESPACE,
        &outbox,
    );
    let head_key = HeadKey::new(b"review-read/head".to_vec()).unwrap();
    let (_, receipt, _) = run(crate::read_basis_async(&fixture.store, &(), &head_key)).unwrap();
    assert!(matches!(
        fixture.store.memory.compare_exchange_head(
            &head_key,
            receipt.token(),
            head.generation,
            &fgit_codec::encode_body(&head).unwrap(),
        ),
        Ok(CasOutcome::Committed(_))
    ));
    fixture.basis = run(crate::read_basis_async(&fixture.store, &(), &head_key))
        .unwrap()
        .0;
    fixture.store.reset_reads();
    storage::body_key(storage::EVENT_NAMESPACE, repository, payload).unwrap()
}

fn quorum_at(
    fixture: &Fixture,
    basis: &PublicationBasis,
    reviewers: &[u8],
    required: u16,
) -> Result<(), ProjectionFailure> {
    let intent = crate::merge::native::NativeMergeIntent::new(
        PullRequestNumber::FIRST,
        ExpectedVersion::Exactly(AggregateVersion::FIRST),
        fixture.candidate.merge(&fixture.subject),
    )
    .unwrap();
    let reviewers: Vec<_> = reviewers.iter().copied().map(principal).collect();
    run(gate::verify_quorum_at(
        &fixture.store,
        &(),
        basis,
        &intent,
        principal(3),
        PolicyEpoch::FIRST,
        &reviewers,
        required,
        &|| fixture.store.cancelled.load(Ordering::Relaxed),
    ))
}

fn denied(result: Result<(), ProjectionFailure>) {
    assert!(
        matches!(
            result,
            Err(ProjectionFailure::Refuse(
                RefusalCode::ProtectedRefTransitionDenied
            ))
        ),
        "{result:?}"
    );
}

#[test]
fn a_later_agent_declaration_invalidates_old_votes_without_reclassifying_ordinary_reviewers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(
            format,
            0,
            vec![vote(format, 9), vote(format, 12), vote(format, 13)],
        );
        let original = fixture.basis.clone();
        let approval = fixture.key(9);
        fixture.gate(vec![principal(9)]).unwrap();
        quorum_at(&fixture, &original, &[9, 12], 2).unwrap();

        // An unattached immutable declaration is not canonical identity.
        stage(
            &fixture.store,
            fixture.basis.body().repository_id,
            storage::EVENT_NAMESPACE,
            &ForgeEventBatch::of_one(declaration(9, false)),
        );
        fixture.gate(vec![principal(9)]).unwrap();

        for revoked in [false, true] {
            append(&mut fixture, declaration(9, revoked));
            assert_ne!(fixture.basis.id(), original.id());
            assert_eq!(
                fixture.basis.body().policy_epoch,
                original.body().policy_epoch
            );
            assert_eq!(fixture.key(9), approval, "the original review is unchanged");
            denied(fixture.gate(vec![principal(9)]));
            denied(quorum_at(&fixture, &fixture.basis, &[9, 12], 2));
            // The policy's numeric threshold does not shrink. Independent
            // ordinary approvals can still meet it, without any human claim.
            quorum_at(&fixture, &fixture.basis, &[9, 12, 13], 2).unwrap();
            // Retained identities are read from the named basis, not an
            // ambient latest-head lookup that would alter historical replay.
            quorum_at(&fixture, &original, &[9, 12], 2).unwrap();
        }
    }
}

#[test]
fn selected_agent_registry_corruption_refuses_even_an_otherwise_sufficient_quorum() {
    let mut fixture = Fixture::new(
        GitHashAlgorithm::Sha256,
        0,
        vec![
            vote(GitHashAlgorithm::Sha256, 12),
            vote(GitHashAlgorithm::Sha256, 13),
        ],
    );
    let registry = append(&mut fixture, declaration(9, false));
    quorum_at(&fixture, &fixture.basis, &[12, 13], 2).unwrap();
    for (fault, expected) in [
        (ReadFault::Missing, RefusalCode::EvidenceMissing),
        (ReadFault::Tampered, RefusalCode::EvidenceInvalid),
    ] {
        *fixture.store.fault.lock().unwrap() = Some((registry.clone(), fault));
        assert!(matches!(
            quorum_at(&fixture, &fixture.basis, &[12, 13], 2),
            Err(ProjectionFailure::Unavailable(observed)) if observed == expected
        ));
        *fixture.store.fault.lock().unwrap() = None;
        quorum_at(&fixture, &fixture.basis, &[12, 13], 2).unwrap();
    }
}

#[test]
fn cancellation_while_reading_agent_eligibility_cannot_return_an_approval() {
    let mut fixture = Fixture::new(
        GitHashAlgorithm::Sha1,
        0,
        vec![vote(GitHashAlgorithm::Sha1, 12)],
    );
    let registry = append(&mut fixture, declaration(9, false));
    fixture.pr_page();
    let parent_reads = fixture.store.reads_of(&registry);
    fixture.store.reset_reads();
    *fixture.store.cancel_on.lock().unwrap() = Some((registry, parent_reads + 1));
    assert!(matches!(
        quorum_at(&fixture, &fixture.basis, &[12], 1),
        Err(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress
        ))
    ));
    fixture.store.reset_reads();
    quorum_at(&fixture, &fixture.basis, &[12], 1).unwrap();
}
