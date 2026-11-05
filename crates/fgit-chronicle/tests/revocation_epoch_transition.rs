#![forbid(unsafe_code)]
//! Opaque carry-forward publication, structural replay, and losing-CAS rebinding.

#[path = "support/policy_transition.rs"]
mod fixture;

use fgit_authority::{
    AuthorityVersionToken, read_head_selected_capability_revocation_generation,
    read_repository_incarnation_configuration,
};
use fgit_chronicle::{
    ChronicleRefusal, PublicationBasis, PublicationPlan, PublicationVerdict, ResultingRoots,
    batch_identity, publish_with_cumulative, verify_pair,
};
use fgit_codec::CryptoBodyIdentity;
use fgit_types::{
    CANONICAL_CODEC_VERSION, PolicyEpoch, RefusalCode, RefusalRecordId, RegistryEpoch,
};
use fixture::{Fixture, TENANT, digest, plan, record, roots, tx};

fn refusal_record() -> RefusalRecordId {
    RefusalRecordId::from_digest(
        digest(0xe0).algorithm(),
        CANONICAL_CODEC_VERSION,
        *digest(0xe0).bytes(),
    )
}

#[test]
fn committed_policy_publication_keeps_revocation_readable_and_old_members_revoked() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let original = read_head_selected_capability_revocation_generation(
        &fixture.store,
        TENANT,
        &current.authenticated,
    )
    .expect("original selected snapshot");
    let transition = fixture.transition(&current, digest(0xa0));
    let publication = plan(&current, 0xa1, digest(0xa0))
        .seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&current, 0xa1),
            &current.cumulative,
            current.authenticated.receipt().token(),
            &transition,
        )
        .expect("matched proof seals");
    transition
        .stage(&fixture.store)
        .expect("stage dependencies");
    assert_eq!(
        publication.head().configuration_root,
        transition.configuration_root()
    );
    assert_eq!(
        publication.batch().committed_rcrs[0].policy_epoch,
        current.basis.body().policy_epoch
    );
    assert_eq!(
        publication.head().policy_epoch,
        transition.successor_epoch()
    );
    verify_pair(
        &CryptoBodyIdentity,
        &current.basis,
        publication.batch(),
        publication.head(),
    )
    .expect("stored pair replays without a process proof");
    fgit_authority::verify_capability_revocation_epoch_transition(
        &fixture.store,
        current.basis.body(),
        publication.head(),
        publication.batch().committed_rcrs[0].forge_event_batch_root,
    )
    .expect("read-only immutable replay verifies the committed carry-forward");
    assert!(matches!(
        publish_with_cumulative(
            &fixture.store,
            &fixture.key,
            publication.expected_head_token(),
            &publication,
            TENANT,
            &current.cumulative
        )
        .expect("publish exact predecessor"),
        PublicationVerdict::Published(_)
    ));
    let selected = fixture.current();
    let carried = read_head_selected_capability_revocation_generation(
        &fixture.store,
        TENANT,
        &selected.authenticated,
    )
    .expect("new epoch remains readable");
    assert_eq!(
        carried.body().revoked_capability_ids(),
        original.body().revoked_capability_ids()
    );
    assert_eq!(
        carried.body().predecessor_generation_id(),
        Some(original.generation_id())
    );
    assert_eq!(carried.body().evidence_root(), digest(0xa0));
    let before = read_repository_incarnation_configuration(
        &fixture.store,
        &current.basis.body().configuration_root,
    )
    .expect("old configuration");
    let after = read_repository_incarnation_configuration(
        &fixture.store,
        &selected.basis.body().configuration_root,
    )
    .expect("new configuration");
    assert_eq!(before.root_layout, after.root_layout);
    assert_eq!(before.object_format, after.object_format);
    assert_eq!(
        before.repository_incarnation_id,
        after.repository_incarnation_id
    );
    assert_eq!(before.policy_root, after.policy_root);
    assert_ne!(
        before.capability_revocation_root,
        after.capability_revocation_root
    );
}

#[test]
fn proof_requires_exact_basis_token_epoch_event_and_unchanged_source_roots() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let transition = fixture.transition(&current, digest(0xa0));
    for case in 0..10 {
        let mut basis = current.basis.clone();
        let mut candidate = record(&current, 0xa1, digest(0xa0));
        let mut resulting = roots(&current, 0xa1);
        let mut token = current.authenticated.receipt().token();
        let field = match case {
            0 => {
                candidate.forge_event_batch_root = digest(0xee);
                "policy event root"
            }
            1 => {
                candidate.policy_epoch = resulting.policy_epoch;
                "admission policy epoch"
            }
            2 => {
                candidate.resulting_ref_root = digest(0xee);
                "committed ref root"
            }
            3 => {
                resulting.ref_root = digest(0xee);
                "ref root"
            }
            4 => {
                resulting.retention_root = digest(0xee);
                "retention root"
            }
            5 => {
                resulting.policy_epoch = current.basis.body().policy_epoch;
                "resulting policy epoch"
            }
            6 => {
                resulting.compaction_generation_link = Some(digest(0xee));
                "compaction link"
            }
            7 => {
                token = AuthorityVersionToken::from_opaque_bytes([0xff; 16]);
                "predecessor token"
            }
            8 => {
                let mut body = current.basis.body().clone();
                body.configuration_root = digest(0xee);
                basis = PublicationBasis::new(current.basis.id(), body);
                "predecessor body"
            }
            _ => {
                let id = fgit_types::RepositoryAuthorityHeadId::from_digest(
                    digest(0xee).algorithm(),
                    CANONICAL_CODEC_VERSION,
                    *digest(0xee).bytes(),
                );
                basis = PublicationBasis::new(id, current.basis.body().clone());
                "predecessor identity"
            }
        };
        let mut candidate_plan = PublicationPlan::open(basis).expect("plan opens");
        candidate_plan.commit(candidate);
        assert_eq!(
            candidate_plan
                .seal_with_revocation_epoch_transition(
                    &CryptoBodyIdentity,
                    resulting,
                    &current.cumulative,
                    token,
                    &transition
                )
                .expect_err("mismatched proof refuses"),
            ChronicleRefusal::RevocationTransitionMismatch { field },
            "case {case}"
        );
    }
    let _permitted = plan(&current, 0xa1, digest(0xa0))
        .seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&current, 0xa1),
            &current.cumulative,
            current.authenticated.receipt().token(),
            &transition,
        )
        .expect("unchanged permitted twin");
}

#[test]
fn proof_cannot_publish_without_exactly_one_committed_decision() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let transition = fixture.transition(&current, digest(0xa0));
    for kind in 0..4 {
        let mut candidate = PublicationPlan::open(current.basis.clone()).expect("plan");
        if kind == 1 || kind == 2 {
            candidate.refuse(tx(0xb1), RefusalCode::EvidenceInvalid, refusal_record());
        }
        if kind >= 2 {
            candidate.commit(record(&current, 0xb2, digest(0xa0)));
        }
        if kind == 3 {
            candidate.commit(record(&current, 0xb3, digest(0xa0)));
        }
        assert_eq!(
            candidate
                .seal_with_revocation_epoch_transition(
                    &CryptoBodyIdentity,
                    roots(&current, 0xb2),
                    &current.cumulative,
                    current.authenticated.receipt().token(),
                    &transition
                )
                .expect_err("no empty/refusal/mixed/multiple path"),
            ChronicleRefusal::RevocationTransitionMismatch {
                field: "one committed policy decision"
            }
        );
    }
}

#[test]
fn independent_replay_refuses_configuration_and_policy_changes_without_committed_shape() {
    let fixture = Fixture::new(true);
    let current = fixture.current();
    let mut candidate = PublicationPlan::open(current.basis.clone()).expect("plan");
    candidate.refuse(tx(0xc1), RefusalCode::EvidenceInvalid, refusal_record());
    let refusal = candidate
        .seal(
            &CryptoBodyIdentity,
            ResultingRoots::carried_forward(&current.basis),
            &current.cumulative,
            current.authenticated.receipt().token(),
        )
        .expect("normal refusal");
    let mut head = refusal.head().clone();
    head.configuration_root = digest(0xed);
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &current.basis, refusal.batch(), &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "configuration_root"
        })
    );
    let mut batch = refusal.batch().clone();
    head = refusal.head().clone();
    batch.resulting_policy_epoch = PolicyEpoch::FIRST.next().expect("next");
    head.policy_epoch = batch.resulting_policy_epoch;
    head.decision_tail_id =
        Some(batch_identity(&CryptoBodyIdentity, &batch).expect("rebind batch"));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &current.basis, &batch, &head),
        Err(ChronicleRefusal::RefusalOnlyBatchAdvancedCommittedState {
            field: "resulting_policy_epoch"
        })
    );

    let transition = fixture.transition(&current, digest(0xa0));
    let valid = plan(&current, 0xa1, digest(0xa0))
        .seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&current, 0xa1),
            &current.cumulative,
            current.authenticated.receipt().token(),
            &transition,
        )
        .expect("valid policy pair");
    for case in 0..4 {
        let mut batch = valid.batch().clone();
        let mut head = valid.head().clone();
        let field = match case {
            0 => {
                head.policy_epoch = PolicyEpoch::FIRST;
                batch.resulting_policy_epoch = head.policy_epoch;
                "immediate policy epoch"
            }
            1 => {
                head.policy_epoch = PolicyEpoch::try_new(3).expect("third");
                batch.resulting_policy_epoch = head.policy_epoch;
                "immediate policy epoch"
            }
            2 => {
                head.ref_root = digest(0xed);
                batch.resulting_ref_root = head.ref_root;
                "ref root"
            }
            _ => {
                head.retention_root = digest(0xed);
                batch.resulting_retention_root = head.retention_root;
                "retention root"
            }
        };
        head.decision_tail_id =
            Some(batch_identity(&CryptoBodyIdentity, &batch).expect("rebind batch"));
        assert_eq!(
            verify_pair(&CryptoBodyIdentity, &current.basis, &batch, &head),
            Err(ChronicleRefusal::PolicyTransitionMismatch { field })
        );
    }
    let mut head = valid.head().clone();
    head.format_registry_epoch = RegistryEpoch::FIRST.next().expect("next registry epoch");
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &current.basis, valid.batch(), &head),
        Err(ChronicleRefusal::PermanentHeadFieldChanged {
            field: "format_registry_epoch"
        })
    );
    let mut head = valid.head().clone();
    head.last_checkpoint_id = Some(fgit_types::RepositoryCapsuleId::from_digest(
        digest(0xed).algorithm(),
        CANONICAL_CODEC_VERSION,
        *digest(0xed).bytes(),
    ));
    assert_eq!(
        verify_pair(&CryptoBodyIdentity, &current.basis, valid.batch(), &head),
        Err(ChronicleRefusal::PermanentHeadFieldChanged {
            field: "last_checkpoint_id"
        })
    );
}

#[test]
fn lost_cas_requires_a_fresh_proof_and_preserves_the_winners_generation_lineage() {
    let fixture = Fixture::new(true);
    let original = fixture.current();
    let winner_proof = fixture.transition(&original, digest(0xa0));
    let loser_proof = fixture.transition(&original, digest(0xb0));
    let winner = plan(&original, 0xa1, digest(0xa0))
        .seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&original, 0xa1),
            &original.cumulative,
            original.authenticated.receipt().token(),
            &winner_proof,
        )
        .expect("winner candidate");
    let loser = plan(&original, 0xb1, digest(0xb0))
        .seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&original, 0xb1),
            &original.cumulative,
            original.authenticated.receipt().token(),
            &loser_proof,
        )
        .expect("loser candidate");
    winner_proof
        .stage(&fixture.store)
        .expect("winner dependencies");
    loser_proof
        .stage(&fixture.store)
        .expect("loser dependencies");
    assert!(matches!(
        publish_with_cumulative(
            &fixture.store,
            &fixture.key,
            winner.expected_head_token(),
            &winner,
            TENANT,
            &original.cumulative
        )
        .expect("first wins"),
        PublicationVerdict::Published(_)
    ));
    assert!(matches!(
        publish_with_cumulative(
            &fixture.store,
            &fixture.key,
            loser.expected_head_token(),
            &loser,
            TENANT,
            &original.cumulative
        )
        .expect("second loses"),
        PublicationVerdict::Lost(_)
    ));
    let current = fixture.current();
    assert!(matches!(
        plan(&current, 0xb1, digest(0xb0)).seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&current, 0xb1),
            &current.cumulative,
            current.authenticated.receipt().token(),
            &loser_proof
        ),
        Err(ChronicleRefusal::RevocationTransitionMismatch { .. })
    ));
    let rebased_proof = fixture.transition(&current, digest(0xb0));
    assert_eq!(
        rebased_proof.generation().predecessor_generation_id(),
        Some(
            winner_proof
                .generation()
                .generation_id()
                .expect("winner generation ID")
        )
    );
    assert_eq!(
        rebased_proof.generation().revoked_capability_ids(),
        winner_proof.generation().revoked_capability_ids()
    );
    let rebased = plan(&current, 0xb1, digest(0xb0))
        .seal_with_revocation_epoch_transition(
            &CryptoBodyIdentity,
            roots(&current, 0xb1),
            &current.cumulative,
            current.authenticated.receipt().token(),
            &rebased_proof,
        )
        .expect("fresh proof for same logical transaction");
    rebased_proof
        .stage(&fixture.store)
        .expect("new dependencies");
    assert!(matches!(
        publish_with_cumulative(
            &fixture.store,
            &fixture.key,
            rebased.expected_head_token(),
            &rebased,
            TENANT,
            &current.cumulative
        )
        .expect("rebased candidate publishes"),
        PublicationVerdict::Published(_)
    ));
    let current = fixture.current();
    assert_eq!(
        read_head_selected_capability_revocation_generation(
            &fixture.store,
            TENANT,
            &current.authenticated
        )
        .expect("final selected generation")
        .body(),
        rebased_proof.generation()
    );
}
