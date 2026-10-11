use super::*;

use fgit_authority::{
    HeadInit, HeadKey, MemoryAuthorityStore, StoreInstanceId, initialize_repository,
};
use fgit_codec::harness::{advanced_head, capsule_id, digest_of, genesis_head, head_id};
use fgit_codec::{DecodeLimits, decode_body};
use fgit_types::{HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId};

use crate::{
    BackupProfile, CapsuleClosure, RepositoryCapsuleBody, activate_frozen_capsule,
    capsule_identity, freeze_capsule,
};

fn activated(
    mut head: RepositoryAuthorityHeadBody,
) -> (PublicationBasis, RepositoryAuthorityHeadBody, Vec<u8>) {
    head.last_checkpoint_id = None;
    let store = MemoryAuthorityStore::new(StoreInstanceId::from_raw(0xc4));
    let key = HeadKey::new(b"checkpoint-transition-test".to_vec()).unwrap();
    let (HeadInit::Created(receipt) | HeadInit::IdenticalRetry(receipt)) =
        initialize_repository(&store, &key, &head).unwrap()
    else {
        panic!("fresh authority initializes");
    };
    let frozen = freeze_capsule(
        &store,
        &CryptoBodyIdentity,
        &receipt,
        None,
        CapsuleClosure {
            object_closure_root: digest_of(0x91),
            segment_manifest_root: digest_of(0x92),
            backup_profile: BackupProfile::DecisionHistoryOnly,
        },
    )
    .unwrap();
    let bytes = encode_body(frozen.capsule()).unwrap();
    let activated = activate_frozen_capsule(&store, &receipt, &frozen).unwrap();
    (
        PublicationBasis::new(authority_head_identity(&head).unwrap(), head),
        decode_body(activated.head().body(), DecodeLimits::DEFAULT).unwrap(),
        bytes,
    )
}

#[test]
fn actual_capsule_activation_preserves_empty_and_nonempty_decision_boundaries() {
    for head in [genesis_head(), advanced_head()] {
        let (basis, successor, bytes) = activated(head);
        verify_checkpoint_successor(&basis, &successor, &bytes).unwrap();
        assert_eq!(successor.decision_tail_id, basis.body().decision_tail_id);
        assert_eq!(
            successor.latest_decision_sequence,
            basis.body().latest_decision_sequence
        );
        assert_eq!(successor.generation, basis.generation().next().unwrap());
    }
}

#[test]
fn every_nonactivation_field_and_each_exact_activation_value_is_checked() {
    type MutateHead = fn(&mut RepositoryAuthorityHeadBody);
    let mutations: &[(&str, MutateHead)] = &[
        ("repository", |h| {
            h.repository_id = RepositoryId::from_bytes([0xfd; 16])
        }),
        ("generation", |h| {
            h.generation = h.generation.next().unwrap()
        }),
        ("predecessor", |h| h.predecessor_head_id = None),
        ("tail", |h| h.decision_tail_id = None),
        ("decision sequence", |h| h.latest_decision_sequence = None),
        ("committed RCR", |h| h.latest_committed_rcr_id = None),
        ("repository sequence", |h| {
            h.latest_repository_sequence = None
        }),
        ("refs", |h| h.ref_root = digest_of(0xfe)),
        ("forge", |h| h.forge_position_root = digest_of(0xfe)),
        ("outcomes", |h| h.outcome_index_root = digest_of(0xfe)),
        ("retention", |h| h.retention_root = digest_of(0xfe)),
        ("outbox", |h| h.outbox_root = digest_of(0xfe)),
        ("configuration", |h| h.configuration_root = digest_of(0xfe)),
        ("policy", |h| h.policy_epoch = PolicyEpoch::FIRST),
        ("registry", |h| {
            h.format_registry_epoch = RegistryEpoch::FIRST
        }),
        ("checkpoint", |h| h.last_checkpoint_id = None),
    ];
    let (basis, successor, bytes) = activated(advanced_head());
    for (field, change) in mutations {
        let mut changed = successor.clone();
        change(&mut changed);
        assert_ne!(changed, successor, "{field} mutation must change its field");
        assert!(
            verify_checkpoint_successor(&basis, &changed, &bytes).is_err(),
            "{field} must not change under a checkpoint-only transition"
        );
    }
    verify_checkpoint_successor(&basis, &successor, &bytes).unwrap();
}

#[test]
fn canonical_capsule_identity_and_every_predecessor_binding_are_required() {
    type MutateCapsule = fn(&mut RepositoryCapsuleBody);
    let mutations: &[(&str, MutateCapsule)] = &[
        ("head identity", |c| c.head_id = head_id()),
        ("head generation", |c| {
            c.head_generation = c.head_generation.next().unwrap()
        }),
        ("repository", |c| {
            c.repository_id = RepositoryId::from_bytes([0xfd; 16])
        }),
        ("tail", |c| c.decision_tail_id = None),
        ("decision sequence", |c| c.latest_decision_sequence = None),
        ("committed RCR", |c| c.latest_committed_rcr_id = None),
        ("repository sequence", |c| {
            c.latest_repository_sequence = None
        }),
        ("refs", |c| c.ref_root = digest_of(0xfe)),
        ("forge", |c| c.forge_position_root = digest_of(0xfe)),
        ("retention", |c| c.retention_root = digest_of(0xfe)),
        ("configuration", |c| c.configuration_root = digest_of(0xfe)),
        ("policy", |c| c.policy_epoch = PolicyEpoch::FIRST),
        ("registry", |c| {
            c.format_registry_epoch = RegistryEpoch::FIRST
        }),
        ("capsule predecessor", |c| {
            c.predecessor_capsule_id = Some(capsule_id())
        }),
    ];
    let (basis, successor, bytes) = activated(advanced_head());
    let capsule: RepositoryCapsuleBody = decode_body(&bytes, DecodeLimits::DEFAULT).unwrap();
    for (field, change) in mutations {
        let mut changed = capsule.clone();
        change(&mut changed);
        assert_ne!(changed, capsule, "{field} mutation must change its field");
        let bytes = encode_body(&changed).unwrap();
        let mut changed_successor = successor.clone();
        changed_successor.last_checkpoint_id =
            Some(capsule_identity(&CryptoBodyIdentity, &changed).unwrap());
        assert!(
            verify_checkpoint_successor(&basis, &changed_successor, &bytes).is_err(),
            "re-identifying a capsule must not forgive an incorrect {field} binding"
        );
    }
}

#[test]
fn original_capsule_bytes_refuse_wrong_identity_truncation_and_trailing_data() {
    let (basis, successor, bytes) = activated(genesis_head());
    let mut wrong_pointer = successor.clone();
    wrong_pointer.last_checkpoint_id = Some(capsule_id());
    assert!(verify_checkpoint_successor(&basis, &wrong_pointer, &bytes).is_err());
    for length in [0, 1, bytes.len() - 1] {
        assert!(verify_checkpoint_successor(&basis, &successor, &bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(verify_checkpoint_successor(&basis, &successor, &trailing).is_err());
    verify_checkpoint_successor(&basis, &successor, &bytes).unwrap();
}

#[test]
fn predecessor_identity_and_generation_exhaustion_cannot_be_bypassed() {
    let (basis, successor, bytes) = activated(genesis_head());
    let wrong_basis = PublicationBasis::new(head_id(), basis.body().clone());
    assert!(matches!(
        verify_checkpoint_successor(&wrong_basis, &successor, &bytes),
        Err(CheckpointTransitionRefusal::PredecessorIdentity)
    ));
    let mut exhausted = basis.body().clone();
    exhausted.generation = HeadGeneration::try_new(u64::MAX).unwrap();
    let exhausted = PublicationBasis::new(authority_head_identity(&exhausted).unwrap(), exhausted);
    assert!(matches!(
        verify_checkpoint_successor(&exhausted, &successor, &bytes),
        Err(CheckpointTransitionRefusal::GenerationExhausted)
    ));
}
