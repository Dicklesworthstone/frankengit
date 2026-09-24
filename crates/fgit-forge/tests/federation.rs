#![forbid(unsafe_code)]
//! Integration and verification tests for FG-063 Federation and Local-First Collaboration.
//!
//! # Covered Acceptance Criteria
//!
//! 1. Offline work bundle round-trip: create offline against a capsule, import online,
//!    revalidation catches a staged conflict fixture.
//! 2. Mirror-namespace and proposed-RefTxn flows implemented; direct remote-head merge
//!    into canonical refs is unrepresentable.
//! 3. Equivocation fixture (one peer signs conflicting claims) produces durable evidence
//!    and review-surface routing.
//! 4. Federated event classes each declare monotone/CRDT/coordinated per the CALM registry.
//! 5. Two-instance collaboration workflow with paired permitted/refusal twins.

use std::collections::BTreeMap;

use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_crypto::{DetachedSignature, Identity, KeyEpoch, KeyScope, RootSecret, SecretKey};
use fgit_forge::federation::{
    BasisCapsule, CanonicalRef, CurrentAuthorityState, EquivocationDetector, FederatedEventClass,
    FederationRefusal, MirrorRef, ObservationOutcome, OfflineEffect, OfflineEvidence,
    OfflineIntent, OfflineSigner, OfflineWorkBundle, PeerId, PeerKeyHistory, ProposedRefTxn,
    ProposedTxnId, ReviewRouting, SignedClaim, create_offline_bundle, import_offline_bundle,
};
use fgit_types::GitOid;

const fn test_root_secret(seed: u8) -> RootSecret {
    RootSecret::from_bytes([seed; 32])
}

fn test_secret_key(seed: u8) -> SecretKey<Identity> {
    SecretKey::<Identity>::derive(&test_root_secret(seed), KeyEpoch::FIRST, KeyScope::OPERATOR)
}

const fn sample_git_oid(byte: u8) -> GitOid {
    GitOid::Sha1(fgit_types::GitOidSha1::from_bytes([byte; 20]))
}

const fn sample_basis_capsule(generation: u64, tip_byte: u8) -> BasisCapsule {
    BasisCapsule {
        capsule_id: [0xaa; 32],
        repo_id: [0x11; 32],
        head_generation: generation,
        head_tip: sample_git_oid(tip_byte),
        snapshot_root: [0xbb; 32],
    }
}

// =========================================================================
// 1. Offline Work Bundle Round-Trip and Staged Conflict Revalidation
// =========================================================================

#[test]
fn offline_work_bundle_codec_round_trip() {
    let key = test_secret_key(0x42);
    let signer = OfflineSigner::new(&key, KeyEpoch::FIRST);
    let peer_id = PeerId::from_bytes(*signer.verifying_key().as_bytes());

    let basis = sample_basis_capsule(1, 0x10);
    let intents = vec![
        OfflineIntent::ProposedRefChange {
            target_ref: "refs/heads/main".to_owned(),
            expected_basis: sample_git_oid(0x10),
            proposed_tip: sample_git_oid(0x20),
        },
        OfflineIntent::AppendSocialComment {
            topic: "issue-42".to_owned(),
            content_digest: [0xcc; 32],
            author: peer_id,
        },
        OfflineIntent::ReviewAttestation {
            pull_request_number: 101,
            decision_tag: "approved".to_owned(),
            review_digest: [0xdd; 32],
        },
    ];
    let effects = vec![OfflineEffect {
        effect_id: [0xee; 32],
        object_id: sample_git_oid(0x20),
        byte_length: 512,
    }];
    let evidence = vec![OfflineEvidence {
        evidence_id: [0xff; 32],
        claim_class: "differential_provenance".to_owned(),
        payload: b"independent verification artifact".to_vec(),
    }];

    let original_bundle =
        create_offline_bundle(basis, peer_id, &signer, intents, effects, evidence)
            .expect("bundle creation must succeed");

    // Canonical serialization
    let encoded = encode_body(&original_bundle).expect("encoding must succeed");

    // Canonical deserialization
    let decoded_bundle: OfflineWorkBundle =
        decode_body(&encoded, DecodeLimits::DEFAULT).expect("decoding must succeed");

    assert_eq!(original_bundle.bundle_id, decoded_bundle.bundle_id);
    assert_eq!(original_bundle.peer_id, decoded_bundle.peer_id);
    assert_eq!(original_bundle.basis_capsule, decoded_bundle.basis_capsule);
    assert_eq!(original_bundle.intents, decoded_bundle.intents);
    assert_eq!(original_bundle.effects, decoded_bundle.effects);
    assert_eq!(original_bundle.evidence, decoded_bundle.evidence);
    assert_eq!(original_bundle.signature, decoded_bundle.signature);
}

#[test]
fn offline_bundle_import_revalidation_staged_conflict_refused_vs_matching_permitted() {
    let key = test_secret_key(0x42);
    let signer = OfflineSigner::new(&key, KeyEpoch::FIRST);
    let peer_id = PeerId::from_bytes(*signer.verifying_key().as_bytes());

    let mut key_history = PeerKeyHistory::new();
    key_history.register_key(0, *signer.verifying_key().as_bytes());

    let mut detector = EquivocationDetector::new();

    let initial_tip = sample_git_oid(0x10);
    let proposed_tip = sample_git_oid(0x20);
    let conflicting_tip = sample_git_oid(0x99);

    let basis = sample_basis_capsule(1, 0x10);
    let intents = vec![OfflineIntent::ProposedRefChange {
        target_ref: "refs/heads/main".to_owned(),
        expected_basis: initial_tip,
        proposed_tip,
    }];
    let effects = vec![OfflineEffect {
        effect_id: [0x01; 32],
        object_id: proposed_tip,
        byte_length: 1024,
    }];
    let evidence = vec![];

    let bundle = create_offline_bundle(basis, peer_id, &signer, intents, effects, evidence)
        .expect("bundle creation");

    // Case 1 (Permitted twin): Current authority state matches expected basis
    let mut refs_ok = BTreeMap::new();
    refs_ok.insert("refs/heads/main".to_owned(), initial_tip);
    let current_head_ok = CurrentAuthorityState {
        head_generation: 1,
        head_tip: initial_tip,
        refs: refs_ok,
    };

    let receipt = import_offline_bundle(&bundle, &current_head_ok, &mut detector, &key_history)
        .expect("import must succeed when basis matches");

    assert_eq!(receipt.admitted_proposals.len(), 1);
    assert_eq!(receipt.admitted_proposals[0].expected_basis, initial_tip);
    assert_eq!(receipt.admitted_proposals[0].proposed_tip, proposed_tip);
    assert_eq!(receipt.admitted_mirror_refs.len(), 1);
    assert_eq!(
        receipt.admitted_mirror_refs[0].full_ref_path(),
        format!("refs/federation/{}/main", peer_id.to_hex())
    );

    // Case 2 (Refusal): Current authority state has moved on refs/heads/main (staged conflict)
    let mut refs_conflicted = BTreeMap::new();
    refs_conflicted.insert("refs/heads/main".to_owned(), conflicting_tip);
    let current_head_conflicted = CurrentAuthorityState {
        head_generation: 2,
        head_tip: conflicting_tip,
        refs: refs_conflicted,
    };

    let outcome = import_offline_bundle(
        &bundle,
        &current_head_conflicted,
        &mut detector,
        &key_history,
    );
    match outcome {
        Err(FederationRefusal::StagedConflict {
            target_ref,
            expected,
            current,
        }) => {
            assert_eq!(target_ref, "refs/heads/main");
            assert_eq!(expected, initial_tip);
            assert_eq!(current, conflicting_tip);
        }
        other => panic!("expected StagedConflict refusal, got {other:?}"),
    }
}

#[test]
fn offline_bundle_tampered_signature_is_refused() {
    let key = test_secret_key(0x42);
    let signer = OfflineSigner::new(&key, KeyEpoch::FIRST);
    let peer_id = PeerId::from_bytes(*signer.verifying_key().as_bytes());

    let mut key_history = PeerKeyHistory::new();
    key_history.register_key(0, *signer.verifying_key().as_bytes());
    let mut detector = EquivocationDetector::new();

    let basis = sample_basis_capsule(1, 0x10);
    let intents = vec![OfflineIntent::ProposedRefChange {
        target_ref: "refs/heads/main".to_owned(),
        expected_basis: sample_git_oid(0x10),
        proposed_tip: sample_git_oid(0x20),
    }];

    let mut bundle = create_offline_bundle(basis, peer_id, &signer, intents, vec![], vec![])
        .expect("bundle creation");

    // Tamper with signature
    let mut sig_bytes = *bundle.signature.signature();
    sig_bytes[0] ^= 0xff;
    bundle.signature = DetachedSignature::from_parts(
        bundle.signature.scheme(),
        bundle.signature.purpose(),
        bundle.signature.epoch(),
        *bundle.signature.key_commitment(),
        *bundle.signature.declared_verifying_key().as_bytes(),
        sig_bytes,
    );

    let mut refs = BTreeMap::new();
    refs.insert("refs/heads/main".to_owned(), sample_git_oid(0x10));
    let head = CurrentAuthorityState {
        head_generation: 1,
        head_tip: sample_git_oid(0x10),
        refs,
    };

    let result = import_offline_bundle(&bundle, &head, &mut detector, &key_history);
    assert_eq!(result, Err(FederationRefusal::InvalidSignature));
}

#[test]
fn empty_offline_bundle_is_refused() {
    let key = test_secret_key(0x42);
    let signer = OfflineSigner::new(&key, KeyEpoch::FIRST);
    let peer_id = PeerId::from_bytes(*signer.verifying_key().as_bytes());
    let basis = sample_basis_capsule(1, 0x10);

    let result = create_offline_bundle(basis, peer_id, &signer, vec![], vec![], vec![]);
    assert_eq!(result, Err(FederationRefusal::EmptyBundle));
}

// =========================================================================
// 2. Mirror Namespace and Proposed RefTxn Flows (Ref Authority Invariant)
// =========================================================================

#[test]
fn mirror_ref_uses_isolated_namespace_and_prevents_canonical_direct_write() {
    let peer_id = PeerId::from_bytes([0x77; 32]);
    let tip = sample_git_oid(0x44);

    // Permitted: valid branch in mirror namespace
    let mirror = MirrorRef::new(peer_id, "feature-x", tip, 5).expect("valid mirror ref");
    assert_eq!(
        mirror.full_ref_path(),
        format!("refs/federation/{}/feature-x", peer_id.to_hex())
    );
    assert_eq!(mirror.branch_name(), "feature-x");
    assert_eq!(mirror.tip(), tip);
    assert_eq!(mirror.observed_at_generation(), 5);

    // Stripping canonical prefix to mirror: "refs/heads/main" -> branch "main"
    let mirror2 = MirrorRef::new(peer_id, "refs/heads/main", tip, 6).expect("sanitized mirror ref");
    assert_eq!(
        mirror2.full_ref_path(),
        format!("refs/federation/{}/main", peer_id.to_hex())
    );

    // Refusal: attempting to direct-write to reserved refs other than heads
    let forbidden = MirrorRef::new(peer_id, "refs/tags/v1.0", tip, 7);
    assert_eq!(
        forbidden,
        Err(FederationRefusal::CanonicalRefDirectWriteForbidden {
            requested_ref: "refs/tags/v1.0".to_owned()
        })
    );
}

#[test]
fn proposed_reftxn_evaluation_against_authority_head() {
    let peer_id = PeerId::from_bytes([0x88; 32]);
    let target = CanonicalRef::parse("refs/heads/release").expect("valid canonical ref");
    let expected = sample_git_oid(0x50);
    let proposed = sample_git_oid(0x60);

    let proposal = ProposedRefTxn {
        proposal_id: ProposedTxnId::from_bytes([0x99; 32]),
        peer_id,
        target_ref: target,
        expected_basis: expected,
        proposed_tip: proposed,
        intent_id: [0x12; 32],
        signature: [0x00; 64],
        rationale: "Release v1.2 candidate".to_owned(),
    };

    // Case 1 (Permitted): Head is at expected commit
    let admitted = proposal
        .evaluate_against_head(expected, 12)
        .expect("proposal admitted when basis matches");
    assert_eq!(admitted.expected_basis, expected);
    assert_eq!(admitted.proposed_tip, proposed);
    assert_eq!(admitted.evaluated_at_generation, 12);

    // Case 2 (Refusal): Head has moved (conflict)
    let stale_outcome = proposal.evaluate_against_head(sample_git_oid(0x51), 13);
    assert_eq!(
        stale_outcome,
        Err(FederationRefusal::StagedConflict {
            target_ref: "refs/heads/release".to_owned(),
            expected,
            current: sample_git_oid(0x51),
        })
    );
}

// =========================================================================
// 3. Equivocation Fixture and Review-Surface Routing (§23.6 & ADR-0009)
// =========================================================================

#[test]
fn equivocation_fixture_produces_durable_evidence_and_routes_to_review() {
    let mut detector = EquivocationDetector::new();
    let peer_id = PeerId::from_bytes([0x33; 32]);

    let claim1 = SignedClaim {
        claim_id: [0x01; 32],
        peer_id,
        scope: "refs/heads/main".to_owned(),
        generation: 10,
        claimed_value: sample_git_oid(0xaa),
        signature: [0x11; 64],
    };

    // First claim recorded
    let outcome1 = detector
        .observe_claim(claim1.clone(), 1000)
        .expect("first claim recorded");
    assert_eq!(outcome1, ObservationOutcome::ClaimRecorded);
    assert!(!detector.is_quarantined(&peer_id));
    assert_eq!(detector.evidence_count(), 0);

    // Idempotent duplicate ignored
    let outcome2 = detector
        .observe_claim(claim1, 1001)
        .expect("duplicate claim");
    assert_eq!(outcome2, ObservationOutcome::DuplicateIgnored);
    assert!(!detector.is_quarantined(&peer_id));

    // Second CONTRADICTORY claim signed by the same peer for same scope & generation
    let claim2 = SignedClaim {
        claim_id: [0x02; 32],
        peer_id,
        scope: "refs/heads/main".to_owned(),
        generation: 10,
        claimed_value: sample_git_oid(0xbb), // Contradiction: 0xbb != 0xaa!
        signature: [0x22; 64],
    };

    let outcome3 = detector
        .observe_claim(claim2, 1002)
        .expect("equivocation detection");

    match outcome3 {
        ObservationOutcome::EquivocationDetected {
            evidence,
            review_routing,
        } => {
            // Durable evidence retains BOTH claims
            assert_eq!(evidence.peer_id, peer_id);
            assert_eq!(evidence.generation, 10);
            assert_eq!(evidence.scope, "refs/heads/main");
            assert_eq!(evidence.first_claim.claimed_value, sample_git_oid(0xaa));
            assert_eq!(evidence.second_claim.claimed_value, sample_git_oid(0xbb));

            // Review routing created
            match review_routing {
                ReviewRouting::ReviewQueue {
                    peer_id: r_peer,
                    scope,
                    reason,
                    ..
                } => {
                    assert_eq!(r_peer, peer_id);
                    assert_eq!(scope, "refs/heads/main");
                    assert!(reason.contains("contradictory claims"));
                }
            }
        }
        other => panic!("expected EquivocationDetected, got {other:?}"),
    }

    // Peer is now quarantined
    assert!(detector.is_quarantined(&peer_id));
    assert_eq!(detector.evidence_count(), 1);
    assert_eq!(detector.review_queue().len(), 1);

    // Subsequent claims from the quarantined peer are refused
    let claim3 = SignedClaim {
        claim_id: [0x03; 32],
        peer_id,
        scope: "refs/heads/feature".to_owned(),
        generation: 11,
        claimed_value: sample_git_oid(0xcc),
        signature: [0x33; 64],
    };
    let outcome4 = detector.observe_claim(claim3, 1003);
    match outcome4 {
        Err(FederationRefusal::PeerQuarantined {
            peer_id: p,
            evidence_id: _,
        }) => {
            assert_eq!(p, peer_id);
        }
        other => panic!("expected PeerQuarantined refusal, got {other:?}"),
    }
}

// =========================================================================
// 4. Federated Event Classes and CALM Registry Alignment (§23.2)
// =========================================================================

#[test]
fn federated_event_classes_declare_calm_properties() {
    use fgit_calm::CoordinationClass;

    // Verify all 9 variants
    assert_eq!(FederatedEventClass::ALL.len(), 9);

    for class in FederatedEventClass::ALL {
        let calm_class = class.coordination_class();
        let is_free = class.is_coordination_free();
        let requires_cas = class.requires_local_authority();

        match class {
            FederatedEventClass::ImmutableObjectCapsule => {
                assert_eq!(calm_class, CoordinationClass::MonotoneWithAuthentication);
                assert!(is_free);
                assert!(!requires_cas);
            }
            FederatedEventClass::MirrorObservation => {
                assert_eq!(calm_class, CoordinationClass::CommutativeButBounded);
                assert!(is_free);
                assert!(!requires_cas);
            }
            FederatedEventClass::ProposedRefTxn => {
                assert_eq!(calm_class, CoordinationClass::HeadCasRequired);
                assert!(!is_free);
                assert!(requires_cas);
            }
            FederatedEventClass::SocialEvent => {
                assert_eq!(calm_class, CoordinationClass::CommutativeButBounded);
                assert!(is_free);
                assert!(!requires_cas);
            }
            FederatedEventClass::ModerationAndProtection => {
                assert_eq!(calm_class, CoordinationClass::HeadCasRequired);
                assert!(!is_free);
                assert!(requires_cas);
            }
            FederatedEventClass::ReviewAndEvidenceBundle => {
                assert_eq!(calm_class, CoordinationClass::MonotoneWithAuthentication);
                assert!(is_free);
                assert!(!requires_cas);
            }
            FederatedEventClass::ReleaseAttestation => {
                assert_eq!(calm_class, CoordinationClass::MonotoneWithAuthentication);
                assert!(is_free);
                assert!(!requires_cas);
            }
            FederatedEventClass::EquivocationEvidence => {
                assert_eq!(calm_class, CoordinationClass::MonotoneWithAuthentication);
                assert!(is_free);
                assert!(!requires_cas);
            }
            FederatedEventClass::OfflineWorkBundleImport => {
                assert_eq!(calm_class, CoordinationClass::HeadCasRequired);
                assert!(!is_free);
                assert!(requires_cas);
            }
        }
    }
}

// =========================================================================
// 5. Two-Instance Collaboration Scenario
// =========================================================================

#[test]
fn two_instance_collaboration_roundtrip_exchange() {
    // Instance A: Canonical Forge Node
    let instance_a_tip = sample_git_oid(0x01);
    let mut instance_a_refs = BTreeMap::new();
    instance_a_refs.insert("refs/heads/main".to_owned(), instance_a_tip);
    let instance_a_head = CurrentAuthorityState {
        head_generation: 10,
        head_tip: instance_a_tip,
        refs: instance_a_refs,
    };
    let mut instance_a_detector = EquivocationDetector::new();

    // Instance B: Offline Contributor
    let instance_b_key = test_secret_key(0x7b);
    let instance_b_signer = OfflineSigner::new(&instance_b_key, KeyEpoch::FIRST);
    let instance_b_peer = PeerId::from_bytes(*instance_b_signer.verifying_key().as_bytes());

    let mut instance_a_key_history = PeerKeyHistory::new();
    instance_a_key_history.register_key(0, *instance_b_signer.verifying_key().as_bytes());

    // Step 1: Instance B receives basis capsule from Instance A
    let basis_from_a = BasisCapsule {
        capsule_id: [0x55; 32],
        repo_id: [0x01; 32],
        head_generation: 10,
        head_tip: instance_a_tip,
        snapshot_root: [0x66; 32],
    };

    // Step 2: Instance B develops offline and commits a new patch
    let b_new_tip = sample_git_oid(0x02);
    let bundle_from_b = create_offline_bundle(
        basis_from_a,
        instance_b_peer,
        &instance_b_signer,
        vec![
            OfflineIntent::ProposedRefChange {
                target_ref: "refs/heads/main".to_owned(),
                expected_basis: instance_a_tip,
                proposed_tip: b_new_tip,
            },
            OfflineIntent::AppendSocialComment {
                topic: "patch-001".to_owned(),
                content_digest: [0x99; 32],
                author: instance_b_peer,
            },
        ],
        vec![OfflineEffect {
            effect_id: [0x88; 32],
            object_id: b_new_tip,
            byte_length: 2048,
        }],
        vec![OfflineEvidence {
            evidence_id: [0x77; 32],
            claim_class: "local_reproducibility".to_owned(),
            payload: b"tests passed offline".to_vec(),
        }],
    )
    .expect("bundle created offline");

    // Step 3: Bundle is transferred to Instance A and imported
    let receipt = import_offline_bundle(
        &bundle_from_b,
        &instance_a_head,
        &mut instance_a_detector,
        &instance_a_key_history,
    )
    .expect("instance A imports valid offline bundle");

    assert_eq!(receipt.admitted_proposals.len(), 1);
    assert_eq!(receipt.admitted_proposals[0].expected_basis, instance_a_tip);
    assert_eq!(receipt.admitted_proposals[0].proposed_tip, b_new_tip);
    assert_eq!(receipt.admitted_mirror_refs.len(), 1);
    assert_eq!(
        receipt.admitted_mirror_refs[0].full_ref_path(),
        format!("refs/federation/{}/main", instance_b_peer.to_hex())
    );
    assert_eq!(receipt.admitted_social_events.len(), 1);
    assert_eq!(receipt.retained_evidence.len(), 1);
}
