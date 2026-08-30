//! Envelope verification and disclosure-boundary coverage for FG-037a.

use core::cell::Cell;

use fgit_authority::{TerminalOutcome, outcome_index_proof, outcome_index_root};
use fgit_codec::{CryptoBodyIdentity, RepositoryConfigurationBody, body_id, harness::genesis_head};
use fgit_crypto::{
    IdentityDomain, object_closure_membership_proof, object_closure_merkle_root,
    object_closure_non_membership_proof, ref_state_membership_proof, ref_state_merkle_root,
    ref_state_non_membership_proof,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryCommitId, TxId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::DecisionSequence;
use fgit_types::refs::RefName;
use fgit_types::vocabulary::DecisionOutcome;
use fgit_verified_read::{
    ObjectDisclosurePolicy, PinnedAuthorityHead, ReadResponse, RefDisclosurePolicy,
    UnprovenReadAnswer, VerifiedMembership, VerifiedReadAnswer, VerifiedReadCapability,
    VerifiedReadEnvelope, VerifiedReadRefusal, VerifiedReadResponseMode, authorize_object_absence,
    authorize_ref_absence, negotiate_response_mode, refuse_forge_position_proof, verify_envelope,
};

struct AllowAll;

impl RefDisclosurePolicy for AllowAll {
    fn permits_ref_disclosure(&self, _name: &RefName) -> bool {
        true
    }
}

struct DenyAll;

impl RefDisclosurePolicy for DenyAll {
    fn permits_ref_disclosure(&self, _name: &RefName) -> bool {
        false
    }
}

struct AllowAllObject;

impl ObjectDisclosurePolicy for AllowAllObject {
    fn permits_object_disclosure(&self, _oid: &GitOid) -> bool {
        true
    }
}

struct DenyAllObject;

impl ObjectDisclosurePolicy for DenyAllObject {
    fn permits_object_disclosure(&self, _oid: &GitOid) -> bool {
        false
    }
}

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).expect("fixture ref name is valid")
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
}

fn tx(byte: u8) -> TxId {
    TxId::from_digest(
        IdentityDomain::RefTransaction.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixture digest is bounded"),
    )
}

fn committed(sequence: u64, byte: u8) -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(sequence)
            .expect("fixture sequence is positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                IdentityDomain::RepositoryCommitRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[byte; 32]).expect("fixture digest is bounded"),
            ),
        },
    }
}

fn v1_configuration() -> (RepositoryConfigurationBody, Digest) {
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    };
    let identity = body_id(&CryptoBodyIdentity, &configuration)
        .expect("the canonical configuration has an identity");
    (
        configuration,
        Digest::new(identity.algorithm(), *identity.digest()),
    )
}

/// The cumulative layout for the object-family cases: only
/// `RefStateAndObjectClosureMerkleV1` admits object-closure proofs
/// (`RootLayoutVersion::admits_object_closure_membership_proof`), so a head
/// under the ref-only V1 layout must refuse every honest object answer with
/// `ObjectLayout(LayoutAdmitsNoProof)` — that is the layout contract working,
/// not a bug. The ref-path fixtures below deliberately keep `v1_configuration`
/// so both layouts stay covered.
fn combined_configuration() -> (RepositoryConfigurationBody, Digest) {
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateAndObjectClosureMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    };
    let identity = body_id(&CryptoBodyIdentity, &configuration)
        .expect("the canonical configuration has an identity");
    (
        configuration,
        Digest::new(identity.algorithm(), *identity.digest()),
    )
}

fn ref_fixture() -> (PinnedAuthorityHead, VerifiedReadEnvelope, RefName, GitOid) {
    let main = name(b"refs/heads/main");
    let entries = vec![
        (main.clone(), oid(0x11)),
        (name(b"refs/tags/v1"), oid(0x22)),
    ];
    let root = ref_state_merkle_root(&entries).expect("the ref map is canonical");
    let (bound_oid, proof) =
        ref_state_membership_proof(&entries, &main).expect("the named ref is present");
    let (configuration, configuration_root) = v1_configuration();
    let mut head = genesis_head();
    head.ref_root = root;
    head.configuration_root = configuration_root;
    let pinned = PinnedAuthorityHead::new(head.clone());
    let envelope = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::RefMembership {
            name: main.clone(),
            oid: bound_oid,
            proof: Box::new(proof),
        },
    );
    (pinned, envelope, main, bound_oid)
}

#[test]
fn a_versioned_ref_envelope_verifies_against_its_exact_pinned_head() {
    let (pinned, envelope, _, _) = ref_fixture();

    assert_eq!(
        verify_envelope(&pinned, &envelope),
        Ok(VerifiedMembership::Ref),
        "the canonical ref proof must verify only when the envelope and client select the same head"
    );
}

#[test]
fn a_ref_proof_cannot_be_rebound_to_a_different_object_or_head() {
    let (pinned, envelope, name, _) = ref_fixture();
    let VerifiedReadAnswer::RefMembership { proof, .. } = envelope.answer().clone() else {
        panic!("the fixture is a ref membership response");
    };
    let rebound = VerifiedReadEnvelope::new(
        envelope.head().clone(),
        envelope.configuration().cloned(),
        VerifiedReadAnswer::RefMembership {
            name,
            oid: oid(0x33),
            proof,
        },
    );
    assert_eq!(
        verify_envelope(&pinned, &rebound),
        Err(VerifiedReadRefusal::ProofRejected),
        "a path for one native object identity must not prove another"
    );

    let other_pin = PinnedAuthorityHead::new(genesis_head());
    assert_eq!(
        verify_envelope(&other_pin, &envelope),
        Err(VerifiedReadRefusal::PinnedHeadMismatch),
        "the served head is data, never permission to replace the client's pin"
    );
}

#[test]
fn a_ref_proof_requires_a_configuration_that_identifies_to_the_pinned_head() {
    let (pinned, envelope, _, _) = ref_fixture();
    let missing_configuration =
        VerifiedReadEnvelope::new(envelope.head().clone(), None, envelope.answer().clone());

    assert!(matches!(
        verify_envelope(&pinned, &missing_configuration),
        Err(VerifiedReadRefusal::RefLayout(_))
    ));
    let mut mismatched_head = envelope.head().clone();
    mismatched_head.configuration_root = genesis_head().configuration_root;
    let mismatched_pin = PinnedAuthorityHead::new(mismatched_head.clone());
    let mismatched_configuration = VerifiedReadEnvelope::new(
        mismatched_head,
        envelope.configuration().cloned(),
        envelope.answer().clone(),
    );
    assert_eq!(
        verify_envelope(&mismatched_pin, &mismatched_configuration),
        Err(VerifiedReadRefusal::ConfigurationRootMismatch),
        "a serving cell cannot select a V1 layout body that the pinned head did not commit to"
    );
    assert_eq!(
        envelope
            .configuration()
            .expect("fixture includes configuration")
            .root_layout,
        RootLayoutVersion::RefStateMerkleV1,
        "the permitted twin carries the exact configuration body selected by the head"
    );
    assert_eq!(
        verify_envelope(&pinned, &envelope),
        Ok(VerifiedMembership::Ref)
    );
}

#[test]
fn an_outcome_envelope_verifies_against_the_pinned_outcome_index_root() {
    let outcome = committed(1, 0x55);
    let entries = vec![(tx(0xA1), outcome)];
    let root = outcome_index_root(&entries).expect("a terminal outcome has a canonical root");
    let proof = outcome_index_proof(&entries, tx(0xA1), &outcome)
        .expect("the indexed terminal outcome has a membership proof");
    let mut head = genesis_head();
    head.outcome_index_root = root;
    let pinned = PinnedAuthorityHead::new(head.clone());
    let envelope = VerifiedReadEnvelope::new(
        head,
        None,
        VerifiedReadAnswer::OutcomeMembership {
            tx_id: tx(0xA1),
            outcome: Box::new(outcome),
            proof: Box::new(proof),
        },
    );

    assert_eq!(
        verify_envelope(&pinned, &envelope),
        Ok(VerifiedMembership::Outcome)
    );
}

#[test]
fn denied_absence_queries_are_indistinguishable_and_never_reach_lookup() {
    let policy = DenyAll;
    let existing_lookup_called = Cell::new(false);
    let absent_lookup_called = Cell::new(false);
    let hidden_existing = authorize_ref_absence(&policy, name(b"refs/hidden/existing"), |_| {
        existing_lookup_called.set(true);
        true
    });
    let hidden_absent = authorize_ref_absence(&policy, name(b"refs/hidden/absent"), |_| {
        absent_lookup_called.set(true);
        false
    });

    assert_eq!(
        hidden_existing,
        Err(VerifiedReadRefusal::RefNotFoundOrUnauthorized),
        "a hidden existing ref must report the public absence refusal"
    );
    assert_eq!(
        hidden_absent,
        Err(VerifiedReadRefusal::RefNotFoundOrUnauthorized),
        "a hidden absent ref must report the same public refusal"
    );
    assert!(!existing_lookup_called.get());
    assert!(!absent_lookup_called.get());
}

#[test]
fn authorized_absence_verifies_across_v1_positions_and_membership_remains_permitted() {
    let main = name(b"refs/heads/main");
    let tag = name(b"refs/tags/v1");
    let entries = vec![(main, oid(0x11)), (tag, oid(0x22))];
    for (label, state, query) in [
        ("empty", Vec::new(), name(b"refs/heads/missing")),
        ("before-first", entries.clone(), name(b"refs/heads/aaa")),
        ("between", entries.clone(), name(b"refs/heads/mid")),
        ("after-last", entries, name(b"refs/zzzz")),
    ] {
        let root = ref_state_merkle_root(&state).expect("fixture state has a canonical root");
        let proof = ref_state_non_membership_proof(&state, &query)
            .expect("fixture query is genuinely absent");
        let absence = authorize_ref_absence(&AllowAll, query, |_| false)
            .expect("authorized absent ref may be proven");
        let (configuration, configuration_root) = v1_configuration();
        let mut head = genesis_head();
        head.ref_root = root;
        head.configuration_root = configuration_root;
        let pinned = PinnedAuthorityHead::new(head.clone());
        let envelope = VerifiedReadEnvelope::new(
            head,
            Some(configuration),
            VerifiedReadAnswer::AuthorizedRefAbsence {
                absence,
                proof: Box::new(proof),
            },
        );
        assert_eq!(
            verify_envelope(&pinned, &envelope),
            Ok(VerifiedMembership::RefAbsence),
            "the {label} V1 position must verify under the exact pin"
        );
    }

    let (pinned, membership, _, _) = ref_fixture();
    assert_eq!(
        verify_envelope(&pinned, &membership),
        Ok(VerifiedMembership::Ref),
        "proving authorized absence does not weaken the permitted membership twin"
    );
}

#[test]
fn authorized_absence_proof_refuses_a_name_outside_its_proven_interval() {
    let entries = vec![
        (name(b"refs/heads/main"), oid(0x11)),
        (name(b"refs/tags/v1"), oid(0x22)),
    ];
    let query = name(b"refs/heads/mid");
    let root = ref_state_merkle_root(&entries).expect("fixture state has a canonical root");
    let proof = ref_state_non_membership_proof(&entries, &query)
        .expect("fixture query is genuinely absent");
    let (configuration, configuration_root) = v1_configuration();
    let mut head = genesis_head();
    head.ref_root = root;
    head.configuration_root = configuration_root;
    let pinned = PinnedAuthorityHead::new(head.clone());
    let rebound_absence = authorize_ref_absence(&AllowAll, name(b"refs/heads/aaa"), |_| false)
        .expect("the second fixture query is authorized and absent");
    let rebound = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::AuthorizedRefAbsence {
            absence: rebound_absence,
            proof: Box::new(proof),
        },
    );

    assert_eq!(
        verify_envelope(&pinned, &rebound),
        Err(VerifiedReadRefusal::ProofRejected),
        "a between-neighbour proof must not prove a name before its first leaf"
    );
}

#[test]
fn unproven_mode_stays_available_and_forge_positions_remain_refused() {
    assert_eq!(
        negotiate_response_mode(VerifiedReadCapability::Unproven),
        VerifiedReadResponseMode::Unproven
    );
    assert_eq!(
        negotiate_response_mode(VerifiedReadCapability::EnvelopeV1),
        VerifiedReadResponseMode::EnvelopeV1
    );
    let expected_absent = name(b"refs/heads/missing");
    let unproven = ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Ref {
        name: expected_absent.clone(),
        oid: None,
    }));
    let ReadResponse::Unproven(answer) = unproven else {
        panic!("fixture negotiated the unproven representation");
    };
    assert_eq!(
        answer.as_ref(),
        &UnprovenReadAnswer::Ref {
            name: expected_absent,
            oid: None,
        }
    );
    let unproven_outcome = ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Outcome {
        tx_id: tx(0xA1),
        outcome: Some(Box::new(committed(1, 0x55))),
    }));
    assert!(matches!(
        unproven_outcome,
        ReadResponse::Unproven(answer)
            if matches!(answer.as_ref(), UnprovenReadAnswer::Outcome { outcome: Some(_), .. })
    ));
    let unproven_object = ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Object {
        oid: oid(0x11),
        present: true,
    }));
    assert_eq!(
        unproven_object,
        ReadResponse::Unproven(Box::new(UnprovenReadAnswer::Object {
            oid: oid(0x11),
            present: true,
        }))
    );
    assert_eq!(
        refuse_forge_position_proof(),
        Err(VerifiedReadRefusal::ForgePositionProofUnavailable),
        "forge roots remain a typed non-claim until their canonical layout exists"
    );
}

#[test]
fn an_object_envelope_verifies_against_the_pinned_object_closure_root() {
    let objects = vec![oid(0x11), oid(0x22), oid(0x33)];
    let root = object_closure_merkle_root(&objects).expect("object closure root");
    let proof = object_closure_membership_proof(&objects, &oid(0x22)).expect("object proof");
    let (configuration, configuration_root) = combined_configuration();
    let mut head = genesis_head();
    head.configuration_root = configuration_root;
    let pinned = PinnedAuthorityHead::new_with_object_closure(head.clone(), root);
    let envelope = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::ObjectMembership {
            oid: oid(0x22),
            proof: Box::new(proof),
        },
    );

    assert_eq!(
        verify_envelope(&pinned, &envelope),
        Ok(VerifiedMembership::Object),
    );
}

#[test]
fn denied_object_absence_queries_are_indistinguishable_and_never_reach_lookup() {
    let policy = DenyAllObject;
    let existing_lookup_called = Cell::new(false);
    let absent_lookup_called = Cell::new(false);
    let hidden_existing = authorize_object_absence(&policy, oid(0x11), |_| {
        existing_lookup_called.set(true);
        true
    });
    let hidden_absent = authorize_object_absence(&policy, oid(0x99), |_| {
        absent_lookup_called.set(true);
        false
    });

    assert_eq!(
        hidden_existing,
        Err(VerifiedReadRefusal::ObjectNotFoundOrUnauthorized),
        "a hidden existing object must report the public absence refusal"
    );
    assert_eq!(
        hidden_absent,
        Err(VerifiedReadRefusal::ObjectNotFoundOrUnauthorized),
        "a hidden absent object must report the same public refusal"
    );
    assert!(!existing_lookup_called.get());
    assert!(!absent_lookup_called.get());
}

#[test]
fn authorized_object_absence_verifies_across_v1_positions_and_membership_remains_permitted() {
    let objects = vec![oid(0x11), oid(0x22), oid(0x33)];
    for (label, state, query) in [
        ("empty", Vec::new(), oid(0x15)),
        ("before-first", objects.clone(), oid(0x05)),
        ("between", objects.clone(), oid(0x15)),
        ("after-last", objects, oid(0x40)),
    ] {
        let root = object_closure_merkle_root(&state).expect("root");
        let proof = object_closure_non_membership_proof(&state, &query).expect("absence proof");
        let absence = authorize_object_absence(&AllowAllObject, query, |_| false)
            .expect("authorized absence");
        let (configuration, configuration_root) = combined_configuration();
        let mut head = genesis_head();
        head.configuration_root = configuration_root;
        let pinned = PinnedAuthorityHead::new_with_object_closure(head.clone(), root);
        let envelope = VerifiedReadEnvelope::new(
            head,
            Some(configuration),
            VerifiedReadAnswer::AuthorizedObjectAbsence {
                absence,
                proof: Box::new(proof),
            },
        );
        assert_eq!(
            verify_envelope(&pinned, &envelope),
            Ok(VerifiedMembership::ObjectAbsence),
            "the {label} object position must verify under the exact pin"
        );
    }
}
