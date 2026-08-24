//! Envelope verification and disclosure-boundary coverage for FG-037a.

use core::cell::Cell;

use fgit_authority::{TerminalOutcome, outcome_index_proof, outcome_index_root};
use fgit_codec::{CryptoBodyIdentity, RepositoryConfigurationBody, body_id, harness::genesis_head};
use fgit_crypto::{IdentityDomain, ref_state_membership_proof, ref_state_merkle_root};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryCommitId, TxId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::DecisionSequence;
use fgit_types::refs::RefName;
use fgit_types::vocabulary::DecisionOutcome;
use fgit_verified_read::{
    PinnedAuthorityHead, ReadResponse, RefDisclosurePolicy, UnprovenReadAnswer, VerifiedMembership,
    VerifiedReadAnswer, VerifiedReadCapability, VerifiedReadEnvelope, VerifiedReadRefusal,
    VerifiedReadResponseMode, authorize_ref_absence, negotiate_response_mode,
    refuse_forge_position_proof, verify_envelope,
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

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).expect("fixture ref name is valid")
}

fn oid(byte: u8) -> GitOid {
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
            proof,
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
        envelope.configuration().copied(),
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
        envelope.configuration().copied(),
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
            outcome,
            proof,
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
fn authorized_absence_is_explicitly_unproven_and_unproven_mode_stays_available() {
    let absence = authorize_ref_absence(&AllowAll, name(b"refs/heads/missing"), |_| false)
        .expect("an authorized lookup may report absence");
    let head = genesis_head();
    let pinned = PinnedAuthorityHead::new(head.clone());
    let envelope = VerifiedReadEnvelope::new(
        head,
        None,
        VerifiedReadAnswer::AuthorizedRefAbsence(absence.clone()),
    );

    assert_eq!(
        verify_envelope(&pinned, &envelope),
        Err(VerifiedReadRefusal::RefAbsenceNotIndependentlyProven),
        "no empty Merkle path may be upgraded into a false non-membership claim"
    );
    assert_eq!(
        negotiate_response_mode(VerifiedReadCapability::Unproven),
        VerifiedReadResponseMode::Unproven
    );
    assert_eq!(
        negotiate_response_mode(VerifiedReadCapability::EnvelopeV1),
        VerifiedReadResponseMode::EnvelopeV1
    );
    let unproven = ReadResponse::Unproven(UnprovenReadAnswer::Ref {
        name: absence.name().clone(),
        oid: None,
    });
    assert!(matches!(
        unproven,
        ReadResponse::Unproven(UnprovenReadAnswer::Ref {
            name,
            oid: None
        }) if name == *absence.name()
    ));
    assert_eq!(
        refuse_forge_position_proof(),
        Err(VerifiedReadRefusal::ForgePositionProofUnavailable),
        "forge roots remain a typed non-claim until their canonical layout exists"
    );
}
