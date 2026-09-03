#![forbid(unsafe_code)]
//! Public-path tests for the pure merge delivery transition.

use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState};
use fgit_reference::{
    MergeDeliveryInput, MergeDeliveryTransitionRefusal, apply_merge_delivery_transition,
};
use fgit_reference::intent::{ForgeStreamId, ForgeStreamPosition};
use fgit_types::{
    AsciiSlug, CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes,
    RepositoryCommitId, RepositoryId, TxId,
};

fn algorithm() -> DigestAlgorithmId {
    DigestAlgorithmId::try_new(2).expect("registered SHA-256 code point")
}

fn bytes(byte: u8) -> DigestBytes {
    DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest")
}

fn digest(byte: u8) -> Digest {
    Digest::new(algorithm(), bytes(byte))
}

fn tx(byte: u8) -> TxId {
    TxId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, bytes(byte))
}

fn rcr(byte: u8) -> RepositoryCommitId {
    RepositoryCommitId::from_digest(
        algorithm(),
        CANONICAL_CODEC_VERSION,
        bytes(byte),
    )
}

fn input(repository_id: RepositoryId, payload: u8) -> MergeDeliveryInput {
    MergeDeliveryInput::new(
        repository_id,
        ForgeStreamId::new(AsciiSlug::from_static("pull-requests")),
        ForgeStreamPosition::GENESIS,
        1,
        digest(0x41),
        AsciiSlug::from_static("forge-event-delivery"),
        AsciiSlug::from_static("forge-stream"),
        digest(payload),
        tx(0x51),
        Some(rcr(0x52)),
        digest(0x53),
    )
}

fn empty_basis(
    repository_id: RepositoryId,
) -> (CanonicalForgePositionState, CanonicalOutboxState) {
    (
        CanonicalForgePositionState::try_new(repository_id, Vec::new())
            .expect("empty forge state"),
        CanonicalOutboxState::try_new(repository_id, Vec::new())
            .expect("empty outbox state"),
    )
}

#[test]
fn identical_inputs_produce_identical_successor_roots_and_delivery_key() {
    let repository_id = RepositoryId::from_bytes([0x11; 16]);
    let (forge, outbox) = empty_basis(repository_id);
    let first = apply_merge_delivery_transition(&forge, &outbox, input(repository_id, 0x61))
        .expect("valid transition");
    let second = apply_merge_delivery_transition(&forge, &outbox, input(repository_id, 0x61))
        .expect("identical transition");

    assert_eq!(first, second);
    assert_eq!(first.delivery_key().label().len(), 64);
    assert_eq!(
        first
            .forge_positions()
            .entry(AsciiSlug::from_static("pull-requests"))
            .expect("stream")
            .successor_position(),
        1
    );
    assert!(first
        .outbox()
        .entry(first.delivery_key().label())
        .is_some());
    assert_ne!(first.forge_position_root(), forge.root().expect("basis root"));
    assert_ne!(first.outbox_root(), outbox.root().expect("basis root"));
}

#[test]
fn payload_changes_delivery_identity_without_changing_forge_position_state() {
    let repository_id = RepositoryId::from_bytes([0x22; 16]);
    let (forge, outbox) = empty_basis(repository_id);
    let first = apply_merge_delivery_transition(&forge, &outbox, input(repository_id, 0x61))
        .expect("valid transition");
    let changed = apply_merge_delivery_transition(&forge, &outbox, input(repository_id, 0x62))
        .expect("valid changed transition");

    assert_ne!(first.delivery_key(), changed.delivery_key());
    assert_ne!(first.outbox_root(), changed.outbox_root());
    assert_eq!(first.forge_position_root(), changed.forge_position_root());
}

#[test]
fn stale_position_and_existing_delivery_key_fail_closed() {
    let repository_id = RepositoryId::from_bytes([0x33; 16]);
    let (forge, outbox) = empty_basis(repository_id);
    let first = apply_merge_delivery_transition(&forge, &outbox, input(repository_id, 0x61))
        .expect("valid transition");

    assert_eq!(
        apply_merge_delivery_transition(
            first.forge_positions(),
            first.outbox(),
            input(repository_id, 0x61),
        )
        .expect_err("the original expected position is stale"),
        MergeDeliveryTransitionRefusal::ForgePositionMismatch {
            stream: ForgeStreamId::new(AsciiSlug::from_static("pull-requests")),
            expected: ForgeStreamPosition::GENESIS,
            observed: ForgeStreamPosition::new(1),
        }
    );

    assert_eq!(
        apply_merge_delivery_transition(&forge, first.outbox(), input(repository_id, 0x61))
            .expect_err("stable key cannot overwrite an existing obligation"),
        MergeDeliveryTransitionRefusal::DeliveryKeyAlreadyPresent {
            delivery_key: first.delivery_key(),
        }
    );
}

#[test]
fn repository_mismatch_is_refused_before_any_successor_is_built() {
    let repository_id = RepositoryId::from_bytes([0x44; 16]);
    let other = RepositoryId::from_bytes([0x45; 16]);
    let (forge, _) = empty_basis(repository_id);
    let (_, outbox) = empty_basis(other);

    assert_eq!(
        apply_merge_delivery_transition(&forge, &outbox, input(repository_id, 0x61))
            .expect_err("cross-repository state cannot be combined"),
        MergeDeliveryTransitionRefusal::RepositoryMismatch {
            expected: repository_id,
            forge_observed: repository_id,
            outbox_observed: other,
        }
    );
}
