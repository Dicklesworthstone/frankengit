#![forbid(unsafe_code)]
//! Public-path tests for the pure merge delivery transition.

use fgit_codec::{CanonicalForgePositionState, CanonicalOutboxState};
use fgit_reference::intent::{ForgeStreamId, ForgeStreamPosition};
use fgit_reference::merge_delivery::apply_batch_delivery_transition;
use fgit_reference::{
    MergeDeliveryInput, MergeDeliveryTransitionRefusal, apply_merge_delivery_transition,
};
use fgit_types::{
    AsciiSlug, CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, RepositoryCommitId,
    RepositoryId, TxId,
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
    RepositoryCommitId::from_digest(algorithm(), CANONICAL_CODEC_VERSION, bytes(byte))
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

fn empty_basis(repository_id: RepositoryId) -> (CanonicalForgePositionState, CanonicalOutboxState) {
    (
        CanonicalForgePositionState::try_new(repository_id, Vec::new()).expect("empty forge state"),
        CanonicalOutboxState::try_new(repository_id, Vec::new()).expect("empty outbox state"),
    )
}

fn another_stream(
    original: MergeDeliveryInput,
    stream: &'static str,
    position: u64,
    count: u32,
) -> MergeDeliveryInput {
    MergeDeliveryInput::new(
        original.repository_id(),
        ForgeStreamId::new(AsciiSlug::from_static(stream)),
        ForgeStreamPosition::new(position),
        count,
        original.event_batch_root(),
        original.effect_class(),
        original.destination(),
        original.payload_root(),
        original.tx_id(),
        original.predecessor_rcr_id(),
        original.initial_effect_state_root(),
    )
}

#[test]
fn multi_stream_merge_delivery_uses_one_obligation_and_exact_independent_positions() {
    let repository = RepositoryId::from_bytes([0x71; 16]);
    let (forge, outbox) = empty_basis(repository);
    let pull = input(repository, 0x61);
    let queue = another_stream(pull, "queue/1", 0, 2);
    let transition = apply_batch_delivery_transition(&forge, &outbox, &[queue, pull]).unwrap();
    assert_eq!(transition.forge_positions().entries().len(), 2);
    assert_eq!(transition.outbox().entries().len(), 1);
    for (stream, count) in [(pull.stream(), 1), (queue.stream(), 2)] {
        let advanced = transition.forge_positions().entry(stream.label()).unwrap();
        assert_eq!(advanced.event_count(), count);
        assert_eq!(advanced.successor_position(), u64::from(count));
        assert_eq!(advanced.event_batch_root(), pull.event_batch_root());
    }
    assert_eq!(
        transition,
        apply_batch_delivery_transition(&forge, &outbox, &[pull, queue]).unwrap(),
    );
    assert_eq!(
        apply_batch_delivery_transition(&forge, &outbox, &[pull]).unwrap(),
        apply_merge_delivery_transition(&forge, &outbox, pull).unwrap(),
    );
    let next_pull = another_stream(input(repository, 0x62), "pull-requests", 1, 1);
    let next_queue = another_stream(next_pull, "queue/1", 2, 2);
    let next = apply_batch_delivery_transition(
        transition.forge_positions(),
        transition.outbox(),
        &[next_pull, next_queue],
    )
    .unwrap();
    assert_eq!(next.outbox().entries().len(), 2);
    assert_eq!(
        next.forge_positions()
            .entry(queue.stream().label())
            .unwrap()
            .successor_position(),
        4
    );
}

#[test]
fn multi_stream_merge_delivery_rejects_duplicates_mixed_bindings_and_stale_second_stream() {
    let repository = RepositoryId::from_bytes([0x72; 16]);
    let (forge, outbox) = empty_basis(repository);
    let pull = input(repository, 0x61);
    let queue = another_stream(pull, "queue/1", 0, 2);
    for inputs in [
        vec![],
        vec![pull, pull],
        vec![
            pull,
            another_stream(input(repository, 0x62), "queue/1", 0, 2),
        ],
        vec![pull, another_stream(pull, "queue/1", 1, 2)],
        vec![pull, another_stream(pull, "queue/1", 0, 0)],
    ] {
        assert!(apply_batch_delivery_transition(&forge, &outbox, &inputs).is_err());
    }
    let first = apply_batch_delivery_transition(&forge, &outbox, &[pull, queue]).unwrap();
    let updated_pull = another_stream(input(repository, 0x62), "pull-requests", 1, 1);
    let stale_queue = another_stream(updated_pull, "queue/1", 0, 2);
    assert!(matches!(
        apply_batch_delivery_transition(first.forge_positions(), first.outbox(), &[updated_pull, stale_queue]),
        Err(MergeDeliveryTransitionRefusal::ForgePositionMismatch { stream, .. }) if stream == queue.stream()
    ));
    assert_eq!(forge.entries().len(), 0);
    assert_eq!(outbox.entries().len(), 0);
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
    assert!(first.outbox().entry(first.delivery_key().label()).is_some());
    assert_ne!(
        first.forge_position_root(),
        forge.root().expect("basis root")
    );
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
