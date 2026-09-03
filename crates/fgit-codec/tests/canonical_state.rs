#![forbid(unsafe_code)]
//! Public-path tests for canonical forge-position and outbox state bodies.

use fgit_codec::{
    CanonicalForgePositionState, CanonicalOutboxState, CanonicalOutboxStateEntry,
    CodecRefusal, DecodeLimits, ForgePositionStateEntry, decode_body, encode_body,
};
use fgit_types::{
    AsciiSlug, Digest, DigestAlgorithmId, DigestBytes, RepositoryId,
};

fn slug(value: &'static str) -> AsciiSlug {
    AsciiSlug::from_static(value)
}

fn digest(byte: u8) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("registered SHA-256 code point"),
        DigestBytes::try_new(&[byte; 32]).expect("fixed-width digest"),
    )
}

fn forge_entry(
    stream: &'static str,
    predecessor_position: u64,
    event_count: u32,
    event_root: u8,
) -> ForgePositionStateEntry {
    ForgePositionStateEntry::try_new(
        slug(stream),
        predecessor_position,
        event_count,
        digest(event_root),
    )
    .expect("valid forge-position entry")
}

fn outbox_entry(key: &'static str, payload_root: u8) -> CanonicalOutboxStateEntry {
    CanonicalOutboxStateEntry::new(
        slug(key),
        slug("forge-event-delivery"),
        slug("forge-stream"),
        digest(payload_root),
        digest(0x61),
        digest(0x62),
        digest(0x63),
        Some(digest(0x64)),
    )
}

#[test]
fn forge_position_state_round_trips_and_root_ignores_input_order() {
    let repository_id = RepositoryId::from_bytes([0x11; 16]);
    let first = CanonicalForgePositionState::try_new(
        repository_id,
        vec![
            forge_entry("pull-requests", 40, 2, 0x41),
            forge_entry("issues", 7, 1, 0x42),
        ],
    )
    .expect("valid forge state");
    let reordered = CanonicalForgePositionState::try_new(
        repository_id,
        vec![
            forge_entry("issues", 7, 1, 0x42),
            forge_entry("pull-requests", 40, 2, 0x41),
        ],
    )
    .expect("same map in another caller order");

    let encoded = encode_body(&first).expect("canonical frame");
    let decoded = decode_body::<CanonicalForgePositionState>(
        &encoded,
        DecodeLimits::DEFAULT,
    )
    .expect("strict decode");

    assert_eq!(decoded, first);
    assert_eq!(first, reordered);
    assert_eq!(first.root().expect("root"), reordered.root().expect("root"));
    let pulls = first
        .entry(slug("pull-requests"))
        .expect("stream is present");
    assert_eq!(pulls.predecessor_position(), 40);
    assert_eq!(pulls.event_count(), 2);
    assert_eq!(pulls.successor_position(), 42);
}

#[test]
fn outbox_state_round_trips_and_every_semantic_field_is_bound() {
    let repository_id = RepositoryId::from_bytes([0x22; 16]);
    let first = CanonicalOutboxState::try_new(
        repository_id,
        vec![outbox_entry("delivery-b", 0x51), outbox_entry("delivery-a", 0x52)],
    )
    .expect("valid outbox state");
    let reordered = CanonicalOutboxState::try_new(
        repository_id,
        vec![outbox_entry("delivery-a", 0x52), outbox_entry("delivery-b", 0x51)],
    )
    .expect("same map in another caller order");
    let payload_changed = CanonicalOutboxState::try_new(
        repository_id,
        vec![outbox_entry("delivery-a", 0x53), outbox_entry("delivery-b", 0x51)],
    )
    .expect("valid changed outbox state");

    let encoded = encode_body(&first).expect("canonical frame");
    let decoded = decode_body::<CanonicalOutboxState>(&encoded, DecodeLimits::DEFAULT)
        .expect("strict decode");

    assert_eq!(decoded, first);
    assert_eq!(first, reordered);
    assert_eq!(first.root().expect("root"), reordered.root().expect("root"));
    assert_ne!(
        first.root().expect("root"),
        payload_changed.root().expect("changed root")
    );
    let delivery = first
        .entry(slug("delivery-a"))
        .expect("delivery is present");
    assert_eq!(delivery.payload_root(), digest(0x52));
    assert_eq!(delivery.effect_class(), slug("forge-event-delivery"));
    assert_eq!(delivery.destination(), slug("forge-stream"));
}

#[test]
fn duplicate_map_keys_are_refused_before_encoding() {
    let repository_id = RepositoryId::from_bytes([0x33; 16]);
    assert!(matches!(
        CanonicalForgePositionState::try_new(
            repository_id,
            vec![
                forge_entry("issues", 0, 1, 0x41),
                forge_entry("issues", 1, 1, 0x42),
            ],
        ),
        Err(CodecRefusal::CollectionDuplicate {
            field: "forge_positions",
            ..
        })
    ));
    assert!(matches!(
        CanonicalOutboxState::try_new(
            repository_id,
            vec![
                outbox_entry("delivery-a", 0x51),
                outbox_entry("delivery-a", 0x52),
            ],
        ),
        Err(CodecRefusal::CollectionDuplicate {
            field: "outbox_entries",
            ..
        })
    ));
}

#[test]
fn decode_limits_refuse_large_maps_before_the_body_is_accepted() {
    let state = CanonicalForgePositionState::try_new(
        RepositoryId::from_bytes([0x44; 16]),
        vec![
            forge_entry("issues", 0, 1, 0x41),
            forge_entry("pull-requests", 0, 1, 0x42),
        ],
    )
    .expect("valid state");
    let encoded = encode_body(&state).expect("canonical frame");
    let limits = DecodeLimits {
        elements: 1,
        ..DecodeLimits::DEFAULT
    };

    assert_eq!(
        decode_body::<CanonicalForgePositionState>(&encoded, limits)
            .expect_err("two entries exceed the caller's one-entry bound"),
        CodecRefusal::CountBoundExceeded {
            field: "forge_positions",
            observed: 2,
            limit: 1,
        }
    );
}

#[test]
fn forge_and_outbox_frames_are_not_cross_decodable() {
    let forge = CanonicalForgePositionState::try_new(
        RepositoryId::from_bytes([0x55; 16]),
        vec![forge_entry("issues", 0, 1, 0x41)],
    )
    .expect("valid forge state");
    let encoded = encode_body(&forge).expect("canonical frame");

    assert!(matches!(
        decode_body::<CanonicalOutboxState>(&encoded, DecodeLimits::DEFAULT),
        Err(CodecRefusal::SchemaFamilyUnexpected { .. })
    ));
}
