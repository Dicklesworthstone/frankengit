//! Stable semantic identity for one canonical outbox delivery.
//!
//! A delivery key must not depend on process identity, wall-clock time, retry
//! count, map iteration order, allocation order, or the authority-head
//! generation that happens to win. It is derived only from immutable delivery
//! semantics that are known before the resulting outbox root and RCR exist.
//!
//! The resulting lowercase SHA-256 text is a valid 64-byte [`AsciiSlug`], so it
//! can flow through the existing reference outbox vocabulary without creating
//! a second opaque identity type.

use fgit_crypto::{IdentityDomain, internal_digest_value, lowercase_hex};
use fgit_types::{
    AsciiSlug, Digest, RepositoryCommitId, RepositoryId, SchemaFamily, SchemaId, TxId,
};

use crate::{CodecRefusal, Encoder};

const DELIVERY_IDENTITY_SCHEMA: SchemaId =
    SchemaId::new(SchemaFamily::from_static("outbox-delivery-key"), 1, 0);

/// Immutable semantic inputs defining one external delivery obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutboxDeliveryIdentityInput {
    repository_id: RepositoryId,
    effect_class: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    tx_id: TxId,
    predecessor_rcr_id: Option<RepositoryCommitId>,
}

impl OutboxDeliveryIdentityInput {
    /// Creates one complete semantic identity input.
    #[must_use]
    pub const fn new(
        repository_id: RepositoryId,
        effect_class: AsciiSlug,
        destination: AsciiSlug,
        payload_root: Digest,
        tx_id: TxId,
        predecessor_rcr_id: Option<RepositoryCommitId>,
    ) -> Self {
        Self {
            repository_id,
            effect_class,
            destination,
            payload_root,
            tx_id,
            predecessor_rcr_id,
        }
    }

    /// Repository namespace.
    #[must_use]
    pub const fn repository_id(self) -> RepositoryId {
        self.repository_id
    }

    /// Stable effect class.
    #[must_use]
    pub const fn effect_class(self) -> AsciiSlug {
        self.effect_class
    }

    /// Stable destination or audience.
    #[must_use]
    pub const fn destination(self) -> AsciiSlug {
        self.destination
    }

    /// Immutable payload commitment.
    #[must_use]
    pub const fn payload_root(self) -> Digest {
        self.payload_root
    }

    /// Sealed transaction producing the obligation.
    #[must_use]
    pub const fn tx_id(self) -> TxId {
        self.tx_id
    }

    /// Previously committed RCR at the semantic basis.
    #[must_use]
    pub const fn predecessor_rcr_id(self) -> Option<RepositoryCommitId> {
        self.predecessor_rcr_id
    }
}

/// Derives the stable idempotency key for one delivery.
///
/// # Errors
///
/// Refuses canonical framing failure. The produced hexadecimal label is valid
/// by construction; its typed conversion remains fallible so that invariant is
/// not represented by a panic.
pub fn derive_outbox_delivery_key(
    input: OutboxDeliveryIdentityInput,
) -> Result<AsciiSlug, CodecRefusal> {
    let mut encoder = Encoder::with_capacity(320);
    encoder.write_opaque_id(input.repository_id.as_bytes());
    encoder.write_bytes("outbox_effect_class", input.effect_class.as_bytes())?;
    encoder.write_bytes("outbox_destination", input.destination.as_bytes())?;
    encoder.write_digest(&input.payload_root)?;
    encoder.write_internal_object_id(input.tx_id.as_internal_object_id())?;
    encoder.write_option(input.predecessor_rcr_id.as_ref(), |encoder, rcr_id| {
        encoder.write_internal_object_id(rcr_id.as_internal_object_id())
    })?;
    let digest = internal_digest_value(
        IdentityDomain::Generation,
        DELIVERY_IDENTITY_SCHEMA,
        &encoder.into_bytes(),
    );
    let text = lowercase_hex(digest.as_bytes());
    AsciiSlug::try_new("outbox_delivery_key", text.as_bytes()).map_err(CodecRefusal::from)
}

#[cfg(test)]
mod tests {
    use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes};

    use super::*;

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

    fn input() -> OutboxDeliveryIdentityInput {
        OutboxDeliveryIdentityInput::new(
            RepositoryId::from_bytes([0x11; 16]),
            AsciiSlug::from_static("forge-event-delivery"),
            AsciiSlug::from_static("forge-stream"),
            digest(0x41),
            tx(0x31),
            Some(rcr(0x32)),
        )
    }

    #[test]
    fn identity_is_deterministic_and_canonical_text() {
        let first = derive_outbox_delivery_key(input()).expect("delivery key");
        let identical = derive_outbox_delivery_key(input()).expect("delivery key");

        assert_eq!(first, identical);
        assert_eq!(first.len(), 64);
        assert!(
            first
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }

    #[test]
    fn every_semantic_field_changes_the_identity() {
        let basis = input();
        let expected = derive_outbox_delivery_key(basis).expect("basis key");
        let variants = [
            OutboxDeliveryIdentityInput::new(
                RepositoryId::from_bytes([0x12; 16]),
                basis.effect_class(),
                basis.destination(),
                basis.payload_root(),
                basis.tx_id(),
                basis.predecessor_rcr_id(),
            ),
            OutboxDeliveryIdentityInput::new(
                basis.repository_id(),
                AsciiSlug::from_static("another-effect-class"),
                basis.destination(),
                basis.payload_root(),
                basis.tx_id(),
                basis.predecessor_rcr_id(),
            ),
            OutboxDeliveryIdentityInput::new(
                basis.repository_id(),
                basis.effect_class(),
                AsciiSlug::from_static("another-destination"),
                basis.payload_root(),
                basis.tx_id(),
                basis.predecessor_rcr_id(),
            ),
            OutboxDeliveryIdentityInput::new(
                basis.repository_id(),
                basis.effect_class(),
                basis.destination(),
                digest(0x42),
                basis.tx_id(),
                basis.predecessor_rcr_id(),
            ),
            OutboxDeliveryIdentityInput::new(
                basis.repository_id(),
                basis.effect_class(),
                basis.destination(),
                basis.payload_root(),
                tx(0x33),
                basis.predecessor_rcr_id(),
            ),
            OutboxDeliveryIdentityInput::new(
                basis.repository_id(),
                basis.effect_class(),
                basis.destination(),
                basis.payload_root(),
                basis.tx_id(),
                None,
            ),
        ];

        for variant in variants {
            assert_ne!(
                derive_outbox_delivery_key(variant).expect("variant key"),
                expected
            );
        }
    }
}
