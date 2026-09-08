//! Bounded immutable observations returned by a canonical outbox destination.
//!
//! A receipt binds the downstream observation to the exact obligation state
//! that authorized the call. Its root is evidence for a lifecycle transition;
//! decoding a receipt alone does not authenticate its source or publish it.

use fgit_types::{AsciiSlug, Digest, DomainTag, RepositoryId, SchemaFamily, TypeRefusal};

use crate::{CanonicalBody, CodecRefusal, CryptoBodyIdentity, Decoder, Encoder, body_id};

/// Permanent schema-v1 ceiling for a destination's observation bytes.
pub const MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES: usize = 4096;

const EVIDENCE_FIELD: &str = "outbox_delivery_receipt_evidence";

/// Closed downstream observation vocabulary; retry policy belongs to the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutboxDeliveryDisposition {
    /// The destination provided positive delivery acknowledgement.
    Acknowledged,
    /// The destination provided a terminal refusal.
    TerminallyRefused,
    /// Delivery could not be determined and requires reconciliation.
    Indeterminate,
}

impl OutboxDeliveryDisposition {
    const fn tag(self) -> u16 {
        match self {
            Self::Acknowledged => 0,
            Self::TerminallyRefused => 1,
            Self::Indeterminate => 2,
        }
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        match input.read_scalar::<u16>("outbox_delivery_disposition")? {
            0 => Ok(Self::Acknowledged),
            1 => Ok(Self::TerminallyRefused),
            2 => Ok(Self::Indeterminate),
            observed => Err(CodecRefusal::VariantUnknown {
                field: "outbox_delivery_disposition",
                observed: u32::from(observed),
                offset,
            }),
        }
    }
}

/// Canonical evidence from one actual downstream delivery or reconciliation call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalOutboxDeliveryReceipt {
    repository_id: RepositoryId,
    delivery_key: AsciiSlug,
    destination: AsciiSlug,
    payload_root: Digest,
    predecessor_effect_state_root: Digest,
    disposition: OutboxDeliveryDisposition,
    evidence: Vec<u8>,
}

impl CanonicalOutboxDeliveryReceipt {
    /// Binds a destination observation to the obligation state it observed.
    ///
    /// # Errors
    ///
    /// Refuses oversized evidence or a terminal observation without evidence.
    pub fn try_new(
        repository_id: RepositoryId,
        delivery_key: AsciiSlug,
        destination: AsciiSlug,
        payload_root: Digest,
        predecessor_effect_state_root: Digest,
        disposition: OutboxDeliveryDisposition,
        evidence: Vec<u8>,
    ) -> Result<Self, CodecRefusal> {
        validate_evidence(disposition, evidence.len())?;
        Ok(Self {
            repository_id,
            delivery_key,
            destination,
            payload_root,
            predecessor_effect_state_root,
            disposition,
            evidence,
        })
    }

    /// Repository namespace of the canonical obligation.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// Stable delivery/idempotency identity presented to the destination.
    #[must_use]
    pub const fn delivery_key(&self) -> AsciiSlug {
        self.delivery_key
    }

    /// Exact downstream destination identity.
    #[must_use]
    pub const fn destination(&self) -> AsciiSlug {
        self.destination
    }

    /// Original immutable payload commitment.
    #[must_use]
    pub const fn payload_root(&self) -> Digest {
        self.payload_root
    }

    /// Exact obligation state that authorized the downstream observation.
    #[must_use]
    pub const fn predecessor_effect_state_root(&self) -> Digest {
        self.predecessor_effect_state_root
    }

    /// Downstream observation, independent of retry policy.
    #[must_use]
    pub const fn disposition(&self) -> OutboxDeliveryDisposition {
        self.disposition
    }

    /// Bounded destination evidence, retained byte for byte.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// Immutable evidence root named by the settled obligation and its RCR.
    ///
    /// # Errors
    ///
    /// Refuses malformed evidence or canonical identity failure.
    pub fn root(&self) -> Result<Digest, CodecRefusal> {
        let identity = body_id(&CryptoBodyIdentity, self)?;
        Ok(Digest::new(identity.algorithm(), *identity.digest()))
    }
}

impl CanonicalBody for CanonicalOutboxDeliveryReceipt {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/generation/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("outbox-delivery-receipt");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        validate_evidence(self.disposition, self.evidence.len())?;
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_bytes("outbox_delivery_key", self.delivery_key.as_bytes())?;
        out.write_bytes("outbox_destination", self.destination.as_bytes())?;
        out.write_digest(&self.payload_root)?;
        out.write_digest(&self.predecessor_effect_state_root)?;
        out.write_scalar(self.disposition.tag());
        out.write_bytes(EVIDENCE_FIELD, &self.evidence)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let delivery_key = AsciiSlug::try_new(
            "outbox_delivery_key",
            input.read_bytes("outbox_delivery_key")?,
        )?;
        let destination = AsciiSlug::try_new(
            "outbox_destination",
            input.read_bytes("outbox_destination")?,
        )?;
        let payload_root = input.read_digest()?;
        let predecessor_effect_state_root = input.read_digest()?;
        let disposition = OutboxDeliveryDisposition::read(input)?;
        // Enforce both caller and permanent limits on the declared length before
        // taking bytes or allocating an owned buffer, including truncated input.
        let length = input.read_scalar::<u32>(EVIDENCE_FIELD)?;
        let limit = input
            .limits()
            .byte_string_bytes
            .min(MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES as u64);
        if u64::from(length) > limit {
            return Err(CodecRefusal::LengthBoundExceeded {
                field: EVIDENCE_FIELD,
                observed: u64::from(length),
                limit,
            });
        }
        let length = length as usize; // The permanent bound fits every target.
        validate_evidence(disposition, length)?;
        let evidence = input.take(EVIDENCE_FIELD, length)?.to_vec();
        Ok(Self {
            repository_id,
            delivery_key,
            destination,
            payload_root,
            predecessor_effect_state_root,
            disposition,
            evidence,
        })
    }
}

fn validate_evidence(
    disposition: OutboxDeliveryDisposition,
    length: usize,
) -> Result<(), CodecRefusal> {
    if length > MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES {
        return Err(CodecRefusal::LengthBoundExceeded {
            field: EVIDENCE_FIELD,
            observed: u64::try_from(length).unwrap_or(u64::MAX),
            limit: MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES as u64,
        });
    }
    if length == 0 && disposition != OutboxDeliveryDisposition::Indeterminate {
        return Err(TypeRefusal::LengthOutOfRange {
            field: EVIDENCE_FIELD,
            observed: 0,
            minimum: 1,
            maximum: MAX_OUTBOX_DELIVERY_RECEIPT_EVIDENCE_BYTES as u32,
        }
        .into());
    }
    Ok(())
}
