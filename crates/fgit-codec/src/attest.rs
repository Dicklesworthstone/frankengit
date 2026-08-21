//! The signed-envelope convention.
//!
//! A signature never changes what it signs. An envelope carries the unsigned
//! body's canonical frame bytes **verbatim** and attaches detached signatures
//! that commit over the body's identity. Adding, removing, or replacing a
//! signature therefore changes the envelope's bytes and leaves the body's
//! bytes and identity untouched.
//!
//! The alternative — a signature field inside the body — would make identity
//! depend on who had signed so far, so the same logical body would have a
//! different identity before and after countersigning, and a body could not be
//! re-signed without being re-identified.
//!
//! # What this module does not do
//!
//! It performs no cryptography, and it does not define the digest preimage
//! either. [`BodyIdentity`] is the seam, and it is deliberately shaped as
//! *(domain, schema, canonical body)* rather than *(bytes)*: `fgit-crypto`
//! owns the preimage framing, the digest algorithms, the algorithm registry,
//! signature schemes, and verification. Handing it the three components rather
//! than a pre-assembled buffer is what keeps a second, silently divergent
//! preimage from existing in this crate.
//!
//! This module owns the byte layout and the structural checks that need no key
//! material.

use fgit_types::identity::InternalObjectId;
use fgit_types::{DomainTag, SchemaFamily, SchemaId};

use crate::bounds::DecodeLimits;
use crate::error::CodecRefusal;
use crate::reader::Decoder;
use crate::wire::{
    CanonicalBody, canonical_body_bytes, decode_body, encode_body, peek_frame_domain, split_frame,
};
use crate::writer::Encoder;

/// Largest accepted signing-key identifier, in bytes.
pub const MAX_KEY_ID_LEN: usize = 128;
/// Largest accepted signature, in bytes.
pub const MAX_SIGNATURE_LEN: usize = 1024;
/// Largest accepted carried body, in bytes.
pub const MAX_CARRIED_BODY_LEN: usize = 8 * 1024 * 1024;

/// Turns a body's domain, schema, and canonical bytes into its identity.
///
/// This crate never implements one and never assembles a digest preimage.
/// `fgit-crypto` owns the preimage framing, the digest construction, and the
/// algorithm registry; giving it the three components separately is what stops
/// a second preimage definition from growing here.
pub trait BodyIdentity {
    /// The identity of one canonical body.
    fn identify(
        &self,
        domain: DomainTag,
        schema: SchemaId,
        canonical_body: &[u8],
    ) -> InternalObjectId;
}

/// The identity of a body.
///
/// Computed over the body's payload, not its frame: transport framing is
/// excluded from canonical body bytes, so re-framing a body cannot change what
/// it is.
pub fn body_id<B, I>(identity: &I, body: &B) -> Result<InternalObjectId, CodecRefusal>
where
    B: CanonicalBody,
    I: BodyIdentity + ?Sized,
{
    let payload = canonical_body_bytes(body)?;
    Ok(identity.identify(B::DOMAIN, B::schema_id(), &payload))
}

/// The identity of a frame already in byte form.
///
/// The domain and schema are read from the frame rather than supplied, so a
/// caller cannot label one body's bytes with another body's domain.
pub fn body_id_of_frame<I>(
    identity: &I,
    frame: &[u8],
    limits: DecodeLimits,
) -> Result<InternalObjectId, CodecRefusal>
where
    I: BodyIdentity + ?Sized,
{
    let (header, payload) = split_frame(frame, limits)?;
    Ok(identity.identify(header.domain, header.schema, payload))
}

/// Registry code point naming a signature scheme.
///
/// Opaque here: `fgit-crypto` owns the mapping to a construction. Zero is
/// reserved, so a zeroed buffer is never a valid scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignatureSchemeId(u16);

impl SignatureSchemeId {
    /// Builds a scheme code point, refusing the reserved zero slot.
    pub const fn try_new(code_point: u16) -> Result<Self, CodecRefusal> {
        if code_point == 0 {
            return Err(CodecRefusal::VariantUnknown {
                field: "SignatureSchemeId",
                observed: 0,
                offset: 0,
            });
        }
        Ok(Self(code_point))
    }

    /// The registry code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        self.0
    }
}

/// One detached signature over a body's identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DetachedSignature {
    /// Scheme the signature was produced under.
    pub scheme: SignatureSchemeId,
    /// Identifier of the signing key, bounded by [`MAX_KEY_ID_LEN`].
    pub key_id: Vec<u8>,
    /// The body identity this signature commits over.
    pub body_id: InternalObjectId,
    /// Signature bytes, bounded by [`MAX_SIGNATURE_LEN`].
    pub signature: Vec<u8>,
}

impl DetachedSignature {
    fn write(out: &mut Encoder, value: &Self) -> Result<(), CodecRefusal> {
        value.write_into(out)
    }

    fn write_into(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.key_id.len() > MAX_KEY_ID_LEN {
            return Err(CodecRefusal::ValueUnrepresentable {
                field: "DetachedSignature.key_id",
                observed: u64::try_from(self.key_id.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_KEY_ID_LEN).unwrap_or(u64::MAX),
            });
        }
        if self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(CodecRefusal::ValueUnrepresentable {
                field: "DetachedSignature.signature",
                observed: u64::try_from(self.signature.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_SIGNATURE_LEN).unwrap_or(u64::MAX),
            });
        }
        out.write_scalar(self.scheme.code_point());
        out.write_bytes("DetachedSignature.key_id", &self.key_id)?;
        out.write_internal_object_id(&self.body_id)?;
        out.write_bytes("DetachedSignature.signature", &self.signature)
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let raw_scheme = input.read_scalar::<u16>("DetachedSignature.scheme")?;
        let scheme =
            SignatureSchemeId::try_new(raw_scheme).map_err(|_| CodecRefusal::VariantUnknown {
                field: "SignatureSchemeId",
                observed: u32::from(raw_scheme),
                offset,
            })?;
        let key_id = bounded(input, "DetachedSignature.key_id", MAX_KEY_ID_LEN)?;
        let body_id = input.read_internal_object_id()?;
        let signature = bounded(input, "DetachedSignature.signature", MAX_SIGNATURE_LEN)?;
        Ok(Self {
            scheme,
            key_id,
            body_id,
            signature,
        })
    }
}

fn bounded(
    input: &mut Decoder<'_>,
    field: &'static str,
    limit: usize,
) -> Result<Vec<u8>, CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    if bytes.len() > limit {
        return Err(CodecRefusal::LengthBoundExceeded {
            field,
            observed: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            limit: u64::try_from(limit).unwrap_or(u64::MAX),
        });
    }
    Ok(bytes.to_vec())
}

/// An unsigned body carried verbatim, plus detached signatures over its
/// identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SignedEnvelopeBody {
    /// The unsigned body's canonical frame bytes, exactly as they were
    /// produced. Its identity is computed from the payload inside them.
    body_frame: Vec<u8>,
    /// Detached signatures. Encoded as a canonical set, so their order in
    /// this vector never affects the envelope's bytes and a repeat is refused.
    signatures: Vec<DetachedSignature>,
}

impl SignedEnvelopeBody {
    /// Wraps a body with no signatures yet.
    pub fn seal<B: CanonicalBody>(body: &B) -> Result<Self, CodecRefusal> {
        Ok(Self {
            body_frame: encode_body(body)?,
            signatures: Vec::new(),
        })
    }

    /// Wraps frame bytes that are already canonical.
    pub fn from_frame(body_frame: Vec<u8>, limits: DecodeLimits) -> Result<Self, CodecRefusal> {
        // Reading the domain proves these really are canonical frame bytes.
        peek_frame_domain(&body_frame, limits)?;
        Ok(Self {
            body_frame,
            signatures: Vec::new(),
        })
    }

    /// The carried body's canonical frame bytes.
    #[must_use]
    pub const fn body_frame(&self) -> &[u8] {
        self.body_frame.as_slice()
    }

    /// The attached signatures.
    #[must_use]
    pub const fn signatures(&self) -> &[DetachedSignature] {
        self.signatures.as_slice()
    }

    /// Attaches a signature.
    ///
    /// The signature must commit over an identity in the carried body's own
    /// domain, which stops a signature over a different schema's body from
    /// being grafted on.
    pub fn attach(
        &mut self,
        signature: DetachedSignature,
        limits: DecodeLimits,
    ) -> Result<(), CodecRefusal> {
        let domain = peek_frame_domain(&self.body_frame, limits)?;
        if signature.body_id.domain() != domain {
            return Err(CodecRefusal::domain_unexpected(
                domain,
                signature.body_id.domain(),
            ));
        }
        self.signatures.push(signature);
        Ok(())
    }

    /// The carried body's identity.
    ///
    /// This depends only on the carried body's own bytes, so it is the same
    /// value for the unsigned body and for every envelope that carries it,
    /// whatever signatures are attached.
    pub fn carried_body_id<I>(
        &self,
        identity: &I,
        limits: DecodeLimits,
    ) -> Result<InternalObjectId, CodecRefusal>
    where
        I: BodyIdentity + ?Sized,
    {
        body_id_of_frame(identity, &self.body_frame, limits)
    }

    /// Decodes the carried body.
    pub fn carried_body<B: CanonicalBody>(&self, limits: DecodeLimits) -> Result<B, CodecRefusal> {
        decode_body::<B>(&self.body_frame, limits)
    }
}

impl CanonicalBody for SignedEnvelopeBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/signed-envelope/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("signed-envelope");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.body_frame.len() > MAX_CARRIED_BODY_LEN {
            return Err(CodecRefusal::ValueUnrepresentable {
                field: "SignedEnvelopeBody.body_frame",
                observed: u64::try_from(self.body_frame.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_CARRIED_BODY_LEN).unwrap_or(u64::MAX),
            });
        }
        out.write_bytes("SignedEnvelopeBody.body_frame", &self.body_frame)?;
        out.write_canonical_set(
            "SignedEnvelopeBody.signatures",
            &self.signatures,
            DetachedSignature::write,
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let body_frame = bounded(input, "SignedEnvelopeBody.body_frame", MAX_CARRIED_BODY_LEN)?;
        let domain = peek_frame_domain(&body_frame, input.limits())?;
        let signatures =
            input.read_canonical_set("SignedEnvelopeBody.signatures", DetachedSignature::read)?;
        for signature in &signatures {
            if signature.body_id.domain() != domain {
                return Err(CodecRefusal::domain_unexpected(
                    domain,
                    signature.body_id.domain(),
                ));
            }
        }
        Ok(Self {
            body_frame,
            signatures,
        })
    }
}
