#![forbid(unsafe_code)]
//! Immutable object envelopes and deterministic microsegments.
//!
//! This object-fabric slice owns byte layout, bounded parsing, ordering,
//! index/Merkle/footer verification, local immutable placement, manifests, and
//! authenticated-retention hooks. The digest trait is an adapter boundary:
//! production callers bind the `fgit-crypto` domain-separated digest
//! implementation and typed `fgit-types` OIDs here. This crate never
//! implements a cryptographic hash or invents a parallel ID type.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use fgit_crypto::{
    DigestHasher as CryptoDigestHasher, GitObjectKind as CryptoObjectKind, IdentityDomain,
    Sha256Hasher,
};
use fgit_types::{
    CodecVersion, GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, SchemaFamily, SchemaId,
    TypeRefusal,
};

pub mod fabric;
pub mod local;
pub mod reference;

const ENVELOPE_MAGIC: &[u8; 4] = b"FGEN";
const SEGMENT_MAGIC: &[u8; 4] = b"FGMS";
const INDEX_MAGIC: &[u8; 4] = b"FGIX";
const FOOTER_MAGIC: &[u8; 4] = b"FGFT";
const FORMAT_VERSION: u16 = 1;
const COMMITMENT_BYTES: usize = 32;
const FOOTER_BYTES: usize = 92;
const FOOTER_CORE_BYTES: usize = FOOTER_BYTES - COMMITMENT_BYTES;
const MICROSEGMENT_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.git-object-microsegment"),
    1,
    0,
);
pub(crate) const ENVELOPE_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.object-envelope"),
    1,
    0,
);
const MICROSEGMENT_MERKLE_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.git-object-microsegment-merkle"),
    1,
    0,
);

/// Domain labels supplied to the adopted fgit-crypto registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestDomain {
    Payload,
    LogicalObject,
    MerkleLeaf,
    MerkleNode,
    Segment,
}

/// Adapter for the selected domain-separated cryptographic digest registry.
///
/// `Commitment` is the canonical 32-byte serialized digest field required by
/// the v1 segment format. This trait intentionally contains no algorithm or
/// ID implementation; fgit-crypto supplies that authority in the integration
/// step once its public surface is frozen.
pub trait DigestAlgorithm {
    type State;

    fn begin(&self, domain: DigestDomain, content_len: usize) -> Result<Self::State, FabricError>;

    fn update(&self, state: &mut Self::State, bytes: &[u8]);

    fn finish(&self, state: Self::State) -> Commitment;

    fn digest(&self, domain: DigestDomain, pieces: &[&[u8]]) -> Result<Commitment, FabricError> {
        let content_len = pieces.iter().try_fold(0usize, |total, piece| {
            total
                .checked_add(piece.len())
                .ok_or(FabricError::LengthOverflow)
        })?;
        let mut state = self.begin(domain, content_len)?;
        for piece in pieces {
            self.update(&mut state, piece);
        }
        Ok(self.finish(state))
    }

    fn payload_commitment(
        &self,
        _object_kind: ObjectKind,
        payload: &[u8],
    ) -> Result<Commitment, FabricError> {
        self.digest(DigestDomain::Payload, &[payload])
    }
}

/// Canonical on-wire representation of an fgit-crypto digest commitment.
pub type Commitment = [u8; COMMITMENT_BYTES];

const fn commitment_from_bytes(bytes: &[u8]) -> Result<Commitment, FabricError> {
    if bytes.len() != COMMITMENT_BYTES {
        return Err(FabricError::CryptoDigestWidthMismatch);
    }
    let mut commitment = [0; COMMITMENT_BYTES];
    commitment.copy_from_slice(bytes);
    Ok(commitment)
}

/// Production digest adapter bound to the `fgit-crypto` registry.
///
/// Payload commitments use its native-object commitment construction; the
/// microsegment footer uses the registered `GitObjectMicrosegment` domain.
/// Merkle leaves and nodes are domain-separated internal commitments, not
/// standalone object identifiers.
#[derive(Debug, Default, Clone, Copy)]
pub struct CryptoDigest;

/// Streaming SHA-256 state held by [`CryptoDigest`].
#[derive(Debug, Clone)]
pub struct CryptoDigestState(Sha256Hasher);

impl DigestAlgorithm for CryptoDigest {
    type State = CryptoDigestState;

    fn begin(&self, domain: DigestDomain, content_len: usize) -> Result<Self::State, FabricError> {
        let mut hasher = Sha256Hasher::new();
        let (identity_domain, schema) = crypto_identity_parameters(domain)?;
        let body_len = u64::try_from(content_len).map_err(|_| FabricError::LengthOverflow)?;
        let header = fgit_crypto::internal_id_preimage_header(identity_domain, schema, body_len);
        CryptoDigestHasher::update(&mut hasher, &header);
        Ok(CryptoDigestState(hasher))
    }

    fn update(&self, state: &mut Self::State, bytes: &[u8]) {
        CryptoDigestHasher::update(&mut state.0, bytes);
    }

    fn finish(&self, state: Self::State) -> Commitment {
        CryptoDigestHasher::finish(state.0)
    }

    fn digest(&self, domain: DigestDomain, pieces: &[&[u8]]) -> Result<Commitment, FabricError> {
        let (identity_domain, schema) = crypto_identity_parameters(domain)?;
        let digest = fgit_crypto::internal_digest_over_parts(identity_domain, schema, pieces);
        commitment_from_bytes(digest.as_bytes())
    }

    fn payload_commitment(
        &self,
        object_kind: ObjectKind,
        payload: &[u8],
    ) -> Result<Commitment, FabricError> {
        let object_kind = match object_kind {
            ObjectKind::Commit => CryptoObjectKind::Commit,
            ObjectKind::Tree => CryptoObjectKind::Tree,
            ObjectKind::Blob => CryptoObjectKind::Blob,
            ObjectKind::Tag => CryptoObjectKind::Tag,
            ObjectKind::Internal => return Err(FabricError::InternalObjectKindUnsupported),
        };
        let identity =
            fgit_crypto::git_payload_commitment(object_kind, payload, CodecVersion::new(1, 0));
        commitment_from_bytes(identity.digest().as_bytes())
    }
}

const fn crypto_identity_parameters(
    domain: DigestDomain,
) -> Result<(IdentityDomain, SchemaId), FabricError> {
    match domain {
        DigestDomain::Payload => Err(FabricError::PayloadObjectKindRequired),
        DigestDomain::LogicalObject => Ok((IdentityDomain::ObjectEnvelope, ENVELOPE_SCHEMA)),
        DigestDomain::MerkleLeaf => Ok((IdentityDomain::MerkleLeaf, MICROSEGMENT_MERKLE_SCHEMA)),
        DigestDomain::MerkleNode => Ok((IdentityDomain::MerkleNode, MICROSEGMENT_MERKLE_SCHEMA)),
        DigestDomain::Segment => Ok((IdentityDomain::GitObjectMicrosegment, MICROSEGMENT_SCHEMA)),
    }
}

/// Bounded decoding and construction limits for one microsegment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentLimits {
    pub max_segment_bytes: usize,
    pub max_records: u32,
    pub max_namespace_bytes: usize,
    pub max_object_identity_bytes: usize,
    pub max_envelope_bytes: usize,
    pub max_record_bytes: usize,
}

impl Default for SegmentLimits {
    fn default() -> Self {
        Self {
            max_segment_bytes: 16 * 1024 * 1024,
            max_records: 65_536,
            max_namespace_bytes: 256,
            max_object_identity_bytes: 64,
            max_envelope_bytes: 1024,
            max_record_bytes: 1024 * 1024,
        }
    }
}

/// Exact immutable object type committed by an envelope and segment index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ObjectKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    Internal = 5,
}

impl ObjectKind {
    const fn to_wire(self) -> u8 {
        match self {
            Self::Commit => 1,
            Self::Tree => 2,
            Self::Blob => 3,
            Self::Tag => 4,
            Self::Internal => 5,
        }
    }

    const fn from_wire(value: u8) -> Result<Self, FabricError> {
        match value {
            1 => Ok(Self::Commit),
            2 => Ok(Self::Tree),
            3 => Ok(Self::Blob),
            4 => Ok(Self::Tag),
            5 => Ok(Self::Internal),
            _ => Err(FabricError::UnknownObjectKind(value)),
        }
    }
}

/// Typed refusal for malformed, noncanonical, or over-budget fabric bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FabricError {
    EmptyNamespace,
    NamespaceTooLarge,
    ZeroObjectIdentity,
    ObjectIdentityTooLarge,
    CodecNamespaceTooLarge,
    EnvelopeTooLarge,
    SegmentTooLarge,
    TooManyRecords,
    RecordTooLarge,
    LengthOverflow,
    PayloadLengthMismatch,
    PayloadCommitmentMismatch,
    PayloadObjectKindRequired,
    InternalObjectKindUnsupported,
    CryptoDigestWidthMismatch,
    CryptoFramingInvalid,
    MixedNamespace,
    NonCanonicalRecordOrder,
    DuplicateObjectIdentity,
    Truncated,
    InvalidMagic,
    UnknownVersion(u16),
    UnknownObjectKind(u8),
    GitObjectIdentity(TypeRefusal),
    InvalidEnvelope,
    InvalidFooter,
    InvalidIndex,
    IndexRecordMismatch,
    MerkleRootMismatch,
    SegmentDigestMismatch,
    TrailingBytes,
    StreamingLengthMismatch,
}

impl fmt::Display for FabricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyNamespace => "namespace must not be empty",
            Self::NamespaceTooLarge => "namespace exceeds its configured bound",
            Self::ZeroObjectIdentity => {
                "all-zero native object identity cannot name a stored object"
            }
            Self::ObjectIdentityTooLarge => "object identity exceeds its configured bound",
            Self::CodecNamespaceTooLarge => "codec namespace exceeds its configured bound",
            Self::EnvelopeTooLarge => "envelope exceeds its configured bound",
            Self::SegmentTooLarge => "segment exceeds its configured bound",
            Self::TooManyRecords => "segment exceeds its configured record count",
            Self::RecordTooLarge => "record exceeds its configured bound",
            Self::LengthOverflow => "wire length arithmetic overflowed",
            Self::PayloadLengthMismatch => "payload bytes do not match the declared length",
            Self::PayloadCommitmentMismatch => "payload bytes do not match the committed digest",
            Self::PayloadObjectKindRequired => {
                "native payload commitment requires the Git object kind"
            }
            Self::InternalObjectKindUnsupported => {
                "internal object kind has no native Git payload commitment"
            }
            Self::CryptoDigestWidthMismatch => {
                "crypto registry returned a digest with an unexpected width"
            }
            Self::CryptoFramingInvalid => {
                "crypto registry returned an invalid internal identity preimage"
            }
            Self::MixedNamespace => "segment records use more than one namespace",
            Self::NonCanonicalRecordOrder => "record identities are not strictly canonical order",
            Self::DuplicateObjectIdentity => "segment contains a duplicate object identity",
            Self::Truncated => "wire bytes are truncated",
            Self::InvalidMagic => "wire magic is invalid",
            Self::UnknownVersion(_) => "wire format version is unsupported",
            Self::UnknownObjectKind(_) => "object kind tag is unsupported",
            Self::GitObjectIdentity(_) => "native Git object identity is malformed",
            Self::InvalidEnvelope => "envelope fields are malformed",
            Self::InvalidFooter => "segment footer is malformed",
            Self::InvalidIndex => "segment index is malformed",
            Self::IndexRecordMismatch => "segment index does not match its record",
            Self::MerkleRootMismatch => "segment Merkle root does not match its records",
            Self::SegmentDigestMismatch => "segment digest does not match its bytes",
            Self::TrailingBytes => "canonical value has trailing bytes",
            Self::StreamingLengthMismatch => {
                "stream length differs from its declared segment length"
            }
        };
        formatter.write_str(message)
    }
}

impl Error for FabricError {}

/// Immutable metadata that binds an object to its payload and logical identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEnvelope {
    namespace: Vec<u8>,
    object_identity: GitOid,
    object_kind: ObjectKind,
    declared_length: u64,
    payload_commitment: Commitment,
    codec_namespace: Vec<u8>,
    logical_content_identity: Commitment,
    manifest_reference: Option<Commitment>,
}

impl ObjectEnvelope {
    pub fn new(
        namespace: Vec<u8>,
        object_identity: GitOid,
        object_kind: ObjectKind,
        declared_length: u64,
        payload_commitment: Commitment,
        codec_namespace: Vec<u8>,
        logical_content_identity: Commitment,
        manifest_reference: Option<Commitment>,
        limits: &SegmentLimits,
    ) -> Result<Self, FabricError> {
        validate_namespace(&namespace, limits)?;
        validate_object_identity(object_identity, limits)?;
        if codec_namespace.len() > limits.max_namespace_bytes {
            return Err(FabricError::CodecNamespaceTooLarge);
        }
        let envelope = Self {
            namespace,
            object_identity,
            object_kind,
            declared_length,
            payload_commitment,
            codec_namespace,
            logical_content_identity,
            manifest_reference,
        };
        if envelope.encoded_len()? > limits.max_envelope_bytes {
            return Err(FabricError::EnvelopeTooLarge);
        }
        Ok(envelope)
    }

    pub fn decode(bytes: &[u8], limits: &SegmentLimits) -> Result<Self, FabricError> {
        let mut cursor = Cursor::new(bytes);
        cursor.expect_magic(*ENVELOPE_MAGIC)?;
        let version = cursor.read_u16()?;
        if version != FORMAT_VERSION {
            return Err(FabricError::UnknownVersion(version));
        }
        let namespace = cursor.read_prefixed_bytes(limits.max_namespace_bytes)?;
        let object_identity = cursor.read_object_identity(limits)?;
        let object_kind = ObjectKind::from_wire(cursor.read_u8()?)?;
        let declared_length = cursor.read_u64()?;
        let payload_commitment = cursor.read_commitment()?;
        let codec_namespace = cursor.read_prefixed_bytes(limits.max_namespace_bytes)?;
        let logical_content_identity = cursor.read_commitment()?;
        let manifest_reference = match cursor.read_u8()? {
            0 => None,
            1 => Some(cursor.read_commitment()?),
            _ => return Err(FabricError::InvalidEnvelope),
        };
        if !cursor.is_finished() {
            return Err(FabricError::TrailingBytes);
        }
        Self::new(
            namespace,
            object_identity,
            object_kind,
            declared_length,
            payload_commitment,
            codec_namespace,
            logical_content_identity,
            manifest_reference,
            limits,
        )
    }

    pub fn encode(&self) -> Result<Vec<u8>, FabricError> {
        let mut output = Vec::with_capacity(self.encoded_len()?);
        output.extend_from_slice(ENVELOPE_MAGIC);
        push_u16(&mut output, FORMAT_VERSION);
        push_prefixed_bytes(&mut output, &self.namespace)?;
        push_object_identity(&mut output, self.object_identity);
        output.push(self.object_kind.to_wire());
        push_u64(&mut output, self.declared_length);
        output.extend_from_slice(&self.payload_commitment);
        push_prefixed_bytes(&mut output, &self.codec_namespace)?;
        output.extend_from_slice(&self.logical_content_identity);
        match self.manifest_reference {
            None => output.push(0),
            Some(reference) => {
                output.push(1);
                output.extend_from_slice(&reference);
            }
        }
        Ok(output)
    }

    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    #[must_use]
    pub const fn object_identity(&self) -> GitOid {
        self.object_identity
    }

    #[must_use]
    pub const fn object_kind(&self) -> ObjectKind {
        self.object_kind
    }

    #[must_use]
    pub const fn declared_length(&self) -> u64 {
        self.declared_length
    }

    #[must_use]
    pub const fn payload_commitment(&self) -> Commitment {
        self.payload_commitment
    }

    #[must_use]
    pub fn codec_namespace(&self) -> &[u8] {
        &self.codec_namespace
    }

    #[must_use]
    pub const fn logical_content_identity(&self) -> Commitment {
        self.logical_content_identity
    }

    #[must_use]
    pub const fn manifest_reference(&self) -> Option<Commitment> {
        self.manifest_reference
    }

    fn encoded_len(&self) -> Result<usize, FabricError> {
        let manifest_len = if self.manifest_reference.is_some() {
            COMMITMENT_BYTES
        } else {
            0
        };
        4usize
            .checked_add(2)
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(self.namespace.len()))
            .and_then(|value| value.checked_add(2))
            .and_then(|value| value.checked_add(self.object_identity.as_bytes().len()))
            .and_then(|value| value.checked_add(1 + 8 + COMMITMENT_BYTES))
            .and_then(|value| value.checked_add(2 + self.codec_namespace.len()))
            .and_then(|value| value.checked_add(COMMITMENT_BYTES + 1 + manifest_len))
            .ok_or(FabricError::LengthOverflow)
    }
}

/// One immutable object payload supplied to a segment builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecordInput {
    pub envelope: ObjectEnvelope,
    pub payload: Vec<u8>,
}

/// A built microsegment plus its independently verifiable commitments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Microsegment {
    bytes: Vec<u8>,
    segment_digest: Commitment,
    merkle_root: Commitment,
    record_count: u32,
}

impl Microsegment {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn segment_digest(&self) -> Commitment {
        self.segment_digest
    }

    #[must_use]
    pub const fn merkle_root(&self) -> Commitment {
        self.merkle_root
    }

    #[must_use]
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }
}

/// Deterministic, order-preserving segment builder.
pub struct MicrosegmentBuilder<'a, H> {
    hasher: &'a H,
    limits: SegmentLimits,
    namespace: Option<Vec<u8>>,
    records: Vec<SegmentRecordInput>,
    records_wire_len: usize,
    index_entries_wire_len: usize,
}

impl<'a, H: DigestAlgorithm> MicrosegmentBuilder<'a, H> {
    pub const fn new(hasher: &'a H, limits: SegmentLimits) -> Self {
        Self {
            hasher,
            limits,
            namespace: None,
            records: Vec::new(),
            records_wire_len: 0,
            index_entries_wire_len: 0,
        }
    }

    pub fn push(&mut self, record: SegmentRecordInput) -> Result<(), FabricError> {
        validate_namespace(record.envelope.namespace(), &self.limits)?;
        validate_object_identity(record.envelope.object_identity(), &self.limits)?;
        let payload_len =
            u64::try_from(record.payload.len()).map_err(|_| FabricError::LengthOverflow)?;
        if record.envelope.declared_length() != payload_len {
            return Err(FabricError::PayloadLengthMismatch);
        }
        let computed_payload = self
            .hasher
            .payload_commitment(record.envelope.object_kind(), &record.payload)?;
        if computed_payload != record.envelope.payload_commitment() {
            return Err(FabricError::PayloadCommitmentMismatch);
        }
        let namespace = match &self.namespace {
            Some(namespace) if namespace.as_slice() != record.envelope.namespace() => {
                return Err(FabricError::MixedNamespace);
            }
            Some(namespace) => namespace.as_slice(),
            None => record.envelope.namespace(),
        };
        if let Some(previous) = self.records.last() {
            match previous
                .envelope
                .object_identity()
                .cmp(&record.envelope.object_identity())
            {
                Ordering::Greater => return Err(FabricError::NonCanonicalRecordOrder),
                Ordering::Equal => return Err(FabricError::DuplicateObjectIdentity),
                Ordering::Less => {}
            }
        }
        let next_count = self
            .records
            .len()
            .checked_add(1)
            .ok_or(FabricError::LengthOverflow)?;
        if next_count
            > usize::try_from(self.limits.max_records).map_err(|_| FabricError::LengthOverflow)?
        {
            return Err(FabricError::TooManyRecords);
        }
        let record_len = record_wire_body_len(&record)?;
        let record_wire_len = record_len
            .checked_add(4)
            .ok_or(FabricError::LengthOverflow)?;
        if record_wire_len > self.limits.max_record_bytes {
            return Err(FabricError::RecordTooLarge);
        }
        let next_records_wire_len = self
            .records_wire_len
            .checked_add(record_wire_len)
            .ok_or(FabricError::LengthOverflow)?;
        let index_entry_wire_len = index_entry_wire_len(record.envelope.object_identity())?;
        let next_index_entries_wire_len = self
            .index_entries_wire_len
            .checked_add(index_entry_wire_len)
            .ok_or(FabricError::LengthOverflow)?;
        let next_segment_len = header_wire_len(namespace)?
            .checked_add(next_records_wire_len)
            .and_then(|value| value.checked_add(INDEX_MAGIC.len() + 4))
            .and_then(|value| value.checked_add(next_index_entries_wire_len))
            .and_then(|value| value.checked_add(FOOTER_BYTES))
            .ok_or(FabricError::LengthOverflow)?;
        if next_segment_len > self.limits.max_segment_bytes {
            return Err(FabricError::SegmentTooLarge);
        }
        if self.namespace.is_none() {
            self.namespace = Some(record.envelope.namespace().to_vec());
        }
        self.records_wire_len = next_records_wire_len;
        self.index_entries_wire_len = next_index_entries_wire_len;
        self.records.push(record);
        Ok(())
    }

    pub fn build(self) -> Result<Microsegment, FabricError> {
        let namespace = self.namespace.ok_or(FabricError::EmptyNamespace)?;
        let record_count =
            u32::try_from(self.records.len()).map_err(|_| FabricError::TooManyRecords)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SEGMENT_MAGIC);
        push_u16(&mut bytes, FORMAT_VERSION);
        push_prefixed_bytes(&mut bytes, &namespace)?;
        push_u32(&mut bytes, record_count);

        let mut index_entries = Vec::with_capacity(self.records.len());
        for record in &self.records {
            let start = bytes.len();
            let envelope_bytes = record.envelope.encode()?;
            let body_len = record_wire_body_len(record)?;
            let body_len_u32 = u32::try_from(body_len).map_err(|_| FabricError::RecordTooLarge)?;
            push_u32(&mut bytes, body_len_u32);
            push_u32(
                &mut bytes,
                u32::try_from(envelope_bytes.len()).map_err(|_| FabricError::EnvelopeTooLarge)?,
            );
            bytes.extend_from_slice(&envelope_bytes);
            push_u64(
                &mut bytes,
                u64::try_from(record.payload.len()).map_err(|_| FabricError::LengthOverflow)?,
            );
            bytes.extend_from_slice(&record.payload);
            let end = bytes.len();
            let total_len = end.checked_sub(start).ok_or(FabricError::LengthOverflow)?;
            if total_len > self.limits.max_record_bytes {
                return Err(FabricError::RecordTooLarge);
            }
            let leaf = self
                .hasher
                .digest(DigestDomain::MerkleLeaf, &[&bytes[start..end]])?;
            index_entries.push(BuildIndexEntry {
                object_identity: record.envelope.object_identity(),
                record_offset: u64::try_from(start).map_err(|_| FabricError::LengthOverflow)?,
                record_len: u32::try_from(total_len).map_err(|_| FabricError::RecordTooLarge)?,
                object_kind: record.envelope.object_kind(),
                payload_len: record.envelope.declared_length(),
                payload_commitment: record.envelope.payload_commitment(),
                leaf,
            });
        }

        let index_offset = u64::try_from(bytes.len()).map_err(|_| FabricError::LengthOverflow)?;
        bytes.extend_from_slice(INDEX_MAGIC);
        push_u32(&mut bytes, record_count);
        for entry in &index_entries {
            push_object_identity(&mut bytes, entry.object_identity);
            push_u64(&mut bytes, entry.record_offset);
            push_u32(&mut bytes, entry.record_len);
            bytes.push(entry.object_kind.to_wire());
            push_u64(&mut bytes, entry.payload_len);
            bytes.extend_from_slice(&entry.payload_commitment);
            bytes.extend_from_slice(&entry.leaf);
        }
        let index_len = u64::try_from(bytes.len())
            .map_err(|_| FabricError::LengthOverflow)?
            .checked_sub(index_offset)
            .ok_or(FabricError::LengthOverflow)?;
        let leaves = index_entries
            .iter()
            .map(|entry| entry.leaf)
            .collect::<Vec<_>>();
        let merkle_root = merkle_root(self.hasher, &leaves)?;

        bytes.extend_from_slice(FOOTER_MAGIC);
        push_u16(&mut bytes, FORMAT_VERSION);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, record_count);
        push_u64(&mut bytes, index_offset);
        push_u64(&mut bytes, index_len);
        bytes.extend_from_slice(&merkle_root);
        let segment_digest = self
            .hasher
            .digest(DigestDomain::Segment, &[bytes.as_slice()])?;
        bytes.extend_from_slice(&segment_digest);
        if bytes.len() > self.limits.max_segment_bytes {
            return Err(FabricError::SegmentTooLarge);
        }
        Ok(Microsegment {
            bytes,
            segment_digest,
            merkle_root,
            record_count,
        })
    }
}

#[derive(Debug, Clone)]
struct BuildIndexEntry {
    object_identity: GitOid,
    record_offset: u64,
    record_len: u32,
    object_kind: ObjectKind,
    payload_len: u64,
    payload_commitment: Commitment,
    leaf: Commitment,
}

#[derive(Debug, Clone)]
struct RecordMeta {
    offset: usize,
    total_len: usize,
    payload_offset: usize,
    payload_len: usize,
    envelope: ObjectEnvelope,
    leaf: Commitment,
}

/// Verified read-only view over a canonical microsegment.
pub struct MicrosegmentReader<'a, H> {
    bytes: &'a [u8],
    namespace: Vec<u8>,
    records: Vec<RecordMeta>,
    merkle_root: Commitment,
    segment_digest: Commitment,
    marker: std::marker::PhantomData<&'a H>,
}

impl<'a, H: DigestAlgorithm> MicrosegmentReader<'a, H> {
    pub fn open(bytes: &'a [u8], hasher: &H, limits: &SegmentLimits) -> Result<Self, FabricError> {
        if bytes.len() > limits.max_segment_bytes {
            return Err(FabricError::SegmentTooLarge);
        }
        if bytes.len() < FOOTER_BYTES {
            return Err(FabricError::Truncated);
        }
        let footer_offset = bytes
            .len()
            .checked_sub(FOOTER_BYTES)
            .ok_or(FabricError::Truncated)?;
        let mut header = Cursor::new(&bytes[..footer_offset]);
        header.expect_magic(*SEGMENT_MAGIC)?;
        let version = header.read_u16()?;
        if version != FORMAT_VERSION {
            return Err(FabricError::UnknownVersion(version));
        }
        let namespace = header.read_prefixed_bytes(limits.max_namespace_bytes)?;
        validate_namespace(&namespace, limits)?;
        let record_count = header.read_u32()?;
        if record_count > limits.max_records {
            return Err(FabricError::TooManyRecords);
        }
        let records_start = header.position();

        let footer = parse_footer(&bytes[footer_offset..])?;
        if footer.record_count != record_count {
            return Err(FabricError::InvalidFooter);
        }
        let index_offset =
            usize::try_from(footer.index_offset).map_err(|_| FabricError::InvalidFooter)?;
        let index_len =
            usize::try_from(footer.index_len).map_err(|_| FabricError::InvalidFooter)?;
        let index_end = index_offset
            .checked_add(index_len)
            .ok_or(FabricError::InvalidFooter)?;
        if index_offset < records_start || index_end != footer_offset {
            return Err(FabricError::InvalidFooter);
        }
        let mut record_cursor = Cursor::new(&bytes[records_start..index_offset]);
        let mut records: Vec<RecordMeta> = Vec::with_capacity(
            usize::try_from(record_count).map_err(|_| FabricError::LengthOverflow)?,
        );
        for _ in 0..record_count {
            let local_start = record_cursor.position();
            let body_len = usize::try_from(record_cursor.read_u32()?)
                .map_err(|_| FabricError::RecordTooLarge)?;
            let total_record_len = body_len.checked_add(4).ok_or(FabricError::LengthOverflow)?;
            if total_record_len > limits.max_record_bytes {
                return Err(FabricError::RecordTooLarge);
            }
            let body_start = record_cursor.position();
            let body_end = body_start
                .checked_add(body_len)
                .ok_or(FabricError::LengthOverflow)?;
            if body_end > record_cursor.total_len() {
                return Err(FabricError::Truncated);
            }
            let envelope_len = usize::try_from(record_cursor.read_u32()?)
                .map_err(|_| FabricError::EnvelopeTooLarge)?;
            if envelope_len > limits.max_envelope_bytes {
                return Err(FabricError::EnvelopeTooLarge);
            }
            let envelope_bytes = record_cursor.take(envelope_len)?;
            let envelope = ObjectEnvelope::decode(envelope_bytes, limits)?;
            if envelope.namespace() != namespace.as_slice() {
                return Err(FabricError::MixedNamespace);
            }
            let payload_len_u64 = record_cursor.read_u64()?;
            let payload_len =
                usize::try_from(payload_len_u64).map_err(|_| FabricError::RecordTooLarge)?;
            let payload_offset = records_start
                .checked_add(record_cursor.position())
                .ok_or(FabricError::LengthOverflow)?;
            let payload = record_cursor.take(payload_len)?;
            if record_cursor.position() != body_end {
                return Err(FabricError::InvalidIndex);
            }
            if envelope.declared_length() != payload_len_u64 {
                return Err(FabricError::PayloadLengthMismatch);
            }
            if hasher.payload_commitment(envelope.object_kind(), payload)?
                != envelope.payload_commitment()
            {
                return Err(FabricError::PayloadCommitmentMismatch);
            }
            let absolute_start = records_start
                .checked_add(local_start)
                .ok_or(FabricError::LengthOverflow)?;
            let absolute_end = records_start
                .checked_add(record_cursor.position())
                .ok_or(FabricError::LengthOverflow)?;
            let total_len = absolute_end
                .checked_sub(absolute_start)
                .ok_or(FabricError::LengthOverflow)?;
            if total_len != total_record_len || total_len > limits.max_record_bytes {
                return Err(FabricError::RecordTooLarge);
            }
            let leaf = hasher.digest(
                DigestDomain::MerkleLeaf,
                &[&bytes[absolute_start..absolute_end]],
            )?;
            if let Some(previous) = records.last() {
                match previous
                    .envelope
                    .object_identity()
                    .cmp(&envelope.object_identity())
                {
                    Ordering::Greater => return Err(FabricError::NonCanonicalRecordOrder),
                    Ordering::Equal => return Err(FabricError::DuplicateObjectIdentity),
                    Ordering::Less => {}
                }
            }
            records.push(RecordMeta {
                offset: absolute_start,
                total_len,
                payload_offset,
                payload_len,
                envelope,
                leaf,
            });
        }
        if !record_cursor.is_finished() {
            return Err(FabricError::InvalidIndex);
        }

        validate_index(
            &bytes[index_offset..index_end],
            &records,
            record_count,
            limits,
        )?;
        let leaves = records.iter().map(|record| record.leaf).collect::<Vec<_>>();
        let computed_root = merkle_root(hasher, &leaves)?;
        if computed_root != footer.merkle_root {
            return Err(FabricError::MerkleRootMismatch);
        }
        let digest_end = footer_offset
            .checked_add(FOOTER_CORE_BYTES)
            .ok_or(FabricError::LengthOverflow)?;
        let computed_digest = hasher.digest(DigestDomain::Segment, &[&bytes[..digest_end]])?;
        if computed_digest != footer.segment_digest {
            return Err(FabricError::SegmentDigestMismatch);
        }
        Ok(Self {
            bytes,
            namespace,
            records,
            merkle_root: footer.merkle_root,
            segment_digest: footer.segment_digest,
            marker: std::marker::PhantomData,
        })
    }

    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    #[must_use]
    pub const fn merkle_root(&self) -> Commitment {
        self.merkle_root
    }

    #[must_use]
    pub const fn segment_digest(&self) -> Commitment {
        self.segment_digest
    }

    #[must_use]
    pub fn record(&self, index: usize) -> Option<RecordView<'_>> {
        self.records.get(index).and_then(|record| {
            let payload_end = record.payload_offset.checked_add(record.payload_len)?;
            Some(RecordView {
                envelope: &record.envelope,
                payload: &self.bytes[record.payload_offset..payload_end],
                offset: record.offset,
                total_len: record.total_len,
            })
        })
    }

    #[must_use]
    pub fn lookup(&self, object_identity: GitOid) -> Option<RecordView<'_>> {
        self.lookup_with_witness(object_identity).record
    }

    #[must_use]
    pub fn lookup_with_witness(&self, object_identity: GitOid) -> LookupResult<'_> {
        let mut lower = 0usize;
        let mut upper = self.records.len();
        let mut comparisons = 0usize;
        while lower < upper {
            let midpoint = lower + (upper - lower) / 2;
            comparisons += 1;
            match self.records[midpoint]
                .envelope
                .object_identity()
                .cmp(&object_identity)
            {
                Ordering::Less => lower = midpoint + 1,
                Ordering::Greater => upper = midpoint,
                Ordering::Equal => {
                    return LookupResult {
                        record: self.record(midpoint),
                        comparisons,
                    };
                }
            }
        }
        LookupResult {
            record: None,
            comparisons,
        }
    }

    pub fn merkle_proof(&self, index: usize, hasher: &H) -> Option<MerkleProof> {
        self.records.get(index)?;
        let leaves = self
            .records
            .iter()
            .map(|record| record.leaf)
            .collect::<Vec<_>>();
        let mut level = leaves;
        let mut cursor = index;
        let mut siblings = Vec::new();
        while level.len() > 1 {
            let sibling_index = if cursor.is_multiple_of(2) {
                if cursor + 1 < level.len() {
                    cursor + 1
                } else {
                    cursor
                }
            } else {
                cursor - 1
            };
            siblings.push(level[sibling_index]);
            level = next_merkle_level(hasher, &level).ok()?;
            cursor /= 2;
        }
        Some(MerkleProof {
            leaf_index: index,
            leaf_count: self.records.len(),
            siblings,
        })
    }
}

/// One record returned by a verified random-access read.
#[derive(Debug, Clone, Copy)]
pub struct RecordView<'a> {
    pub envelope: &'a ObjectEnvelope,
    pub payload: &'a [u8],
    pub offset: usize,
    pub total_len: usize,
}

/// Observable bounded-work receipt for the sorted-index lookup path.
#[derive(Debug, Clone, Copy)]
pub struct LookupResult<'a> {
    pub record: Option<RecordView<'a>>,
    pub comparisons: usize,
}

/// Authentication path from a record leaf to the segment's Merkle root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub siblings: Vec<Commitment>,
}

pub fn verify_merkle_proof<H: DigestAlgorithm>(
    hasher: &H,
    leaf: Commitment,
    proof: &MerkleProof,
    expected_root: Commitment,
) -> bool {
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return false;
    }
    let mut current = leaf;
    let mut index = proof.leaf_index;
    let mut width = proof.leaf_count;
    for sibling in &proof.siblings {
        if width <= 1 {
            return false;
        }
        let right = if index.is_multiple_of(2) {
            *sibling
        } else {
            current
        };
        let left = if index.is_multiple_of(2) {
            current
        } else {
            *sibling
        };
        let Ok(next) = hasher.digest(DigestDomain::MerkleNode, &[&left, &right]) else {
            return false;
        };
        current = next;
        index /= 2;
        width = width.div_ceil(2);
    }
    width == 1 && current == expected_root
}

/// Integrity verifier that hashes a segment incrementally without buffering it.
///
/// It verifies the footer's segment digest; callers then open the retained bytes
/// with [`MicrosegmentReader`] for structural/index/Merkle verification.
pub struct StreamingSegmentVerifier<'a, H: DigestAlgorithm> {
    hasher: &'a H,
    state: Option<H::State>,
    total_len: usize,
    digest_offset: usize,
    received: usize,
    footer_digest: Commitment,
}

impl<'a, H: DigestAlgorithm> StreamingSegmentVerifier<'a, H> {
    pub fn new(
        hasher: &'a H,
        total_len: usize,
        limits: &SegmentLimits,
    ) -> Result<Self, FabricError> {
        if total_len > limits.max_segment_bytes {
            return Err(FabricError::SegmentTooLarge);
        }
        if total_len < FOOTER_BYTES {
            return Err(FabricError::Truncated);
        }
        let digest_offset = total_len
            .checked_sub(COMMITMENT_BYTES)
            .ok_or(FabricError::Truncated)?;
        Ok(Self {
            hasher,
            state: Some(hasher.begin(DigestDomain::Segment, digest_offset)?),
            total_len,
            digest_offset,
            received: 0,
            footer_digest: [0; COMMITMENT_BYTES],
        })
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<(), FabricError> {
        let chunk_end = self
            .received
            .checked_add(chunk.len())
            .ok_or(FabricError::LengthOverflow)?;
        if chunk_end > self.total_len {
            return Err(FabricError::StreamingLengthMismatch);
        }
        let hash_end = chunk_end.min(self.digest_offset);
        if self.received < hash_end {
            let hash_len = hash_end - self.received;
            let state = self
                .state
                .as_mut()
                .ok_or(FabricError::StreamingLengthMismatch)?;
            self.hasher.update(state, &chunk[..hash_len]);
        }
        if chunk_end > self.digest_offset {
            let start = self.digest_offset.saturating_sub(self.received);
            let digest_start = self.received.max(self.digest_offset);
            let destination = digest_start - self.digest_offset;
            let digest_len = chunk_end - digest_start;
            self.footer_digest[destination..destination + digest_len]
                .copy_from_slice(&chunk[start..start + digest_len]);
        }
        self.received = chunk_end;
        Ok(())
    }

    pub fn finish(mut self) -> Result<Commitment, FabricError> {
        if self.received != self.total_len {
            return Err(FabricError::StreamingLengthMismatch);
        }
        let state = self
            .state
            .take()
            .ok_or(FabricError::StreamingLengthMismatch)?;
        let computed = self.hasher.finish(state);
        if computed != self.footer_digest {
            return Err(FabricError::SegmentDigestMismatch);
        }
        Ok(computed)
    }
}

#[derive(Debug, Clone, Copy)]
struct Footer {
    record_count: u32,
    index_offset: u64,
    index_len: u64,
    merkle_root: Commitment,
    segment_digest: Commitment,
}

fn parse_footer(bytes: &[u8]) -> Result<Footer, FabricError> {
    if bytes.len() != FOOTER_BYTES {
        return Err(FabricError::InvalidFooter);
    }
    let mut cursor = Cursor::new(bytes);
    cursor.expect_magic(*FOOTER_MAGIC)?;
    let version = cursor.read_u16()?;
    if version != FORMAT_VERSION {
        return Err(FabricError::UnknownVersion(version));
    }
    if cursor.read_u16()? != 0 {
        return Err(FabricError::InvalidFooter);
    }
    let footer = Footer {
        record_count: cursor.read_u32()?,
        index_offset: cursor.read_u64()?,
        index_len: cursor.read_u64()?,
        merkle_root: cursor.read_commitment()?,
        segment_digest: cursor.read_commitment()?,
    };
    if !cursor.is_finished() {
        return Err(FabricError::InvalidFooter);
    }
    Ok(footer)
}

fn validate_index(
    bytes: &[u8],
    records: &[RecordMeta],
    record_count: u32,
    limits: &SegmentLimits,
) -> Result<(), FabricError> {
    let mut cursor = Cursor::new(bytes);
    cursor.expect_magic(*INDEX_MAGIC)?;
    if cursor.read_u32()? != record_count {
        return Err(FabricError::InvalidIndex);
    }
    for record in records {
        let object_identity = cursor.read_object_identity(limits)?;
        let record_offset =
            usize::try_from(cursor.read_u64()?).map_err(|_| FabricError::InvalidIndex)?;
        let record_len =
            usize::try_from(cursor.read_u32()?).map_err(|_| FabricError::InvalidIndex)?;
        let object_kind = ObjectKind::from_wire(cursor.read_u8()?)?;
        let payload_len = cursor.read_u64()?;
        let payload_commitment = cursor.read_commitment()?;
        let leaf = cursor.read_commitment()?;
        if object_identity != record.envelope.object_identity()
            || record_offset != record.offset
            || record_len != record.total_len
            || object_kind != record.envelope.object_kind()
            || payload_len != record.envelope.declared_length()
            || payload_commitment != record.envelope.payload_commitment()
            || leaf != record.leaf
        {
            return Err(FabricError::IndexRecordMismatch);
        }
    }
    if !cursor.is_finished() {
        return Err(FabricError::InvalidIndex);
    }
    Ok(())
}

fn merkle_root<H: DigestAlgorithm>(
    hasher: &H,
    leaves: &[Commitment],
) -> Result<Commitment, FabricError> {
    let mut level = leaves.to_vec();
    let first = *level.first().ok_or(FabricError::EmptyNamespace)?;
    if level.len() == 1 {
        return Ok(first);
    }
    while level.len() > 1 {
        level = next_merkle_level(hasher, &level)?;
    }
    Ok(level[0])
}

fn next_merkle_level<H: DigestAlgorithm>(
    hasher: &H,
    level: &[Commitment],
) -> Result<Vec<Commitment>, FabricError> {
    if level.is_empty() {
        return Err(FabricError::InvalidFooter);
    }
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        let left = pair[0];
        let right = pair.get(1).copied().unwrap_or(left);
        next.push(hasher.digest(DigestDomain::MerkleNode, &[&left, &right])?);
    }
    Ok(next)
}

fn record_wire_body_len(record: &SegmentRecordInput) -> Result<usize, FabricError> {
    4usize
        .checked_add(record.envelope.encoded_len()?)
        .and_then(|value| value.checked_add(8))
        .and_then(|value| value.checked_add(record.payload.len()))
        .ok_or(FabricError::LengthOverflow)
}

fn header_wire_len(namespace: &[u8]) -> Result<usize, FabricError> {
    4usize
        .checked_add(2)
        .and_then(|value| value.checked_add(2))
        .and_then(|value| value.checked_add(namespace.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or(FabricError::LengthOverflow)
}

fn index_entry_wire_len(object_identity: GitOid) -> Result<usize, FabricError> {
    2usize
        .checked_add(object_identity.as_bytes().len())
        .and_then(|value| value.checked_add(8 + 4 + 1 + 8))
        .and_then(|value| value.checked_add(COMMITMENT_BYTES * 2))
        .ok_or(FabricError::LengthOverflow)
}

fn validate_namespace(namespace: &[u8], limits: &SegmentLimits) -> Result<(), FabricError> {
    if namespace.is_empty() {
        return Err(FabricError::EmptyNamespace);
    }
    if namespace.len() > limits.max_namespace_bytes || namespace.len() > usize::from(u16::MAX) {
        return Err(FabricError::NamespaceTooLarge);
    }
    Ok(())
}

fn validate_object_identity(
    object_identity: GitOid,
    limits: &SegmentLimits,
) -> Result<(), FabricError> {
    if object_identity.is_zero() {
        return Err(FabricError::ZeroObjectIdentity);
    }
    if object_identity.as_bytes().len() > limits.max_object_identity_bytes {
        return Err(FabricError::ObjectIdentityTooLarge);
    }
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_prefixed_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), FabricError> {
    let len = u16::try_from(value.len()).map_err(|_| FabricError::LengthOverflow)?;
    push_u16(output, len);
    output.extend_from_slice(value);
    Ok(())
}

fn push_object_identity(output: &mut Vec<u8>, object_identity: GitOid) {
    push_u16(output, object_identity.algorithm().code_point());
    output.extend_from_slice(object_identity.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    const fn total_len(&self) -> usize {
        self.bytes.len()
    }

    const fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn expect_magic(&mut self, expected: [u8; 4]) -> Result<(), FabricError> {
        if self.take(4)? != expected {
            return Err(FabricError::InvalidMagic);
        }
        Ok(())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FabricError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(FabricError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(FabricError::Truncated);
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn read_u8(&mut self) -> Result<u8, FabricError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, FabricError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, FabricError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, FabricError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_prefixed_bytes(&mut self, max_len: usize) -> Result<Vec<u8>, FabricError> {
        let len = usize::from(self.read_u16()?);
        if len > max_len {
            return Err(FabricError::NamespaceTooLarge);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn read_object_identity(&mut self, limits: &SegmentLimits) -> Result<GitOid, FabricError> {
        let algorithm = GitHashAlgorithm::from_code_point(self.read_u16()?)
            .map_err(FabricError::GitObjectIdentity)?;
        let object_identity = match algorithm {
            GitHashAlgorithm::Sha1 => {
                let mut bytes = [0_u8; GitOidSha1::LEN];
                bytes.copy_from_slice(self.take(GitOidSha1::LEN)?);
                GitOid::Sha1(GitOidSha1::from_bytes(bytes))
            }
            GitHashAlgorithm::Sha256 => {
                let mut bytes = [0_u8; GitOidSha256::LEN];
                bytes.copy_from_slice(self.take(GitOidSha256::LEN)?);
                GitOid::Sha256(GitOidSha256::from_bytes(bytes))
            }
        };
        validate_object_identity(object_identity, limits)?;
        Ok(object_identity)
    }

    fn read_commitment(&mut self) -> Result<Commitment, FabricError> {
        let bytes = self.take(COMMITMENT_BYTES)?;
        let mut commitment = [0; COMMITMENT_BYTES];
        commitment.copy_from_slice(bytes);
        Ok(commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SegmentLimits {
        SegmentLimits {
            max_segment_bytes: 64 * 1024,
            max_records: 128,
            max_namespace_bytes: 16,
            max_object_identity_bytes: 32,
            max_envelope_bytes: 256,
            max_record_bytes: 512,
        }
    }

    fn envelope(identity: u8) -> ObjectEnvelope {
        let payload = payload(identity);
        let digest = CryptoDigest;
        ObjectEnvelope::new(
            vec![b'n'],
            oid(identity),
            ObjectKind::Blob,
            u64::try_from(payload.len()).expect("fixture payload length must fit u64"),
            digest
                .payload_commitment(ObjectKind::Blob, &payload)
                .expect("registered payload commitment must succeed"),
            vec![b'c'],
            [4; COMMITMENT_BYTES],
            None,
            &limits(),
        )
        .expect("fixture envelope must be valid")
    }

    fn oid(identity: u8) -> GitOid {
        GitOid::Sha1(GitOidSha1::from_bytes([identity; GitOidSha1::LEN]))
    }

    fn payload(identity: u8) -> Vec<u8> {
        vec![b'p', identity]
    }

    fn segment_with(identities: &[u8]) -> Microsegment {
        let digest = CryptoDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        for identity in identities {
            builder
                .push(SegmentRecordInput {
                    envelope: envelope(*identity),
                    payload: payload(*identity),
                })
                .expect("ordered fixture record must be valid");
        }
        builder.build().expect("fixture segment must build")
    }

    /// Independently frames the one-record golden using the V1 layout rather
    /// than `MicrosegmentBuilder`. Its hashes are the registered fgit-crypto
    /// constructions, so changing canonical framing or a commitment domain
    /// changes this independently assembled vector.
    fn independently_framed_one_record_segment() -> Vec<u8> {
        let digest = CryptoDigest;
        let object_identity = oid(b'o');
        let payload = payload(b'o');
        let payload_commitment = digest
            .payload_commitment(ObjectKind::Blob, &payload)
            .expect("registered payload commitment must succeed");

        let mut envelope = Vec::new();
        envelope.extend_from_slice(ENVELOPE_MAGIC);
        envelope.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        envelope.extend_from_slice(&1_u16.to_be_bytes());
        envelope.push(b'n');
        envelope.extend_from_slice(&object_identity.algorithm().code_point().to_be_bytes());
        envelope.extend_from_slice(object_identity.as_bytes());
        envelope.push(ObjectKind::Blob.to_wire());
        envelope.extend_from_slice(
            &u64::try_from(payload.len())
                .expect("fixture payload length must fit u64")
                .to_be_bytes(),
        );
        envelope.extend_from_slice(&payload_commitment);
        envelope.extend_from_slice(&1_u16.to_be_bytes());
        envelope.push(b'c');
        envelope.extend_from_slice(&[4; COMMITMENT_BYTES]);
        envelope.push(0);

        let mut record = Vec::new();
        let record_body_len = 4usize
            .checked_add(envelope.len())
            .and_then(|value| value.checked_add(8))
            .and_then(|value| value.checked_add(payload.len()))
            .expect("one-record golden body length must fit usize");
        record.extend_from_slice(
            &u32::try_from(record_body_len)
                .expect("one-record golden record body must fit u32")
                .to_be_bytes(),
        );
        record.extend_from_slice(
            &u32::try_from(envelope.len())
                .expect("one-record golden envelope must fit u32")
                .to_be_bytes(),
        );
        record.extend_from_slice(&envelope);
        record.extend_from_slice(
            &u64::try_from(payload.len())
                .expect("fixture payload length must fit u64")
                .to_be_bytes(),
        );
        record.extend_from_slice(&payload);
        let leaf = digest
            .digest(DigestDomain::MerkleLeaf, &[&record])
            .expect("registered Merkle leaf digest must succeed");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(SEGMENT_MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.push(b'n');
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        let index_offset = bytes
            .len()
            .checked_add(record.len())
            .expect("one-record golden index offset must fit usize");
        bytes.extend_from_slice(&record);

        let mut index = Vec::new();
        index.extend_from_slice(INDEX_MAGIC);
        index.extend_from_slice(&1_u32.to_be_bytes());
        index.extend_from_slice(&object_identity.algorithm().code_point().to_be_bytes());
        index.extend_from_slice(object_identity.as_bytes());
        index.extend_from_slice(&13_u64.to_be_bytes());
        index.extend_from_slice(
            &u32::try_from(record.len())
                .expect("one-record golden record length must fit u32")
                .to_be_bytes(),
        );
        index.push(ObjectKind::Blob.to_wire());
        index.extend_from_slice(
            &u64::try_from(payload.len())
                .expect("fixture payload length must fit u64")
                .to_be_bytes(),
        );
        index.extend_from_slice(&payload_commitment);
        index.extend_from_slice(&leaf);
        bytes.extend_from_slice(&index);

        bytes.extend_from_slice(FOOTER_MAGIC);
        bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(
            &u64::try_from(index_offset)
                .expect("one-record golden index offset must fit u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u64::try_from(index.len())
                .expect("one-record golden index length must fit u64")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&leaf);
        let segment_digest = digest
            .digest(DigestDomain::Segment, &[&bytes])
            .expect("registered segment digest must succeed");
        bytes.extend_from_slice(&segment_digest);
        bytes
    }

    #[test]
    fn one_record_segment_matches_pinned_golden_and_round_trips() {
        let digest = CryptoDigest;
        let segment = segment_with(b"o");
        let expected = decode_hex(include_str!(
            "../tests/goldens/microsegment_v1_one_record.hex"
        ));
        assert_eq!(
            expected,
            independently_framed_one_record_segment(),
            "the fixed golden must retain the V1 independently framed bytes"
        );
        let golden_reader = MicrosegmentReader::open(&expected, &digest, &limits())
            .expect("pinned golden must be independently readable");
        assert_eq!(
            golden_reader
                .record(0)
                .expect("golden record must exist")
                .offset,
            13
        );
        assert_eq!(segment.as_bytes(), expected.as_slice());
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("golden segment must be readable");
        assert_eq!(reader.len(), 1);
        assert_eq!(reader.record(0).expect("record must exist").payload, b"po");
        assert_eq!(reader.segment_digest(), segment.segment_digest());
    }

    #[test]
    fn build_read_rebuild_round_trips_canonical_segment() {
        let digest = CryptoDigest;
        let segment = segment_with(b"abc");
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("fixture segment must be readable");
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        for index in 0..reader.len() {
            let record = reader.record(index).expect("record index must be valid");
            builder
                .push(SegmentRecordInput {
                    envelope: record.envelope.clone(),
                    payload: record.payload.to_vec(),
                })
                .expect("verified record must rebuild");
        }
        let rebuilt = builder.build().expect("rebuilt segment must be valid");
        assert_eq!(rebuilt.as_bytes(), segment.as_bytes());
    }

    #[test]
    fn crypto_digest_binds_native_payload_and_registered_segment_identity() {
        let digest = CryptoDigest;
        let payload = b"native payload";
        let payload_commitment = digest
            .payload_commitment(ObjectKind::Blob, payload)
            .expect("native blob payload must have a strong commitment");
        let envelope = ObjectEnvelope::new(
            vec![b'n'],
            oid(b'z'),
            ObjectKind::Blob,
            u64::try_from(payload.len()).expect("fixture payload length must fit u64"),
            payload_commitment,
            vec![b'c'],
            [7; COMMITMENT_BYTES],
            None,
            &limits(),
        )
        .expect("crypto fixture envelope must be valid");
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        builder
            .push(SegmentRecordInput {
                envelope,
                payload: payload.to_vec(),
            })
            .expect("payload commitment must admit its matching native object");
        let segment = builder.build().expect("crypto fixture segment must build");
        let canonical_body = &segment.as_bytes()[..segment.as_bytes().len() - COMMITMENT_BYTES];
        let identity = fgit_crypto::internal_object_id(
            IdentityDomain::GitObjectMicrosegment,
            MICROSEGMENT_SCHEMA,
            CodecVersion::new(1, 0),
            canonical_body,
        );
        assert_eq!(
            segment.segment_digest(),
            commitment_from_bytes(identity.digest().as_bytes())
                .expect("registered microsegment identity must use SHA-256")
        );
        assert_eq!(
            fgit_crypto::verify_internal_object_id(
                &identity,
                IdentityDomain::GitObjectMicrosegment,
                MICROSEGMENT_SCHEMA,
                CodecVersion::new(1, 0),
                canonical_body,
            ),
            Ok(())
        );
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("crypto segment must be structurally and cryptographically valid");
        assert_eq!(
            reader.record(0).expect("record must exist").payload,
            payload
        );
        let mut verifier =
            StreamingSegmentVerifier::new(&digest, segment.as_bytes().len(), &limits())
                .expect("crypto stream verifier must initialize");
        for chunk in segment.as_bytes().chunks(3) {
            verifier
                .push(chunk)
                .expect("canonical crypto segment chunk must be accepted");
        }
        assert_eq!(
            verifier
                .finish()
                .expect("crypto stream must reproduce the registered segment identity"),
            segment.segment_digest()
        );

        let mut corrupt = segment.as_bytes().to_vec();
        corrupt[0] ^= 1;
        let mut verifier = StreamingSegmentVerifier::new(&digest, corrupt.len(), &limits())
            .expect("corrupt stream verifier must initialize");
        for chunk in corrupt.chunks(5) {
            verifier
                .push(chunk)
                .expect("bounded corrupt chunk must be accepted before final verification");
        }
        assert_eq!(verifier.finish(), Err(FabricError::SegmentDigestMismatch));
    }

    #[test]
    fn crypto_digest_refuses_internal_kind_but_accepts_native_kind() {
        let digest = CryptoDigest;
        assert!(digest.payload_commitment(ObjectKind::Blob, b"p").is_ok());
        assert_eq!(
            digest.payload_commitment(ObjectKind::Internal, b"p"),
            Err(FabricError::InternalObjectKindUnsupported)
        );
    }

    #[test]
    fn crypto_digest_uses_registered_merkle_domains() {
        let digest = CryptoDigest;
        let leaf = digest
            .digest(DigestDomain::MerkleLeaf, &[b"record"])
            .expect("registered Merkle leaf digest must succeed");
        let expected_leaf = commitment_from_bytes(
            fgit_crypto::internal_digest_over_parts(
                IdentityDomain::MerkleLeaf,
                MICROSEGMENT_MERKLE_SCHEMA,
                &[b"record"],
            )
            .as_bytes(),
        )
        .expect("Merkle leaf registry construction must be SHA-256");
        assert_eq!(leaf, expected_leaf);
        let node = digest
            .digest(DigestDomain::MerkleNode, &[&leaf, &leaf])
            .expect("registered Merkle node digest must succeed");
        assert_ne!(leaf, node);
        assert_eq!(
            digest.digest(DigestDomain::Payload, &[b"record"]),
            Err(FabricError::PayloadObjectKindRequired)
        );
    }

    #[test]
    fn envelope_round_trips_with_every_identity_bearing_field() {
        let envelope = ObjectEnvelope::new(
            vec![b'n'],
            oid(b'o'),
            ObjectKind::Tag,
            42,
            [1; COMMITMENT_BYTES],
            vec![b'c'],
            [4; COMMITMENT_BYTES],
            Some([9; COMMITMENT_BYTES]),
            &limits(),
        )
        .expect("fixture envelope must be valid");
        assert_eq!(
            ObjectEnvelope::decode(
                &envelope.encode().expect("fixture envelope must encode"),
                &limits()
            ),
            Ok(envelope)
        );
    }

    #[test]
    fn deterministic_builds_are_byte_identical() {
        assert_eq!(
            segment_with(b"abc").as_bytes(),
            segment_with(b"abc").as_bytes()
        );
    }

    #[test]
    fn sorted_index_lookup_matches_linear_oracle_with_logarithmic_witness() {
        let digest = CryptoDigest;
        let identities = (1u8..64).collect::<Vec<_>>();
        let segment = segment_with(&identities);
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("fixture segment must be readable");
        let mut state = 0xDEAD_BEEF_CAFE_BABEu64;
        for _ in 0..256 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let query = state.to_be_bytes()[0];
            let expected = identities.iter().position(|identity| *identity == query);
            let found = reader.lookup_with_witness(oid(query));
            assert_eq!(found.record.is_some(), expected.is_some());
            if let Some(record) = found.record {
                assert_eq!(record.envelope.object_identity(), oid(query));
            }
            assert!(
                found.comparisons <= 6,
                "binary lookup exceeded ceil(log2(64))"
            );
        }
    }

    #[test]
    fn every_record_merkle_proof_verifies() {
        let digest = CryptoDigest;
        let segment = segment_with(b"abc");
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("fixture segment must be readable");
        for index in 0..reader.len() {
            let proof = reader
                .merkle_proof(index, &digest)
                .expect("proof must exist");
            let leaf = reader.records[index].leaf;
            assert!(verify_merkle_proof(
                &digest,
                leaf,
                &proof,
                reader.merkle_root()
            ));
            let mut wrong_sibling = proof;
            wrong_sibling.siblings[0][0] ^= 1;
            assert!(
                !verify_merkle_proof(&digest, leaf, &wrong_sibling, reader.merkle_root()),
                "a changed authentication-path sibling must not verify"
            );
        }
    }

    #[test]
    fn streaming_integrity_verification_accepts_arbitrary_chunk_boundaries() {
        let digest = CryptoDigest;
        let segment = segment_with(b"ab");
        let mut verifier =
            StreamingSegmentVerifier::new(&digest, segment.as_bytes().len(), &limits())
                .expect("stream verifier must initialize");
        for chunk in segment.as_bytes().chunks(7) {
            verifier.push(chunk).expect("chunk must be accepted");
        }
        assert_eq!(
            verifier.finish().expect("stream digest must verify"),
            segment.segment_digest()
        );

        let mut corrupt = segment.as_bytes().to_vec();
        let final_byte = corrupt.len() - 1;
        corrupt[final_byte] ^= 1;
        let mut verifier = StreamingSegmentVerifier::new(&digest, corrupt.len(), &limits())
            .expect("stream verifier must initialize");
        for chunk in corrupt.chunks(11) {
            verifier.push(chunk).expect("chunk must be accepted");
        }
        assert_eq!(verifier.finish(), Err(FabricError::SegmentDigestMismatch));
    }

    #[test]
    fn builder_refuses_mixed_namespaces_out_of_order_and_wrong_payload_commitment() {
        let digest = CryptoDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        builder
            .push(SegmentRecordInput {
                envelope: envelope(b'b'),
                payload: payload(b'b'),
            })
            .expect("first record must be valid");
        assert_eq!(
            builder.push(SegmentRecordInput {
                envelope: envelope(b'a'),
                payload: payload(b'a'),
            }),
            Err(FabricError::NonCanonicalRecordOrder)
        );
        let mut other_namespace = envelope(b'c');
        other_namespace.namespace = vec![b'x'];
        assert_eq!(
            builder.push(SegmentRecordInput {
                envelope: other_namespace,
                payload: payload(b'c'),
            }),
            Err(FabricError::MixedNamespace)
        );
        let mut wrong_commitment = envelope(b'c');
        wrong_commitment.payload_commitment = [9; COMMITMENT_BYTES];
        assert_eq!(
            builder.push(SegmentRecordInput {
                envelope: wrong_commitment,
                payload: payload(b'c'),
            }),
            Err(FabricError::PayloadCommitmentMismatch)
        );
        assert_eq!(
            ObjectEnvelope::new(
                vec![b'n'],
                GitOid::Sha1(GitOidSha1::ZERO),
                ObjectKind::Blob,
                1,
                [1; COMMITMENT_BYTES],
                vec![b'c'],
                [4; COMMITMENT_BYTES],
                None,
                &limits(),
            ),
            Err(FabricError::ZeroObjectIdentity)
        );
    }

    #[test]
    fn reader_refuses_truncated_footer_index_record_mismatch_and_corruption() {
        let digest = CryptoDigest;
        let segment = segment_with(b"ab");
        assert!(matches!(
            MicrosegmentReader::open(
                &segment.as_bytes()[..segment.as_bytes().len() - 1],
                &digest,
                &limits()
            ),
            Err(FabricError::InvalidMagic | FabricError::InvalidFooter | FabricError::Truncated)
        ));
        let mut index_corrupt = segment.as_bytes().to_vec();
        let footer_start = index_corrupt.len() - FOOTER_BYTES;
        let index_offset = usize::try_from(u64::from_be_bytes(
            index_corrupt[footer_start + 12..footer_start + 20]
                .try_into()
                .expect("footer index offset must be eight bytes"),
        ))
        .expect("fixture index offset must fit usize");
        index_corrupt[index_offset + 42] ^= 1;
        assert!(matches!(
            MicrosegmentReader::open(&index_corrupt, &digest, &limits()),
            Err(FabricError::IndexRecordMismatch)
        ));
        let mut record_corrupt = segment.as_bytes().to_vec();
        record_corrupt[13] ^= 1;
        assert!(matches!(
            MicrosegmentReader::open(&record_corrupt, &digest, &limits()),
            Err(FabricError::Truncated
                | FabricError::InvalidIndex
                | FabricError::IndexRecordMismatch
                | FabricError::RecordTooLarge)
        ));
        let mut footer_corrupt = segment.as_bytes().to_vec();
        let footer_start = footer_corrupt.len() - FOOTER_BYTES;
        footer_corrupt[footer_start + 28] ^= 1;
        assert!(matches!(
            MicrosegmentReader::open(&footer_corrupt, &digest, &limits()),
            Err(FabricError::MerkleRootMismatch)
        ));
        let mut footer_digest_corrupt = segment.as_bytes().to_vec();
        let footer_start = footer_digest_corrupt.len() - FOOTER_BYTES;
        footer_digest_corrupt[footer_start + FOOTER_CORE_BYTES] ^= 1;
        assert!(matches!(
            MicrosegmentReader::open(&footer_digest_corrupt, &digest, &limits()),
            Err(FabricError::SegmentDigestMismatch)
        ));
    }

    #[test]
    fn reader_refuses_noncanonical_order_and_mixed_namespace() {
        let digest = CryptoDigest;
        let segment = segment_with(b"ab");
        let records_start = SEGMENT_MAGIC.len() + 2 + 2 + 1 + 4;
        let mut noncanonical = segment.as_bytes().to_vec();
        let first_body_len = usize::try_from(u32::from_be_bytes(
            noncanonical[records_start..records_start + 4]
                .try_into()
                .expect("record body length must be four bytes"),
        ))
        .expect("fixture record length must fit usize");
        let first_record_len = first_body_len + 4;
        let (first, second) = noncanonical[records_start..records_start + first_record_len * 2]
            .split_at_mut(first_record_len);
        first.swap_with_slice(second);
        assert!(matches!(
            MicrosegmentReader::open(&noncanonical, &digest, &limits()),
            Err(FabricError::NonCanonicalRecordOrder)
        ));

        let mut mixed_namespace = segment.as_bytes().to_vec();
        let envelope_start = records_start + 8;
        let namespace_byte = envelope_start + ENVELOPE_MAGIC.len() + 2 + 2;
        mixed_namespace[namespace_byte] ^= 1;
        assert!(matches!(
            MicrosegmentReader::open(&mixed_namespace, &digest, &limits()),
            Err(FabricError::MixedNamespace)
        ));
    }

    #[test]
    fn decoder_refuses_unknown_versions_and_trailing_envelope_bytes() {
        let envelope = envelope(b'a');
        let mut unknown_version = envelope.encode().expect("fixture envelope must encode");
        unknown_version[4] = 0;
        unknown_version[5] = 2;
        assert_eq!(
            ObjectEnvelope::decode(&unknown_version, &limits()),
            Err(FabricError::UnknownVersion(2))
        );
        let mut trailing = envelope.encode().expect("fixture envelope must encode");
        trailing.push(0);
        assert_eq!(
            ObjectEnvelope::decode(&trailing, &limits()),
            Err(FabricError::TrailingBytes)
        );
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        let compact = input
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        assert_eq!(compact.len() % 2, 0, "golden hex must contain whole bytes");
        compact
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]);
                let low = hex_nibble(pair[1]);
                high * 16 + low
            })
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("golden contains non-hex input"),
        }
    }

    // -----------------------------------------------------------------
    // frankengit-syca: three ObjectEnvelope refusals whose siblings on the
    // same function are already covered.
    //
    // `decoder_refuses_unknown_versions_and_trailing_envelope_bytes` above
    // exercises `UnknownVersion` and `TrailingBytes` on `ObjectEnvelope::decode`.
    // These three sit on the same path and were never reached.
    //
    // BYTE OFFSETS ARE LOCATED, NEVER HARD-CODED. The envelope puts the kind
    // byte after two variable-length fields, so a literal offset would drift
    // silently the day the fixture changes and the probe would corrupt
    // something else while still refusing. Each offset below is derived and
    // then asserted before it is used.
    // -----------------------------------------------------------------

    /// The offset of the object-kind byte, found by diffing two encodings that
    /// differ in nothing else.
    ///
    /// Asserts exactly one byte differs, so if the layout ever changes such
    /// that `object_kind` is not a single byte, this fails loudly instead of
    /// silently mutating a neighbour.
    fn object_kind_offset() -> usize {
        let payload = payload(b'a');
        let commitment = CryptoDigest
            .payload_commitment(ObjectKind::Blob, &payload)
            .expect("registered payload commitment must succeed");
        let build = |kind: ObjectKind| {
            ObjectEnvelope::new(
                vec![b'n'],
                oid(b'a'),
                kind,
                u64::try_from(payload.len()).expect("fixture length fits u64"),
                commitment,
                vec![b'c'],
                [4; COMMITMENT_BYTES],
                None,
                &limits(),
            )
            .expect("fixture envelope must be valid")
            .encode()
            .expect("fixture envelope must encode")
        };
        let blob = build(ObjectKind::Blob);
        let tag = build(ObjectKind::Tag);
        assert_eq!(blob.len(), tag.len(), "only the kind byte may differ");
        let differing: Vec<usize> = (0..blob.len()).filter(|i| blob[*i] != tag[*i]).collect();
        assert_eq!(
            differing.len(),
            1,
            "exactly one byte must distinguish two kinds; got {differing:?}",
        );
        differing[0]
    }

    /// Object-kind codes outside the wire set are refused, at both boundaries.
    ///
    /// `from_wire` accepts 1..=5. Code 0 is below the set and 6 is immediately
    /// above it, so probing both is what separates an enumeration from a range
    /// check — a guard written as `value <= 5` would admit 0, and one written
    /// as `value >= 1` would admit 6.
    ///
    /// Earlier fields are untouched, so magic, version, namespace and identity
    /// all parse and the walk genuinely reaches the kind byte.
    #[test]
    fn object_kind_codes_outside_the_wire_set_are_refused_at_both_boundaries() {
        let offset = object_kind_offset();
        let good = envelope(b'a')
            .encode()
            .expect("fixture envelope must encode");

        for code in [0_u8, 6] {
            let mut bad = good.clone();
            bad[offset] = code;
            assert_eq!(
                ObjectEnvelope::decode(&bad, &limits()),
                Err(FabricError::UnknownObjectKind(code)),
                "wire kind {code} must be refused, naming itself",
            );
        }
    }

    /// Every valid wire kind decodes through the same path.
    ///
    /// The permitted twin for the boundary probe above: without it, both
    /// refusals are equally satisfied by a `from_wire` that refuses
    /// everything.
    #[test]
    fn every_valid_object_kind_code_decodes() {
        let offset = object_kind_offset();
        let good = envelope(b'a')
            .encode()
            .expect("fixture envelope must encode");

        for code in 1_u8..=5 {
            let mut bytes = good.clone();
            bytes[offset] = code;
            let decoded = ObjectEnvelope::decode(&bytes, &limits());
            assert!(
                !matches!(decoded, Err(FabricError::UnknownObjectKind(_))),
                "wire kind {code} is valid and must not be refused as unknown; \
                 got {decoded:?}",
            );
        }
    }

    /// A manifest-reference discriminant outside {0, 1} is refused.
    ///
    /// The fixture carries `manifest_reference: None`, and `decode` reads that
    /// discriminant last before its end-of-input check — so for a `None`
    /// envelope it is the final byte. That is asserted rather than assumed
    /// before the byte is touched.
    ///
    /// Both twins are exercised: discriminant 0 decodes as-is, and 1 decodes
    /// once a commitment follows it. So the refusal is attributable to the
    /// third value and not to that position being read at all.
    #[test]
    fn a_manifest_reference_discriminant_outside_zero_and_one_is_refused() {
        let good = envelope(b'a')
            .encode()
            .expect("fixture envelope must encode");
        let discriminant = good.len() - 1;
        assert_eq!(
            good[discriminant], 0,
            "a None manifest reference must encode as a trailing zero \
             discriminant; the layout changed",
        );

        let mut bad = good.clone();
        bad[discriminant] = 2;
        assert_eq!(
            ObjectEnvelope::decode(&bad, &limits()),
            Err(FabricError::InvalidEnvelope),
        );

        // Twin one: discriminant 0, untouched.
        ObjectEnvelope::decode(&good, &limits()).expect("a None reference decodes");

        // Twin two: discriminant 1 with a commitment after it, built through
        // the constructor so the encoding is canonical rather than hand-spliced.
        let payload = payload(b'a');
        let with_reference = ObjectEnvelope::new(
            vec![b'n'],
            oid(b'a'),
            ObjectKind::Blob,
            u64::try_from(payload.len()).expect("fixture length fits u64"),
            CryptoDigest
                .payload_commitment(ObjectKind::Blob, &payload)
                .expect("registered payload commitment must succeed"),
            vec![b'c'],
            [4; COMMITMENT_BYTES],
            Some([9; COMMITMENT_BYTES]),
            &limits(),
        )
        .expect("a Some reference is valid");
        let bytes = with_reference
            .encode()
            .expect("fixture envelope must encode");
        assert_eq!(
            ObjectEnvelope::decode(&bytes, &limits()),
            Ok(with_reference),
            "a Some reference decodes through the same discriminant position",
        );
    }

    /// An envelope larger than the caller's declared bound is refused.
    ///
    /// Unreachable with the fixture limits — `max_envelope_bytes` is 256 and a
    /// maximal envelope under `max_namespace_bytes = 16` /
    /// `max_object_identity_bytes = 32` encodes to well under that. So the
    /// probe tightens the bound instead of inflating the envelope, which is
    /// legitimate because limits are a caller-supplied parameter, and is the
    /// honest way to reach a guard whose default headroom is generous.
    ///
    /// The comparison is `>`, so the twin sits on the exact encoded length.
    #[test]
    fn an_envelope_past_the_callers_declared_bound_is_refused() {
        let encoded_len = envelope(b'a')
            .encode()
            .expect("fixture envelope must encode")
            .len();

        let build = |max_envelope_bytes: usize| {
            let payload = payload(b'a');
            let mut tightened = limits();
            tightened.max_envelope_bytes = max_envelope_bytes;
            ObjectEnvelope::new(
                vec![b'n'],
                oid(b'a'),
                ObjectKind::Blob,
                u64::try_from(payload.len()).expect("fixture length fits u64"),
                CryptoDigest
                    .payload_commitment(ObjectKind::Blob, &payload)
                    .expect("registered payload commitment must succeed"),
                vec![b'c'],
                [4; COMMITMENT_BYTES],
                None,
                &tightened,
            )
        };

        assert_eq!(build(encoded_len - 1), Err(FabricError::EnvelopeTooLarge));
        build(encoded_len).expect("an envelope of exactly the bound is admissible");
    }
}
