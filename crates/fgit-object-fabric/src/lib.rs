#![forbid(unsafe_code)]
//! Immutable object envelopes and deterministic microsegments.
//!
//! This first object-fabric slice owns byte layout, bounded parsing, ordering,
//! index/Merkle/footer verification, and random-access lookup. It deliberately
//! does not own storage backends, placement manifests, or object admission. The
//! digest trait is an adapter boundary: production callers bind the fgit-crypto
//! domain-separated digest implementation and typed fgit-types OIDs here. This
//! crate never implements a cryptographic hash or invents a parallel ID type.

use std::cmp::Ordering;
use std::error::Error;
use std::fmt;

use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, TypeRefusal};

const ENVELOPE_MAGIC: &[u8; 4] = b"FGEN";
const SEGMENT_MAGIC: &[u8; 4] = b"FGMS";
const INDEX_MAGIC: &[u8; 4] = b"FGIX";
const FOOTER_MAGIC: &[u8; 4] = b"FGFT";
const FORMAT_VERSION: u16 = 1;
const COMMITMENT_BYTES: usize = 32;
const FOOTER_BYTES: usize = 92;
const FOOTER_CORE_BYTES: usize = FOOTER_BYTES - COMMITMENT_BYTES;

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

    fn begin(&self, domain: DigestDomain) -> Self::State;

    fn update(&self, state: &mut Self::State, bytes: &[u8]);

    fn finish(&self, state: Self::State) -> Commitment;

    fn digest(&self, domain: DigestDomain, pieces: &[&[u8]]) -> Commitment {
        let mut state = self.begin(domain);
        for piece in pieces {
            self.update(&mut state, piece);
        }
        self.finish(state)
    }
}

/// Canonical on-wire representation of an fgit-crypto digest commitment.
pub type Commitment = [u8; COMMITMENT_BYTES];

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

    fn from_wire(value: u8) -> Result<Self, FabricError> {
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
    #[allow(clippy::too_many_arguments)]
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
        cursor.expect_magic(ENVELOPE_MAGIC)?;
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

    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    pub const fn object_identity(&self) -> GitOid {
        self.object_identity
    }

    pub const fn object_kind(&self) -> ObjectKind {
        self.object_kind
    }

    pub const fn declared_length(&self) -> u64 {
        self.declared_length
    }

    pub const fn payload_commitment(&self) -> Commitment {
        self.payload_commitment
    }

    pub fn codec_namespace(&self) -> &[u8] {
        &self.codec_namespace
    }

    pub const fn logical_content_identity(&self) -> Commitment {
        self.logical_content_identity
    }

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
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn segment_digest(&self) -> Commitment {
        self.segment_digest
    }

    pub const fn merkle_root(&self) -> Commitment {
        self.merkle_root
    }

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
    pub fn new(hasher: &'a H, limits: SegmentLimits) -> Self {
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
            .digest(DigestDomain::Payload, &[record.payload.as_slice()]);
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
                .digest(DigestDomain::MerkleLeaf, &[&bytes[start..end]]);
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
            .digest(DigestDomain::Segment, &[bytes.as_slice()]);
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
        header.expect_magic(SEGMENT_MAGIC)?;
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
            if hasher.digest(DigestDomain::Payload, &[payload]) != envelope.payload_commitment() {
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
            );
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
        let computed_digest = hasher.digest(DigestDomain::Segment, &[&bytes[..digest_end]]);
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

    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub const fn merkle_root(&self) -> Commitment {
        self.merkle_root
    }

    pub const fn segment_digest(&self) -> Commitment {
        self.segment_digest
    }

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

    pub fn lookup(&self, object_identity: GitOid) -> Option<RecordView<'_>> {
        self.lookup_with_witness(object_identity).record
    }

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
            let sibling_index = if cursor % 2 == 0 {
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
        let right = if index % 2 == 0 { *sibling } else { current };
        let left = if index % 2 == 0 { current } else { *sibling };
        current = hasher.digest(DigestDomain::MerkleNode, &[&left, &right]);
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
            state: Some(hasher.begin(DigestDomain::Segment)),
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
    cursor.expect_magic(FOOTER_MAGIC)?;
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
    cursor.expect_magic(INDEX_MAGIC)?;
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
        next.push(hasher.digest(DigestDomain::MerkleNode, &[&left, &right]));
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

    fn expect_magic(&mut self, expected: &[u8; 4]) -> Result<(), FabricError> {
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

    #[derive(Debug, Clone, Copy)]
    struct FixtureDigest;

    #[derive(Debug, Clone, Copy)]
    struct FixtureState(DigestDomain);

    impl DigestAlgorithm for FixtureDigest {
        type State = FixtureState;

        fn begin(&self, domain: DigestDomain) -> Self::State {
            FixtureState(domain)
        }

        fn update(&self, _state: &mut Self::State, _bytes: &[u8]) {}

        fn finish(&self, state: Self::State) -> Commitment {
            match state.0 {
                DigestDomain::Payload => [1; COMMITMENT_BYTES],
                DigestDomain::MerkleLeaf => [2; COMMITMENT_BYTES],
                DigestDomain::MerkleNode => [3; COMMITMENT_BYTES],
                DigestDomain::Segment => [3; COMMITMENT_BYTES],
                DigestDomain::LogicalObject => [4; COMMITMENT_BYTES],
            }
        }
    }

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
        ObjectEnvelope::new(
            vec![b'n'],
            oid(identity),
            ObjectKind::Blob,
            1,
            [1; COMMITMENT_BYTES],
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

    fn segment_with(identities: &[u8]) -> Microsegment {
        let digest = FixtureDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        for identity in identities {
            builder
                .push(SegmentRecordInput {
                    envelope: envelope(*identity),
                    payload: vec![b'p'],
                })
                .expect("ordered fixture record must be valid");
        }
        builder.build().expect("fixture segment must build")
    }

    #[test]
    fn one_record_segment_matches_pinned_golden_and_round_trips() {
        let digest = FixtureDigest;
        let segment = segment_with(&[b'o']);
        let expected = decode_hex(include_str!(
            "../tests/goldens/microsegment_v1_one_record.hex"
        ));
        assert_eq!(segment.as_bytes(), expected.as_slice());
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("golden segment must be readable");
        assert_eq!(reader.len(), 1);
        assert_eq!(reader.record(0).expect("record must exist").payload, b"p");
        assert_eq!(reader.segment_digest(), segment.segment_digest());
    }

    #[test]
    fn build_read_rebuild_round_trips_canonical_segment() {
        let digest = FixtureDigest;
        let segment = segment_with(&[b'a', b'b', b'c']);
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
            segment_with(&[b'a', b'b', b'c']).as_bytes(),
            segment_with(&[b'a', b'b', b'c']).as_bytes()
        );
    }

    #[test]
    fn sorted_index_lookup_matches_linear_oracle_with_logarithmic_witness() {
        let digest = FixtureDigest;
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
        let digest = FixtureDigest;
        let segment = segment_with(&[b'a', b'b', b'c']);
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
        }
    }

    #[test]
    fn streaming_integrity_verification_accepts_arbitrary_chunk_boundaries() {
        let digest = FixtureDigest;
        let segment = segment_with(&[b'a', b'b']);
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
        let digest = FixtureDigest;
        let mut builder = MicrosegmentBuilder::new(&digest, limits());
        builder
            .push(SegmentRecordInput {
                envelope: envelope(b'b'),
                payload: vec![b'p'],
            })
            .expect("first record must be valid");
        assert_eq!(
            builder.push(SegmentRecordInput {
                envelope: envelope(b'a'),
                payload: vec![b'p'],
            }),
            Err(FabricError::NonCanonicalRecordOrder)
        );
        let mut other_namespace = envelope(b'c');
        other_namespace.namespace = vec![b'x'];
        assert_eq!(
            builder.push(SegmentRecordInput {
                envelope: other_namespace,
                payload: vec![b'p'],
            }),
            Err(FabricError::MixedNamespace)
        );
        let mut wrong_commitment = envelope(b'c');
        wrong_commitment.payload_commitment = [9; COMMITMENT_BYTES];
        assert_eq!(
            builder.push(SegmentRecordInput {
                envelope: wrong_commitment,
                payload: vec![b'p'],
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
        let digest = FixtureDigest;
        let segment = segment_with(&[b'a', b'b']);
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
        let digest = FixtureDigest;
        let segment = segment_with(&[b'a', b'b']);
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
}
