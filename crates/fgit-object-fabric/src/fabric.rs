//! Immutable fabric contracts, deterministic location manifests, and retention hooks.
//!
//! This module deliberately has no bucket-listing operation. A caller rebuilds
//! locator state only from the manifest identities named by an authenticated
//! retention root; directory contents are physical residue, never authority.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::future::Future;

use asupersync::{Cx, Outcome};
use fgit_codec::{CodecRefusal, DecodeLimits, Decoder, Encoder};
use fgit_resource::kinds::AdmissionRefusal;
use fgit_resource::{
    BudgetGrant, IdentityError, LifecycleError, ObligationLedger, OpaqueHandle, ReserveError,
    ResourceError,
};
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, GitOid, PublicationEpoch, RepositoryAuthorityHeadId,
    SchemaFamily, SchemaId, SegmentManifestId, TypeRefusal,
};

use crate::{
    Commitment, CryptoDigest, DigestAlgorithm, FabricError, MicrosegmentReader, ObjectEnvelope,
    ObjectKind,
};

const MANIFEST_MAGIC: &[u8; 4] = b"FGMF";
const MANIFEST_VERSION: u16 = 1;
const MANIFEST_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.segment-manifest"),
    1,
    0,
);

/// Bounds used before a manifest decoder allocates or copies caller-controlled data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLimits {
    pub max_namespace_bytes: usize,
    pub max_entries: u32,
    pub max_placements: u32,
}

impl Default for ManifestLimits {
    fn default() -> Self {
        Self {
            max_namespace_bytes: 256,
            max_entries: 65_536,
            max_placements: 256,
        }
    }
}

/// Typed refusal from object-fabric storage contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreRefusal {
    EmptyNamespace,
    NamespaceTooLarge,
    TooManyEntries,
    TooManyPlacements,
    NonCanonicalObjectOrder,
    DuplicateObjectIdentity,
    NonCanonicalPlacementOrder,
    DuplicatePlacement,
    NonCanonicalManifestOrder,
    NonCanonicalRetentionOrder,
    InvalidMagic,
    UnknownVersion(u16),
    Truncated,
    TrailingBytes,
    LengthOverflow,
    InvalidPlacementKind(u8),
    ManifestIdentityMismatch,
    ManifestRealityMismatch,
    NativeObjectIdentityMismatch,
    PayloadCommitmentMismatch,
    PartialRangeUnverified,
    RangeOutOfBounds,
    RetentionRevalidationFailed,
    DeletionRetained,
    NamespaceMismatch,
    ObjectAbsent,
    StoredObjectTooLarge {
        offered: u64,
        maximum: u64,
    },
    MalformedStoredObject,
    StoredObjectMismatch,
    InvalidStreamingBudget,
    StreamingBudgetExceeded {
        offered: u64,
        maximum: u64,
    },
    RuntimeCheckpointRejected,
    RuntimeSpawnUnavailable,
    RuntimeJoinConsumed,
    StorageIo {
        operation: StorageOperation,
        kind: std::io::ErrorKind,
    },
    Resource(ResourceError),
    Reserve(ReserveError),
    Settlement(LifecycleError),
    AdmissionEvidence(AdmissionRefusal),
    Codec(CodecRefusal),
    Fabric(FabricError),
    Type(TypeRefusal),
    OpaqueIdentity(IdentityError),
}

impl fmt::Display for StoreRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyNamespace => formatter.write_str("manifest namespace must not be empty"),
            Self::NamespaceTooLarge => formatter.write_str("manifest namespace exceeds its bound"),
            Self::TooManyEntries => formatter.write_str("manifest entry count exceeds its bound"),
            Self::TooManyPlacements => {
                formatter.write_str("manifest placement count exceeds its bound")
            }
            Self::NonCanonicalObjectOrder => {
                formatter.write_str("manifest objects are not in canonical identity order")
            }
            Self::DuplicateObjectIdentity => {
                formatter.write_str("manifest contains a duplicate object identity")
            }
            Self::NonCanonicalPlacementOrder => {
                formatter.write_str("manifest placements are not in canonical order")
            }
            Self::DuplicatePlacement => {
                formatter.write_str("manifest contains a duplicate placement")
            }
            Self::NonCanonicalManifestOrder => {
                formatter.write_str("authenticated manifest identities are not in canonical order")
            }
            Self::NonCanonicalRetentionOrder => {
                formatter.write_str("retention manifest identities are not in canonical order")
            }
            Self::InvalidMagic => formatter.write_str("manifest magic is invalid"),
            Self::UnknownVersion(_) => formatter.write_str("manifest version is unsupported"),
            Self::Truncated => formatter.write_str("manifest bytes are truncated"),
            Self::TrailingBytes => formatter.write_str("manifest bytes contain a trailing suffix"),
            Self::LengthOverflow => formatter.write_str("manifest length arithmetic overflowed"),
            Self::InvalidPlacementKind(_) => {
                formatter.write_str("placement backend kind is unsupported")
            }
            Self::ManifestIdentityMismatch => {
                formatter.write_str("manifest bytes do not match their typed identity")
            }
            Self::ManifestRealityMismatch => {
                formatter.write_str("manifest entry does not match the verified segment reality")
            }
            Self::NativeObjectIdentityMismatch => {
                formatter.write_str("object bytes do not match the native Git identity")
            }
            Self::PayloadCommitmentMismatch => {
                formatter.write_str("object bytes do not match the strong payload commitment")
            }
            Self::PartialRangeUnverified => {
                formatter.write_str("partial range has no authenticated sub-object commitment")
            }
            Self::RangeOutOfBounds => formatter.write_str("requested range exceeds object bounds"),
            Self::RetentionRevalidationFailed => {
                formatter.write_str("authenticated retention root did not revalidate")
            }
            Self::DeletionRetained => {
                formatter.write_str("authenticated retention registry still protects this object")
            }
            Self::NamespaceMismatch => {
                formatter.write_str("object namespace does not match the local fabric scope")
            }
            Self::ObjectAbsent => formatter.write_str("object is absent from the local fabric"),
            Self::StoredObjectTooLarge { .. } => {
                formatter.write_str("stored object exceeds the configured local bound")
            }
            Self::MalformedStoredObject => {
                formatter.write_str("stored local object body is malformed")
            }
            Self::StoredObjectMismatch => {
                formatter.write_str("stored immutable body disagrees with its exact key")
            }
            Self::InvalidStreamingBudget => formatter
                .write_str("verified stream budget must have positive byte and chunk bounds"),
            Self::StreamingBudgetExceeded { .. } => {
                formatter.write_str("verified stream exceeds its caller-owned byte budget")
            }
            Self::RuntimeCheckpointRejected => {
                formatter.write_str("runtime checkpoint rejected the object-fabric operation")
            }
            Self::RuntimeSpawnUnavailable => {
                formatter.write_str("runtime cannot own the local blocking operation")
            }
            Self::RuntimeJoinConsumed => formatter
                .write_str("runtime task result was consumed before object-fabric observation"),
            Self::StorageIo { operation, kind } => {
                write!(formatter, "local storage {operation} failed: {kind}")
            }
            Self::Resource(error) => fmt::Display::fmt(error, formatter),
            Self::Reserve(error) => fmt::Display::fmt(error, formatter),
            Self::Settlement(error) => fmt::Display::fmt(error, formatter),
            Self::AdmissionEvidence(error) => fmt::Display::fmt(error, formatter),
            Self::Codec(error) => fmt::Display::fmt(error, formatter),
            Self::Fabric(error) => fmt::Display::fmt(error, formatter),
            Self::Type(error) => fmt::Display::fmt(error, formatter),
            Self::OpaqueIdentity(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl Error for StoreRefusal {}

impl From<FabricError> for StoreRefusal {
    fn from(error: FabricError) -> Self {
        Self::Fabric(error)
    }
}

impl From<TypeRefusal> for StoreRefusal {
    fn from(error: TypeRefusal) -> Self {
        Self::Type(error)
    }
}

impl From<IdentityError> for StoreRefusal {
    fn from(error: IdentityError) -> Self {
        Self::OpaqueIdentity(error)
    }
}

impl From<ResourceError> for StoreRefusal {
    fn from(error: ResourceError) -> Self {
        Self::Resource(error)
    }
}

impl From<ReserveError> for StoreRefusal {
    fn from(error: ReserveError) -> Self {
        Self::Reserve(error)
    }
}

impl From<AdmissionRefusal> for StoreRefusal {
    fn from(error: AdmissionRefusal) -> Self {
        Self::AdmissionEvidence(error)
    }
}

/// Filesystem step that failed without producing a partial success claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageOperation {
    CreateDirectory,
    WriteStage,
    SyncStage,
    PublishImmutableBody,
    SyncDirectory,
    ReadBody,
    RemoveBody,
    PublishRetentionBody,
    PublishRetentionRoot,
}

impl fmt::Display for StorageOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::CreateDirectory => "directory creation",
            Self::WriteStage => "staged body write",
            Self::SyncStage => "staged body sync",
            Self::PublishImmutableBody => "immutable body publication",
            Self::SyncDirectory => "directory sync",
            Self::ReadBody => "body read",
            Self::RemoveBody => "body removal",
            Self::PublishRetentionBody => "retention body publication",
            Self::PublishRetentionRoot => "retention root publication",
        };
        formatter.write_str(name)
    }
}

fn codec_refusal(error: CodecRefusal) -> StoreRefusal {
    match error {
        CodecRefusal::InputTruncated { .. } => StoreRefusal::Truncated,
        CodecRefusal::Type(error) => StoreRefusal::Type(error),
        error => StoreRefusal::Codec(error),
    }
}

/// One supported physical placement backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PlacementBackend {
    LocalFilesystem = 1,
}

impl PlacementBackend {
    const fn to_wire(self) -> u8 {
        self as u8
    }

    const fn from_wire(value: u8) -> Result<Self, StoreRefusal> {
        match value {
            1 => Ok(Self::LocalFilesystem),
            _ => Err(StoreRefusal::InvalidPlacementKind(value)),
        }
    }
}

/// Immutable evidence for one verified object or segment placement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlacementReceipt {
    backend: PlacementBackend,
    locator: OpaqueHandle,
    failure_domain: OpaqueHandle,
    encryption_dependency: OpaqueHandle,
}

impl PlacementReceipt {
    /// Builds a placement receipt from bounded opaque handles.
    #[must_use]
    pub const fn new(
        backend: PlacementBackend,
        locator: OpaqueHandle,
        failure_domain: OpaqueHandle,
        encryption_dependency: OpaqueHandle,
    ) -> Self {
        Self {
            backend,
            locator,
            failure_domain,
            encryption_dependency,
        }
    }

    #[must_use]
    pub const fn backend(&self) -> PlacementBackend {
        self.backend
    }

    #[must_use]
    pub const fn locator(&self) -> OpaqueHandle {
        self.locator
    }

    #[must_use]
    pub const fn failure_domain(&self) -> OpaqueHandle {
        self.failure_domain
    }

    #[must_use]
    pub const fn encryption_dependency(&self) -> OpaqueHandle {
        self.encryption_dependency
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, StoreRefusal> {
        let mut bytes = Encoder::with_capacity(
            4 + self.locator.len() + self.failure_domain.len() + self.encryption_dependency.len(),
        );
        bytes.write_raw_byte(self.backend.to_wire());
        push_handle(&mut bytes, self.locator)?;
        push_handle(&mut bytes, self.failure_domain)?;
        push_handle(&mut bytes, self.encryption_dependency)?;
        Ok(bytes.into_bytes())
    }
}

/// One object record named by an authenticated segment manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    object_identity: GitOid,
    record_offset: u64,
    record_length: u32,
    object_kind: ObjectKind,
    payload_length: u64,
    payload_commitment: Commitment,
}

impl ManifestEntry {
    #[must_use]
    pub const fn object_identity(&self) -> GitOid {
        self.object_identity
    }

    #[must_use]
    pub const fn record_offset(&self) -> u64 {
        self.record_offset
    }

    #[must_use]
    pub const fn record_length(&self) -> u32 {
        self.record_length
    }

    #[must_use]
    pub const fn object_kind(&self) -> ObjectKind {
        self.object_kind
    }

    #[must_use]
    pub const fn payload_length(&self) -> u64 {
        self.payload_length
    }

    #[must_use]
    pub const fn payload_commitment(&self) -> Commitment {
        self.payload_commitment
    }
}

/// Deterministic immutable segment metadata and its verified placements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentManifest {
    namespace: Vec<u8>,
    segment_digest: Commitment,
    entries: Vec<ManifestEntry>,
    placements: Vec<PlacementReceipt>,
}

impl SegmentManifest {
    /// Builds a manifest only when its identity-bearing collections are already canonical.
    pub fn new(
        namespace: Vec<u8>,
        segment_digest: Commitment,
        entries: Vec<ManifestEntry>,
        placements: Vec<PlacementReceipt>,
        limits: &ManifestLimits,
    ) -> Result<Self, StoreRefusal> {
        validate_manifest_parts(&namespace, &entries, &placements, limits)?;
        Ok(Self {
            namespace,
            segment_digest,
            entries,
            placements,
        })
    }

    /// Extracts an independently checkable manifest from a verified segment reader.
    pub fn from_verified_segment<H: DigestAlgorithm>(
        reader: &MicrosegmentReader<'_, H>,
        placements: Vec<PlacementReceipt>,
        limits: &ManifestLimits,
    ) -> Result<Self, StoreRefusal> {
        let mut entries = Vec::with_capacity(reader.len());
        for index in 0..reader.len() {
            let record = reader
                .record(index)
                .ok_or(StoreRefusal::ManifestRealityMismatch)?;
            entries.push(entry_from_record(record)?);
        }
        Self::new(
            reader.namespace().to_vec(),
            reader.segment_digest(),
            entries,
            placements,
            limits,
        )
    }

    /// Rechecks every manifest entry against the independently verified segment reader.
    pub fn verify_segment_reality<H: DigestAlgorithm>(
        &self,
        reader: &MicrosegmentReader<'_, H>,
    ) -> Result<(), StoreRefusal> {
        if self.namespace != reader.namespace() || self.segment_digest != reader.segment_digest() {
            return Err(StoreRefusal::ManifestRealityMismatch);
        }
        if self.entries.len() != reader.len() {
            return Err(StoreRefusal::ManifestRealityMismatch);
        }
        for (index, expected) in self.entries.iter().enumerate() {
            let actual = reader
                .record(index)
                .ok_or(StoreRefusal::ManifestRealityMismatch)?;
            if *expected != entry_from_record(actual)? {
                return Err(StoreRefusal::ManifestRealityMismatch);
            }
        }
        Ok(())
    }

    /// Canonical body bytes, excluding transport framing and the typed identity.
    pub fn encode(&self) -> Result<Vec<u8>, StoreRefusal> {
        let mut bytes = Encoder::new();
        bytes.write_raw(MANIFEST_MAGIC);
        push_u16(&mut bytes, MANIFEST_VERSION);
        push_u16(
            &mut bytes,
            u16::try_from(self.namespace.len()).map_err(|_| StoreRefusal::NamespaceTooLarge)?,
        );
        bytes.write_raw(&self.namespace);
        bytes.write_raw(&self.segment_digest);
        push_u32(
            &mut bytes,
            u32::try_from(self.entries.len()).map_err(|_| StoreRefusal::TooManyEntries)?,
        );
        for entry in &self.entries {
            push_git_oid(&mut bytes, entry.object_identity);
            push_u64(&mut bytes, entry.record_offset);
            push_u32(&mut bytes, entry.record_length);
            bytes.write_raw_byte(entry.object_kind.to_wire());
            push_u64(&mut bytes, entry.payload_length);
            bytes.write_raw(&entry.payload_commitment);
        }
        push_u32(
            &mut bytes,
            u32::try_from(self.placements.len()).map_err(|_| StoreRefusal::TooManyPlacements)?,
        );
        for placement in &self.placements {
            bytes.write_raw(&placement.canonical_bytes()?);
        }
        Ok(bytes.into_bytes())
    }

    /// Decodes a bounded manifest and rechecks every canonical ordering rule.
    pub fn decode(bytes: &[u8], limits: &ManifestLimits) -> Result<Self, StoreRefusal> {
        let mut cursor = ManifestCursor::new(bytes);
        cursor.expect_magic(*MANIFEST_MAGIC)?;
        let version = cursor.read_u16()?;
        if version != MANIFEST_VERSION {
            return Err(StoreRefusal::UnknownVersion(version));
        }
        let namespace_len = usize::from(cursor.read_u16()?);
        if namespace_len == 0 {
            return Err(StoreRefusal::EmptyNamespace);
        }
        if namespace_len > limits.max_namespace_bytes {
            return Err(StoreRefusal::NamespaceTooLarge);
        }
        let namespace = cursor.take(namespace_len)?.to_vec();
        let segment_digest = cursor.read_commitment()?;
        let entry_count =
            usize::try_from(cursor.read_u32()?).map_err(|_| StoreRefusal::TooManyEntries)?;
        if entry_count
            > usize::try_from(limits.max_entries).map_err(|_| StoreRefusal::TooManyEntries)?
        {
            return Err(StoreRefusal::TooManyEntries);
        }
        if entry_count > cursor.remaining() {
            return Err(StoreRefusal::TooManyEntries);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(ManifestEntry {
                object_identity: cursor.read_git_oid()?,
                record_offset: cursor.read_u64()?,
                record_length: cursor.read_u32()?,
                object_kind: ObjectKind::from_wire(cursor.read_u8()?)?,
                payload_length: cursor.read_u64()?,
                payload_commitment: cursor.read_commitment()?,
            });
        }
        let placement_count =
            usize::try_from(cursor.read_u32()?).map_err(|_| StoreRefusal::TooManyPlacements)?;
        if placement_count
            > usize::try_from(limits.max_placements).map_err(|_| StoreRefusal::TooManyPlacements)?
        {
            return Err(StoreRefusal::TooManyPlacements);
        }
        if placement_count > cursor.remaining() {
            return Err(StoreRefusal::TooManyPlacements);
        }
        let mut placements = Vec::with_capacity(placement_count);
        for _ in 0..placement_count {
            placements.push(PlacementReceipt::new(
                PlacementBackend::from_wire(cursor.read_u8()?)?,
                cursor.read_handle()?,
                cursor.read_handle()?,
                cursor.read_handle()?,
            ));
        }
        if !cursor.is_finished() {
            return Err(StoreRefusal::TrailingBytes);
        }
        Self::new(namespace, segment_digest, entries, placements, limits)
    }

    /// Computes the `fgit-types` manifest identity under the frozen crypto registry.
    pub fn identity(&self) -> Result<SegmentManifestId, StoreRefusal> {
        let bytes = self.encode()?;
        let identity = fgit_crypto::internal_object_id(
            fgit_crypto::IdentityDomain::SegmentManifest,
            MANIFEST_SCHEMA,
            CANONICAL_CODEC_VERSION,
            &bytes,
        );
        SegmentManifestId::from_internal_object_id(identity).map_err(StoreRefusal::from)
    }

    /// Decodes bytes only if they reproduce the caller-supplied typed identity.
    pub fn decode_verified(
        bytes: &[u8],
        expected_identity: SegmentManifestId,
        limits: &ManifestLimits,
    ) -> Result<Self, StoreRefusal> {
        let manifest = Self::decode(bytes, limits)?;
        if manifest.identity()? != expected_identity {
            return Err(StoreRefusal::ManifestIdentityMismatch);
        }
        Ok(manifest)
    }

    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        &self.namespace
    }

    #[must_use]
    pub const fn segment_digest(&self) -> Commitment {
        self.segment_digest
    }

    #[must_use]
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    #[must_use]
    pub fn placements(&self) -> &[PlacementReceipt] {
        &self.placements
    }
}

fn entry_from_record(record: crate::RecordView<'_>) -> Result<ManifestEntry, StoreRefusal> {
    Ok(ManifestEntry {
        object_identity: record.envelope.object_identity(),
        record_offset: u64::try_from(record.offset).map_err(|_| StoreRefusal::LengthOverflow)?,
        record_length: u32::try_from(record.total_len).map_err(|_| StoreRefusal::LengthOverflow)?,
        object_kind: record.envelope.object_kind(),
        payload_length: record.envelope.declared_length(),
        payload_commitment: record.envelope.payload_commitment(),
    })
}

fn validate_manifest_parts(
    namespace: &[u8],
    entries: &[ManifestEntry],
    placements: &[PlacementReceipt],
    limits: &ManifestLimits,
) -> Result<(), StoreRefusal> {
    if namespace.is_empty() {
        return Err(StoreRefusal::EmptyNamespace);
    }
    if namespace.len() > limits.max_namespace_bytes || namespace.len() > usize::from(u16::MAX) {
        return Err(StoreRefusal::NamespaceTooLarge);
    }
    if entries.len()
        > usize::try_from(limits.max_entries).map_err(|_| StoreRefusal::TooManyEntries)?
    {
        return Err(StoreRefusal::TooManyEntries);
    }
    if placements.len()
        > usize::try_from(limits.max_placements).map_err(|_| StoreRefusal::TooManyPlacements)?
    {
        return Err(StoreRefusal::TooManyPlacements);
    }
    for pair in entries.windows(2) {
        match pair[0].object_identity.cmp(&pair[1].object_identity) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(StoreRefusal::DuplicateObjectIdentity),
            std::cmp::Ordering::Greater => return Err(StoreRefusal::NonCanonicalObjectOrder),
        }
    }
    for pair in placements.windows(2) {
        match pair[0].canonical_bytes()?.cmp(&pair[1].canonical_bytes()?) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(StoreRefusal::DuplicatePlacement),
            std::cmp::Ordering::Greater => return Err(StoreRefusal::NonCanonicalPlacementOrder),
        }
    }
    Ok(())
}

/// Caller-supplied budget custody for one placement operation.
///
/// The local backend consumes this value to reserve an
/// `fgit-resource::ObjectAdmissionPermit`; a write cannot silently escape the
/// caller's region or resource accounting.
#[must_use]
pub struct PlacementAdmission<'a> {
    ledger: &'a ObligationLedger,
    budget: BudgetGrant,
}

impl<'a> PlacementAdmission<'a> {
    pub const fn new(ledger: &'a ObligationLedger, budget: BudgetGrant) -> Self {
        Self { ledger, budget }
    }

    #[must_use]
    pub const fn ledger(&self) -> &ObligationLedger {
        self.ledger
    }

    /// Consumes this custody token so the backend can reserve and settle the
    /// concrete `ObjectAdmissionPermit` around a physical placement write.
    pub fn into_parts(self) -> (&'a ObligationLedger, BudgetGrant) {
        (self.ledger, self.budget)
    }
}

/// Exact object bytes that have been checked against their immutable envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObject {
    envelope: ObjectEnvelope,
    payload: Vec<u8>,
}

impl VerifiedObject {
    /// Verifies native Git identity, exact length, and the strong payload commitment.
    pub fn new(envelope: ObjectEnvelope, payload: Vec<u8>) -> Result<Self, StoreRefusal> {
        let declared_len =
            u64::try_from(payload.len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        if envelope.declared_length() != declared_len {
            return Err(StoreRefusal::PayloadCommitmentMismatch);
        }
        let digest = CryptoDigest;
        if digest.payload_commitment(envelope.object_kind(), &payload)?
            != envelope.payload_commitment()
        {
            return Err(StoreRefusal::PayloadCommitmentMismatch);
        }
        let object_kind = match envelope.object_kind() {
            ObjectKind::Commit => fgit_crypto::GitObjectKind::Commit,
            ObjectKind::Tree => fgit_crypto::GitObjectKind::Tree,
            ObjectKind::Blob => fgit_crypto::GitObjectKind::Blob,
            ObjectKind::Tag => fgit_crypto::GitObjectKind::Tag,
            ObjectKind::Internal => return Err(StoreRefusal::NativeObjectIdentityMismatch),
        };
        let native = fgit_crypto::git_object_id(
            envelope.object_identity().algorithm(),
            object_kind,
            &payload,
        );
        if native != envelope.object_identity() {
            return Err(StoreRefusal::NativeObjectIdentityMismatch);
        }
        Ok(Self { envelope, payload })
    }

    #[must_use]
    pub const fn identity(&self) -> GitOid {
        self.envelope.object_identity()
    }

    #[must_use]
    pub const fn envelope(&self) -> &ObjectEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A request for a subset of a verified object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectRange {
    offset: u64,
    length: u64,
}

impl ObjectRange {
    pub fn new(offset: u64, length: u64, object_length: u64) -> Result<Self, StoreRefusal> {
        let end = offset
            .checked_add(length)
            .ok_or(StoreRefusal::RangeOutOfBounds)?;
        if end > object_length {
            return Err(StoreRefusal::RangeOutOfBounds);
        }
        Ok(Self { offset, length })
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    #[must_use]
    pub const fn length(&self) -> u64 {
        self.length
    }
}

/// A fully verified exact object read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholeObjectRead {
    pub object: VerifiedObject,
    pub placement: PlacementReceipt,
}

/// Caller-owned bounds for one verified object stream.
///
/// The local V1 backend verifies the complete immutable body before it emits
/// its first chunk. This deliberately favors the no-unverified-range rule;
/// later backends may verify committed sub-object chunks without changing this
/// stream contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedStreamBudget {
    maximum_bytes: u64,
    chunk_bytes: usize,
}

impl VerifiedStreamBudget {
    /// Builds a finite stream budget.
    pub fn new(maximum_bytes: u64, chunk_bytes: usize) -> Result<Self, StoreRefusal> {
        if maximum_bytes == 0 || chunk_bytes == 0 {
            return Err(StoreRefusal::InvalidStreamingBudget);
        }
        Ok(Self {
            maximum_bytes,
            chunk_bytes,
        })
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> u64 {
        self.maximum_bytes
    }

    #[must_use]
    pub const fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }
}

/// One immutable, already-authenticated payload chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStreamChunk<'a> {
    pub object_identity: GitOid,
    pub offset: u64,
    pub bytes: &'a [u8],
    pub placement: PlacementReceipt,
}

/// A bounded emission cursor over one fully verified immutable object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedObjectStream {
    whole: WholeObjectRead,
    cursor: usize,
    chunk_bytes: usize,
}

impl VerifiedObjectStream {
    /// Begins chunked emission only after exact-body verification has completed.
    pub fn new(whole: WholeObjectRead, budget: VerifiedStreamBudget) -> Result<Self, StoreRefusal> {
        let offered = u64::try_from(whole.object.payload().len())
            .map_err(|_| StoreRefusal::LengthOverflow)?;
        if offered > budget.maximum_bytes() {
            return Err(StoreRefusal::StreamingBudgetExceeded {
                offered,
                maximum: budget.maximum_bytes(),
            });
        }
        Ok(Self {
            whole,
            cursor: 0,
            chunk_bytes: budget.chunk_bytes(),
        })
    }

    /// Emits at most one bounded authenticated chunk, observing cancellation
    /// before every externally visible emission.
    pub fn next_chunk<'a, Caps>(
        &'a mut self,
        cx: &Cx<Caps>,
    ) -> Outcome<Option<VerifiedStreamChunk<'a>>, StoreRefusal> {
        if let Some(outcome) = checkpoint_outcome(cx) {
            return outcome;
        }
        let payload = self.whole.object.payload();
        if self.cursor == payload.len() {
            return Outcome::Ok(None);
        }
        let end = self
            .cursor
            .saturating_add(self.chunk_bytes)
            .min(payload.len());
        let offset = match u64::try_from(self.cursor) {
            Ok(offset) => offset,
            Err(_) => return Outcome::Err(StoreRefusal::LengthOverflow),
        };
        let chunk = VerifiedStreamChunk {
            object_identity: self.whole.object.identity(),
            offset,
            bytes: &payload[self.cursor..end],
            placement: self.whole.placement.clone(),
        };
        self.cursor = end;
        Outcome::Ok(Some(chunk))
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.cursor == self.whole.object.payload().len()
    }
}

/// A verified range response. A backend must refuse instead of returning bytes
/// when it cannot authenticate the requested sub-object range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRangeRead {
    pub object_identity: GitOid,
    pub range: ObjectRange,
    pub bytes: Vec<u8>,
    pub placement: PlacementReceipt,
}

/// The observable outcome of immutable conditional creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutIfAbsent {
    Created {
        placement: PlacementReceipt,
        epochs: PublicationState,
    },
    AlreadyPresent {
        placement: PlacementReceipt,
        epochs: PublicationState,
    },
}

/// A non-conflating report of object existence, canonical visibility, and durability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicationState {
    staged: bool,
    visible: bool,
    durable: bool,
}

impl PublicationState {
    #[must_use]
    pub const fn new(staged: bool, visible: bool, durable: bool) -> Self {
        Self {
            staged,
            visible,
            durable,
        }
    }

    #[must_use]
    pub const fn contains(&self, epoch: PublicationEpoch) -> bool {
        match epoch {
            PublicationEpoch::Staged => self.staged,
            PublicationEpoch::Visible => self.visible,
            PublicationEpoch::Durable => self.durable,
        }
    }
}

/// Idempotent conditional-deletion evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionReceipt {
    Deleted,
    AlreadyAbsent,
}

/// One capability an immutable storage backend may expose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricCapability {
    ConditionalPutIfAbsent,
    VerifiedWholeReads,
    AuthenticatedPartialRanges,
    ConditionalDeletion,
}

/// Capability report used by callers to choose an explicit profile.
///
/// Listing is intentionally absent: physical listings are never authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FabricCapabilities {
    supported: &'static [FabricCapability],
}

impl FabricCapabilities {
    /// Builds a capability report from its exact supported operation set.
    #[must_use]
    pub const fn new(supported: &'static [FabricCapability]) -> Self {
        Self { supported }
    }

    /// Reports whether this backend provides one explicitly named capability.
    #[must_use]
    pub fn supports(&self, capability: FabricCapability) -> bool {
        self.supported.contains(&capability)
    }
}

/// An authority-owned verifier for retention roots and deletion eligibility.
///
/// Implementations authenticate and revalidate against the current authority
/// head. The local backend stores only the result; it never decides which
/// objects are retained from filesystem state or a locator cache.
pub trait AuthenticatedRetentionRegistry {
    fn revalidate_root(&self, proposal: &RetentionRootProposal) -> Result<(), StoreRefusal>;

    fn permits_placement_deletion(&self, object: GitOid) -> Result<(), StoreRefusal>;
}

/// A candidate retention-root update supplied by decision publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionRootProposal {
    authority_head: RepositoryAuthorityHeadId,
    retention_root: Digest,
    manifests: Vec<SegmentManifestId>,
}

impl RetentionRootProposal {
    pub fn new(
        authority_head: RepositoryAuthorityHeadId,
        retention_root: Digest,
        manifests: Vec<SegmentManifestId>,
    ) -> Result<Self, StoreRefusal> {
        for pair in manifests.windows(2) {
            if pair[0] >= pair[1] {
                return Err(StoreRefusal::NonCanonicalRetentionOrder);
            }
        }
        Ok(Self {
            authority_head,
            retention_root,
            manifests,
        })
    }

    #[must_use]
    pub const fn authority_head(&self) -> RepositoryAuthorityHeadId {
        self.authority_head
    }

    #[must_use]
    pub const fn retention_root(&self) -> Digest {
        self.retention_root
    }

    #[must_use]
    pub fn manifests(&self) -> &[SegmentManifestId] {
        &self.manifests
    }

    /// Stable local-root body bytes. These bytes are storage evidence only;
    /// authority is still supplied by the registry that revalidated this value.
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>, StoreRefusal> {
        let mut bytes = Encoder::new();
        bytes.write_raw(b"FGRT");
        push_u16(&mut bytes, 1);
        push_internal_object_id(&mut bytes, self.authority_head.as_internal_object_id())?;
        push_u16(&mut bytes, self.retention_root.algorithm().code_point());
        let root_bytes = self.retention_root.bytes().as_bytes();
        bytes.write_raw_byte(
            u8::try_from(root_bytes.len()).map_err(|_| StoreRefusal::LengthOverflow)?,
        );
        bytes.write_raw(root_bytes);
        push_u32(
            &mut bytes,
            u32::try_from(self.manifests.len()).map_err(|_| StoreRefusal::TooManyEntries)?,
        );
        for manifest in &self.manifests {
            push_internal_object_id(&mut bytes, manifest.as_internal_object_id())?;
        }
        Ok(bytes.into_bytes())
    }
}

/// Final storage interface; it intentionally has no list operation.
pub trait ImmutableObjectFabric {
    fn capabilities(&self) -> FabricCapabilities;

    fn put_if_absent(
        &self,
        object: VerifiedObject,
        admission: PlacementAdmission<'_>,
    ) -> Result<PutIfAbsent, StoreRefusal>;

    fn read_whole(&self, identity: GitOid) -> Result<WholeObjectRead, StoreRefusal>;

    fn read_range_verified(
        &self,
        identity: GitOid,
        range: ObjectRange,
    ) -> Result<VerifiedRangeRead, StoreRefusal>;

    fn write_manifest(&self, manifest: &SegmentManifest)
    -> Result<SegmentManifestId, StoreRefusal>;

    fn read_manifest(&self, identity: SegmentManifestId) -> Result<SegmentManifest, StoreRefusal>;

    fn publish_retention_root<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        proposal: &RetentionRootProposal,
    ) -> Result<PublicationState, StoreRefusal>;

    fn delete_if_unretained<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        identity: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal>;
}

/// Runtime-owned object-fabric operations.
///
/// The synchronous trait remains the exact storage algebra. This companion
/// trait is the request-path boundary: every effectful implementation accepts
/// a runtime-owned [`Cx`] first and preserves all four Asupersync outcome arms
/// instead of collapsing cancellation or containment into `StoreRefusal`.
pub trait RuntimeImmutableObjectFabric: ImmutableObjectFabric {
    /// Reads, verifies, and opens a bounded object stream through one owned
    /// runtime operation.
    fn open_verified_stream<'a>(
        &'a self,
        cx: &'a Cx,
        identity: GitOid,
        budget: VerifiedStreamBudget,
    ) -> impl Future<Output = Outcome<VerifiedObjectStream, StoreRefusal>> + 'a;
}

pub(crate) fn checkpoint_outcome<T, Caps>(cx: &Cx<Caps>) -> Option<Outcome<T, StoreRefusal>> {
    if cx.checkpoint().is_ok() {
        return None;
    }
    match cx.cancel_reason() {
        Some(reason) => Some(Outcome::Cancelled(reason)),
        None => Some(Outcome::Err(StoreRefusal::RuntimeCheckpointRejected)),
    }
}

/// A deliberately rebuildable, non-authoritative OID-to-manifest accelerator.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LocatorCache {
    locations: BTreeMap<GitOid, Vec<ManifestLocation>>,
}

/// One location discovered by reading an authenticated manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ManifestLocation {
    pub manifest: SegmentManifestId,
    pub entry_index: usize,
}

impl LocatorCache {
    /// Discards only the derived accelerator. It has no effect on canonical retention.
    pub fn wipe(&mut self) {
        self.locations.clear();
    }

    /// Rebuilds solely from the canonical manifest identities supplied by a root reader.
    pub fn rebuild_from_manifests(
        &mut self,
        manifests: &[SegmentManifest],
    ) -> Result<(), StoreRefusal> {
        self.wipe();
        let mut previous = None;
        for manifest in manifests {
            let identity = manifest.identity()?;
            if previous.is_some_and(|prior| prior >= identity) {
                return Err(StoreRefusal::NonCanonicalManifestOrder);
            }
            previous = Some(identity);
            for (entry_index, entry) in manifest.entries().iter().enumerate() {
                self.locations
                    .entry(entry.object_identity())
                    .or_default()
                    .push(ManifestLocation {
                        manifest: identity,
                        entry_index,
                    });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn locate(&self, object: GitOid) -> &[ManifestLocation] {
        self.locations
            .get(&object)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

fn push_u16(output: &mut Encoder, value: u16) {
    output.write_scalar(value);
}

fn push_u32(output: &mut Encoder, value: u32) {
    output.write_scalar(value);
}

fn push_u64(output: &mut Encoder, value: u64) {
    output.write_scalar(value);
}

fn push_git_oid(output: &mut Encoder, identity: GitOid) {
    output.write_git_oid(&identity);
}

fn push_internal_object_id(
    output: &mut Encoder,
    identity: &fgit_types::InternalObjectId,
) -> Result<(), StoreRefusal> {
    push_u16(output, identity.algorithm().code_point());
    let domain_tag = identity.domain();
    let domain = domain_tag.as_bytes();
    output.write_raw_byte(u8::try_from(domain.len()).map_err(|_| StoreRefusal::LengthOverflow)?);
    output.write_raw(domain);
    push_u16(output, identity.codec_version().major());
    push_u16(output, identity.codec_version().minor());
    let digest = identity.digest().as_bytes();
    output.write_raw_byte(u8::try_from(digest.len()).map_err(|_| StoreRefusal::LengthOverflow)?);
    output.write_raw(digest);
    Ok(())
}

fn push_handle(output: &mut Encoder, handle: OpaqueHandle) -> Result<(), StoreRefusal> {
    output.write_raw_byte(u8::try_from(handle.len()).map_err(|_| StoreRefusal::LengthOverflow)?);
    output.write_raw(handle.as_bytes());
    Ok(())
}

struct ManifestCursor<'a> {
    decoder: Decoder<'a>,
}

impl<'a> ManifestCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            decoder: Decoder::new(bytes, DecodeLimits::default()),
        }
    }

    fn expect_magic(&mut self, expected: [u8; 4]) -> Result<(), StoreRefusal> {
        if self.take(4)? != expected {
            return Err(StoreRefusal::InvalidMagic);
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreRefusal> {
        self.decoder
            .take("segment manifest", length)
            .map_err(codec_refusal)
    }

    fn read_u8(&mut self) -> Result<u8, StoreRefusal> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, StoreRefusal> {
        self.decoder
            .read_scalar("segment manifest u16")
            .map_err(codec_refusal)
    }

    fn read_u32(&mut self) -> Result<u32, StoreRefusal> {
        self.decoder
            .read_scalar("segment manifest u32")
            .map_err(codec_refusal)
    }

    fn read_u64(&mut self) -> Result<u64, StoreRefusal> {
        self.decoder
            .read_scalar("segment manifest u64")
            .map_err(codec_refusal)
    }

    fn read_commitment(&mut self) -> Result<Commitment, StoreRefusal> {
        let mut commitment = [0; 32];
        commitment.copy_from_slice(self.take(32)?);
        Ok(commitment)
    }

    fn read_git_oid(&mut self) -> Result<GitOid, StoreRefusal> {
        self.decoder.read_git_oid().map_err(codec_refusal)
    }

    fn read_handle(&mut self) -> Result<OpaqueHandle, StoreRefusal> {
        let length = usize::from(self.read_u8()?);
        OpaqueHandle::new(self.take(length)?).map_err(StoreRefusal::from)
    }

    const fn remaining(&self) -> usize {
        self.decoder.remaining()
    }

    const fn is_finished(&self) -> bool {
        self.remaining() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{DigestAlgorithmId, DigestBytes, GitOidSha1};

    use crate::{MicrosegmentBuilder, SegmentLimits, SegmentRecordInput, verify_merkle_proof};

    fn manifest_limits() -> ManifestLimits {
        ManifestLimits {
            max_namespace_bytes: 16,
            max_entries: 8,
            max_placements: 8,
        }
    }

    fn placement() -> PlacementReceipt {
        PlacementReceipt::new(
            PlacementBackend::LocalFilesystem,
            OpaqueHandle::new(b"local-a").expect("fixture locator must fit"),
            OpaqueHandle::new(b"rack-a").expect("fixture failure domain must fit"),
            OpaqueHandle::new(b"key-a").expect("fixture key dependency must fit"),
        )
    }

    fn oid(value: u8) -> GitOid {
        GitOid::Sha1(GitOidSha1::from_bytes([value; GitOidSha1::LEN]))
    }

    fn manifest_entry(value: u8) -> ManifestEntry {
        ManifestEntry {
            object_identity: oid(value),
            record_offset: u64::from(value),
            record_length: 17,
            object_kind: ObjectKind::Blob,
            payload_length: 1,
            payload_commitment: [value; 32],
        }
    }

    fn digest(value: u8) -> Digest {
        Digest::new(
            DigestAlgorithmId::try_new(1).expect("fixture algorithm must be valid"),
            DigestBytes::try_new(&[value; 32]).expect("fixture digest must fit"),
        )
    }

    fn manifest() -> SegmentManifest {
        SegmentManifest::new(
            vec![b'n'],
            [9; 32],
            vec![manifest_entry(b'a'), manifest_entry(b'b')],
            vec![placement()],
            &manifest_limits(),
        )
        .expect("fixture manifest must be canonical")
    }

    #[test]
    fn deterministic_manifest_round_trip_reproduces_typed_identity() {
        let manifest = manifest();
        let bytes = manifest.encode().expect("manifest must encode");
        let identity = manifest.identity().expect("manifest must have an identity");
        assert_eq!(
            SegmentManifest::decode_verified(&bytes, identity, &manifest_limits()),
            Ok(manifest)
        );
    }

    #[test]
    fn manifest_refuses_unordered_entries_and_placements() {
        assert_eq!(
            SegmentManifest::new(
                vec![b'n'],
                [9; 32],
                vec![manifest_entry(b'b'), manifest_entry(b'a')],
                vec![placement()],
                &manifest_limits(),
            ),
            Err(StoreRefusal::NonCanonicalObjectOrder)
        );
        let earlier = PlacementReceipt::new(
            PlacementBackend::LocalFilesystem,
            OpaqueHandle::new(b"a").expect("fixture locator must fit"),
            OpaqueHandle::new(b"rack-a").expect("fixture failure domain must fit"),
            OpaqueHandle::new(b"key-a").expect("fixture key dependency must fit"),
        );
        let later = PlacementReceipt::new(
            PlacementBackend::LocalFilesystem,
            OpaqueHandle::new(b"z").expect("fixture locator must fit"),
            OpaqueHandle::new(b"rack-a").expect("fixture failure domain must fit"),
            OpaqueHandle::new(b"key-a").expect("fixture key dependency must fit"),
        );
        assert_eq!(
            SegmentManifest::new(
                vec![b'n'],
                [9; 32],
                vec![manifest_entry(b'a')],
                vec![later, earlier],
                &manifest_limits(),
            ),
            Err(StoreRefusal::NonCanonicalPlacementOrder)
        );
    }

    #[test]
    fn locator_wipe_and_rebuild_from_manifests_restores_locations() {
        let manifest = manifest();
        let mut cache = LocatorCache::default();
        cache
            .rebuild_from_manifests(std::slice::from_ref(&manifest))
            .expect("canonical manifest list must rebuild the locator");
        let expected = cache.locate(oid(b'a')).to_vec();
        assert_eq!(expected.len(), 1);
        cache.wipe();
        assert_eq!(cache.locate(oid(b'a')), []);
        cache
            .rebuild_from_manifests(std::slice::from_ref(&manifest))
            .expect("the same manifest must rebuild the wiped locator");
        assert_eq!(cache.locate(oid(b'a')), expected.as_slice());
    }

    #[test]
    fn manifest_reality_divergence_is_detected_not_trusted() {
        let digest = CryptoDigest;
        let limits = SegmentLimits::default();
        let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());
        for value in *b"ab" {
            let payload = [value];
            let commitment = digest
                .payload_commitment(ObjectKind::Blob, &payload)
                .expect("native payload must commit");
            let native = fgit_crypto::git_object_id(
                fgit_types::GitHashAlgorithm::Sha1,
                fgit_crypto::GitObjectKind::Blob,
                &payload,
            );
            let envelope = ObjectEnvelope::new(
                vec![b'n'],
                native,
                ObjectKind::Blob,
                1,
                commitment,
                vec![b'c'],
                [4; 32],
                None,
                &limits,
            )
            .expect("fixture envelope must be valid");
            builder
                .push(SegmentRecordInput {
                    envelope,
                    payload: payload.to_vec(),
                })
                .expect("fixture record must be valid");
        }
        let segment = builder.build().expect("fixture segment must build");
        let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits)
            .expect("fixture segment must verify");
        let mut manifest =
            SegmentManifest::from_verified_segment(&reader, vec![placement()], &manifest_limits())
                .expect("verified segment must produce a manifest");
        manifest
            .verify_segment_reality(&reader)
            .expect("matching manifest must verify against segment reality");
        for index in 0..reader.len() {
            let proof = reader
                .merkle_proof(index, &digest)
                .expect("verified crypto reader must produce each proof");
            assert!(verify_merkle_proof(
                &digest,
                reader.records[index].leaf,
                &proof,
                reader.merkle_root(),
            ));
        }
        manifest.entries[0].record_length += 1;
        assert_eq!(
            manifest.verify_segment_reality(&reader),
            Err(StoreRefusal::ManifestRealityMismatch)
        );
    }

    #[derive(Debug)]
    struct FixtureRegistry {
        expected_root: Digest,
        allow_delete: bool,
    }

    impl AuthenticatedRetentionRegistry for FixtureRegistry {
        fn revalidate_root(&self, proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
            if proposal.retention_root() == self.expected_root {
                Ok(())
            } else {
                Err(StoreRefusal::RetentionRevalidationFailed)
            }
        }

        fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
            if self.allow_delete {
                Ok(())
            } else {
                Err(StoreRefusal::DeletionRetained)
            }
        }
    }

    #[test]
    fn retention_root_requires_revalidation_before_maintenance() {
        let manifest = manifest();
        let proposal = RetentionRootProposal::new(
            RepositoryAuthorityHeadId::from_digest(
                DigestAlgorithmId::try_new(1).expect("fixture algorithm must be valid"),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[3; 32]).expect("fixture digest must fit"),
            ),
            digest(4),
            vec![manifest.identity().expect("fixture manifest must identify")],
        )
        .expect("fixture proposal must be canonical");
        let current = FixtureRegistry {
            expected_root: digest(4),
            allow_delete: false,
        };
        assert_eq!(current.revalidate_root(&proposal), Ok(()));
        assert_eq!(
            current.permits_placement_deletion(oid(b'a')),
            Err(StoreRefusal::DeletionRetained)
        );
        let stale = FixtureRegistry {
            expected_root: digest(5),
            allow_delete: true,
        };
        assert_eq!(
            stale.revalidate_root(&proposal),
            Err(StoreRefusal::RetentionRevalidationFailed)
        );
    }
}
