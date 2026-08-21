//! Safe local-directory implementation of the immutable object-fabric traits.
//!
//! Object bodies are written to a unique staging file and synced before an
//! atomic hard-link publishes their exact-key body.  A retention-root body is
//! likewise durable before the immutable per-authority-head root file links to
//! it.  Directory scans never participate in recovery or authority.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_resource::kinds::{
    AdmissionAbandoned, AdmissionAbortReason, AdmittedObject, ObjectAdmission,
    ObjectAdmissionPermit, ObjectClass, StructureVerdict,
};
use fgit_resource::{Grade, OpaqueHandle, ReservedObligation, ResourceVector};
use fgit_types::{CANONICAL_CODEC_VERSION, Digest, GitOid, ObjectEnvelopeId, SegmentManifestId};

use crate::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, ImmutableObjectFabric,
    ObjectRange, PlacementAdmission, PlacementBackend, PlacementReceipt, PublicationState,
    PutIfAbsent, RetentionRootProposal, SegmentManifest, StorageOperation, StoreRefusal,
    VerifiedObject, VerifiedRangeRead, WholeObjectRead,
};
use crate::{ENVELOPE_SCHEMA, ObjectEnvelope, ObjectKind, SegmentLimits};

const OBJECT_MAGIC: &[u8; 4] = b"FGOB";
const MAX_STAGE_ATTEMPTS: u64 = 1_024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

/// Configuration for one namespace-scoped local object fabric.
#[derive(Debug, Clone)]
pub struct LocalFilesystemConfig {
    root: PathBuf,
    namespace: Vec<u8>,
    failure_domain: OpaqueHandle,
    encryption_dependency: OpaqueHandle,
    max_stored_object_bytes: u64,
    envelope_limits: SegmentLimits,
}

impl LocalFilesystemConfig {
    /// Creates a bounded filesystem profile rooted at an operator-selected directory.
    #[must_use]
    pub fn new(
        root: PathBuf,
        namespace: Vec<u8>,
        failure_domain: OpaqueHandle,
        encryption_dependency: OpaqueHandle,
        max_stored_object_bytes: u64,
        envelope_limits: SegmentLimits,
    ) -> Self {
        Self {
            root,
            namespace,
            failure_domain,
            encryption_dependency,
            max_stored_object_bytes,
            envelope_limits,
        }
    }
}

/// A body-first, root-last local object-fabric backend.
#[derive(Debug)]
pub struct LocalFilesystemFabric {
    root: PathBuf,
    namespace: Vec<u8>,
    failure_domain: OpaqueHandle,
    encryption_dependency: OpaqueHandle,
    max_stored_object_bytes: u64,
    envelope_limits: SegmentLimits,
    #[cfg(test)]
    crash_point: Option<LocalCrashPoint>,
}

/// A deterministic test-only interruption point in local publication.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCrashPoint {
    AfterStageWrite,
    BeforeImmutablePublish,
}

impl LocalFilesystemFabric {
    /// Opens a namespace-scoped local fabric, making no authority decision.
    pub fn open(config: LocalFilesystemConfig) -> Result<Self, StoreRefusal> {
        if config.namespace.is_empty() {
            return Err(StoreRefusal::EmptyNamespace);
        }
        if config.namespace.len() > config.envelope_limits.max_namespace_bytes {
            return Err(StoreRefusal::NamespaceTooLarge);
        }
        if config.max_stored_object_bytes == 0 {
            return Err(StoreRefusal::StoredObjectTooLarge {
                offered: 1,
                maximum: 0,
            });
        }
        let fabric = Self {
            root: config.root,
            namespace: config.namespace,
            failure_domain: config.failure_domain,
            encryption_dependency: config.encryption_dependency,
            max_stored_object_bytes: config.max_stored_object_bytes,
            envelope_limits: config.envelope_limits,
            #[cfg(test)]
            crash_point: None,
        };
        for directory in [
            fabric.root.clone(),
            fabric.staging_dir(),
            fabric.objects_dir(),
            fabric.manifests_dir(),
            fabric.retention_bodies_dir(),
            fabric.retention_roots_dir(),
        ] {
            fabric.create_directory(&directory)?;
        }
        Ok(fabric)
    }

    /// Returns the configured filesystem root without using it as authority.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    fn with_crash_point(mut self, crash_point: LocalCrashPoint) -> Self {
        self.crash_point = Some(crash_point);
        self
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    fn retention_bodies_dir(&self) -> PathBuf {
        self.root.join("retention").join("bodies")
    }

    fn retention_roots_dir(&self) -> PathBuf {
        self.root.join("retention").join("roots")
    }

    fn object_path(&self, identity: GitOid) -> PathBuf {
        self.objects_dir()
            .join(hex(&self.namespace))
            .join(hex(&identity.algorithm().code_point().to_be_bytes()))
            .join(hex(identity.as_bytes()))
    }

    fn manifest_path(&self, identity: SegmentManifestId) -> PathBuf {
        self.manifests_dir()
            .join(internal_key(identity.as_internal_object_id()))
    }

    fn retention_body_path(&self, root: Digest) -> PathBuf {
        self.retention_bodies_dir().join(digest_key(root))
    }

    fn retention_root_path(&self, proposal: &RetentionRootProposal) -> PathBuf {
        self.retention_roots_dir().join(internal_key(
            proposal.authority_head().as_internal_object_id(),
        ))
    }

    fn create_directory(&self, directory: &Path) -> Result<(), StoreRefusal> {
        fs::create_dir_all(directory)
            .map_err(|error| storage_error(StorageOperation::CreateDirectory, error))?;
        sync_directory(directory)
    }

    fn placement_for(&self, envelope: ObjectEnvelopeId) -> Result<PlacementReceipt, StoreRefusal> {
        let locator = OpaqueHandle::new(envelope.as_internal_object_id().digest().as_bytes())?;
        Ok(PlacementReceipt::new(
            PlacementBackend::LocalFilesystem,
            locator,
            self.failure_domain,
            self.encryption_dependency,
        ))
    }

    fn object_envelope_id(
        &self,
        object: &VerifiedObject,
    ) -> Result<ObjectEnvelopeId, StoreRefusal> {
        let bytes = object.envelope().encode()?;
        let identity = fgit_crypto::internal_object_id(
            fgit_crypto::IdentityDomain::ObjectEnvelope,
            ENVELOPE_SCHEMA,
            CANONICAL_CODEC_VERSION,
            &bytes,
        );
        ObjectEnvelopeId::from_internal_object_id(identity).map_err(StoreRefusal::from)
    }

    fn load_object(&self, identity: GitOid) -> Result<VerifiedObject, StoreRefusal> {
        let bytes = self.read_bounded(&self.object_path(identity))?;
        if bytes.len() < 8 || bytes.get(..4) != Some(OBJECT_MAGIC.as_slice()) {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        let envelope_len = u32::from_be_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| StoreRefusal::MalformedStoredObject)?,
        );
        let envelope_len =
            usize::try_from(envelope_len).map_err(|_| StoreRefusal::LengthOverflow)?;
        let payload_start = 8usize
            .checked_add(envelope_len)
            .ok_or(StoreRefusal::LengthOverflow)?;
        if payload_start > bytes.len() {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        let envelope = ObjectEnvelope::decode(&bytes[8..payload_start], &self.envelope_limits)?;
        if envelope.namespace() != self.namespace {
            return Err(StoreRefusal::NamespaceMismatch);
        }
        let object = VerifiedObject::new(envelope, bytes[payload_start..].to_vec())?;
        if object.identity() != identity {
            return Err(StoreRefusal::StoredObjectMismatch);
        }
        Ok(object)
    }

    fn read_bounded(&self, path: &Path) -> Result<Vec<u8>, StoreRefusal> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreRefusal::ObjectAbsent);
            }
            Err(error) => return Err(storage_error(StorageOperation::ReadBody, error)),
        };
        let offered = metadata.len();
        if offered > self.max_stored_object_bytes {
            return Err(StoreRefusal::StoredObjectTooLarge {
                offered,
                maximum: self.max_stored_object_bytes,
            });
        }
        fs::read(path).map_err(|error| storage_error(StorageOperation::ReadBody, error))
    }

    fn fresh_stage(&self) -> Result<(PathBuf, File), StoreRefusal> {
        let directory = self.staging_dir();
        self.create_directory(&directory)?;
        for _ in 0..MAX_STAGE_ATTEMPTS {
            let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("{sequence:016x}.stage"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(storage_error(StorageOperation::WriteStage, error)),
            }
        }
        Err(StoreRefusal::StorageIo {
            operation: StorageOperation::WriteStage,
            kind: std::io::ErrorKind::AlreadyExists,
        })
    }

    fn write_object_stage(
        &self,
        object: &VerifiedObject,
    ) -> Result<PathBuf, PlacementAttemptError> {
        let envelope = object
            .envelope()
            .encode()
            .map_err(|error| PlacementAttemptError::before_write(StoreRefusal::from(error)))?;
        let payload_len = u64::try_from(object.payload().len())
            .map_err(|_| PlacementAttemptError::before_write(StoreRefusal::LengthOverflow))?;
        let total_len =
            8_u64
                .checked_add(u64::try_from(envelope.len()).map_err(|_| {
                    PlacementAttemptError::before_write(StoreRefusal::LengthOverflow)
                })?)
                .and_then(|value| value.checked_add(payload_len))
                .ok_or_else(|| PlacementAttemptError::before_write(StoreRefusal::LengthOverflow))?;
        if total_len > self.max_stored_object_bytes {
            return Err(PlacementAttemptError::before_write(
                StoreRefusal::StoredObjectTooLarge {
                    offered: total_len,
                    maximum: self.max_stored_object_bytes,
                },
            ));
        }
        let envelope_len = u32::try_from(envelope.len())
            .map_err(|_| PlacementAttemptError::before_write(StoreRefusal::LengthOverflow))?;
        let (path, mut stage) = self
            .fresh_stage()
            .map_err(PlacementAttemptError::before_write)?;
        stage
            .write_all(OBJECT_MAGIC)
            .and_then(|()| stage.write_all(&envelope_len.to_be_bytes()))
            .and_then(|()| stage.write_all(&envelope))
            .and_then(|()| stage.write_all(object.payload()))
            .map_err(|error| {
                PlacementAttemptError::after_write(storage_error(
                    StorageOperation::WriteStage,
                    error,
                ))
            })?;
        self.crash_if(LocalCrashPointName::AfterStageWrite)
            .map_err(PlacementAttemptError::after_write)?;
        stage.sync_all().map_err(|error| {
            PlacementAttemptError::after_write(storage_error(StorageOperation::SyncStage, error))
        })?;
        Ok(path)
    }

    fn publish_object_stage(
        &self,
        stage: &Path,
        object: &VerifiedObject,
    ) -> Result<ImmutableWrite, StoreRefusal> {
        self.crash_if(LocalCrashPointName::BeforeImmutablePublish)?;
        let final_path = self.object_path(object.identity());
        let parent = final_path
            .parent()
            .ok_or(StoreRefusal::MalformedStoredObject)?;
        self.create_directory(parent)?;
        match fs::hard_link(stage, &final_path) {
            Ok(()) => {
                sync_directory(parent)?;
                let _cleanup = fs::remove_file(stage);
                Ok(ImmutableWrite::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stored = self.load_object(object.identity())?;
                if stored != *object {
                    return Err(StoreRefusal::StoredObjectMismatch);
                }
                let _cleanup = fs::remove_file(stage);
                Ok(ImmutableWrite::AlreadyPresent)
            }
            Err(error) => Err(storage_error(StorageOperation::PublishImmutableBody, error)),
        }
    }

    fn write_immutable_bytes(
        &self,
        final_path: &Path,
        body: &[u8],
        operation: StorageOperation,
    ) -> Result<ImmutableWrite, StoreRefusal> {
        let offered = u64::try_from(body.len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        if offered > self.max_stored_object_bytes {
            return Err(StoreRefusal::StoredObjectTooLarge {
                offered,
                maximum: self.max_stored_object_bytes,
            });
        }
        let parent = final_path
            .parent()
            .ok_or(StoreRefusal::MalformedStoredObject)?;
        self.create_directory(parent)?;
        let (stage_path, mut stage) = self.fresh_stage()?;
        stage
            .write_all(body)
            .map_err(|error| storage_error(StorageOperation::WriteStage, error))?;
        stage
            .sync_all()
            .map_err(|error| storage_error(StorageOperation::SyncStage, error))?;
        match fs::hard_link(&stage_path, final_path) {
            Ok(()) => {
                sync_directory(parent)?;
                let _cleanup = fs::remove_file(stage_path);
                Ok(ImmutableWrite::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self.read_bounded(final_path)?;
                if existing != body {
                    return Err(StoreRefusal::StoredObjectMismatch);
                }
                let _cleanup = fs::remove_file(stage_path);
                Ok(ImmutableWrite::AlreadyPresent)
            }
            Err(error) => Err(storage_error(operation, error)),
        }
    }

    fn crash_if(&self, point: LocalCrashPointName) -> Result<(), StoreRefusal> {
        #[cfg(test)]
        {
            let expected = match point {
                LocalCrashPointName::AfterStageWrite => LocalCrashPoint::AfterStageWrite,
                LocalCrashPointName::BeforeImmutablePublish => {
                    LocalCrashPoint::BeforeImmutablePublish
                }
            };
            if self.crash_point == Some(expected) {
                return Err(StoreRefusal::StorageIo {
                    operation: StorageOperation::WriteStage,
                    kind: std::io::ErrorKind::Interrupted,
                });
            }
        }
        #[cfg(not(test))]
        let _ = point;
        Ok(())
    }
}

impl ImmutableObjectFabric for LocalFilesystemFabric {
    fn capabilities(&self) -> FabricCapabilities {
        FabricCapabilities {
            conditional_put_if_absent: true,
            verified_whole_reads: true,
            authenticated_partial_ranges: false,
            conditional_deletion: true,
            listing_is_authority: false,
        }
    }

    fn put_if_absent(
        &self,
        object: VerifiedObject,
        admission: PlacementAdmission<'_>,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        if object.envelope().namespace() != self.namespace {
            return Err(StoreRefusal::NamespaceMismatch);
        }
        let placement_identity = self.object_envelope_id(&object)?;
        let placement = self.placement_for(placement_identity)?;
        let (ledger, budget) = admission.into_parts();
        match self.load_object(object.identity()) {
            Ok(existing) => {
                let _released = budget.release();
                if existing != object {
                    return Err(StoreRefusal::StoredObjectMismatch);
                }
                return Ok(PutIfAbsent::AlreadyPresent {
                    placement,
                    epochs: PublicationState::new(true, false, true),
                });
            }
            Err(StoreRefusal::ObjectAbsent) => {}
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        }
        let declared_len =
            u64::try_from(object.payload().len()).map_err(|_| StoreRefusal::LengthOverflow)?;
        let actual =
            ResourceVector::from_grades(&[(Grade::Bytes, declared_len), (Grade::Objects, 1)]);
        if let Some(error) = budget.amount().first_deficit(&actual) {
            let _released = budget.release();
            return Err(StoreRefusal::Resource(error));
        }
        let reservation = ObjectAdmission {
            class: ObjectClass::GitObject,
            declared_len,
            staging: placement_identity,
        };
        let reserved = ledger.reserve::<ObjectAdmissionPermit>(reservation, budget)?;
        if let Err(error) = reserved.can_settle(&actual) {
            let _settled = reserved.abort_unused(AdmissionAbandoned {
                reason: AdmissionAbortReason::QuotaWithdrawn,
            });
            return Err(StoreRefusal::Settlement(error));
        }
        let stage = match self.write_object_stage(&object) {
            Ok(stage) => stage,
            Err(failure) => {
                let spent = if failure.body_write_started {
                    actual
                } else {
                    ResourceVector::ZERO
                };
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &spent,
                )?;
                return Err(failure.refusal);
            }
        };
        match self.publish_object_stage(&stage, &object) {
            Ok(ImmutableWrite::AlreadyPresent) => {
                settle_admission_abort(reserved, AdmissionAbortReason::Superseded, &actual)?;
                Ok(PutIfAbsent::AlreadyPresent {
                    placement,
                    epochs: PublicationState::new(true, false, true),
                })
            }
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &actual,
                )?;
                Err(error)
            }
            Ok(ImmutableWrite::Created) => {
                let strong_identity =
                    payload_identity(object.envelope().object_kind(), object.payload())?;
                let receipt = AdmittedObject::verified(
                    &reservation,
                    object.identity(),
                    strong_identity,
                    declared_len,
                    StructureVerdict::Verified,
                )?;
                match reserved.commit_internal(receipt, &actual) {
                    Ok(_settled) => Ok(PutIfAbsent::Created {
                        placement,
                        epochs: PublicationState::new(true, false, true),
                    }),
                    Err(refused) => {
                        let error = refused.error();
                        let reservation = refused.into_obligation();
                        settle_admission_abort(
                            reservation,
                            AdmissionAbortReason::PlacementWriteFailed,
                            &actual,
                        )?;
                        Err(StoreRefusal::Settlement(error))
                    }
                }
            }
        }
    }

    fn read_whole(&self, identity: GitOid) -> Result<WholeObjectRead, StoreRefusal> {
        let object = self.load_object(identity)?;
        let placement = self.placement_for(self.object_envelope_id(&object)?)?;
        Ok(WholeObjectRead { object, placement })
    }

    fn read_range_verified(
        &self,
        identity: GitOid,
        range: ObjectRange,
    ) -> Result<VerifiedRangeRead, StoreRefusal> {
        let whole = self.read_whole(identity)?;
        let full_len = u64::try_from(whole.object.payload().len())
            .map_err(|_| StoreRefusal::LengthOverflow)?;
        if range.offset() != 0 || range.length() != full_len {
            return Err(StoreRefusal::PartialRangeUnverified);
        }
        Ok(VerifiedRangeRead {
            object_identity: identity,
            range,
            bytes: whole.object.payload().to_vec(),
            placement: whole.placement,
        })
    }

    fn write_manifest(
        &self,
        manifest: &SegmentManifest,
    ) -> Result<SegmentManifestId, StoreRefusal> {
        let identity = manifest.identity()?;
        let body = manifest.encode()?;
        let _outcome = self.write_immutable_bytes(
            &self.manifest_path(identity),
            &body,
            StorageOperation::PublishImmutableBody,
        )?;
        Ok(identity)
    }

    fn read_manifest(&self, identity: SegmentManifestId) -> Result<SegmentManifest, StoreRefusal> {
        let bytes = self.read_bounded(&self.manifest_path(identity))?;
        SegmentManifest::decode_verified(
            &bytes,
            identity,
            &self.envelope_limits_to_manifest_limits(),
        )
    }

    fn publish_retention_root<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        proposal: &RetentionRootProposal,
    ) -> Result<PublicationState, StoreRefusal> {
        registry.revalidate_root(proposal)?;
        let body = proposal.canonical_bytes()?;
        let _body = self.write_immutable_bytes(
            &self.retention_body_path(proposal.retention_root()),
            &body,
            StorageOperation::PublishRetentionBody,
        )?;
        let pointer = retention_pointer(proposal.retention_root());
        let _root = self.write_immutable_bytes(
            &self.retention_root_path(proposal),
            &pointer,
            StorageOperation::PublishRetentionRoot,
        )?;
        Ok(PublicationState::new(true, true, true))
    }

    fn delete_if_unretained<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        identity: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal> {
        registry.permits_placement_deletion(identity)?;
        match fs::remove_file(self.object_path(identity)) {
            Ok(()) => Ok(DeletionReceipt::Deleted),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(DeletionReceipt::AlreadyAbsent)
            }
            Err(error) => Err(storage_error(StorageOperation::RemoveBody, error)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImmutableWrite {
    Created,
    AlreadyPresent,
}

#[derive(Debug)]
struct PlacementAttemptError {
    refusal: StoreRefusal,
    body_write_started: bool,
}

impl PlacementAttemptError {
    const fn before_write(refusal: StoreRefusal) -> Self {
        Self {
            refusal,
            body_write_started: false,
        }
    }

    const fn after_write(refusal: StoreRefusal) -> Self {
        Self {
            refusal,
            body_write_started: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalCrashPointName {
    AfterStageWrite,
    BeforeImmutablePublish,
}

fn payload_identity(kind: ObjectKind, payload: &[u8]) -> Result<Digest, StoreRefusal> {
    let kind = match kind {
        ObjectKind::Commit => fgit_crypto::GitObjectKind::Commit,
        ObjectKind::Tree => fgit_crypto::GitObjectKind::Tree,
        ObjectKind::Blob => fgit_crypto::GitObjectKind::Blob,
        ObjectKind::Tag => fgit_crypto::GitObjectKind::Tag,
        ObjectKind::Internal => return Err(StoreRefusal::NativeObjectIdentityMismatch),
    };
    let identity = fgit_crypto::git_payload_commitment(kind, payload, CANONICAL_CODEC_VERSION);
    Ok(Digest::new(identity.algorithm(), *identity.digest()))
}

fn settle_admission_abort(
    reserved: ReservedObligation<ObjectAdmissionPermit>,
    reason: AdmissionAbortReason,
    spent: &ResourceVector,
) -> Result<(), StoreRefusal> {
    match reserved.abort(AdmissionAbandoned { reason }, spent) {
        Ok(_settled) => Ok(()),
        Err(refused) => {
            let error = refused.error();
            let reservation = refused.into_obligation();
            let _settled = reservation.abort_unused(AdmissionAbandoned { reason });
            Err(StoreRefusal::Settlement(error))
        }
    }
}

fn retention_pointer(root: Digest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + root.bytes().len());
    bytes.extend_from_slice(&root.algorithm().code_point().to_be_bytes());
    bytes.extend_from_slice(root.bytes().as_bytes());
    bytes
}

fn digest_key(digest: Digest) -> String {
    let mut key = hex(&digest.algorithm().code_point().to_be_bytes());
    key.push_str(&hex(digest.bytes().as_bytes()));
    key
}

fn internal_key(identity: &fgit_types::InternalObjectId) -> String {
    let mut key = hex(&identity.algorithm().code_point().to_be_bytes());
    key.push('-');
    key.push_str(&hex(&identity.codec_version().major().to_be_bytes()));
    key.push('-');
    key.push_str(&hex(&identity.codec_version().minor().to_be_bytes()));
    key.push('-');
    key.push_str(&hex(identity.digest().as_bytes()));
    key
}

fn storage_error(operation: StorageOperation, error: std::io::Error) -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation,
        kind: error.kind(),
    }
}

fn sync_directory(directory: &Path) -> Result<(), StoreRefusal> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| storage_error(StorageOperation::SyncDirectory, error))
}

fn hex(source: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(source.len().saturating_mul(2));
    for byte in source {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

impl LocalFilesystemFabric {
    fn envelope_limits_to_manifest_limits(&self) -> crate::fabric::ManifestLimits {
        crate::fabric::ManifestLimits {
            max_namespace_bytes: self.envelope_limits.max_namespace_bytes,
            max_entries: self.envelope_limits.max_records,
            max_placements: self.envelope_limits.max_records,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use fgit_resource::{LeakDisposition, ObligationLedger, RegionCloseOutcome, RegionId};
    use fgit_types::{
        DigestAlgorithmId, DigestBytes, GitHashAlgorithm, PublicationEpoch,
        RepositoryAuthorityHeadId,
    };

    use super::*;

    static NEXT_TEST_ROOT: AtomicU64 = AtomicU64::new(1);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let sequence = NEXT_TEST_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "frankengit-object-fabric-local-{}-{sequence}",
                std::process::id()
            ));
            Self(path)
        }

        fn path(&self) -> PathBuf {
            self.0.clone()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    struct AllowDeletion;

    impl AuthenticatedRetentionRegistry for AllowDeletion {
        fn revalidate_root(&self, _proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
            Ok(())
        }

        fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
            Ok(())
        }
    }

    struct RejectRetention;

    impl AuthenticatedRetentionRegistry for RejectRetention {
        fn revalidate_root(&self, _proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
            Err(StoreRefusal::RetentionRevalidationFailed)
        }

        fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
            Err(StoreRefusal::DeletionRetained)
        }
    }

    fn limits() -> SegmentLimits {
        SegmentLimits {
            max_segment_bytes: 4096,
            max_records: 16,
            max_namespace_bytes: 16,
            max_object_identity_bytes: 32,
            max_envelope_bytes: 256,
            max_record_bytes: 512,
        }
    }

    fn fabric(root: PathBuf) -> LocalFilesystemFabric {
        LocalFilesystemFabric::open(LocalFilesystemConfig::new(
            root,
            vec![b'n'],
            OpaqueHandle::new(b"rack-a").expect("test failure domain must fit"),
            OpaqueHandle::new(b"key-a").expect("test key dependency must fit"),
            4096,
            limits(),
        ))
        .expect("test fabric must open")
    }

    fn object(payload: &[u8]) -> VerifiedObject {
        object_in_namespace(b"n", payload)
    }

    fn object_in_namespace(namespace: &[u8], payload: &[u8]) -> VerifiedObject {
        let native = fgit_crypto::git_object_id(
            GitHashAlgorithm::Sha1,
            fgit_crypto::GitObjectKind::Blob,
            payload,
        );
        let commitment = fgit_crypto::git_payload_commitment(
            fgit_crypto::GitObjectKind::Blob,
            payload,
            CANONICAL_CODEC_VERSION,
        );
        let mut commitment_bytes = [0; 32];
        commitment_bytes.copy_from_slice(commitment.digest().as_bytes());
        let envelope = ObjectEnvelope::new(
            namespace.to_vec(),
            native,
            ObjectKind::Blob,
            u64::try_from(payload.len()).expect("test payload length must fit"),
            commitment_bytes,
            b"raw".to_vec(),
            [7; 32],
            None,
            &limits(),
        )
        .expect("test envelope must be valid");
        VerifiedObject::new(envelope, payload.to_vec()).expect("test object must verify")
    }

    fn ledger() -> ObligationLedger {
        ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            ResourceVector::from_grades(&[(Grade::Bytes, 4096), (Grade::Objects, 16)]),
        )
    }

    fn admission<'a>(
        ledger: &'a ObligationLedger,
        object: &VerifiedObject,
    ) -> PlacementAdmission<'a> {
        let grant = ledger
            .grant(ResourceVector::from_grades(&[
                (
                    Grade::Bytes,
                    u64::try_from(object.payload().len()).expect("test length must fit"),
                ),
                (Grade::Objects, 1),
            ]))
            .expect("test grant must succeed");
        PlacementAdmission::new(ledger, grant)
    }

    fn assert_quiescent(ledger: ObligationLedger) {
        assert!(matches!(ledger.close(), RegionCloseOutcome::Quiescent(_)));
    }

    #[test]
    fn local_put_reads_whole_and_refuses_uncommitted_subranges() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let object = object(b"payload");
        let ledger = ledger();
        let outcome = fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("local placement must succeed");
        assert!(matches!(outcome, PutIfAbsent::Created { .. }));
        let whole = fabric
            .read_whole(object.identity())
            .expect("exact whole read must verify");
        assert_eq!(whole.object, object);
        let full = ObjectRange::new(
            0,
            u64::try_from(whole.object.payload().len()).expect("test length must fit"),
            u64::try_from(whole.object.payload().len()).expect("test length must fit"),
        )
        .expect("full range must be valid");
        assert_eq!(
            fabric
                .read_range_verified(whole.object.identity(), full)
                .expect("whole-object range is verified")
                .bytes,
            b"payload"
        );
        let partial = ObjectRange::new(1, 1, 7).expect("partial range bounds must be valid");
        assert_eq!(
            fabric.read_range_verified(whole.object.identity(), partial),
            Err(StoreRefusal::PartialRangeUnverified)
        );
        assert_quiescent(ledger);
    }

    #[test]
    fn crash_points_leave_only_non_authoritative_staging_residue() {
        for point in [
            LocalCrashPoint::AfterStageWrite,
            LocalCrashPoint::BeforeImmutablePublish,
        ] {
            let root = TestRoot::new();
            let object = object(b"payload");
            let crashing = fabric(root.path()).with_crash_point(point);
            let ledger = ledger();
            assert!(matches!(
                crashing.put_if_absent(object.clone(), admission(&ledger, &object)),
                Err(StoreRefusal::StorageIo {
                    kind: std::io::ErrorKind::Interrupted,
                    ..
                })
            ));
            assert_quiescent(ledger);
            let reopened = fabric(root.path());
            assert_eq!(
                reopened.read_whole(object.identity()),
                Err(StoreRefusal::ObjectAbsent)
            );
        }
    }

    #[test]
    fn local_deletion_revalidates_then_is_idempotent() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let object = object(b"payload");
        let ledger = ledger();
        fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("local placement must succeed");
        let registry = AllowDeletion;
        assert_eq!(
            fabric
                .delete_if_unretained(&registry, object.identity())
                .expect("unretained body must delete"),
            DeletionReceipt::Deleted
        );
        assert_eq!(
            fabric
                .delete_if_unretained(&registry, object.identity())
                .expect("second delete must be a no-op"),
            DeletionReceipt::AlreadyAbsent
        );
        assert_quiescent(ledger);
    }

    #[test]
    fn configured_namespace_rejects_a_near_identical_object() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let object = object_in_namespace(b"x", b"payload");
        let ledger = ledger();
        let grant = ledger
            .grant(ResourceVector::from_grades(&[
                (Grade::Bytes, 7),
                (Grade::Objects, 1),
            ]))
            .expect("test grant must succeed");
        assert_eq!(
            fabric.put_if_absent(object, PlacementAdmission::new(&ledger, grant)),
            Err(StoreRefusal::NamespaceMismatch)
        );
        assert_quiescent(ledger);
    }

    #[test]
    fn local_manifest_store_verifies_its_typed_identity_on_every_read() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let object = object(b"payload");
        let digest = crate::CryptoDigest;
        let mut builder = crate::MicrosegmentBuilder::new(&digest, limits());
        builder
            .push(crate::SegmentRecordInput {
                envelope: object.envelope().clone(),
                payload: object.payload().to_vec(),
            })
            .expect("test segment record must be accepted");
        let segment = builder.build().expect("test segment must build");
        let reader = crate::MicrosegmentReader::open(segment.as_bytes(), &digest, &limits())
            .expect("test segment must read");
        let manifest = SegmentManifest::from_verified_segment(
            &reader,
            Vec::new(),
            &crate::fabric::ManifestLimits {
                max_namespace_bytes: 16,
                max_entries: 8,
                max_placements: 8,
            },
        )
        .expect("verified segment must form a manifest");
        let identity = fabric
            .write_manifest(&manifest)
            .expect("manifest write must succeed");
        assert_eq!(
            fabric
                .read_manifest(identity)
                .expect("manifest identity must verify"),
            manifest
        );
        let path = fabric.manifest_path(identity);
        let mut corrupt = fs::read(&path).expect("stored manifest must be readable in test");
        corrupt[0] ^= 1;
        fs::write(path, corrupt).expect("test corruption write must succeed");
        assert!(matches!(
            fabric.read_manifest(identity),
            Err(StoreRefusal::InvalidMagic | StoreRefusal::ManifestIdentityMismatch)
        ));
    }

    #[test]
    fn retention_root_is_revalidated_before_any_local_root_is_published() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let algorithm = DigestAlgorithmId::try_new(2).expect("sha-256 code point is valid");
        let head = RepositoryAuthorityHeadId::from_digest(
            algorithm,
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[3; 32]).expect("test digest must fit"),
        );
        let proposal = RetentionRootProposal::new(
            head,
            Digest::new(
                algorithm,
                DigestBytes::try_new(&[4; 32]).expect("test digest must fit"),
            ),
            Vec::new(),
        )
        .expect("test proposal must be canonical");
        assert_eq!(
            fabric.publish_retention_root(&RejectRetention, &proposal),
            Err(StoreRefusal::RetentionRevalidationFailed)
        );
        assert!(!fabric.retention_root_path(&proposal).exists());
        let publication = fabric
            .publish_retention_root(&AllowDeletion, &proposal)
            .expect("revalidated retention root must publish body before root");
        assert!(publication.contains(PublicationEpoch::Staged));
        assert!(publication.contains(PublicationEpoch::Durable));
        assert!(publication.contains(PublicationEpoch::Visible));
        assert!(
            fabric
                .retention_body_path(proposal.retention_root())
                .exists()
        );
        assert!(fabric.retention_root_path(&proposal).exists());
    }
}
