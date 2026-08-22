//! Safe local-directory implementation of the immutable object-fabric traits.
//!
//! Object bodies are written to a unique staging file and synced before an
//! atomic hard-link publishes their exact-key body.  A retention-root body is
//! likewise durable before the immutable per-authority-head root file links to
//! it.  Directory scans never participate in recovery or authority.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::runtime::JoinError;
use asupersync::{Cx, Outcome};
use fgit_resource::kinds::{
    AdmissionAbandoned, AdmissionAbortReason, AdmittedObject, ObjectAdmission,
    ObjectAdmissionPermit, ObjectClass, StructureVerdict,
};
use fgit_resource::{Grade, OpaqueHandle, ReservedObligation, ResourceVector};
use fgit_types::{CANONICAL_CODEC_VERSION, Digest, GitOid, ObjectEnvelopeId, SegmentManifestId};

use crate::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, FabricCapability,
    ImmutableObjectFabric, ObjectRange, PlacementAdmission, PlacementBackend, PlacementReceipt,
    PublicationState, PutIfAbsent, RetentionRootProposal, RuntimeImmutableObjectFabric,
    SegmentManifest, StorageOperation, StoreRefusal, VerifiedObject, VerifiedObjectStream,
    VerifiedRangeRead, VerifiedStreamBudget, WholeObjectRead, checkpoint_outcome,
};
use crate::{ENVELOPE_SCHEMA, ObjectEnvelope, ObjectKind, SegmentLimits};

const OBJECT_MAGIC: &[u8; 4] = b"FGOB";
const MAX_STAGE_ATTEMPTS: u64 = 1_024;
static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

/// One locally-owned staging file, removed whenever its placement returns.
///
/// A physical crash cannot run [`Drop`], so recovery continues to treat any
/// residue as non-authoritative. Returned refusals, however, must not grow the
/// staging directory: they close the handle and remove this one known path.
struct StageFile {
    path: PathBuf,
    file: Option<File>,
}

impl StageFile {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(file),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.write_all(bytes),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "staging file is already closed",
            )),
        }
    }

    fn sync_all(&self) -> std::io::Result<()> {
        match self.file.as_ref() {
            Some(file) => file.sync_all(),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "staging file is already closed",
            )),
        }
    }

    fn close(&mut self) {
        drop(self.file.take());
    }
}

impl Drop for StageFile {
    fn drop(&mut self) {
        drop(self.file.take());
        let _cleanup = fs::remove_file(&self.path);
    }
}

/// Configuration for one namespace-scoped local object fabric.
#[derive(Debug, Clone)]
pub struct LocalFilesystemConfig {
    root: PathBuf,
    namespace: Vec<u8>,
    failure_domain: OpaqueHandle,
    encryption_dependency: OpaqueHandle,
    max_stored_object_bytes: u64,
    envelope_limits: SegmentLimits,
    crash_point: Option<LocalCrashPoint>,
}

impl LocalFilesystemConfig {
    /// Creates a bounded filesystem profile rooted at an operator-selected directory.
    #[must_use]
    pub const fn new(
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
            crash_point: None,
        }
    }

    /// Installs one deterministic interruption point for a fault drill.
    ///
    /// This is opt-in and defaults to no interruption. It exists so crash
    /// tests exercise the same publication code as a live local backend
    /// instead of a `cfg(test)` shadow path. An interrupted operation never
    /// reports placement success; a reopen may observe only absence or the
    /// exact immutable object body.
    #[must_use]
    pub const fn with_crash_injection(mut self, crash_point: LocalCrashPoint) -> Self {
        self.crash_point = Some(crash_point);
        self
    }
}

/// Exact interruption boundaries in the local body-first/root-last protocol.
///
/// These points are used by deterministic fault drills. They deliberately
/// span body write, body sync, immutable-root link, directory sync, and
/// cleanup so a test cannot claim a crash matrix from only one early write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalCrashPoint {
    BeforeStageWrite,
    AfterStageWrite,
    AfterStageSync,
    BeforeImmutablePublish,
    AfterImmutablePublish,
    AfterPublishDirectorySync,
    BeforeStageCleanup,
}

/// A body-first, root-last local object-fabric backend.
#[derive(Debug, Clone)]
pub struct LocalFilesystemFabric {
    root: PathBuf,
    namespace: Vec<u8>,
    failure_domain: OpaqueHandle,
    encryption_dependency: OpaqueHandle,
    max_stored_object_bytes: u64,
    envelope_limits: SegmentLimits,
    crash_point: Option<LocalCrashPoint>,
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
            crash_point: config.crash_point,
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
        let directories = directory_chain(&self.root, directory)?;
        let root_was_directory = self.root.is_dir();
        fs::create_dir_all(&self.root)
            .map_err(|error| storage_error(StorageOperation::CreateDirectory, error))?;

        let mut created_directory = !root_was_directory;
        for child in directories.iter().skip(1) {
            match fs::create_dir(child) {
                Ok(()) => created_directory = true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if !child.is_dir() {
                        return Err(storage_error(StorageOperation::CreateDirectory, error));
                    }
                }
                Err(error) => {
                    return Err(storage_error(StorageOperation::CreateDirectory, error));
                }
            }
        }

        if created_directory {
            for created_or_parent in directories.iter().rev() {
                sync_directory(created_or_parent)?;
            }
            Ok(())
        } else {
            sync_directory(directory)
        }
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

    fn object_envelope_id(object: &VerifiedObject) -> Result<ObjectEnvelopeId, StoreRefusal> {
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

    fn fresh_stage(&self) -> Result<StageFile, StoreRefusal> {
        let directory = self.staging_dir();
        self.create_directory(&directory)?;
        for _ in 0..MAX_STAGE_ATTEMPTS {
            let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let path = directory.join(format!("{sequence:016x}.stage"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok(StageFile::new(path, file)),
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
    ) -> Result<StageFile, PlacementAttemptError> {
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
        let mut stage = self
            .fresh_stage()
            .map_err(PlacementAttemptError::before_write)?;
        self.crash_if(LocalCrashPoint::BeforeStageWrite)
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
        self.crash_if(LocalCrashPoint::AfterStageWrite)
            .map_err(PlacementAttemptError::after_write)?;
        stage.sync_all().map_err(|error| {
            PlacementAttemptError::after_write(storage_error(StorageOperation::SyncStage, error))
        })?;
        self.crash_if(LocalCrashPoint::AfterStageSync)
            .map_err(PlacementAttemptError::after_write)?;
        stage.close();
        Ok(stage)
    }

    fn publish_object_stage(
        &self,
        stage: StageFile,
        object: &VerifiedObject,
    ) -> Result<ImmutableWrite, StoreRefusal> {
        self.crash_if(LocalCrashPoint::BeforeImmutablePublish)?;
        let final_path = self.object_path(object.identity());
        let parent = final_path
            .parent()
            .ok_or(StoreRefusal::MalformedStoredObject)?;
        self.create_directory(parent)?;
        match fs::hard_link(stage.path(), &final_path) {
            Ok(()) => {
                self.crash_if(LocalCrashPoint::AfterImmutablePublish)?;
                sync_directory(parent)?;
                self.crash_if(LocalCrashPoint::AfterPublishDirectorySync)?;
                self.crash_if(LocalCrashPoint::BeforeStageCleanup)?;
                Ok(ImmutableWrite::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stored = self.load_object(object.identity())?;
                if stored != *object {
                    return Err(StoreRefusal::StoredObjectMismatch);
                }
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
        let mut stage = self.fresh_stage()?;
        self.crash_if(LocalCrashPoint::BeforeStageWrite)?;
        stage
            .write_all(body)
            .map_err(|error| storage_error(StorageOperation::WriteStage, error))?;
        self.crash_if(LocalCrashPoint::AfterStageWrite)?;
        stage
            .sync_all()
            .map_err(|error| storage_error(StorageOperation::SyncStage, error))?;
        self.crash_if(LocalCrashPoint::AfterStageSync)?;
        self.crash_if(LocalCrashPoint::BeforeImmutablePublish)?;
        stage.close();
        match fs::hard_link(stage.path(), final_path) {
            Ok(()) => {
                self.crash_if(LocalCrashPoint::AfterImmutablePublish)?;
                sync_directory(parent)?;
                self.crash_if(LocalCrashPoint::AfterPublishDirectorySync)?;
                self.crash_if(LocalCrashPoint::BeforeStageCleanup)?;
                Ok(ImmutableWrite::Created)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = self.read_bounded(final_path)?;
                if existing != body {
                    return Err(StoreRefusal::StoredObjectMismatch);
                }
                Ok(ImmutableWrite::AlreadyPresent)
            }
            Err(error) => Err(storage_error(operation, error)),
        }
    }

    fn crash_if(&self, point: LocalCrashPoint) -> Result<(), StoreRefusal> {
        if self.crash_point == Some(point) {
            let operation = match point {
                LocalCrashPoint::BeforeStageWrite | LocalCrashPoint::AfterStageWrite => {
                    StorageOperation::WriteStage
                }
                LocalCrashPoint::AfterStageSync => StorageOperation::SyncStage,
                LocalCrashPoint::BeforeImmutablePublish
                | LocalCrashPoint::AfterImmutablePublish => StorageOperation::PublishImmutableBody,
                LocalCrashPoint::AfterPublishDirectorySync => StorageOperation::SyncDirectory,
                LocalCrashPoint::BeforeStageCleanup => StorageOperation::RemoveBody,
            };
            return Err(StoreRefusal::StorageIo {
                operation,
                kind: std::io::ErrorKind::Interrupted,
            });
        }
        Ok(())
    }
}

impl ImmutableObjectFabric for LocalFilesystemFabric {
    fn capabilities(&self) -> FabricCapabilities {
        FabricCapabilities::new(&[
            FabricCapability::ConditionalPutIfAbsent,
            FabricCapability::VerifiedWholeReads,
            FabricCapability::ConditionalDeletion,
        ])
    }

    fn put_if_absent(
        &self,
        object: VerifiedObject,
        admission: PlacementAdmission<'_>,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        // Take custody before any validation that can refuse.  A caller has
        // already carved this grant from its region; returning it explicitly
        // on every pre-reservation refusal keeps an invalid placement request
        // from becoming a resource-accounting leak.
        let (ledger, budget) = admission.into_parts();
        if object.envelope().namespace() != self.namespace {
            let _released = budget.release();
            return Err(StoreRefusal::NamespaceMismatch);
        }
        let placement_identity = match Self::object_envelope_id(&object) {
            Ok(identity) => identity,
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        };
        let placement = match self.placement_for(placement_identity) {
            Ok(placement) => placement,
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        };
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
        let declared_len = match u64::try_from(object.payload().len()) {
            Ok(length) => length,
            Err(_) => {
                let _released = budget.release();
                return Err(StoreRefusal::LengthOverflow);
            }
        };
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
        match self.publish_object_stage(stage, &object) {
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
        let placement = self.placement_for(Self::object_envelope_id(&object)?)?;
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

impl RuntimeImmutableObjectFabric for LocalFilesystemFabric {
    async fn open_verified_stream(
        &self,
        cx: &Cx,
        identity: GitOid,
        budget: VerifiedStreamBudget,
    ) -> Outcome<VerifiedObjectStream, StoreRefusal> {
        if let Some(outcome) = checkpoint_outcome(cx) {
            return outcome;
        }
        let fabric = self.clone();
        let mut task = match cx.spawn_blocking(move |child_cx| {
            if child_cx.checkpoint().is_err() {
                return Err(StoreRefusal::RuntimeCheckpointRejected);
            }
            fabric.read_whole(identity)
        }) {
            Ok(task) => task,
            Err(_) => return Outcome::Err(StoreRefusal::RuntimeSpawnUnavailable),
        };
        match task.join(cx).await {
            Ok(Ok(whole)) => {
                if let Some(outcome) = checkpoint_outcome(cx) {
                    return outcome;
                }
                match VerifiedObjectStream::new(whole, budget) {
                    Ok(stream) => Outcome::Ok(stream),
                    Err(error) => Outcome::Err(error),
                }
            }
            Ok(Err(error)) => Outcome::Err(error),
            Err(JoinError::Cancelled(reason)) => Outcome::Cancelled(reason),
            Err(JoinError::Panicked(payload)) => Outcome::Panicked(payload),
            Err(JoinError::PolledAfterCompletion) => {
                Outcome::Err(StoreRefusal::RuntimeJoinConsumed)
            }
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

/// Lists the store-root-bounded directory chain that a new descendant must sync.
///
/// Callers sync this list in reverse so the leaf reaches stable storage before
/// every parent directory entry up to the configured store root.
fn directory_chain(root: &Path, directory: &Path) -> Result<Vec<PathBuf>, StoreRefusal> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| StoreRefusal::MalformedStoredObject)?;
    let mut directories = Vec::with_capacity(relative.components().count().saturating_add(1));
    let mut current = root.to_path_buf();
    directories.push(current.clone());
    for component in relative.components() {
        match component {
            Component::Normal(segment) => {
                current.push(segment);
                directories.push(current.clone());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(StoreRefusal::MalformedStoredObject);
            }
        }
    }
    Ok(directories)
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
    const fn envelope_limits_to_manifest_limits(&self) -> crate::fabric::ManifestLimits {
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
    use std::time::Duration;

    use asupersync::runtime::RuntimeBuilder;
    use asupersync::{Budget, CancelKind, Cx, Outcome};
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

    fn fabric_with_crash(root: PathBuf, point: LocalCrashPoint) -> LocalFilesystemFabric {
        LocalFilesystemFabric::open(
            LocalFilesystemConfig::new(
                root,
                vec![b'n'],
                OpaqueHandle::new(b"rack-a").expect("test failure domain must fit"),
                OpaqueHandle::new(b"key-a").expect("test key dependency must fit"),
                4096,
                limits(),
            )
            .with_crash_injection(point),
        )
        .expect("fault-injected test fabric must open")
    }

    fn assert_staging_is_empty(fabric: &LocalFilesystemFabric) {
        assert_eq!(
            fs::read_dir(fabric.staging_dir())
                .expect("local staging directory must remain readable")
                .count(),
            0,
            "a returned failure must release its staging file instead of growing the placement volume"
        );
    }

    #[test]
    fn newly_created_nested_directories_sync_a_chain_bounded_by_store_root() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let namespace = fabric.objects_dir().join("namespace");
        let leaf = namespace.join("algorithm");
        let expected_chain = vec![
            fabric.root().to_path_buf(),
            fabric.objects_dir(),
            namespace.clone(),
            leaf.clone(),
        ];
        assert_eq!(
            directory_chain(fabric.root(), &leaf)
                .expect("object descendants must stay beneath the store root"),
            expected_chain
        );

        fabric
            .create_directory(&leaf)
            .expect("new nested object directory must be made durable through the store root");
        assert!(namespace.is_dir());
        assert!(leaf.is_dir());
    }

    #[test]
    fn directory_sync_chain_refuses_a_path_outside_the_store_root() {
        let root = TestRoot::new();
        let store_root = root.path().join("store");
        let outside = root.path().join("outside");
        assert_eq!(
            directory_chain(&store_root, &outside),
            Err(StoreRefusal::MalformedStoredObject)
        );
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
    fn verified_stream_emits_only_verified_chunks_and_preserves_cancellation() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let object = object(b"payload");
        let ledger = ledger();
        fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("local placement must succeed");
        let whole = fabric
            .read_whole(object.identity())
            .expect("whole body must verify before stream construction");
        let mut stream = VerifiedObjectStream::new(
            whole,
            VerifiedStreamBudget::new(7, 3).expect("finite stream budget must be valid"),
        )
        .expect("verified body within budget must open a stream");
        let active = Cx::detached_cancel_context();
        let first = stream.next_chunk(&active);
        assert!(matches!(
            first,
            Outcome::Ok(Some(chunk)) if chunk.bytes == b"pay" && chunk.offset == 0
        ));
        let cancelled = Cx::detached_cancel_context();
        cancelled.cancel_with(CancelKind::User, Some("fabric stream test"));
        assert!(matches!(
            stream.next_chunk(&cancelled),
            Outcome::Cancelled(_)
        ));
        assert_quiescent(ledger);
    }

    #[test]
    fn open_verified_stream_runs_runtime_blocking_read_then_emits_verified_chunks() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let object = object(b"payload");
        let ledger = ledger();
        fabric
            .put_if_absent(object.clone(), admission(&ledger, &object))
            .expect("local placement must succeed");

        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .expect("test runtime must build");
        let seed = runtime
            .request_cx_with_budget(Budget::new().with_poll_quota(1_024).with_cost_quota(1_024));
        let cx = runtime.request_cx_with_budget(seed.budget_for_timeout(Duration::from_secs(1)));
        let mut stream = match runtime.block_on(fabric.open_verified_stream(
            &cx,
            object.identity(),
            VerifiedStreamBudget::new(7, 3).expect("finite stream budget must be valid"),
        )) {
            Outcome::Ok(stream) => stream,
            outcome => {
                panic!("runtime-owned blocking read must open a verified stream: {outcome:?}")
            }
        };
        assert!(matches!(
            stream.next_chunk(&cx),
            Outcome::Ok(Some(chunk)) if chunk.bytes == b"pay" && chunk.offset == 0
        ));
        assert!(matches!(
            stream.next_chunk(&cx),
            Outcome::Ok(Some(chunk)) if chunk.bytes == b"loa" && chunk.offset == 3
        ));
        assert!(matches!(
            stream.next_chunk(&cx),
            Outcome::Ok(Some(chunk)) if chunk.bytes == b"d" && chunk.offset == 6
        ));
        assert!(matches!(stream.next_chunk(&cx), Outcome::Ok(None)));
        drop(cx);
        drop(seed);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
        assert_quiescent(ledger);
    }

    #[test]
    fn open_verified_stream_refuses_a_cancelled_runtime_request_before_spawn() {
        let root = TestRoot::new();
        let fabric = fabric(root.path());
        let runtime = RuntimeBuilder::current_thread()
            .blocking_threads(1, 1)
            .build()
            .expect("test runtime must build");
        let seed = runtime
            .request_cx_with_budget(Budget::new().with_poll_quota(1_024).with_cost_quota(1_024));
        let cx = runtime.request_cx_with_budget(seed.budget_for_timeout(Duration::from_secs(1)));
        cx.cancel_with(CancelKind::User, Some("cancel before local stream open"));
        assert!(matches!(
            runtime.block_on(fabric.open_verified_stream(
                &cx,
                object(b"payload").identity(),
                VerifiedStreamBudget::new(7, 3).expect("finite stream budget must be valid"),
            )),
            Outcome::Cancelled(_)
        ));
        drop(cx);
        drop(seed);
        assert!(runtime.shutdown_timeout(Duration::from_secs(1)));
    }

    #[test]
    fn full_crash_matrix_leaves_only_absent_or_complete_immutable_objects() {
        for point in [
            LocalCrashPoint::BeforeStageWrite,
            LocalCrashPoint::AfterStageWrite,
            LocalCrashPoint::AfterStageSync,
            LocalCrashPoint::BeforeImmutablePublish,
            LocalCrashPoint::AfterImmutablePublish,
            LocalCrashPoint::AfterPublishDirectorySync,
            LocalCrashPoint::BeforeStageCleanup,
        ] {
            let root = TestRoot::new();
            let object = object(b"payload");
            let crashing = fabric_with_crash(root.path(), point);
            let ledger = ledger();
            match crashing.put_if_absent(object.clone(), admission(&ledger, &object)) {
                Err(StoreRefusal::StorageIo { operation, kind }) => {
                    assert_eq!(kind, std::io::ErrorKind::Interrupted);
                    if point == LocalCrashPoint::BeforeStageCleanup {
                        assert_eq!(
                            operation,
                            StorageOperation::RemoveBody,
                            "cleanup follows a durable publish and must never report publication failure"
                        );
                    }
                }
                other => panic!(
                    "crash point {point:?} must return an interrupted storage error, got {other:?}"
                ),
            }
            assert_quiescent(ledger);
            let reopened = fabric(root.path());
            match reopened.read_whole(object.identity()) {
                Err(StoreRefusal::ObjectAbsent) => {}
                Ok(whole) => assert_eq!(whole.object, object),
                Err(error) => panic!(
                    "crash point {point:?} exposed neither absence nor the exact immutable body: {error}"
                ),
            }
            assert_staging_is_empty(&reopened);
        }
    }

    #[test]
    fn returned_immutable_body_failure_releases_its_stage_file() {
        let root = TestRoot::new();
        let crashing = fabric_with_crash(root.path(), LocalCrashPoint::BeforeImmutablePublish);
        let final_path = crashing.root().join("test").join("body");

        assert_eq!(
            crashing.write_immutable_bytes(
                &final_path,
                b"body",
                StorageOperation::PublishImmutableBody,
            ),
            Err(StoreRefusal::StorageIo {
                operation: StorageOperation::PublishImmutableBody,
                kind: std::io::ErrorKind::Interrupted,
            })
        );
        assert_staging_is_empty(&crashing);
        assert!(
            !final_path.exists(),
            "the pre-publish interruption must not expose an immutable body"
        );
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
