//! Deferred custody of a verified streamed blob. No immutable name is linked
//! until the consuming publication call reauthenticates the owned private file.

use super::{
    AdmissionAbortReason, AdmittedObject, GitOid, Grade, ImmutableWrite, LocalCrashPoint,
    LocalFilesystemFabric, ObjectAdmission, ObjectAdmissionPermit, ObjectClass, ObjectEnvelope,
    PlacementAdmission, PlacementAttemptError, PlacementReceipt, PublicationState, PutIfAbsent,
    ReservedObligation, ResourceVector, StageFile, StorageOperation, StoreRefusal,
    StructureVerdict, VerifiedObject, blob_stream, blob_write, bounded_read, fs,
    settle_admission_abort, storage_error, sync_directory,
};
use fgit_crypto::DigestHasher;
use std::io::Read;
use std::path::Path;

use blob_write::{PreparedBlob, checkpoint, chunk_buffer, read_some};

/// A synced, closed private blob and its still-reserved admission resources.
///
/// This owns no payload or open descriptor and grants no placement receipt or
/// repository authority. Publication reauthenticates the original envelope,
/// native identity and strong payload commitment. Explicit abandonment removes
/// only the owned file and reports cleanup failures; drop also aborts its
/// reservation and attempts the same cleanup.
///
/// The operator must keep the fabric root and its ancestors stable. This local
/// profile uses Unix regular-file identity; other platforms return a typed
/// unsupported refusal before reading a source.
#[must_use = "a synced blob holds private custody until published or abandoned"]
pub struct SyncedBlob {
    envelope: ObjectEnvelope,
    custody: Option<BlobCustody>,
}

struct BlobCustody {
    stage: PrivateBlobStage,
    reserved: ReservedObligation<ObjectAdmissionPermit>,
    actual: ResourceVector,
    placement: PlacementReceipt,
    evidence: AdmittedObject,
}

impl std::fmt::Debug for SyncedBlob {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyncedBlob")
            .field("identity", &self.identity())
            .field("payload_bytes", &self.envelope.declared_length())
            .finish_non_exhaustive()
    }
}

impl SyncedBlob {
    /// Native Git identity of this private candidate.
    #[must_use]
    pub const fn identity(&self) -> GitOid {
        self.envelope.object_identity()
    }

    /// Read an owned candidate without publishing it, under an independent
    /// payload ceiling. None means only that this owner has another identity.
    /// Missing, changed, oversized or corrupt owned data always refuses, even
    /// when an immutable copy has appeared meanwhile.
    ///
    /// Every byte is checked against the original envelope. No descriptor or
    /// payload is retained by this owner after the read; callers own cancellation checkpoints
    /// before and after this synchronous, bounded operation.
    pub fn read_object_bounded(
        &self,
        fabric: &LocalFilesystemFabric,
        identity: GitOid,
        maximum_payload_bytes: u64,
    ) -> Result<Option<VerifiedObject>, StoreRefusal> {
        if identity != self.identity() {
            return Ok(None);
        }
        let custody = self.require_fabric(fabric)?;
        check_payload_bound(&self.envelope, maximum_payload_bytes)?;
        let mut payload = Vec::new();
        custody.stage.authenticate(
            fabric,
            &self.envelope,
            maximum_payload_bytes,
            &mut || true,
            &mut |bytes| {
                // Allocation follows checked framing, original envelope and
                // this read's payload limit, never an unchecked file length.
                if payload.capacity() == 0 {
                    payload
                        .try_reserve_exact(
                            usize::try_from(self.envelope.declared_length())
                                .map_err(|_| StoreRefusal::LengthOverflow)?,
                        )
                        .map_err(|_| allocation_refusal())?;
                }
                payload.extend_from_slice(bytes);
                Ok(())
            },
        )?;
        Ok(Some(VerifiedObject::new(self.envelope.clone(), payload)?))
    }

    /// Settle the reservation and remove this private file without linking it.
    /// A replaced path is refused and left untouched.
    pub fn abandon(mut self) -> Result<(), StoreRefusal> {
        self.abandon_inner()
    }

    fn require_fabric(&self, fabric: &LocalFilesystemFabric) -> Result<&BlobCustody, StoreRefusal> {
        if self.envelope.namespace() != fabric.namespace {
            return Err(StoreRefusal::NamespaceMismatch);
        }
        let custody = self
            .custody
            .as_ref()
            .ok_or(StoreRefusal::MalformedStoredObject)?;
        if custody.stage.path().parent() != Some(fabric.staging_dir().as_path())
            || fabric.placement_for(custody.reserved.reservation().staging)? != custody.placement
        {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        Ok(custody)
    }

    fn abandon_inner(&mut self) -> Result<(), StoreRefusal> {
        let Some(mut custody) = self.custody.take() else {
            return Ok(());
        };
        let cleanup = custody.stage.cleanup();
        settle_admission_abort(
            custody.reserved,
            AdmissionAbortReason::PlacementWriteFailed,
            &custody.actual,
        )?;
        cleanup
    }
}

impl Drop for SyncedBlob {
    fn drop(&mut self) {
        // This is an explicit abort, not a dropped ReservedObligation. Its
        // fallback settlement also disarms the grant on a settlement refusal.
        let _abandoned = self.abandon_inner();
    }
}

impl LocalFilesystemFabric {
    /// Verify, sync and close a bounded blob stream while retaining private
    /// custody. This performs the same framing, native/strong hash and exact
    /// EOF checks as immediate streaming placement, including on duplicates.
    /// This call links no immutable name and returns no placement receipt.
    ///
    /// The owner keeps the reservation until publication or abandonment; a
    /// failed staging call settles it before returning. Payload I/O and durability
    /// steps are bracketed by the caller's cancellation/work checkpoint.
    pub fn stage_synced_blob_stream_if_absent(
        &self,
        envelope: ObjectEnvelope,
        input: &mut dyn Read,
        maximum_payload_bytes: u64,
        admission: PlacementAdmission<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<SyncedBlob, StoreRefusal> {
        let (ledger, budget) = admission.into_parts();
        let prepared = self
            .prepare_blob_stream(&envelope, maximum_payload_bytes, live)
            .and_then(|prepared| {
                ensure_identity_supported()?;
                Ok(prepared)
            });
        let PreparedBlob {
            encoded,
            staging,
            placement,
            strong,
        } = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        };
        let length = envelope.declared_length();
        let actual = ResourceVector::from_grades(&[(Grade::Bytes, length), (Grade::Objects, 1)]);
        if let Some(error) = budget.amount().first_deficit(&actual) {
            let _released = budget.release();
            return Err(StoreRefusal::Resource(error));
        }
        let reservation = ObjectAdmission {
            class: ObjectClass::GitObject,
            declared_len: length,
            staging,
        };
        let reserved = ledger.reserve::<ObjectAdmissionPermit>(reservation, budget)?;
        if let Err(error) = reserved.can_settle(&actual) {
            settle_admission_abort(
                reserved,
                AdmissionAbortReason::QuotaWithdrawn,
                &ResourceVector::ZERO,
            )?;
            return Err(StoreRefusal::Settlement(error));
        }
        let written: Result<PrivateBlobStage, PlacementAttemptError> = (|| {
            checkpoint(live).map_err(before_body)?;
            let stage = self.fresh_stage().map_err(before_body)?;
            // Capture the descriptor's identity before any caller/source
            // callback can replace the private pathname.
            let mut stage = PrivateBlobStage::new(stage).map_err(before_body)?;
            self.write_blob_stage_contents(&mut stage.stage, &envelope, &encoded, input, live)?;
            stage.seal().map_err(|refusal| PlacementAttemptError {
                refusal,
                body_write_started: true,
            })?;
            Ok(stage)
        })();
        let stage = match written {
            Ok(stage) => stage,
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &if error.body_write_started {
                        actual
                    } else {
                        ResourceVector::ZERO
                    },
                )?;
                return Err(error.refusal);
            }
        };
        let evidence = match AdmittedObject::verified(
            &reservation,
            envelope.object_identity(),
            strong,
            length,
            StructureVerdict::Verified,
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &actual,
                )?;
                return Err(error.into());
            }
        };
        Ok(SyncedBlob {
            envelope,
            custody: Some(BlobCustody {
                stage,
                reserved,
                actual,
                placement,
                evidence,
            }),
        })
    }

    /// Reauthenticate and publish one privately synced blob. Concurrent
    /// existing names are authenticated and compared in bounded chunks; a
    /// different envelope or body is never overwritten or accepted as dedup.
    ///
    /// No success receipt escapes before directory sync and settlement. A
    /// refusal after the hard link can leave verified unreferenced placement;
    /// it never establishes repository authority or proves non-publication.
    pub fn publish_synced_blob(
        &self,
        mut owner: SyncedBlob,
        live: &mut impl FnMut() -> bool,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        let published = self.publish_private_blob(&mut owner, live);
        let mut custody = owner
            .custody
            .take()
            .ok_or(StoreRefusal::MalformedStoredObject)?;
        let cleanup = custody.stage.cleanup();
        match published.and_then(|result| cleanup.map(|()| result)) {
            Err(error) => {
                settle_admission_abort(
                    custody.reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &custody.actual,
                )?;
                Err(error)
            }
            Ok(ImmutableWrite::AlreadyPresent) => {
                settle_admission_abort(
                    custody.reserved,
                    AdmissionAbortReason::Superseded,
                    &custody.actual,
                )?;
                Ok(PutIfAbsent::AlreadyPresent {
                    placement: custody.placement,
                    epochs: PublicationState::new(true, false, true),
                })
            }
            Ok(ImmutableWrite::Created) => {
                match custody
                    .reserved
                    .commit_internal(custody.evidence, &custody.actual)
                {
                    Ok(_settled) => Ok(PutIfAbsent::Created {
                        placement: custody.placement,
                        epochs: PublicationState::new(true, false, true),
                    }),
                    Err(refused) => {
                        let error = refused.error();
                        settle_admission_abort(
                            refused.into_obligation(),
                            AdmissionAbortReason::PlacementWriteFailed,
                            &custody.actual,
                        )?;
                        Err(StoreRefusal::Settlement(error))
                    }
                }
            }
        }
    }

    fn publish_private_blob(
        &self,
        owner: &mut SyncedBlob,
        live: &mut impl FnMut() -> bool,
    ) -> Result<ImmutableWrite, StoreRefusal> {
        checkpoint(live)?;
        let custody = owner.require_fabric(self)?;
        custody
            .reserved
            .can_settle(&custody.actual)
            .map_err(StoreRefusal::Settlement)?;
        let encoded_length = custody.stage.authenticate(
            self,
            &owner.envelope,
            owner.envelope.declared_length(),
            live,
            &mut |_| Ok(()),
        )?;
        let target = self.object_path(owner.identity());
        let parent = target.parent().ok_or(StoreRefusal::MalformedStoredObject)?;
        checkpoint(live)?;
        self.create_directory(parent)?;
        checkpoint(live)?;
        self.crash_if(LocalCrashPoint::BeforeImmutablePublish)?;
        let custody = owner
            .custody
            .as_mut()
            .ok_or(StoreRefusal::MalformedStoredObject)?;
        // No caller checkpoint separates this final identity/version check
        // from linking the private name. Stable ancestors remain a precondition.
        custody.stage.check()?;
        let result = match fs::hard_link(custody.stage.path(), &target) {
            Ok(()) => {
                custody.stage.record_link()?;
                self.crash_if(LocalCrashPoint::AfterImmutablePublish)?;
                ImmutableWrite::Created
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.compare_blob_stage(
                    &custody.stage.stage,
                    &owner.envelope,
                    encoded_length,
                    live,
                )?;
                ImmutableWrite::AlreadyPresent
            }
            Err(error) => {
                return Err(storage_error(StorageOperation::PublishImmutableBody, error));
            }
        };
        checkpoint(live)?;
        sync_directory(parent)?;
        self.crash_if(LocalCrashPoint::AfterPublishDirectorySync)?;
        checkpoint(live)?;
        self.crash_if(LocalCrashPoint::BeforeStageCleanup)?;
        custody.stage.check()?;
        Ok(result)
    }
}

const fn before_body(refusal: StoreRefusal) -> PlacementAttemptError {
    PlacementAttemptError {
        refusal,
        body_write_started: false,
    }
}

const fn check_payload_bound(envelope: &ObjectEnvelope, maximum: u64) -> Result<(), StoreRefusal> {
    let offered = envelope.declared_length();
    if offered > maximum {
        Err(StoreRefusal::StreamingBudgetExceeded { offered, maximum })
    } else {
        Ok(())
    }
}

const fn allocation_refusal() -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation: StorageOperation::ReadBody,
        kind: std::io::ErrorKind::OutOfMemory,
    }
}

/// The pathname alone is not custody: retain the file identity from the
/// originally opened descriptor, then a sealed version once writes finish.
struct PrivateBlobStage {
    stage: StageFile,
    identity: FileIdentity,
    sealed: Option<FileVersion>,
}

impl PrivateBlobStage {
    fn new(stage: StageFile) -> Result<Self, StoreRefusal> {
        let metadata = stage
            .file
            .as_ref()
            .ok_or(StoreRefusal::MalformedStoredObject)?
            .metadata()
            .map_err(|error| storage_error(StorageOperation::WriteStage, error))?;
        let identity = FileIdentity::of(&metadata)?;
        Ok(Self {
            stage,
            identity,
            sealed: None,
        })
    }

    fn path(&self) -> &Path {
        self.stage.path()
    }

    fn metadata(&self) -> Result<fs::Metadata, StoreRefusal> {
        let metadata = fs::symlink_metadata(self.path()).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StoreRefusal::ObjectAbsent
            } else {
                storage_error(StorageOperation::ReadBody, error)
            }
        })?;
        self.check_identity(&metadata)?;
        Ok(metadata)
    }

    fn check_identity(&self, metadata: &fs::Metadata) -> Result<(), StoreRefusal> {
        if FileIdentity::of(metadata)? != self.identity {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        Ok(())
    }

    fn check_metadata(&self, metadata: &fs::Metadata) -> Result<(), StoreRefusal> {
        self.check_identity(metadata)?;
        if self.sealed != Some(FileVersion::of(metadata)?) {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        Ok(())
    }

    fn seal(&mut self) -> Result<(), StoreRefusal> {
        self.sealed = Some(FileVersion::of(&self.metadata()?)?);
        Ok(())
    }

    fn check(&self) -> Result<(), StoreRefusal> {
        self.check_metadata(&self.metadata()?)
    }

    fn record_link(&mut self) -> Result<(), StoreRefusal> {
        let version = FileVersion::of(&self.metadata()?)?;
        let before = self.sealed.ok_or(StoreRefusal::MalformedStoredObject)?;
        // A hard link changes ctime, but does not write the file or change its
        // length/mtime. Keep detecting edits made after authentication.
        if before.length != version.length || before.modified != version.modified {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        self.sealed = Some(version);
        Ok(())
    }

    fn authenticate(
        &self,
        fabric: &LocalFilesystemFabric,
        original: &ObjectEnvelope,
        maximum_payload_bytes: u64,
        live: &mut impl FnMut() -> bool,
        consume: &mut impl FnMut(&[u8]) -> Result<(), StoreRefusal>,
    ) -> Result<usize, StoreRefusal> {
        check_payload_bound(original, maximum_payload_bytes)?;
        checkpoint(live)?;
        self.check()?;
        let opened = bounded_read::open_envelope(
            self.path(),
            fabric.max_stored_object_bytes,
            fabric.envelope_limits.max_envelope_bytes,
        );
        checkpoint(live)?;
        let (mut file, encoded, offered) = opened?;
        self.check_metadata(
            &file
                .metadata()
                .map_err(|error| storage_error(StorageOperation::ReadBody, error))?,
        )?;
        let envelope = ObjectEnvelope::decode(&encoded, &fabric.envelope_limits)?;
        if envelope.namespace() != fabric.namespace {
            return Err(StoreRefusal::NamespaceMismatch);
        }
        if &envelope != original {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        if offered != original.declared_length() {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        let mut native = blob_stream::NativeHash::new(original.object_identity(), offered);
        let mut strong = blob_stream::strong_hasher(offered)?;
        let mut buffer = chunk_buffer(StorageOperation::ReadBody)?;
        let mut remaining = offered;
        while remaining != 0 {
            let request = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| StoreRefusal::LengthOverflow)?;
            let count = read_some(&mut file, &mut buffer[..request], live)?;
            if count == 0 {
                return Err(StoreRefusal::MalformedStoredObject);
            }
            native.update(&buffer[..count])?;
            strong.update(&buffer[..count]);
            consume(&buffer[..count])?;
            remaining -= count as u64;
        }
        if read_some(&mut file, &mut [0], live)? != 0 {
            return Err(StoreRefusal::MalformedStoredObject);
        }
        if native.finish()? != original.object_identity() {
            return Err(StoreRefusal::NativeObjectIdentityMismatch);
        }
        if strong.finish() != original.payload_commitment() {
            return Err(StoreRefusal::PayloadCommitmentMismatch);
        }
        checkpoint(live)?;
        self.check_metadata(
            &file
                .metadata()
                .map_err(|error| storage_error(StorageOperation::ReadBody, error))?,
        )?;
        self.check()?;
        Ok(encoded.len())
    }

    fn cleanup(&mut self) -> Result<(), StoreRefusal> {
        self.stage.close();
        if self.stage.path.as_os_str().is_empty() {
            return Ok(());
        }
        let result = match self.metadata() {
            Ok(_) => fs::remove_file(self.path())
                .map_err(|error| storage_error(StorageOperation::RemoveBody, error)),
            Err(StoreRefusal::ObjectAbsent) => Ok(()),
            Err(error) => Err(error),
        };
        // Disarm StageFile's unconditional path cleanup even on refusal: a
        // foreign replacement must never be unlinked by either destructor.
        self.stage.path.clear();
        result
    }
}

impl Drop for PrivateBlobStage {
    fn drop(&mut self) {
        let _cleanup = self.cleanup();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(metadata: &fs::Metadata) -> Result<Self, StoreRefusal> {
        if !metadata.file_type().is_file() {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            Err(unsupported_identity())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileVersion {
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl FileVersion {
    fn of(metadata: &fs::Metadata) -> Result<Self, StoreRefusal> {
        if !metadata.file_type().is_file() {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                length: metadata.len(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
            })
        }
        #[cfg(not(unix))]
        {
            let _metadata = metadata;
            Err(unsupported_identity())
        }
    }
}

const fn ensure_identity_supported() -> Result<(), StoreRefusal> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(unsupported_identity())
    }
}

const fn unsupported_identity() -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation: StorageOperation::WriteStage,
        kind: std::io::ErrorKind::Unsupported,
    }
}

#[cfg(all(test, unix))]
#[path = "local_synced_blob/tests.rs"]
mod tests;
