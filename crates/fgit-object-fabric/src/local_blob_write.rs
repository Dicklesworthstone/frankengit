//! Bounded blob admission through the ordinary immutable object-file format.
//! Source bytes remain in private staging until both original commitments and
//! exact EOF verify. Placement alone never publishes repository visibility.

use super::{
    AdmissionAbandoned, AdmissionAbortReason, AdmittedObject, CANONICAL_CODEC_VERSION, Digest,
    DigestBytes, ENVELOPE_SCHEMA, File, Grade, ImmutableWrite, LocalCrashPoint,
    LocalFilesystemFabric, OBJECT_MAGIC, ObjectAdmission, ObjectAdmissionPermit, ObjectClass,
    ObjectEnvelope, ObjectEnvelopeId, ObjectKind, PlacementAdmission, PlacementAttemptError,
    PlacementReceipt, PublicationState, PutIfAbsent, ResourceVector, StageFile, StorageOperation,
    StoreRefusal, StructureVerdict, Write, blob_stream, fs, settle_admission_abort, storage_error,
    sync_directory,
};
use std::io::{Read, Seek, SeekFrom};

use fgit_crypto::DigestHasher;

pub(super) const CHUNK_BYTES: usize = 64 * 1024;

pub(super) struct PreparedBlob {
    pub(super) encoded: Vec<u8>,
    pub(super) staging: ObjectEnvelopeId,
    pub(super) placement: PlacementReceipt,
    pub(super) strong: Digest,
}

impl LocalFilesystemFabric {
    /// Authenticate and immutably place a blob without buffering its payload.
    ///
    /// The envelope is an untrusted claim. Native Git identity, the registered
    /// strong payload commitment, exact length and EOF are independently checked
    /// before the staged file is synced and linked. An existing object is
    /// reauthenticated and compared byte-for-byte, including its envelope.
    /// Every resource grant is released or explicitly settled on every result.
    /// The caller keeps the storage root stable and owns cancellation; this
    /// function checks it around each bounded read/write and durability step.
    /// A refusal after linking can leave a verified unreferenced object, and
    /// never establishes repository publication or non-publication.
    pub fn put_blob_stream_if_absent(
        &self,
        envelope: ObjectEnvelope,
        input: &mut dyn Read,
        maximum_payload_bytes: u64,
        admission: PlacementAdmission<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        let (ledger, budget) = admission.into_parts();
        let prepared = self.prepare_blob_stream(&envelope, maximum_payload_bytes, live);
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
            let _settled = reserved.abort_unused(AdmissionAbandoned {
                reason: AdmissionAbortReason::QuotaWithdrawn,
            });
            return Err(StoreRefusal::Settlement(error));
        }
        let stage = match self.write_blob_stage(&envelope, &encoded, input, live) {
            Ok(stage) => stage,
            Err(error) => {
                let spent = if error.body_write_started {
                    actual
                } else {
                    ResourceVector::ZERO
                };
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &spent,
                )?;
                return Err(error.refusal);
            }
        };
        match self.publish_blob_stage(stage, &envelope, encoded.len(), live) {
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &actual,
                )?;
                Err(error)
            }
            Ok(ImmutableWrite::AlreadyPresent) => {
                settle_admission_abort(reserved, AdmissionAbortReason::Superseded, &actual)?;
                Ok(PutIfAbsent::AlreadyPresent {
                    placement,
                    epochs: PublicationState::new(true, false, true),
                })
            }
            Ok(ImmutableWrite::Created) => {
                let receipt = match AdmittedObject::verified(
                    &reservation,
                    envelope.object_identity(),
                    strong,
                    length,
                    StructureVerdict::Verified,
                ) {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        settle_admission_abort(
                            reserved,
                            AdmissionAbortReason::PlacementWriteFailed,
                            &actual,
                        )?;
                        return Err(StoreRefusal::from(error));
                    }
                };
                match reserved.commit_internal(receipt, &actual) {
                    Ok(_settled) => Ok(PutIfAbsent::Created {
                        placement,
                        epochs: PublicationState::new(true, false, true),
                    }),
                    Err(refused) => {
                        let error = refused.error();
                        settle_admission_abort(
                            refused.into_obligation(),
                            AdmissionAbortReason::PlacementWriteFailed,
                            &actual,
                        )?;
                        Err(StoreRefusal::Settlement(error))
                    }
                }
            }
        }
    }

    pub(super) fn prepare_blob_stream(
        &self,
        envelope: &ObjectEnvelope,
        maximum_payload_bytes: u64,
        live: &mut impl FnMut() -> bool,
    ) -> Result<PreparedBlob, StoreRefusal> {
        checkpoint(live)?;
        if envelope.namespace() != self.namespace {
            return Err(StoreRefusal::NamespaceMismatch);
        }
        if envelope.object_kind() != ObjectKind::Blob {
            return Err(StoreRefusal::NativeObjectIdentityMismatch);
        }
        if maximum_payload_bytes == 0 {
            return Err(StoreRefusal::InvalidStreamingBudget);
        }
        let length = envelope.declared_length();
        if length > maximum_payload_bytes {
            return Err(StoreRefusal::StreamingBudgetExceeded {
                offered: length,
                maximum: maximum_payload_bytes,
            });
        }
        // Inspect the encoded length before allocating: the envelope may
        // have been constructed under a much larger foreign profile.
        if envelope.encoded_len()? > self.envelope_limits.max_envelope_bytes {
            return Err(StoreRefusal::Fabric(crate::FabricError::EnvelopeTooLarge));
        }
        let encoded = envelope.encode()?;
        // Envelopes can be constructed under another caller's limits.
        // Reapply this backend's envelope profile before any payload I/O.
        ObjectEnvelope::decode(&encoded, &self.envelope_limits)?;
        let stored = 8_u64
            .checked_add(encoded.len() as u64)
            .and_then(|n| n.checked_add(length))
            .ok_or(StoreRefusal::LengthOverflow)?;
        if stored > self.max_stored_object_bytes {
            return Err(StoreRefusal::StoredObjectTooLarge {
                offered: stored,
                maximum: self.max_stored_object_bytes,
            });
        }
        let id = fgit_crypto::internal_object_id(
            fgit_crypto::IdentityDomain::ObjectEnvelope,
            ENVELOPE_SCHEMA,
            CANONICAL_CODEC_VERSION,
            &encoded,
        );
        let id = ObjectEnvelopeId::from_internal_object_id(id)?;
        let placement = self.placement_for(id)?;
        let algorithm = fgit_crypto::IdentityDomain::GitPayloadCommitment.algorithm();
        let strong = Digest::new_checked(
            algorithm.id(),
            DigestBytes::try_new(&envelope.payload_commitment())?,
            algorithm.digest_len(),
        )?;
        Ok(PreparedBlob {
            encoded,
            staging: id,
            placement,
            strong,
        })
    }

    fn write_blob_stage(
        &self,
        envelope: &ObjectEnvelope,
        encoded: &[u8],
        input: &mut dyn Read,
        live: &mut impl FnMut() -> bool,
    ) -> Result<StageFile, PlacementAttemptError> {
        let mut stage = checkpoint(live)
            .and_then(|()| self.fresh_stage())
            .map_err(|refusal| PlacementAttemptError {
                refusal,
                body_write_started: false,
            })?;
        self.write_blob_stage_contents(&mut stage, envelope, encoded, input, live)?;
        Ok(stage)
    }

    pub(super) fn write_blob_stage_contents(
        &self,
        stage: &mut StageFile,
        envelope: &ObjectEnvelope,
        encoded: &[u8],
        input: &mut dyn Read,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), PlacementAttemptError> {
        let mut started = false;
        let result = (|| {
            let mut native = blob_stream::NativeHash::new(
                envelope.object_identity(),
                envelope.declared_length(),
            );
            let mut strong = blob_stream::strong_hasher(envelope.declared_length())?;
            let encoded_length =
                u32::try_from(encoded.len()).map_err(|_| StoreRefusal::LengthOverflow)?;
            self.crash_if(LocalCrashPoint::BeforeStageWrite)?;
            checkpoint(live)?;
            started = true;
            write_stage(stage, OBJECT_MAGIC, live)?;
            write_stage(stage, &encoded_length.to_be_bytes(), live)?;
            write_stage(stage, encoded, live)?;
            let mut remaining = envelope.declared_length();
            let mut buffer = chunk_buffer(StorageOperation::WriteStage)?;
            while remaining != 0 {
                let capacity = remaining.min(CHUNK_BYTES as u64) as usize;
                let count = read_some(input, &mut buffer[..capacity], live)?;
                if count == 0 {
                    return Err(StoreRefusal::MalformedStoredObject);
                }
                native.update(&buffer[..count])?;
                strong.update(&buffer[..count]);
                checkpoint(live)?;
                write_stage(stage, &buffer[..count], live)?;
                checkpoint(live)?;
                remaining -= count as u64;
            }
            // Force a source reader's own terminal authentication, and refuse
            // a source longer than the promised body even on an existing key.
            if read_some(input, &mut [0], live)? != 0 {
                return Err(StoreRefusal::MalformedStoredObject);
            }
            if native.finish()? != envelope.object_identity() {
                return Err(StoreRefusal::NativeObjectIdentityMismatch);
            }
            if strong.finish() != envelope.payload_commitment() {
                return Err(StoreRefusal::PayloadCommitmentMismatch);
            }
            checkpoint(live)?;
            self.crash_if(LocalCrashPoint::AfterStageWrite)?;
            stage
                .sync_all()
                .map_err(|e| storage_error(StorageOperation::SyncStage, e))?;
            checkpoint(live)?;
            self.crash_if(LocalCrashPoint::AfterStageSync)?;
            stage.close();
            Ok(())
        })();
        result.map_err(|refusal| PlacementAttemptError {
            refusal,
            body_write_started: started,
        })
    }

    fn publish_blob_stage(
        &self,
        stage: StageFile,
        envelope: &ObjectEnvelope,
        encoded_length: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<ImmutableWrite, StoreRefusal> {
        checkpoint(live)?;
        let target = self.object_path(envelope.object_identity());
        let parent = target.parent().ok_or(StoreRefusal::MalformedStoredObject)?;
        self.create_directory(parent)?;
        checkpoint(live)?;
        self.crash_if(LocalCrashPoint::BeforeImmutablePublish)?;
        let result = match fs::hard_link(stage.path(), &target) {
            Ok(()) => {
                self.crash_if(LocalCrashPoint::AfterImmutablePublish)?;
                ImmutableWrite::Created
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.compare_blob_stage(&stage, envelope, encoded_length, live)?;
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
        Ok(result)
    }

    pub(super) fn compare_blob_stage(
        &self,
        stage: &StageFile,
        envelope: &ObjectEnvelope,
        encoded_length: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), StoreRefusal> {
        checkpoint(live)?;
        let mut stored =
            self.open_blob_stream_bounded(envelope.object_identity(), envelope.declared_length())?;
        if stored.envelope() != envelope {
            return Err(StoreRefusal::StoredObjectIdentityCollision);
        }
        let mut staged =
            File::open(stage.path()).map_err(|e| storage_error(StorageOperation::ReadBody, e))?;
        let payload_offset = 8_u64
            .checked_add(encoded_length as u64)
            .ok_or(StoreRefusal::LengthOverflow)?;
        staged
            .seek(SeekFrom::Start(payload_offset))
            .map_err(|e| storage_error(StorageOperation::ReadBody, e))?;
        let mut actual = chunk_buffer(StorageOperation::ReadBody)?;
        let mut expected = chunk_buffer(StorageOperation::ReadBody)?;
        loop {
            checkpoint(live)?;
            let count = match stored.read_tentative(&mut actual) {
                Err(StoreRefusal::StorageIo {
                    kind: std::io::ErrorKind::Interrupted,
                    ..
                }) => continue,
                other => other?,
            };
            checkpoint(live)?;
            if count == 0 {
                if read_some(&mut staged, &mut expected[..1], live)? != 0 {
                    return Err(StoreRefusal::StoredObjectIdentityCollision);
                }
                return Ok(());
            }
            let mut read = 0;
            while read != count {
                let n = read_some(&mut staged, &mut expected[read..count], live)?;
                if n == 0 {
                    return Err(StoreRefusal::StoredObjectIdentityCollision);
                }
                read += n;
            }
            if actual[..count] != expected[..count] {
                return Err(StoreRefusal::StoredObjectIdentityCollision);
            }
        }
    }
}

pub(super) fn chunk_buffer(operation: StorageOperation) -> Result<Vec<u8>, StoreRefusal> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(CHUNK_BYTES)
        .map_err(|_| StoreRefusal::StorageIo {
            operation,
            kind: std::io::ErrorKind::OutOfMemory,
        })?;
    buffer.resize(CHUNK_BYTES, 0_u8);
    Ok(buffer)
}

pub(super) fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), StoreRefusal> {
    if live() {
        Ok(())
    } else {
        Err(StoreRefusal::RuntimeCheckpointRejected)
    }
}

fn write_stage(
    stage: &mut StageFile,
    mut bytes: &[u8],
    live: &mut impl FnMut() -> bool,
) -> Result<(), StoreRefusal> {
    while !bytes.is_empty() {
        checkpoint(live)?;
        let capacity = bytes.len().min(CHUNK_BYTES);
        let result = stage
            .file
            .as_mut()
            .ok_or(StoreRefusal::MalformedStoredObject)?
            .write(&bytes[..capacity]);
        checkpoint(live)?;
        match result {
            Ok(0) => {
                return Err(StoreRefusal::StorageIo {
                    operation: StorageOperation::WriteStage,
                    kind: std::io::ErrorKind::WriteZero,
                });
            }
            Ok(count) if count <= capacity => bytes = &bytes[count..],
            Ok(_) => return Err(StoreRefusal::MalformedStoredObject),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(storage_error(StorageOperation::WriteStage, error)),
        }
    }
    Ok(())
}

pub(super) fn read_some(
    input: &mut dyn Read,
    output: &mut [u8],
    live: &mut impl FnMut() -> bool,
) -> Result<usize, StoreRefusal> {
    loop {
        checkpoint(live)?;
        let read = input.read(output);
        checkpoint(live)?;
        match read {
            Ok(count) if count <= output.len() => return Ok(count),
            Ok(_) => return Err(StoreRefusal::MalformedStoredObject),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(storage_error(StorageOperation::ReadBody, error)),
        }
    }
}

#[cfg(test)]
#[path = "local_blob_write/tests.rs"]
mod tests;
