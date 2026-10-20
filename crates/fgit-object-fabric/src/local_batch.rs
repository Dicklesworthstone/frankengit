//! Bounded group durability using the unchanged immutable object-file format.
//! No result escapes until every target directory is synced. Failed batches
//! may leave verified placement, never canonical visibility or success receipts.

use super::{
    AdmissionAbortReason, AdmittedObject, GitOid, Grade, ImmutableWrite, LocalCrashPoint,
    LocalFilesystemFabric, ObjectAdmission, ObjectAdmissionPermit, ObjectClass, PlacementAdmission,
    PlacementReceipt, PublicationState, PutIfAbsent, ReservedObligation, ResourceVector, StageFile,
    StoreRefusal, StructureVerdict, VerifiedObject, payload_identity, settle_admission_abort,
    sync_directory,
};
use fgit_resource::{BudgetGrant, ObligationLedger};
use std::collections::BTreeSet;

const MAX_BATCH_OBJECTS: usize = 256;
const MAX_BATCH_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

impl LocalFilesystemFabric {
    /// Place up to 256 identity-sorted objects and 64 MiB of payloads with one
    /// final directory sync per native hash domain, rather than per object.
    /// Each file is still synced before its immutable name is linked. The
    /// caller must keep the storage root and ancestors stable during the call.
    ///
    /// All objects and the complete resource grant are preflighted before I/O.
    /// Success receipts are returned together, after the durability fence and
    /// explicit settlement of every per-object obligation. A returned failure
    /// can leave verified unreferenced objects; it never authorizes publication.
    /// Cancellation is polled between bounded files and directory operations.
    /// Existing objects are reverified, including concurrent put-if-absent races.
    pub fn put_batch_if_absent(
        &self,
        objects: &[VerifiedObject],
        admission: PlacementAdmission<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Vec<PutIfAbsent>, StoreRefusal> {
        let (ledger, mut budget) = admission.into_parts();
        let mut pending = Vec::new();
        let staged = (|| {
            let required = self.preflight_batch(objects, live)?;
            if let Some(error) = budget.amount().first_deficit(&required) {
                return Err(StoreRefusal::Resource(error));
            }
            if objects.is_empty() {
                return Ok(());
            }
            // Bounded by the two native hash domains; no global directory cache.
            let mut directories = BTreeSet::new();
            batch_checkpoint(live)?;
            self.create_directory(&self.staging_dir())?;
            for object in objects {
                batch_checkpoint(live)?;
                let path = self.object_path(object.identity());
                let parent = path.parent().ok_or(StoreRefusal::MalformedStoredObject)?;
                if directories.insert(parent.to_path_buf()) {
                    self.create_directory(parent)?;
                }
                let amount = batch_resources((object.payload().len() as u64).max(1), 1);
                let grant = budget.split_off(&amount).map_err(StoreRefusal::Resource)?;
                pending.push(self.stage_batch_object(object, ledger, grant)?);
            }
            for directory in directories {
                batch_checkpoint(live)?;
                sync_directory(&directory)?;
            }
            self.crash_if(LocalCrashPoint::AfterPublishDirectorySync)?;
            self.crash_if(LocalCrashPoint::BeforeStageCleanup)?;
            batch_checkpoint(live)
        })();
        let _released = budget.release();
        if let Err(error) = staged {
            // Drain ALL prior reservations, even when one settlement refuses.
            let mut failure = None;
            for entry in pending {
                if let Err(error) = entry.abort() {
                    failure.get_or_insert(error);
                }
            }
            return Err(failure.unwrap_or(error));
        }
        let mut results = Vec::with_capacity(pending.len());
        let mut failure = None;
        for entry in pending {
            if failure.is_some() {
                if let Err(error) = entry.abort() {
                    failure = Some(error);
                }
            } else {
                match entry.commit() {
                    Ok(result) => results.push(result),
                    Err(error) => failure = Some(error),
                }
            }
        }
        failure.map_or(Ok(results), Err)
    }

    fn preflight_batch(
        &self,
        objects: &[VerifiedObject],
        live: &mut impl FnMut() -> bool,
    ) -> Result<ResourceVector, StoreRefusal> {
        batch_checkpoint(live)?;
        if objects.len() > MAX_BATCH_OBJECTS {
            return Err(StoreRefusal::TooManyEntries);
        }
        let mut bytes = 0_u64;
        let mut reserved_bytes = 0_u64;
        let mut previous: Option<GitOid> = None;
        for object in objects {
            batch_checkpoint(live)?;
            if object.envelope().namespace() != self.namespace {
                return Err(StoreRefusal::NamespaceMismatch);
            }
            if let Some(id) = previous {
                match id.cmp(&object.identity()) {
                    std::cmp::Ordering::Equal => return Err(StoreRefusal::DuplicateObjectIdentity),
                    std::cmp::Ordering::Greater => {
                        return Err(StoreRefusal::NonCanonicalObjectOrder);
                    }
                    std::cmp::Ordering::Less => {}
                }
            }
            previous = Some(object.identity());
            let payload = object.payload().len() as u64;
            reserved_bytes = reserved_bytes
                .checked_add(payload.max(1))
                .ok_or(StoreRefusal::LengthOverflow)?;
            let encoded = object.envelope().encode()?.len() as u64;
            let stored = payload
                .checked_add(encoded)
                .and_then(|n| n.checked_add(8))
                .ok_or(StoreRefusal::LengthOverflow)?;
            if stored > self.max_stored_object_bytes {
                return Err(StoreRefusal::StoredObjectTooLarge {
                    offered: stored,
                    maximum: self.max_stored_object_bytes,
                });
            }
            bytes = bytes
                .checked_add(payload)
                .ok_or(StoreRefusal::LengthOverflow)?;
            if bytes > MAX_BATCH_PAYLOAD_BYTES {
                return Err(StoreRefusal::StreamingBudgetExceeded {
                    offered: bytes,
                    maximum: MAX_BATCH_PAYLOAD_BYTES,
                });
            }
        }
        Ok(batch_resources(reserved_bytes, objects.len() as u64))
    }

    fn stage_batch_object(
        &self,
        object: &VerifiedObject,
        ledger: &ObligationLedger,
        budget: BudgetGrant,
    ) -> Result<PendingPlacement, StoreRefusal> {
        // Derive every fallible receipt field before reserving responsibility.
        let prepared = (|| {
            let id = Self::object_envelope_id(object)?;
            let placement = self.placement_for(id)?;
            match self.load_object(object.identity()) {
                Ok(existing) if existing == *object => return Ok((placement, None)),
                Ok(_) => return Err(StoreRefusal::StoredObjectIdentityCollision),
                Err(StoreRefusal::ObjectAbsent) => {}
                Err(error) => return Err(error),
            }
            let reservation = ObjectAdmission {
                class: ObjectClass::GitObject,
                declared_len: object.payload().len() as u64,
                staging: id,
            };
            let evidence = AdmittedObject::verified(
                &reservation,
                object.identity(),
                payload_identity(object.envelope().object_kind(), object.payload())?,
                reservation.declared_len,
                StructureVerdict::Verified,
            )?;
            Ok((placement, Some((reservation, evidence))))
        })();
        let (placement, reservation, evidence) = match prepared {
            Ok((placement, Some((reservation, evidence)))) => (placement, reservation, evidence),
            Ok((placement, None)) => {
                let _released = budget.release();
                return Ok(PendingPlacement::Existing(placement));
            }
            Err(error) => {
                let _released = budget.release();
                return Err(error);
            }
        };
        let actual = batch_resources(reservation.declared_len, 1);
        let reserved = ledger.reserve::<ObjectAdmissionPermit>(reservation, budget)?;
        if let Err(error) = reserved.can_settle(&actual) {
            settle_admission_abort(
                reserved,
                AdmissionAbortReason::QuotaWithdrawn,
                &ResourceVector::ZERO,
            )?;
            return Err(StoreRefusal::Settlement(error));
        }
        let stage = match self.write_object_stage_in(object, true) {
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
        let created = match self.link_object_stage(&stage, object) {
            Ok(ImmutableWrite::Created) => true,
            Ok(ImmutableWrite::AlreadyPresent) => false,
            Err(error) => {
                settle_admission_abort(
                    reserved,
                    AdmissionAbortReason::PlacementWriteFailed,
                    &actual,
                )?;
                return Err(error);
            }
        };
        Ok(PendingPlacement::Written {
            reserved,
            evidence,
            actual,
            placement,
            created,
            stage,
        })
    }
}

fn batch_resources(bytes: u64, count: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::Objects, count)])
}
fn batch_checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), StoreRefusal> {
    if live() {
        Ok(())
    } else {
        Err(StoreRefusal::RuntimeCheckpointRejected)
    }
}

enum PendingPlacement {
    Existing(PlacementReceipt),
    Written {
        reserved: ReservedObligation<ObjectAdmissionPermit>,
        evidence: AdmittedObject,
        actual: ResourceVector,
        placement: PlacementReceipt,
        created: bool,
        stage: StageFile,
    },
}
impl PendingPlacement {
    fn abort(self) -> Result<(), StoreRefusal> {
        if let Self::Written {
            reserved,
            actual,
            stage,
            ..
        } = self
        {
            let result = settle_admission_abort(
                reserved,
                AdmissionAbortReason::PlacementWriteFailed,
                &actual,
            );
            drop(stage);
            result
        } else {
            Ok(())
        }
    }
    fn commit(self) -> Result<PutIfAbsent, StoreRefusal> {
        let epochs = PublicationState::new(true, false, true);
        match self {
            Self::Existing(placement) => Ok(PutIfAbsent::AlreadyPresent { placement, epochs }),
            Self::Written {
                reserved,
                evidence,
                actual,
                placement,
                created,
                stage,
            } => {
                let result = if created {
                    match reserved.commit_internal(evidence, &actual) {
                        Ok(_) => Ok(PutIfAbsent::Created { placement, epochs }),
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
                } else {
                    settle_admission_abort(reserved, AdmissionAbortReason::Superseded, &actual)?;
                    Ok(PutIfAbsent::AlreadyPresent { placement, epochs })
                };
                drop(stage);
                result
            }
        }
    }
}
