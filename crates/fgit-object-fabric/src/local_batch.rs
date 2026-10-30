//! Bounded group durability using the unchanged immutable object-file format.
//! No result escapes until every target directory is synced. Failed batches
//! may leave verified placement, never canonical visibility or success receipts.

use super::{
    AdmissionAbortReason, AdmittedObject, GitOid, Grade, ImmutableWrite, LocalCrashPoint,
    LocalFilesystemFabric, ObjectAdmission, ObjectAdmissionPermit, ObjectClass, PlacementAdmission,
    PlacementReceipt, PublicationState, PutIfAbsent, ReservedObligation, ResourceVector, StageFile,
    StorageOperation, StoreRefusal, StructureVerdict, VerifiedObject, payload_identity,
    settle_admission_abort, storage_error, sync_directory,
};
use fgit_resource::{BudgetGrant, ObligationLedger};
use std::collections::BTreeSet;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;

const MAX_BATCH_OBJECTS: usize = 1024;
const MAX_BATCH_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// Staged files held open at once, and so the descriptors a batch needs. The
/// blocking form syncs and closes each group of this many before writing the
/// next, so a 1,024-object batch shares one link pass and one directory sync
/// per object directory without needing 1,024 descriptors: under the common
/// 1,024 soft `RLIMIT_NOFILE` that refused the whole push. The overlapped
/// form keeps its files open until publication and so takes at most one group.
const SYNC_GROUP_FILES: usize = 256;
/// Upper bound on the threads that sync one group of staged files: one per
/// file. Every fsync of a group is then in flight at once, so the journal
/// commits it waits for are shared by the whole group. With 32 threads, each
/// thread of a full batch ran eight fsyncs in sequence (frankengit-pc9g).
const MAX_SYNC_THREADS: usize = SYNC_GROUP_FILES;
/// A sync thread only calls `fsync`; it needs a small stack, not the default.
const SYNC_THREAD_STACK_BYTES: usize = 64 * 1024;

impl LocalFilesystemFabric {
    /// Place up to 1,024 identity-sorted objects and 64 MiB of payloads with
    /// one final directory sync per native hash domain, rather than per
    /// object. Each file is still synced before its immutable name is linked:
    /// staged files are written and synced concurrently in groups of 256,
    /// then the names are linked. One fsync at a time paid a journal commit
    /// per file (about 6 ms each on ext4/NVMe); concurrent fsyncs share
    /// commits, and the three directory syncs of a batch are paid once per
    /// 1,024 objects rather than per 256 (frankengit-pc9g). The caller must
    /// keep the storage root and ancestors
    /// stable during the call. A failed batch links no name it staged after
    /// the failure point and may have linked none at all.
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
        let mut pending = Pending::default();
        let staged = self
            .stage_pending(objects, ledger, &mut budget, &mut pending, live, true)
            .and_then(|()| SyncFence::start(&mut pending.entries).wait())
            .and_then(|()| self.link_pending(objects, &mut pending, live));
        let _released = budget.release();
        settle(pending.entries, staged)
    }

    /// The first half of [`Self::put_batch_if_absent`], for a caller that
    /// prepares its next batch while this one becomes durable
    /// (frankengit-ai60). Preflight, reservation and staged writes are exactly
    /// the blocking form's; every staged file's sync then starts on
    /// background threads and this returns without linking any name. On a
    /// refusal every reservation is already settled.
    pub fn stage_batch_if_absent(
        &self,
        objects: Vec<VerifiedObject>,
        admission: PlacementAdmission<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<StagedBatch, StoreRefusal> {
        let (ledger, mut budget) = admission.into_parts();
        let mut pending = Pending::default();
        let staged = self.stage_pending(&objects, ledger, &mut budget, &mut pending, live, false);
        let _released = budget.release();
        if let Err(error) = staged {
            return Err(abort_all(pending.entries).err().unwrap_or(error));
        }
        Ok(StagedBatch {
            syncing: SyncFence::start(&mut pending.entries),
            objects,
            pending,
        })
    }

    /// The second half: waits for every staged file of `batch` to sync, then
    /// links, syncs each object directory and settles exactly as
    /// [`Self::put_batch_if_absent`] does. No receipt escapes before that
    /// fence; a refusal links nothing further and settles every reservation.
    pub fn publish_staged_batch(
        &self,
        batch: StagedBatch,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Vec<PutIfAbsent>, StoreRefusal> {
        let StagedBatch {
            mut syncing,
            objects,
            mut pending,
        } = batch;
        let staged = syncing
            .wait()
            .and_then(|()| self.link_pending(&objects, &mut pending, live));
        settle(pending.entries, staged)
    }

    /// Stages up to 1,024 objects exactly as [`Self::put_batch_if_absent`]
    /// does, every staged file synced in groups, but links no immutable name
    /// (frankengit-tz5z). The returned batch holds only staged paths and
    /// reservations: no payload, descriptor or sync thread. A receive can
    /// therefore keep many across admission and publish them only when its
    /// decision commits. Settle it with [`Self::publish_synced_batch`] or
    /// [`SyncedBatch::abandon`]. On a refusal every reservation is settled.
    pub fn stage_synced_batch_if_absent(
        &self,
        objects: &[VerifiedObject],
        admission: PlacementAdmission<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<SyncedBatch, StoreRefusal> {
        let (ledger, mut budget) = admission.into_parts();
        let mut pending = Pending::default();
        let staged = self
            .stage_pending(objects, ledger, &mut budget, &mut pending, live, true)
            .and_then(|()| SyncFence::start(&mut pending.entries).wait());
        let _released = budget.release();
        if let Err(error) = staged {
            return Err(abort_all(pending.entries).err().unwrap_or(error));
        }
        Ok(SyncedBatch {
            identities: objects.iter().map(VerifiedObject::identity).collect(),
            pending,
        })
    }

    /// Links every synced staged file of `batch`, syncs each object directory
    /// once and settles, as the second half of [`Self::put_batch_if_absent`]
    /// does. A name that already exists must hold exactly the staged bytes.
    /// A refusal links nothing further and settles every reservation.
    pub fn publish_synced_batch(
        &self,
        mut batch: SyncedBatch,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Vec<PutIfAbsent>, StoreRefusal> {
        let linked = self.link_synced(&batch.identities, &mut batch.pending, live);
        settle(std::mem::take(&mut batch.pending.entries), linked)
    }

    fn link_synced(
        &self,
        identities: &[GitOid],
        pending: &mut Pending,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), StoreRefusal> {
        if pending.entries.is_empty() {
            return Ok(());
        }
        self.crash_if(LocalCrashPoint::AfterStageSync)?;
        for (entry, identity) in pending.entries.iter_mut().zip(identities) {
            batch_checkpoint(live)?;
            entry.link_synced(self, *identity)?;
        }
        for directory in &pending.directories {
            batch_checkpoint(live)?;
            sync_directory(directory)?;
        }
        self.crash_if(LocalCrashPoint::AfterPublishDirectorySync)?;
        self.crash_if(LocalCrashPoint::BeforeStageCleanup)?;
        batch_checkpoint(live)
    }

    /// Preflights the whole batch, then reserves and writes each staged file.
    /// Objects already stored are reverified, not staged. With `group_syncs`
    /// each full group of [`SYNC_GROUP_FILES`] written files is synced and
    /// closed before the next is written; the caller syncs the rest. Without
    /// it no file is synced here, and the batch may hold at most one group.
    fn stage_pending(
        &self,
        objects: &[VerifiedObject],
        ledger: &ObligationLedger,
        budget: &mut BudgetGrant,
        pending: &mut Pending,
        live: &mut impl FnMut() -> bool,
        group_syncs: bool,
    ) -> Result<(), StoreRefusal> {
        let required = self.preflight_batch(objects, live)?;
        if !group_syncs && objects.len() > SYNC_GROUP_FILES {
            return Err(StoreRefusal::TooManyEntries);
        }
        if let Some(error) = budget.amount().first_deficit(&required) {
            return Err(StoreRefusal::Resource(error));
        }
        if objects.is_empty() {
            return Ok(());
        }
        batch_checkpoint(live)?;
        // A directory that already exists is not synced again here: staged
        // names are scratch, and link_pending syncs every object directory
        // after linking. A directory created here is made durable through
        // the store root, as by create_directory.
        self.create_directory_for_batch(&self.staging_dir())?;
        let mut open_files = 0;
        for object in objects {
            batch_checkpoint(live)?;
            let path = self.object_path(object.identity());
            let parent = path.parent().ok_or(StoreRefusal::MalformedStoredObject)?;
            if pending.directories.insert(parent.to_path_buf()) {
                self.create_directory_for_batch(parent)?;
            }
            let amount = batch_resources((object.payload().len() as u64).max(1), 1);
            let grant = budget.split_off(&amount).map_err(StoreRefusal::Resource)?;
            let entry = self.stage_batch_object(object, ledger, grant)?;
            if matches!(entry, PendingPlacement::Written { .. }) {
                open_files += 1;
            }
            pending.entries.push(entry);
            if group_syncs && open_files == SYNC_GROUP_FILES {
                batch_checkpoint(live)?;
                SyncFence::start(&mut pending.entries).wait()?;
                open_files = 0;
            }
        }
        batch_checkpoint(live)
    }

    /// Links every synced staged file under its immutable name, then syncs
    /// each object directory once. The caller has synced every staged file.
    fn link_pending(
        &self,
        objects: &[VerifiedObject],
        pending: &mut Pending,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), StoreRefusal> {
        if pending.entries.is_empty() {
            return Ok(());
        }
        self.crash_if(LocalCrashPoint::AfterStageSync)?;
        for (entry, object) in pending.entries.iter_mut().zip(objects) {
            batch_checkpoint(live)?;
            entry.link(self, object)?;
        }
        for directory in &pending.directories {
            batch_checkpoint(live)?;
            sync_directory(directory)?;
        }
        self.crash_if(LocalCrashPoint::AfterPublishDirectorySync)?;
        self.crash_if(LocalCrashPoint::BeforeStageCleanup)?;
        batch_checkpoint(live)
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
            // One object alone is bounded only by the stored-object limit
            // above, as a single placement is: a receive stages a large
            // object in a batch of its own (frankengit-tz5z).
            if bytes > MAX_BATCH_PAYLOAD_BYTES && objects.len() > 1 {
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
                payload_identity(object)?,
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
        let stage = match self.write_object_stage_unsynced(object, true) {
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
        // Synced and linked by the caller once every staged file is written.
        Ok(PendingPlacement::Written {
            reserved,
            evidence,
            actual,
            placement,
            created: None,
            stage,
        })
    }
}

fn batch_resources(bytes: u64, count: u64) -> ResourceVector {
    ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::Objects, count)])
}

/// Aborts every reservation, draining ALL of them even when one settlement
/// refuses; the first such refusal is returned.
fn abort_all(entries: Vec<PendingPlacement>) -> Result<(), StoreRefusal> {
    let mut failure = None;
    for entry in entries {
        if let Err(error) = entry.abort() {
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

/// Settles a batch: on a refusal aborts every reservation (an abort refusal
/// outranks the original one); otherwise commits each receipt in order.
fn settle(
    entries: Vec<PendingPlacement>,
    staged: Result<(), StoreRefusal>,
) -> Result<Vec<PutIfAbsent>, StoreRefusal> {
    if let Err(error) = staged {
        return Err(abort_all(entries).err().unwrap_or(error));
    }
    let mut results = Vec::with_capacity(entries.len());
    let mut failure = None;
    for entry in entries {
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

/// One batch's reservations and staged files, in object order.
#[derive(Default)]
struct Pending {
    entries: Vec<PendingPlacement>,
    /// Bounded by the two native hash domains; no global directory cache.
    directories: BTreeSet<PathBuf>,
}

/// A batch staged by [`LocalFilesystemFabric::stage_batch_if_absent`]: every
/// staged file is written and syncing on background threads, no immutable
/// name is linked and no receipt exists. Settle it with
/// [`LocalFilesystemFabric::publish_staged_batch`] or [`Self::abandon`], or
/// retain it without payload buffers through [`Self::synchronize`].
/// Dropping it unsettled still joins its syncs and removes its staged files,
/// but its reservations then count as leaks in their ledger.
#[must_use = "a staged batch holds reservations until it is published or abandoned"]
pub struct StagedBatch {
    // Declared first so a drop joins the syncs before removing staged files.
    syncing: SyncFence,
    objects: Vec<VerifiedObject>,
    pending: Pending,
}

impl std::fmt::Debug for StagedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedBatch")
            .field("objects", &self.objects.len())
            .field("directories", &self.pending.directories.len())
            .finish_non_exhaustive()
    }
}

impl StagedBatch {
    /// Joins every sync without linking an immutable name, then releases the
    /// payload buffers and file descriptors. The returned custody holds only
    /// identities, staged paths and the original reservations, so a caller can
    /// prepare subsequent batches while retaining this one until admission.
    ///
    /// Cancellation and sync failure drain all workers and abort every
    /// reservation before returning. A settlement failure outranks the
    /// original refusal, exactly as [`Self::abandon`] does.
    pub fn synchronize(
        mut self,
        live: &mut impl FnMut() -> bool,
    ) -> Result<SyncedBatch, StoreRefusal> {
        let before = batch_checkpoint(live);
        // Always join, including when the caller was already cancelled.
        let synced = self.syncing.wait();
        let result = before.and(synced).and_then(|()| batch_checkpoint(live));
        if let Err(error) = result {
            return Err(abort_all(std::mem::take(&mut self.pending.entries))
                .err()
                .unwrap_or(error));
        }
        Ok(SyncedBatch {
            identities: self.objects.iter().map(VerifiedObject::identity).collect(),
            pending: std::mem::take(&mut self.pending),
        })
    }

    /// Waits for every sync, then aborts every reservation and removes every
    /// staged file. Links nothing.
    pub fn abandon(mut self) -> Result<(), StoreRefusal> {
        // A sync failure is moot: nothing staged here will be linked.
        let _synced = self.syncing.wait();
        abort_all(std::mem::take(&mut self.pending.entries))
    }
}

/// A batch staged by [`LocalFilesystemFabric::stage_synced_batch_if_absent`]:
/// every staged file is written, synced and closed, its sync threads have
/// finished, and no immutable name is linked. It holds only staged paths and
/// reservations (frankengit-tz5z). Settle it with
/// [`LocalFilesystemFabric::publish_synced_batch`] or [`Self::abandon`].
/// Dropping it unsettled still removes its staged files, but its reservations
/// then count as leaks in their ledger.
#[must_use = "a synced batch holds reservations until it is published or abandoned"]
pub struct SyncedBatch {
    identities: Vec<GitOid>,
    pending: Pending,
}

impl std::fmt::Debug for SyncedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncedBatch")
            .field("objects", &self.identities.len())
            .field("directories", &self.pending.directories.len())
            .finish_non_exhaustive()
    }
}

impl SyncedBatch {
    /// The batch's object identities, in its canonical order.
    #[must_use]
    pub fn identities(&self) -> &[GitOid] {
        &self.identities
    }

    /// Aborts every reservation and removes every staged file. Links nothing.
    pub fn abandon(mut self) -> Result<(), StoreRefusal> {
        abort_all(std::mem::take(&mut self.pending.entries))
    }
}

/// Background syncs of one batch's staged files, on up to
/// [`MAX_SYNC_THREADS`] threads. Each worker shares ownership of its files
/// and they close once synced. Dropping the fence joins every worker, so no
/// sync outlives its batch.
struct SyncFence {
    workers: Vec<JoinHandle<std::io::Result<()>>>,
    /// The first failure among shares synced inline because no thread started.
    inline: std::io::Result<()>,
}

impl SyncFence {
    fn start(entries: &mut [PendingPlacement]) -> Self {
        let files: Vec<File> = entries
            .iter_mut()
            .filter_map(|entry| match entry {
                PendingPlacement::Written { stage, .. } => stage.take_file(),
                PendingPlacement::Existing(_) => None,
            })
            .collect();
        let mut fence = Self {
            workers: Vec::new(),
            inline: Ok(()),
        };
        if files.is_empty() {
            return fence;
        }
        let per_thread = files.len().div_ceil(files.len().min(MAX_SYNC_THREADS));
        let mut files = files.into_iter();
        loop {
            let share: Arc<[File]> = files.by_ref().take(per_thread).collect();
            if share.is_empty() {
                return fence;
            }
            let worker = Arc::clone(&share);
            match std::thread::Builder::new()
                .name("fgit-stage-sync".to_owned())
                .stack_size(SYNC_THREAD_STACK_BYTES)
                .spawn(move || sync_files(&worker))
            {
                Ok(handle) => fence.workers.push(handle),
                // The share is still owned here: sync it on this thread.
                Err(_) => {
                    if let Err(error) = sync_files(&share)
                        && fence.inline.is_ok()
                    {
                        fence.inline = Err(error);
                    }
                }
            }
        }
    }

    /// Joins every worker; the first sync failure refuses the batch.
    fn wait(&mut self) -> Result<(), StoreRefusal> {
        let mut first = std::mem::replace(&mut self.inline, Ok(()));
        for worker in self.workers.drain(..) {
            let synced = worker.join().unwrap_or_else(|_| {
                Err(std::io::Error::other("a staged-file sync thread panicked"))
            });
            first = first.and(synced);
        }
        first.map_err(|error| storage_error(StorageOperation::SyncStage, error))
    }
}

impl Drop for SyncFence {
    fn drop(&mut self) {
        for worker in self.workers.drain(..) {
            let _joined = worker.join();
        }
    }
}

fn sync_files(files: &[File]) -> std::io::Result<()> {
    files.iter().try_for_each(File::sync_all)
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
        /// `None` until the synced stage is linked; then whether this batch
        /// created the immutable name.
        created: Option<bool>,
        stage: StageFile,
    },
}
impl PendingPlacement {
    /// Links one synced staged file under its immutable name.
    fn link(
        &mut self,
        fabric: &LocalFilesystemFabric,
        object: &VerifiedObject,
    ) -> Result<(), StoreRefusal> {
        if let Self::Written { stage, created, .. } = self {
            stage.close();
            *created = Some(matches!(
                fabric.link_object_stage(stage, object)?,
                ImmutableWrite::Created
            ));
        }
        Ok(())
    }

    fn link_synced(
        &mut self,
        fabric: &LocalFilesystemFabric,
        identity: GitOid,
    ) -> Result<(), StoreRefusal> {
        if let Self::Written { stage, created, .. } = self {
            stage.close();
            *created = Some(matches!(
                fabric.link_synced_stage(stage, identity)?,
                ImmutableWrite::Created
            ));
        }
        Ok(())
    }

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
                let Some(created) = created else {
                    // Unreachable: commit runs only after every entry linked.
                    settle_admission_abort(
                        reserved,
                        AdmissionAbortReason::PlacementWriteFailed,
                        &actual,
                    )?;
                    return Err(StoreRefusal::StorageIo {
                        operation: StorageOperation::PublishImmutableBody,
                        kind: std::io::ErrorKind::Other,
                    });
                };
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
