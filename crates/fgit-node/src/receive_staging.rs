//! A receive's verified objects, staged and synced but placed only when
//! admission prepares a commit (frankengit-tz5z).
//!
//! A refused push used to leave its whole pack in the object store: the
//! quarantine validator linked every verified object before admission
//! decided, and nothing reclaims an unreferenced object
//! (frankengit-root-doctrine-x2mv.4.10). A receive now owns one
//! [`ReceiveStaging`]. Validation, and a pre-stage while the receive waits for
//! the writer, writes and syncs each verified object into `staging/` through
//! synced batches, which hold only paths and reservations. Admission
//! publishes them (links the names, syncs their directories) once, when it
//! stages the receive's first commit and before any head CAS, so a committed
//! head never names an object that is not durable. A receive rejected before
//! commit preparation drops its holder and abandons every batch: the staged files
//! are removed and nothing reaches the object store. Every refusal pays the
//! same staging and skips only the link, so a hidden-ref refusal and a
//! stale-info refusal stay indistinguishable in latency as well as in bytes.
//!
//! Every raw receive entry (git://, SSH, smart HTTP, the loopback and native
//! session APIs), durable local directory imports, bundle import/fetch and
//! reviewed workspace, rebase, merge and squash paths own one. Candidate validators can read
//! verified private custody without linking objects. Directory imports preserve
//! their overlapped batch syncing and transfer payload-free custody here before
//! ordinary admission. Native merge admission releases custody only after its
//! complete policy, review and record-linkage preparation succeeds.
//! Residue that remains: a commit planned, published
//! and then lost at the head CAS to another process, whose replan refuses,
//! leaves its objects linked and unreferenced, as every refusal did before;
//! in a non-atomic session the first commit publishes the objects of its
//! refused siblings too. A failure or cancellation after placement starts can
//! also leave linked objects. Authenticated reclamation remains separate.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fgit_object_fabric::fabric::{PlacementAdmission, StoreRefusal, VerifiedObject};
use fgit_object_fabric::local::{LocalFilesystemFabric, SyncedBatch, SyncedBlob};
use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{GitOid, RefusalCode};

use crate::received_pack::PendingReceivedPack;
use crate::{NodeRefusal, OneNode, VerifiedFabricPackSource};

/// One receive's staged, synced and unpublished verified objects.
#[derive(Default)]
pub struct ReceiveStaging {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    batches: Vec<(ObligationLedger, SyncedBatch)>,
    blobs: Vec<(ObligationLedger, SyncedBlob)>,
    // Exact owned identity -> batch index: private graph reads never scan all batches.
    staged: BTreeMap<GitOid, Custody>,
    /// Prepared representation custody is ineligible for serving until every
    /// staged object passes publication's final identity-collision recheck.
    received_pack: Option<PendingReceivedPack>,
    published: bool,
    /// A failed publication may have linked some batches and abandoned the
    /// rest, so no later caller may treat this receive's objects as placed.
    failed: Option<Failure>,
}

#[derive(Clone, Copy)]
enum Custody {
    Batch(usize),
    Blob(usize),
}

#[derive(Clone)]
enum Failure {
    Store(StoreRefusal),
    Containment,
}

impl Failure {
    fn refusal(&self) -> NodeRefusal {
        match self {
            Self::Store(refusal) => NodeRefusal::Fabric(Box::new(refusal.clone())),
            Self::Containment => NodeRefusal::ResourceContainment,
        }
    }
}

impl std::fmt::Debug for ReceiveStaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lock();
        f.debug_struct("ReceiveStaging")
            .field("batches", &state.batches.len())
            .field("streamed_blobs", &state.blobs.len())
            .field("staged", &state.staged.len())
            .field("received_pack_pending", &state.received_pack.is_some())
            .field("published", &state.published)
            .field("failed", &state.failed.is_some())
            .finish()
    }
}

impl ReceiveStaging {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            // Publication may have drained every batch before an unwind
            // abandoned the remaining custody. An empty list is not evidence
            // that those objects became durable. Contain this owner permanently.
            state.failed = Some(Failure::Containment);
            state.received_pack.take();
            state
        })
    }

    /// Whether this receive has already staged `id` (a waiting pre-stage did).
    pub(crate) fn contains(&self, id: GitOid) -> bool {
        self.lock().staged.contains_key(&id)
    }

    /// Read only custody owned by this request. Missing/corrupt owned data is
    /// an error, never permission to try an unrelated permanent representation.
    /// Holding the mutex prevents publication/drop from consuming a stage file
    /// while its bounded read and original-commitment verification are in flight.
    pub(crate) fn read_object_bounded(
        &self,
        fabric: &LocalFilesystemFabric,
        identity: GitOid,
        maximum_payload_bytes: u64,
    ) -> Result<Option<VerifiedObject>, NodeRefusal> {
        let state = self.lock();
        if let Some(failure) = &state.failed {
            return Err(failure.refusal());
        }
        let Some(custody) = state.staged.get(&identity) else {
            return Ok(None);
        };
        if state.published {
            // A head-CAS retry may revalidate after this holder linked all its
            // objects. Its private files are gone; ordinary immutable reads
            // still verify the exact identity, namespace and payload bounds.
            return fabric
                .read_whole_bounded(identity, maximum_payload_bytes)
                .map(|read| Some(read.object))
                .map_err(NodeRefusal::from);
        }
        let object = match *custody {
            Custody::Batch(index) => state
                .batches
                .get(index)
                .ok_or(NodeRefusal::ResourceContainment)?
                .1
                .read_object_bounded(fabric, identity, maximum_payload_bytes),
            Custody::Blob(index) => state
                .blobs
                .get(index)
                .ok_or(NodeRefusal::ResourceContainment)?
                .1
                .read_object_bounded(fabric, identity, maximum_payload_bytes),
        };
        object
            .map_err(NodeRefusal::from)?
            .map(Some)
            .ok_or(NodeRefusal::ResourceContainment)
    }

    /// Keep a verified representation under the same publication responsibility
    /// as its objects. Speculative validation may offer the same receive twice;
    /// retaining the first candidate avoids duplicate cache reservations.
    pub(crate) fn retain_received_pack(
        &self,
        pending: PendingReceivedPack,
    ) -> Result<(), RefusalCode> {
        let mut state = self.lock();
        if state.published || state.failed.is_some() {
            return Err(RefusalCode::InternalInvariantBreach);
        }
        if state.received_pack.is_none() {
            state.received_pack = Some(pending);
        }
        Ok(())
    }

    /// Stages and syncs identity-sorted `objects` (at most one synced batch)
    /// for this receive without linking them.
    pub(crate) fn stage(
        &self,
        node: &OneNode,
        objects: &[VerifiedObject],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodeRefusal> {
        if objects.is_empty() {
            return Ok(());
        }
        let staged = node.stage_synced_git_objects(objects, live)?;
        self.retain_synced(staged)
    }

    /// Retains an already-synced private batch and its reservation owner.
    /// Import can overlap the next batch's preparation with this batch's
    /// syncing, then transfer only paths and reservations into admission.
    pub(crate) fn retain_synced(
        &self,
        staged: (ObligationLedger, SyncedBatch),
    ) -> Result<(), NodeRefusal> {
        let mut state = self.lock();
        if state.published || state.failed.is_some() {
            // Validation finishes before admission publishes, so this is
            // unreachable; refuse rather than leave objects unpublished.
            drop(state);
            settle_abandoned(staged);
            return Err(NodeRefusal::ResourceContainment);
        }
        let index = state.batches.len();
        for identity in staged.1.identities() {
            state
                .staged
                .entry(*identity)
                .or_insert(Custody::Batch(index));
        }
        state.batches.push(staged);
        Ok(())
    }

    /// Retain a fully authenticated, synced streamed blob without linking its
    /// permanent name. The owner keeps the original commitments for publication.
    pub(crate) fn retain_synced_blob(
        &self,
        staged: (ObligationLedger, SyncedBlob),
    ) -> Result<(), NodeRefusal> {
        let mut state = self.lock();
        if state.published || state.failed.is_some() {
            drop(state);
            settle_abandoned_blob(staged);
            return Err(NodeRefusal::ResourceContainment);
        }
        let index = state.blobs.len();
        state
            .staged
            .entry(staged.1.identity())
            .or_insert(Custody::Blob(index));
        state.blobs.push(staged);
        Ok(())
    }

    /// Publishes every staged object, once: links each name and syncs each
    /// object directory. Later calls succeed without work. After a failure
    /// every call fails, because some batches may be linked and others gone.
    pub(crate) fn publish(
        &self,
        fabric: &LocalFilesystemFabric,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodeRefusal> {
        let mut state = self.lock();
        if let Some(failure) = &state.failed {
            return Err(failure.refusal());
        }
        if state.published {
            return Ok(());
        }
        let mut batches = std::mem::take(&mut state.batches).into_iter();
        while let Some((ledger, batch)) = batches.next() {
            let outcome = fabric.publish_synced_batch(batch, live);
            let failure = if ledger.close().is_quiescent() {
                outcome.err().map(Failure::Store)
            } else {
                Some(Failure::Containment)
            };
            if let Some(failure) = failure {
                for remaining in batches {
                    settle_abandoned(remaining);
                }
                for remaining in state.blobs.drain(..) {
                    settle_abandoned_blob(remaining);
                }
                let refusal = failure.refusal();
                state.failed = Some(failure);
                state.received_pack.take();
                return Err(refusal);
            }
        }
        let mut blobs = std::mem::take(&mut state.blobs).into_iter();
        while let Some((ledger, blob)) = blobs.next() {
            let outcome = fabric.publish_synced_blob(blob, live);
            let failure = if ledger.close().is_quiescent() {
                outcome.err().map(Failure::Store)
            } else {
                Some(Failure::Containment)
            };
            if let Some(failure) = failure {
                for remaining in blobs {
                    settle_abandoned_blob(remaining);
                }
                let refusal = failure.refusal();
                state.failed = Some(failure);
                state.received_pack.take();
                return Err(refusal);
            }
        }
        state.published = true;
        if let Some(pending) = state.received_pack.take() {
            pending.commit();
        }
        Ok(())
    }
}

impl Drop for ReceiveStaging {
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        for staged in state.batches.drain(..) {
            settle_abandoned(staged);
        }
        for staged in state.blobs.drain(..) {
            settle_abandoned_blob(staged);
        }
    }
}

/// Abandons one batch: removes its staged files and settles its reservations.
fn settle_abandoned((ledger, batch): (ObligationLedger, SyncedBatch)) {
    let _abandoned = batch.abandon();
    let _closed = ledger.close();
}

fn settle_abandoned_blob((ledger, blob): (ObligationLedger, SyncedBlob)) {
    let _abandoned = blob.abandon();
    let _closed = ledger.close();
}

impl OneNode {
    /// Retain a streamed blob and its reservation in synced private custody.
    /// The ordinary admission projection owns the later publication decision.
    pub(crate) fn stage_synced_git_blob(
        &self,
        identity: GitOid,
        length: u64,
        commitment: [u8; 32],
        maximum_payload_bytes: u64,
        reader: &mut dyn std::io::Read,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(ObligationLedger, SyncedBlob), NodeRefusal> {
        if identity.algorithm() != self.object_format {
            return Err(NodeRefusal::ObjectFormatMismatch {
                stored: self.object_format,
                supplied: identity.algorithm(),
            });
        }
        let envelope = fgit_object_fabric::ObjectEnvelope::new(
            self.namespace.clone(),
            identity,
            fgit_object_fabric::ObjectKind::Blob,
            length,
            commitment,
            crate::OBJECT_CODEC_NAMESPACE.to_vec(),
            commitment,
            None,
            &self.segment_limits,
        )
        .map_err(|error| NodeRefusal::from(StoreRefusal::Fabric(error)))?;
        let resources = crate::placement_resources(length);
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            resources,
        );
        let grant = match ledger.grant(resources) {
            Ok(grant) => grant,
            Err(error) => {
                return if ledger.close().is_quiescent() {
                    Err(NodeRefusal::from(error))
                } else {
                    Err(NodeRefusal::ResourceContainment)
                };
            }
        };
        match self.fabric.stage_synced_blob_stream_if_absent(
            envelope,
            reader,
            maximum_payload_bytes,
            PlacementAdmission::new(&ledger, grant),
            live,
        ) {
            Ok(blob) => Ok((ledger, blob)),
            Err(error) => {
                if ledger.close().is_quiescent() {
                    Err(NodeRefusal::from(error))
                } else {
                    Err(NodeRefusal::ResourceContainment)
                }
            }
        }
    }

    /// [`Self::put_verified_git_objects`] without linking: the identity-sorted
    /// objects are written and synced into `staging/` as one synced batch,
    /// returned with the ledger holding its reservations (frankengit-tz5z).
    /// A single object may exceed the batch payload bound.
    pub(crate) fn stage_synced_git_objects(
        &self,
        objects: &[VerifiedObject],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(ObligationLedger, SyncedBatch), NodeRefusal> {
        let mut bytes = 0_u64;
        for object in objects {
            let length = u64::try_from(object.payload().len())
                .map_err(|_| NodeRefusal::ObjectLengthOverflow)?;
            bytes = bytes
                .checked_add(length.max(1))
                .ok_or(NodeRefusal::ObjectLengthOverflow)?;
        }
        let count = u64::try_from(objects.len()).map_err(|_| NodeRefusal::ObjectLengthOverflow)?;
        let resources =
            ResourceVector::from_grades(&[(Grade::Bytes, bytes), (Grade::Objects, count)]);
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            resources,
        );
        let grant = match ledger.grant(resources) {
            Ok(grant) => grant,
            Err(error) => {
                return if ledger.close().is_quiescent() {
                    Err(NodeRefusal::from(error))
                } else {
                    Err(NodeRefusal::ResourceContainment)
                };
            }
        };
        match self.fabric.stage_synced_batch_if_absent(
            objects,
            PlacementAdmission::new(&ledger, grant),
            live,
        ) {
            Ok(batch) => Ok((ledger, batch)),
            Err(error) => {
                // As for a single placement: a leaked region outranks the
                // fabric's own refusal.
                if !ledger.close().is_quiescent() {
                    return Err(NodeRefusal::ResourceContainment);
                }
                Err(NodeRefusal::from(error))
            }
        }
    }
}

/// A candidate validator's source, never an upload or disclosure source.
/// New objects are read from this request's synced custody; dependencies not
/// owned by it use the existing verified fabric path.
pub struct StagedCandidatePackSource<'source, 'staging> {
    source: VerifiedFabricPackSource<'source>,
    staging: &'staging ReceiveStaging,
}

impl<'source> VerifiedFabricPackSource<'source> {
    pub(crate) fn with_staging<'staging>(
        self,
        staging: &'staging ReceiveStaging,
    ) -> StagedCandidatePackSource<'source, 'staging> {
        StagedCandidatePackSource {
            source: self,
            staging,
        }
    }
}

impl StagedCandidatePackSource<'_, '_> {
    pub(crate) fn read_object(
        &self,
        id: &GitOid,
    ) -> Result<(fgit_git_object::ObjectType, Vec<u8>), PackWriteError> {
        self.source.read_object_using(None, |maximum| {
            match self
                .staging
                .read_object_bounded(self.source.fabric, *id, maximum)
            {
                Ok(Some(object)) => Ok(object),
                Ok(None) => self
                    .source
                    .fabric
                    .read_whole_bounded(*id, maximum)
                    .map(|read| read.object)
                    .map_err(|error| self.source.object_read_refusal(*id, error)),
                Err(NodeRefusal::Fabric(error)) => {
                    Err(self.source.object_read_refusal(*id, *error))
                }
                Err(_) => Err(PackWriteError::TemporaryReadRefused),
            }
        })
    }
}

impl CanonicalObjectSource for StagedCandidatePackSource<'_, '_> {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self.read_object(id)?;
        Ok(CanonicalPackObject::new(*id, kind, body, Vec::new(), 0, 0))
    }
}
