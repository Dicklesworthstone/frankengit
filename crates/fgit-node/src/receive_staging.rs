//! A receive's verified objects, staged and synced but published only when
//! the receive commits (frankengit-tz5z).
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
//! head never names an object that is not durable. A receive that ends without
//! a commit drops its holder, which abandons every batch: the staged files
//! are removed and nothing reaches the object store. Every refusal pays the
//! same staging and skips only the link, so a hidden-ref refusal and a
//! stale-info refusal stay indistinguishable in latency as well as in bytes.
//!
//! Every raw receive entry (git://, SSH, smart HTTP, the loopback and native
//! session APIs) owns one. Residue that remains: a commit planned, published
//! and then lost at the head CAS to another process, whose replan refuses,
//! leaves its objects linked and unreferenced, as every refusal did before;
//! in a non-atomic session the first commit publishes the objects of its
//! refused siblings too; and workspace publications (branches, full bundles,
//! TreeFS publication) and `fg import` still place objects before admission.

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};

use fgit_object_fabric::fabric::{PlacementAdmission, StoreRefusal, VerifiedObject};
use fgit_object_fabric::local::{LocalFilesystemFabric, SyncedBatch};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{GitOid, RefusalCode};

use crate::received_pack::PendingReceivedPack;
use crate::{NodeRefusal, OneNode};

/// One receive's staged, synced and unpublished verified objects.
#[derive(Default)]
pub struct ReceiveStaging {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    batches: Vec<(ObligationLedger, SyncedBatch)>,
    staged: BTreeSet<GitOid>,
    /// Prepared representation custody is ineligible for serving until every
    /// staged object passes publication's final identity-collision recheck.
    received_pack: Option<PendingReceivedPack>,
    published: bool,
    /// A failed publication may have linked some batches and abandoned the
    /// rest, so no later caller may treat this receive's objects as placed.
    failed: Option<Failure>,
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
            .field("staged", &state.staged.len())
            .field("received_pack_pending", &state.received_pack.is_some())
            .field("published", &state.published)
            .field("failed", &state.failed.is_some())
            .finish()
    }
}

impl ReceiveStaging {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether this receive has already staged `id` (a waiting pre-stage did).
    pub(crate) fn contains(&self, id: GitOid) -> bool {
        self.lock().staged.contains(&id)
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
        let mut state = self.lock();
        if state.published || state.failed.is_some() {
            // Validation finishes before admission publishes, so this is
            // unreachable; refuse rather than leave objects unpublished.
            drop(state);
            settle_abandoned(staged);
            return Err(NodeRefusal::ResourceContainment);
        }
        state
            .staged
            .extend(objects.iter().map(VerifiedObject::identity));
        state.batches.push(staged);
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
    }
}

/// Abandons one batch: removes its staged files and settles its reservations.
fn settle_abandoned((ledger, batch): (ObligationLedger, SyncedBatch)) {
    let _abandoned = batch.abandon();
    let _closed = ledger.close();
}

impl OneNode {
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
