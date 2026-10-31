//! Native cumulative-outcome collection with bounded, cancellable fabric reads.
//!
//! Retained chunks are immutable evidence selected by the authority capsule.
//! The chronicle verifier owns fallback and exact-position/root checks; this
//! adapter only supplies the namespace capability and the request lifetime.

use fgit_authority::{
    AmbiguityReason, AuthenticatedHead, AuthorityFailure, CumulativeOutcomes, HeadKey,
    OutcomeFailure,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_codec::CryptoBodyIdentity;
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, ImmutableObjectFabric,
    ObjectRange, PlacementAdmission, PublicationState, PutIfAbsent, RetentionRootProposal,
    SegmentManifest, StoreRefusal, VerifiedObject, VerifiedRangeRead, WholeObjectRead,
};
use fgit_object_fabric::local::LocalFilesystemFabric;
use fgit_types::{GitOid, SegmentManifestId};

use crate::{FsqliteCx, PackContextCheckpoint, checkpoint_pack_context};

pub(super) async fn collect(
    authority: &FsqliteAuthorityStore,
    cx: &FsqliteCx,
    head_key: &HeadKey,
    authenticated: &AuthenticatedHead,
    fabric: Option<&LocalFilesystemFabric>,
) -> Result<CumulativeOutcomes, OutcomeFailure> {
    live(cx)?;
    let result = match fabric {
        Some(fabric) => {
            let guarded = RequestFabric { fabric, cx };
            fgit_chronicle::collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_with_fabric_async(
                authority,
                cx,
                &guarded,
                &CryptoBodyIdentity,
                head_key,
                authenticated,
            )
            .await
        }
        None => {
            fgit_chronicle::collect_cumulative_outcomes_from_authenticated_capsule_checkpoint_async(
                authority,
                cx,
                &CryptoBodyIdentity,
                head_key,
                authenticated,
            )
            .await
        }
    };
    // A cancelled chunk read is unavailable evidence, never permission to
    // acknowledge a partial result or reset the request for the genesis path.
    live(cx)?;
    result
}

fn live(cx: &FsqliteCx) -> Result<(), OutcomeFailure> {
    match checkpoint_pack_context(cx) {
        PackContextCheckpoint::Live => Ok(()),
        PackContextCheckpoint::Stopped { .. } => {
            Err(AuthorityFailure::Ambiguous(AmbiguityReason::Cancelled).into())
        }
    }
}

/// The file backend is synchronous but bounded. Every archive manifest and
/// chunk operation checks the same runtime-owned context before and after I/O;
/// no detached worker or new request budget is introduced.
pub(super) struct RequestFabric<'a> {
    fabric: &'a LocalFilesystemFabric,
    cx: &'a FsqliteCx,
}

impl<'a> RequestFabric<'a> {
    pub(super) const fn new(fabric: &'a LocalFilesystemFabric, cx: &'a FsqliteCx) -> Self {
        Self { fabric, cx }
    }

    fn within<T>(
        &self,
        operation: impl FnOnce() -> Result<T, StoreRefusal>,
    ) -> Result<T, StoreRefusal> {
        live(self.cx).map_err(|_| StoreRefusal::RuntimeCheckpointRejected)?;
        let result = operation();
        live(self.cx).map_err(|_| StoreRefusal::RuntimeCheckpointRejected)?;
        result
    }
}

impl ImmutableObjectFabric for RequestFabric<'_> {
    fn capabilities(&self) -> FabricCapabilities {
        self.fabric.capabilities()
    }

    fn put_if_absent(
        &self,
        object: VerifiedObject,
        admission: PlacementAdmission<'_>,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        self.within(|| self.fabric.put_if_absent(object, admission))
    }

    fn read_whole(&self, identity: GitOid) -> Result<WholeObjectRead, StoreRefusal> {
        self.within(|| self.fabric.read_whole(identity))
    }

    fn read_range_verified(
        &self,
        identity: GitOid,
        range: ObjectRange,
    ) -> Result<VerifiedRangeRead, StoreRefusal> {
        self.within(|| self.fabric.read_range_verified(identity, range))
    }

    fn write_manifest(
        &self,
        manifest: &SegmentManifest,
    ) -> Result<SegmentManifestId, StoreRefusal> {
        self.within(|| self.fabric.write_manifest(manifest))
    }

    fn read_manifest(&self, identity: SegmentManifestId) -> Result<SegmentManifest, StoreRefusal> {
        self.within(|| self.fabric.read_manifest(identity))
    }

    fn publish_retention_root<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        proposal: &RetentionRootProposal,
    ) -> Result<PublicationState, StoreRefusal> {
        self.within(|| self.fabric.publish_retention_root(registry, proposal))
    }

    fn delete_if_unretained<R: AuthenticatedRetentionRegistry>(
        &self,
        registry: &R,
        identity: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal> {
        self.within(|| self.fabric.delete_if_unretained(registry, identity))
    }
}
