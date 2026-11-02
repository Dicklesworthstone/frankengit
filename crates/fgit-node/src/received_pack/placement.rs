//! Join verified transport bytes to the actual selected immutable placements.
//! Native identities alone cannot discharge this proof in the SHA-1 domain.

use std::collections::BTreeMap;

use fgit_types::GitOid;

use super::PendingReceivedPack;

/// Each raw member must match the registered strong payload commitment of the
/// actual body chosen for staging. Completion still grants no serving custody:
/// final publication/collision checks belong to the ReceiveStaging owner.
pub(crate) struct PlacementBoundPack {
    pending: Option<PendingReceivedPack>,
    commitments: BTreeMap<GitOid, [u8; 32]>,
}

impl PlacementBoundPack {
    pub(crate) fn new(
        pending: PendingReceivedPack,
        commitments: BTreeMap<GitOid, [u8; 32]>,
    ) -> Self {
        Self {
            pending: Some(pending),
            commitments,
        }
    }

    pub(crate) fn observe(&mut self, id: GitOid, commitment: [u8; 32]) {
        if let Some(expected) = self.commitments.remove(&id)
            && expected != commitment
        {
            self.pending.take();
            self.commitments.clear();
        }
    }

    pub(crate) fn complete(self) -> Option<PendingReceivedPack> {
        self.commitments
            .is_empty()
            .then_some(self.pending)
            .flatten()
    }
}
