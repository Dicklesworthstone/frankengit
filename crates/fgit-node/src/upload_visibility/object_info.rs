//! Size metadata from the connection's exact authenticated visible projection.
//! No object lookup, body read, or additional membership authority is introduced.
//! Blob metadata comes from bounded envelope reads: namespace and requested
//! OID must match, and declared payload length must match the file's payload
//! length. This proof authorizes visible membership; it does not rehash blob
//! payloads or attest their integrity. Body-serving paths verify payloads.

use super::{
    Arc, BTreeMap, GitDaemonSessionDeadline, GitOid, WireError, partial_clone::FilterObject,
};

#[derive(Clone, Debug)]
pub(crate) struct ObjectInfoProof {
    objects: Arc<BTreeMap<GitOid, FilterObject>>,
    deadline: GitDaemonSessionDeadline,
}

impl ObjectInfoProof {
    pub(super) const fn new(
        objects: Arc<BTreeMap<GitOid, FilterObject>>,
        deadline: GitDaemonSessionDeadline,
    ) -> Self {
        Self { objects, deadline }
    }

    pub(crate) fn checkpoint(&self) -> Result<(), WireError> {
        if self.deadline.expired() {
            Err(WireError::PackSourceRefused)
        } else {
            Ok(())
        }
    }

    pub(crate) fn size(&self, oid: GitOid) -> Result<Option<u64>, WireError> {
        self.checkpoint()?;
        self.objects
            .get(&oid)
            .map(|object| u64::try_from(object.size).map_err(|_| WireError::PackSourceRefused))
            .transpose()
    }
}
