//! File-backed blob custody for native backup and recovery.

use super::*;
use fgit_object_fabric::local::StoredObjectHeader;

impl OneNode {
    /// Inspect the stored kind and length without buffering a payload.
    /// This is only a bounded framing check; use a verified whole-object read
    /// or drain [`Self::open_git_blob_stream`] before relying on its content.
    pub fn git_object_header(&self, identity: GitOid) -> Result<StoredObjectHeader, NodeRefusal> {
        self.check_blob_identity_format(identity)?;
        self.fabric
            .read_header_bounded(identity, u64::MAX)
            .map_err(NodeRefusal::from)
    }

    /// Open a bounded blob stream whose native and strong commitments are
    /// authenticated only at exact EOF. Derived output must remain private
    /// until that terminal check succeeds. The configured stored-file limit
    /// remains independent of this caller's payload allowance.
    pub fn open_git_blob_stream(
        &self,
        identity: GitOid,
        maximum_payload_bytes: u64,
    ) -> Result<LocalBlobStream, NodeRefusal> {
        self.check_blob_identity_format(identity)?;
        self.fabric
            .open_blob_stream_bounded(identity, maximum_payload_bytes)
            .map_err(NodeRefusal::from)
    }

    /// Verify and place one exact native blob through bounded private staging.
    /// No body-sized allocation is required. Both caller-supplied commitments
    /// are checked independently before the immutable name is linked, and the
    /// resource region must close quiescent before any placement receipt escapes.
    /// This never publishes repository visibility or a canonical authority head.
    pub fn put_git_blob_stream(
        &self,
        identity: GitOid,
        length: u64,
        commitment: [u8; 32],
        maximum_payload_bytes: u64,
        reader: &mut dyn Read,
        live: &mut impl FnMut() -> bool,
    ) -> Result<StoredObject, NodeRefusal> {
        self.check_blob_identity_format(identity)?;
        let envelope = ObjectEnvelope::new(
            self.namespace.clone(),
            identity,
            ObjectKind::Blob,
            length,
            commitment,
            OBJECT_CODEC_NAMESPACE.to_vec(),
            commitment,
            None,
            &self.segment_limits,
        )
        .map_err(|error| NodeRefusal::from(StoreRefusal::Fabric(error)))?;
        let resources = placement_resources(length);
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
        let placed = self.fabric.put_blob_stream_if_absent(
            envelope,
            reader,
            maximum_payload_bytes,
            PlacementAdmission::new(&ledger, grant),
            live,
        );
        if !ledger.close().is_quiescent() {
            return Err(NodeRefusal::ResourceContainment);
        }
        match placed.map_err(NodeRefusal::from)? {
            PutIfAbsent::Created { .. } => Ok(StoredObject::Created(identity)),
            PutIfAbsent::AlreadyPresent { .. } => Ok(StoredObject::AlreadyPresent(identity)),
        }
    }

    fn check_blob_identity_format(&self, identity: GitOid) -> Result<(), NodeRefusal> {
        if identity.algorithm() == self.object_format {
            Ok(())
        } else {
            Err(NodeRefusal::ObjectFormatMismatch {
                stored: self.object_format,
                supplied: identity.algorithm(),
            })
        }
    }
}
