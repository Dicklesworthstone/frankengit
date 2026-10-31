//! One authority-selected retained outcome archive in the recovery transport.
//!
//! These are immutable input bytes, not a second authority or a durable fabric.
//! Historical placement receipts remain part of the original manifest identity;
//! restore obtains fresh local placement/readback evidence without rewriting it.
use fgit_chronicle::outcome_index_leaf_archive_namespace;
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, DeletionReceipt, FabricCapabilities, FabricCapability,
    ImmutableObjectFabric, ManifestLimits, ObjectRange, PlacementAdmission, PlacementBackend,
    PlacementReceipt, PublicationState, PutIfAbsent, RetentionRootProposal, SegmentManifest,
    StorageOperation, StoreRefusal, VerifiedObject, VerifiedRangeRead, WholeObjectRead,
    read_verified_manifest_closure,
};
use fgit_object_fabric::{ObjectEnvelope, ObjectKind, SegmentLimits};
use fgit_resource::{LeakDisposition, ObligationLedger, OpaqueHandle, RegionId};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes, GitOid, SegmentManifestId};

use super::{archive::Identity, profile::Deadline};
use crate::{MaterializedAdmission, NodeRequestContext, OneNode};

pub(super) const MAX_EVIDENCE_BYTES: usize = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const CHUNK_CODEC: &[u8] = b"frankengit/outcome-index-checkpoint-leaf-chunk/v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CheckpointEvidence {
    root: Digest,
    manifest: SegmentManifest,
    objects: Vec<WholeObjectRead>,
}

fn error(error: impl std::fmt::Display) -> String {
    format!("retained outcome checkpoint: {error}")
}

impl CheckpointEvidence {
    pub(super) fn capture(
        node: &OneNode,
        request: &NodeRequestContext,
        selected: &MaterializedAdmission,
        deadline: Deadline,
    ) -> Result<Option<Self>, String> {
        deadline.in_request(request)?;
        let fabric = crate::outcome_collection::RequestFabric::new(
            &node.outcome_checkpoint_fabric,
            request.authority(),
        );
        let predecessor = node
            .runtime()
            .block_on(node.checkpoint_predecessor_in(request, selected, &fabric))
            .map_err(error)?;
        let Some((root, checkpoint)) = predecessor.retained else {
            return Ok(None);
        };
        deadline.in_request(request)?;
        let closure = read_verified_manifest_closure(
            &fabric,
            checkpoint.leaf_archive_manifest,
            &SegmentLimits::default(),
        )
        .map_err(error)?;
        deadline.in_request(request)?;
        let evidence = Self {
            root,
            manifest: closure.manifest().clone(),
            objects: closure.objects().to_vec(),
        };
        // Check the transport-specific ceiling before the writer starts.
        evidence.encode()?;
        Ok(Some(evidence))
    }

    /// Exact original canonical envelopes, manifest, and historical receipts.
    /// No leaf rechunking, manifest regeneration, or filesystem path is encoded.
    pub(super) fn encode(&self) -> Result<Vec<u8>, String> {
        let limits = SegmentLimits::default();
        let mut out = Buffer(Vec::new());
        out.push(&self.root.algorithm().code_point().to_be_bytes())?;
        out.push(&[self.root.bytes().len() as u8])?;
        out.push(self.root.bytes().as_bytes())?;
        let manifest = self.manifest.encode().map_err(error)?;
        if manifest.len() > MAX_MANIFEST_BYTES || self.objects.len() > limits.max_records as usize {
            return Err(error("manifest or retained-object count limit"));
        }
        out.bytes(&manifest)?;
        out.push(&(self.objects.len() as u32).to_be_bytes())?;
        for whole in &self.objects {
            let envelope = whole.object.envelope().encode().map_err(error)?;
            if envelope.len() > limits.max_envelope_bytes
                || whole.object.payload().len() > limits.max_record_bytes
            {
                return Err(error("retained-object byte limit"));
            }
            out.bytes(&envelope)?;
            out.bytes(whole.object.payload())?;
            out.push(&[match whole.placement.backend() {
                PlacementBackend::LocalFilesystem => 1,
                PlacementBackend::MemoryReference => 2,
            }])?;
            for handle in [
                whole.placement.locator(),
                whole.placement.failure_domain(),
                whole.placement.encryption_dependency(),
            ] {
                out.push(&[handle.len() as u8])?;
                out.push(handle.as_bytes())?;
            }
        }
        Ok(out.0)
    }

    pub(super) fn decode(bytes: &[u8], identity: Identity) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(error("evidence byte limit"));
        }
        let limits = SegmentLimits::default();
        let mut input = Cursor(bytes);
        let algorithm =
            DigestAlgorithmId::try_new(u16::from_be_bytes(input.array()?)).map_err(error)?;
        let root_length = usize::from(input.array::<1>()?[0]);
        let root = Digest::new(
            algorithm,
            DigestBytes::try_new(input.take(root_length)?).map_err(error)?,
        );
        let manifest_bytes = input.bytes(MAX_MANIFEST_BYTES)?;
        let manifest =
            SegmentManifest::decode(manifest_bytes, &ManifestLimits::default()).map_err(error)?;
        if manifest.encode().map_err(error)? != manifest_bytes
            || manifest.namespace() != outcome_index_leaf_archive_namespace(identity.repository)
        {
            return Err(error("noncanonical or foreign manifest"));
        }
        let count = usize::try_from(u32::from_be_bytes(input.array()?)).map_err(error)?;
        if count == 0
            || count > limits.max_records as usize
            || count != manifest.entries().len()
            || count > input.0.len() / 23
        {
            return Err(error("retained object inventory does not equal manifest"));
        }
        let mut objects = Vec::new();
        objects.try_reserve_exact(count).map_err(error)?;
        let mut payload_bytes = 0_u64;
        for entry in manifest.entries() {
            let encoded = input.bytes(limits.max_envelope_bytes)?;
            let envelope = ObjectEnvelope::decode(encoded, &limits).map_err(error)?;
            if envelope.encode().map_err(error)? != encoded
                || envelope.namespace() != manifest.namespace()
                || envelope.object_identity() != entry.object_identity()
                || envelope.object_identity().algorithm() != identity.format
                || envelope.object_kind() != ObjectKind::Blob
                || envelope.codec_namespace() != CHUNK_CODEC
                || envelope.logical_content_identity() != envelope.payload_commitment()
            {
                return Err(error(
                    "retained envelope, namespace or object order mismatch",
                ));
            }
            let payload = input.bytes(limits.max_record_bytes)?;
            payload_bytes = payload_bytes
                .checked_add(payload.len() as u64)
                .filter(|length| *length <= limits.max_segment_bytes as u64)
                .ok_or_else(|| error("retained payload byte limit"))?;
            let object = VerifiedObject::new(envelope, payload.to_vec()).map_err(error)?;
            let backend = match input.array::<1>()?[0] {
                1 => PlacementBackend::LocalFilesystem,
                2 => PlacementBackend::MemoryReference,
                _ => return Err(error("unknown historical placement backend")),
            };
            let placement =
                PlacementReceipt::new(backend, input.handle()?, input.handle()?, input.handle()?);
            objects.push(WholeObjectRead { object, placement });
        }
        if !input.0.is_empty() {
            return Err(error("trailing checkpoint evidence"));
        }
        Ok(Self {
            root,
            manifest,
            objects,
        })
    }

    pub(super) fn verify(
        &self,
        node: &OneNode,
        request: &NodeRequestContext,
        selected: &MaterializedAdmission,
        deadline: Deadline,
        local: bool,
    ) -> Result<(), String> {
        deadline.in_request(request)?;
        let retained = if local {
            let fabric = crate::outcome_collection::RequestFabric::new(
                &node.outcome_checkpoint_fabric,
                request.authority(),
            );
            node.runtime()
                .block_on(node.checkpoint_predecessor_in(request, selected, &fabric))
        } else {
            let fabric = ArchiveView {
                evidence: self,
                request,
                deadline,
            };
            node.runtime()
                .block_on(node.checkpoint_predecessor_in(request, selected, &fabric))
        }
        .map_err(error)?
        .retained;
        deadline.in_request(request)?;
        if retained.is_none_or(|(root, body)| {
            root != self.root || self.manifest.identity().ok() != Some(body.leaf_archive_manifest)
        }) {
            return Err(error(
                "archive does not preserve the authority-selected retained root",
            ));
        }
        Ok(())
    }

    pub(super) fn install(
        &self,
        node: &OneNode,
        request: &NodeRequestContext,
        deadline: Deadline,
    ) -> Result<(), String> {
        let fabric = crate::outcome_collection::RequestFabric::new(
            &node.outcome_checkpoint_fabric,
            request.authority(),
        );
        for whole in &self.objects {
            deadline.in_request(request)?;
            let resources = crate::placement_resources(whole.object.payload().len() as u64);
            let ledger = ObligationLedger::root(
                RegionId::new(1),
                LeakDisposition::RecordAndContinue,
                resources,
            );
            let grant = ledger.grant(resources).map_err(error)?;
            let placement = fabric.put_if_absent(
                whole.object.clone(),
                PlacementAdmission::new(&ledger, grant),
            );
            if !ledger.close().is_quiescent() {
                return Err(error("placement custody did not close"));
            }
            placement.map_err(error)?;
        }
        deadline.in_request(request)?;
        // Receipt locators in this manifest describe the source placement. They
        // are immutable identity-bearing history, never proof of local durability.
        let actual = fabric.write_manifest(&self.manifest).map_err(error)?;
        if actual != self.manifest.identity().map_err(error)? {
            return Err(error("destination rewrote the retained manifest"));
        }
        deadline.in_request(request)
    }
}

/// Receipt fields are meaningful only after the operation's strict verification.
pub(super) fn receipt(evidence: Option<&CheckpointEvidence>) -> String {
    match evidence {
        Some(evidence) => format!(
            ",\"transport_version\":2,\"retained_outcome_checkpoint_verified\":true,\"retained_outcome_checkpoint_root\":\"{}:{}\",\"retained_outcome_objects\":{},\"retained_outcome_payload_bytes\":{}",
            evidence.root.algorithm().code_point(), super::super::hex(evidence.root.bytes().as_bytes()),
            evidence.objects.len(), evidence.objects.iter().map(|whole| whole.object.payload().len() as u64).sum::<u64>(),
        ),
        None => ",\"transport_version\":1,\"retained_outcome_checkpoint_verified\":false,\"retained_outcome_checkpoint_root\":null,\"retained_outcome_objects\":0,\"retained_outcome_payload_bytes\":0".into(),
    }
}

struct Buffer(Vec<u8>);
impl Buffer {
    fn push(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.0
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_EVIDENCE_BYTES)
            .ok_or_else(|| error("evidence byte limit"))?;
        self.0.try_reserve(bytes.len()).map_err(error)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.push(&(bytes.len() as u64).to_be_bytes())?;
        self.push(bytes)
    }
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let bytes = self
            .0
            .get(..length)
            .ok_or_else(|| error("truncated evidence"))?;
        self.0 = &self.0[length..];
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?.try_into().map_err(error)
    }
    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], String> {
        let size = usize::try_from(u64::from_be_bytes(self.array()?))
            .ok()
            .filter(|size| *size <= maximum)
            .ok_or_else(|| error("declared checkpoint byte limit"))?;
        self.take(size)
    }
    fn handle(&mut self) -> Result<OpaqueHandle, String> {
        let length = usize::from(self.array::<1>()?[0]);
        OpaqueHandle::new(self.take(length)?).map_err(error)
    }
}

/// Read-only view of bounded, pinned transport evidence. No path, authority,
/// retention decision, mutable cache, or storage publication lives here.
struct ArchiveView<'a> {
    evidence: &'a CheckpointEvidence,
    request: &'a NodeRequestContext,
    deadline: Deadline,
}
impl ArchiveView<'_> {
    fn live(&self) -> Result<(), StoreRefusal> {
        self.deadline
            .in_request(self.request)
            .map_err(|_| StoreRefusal::RuntimeCheckpointRejected)?;
        match crate::checkpoint_pack_context(self.request.authority()) {
            crate::PackContextCheckpoint::Live => Ok(()),
            crate::PackContextCheckpoint::Stopped { .. } => {
                Err(StoreRefusal::RuntimeCheckpointRejected)
            }
        }
    }
}
fn read_only(operation: StorageOperation) -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation,
        kind: std::io::ErrorKind::PermissionDenied,
    }
}
impl ImmutableObjectFabric for ArchiveView<'_> {
    fn capabilities(&self) -> FabricCapabilities {
        FabricCapabilities::new(&[FabricCapability::VerifiedWholeReads])
    }
    fn read_whole(&self, identity: GitOid) -> Result<WholeObjectRead, StoreRefusal> {
        self.live()?;
        let at = self
            .evidence
            .objects
            .binary_search_by_key(&identity, |whole| whole.object.identity())
            .map_err(|_| StoreRefusal::ObjectAbsent)?;
        let read = self.evidence.objects[at].clone();
        self.live()?;
        Ok(read)
    }
    fn read_manifest(&self, identity: SegmentManifestId) -> Result<SegmentManifest, StoreRefusal> {
        self.live()?;
        if self.evidence.manifest.identity()? != identity {
            return Err(StoreRefusal::ObjectAbsent);
        }
        let manifest = self.evidence.manifest.clone();
        self.live()?;
        Ok(manifest)
    }
    fn read_range_verified(
        &self,
        _: GitOid,
        _: ObjectRange,
    ) -> Result<VerifiedRangeRead, StoreRefusal> {
        Err(StoreRefusal::PartialRangeUnverified)
    }
    fn put_if_absent(
        &self,
        _: VerifiedObject,
        _: PlacementAdmission<'_>,
    ) -> Result<PutIfAbsent, StoreRefusal> {
        Err(read_only(StorageOperation::PublishImmutableBody))
    }
    fn write_manifest(&self, _: &SegmentManifest) -> Result<SegmentManifestId, StoreRefusal> {
        Err(read_only(StorageOperation::PublishImmutableBody))
    }
    fn publish_retention_root<R: AuthenticatedRetentionRegistry>(
        &self,
        _: &R,
        _: &RetentionRootProposal,
    ) -> Result<PublicationState, StoreRefusal> {
        Err(read_only(StorageOperation::PublishRetentionRoot))
    }
    fn delete_if_unretained<R: AuthenticatedRetentionRegistry>(
        &self,
        _: &R,
        _: GitOid,
    ) -> Result<DeletionReceipt, StoreRefusal> {
        Err(read_only(StorageOperation::RemoveBody))
    }
}

#[cfg(test)]
#[path = "checkpoint_tests.rs"]
mod tests;
