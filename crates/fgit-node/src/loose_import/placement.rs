//! Import placement through bounded, fully settled object batches.
use super::{ImportControl, LooseGitImportRefusal, OneNode};
use crate::{NodeRefusal, OBJECT_CODEC_NAMESPACE, crypto_object_kind, fabric_object_kind};
use fgit_crypto::{git_object_id, git_payload_commitment};
use fgit_git_object::LooseObject;
use fgit_object_fabric::ObjectEnvelope;
use fgit_object_fabric::fabric::{PlacementAdmission, StoreRefusal, VerifiedObject};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::{CANONICAL_CODEC_VERSION, GitOid};

const CHUNK_OBJECTS: usize = 256;
const CHUNK_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct Placements<'a> {
    node: &'a OneNode,
    objects: Vec<VerifiedObject>,
    bytes: usize,
}
impl<'a> Placements<'a> {
    pub(super) fn new(node: &'a OneNode) -> Self {
        Self {
            node,
            objects: Vec::new(),
            bytes: 0,
        }
    }
    pub(super) fn prepare(
        &mut self,
        length: usize,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        control.checkpoint()?;
        if self.objects.len() == CHUNK_OBJECTS || length > CHUNK_BYTES.saturating_sub(self.bytes) {
            self.flush(control)?;
        }
        Ok(())
    }
}
fn node_error(error: NodeRefusal) -> LooseGitImportRefusal {
    LooseGitImportRefusal::Node(Box::new(error))
}

impl Placements<'_> {
    pub(super) fn push(
        &mut self,
        expected: GitOid,
        object: LooseObject,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        self.prepare(object.body.len(), control)?;
        if object.body.len() > CHUNK_BYTES {
            let stored = self
                .node
                .put_git_object(object.object_type, object.body)
                .map_err(node_error)?;
            if stored.identity() != expected {
                return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                    expected,
                    observed: stored.identity(),
                });
            }
            return control.checkpoint();
        }
        let verified = self.verify(expected, object)?;
        self.bytes += verified.payload().len();
        self.objects.push(verified);
        Ok(())
    }

    fn verify(
        &self,
        expected: GitOid,
        object: LooseObject,
    ) -> Result<VerifiedObject, LooseGitImportRefusal> {
        let offered = object.body.len() as u64;
        if offered > self.node.max_object_bytes {
            return Err(node_error(NodeRefusal::ObjectTooLarge {
                offered,
                maximum: self.node.max_object_bytes,
            }));
        }
        let kind = crypto_object_kind(object.object_type);
        let identity = git_object_id(self.node.object_format, kind, &object.body);
        if identity != expected {
            return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                expected,
                observed: identity,
            });
        }
        let commitment = git_payload_commitment(kind, &object.body, CANONICAL_CODEC_VERSION);
        let bytes: [u8; 32] = commitment
            .digest()
            .as_bytes()
            .try_into()
            .map_err(|_| node_error(NodeRefusal::ObjectLengthOverflow))?;
        // Byte-identical to the established single-object envelope. Tests pin
        // all envelope fields as well as native identities and stored payloads.
        let envelope = ObjectEnvelope::new(
            self.node.namespace.clone(),
            identity,
            fabric_object_kind(object.object_type),
            offered,
            bytes,
            OBJECT_CODEC_NAMESPACE.to_vec(),
            bytes,
            None,
            &self.node.segment_limits,
        )
        .map_err(|e| node_error(NodeRefusal::from(StoreRefusal::Fabric(e))))?;
        VerifiedObject::new(envelope, object.body).map_err(|e| node_error(NodeRefusal::from(e)))
    }

    pub(super) fn flush(
        &mut self,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        control.checkpoint()?;
        if self.objects.is_empty() {
            return Ok(());
        }
        let reserved_bytes = self
            .objects
            .iter()
            .map(|o| (o.payload().len() as u64).max(1))
            .sum();
        let resources = ResourceVector::from_grades(&[
            (Grade::Bytes, reserved_bytes),
            (Grade::Objects, self.objects.len() as u64),
        ]);
        let ledger = ObligationLedger::root(
            RegionId::new(1),
            LeakDisposition::RecordAndContinue,
            resources,
        );
        let grant = match ledger.grant(resources) {
            Ok(grant) => grant,
            Err(error) => {
                let closed = ledger.close();
                if !closed.is_quiescent() {
                    return Err(node_error(NodeRefusal::ResourceContainment));
                }
                return Err(node_error(NodeRefusal::from(error)));
            }
        };
        let result = self.node.fabric.put_batch_if_absent(
            &self.objects,
            PlacementAdmission::new(&ledger, grant),
            &mut || control.is_live(),
        );
        let closed = ledger.close();
        if !closed.is_quiescent() {
            return Err(node_error(NodeRefusal::ResourceContainment));
        }
        control.after(result, |e| node_error(NodeRefusal::from(e)))?;
        self.objects.clear();
        self.bytes = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
