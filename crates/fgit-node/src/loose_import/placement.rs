//! Import placement through bounded, fully settled object batches.
use super::{ImportControl, LooseGitImportRefusal, OneNode};
use crate::{NodeRefusal, OBJECT_CODEC_NAMESPACE};
use fgit_crypto::IdentifiedGitObject;
use fgit_object_fabric::fabric::{PlacementAdmission, VerifiedObject};
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::GitOid;

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
        object: IdentifiedGitObject,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        self.prepare(object.body().len(), control)?;
        if object.body().len() > CHUNK_BYTES {
            let kind = object.kind();
            let stored = self
                .node
                .put_git_object(kind, object.into_body())
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
        object: IdentifiedGitObject,
    ) -> Result<VerifiedObject, LooseGitImportRefusal> {
        let offered = object.body().len() as u64;
        if offered > self.node.max_object_bytes {
            return Err(node_error(NodeRefusal::ObjectTooLarge {
                offered,
                maximum: self.node.max_object_bytes,
            }));
        }
        // The custody read computed this identity from these exact bytes.
        if object.identity() != expected {
            return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                expected,
                observed: object.identity(),
            });
        }
        // Byte-identical to the established single-object envelope. Tests pin
        // all envelope fields as well as native identities and stored payloads.
        VerifiedObject::seal(
            self.node.namespace.clone(),
            object,
            OBJECT_CODEC_NAMESPACE.to_vec(),
            &self.node.segment_limits,
        )
        .map_err(|e| node_error(NodeRefusal::from(e)))
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
