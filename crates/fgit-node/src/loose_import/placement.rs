//! Import placement through bounded, fully settled object batches.
//!
//! One batch at a time is in flight: staged, with its files syncing in the
//! background and no name linked. It is settled before the next batch stages
//! and before placement returns, so reading, hashing and sealing the next
//! batch overlaps that sync (frankengit-ai60).
use super::{ImportControl, LooseGitImportRefusal, OneNode};
use crate::{NodeRefusal, OBJECT_CODEC_NAMESPACE};
use fgit_crypto::IdentifiedGitObject;
use fgit_object_fabric::fabric::{PlacementAdmission, VerifiedObject};
use fgit_object_fabric::local::StagedBatch;
use fgit_resource::{Grade, LeakDisposition, ObligationLedger, RegionId, ResourceVector};
use fgit_types::GitOid;

const CHUNK_OBJECTS: usize = 256;
const CHUNK_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct Placements<'a> {
    node: &'a OneNode,
    objects: Vec<VerifiedObject>,
    bytes: usize,
    in_flight: Option<InFlight>,
}

/// A staged batch and the ledger holding its reservations.
struct InFlight {
    batch: StagedBatch,
    ledger: ObligationLedger,
}

impl<'a> Placements<'a> {
    pub(super) fn new(node: &'a OneNode) -> Self {
        Self {
            node,
            objects: Vec::new(),
            bytes: 0,
            in_flight: None,
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

    /// Settles the batch in flight, then stages the pending objects as the
    /// next batch in flight. Nothing staged here is durable until
    /// [`Self::finish`].
    pub(super) fn flush(
        &mut self,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        control.checkpoint()?;
        self.settle(control)?;
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
        let staged = self.node.fabric.stage_batch_if_absent(
            std::mem::take(&mut self.objects),
            PlacementAdmission::new(&ledger, grant),
            &mut || control.is_live(),
        );
        self.bytes = 0;
        match staged {
            Ok(batch) => {
                self.in_flight = Some(InFlight { batch, ledger });
                Ok(())
            }
            Err(error) => {
                if !ledger.close().is_quiescent() {
                    return Err(node_error(NodeRefusal::ResourceContainment));
                }
                control.after(Err(error), |e| node_error(NodeRefusal::from(e)))
            }
        }
    }

    /// Places the pending objects and settles every batch. Only after this
    /// returns is each placed object durable under its immutable name.
    pub(super) fn finish(
        &mut self,
        control: &ImportControl<'_>,
    ) -> Result<(), LooseGitImportRefusal> {
        self.flush(control)?;
        self.settle(control)
    }

    /// Settles a batch left in flight by `refusal`: waits for its syncs and
    /// aborts its reservations, linking nothing. A leaked reservation, then a
    /// refused abort, outranks `refusal`, as in a single batch placement.
    pub(super) fn abandon(&mut self, refusal: LooseGitImportRefusal) -> LooseGitImportRefusal {
        let Some(InFlight { batch, ledger }) = self.in_flight.take() else {
            return refusal;
        };
        let aborted = batch.abandon();
        if !ledger.close().is_quiescent() {
            return node_error(NodeRefusal::ResourceContainment);
        }
        aborted.map_or_else(|error| node_error(NodeRefusal::from(error)), |()| refusal)
    }

    /// Waits for the batch in flight to sync, then links its names and syncs
    /// their directories.
    fn settle(&mut self, control: &ImportControl<'_>) -> Result<(), LooseGitImportRefusal> {
        let Some(InFlight { batch, ledger }) = self.in_flight.take() else {
            return Ok(());
        };
        let result = self
            .node
            .fabric
            .publish_staged_batch(batch, &mut || control.is_live());
        if !ledger.close().is_quiescent() {
            return Err(node_error(NodeRefusal::ResourceContainment));
        }
        control.after(result, |e| node_error(NodeRefusal::from(e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
