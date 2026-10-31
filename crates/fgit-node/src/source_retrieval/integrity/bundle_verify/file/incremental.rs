//! File-backed incremental intake with a separately authorized prerequisite
//! source. Captured original spans are native-verified content, never pack
//! entries or authority. Current-basis admission remains the node's job.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};
use std::path::Path;

use fgit_git_object::ObjectType;
use fgit_pack::StreamPackReceipt;
use fgit_pack::full_bundle::{FullBundleError, FullBundleHeader};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::super::{BundleVerifyError, BundleVerifyLimits, GraphRefusal};
use super::import::{
    BundleImportObjectPlan, FullBundleImportBlobReader, FullBundleImportObject, OwnedScratch,
    RetainedBundleObjects, select_closure, select_objects,
};
use super::resolve::{Inventory, NativeEntryHash};
use super::storage::Scratch;
use super::{checkpoint, verify_reader_contents};

/// Metadata discovered within the authenticated visible prerequisite closure.
/// These facts alone establish neither body health nor a usable delta base.
#[derive(Clone, Copy, Debug)]
pub struct BundleOriginalObject {
    pub(crate) kind: ObjectType,
    pub(crate) length: usize,
}

/// A node-owned source selected from one authenticated basis and visible graph.
/// Implementations must authorize all prerequisites before inspecting their
/// individual kinds, expose exactly their complete native closure, and refuse
/// reads outside it. `read_into` succeeds only after the original fabric/native
/// stream reaches authenticated EOF. Its physical-read ledger continues the
/// discovery reads; it is never reset for capture or for another object.
///
/// The verifier independently binds the declared roots, hashes exact bodies,
/// checks the original-only closure and retains its own private descriptor.
/// No caller supplies scratch spans, pack offsets or completion receipts.
pub trait BundleOriginalSource {
    fn prerequisites(&self) -> &[GitOid];
    fn objects(&self) -> &BTreeMap<GitOid, BundleOriginalObject>;
    fn discovery_read_bytes(&self) -> usize;
    fn read_into(
        &mut self,
        identity: GitOid,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), BundleVerifyError>,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<(), BundleVerifyError>;
}

/// Actual incremental input plus retained upload custody. The selected union
/// contains borrowed native and transport dependencies; only uploaded members
/// can be read for staging. This is not self-contained full-bundle evidence.
pub struct IncrementalBundleImportPlan {
    header: FullBundleHeader,
    receipt: StreamPackReceipt,
    uploaded: BTreeSet<GitOid>,
    objects: RetainedBundleObjects,
}

impl IncrementalBundleImportPlan {
    pub(crate) const fn header(&self) -> &FullBundleHeader {
        &self.header
    }

    pub(crate) const fn receipt(&self) -> &StreamPackReceipt {
        &self.receipt
    }

    pub(crate) const fn selected_ids(&self) -> &BTreeSet<GitOid> {
        self.objects.selected_ids()
    }

    pub(crate) const fn uploaded_ids(&self) -> &BTreeSet<GitOid> {
        &self.uploaded
    }

    /// Only selected uploaded bytes are charged to incoming object placement.
    pub(crate) const fn total_selected_bytes(&self) -> u64 {
        self.objects.total_selected_bytes()
    }

    pub(crate) fn finish(self) -> Result<(), BundleVerifyError> {
        self.objects.finish()
    }
}

impl BundleImportObjectPlan for IncrementalBundleImportPlan {
    fn uploaded_ids(&self) -> &BTreeSet<GitOid> {
        self.uploaded_ids()
    }

    fn object(&self, identity: GitOid) -> Option<FullBundleImportObject> {
        self.objects.object(identity)
    }

    fn read_metadata(
        &mut self,
        identity: GitOid,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<Vec<u8>, BundleVerifyError> {
        self.objects.read_metadata(identity, &mut || live())
    }

    fn open_blob<'a>(
        &'a mut self,
        identity: GitOid,
        live: &'a mut dyn FnMut() -> bool,
    ) -> Result<FullBundleImportBlobReader<'a>, BundleVerifyError> {
        self.objects.open_blob(identity, live)
    }
}

/// Verify every supplied object and every declared prerequisite body, resolve
/// only native-verified pack or original bases, and retain the selected upload
/// closure. `max_original_bytes` includes actual discovery and capture reads;
/// incoming pack input/expansion limits remain independent. Original scratch
/// has the same exclusive identity and poisoned-reader rules as full import.
pub fn prepare_incremental_bundle_import_reader<R: Read + Seek>(
    input: &mut R,
    expected_format: GitHashAlgorithm,
    scratch_path: &Path,
    originals: &mut impl BundleOriginalSource,
    max_original_bytes: usize,
    limits: &BundleVerifyLimits,
    allow_work: &mut impl FnMut() -> bool,
) -> Result<IncrementalBundleImportPlan, BundleVerifyError> {
    let mut stopped = false;
    let mut live = || {
        if !stopped && !allow_work() {
            stopped = true;
        }
        !stopped
    };
    checkpoint(&mut live)?;
    let mut scratch = OwnedScratch::create(scratch_path)?;
    let prepared = (|| {
        let mut verified = verify_reader_contents(
            input,
            scratch.file_mut()?,
            limits,
            None,
            Some(expected_format),
            Some(originals),
            max_original_bytes,
            &mut live,
        )?;
        let original_bytes = verified.inventory.original_bytes() as u64;
        let mut workspace = Scratch::reopen_with_originals(
            scratch.file_mut()?,
            verified.scratch_bytes,
            limits,
            original_bytes,
            &mut live,
        )?;
        let mut union_limits = limits.clone();
        union_limits.graph.max_payload_bytes = union_limits
            .graph
            .max_payload_bytes
            .checked_add(original_bytes)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "payload bytes",
            )))?;
        let references = verified
            .header
            .references()
            .iter()
            .map(|row| (row.name().clone(), *row.target()))
            .collect();
        let (selected, mut objects, _) = select_closure(
            &mut verified.inventory,
            &mut workspace,
            verified.header.format(),
            &references,
            None,
            &union_limits,
            &mut live,
        )?;
        let mut uploaded = BTreeSet::new();
        let mut total = 0_u64;
        for &id in &selected {
            checkpoint(&mut live)?;
            if verified.inventory.by_id.contains_key(&id) {
                uploaded.insert(id);
                let facts = objects
                    .get(&id)
                    .ok_or(BundleVerifyError::ResolutionIncomplete)?;
                total = total
                    .checked_add(facts.facts.length as u64)
                    .filter(|bytes| *bytes <= limits.graph.max_payload_bytes)
                    .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                        "selected uploaded bytes",
                    )))?;
            }
        }
        objects.retain(|id, _| uploaded.contains(id));
        workspace.finish(&mut live)?;
        checkpoint(&mut live)?;
        Ok((verified, original_bytes, selected, uploaded, objects, total))
    })();
    let (verified, original_bytes, selected, uploaded, objects, total) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            scratch.cleanup()?;
            return Err(error);
        }
    };
    Ok(IncrementalBundleImportPlan {
        header: verified.header,
        receipt: verified.receipt,
        uploaded,
        objects: RetainedBundleObjects {
            scratch,
            scratch_bytes: verified.scratch_bytes,
            original_bytes,
            selected,
            objects,
            total_selected_bytes: total,
            limits: limits.clone(),
            failed: false,
        },
    })
}

pub(super) fn capture_originals<W: Read + Write + Seek>(
    source: &mut dyn BundleOriginalSource,
    header: &FullBundleHeader,
    inventory: &mut Inventory,
    scratch: &mut Scratch<'_, W>,
    max_original_bytes: usize,
    limits: &BundleVerifyLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), BundleVerifyError> {
    checkpoint(live)?;
    if source.prerequisites() != header.prerequisites() {
        return Err(BundleVerifyError::SourceChanged);
    }
    if source.objects().len() > limits.graph.max_objects {
        return Err(BundleVerifyError::Graph(GraphRefusal::Limit(
            "original objects",
        )));
    }
    let mut read_bytes = source.discovery_read_bytes();
    if read_bytes > max_original_bytes {
        return Err(BundleVerifyError::Graph(GraphRefusal::Limit(
            "original read bytes",
        )));
    }
    inventory.charge_selection_work(read_bytes, limits)?;
    let mut facts = Vec::new();
    facts
        .try_reserve_exact(source.objects().len())
        .map_err(|_| BundleVerifyError::Allocation)?;
    let mut planned_bytes = read_bytes;
    for (&identity, &object) in source.objects() {
        checkpoint(live)?;
        if identity.is_zero() || identity.algorithm() != header.format() {
            return Err(BundleVerifyError::Graph(GraphRefusal::ObjectFormat(
                identity,
            )));
        }
        let maximum = if object.kind == ObjectType::Blob {
            limits.max_streamed_blob_bytes
        } else {
            limits
                .pack
                .max_object_bytes
                .min(limits.graph.max_object_bytes)
        };
        if object.length > maximum {
            return Err(BundleVerifyError::Graph(GraphRefusal::Limit(
                "original object bytes",
            )));
        }
        planned_bytes = planned_bytes
            .checked_add(object.length)
            .filter(|bytes| *bytes <= max_original_bytes)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                "original read bytes",
            )))?;
        facts.push((identity, object));
    }
    for &identity in header.prerequisites() {
        checkpoint(live)?;
        let object = source
            .objects()
            .get(&identity)
            .ok_or(BundleVerifyError::Graph(GraphRefusal::MissingTarget {
                source: None,
                target: identity,
            }))?;
        if object.kind != ObjectType::Commit {
            return Err(BundleVerifyError::Graph(GraphRefusal::TargetKind {
                target: identity,
                expected: ObjectType::Commit,
                actual: object.kind,
            }));
        }
    }
    // Freeze source metadata before any callback. No caller can change a span
    // length/kind after the exact bounded native hash has been initialized.
    for (identity, object) in facts {
        checkpoint(live)?;
        inventory.charge_selection_work(1, limits)?;
        let mut append = scratch.begin_append(object.length, live)?;
        let mut native = NativeEntryHash::new(header.format(), object.kind, object.length);
        let mut failed = false;
        {
            let gate = RefCell::new(&mut *live);
            let mut source_live = || (gate.borrow_mut())();
            let mut sink = |bytes: &[u8]| {
                let result = (|| {
                    if failed {
                        return Err(BundleVerifyError::Graph(GraphRefusal::Failed));
                    }
                    let mut sink_live = || (gate.borrow_mut())();
                    checkpoint(&mut sink_live)?;
                    read_bytes = read_bytes
                        .checked_add(bytes.len())
                        .filter(|count| *count <= max_original_bytes)
                        .ok_or(BundleVerifyError::Graph(GraphRefusal::Limit(
                            "original read bytes",
                        )))?;
                    inventory.charge_selection_work(bytes.len(), limits)?;
                    native.update(bytes)?;
                    scratch.append_chunk(&mut append, bytes, &mut sink_live)
                })();
                if result.is_err() {
                    failed = true;
                }
                result
            };
            let result = source.read_into(identity, &mut sink, &mut source_live);
            checkpoint(&mut source_live)?;
            result?;
        }
        if failed {
            return Err(BundleVerifyError::Graph(GraphRefusal::Failed));
        }
        if native.finish()? != identity {
            return Err(BundleVerifyError::Graph(GraphRefusal::IdentityMismatch(
                identity,
            )));
        }
        let span = scratch.finish_append(append, live)?;
        inventory.retain_original(identity, object.kind, span, limits)?;
    }
    if read_bytes != planned_bytes {
        return Err(BundleVerifyError::SourceChanged);
    }
    checkpoint(live)
}

pub(super) fn validate_original_closure<W: Read + Write + Seek>(
    header: &FullBundleHeader,
    inventory: &mut Inventory,
    scratch: &mut Scratch<'_, W>,
    limits: &BundleVerifyLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), BundleVerifyError> {
    let roots = header.prerequisites().iter().copied().collect();
    let (selected, _, _) = select_objects(
        inventory,
        scratch,
        header.format(),
        roots,
        true,
        limits,
        live,
    )?;
    if selected.len() != inventory.originals.len() {
        return Err(BundleVerifyError::Envelope(FullBundleError::Invalid(
            "original object outside declared prerequisite closure",
        )));
    }
    checkpoint(live)
}
