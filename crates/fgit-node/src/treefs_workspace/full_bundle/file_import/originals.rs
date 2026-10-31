//! Native custody for declared incremental-bundle prerequisites.
//!
//! Visibility discovery selects identities and typed edges from one authenticated
//! admission snapshot. Blob envelopes are selection facts only. Every selected
//! original is read again through authenticated native storage before the bundle
//! verifier may rely on it; one byte ledger covers both phases.

use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;

use fgit_admission::PermittedObjectClosure;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, parse_object_body};
use fgit_object_fabric::fabric::VerifiedObject;
use fgit_object_fabric::{ObjectKind, StoreRefusal};
use fgit_pack::full_bundle::stream::MAX_INCREMENTAL_EXTERNAL_OBJECTS;
use fgit_pack::full_bundle::{FullBundleError, MAX_BUNDLE_PREREQUISITES};
use fgit_treefs::integrity::GraphRefusal;
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

use crate::source_retrieval::integrity::bundle_verify::{
    BundleOriginalObject, BundleOriginalSource, BundleVerifyError, BundleVerifyLimits,
};
use crate::{MaterializedAdmission, NodeRequestContext, OneNode};

use super::{NodeWorkspaceRefusal, StreamBundleImportRefusal};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_DISCOVERY_EDGES: usize = 4_000_000;

struct DiscoveredObject {
    metadata: BundleOriginalObject,
    edges: Vec<(GitOid, ObjectType)>,
}

/// The frozen borrowing set is exactly the complete closure of declared,
/// currently visible commit prerequisites. Merely stored objects are never read.
pub(in crate::treefs_workspace::full_bundle) struct SelectedBundleOriginals<'a> {
    node: &'a OneNode,
    request: &'a NodeRequestContext,
    prerequisites: Vec<GitOid>,
    objects: BTreeMap<GitOid, BundleOriginalObject>,
    discovery_read_bytes: usize,
    read_bytes: usize,
    maximum_read_bytes: usize,
    maximum_metadata_bytes: usize,
    maximum_blob_bytes: usize,
    stopped: bool,
    failed: bool,
}

impl<'a> SelectedBundleOriginals<'a> {
    pub(in crate::treefs_workspace::full_bundle) fn new(
        node: &'a OneNode,
        request: &'a NodeRequestContext,
        materialized: &MaterializedAdmission,
        prerequisites: &[GitOid],
        limits: &BundleVerifyLimits,
        max_original_bytes: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, StreamBundleImportRefusal> {
        let mut selected = Self {
            node,
            request,
            prerequisites: Vec::new(),
            objects: BTreeMap::new(),
            discovery_read_bytes: 0,
            read_bytes: 0,
            maximum_read_bytes: max_original_bytes,
            maximum_metadata_bytes: limits
                .pack
                .max_object_bytes
                .min(limits.graph.max_object_bytes)
                .min(usize::try_from(node.max_object_bytes).unwrap_or(usize::MAX))
                .min(crate::DEFAULT_MAX_OBJECT_BYTES as usize),
            maximum_blob_bytes: limits.max_streamed_blob_bytes.min(
                node.service_config
                    .bundle_import_blob_limit
                    .unwrap_or_else(|| {
                        usize::try_from(node.max_object_bytes).unwrap_or(usize::MAX)
                    }),
            ),
            stopped: false,
            failed: false,
        };
        selected.checkpoint(live)?;
        if prerequisites.is_empty() {
            // A full bundle sent through sync-import borrows nothing, even when
            // the receiver already has useful objects in its local fabric.
            return Ok(selected);
        }
        let maximum_objects = limits
            .graph
            .max_objects
            .min(usize::try_from(limits.pack.max_entries).unwrap_or(usize::MAX))
            .min(limits.pack.max_index_entries)
            .min(MAX_INCREMENTAL_EXTERNAL_OBJECTS);
        if prerequisites.len() > MAX_BUNDLE_PREREQUISITES || prerequisites.len() > maximum_objects {
            return Err(limit("original prerequisites").into());
        }
        selected
            .prerequisites
            .try_reserve_exact(prerequisites.len())
            .map_err(|_| BundleVerifyError::Allocation)?;
        selected.prerequisites.extend_from_slice(prerequisites);
        selected.prerequisites.sort_unstable();
        for index in 0..selected.prerequisites.len() {
            selected.checkpoint(live)?;
            let id = selected.prerequisites[index];
            if id.is_zero() || id.algorithm() != node.object_format {
                return Err(BundleVerifyError::Graph(GraphRefusal::ObjectFormat(id)).into());
            }
            if index > 0 && selected.prerequisites[index - 1] == id {
                return Err(BundleVerifyError::Envelope(FullBundleError::Invalid(
                    "duplicate prerequisite",
                ))
                .into());
            }
            if !materialized
                .selected_closure()
                .closure()
                .objects()
                .contains(&id)
            {
                return Err(NodeWorkspaceRefusal::RefUnavailable.into());
            }
        }

        let graph = selected.discover_visible(materialized, limits, maximum_objects, live)?;
        // Check the visibility of ALL requested roots before exposing a kind.
        for index in 0..selected.prerequisites.len() {
            selected.checkpoint(live)?;
            let id = &selected.prerequisites[index];
            if !graph.contains_key(id) {
                return Err(NodeWorkspaceRefusal::RefUnavailable.into());
            }
        }
        for index in 0..selected.prerequisites.len() {
            selected.checkpoint(live)?;
            let id = &selected.prerequisites[index];
            if graph[id].metadata.kind != ObjectType::Commit {
                return Err(NodeWorkspaceRefusal::CommitRequired.into());
            }
        }

        let mut pending: BTreeSet<_> = selected.prerequisites.iter().copied().collect();
        let mut seen = pending.clone();
        let mut edges_left = limits.graph.max_edges.min(MAX_DISCOVERY_EDGES);
        let mut capture_bytes = 0usize;
        while let Some(id) = pending.pop_first() {
            selected.checkpoint(live)?;
            let original = graph.get(&id).ok_or_else(|| missing(None, id))?;
            if original.metadata.kind == ObjectType::Blob
                && original.metadata.length > selected.maximum_blob_bytes
            {
                return Err(limit("original blob bytes").into());
            }
            capture_bytes = capture_bytes
                .checked_add(original.metadata.length)
                .ok_or_else(|| limit("original read bytes"))?;
            selected.require_remaining(capture_bytes)?;
            selected.objects.insert(id, original.metadata);
            for &(child, expected) in &original.edges {
                selected.checkpoint(live)?;
                edges_left = edges_left
                    .checked_sub(1)
                    .ok_or_else(|| limit("original closure edges"))?;
                let target = graph.get(&child).ok_or_else(|| missing(Some(id), child))?;
                require_kind(child, expected, target.metadata.kind)?;
                if !seen.contains(&child) {
                    if seen.len() >= maximum_objects {
                        return Err(limit("original objects").into());
                    }
                    seen.insert(child);
                    pending.insert(child);
                }
            }
        }
        selected.checkpoint(live)?;
        selected.discovery_read_bytes = selected.read_bytes;
        Ok(selected)
    }

    /// Read each visible metadata object once, retaining only native typed edges.
    /// Blob bodies remain unread. This walk proves membership, never blob health.
    fn discover_visible(
        &mut self,
        materialized: &MaterializedAdmission,
        limits: &BundleVerifyLimits,
        maximum_objects: usize,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<BTreeMap<GitOid, DiscoveredObject>, BundleVerifyError> {
        let admitted = materialized.selected_closure().closure();
        let mut required = BTreeMap::new();
        let mut pending = BTreeSet::new();
        let mut graph: BTreeMap<GitOid, DiscoveredObject> = BTreeMap::new();
        let mut references = 0usize;
        // Validate all visible roots against the selected closure before reads.
        for (name, &tip) in &materialized.snapshot().refs {
            self.checkpoint(live)?;
            if materialized.snapshot().hidden_refs.hides(name.as_bytes()) {
                continue;
            }
            references = references
                .checked_add(1)
                .ok_or_else(|| limit("original visible references"))?;
            // Existing repository refs are independent of the incoming bundle's
            // advertised-ref and atomic-command ceilings. Count duplicate tips
            // too, under the finite original discovery/frontier allowance.
            if references > maximum_objects {
                return Err(limit("original visible references"));
            }
            enqueue(
                self.node.object_format,
                admitted,
                tip,
                None,
                maximum_objects,
                &mut required,
                &mut pending,
            )?;
        }
        let parse_limits = ParseLimits {
            max_object_bytes: self.maximum_metadata_bytes,
            tree_reference_bytes: self.node.object_format.digest_len(),
            ..ParseLimits::default()
        };
        let mut edges_left = limits.graph.max_edges.min(MAX_DISCOVERY_EDGES);
        while let Some(id) = pending.pop_first() {
            let metadata = self.read_header(id, live)?;
            if let Some(Some(expected)) = required.get(&id) {
                require_kind(id, *expected, metadata.kind)?;
            }
            let edges = if metadata.kind == ObjectType::Blob {
                Vec::new()
            } else {
                let object = self.read_metadata(id, metadata, live)?;
                let parse_limits = ParseLimits {
                    max_tree_entries: parse_limits.max_tree_entries.min(edges_left),
                    ..parse_limits.clone()
                };
                let parsed = parse_object_body(
                    metadata.kind,
                    object.payload(),
                    AcceptanceProfile::GitCompatibleImport,
                    &parse_limits,
                );
                self.checkpoint(live)?;
                let parsed = parsed.map_err(|cause| {
                    BundleVerifyError::Graph(GraphRefusal::Malformed {
                        object: id,
                        cause: Box::new(cause),
                    })
                })?;
                let edges = crate::loose_import::graph::references(
                    self.node.object_format,
                    &parsed,
                    object.payload(),
                    &parse_limits,
                    &mut edges_left,
                    &mut || self.checkpoint(live).is_ok(),
                );
                // The sticky stop observed inside the parser owns the refusal.
                self.checkpoint(live)?;
                edges.map_err(|code| match code {
                    RefusalCode::ResourceBudgetExceeded => limit("original discovery edges"),
                    RefusalCode::CancellationInProgress => BundleVerifyError::Stopped,
                    _ => BundleVerifyError::Graph(GraphRefusal::Failed),
                })?
            };
            for &(child, expected) in &edges {
                self.checkpoint(live)?;
                if let Some(known) = graph.get(&child) {
                    require_kind(child, expected, known.metadata.kind)?;
                }
                enqueue(
                    self.node.object_format,
                    admitted,
                    child,
                    Some(expected),
                    maximum_objects,
                    &mut required,
                    &mut pending,
                )?;
            }
            graph.insert(id, DiscoveredObject { metadata, edges });
        }
        self.checkpoint(live)?;
        Ok(graph)
    }

    fn checkpoint(&mut self, live: &mut dyn FnMut() -> bool) -> Result<(), BundleVerifyError> {
        if self.stopped {
            return Err(BundleVerifyError::Stopped);
        }
        if self.failed {
            return Err(BundleVerifyError::Graph(GraphRefusal::Failed));
        }
        if !live() || !self.request.is_live() {
            self.stopped = true;
            return Err(BundleVerifyError::Stopped);
        }
        Ok(())
    }

    fn require_remaining(&self, bytes: usize) -> Result<(), BundleVerifyError> {
        if self
            .read_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.maximum_read_bytes)
        {
            Err(limit("original read bytes"))
        } else {
            Ok(())
        }
    }

    fn charge_read(&mut self, bytes: usize) -> Result<(), BundleVerifyError> {
        self.require_remaining(bytes)?;
        self.read_bytes += bytes;
        Ok(())
    }

    fn read_header(
        &mut self,
        identity: GitOid,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<BundleOriginalObject, BundleVerifyError> {
        self.checkpoint(live)?;
        let header = self.node.fabric.read_header_bounded(identity, u64::MAX);
        self.checkpoint(live)?;
        let header = header.map_err(|error| storage_error(identity, error))?;
        let kind = native_kind(header.kind)?;
        let length =
            usize::try_from(header.payload_length).map_err(|_| limit("original object bytes"))?;
        if kind != ObjectType::Blob && length > self.maximum_metadata_bytes {
            return Err(limit("original metadata bytes"));
        }
        Ok(BundleOriginalObject { kind, length })
    }

    fn read_metadata(
        &mut self,
        identity: GitOid,
        expected: BundleOriginalObject,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<VerifiedObject, BundleVerifyError> {
        self.checkpoint(live)?;
        if expected.kind == ObjectType::Blob || expected.length > self.maximum_metadata_bytes {
            return Err(limit("original metadata bytes"));
        }
        // Reserve before the bounded allocation/read. On success its exact
        // length is checked below, so all surviving discovery counts are actual
        // native body bytes. Any read failure poisons the enclosing operation.
        self.charge_read(expected.length)?;
        let loaded = self
            .node
            .fabric
            .read_whole_bounded(identity, expected.length as u64);
        self.checkpoint(live)?;
        let object = loaded
            .map_err(|error| storage_error(identity, error))?
            .object;
        if object.identity() != identity
            || native_kind(object.envelope().object_kind())? != expected.kind
            || object.payload().len() != expected.length
        {
            return Err(BundleVerifyError::SourceChanged);
        }
        Ok(object)
    }

    fn read_selected(
        &mut self,
        identity: GitOid,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), BundleVerifyError>,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        self.checkpoint(live)?;
        let expected = self
            .objects
            .get(&identity)
            .copied()
            .ok_or_else(|| missing(None, identity))?;
        self.require_remaining(expected.length)?;
        if expected.kind != ObjectType::Blob {
            let object = self.read_metadata(identity, expected, live)?;
            let written = sink(object.payload());
            self.checkpoint(live)?;
            return written;
        }
        if expected.length > self.maximum_blob_bytes {
            return Err(limit("original blob bytes"));
        }
        let opened = self
            .node
            .fabric
            .open_blob_stream_bounded(identity, expected.length as u64);
        self.checkpoint(live)?;
        let mut stream = opened.map_err(|error| storage_error(identity, error))?;
        if stream.identity() != identity || stream.declared_length() != expected.length as u64 {
            return Err(BundleVerifyError::SourceChanged);
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(CHUNK_BYTES)
            .map_err(|_| BundleVerifyError::Allocation)?;
        buffer.resize(CHUNK_BYTES, 0);
        let mut consumed = 0usize;
        loop {
            self.checkpoint(live)?;
            let read = stream.read_tentative(&mut buffer);
            if let Ok(count) = read.as_ref() {
                self.charge_read(*count)?;
            }
            self.checkpoint(live)?;
            match read {
                Ok(0) => {
                    if !stream.is_verified() || consumed != expected.length {
                        return Err(BundleVerifyError::SourceChanged);
                    }
                    return Ok(());
                }
                Ok(count) => {
                    consumed = consumed
                        .checked_add(count)
                        .ok_or_else(|| limit("original read bytes"))?;
                    let written = sink(&buffer[..count]);
                    self.checkpoint(live)?;
                    written?;
                }
                Err(StoreRefusal::StorageIo {
                    kind: ErrorKind::Interrupted,
                    ..
                }) => {}
                Err(error) => return Err(storage_error(identity, error)),
            }
        }
    }
}

impl BundleOriginalSource for SelectedBundleOriginals<'_> {
    fn prerequisites(&self) -> &[GitOid] {
        &self.prerequisites
    }

    fn objects(&self) -> &BTreeMap<GitOid, BundleOriginalObject> {
        &self.objects
    }

    fn discovery_read_bytes(&self) -> usize {
        self.discovery_read_bytes
    }

    fn read_into(
        &mut self,
        identity: GitOid,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), BundleVerifyError>,
        live: &mut dyn FnMut() -> bool,
    ) -> Result<(), BundleVerifyError> {
        let result = self.read_selected(identity, sink, live);
        if result.is_err() {
            // A failed consumer has no complete custody. Neither a retry nor a
            // later successful stop probe can turn that partial read into proof.
            self.failed = true;
        }
        result
    }
}

fn limit(name: &'static str) -> BundleVerifyError {
    BundleVerifyError::Graph(GraphRefusal::Limit(name))
}

fn missing(source: Option<GitOid>, target: GitOid) -> BundleVerifyError {
    BundleVerifyError::Graph(GraphRefusal::MissingTarget { source, target })
}

fn native_kind(kind: ObjectKind) -> Result<ObjectType, BundleVerifyError> {
    match kind {
        ObjectKind::Commit => Ok(ObjectType::Commit),
        ObjectKind::Tree => Ok(ObjectType::Tree),
        ObjectKind::Blob => Ok(ObjectType::Blob),
        ObjectKind::Tag => Ok(ObjectType::Tag),
        ObjectKind::Internal => Err(BundleVerifyError::Graph(GraphRefusal::Failed)),
    }
}

fn require_kind(
    target: GitOid,
    expected: ObjectType,
    actual: ObjectType,
) -> Result<(), BundleVerifyError> {
    if expected == actual {
        Ok(())
    } else {
        Err(BundleVerifyError::Graph(GraphRefusal::TargetKind {
            target,
            expected,
            actual,
        }))
    }
}

fn enqueue(
    format: GitHashAlgorithm,
    admitted: &PermittedObjectClosure,
    identity: GitOid,
    expected: Option<ObjectType>,
    maximum: usize,
    required: &mut BTreeMap<GitOid, Option<ObjectType>>,
    pending: &mut BTreeSet<GitOid>,
) -> Result<(), BundleVerifyError> {
    if identity.is_zero() || identity.algorithm() != format {
        return Err(BundleVerifyError::Graph(GraphRefusal::ObjectFormat(
            identity,
        )));
    }
    if !admitted.objects().contains(&identity) {
        return Err(missing(None, identity));
    }
    if let Some(previous) = required.get_mut(&identity) {
        if let (Some(first), Some(next)) = (*previous, expected) {
            require_kind(identity, first, next)?;
        }
        if previous.is_none() {
            *previous = expected;
        }
        return Ok(());
    }
    if required.len() >= maximum {
        return Err(limit("original objects"));
    }
    required.insert(identity, expected);
    pending.insert(identity);
    Ok(())
}

fn storage_error(identity: GitOid, error: StoreRefusal) -> BundleVerifyError {
    match error {
        StoreRefusal::StorageIo { kind, .. } => BundleVerifyError::Io {
            operation: "read selected original",
            kind,
        },
        StoreRefusal::PayloadCommitmentMismatch | StoreRefusal::NativeObjectIdentityMismatch => {
            BundleVerifyError::Graph(GraphRefusal::IdentityMismatch(identity))
        }
        StoreRefusal::StreamingBudgetExceeded { .. } => BundleVerifyError::SourceChanged,
        _ => missing(None, identity),
    }
}
