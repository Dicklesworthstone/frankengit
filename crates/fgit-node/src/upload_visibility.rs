//! Exact-head disclosure for the production upload-pack transport.
//!
//! Cumulative admission proves storage provenance, not current disclosure.
//! Derive one complete visible native graph before negotiation, then use that
//! same private proof for wants, ACKs, and pack selection. Never narrow or
//! rewrite the canonical per-decision closure or the trusted local exporter.
use super::{
    AcceptanceProfile, AdmissionUploadPackRepository, AdvertisedRef, AnyGitOid, Arc, BTreeMap,
    BTreeSet, BudgetClass, Cell, GitDaemonSessionDeadline, GitHashAlgorithm, GitOid,
    MaterializedAdmission, NodeAdmissionViewRefusal, NodeGitDaemonServeRefusal,
    NodePackMaterializationRefusal, NodeRequestContext, ObjectType, OneNode, PackError, PackLimits,
    PackRequest, PackWriteError, ParseLimits, PermittedClosureTraversalSource,
    PermittedObjectClosure, PublicationBasis, RefusalCode, UploadPackRepository,
    VerifiedFabricPackSource, WireError, WireLimits, entry_limit_error, parse_object_body,
};
#[cfg(test)]
use super::{
    AdmissionContext, AdmissionLimits, AdmissionSnapshot, AtomicBool, AtomicU64, Capabilities,
    CeiledFabricSource, Duration, FsqliteCx, GitDaemonSessionOutcome, GitDaemonSessionTimeout,
    GitDaemonSessionWorkScaling, GitObjectKind, HeadGeneration, IdempotencyKey,
    LoopbackReceiveSession, NodeConfig, NodeSmartHttpRefusal, Ordering, PackPlanner,
    PackWriteProfile, PackWriter, Packet, PathBuf, PrincipalId, ReceiveContext, ReceiveLimits,
    RefName, RefVisibility, RepositoryId, SegmentLimits, Shutdown, SignedPushProfile,
    SourceImportOrigin, SourceImportReceipt, SourceRefUpdate, TcpListener, TcpStream, TenantId,
    UploadPackVersion, V2UploadPack, ValidatedClosure, VerifiedFabricBlobReader,
    crypto_object_kind, encode_packets, git_object_id, permitted_object_closure_root,
    selected_pack_ids_and_held, validate_source_import,
};
#[cfg(test)]
use super::{CanonicalBlobReader, PackPayloadSource};
mod partial_clone;
pub(crate) use partial_clone::unserved_filter_name;
pub mod shallow;
pub mod tags;

const MAX_DISCLOSURE_EDGES: usize = 4_000_000;
const DISCLOSURE_OPERATION: &str = "verify visible upload-pack graph";

/// Constructible only after the entire selected graph has been checked:
/// every commit, tree and tag body is read and native-verified, and every blob
/// reached through a typed edge is checked by kind and exact size from its
/// stored envelope. A blob body is verified when a pack selects it, never
/// disclosed unverified. The aggregate read budget therefore counts commit,
/// tree and tag bytes; packs charge blob bytes (frankengit-8xyq).
/// The derived set is not an RCR root and is deliberately not persisted.
pub struct VisibleUploadPack {
    basis: PublicationBasis,
    closure: PermittedObjectClosure,
    repository: AdmissionUploadPackRepository,
    pub(super) tags: tags::TagProjection,
    objects: Arc<BTreeMap<GitOid, partial_clone::FilterObject>>,
}

impl VisibleUploadPack {
    pub(super) fn select_partial(
        &self,
        ids: &mut Vec<GitOid>,
        request: &PackRequest,
        limits: &PackLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodePackMaterializationRefusal> {
        if !shallow::requested(request) {
            return partial_clone::apply_selection(&self.objects, ids, request, limits, live);
        }
        let mut selected = shallow::select(&self.objects, request, limits, live)?;
        // History has already been clipped and validated. Reuse the existing
        // partial-clone engine for omission predicates and explicit lazy roots.
        let mut filtered = request.clone();
        filtered.options = filtered.options.with_deepen_relative(false);
        filtered.shallows.clear();
        filtered.deepen = None;
        filtered.deepen_since = None;
        filtered.deepen_not.clear();
        partial_clone::apply_selection(&self.objects, &mut selected, &filtered, limits, live)?;
        *ids = selected;
        Ok(())
    }

    pub(super) const fn repository(&self) -> &AdmissionUploadPackRepository {
        &self.repository
    }

    /// The verified kind of a visible object, which orders a streamed pack
    /// before any body is read (frankengit-8xyq).
    pub(super) fn kind_of(&self, id: &GitOid) -> Option<ObjectType> {
        self.objects.get(id).map(|object| object.kind)
    }

    /// Pack selection over this proof's verified graph (frankengit-8xyq).
    /// `source` supplies the object format and liveness checkpoints only.
    pub(super) fn selection_source<'a, S>(&'a self, source: &'a S) -> VisibleGraphSelection<'a, S> {
        VisibleGraphSelection {
            objects: &self.objects,
            source,
        }
    }

    pub(super) fn closure_for(
        &self,
        materialized: &MaterializedAdmission,
    ) -> Result<&PermittedObjectClosure, NodePackMaterializationRefusal> {
        if self.basis != *materialized.basis() {
            return Err(disclosure_refusal(RefusalCode::AuthorityReceiptStale));
        }
        Ok(&self.closure)
    }
}

impl OneNode {
    pub(super) fn prepare_visible_upload_pack(
        &self,
        request: &NodeRequestContext,
        materialized: &MaterializedAdmission,
        limits: &WireLimits,
        deadline: &GitDaemonSessionDeadline,
    ) -> Result<VisibleUploadPack, NodeGitDaemonServeRefusal> {
        deadline.check(DISCLOSURE_OPERATION)?;
        let repository = AdmissionUploadPackRepository::from_snapshot(
            materialized.snapshot(),
            self.object_format,
            limits,
        )
        .map_err(NodeAdmissionViewRefusal::from)?;
        let exhaustion = Cell::new(None);
        let live = || !deadline.expired();
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes: self
                .selected_pack_limits
                .max_object_bytes
                .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX)),
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: Some(&live),
        };
        let graph = project_visible_graph(
            &source,
            materialized.selected_closure().closure(),
            repository
                .advertised_refs()
                .iter()
                .map(|reference| reference.oid),
            &self.selected_pack_limits,
        );
        let derived = graph.and_then(|graph| {
            tags::TagProjection::new(&graph.tag_targets, repository.advertised_refs(), || {
                source.checkpoint()
            })
            .map(|tags| (graph, tags))
        });
        // Preserve the established outer-session > Database > object-refusal
        // precedence, including a deadline crossed inside an immutable read.
        deadline.check(DISCLOSURE_OPERATION)?;
        if let Some(dimension) = exhaustion.get() {
            return Err(NodePackMaterializationRefusal::BudgetClassExhausted {
                class: BudgetClass::Database,
                dimension,
                operation: DISCLOSURE_OPERATION,
            }
            .into());
        }
        let (graph, tags) = derived?;
        let closure = graph.closure;
        let mut repository = repository.with_closure_objects(closure.objects().clone());
        repository.tag_peels = tags.peels.clone();
        let objects = Arc::new(graph.objects);
        repository.shallow_proof = Some(shallow::ShallowProof::new(
            Arc::clone(&objects),
            self.selected_pack_limits.clone(),
            deadline.clone(),
        ));
        Ok(VisibleUploadPack {
            basis: materialized.basis().clone(),
            closure,
            repository,
            tags,
            objects,
        })
    }
}

const fn disclosure_refusal(code: RefusalCode) -> NodePackMaterializationRefusal {
    NodePackMaterializationRefusal::DisclosureGraph(code)
}

/// The production implementation always returns native-verified immutable
/// bodies. The narrow seam allows budget and read-set assertions in tests.
trait VisibilitySource {
    fn format(&self) -> GitHashAlgorithm;
    fn parse_limits(&self) -> ParseLimits;
    fn checkpoint(&self) -> Result<(), NodePackMaterializationRefusal>;
    fn load(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), NodePackMaterializationRefusal>;
    /// Kind and exact size without the body, for a blob the walk reached
    /// through a typed edge. Nothing the walk returns discloses its bytes.
    fn load_header(
        &self,
        id: GitOid,
    ) -> Result<(ObjectType, usize), NodePackMaterializationRefusal>;
}

impl VisibilitySource for VerifiedFabricPackSource<'_> {
    fn format(&self) -> GitHashAlgorithm {
        self.object_format
    }
    fn parse_limits(&self) -> ParseLimits {
        VerifiedFabricPackSource::parse_limits(self)
    }
    fn checkpoint(&self) -> Result<(), NodePackMaterializationRefusal> {
        self.session_checkpoint()?;
        if !self.database_read_is_live() {
            return Err(PackWriteError::from(PackError::DeadlineExceeded).into());
        }
        Ok(())
    }
    fn load(&self, id: GitOid) -> Result<(ObjectType, Vec<u8>), NodePackMaterializationRefusal> {
        self.read_object(&id)
            .map_err(NodePackMaterializationRefusal::from)
    }
    fn load_header(
        &self,
        id: GitOid,
    ) -> Result<(ObjectType, usize), NodePackMaterializationRefusal> {
        // The fabric bounds and validates the envelope and stored file. This
        // header-only read allocates no payload. The selected-pack payload
        // ceiling must not reject blobs that a filtered or up-to-date request
        // will never read; every selected body still passes `read_object`.
        self.read_object_header_within(&id, usize::MAX)
            .map_err(NodePackMaterializationRefusal::from)
    }
}

/// Every edge here was taken from a native-verified body (or, for a blob, is
/// absent) during the disclosure walk. Want and have reachability therefore
/// reads no object, and the planner reads and verifies only what it packs.
/// Before, selection re-read every reachable body, blobs included, so even a
/// small incremental fetch read the whole repository once.
pub(super) struct VisibleGraphSelection<'a, S> {
    objects: &'a BTreeMap<GitOid, partial_clone::FilterObject>,
    source: &'a S,
}

impl<S: PermittedClosureTraversalSource> PermittedClosureTraversalSource
    for VisibleGraphSelection<'_, S>
{
    fn object_format(&self) -> GitHashAlgorithm {
        self.source.object_format()
    }

    fn selection_checkpoint(&self) -> Result<(), PackWriteError> {
        self.source.selection_checkpoint()
    }

    fn references(&self, id: &GitOid) -> Result<Vec<GitOid>, PackWriteError> {
        self.source.selection_checkpoint()?;
        let object = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(object.edges.iter().map(|(child, _)| *child).collect())
    }
}

struct VisibleGraph {
    closure: PermittedObjectClosure,
    tag_targets: BTreeMap<GitOid, GitOid>,
    objects: BTreeMap<GitOid, partial_clone::FilterObject>,
}

#[cfg(test)]
fn project_visible_closure(
    source: &impl VisibilitySource,
    admitted: &PermittedObjectClosure,
    roots: impl IntoIterator<Item = GitOid>,
    limits: &PackLimits,
) -> Result<PermittedObjectClosure, NodePackMaterializationRefusal> {
    project_visible_graph(source, admitted, roots, limits).map(|graph| graph.closure)
}

fn project_visible_graph(
    source: &impl VisibilitySource,
    admitted: &PermittedObjectClosure,
    roots: impl IntoIterator<Item = GitOid>,
    limits: &PackLimits,
) -> Result<VisibleGraph, NodePackMaterializationRefusal> {
    source.checkpoint()?;
    let maximum = usize::try_from(limits.max_entries).unwrap_or(usize::MAX);
    let mut required = BTreeMap::<GitOid, Option<ObjectType>>::new();
    let mut pending = BTreeSet::new();
    let mut known = BTreeMap::<GitOid, ObjectType>::new();
    let mut tag_targets = BTreeMap::new();
    let mut objects = BTreeMap::new();
    // Validate ALL roots before a read. A visible ref outside the authenticated
    // admitted set is inconsistent state, never permission to search storage.
    for root in roots {
        source.checkpoint()?;
        enqueue(
            source.format(),
            admitted,
            root,
            None,
            maximum,
            &mut required,
            &mut pending,
        )?;
    }
    let mut bytes = 0_usize;
    let mut edges_left = limits.max_total_expanded_bytes.min(MAX_DISCLOSURE_EDGES);
    let parse_limits = source.parse_limits();
    while let Some(id) = pending.pop_first() {
        source.checkpoint()?;
        // A blob reached through a typed edge has no edges of its own, so the
        // walk needs only its kind and size (frankengit-8xyq). Reading the
        // header keeps every ls-remote and fetch independent of blob bytes,
        // and a blob's body is read and verified only when a pack selects it.
        if required.get(&id) == Some(&Some(ObjectType::Blob)) {
            let header = source.load_header(id);
            source.checkpoint()?;
            let (kind, size) = header?;
            // A typed blob has no outgoing edges. Retain its exact size for
            // filter selection without applying a body-allocation limit to
            // metadata. The pack source checks that limit before any selected
            // body allocation, and verifies the body before emitting bytes.
            require_kind(kind, ObjectType::Blob)?;
            known.insert(id, kind);
            objects.insert(
                id,
                partial_clone::FilterObject {
                    commit_time: None,
                    kind,
                    size,
                    edges: Vec::new(),
                },
            );
            continue;
        }
        let loaded = source.load(id);
        source.checkpoint()?;
        let (kind, body) = loaded?;
        if body.len() > limits.max_object_bytes || body.len() > parse_limits.max_object_bytes {
            return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
        }
        bytes = bytes
            .checked_add(body.len())
            .ok_or_else(|| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
        if bytes > limits.max_total_expanded_bytes {
            return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
        }
        if let Some(Some(expected)) = required.get(&id) {
            require_kind(kind, *expected)?;
        }
        // Blobs have no local edges. Avoid a second full-body parsed copy.
        let mut commit_time = None;
        let edges = if kind == ObjectType::Blob {
            Vec::new()
        } else {
            let parsed = parse_object_body(
                kind,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits,
            );
            source.checkpoint()?;
            let parsed =
                parsed.map_err(|_| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?;
            commit_time = shallow::cutoffs::committer_time(&parsed);
            let mut stopped = None;
            let edges = crate::loose_import::graph::references(
                source.format(),
                &parsed,
                &body,
                &parse_limits,
                &mut edges_left,
                &mut || {
                    if stopped.is_some() {
                        return false;
                    }
                    match source.checkpoint() {
                        Ok(()) => true,
                        Err(error) => {
                            stopped = Some(error);
                            false
                        }
                    }
                },
            );
            // A later successful probe cannot erase an already observed stop.
            if let Some(error) = stopped {
                return Err(error);
            }
            source.checkpoint()?;
            edges.map_err(disclosure_refusal)?
        };
        if kind == ObjectType::Tag {
            let [(target, _)] = edges.as_slice() else {
                return Err(disclosure_refusal(RefusalCode::ObjectHeaderInvalid));
            };
            tag_targets.insert(id, *target);
        }
        known.insert(id, kind);
        for &(child, expected) in &edges {
            source.checkpoint()?;
            // Every edge is checked, including one into an already loaded root.
            if let Some(actual) = known.get(&child) {
                require_kind(*actual, expected)?;
            }
            enqueue(
                source.format(),
                admitted,
                child,
                Some(expected),
                maximum,
                &mut required,
                &mut pending,
            )?;
        }
        objects.insert(
            id,
            partial_clone::FilterObject {
                commit_time,
                kind,
                size: body.len(),
                edges,
            },
        );
    }
    source.checkpoint()?;
    Ok(VisibleGraph {
        closure: PermittedObjectClosure::new(known.into_keys().collect()),
        tag_targets,
        objects,
    })
}

fn enqueue(
    format: GitHashAlgorithm,
    admitted: &PermittedObjectClosure,
    id: GitOid,
    expected: Option<ObjectType>,
    maximum: usize,
    required: &mut BTreeMap<GitOid, Option<ObjectType>>,
    pending: &mut BTreeSet<GitOid>,
) -> Result<(), NodePackMaterializationRefusal> {
    if id.is_zero() || id.algorithm() != format {
        return Err(disclosure_refusal(RefusalCode::ObjectHeaderInvalid));
    }
    if !admitted.objects().contains(&id) {
        return Err(disclosure_refusal(RefusalCode::ObjectClosureIncomplete));
    }
    if let Some(previous) = required.get_mut(&id) {
        if let (Some(first), Some(next)) = (*previous, expected) {
            require_kind(first, next)?;
        }
        if previous.is_none() {
            *previous = expected;
        }
        return Ok(());
    }
    // Count on enqueue, not dequeue: a broad frontier is bounded as well as
    // the completed set. Duplicate edges cannot repeatedly grow either set.
    if required.len() >= maximum {
        return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
    }
    required.insert(id, expected);
    pending.insert(id);
    Ok(())
}

fn require_kind(
    actual: ObjectType,
    expected: ObjectType,
) -> Result<(), NodePackMaterializationRefusal> {
    if actual == expected {
        Ok(())
    } else {
        Err(disclosure_refusal(RefusalCode::EvidenceInvalid))
    }
}

#[cfg(test)]
mod tests;

/// Reuse the transport's complete typed graph verifier for offline transfer.
/// The caller has selected the exact visible ref roots at its authenticated head.
pub fn bundle_visible_closure(
    source: &VerifiedFabricPackSource<'_>,
    admitted: &PermittedObjectClosure,
    roots: impl IntoIterator<Item = GitOid>,
    limits: &PackLimits,
) -> Result<PermittedObjectClosure, NodePackMaterializationRefusal> {
    project_visible_graph(source, admitted, roots, limits).map(|graph| graph.closure)
}
