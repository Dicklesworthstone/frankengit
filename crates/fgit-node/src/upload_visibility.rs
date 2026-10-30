//! Exact-head disclosure for the production upload-pack transport.
//!
//! Cumulative admission proves storage provenance, not current disclosure.
//! Derive one complete visible native graph before negotiation, then use that
//! same private proof for wants, ACKs, and pack selection. Never narrow or
//! rewrite the canonical per-decision closure or the trusted local exporter.
use super::{
    AcceptanceProfile, AdmissionUploadPackRepository, AdvertisedRef, AnyGitOid, Arc, BTreeMap,
    BTreeSet, BudgetClass, CacheBinding, CacheScope, Cell, GitDaemonSessionDeadline,
    GitHashAlgorithm, GitOid, HeadGeneration, MaterializedAdmission, NodeAdmissionViewRefusal,
    NodeGitDaemonServeRefusal, NodePackMaterializationRefusal, NodeRequestContext, ObjectType,
    OneNode, OpaqueHandle, PackError, PackLimits, PackOrderKey, PackRequest, PackWriteError,
    ParseLimits, ParsedObject, PermittedClosureTraversalSource, PermittedObjectClosure,
    PublicationBasis, RefusalCode, RwLock, UploadPackRepository, VerifiedFabricPackSource,
    WireError, WireLimits, entry_limit_error, parse_object_body, selected_pack_ids_and_held,
};
#[cfg(test)]
use super::{
    AdmissionContext, AdmissionLimits, AdmissionSnapshot, AtomicBool, AtomicU64, Capabilities,
    CeiledFabricSource, Duration, FsqliteCx, GitDaemonSessionOutcome, GitDaemonSessionTimeout,
    GitDaemonSessionWorkScaling, GitObjectKind, IdempotencyKey, LoopbackReceiveSession, NodeConfig,
    NodeSmartHttpRefusal, Ordering, PackPlanner, PackWriteProfile, PackWriter, Packet, PathBuf,
    PrincipalId, ReceiveContext, ReceiveLimits, RefName, RefVisibility, RepositoryId,
    SegmentLimits, Shutdown, SignedPushProfile, SourceImportOrigin, SourceImportReceipt,
    SourceRefUpdate, TcpListener, TcpStream, TenantId, UploadPackVersion, V2UploadPack,
    ValidatedClosure, VerifiedFabricBlobReader, crypto_object_kind, encode_packets, git_object_id,
    permitted_object_closure_root, validate_source_import,
};
#[cfg(test)]
use super::{CanonicalBlobReader, PackPayloadSource};
use fgit_pack::basename_path_hash;
use std::cell::RefCell;
mod partial_clone;
pub(crate) use partial_clone::unserved_filter_name;
pub mod shallow;
pub mod tags;

const MAX_DISCLOSURE_EDGES: usize = 4_000_000;
const DISCLOSURE_OPERATION: &str = "verify visible upload-pack graph";
const VISIBLE_PROJECTION_CACHE_SCOPE: &[u8] = b"node/upload-visibility-cache/v1";

/// One reusable visible projection, shared by the service children opened
/// from one configuration (frankengit-8g42).
///
/// `project_visible_graph` reads every visible commit, tree and tag and every
/// blob header, so before this cache every ls-remote, fetch and clone of a long
/// history paid for the whole history even when the head had not moved. The
/// projection is a pure function of the materialization's exact authenticated
/// basis (its repository, head identity and generation, as a [`CacheBinding`]),
/// the advertised roots, and the object format and limits it was computed
/// under; an entry is reused only when all of them match. It never selects objects or grants disclosure on its own: every
/// session still materializes and authenticates its own basis first, wants and
/// packs are still checked against it, and a refused or deadline-cut
/// projection is never stored. Losing the entry only costs a recomputation.
#[derive(Debug, Default)]
pub struct VisibleProjectionCache {
    entry: RwLock<Option<Arc<VisibleProjection>>>,
    reused: std::sync::atomic::AtomicU64,
    computed: std::sync::atomic::AtomicU64,
}

impl VisibleProjectionCache {
    /// Sessions that reused the entry, and sessions that computed one.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.reused.load(std::sync::atomic::Ordering::Relaxed),
            self.computed.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    fn lookup(&self, key: &ProjectionKey<'_>) -> Option<Arc<VisibleProjection>> {
        // A poisoned lock only loses the reuse; the session recomputes.
        let found = self.entry.read().ok().and_then(|entry| {
            entry
                .as_ref()
                .filter(|projection| projection.matches(key))
                .map(Arc::clone)
        });
        let counter = if found.is_some() {
            &self.reused
        } else {
            &self.computed
        };
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        found
    }

    /// The current entry, at any basis and roots, when it was computed under
    /// the same object format and limits: its per-object facts seed the next
    /// walk (slice 2). Facts describe content-addressed objects, so they hold
    /// at every basis; the walk re-applies every check and budget itself.
    fn seed(&self, key: &ProjectionKey<'_>) -> Option<Arc<VisibleProjection>> {
        self.entry.read().ok().and_then(|entry| {
            entry
                .as_ref()
                .filter(|projection| projection.same_terms(key))
                .map(Arc::clone)
        })
    }

    fn publish(&self, projection: Arc<VisibleProjection>) {
        let Ok(mut entry) = self.entry.write() else {
            return;
        };
        // A late session at an older basis must not displace a newer entry.
        let Some(generation) = projection.generation() else {
            return;
        };
        let newer = entry
            .as_ref()
            .and_then(|current| current.generation())
            .is_some_and(|current| current > generation);
        if !newer {
            *entry = Some(projection);
        }
    }
}

/// Everything a cached projection was computed from.
struct ProjectionKey<'a> {
    binding: CacheBinding,
    format: GitHashAlgorithm,
    limits: &'a PackLimits,
    maximum_object_bytes: usize,
    roots: &'a [GitOid],
}

/// The session-independent part of a [`VisibleUploadPack`].
#[derive(Debug)]
struct VisibleProjection {
    /// `None` only when no cache key could be built; such a projection is
    /// used by its own session and never published.
    key: Option<StoredKey>,
    graph: VisibleGraph,
    objects: Arc<BTreeMap<GitOid, partial_clone::FilterObject>>,
}

#[derive(Debug)]
struct StoredKey {
    binding: CacheBinding,
    format: GitHashAlgorithm,
    limits: PackLimits,
    maximum_object_bytes: usize,
    roots: Vec<GitOid>,
}

impl VisibleProjection {
    fn new(key: Option<&ProjectionKey<'_>>, mut graph: VisibleGraph) -> Self {
        let objects = Arc::new(core::mem::take(&mut graph.objects));
        Self {
            key: key.map(|key| StoredKey {
                binding: key.binding,
                format: key.format,
                limits: key.limits.clone(),
                maximum_object_bytes: key.maximum_object_bytes,
                roots: key.roots.to_vec(),
            }),
            graph,
            objects,
        }
    }

    fn matches(&self, key: &ProjectionKey<'_>) -> bool {
        self.same_terms(key)
            && self
                .key
                .as_ref()
                .is_some_and(|stored| stored.binding == key.binding && stored.roots == key.roots)
    }

    fn same_terms(&self, key: &ProjectionKey<'_>) -> bool {
        self.key.as_ref().is_some_and(|stored| {
            stored.format == key.format
                && stored.limits == *key.limits
                && stored.maximum_object_bytes == key.maximum_object_bytes
        })
    }

    fn memo(&self) -> ProjectionMemo<'_> {
        ProjectionMemo {
            objects: &self.objects,
            facts: &self.graph.facts,
        }
    }

    fn generation(&self) -> Option<HeadGeneration> {
        self.key.as_ref().map(|stored| stored.binding.generation())
    }
}

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
    /// One deterministic ordering hint per named visible object. These never
    /// authorize membership or retain names; body verification still governs
    /// every selected object. Unnamed roots retain the zero hint.
    path_hashes: BTreeMap<GitOid, u64>,
}

impl VisibleUploadPack {
    /// Selects once over the verified graph, then counts only the final pack's
    /// exact object bytes. No object-fabric body is read by this preparation.
    pub(super) fn prepare_selection(
        &self,
        request: &PackRequest,
        limits: &PackLimits,
        buffered_object_bytes: usize,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(Vec<PackOrderKey>, BTreeSet<GitOid>, usize), NodePackMaterializationRefusal> {
        let (mut ids, held) = if shallow::requested(request) {
            (Vec::new(), BTreeSet::new())
        } else {
            let source = PreparedGraphSelection {
                format: self.repository.object_format,
                objects: &self.objects,
                live: RefCell::new(&mut *live),
            };
            selected_pack_ids_and_held(
                &source,
                &self.closure,
                Some(&request.wants),
                &request.haves,
                limits,
            )?
        };
        self.select_partial(&mut ids, request, limits, live)?;
        if request.options.include_tag() {
            self.tags.extend_selected(&mut ids, limits, live)?;
        }
        let mut keys = Vec::new();
        keys.try_reserve_exact(ids.len()).map_err(|_| {
            PackWriteError::from(PackError::AllocationFailed {
                requested: ids.len(),
            })
        })?;
        let mut expanded_bytes = 0_usize;
        for id in ids {
            if !live() {
                return Err(PackWriteError::from(PackError::DeadlineExceeded).into());
            }
            let object = self
                .objects
                .get(&id)
                .ok_or(PackWriteError::MissingCanonicalObject(id))?;
            let maximum_object_bytes = if object.kind == ObjectType::Blob {
                limits.max_object_bytes
            } else {
                buffered_object_bytes
            };
            if object.size > maximum_object_bytes {
                return Err(PackWriteError::from(PackError::ObjectSizeLimit {
                    actual: object.size,
                    limit: maximum_object_bytes,
                })
                .into());
            }
            expanded_bytes = expanded_bytes.checked_add(object.size).ok_or_else(|| {
                PackWriteError::from(PackError::IntegerOverflow {
                    context: "selected upload expanded bytes",
                })
            })?;
            keys.push(PackOrderKey {
                id,
                object_type: object.kind,
                recency: 0,
                path_hash: self.path_hash_of(&id),
            });
        }
        // Complete the bounded metadata pass so the refusal reports the actual
        // selected total, rather than the first object that crosses the limit.
        if expanded_bytes > limits.max_total_expanded_bytes {
            return Err(PackWriteError::from(PackError::TotalExpandedLimit {
                actual: expanded_bytes,
                limit: limits.max_total_expanded_bytes,
            })
            .into());
        }
        // Source adapters look up metadata by identity without retaining a
        // second map. The writer independently applies its frozen pack order.
        keys.sort_unstable_by_key(|key| key.id);
        Ok((keys, held, expanded_bytes))
    }

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

    /// A packing hint from verified visible tree metadata, never authority.
    pub(super) fn path_hash_of(&self, id: &GitOid) -> u64 {
        self.path_hashes.get(id).copied().unwrap_or(0)
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

/// The disclosure graph is already verified. Preflight needs its edges and a
/// Transfer checkpoint, never a body-capable fabric source.
struct PreparedGraphSelection<'a, F> {
    format: GitHashAlgorithm,
    objects: &'a BTreeMap<GitOid, partial_clone::FilterObject>,
    live: RefCell<&'a mut F>,
}

impl<F: FnMut() -> bool> PermittedClosureTraversalSource for PreparedGraphSelection<'_, F> {
    fn object_format(&self) -> GitHashAlgorithm {
        self.format
    }

    fn selection_checkpoint(&self) -> Result<(), PackWriteError> {
        if (self.live.borrow_mut())() {
            Ok(())
        } else {
            Err(PackError::DeadlineExceeded.into())
        }
    }

    fn references(&self, id: &GitOid) -> Result<Vec<GitOid>, PackWriteError> {
        self.selection_checkpoint()?;
        let object = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(object.edges.iter().map(|(child, _)| *child).collect())
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
        let maximum_object_bytes = self
            .selected_pack_limits
            .max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric,
            object_format: self.object_format,
            maximum_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: Some(&live),
        };
        let roots = repository
            .advertised_refs()
            .iter()
            .map(|reference| reference.oid)
            .collect::<Vec<_>>();
        // The binding names the exact authenticated basis this session
        // materialized; the scope cannot fail to build from a constant, and
        // without one the session simply does not reuse or publish.
        let key = OpaqueHandle::new(VISIBLE_PROJECTION_CACHE_SCOPE)
            .ok()
            .map(|scope| ProjectionKey {
                binding: CacheBinding::new(
                    self.repository_id,
                    materialized.basis().id(),
                    materialized.basis().generation(),
                    CacheScope::new(scope),
                ),
                format: self.object_format,
                limits: &self.selected_pack_limits,
                maximum_object_bytes,
                roots: &roots,
            });
        let cache = &self.service_config.upload_visibility_cache;
        let reused = key.as_ref().and_then(|key| cache.lookup(key));
        let computed = reused.is_none();
        let projection = reused.map_or_else(
            || {
                let seed = key.as_ref().and_then(|key| cache.seed(key));
                walk_visible_graph(
                    &source,
                    materialized.selected_closure().closure(),
                    roots.iter().copied(),
                    &self.selected_pack_limits,
                    seed.as_deref().map(VisibleProjection::memo).as_ref(),
                )
                .map(|graph| Arc::new(VisibleProjection::new(key.as_ref(), graph)))
            },
            Ok,
        );
        let derived = projection.and_then(|projection| {
            tags::TagProjection::new(
                &projection.graph.tag_targets,
                repository.advertised_refs(),
                || source.checkpoint(),
            )
            .map(|tags| (projection, tags))
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
        let (projection, tags) = derived?;
        if computed {
            cache.publish(Arc::clone(&projection));
        }
        let closure = projection.graph.closure.clone();
        let mut repository = repository.with_closure_objects(closure.objects().clone());
        repository.tag_peels = tags.peels.clone();
        let objects = Arc::clone(&projection.objects);
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
            path_hashes: projection.graph.path_hashes.clone(),
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

#[derive(Debug, PartialEq, Eq)]
struct VisibleGraph {
    closure: PermittedObjectClosure,
    tag_targets: BTreeMap<GitOid, GitOid>,
    objects: BTreeMap<GitOid, partial_clone::FilterObject>,
    path_hashes: BTreeMap<GitOid, u64>,
    /// How the walk handled each object it read whole, so a later walk can
    /// reproduce that without reading it again (frankengit-8g42).
    facts: BTreeMap<GitOid, WalkFacts>,
}

/// What one whole-object read contributed to a walk, beyond its
/// [`partial_clone::FilterObject`]. Objects are content-addressed, so these
/// never depend on the basis; the budgets they are charged against do, and a
/// seeded walk re-applies them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WalkFacts {
    /// Edge-budget units the read charged (a tree's gitlink entries included).
    charged: usize,
    /// For a tree, the basename hint of each local edge, in edge order.
    hints: Vec<u64>,
}

/// Facts from an earlier walk under the same object format and limits.
struct ProjectionMemo<'a> {
    objects: &'a BTreeMap<GitOid, partial_clone::FilterObject>,
    facts: &'a BTreeMap<GitOid, WalkFacts>,
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
    walk_visible_graph(source, admitted, roots, limits, None)
}

/// Walks the visible graph from `roots`. With a `memo`, an object an earlier
/// walk already read is not read again: its stored facts pass through the
/// same checks, in the same order, as a read would (frankengit-8g42), so the
/// result, including any refusal, equals an unseeded walk's.
fn walk_visible_graph(
    source: &impl VisibilitySource,
    admitted: &PermittedObjectClosure,
    roots: impl IntoIterator<Item = GitOid>,
    limits: &PackLimits,
    memo: Option<&ProjectionMemo<'_>>,
) -> Result<VisibleGraph, NodePackMaterializationRefusal> {
    let edge_budget = limits.max_total_expanded_bytes.min(MAX_DISCLOSURE_EDGES);
    walk_within_edge_budget(source, admitted, roots, limits, edge_budget, memo)
}

/// [`walk_visible_graph`] with its edge budget named, so the budget a seeded
/// walk charges can be exercised below the byte envelope.
fn walk_within_edge_budget(
    source: &impl VisibilitySource,
    admitted: &PermittedObjectClosure,
    roots: impl IntoIterator<Item = GitOid>,
    limits: &PackLimits,
    edge_budget: usize,
    memo: Option<&ProjectionMemo<'_>>,
) -> Result<VisibleGraph, NodePackMaterializationRefusal> {
    source.checkpoint()?;
    let maximum = usize::try_from(limits.max_entries).unwrap_or(usize::MAX);
    let mut required = BTreeMap::<GitOid, Option<ObjectType>>::new();
    let mut pending = BTreeSet::new();
    let mut known = BTreeMap::<GitOid, ObjectType>::new();
    let mut tag_targets = BTreeMap::new();
    let mut objects = BTreeMap::new();
    let mut path_hashes = BTreeMap::new();
    let mut facts = BTreeMap::new();
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
    let mut edges_left = edge_budget;
    let parse_limits = source.parse_limits();
    while let Some(id) = pending.pop_first() {
        source.checkpoint()?;
        let remembered = memo.and_then(|memo| memo.objects.get(&id).map(|object| (memo, object)));
        // A blob reached through a typed edge has no edges of its own, so the
        // walk needs only its kind and size (frankengit-8xyq). Reading the
        // header keeps every ls-remote and fetch independent of blob bytes,
        // and a blob's body is read and verified only when a pack selects it.
        if required.get(&id) == Some(&Some(ObjectType::Blob)) {
            let (kind, size) = if let Some((_, object)) = remembered {
                (object.kind, object.size)
            } else {
                let header = source.load_header(id);
                source.checkpoint()?;
                header?
            };
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
        if let Some((object, stored)) =
            remembered.and_then(|(memo, object)| Some((object, memo.facts.get(&id)?)))
        {
            // The checks a read of these exact bytes would make, in order.
            if object.size > limits.max_object_bytes || object.size > parse_limits.max_object_bytes
            {
                return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
            }
            bytes = bytes
                .checked_add(object.size)
                .ok_or_else(|| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
            if bytes > limits.max_total_expanded_bytes {
                return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
            }
            if let Some(Some(expected)) = required.get(&id) {
                require_kind(object.kind, *expected)?;
            }
            edges_left = edges_left
                .checked_sub(stored.charged)
                .ok_or_else(|| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
            visit_edges(
                source,
                admitted,
                maximum,
                id,
                object.kind,
                &object.edges,
                &mut known,
                &mut tag_targets,
                &mut required,
                &mut pending,
            )?;
            merge_path_hints(&object.edges, &stored.hints, &mut path_hashes);
            objects.insert(id, object.clone());
            facts.insert(id, stored.clone());
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
        let parsed = if kind == ObjectType::Blob {
            None
        } else {
            let parsed = parse_object_body(
                kind,
                &body,
                AcceptanceProfile::GitCompatibleImport,
                &parse_limits,
            );
            source.checkpoint()?;
            Some(parsed.map_err(|_| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?)
        };
        let commit_time = parsed.as_ref().and_then(shallow::cutoffs::committer_time);
        let charge_before = edges_left;
        let edges = if let Some(parsed) = &parsed {
            let mut stopped = None;
            let edges = crate::loose_import::graph::references(
                source.format(),
                parsed,
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
        } else {
            Vec::new()
        };
        let charged = charge_before - edges_left;
        visit_edges(
            source,
            admitted,
            maximum,
            id,
            kind,
            &edges,
            &mut known,
            &mut tag_targets,
            &mut required,
            &mut pending,
        )?;
        let hints = if let Some(ParsedObject::Tree(entries)) = &parsed {
            // Every local edge was admitted and charged above, so this map
            // cannot grow beyond the bounded set of required objects. The
            // parser already owns the names; retain only one hash per object.
            tree_path_hints(source, entries, &edges)?
        } else {
            Vec::new()
        };
        merge_path_hints(&edges, &hints, &mut path_hashes);
        objects.insert(
            id,
            partial_clone::FilterObject {
                commit_time,
                kind,
                size: body.len(),
                edges,
            },
        );
        facts.insert(id, WalkFacts { charged, hints });
    }
    source.checkpoint()?;
    Ok(VisibleGraph {
        closure: PermittedObjectClosure::new(known.into_keys().collect()),
        tag_targets,
        objects,
        path_hashes,
        facts,
    })
}

/// Records a loaded object's kind and tag target, and admits its edges.
fn visit_edges(
    source: &impl VisibilitySource,
    admitted: &PermittedObjectClosure,
    maximum: usize,
    id: GitOid,
    kind: ObjectType,
    edges: &[(GitOid, ObjectType)],
    known: &mut BTreeMap<GitOid, ObjectType>,
    tag_targets: &mut BTreeMap<GitOid, GitOid>,
    required: &mut BTreeMap<GitOid, Option<ObjectType>>,
    pending: &mut BTreeSet<GitOid>,
) -> Result<(), NodePackMaterializationRefusal> {
    if kind == ObjectType::Tag {
        let [(target, _)] = edges else {
            return Err(disclosure_refusal(RefusalCode::ObjectHeaderInvalid));
        };
        tag_targets.insert(id, *target);
    }
    known.insert(id, kind);
    for &(child, expected) in edges {
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
            required,
            pending,
        )?;
    }
    Ok(())
}

/// Keeps the minimum hint per object across every tree that names it.
fn merge_path_hints(
    edges: &[(GitOid, ObjectType)],
    hints: &[u64],
    path_hashes: &mut BTreeMap<GitOid, u64>,
) {
    for (&(child, _), &hint) in edges.iter().zip(hints) {
        path_hashes
            .entry(child)
            .and_modify(|previous| *previous = (*previous).min(hint))
            .or_insert(hint);
    }
}

/// Fold names in the same edge order as the shared native graph classifier.
/// The mode's type bits, rather than spelling, exclude imported gitlinks.
/// Multiple names choose the minimum hash independent of root or tree order;
/// collisions can affect compression only, never object disclosure.
fn tree_path_hints(
    source: &impl VisibilitySource,
    entries: &[fgit_git_object::TreeEntry],
    edges: &[(GitOid, ObjectType)],
) -> Result<Vec<u64>, NodePackMaterializationRefusal> {
    let mut hints = Vec::with_capacity(edges.len());
    let mut local_edges = edges.iter();
    for entry in entries {
        source.checkpoint()?;
        let mode = std::str::from_utf8(&entry.mode)
            .ok()
            .and_then(|mode| u32::from_str_radix(mode, 8).ok())
            .ok_or_else(|| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?;
        if mode & 0o170_000 == 0o160_000 {
            continue;
        }
        let (child, _) = local_edges
            .next()
            .ok_or_else(|| disclosure_refusal(RefusalCode::EvidenceInvalid))?;
        if child.as_bytes() != entry.object_id.as_slice() {
            return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
        }
        let hint = basename_path_hash(&entry.name);
        source.checkpoint()?;
        hints.push(hint);
    }
    if local_edges.next().is_some() {
        return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
    }
    Ok(hints)
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
