//! Bounded native commit and merge validation over a real object source.
//! Caller-supplied edge metadata is not closure evidence: outgoing edges and
//! their required kinds are parsed from independently verified native bytes.

use std::collections::{BTreeMap, BTreeSet};

use fgit_diff::{
    AncestryQueryScratch, AncestryQueryWork, CommitAncestryIndex, CommitGraph, MergeBaseError,
    MergeBaseLimits, MergeBaseResult, ParentSet, frontier_merge_bases_all,
};
use fgit_forge::event::NativeMerge;
use fgit_git_object::{
    AcceptanceProfile, ObjectError, ObjectType, ParseLimits, ParsedObject, parse_object_body,
};
use fgit_pack::{CanonicalObjectSource, Deadline, PackError, PackWriteError, verify_native_object};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

use crate::{
    PermittedObjectClosure, ProjectionFailure, ValidatedClosure, permitted_object_closure_root,
};

/// Bounded native metadata at an independently admitted object frontier.
/// This does not claim the payload was read, hashed or scrubbed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalObjectHeader {
    pub id: GitOid,
    pub object_type: ObjectType,
    pub body_bytes: usize,
}

/// Optional metadata lookup for reused objects only. Implementations must
/// retain exact-key, disclosure, size and cancellation checks. `None` keeps
/// ordinary full-body loading and accounting. New/candidate objects are never
/// validated through this interface; pack emission never uses it either.
pub trait FrontierObjectHeaders {
    fn load_header(&self, id: &GitOid) -> Result<Option<CanonicalObjectHeader>, PackWriteError>;
}

/// An authenticated selected set with an optional bounded metadata provider.
/// The caller still owns source authorization: this container grants none.
/// Passing an ordinary `&BTreeSet` retains all historical full-read semantics.
#[derive(Clone, Copy)]
pub struct ObjectFrontier<'a> {
    objects: &'a BTreeSet<GitOid>,
    headers: Option<&'a dyn FrontierObjectHeaders>,
}
impl<'a> ObjectFrontier<'a> {
    #[must_use]
    pub fn with_headers(
        objects: &'a BTreeSet<GitOid>,
        headers: &'a dyn FrontierObjectHeaders,
    ) -> Self {
        Self {
            objects,
            headers: Some(headers),
        }
    }
}
impl<'a> From<&'a BTreeSet<GitOid>> for ObjectFrontier<'a> {
    fn from(objects: &'a BTreeSet<GitOid>) -> Self {
        Self {
            objects,
            headers: None,
        }
    }
}

/// Largest independently bounded admitted-blob metadata profile (16 GiB).
pub const MAX_REUSED_BLOB_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Independent object/work ceilings. A caller also supplies its live deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MergeObjectLimits {
    /// Unique objects requiring bodies in the closure walk. Independently
    /// admitted, header-verified frontier objects spend the edge budget instead.
    /// A missing optional header still reserves one body before loading it.
    /// Full walks and frontiers without a header provider retain their old cap.
    pub max_objects: usize,
    pub max_edges: usize,
    pub max_object_bytes: usize,
    /// Payload length of an admitted blob checked through frontier metadata.
    /// Defaults to 32 MiB and may be raised through [`MAX_REUSED_BLOB_BYTES`].
    /// This never widens a body allocation or a commit/tree/tag parsing bound.
    /// A declined header retains `max_object_bytes`, including for blobs.
    pub max_reused_blob_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for MergeObjectLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_edges: 400_000,
            max_object_bytes: 32 * 1024 * 1024,
            max_reused_blob_bytes: 32 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Verify an explicit reviewed two-parent merge and its entire Git closure.
/// Candidate parents must be target-before then source; the supplied base must
/// actually be an ancestor of both. The tree is the reviewed result, not a
/// claim that this validator reran a particular merge algorithm. Gitlinks are
/// external-repository references and are not traversed.
///
/// Every identity is independently hashed. Caller-supplied edge lists are
/// ignored. Missing bodies remain unavailable dependencies, and no partial
/// closure is returned after cancellation or resource exhaustion.
pub fn validate_merge_objects(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    merge.validate().map_err(|_| invalid())?;
    validate_candidate_objects(
        source,
        merge.merge_commit,
        Some(&[merge.target_tip_before, merge.source_tip]),
        AncestryRequirement::Merge {
            base: merge.base_tip,
        },
        None,
        limits,
        deadline,
    )
}

/// Verify a no-new-commit fast-forward using the SAME bounded, independently
/// hashed object walk. The target must occur in the source's actual commit
/// parent graph, not merely in a claimed edge list, tree, gitlink or local store.
/// The caller separately proves current branch selection and authorization.
/// Divergence is a deterministic refusal; missing/corrupt input and interruption
/// never return a partial or successful closure. The two-parent API is unchanged.
pub fn validate_fast_forward_objects(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    merge.validate().map_err(|_| invalid())?;
    if merge.merge_commit != merge.source_tip || merge.base_tip != merge.target_tip_before {
        return Err(invalid());
    }
    validate_candidate_objects(
        source,
        merge.source_tip,
        None,
        AncestryRequirement::FastForward {
            base: merge.target_tip_before,
        },
        None,
        limits,
        deadline,
    )
}

/// Verify a reviewed one-parent squash and BOTH original branch histories.
/// The candidate must name only target-before as a parent. Its source is an
/// additional commit root in the same deduplicated walk, so source-only trees,
/// blobs and ancestors share every object, byte, edge and cancellation budget.
/// The supplied base must occur through commit parents in both branch histories;
/// a caller's edge metadata or an unrelated object in the store is no proof.
///
/// This returns verified bytes, not source authorization. The caller must bind
/// source/target tips to the selected refs and source/base to the authority's
/// admitted closure. The reviewed tree is not a claim that this validator reran
/// a merge algorithm. No partial closure survives failure or cancellation.
pub fn validate_squash_objects(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    merge.validate().map_err(|_| invalid())?;
    if merge.source_tip == merge.target_tip_before {
        return Err(invalid());
    }
    validate_candidate_objects(
        source,
        merge.merge_commit,
        Some(&[merge.target_tip_before]),
        AncestryRequirement::Squash {
            base: merge.base_tip,
            source: merge.source_tip,
        },
        None,
        limits,
        deadline,
    )
}

/// Verify a single-parent workspace commit with the SAME identity, required
/// object-kind, parser, traversal and budget checks used by merge admission.
/// This operation only reads its supplied source. It does not stage objects,
/// authorize the source, admit a transaction or prove a particular edit log.
/// The caller must independently bind the expected parent and source access.
pub fn validate_workspace_objects(
    source: &impl CanonicalObjectSource,
    candidate: GitOid,
    expected_parent: GitOid,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    validate_candidate_objects(
        source,
        candidate,
        Some(&[expected_parent]),
        AncestryRequirement::None,
        None,
        limits,
        deadline,
    )
}

/// Verify a strictly formed, single-parent workspace candidate above an
/// authenticated object frontier. The expected parent must already be selected;
/// every candidate edge is still checked against its required native kind.
/// The returned per-decision closure contains newly traversed objects and the
/// named candidate/parent, without copying inherited trees, blobs or history.
///
/// The caller owns selection and disclosure: its source must authorize every
/// original read from the intended visible parent, not merely local storage.
/// This validator neither stages objects nor publishes or authorizes a change.
pub fn validate_workspace_objects_above<'a>(
    source: &impl CanonicalObjectSource,
    candidate: GitOid,
    expected_parent: GitOid,
    selected: impl Into<ObjectFrontier<'a>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    let selected = selected.into();
    if candidate.is_zero()
        || expected_parent.is_zero()
        || expected_parent.algorithm() != candidate.algorithm()
        || expected_parent == candidate
    {
        return Err(invalid());
    }
    checkpoint(deadline)?;
    if !selected.objects.contains(&expected_parent) {
        return Err(ProjectionFailure::Refuse(
            RefusalCode::ObjectClosureIncomplete,
        ));
    }
    validate_candidate_objects(
        source,
        candidate,
        Some(&[expected_parent]),
        AncestryRequirement::None,
        Some(selected),
        limits,
        deadline,
    )
}

/// Verify all native dependencies of an already-authorized source commit.
/// This supplies a precise reachable allow-list for read-only artifact tooling:
/// an external delta base must be reachable from an authorized parent, not just
/// present elsewhere in the repository. The caller owns root authorization.
pub fn validate_commit_closure(
    source: &impl CanonicalObjectSource,
    commit: GitOid,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    validate_candidate_objects(
        source,
        commit,
        None,
        AncestryRequirement::None,
        None,
        limits,
        deadline,
    )
}

/// Verify native dependencies above an independently admitted frontier without
/// prescribing a parent shape. The root commit is always loaded and hashed,
/// even if selected; reused edges retain native-kind and resource checks.
///
/// This is NOT a complete reachable-object inventory or source authorization.
/// The caller must prove original disclosure and, for replay/rebase, separately
/// verify the entire supplied commit chain and its exact stopping boundary.
/// Returns newly traversed objects plus the root, not inherited history.
/// Passing an empty frontier reproduces `validate_commit_closure` behavior.
pub fn validate_commit_closure_above<'a>(
    source: &impl CanonicalObjectSource,
    commit: GitOid,
    selected: impl Into<ObjectFrontier<'a>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    validate_candidate_objects(
        source,
        commit,
        None,
        AncestryRequirement::None,
        Some(selected.into()),
        limits,
        deadline,
    )
}

/// Verify an explicit two-parent merge ABOVE the authority-selected closure
/// (frankengit-lh8z). Objects the candidate reaches that are already selected
/// were verified when admitted: checked headers retain kind and size checks
/// without rereading their payloads. If a source declines metadata, its loaded
/// bytes are independently verified under the body budgets. Reused outgoing
/// edges are not walked. Base ancestry is proved by
/// an exact frontier traversal over selected commits instead of a full parent
/// map. The result names the objects this merge adds plus the four commits
/// admission requires; the serving closure, a union over every decision, is
/// unchanged by the objects that were already selected.
pub fn validate_merge_objects_above<'a>(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    selected: impl Into<ObjectFrontier<'a>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    let selected = selected.into();
    merge.validate().map_err(|_| invalid())?;
    validate_candidate_objects(
        source,
        merge.merge_commit,
        Some(&[merge.target_tip_before, merge.source_tip]),
        AncestryRequirement::Merge {
            base: merge.base_tip,
        },
        Some(selected),
        limits,
        deadline,
    )
}

/// [`validate_fast_forward_objects`] above the selected closure: the candidate
/// is the already-selected source tip, so the result names no new object, only
/// the source and target tips. See [`validate_merge_objects_above`].
pub fn validate_fast_forward_objects_above<'a>(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    selected: impl Into<ObjectFrontier<'a>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    let selected = selected.into();
    merge.validate().map_err(|_| invalid())?;
    if merge.merge_commit != merge.source_tip || merge.base_tip != merge.target_tip_before {
        return Err(invalid());
    }
    validate_candidate_objects(
        source,
        merge.source_tip,
        None,
        AncestryRequirement::FastForward {
            base: merge.target_tip_before,
        },
        Some(selected),
        limits,
        deadline,
    )
}

/// [`validate_squash_objects`] above the selected closure. See
/// [`validate_merge_objects_above`].
pub fn validate_squash_objects_above<'a>(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    selected: impl Into<ObjectFrontier<'a>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    let selected = selected.into();
    merge.validate().map_err(|_| invalid())?;
    if merge.source_tip == merge.target_tip_before {
        return Err(invalid());
    }
    validate_candidate_objects(
        source,
        merge.merge_commit,
        Some(&[merge.target_tip_before]),
        AncestryRequirement::Squash {
            base: merge.base_tip,
            source: merge.source_tip,
        },
        Some(selected),
        limits,
        deadline,
    )
}

#[derive(Clone, Copy)]
enum AncestryRequirement {
    None,
    Merge { base: GitOid },
    Squash { base: GitOid, source: GitOid },
    FastForward { base: GitOid },
}

fn validate_candidate_objects(
    source: &impl CanonicalObjectSource,
    candidate: GitOid,
    expected_parents: Option<&[GitOid]>,
    ancestry: AncestryRequirement,
    frontier: Option<ObjectFrontier<'_>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<ValidatedClosure, ProjectionFailure> {
    let format = candidate.algorithm();
    if candidate.is_zero()
        || expected_parents.is_some_and(|parents| {
            parents.is_empty()
                || parents.len() > 2
                || parents
                    .iter()
                    .any(|id| id.is_zero() || id.algorithm() != format || *id == candidate)
                || (parents.len() == 2 && parents[0] == parents[1])
        })
    {
        return Err(invalid());
    }
    let bad_id = |id: GitOid| id.is_zero() || id.algorithm() != format;
    let invalid_ancestry = match ancestry {
        AncestryRequirement::None => false,
        AncestryRequirement::Merge { base } => {
            bad_id(base) || expected_parents.is_none_or(|parents| parents.len() != 2)
        }
        AncestryRequirement::Squash { base, source } => {
            bad_id(base)
                || bad_id(source)
                || expected_parents.is_none_or(|parents| parents.len() != 1)
        }
        AncestryRequirement::FastForward { base } => {
            bad_id(base) || base == candidate || expected_parents.is_some()
        }
    };
    if invalid_ancestry {
        return Err(invalid());
    }
    let maximum = MergeObjectLimits::default();
    if limits.max_objects == 0
        || limits.max_objects > maximum.max_objects
        || limits.max_edges == 0
        || limits.max_edges > maximum.max_edges
        || limits.max_object_bytes == 0
        || limits.max_object_bytes > maximum.max_object_bytes
        || limits.max_reused_blob_bytes == 0
        || u64::try_from(limits.max_reused_blob_bytes).unwrap_or(u64::MAX) > MAX_REUSED_BLOB_BYTES
        || limits.max_total_bytes == 0
        || limits.max_total_bytes > maximum.max_total_bytes
    {
        return Err(budget());
    }
    let parse_limits = ParseLimits {
        max_object_bytes: limits.max_object_bytes,
        max_tree_entries: limits.max_edges,
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    };
    let mut required = BTreeMap::new();
    let mut pending = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut parents = BTreeMap::<GitOid, Vec<GitOid>>::new();
    let mut object_work = ObjectWork {
        candidate,
        header_frontier: frontier
            .filter(|selected| selected.headers.is_some())
            .map(|selected| selected.objects),
        bodies: 0,
    };
    require_object(
        candidate,
        ObjectType::Commit,
        &mut required,
        &mut pending,
        &mut object_work,
        limits,
    )?;
    if let AncestryRequirement::Squash { source, .. } = ancestry {
        require_object(
            source,
            ObjectType::Commit,
            &mut required,
            &mut pending,
            &mut object_work,
            limits,
        )?;
    }
    let mut total_bytes = 0_usize;
    let mut edges = 0_usize;

    while let Some(id) = pending.pop_first() {
        checkpoint(deadline)?;
        let reused =
            id != candidate && frontier.is_some_and(|selected| selected.objects.contains(&id));
        // A selected immutable frontier has already been admitted. Its metadata
        // must match this edge, but undisclosed payloads are not a new closure
        // or scrub obligation. Candidates and unselected objects NEVER enter
        // this branch. Sources lacking bounded headers retain the old full-read
        // path and byte accounting below.
        if reused {
            let header = match frontier.and_then(|selected| selected.headers) {
                Some(headers) => headers.load_header(&id).map_err(source_failure)?,
                None => None,
            };
            checkpoint(deadline)?;
            if let Some(header) = header {
                if header.id != id || required.get(&id) != Some(&header.object_type) {
                    return Err(invalid());
                }
                let maximum_bytes = if header.object_type == ObjectType::Blob {
                    limits.max_reused_blob_bytes
                } else {
                    limits.max_object_bytes
                };
                if header.body_bytes > maximum_bytes {
                    return Err(budget());
                }
                continue;
            }
            // A provider may decline a header for this particular object. Do
            // not turn that fallback into an unmetered payload read. Objects
            // without a provider were already reserved when enqueued.
            if object_work.uses_header(id) {
                object_work.reserve_body(limits)?;
            }
        }
        let object = source.load(&id).map_err(source_failure)?;
        checkpoint(deadline)?;
        if object.id() != id || required.get(&id) != Some(&object.object_type()) {
            return Err(invalid());
        }
        if object.body().len() > limits.max_object_bytes {
            return Err(budget());
        }
        total_bytes = total_bytes
            .checked_add(object.body().len())
            .filter(|bytes| *bytes <= limits.max_total_bytes)
            .ok_or_else(budget)?;
        let profile = if id == candidate && expected_parents.is_some() {
            AcceptanceProfile::StrictCreate
        } else {
            AcceptanceProfile::GitCompatibleImport
        };
        let parsed = verify_native_object(
            format,
            object.object_type(),
            object.body(),
            &id,
            profile,
            &parse_limits,
        )
        .map_err(native_parse_failure)?;
        checkpoint(deadline)?;
        // A declined header can denote newly supplied bytes whose identity was
        // already admitted. Verify those actual bytes before retaining the
        // original frontier; they add no new decision-closure objects here.
        if reused {
            continue;
        }
        visited.insert(id);
        let mut outgoing = Vec::new();
        match parsed {
            ParsedObject::Commit(commit) => {
                if commit
                    .headers()
                    .iter()
                    .filter(|header| header.name == b"tree")
                    .count()
                    != 1
                    || commit.headers().iter().any(|header| {
                        (header.name == b"tree" || header.name == b"parent")
                            && !header.continuations.is_empty()
                    })
                {
                    return Err(invalid());
                }
                let tree = parse_oid(format, commit.tree_reference().ok_or_else(invalid)?)?;
                push_edge(
                    &mut outgoing,
                    &mut edges,
                    limits.max_edges,
                    tree,
                    ObjectType::Tree,
                )?;
                let mut parent_ids = Vec::new();
                for parent in commit.parent_references() {
                    checkpoint(deadline)?;
                    let parent = parse_oid(format, parent)?;
                    push_edge(
                        &mut outgoing,
                        &mut edges,
                        limits.max_edges,
                        parent,
                        ObjectType::Commit,
                    )?;
                    parent_ids.push(parent);
                }
                if id == candidate
                    && expected_parents.is_some_and(|expected| parent_ids.as_slice() != expected)
                {
                    return Err(invalid());
                }
                parents.insert(id, parent_ids);
            }
            ParsedObject::Tree(entries) => {
                for entry in entries {
                    checkpoint(deadline)?;
                    // Even a gitlink consumes traversal work, though its target
                    // belongs to another repository and is not fetched here.
                    charge_edge(&mut edges, limits.max_edges)?;
                    let mode = std::str::from_utf8(&entry.mode)
                        .ok()
                        .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                        .ok_or_else(invalid)?;
                    let kind = match mode & 0o170_000 {
                        0o040_000 => ObjectType::Tree,
                        0o100_000 | 0o120_000 => ObjectType::Blob,
                        0o160_000 => continue,
                        _ => return Err(invalid()),
                    };
                    let hex: String = entry
                        .object_id
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    outgoing.try_reserve(1).map_err(|_| budget())?;
                    outgoing.push((parse_oid(format, hex.as_bytes())?, kind));
                }
            }
            ParsedObject::Blob(_) => {}
            ParsedObject::Tag(_) => return Err(invalid()),
        }
        for (target, kind) in outgoing {
            checkpoint(deadline)?;
            require_object(
                target,
                kind,
                &mut required,
                &mut pending,
                &mut object_work,
                limits,
            )?;
        }
    }
    if let Some(selected) = frontier {
        validate_ancestry_above(
            source,
            format,
            ancestry,
            candidate,
            expected_parents,
            &parents,
            selected.objects,
            limits,
            deadline,
        )?;
        // Admission requires these commits by name; they are already selected
        // (or, for the candidate, verified above), so naming them changes no
        // serving closure.
        visited.insert(candidate);
        visited.extend(expected_parents.into_iter().flatten().copied());
        match ancestry {
            AncestryRequirement::None => {}
            AncestryRequirement::Merge { base } | AncestryRequirement::FastForward { base } => {
                visited.insert(base);
            }
            AncestryRequirement::Squash { base, source } => {
                visited.extend([base, source]);
            }
        }
    } else {
        validate_ancestry(
            ancestry,
            candidate,
            expected_parents,
            &parents,
            limits,
            deadline,
        )?;
    }
    checkpoint(deadline)?;
    let closure = PermittedObjectClosure::new(visited);
    let object_closure_root =
        permitted_object_closure_root(&closure).map_err(ProjectionFailure::Unavailable)?;
    checkpoint(deadline)?;
    Ok(ValidatedClosure {
        object_closure_root,
        objects: closure.objects().clone(),
    })
}

fn charge_edge(edges: &mut usize, limit: usize) -> Result<(), ProjectionFailure> {
    *edges = edges
        .checked_add(1)
        .filter(|count| *count <= limit)
        .ok_or_else(budget)?;
    Ok(())
}

fn push_edge(
    outgoing: &mut Vec<(GitOid, ObjectType)>,
    edges: &mut usize,
    limit: usize,
    target: GitOid,
    kind: ObjectType,
) -> Result<(), ProjectionFailure> {
    charge_edge(edges, limit)?;
    outgoing.try_reserve(1).map_err(|_| budget())?;
    outgoing.push((target, kind));
    Ok(())
}

// The closure walk has at most two explicit roots. Every other unique ID is
// introduced by an already-charged native edge, including inherited objects.
// Keep worklist memory bounded by that edge budget while reserving new/body
// work separately. No membership or object-kind check is skipped.
struct ObjectWork<'a> {
    candidate: GitOid,
    header_frontier: Option<&'a BTreeSet<GitOid>>,
    bodies: usize,
}
impl ObjectWork<'_> {
    fn uses_header(&self, id: GitOid) -> bool {
        id != self.candidate && self.header_frontier.is_some_and(|set| set.contains(&id))
    }

    fn reserve_body(&mut self, limits: MergeObjectLimits) -> Result<(), ProjectionFailure> {
        self.bodies = self
            .bodies
            .checked_add(1)
            .filter(|count| *count <= limits.max_objects)
            .ok_or_else(budget)?;
        Ok(())
    }
}

fn require_object(
    id: GitOid,
    kind: ObjectType,
    required: &mut BTreeMap<GitOid, ObjectType>,
    pending: &mut BTreeSet<GitOid>,
    object_work: &mut ObjectWork<'_>,
    limits: MergeObjectLimits,
) -> Result<(), ProjectionFailure> {
    if id.is_zero() {
        return Err(invalid());
    }
    if let Some(expected) = required.get(&id) {
        if *expected != kind {
            return Err(invalid());
        }
        return Ok(());
    }
    // Reserve non-frontier work at enqueue, before reading or growing the
    // worklist. Header-only dependencies remain bounded by native edge work;
    // a wide inherited tree is not charged as newly introduced payloads.
    if required.len() >= limits.max_edges.saturating_add(2) {
        return Err(budget());
    }
    if !object_work.uses_header(id) {
        object_work.reserve_body(limits)?;
    }
    required.insert(id, kind);
    pending.insert(id);
    Ok(())
}

/// This adapter only sees native commits whose bytes, kinds and complete
/// closure were independently verified in this request. It never reads a
/// store or extends the caller's authority-selected object closure.
struct VerifiedCommitGraph<'a>(&'a BTreeMap<GitOid, Vec<GitOid>>);

impl CommitGraph for VerifiedCommitGraph<'_> {
    type CommitId = GitOid;
    type Error = ProjectionFailure;

    fn parents_of(&self, commit: &GitOid) -> Result<ParentSet<GitOid>, ProjectionFailure> {
        let mut parents = self.0.get(commit).ok_or_else(invalid)?.clone();
        // GitCompatibleImport permits repeated historical parent headers.
        // Reachability uses a simple graph, but the original headers remain
        // untouched: their bytes and every edge have already been charged,
        // and candidate parents were compared in their exact native order.
        parents.sort_unstable();
        parents.dedup();
        Ok(ParentSet::Complete(parents))
    }
}

fn validate_ancestry(
    ancestry: AncestryRequirement,
    candidate: GitOid,
    expected_parents: Option<&[GitOid]>,
    parents: &BTreeMap<GitOid, Vec<GitOid>>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<(), ProjectionFailure> {
    let (base, source, target) = match ancestry {
        AncestryRequirement::None => return Ok(()),
        AncestryRequirement::Merge { base } => {
            let expected = expected_parents.ok_or_else(invalid)?;
            (base, expected[1], expected[0])
        }
        AncestryRequirement::Squash { base, source } => {
            let expected = expected_parents.ok_or_else(invalid)?;
            (base, source, expected[0])
        }
        AncestryRequirement::FastForward { base } => {
            // Cold index construction costs more than this single query.
            // Retain the exact checkpointed walk until an independently
            // verified index can be safely reused. The full native closure
            // has still been verified before this early ancestry answer.
            return if is_ancestor(base, candidate, parents, deadline)? {
                Ok(())
            } else {
                Err(ProjectionFailure::Refuse(
                    RefusalCode::NonFastForwardRefused,
                ))
            };
        }
    };
    let graph_limits = MergeBaseLimits {
        max_commits: limits.max_objects,
        max_edges: limits.max_edges,
    };
    // Merge and squash share one index across their two queries after the
    // full native object walk. Squash needs the source root as well as the
    // candidate; duplicate/redundant roots are harmless.
    // The request owns both this immutable index and its query scratch, so a
    // later attempt must independently verify every object again.
    let index = CommitAncestryIndex::build_with_checkpoints(
        &VerifiedCommitGraph(parents),
        [candidate, source],
        graph_limits,
        || checkpoint(deadline),
    )
    .map_err(ancestry_failure)?;
    // An absent common base cannot satisfy either branch's ancestry.
    if index.generation(&base).is_none() {
        return Err(invalid());
    }
    let mut scratch = AncestryQueryScratch::default();
    if !index
        .is_ancestor(&base, &source, &mut scratch, graph_limits, || {
            checkpoint(deadline)
        })
        .map_err(ancestry_failure)?
    {
        return Err(invalid());
    }
    if !index
        .is_ancestor(&base, &target, &mut scratch, graph_limits, || {
            checkpoint(deadline)
        })
        .map_err(ancestry_failure)?
    {
        return Err(invalid());
    }
    Ok(())
}

/// Commit parents above the selected closure: commits this request walked come
/// from its own verified parent map, selected commits are read and parsed from
/// the source. A commit that is in neither refuses: ancestry never reaches
/// outside the authority-selected closure. Committer dates only order the
/// frontier traversal; they never decide ancestry.
struct FrontierCommitGraph<'a, S> {
    source: &'a S,
    format: GitHashAlgorithm,
    walked: &'a BTreeMap<GitOid, Vec<GitOid>>,
    selected: &'a BTreeSet<GitOid>,
    parse_limits: &'a ParseLimits,
}

impl<S: CanonicalObjectSource> FrontierCommitGraph<'_, S> {
    fn read(&self, commit: &GitOid) -> Result<(ParentSet<GitOid>, i64), ProjectionFailure> {
        let (mut parents, hint) = if let Some(parents) = self.walked.get(commit) {
            // Commits this request created are the newest in the walk.
            (parents.clone(), i64::MAX)
        } else if self.selected.contains(commit) {
            let object = self.source.load(commit).map_err(source_failure)?;
            if object.id() != *commit || object.object_type() != ObjectType::Commit {
                return Err(invalid());
            }
            let ParsedObject::Commit(parsed) = parse_object_body(
                ObjectType::Commit,
                object.body(),
                AcceptanceProfile::GitCompatibleImport,
                self.parse_limits,
            )
            .map_err(object_parse_failure)?
            else {
                return Err(invalid());
            };
            let parents = parsed
                .parent_references()
                .map(|value| parse_oid(self.format, value))
                .collect::<Result<Vec<_>, _>>()?;
            (parents, committer_seconds(&parsed).unwrap_or(i64::MIN))
        } else {
            return Err(ProjectionFailure::Refuse(
                RefusalCode::ObjectClosureIncomplete,
            ));
        };
        // As for VerifiedCommitGraph: repeated historical parent headers keep
        // their bytes, but reachability uses the simple graph.
        parents.sort_unstable();
        parents.dedup();
        Ok((ParentSet::Complete(parents), hint))
    }
}

impl<S: CanonicalObjectSource> CommitGraph for FrontierCommitGraph<'_, S> {
    type CommitId = GitOid;
    type Error = ProjectionFailure;

    fn parents_of(&self, commit: &GitOid) -> Result<ParentSet<GitOid>, ProjectionFailure> {
        self.read(commit).map(|(parents, _)| parents)
    }

    fn parents_with_order_hint(
        &self,
        commit: &GitOid,
    ) -> Result<(ParentSet<GitOid>, i64), ProjectionFailure> {
        self.read(commit)
    }
}

/// The single, uncontinued committer header's seconds field, as an untrusted
/// order hint only.
fn committer_seconds(commit: &fgit_git_object::Commit) -> Option<i64> {
    let mut fields = commit
        .headers()
        .iter()
        .filter(|header| header.name == b"committer");
    let header = fields.next()?;
    if fields.next().is_some() || !header.continuations.is_empty() {
        return None;
    }
    let mut tail = header.value.rsplitn(3, |byte| *byte == b' ');
    tail.next()?;
    std::str::from_utf8(tail.next()?).ok()?.parse().ok()
}

/// `base` is an ancestor of `tip` exactly when it is their only best common
/// ancestor; the frontier traversal reads only the history between them.
fn is_ancestor_above<S: CanonicalObjectSource>(
    graph: &FrontierCommitGraph<'_, S>,
    base: GitOid,
    tip: GitOid,
    limits: MergeBaseLimits,
    deadline: &mut impl Deadline,
) -> Result<bool, ProjectionFailure> {
    let result = frontier_merge_bases_all(
        graph,
        base,
        tip,
        limits,
        &mut AncestryQueryWork::default(),
        || checkpoint(deadline),
    )
    .map_err(ancestry_failure)?;
    Ok(result == MergeBaseResult::Bases(vec![base]))
}

fn validate_ancestry_above<S: CanonicalObjectSource>(
    source: &S,
    format: GitHashAlgorithm,
    ancestry: AncestryRequirement,
    candidate: GitOid,
    expected_parents: Option<&[GitOid]>,
    walked: &BTreeMap<GitOid, Vec<GitOid>>,
    selected: &BTreeSet<GitOid>,
    limits: MergeObjectLimits,
    deadline: &mut impl Deadline,
) -> Result<(), ProjectionFailure> {
    let parse_limits = ParseLimits {
        max_object_bytes: limits.max_object_bytes,
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    };
    let graph = FrontierCommitGraph {
        source,
        format,
        walked,
        selected,
        parse_limits: &parse_limits,
    };
    let graph_limits = MergeBaseLimits {
        max_commits: limits.max_objects,
        max_edges: limits.max_edges,
    };
    let (base, tips) = match ancestry {
        AncestryRequirement::None => return Ok(()),
        AncestryRequirement::Merge { base } => {
            let expected = expected_parents.ok_or_else(invalid)?;
            (base, vec![expected[1], expected[0]])
        }
        AncestryRequirement::Squash { base, source } => {
            let expected = expected_parents.ok_or_else(invalid)?;
            (base, vec![source, expected[0]])
        }
        AncestryRequirement::FastForward { base } => {
            return if is_ancestor_above(&graph, base, candidate, graph_limits, deadline)? {
                Ok(())
            } else {
                Err(ProjectionFailure::Refuse(
                    RefusalCode::NonFastForwardRefused,
                ))
            };
        }
    };
    // The base itself must be selected or walked: an unknown base is invalid,
    // exactly as an absent generation is in the full-closure validator.
    if !selected.contains(&base) && !walked.contains_key(&base) {
        return Err(invalid());
    }
    for tip in tips {
        if !is_ancestor_above(&graph, base, tip, graph_limits, deadline)? {
            return Err(invalid());
        }
    }
    Ok(())
}

fn is_ancestor(
    ancestor: GitOid,
    tip: GitOid,
    parents: &BTreeMap<GitOid, Vec<GitOid>>,
    deadline: &mut impl Deadline,
) -> Result<bool, ProjectionFailure> {
    let mut pending = BTreeSet::from([tip]);
    let mut visited = BTreeSet::from([tip]);
    while let Some(id) = pending.pop_first() {
        checkpoint(deadline)?;
        if id == ancestor {
            return Ok(true);
        }
        for parent in parents.get(&id).ok_or_else(invalid)? {
            checkpoint(deadline)?;
            if visited.insert(*parent) {
                pending.insert(*parent);
            }
        }
    }
    Ok(false)
}

const fn ancestry_failure(error: MergeBaseError<GitOid, ProjectionFailure>) -> ProjectionFailure {
    match error {
        MergeBaseError::Source(failure) => failure,
        MergeBaseError::CommitLimitExceeded { .. } | MergeBaseError::EdgeLimitExceeded { .. } => {
            budget()
        }
        MergeBaseError::ShallowBoundary { .. }
        | MergeBaseError::DuplicateParent { .. }
        | MergeBaseError::GraphClosureViolation
        | MergeBaseError::Cycle => invalid(),
    }
}

fn parse_oid(format: GitHashAlgorithm, bytes: &[u8]) -> Result<GitOid, ProjectionFailure> {
    let hex = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    // Case has no identity significance for parsed references. The original
    // object bytes stay unchanged and are what the native hash verifies.
    GitOid::from_hex(format, &hex.to_ascii_lowercase()).map_err(|_| invalid())
}
const fn invalid() -> ProjectionFailure {
    ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)
}
const fn budget() -> ProjectionFailure {
    ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
}

const fn object_parse_failure(error: ObjectError) -> ProjectionFailure {
    match error {
        ObjectError::ObjectTooLarge { .. }
        | ObjectError::TooManyTreeEntries { .. }
        | ObjectError::HeaderLimitExceeded { .. }
        | ObjectError::AllocationFailure => budget(),
        _ => invalid(),
    }
}

const fn native_parse_failure(error: PackError) -> ProjectionFailure {
    match error {
        PackError::ObjectParse(error) => object_parse_failure(error),
        _ => invalid(),
    }
}
fn checkpoint(deadline: &mut impl Deadline) -> Result<(), ProjectionFailure> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress,
        ))
    }
}
const fn source_failure(error: PackWriteError) -> ProjectionFailure {
    match error {
        PackWriteError::Pack(PackError::DeadlineExceeded) => {
            ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)
        }
        PackWriteError::Pack(PackError::ObjectSizeLimit { .. }) => budget(),
        _ => ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing),
    }
}
