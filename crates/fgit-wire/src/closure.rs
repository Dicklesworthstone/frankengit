//! Deterministic shallow-history and partial-clone closure computation.
//!
//! This module is deliberately storage-free.  The caller supplies the
//! authenticated object graph through [`ObjectClosureRepository`]; the result
//! is a bounded, deterministically ordered pack-object list plus an
//! authenticated promisor-omission manifest.  A cache is therefore unable to
//! invent a closure or to turn an omission into authority.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use fgit_crypto::sha256_digest;

use crate::{AnyGitOid, GitObjectFormat, ObjectFilter, ObjectType, PackRequest};

/// Limits that apply before graph traversal records or output lists grow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureLimits {
    /// Maximum commit records visited while computing a shallow boundary.
    pub max_commits: usize,
    /// Maximum objects visited while computing one filtered closure.
    pub max_objects: usize,
    /// Maximum parent/tree edges inspected in one computation.
    pub max_edges: usize,
}

impl Default for ClosureLimits {
    fn default() -> Self {
        Self {
            max_commits: 1_000_000,
            max_objects: 4_000_000,
            max_edges: 16_000_000,
        }
    }
}

impl ClosureLimits {
    const fn validate(&self) -> Result<(), ClosureError> {
        if self.max_commits == 0 || self.max_objects == 0 || self.max_edges == 0 {
            return Err(ClosureError::InvalidLimit);
        }
        Ok(())
    }
}

/// A typed commit graph view, independent of a repository storage engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitNode {
    /// Root tree named by this commit.
    pub tree: AnyGitOid,
    /// Parent commits in the original commit-header order.
    pub parents: Vec<AnyGitOid>,
    /// Signed UTC seconds from the commit's committer header.
    pub committer_time: i64,
}

/// One typed tree edge exposed to the closure walker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureTreeEntry {
    /// Referenced native Git object identity.
    pub oid: AnyGitOid,
    /// Referenced object's Git type, including `Commit` for a gitlink.
    pub object_type: ObjectType,
}

/// Object facts needed to compute a filtered pack closure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureObject {
    /// Commit ancestry and its root tree.
    Commit(CommitNode),
    /// A tree's exact typed child references in Git tree order.
    Tree(Vec<ClosureTreeEntry>),
    /// Blob length, used by the `blob:limit` filter without reading blob bytes.
    Blob { size: u64 },
    /// An annotated tag target.
    Tag { target: AnyGitOid },
}

impl ClosureObject {
    /// Git's native object type for this graph fact.
    #[must_use]
    pub const fn object_type(&self) -> ObjectType {
        match self {
            Self::Commit(_) => ObjectType::Commit,
            Self::Tree(_) => ObjectType::Tree,
            Self::Blob { .. } => ObjectType::Blob,
            Self::Tag { .. } => ObjectType::Tag,
        }
    }
}

/// Authenticated repository graph access needed by the pure closure functions.
pub trait ObjectClosureRepository {
    /// The native object-ID domain used by every returned object identity.
    fn object_format(&self) -> GitObjectFormat;

    /// Returns the immutable fact for one canonical object identity.
    fn object(&self, oid: AnyGitOid) -> Result<ClosureObject, ClosureError>;
}

/// Parsed shallow controls, ready for graph computation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ShallowRequest {
    /// Existing client shallow roots.
    pub client_shallows: Vec<AnyGitOid>,
    /// Maximum inclusive commit generation from each requested tip.
    pub deepen: Option<u32>,
    /// Oldest committer timestamp to traverse without making a boundary.
    pub deepen_since: Option<i64>,
    /// Tips whose reachable history must not be traversed.
    pub deepen_not: Vec<AnyGitOid>,
}

impl ShallowRequest {
    /// Derives graph controls from an authenticated parsed upload-pack request.
    #[must_use]
    pub fn from_pack_request(request: &PackRequest) -> Self {
        Self {
            client_shallows: request.shallows.clone(),
            deepen: request.deepen,
            deepen_since: request.deepen_since,
            deepen_not: request.deepen_not.clone(),
        }
    }
}

/// Shallow records that the wire adapter must emit before the pack payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShallowUpdate {
    /// New shallow boundary commits, sorted by typed native identity.
    pub shallow: Vec<AnyGitOid>,
    /// Old client boundaries crossed by this response, sorted by identity.
    pub unshallow: Vec<AnyGitOid>,
}

/// One object admitted to a pack-object list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClosureObjectId {
    /// Native object identity.
    pub oid: AnyGitOid,
    /// Native Git object type.
    pub object_type: ObjectType,
}

/// Why an object was deliberately omitted from a promisor pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    /// A blob was excluded by `blob:none` or `blob:limit`.
    BlobFilter,
    /// A tree or descendant was excluded by `tree:<depth>`.
    TreeDepth,
}

/// A single authenticated partial-clone omission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromisorOmission {
    /// Omitted object identity.
    pub oid: AnyGitOid,
    /// Omitted native object type.
    pub object_type: ObjectType,
    /// Object that exposed the omitted reference, if any.
    pub parent: Option<AnyGitOid>,
    /// Root-tree-relative depth of this object.
    pub depth: u32,
    /// Filter predicate that excluded this object.
    pub reason: OmissionReason,
}

/// Canonically ordered promisor omissions with a SHA-256 commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromisorManifest {
    /// Every omitted object, sorted canonically before commitment.
    pub omissions: Vec<PromisorOmission>,
    /// SHA-256 over the canonical omission sequence.
    pub commitment: [u8; 32],
}

impl PromisorManifest {
    fn new(mut omissions: Vec<PromisorOmission>) -> Self {
        omissions.sort_by(compare_omissions);
        let commitment = omission_commitment(&omissions);
        Self {
            omissions,
            commitment,
        }
    }

    /// Verifies that no omission was reordered, substituted, or altered.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.commitment == omission_commitment(&self.omissions)
    }
}

/// A complete bounded result supplied to a pack writer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackClosure {
    /// Deterministically ordered objects the pack writer may emit.
    pub objects: Vec<ClosureObjectId>,
    /// Shallow state changes that accompany this closure.
    pub shallow_update: ShallowUpdate,
    /// Cryptographically committed partial-clone omissions.
    pub promisor: PromisorManifest,
}

impl PackClosure {
    /// Detects a pack-writer leak before it is published to a filtered client.
    pub fn verify_pack_objects(&self, emitted: &[ClosureObjectId]) -> Result<(), ClosureError> {
        for object in emitted {
            if self
                .objects
                .binary_search_by(|candidate| compare_object_ids(candidate, object))
                .is_err()
            {
                return Err(ClosureError::FilteredObjectLeak {
                    oid: object.oid,
                    object_type: object.object_type,
                });
            }
        }
        Ok(())
    }

    /// Returns all omitted identities in canonical follow-up request order.
    #[must_use]
    pub fn lazy_fetch_wants(&self) -> Vec<AnyGitOid> {
        self.promisor
            .omissions
            .iter()
            .map(|omission| omission.oid)
            .collect()
    }
}

/// Typed refusal from bounded shallow or partial-clone computation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosureError {
    /// A graph limit was zero or otherwise unusable.
    InvalidLimit,
    /// A requested deepening depth was zero.
    InvalidDeepenDepth,
    /// A repository returned an OID from the wrong hash-format domain.
    ObjectFormatMismatch {
        /// Expected repository object format.
        expected: GitObjectFormat,
        /// Returned object format.
        observed: GitObjectFormat,
    },
    /// A commit walk encountered a non-commit object.
    ExpectedCommit {
        oid: AnyGitOid,
        observed: ObjectType,
    },
    /// A graph record was internally inconsistent.
    InconsistentGraph { oid: AnyGitOid },
    /// A declared bound was reached before allocating another record.
    ResourceLimit { field: &'static str, limit: usize },
    /// A pack writer attempted to emit an object outside the filtered closure.
    FilteredObjectLeak {
        /// Leaked object identity.
        oid: AnyGitOid,
        /// Leaked object type.
        object_type: ObjectType,
    },
}

impl Display for ClosureError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit => formatter.write_str("invalid closure limit"),
            Self::InvalidDeepenDepth => formatter.write_str("deepen depth must be positive"),
            Self::ObjectFormatMismatch { expected, observed } => {
                write!(
                    formatter,
                    "expected {expected} object ID, observed {observed}"
                )
            }
            Self::ExpectedCommit { oid, observed } => {
                write!(formatter, "expected commit {oid:?}, observed {observed:?}")
            }
            Self::InconsistentGraph { oid } => write!(formatter, "inconsistent graph at {oid:?}"),
            Self::ResourceLimit { field, limit } => {
                write!(formatter, "{field} exceeded closure limit {limit}")
            }
            Self::FilteredObjectLeak { oid, object_type } => {
                write!(formatter, "filtered pack leaked {object_type:?} {oid:?}")
            }
        }
    }
}

impl Error for ClosureError {}

/// Computes the shallow boundary and filtered object closure for one pack request.
pub fn compute_pack_closure(
    repository: &impl ObjectClosureRepository,
    request: &PackRequest,
    limits: &ClosureLimits,
) -> Result<PackClosure, ClosureError> {
    limits.validate()?;
    let shallow_request = ShallowRequest::from_pack_request(request);
    if shallow_request.deepen == Some(0) {
        return Err(ClosureError::InvalidDeepenDepth);
    }
    let excluded = collect_excluded(repository, &shallow_request, limits)?;
    let (commits, boundaries) =
        collect_commits(repository, request, &shallow_request, &excluded, limits)?;
    let shallow_update = shallow_update(&shallow_request, &commits, &boundaries);
    let (objects, omissions) =
        collect_objects(repository, &commits, request.filter.as_ref(), limits)?;
    Ok(PackClosure {
        objects,
        shallow_update,
        promisor: PromisorManifest::new(omissions),
    })
}

/// Completes a lazy promisor fetch without reusing the original filter.
pub fn compute_lazy_fetch_closure(
    repository: &impl ObjectClosureRepository,
    wants: &[AnyGitOid],
    limits: &ClosureLimits,
) -> Result<PackClosure, ClosureError> {
    limits.validate()?;
    let (objects, omissions) = collect_objects_from_roots(repository, wants, None, limits)?;
    Ok(PackClosure {
        objects,
        shallow_update: ShallowUpdate {
            shallow: Vec::new(),
            unshallow: Vec::new(),
        },
        promisor: PromisorManifest::new(omissions),
    })
}

fn collect_excluded(
    repository: &impl ObjectClosureRepository,
    request: &ShallowRequest,
    limits: &ClosureLimits,
) -> Result<BTreeSet<AnyGitOid>, ClosureError> {
    let mut excluded = BTreeSet::new();
    let mut pending = request.deepen_not.clone();
    let mut edge_count = 0_usize;
    while let Some(oid) = pending.pop() {
        ensure_format(repository, oid)?;
        if excluded.contains(&oid) {
            continue;
        }
        if excluded.len() == limits.max_commits {
            return Err(limit_error("excluded commits", limits.max_commits));
        }
        let object = repository.object(oid)?;
        let ClosureObject::Commit(commit) = object else {
            let observed = object.object_type();
            return Err(ClosureError::ExpectedCommit { oid, observed });
        };
        edge_count = edge_count
            .checked_add(commit.parents.len())
            .ok_or_else(|| limit_error("excluded graph edges", limits.max_edges))?;
        if edge_count > limits.max_edges {
            return Err(limit_error("excluded graph edges", limits.max_edges));
        }
        excluded.insert(oid);
        for parent in commit.parents.into_iter().rev() {
            ensure_format(repository, parent)?;
            pending.push(parent);
        }
    }
    Ok(excluded)
}

fn collect_commits(
    repository: &impl ObjectClosureRepository,
    request: &PackRequest,
    shallow: &ShallowRequest,
    excluded: &BTreeSet<AnyGitOid>,
    limits: &ClosureLimits,
) -> Result<(BTreeMap<AnyGitOid, CommitNode>, BTreeSet<AnyGitOid>), ClosureError> {
    let mut commits = BTreeMap::new();
    let mut boundaries = BTreeSet::new();
    let mut pending = Vec::new();
    pending
        .try_reserve(request.wants.len())
        .map_err(|_| limit_error("commit frontier", limits.max_commits))?;
    for want in request.wants.iter().rev() {
        pending.push((*want, 1_u32));
    }
    let mut edge_count = 0_usize;
    while let Some((oid, depth)) = pending.pop() {
        ensure_format(repository, oid)?;
        if commits.contains_key(&oid) || excluded.contains(&oid) {
            continue;
        }
        if commits.len() == limits.max_commits {
            return Err(limit_error("commits", limits.max_commits));
        }
        let object = repository.object(oid)?;
        let ClosureObject::Commit(commit) = object else {
            return Err(ClosureError::ExpectedCommit {
                oid,
                observed: object.object_type(),
            });
        };
        ensure_format(repository, commit.tree)?;
        let is_depth_boundary = shallow.deepen.is_some_and(|maximum| depth >= maximum);
        let is_time_boundary = shallow
            .deepen_since
            .is_some_and(|minimum| commit.committer_time < minimum);
        let has_excluded_parent = commit
            .parents
            .iter()
            .any(|parent| excluded.contains(parent));
        edge_count = edge_count
            .checked_add(commit.parents.len())
            .ok_or_else(|| limit_error("graph edges", limits.max_edges))?;
        if edge_count > limits.max_edges {
            return Err(limit_error("graph edges", limits.max_edges));
        }
        if is_depth_boundary || is_time_boundary || has_excluded_parent {
            boundaries.insert(oid);
        } else {
            let next_depth = depth
                .checked_add(1)
                .ok_or(ClosureError::InconsistentGraph { oid })?;
            for parent in commit.parents.iter().rev() {
                ensure_format(repository, *parent)?;
                pending.push((*parent, next_depth));
            }
        }
        commits.insert(oid, commit);
    }
    Ok((commits, boundaries))
}

fn shallow_update(
    request: &ShallowRequest,
    commits: &BTreeMap<AnyGitOid, CommitNode>,
    boundaries: &BTreeSet<AnyGitOid>,
) -> ShallowUpdate {
    let old = request
        .client_shallows
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let unshallow = old
        .into_iter()
        .filter(|oid| commits.contains_key(oid) && !boundaries.contains(oid))
        .collect();
    ShallowUpdate {
        shallow: boundaries.iter().copied().collect(),
        unshallow,
    }
}

fn collect_objects(
    repository: &impl ObjectClosureRepository,
    commits: &BTreeMap<AnyGitOid, CommitNode>,
    filter: Option<&ObjectFilter>,
    limits: &ClosureLimits,
) -> Result<(Vec<ClosureObjectId>, Vec<PromisorOmission>), ClosureError> {
    if commits.len() > limits.max_objects {
        return Err(limit_error("objects", limits.max_objects));
    }
    let mut objects = Vec::new();
    objects
        .try_reserve(commits.len())
        .map_err(|_| limit_error("pack objects", limits.max_objects))?;
    let mut root_trees = Vec::new();
    root_trees
        .try_reserve(commits.len())
        .map_err(|_| limit_error("object frontier", limits.max_objects))?;
    for (commit, node) in commits {
        objects.push(ClosureObjectId {
            oid: *commit,
            object_type: ObjectType::Commit,
        });
        root_trees.push((node.tree, Some(*commit), 0_u32));
    }
    let (tree_objects, omissions) =
        collect_object_frontier(repository, root_trees, filter, limits)?;
    objects.extend(tree_objects);
    objects.sort_by(compare_object_ids);
    Ok((objects, omissions))
}

fn collect_objects_from_roots(
    repository: &impl ObjectClosureRepository,
    roots: &[AnyGitOid],
    filter: Option<&ObjectFilter>,
    limits: &ClosureLimits,
) -> Result<(Vec<ClosureObjectId>, Vec<PromisorOmission>), ClosureError> {
    let mut frontier = Vec::new();
    frontier
        .try_reserve(roots.len())
        .map_err(|_| limit_error("object frontier", limits.max_objects))?;
    for oid in roots.iter().rev() {
        frontier.push((*oid, None, 0_u32));
    }
    collect_object_frontier(repository, frontier, filter, limits)
}

fn collect_object_frontier(
    repository: &impl ObjectClosureRepository,
    mut frontier: Vec<(AnyGitOid, Option<AnyGitOid>, u32)>,
    filter: Option<&ObjectFilter>,
    limits: &ClosureLimits,
) -> Result<(Vec<ClosureObjectId>, Vec<PromisorOmission>), ClosureError> {
    let mut visited = BTreeSet::new();
    let mut objects = Vec::new();
    let mut omissions = Vec::new();
    let mut edge_count = 0_usize;
    while let Some((oid, parent, depth)) = frontier.pop() {
        ensure_format(repository, oid)?;
        if visited.contains(&oid) {
            continue;
        }
        if visited.len() == limits.max_objects {
            return Err(limit_error("objects", limits.max_objects));
        }
        visited.insert(oid);
        let object = repository.object(oid)?;
        let object_type = object.object_type();
        let reason = omission_reason(filter, &object, depth);
        if let Some(reason) = reason {
            omissions
                .try_reserve(1)
                .map_err(|_| limit_error("promisor omissions", limits.max_objects))?;
            omissions.push(PromisorOmission {
                oid,
                object_type,
                parent,
                depth,
                reason,
            });
            continue;
        }
        objects
            .try_reserve(1)
            .map_err(|_| limit_error("pack objects", limits.max_objects))?;
        objects.push(ClosureObjectId { oid, object_type });
        match object {
            ClosureObject::Commit(commit) => {
                ensure_format(repository, commit.tree)?;
                frontier.push((commit.tree, Some(oid), 0));
                for parent_commit in commit.parents.into_iter().rev() {
                    ensure_format(repository, parent_commit)?;
                    frontier.push((parent_commit, Some(oid), 0));
                }
            }
            ClosureObject::Tree(entries) => {
                edge_count = edge_count
                    .checked_add(entries.len())
                    .ok_or_else(|| limit_error("tree edges", limits.max_edges))?;
                if edge_count > limits.max_edges {
                    return Err(limit_error("tree edges", limits.max_edges));
                }
                let next_depth = depth
                    .checked_add(1)
                    .ok_or(ClosureError::InconsistentGraph { oid })?;
                for entry in entries.into_iter().rev() {
                    ensure_format(repository, entry.oid)?;
                    frontier.push((entry.oid, Some(oid), next_depth));
                }
            }
            ClosureObject::Blob { .. } => {}
            ClosureObject::Tag { target } => {
                ensure_format(repository, target)?;
                frontier.push((target, Some(oid), depth));
            }
        }
    }
    objects.sort_by(compare_object_ids);
    Ok((objects, omissions))
}

fn omission_reason(
    filter: Option<&ObjectFilter>,
    object: &ClosureObject,
    depth: u32,
) -> Option<OmissionReason> {
    let filter = filter?;
    if object.object_type() == ObjectType::Tree && !tree_depth_permits(filter, depth) {
        return Some(OmissionReason::TreeDepth);
    }
    if matches!(object, ClosureObject::Blob { .. }) && !blob_permits(filter, object) {
        return Some(OmissionReason::BlobFilter);
    }
    None
}

fn tree_depth_permits(filter: &ObjectFilter, depth: u32) -> bool {
    match filter {
        ObjectFilter::TreeDepth(maximum) => depth <= *maximum,
        ObjectFilter::Combine(parts) => parts.iter().all(|part| tree_depth_permits(part, depth)),
        ObjectFilter::BlobNone
        | ObjectFilter::BlobLimit(_)
        | ObjectFilter::SparsePath(_)
        | ObjectFilter::SparseObject(_) => true,
    }
}

fn blob_permits(filter: &ObjectFilter, object: &ClosureObject) -> bool {
    let ClosureObject::Blob { size } = object else {
        return true;
    };
    match filter {
        ObjectFilter::BlobNone => false,
        ObjectFilter::BlobLimit(limit) => *size <= *limit,
        ObjectFilter::TreeDepth(_)
        | ObjectFilter::SparsePath(_)
        | ObjectFilter::SparseObject(_) => true,
        ObjectFilter::Combine(parts) => parts.iter().all(|part| blob_permits(part, object)),
    }
}

fn ensure_format(
    repository: &impl ObjectClosureRepository,
    oid: AnyGitOid,
) -> Result<(), ClosureError> {
    let observed = oid.algorithm();
    let expected = repository.object_format();
    if observed == expected {
        Ok(())
    } else {
        Err(ClosureError::ObjectFormatMismatch { expected, observed })
    }
}

const fn object_type_code(object_type: ObjectType) -> u8 {
    match object_type {
        ObjectType::Blob => 1,
        ObjectType::Tree => 2,
        ObjectType::Commit => 3,
        ObjectType::Tag => 4,
    }
}

fn compare_object_ids(left: &ClosureObjectId, right: &ClosureObjectId) -> std::cmp::Ordering {
    left.oid
        .cmp(&right.oid)
        .then_with(|| object_type_code(left.object_type).cmp(&object_type_code(right.object_type)))
}

fn compare_omissions(left: &PromisorOmission, right: &PromisorOmission) -> std::cmp::Ordering {
    left.oid
        .cmp(&right.oid)
        .then_with(|| object_type_code(left.object_type).cmp(&object_type_code(right.object_type)))
        .then_with(|| left.parent.cmp(&right.parent))
        .then_with(|| left.depth.cmp(&right.depth))
        .then_with(|| omission_reason_code(left.reason).cmp(&omission_reason_code(right.reason)))
}

const fn omission_reason_code(reason: OmissionReason) -> u8 {
    match reason {
        OmissionReason::BlobFilter => 1,
        OmissionReason::TreeDepth => 2,
    }
}

fn omission_commitment(omissions: &[PromisorOmission]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"fgit-promisor-omissions-v1\0");
    for omission in omissions {
        bytes.extend_from_slice(&omission.oid.algorithm().code_point().to_be_bytes());
        bytes.extend_from_slice(omission.oid.as_bytes());
        bytes.push(object_type_code(omission.object_type));
        match omission.parent {
            Some(parent) => {
                bytes.push(1);
                bytes.extend_from_slice(&parent.algorithm().code_point().to_be_bytes());
                bytes.extend_from_slice(parent.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&omission.depth.to_be_bytes());
        bytes.push(omission_reason_code(omission.reason));
    }
    sha256_digest(&bytes)
}

const fn limit_error(field: &'static str, limit: usize) -> ClosureError {
    ClosureError::ResourceLimit { field, limit }
}
