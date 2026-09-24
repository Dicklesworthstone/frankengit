#![forbid(unsafe_code)]
//! Bounded native-object graph verification over an explicitly selected set.
//!
//! Selection and disclosure authorization belong to the caller. This checker
//! never discovers objects, widens the set, follows gitlinks, or publishes
//! state. Feed each selected object exactly once in native-ID order, then
//! finish with the selected references. Object bodies are not retained.
//!
//! The import-compatible parser owns syntax. This adds unique typed commit/tag
//! targets, complete local connectivity, reference-target kinds and acyclicity;
//! it does not claim strict Git fsck diagnostics, signature verification, safe
//! host paths, or a retention decision. Storage must separately verify its
//! stronger payload commitments. Native object identities are rechecked here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fgit_crypto::git_object_id;
pub use fgit_git_object::ObjectType as ObjectKind;
use fgit_git_object::{
    AcceptanceProfile, ObjectError, ParseLimits, TagTargetType, parse_annotated_tag, parse_commit,
    parse_tree, validate_reference_target_kind,
};
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RefName};

/// Independent graph, input and parser bounds. Allocator overhead and the
/// caller's retained input set are not included in the payload byte counter.
#[derive(Clone, Copy, Debug)]
pub struct GraphLimits {
    pub max_objects: usize,
    pub max_references: usize,
    /// Counts every inspected local edge AND external gitlink, including duplicates.
    pub max_edges: usize,
    pub max_object_bytes: usize,
    pub max_payload_bytes: u64,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_references: 100_000,
            max_edges: 1_000_000,
            max_object_bytes: 32 * 1024 * 1024,
            max_payload_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphRefusal {
    Limit(&'static str),
    Allocation,
    Cancelled,
    Failed,
    Incomplete,
    ObjectOrder,
    ObjectFormat(GitOid),
    IdentityMismatch(GitOid),
    Malformed {
        object: GitOid,
        cause: Box<ObjectError>,
    },
    InvalidTreeMode(GitOid),
    MissingTarget {
        source: Option<GitOid>,
        target: GitOid,
    },
    TargetKind {
        target: GitOid,
        expected: ObjectKind,
        actual: ObjectKind,
    },
    Cycle(GitOid),
}

impl fmt::Display for GraphRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(name) => write!(out, "graph_limit_exceeded: {name}"),
            Self::Allocation => out.write_str("graph_allocation_refused"),
            Self::Cancelled => out.write_str("graph_checkpoint_refused"),
            Self::Failed => out.write_str("graph_audit_previously_failed"),
            Self::Incomplete => out.write_str("graph_objects_not_completely_observed"),
            Self::ObjectOrder => out.write_str("graph_object_order_or_selection_mismatch"),
            Self::ObjectFormat(id) => write!(out, "graph_native_identity_invalid: {id}"),
            Self::IdentityMismatch(id) => write!(out, "graph_object_identity_mismatch: {id}"),
            Self::Malformed { object, cause } => {
                write!(out, "graph_object_malformed: {object}: {cause}")
            }
            Self::InvalidTreeMode(id) => write!(out, "graph_tree_mode_unsupported: {id}"),
            Self::MissingTarget { source, target } => write!(
                out,
                "graph_target_outside_selection: {target}; source: {source:?}"
            ),
            Self::TargetKind {
                target,
                expected,
                actual,
            } => write!(
                out,
                "graph_target_kind_mismatch: {target}; expected {}, found {}",
                expected.label(),
                actual.label()
            ),
            Self::Cycle(id) => write!(out, "graph_cycle: {id}"),
        }
    }
}
impl std::error::Error for GraphRefusal {}

/// A completed observation, not authority or a storage-durability proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphReport {
    pub objects: usize,
    pub references: usize,
    pub local_edges: usize,
    pub external_gitlinks: usize,
    pub payload_bytes: u64,
}

#[derive(Debug)]
struct Node {
    id: GitOid,
    kind: Option<ObjectKind>,
    start: usize,
    end: usize,
}
#[derive(Debug)]
struct Edge {
    target: usize,
    expected: ObjectKind,
}

/// Streaming audit with dense object ordinals and contiguous adjacency ranges.
/// An observation failure poisons the builder: ignoring an error cannot yield
/// a successful report. Finishing consumes it. No recursive graph walk is used.
#[derive(Debug)]
pub struct ObjectGraphAudit {
    format: GitHashAlgorithm,
    limits: GraphLimits,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    next: usize,
    gitlinks: usize,
    payload_bytes: u64,
    failed: bool,
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), GraphRefusal> {
    if live() {
        Ok(())
    } else {
        Err(GraphRefusal::Cancelled)
    }
}
fn malformed(object: GitOid, cause: ObjectError) -> GraphRefusal {
    match cause {
        ObjectError::AllocationFailure => GraphRefusal::Allocation,
        ObjectError::ObjectTooLarge { .. } => GraphRefusal::Limit("object bytes"),
        ObjectError::TooManyTreeEntries { .. } => GraphRefusal::Limit("tree entries"),
        ObjectError::HeaderLimitExceeded { .. } => GraphRefusal::Limit("header structure"),
        cause => GraphRefusal::Malformed {
            object,
            cause: Box::new(cause),
        },
    }
}

impl ObjectGraphAudit {
    /// Reserve only the selected object table, after its count is bounded.
    /// Empty sets and zero edge budgets are legitimate, independently bounded inputs.
    pub fn new(
        objects: &BTreeSet<GitOid>,
        format: GitHashAlgorithm,
        limits: GraphLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<Self, GraphRefusal> {
        checkpoint(live)?;
        if objects.len() > limits.max_objects {
            return Err(GraphRefusal::Limit("objects"));
        }
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(objects.len())
            .map_err(|_| GraphRefusal::Allocation)?;
        for &id in objects {
            checkpoint(live)?;
            if id.algorithm() != format || id.is_zero() {
                return Err(GraphRefusal::ObjectFormat(id));
            }
            nodes.push(Node {
                id,
                kind: None,
                start: 0,
                end: 0,
            });
        }
        Ok(Self {
            format,
            limits,
            nodes,
            edges: Vec::new(),
            next: 0,
            gitlinks: 0,
            payload_bytes: 0,
            failed: false,
        })
    }

    pub fn observe(
        &mut self,
        id: GitOid,
        kind: ObjectKind,
        body: &[u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), GraphRefusal> {
        if self.failed {
            return Err(GraphRefusal::Failed);
        }
        let result = self.observe_inner(id, kind, body, live);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn observe_inner(
        &mut self,
        id: GitOid,
        kind: ObjectKind,
        body: &[u8],
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), GraphRefusal> {
        checkpoint(live)?;
        if self.nodes.get(self.next).map(|node| node.id) != Some(id) {
            return Err(GraphRefusal::ObjectOrder);
        }
        if body.len() > self.limits.max_object_bytes {
            return Err(GraphRefusal::Limit("object bytes"));
        }
        let payload_bytes = self
            .payload_bytes
            .checked_add(body.len() as u64)
            .filter(|total| *total <= self.limits.max_payload_bytes)
            .ok_or(GraphRefusal::Limit("payload bytes"))?;
        let identity = git_object_id(self.format, kind, body);
        checkpoint(live)?;
        if identity != id {
            return Err(GraphRefusal::IdentityMismatch(id));
        }
        let start = self.edges.len();
        let limits = ParseLimits {
            max_object_bytes: self.limits.max_object_bytes,
            tree_reference_bytes: self.format.digest_len(),
            // Parser work is bounded before copying entries, even when a tree
            // contains only external links or repeated edges.
            max_tree_entries: self
                .remaining_edges()
                .min(ParseLimits::default().max_tree_entries),
            ..ParseLimits::default()
        };
        match kind {
            ObjectKind::Blob => {} // Blobs have no edges: never clone their payload for parsing.
            ObjectKind::Commit => {
                let commit = parse_commit(body, AcceptanceProfile::GitCompatibleImport, &limits)
                    .map_err(|cause| malformed(id, cause))?;
                checkpoint(live)?;
                let mut trees = 0_usize;
                for header in commit.headers() {
                    checkpoint(live)?;
                    let expected = match header.name.as_slice() {
                        b"tree" => {
                            trees += 1;
                            ObjectKind::Tree
                        }
                        b"parent" => ObjectKind::Commit,
                        _ => continue,
                    };
                    if !header.continuations.is_empty() {
                        return Err(malformed(id, ObjectError::MalformedObjectReference));
                    }
                    if trees > 1 {
                        return Err(malformed(id, ObjectError::MissingOrDuplicateCommitTree));
                    }
                    let target = native_hex(self.format, &header.value)
                        .map_err(|cause| malformed(id, cause))?;
                    self.add_edge(id, target, expected)?;
                }
                if trees != 1 {
                    return Err(malformed(id, ObjectError::MissingOrDuplicateCommitTree));
                }
            }
            ObjectKind::Tree => {
                let entries = parse_tree(body, AcceptanceProfile::GitCompatibleImport, &limits)
                    .map_err(|cause| match cause {
                        ObjectError::TooManyTreeEntries { .. }
                            if limits.max_tree_entries == self.remaining_edges() =>
                        {
                            GraphRefusal::Limit("edges")
                        }
                        cause => malformed(id, cause),
                    })?;
                checkpoint(live)?;
                for entry in entries {
                    checkpoint(live)?;
                    let target = native_bytes(self.format, &entry.object_id)
                        .map_err(|cause| malformed(id, cause))?;
                    if target.is_zero() {
                        return Err(GraphRefusal::ObjectFormat(target));
                    }
                    match tree_target_kind(&entry.mode).ok_or(GraphRefusal::InvalidTreeMode(id))? {
                        TreeTarget::Object(expected) => self.add_edge(id, target, expected)?,
                        TreeTarget::Gitlink => {
                            // A gitlink is a foreign commit datum, not permission to
                            // read local bytes, even when this ID is in the selection.
                            self.charge_edge()?;
                            self.gitlinks += 1;
                        }
                    }
                }
            }
            ObjectKind::Tag => {
                let tag = parse_annotated_tag(
                    body,
                    self.format,
                    AcceptanceProfile::GitCompatibleImport,
                    &limits,
                )
                .map_err(|cause| malformed(id, cause))?;
                checkpoint(live)?;
                let target = tag.target();
                let expected = match target.object_type {
                    TagTargetType::Blob => ObjectKind::Blob,
                    TagTargetType::Tree => ObjectKind::Tree,
                    TagTargetType::Commit => ObjectKind::Commit,
                    TagTargetType::Tag => ObjectKind::Tag,
                };
                self.add_edge(id, target.oid, expected)?;
            }
        }
        checkpoint(live)?;
        let node = &mut self.nodes[self.next];
        node.kind = Some(kind);
        node.start = start;
        node.end = self.edges.len();
        self.next += 1;
        self.payload_bytes = payload_bytes;
        Ok(())
    }

    const fn remaining_edges(&self) -> usize {
        self.limits
            .max_edges
            .saturating_sub(self.edges.len())
            .saturating_sub(self.gitlinks)
    }
    const fn charge_edge(&self) -> Result<(), GraphRefusal> {
        if self.remaining_edges() == 0 {
            Err(GraphRefusal::Limit("edges"))
        } else {
            Ok(())
        }
    }
    fn index(&self, source: Option<GitOid>, target: GitOid) -> Result<usize, GraphRefusal> {
        if target.algorithm() != self.format || target.is_zero() {
            return Err(GraphRefusal::ObjectFormat(target));
        }
        self.nodes
            .binary_search_by_key(&target, |node| node.id)
            .map_err(|_| GraphRefusal::MissingTarget { source, target })
    }
    fn add_edge(
        &mut self,
        source: GitOid,
        target: GitOid,
        expected: ObjectKind,
    ) -> Result<(), GraphRefusal> {
        self.charge_edge()?;
        let target = self.index(Some(source), target)?;
        // Geometric growth bounded by max_edges, not one realloc per edge.
        if self.edges.len() == self.edges.capacity() {
            let capacity = self
                .edges
                .capacity()
                .saturating_mul(2)
                .max(16)
                .min(self.limits.max_edges);
            self.edges
                .try_reserve_exact(capacity - self.edges.len())
                .map_err(|_| GraphRefusal::Allocation)?;
        }
        self.edges.push(Edge { target, expected });
        Ok(())
    }

    pub fn finish(
        self,
        references: &BTreeMap<RefName, GitOid>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<GraphReport, GraphRefusal> {
        checkpoint(live)?;
        if self.failed {
            return Err(GraphRefusal::Failed);
        }
        if self.next != self.nodes.len() {
            return Err(GraphRefusal::Incomplete);
        }
        if references.len() > self.limits.max_references {
            return Err(GraphRefusal::Limit("references"));
        }
        for (name, &target) in references {
            checkpoint(live)?;
            let index = self.index(None, target)?;
            let actual = self.nodes[index].kind.ok_or(GraphRefusal::Incomplete)?;
            validate_reference_target_kind(name.as_bytes(), actual).map_err(|error| {
                GraphRefusal::TargetKind {
                    target,
                    expected: error.expected,
                    actual: error.actual,
                }
            })?;
        }
        for edge in &self.edges {
            checkpoint(live)?;
            let node = &self.nodes[edge.target];
            let actual = node.kind.ok_or(GraphRefusal::Incomplete)?;
            if actual != edge.expected {
                return Err(GraphRefusal::TargetKind {
                    target: node.id,
                    expected: edge.expected,
                    actual,
                });
            }
        }
        verify_acyclic(&self.nodes, &self.edges, live)?;
        checkpoint(live)?;
        Ok(GraphReport {
            objects: self.nodes.len(),
            references: references.len(),
            local_edges: self.edges.len(),
            external_gitlinks: self.gitlinks,
            payload_bytes: self.payload_bytes,
        })
    }
}

fn native_hex(format: GitHashAlgorithm, bytes: &[u8]) -> Result<GitOid, ObjectError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ObjectError::MalformedObjectReference)?;
    GitOid::from_hex(format, text).map_err(|_| ObjectError::MalformedObjectReference)
}
fn native_bytes(format: GitHashAlgorithm, bytes: &[u8]) -> Result<GitOid, ObjectError> {
    match format {
        GitHashAlgorithm::Sha1 => bytes
            .try_into()
            .map(GitOidSha1::from_bytes)
            .map(GitOid::from),
        GitHashAlgorithm::Sha256 => bytes
            .try_into()
            .map(GitOidSha256::from_bytes)
            .map(GitOid::from),
    }
    .map_err(|_| ObjectError::MalformedObjectReference)
}

/// What a tree entry's mode says its object ID names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeTarget {
    /// A local object of this kind; the edge is verified like any other.
    Object(ObjectKind),
    /// A submodule commit in a foreign repository; never read locally.
    Gitlink,
}

/// Octal value, not spelling: imported 0160000 remains a gitlink. Import's
/// historical regular-file permission variants have the same blob edge kind.
/// No unknown file type is silently treated as a blob or discarded edge.
fn tree_target_kind(mode: &[u8]) -> Option<TreeTarget> {
    let mut value = 0_u32;
    if mode.is_empty() {
        return None;
    }
    for &digit in mode {
        if !(b'0'..=b'7').contains(&digit) {
            return None;
        }
        value = value.checked_mul(8)?.checked_add(u32::from(digit - b'0'))?;
    }
    if value > 0o177777 {
        return None;
    }
    match value & 0o170000 {
        0o040000 => Some(TreeTarget::Object(ObjectKind::Tree)),
        0o100000 | 0o120000 => Some(TreeTarget::Object(ObjectKind::Blob)),
        0o160000 => Some(TreeTarget::Gitlink),
        _ => None,
    }
}

/// Iterative DFS is O(V+E), counts duplicate edges, and uses O(V) scratch.
/// Colors are local: a cancelled/failed traversal never leaves a reusable proof.
fn verify_acyclic(
    nodes: &[Node],
    edges: &[Edge],
    live: &mut impl FnMut() -> bool,
) -> Result<(), GraphRefusal> {
    let mut colors = Vec::new();
    colors
        .try_reserve_exact(nodes.len())
        .map_err(|_| GraphRefusal::Allocation)?;
    colors.resize(nodes.len(), 0_u8);
    let mut stack: Vec<(usize, usize)> = Vec::new();
    stack
        .try_reserve_exact(nodes.len())
        .map_err(|_| GraphRefusal::Allocation)?;
    for root in 0..nodes.len() {
        checkpoint(live)?;
        if colors[root] != 0 {
            continue;
        }
        colors[root] = 1;
        stack.push((root, nodes[root].start));
        while let Some((node, cursor)) = stack.last_mut() {
            checkpoint(live)?;
            if *cursor == nodes[*node].end {
                colors[*node] = 2;
                stack.pop();
                continue;
            }
            let target = edges[*cursor].target;
            *cursor += 1;
            match colors[target] {
                1 => return Err(GraphRefusal::Cycle(nodes[target].id)),
                0 => {
                    colors[target] = 1;
                    stack.push((target, nodes[target].start));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
