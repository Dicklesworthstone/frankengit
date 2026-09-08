//! Bounded native merge-object validation over a real object source.
//! Caller-supplied edge metadata is not closure evidence: outgoing edges and
//! their required kinds are parsed from independently verified native bytes.

use std::collections::{BTreeMap, BTreeSet};

use fgit_forge::event::NativeMerge;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject};
use fgit_pack::{CanonicalObjectSource, Deadline, PackError, PackWriteError, verify_native_object};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

use crate::{PermittedObjectClosure, ProjectionFailure, ValidatedClosure, permitted_object_closure_root};

/// Independent object/work ceilings. A caller also supplies its live deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MergeObjectLimits {
    pub max_objects: usize,
    pub max_edges: usize,
    pub max_object_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for MergeObjectLimits {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_edges: 400_000,
            max_object_bytes: 32 * 1024 * 1024,
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
    let maximum = MergeObjectLimits::default();
    if limits.max_objects == 0 || limits.max_objects > maximum.max_objects
        || limits.max_edges == 0 || limits.max_edges > maximum.max_edges
        || limits.max_object_bytes == 0 || limits.max_object_bytes > maximum.max_object_bytes
        || limits.max_total_bytes == 0 || limits.max_total_bytes > maximum.max_total_bytes
    { return Err(budget()); }
    let format = merge.merge_commit.algorithm();
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
    require_object(merge.merge_commit, ObjectType::Commit, &mut required, &mut pending, limits)?;
    let mut total_bytes = 0_usize;
    let mut edges = 0_usize;

    while let Some(id) = pending.pop_first() {
        checkpoint(deadline)?;
        let object = source.load(&id).map_err(source_failure)?;
        checkpoint(deadline)?;
        if object.id() != id || required.get(&id) != Some(&object.object_type()) {
            return Err(invalid());
        }
        if object.body().len() > limits.max_object_bytes { return Err(budget()); }
        total_bytes = total_bytes.checked_add(object.body().len())
            .filter(|bytes| *bytes <= limits.max_total_bytes).ok_or_else(budget)?;
        let profile = if id == merge.merge_commit {
            AcceptanceProfile::StrictCreate
        } else {
            AcceptanceProfile::GitCompatibleImport
        };
        let parsed = verify_native_object(format, object.object_type(), object.body(), &id, profile, &parse_limits)
            .map_err(|_| invalid())?;
        checkpoint(deadline)?;
        visited.insert(id);
        let mut outgoing = Vec::new();
        match parsed {
            ParsedObject::Commit(commit) => {
                let tree = parse_oid(format, commit.tree_reference().ok_or_else(invalid)?)?;
                push_edge(&mut outgoing, &mut edges, limits.max_edges, tree, ObjectType::Tree)?;
                let mut parent_ids = Vec::new();
                for parent in commit.parent_references() {
                    checkpoint(deadline)?;
                    let parent = parse_oid(format, parent)?;
                    push_edge(&mut outgoing, &mut edges, limits.max_edges, parent, ObjectType::Commit)?;
                    parent_ids.push(parent);
                }
                if id == merge.merge_commit
                    && (parent_ids.as_slice() != [merge.target_tip_before, merge.source_tip].as_slice()
                        || merge.target_tip_before == merge.source_tip)
                { return Err(invalid()); }
                parents.insert(id, parent_ids);
            }
            ParsedObject::Tree(entries) => {
                for entry in entries {
                    checkpoint(deadline)?;
                    // Even a gitlink consumes traversal work, though its target
                    // belongs to another repository and is not fetched here.
                    charge_edge(&mut edges, limits.max_edges)?;
                    let mode = std::str::from_utf8(&entry.mode).ok()
                        .and_then(|mode| u32::from_str_radix(mode, 8).ok()).ok_or_else(invalid)?;
                    let kind = match mode & 0o170_000 {
                        0o040_000 => ObjectType::Tree,
                        0o100_000 | 0o120_000 => ObjectType::Blob,
                        0o160_000 => continue,
                        _ => return Err(invalid()),
                    };
                    let hex: String = entry.object_id.iter().map(|byte| format!("{byte:02x}")).collect();
                    outgoing.try_reserve(1).map_err(|_| budget())?;
                    outgoing.push((parse_oid(format, hex.as_bytes())?, kind));
                }
            }
            ParsedObject::Blob(_) => {}
            ParsedObject::Tag(_) => return Err(invalid()),
        }
        for (target, kind) in outgoing {
            checkpoint(deadline)?;
            require_object(target, kind, &mut required, &mut pending, limits)?;
        }
    }
    if !parents.contains_key(&merge.base_tip)
        || !is_ancestor(merge.base_tip, merge.source_tip, &parents, deadline)?
        || !is_ancestor(merge.base_tip, merge.target_tip_before, &parents, deadline)?
    { return Err(invalid()); }
    checkpoint(deadline)?;
    let closure = PermittedObjectClosure::new(visited);
    let object_closure_root = permitted_object_closure_root(&closure)
        .map_err(ProjectionFailure::Unavailable)?;
    checkpoint(deadline)?;
    Ok(ValidatedClosure { object_closure_root, objects: closure.objects().clone() })
}

fn charge_edge(edges: &mut usize, limit: usize) -> Result<(), ProjectionFailure> {
    *edges = edges.checked_add(1).filter(|count| *count <= limit).ok_or_else(budget)?;
    Ok(())
}

fn push_edge(
    outgoing: &mut Vec<(GitOid, ObjectType)>, edges: &mut usize, limit: usize,
    target: GitOid, kind: ObjectType,
) -> Result<(), ProjectionFailure> {
    charge_edge(edges, limit)?;
    outgoing.try_reserve(1).map_err(|_| budget())?;
    outgoing.push((target, kind));
    Ok(())
}

fn require_object(
    id: GitOid, kind: ObjectType, required: &mut BTreeMap<GitOid, ObjectType>,
    pending: &mut BTreeSet<GitOid>, limits: MergeObjectLimits,
) -> Result<(), ProjectionFailure> {
    if id.is_zero() { return Err(invalid()); }
    if let Some(expected) = required.get(&id) {
        if *expected != kind { return Err(invalid()); }
        return Ok(());
    }
    // Charge unique membership at enqueue, not after reading: shared edges
    // cannot inflate the worklist and cycles cannot loop indefinitely.
    if required.len() >= limits.max_objects { return Err(budget()); }
    required.insert(id, kind);
    pending.insert(id);
    Ok(())
}

fn is_ancestor(
    ancestor: GitOid, tip: GitOid, parents: &BTreeMap<GitOid, Vec<GitOid>>,
    deadline: &mut impl Deadline,
) -> Result<bool, ProjectionFailure> {
    let mut pending = BTreeSet::from([tip]);
    let mut visited = BTreeSet::from([tip]);
    while let Some(id) = pending.pop_first() {
        checkpoint(deadline)?;
        if id == ancestor { return Ok(true); }
        for parent in parents.get(&id).ok_or_else(invalid)? {
            checkpoint(deadline)?;
            if visited.insert(*parent) { pending.insert(*parent); }
        }
    }
    Ok(false)
}

fn parse_oid(format: GitHashAlgorithm, bytes: &[u8]) -> Result<GitOid, ProjectionFailure> {
    let hex = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    // Case has no identity significance for parsed references. The original
    // object bytes stay unchanged and are what the native hash verifies.
    GitOid::from_hex(format, &hex.to_ascii_lowercase()).map_err(|_| invalid())
}
fn invalid() -> ProjectionFailure { ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid) }
fn budget() -> ProjectionFailure { ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded) }
fn checkpoint(deadline: &mut impl Deadline) -> Result<(), ProjectionFailure> {
    if deadline.checkpoint() { Ok(()) }
    else { Err(ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)) }
}
fn source_failure(error: PackWriteError) -> ProjectionFailure {
    match error {
        PackWriteError::Pack(PackError::DeadlineExceeded) => ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress),
        _ => ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing),
    }
}
