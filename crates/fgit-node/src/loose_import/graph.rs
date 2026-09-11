//! Whole-source native graph validation before local-import staging.
//!
//! The shared edge reader also serves receive quarantine. It grants no object
//! access: callers own source selection, native identity checks and budgets.
use std::collections::{BTreeMap, BTreeSet};

use fgit_git_object::{
    AcceptanceProfile, LooseObject, ObjectType, ParseLimits, ParsedObject,
    TagTargetType, parse_annotated_tag, parse_object_body,
};
use fgit_pack::Deadline;
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RefusalCode};

use super::{LooseGitImportRefusal, MAX_IMPORT_OBJECTS, MAX_IMPORT_TOTAL_OBJECT_BYTES};

/// Independent total edge work; repeated references and gitlinks count too.
const MAX_IMPORT_GRAPH_EDGES: usize = 4_000_000;

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) objects: usize,
    pub(super) edges: usize,
    pub(super) bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            objects: MAX_IMPORT_OBJECTS,
            edges: MAX_IMPORT_GRAPH_EDGES,
            bytes: MAX_IMPORT_TOTAL_OBJECT_BYTES,
        }
    }
}

/// Private proof: no partially validated map can reach the staging loop.
#[derive(Debug)]
pub(super) struct ValidatedImport {
    pub(super) objects: BTreeMap<GitOid, LooseObject>,
    pub(super) total_bytes: u64,
}

/// Read each selected object once, then check every local edge's required kind.
/// Bodies are retained under the existing aggregate byte bound so subsequent
/// source-file changes cannot replace bytes between validation and placement.
/// No fabric write occurs here, even when a late dependency is unavailable.
pub(super) fn validate(
    roots: impl IntoIterator<Item = GitOid>,
    format: GitHashAlgorithm,
    parse_limits: &ParseLimits,
    limits: Limits,
    mut load: impl FnMut(GitOid) -> Result<LooseObject, LooseGitImportRefusal>,
) -> Result<ValidatedImport, LooseGitImportRefusal> {
    let maximum = Limits::default();
    if limits.objects > maximum.objects || limits.edges > maximum.edges
        || limits.bytes > maximum.bytes
    {
        return Err(LooseGitImportRefusal::ObjectLimitExceeded { limit: maximum.objects });
    }
    let mut required = BTreeMap::new();
    let mut pending = BTreeSet::new();
    let mut objects = BTreeMap::<GitOid, LooseObject>::new();
    for root in roots {
        enqueue(root, None, format, limits.objects, &mut required, &mut pending)?;
    }
    let mut total_bytes = 0_u64;
    let mut edges_left = limits.edges;
    while let Some(identity) = pending.pop_first() {
        let object = load(identity)?;
        let observed = fgit_crypto::git_object_id(format, object.object_type, &object.body);
        if observed != identity {
            return Err(LooseGitImportRefusal::ObjectIdentityMismatch { expected: identity, observed });
        }
        if let Some(Some(expected)) = required.get(&identity) {
            require_kind(identity, *expected, object.object_type)?;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(object.body.len()).unwrap_or(u64::MAX));
        if total_bytes > limits.bytes {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: limits.bytes, observed: total_bytes,
            });
        }
        let parsed = parse_object_body(object.object_type, &object.body,
            AcceptanceProfile::GitCompatibleImport, parse_limits)
            .map_err(|error| LooseGitImportRefusal::ObjectStructure(Box::new(error)))?;
        // Retain the established import refusal vocabulary for these cases.
        match &parsed {
            ParsedObject::Commit(commit) if commit.tree_reference().is_none() => {
                return Err(LooseGitImportRefusal::CommitTreeMissing(identity));
            }
            ParsedObject::Tag(tag) if tag.headers().iter().filter(|h| h.name == b"object").count() != 1 => {
                return Err(LooseGitImportRefusal::TagObjectMissing(identity));
            }
            _ => {}
        }
        let edges = references(format, &parsed, &object.body, parse_limits,
            &mut edges_left, &mut || true)
            .map_err(|code| LooseGitImportRefusal::ObjectGraph { identity, code })?;
        // Discard parsed copies before retaining the exact original body.
        drop(parsed);
        objects.insert(identity, object);
        for (child, kind) in edges {
            // Even a previously read root or child must satisfy this new edge.
            // In particular, a root's unconstrained kind cannot hide a later
            // commit/tree/tag requirement.
            if let Some(known) = objects.get(&child) {
                require_kind(child, kind, known.object_type)?;
            }
            enqueue(child, Some(kind), format, limits.objects, &mut required, &mut pending)?;
        }
    }
    Ok(ValidatedImport { objects, total_bytes })
}

fn enqueue(
    id: GitOid, kind: Option<ObjectType>, format: GitHashAlgorithm, limit: usize,
    required: &mut BTreeMap<GitOid, Option<ObjectType>>, pending: &mut BTreeSet<GitOid>,
) -> Result<(), LooseGitImportRefusal> {
    if id.is_zero() || id.algorithm() != format {
        return Err(LooseGitImportRefusal::ObjectGraph { identity: id, code: RefusalCode::ObjectHeaderInvalid });
    }
    if let Some(previous) = required.get_mut(&id) {
        if let (Some(first), Some(next)) = (*previous, kind) {
            require_kind(id, first, next)?;
        }
        if previous.is_none() { *previous = kind; }
        return Ok(());
    }
    // Charge at enqueue: a large frontier cannot allocate beyond the object
    // limit merely because those objects have not yet been read.
    if required.len() >= limit {
        return Err(LooseGitImportRefusal::ObjectLimitExceeded { limit });
    }
    required.insert(id, kind);
    pending.insert(id);
    Ok(())
}

fn require_kind(id: GitOid, expected: ObjectType, actual: ObjectType) -> Result<(), LooseGitImportRefusal> {
    if expected == actual { Ok(()) } else {
        Err(LooseGitImportRefusal::ObjectGraph { identity: id, code: RefusalCode::EvidenceInvalid })
    }
}

/// One shared native-edge vocabulary for local import and receive quarantine.
/// The original parser and typed annotated-tag view own all byte decoding.
/// A caller must supply the parsed view of the same native-verified `body`.
pub(crate) fn references(
    format: GitHashAlgorithm, parsed: &ParsedObject, body: &[u8],
    limits: &ParseLimits, edges_left: &mut usize, deadline: &mut impl Deadline,
) -> Result<Vec<(GitOid, ObjectType)>, RefusalCode> {
    let mut edges = Vec::new();
    checkpoint(deadline)?;
    match parsed {
        ParsedObject::Blob(_) => {}
        ParsedObject::Tree(entries) => {
            for entry in entries {
                checkpoint(deadline)?;
                charge_edge(edges_left)?;
                let mode = std::str::from_utf8(&entry.mode).ok()
                    .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                    .ok_or(RefusalCode::ObjectHeaderInvalid)?;
                let kind = match mode & 0o170_000 {
                    0o040_000 => ObjectType::Tree,
                    0o100_000 | 0o120_000 => ObjectType::Blob,
                    // Type bits, not spelling: import-tolerated padded gitlink
                    // modes still name another repository and cause no read.
                    0o160_000 => continue,
                    _ => return Err(RefusalCode::ObjectHeaderInvalid),
                };
                let id = match format {
                    GitHashAlgorithm::Sha1 => GitOid::from(GitOidSha1::from_bytes(
                        entry.object_id.as_slice().try_into().map_err(|_| RefusalCode::ObjectHeaderInvalid)?)),
                    GitHashAlgorithm::Sha256 => GitOid::from(GitOidSha256::from_bytes(
                        entry.object_id.as_slice().try_into().map_err(|_| RefusalCode::ObjectHeaderInvalid)?)),
                };
                push(&mut edges, id, kind)?;
            }
        }
        ParsedObject::Commit(commit) => {
            let mut trees = 0_usize;
            for header in commit.headers() {
                checkpoint(deadline)?;
                let kind = if header.name == b"tree" {
                    trees += 1;
                    ObjectType::Tree
                } else if header.name == b"parent" {
                    ObjectType::Commit
                } else { continue; };
                if !header.continuations.is_empty() || trees > 1 {
                    return Err(RefusalCode::ObjectHeaderInvalid);
                }
                charge_edge(edges_left)?;
                let text = std::str::from_utf8(&header.value).map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                let id = GitOid::from_hex(format, text).map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                push(&mut edges, id, kind)?;
            }
            if trees != 1 { return Err(RefusalCode::ObjectHeaderInvalid); }
        }
        ParsedObject::Tag(_) => {
            let tag = parse_annotated_tag(body, format, AcceptanceProfile::GitCompatibleImport, limits)
                .map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
            checkpoint(deadline)?;
            let target = tag.target();
            let kind = match target.object_type {
                TagTargetType::Blob => ObjectType::Blob,
                TagTargetType::Tree => ObjectType::Tree,
                TagTargetType::Commit => ObjectType::Commit,
                TagTargetType::Tag => ObjectType::Tag,
            };
            charge_edge(edges_left)?;
            push(&mut edges, target.oid, kind)?;
        }
    }
    checkpoint(deadline)?;
    Ok(edges)
}

fn checkpoint(deadline: &mut impl Deadline) -> Result<(), RefusalCode> {
    if deadline.checkpoint() { Ok(()) } else { Err(RefusalCode::CancellationInProgress) }
}
fn charge_edge(remaining: &mut usize) -> Result<(), RefusalCode> {
    *remaining = remaining.checked_sub(1).ok_or(RefusalCode::ResourceBudgetExceeded)?;
    Ok(())
}
fn push(edges: &mut Vec<(GitOid, ObjectType)>, id: GitOid, kind: ObjectType) -> Result<(), RefusalCode> {
    if id.is_zero() { return Err(RefusalCode::ObjectHeaderInvalid); }
    edges.try_reserve(1).map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
    edges.push((id, kind));
    Ok(())
}

#[cfg(test)]
mod tests;
