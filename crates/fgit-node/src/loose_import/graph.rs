//! Whole-source native graph validation before local-import staging.
//!
//! The shared edge reader also serves receive quarantine. It grants no object
//! access: callers own source selection, native identity checks and budgets.
use std::collections::{BTreeMap, BTreeSet};

use fgit_git_object::{
    AcceptanceProfile, LooseObject, ObjectType, ParseLimits, ParsedObject, TagTargetType,
    parse_annotated_tag, parse_object_body,
};
use fgit_pack::Deadline;
use fgit_types::{GitHashAlgorithm, GitOid, GitOidSha1, GitOidSha256, RefusalCode};

use super::control::ImportControl;
use super::{LooseGitImportRefusal, MAX_IMPORT_OBJECTS};

/// Maximum native bytes retained by one verified reachable-source closure.
/// This is independent of the tighter eager pack-decoder/cache envelope: a
/// large loose source must not inherit a limit intended for hydrated packs.
/// The import request reserves this SAME ceiling before any source I/O.
pub(super) const MAX_REACHABLE_OBJECT_BYTES: u64 = 512 * 1024 * 1024;

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
            bytes: MAX_REACHABLE_OBJECT_BYTES,
        }
    }
}

/// Private proof: no partially validated map can reach the staging loop.
#[derive(Debug)]
pub(super) struct ValidatedImport<T = LooseObject> {
    pub(super) objects: BTreeMap<GitOid, T>,
    pub(super) total_bytes: u64,
}

/// Read each selected object once, then check every local edge's required kind.
/// Bodies are retained under the existing aggregate byte bound so subsequent
/// source-file changes cannot replace bytes between validation and placement.
/// No fabric write occurs here, even when a late dependency is unavailable.
#[cfg(test)]
pub(super) fn validate(
    roots: impl IntoIterator<Item = GitOid>,
    format: GitHashAlgorithm,
    parse_limits: &ParseLimits,
    limits: Limits,
    load: impl FnMut(GitOid) -> Result<LooseObject, LooseGitImportRefusal>,
) -> Result<ValidatedImport, LooseGitImportRefusal> {
    let mut live = || true;
    let control = ImportControl::new(&mut live);
    validate_controlled(roots, format, parse_limits, limits, load, &control)
}

/// Unconstrained graph roots are used only by graph/control unit tests. Real
/// repository import must retain the namespace constraint of every direct ref.
#[cfg(test)]
pub(super) fn validate_controlled(
    roots: impl IntoIterator<Item = GitOid>,
    format: GitHashAlgorithm,
    parse_limits: &ParseLimits,
    limits: Limits,
    load: impl FnMut(GitOid) -> Result<LooseObject, LooseGitImportRefusal>,
    control: &ImportControl<'_>,
) -> Result<ValidatedImport, LooseGitImportRefusal> {
    validate_typed_controlled(
        roots.into_iter().map(|id| (id, None)),
        format,
        parse_limits,
        limits,
        load,
        control,
    )
}

#[cfg(test)]
pub(super) fn validate_typed_controlled(
    roots: impl IntoIterator<Item = (GitOid, Option<ObjectType>)>,
    format: GitHashAlgorithm,
    parse_limits: &ParseLimits,
    limits: Limits,
    load: impl FnMut(GitOid) -> Result<LooseObject, LooseGitImportRefusal>,
    control: &ImportControl<'_>,
) -> Result<ValidatedImport, LooseGitImportRefusal> {
    validate_typed_with_custody(
        roots,
        format,
        parse_limits,
        limits,
        load,
        |_, object| Ok(object),
        control,
    )
}

/// The one graph validator owns identity, type, completeness and resource checks.
/// Custody may retain bytes in memory (the test oracle) or in an owned private
/// spool (production). No custody handle is a publication capability.
pub(super) fn validate_typed_with_custody<T>(
    roots: impl IntoIterator<Item = (GitOid, Option<ObjectType>)>,
    format: GitHashAlgorithm,
    parse_limits: &ParseLimits,
    limits: Limits,
    mut load: impl FnMut(GitOid) -> Result<LooseObject, LooseGitImportRefusal>,
    mut retain: impl FnMut(GitOid, LooseObject) -> Result<T, LooseGitImportRefusal>,
    control: &ImportControl<'_>,
) -> Result<ValidatedImport<T>, LooseGitImportRefusal> {
    control.checkpoint()?;
    let maximum = Limits::default();
    if limits.bytes > maximum.bytes {
        return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
            limit: maximum.bytes,
            observed: limits.bytes,
        });
    }
    if limits.objects > maximum.objects || limits.edges > maximum.edges {
        return Err(LooseGitImportRefusal::ObjectLimitExceeded {
            limit: maximum.objects,
        });
    }
    let mut required = BTreeMap::new();
    let mut pending = BTreeSet::new();
    let mut objects = BTreeMap::<GitOid, T>::new();
    let mut kinds = BTreeMap::<GitOid, ObjectType>::new();
    for (root, kind) in roots {
        control.checkpoint()?;
        enqueue(
            root,
            kind,
            format,
            limits.objects,
            &mut required,
            &mut pending,
        )?;
    }
    let mut total_bytes = 0_u64;
    let mut edges_left = limits.edges;
    while let Some(identity) = pending.pop_first() {
        control.checkpoint()?;
        let loaded = load(identity);
        let object = control.after(loaded, |error| error)?;
        let observed = fgit_crypto::git_object_id(format, object.object_type, &object.body);
        control.checkpoint()?;
        if observed != identity {
            return Err(LooseGitImportRefusal::ObjectIdentityMismatch {
                expected: identity,
                observed,
            });
        }
        if let Some(Some(expected)) = required.get(&identity) {
            require_kind(identity, *expected, object.object_type)?;
        }
        total_bytes =
            total_bytes.saturating_add(u64::try_from(object.body.len()).unwrap_or(u64::MAX));
        if total_bytes > limits.bytes {
            return Err(LooseGitImportRefusal::TotalObjectBytesExceeded {
                limit: limits.bytes,
                observed: total_bytes,
            });
        }
        // Blobs are opaque leaves. Their native identity and required kind were
        // checked above; the parser adds only a size check and an owned copy.
        // Preserve that exact refusal without allocating a second entire body.
        if object.object_type == ObjectType::Blob {
            if object.body.len() > parse_limits.max_object_bytes {
                return Err(LooseGitImportRefusal::ObjectStructure(Box::new(
                    fgit_git_object::ObjectError::ObjectTooLarge {
                        limit: parse_limits.max_object_bytes,
                    },
                )));
            }
            control.checkpoint()?;
            kinds.insert(identity, object.object_type);
            objects.insert(identity, retain(identity, object)?);
            continue;
        }
        let parsed = parse_object_body(
            object.object_type,
            &object.body,
            AcceptanceProfile::GitCompatibleImport,
            parse_limits,
        )
        .map_err(|error| LooseGitImportRefusal::ObjectStructure(Box::new(error)))?;
        control.checkpoint()?;
        // Retain the established import refusal vocabulary for these cases.
        match &parsed {
            ParsedObject::Commit(commit) if commit.tree_reference().is_none() => {
                return Err(LooseGitImportRefusal::CommitTreeMissing(identity));
            }
            ParsedObject::Tag(tag)
                if tag.headers().iter().filter(|h| h.name == b"object").count() != 1 =>
            {
                return Err(LooseGitImportRefusal::TagObjectMissing(identity));
            }
            _ => {}
        }
        let edges = references(
            format,
            &parsed,
            &object.body,
            parse_limits,
            &mut edges_left,
            &mut || control.is_live(),
        );
        let edges = control.after(edges, |code| LooseGitImportRefusal::ObjectGraph {
            identity,
            code,
        })?;
        // Discard parsed copies before retaining the exact original body.
        drop(parsed);
        kinds.insert(identity, object.object_type);
        objects.insert(identity, retain(identity, object)?);
        for (child, kind) in edges {
            control.checkpoint()?;
            // Even a previously read root or child must satisfy this new edge.
            // In particular, a root's unconstrained kind cannot hide a later
            // commit/tree/tag requirement.
            if let Some(known) = kinds.get(&child) {
                require_kind(child, kind, *known)?;
            }
            enqueue(
                child,
                Some(kind),
                format,
                limits.objects,
                &mut required,
                &mut pending,
            )?;
        }
    }
    control.checkpoint()?;
    Ok(ValidatedImport {
        objects,
        total_bytes,
    })
}

fn enqueue(
    id: GitOid,
    kind: Option<ObjectType>,
    format: GitHashAlgorithm,
    limit: usize,
    required: &mut BTreeMap<GitOid, Option<ObjectType>>,
    pending: &mut BTreeSet<GitOid>,
) -> Result<(), LooseGitImportRefusal> {
    if id.is_zero() || id.algorithm() != format {
        return Err(LooseGitImportRefusal::ObjectGraph {
            identity: id,
            code: RefusalCode::ObjectHeaderInvalid,
        });
    }
    if let Some(previous) = required.get_mut(&id) {
        if let (Some(first), Some(next)) = (*previous, kind) {
            require_kind(id, first, next)?;
        }
        if previous.is_none() {
            *previous = kind;
        }
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

fn require_kind(
    id: GitOid,
    expected: ObjectType,
    actual: ObjectType,
) -> Result<(), LooseGitImportRefusal> {
    if expected == actual {
        Ok(())
    } else {
        Err(LooseGitImportRefusal::ObjectGraph {
            identity: id,
            code: RefusalCode::EvidenceInvalid,
        })
    }
}

/// One shared native-edge vocabulary for local import and receive quarantine.
/// The original parser and typed annotated-tag view own all byte decoding.
/// A caller must supply the parsed view of the same native-verified `body`.
pub fn references(
    format: GitHashAlgorithm,
    parsed: &ParsedObject,
    body: &[u8],
    limits: &ParseLimits,
    edges_left: &mut usize,
    deadline: &mut impl Deadline,
) -> Result<Vec<(GitOid, ObjectType)>, RefusalCode> {
    let mut edges = Vec::new();
    checkpoint(deadline)?;
    match parsed {
        ParsedObject::Blob(_) => {}
        ParsedObject::Tree(entries) => {
            for entry in entries {
                checkpoint(deadline)?;
                charge_edge(edges_left)?;
                let mode = std::str::from_utf8(&entry.mode)
                    .ok()
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
                        entry
                            .object_id
                            .as_slice()
                            .try_into()
                            .map_err(|_| RefusalCode::ObjectHeaderInvalid)?,
                    )),
                    GitHashAlgorithm::Sha256 => GitOid::from(GitOidSha256::from_bytes(
                        entry
                            .object_id
                            .as_slice()
                            .try_into()
                            .map_err(|_| RefusalCode::ObjectHeaderInvalid)?,
                    )),
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
                } else {
                    continue;
                };
                if !header.continuations.is_empty() || trees > 1 {
                    return Err(RefusalCode::ObjectHeaderInvalid);
                }
                charge_edge(edges_left)?;
                let text = std::str::from_utf8(&header.value)
                    .map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                let id =
                    GitOid::from_hex(format, text).map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                push(&mut edges, id, kind)?;
            }
            if trees != 1 {
                return Err(RefusalCode::ObjectHeaderInvalid);
            }
        }
        ParsedObject::Tag(_) => {
            let tag =
                parse_annotated_tag(body, format, AcceptanceProfile::GitCompatibleImport, limits)
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
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(RefusalCode::CancellationInProgress)
    }
}
fn charge_edge(remaining: &mut usize) -> Result<(), RefusalCode> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or(RefusalCode::ResourceBudgetExceeded)?;
    Ok(())
}
fn push(
    edges: &mut Vec<(GitOid, ObjectType)>,
    id: GitOid,
    kind: ObjectType,
) -> Result<(), RefusalCode> {
    if id.is_zero() {
        return Err(RefusalCode::ObjectHeaderInvalid);
    }
    edges
        .try_reserve(1)
        .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
    edges.push((id, kind));
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod byte_budget_tests;
