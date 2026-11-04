//! Native target-to-candidate path facts. Caller-supplied object edges, patch
//! summaries and source-side diffs cannot construct this witness.

use std::collections::BTreeMap;

use fgit_forge::event::NativeMerge;
use fgit_git_object::{AcceptanceProfile, ObjectError, ObjectType, ParseLimits, ParsedObject};
use fgit_pack::{CanonicalObjectSource, PackError, PackWriteError, verify_native_object};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

use super::{
    MAX_MERGE_CHANGED_PATH_BYTES, MAX_MERGE_CHANGED_PATHS, MAX_MERGE_PATH_BYTES,
    MAX_MERGE_PATH_DEPTH, VerifiedMergePaths,
};
use crate::ProjectionFailure;
use crate::merge::native::objects::{MAX_REUSED_BLOB_BYTES, MergeObjectLimits};

/// Compare the actual target-before and candidate commit trees. Every loaded
/// commit/tree is independently hashed; identical subtree identities require
/// no body read. This proves path facts only: the caller still validates merge
/// ancestry, candidate closure, selected refs and source authorization.
///
/// Changed leaves include mode-only and gitlink changes. Directory additions,
/// removals and type/mode changes include the directory and every affected
/// descendant; a directory's changed tree OID alone is not a changed path.
/// Names remain raw bytes. Ambiguous imported names/duplicate entries refuse.
/// No partial witness escapes cancellation, missing objects or any limit.
pub fn verify_merge_paths(
    source: &impl CanonicalObjectSource,
    merge: &NativeMerge,
    limits: MergeObjectLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<VerifiedMergePaths, ProjectionFailure> {
    checkpoint(live)?;
    merge.validate().map_err(|_| invalid())?;
    validate_limits(limits)?;
    let mut walk = Walk {
        source,
        live,
        format: merge.merge_commit.algorithm(),
        limits,
        objects: 0,
        bytes: 0,
        entries: 0,
        changed_bytes: 0,
        changed: Vec::new(),
        pending: Vec::new(),
        pending_bytes: 0,
    };
    let before = walk.commit_tree(merge.target_tip_before)?;
    let after = walk.commit_tree(merge.merge_commit)?;
    walk.pending.push(Trees {
        path: Vec::new(),
        depth: 0,
        before: Some(before),
        after: Some(after),
    });
    while let Some(trees) = walk.pending.pop() {
        walk.pending_bytes -= trees.path.len();
        checkpoint(walk.live)?;
        if trees.before == trees.after {
            continue;
        }
        let before = walk.tree(trees.before)?;
        let mut after = walk.tree(trees.after)?;
        for (name, old) in before {
            checkpoint(walk.live)?;
            let new = after.remove(&name);
            walk.entry(&trees, &name, Some(old), new)?;
        }
        for (name, new) in after {
            checkpoint(walk.live)?;
            walk.entry(&trees, &name, None, Some(new))?;
        }
    }
    checkpoint(walk.live)?;
    walk.changed.sort_unstable();
    checkpoint(walk.live)?;
    Ok(VerifiedMergePaths {
        merge: merge.clone(),
        changed_paths: walk.changed,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    mode: u32,
    id: GitOid,
}
impl Entry {
    fn tree(self) -> Option<GitOid> {
        (self.mode & 0o170_000 == 0o040_000).then_some(self.id)
    }
}

struct Trees {
    path: Vec<u8>,
    depth: usize,
    before: Option<GitOid>,
    after: Option<GitOid>,
}

struct Walk<'a, S, L> {
    source: &'a S,
    live: &'a mut L,
    format: GitHashAlgorithm,
    limits: MergeObjectLimits,
    objects: usize,
    bytes: usize,
    entries: usize,
    changed_bytes: usize,
    changed: Vec<Vec<u8>>,
    pending: Vec<Trees>,
    pending_bytes: usize,
}

impl<S: CanonicalObjectSource, L: FnMut() -> bool> Walk<'_, S, L> {
    fn read(&mut self, id: GitOid, kind: ObjectType) -> Result<ParsedObject, ProjectionFailure> {
        checkpoint(self.live)?;
        self.objects = self
            .objects
            .checked_add(1)
            .filter(|count| *count <= self.limits.max_objects)
            .ok_or_else(budget)?;
        let object = self.source.load(&id).map_err(source_failure)?;
        checkpoint(self.live)?;
        if object.id() != id || object.object_type() != kind || id.algorithm() != self.format {
            return Err(invalid());
        }
        if object.body().len() > self.limits.max_object_bytes {
            return Err(budget());
        }
        self.bytes = self
            .bytes
            .checked_add(object.body().len())
            .filter(|bytes| *bytes <= self.limits.max_total_bytes)
            .ok_or_else(budget)?;
        let parsed = verify_native_object(
            self.format,
            kind,
            object.body(),
            &id,
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits {
                max_object_bytes: self.limits.max_object_bytes,
                max_tree_entries: self.limits.max_edges - self.entries,
                tree_reference_bytes: self.format.digest_len(),
                ..ParseLimits::default()
            },
        )
        .map_err(native_failure)?;
        checkpoint(self.live)?;
        Ok(parsed)
    }

    fn commit_tree(&mut self, id: GitOid) -> Result<GitOid, ProjectionFailure> {
        let ParsedObject::Commit(commit) = self.read(id, ObjectType::Commit)? else {
            return Err(invalid());
        };
        if commit
            .headers()
            .iter()
            .filter(|header| header.name == b"tree")
            .count()
            != 1
            || commit
                .headers()
                .iter()
                .any(|header| header.name == b"tree" && !header.continuations.is_empty())
        {
            return Err(invalid());
        }
        let tree = std::str::from_utf8(commit.tree_reference().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
        let tree =
            GitOid::from_hex(self.format, &tree.to_ascii_lowercase()).map_err(|_| invalid())?;
        if tree.is_zero() {
            return Err(invalid());
        }
        Ok(tree)
    }

    fn tree(&mut self, id: Option<GitOid>) -> Result<BTreeMap<Vec<u8>, Entry>, ProjectionFailure> {
        let mut result = BTreeMap::new();
        let Some(id) = id else {
            return Ok(result);
        };
        let ParsedObject::Tree(entries) = self.read(id, ObjectType::Tree)? else {
            return Err(invalid());
        };
        for entry in entries {
            checkpoint(self.live)?;
            // Count every parsed entry, including equal entries and gitlinks.
            self.entries = self
                .entries
                .checked_add(1)
                .filter(|count| *count <= self.limits.max_edges)
                .ok_or_else(budget)?;
            if entry.name.is_empty()
                || entry.name == b"."
                || entry.name == b".."
                || entry.name.contains(&b'/')
            {
                return Err(invalid());
            }
            if entry.name.len() > MAX_MERGE_PATH_BYTES {
                return Err(budget());
            }
            let mode = std::str::from_utf8(&entry.mode)
                .ok()
                .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                .ok_or_else(invalid)?;
            if !matches!(
                mode & 0o170_000,
                0o040_000 | 0o100_000 | 0o120_000 | 0o160_000
            ) {
                return Err(invalid());
            }
            let mut hex = String::new();
            hex.try_reserve(self.format.digest_len() * 2)
                .map_err(|_| budget())?;
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in entry.object_id {
                hex.push(char::from(HEX[usize::from(byte >> 4)]));
                hex.push(char::from(HEX[usize::from(byte & 15)]));
            }
            let id = GitOid::from_hex(self.format, &hex).map_err(|_| invalid())?;
            if id.is_zero() || result.insert(entry.name, Entry { mode, id }).is_some() {
                return Err(invalid());
            }
        }
        Ok(result)
    }

    fn entry(
        &mut self,
        trees: &Trees,
        name: &[u8],
        before: Option<Entry>,
        after: Option<Entry>,
    ) -> Result<(), ProjectionFailure> {
        if before == after {
            return Ok(());
        }
        let depth = trees
            .depth
            .checked_add(1)
            .filter(|n| *n <= MAX_MERGE_PATH_DEPTH)
            .ok_or_else(budget)?;
        let length = trees
            .path
            .len()
            .checked_add(usize::from(!trees.path.is_empty()))
            .and_then(|n| n.checked_add(name.len()))
            .filter(|n| *n <= MAX_MERGE_PATH_BYTES)
            .ok_or_else(budget)?;
        let mut path = Vec::new();
        path.try_reserve_exact(length).map_err(|_| budget())?;
        path.extend_from_slice(&trees.path);
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name);
        let old_tree = before.and_then(Entry::tree);
        let new_tree = after.and_then(Entry::tree);
        let only_subtree_identity = old_tree.is_some()
            && new_tree.is_some()
            && before.map(|entry| entry.mode) == after.map(|entry| entry.mode);
        if !only_subtree_identity {
            if self.changed.len() == MAX_MERGE_CHANGED_PATHS {
                return Err(budget());
            }
            self.changed_bytes = self
                .changed_bytes
                .checked_add(path.len())
                .filter(|n| *n <= MAX_MERGE_CHANGED_PATH_BYTES)
                .ok_or_else(budget)?;
            self.changed.try_reserve(1).map_err(|_| budget())?;
            self.changed.push(path.clone());
        }
        if old_tree != new_tree {
            // Either side may be a removed/replaced directory. Descend both,
            // even when its parent entry already matches an exact rule.
            if self.pending.len() == MAX_MERGE_CHANGED_PATHS {
                return Err(budget());
            }
            self.pending_bytes = self
                .pending_bytes
                .checked_add(path.len())
                .filter(|n| *n <= MAX_MERGE_CHANGED_PATH_BYTES)
                .ok_or_else(budget)?;
            self.pending.try_reserve(1).map_err(|_| budget())?;
            self.pending.push(Trees {
                path,
                depth,
                before: old_tree,
                after: new_tree,
            });
        }
        Ok(())
    }
}

fn validate_limits(limits: MergeObjectLimits) -> Result<(), ProjectionFailure> {
    let maximum = MergeObjectLimits::default();
    if limits.max_objects == 0
        || limits.max_objects > maximum.max_objects
        || limits.max_edges == 0
        || limits.max_edges > maximum.max_edges
        || limits.max_object_bytes == 0
        || limits.max_object_bytes > maximum.max_object_bytes
        || limits.max_total_bytes == 0
        || limits.max_total_bytes > maximum.max_total_bytes
        || limits.max_reused_blob_bytes == 0
        || u64::try_from(limits.max_reused_blob_bytes).unwrap_or(u64::MAX) > MAX_REUSED_BLOB_BYTES
    {
        return Err(budget());
    }
    Ok(())
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ProjectionFailure> {
    if live() {
        Ok(())
    } else {
        Err(ProjectionFailure::Unavailable(
            RefusalCode::CancellationInProgress,
        ))
    }
}
const fn invalid() -> ProjectionFailure {
    ProjectionFailure::Refuse(RefusalCode::EvidenceInvalid)
}
const fn budget() -> ProjectionFailure {
    ProjectionFailure::Unavailable(RefusalCode::ResourceBudgetExceeded)
}
const fn native_failure(error: PackError) -> ProjectionFailure {
    match error {
        PackError::ObjectParse(
            ObjectError::ObjectTooLarge { .. }
            | ObjectError::TooManyTreeEntries { .. }
            | ObjectError::HeaderLimitExceeded { .. }
            | ObjectError::AllocationFailure,
        ) => budget(),
        _ => invalid(),
    }
}
const fn source_failure(error: PackWriteError) -> ProjectionFailure {
    match error {
        PackWriteError::Pack(PackError::DeadlineExceeded) => {
            ProjectionFailure::Unavailable(RefusalCode::CancellationInProgress)
        }
        PackWriteError::Pack(
            PackError::ObjectSizeLimit { .. } | PackError::AllocationFailed { .. },
        ) => budget(),
        _ => ProjectionFailure::Unavailable(RefusalCode::EvidenceMissing),
    }
}
