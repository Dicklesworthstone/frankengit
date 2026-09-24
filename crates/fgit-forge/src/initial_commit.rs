//! Root-commit construction from an exact creation-only patch. No repository
//! reads, synthetic parent, mutable checkout, or publication authority.

use crate::patch::{FileChange, IndexExpectation, PatchError, PatchLimits, UnifiedPatch};
use crate::preparation::{MergeMetadata, PlannedMergeObject, PreparationError};
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::BTreeMap;

/// An additional hard ceiling on the complete native closure, including trees.
pub const MAX_INITIAL_OBJECTS: usize = 32_768;

#[derive(Debug)]
pub enum InitialCommitError {
    Patch(PatchError),
    Metadata(PreparationError),
    CreationRequired,
    IndexMismatch,
    Budget(&'static str),
    InvalidTree,
    IdentityCollision,
}
impl std::fmt::Display for InitialCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "initial commit refused: {self:?}")
    }
}
impl std::error::Error for InitialCommitError {}
impl From<PatchError> for InitialCommitError {
    fn from(error: PatchError) -> Self {
        Self::Patch(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialFile {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub mode: u32,
    pub bytes: usize,
}

/// A complete immutable object plan. Its commit has exactly zero parents.
/// Fields are inspection data, not proof authorizing any repository change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitialCommitPlan {
    pub object_format: GitHashAlgorithm,
    pub commit: GitOid,
    pub tree: GitOid,
    pub patch_sha256: [u8; 32],
    pub files: Vec<InitialFile>,
    pub objects: Vec<PlannedMergeObject>,
}

fn checkpoint(cancelled: &dyn Fn() -> bool) -> Result<(), InitialCommitError> {
    if cancelled() {
        Err(PatchError::Cancelled.into())
    } else {
        Ok(())
    }
}

struct Objects {
    format: GitHashAlgorithm,
    remaining: usize,
    by_id: BTreeMap<GitOid, PlannedMergeObject>,
}
impl Objects {
    fn emit(&mut self, kind: GitObjectKind, body: Vec<u8>) -> Result<GitOid, InitialCommitError> {
        let id = git_object_id(self.format, kind, &body);
        if let Some(existing) = self.by_id.get(&id) {
            if existing.kind != kind || existing.body != body {
                return Err(InitialCommitError::IdentityCollision);
            }
            return Ok(id);
        }
        if self.by_id.len() == MAX_INITIAL_OBJECTS {
            return Err(InitialCommitError::Budget("objects"));
        }
        self.remaining = self
            .remaining
            .checked_sub(body.len())
            .ok_or(InitialCommitError::Budget("complete object bytes"))?;
        self.by_id.insert(id, PlannedMergeObject { id, kind, body });
        Ok(id)
    }
}

#[derive(Debug)]
struct Entry {
    name: Vec<u8>,
    mode: u32,
    id: GitOid,
}

/// Construct all blobs, trees and one root commit using exact creation hunks.
/// Supplied blob-index prefixes are checked in the selected native hash domain.
/// Tree entry ordering is Git's virtual-slash order, not ordinary path order.
/// File receipts and objects are sorted independently of patch section order.
///
/// The patch output limit also bounds the sum of unique native object bodies,
/// including every directory and the commit. Duplicate contents share objects.
/// Deletion/modification, empty patch input, unsafe paths, conflicting path
/// prefixes, unsupported modes, and cancellation never yield a partial plan.
pub fn prepare_initial_commit(
    format: GitHashAlgorithm,
    patch_bytes: &[u8],
    metadata: &MergeMetadata,
    limits: PatchLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<InitialCommitPlan, InitialCommitError> {
    prepare(
        format,
        patch_bytes,
        metadata,
        limits,
        cancelled,
        false,
        |_, _, _| {
            Err(PatchError::Unsupported {
                line: 1,
                feature: "native binary decoder required",
            })
        },
    )
}

/// Opt into compressed creation records without adding a decoder dependency to
/// the forge. The caller MUST use a native, bounded decoder that verifies the
/// full index identities and every supplied reverse image, with one shared
/// allowance for all binary files. The callback is never used for literal hunks.
///
/// All records are checked as creations in the selected hash domain before the
/// first callback. Returned bytes still pass the ordinary exact blob-identity,
/// aggregate output, complete closure and zero-parent commit checks. Neither
/// this function nor its callback receives repository publication authority.
pub fn prepare_initial_commit_with_binary_decoder(
    format: GitHashAlgorithm,
    patch_bytes: &[u8],
    metadata: &MergeMetadata,
    limits: PatchLimits,
    cancelled: &dyn Fn() -> bool,
    decoder: impl FnMut(&[u8], &IndexExpectation, &[u8]) -> Result<Vec<u8>, PatchError>,
) -> Result<InitialCommitPlan, InitialCommitError> {
    prepare(
        format,
        patch_bytes,
        metadata,
        limits,
        cancelled,
        true,
        decoder,
    )
}

fn prepare(
    format: GitHashAlgorithm,
    patch_bytes: &[u8],
    metadata: &MergeMetadata,
    limits: PatchLimits,
    cancelled: &dyn Fn() -> bool,
    binary: bool,
    mut decoder: impl FnMut(&[u8], &IndexExpectation, &[u8]) -> Result<Vec<u8>, PatchError>,
) -> Result<InitialCommitPlan, InitialCommitError> {
    checkpoint(cancelled)?;
    limits.validate()?;
    metadata.validate().map_err(InitialCommitError::Metadata)?;
    let patch = if binary {
        UnifiedPatch::parse_with_binary(patch_bytes, limits, cancelled)?
    } else {
        UnifiedPatch::parse(patch_bytes, limits, cancelled)?
    };
    if binary {
        // Refuse a late modification/deletion or foreign-width index before any
        // earlier record can spend the caller's decompression allowance.
        for file in patch.files() {
            checkpoint(cancelled)?;
            if file.change() != FileChange::Create || file.renamed_from().is_some() {
                return Err(InitialCommitError::CreationRequired);
            }
            fgit_treefs::TreePath::parse_default(file.path())
                .map_err(|_| PatchError::InvalidPath)?;
            if file.binary_hunks().is_some() {
                let index = file.index().ok_or(InitialCommitError::IndexMismatch)?;
                if index.old.len() != format.digest_len() * 2
                    || index.new.len() != format.digest_len() * 2
                    || !IndexExpectation::matches(&index.old, None)
                    || index.new.iter().all(|byte| *byte == b'0')
                {
                    return Err(InitialCommitError::IndexMismatch);
                }
            }
        }
    }
    let mut objects = Objects {
        format,
        remaining: limits.max_output_bytes,
        by_id: BTreeMap::new(),
    };
    let mut directories: BTreeMap<Vec<u8>, Vec<Entry>> = BTreeMap::from([(Vec::new(), Vec::new())]);
    let mut files = Vec::with_capacity(patch.files().len());
    let mut expanded_files = 0usize;
    for file in patch.files() {
        checkpoint(cancelled)?;
        if file.change() != FileChange::Create {
            return Err(InitialCommitError::CreationRequired);
        }
        fgit_treefs::TreePath::parse_default(file.path()).map_err(|_| PatchError::InvalidPath)?;
        let result = file
            .apply_with_binary_decoder(None, limits, cancelled, |bytes, index, base| {
                decoder(bytes, index, base)
            })?
            .ok_or(InitialCommitError::CreationRequired)?;
        expanded_files = expanded_files
            .checked_add(result.content.len())
            .filter(|n| *n <= limits.max_output_bytes)
            .ok_or(InitialCommitError::Budget("expanded file bytes"))?;
        let size = result.content.len();
        let blob = objects.emit(GitObjectKind::Blob, result.content)?;
        if let Some(index) = file.index()
            && (index.old.len() > format.digest_len() * 2
                || !IndexExpectation::matches(&index.old, None)
                || !IndexExpectation::matches(&index.new, Some(blob.to_string().as_bytes())))
        {
            return Err(InitialCommitError::IndexMismatch);
        }
        let parts: Vec<_> = file.path().split(|b| *b == b'/').collect();
        let mut directory = Vec::new();
        for part in &parts[..parts.len() - 1] {
            checkpoint(cancelled)?;
            if !directory.is_empty() {
                directory.push(b'/');
            }
            directory.extend_from_slice(part);
            if !directories.contains_key(&directory) {
                if directories.len() == MAX_INITIAL_OBJECTS {
                    return Err(InitialCommitError::Budget("directories"));
                }
                directories.insert(directory.clone(), Vec::new());
            }
        }
        directories
            .get_mut(&directory)
            .ok_or(InitialCommitError::InvalidTree)?
            .push(Entry {
                name: parts
                    .last()
                    .ok_or(InitialCommitError::InvalidTree)?
                    .to_vec(),
                mode: result.mode,
                id: blob,
            });
        files.push(InitialFile {
            path: file.path().to_vec(),
            blob,
            mode: result.mode,
            bytes: size,
        });
    }
    // A descendant sorts after its strict prefix; reverse byte order therefore
    // emits every child before its parent without recursion or synthetic roots.
    let mut root = None;
    while let Some((path, mut entries)) = directories.pop_last() {
        checkpoint(cancelled)?;
        entries.sort_by(|a, b| {
            a.name
                .iter()
                .copied()
                .chain(std::iter::once(if a.mode == 0o40000 { b'/' } else { 0 }))
                .cmp(
                    b.name
                        .iter()
                        .copied()
                        .chain(std::iter::once(if b.mode == 0o40000 { b'/' } else { 0 })),
                )
        });
        let mut body = Vec::new();
        for entry in entries {
            checkpoint(cancelled)?;
            let header = format!("{:o} ", entry.mode);
            let extra = header
                .len()
                .checked_add(entry.name.len())
                .and_then(|n| n.checked_add(1 + format.digest_len()))
                .ok_or(InitialCommitError::Budget("tree bytes"))?;
            if extra > limits.max_output_bytes.saturating_sub(body.len()) {
                return Err(InitialCommitError::Budget("tree bytes"));
            }
            body.extend_from_slice(header.as_bytes());
            body.extend_from_slice(&entry.name);
            body.push(0);
            body.extend_from_slice(entry.id.as_bytes());
        }
        let id = objects.emit(GitObjectKind::Tree, body)?;
        if path.is_empty() {
            root = Some(id);
            break;
        }
        let split = path.iter().rposition(|b| *b == b'/');
        let (parent, name) = split.map_or((&b""[..], path.as_slice()), |at| {
            (&path[..at], &path[at + 1..])
        });
        directories
            .get_mut(parent)
            .ok_or(InitialCommitError::InvalidTree)?
            .push(Entry {
                name: name.to_vec(),
                mode: 0o40000,
                id,
            });
    }
    let tree = root.ok_or(InitialCommitError::InvalidTree)?;
    let mut body = format!(
        "tree {tree}\nauthor {} {} +0000\ncommitter {} {} +0000\n\n",
        metadata.author, metadata.timestamp, metadata.committer, metadata.timestamp
    )
    .into_bytes();
    if body
        .len()
        .checked_add(metadata.message.len())
        .is_none_or(|n| n > objects.remaining)
    {
        return Err(InitialCommitError::Budget("commit bytes"));
    }
    body.extend_from_slice(&metadata.message);
    let commit = objects.emit(GitObjectKind::Commit, body)?;
    checkpoint(cancelled)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let patch_sha256 = sha256_digest(patch_bytes);
    checkpoint(cancelled)?;
    Ok(InitialCommitPlan {
        object_format: format,
        commit,
        tree,
        patch_sha256,
        files,
        objects: objects.by_id.into_values().collect(),
    })
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod binary_tests;
