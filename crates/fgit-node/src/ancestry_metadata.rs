//! Bounded reuse of native commit metadata, never an ancestry authority.
//!
//! Only verified Git-compatible commit bytes construct an entry. A consumer
//! must select its own authenticated closure before each lookup and charge the
//! original logical object/parser budgets even when no body read is needed.
//! The cache retains tree/parent identities and an ordering hint, not messages,
//! signatures, complete bodies, query answers, or a repository selection.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fgit_crypto::git_object_id;
use fgit_forge::preparation::{CommitInput, MergeSourceError};
use fgit_git_object::{
    AcceptanceProfile, ObjectError, ObjectType, ParseLimits, ParsedObject, parse_object_body,
};
use fgit_types::{GitHashAlgorithm, GitOid, RepositoryId, RepositoryIncarnationId, TenantId};

use crate::OneNode;
use crate::upload_visibility::shallow::cutoffs::committer_time;

// Conservative room for each entry in both B-trees and allocator bookkeeping.
// The scope additionally reserves both partially occupied root allocations,
// including for a one-entry cache. Parent capacity is charged separately.
const ENTRY_OVERHEAD: usize = 1024;
const SCOPE_OVERHEAD: usize = 4096;
const MAX_ENTRIES: usize = 32_768;

#[derive(Clone, Copy)]
struct Scope<'a> {
    store_root: &'a Path,
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    format: GitHashAlgorithm,
}

#[derive(Debug)]
struct OwnedScope {
    store_root: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    incarnation: RepositoryIncarnationId,
    format: GitHashAlgorithm,
}

impl OwnedScope {
    fn matches(&self, other: Scope<'_>) -> bool {
        self.store_root == other.store_root
            && self.tenant == other.tenant
            && self.repository == other.repository
            && self.incarnation == other.incarnation
            && self.format == other.format
    }

    fn from_scope(scope: Scope<'_>) -> Self {
        Self {
            store_root: scope.store_root.to_path_buf(),
            tenant: scope.tenant,
            repository: scope.repository,
            incarnation: scope.incarnation,
            format: scope.format,
        }
    }

    fn retained_bytes(&self) -> Option<usize> {
        SCOPE_OVERHEAD.checked_add(self.store_root.capacity())
    }
}

/// An immutable certificate of one complete native parse. Fields stay private:
/// parsed adjacency cannot be substituted by an unverified caller.
#[derive(Debug)]
pub struct VerifiedCommitMetadata {
    id: GitOid,
    tree: GitOid,
    parents: Vec<GitOid>,
    date: Option<i64>,
    body_bytes: usize,
    header_lines: usize,
    maximum_header_line_bytes: usize,
}

impl VerifiedCommitMetadata {
    pub(crate) fn parse(
        id: GitOid,
        body: &[u8],
        limits: &ParseLimits,
    ) -> Result<Self, MergeSourceError> {
        if id.is_zero() || git_object_id(id.algorithm(), ObjectType::Commit, body) != id {
            return Err(MergeSourceError::InvalidObject(id));
        }
        let parsed = parse_object_body(
            ObjectType::Commit,
            body,
            AcceptanceProfile::GitCompatibleImport,
            limits,
        )
        .map_err(|error| parse_error(id, error))?;
        // The date orders exploration only; it never proves ancestry.
        let date = committer_time(&parsed);
        let ParsedObject::Commit(commit) = parsed else {
            return Err(MergeSourceError::InvalidObject(id));
        };
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
            return Err(MergeSourceError::InvalidObject(id));
        }
        let oid = |value: &[u8]| {
            let text =
                std::str::from_utf8(value).map_err(|_| MergeSourceError::InvalidObject(id))?;
            GitOid::from_hex(id.algorithm(), &text.to_ascii_lowercase())
                .map_err(|_| MergeSourceError::InvalidObject(id))
        };
        let tree = oid(commit
            .tree_reference()
            .ok_or(MergeSourceError::InvalidObject(id))?)?;
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(commit.parent_references().count())
            .map_err(|_| MergeSourceError::BudgetExceeded)?;
        for parent in commit.parent_references() {
            parents.push(oid(parent)?);
        }
        let mut header_lines = 0usize;
        let mut maximum_header_line_bytes = 0usize;
        for header in commit.headers() {
            header_lines += 1 + header.continuations.len();
            maximum_header_line_bytes =
                maximum_header_line_bytes.max(header.name.len() + 1 + header.value.len());
            for continuation in &header.continuations {
                maximum_header_line_bytes = maximum_header_line_bytes.max(1 + continuation.len());
            }
        }
        Ok(Self {
            id,
            tree,
            parents,
            date,
            body_bytes: body.len(),
            header_lines,
            maximum_header_line_bytes,
        })
    }

    pub(crate) const fn body_bytes(&self) -> usize {
        self.body_bytes
    }

    pub(crate) fn into_commit(self) -> (CommitInput, Option<i64>) {
        (
            CommitInput {
                tree: self.tree,
                parents: self.parents,
            },
            self.date,
        )
    }

    const fn fits(&self, limits: &ParseLimits, object_limit: usize) -> bool {
        self.body_bytes <= object_limit
            && self.body_bytes <= limits.max_object_bytes
            && self.header_lines <= limits.max_header_lines
            && self.maximum_header_line_bytes <= limits.max_header_line_bytes
    }

    fn try_copy(&self) -> Result<Self, MergeSourceError> {
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(self.parents.len())
            .map_err(|_| MergeSourceError::BudgetExceeded)?;
        parents.extend_from_slice(&self.parents);
        Ok(Self {
            id: self.id,
            tree: self.tree,
            parents,
            date: self.date,
            body_bytes: self.body_bytes,
            header_lines: self.header_lines,
            maximum_header_line_bytes: self.maximum_header_line_bytes,
        })
    }

    fn retained_bytes(&self) -> Option<usize> {
        self.parents
            .capacity()
            .checked_mul(std::mem::size_of::<GitOid>())
            .and_then(|bytes| bytes.checked_add(ENTRY_OVERHEAD))
    }
}

const fn parse_error(id: GitOid, error: ObjectError) -> MergeSourceError {
    match error {
        ObjectError::ObjectTooLarge { .. }
        | ObjectError::TooManyTreeEntries { .. }
        | ObjectError::HeaderLimitExceeded { .. }
        | ObjectError::AllocationFailure => MergeSourceError::BudgetExceeded,
        _ => MergeSourceError::InvalidObject(id),
    }
}

#[derive(Debug, Default)]
struct State {
    scope: Option<OwnedScope>,
    entries: BTreeMap<GitOid, (u64, VerifiedCommitMetadata)>,
    order: BTreeMap<u64, GitOid>,
    retained_bytes: usize,
    sequence: u64,
}

/// Disposable FIFO metadata shared by independently reopened service children.
/// Lock contention/poison, a disabled cache and scope mismatch all mean a miss.
/// Neither a cache read nor insertion performs I/O or chooses repository state.
#[derive(Debug)]
pub struct AncestryMetadataCache {
    max_bytes: usize,
    state: Mutex<State>,
    #[cfg(test)]
    body_reads: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    hits: std::sync::atomic::AtomicUsize,
}

impl AncestryMetadataCache {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            state: Mutex::new(State::default()),
            #[cfg(test)]
            body_reads: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            hits: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) const fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    fn lookup(
        &self,
        scope: Scope<'_>,
        id: GitOid,
        limits: &ParseLimits,
        object_limit: usize,
    ) -> Option<Result<VerifiedCommitMetadata, MergeSourceError>> {
        if self.max_bytes == 0 || id.algorithm() != scope.format {
            return None;
        }
        let state = self.state.try_lock().ok()?;
        if !state.scope.as_ref()?.matches(scope) {
            return None;
        }
        let (_, entry) = state.entries.get(&id)?;
        if !entry.fits(limits, object_limit) {
            return Some(Err(MergeSourceError::BudgetExceeded));
        }
        let copied = entry.try_copy();
        #[cfg(test)]
        if copied.is_ok() {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Some(copied)
    }

    fn insert(&self, scope: Scope<'_>, entry: &VerifiedCommitMetadata) {
        if self.max_bytes == 0 || entry.id.algorithm() != scope.format {
            return;
        }
        let Some(minimum) = entry
            .retained_bytes()
            .and_then(|bytes| bytes.checked_add(SCOPE_OVERHEAD))
            .and_then(|bytes| bytes.checked_add(scope.store_root.as_os_str().len()))
        else {
            return;
        };
        if minimum > self.max_bytes {
            return;
        }
        let Ok(mut state) = self.state.try_lock() else {
            return;
        };
        let matches = state
            .scope
            .as_ref()
            .is_some_and(|stored| stored.matches(scope));
        if matches && state.entries.contains_key(&entry.id) {
            return;
        }
        let Ok(copy) = entry.try_copy() else {
            return;
        };
        let Some(charge) = copy.retained_bytes() else {
            return;
        };
        if !matches || state.sequence == u64::MAX {
            let owned = OwnedScope::from_scope(scope);
            let Some(scope_charge) = owned.retained_bytes() else {
                return;
            };
            if scope_charge
                .checked_add(charge)
                .is_none_or(|total| total > self.max_bytes)
            {
                return;
            }
            *state = State {
                scope: Some(owned),
                retained_bytes: scope_charge,
                ..State::default()
            };
        }
        while state.entries.len() >= MAX_ENTRIES
            || state
                .retained_bytes
                .checked_add(charge)
                .is_none_or(|total| total > self.max_bytes)
        {
            let Some((_, oldest)) = state.order.pop_first() else {
                return;
            };
            if let Some((_, removed)) = state.entries.remove(&oldest) {
                state.retained_bytes -= removed.retained_bytes().unwrap_or(0);
            }
        }
        let sequence = state.sequence;
        state.sequence += 1;
        state.retained_bytes += charge;
        state.order.insert(sequence, copy.id);
        state.entries.insert(copy.id, (sequence, copy));
    }

    #[cfg(test)]
    pub(crate) fn test_counts(&self) -> (usize, usize) {
        use std::sync::atomic::Ordering;
        (
            self.body_reads.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
        )
    }
}

/// Borrowed service scope plus cache; SelectedSource retains responsibility for
/// current membership, logical byte accounting and runtime checkpoints.
pub struct AncestryMetadataAccess<'a> {
    cache: &'a AncestryMetadataCache,
    scope: Scope<'a>,
}

impl<'a> AncestryMetadataAccess<'a> {
    pub(crate) fn for_node(node: &'a OneNode) -> Self {
        Self {
            cache: node.ancestry_metadata_cache(),
            scope: Scope {
                store_root: node.fabric.root(),
                tenant: node.tenant_id,
                repository: node.repository_id,
                incarnation: node.repository_incarnation_id,
                format: node.object_format,
            },
        }
    }

    pub(crate) fn lookup(
        &self,
        id: GitOid,
        limits: &ParseLimits,
        object_limit: usize,
    ) -> Option<Result<VerifiedCommitMetadata, MergeSourceError>> {
        self.cache.lookup(self.scope, id, limits, object_limit)
    }

    pub(crate) fn insert(&self, entry: &VerifiedCommitMetadata) {
        self.cache.insert(self.scope, entry);
    }

    #[cfg(test)]
    pub(crate) fn record_body_read(&self) {
        self.cache
            .body_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests;
