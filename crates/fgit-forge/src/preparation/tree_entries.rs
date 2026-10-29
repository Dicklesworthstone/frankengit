//! Request-owned immutable directory metadata and a borrowed three-way join.
//!
//! These values are neither an object source nor disclosure authority. Only
//! checked source results and the planner's own generated trees enter the cache.
//! Every visit still spends the planner's original tree-entry allowance.

use super::{GitHashAlgorithm, MergeEntry, MergeSourceError, PreparationError};
use std::collections::{BTreeMap, btree_map};
use std::iter::Peekable;
use std::sync::Arc;

pub(super) type Tree = Arc<BTreeMap<Vec<u8>, MergeEntry>>;

// Original-source caching is optional and deterministic. These ceilings bound
// retained copies independently of source-object bytes. Generated trees retain
// their existing object/output limits and are never evicted: later rebase steps
// must read them without asking a source that intentionally has no such object.
pub(super) const MAX_CACHED_SOURCE_TREES: usize = 128;
pub(super) const MAX_CACHED_SOURCE_ENTRIES: usize = 4096;
pub(super) const MAX_CACHED_SOURCE_NAME_BYTES: usize = 32 * 1024;

pub(super) fn checked(
    entries: Vec<MergeEntry>,
    format: GitHashAlgorithm,
    max_path_bytes: usize,
    mut live: impl FnMut() -> Result<(), MergeSourceError>,
) -> Result<(Tree, usize), PreparationError> {
    live()?;
    let mut names = 0usize;
    let mut map = BTreeMap::new();
    for entry in entries {
        live()?;
        if entry.name.is_empty()
            || entry.name.len() > max_path_bytes
            || entry.name.contains(&0)
            || entry.name.contains(&b'/')
            || entry.name == b"."
            || entry.name == b".."
            || entry.name.eq_ignore_ascii_case(b".git")
            || !matches!(entry.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000)
            || entry.oid.is_zero()
            || entry.oid.algorithm() != format
        {
            return Err(PreparationError::InvalidTree);
        }
        names = names.checked_add(entry.name.len())
            .ok_or(PreparationError::Budget("tree name bytes"))?;
        if map.insert(entry.name.clone(), entry).is_some() {
            return Err(PreparationError::InvalidTree);
        }
    }
    live()?;
    Ok((Arc::new(map), names))
}

/// A clean retained entry or deletion, or a request for the full merge path.
pub(super) enum Trivial<'a> {
    Entry(&'a MergeEntry),
    Delete,
    Nontrivial,
}

/// Resolve identity/equal-side cases without creating a full path.
/// Callers must still validate the full path length before taking this shortcut.
pub(super) fn trivial<'a>(
    base: Option<&'a MergeEntry>,
    ours: Option<&'a MergeEntry>,
    theirs: Option<&'a MergeEntry>,
) -> Trivial<'a> {
    let entry = if ours == theirs || base == theirs {
        ours
    } else if base == ours {
        theirs
    } else {
        return Trivial::Nontrivial;
    };
    match entry {
        Some(entry) => Trivial::Entry(entry),
        None => Trivial::Delete,
    }
}

type Entries<'a> = Peekable<btree_map::Values<'a, Vec<u8>, MergeEntry>>;

/// Sorted union in raw-name order with O(1) auxiliary state, no copied name
/// set, and no repeated map lookup. Native Git serialization order is separate.
pub(super) struct Join<'a> {
    inputs: [Entries<'a>; 3],
}
impl<'a> Join<'a> {
    pub(super) fn new(
        base: &'a BTreeMap<Vec<u8>, MergeEntry>,
        ours: &'a BTreeMap<Vec<u8>, MergeEntry>,
        theirs: &'a BTreeMap<Vec<u8>, MergeEntry>,
    ) -> Self {
        Self { inputs: [base.values().peekable(), ours.values().peekable(), theirs.values().peekable()] }
    }
}
impl<'a> Iterator for Join<'a> {
    type Item = (&'a [u8], [Option<&'a MergeEntry>; 3]);

    fn next(&mut self) -> Option<Self::Item> {
        let heads: [Option<&'a MergeEntry>; 3] = [
            self.inputs[0].peek().copied(),
            self.inputs[1].peek().copied(),
            self.inputs[2].peek().copied(),
        ];
        let name: &'a [u8] = heads.into_iter().flatten().map(|entry| entry.name.as_slice()).min()?;
        let mut values = [None; 3];
        for (index, head) in heads.iter().enumerate() {
            if head.is_some_and(|entry| entry.name.as_slice() == name) {
                values[index] = self.inputs[index].next();
            }
        }
        Some((name, values))
    }
}
