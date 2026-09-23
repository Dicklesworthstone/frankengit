//! Exact-identity rename alignment for the existing native path merge planner.
//!
//! Virtual trees are derived preparation objects with their own native IDs.
//! Original tree/commit IDs are never rebound to different bytes. Only objects
//! reachable from the final candidate escape; no virtual base is published.
//! This is not Git ort equivalence, similarity matching or directory inference.

use super::{
    GitObjectKind, GitOid, MergeEntry, MergeObjectSource, Planner,
    PreparationError, git_object_id,
};
use std::collections::{BTreeMap, BTreeSet};

/// Fixed additional ceilings for ExactRenamesV1. Existing caller limits may
/// narrow these further; they never authorize more reads, objects or output.
pub const MAX_RENAMES: usize = 1024;
pub const MAX_PATH_STORAGE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenameSide {
    Target,
    Source,
}

/// A refusal carries no partial tree or candidate. Paths are raw Git bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenameRefusal {
    AmbiguousIdentity { side: RenameSide, oid: GitOid },
    Divergent { from: Vec<u8>, target: Vec<u8>, source: Vec<u8> },
    RenameDelete { from: Vec<u8>, to: Vec<u8> },
    DestinationOccupied { path: Vec<u8> },
    UnsupportedEntry { path: Vec<u8> },
    AttributesRequireDriver { path: Vec<u8> },
}
impl From<RenameRefusal> for PreparationError {
    fn from(error: RenameRefusal) -> Self {
        Self::Rename(error)
    }
}

type Flat = BTreeMap<Vec<u8>, MergeEntry>;
type Moves = BTreeMap<Vec<u8>, Vec<u8>>;

struct PathBudget {
    used: usize,
    maximum: usize,
}
impl PathBudget {
    fn charge(&mut self, bytes: usize) -> Result<(), PreparationError> {
        self.used = self.used.checked_add(bytes)
            .filter(|count| *count <= self.maximum)
            .ok_or(PreparationError::Budget("rename path storage"))?;
        Ok(())
    }
}
fn regular(entry: &MergeEntry) -> bool {
    matches!(entry.mode, 0o100644 | 0o100755)
}
fn parent(path: &[u8]) -> &[u8] {
    path.iter().rposition(|b| *b == b'/').map_or(&[], |i| &path[..i])
}
fn basename(path: &[u8]) -> &[u8] {
    path.rsplit(|b| *b == b'/').next().unwrap_or(path)
}
fn charge_entry<S>(planner: &mut Planner<'_, S>) -> Result<(), PreparationError> {
    planner.entries = planner.entries.checked_add(1)
        .filter(|count| *count <= planner.limits.max_tree_entries)
        .ok_or(PreparationError::Budget("tree entries"))?;
    Ok(())
}

pub(super) fn merge<S: MergeObjectSource>(
    planner: &mut Planner<'_, S>, base: GitOid, ours: GitOid, theirs: GitOid,
) -> Result<Option<GitOid>, PreparationError> {
    // Trivial equality needs no inferred correspondence or extra inventory.
    if ours == theirs || base == ours || base == theirs {
        return planner.directory(Some(base), ours, theirs, &[], 0, false);
    }
    let mut budget = PathBudget {
        used: 0,
        maximum: MAX_PATH_STORAGE_BYTES.min(planner.limits.max_output_bytes),
    };
    let mut original_trees = BTreeSet::new();
    let mut b = Flat::new();
    let mut o = Flat::new();
    let mut t = Flat::new();
    flatten(planner, base, &[], 0, &mut b, &mut original_trees, &mut budget)?;
    flatten(planner, ours, &[], 0, &mut o, &mut original_trees, &mut budget)?;
    flatten(planner, theirs, &[], 0, &mut t, &mut original_trees, &mut budget)?;
    let left = detect(planner, &b, &o, RenameSide::Target, &mut budget)?;
    let right = detect(planner, &b, &t, RenameSide::Source, &mut budget)?;
    if left.is_empty() && right.is_empty() {
        return planner.directory(Some(base), ours, theirs, &[], 0, false);
    }
    let moves = join(planner, &b, &o, &t, &left, &right, &mut budget)?;
    // Complete preflight before rewriting any comparison tree. The maps below
    // are disposable metadata, never a catalog or a second authority source.
    align(planner, &mut b, &moves, &Moves::new(), &mut budget)?;
    align(planner, &mut o, &moves, &left, &mut budget)?;
    align(planner, &mut t, &moves, &right, &mut budget)?;
    let b = rebuild(planner, b, &original_trees, &mut budget)?;
    let o = rebuild(planner, o, &original_trees, &mut budget)?;
    let t = rebuild(planner, t, &original_trees, &mut budget)?;
    let tree = planner.directory(Some(b), o, t, &[], 0, false)?;
    if let Some(root) = tree {
        if planner.objects.len() == planner.limits.max_objects {
            return Err(PreparationError::Budget("objects"));
        }
        retain_candidate_objects(planner, root)?;
    }
    planner.source.checkpoint()?;
    Ok(tree)
}

fn flatten<S: MergeObjectSource>(
    planner: &mut Planner<'_, S>, root: GitOid, prefix: &[u8], depth: usize,
    flat: &mut Flat, originals: &mut BTreeSet<GitOid>, budget: &mut PathBudget,
) -> Result<(), PreparationError> {
    planner.source.checkpoint()?;
    if depth > planner.limits.max_depth {
        return Err(PreparationError::Budget("tree depth"));
    }
    let entries = planner.entries(Some(root))?;
    originals.insert(root);
    for entry in entries.into_values() {
        planner.source.checkpoint()?;
        let count = prefix.len().checked_add(usize::from(!prefix.is_empty()))
            .and_then(|n| n.checked_add(entry.name.len()))
            .filter(|n| *n <= planner.limits.max_path_bytes)
            .ok_or(PreparationError::Budget("path bytes"))?;
        budget.charge(count)?;
        let mut path = Vec::new();
        path.try_reserve_exact(count).map_err(|_| PreparationError::Budget("rename allocation"))?;
        path.extend_from_slice(prefix);
        if !prefix.is_empty() { path.push(b'/'); }
        path.extend_from_slice(&entry.name);
        if entry.mode == 0o040000 {
            flatten(planner, entry.oid, &path, depth + 1, flat, originals, budget)?;
        }
        if flat.insert(path, entry).is_some() {
            return Err(PreparationError::InvalidTree);
        }
    }
    Ok(())
}

fn detect<S: MergeObjectSource>(
    planner: &Planner<'_, S>, base: &Flat, side: &Flat, which: RenameSide,
    budget: &mut PathBudget,
) -> Result<Moves, PreparationError> {
    let mut deleted: BTreeMap<GitOid, Vec<&[u8]>> = BTreeMap::new();
    let mut added: BTreeMap<GitOid, Vec<&[u8]>> = BTreeMap::new();
    for (path, entry) in base {
        planner.source.checkpoint()?;
        if regular(entry) && !side.contains_key(path) {
            deleted.entry(entry.oid).or_default().push(path);
        }
    }
    for (path, entry) in side {
        planner.source.checkpoint()?;
        if regular(entry) && !base.contains_key(path) {
            added.entry(entry.oid).or_default().push(path);
        }
    }
    let mut moves = Moves::new();
    for (oid, old) in deleted {
        planner.source.checkpoint()?;
        let Some(new) = added.get(&oid) else { continue; };
        // Never choose a duplicate by path order, traversal order or score.
        if old.len() != 1 || new.len() != 1 {
            return Err(RenameRefusal::AmbiguousIdentity { side: which, oid }.into());
        }
        if moves.len() == MAX_RENAMES {
            return Err(PreparationError::Budget("renames"));
        }
        budget.charge(old[0].len() + new[0].len())?;
        moves.insert(old[0].to_vec(), new[0].to_vec());
    }
    Ok(moves)
}

fn join<S: MergeObjectSource>(
    planner: &Planner<'_, S>, base: &Flat, ours: &Flat, theirs: &Flat,
    left: &Moves, right: &Moves, budget: &mut PathBudget,
) -> Result<Moves, PreparationError> {
    let mut moves = Moves::new();
    let mut destinations = BTreeMap::new();
    for (from, to) in left.iter().chain(right) {
        planner.source.checkpoint()?;
        if moves.contains_key(from) { continue; }
        if moves.len() == MAX_RENAMES {
            return Err(PreparationError::Budget("renames"));
        }
        if let (Some(l), Some(r)) = (left.get(from), right.get(from)) {
            if l != r {
                return Err(RenameRefusal::Divergent {
                    from: from.clone(), target: l.clone(), source: r.clone(),
                }.into());
            }
        }
        if destinations.insert(to.clone(), from.clone()).is_some() {
            return Err(RenameRefusal::DestinationOccupied { path: to.clone() }.into());
        }
        for (flat, detected) in [(ours, left), (theirs, right)] {
            planner.source.checkpoint()?;
            if !detected.contains_key(from) {
                let Some(entry) = flat.get(from) else {
                    return Err(RenameRefusal::RenameDelete { from: from.clone(), to: to.clone() }.into());
                };
                if !regular(entry) {
                    return Err(RenameRefusal::UnsupportedEntry { path: from.clone() }.into());
                }
                if flat.contains_key(to) {
                    return Err(RenameRefusal::DestinationOccupied { path: to.clone() }.into());
                }
            }
        }
        for flat in [base, ours, theirs] {
            let mut ancestor = parent(to);
            while !ancestor.is_empty() {
                planner.source.checkpoint()?;
                if flat.get(ancestor).is_some_and(|entry| entry.mode != 0o040000) {
                    return Err(RenameRefusal::DestinationOccupied { path: ancestor.to_vec() }.into());
                }
                ancestor = parent(ancestor);
            }
            for path in [from.as_slice(), to.as_slice()] {
                if attributes(flat, path) {
                    return Err(RenameRefusal::AttributesRequireDriver { path: path.to_vec() }.into());
                }
            }
        }
        budget.charge(2 * (from.len() + to.len()))?;
        moves.insert(from.clone(), to.clone());
    }
    for to in destinations.keys() {
        let mut ancestor = parent(to);
        while !ancestor.is_empty() {
            planner.source.checkpoint()?;
            if destinations.contains_key(ancestor) {
                return Err(RenameRefusal::DestinationOccupied { path: ancestor.to_vec() }.into());
            }
            ancestor = parent(ancestor);
        }
    }
    Ok(moves)
}

fn attributes(flat: &Flat, path: &[u8]) -> bool {
    if basename(path) == b".gitattributes" { return true; }
    let mut directory = parent(path);
    loop {
        let mut key = directory.to_vec();
        if !key.is_empty() { key.push(b'/'); }
        key.extend_from_slice(b".gitattributes");
        if flat.contains_key(&key) { return true; }
        if directory.is_empty() { return false; }
        directory = parent(directory);
    }
}

fn align<S: MergeObjectSource>(
    planner: &Planner<'_, S>, flat: &mut Flat, moves: &Moves, already: &Moves,
    budget: &mut PathBudget,
) -> Result<(), PreparationError> {
    for (from, to) in moves {
        planner.source.checkpoint()?;
        if already.contains_key(from) { continue; }
        let mut entry = flat.remove(from).ok_or(PreparationError::InvalidTree)?;
        if flat.contains_key(to) {
            return Err(RenameRefusal::DestinationOccupied { path: to.clone() }.into());
        }
        budget.charge(to.len() + basename(to).len())?;
        entry.name = basename(to).to_vec();
        flat.insert(to.clone(), entry);
    }
    // Remove only ancestors emptied by our moves. Unrelated explicit empty
    // trees survive, and another branch's new files keep their original paths.
    for from in moves.keys() {
        if already.contains_key(from) { continue; }
        let mut directory = parent(from);
        while !directory.is_empty() {
            planner.source.checkpoint()?;
            let mut prefix = directory.to_vec();
            prefix.push(b'/');
            let has_child = flat.range(prefix.clone()..).next()
                .is_some_and(|(path, _)| path.starts_with(&prefix));
            if has_child { break; }
            flat.remove(directory);
            directory = parent(directory);
        }
    }
    Ok(())
}

type Directories = BTreeMap<Vec<u8>, BTreeMap<Vec<u8>, MergeEntry>>;
fn ensure_directory<S: MergeObjectSource>(
    planner: &mut Planner<'_, S>, directories: &mut Directories,
    path: &[u8], budget: &mut PathBudget,
) -> Result<(), PreparationError> {
    let depth = if path.is_empty() { 0 } else { path.split(|b| *b == b'/').count() };
    if depth > planner.limits.max_depth {
        return Err(PreparationError::Budget("tree depth"));
    }
    let mut path = path;
    loop {
        planner.source.checkpoint()?;
        if !directories.contains_key(path) {
            charge_entry(planner)?;
            budget.charge(path.len())?;
            directories.insert(path.to_vec(), BTreeMap::new());
        }
        if path.is_empty() { return Ok(()); }
        path = parent(path);
    }
}

fn rebuild<S: MergeObjectSource>(
    planner: &mut Planner<'_, S>, flat: Flat, originals: &BTreeSet<GitOid>,
    budget: &mut PathBudget,
) -> Result<GitOid, PreparationError> {
    let mut directories = Directories::new();
    ensure_directory(planner, &mut directories, &[], budget)?;
    for (path, entry) in flat {
        planner.source.checkpoint()?;
        if entry.mode == 0o040000 {
            ensure_directory(planner, &mut directories, &path, budget)?;
        } else {
            ensure_directory(planner, &mut directories, parent(&path), budget)?;
            charge_entry(planner)?;
            budget.charge(entry.name.len())?;
            let children = directories.get_mut(parent(&path)).ok_or(PreparationError::InvalidTree)?;
            if children.insert(entry.name.clone(), entry).is_some() {
                return Err(PreparationError::InvalidTree);
            }
        }
    }
    // A prefix sorts before every descendant, so pop_last builds children
    // before parents without recursive allocation or platform path semantics.
    while let Some((path, children)) = directories.pop_last() {
        planner.source.checkpoint()?;
        let mut entries: Vec<_> = children.into_values().collect();
        entries.sort_by(|a, b| {
            a.name.iter().copied().chain(std::iter::once(if a.mode == 0o040000 { b'/' } else { 0 }))
                .cmp(b.name.iter().copied().chain(std::iter::once(if b.mode == 0o040000 { b'/' } else { 0 })))
        });
        let mut body = Vec::new();
        for entry in &entries {
            planner.source.checkpoint()?;
            let mode = format!("{:o} ", entry.mode);
            let count = mode.len() + entry.name.len() + 1 + entry.oid.as_bytes().len();
            if body.len().checked_add(count).is_none_or(|n| n > planner.limits.max_output_bytes) {
                return Err(PreparationError::Budget("tree bytes"));
            }
            body.try_reserve(count).map_err(|_| PreparationError::Budget("tree allocation"))?;
            body.extend_from_slice(mode.as_bytes());
            body.extend_from_slice(&entry.name);
            body.push(0);
            body.extend_from_slice(entry.oid.as_bytes());
        }
        let id = git_object_id(planner.format, GitObjectKind::Tree, &body);
        if !originals.contains(&id) {
            planner.emit(GitObjectKind::Tree, body)?;
            planner.trees.insert(id, entries);
        }
        if path.is_empty() { return Ok(id); }
        let children = directories.get_mut(parent(&path)).ok_or(PreparationError::InvalidTree)?;
        let entry = MergeEntry { name: basename(&path).to_vec(), mode: 0o040000, oid: id };
        if children.insert(entry.name.clone(), entry).is_some() {
            return Err(RenameRefusal::DestinationOccupied { path }.into());
        }
    }
    Err(PreparationError::InvalidTree)
}

fn retain_candidate_objects<S: MergeObjectSource>(
    planner: &mut Planner<'_, S>, root: GitOid,
) -> Result<(), PreparationError> {
    let mut pending = vec![root];
    let mut keep = BTreeSet::new();
    while let Some(id) = pending.pop() {
        planner.source.checkpoint()?;
        if !planner.objects.contains_key(&id) || !keep.insert(id) { continue; }
        if planner.objects[&id].kind == GitObjectKind::Tree {
            let entries = planner.trees.get(&id).ok_or(PreparationError::InvalidTree)?;
            planner.entries = planner.entries.checked_add(entries.len())
                .filter(|count| *count <= planner.limits.max_tree_entries)
                .ok_or(PreparationError::Budget("tree entries"))?;
            for entry in entries {
                planner.source.checkpoint()?;
                pending.push(entry.oid);
            }
        }
    }
    planner.objects.retain(|id, _| keep.contains(id));
    // Deliberately do not refund construction bytes or object/tree work.
    Ok(())
}

#[cfg(test)]
mod tests;
