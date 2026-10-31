//! Candidate trees are untrusted navigation hints, not a disclosure frontier.
//! Only observe(), starting at the independently selected parent commits, can
//! add a typed original edge. Compare matching directory names without opening
//! unchanged siblings, original blobs, or the parents' old commit histories.

use super::{
    BTreeMap, BTreeSet, GitOid, MergeSourceError, ObjectType, ParentReachability,
    PlannedMergeObject, git_object_id, native_edges,
};

pub(super) fn guide(
    proof: &mut ParentReachability,
    uploaded: &BTreeMap<GitOid, PlannedMergeObject>,
    load: &mut impl FnMut(GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError>,
    live: &mut impl FnMut() -> Result<(), MergeSourceError>,
) -> Result<(), MergeSourceError> {
    live()?;
    // Packs without commits (including zero-object rebase results) need no
    // additional proof. Thin external delta bases retain their original gate.
    if !uploaded
        .values()
        .any(|object| object.kind == ObjectType::Commit)
    {
        return live();
    }
    let mut trees = BTreeMap::new();
    let mut roots = BTreeSet::new();
    for (id, object) in uploaded {
        live()?;
        if !matches!(object.kind, ObjectType::Commit | ObjectType::Tree) {
            continue;
        }
        if proof.expanded.len().saturating_add(proof.hint_objects) >= proof.limits.max_objects
            || object.body.len() > proof.limits.max_object_bytes
        {
            return Err(MergeSourceError::BudgetExceeded);
        }
        proof.hint_objects += 1;
        proof.bytes = proof
            .bytes
            .checked_add(object.body.len())
            .filter(|bytes| *bytes <= proof.limits.max_total_bytes)
            .ok_or(MergeSourceError::BudgetExceeded)?;
        if *id != object.id
            || id.is_zero()
            || id.algorithm() != proof.format
            || git_object_id(proof.format, object.kind, &object.body) != *id
        {
            return Err(MergeSourceError::InvalidObject(*id));
        }
        let edges = native_edges(*id, object.kind, &object.body, proof.limits, live)?;
        charge(proof, edges.work.saturating_add(1))?;
        if let Some(root) = edges.root_tree {
            roots.insert(root);
        }
        if object.kind == ObjectType::Tree {
            trees.insert(*id, edges.directories);
        }
    }
    // Every supplied commit's tree is useful as a hint, including intermediate
    // rewritten commits. Even an unrelated supplied commit cannot grant access:
    // the OLD side below comes exclusively from this proof's selected roots.
    let mut pending = BTreeSet::new();
    for root in proof.roots.clone() {
        expand(proof, root, ObjectType::Commit, load, live)?;
        let old = *proof
            .commit_trees
            .get(&root)
            .ok_or(MergeSourceError::InvalidObject(root))?;
        for new in &roots {
            live()?;
            charge(proof, 1)?;
            if *new != old && trees.contains_key(new) {
                pending.insert((*new, old));
            }
        }
    }
    let mut paired = BTreeSet::new();
    while let Some((new, old)) = pending.pop_first() {
        live()?;
        charge(proof, 1)?;
        if new == old || !paired.insert((new, old)) {
            continue;
        }
        expand(proof, old, ObjectType::Tree, load, live)?;
        let next = trees
            .get(&new)
            .ok_or(MergeSourceError::InvalidObject(new))?;
        // Cached comparisons are work too. Charge before scanning, including
        // names, rather than giving each rewritten tree a new allowance.
        let work = next.keys().try_fold(1usize, |sum, name| {
            sum.checked_add(name.len())
                .and_then(|n| n.checked_add(1))
                .ok_or(MergeSourceError::BudgetExceeded)
        })?;
        charge(proof, work)?;
        let before = proof
            .directories
            .get(&old)
            .ok_or(MergeSourceError::InvalidObject(old))?;
        for (name, child) in next {
            live()?;
            if !trees.contains_key(child) {
                continue;
            }
            if let Some(previous) = before.get(name)
                && child != previous
                && !paired.contains(&(*child, *previous))
            {
                pending.insert((*child, *previous));
            }
        }
    }
    live()
}

fn charge(proof: &mut ParentReachability, work: usize) -> Result<(), MergeSourceError> {
    proof.edges = proof
        .edges
        .checked_add(work)
        .filter(|edges| *edges <= proof.limits.max_edges)
        .ok_or(MergeSourceError::BudgetExceeded)?;
    Ok(())
}

fn expand(
    proof: &mut ParentReachability,
    id: GitOid,
    expected: ObjectType,
    load: &mut impl FnMut(GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError>,
    live: &mut impl FnMut() -> Result<(), MergeSourceError>,
) -> Result<(), MergeSourceError> {
    live()?;
    // This check precedes I/O. A caller-supplied name or ID can never select an
    // object merely because it exists elsewhere in the admitted repository.
    proof.require_kind(id, expected)?;
    if !proof.expanded.contains(&id) {
        if proof.expanded.len().saturating_add(proof.hint_objects) >= proof.limits.max_objects {
            return Err(MergeSourceError::BudgetExceeded);
        }
        let (kind, body) = load(id)?;
        proof.observe(id, kind, &body, live)?;
    }
    live()
}

#[cfg(test)]
#[path = "path_frontier/tests.rs"]
mod tests;
