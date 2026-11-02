//! Candidate trees are untrusted navigation hints, not a disclosure frontier.
//! Only observe(), starting at the independently selected parent commits, can
//! add a typed original edge. Compare matching directory names without opening
//! unchanged siblings, original blobs, or the parents' old commit histories.

use super::{
    BTreeMap, BTreeSet, GitOid, MergeSourceError, ObjectType, ParentReachability,
    PlannedMergeObject, git_object_id, native_edges,
};

/// Parsed upload-only navigation state. It owns no original-object grants.
/// A new tree may arrive after its parent because it is itself a thin delta;
/// waiting pairs resume when that tree has actually passed native validation.
#[derive(Default)]
pub(super) struct Guide {
    seen: BTreeSet<GitOid>,
    trees: BTreeMap<GitOid, BTreeMap<Vec<u8>, GitOid>>,
    roots: BTreeSet<GitOid>,
    scheduled: BTreeSet<(GitOid, GitOid)>,
    pending: BTreeSet<(GitOid, GitOid)>,
    waiting: BTreeMap<GitOid, BTreeSet<GitOid>>,
}

impl Guide {
    pub(super) fn extend<'a>(
        &mut self,
        proof: &mut ParentReachability,
        uploaded: impl IntoIterator<Item = (&'a GitOid, &'a PlannedMergeObject)>,
        load: &mut impl FnMut(GitOid) -> Result<(ObjectType, Vec<u8>), MergeSourceError>,
        live: &mut impl FnMut() -> Result<(), MergeSourceError>,
    ) -> Result<(), MergeSourceError> {
        live()?;
        let mut roots = BTreeSet::new();
        for (id, object) in uploaded {
            live()?;
            if !matches!(object.kind, ObjectType::Commit | ObjectType::Tree) {
                continue;
            }
            if self.seen.contains(id) {
                return Err(MergeSourceError::InvalidObject(*id));
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
            self.seen.insert(*id);
            if let Some(root) = edges.root_tree
                && self.roots.insert(root)
            {
                roots.insert(root);
            }
            if object.kind == ObjectType::Tree {
                self.trees.insert(*id, edges.directories);
                if let Some(previous) = self.waiting.remove(id) {
                    for old in previous {
                        live()?;
                        self.pending.insert((*id, old));
                    }
                }
            }
        }
        // Every verified uploaded commit's tree is a navigation hint. The old
        // side still comes exclusively from the independently selected roots.
        if !roots.is_empty() {
            for root in proof.roots.clone() {
                expand(proof, root, ObjectType::Commit, load, live)?;
                let old = *proof
                    .commit_trees
                    .get(&root)
                    .ok_or(MergeSourceError::InvalidObject(root))?;
                for new in &roots {
                    live()?;
                    self.schedule(proof, *new, old)?;
                }
            }
        }
        while let Some((new, old)) = self.pending.pop_first() {
            live()?;
            expand(proof, old, ObjectType::Tree, load, live)?;
            let next = self
                .trees
                .get(&new)
                .ok_or(MergeSourceError::InvalidObject(new))?;
            // Cached comparisons are work too. Charge names before scanning;
            // a previously completed pair is never scanned in a later stage.
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
            let mut pairs = Vec::new();
            for (name, child) in next {
                live()?;
                if let Some(previous) = before.get(name)
                    && child != previous
                {
                    pairs
                        .try_reserve(1)
                        .map_err(|_| MergeSourceError::BudgetExceeded)?;
                    pairs.push((*child, *previous));
                }
            }
            for (child, previous) in pairs {
                live()?;
                // Remember missing new-side trees; they can be decoded using
                // already-proved external bases in the next resolution stage.
                self.schedule(proof, child, previous)?;
            }
        }
        live()
    }

    fn schedule(
        &mut self,
        proof: &mut ParentReachability,
        new: GitOid,
        old: GitOid,
    ) -> Result<(), MergeSourceError> {
        if new == old || self.scheduled.contains(&(new, old)) {
            return Ok(());
        }
        // This also bounds pending/waiting allocation before inserting a pair.
        charge(proof, 1)?;
        self.scheduled.insert((new, old));
        if self.trees.contains_key(&new) {
            self.pending.insert((new, old));
        } else {
            self.waiting.entry(new).or_default().insert(old);
        }
        Ok(())
    }
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
