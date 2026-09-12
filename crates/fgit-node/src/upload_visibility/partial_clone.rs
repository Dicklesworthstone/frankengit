//! Partial-clone selection over the same native-verified disclosure proof.
//! Filtering never changes canonical retention and never supplies permission.
use super::*;
use fgit_wire::ObjectFilter;

#[derive(Debug)]
pub(super) struct FilterObject {
    pub(super) kind: ObjectType,
    pub(super) size: usize,
    pub(super) edges: Vec<(GitOid, ObjectType)>,
}

struct Work<'a, F> {
    live: &'a mut F,
    remaining: usize,
    maximum: usize,
}
impl<F: FnMut() -> bool> Work<'_, F> {
    fn tick(&mut self) -> Result<(), NodePackMaterializationRefusal> {
        if !(self.live)() {
            return Err(PackWriteError::from(PackError::DeadlineExceeded).into());
        }
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or_else(|| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
        Ok(())
    }
    fn count(&self, count: usize) -> Result<(), NodePackMaterializationRefusal> {
        if count > self.maximum {
            Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded))
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct Predicate {
    blob_limit: Option<u64>,
    tree_depth: Option<u32>,
}
impl Predicate {
    fn compile(
        filter: Option<&ObjectFilter>,
        work: &mut Work<'_, impl FnMut() -> bool>,
    ) -> Result<Self, NodePackMaterializationRefusal> {
        let mut result = Self::default();
        let mut pending = Vec::new();
        if let Some(filter) = filter {
            pending.push(filter);
        }
        while let Some(filter) = pending.pop() {
            work.tick()?;
            match filter {
                ObjectFilter::BlobNone => result.blob_limit = Some(0),
                ObjectFilter::BlobLimit(limit) => {
                    result.blob_limit =
                        Some(result.blob_limit.map_or(*limit, |old| old.min(*limit)));
                }
                ObjectFilter::TreeDepth(depth) => {
                    result.tree_depth =
                        Some(result.tree_depth.map_or(*depth, |old| old.min(*depth)));
                }
                ObjectFilter::Combine(parts) => {
                    if parts.is_empty() || pending.len().saturating_add(parts.len()) > 65_520 {
                        return Err(disclosure_refusal(RefusalCode::ResourceBudgetExceeded));
                    }
                    pending
                        .try_reserve(parts.len())
                        .map_err(|_| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
                    pending.extend(parts.iter().rev());
                }
                ObjectFilter::SparseObject(_) | ObjectFilter::SparsePath(_) => {
                    return Err(NodePackMaterializationRefusal::UnsupportedFetch(
                        "sparse filters",
                    ));
                }
            }
        }
        Ok(result)
    }
    fn permits(
        &self,
        object: &FilterObject,
        depth: Option<u32>,
    ) -> Result<bool, NodePackMaterializationRefusal> {
        if object.kind == ObjectType::Blob
            && self
                .blob_limit
                .is_some_and(|limit| u64::try_from(object.size).unwrap_or(u64::MAX) >= limit)
        {
            return Ok(false);
        }
        if matches!(object.kind, ObjectType::Blob | ObjectType::Tree)
            && let Some(maximum) = self.tree_depth
        {
            return depth
                .map(|depth| depth < maximum)
                .ok_or_else(|| disclosure_refusal(RefusalCode::EvidenceInvalid));
        }
        Ok(true)
    }
}

fn object(
    objects: &BTreeMap<GitOid, FilterObject>,
    id: GitOid,
) -> Result<&FilterObject, NodePackMaterializationRefusal> {
    objects
        .get(&id)
        .ok_or_else(|| disclosure_refusal(RefusalCode::ObjectClosureIncomplete))
}

/// Install the filtered selection atomically, after all controls and bounds pass.
/// `objects` can only be supplied by the parent's complete visible-graph proof.
pub(super) fn apply_selection(
    objects: &BTreeMap<GitOid, FilterObject>,
    ids: &mut Vec<GitOid>,
    request: &PackRequest,
    limits: &PackLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<(), NodePackMaterializationRefusal> {
    let mut work = Work {
        live,
        remaining: limits.max_delta_work,
        maximum: usize::try_from(limits.max_entries).unwrap_or(usize::MAX),
    };
    work.tick()?;
    if request.options.deepen_relative() || !request.shallows.is_empty()
        || request.deepen.is_some()
        || request.deepen_since.is_some()
        || !request.deepen_not.is_empty()
    {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "shallow history",
        ));
    }
    let predicate = Predicate::compile(request.filter.as_ref(), &mut work)?;
    work.count(ids.len())?;
    work.count(request.wants.len())?;
    let mut selected = BTreeSet::new();
    for &id in ids.iter() {
        work.tick()?;
        object(objects, id)?;
        selected.insert(id);
    }
    let mut explicit = BTreeSet::new();
    for &id in &request.wants {
        work.tick()?;
        // A filter, prior promise, or physical object cannot authorize a want.
        if !objects.contains_key(&id) {
            return Err(NodePackMaterializationRefusal::RequestedWantOutsideClosure(
                id,
            ));
        }
        explicit.insert(id);
    }
    let direct_haves: BTreeSet<_> = request.haves.iter().copied().collect();
    // A partial client's have-commit does not prove that an explicitly wanted
    // blob/tree is present. Restore those lazy object roots and their subtree,
    // never commit history. Explicit have of the same object still wins.
    let mut frontier = BTreeSet::new();
    for &id in &explicit {
        work.tick()?;
        if !direct_haves.contains(&id)
            && matches!(
                object(objects, id)?.kind,
                ObjectType::Blob | ObjectType::Tree
            )
        {
            frontier.insert(id);
        }
    }
    let mut restored = BTreeSet::new();
    while let Some(id) = frontier.pop_first() {
        work.tick()?;
        if !restored.insert(id) {
            continue;
        }
        work.count(restored.len())?;
        selected.insert(id);
        work.count(selected.len())?;
        for &(child, _) in &object(objects, id)?.edges {
            work.tick()?;
            if !restored.contains(&child) {
                work.count(
                    frontier
                        .len()
                        .saturating_add(usize::from(!frontier.contains(&child))),
                )?;
                frontier.insert(child);
            }
        }
    }
    let depths = if predicate.tree_depth.is_some() {
        tree_depths(objects, &selected, &explicit, &mut work)?
    } else {
        BTreeMap::new()
    };
    let mut result = Vec::new();
    result
        .try_reserve_exact(selected.len())
        .map_err(|_| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
    for id in selected {
        work.tick()?;
        if explicit.contains(&id)
            || predicate.permits(object(objects, id)?, depths.get(&id).copied())?
        {
            result.push(id);
        }
    }
    work.tick()?;
    *ids = result;
    Ok(())
}

/// Multi-source shortest tree depth, not first-visit DFS depth. All commit
/// roots and explicitly requested trees seed depth zero before expansion.
fn tree_depths(
    objects: &BTreeMap<GitOid, FilterObject>,
    selected: &BTreeSet<GitOid>,
    explicit: &BTreeSet<GitOid>,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<BTreeMap<GitOid, u32>, NodePackMaterializationRefusal> {
    let mut depths = BTreeMap::new();
    let mut frontier = BTreeSet::new();
    let mut tag_seen = BTreeSet::new();
    let seed = |id, depths: &mut BTreeMap<GitOid, u32>, frontier: &mut BTreeSet<(u32, GitOid)>| {
        if selected.contains(&id) && depths.insert(id, 0) != Some(0) {
            frontier.insert((0, id));
        }
    };
    for &id in selected {
        work.tick()?;
        let item = object(objects, id)?;
        match item.kind {
            ObjectType::Commit => {
                for &(child, kind) in &item.edges {
                    work.tick()?;
                    if kind == ObjectType::Tree {
                        seed(child, &mut depths, &mut frontier);
                    }
                }
            }
            ObjectType::Tree | ObjectType::Blob if explicit.contains(&id) => {
                seed(id, &mut depths, &mut frontier);
            }
            ObjectType::Tag => {
                let mut target = id;
                loop {
                    work.tick()?;
                    let item = object(objects, target)?;
                    if item.kind != ObjectType::Tag {
                        if matches!(item.kind, ObjectType::Tree | ObjectType::Blob) {
                            seed(target, &mut depths, &mut frontier);
                        }
                        break;
                    }
                    if !tag_seen.insert(target) {
                        break;
                    }
                    let [(child, _)] = item.edges.as_slice() else {
                        return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
                    };
                    target = *child;
                }
            }
            _ => {}
        }
    }
    work.count(depths.len())?;
    while let Some((depth, id)) = frontier.pop_first() {
        work.tick()?;
        if depths.get(&id) != Some(&depth) {
            continue;
        }
        let item = object(objects, id)?;
        if item.kind != ObjectType::Tree {
            continue;
        }
        let next_depth = depth
            .checked_add(1)
            .ok_or_else(|| disclosure_refusal(RefusalCode::ResourceBudgetExceeded))?;
        for &(child, _) in &item.edges {
            work.tick()?;
            if !selected.contains(&child) {
                continue;
            }
            if depths.get(&child).is_some_and(|known| *known <= next_depth) {
                continue;
            }
            if let Some(old) = depths.insert(child, next_depth) {
                frontier.remove(&(old, child));
            }
            work.count(depths.len())?;
            frontier.insert((next_depth, child));
        }
    }
    Ok(depths)
}
