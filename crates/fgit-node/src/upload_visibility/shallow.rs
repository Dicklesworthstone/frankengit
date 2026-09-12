//! Shallow history over the private, complete, native-verified disclosure graph.
//! Client shallow markers constrain ancestry; they never grant object access.
use super::partial_clone::FilterObject;
use super::*;
use fgit_wire::closure::ShallowUpdate;
pub(super) mod cutoffs;
mod relative;

/// Shared only with the repository view for the lifetime of this connection.
/// This is a derived proof, not a persisted promise or an authority root.
#[derive(Clone, Debug)]
pub(crate) struct ShallowProof {
    objects: Arc<BTreeMap<GitOid, FilterObject>>,
    limits: PackLimits,
    deadline: GitDaemonSessionDeadline,
}

impl ShallowProof {
    pub(super) fn new(
        objects: Arc<BTreeMap<GitOid, FilterObject>>,
        limits: PackLimits,
        deadline: GitDaemonSessionDeadline,
    ) -> Self {
        Self {
            objects,
            limits,
            deadline,
        }
    }

    pub(crate) fn update(&self, request: &PackRequest) -> Result<ShallowUpdate, WireError> {
        boundary_update(&self.objects, request, &self.limits, &mut || {
            !self.deadline.expired()
        })
        .map_err(|_| WireError::PackSourceRefused)
    }
}

pub(crate) fn requested(request: &PackRequest) -> bool {
    request.options.deepen_relative()
        || !request.shallows.is_empty()
        || request.deepen.is_some()
        || request.deepen_since.is_some()
        || !request.deepen_not.is_empty()
}

struct Work<'a, F> {
    live: &'a mut F,
    left: usize,
    maximum: usize,
}

impl<'a, F: FnMut() -> bool> Work<'a, F> {
    fn new(limits: &PackLimits, live: &'a mut F) -> Self {
        Self {
            live,
            left: limits.max_delta_work,
            maximum: usize::try_from(limits.max_entries).unwrap_or(usize::MAX),
        }
    }

    fn tick(&mut self) -> Result<(), NodePackMaterializationRefusal> {
        if !(self.live)() {
            return Err(PackWriteError::from(PackError::DeadlineExceeded).into());
        }
        self.left = self.left.checked_sub(1).ok_or_else(budget)?;
        Ok(())
    }

    fn count(&self, count: usize) -> Result<(), NodePackMaterializationRefusal> {
        if count > self.maximum {
            Err(budget())
        } else {
            Ok(())
        }
    }

    fn insert<T: Ord>(
        &mut self,
        set: &mut BTreeSet<T>,
        value: T,
    ) -> Result<bool, NodePackMaterializationRefusal> {
        self.tick()?;
        if set.contains(&value) {
            return Ok(false);
        }
        self.count(set.len().checked_add(1).ok_or_else(budget)?)?;
        Ok(set.insert(value))
    }
}

fn budget() -> NodePackMaterializationRefusal {
    disclosure_refusal(RefusalCode::ResourceBudgetExceeded)
}

fn object(
    objects: &BTreeMap<GitOid, FilterObject>,
    id: GitOid,
) -> Result<&FilterObject, NodePackMaterializationRefusal> {
    objects
        .get(&id)
        .ok_or_else(|| disclosure_refusal(RefusalCode::ObjectClosureIncomplete))
}

struct History {
    old: BTreeSet<GitOid>,
    boundaries: BTreeSet<GitOid>,
    update: ShallowUpdate,
}

fn history(
    objects: &BTreeMap<GitOid, FilterObject>,
    request: &PackRequest,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<History, NodePackMaterializationRefusal> {
    work.tick()?;
    work.count(request.wants.len())?;
    work.count(request.haves.len())?;
    work.count(request.shallows.len())?;
    if request.deepen == Some(0) {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "zero shallow depth",
        ));
    }
    for &id in &request.wants {
        work.tick()?;
        if !objects.contains_key(&id) {
            return Err(NodePackMaterializationRefusal::RequestedWantOutsideClosure(
                id,
            ));
        }
    }
    let mut old = BTreeSet::new();
    for &id in &request.shallows {
        work.tick()?;
        // Disconnected, hidden, and foreign markers cannot cause a storage read
        // or be echoed back. An accessible non-commit is an invalid boundary.
        if let Some(item) = objects.get(&id) {
            if item.kind != ObjectType::Commit {
                return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
            }
            work.insert(&mut old, id)?;
        }
    }
    if cutoffs::requested(request) {
        return cutoffs::history(objects, request, old, work);
    }
    let effective_depth = relative::effective_depth(objects, request, &old, work)?;
    let mut depths = BTreeMap::new();
    let mut pending = BTreeSet::new();
    for &id in &request.wants {
        enqueue(&mut depths, &mut pending, id, 1, work)?;
    }
    let mut commits = BTreeSet::new();
    let mut boundaries = BTreeSet::new();
    while let Some((depth, id)) = pending.pop_first() {
        work.tick()?;
        if depths.get(&id) != Some(&depth) {
            continue;
        }
        let item = object(objects, id)?;
        match item.kind {
            ObjectType::Tag => {
                let [(target, _)] = item.edges.as_slice() else {
                    return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
                };
                enqueue(&mut depths, &mut pending, *target, depth, work)?;
            }
            ObjectType::Commit => {
                work.insert(&mut commits, id)?;
                let boundary = effective_depth.map_or_else(
                    || old.contains(&id),
                    |maximum| maximum != relative::INFINITE_DEPTH && depth >= maximum,
                );
                if boundary {
                    // Git also marks a natural root at the exact requested
                    // depth. Do not substitute "has an omitted parent" here.
                    work.insert(&mut boundaries, id)?;
                    continue;
                }
                let next = depth.checked_add(1).ok_or_else(budget)?;
                for &(parent, kind) in &item.edges {
                    work.tick()?;
                    if kind == ObjectType::Commit {
                        enqueue(&mut depths, &mut pending, parent, next, work)?;
                    }
                }
            }
            ObjectType::Tree | ObjectType::Blob => {}
        }
    }
    let mut update = ShallowUpdate {
        shallow: Vec::new(),
        unshallow: Vec::new(),
    };
    if request.deepen.is_some() {
        update
            .shallow
            .try_reserve_exact(boundaries.len())
            .map_err(|_| budget())?;
        update
            .unshallow
            .try_reserve_exact(old.len())
            .map_err(|_| budget())?;
        for &id in &boundaries {
            work.tick()?;
            if !old.contains(&id) {
                update.shallow.push(id);
            }
        }
        for &id in &old {
            work.tick()?;
            // Git's INFINITE_DEPTH removes every supplied boundary present
            // in the server's complete repository, not only wanted ancestry.
            // Here membership is narrowed to the authenticated visible graph.
            if (request.deepen == Some(2_147_483_647) || commits.contains(&id))
                && !boundaries.contains(&id)
            {
                update.unshallow.push(id);
            }
        }
    }
    work.tick()?;
    Ok(History {
        old,
        boundaries,
        update,
    })
}

fn enqueue(
    depths: &mut BTreeMap<GitOid, u32>,
    pending: &mut BTreeSet<(u32, GitOid)>,
    id: GitOid,
    depth: u32,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<(), NodePackMaterializationRefusal> {
    work.tick()?;
    if depths.get(&id).is_some_and(|previous| *previous <= depth) {
        return Ok(());
    }
    work.count(
        depths
            .len()
            .checked_add(usize::from(!depths.contains_key(&id)))
            .ok_or_else(budget)?,
    )?;
    if let Some(previous) = depths.insert(id, depth) {
        pending.remove(&(previous, id));
    }
    work.insert(pending, (depth, id))?;
    Ok(())
}

/// Traverse repository-local edges, treating each boundary commit as a root
/// of history while still including its complete tree. Gitlinks were removed
/// by the native-verified disclosure projection, not by caller path filtering.
fn walk(
    objects: &BTreeMap<GitOid, FilterObject>,
    roots: &[GitOid],
    boundaries: &BTreeSet<GitOid>,
    ignore_unknown_roots: bool,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<BTreeSet<GitOid>, NodePackMaterializationRefusal> {
    let mut seen = BTreeSet::new();
    let mut pending = BTreeSet::new();
    for &id in roots {
        work.tick()?;
        if ignore_unknown_roots && !objects.contains_key(&id) {
            continue;
        }
        work.insert(&mut pending, id)?;
    }
    while let Some(id) = pending.pop_first() {
        work.tick()?;
        if !work.insert(&mut seen, id)? {
            continue;
        }
        let item = object(objects, id)?;
        for &(child, kind) in &item.edges {
            work.tick()?;
            if item.kind == ObjectType::Commit
                && kind == ObjectType::Commit
                && boundaries.contains(&id)
            {
                continue;
            }
            if !seen.contains(&child) {
                work.insert(&mut pending, child)?;
            }
        }
    }
    Ok(seen)
}

/// Compute the pre-pack update at the same immutable connection basis, before
/// legacy clients begin have negotiation. No packet is emitted by this layer.
fn boundary_update(
    objects: &BTreeMap<GitOid, FilterObject>,
    request: &PackRequest,
    limits: &PackLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<ShallowUpdate, NodePackMaterializationRefusal> {
    history(objects, request, &mut Work::new(limits, live)).map(|result| result.update)
}

/// Return the exact unfiltered transfer selection. Unlike ordinary have
/// subtraction, known history stops at the CLIENT'S old boundaries. Desired
/// history stops at the NEW boundary. This difference supplies the ancestors
/// that a client needs when it deepens a commit it already has.
pub(super) fn select(
    objects: &BTreeMap<GitOid, FilterObject>,
    request: &PackRequest,
    limits: &PackLimits,
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<GitOid>, NodePackMaterializationRefusal> {
    let mut work = Work::new(limits, live);
    let history = history(objects, request, &mut work)?;
    let mut roots = BTreeSet::new();
    for &id in &request.wants {
        work.insert(&mut roots, id)?;
    }
    // Removing an old boundary is a promise to deliver its missing parents,
    // including visible shallow histories on other client branches. Starting
    // at parents avoids retransmitting a natural root solely for unshallow.
    // All lookups remain inside the same verified graph and work ledger.
    for &boundary in &history.update.unshallow {
        work.tick()?;
        for &(parent, kind) in &object(objects, boundary)?.edges {
            work.tick()?;
            if kind == ObjectType::Commit {
                work.insert(&mut roots, parent)?;
            }
        }
    }
    let mut desired_roots = Vec::new();
    desired_roots
        .try_reserve_exact(roots.len())
        .map_err(|_| budget())?;
    for root in roots {
        work.tick()?;
        desired_roots.push(root);
    }
    let desired = walk(
        objects,
        &desired_roots,
        &history.boundaries,
        false,
        &mut work,
    )?;
    let known = walk(objects, &request.haves, &history.old, true, &mut work)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(desired.len())
        .map_err(|_| budget())?;
    for id in desired {
        work.tick()?;
        if !known.contains(&id) {
            result.push(id);
        }
    }
    work.tick()?;
    Ok(result)
}

#[cfg(test)]
mod tests;
