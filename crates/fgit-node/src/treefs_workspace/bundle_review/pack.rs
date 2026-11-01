//! Stage-free use of the existing pack inflater and typed delta resolver.
//! Native identities are discovered in bounded passes, allowing forward REF
//! bases without trusting an uploaded index or widening original-object scope.

use super::{
    AcceptanceProfile, BTreeMap, BTreeSet, BundleInspectionRefusal, GitHashAlgorithm, GitOid,
    MergeObjectLimits, MergeSourceError, ObjectType, OriginalSource, PackError, PackLimits,
    ParseLimits, PlannedMergeObject, git_object_id, invalid, reachability,
};
use fgit_pack::{
    CachedResolver, DeltaBase, ExternalBaseLookup, NativeChecksumVerifier, PackObject,
    QuarantinedPack, ResolutionBudget, read_verified_pack, verify_native_object,
};

pub(super) struct Unpacked {
    pub objects: BTreeMap<GitOid, PlannedMergeObject>,
    pub expanded_bytes: usize,
    dependencies: BTreeMap<GitOid, BTreeSet<GitOid>>,
}
impl Unpacked {
    /// Validate uploaded native edges even when an uploaded identity was already
    /// admitted. A selected tree supplied in the pack is not permission to read
    /// its omitted descendants from a hidden branch. Thick parent-reachable
    /// objects are allowed; unrelated bytes remain limited to delta transport.
    pub(super) fn check_frontier_coverage(
        &self,
        closure: &BTreeSet<GitOid>,
        original: &OriginalSource<'_>,
        limits: MergeObjectLimits,
    ) -> Result<usize, BundleInspectionRefusal> {
        let mut pending: BTreeSet<_> = self
            .objects
            .keys()
            .filter(|id| closure.contains(*id))
            .copied()
            .collect();
        let mut graph = BTreeSet::new();
        let mut required = BTreeMap::new();
        let mut edges = 0usize;
        self.walk_uploaded(
            &mut pending,
            &mut graph,
            &mut required,
            &mut edges,
            original,
            limits,
        )?;
        let mut covered = self.with_delta_bases(&graph);
        for (id, object) in &self.objects {
            original.live().map_err(BundleInspectionRefusal::Source)?;
            if covered.contains(id) {
                continue;
            }
            if original
                .permits(*id)
                .map_err(BundleInspectionRefusal::Source)?
            {
                original
                    .verify_reused(*id, object.kind)
                    .map_err(BundleInspectionRefusal::Source)?;
                pending.insert(*id);
                self.walk_uploaded(
                    &mut pending,
                    &mut graph,
                    &mut required,
                    &mut edges,
                    original,
                    limits,
                )?;
                covered = self.with_delta_bases(&graph);
            }
        }
        if covered.len() != self.objects.len() {
            return Err(invalid(
                "pack includes objects unrelated to the candidate or its delta reconstruction",
            ));
        }
        original.live().map_err(BundleInspectionRefusal::Source)?;
        Ok(covered.len() - graph.len())
    }

    fn walk_uploaded(
        &self,
        pending: &mut BTreeSet<GitOid>,
        graph: &mut BTreeSet<GitOid>,
        required: &mut BTreeMap<GitOid, ObjectType>,
        edges: &mut usize,
        original: &OriginalSource<'_>,
        limits: MergeObjectLimits,
    ) -> Result<(), BundleInspectionRefusal> {
        while let Some(id) = pending.pop_first() {
            original.live().map_err(BundleInspectionRefusal::Source)?;
            if !graph.insert(id) {
                continue;
            }
            let object = self
                .objects
                .get(&id)
                .ok_or_else(|| invalid("missing uploaded object"))?;
            if required.get(&id).is_some_and(|kind| *kind != object.kind) {
                return Err(invalid("uploaded edge has the wrong native kind"));
            }
            let outgoing =
                reachability::native_edges(id, object.kind, &object.body, limits, &mut || {
                    original.live()
                })
                .map_err(BundleInspectionRefusal::Source)?;
            *edges = edges
                .checked_add(outgoing.work)
                .filter(|total| *total <= limits.max_edges)
                .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
            for (child, kind) in outgoing.objects {
                original.live().map_err(BundleInspectionRefusal::Source)?;
                if required
                    .insert(child, kind)
                    .is_some_and(|expected| expected != kind)
                {
                    return Err(invalid("native edges disagree on object kind"));
                }
                if let Some(uploaded) = self.objects.get(&child) {
                    if uploaded.kind != kind {
                        return Err(invalid("uploaded edge has the wrong native kind"));
                    }
                    if !graph.contains(&child) {
                        pending.insert(child);
                    }
                } else {
                    // The parent proof authenticates this reused edge. Its
                    // payload is not needed to validate uploaded graph bytes;
                    // fetching every unchanged blob recreates a full-byte walk.
                    original
                        .verify_reused(child, kind)
                        .map_err(BundleInspectionRefusal::Source)?;
                }
            }
        }
        Ok(())
    }

    fn with_delta_bases(&self, graph: &BTreeSet<GitOid>) -> BTreeSet<GitOid> {
        let mut pending = graph.clone();
        let mut covered = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            if covered.insert(id)
                && let Some(bases) = self.dependencies.get(&id)
            {
                pending.extend(bases.iter().copied());
            }
        }
        covered
    }

    /// Whole-closure reference for pack-local tests. Production reviews use
    /// `check_frontier_coverage` for the authenticated sparse frontier.
    ///
    /// An extra uploaded object is not silently hidden from review. Permit
    /// only Git-reachable objects and their transitive pack-local delta bases;
    /// the latter are counted separately and never called candidate content.
    #[cfg(test)]
    pub(super) fn check_coverage(
        &self,
        closure: &BTreeSet<GitOid>,
    ) -> Result<usize, BundleInspectionRefusal> {
        let mut pending: BTreeSet<_> = self
            .objects
            .keys()
            .filter(|id| closure.contains(*id))
            .copied()
            .collect();
        let graph_objects = pending.len();
        let mut covered = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            if !covered.insert(id) {
                continue;
            }
            if let Some(bases) = self.dependencies.get(&id) {
                pending.extend(bases.iter().copied());
            }
        }
        if covered.len() != self.objects.len() {
            return Err(invalid(
                "pack includes objects unrelated to the candidate or its delta reconstruction",
            ));
        }
        Ok(covered.len() - graph_objects)
    }
}

pub(super) fn unpack(
    input: &[u8],
    format: GitHashAlgorithm,
    limits: &PackLimits,
    original: &OriginalSource<'_>,
) -> Result<Unpacked, BundleInspectionRefusal> {
    let mut live = || original.live().is_ok();
    let parsed = read_verified_pack(input, format, limits, &mut live, &NativeChecksumVerifier)?;
    let unpacked = reconstruct(parsed, format, limits, original, &mut live)?;
    original.live().map_err(BundleInspectionRefusal::Source)?;
    Ok(unpacked)
}

fn guide_resolved(
    original: &OriginalSource<'_>,
    objects: &BTreeMap<GitOid, PlannedMergeObject>,
    pending: &mut BTreeSet<GitOid>,
    has_commit: bool,
) -> Result<(), BundleInspectionRefusal> {
    original.live().map_err(BundleInspectionRefusal::Source)?;
    // Preserve blob-only/transport-only behavior. Retain earlier tree hints
    // until an actual decoded commit supplies their candidate roots.
    if !has_commit || pending.is_empty() {
        return Ok(());
    }
    if let Some(frontier) = &original.frontier {
        let guided = frontier.borrow_mut().guide_uploaded(
            pending.iter().map(|id| (id, &objects[id])),
            |id| original.read_selected(id),
            || original.live(),
        );
        if matches!(guided, Err(MergeSourceError::BudgetExceeded)) {
            original.budget.exhausted.set(true);
        }
        guided.map_err(BundleInspectionRefusal::Source)?;
    }
    pending.clear();
    original.live().map_err(BundleInspectionRefusal::Source)
}

#[derive(Default)]
struct ExternalBases {
    objects: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    bytes: usize,
    declined: BTreeSet<GitOid>,
}
impl ExternalBaseLookup for ExternalBases {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> {
        self.objects.get(id).map(|(_, body)| body.as_slice())
    }
    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.objects
            .get(id)
            .map(|(kind, body)| (*kind, body.as_slice()))
    }
}
impl ExternalBases {
    fn read(
        &mut self,
        id: GitOid,
        original: &OriginalSource<'_>,
        limits: &PackLimits,
    ) -> Result<bool, BundleInspectionRefusal> {
        // This gate remains mandatory even for an already-proved scheduling
        // hint: the current selected set and typed native proof both apply.
        if !original
            .permits(id)
            .map_err(BundleInspectionRefusal::Source)?
        {
            self.declined.insert(id);
            return Ok(false);
        }
        let (kind, body) = original.read(id).map_err(BundleInspectionRefusal::Source)?;
        self.bytes = self
            .bytes
            .checked_add(body.len())
            .filter(|total| *total <= limits.max_cached_bytes)
            .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
        self.objects.insert(id, (kind, body));
        Ok(true)
    }
}

/// Resolve every already-proved base before attempting an unknown path. If
/// breadth-first discovery is necessary, fetch one useful base and let its
/// decoded graph extend the guide before another original lookup.
fn load_external_stage(
    inputs: &[PackObject],
    objects: &BTreeMap<GitOid, PlannedMergeObject>,
    bases: &mut ExternalBases,
    original: &OriginalSource<'_>,
    limits: &PackLimits,
    budget: &mut ResolutionBudget,
    deadline: &mut impl fgit_pack::Deadline,
) -> Result<bool, BundleInspectionRefusal> {
    let mut candidates = Vec::new();
    let mut seen = BTreeSet::new();
    for input in inputs {
        check(deadline)?;
        budget.charge_work(1, limits)?;
        let PackObject::Delta(delta) = input else {
            continue;
        };
        let DeltaBase::Ref(base) = &delta.base else {
            continue;
        };
        if objects.contains_key(base)
            || bases.objects.contains_key(base)
            || bases.declined.contains(base)
            || !seen.insert(*base)
        {
            continue;
        }
        candidates
            .try_reserve(1)
            .map_err(|_| BundleInspectionRefusal::BudgetExceeded)?;
        candidates.push(*base);
    }
    let mut loaded = false;
    for id in &candidates {
        check(deadline)?;
        budget.charge_work(1, limits)?;
        let known = original
            .frontier
            .as_ref()
            .is_none_or(|frontier| frontier.borrow().already_proves(*id));
        if known {
            loaded |= bases.read(*id, original, limits)?;
        }
    }
    if loaded {
        return Ok(true);
    }
    for id in candidates {
        check(deadline)?;
        budget.charge_work(1, limits)?;
        if !bases.declined.contains(&id) && bases.read(id, original, limits)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn reconstruct(
    pack: QuarantinedPack,
    format: GitHashAlgorithm,
    limits: &PackLimits,
    original: &OriginalSource<'_>,
    deadline: &mut impl fgit_pack::Deadline,
) -> Result<Unpacked, BundleInspectionRefusal> {
    let mut inputs = pack.into_scalar_objects(|_| None)?;
    let offsets: BTreeMap<_, _> = inputs
        .iter()
        .enumerate()
        .map(|(index, object)| (offset(object), index))
        .collect();
    if offsets.len() != inputs.len() {
        return Err(invalid("duplicate pack offset"));
    }
    let mut objects = BTreeMap::new();
    let mut ids = BTreeMap::new();
    let mut expanded_bytes = 0usize;
    let mut budget = ResolutionBudget::new();
    let mut bases = ExternalBases::default();
    let mut pending_hints = BTreeSet::new();
    let mut has_commit = false;
    let parse_limits = ParseLimits {
        max_object_bytes: limits.max_object_bytes,
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    };
    for _ in 0..=limits.max_delta_depth {
        check(deadline)?;
        let mut assigned = Vec::new();
        loop {
            let mut newly_resolved = Vec::new();
            let mut pending_bytes = 0usize;
            {
                let mut resolver = CachedResolver::new(&inputs, &bases, limits, deadline)?;
                for location in offsets.keys() {
                    check(deadline)?;
                    budget.charge_work(1, limits)?;
                    if ids.contains_key(location) {
                        continue;
                    }
                    match resolver.resolve_offset_typed_with_budget(
                        *location,
                        &mut budget,
                        deadline,
                    ) {
                        Ok((kind, body)) => {
                            pending_bytes = pending_bytes
                                .checked_add(body.len())
                                .and_then(|total| total.checked_add(expanded_bytes))
                                .filter(|total| *total <= limits.max_total_expanded_bytes)
                                .map(|total| total - expanded_bytes)
                                .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
                            newly_resolved.push((*location, kind, body));
                        }
                        Err(PackError::MissingDeltaBase) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            for (location, kind, body) in newly_resolved {
                check(deadline)?;
                let id = git_object_id(format, kind, &body);
                let parsed = verify_native_object(
                    format,
                    kind,
                    &body,
                    &id,
                    AcceptanceProfile::GitCompatibleImport,
                    &parse_limits,
                )?;
                drop(parsed);
                check(deadline)?;
                expanded_bytes = expanded_bytes
                    .checked_add(body.len())
                    .filter(|total| *total <= limits.max_total_expanded_bytes)
                    .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
                if objects
                    .insert(id, PlannedMergeObject { id, kind, body })
                    .is_some()
                    || ids.insert(location, id).is_some()
                {
                    return Err(invalid("duplicate native object in candidate pack"));
                }
                if matches!(kind, ObjectType::Commit | ObjectType::Tree) {
                    pending_hints.insert(id);
                    has_commit |= kind == ObjectType::Commit;
                }
                let index = *offsets
                    .get(&location)
                    .ok_or_else(|| invalid("missing pack offset"))?;
                assigned.push((index, id));
            }
            if ids.len() == inputs.len() {
                break;
            }
            // A newly discovered in-pack REF identity gets the next original
            // discovery pass before any external lookup. Installing it here
            // would silently reset the existing depth/pass envelope.
            let mut local_progress = false;
            for input in &inputs {
                check(deadline)?;
                budget.charge_work(1, limits)?;
                if !ids.contains_key(&offset(input))
                    && let PackObject::Delta(delta) = input
                    && let DeltaBase::Ref(base) = &delta.base
                    && objects.contains_key(base)
                {
                    local_progress = true;
                    break;
                }
            }
            if local_progress {
                break;
            }
            // The verified partial graph can now navigate visible parent
            // paths before an unresolved external delta asks for their bytes.
            guide_resolved(original, &objects, &mut pending_hints, has_commit)?;
            if !load_external_stage(
                &inputs,
                &objects,
                &mut bases,
                original,
                limits,
                &mut budget,
                deadline,
            )? {
                break;
            }
        }
        if assigned.is_empty() {
            break;
        }
        for (index, id) in assigned {
            check(deadline)?;
            match &mut inputs[index] {
                PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => {
                    *slot = Some(id);
                }
                PackObject::Delta(delta) => delta.id = Some(id),
            }
        }
        if objects.len() == inputs.len() {
            break;
        }
    }
    if objects.len() != inputs.len() {
        return Err(PackError::MissingDeltaBase.into());
    }
    guide_resolved(original, &objects, &mut pending_hints, has_commit)?;
    validate_dependency_depths(&inputs, &ids, &offsets, limits, &mut budget, deadline)?;
    let mut dependencies: BTreeMap<GitOid, BTreeSet<GitOid>> = BTreeMap::new();
    for object in &inputs {
        check(deadline)?;
        let PackObject::Delta(delta) = object else {
            continue;
        };
        let id = *ids
            .get(&delta.offset)
            .ok_or_else(|| invalid("unresolved delta target"))?;
        let base = match &delta.base {
            DeltaBase::Ofs(at) => *ids.get(at).ok_or_else(|| invalid("unresolved OFS base"))?,
            DeltaBase::Ref(id) if objects.contains_key(id) => *id,
            DeltaBase::Ref(_) => continue,
        };
        dependencies.entry(id).or_default().insert(base);
    }
    check(deadline)?;
    Ok(Unpacked {
        objects,
        expanded_bytes,
        dependencies,
    })
}

/// Cached bytes do not carry their original chain depth. Re-derive that depth
/// from the original pack edges after every native identity is known, so an
/// earlier cache hit cannot hide a long backward OFS or discovered REF chain.
fn validate_dependency_depths(
    inputs: &[PackObject],
    ids: &BTreeMap<u64, GitOid>,
    offsets: &BTreeMap<u64, usize>,
    limits: &PackLimits,
    budget: &mut ResolutionBudget,
    deadline: &mut impl fgit_pack::Deadline,
) -> Result<(), BundleInspectionRefusal> {
    let mut by_id = BTreeMap::new();
    for (location, id) in ids {
        check(deadline)?;
        budget.charge_work(1, limits)?;
        by_id.insert(*id, *location);
    }
    let mut parents = BTreeMap::new();
    let mut depths = BTreeMap::new();
    for input in inputs {
        check(deadline)?;
        budget.charge_work(1, limits)?;
        match input {
            PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => {
                depths.insert(*offset, 0usize);
            }
            PackObject::Delta(delta) => {
                let parent = match &delta.base {
                    DeltaBase::Ofs(base) => {
                        if !offsets.contains_key(base) {
                            return Err(PackError::MissingDeltaBase.into());
                        }
                        Some(*base)
                    }
                    DeltaBase::Ref(base) => by_id.get(base).copied(),
                };
                parents.insert(delta.offset, parent);
            }
        }
    }
    for location in offsets.keys() {
        check(deadline)?;
        budget.charge_work(1, limits)?;
        let mut current = *location;
        let mut chain = Vec::new();
        let mut active = BTreeSet::new();
        let mut depth = loop {
            check(deadline)?;
            budget.charge_work(1, limits)?;
            if let Some(depth) = depths.get(&current) {
                break *depth;
            }
            if !active.insert(current) {
                return Err(PackError::DeltaCycle.into());
            }
            let minimum = chain
                .len()
                .checked_add(1)
                .ok_or(PackError::IntegerOverflow {
                    context: "inspection delta depth",
                })?;
            if minimum > limits.max_delta_depth {
                return Err(PackError::DeltaDepthLimit {
                    depth: minimum,
                    limit: limits.max_delta_depth,
                }
                .into());
            }
            chain
                .try_reserve(1)
                .map_err(|_| BundleInspectionRefusal::BudgetExceeded)?;
            chain.push(current);
            match parents.get(&current).ok_or(PackError::MissingDeltaBase)? {
                Some(parent) => current = *parent,
                None => break 0,
            }
        };
        while let Some(location) = chain.pop() {
            check(deadline)?;
            budget.charge_work(1, limits)?;
            depth = depth.checked_add(1).ok_or(PackError::IntegerOverflow {
                context: "inspection delta depth",
            })?;
            if depth > limits.max_delta_depth {
                return Err(PackError::DeltaDepthLimit {
                    depth,
                    limit: limits.max_delta_depth,
                }
                .into());
            }
            depths.insert(location, depth);
        }
    }
    check(deadline)
}

const fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}
fn check(deadline: &mut impl fgit_pack::Deadline) -> Result<(), BundleInspectionRefusal> {
    if deadline.checkpoint() {
        Ok(())
    } else {
        Err(PackError::DeadlineExceeded.into())
    }
}
