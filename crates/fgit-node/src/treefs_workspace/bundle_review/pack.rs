//! Stage-free use of the existing pack inflater and typed delta resolver.
//! Native identities are discovered in bounded passes, allowing forward REF
//! bases without trusting an uploaded index or widening original-object scope.

use super::{
    AcceptanceProfile, BTreeMap, BTreeSet, BundleInspectionRefusal, GitHashAlgorithm, GitOid,
    MergeObjectLimits, ObjectType, OriginalSource, PackError, PackLimits, ParseLimits,
    PlannedMergeObject, git_object_id, invalid, reachability,
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
            if covered.insert(id) {
                if let Some(bases) = self.dependencies.get(&id) {
                    pending.extend(bases.iter().copied());
                }
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
    reconstruct(parsed, format, limits, original, &mut live)
}

#[derive(Default)]
struct ExternalBases(BTreeMap<GitOid, (ObjectType, Vec<u8>)>);
impl ExternalBaseLookup for ExternalBases {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> {
        self.0.get(id).map(|(_, body)| body.as_slice())
    }
    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.0.get(id).map(|(kind, body)| (*kind, body.as_slice()))
    }
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
    let mut external_attempted = false;
    let parse_limits = ParseLimits {
        max_object_bytes: limits.max_object_bytes,
        tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    };
    for _ in 0..=limits.max_delta_depth {
        check(deadline)?;
        let mut newly_resolved = Vec::new();
        let mut pending_bytes = 0usize;
        loop {
            {
                let mut resolver = CachedResolver::new(&inputs, &bases, limits, deadline)?;
                for location in offsets.keys() {
                    check(deadline)?;
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
            if !newly_resolved.is_empty() || external_attempted || ids.len() == inputs.len() {
                break;
            }
            // Exhaust pack-local progress before looking up original bytes.
            // In particular, a selected hidden object supplied in this pack is
            // a transport base, not a request to disclose it from repository
            // history. Only unresolved native REF identities need permission.
            external_attempted = true;
            let mut base_bytes = 0usize;
            for input in &inputs {
                original.live().map_err(BundleInspectionRefusal::Source)?;
                let PackObject::Delta(delta) = input else {
                    continue;
                };
                let DeltaBase::Ref(base) = &delta.base else {
                    continue;
                };
                if objects.contains_key(base)
                    || bases.0.contains_key(base)
                    || !original
                        .permits(*base)
                        .map_err(BundleInspectionRefusal::Source)?
                {
                    continue;
                }
                let (kind, body) = original
                    .read(*base)
                    .map_err(BundleInspectionRefusal::Source)?;
                base_bytes = base_bytes
                    .checked_add(body.len())
                    .filter(|total| *total <= limits.max_cached_bytes)
                    .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
                bases.0.insert(*base, (kind, body));
            }
            if bases.0.is_empty() {
                break;
            }
            // Retry this same pass once with authorized external bases. The
            // original ResolutionBudget and outer depth/pass limit still apply.
        }
        if newly_resolved.is_empty() {
            break;
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
            let index = *offsets
                .get(&location)
                .ok_or_else(|| invalid("missing pack offset"))?;
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
