//! Stage-free use of the existing pack inflater and typed delta resolver.
//! Native identities are discovered in bounded passes, allowing forward REF
//! bases without trusting an uploaded index or widening original-object scope.

use super::*;
use fgit_pack::{CachedResolver, DeltaBase, ExternalBaseLookup, NativeChecksumVerifier, PackObject,
    ParsedDeltaBase, QuarantinedPack, ResolutionBudget, read_verified_pack, verify_native_object};

pub(super) struct Unpacked {
    pub objects: BTreeMap<GitOid, PlannedMergeObject>,
    pub expanded_bytes: usize,
    dependencies: BTreeMap<GitOid, BTreeSet<GitOid>>,
}
impl Unpacked {
    /// An extra uploaded object is not silently hidden from review. Permit
    /// only Git-reachable objects and their transitive pack-local delta bases;
    /// the latter are counted separately and never called candidate content.
    pub(super) fn check_coverage(&self, closure: &BTreeSet<GitOid>) -> Result<usize, BundleInspectionRefusal> {
        let mut pending: BTreeSet<_> = self.objects.keys().filter(|id| closure.contains(*id)).copied().collect();
        let graph_objects = pending.len();
        let mut covered = BTreeSet::new();
        while let Some(id) = pending.pop_first() {
            if !covered.insert(id) { continue; }
            if let Some(bases) = self.dependencies.get(&id) { pending.extend(bases.iter().copied()); }
        }
        if covered.len() != self.objects.len() {
            return Err(invalid("pack includes objects unrelated to the candidate or its delta reconstruction"));
        }
        Ok(covered.len() - graph_objects)
    }
}

pub(super) fn unpack(
    input: &[u8], format: GitHashAlgorithm, limits: &PackLimits, original: &OriginalSource<'_>,
) -> Result<Unpacked, BundleInspectionRefusal> {
    let mut live = || original.live().is_ok();
    let parsed = read_verified_pack(input, format, limits, &mut live, &NativeChecksumVerifier)?;
    let mut bases = ExternalBases::default();
    let mut base_bytes = 0usize;
    for entry in parsed.entries() {
        original.live().map_err(BundleInspectionRefusal::Source)?;
        let Some(ParsedDeltaBase::Ref { base, .. }) = &entry.delta_base else { continue; };
        if bases.0.contains_key(base) || !original.allowed.contains(base) { continue; }
        let (kind, body) = original.read(*base).map_err(BundleInspectionRefusal::Source)?;
        base_bytes = base_bytes.checked_add(body.len()).filter(|total| *total <= limits.max_cached_bytes)
            .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
        bases.0.insert(*base, (kind, body));
    }
    reconstruct(parsed, format, limits, &bases, &mut live)
}

#[derive(Default)]
struct ExternalBases(BTreeMap<GitOid, (ObjectType, Vec<u8>)>);
impl ExternalBaseLookup for ExternalBases {
    fn lookup(&self, id: &GitOid) -> Option<&[u8]> { self.0.get(id).map(|(_, body)| body.as_slice()) }
    fn lookup_typed(&self, id: &GitOid) -> Option<(ObjectType, &[u8])> {
        self.0.get(id).map(|(kind, body)| (*kind, body.as_slice()))
    }
}

fn reconstruct(
    pack: QuarantinedPack, format: GitHashAlgorithm, limits: &PackLimits,
    bases: &ExternalBases, deadline: &mut impl fgit_pack::Deadline,
) -> Result<Unpacked, BundleInspectionRefusal> {
    let mut inputs = pack.into_scalar_objects(|_| None)?;
    let offsets: BTreeMap<_, _> = inputs.iter().enumerate().map(|(index, object)| (offset(object), index)).collect();
    if offsets.len() != inputs.len() { return Err(invalid("duplicate pack offset")); }
    let mut objects = BTreeMap::new();
    let mut ids = BTreeMap::new();
    let mut expanded_bytes = 0usize;
    let mut budget = ResolutionBudget::new();
    let parse_limits = ParseLimits {
        max_object_bytes: limits.max_object_bytes, tree_reference_bytes: format.digest_len(),
        ..ParseLimits::default()
    };
    for _ in 0..=limits.max_delta_depth {
        check(deadline)?;
        let mut newly_resolved = Vec::new();
        let mut pending_bytes = 0usize;
        {
            let mut resolver = CachedResolver::new(&inputs, bases, limits, deadline)?;
            for location in offsets.keys() {
                check(deadline)?;
                if ids.contains_key(location) { continue; }
                match resolver.resolve_offset_typed_with_budget(*location, &mut budget, deadline) {
                    Ok((kind, body)) => {
                        pending_bytes = pending_bytes.checked_add(body.len())
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
        if newly_resolved.is_empty() { break; }
        for (location, kind, body) in newly_resolved {
            check(deadline)?;
            let id = git_object_id(format, kind, &body);
            let parsed = verify_native_object(format, kind, &body, &id,
                AcceptanceProfile::GitCompatibleImport, &parse_limits)?;
            drop(parsed);
            check(deadline)?;
            expanded_bytes = expanded_bytes.checked_add(body.len()).filter(|total| *total <= limits.max_total_expanded_bytes)
                .ok_or(BundleInspectionRefusal::BudgetExceeded)?;
            if objects.insert(id, PlannedMergeObject { id, kind, body }).is_some() || ids.insert(location, id).is_some() {
                return Err(invalid("duplicate native object in candidate pack"));
            }
            let index = *offsets.get(&location).ok_or_else(|| invalid("missing pack offset"))?;
            match &mut inputs[index] {
                PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => *slot = Some(id),
                PackObject::Delta(delta) => delta.id = Some(id),
            }
        }
        if objects.len() == inputs.len() { break; }
    }
    if objects.len() != inputs.len() { return Err(PackError::MissingDeltaBase.into()); }
    let mut dependencies: BTreeMap<GitOid, BTreeSet<GitOid>> = BTreeMap::new();
    for object in &inputs {
        check(deadline)?;
        let PackObject::Delta(delta) = object else { continue; };
        let id = *ids.get(&delta.offset).ok_or_else(|| invalid("unresolved delta target"))?;
        let base = match &delta.base {
            DeltaBase::Ofs(at) => *ids.get(at).ok_or_else(|| invalid("unresolved OFS base"))?,
            DeltaBase::Ref(id) if objects.contains_key(id) => *id,
            DeltaBase::Ref(_) => continue,
        };
        dependencies.entry(id).or_default().insert(base);
    }
    check(deadline)?;
    Ok(Unpacked { objects, expanded_bytes, dependencies })
}
fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}
fn check(deadline: &mut impl fgit_pack::Deadline) -> Result<(), BundleInspectionRefusal> {
    if deadline.checkpoint() { Ok(()) } else { Err(PackError::DeadlineExceeded.into()) }
}
