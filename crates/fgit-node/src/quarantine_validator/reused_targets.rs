//! Visible-source proofs for every original dependency consumed by a receive.
//!
//! Prior admission is necessary, not sufficient: every reused root and
//! dependency must be reachable from visible refs at the materialization selecting
//! this validator. The per-call reader shares its original-input ledger and
//! verified-kind cache with ordinary uploaded-graph frontier checks.

use super::*;

pub(super) const MAX_ORIGINAL_OBJECTS: usize = 1_000_000;

pub(super) struct OriginalFrontier<'a, 'node> {
    validator: &'a ProductionQuarantineValidator<'node>,
    bases: &'a ExternalBases,
    bytes: usize,
    kinds: BTreeMap<GitOid, ObjectType>,
    authorized: BTreeSet<GitOid>,
}

impl<'a, 'node> OriginalFrontier<'a, 'node> {
    pub(super) fn new(
        validator: &'a ProductionQuarantineValidator<'node>,
        bases: &'a ExternalBases,
    ) -> Result<Self, RefusalCode> {
        if bases.read_bytes > validator.external_read_limit() {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(Self { validator, bases, bytes: bases.read_bytes, kinds: BTreeMap::new(), authorized: BTreeSet::new() })
    }

    pub(super) fn kind(
        &mut self, id: GitOid, deadline: &mut impl Deadline,
    ) -> Result<ObjectType, RefusalCode> {
        checkpoint(deadline)?;
        if !self.authorized.contains(&id) { return Err(RefusalCode::ObjectClosureIncomplete); }
        self.read_kind(id, deadline)
    }

    fn read_kind(&mut self, id: GitOid, deadline: &mut impl Deadline)
        -> Result<ObjectType, RefusalCode>
    {
        checkpoint(deadline)?;
        self.require_selected(id)?;
        if let Some(kind) = self.kinds.get(&id) { return Ok(*kind); }
        self.with_object(id, deadline, |kind, _, _| Ok(kind))
    }

    fn require_selected(&self, id: GitOid) -> Result<(), RefusalCode> {
        if id.is_zero() || id.algorithm() != self.validator.node.object_format {
            return Err(RefusalCode::ObjectHeaderInvalid);
        }
        if !self.validator.selected_closure.closure().objects().contains(&id) {
            return Err(RefusalCode::ObjectClosureIncomplete);
        }
        Ok(())
    }

    fn with_object<D: Deadline, R>(
        &mut self, id: GitOid, deadline: &mut D,
        inspect: impl FnOnce(ObjectType, &[u8], &mut D) -> Result<R, RefusalCode>,
    ) -> Result<R, RefusalCode> {
        checkpoint(deadline)?;
        self.require_selected(id)?;
        if !self.kinds.contains_key(&id) && self.kinds.len() >= MAX_ORIGINAL_OBJECTS {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        // Delta bases were already verified and charged before reconstruction.
        // Borrow their bodies, never make or charge another original copy.
        let result = if let Some(base) = self.bases.bases.get(&id) {
            self.kinds.insert(id, base.object_type);
            inspect(base.object_type, &base.body, deadline)
        } else {
            let limit = self.validator.external_read_limit();
            let remaining = limit.checked_sub(self.bytes)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
            let object = self.validator.load_selected_external_base(id, remaining, deadline)?
                .ok_or(RefusalCode::ObjectClosureIncomplete)?;
            self.bytes = self.bytes.checked_add(object.body.len())
                .filter(|bytes| *bytes <= limit).ok_or(RefusalCode::ResourceBudgetExceeded)?;
            self.kinds.insert(id, object.object_type);
            inspect(object.object_type, &object.body, deadline)
        };
        checkpoint(deadline)?;
        result
    }

    /// Establish all requested original inputs together, before any of their
    /// kinds can be consumed by admission. Upload edges are never proof paths:
    /// only previously authenticated visible roots seed this walk. A failed
    /// proof grants no partial set and cannot publish or stage any upload.
    pub(super) fn authorize(
        &mut self,
        required: &BTreeSet<GitOid>,
        edges_left: &mut usize,
        deadline: &mut impl Deadline,
    ) -> Result<(), RefusalCode> {
        self.authorized.clear();
        checkpoint(deadline)?;
        if required.len() > MAX_ORIGINAL_OBJECTS {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        for id in required { checkpoint(deadline)?; self.require_selected(*id)?; }
        if required.is_empty() { return Ok(()); }
        let mut wanted = required.clone();
        // Direct visible roots need no traversal, but their actual bodies
        // must exist, reproduce their native IDs and fit the shared budget.
        if wanted.iter().all(|id| self.validator.visible_roots.contains(id)) {
            for id in &wanted { self.read_kind(*id, deadline)?; }
            checkpoint(deadline)?;
            self.authorized = required.clone();
            return Ok(());
        }
        let mut pending = Vec::new();
        let mut requirements = BTreeMap::new();
        for id in self.validator.visible_roots.iter().rev() {
            enqueue(*id, None, &mut pending, &mut requirements, &self.kinds, deadline)?;
        }
        // A root is visited once. Every subsequently discovered kind
        // requirement is nevertheless checked, including after that visit.
        while let Some(id) = pending.pop() {
            checkpoint(deadline)?;
            let expected = requirements.get(&id).copied().flatten();
            if wanted.len() == 1 && wanted.contains(&id) {
                let actual = self.read_kind(id, deadline)?;
                check_kind(actual, expected)?;
                checkpoint(deadline)?;
                self.authorized = required.clone();
                return Ok(());
            }
            // Irrelevant file contents cannot lead to a wanted object. Do not
            // read/copy their bodies just to prove reachability elsewhere.
            // Their edge constraints still live in `requirements`; no claim
            // of a complete historical fsck is made by this proof.
            if expected == Some(ObjectType::Blob) && !wanted.contains(&id) { continue; }
            let format = self.validator.node.object_format;
            let limits = self.validator.parse_limits.clone();
            let (actual, edges) = self.with_object(id, deadline, |kind, body, deadline| {
                let parsed = fgit_git_object::parse_object_body(
                    kind, body, AcceptanceProfile::GitCompatibleImport, &limits,
                ).map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                let edges = crate::loose_import::graph::references(
                    format, &parsed, body, &limits, edges_left, deadline,
                )?;
                Ok((kind, edges))
            })?;
            check_kind(actual, expected)?;
            wanted.remove(&id);
            // Stored edges are traversed deterministically. Commit parents are
            // visited ahead of their trees, avoiding file-body work on the
            // usual existing-ancestor branch creation path.
            for (child, kind) in edges {
                enqueue(child, Some(kind), &mut pending, &mut requirements, &self.kinds, deadline)?;
            }
        }
        // An uploaded wrapper commit/tree or a delta program cannot revive
        // hidden-only/disconnected input any more than an omitted root can.
        Err(RefusalCode::ObjectClosureIncomplete)
    }
}

fn check_kind(actual: ObjectType, expected: Option<ObjectType>) -> Result<(), RefusalCode> {
    if expected.is_some_and(|kind| kind != actual) { Err(RefusalCode::EvidenceInvalid) }
    else { Ok(()) }
}

fn enqueue(
    id: GitOid, expected: Option<ObjectType>, pending: &mut Vec<GitOid>,
    requirements: &mut BTreeMap<GitOid, Option<ObjectType>>,
    kinds: &BTreeMap<GitOid, ObjectType>, deadline: &mut impl Deadline,
) -> Result<(), RefusalCode> {
    checkpoint(deadline)?;
    if let Some(actual) = kinds.get(&id) { check_kind(*actual, expected)?; }
    if let Some(previous) = requirements.get_mut(&id) {
        if let (Some(previous), Some(expected)) = (*previous, expected) {
            if previous != expected { return Err(RefusalCode::EvidenceInvalid); }
        }
        if previous.is_none() { *previous = expected; }
        return Ok(());
    }
    if requirements.len() >= MAX_ORIGINAL_OBJECTS {
        return Err(RefusalCode::ResourceBudgetExceeded);
    }
    pending.try_reserve(1).map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
    requirements.insert(id, expected);
    pending.push(id);
    Ok(())
}

/// Identify bodies derivable wholly from uploaded bytes, without originals.
/// Hash equality with an uploaded RESULT alone is insufficient: a delta may
/// copy its hidden external base verbatim and produce that very same OID.
/// Full entries seed this dependency walk; unseeded REF cycles do not.
pub(super) fn independent_uploads(
    pack: &QuarantinedPack, ids: &BTreeMap<u64, GitOid>, deadline: &mut impl Deadline,
) -> Result<BTreeSet<GitOid>, RefusalCode> {
    let mut independent = BTreeSet::new();
    let mut pending = Vec::new();
    let mut dependents: BTreeMap<GitOid, Vec<GitOid>> = BTreeMap::new();
    for entry in pack.entries() {
        checkpoint(deadline)?;
        let id = *ids.get(&entry.offset).ok_or(RefusalCode::PackFramingInvalid)?;
        let base = match entry.delta_base.as_ref() {
            None => {
                if independent.insert(id) {
                    pending.try_reserve(1).map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
                    pending.push(id);
                }
                continue;
            }
            Some(ParsedDeltaBase::Ofs { base_offset, .. }) =>
                *ids.get(base_offset).ok_or(RefusalCode::PackFramingInvalid)?,
            Some(ParsedDeltaBase::Ref { base, .. }) => *base,
        };
        let children = dependents.entry(base).or_default();
        children.try_reserve(1).map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
        children.push(id);
    }
    while let Some(base) = pending.pop() {
        checkpoint(deadline)?;
        if let Some(children) = dependents.remove(&base) {
            for child in children {
                checkpoint(deadline)?;
                if independent.insert(child) {
                    pending.try_reserve(1).map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
                    pending.push(child);
                }
            }
        }
    }
    checkpoint(deadline)?;
    Ok(independent)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod visibility_tests;
