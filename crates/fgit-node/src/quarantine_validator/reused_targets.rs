//! Reuse of native ref targets absent from an otherwise valid receive pack.
//!
//! Prior admission is necessary, not sufficient: each reused root must also
//! be reachable from a visible ref in the exact materialization that selected
//! this validator. The per-call reader shares its original-input ledger and
//! verified-kind cache with ordinary uploaded-graph frontier checks.

use super::*;

const MAX_ORIGINAL_OBJECTS: usize = 1_000_000;

pub(super) struct OriginalFrontier<'a, 'node> {
    validator: &'a ProductionQuarantineValidator<'node>,
    bases: &'a ExternalBases,
    bytes: usize,
    kinds: BTreeMap<GitOid, ObjectType>,
}

impl<'a, 'node> OriginalFrontier<'a, 'node> {
    pub(super) fn new(
        validator: &'a ProductionQuarantineValidator<'node>,
        bases: &'a ExternalBases,
    ) -> Result<Self, RefusalCode> {
        if bases.read_bytes > validator.external_read_limit() {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(Self { validator, bases, bytes: bases.read_bytes, kinds: BTreeMap::new() })
    }

    pub(super) fn kind(
        &mut self, id: GitOid, deadline: &mut impl Deadline,
    ) -> Result<ObjectType, RefusalCode> {
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

    /// Return exactly the requested roots missing from this upload. An empty
    /// result does not touch original objects or add costs to ordinary pushes.
    pub(super) fn reused_roots(
        &mut self,
        request: &ReceiveRequest,
        uploaded: &BTreeMap<GitOid, VerifiedObject>,
        edges_left: &mut usize,
        deadline: &mut impl Deadline,
    ) -> Result<BTreeSet<GitOid>, RefusalCode> {
        let mut wanted = BTreeSet::new();
        for command in &request.commands {
            checkpoint(deadline)?;
            if command.new.is_zero() || uploaded.contains_key(&command.new) { continue; }
            self.require_selected(command.new)?;
            if wanted.len() >= MAX_ORIGINAL_OBJECTS && !wanted.contains(&command.new) {
                return Err(RefusalCode::ResourceBudgetExceeded);
            }
            wanted.insert(command.new);
        }
        if wanted.is_empty() { return Ok(wanted); }
        let result = wanted.clone();
        // Copying a currently advertised tip needs no history traversal. Its
        // exact body must still exist, hash correctly and fit the same budget.
        if wanted.iter().all(|id| self.validator.visible_roots.contains(id)) {
            for id in &wanted { self.kind(*id, deadline)?; }
            checkpoint(deadline)?;
            return Ok(result);
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
                let actual = self.kind(id, deadline)?;
                check_kind(actual, expected)?;
                return Ok(result);
            }
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
        // Membership in the cumulative admitted set cannot revive a hidden-only
        // or no-longer-reachable object by making it the target of a new ref.
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

#[cfg(test)]
mod tests;
