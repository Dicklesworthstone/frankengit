//! Required-kind closure verification at the production receive boundary.
//!
//! Hash-valid individual objects need not form a valid Git graph. Only the
//! requested uploaded closure is selected here; every native edge must resolve
//! to its required kind, including edges ending in the authenticated frontier.
//! Transport-only delta bases retain their existing closure responsibility.
use super::*;

// Bounds on additional verification state, independent of uploaded entry count.
// A single new tree may legitimately reference many already-selected objects.
const MAX_GRAPH_EDGES: usize = 4_000_000;
const MAX_FRONTIER_OBJECTS: usize = 1_000_000;

impl ProductionQuarantineValidator<'_> {
    pub(super) fn reachable_uploaded_closure(
        &self,
        request: &ReceiveRequest,
        verified: &BTreeMap<GitOid, VerifiedObject>,
        in_pack_delta_bases: &BTreeMap<GitOid, BTreeSet<GitOid>>,
        external_bases: &ExternalBases,
        deadline: &mut impl Deadline,
    ) -> Result<BTreeSet<GitOid>, RefusalCode> {
        let mut pending = BTreeSet::new();
        let mut closure = BTreeSet::new();
        let mut frontier_kinds = BTreeMap::new();
        let mut external_bytes = external_bases.read_bytes;
        let byte_limit = self.external_read_limit();
        if external_bytes > byte_limit { return Err(RefusalCode::ResourceBudgetExceeded); }
        // Every native edge occupies input bytes. The hard ceiling additionally
        // bounds work when an operator admits a larger expanded-byte envelope.
        let mut edges_left = self.pack_limits.max_total_expanded_bytes.min(MAX_GRAPH_EDGES);
        for command in &request.commands {
            checkpoint(deadline)?;
            if command.new.is_zero() { continue; }
            if !verified.contains_key(&command.new) {
                return Err(RefusalCode::ObjectClosureIncomplete);
            }
            pending.insert(command.new);
        }
        while let Some(id) = pending.pop_first() {
            checkpoint(deadline)?;
            if !closure.insert(id) { continue; }
            let object = verified.get(&id).ok_or(RefusalCode::ObjectClosureIncomplete)?;
            if let Some(bases) = in_pack_delta_bases.get(&id) {
                for base in bases {
                    checkpoint(deadline)?;
                    charge_edge(&mut edges_left)?;
                    let base_object = verified.get(base).ok_or(RefusalCode::ObjectClosureIncomplete)?;
                    require_kind(base_object.object_type, object.object_type)?;
                    pending.insert(*base);
                }
            }
            let edges = self.typed_object_references(object, &mut edges_left, deadline)?;
            for (child, expected) in edges {
                checkpoint(deadline)?;
                if child.is_zero() || child.algorithm() != self.node.object_format {
                    return Err(RefusalCode::ObjectHeaderInvalid);
                }
                if let Some(uploaded) = verified.get(&child) {
                    // Check EVERY edge, even when its target was visited before:
                    // one object cannot satisfy contradictory kind requirements.
                    require_kind(uploaded.object_type, expected)?;
                    pending.insert(child);
                    continue;
                }
                if !self.selected_closure.closure().objects().contains(&child) {
                    return Err(RefusalCode::ObjectClosureIncomplete);
                }
                let actual = if let Some(base) = external_bases.bases.get(&child) {
                    // This body already passed exact native verification and its
                    // bytes were charged before delta reconstruction.
                    base.object_type
                } else if let Some(kind) = frontier_kinds.get(&child) {
                    *kind
                } else {
                    if frontier_kinds.len() >= MAX_FRONTIER_OBJECTS {
                        return Err(RefusalCode::ResourceBudgetExceeded);
                    }
                    let remaining = byte_limit.checked_sub(external_bytes)
                        .ok_or(RefusalCode::ResourceBudgetExceeded)?;
                    let loaded = self.load_selected_external_base(child, remaining, deadline)?
                        .ok_or(RefusalCode::ObjectClosureIncomplete)?;
                    external_bytes = external_bytes.checked_add(loaded.body.len())
                        .filter(|n| *n <= byte_limit).ok_or(RefusalCode::ResourceBudgetExceeded)?;
                    // Retain only a verified kind, not every original body. This
                    // is a per-call cache, never a second authority source.
                    frontier_kinds.insert(child, loaded.object_type);
                    loaded.object_type
                };
                require_kind(actual, expected)?;
            }
        }
        checkpoint(deadline)?;
        Ok(closure)
    }

    fn typed_object_references(
        &self, object: &VerifiedObject, edges_left: &mut usize,
        deadline: &mut impl Deadline,
    ) -> Result<Vec<(GitOid, ObjectType)>, RefusalCode> {
        // Source selection and graph traversal remain distinct. Only native
        // edge interpretation is shared with complete local-source imports.
        crate::loose_import::graph::references(
            self.node.object_format, &object.parsed, &object.body,
            &self.parse_limits, edges_left, deadline,
        )
    }
}

fn require_kind(actual: ObjectType, expected: ObjectType) -> Result<(), RefusalCode> {
    if actual == expected { Ok(()) } else { Err(RefusalCode::EvidenceInvalid) }
}
fn charge_edge(remaining: &mut usize) -> Result<(), RefusalCode> {
    *remaining = remaining.checked_sub(1).ok_or(RefusalCode::ResourceBudgetExceeded)?;
    Ok(())
}

#[cfg(test)]
mod tests;
