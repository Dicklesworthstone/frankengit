//! Required-kind closure verification at the production receive boundary.
//!
//! Hash-valid individual objects need not form a valid Git graph. Only the
//! requested uploaded closure is selected here; every native edge must resolve
//! to its required kind, including edges ending in the authenticated frontier.
//! Transport-only delta bases retain their existing closure responsibility.
use super::*;
use fgit_git_object::{TagTargetType, parse_annotated_tag};

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
        let mut edges = Vec::new();
        match &object.parsed {
            ParsedObject::Blob(_) => {}
            ParsedObject::Tree(entries) => {
                for entry in entries {
                    checkpoint(deadline)?;
                    charge_edge(edges_left)?;
                    let mode = std::str::from_utf8(&entry.mode).ok()
                        .and_then(|mode| u32::from_str_radix(mode, 8).ok())
                        .ok_or(RefusalCode::ObjectHeaderInvalid)?;
                    let kind = match mode & 0o170_000 {
                        0o040_000 => ObjectType::Tree,
                        0o100_000 | 0o120_000 => ObjectType::Blob,
                        // Gitlinks are external-repository references, including
                        // import-tolerated octal spellings. They consume work,
                        // but do not authorize a local read or a dependency.
                        0o160_000 => continue,
                        _ => return Err(RefusalCode::ObjectHeaderInvalid),
                    };
                    push(&mut edges, self.native_reference_from_bytes(&entry.object_id)?, kind)?;
                }
            }
            ParsedObject::Commit(commit) => {
                let mut tree_count = 0usize;
                for header in commit.headers() {
                    checkpoint(deadline)?;
                    let kind = if header.name == b"tree" {
                        tree_count += 1;
                        ObjectType::Tree
                    } else if header.name == b"parent" {
                        ObjectType::Commit
                    } else { continue; };
                    // Generic import parsing preserves unusual headers. A
                    // publication walk cannot choose an arbitrary tree or drop
                    // continuation bytes while inventing an unambiguous edge.
                    if !header.continuations.is_empty() || tree_count > 1 {
                        return Err(RefusalCode::ObjectHeaderInvalid);
                    }
                    charge_edge(edges_left)?;
                    push(&mut edges, self.native_reference_from_hex(&header.value)?, kind)?;
                }
                if tree_count != 1 { return Err(RefusalCode::ObjectHeaderInvalid); }
            }
            ParsedObject::Tag(_) => {
                checkpoint(deadline)?;
                let tag = parse_annotated_tag(&object.body, self.node.object_format,
                    AcceptanceProfile::GitCompatibleImport, &self.parse_limits)
                    .map_err(|_| RefusalCode::ObjectHeaderInvalid)?;
                checkpoint(deadline)?;
                let target = tag.target();
                let kind = match target.object_type {
                    TagTargetType::Blob => ObjectType::Blob,
                    TagTargetType::Tree => ObjectType::Tree,
                    TagTargetType::Commit => ObjectType::Commit,
                    TagTargetType::Tag => ObjectType::Tag,
                };
                charge_edge(edges_left)?;
                push(&mut edges, target.oid, kind)?;
            }
        }
        Ok(edges)
    }
}

fn require_kind(actual: ObjectType, expected: ObjectType) -> Result<(), RefusalCode> {
    if actual == expected { Ok(()) } else { Err(RefusalCode::EvidenceInvalid) }
}
fn charge_edge(remaining: &mut usize) -> Result<(), RefusalCode> {
    *remaining = remaining.checked_sub(1).ok_or(RefusalCode::ResourceBudgetExceeded)?;
    Ok(())
}
fn push(edges: &mut Vec<(GitOid, ObjectType)>, oid: GitOid, kind: ObjectType) -> Result<(), RefusalCode> {
    if oid.is_zero() { return Err(RefusalCode::ObjectHeaderInvalid); }
    edges.try_reserve(1).map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
    edges.push((oid, kind));
    Ok(())
}

#[cfg(test)]
mod tests;
