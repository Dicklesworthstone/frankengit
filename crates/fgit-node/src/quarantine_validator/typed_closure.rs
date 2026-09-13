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
#[derive(Clone, Copy, Eq, PartialEq)]
enum ClosureProfile { Receive, FullBundle, IncrementalBundle }


impl ProductionQuarantineValidator<'_> {
    pub(super) fn reachable_uploaded_closure(
        &self,
        request: &ReceiveRequest,
        verified: &BTreeMap<GitOid, VerifiedObject>,
        in_pack_delta_bases: &BTreeMap<GitOid, BTreeSet<GitOid>>,
        external_bases: &ExternalBases,
        independent_uploads: &BTreeSet<GitOid>,
        deadline: &mut impl Deadline,
    ) -> Result<BTreeSet<GitOid>, RefusalCode> {
        self.reachable_uploaded_closure_profile(request, verified, in_pack_delta_bases,
            external_bases, independent_uploads, ClosureProfile::Receive, deadline)
    }

    fn reachable_uploaded_closure_profile(
        &self, request: &ReceiveRequest, verified: &BTreeMap<GitOid, VerifiedObject>,
        in_pack_delta_bases: &BTreeMap<GitOid, BTreeSet<GitOid>>,
        external_bases: &ExternalBases, independent_uploads: &BTreeSet<GitOid>,
        profile: ClosureProfile, deadline: &mut impl Deadline,
    ) -> Result<BTreeSet<GitOid>, RefusalCode> {
        let mut pending = BTreeSet::new();
        let mut originals = reused_targets::OriginalFrontier::new(self, external_bases)?;
        // Every native edge occupies input bytes. The hard ceiling additionally
        // bounds work when an operator admits a larger expanded-byte envelope.
        let mut edges_left = self.pack_limits.max_total_expanded_bytes.min(MAX_GRAPH_EDGES);
        let mut closure = BTreeSet::new();
        let mut required = BTreeMap::new();
        // A provided full body (or a delta grounded only in provided bytes)
        // does not need existing-history permission. A delta RESULT with the
        // same OID as its original base does: identity is not provenance.
        for (id, base) in &external_bases.bases {
            checkpoint(deadline)?;
            if !independent_uploads.contains(id) {
                require_original(&mut required, *id, Some(base.object_type))?;
            }
        }
        for command in &request.commands {
            checkpoint(deadline)?;
            if command.new.is_zero() { continue; }
            if let Some(object) = verified.get(&command.new) {
                if profile != ClosureProfile::Receive && command.ref_name.as_slice().starts_with(b"refs/heads/") {
                    require_kind(object.object_type, ObjectType::Commit)?;
                }
                pending.insert(command.new);
            } else {
                let kind = (profile != ClosureProfile::Receive && command.ref_name.starts_with(b"refs/heads/"))
                    .then_some(ObjectType::Commit);
                require_original(&mut required, command.new, kind)?;
                closure.insert(command.new);
            }
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
                require_original(&mut required, child, Some(expected))?;
            }
        }
        // One proof over the entire original dependency set, not one walk per
        // tree entry or a check confined to omitted command roots. Originals
        // used for reconstruction and graph verification share one byte ledger.
        if profile == ClosureProfile::FullBundle && !required.is_empty() {
            return Err(RefusalCode::ObjectClosureIncomplete);
        }
        let identities = required.keys().copied().collect();
        originals.authorize(&identities, &mut edges_left, deadline)?;
        for (id, expected) in required {
            checkpoint(deadline)?;
            let actual = originals.kind(id, deadline)?;
            if let Some(expected) = expected { require_kind(actual, expected)?; }
        }
        checkpoint(deadline)?;
        Ok(closure)
    }


    /// Complete-bundle intake deliberately supplies no external delta bases and
    /// refuses every omitted graph edge, even when current storage could satisfy
    /// it. Ordinary receive keeps its existing authenticated borrowing profile.
    /// Native reconstruction, required-kind traversal and staging are shared.
    pub(crate) fn validate_full_bundle(
        &self, request: &ReceiveRequest, pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt, deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        self.validate_bundle_profile(request, pack, receipt, None, false, deadline)
    }

    pub(crate) fn validate_bundle_fetch(
        &self, request: &ReceiveRequest, pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt, deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        self.validate_bundle_profile(request, pack, receipt, None, true, deadline)
    }

    /// Only a prerequisite already reachable from the current visible refs can
    /// seed borrowing. After that proof, every omitted dependency and external
    /// delta base must be reachable from the DECLARED prerequisite frontier.
    pub(crate) fn validate_incremental_bundle(
        &self, request: &ReceiveRequest, pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt, prerequisites: &[GitOid], deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        self.validate_bundle_profile(request, pack, receipt, Some(prerequisites), false, deadline)
    }

    fn validate_bundle_profile(
        &self, request: &ReceiveRequest, pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt, prerequisites: Option<&[GitOid]>, fetch: bool, deadline: &mut impl Deadline,
    ) -> Result<ValidatedClosure, RefusalCode> {
        checkpoint(deadline)?;
        let pack = pack.ok_or(RefusalCode::ObjectClosureIncomplete)?;
        if request.deletes_only() || receipt.delete_only
            || request.commands.iter().any(|command| command.new.is_zero()
                || (prerequisites.is_none() && !fetch && !command.old.is_zero()))
            || u32::try_from(pack.entries().len()).ok() != Some(receipt.object_count) {
            return Err(RefusalCode::PackFramingInvalid);
        }
        if pack.format != receipt.object_format || pack.format != self.node.object_format {
            return Err(RefusalCode::HashAlgorithmDomainMismatch);
        }
        let mut restricted = None;
        let mut bytes_read = 0;
        if let Some(prerequisites) = prerequisites {
            if prerequisites.len() > fgit_pack::full_bundle::MAX_BUNDLE_PREREQUISITES {
                return Err(RefusalCode::ResourceBudgetExceeded);
            }
            let required: BTreeSet<_> = prerequisites.iter().copied().collect();
            if required.len() != prerequisites.len() { return Err(RefusalCode::EvidenceInvalid); }
            let empty = ExternalBases { bases: BTreeMap::new(), read_bytes: 0 };
            let mut originals = reused_targets::OriginalFrontier::new(self, &empty)?;
            let mut edges = self.pack_limits.max_total_expanded_bytes.min(MAX_GRAPH_EDGES);
            let complete = originals.prerequisite_closure(&required, &mut edges, deadline)?;
            bytes_read = originals.read_bytes();
            restricted = Some(ProductionQuarantineValidator {
                node: self.node, selected_closure: self.selected_closure.clone(),
                visible_roots: complete, pack_limits: self.pack_limits.clone(),
                parse_limits: self.parse_limits.clone(),
            });
        }
        let validator = restricted.as_ref().unwrap_or(self);
        let bases = if prerequisites.is_some() {
            // Continue the original-input ledger; proving prerequisite visibility
            // does not mint a new byte envelope for delta or graph reads.
            validator.external_bases_with_initial_bytes(pack, bytes_read, Some(&validator.visible_roots), deadline)?
        } else { ExternalBases { bases: BTreeMap::new(), read_bytes: 0 } };
        let (mut verified, offsets) = validator.verified_pack_objects(pack, &bases, deadline)?;
        let delta_bases = Self::in_pack_delta_bases(pack, &offsets, deadline)?;
        let independent = reused_targets::independent_uploads(pack, &offsets, deadline)?;
        let profile = if prerequisites.is_some() { ClosureProfile::IncrementalBundle }
            else { ClosureProfile::FullBundle };
        let closure = validator.reachable_uploaded_closure_profile(
            request, &verified, &delta_bases, &bases, &independent, profile, deadline,
        )?;
        if fetch {
            require_fetch_fast_forwards(request, &verified,
                self.pack_limits.max_total_expanded_bytes.min(MAX_GRAPH_EDGES), deadline)?;
        }
        for id in &closure {
            checkpoint(deadline)?;
            if let Some(object) = verified.remove(id) {
                validator.stage(*id, object.object_type, object.body, deadline)?;
            } else if !validator.selected_closure.closure().objects().contains(id) {
                return Err(RefusalCode::ObjectClosureIncomplete);
            }
        }
        checkpoint(deadline)?;
        Ok(ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(closure.clone()))?,
            objects: closure,
        })
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

/// Native commit ancestry, never tree reachability or caller-provided parentage.
/// One work budget is shared across all selected refs and all parent edges.
fn require_fetch_fast_forwards(
    request: &ReceiveRequest, verified: &BTreeMap<GitOid, VerifiedObject>,
    mut work: usize, deadline: &mut impl Deadline,
) -> Result<(), RefusalCode> {
    for command in &request.commands {
        checkpoint(deadline)?;
        let is_tag = command.ref_name.starts_with(b"refs/tags/");
        let is_branch = command.ref_name.starts_with(b"refs/heads/")
            || command.ref_name.starts_with(b"refs/remotes/");
        if !is_tag && !is_branch { return Err(RefusalCode::RefNameInvalid); }
        if is_branch {
            let target = verified.get(&command.new).ok_or(RefusalCode::ObjectClosureIncomplete)?;
            require_kind(target.object_type, ObjectType::Commit)?;
        }
        if command.old.is_zero() || command.old == command.new { continue; }
        if is_tag { return Err(RefusalCode::NonFastForwardRefused); }
        let mut pending = BTreeSet::from([command.new]);
        let mut seen = BTreeSet::new();
        let mut found = false;
        while let Some(id) = pending.pop_first() {
            checkpoint(deadline)?;
            charge_edge(&mut work)?;
            if !seen.insert(id) { continue; }
            let object = verified.get(&id).ok_or(RefusalCode::ObjectClosureIncomplete)?;
            let ParsedObject::Commit(commit) = &object.parsed else {
                return Err(RefusalCode::EvidenceInvalid);
            };
            if id == command.old { found = true; break; }
            for parent in commit.parent_references() {
                checkpoint(deadline)?;
                charge_edge(&mut work)?;
                let parent = std::str::from_utf8(parent).ok()
                    .and_then(|text| GitOid::from_hex(command.new.algorithm(), &text.to_ascii_lowercase()).ok())
                    .ok_or(RefusalCode::ObjectHeaderInvalid)?;
                if !seen.contains(&parent) { pending.insert(parent); }
            }
        }
        if !found { return Err(RefusalCode::NonFastForwardRefused); }
    }
    checkpoint(deadline)
}

fn require_original(
    required: &mut BTreeMap<GitOid, Option<ObjectType>>, id: GitOid, expected: Option<ObjectType>,
) -> Result<(), RefusalCode> {
    if id.is_zero() { return Err(RefusalCode::ObjectHeaderInvalid); }
    if let Some(previous) = required.get_mut(&id) {
        if let (Some(actual), Some(expected)) = (*previous, expected) { require_kind(actual, expected)?; }
        if previous.is_none() { *previous = expected; }
    } else {
        if required.len() >= reused_targets::MAX_ORIGINAL_OBJECTS {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        required.insert(id, expected);
    }
    Ok(())
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
