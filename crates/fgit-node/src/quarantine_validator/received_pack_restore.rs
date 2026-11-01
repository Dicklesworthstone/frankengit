//! Reestablish received-pack custody from untrusted persisted bytes and hints.
//! No object is staged and no admission decision is made on this path.

use super::{
    BTreeMap, BTreeSet, Deadline, ExternalBase, ExternalBases, GitOid, ObjectBody, ObjectType,
    PackError, ParsedDeltaBase, ProductionQuarantineValidator, QuarantinedPack, RefusalCode,
    ResolutionBudget, StoreRefusal, checkpoint, copy_bytes, crypto_object_kind, map_pack_error,
};
use crate::fabric_object_kind;
use crate::received_pack::{PendingReceivedPack, VerifiedReceivedObject};
use fgit_crypto::git_payload_commitment;
use fgit_types::CANONICAL_CODEC_VERSION;

impl ProductionQuarantineValidator<'_> {
    /// Restore optional custody after bounded parsing of a persisted pack.
    ///
    /// `hints` are untrusted, even though their shape matches live verified
    /// metadata. Every identity, kind and length must be rederived from the
    /// actual pack and match an independently authenticated canonical payload.
    /// `authorized` is the current upload's selected/client-held set; cumulative
    /// admission membership alone never widens it. The caller retains one
    /// resolution budget across all candidates, including failed candidates.
    ///
    /// Invalid or unavailable cache evidence is a miss. Exhausted shared work
    /// returns `ResourceBudgetExceeded` so the caller stops trying candidates;
    /// its ordinary writer fallback remains available. Cancellation remains a
    /// stop condition for the whole request. A successful result has completed
    /// the fabric collision check and may be committed directly.
    pub(crate) fn restore_received_pack(
        &self,
        pack: &QuarantinedPack,
        hints: &[VerifiedReceivedObject],
        authorized: &BTreeSet<GitOid>,
        resolution_budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<Option<PendingReceivedPack>, RefusalCode> {
        checkpoint(deadline)?;
        let result = self.restore_received_pack_checked(
            pack,
            hints,
            authorized,
            resolution_budget,
            deadline,
        );
        // An expiry discovered after failed I/O still outranks cache damage.
        checkpoint(deadline)?;
        match result {
            Err(
                code @ (RefusalCode::CancellationInProgress | RefusalCode::ResourceBudgetExceeded),
            ) => Err(code),
            Err(_) => Ok(None),
            result => result,
        }
    }

    fn restore_received_pack_checked(
        &self,
        pack: &QuarantinedPack,
        hints: &[VerifiedReceivedObject],
        authorized: &BTreeSet<GitOid>,
        resolution_budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<Option<PendingReceivedPack>, RefusalCode> {
        if hints.is_empty()
            || hints.len() != pack.entries().len()
            || hints.len() > self.pack_limits.max_entries as usize
            || pack.format != self.node.object_format
            || pack.retained_bytes().is_none()
            || self.staging.is_some()
        {
            return Ok(None);
        }
        let retained = pack.retained_bytes().ok_or(RefusalCode::EvidenceMissing)?;
        if retained.bytes().len() > self.node.received_pack_cache().capture_limit()
            || retained.retained_capacity() > self.node.received_pack_cache().capture_limit()
        {
            return Ok(None);
        }
        let mut previous = None;
        let mut total = 0_usize;
        for hint in hints {
            checkpoint(deadline)?;
            resolution_budget
                .charge_work(1, &self.pack_limits)
                .map_err(restore_pack_refusal)?;
            if hint.id.is_zero()
                || hint.id.algorithm() != self.node.object_format
                || previous.is_some_and(|id| id >= hint.id)
                || !authorized.contains(&hint.id)
                || !self.selected_closure.closure().objects().contains(&hint.id)
                || hint.bytes > self.pack_limits.max_object_bytes
                || hint.bytes > self.parse_limits.max_object_bytes
            {
                return Ok(None);
            }
            total = total
                .checked_add(hint.bytes)
                .filter(|bytes| *bytes <= self.pack_limits.max_total_expanded_bytes)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
            previous = Some(hint.id);
        }

        let bases =
            self.restored_pack_bases(pack, hints, authorized, resolution_budget, deadline)?;
        let (verified, ids_at_offset, mut spool) = self.verified_pack_objects_with_budget(
            pack,
            &bases,
            resolution_budget,
            deadline,
            restore_pack_refusal,
        )?;
        // Resolution no longer needs these buffered canonical bases while
        // the independent per-object integrity scans run.
        drop(bases);
        if verified.len() != hints.len() {
            return Ok(None);
        }
        for ((id, object), hint) in verified.into_iter().zip(hints) {
            checkpoint(deadline)?;
            if id != hint.id || object.object_type != hint.kind {
                return Ok(None);
            }
            let bytes = match object.body {
                ObjectBody::Resident(bytes) => bytes,
                ObjectBody::Spooled(handle) => {
                    // A changed scratch body must still match the canonical
                    // strong commitment below; spooling creates no new proof.
                    let read = spool.read(handle);
                    checkpoint(deadline)?;
                    read.map_err(|_| RefusalCode::EvidenceInvalid)?
                }
            };
            if bytes.len() != hint.bytes {
                return Ok(None);
            }
            // Charge both hashing the reconstructed bytes and reading the
            // canonical bytes before doing either. Failed candidates retain
            // these charges in the caller's operation-wide work budget.
            let work = bytes
                .len()
                .checked_mul(2)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
            resolution_budget
                .charge_work(work, &self.pack_limits)
                .map_err(restore_pack_refusal)?;
            let commitment = git_payload_commitment(
                crypto_object_kind(object.object_type),
                &bytes,
                CANONICAL_CODEC_VERSION,
            );
            drop(bytes);
            checkpoint(deadline)?;
            let canonical = self.node.fabric.verify_object_integrity_bounded(
                id,
                hint.bytes as u64,
                &mut || deadline.checkpoint(),
            );
            checkpoint(deadline)?;
            let canonical = canonical.map_err(|error| match error {
                StoreRefusal::RuntimeCheckpointRejected => RefusalCode::CancellationInProgress,
                _ => RefusalCode::EvidenceInvalid,
            })?;
            if canonical.identity() != id
                || canonical.object_kind() != fabric_object_kind(object.object_type)
                || canonical.payload_length() != hint.bytes as u64
                || canonical.payload_commitment().as_slice() != commitment.digest().as_bytes()
            {
                return Ok(None);
            }
        }
        // Only now do the originally untrusted hints describe independently
        // verified immutable native objects. This rebuilds spans, dependencies,
        // receipts and binding digests from the checked pack, never from disk.
        self.node
            .received_pack_cache()
            .prepare_verified(
                pack,
                hints.iter().copied(),
                &ids_at_offset,
                &self.pack_limits,
                deadline,
            )
            .map_err(map_pack_error)
    }

    fn restored_pack_bases(
        &self,
        pack: &QuarantinedPack,
        hints: &[VerifiedReceivedObject],
        authorized: &BTreeSet<GitOid>,
        resolution_budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<ExternalBases, RefusalCode> {
        let mut bases = BTreeMap::new();
        let mut read_bytes = 0_usize;
        for entry in pack.entries() {
            checkpoint(deadline)?;
            let Some(ParsedDeltaBase::Ref { base, .. }) = &entry.delta_base else {
                continue;
            };
            let base = *base;
            if hints.binary_search_by_key(&base, |hint| hint.id).is_ok()
                || bases.contains_key(&base)
            {
                // Provisional pack-local association only avoids an external
                // read. The resolver and exact hint comparison must prove it.
                continue;
            }
            if !authorized.contains(&base)
                || !self.selected_closure.closure().objects().contains(&base)
            {
                return Err(RefusalCode::ThinPackBaseMissing);
            }
            let maximum = self
                .external_read_limit()
                .checked_sub(read_bytes)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?
                .min(self.pack_limits.max_object_bytes)
                .min(self.parse_limits.max_object_bytes);
            // The header is only a read-budget hint. Its length is charged
            // before a separately bounded, fully verified body read; changing
            // the file cannot widen that read or authenticate its contents.
            let header = self.node.fabric.read_header_bounded(base, maximum as u64);
            checkpoint(deadline)?;
            let header = header.map_err(|_| RefusalCode::EvidenceInvalid)?;
            let length = usize::try_from(header.payload_length)
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
            resolution_budget
                .charge_work(length, &self.pack_limits)
                .map_err(restore_pack_refusal)?;
            let read = self
                .node
                .fabric
                .read_whole_bounded(base, header.payload_length);
            checkpoint(deadline)?;
            let object = read.map_err(|_| RefusalCode::EvidenceInvalid)?.object;
            let kind = match object.envelope().object_kind() {
                fgit_object_fabric::ObjectKind::Commit => ObjectType::Commit,
                fgit_object_fabric::ObjectKind::Tree => ObjectType::Tree,
                fgit_object_fabric::ObjectKind::Blob => ObjectType::Blob,
                fgit_object_fabric::ObjectKind::Tag => ObjectType::Tag,
                fgit_object_fabric::ObjectKind::Internal => {
                    return Err(RefusalCode::EvidenceInvalid);
                }
            };
            let body = copy_bytes(object.payload(), deadline)?;
            read_bytes = read_bytes
                .checked_add(body.len())
                .filter(|bytes| *bytes <= self.external_read_limit())
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
            bases.insert(
                base,
                ExternalBase {
                    object_type: kind,
                    body,
                },
            );
        }
        Ok(ExternalBases { bases, read_bytes })
    }
}

fn restore_pack_refusal(error: PackError) -> RefusalCode {
    match error {
        // The ordinary receive mapping groups this with malformed/deep delta
        // graphs. Here the work budget is shared across optional candidates,
        // so exhaustion must stop attempts without erasing earlier charges.
        PackError::DeltaWorkLimit { .. } => RefusalCode::ResourceBudgetExceeded,
        other => map_pack_error(other),
    }
}
