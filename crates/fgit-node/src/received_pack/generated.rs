//! Retain independently verified native output for the next exact selection.
//!
//! A writer receipt is not reusable object custody. Its completed scratch bytes
//! pass the same bounded native reconstruction and canonical strong-commitment
//! checks as a persisted representation before they can enter this cache.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use fgit_git_object::ParseLimits;
use fgit_pack::{
    NativeChecksumVerifier, PackError, PackLimits, PackOrderKey, PackWriteError, PackWriteReceipt,
    ResolutionBudget, ThinBase, read_verified_pack_owned,
};
use fgit_types::RefusalCode;

use super::VerifiedReceivedObject;
use crate::pack_spool::SpooledPack;
use crate::{MaterializedAdmission, NodePackMaterializationRefusal, OneNode, fabric_object_kind};

// Best-effort verification must not inherit a large clone's entire remaining
// lifetime. Each checkpoint also checks the authoritative request; expiry of
// this smaller optional allowance only discards the candidate.
const CAPTURE_TIME_LIMIT: Duration = Duration::from_secs(2);

/// Only the identities actually written by this native run, plus the proven
/// client-held bases the planner was allowed to consider. A hybrid's native
/// suffix passes its own missing keys, never the larger combined selection.
pub(crate) struct GeneratedPackSelection<'a> {
    pub(crate) keys: &'a [PackOrderKey],
    pub(crate) thin_bases: &'a [ThinBase],
    pub(crate) limits: &'a PackLimits,
}

impl OneNode {
    /// This is optional acceleration after successful native emission. Cache
    /// allocation, I/O, or verification failures leave that response intact;
    /// the original request's cancellation still terminates the operation.
    pub(crate) fn retain_generated_pack(
        &self,
        materialized: &MaterializedAdmission,
        spool: &mut SpooledPack,
        receipt: &PackWriteReceipt,
        selection: GeneratedPackSelection<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodePackMaterializationRefusal> {
        self.retain_generated_pack_with_budget(
            materialized,
            spool,
            receipt,
            selection,
            live,
            CAPTURE_TIME_LIMIT,
        )
    }

    pub(crate) fn retain_generated_pack_with_budget(
        &self,
        materialized: &MaterializedAdmission,
        spool: &mut SpooledPack,
        receipt: &PackWriteReceipt,
        selection: GeneratedPackSelection<'_>,
        live: &mut impl FnMut() -> bool,
        allowance: Duration,
    ) -> Result<(), NodePackMaterializationRefusal> {
        let started = Instant::now();
        let mut request_stopped = false;
        let mut optional_exhausted = false;
        let result = {
            let mut capture_live = || {
                if request_stopped || optional_exhausted {
                    return false;
                }
                if !live() {
                    request_stopped = true;
                    return false;
                }
                if started.elapsed() >= allowance {
                    optional_exhausted = true;
                    return false;
                }
                true
            };
            self.retain_generated_pack_checked(
                materialized,
                spool,
                receipt,
                selection,
                &mut capture_live,
            )
        };
        if request_stopped
            || (matches!(result, Err(RefusalCode::CancellationInProgress)) && !optional_exhausted)
            || !live()
        {
            return Err(PackWriteError::from(PackError::DeadlineExceeded).into());
        }
        Ok(())
    }

    fn retain_generated_pack_checked(
        &self,
        materialized: &MaterializedAdmission,
        spool: &mut SpooledPack,
        receipt: &PackWriteReceipt,
        selection: GeneratedPackSelection<'_>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), RefusalCode> {
        checkpoint(live)?;
        let GeneratedPackSelection {
            keys,
            thin_bases,
            limits,
        } = selection;
        let cache = self.received_pack_cache();
        if cache.max_bytes() == 0
            || keys.is_empty()
            || keys.len() != receipt.object_count as usize
            || receipt.compression.len() != keys.len()
            || receipt.checksum.algorithm() != self.object_format
            || receipt.output_bytes > cache.capture_limit()
            || (!receipt.profile.thin && !thin_bases.is_empty())
        {
            return Ok(());
        }

        // Retention must not turn a large streamed upload allowance into an
        // equally large buffered parser or canonical-object allocation. Use
        // the existing optional-custody and receive parser ceilings as well as
        // this exact native run's envelope. The writer's result still succeeds
        // when a representation is too large for this accelerator.
        let receive_limits = &self.service_config.git_daemon_receive_limits.pack;
        let mut restore_limits = limits.clone();
        restore_limits.max_total_expanded_bytes = restore_limits
            .max_total_expanded_bytes
            .min(cache.max_bytes())
            .min(receive_limits.max_total_expanded_bytes);
        if receipt.total_object_bytes > restore_limits.max_total_expanded_bytes {
            return Ok(());
        }
        restore_limits.max_object_bytes = restore_limits
            .max_object_bytes
            .min(receive_limits.max_object_bytes);
        restore_limits.max_cached_bytes = restore_limits.max_cached_bytes.min(cache.max_bytes());
        restore_limits.max_delta_work = crate::receive_delta_work_limit(
            restore_limits.max_total_expanded_bytes,
            receipt.object_count,
        )
        .saturating_add(restore_limits.max_total_expanded_bytes.saturating_mul(2))
        .saturating_add(cache.capture_limit().saturating_mul(2))
        .min(limits.max_delta_work);
        let mut parser_limits = restore_limits.clone();
        parser_limits.max_input_bytes = parser_limits.max_input_bytes.min(cache.capture_limit());
        parser_limits.max_total_expanded_bytes = parser_limits
            .max_total_expanded_bytes
            .min(cache.max_bytes())
            .min(receive_limits.max_total_expanded_bytes);
        parser_limits.max_object_bytes = parser_limits
            .max_object_bytes
            .min(parser_limits.max_total_expanded_bytes);
        let inflation = receipt
            .compression
            .iter()
            .try_fold(0_usize, |total, member| {
                total.checked_add(member.input_bytes)
            });
        if receipt.object_count > parser_limits.max_entries
            || receipt.output_bytes > parser_limits.max_input_bytes
            || inflation.is_none_or(|bytes| bytes > parser_limits.max_total_expanded_bytes)
            || receipt
                .compression
                .iter()
                .any(|member| member.input_bytes > parser_limits.max_object_bytes)
        {
            return Ok(());
        }
        // Reserve raw bytes and per-object metadata before either allocation.
        // The reservation is transferred through validation, never doubled.
        let Some(reservation) = cache.reserve_streamed_capture(receipt.output_bytes, keys.len())
        else {
            return Ok(());
        };
        let mut hints = Vec::new();
        hints
            .try_reserve_exact(keys.len())
            .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
        let mut authorized = BTreeSet::new();
        let mut previous = None;
        let mut total = 0_usize;
        for key in keys {
            checkpoint(live)?;
            if key.id.is_zero()
                || key.id.algorithm() != self.object_format
                || previous.is_some_and(|id| id >= key.id)
                || !materialized
                    .selected_closure()
                    .closure()
                    .objects()
                    .contains(&key.id)
            {
                return Ok(());
            }
            // An envelope length is only a bounded hint. Reconstruction and
            // the EOF-authenticated canonical read below must both agree.
            let header = self
                .fabric
                .read_header_bounded(key.id, restore_limits.max_object_bytes as u64)
                .map_err(|_| RefusalCode::EvidenceMissing)?;
            checkpoint(live)?;
            if header.kind != fabric_object_kind(key.object_type) {
                return Ok(());
            }
            let bytes = usize::try_from(header.payload_length)
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
            total = total
                .checked_add(bytes)
                .filter(|bytes| *bytes <= restore_limits.max_total_expanded_bytes)
                .ok_or(RefusalCode::ResourceBudgetExceeded)?;
            hints.push(VerifiedReceivedObject {
                id: key.id,
                kind: key.object_type,
                bytes,
            });
            authorized.insert(key.id);
            previous = Some(key.id);
        }
        if total != receipt.total_object_bytes {
            return Ok(());
        }
        for base in thin_bases {
            checkpoint(live)?;
            if keys
                .binary_search_by_key(&base.target(), |key| key.id)
                .is_err()
                || base.base().algorithm() != self.object_format
                || !materialized
                    .selected_closure()
                    .closure()
                    .objects()
                    .contains(&base.base())
            {
                return Ok(());
            }
            authorized.insert(base.base());
        }
        let Some(bytes) = spool
            .copy_for_custody(receipt.output_bytes, cache.capture_limit(), live)
            .map_err(pack_refusal)?
        else {
            return Ok(());
        };
        let pack = read_verified_pack_owned(
            bytes,
            self.object_format,
            &parser_limits,
            live,
            &NativeChecksumVerifier,
            cache.capture_limit(),
        )
        .map_err(pack_refusal)?;
        checkpoint(live)?;
        if pack.trailer != receipt.checksum || pack.entries().len() != keys.len() {
            return Ok(());
        }
        let parse_limits = ParseLimits {
            max_object_bytes: restore_limits.max_object_bytes,
            tree_reference_bytes: self.object_format.digest_len(),
            ..ParseLimits::default()
        };
        let validator = self
            .production_quarantine_validator(materialized, restore_limits.clone(), parse_limits)?
            .for_received_pack_restoration();
        let mut budget = ResolutionBudget::new();
        budget
            .charge_work(receipt.output_bytes, &restore_limits)
            .map_err(pack_refusal)?;
        for entry in pack.entries() {
            checkpoint(live)?;
            budget
                .charge_work(entry.inflated.len(), &restore_limits)
                .map_err(pack_refusal)?;
        }
        if let Some(pending) = validator.restore_captured_pack(
            &pack,
            &hints,
            &authorized,
            &mut budget,
            live,
            reservation,
        )? {
            pending
                .with_persistence(self.durable_received_pack_store())
                .commit_with_deadline(live)
                .map_err(pack_refusal)?;
        }
        checkpoint(live)
    }
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), RefusalCode> {
    if live() {
        Ok(())
    } else {
        Err(RefusalCode::CancellationInProgress)
    }
}

fn pack_refusal(error: PackError) -> RefusalCode {
    match error {
        PackError::DeadlineExceeded => RefusalCode::CancellationInProgress,
        _ => RefusalCode::EvidenceInvalid,
    }
}
