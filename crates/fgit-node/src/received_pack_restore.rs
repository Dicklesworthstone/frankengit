//! Optional received-pack restoration under the current upload disclosure.
//!
//! Disk records never recreate a trusted receipt by decoding it. Native pack
//! reconstruction and EOF-authenticated canonical object equality reestablish
//! the same private custody that live receive creates after collision checks.

use std::collections::BTreeSet;

use fgit_git_object::ParseLimits;
use fgit_pack::{
    NativeChecksumVerifier, PackError, PackLimits, PackOrderKey, PackWriteError, ResolutionBudget,
    read_verified_pack_owned,
};
use fgit_types::{GitHashAlgorithm, GitOid, RefusalCode};

use crate::received_pack::persistence::DurableStore;
use crate::{MaterializedAdmission, NodePackMaterializationRefusal, OneNode};

impl OneNode {
    pub(crate) fn durable_received_pack_store(&self) -> DurableStore {
        // NodeConfig accepts ordinary relative repository roots. Make the
        // descriptor walk absolute without resolving symlink components;
        // unavailable current-directory state remains an optional cache miss.
        let root = std::path::absolute(self.storage_root())
            .unwrap_or_else(|_| self.storage_root().to_path_buf());
        DurableStore::new(
            root.join("received-pack-cache").join("v1"),
            self.tenant_id(),
            self.repository_id(),
            self.repository_incarnation_id(),
            self.object_format,
            self.received_pack_cache().max_bytes(),
        )
    }

    /// This runs only after exact selection and work admission. A cold miss
    /// keeps the existing writer path; a stopped request never earns fallback.
    pub(crate) fn restore_received_pack_custody(
        &self,
        materialized: &MaterializedAdmission,
        keys: &[PackOrderKey],
        held: &BTreeSet<GitOid>,
        limits: &PackLimits,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), NodePackMaterializationRefusal> {
        checkpoint(live)?;
        let cache = self.received_pack_cache();
        if cache.max_bytes() == 0 || keys.is_empty() {
            return Ok(());
        }
        let Some(_restoration) = cache.begin_restoration() else {
            return Ok(());
        };
        let mut selected = BTreeSet::new();
        for key in keys {
            checkpoint(live)?;
            selected.insert(key.id);
        }
        let mut known = cache.source_fingerprints();
        let candidates = self
            .durable_received_pack_store()
            .candidates(&selected, held, &known, live)
            .map_err(PackWriteError::from)?;
        if candidates.is_empty() {
            return Ok(());
        }
        // Do not let cumulative repository membership widen this fetch. The
        // same proof is checked again for each reconstructed object and each
        // external REF base before canonical reads.
        let mut authorized = selected;
        for id in held {
            checkpoint(live)?;
            authorized.insert(*id);
        }
        let mut restore_limits = limits.clone();
        // Native delta reconstruction charges base/result work; strong hashing
        // and canonical integrity verification each read every result again.
        // This one finite budget survives failed and overlapping candidates.
        restore_limits.max_delta_work = crate::receive_delta_work_limit(
            restore_limits.max_total_expanded_bytes,
            restore_limits.max_entries,
        )
        .saturating_add(restore_limits.max_total_expanded_bytes.saturating_mul(2))
        .saturating_add(cache.max_bytes().saturating_mul(2));
        restore_limits.max_cached_bytes = restore_limits.max_cached_bytes.min(cache.max_bytes());
        let parse_limits = ParseLimits {
            max_object_bytes: restore_limits.max_object_bytes,
            tree_reference_bytes: match self.object_format {
                GitHashAlgorithm::Sha1 => 20,
                GitHashAlgorithm::Sha256 => 32,
            },
            ..ParseLimits::default()
        };
        let validator = match self.production_quarantine_validator(
            materialized,
            restore_limits.clone(),
            parse_limits,
        ) {
            Ok(validator) => validator,
            Err(RefusalCode::CancellationInProgress) => return Err(stopped()),
            Err(_) => return Ok(()),
        };
        // The parser retains inflated entry programs in memory. Its ceiling
        // must not inherit a multi-GiB resolved-object upload allowance alone.
        // Large resolved blobs still use the validator's bounded spool path.
        let mut parser_limits = restore_limits.clone();
        parser_limits.max_input_bytes = parser_limits.max_input_bytes.min(cache.capture_limit());
        parser_limits.max_total_expanded_bytes = parser_limits
            .max_total_expanded_bytes
            .min(cache.max_bytes())
            .min(
                self.service_config
                    .git_daemon_receive_limits
                    .pack
                    .max_total_expanded_bytes,
            );
        parser_limits.max_object_bytes = parser_limits
            .max_object_bytes
            .min(parser_limits.max_total_expanded_bytes);
        let mut remaining_inflation = parser_limits.max_total_expanded_bytes;
        let mut budget = ResolutionBudget::new();
        for candidate in candidates {
            checkpoint(live)?;
            // Another candidate may already have reestablished this source.
            // An untrusted claimed hash can only suppress optional work.
            if known.contains(&candidate.sha256) {
                continue;
            }
            parser_limits.max_total_expanded_bytes = remaining_inflation;
            parser_limits.max_object_bytes =
                parser_limits.max_object_bytes.min(remaining_inflation);
            let raw_bytes = candidate.bytes.len();
            let parsed = read_verified_pack_owned(
                candidate.bytes,
                self.object_format,
                &parser_limits,
                live,
                &NativeChecksumVerifier,
                cache.capture_limit(),
            );
            checkpoint(live)?;
            let pack = match parsed {
                Ok(pack) => pack,
                Err(PackError::DeadlineExceeded) => return Err(stopped()),
                // The parser has no failure-progress receipt. Conservatively
                // spend its remaining allowance rather than giving a damaged
                // candidate's unknown inflation work back to the next slot.
                Err(_) => break,
            };
            for entry in pack.entries() {
                checkpoint(live)?;
                let Some(remaining) = remaining_inflation.checked_sub(entry.inflated.len()) else {
                    return Ok(());
                };
                remaining_inflation = remaining;
                if budget
                    .charge_work(entry.inflated.len(), &restore_limits)
                    .is_err()
                {
                    return Ok(());
                }
            }
            if budget.charge_work(raw_bytes, &restore_limits).is_err() {
                break;
            }
            match validator.restore_received_pack(
                &pack,
                &candidate.objects,
                &authorized,
                &mut budget,
                live,
            ) {
                Ok(Some(pending)) => {
                    // Restoration is read-only: do not rewrite disk custody or
                    // stage an object that a missing canonical source withheld.
                    pending.commit();
                    known = cache.source_fingerprints();
                }
                Err(RefusalCode::CancellationInProgress) => return Err(stopped()),
                Err(RefusalCode::ResourceBudgetExceeded) => break,
                Ok(None) | Err(_) => {}
            }
        }
        checkpoint(live)
    }
}

fn stopped() -> NodePackMaterializationRefusal {
    PackWriteError::from(PackError::DeadlineExceeded).into()
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), NodePackMaterializationRefusal> {
    if live() { Ok(()) } else { Err(stopped()) }
}
