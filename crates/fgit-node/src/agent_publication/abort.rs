//! Cold cleanup of an exact unstarted native ref-publication reservation.
//!
//! The original journal, not an absent canonical outcome, proves eligibility.
//! No admission, issuing broker or resumed submission is created by this path.

use core::fmt;
use std::path::Path;

use fgit_agent::{
    EffectId, LogicalTime, RunId,
    effect_journal::{EffectJournalPersistenceRefusal, EffectJournalPosition},
    ref_publication::{
        RefTransactionAbortPersistenceRefused, RefTransactionAbortRefusal, RefTransactionBinding,
        prepare_recovered_ref_transaction_abort,
    },
};
use fgit_types::PrincipalId;

use crate::{
    NodeRequestContext, OneNode,
    agent_journal::{
        AgentJournalHostRefusal, RecoveredAgentJournal, settlement::FileRefTransactionSettlement,
    },
};

/// Durable cleanup of one original reservation that never started submission.
/// This result neither observes a canonical outcome nor settles other effects.
/// Retain `recovered.journal().position()` independently for subsequent recovery.
#[must_use]
#[derive(Debug)]
pub struct NativeRecoveredRefTransactionAbort {
    pub binding: RefTransactionBinding,
    pub recovered: RecoveredAgentJournal,
    pub already_aborted: bool,
}

/// An abort-specific failure never authorizes acknowledgement or another
/// submission. Persistence ambiguity retains its exact prepared cleanup bytes.
#[must_use]
#[derive(Debug)]
pub enum NativeRecoveredRefTransactionAbortRefusal {
    Journal(AgentJournalHostRefusal),
    Binding,
    Preparation(RefTransactionAbortRefusal),
    Persistence(RefTransactionAbortPersistenceRefused),
}

impl fmt::Display for NativeRecoveredRefTransactionAbortRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(reason) => write!(formatter, "recovered ref reservation abort: {reason}"),
            Self::Binding => {
                formatter.write_str("recovered ref reservation abort: original binding mismatch")
            }
            Self::Preparation(reason) => {
                write!(formatter, "recovered ref reservation abort: {reason}")
            }
            Self::Persistence(reason) => {
                write!(formatter, "recovered ref reservation abort: {reason}")
            }
        }
    }
}
impl core::error::Error for NativeRecoveredRefTransactionAbortRefusal {}

impl OneNode {
    /// Durably abort one recovered pre-start reservation for its original
    /// authenticated principal, including after run expiry or revocation.
    ///
    /// The caller must independently retain the complete original run commitment
    /// and exact journal tail, and authorize this principal for cleanup. The
    /// saved run is reauthenticated through this node's persistent authority
    /// ledger. While holding exclusive journal custody, this method checks the
    /// original tenant, repository, native custody and sealed principal before
    /// deriving the only permitted Abort frame. Already-started effects refuse.
    ///
    /// An old Reserved tail does not prove the file is still unstarted. Only an
    /// exact partial or complete copy of this Abort may follow it; Commit,
    /// unknown or extra bytes refuse without truncation. Exact retries sync the
    /// existing frame again. `observed_at` dates inspection, never renews the run,
    /// and does not affect the deterministic cleanup bytes. This path never
    /// queries canonical outcome absence or reopens an issuing broker.
    pub async fn abort_recovered_agent_ref_transaction_for_principal_in(
        &self,
        request: &NodeRequestContext,
        directory: &Path,
        run_id: RunId,
        expected_run: &[u8; 32],
        expected_tail: EffectJournalPosition,
        effect: EffectId,
        expected_principal: PrincipalId,
        observed_at: LogicalTime,
    ) -> Result<NativeRecoveredRefTransactionAbort, NativeRecoveredRefTransactionAbortRefusal> {
        let run = self
            .restore_original_agent_run_in(request, directory, run_id, expected_run)
            .await
            .map_err(NativeRecoveredRefTransactionAbortRefusal::Journal)?;
        let owned = request.authority().clone();
        let (mut file, prefix) = FileRefTransactionSettlement::open(
            directory,
            &run,
            expected_tail,
            Box::new(move || {
                if matches!(
                    crate::checkpoint_pack_context(&owned),
                    crate::PackContextCheckpoint::Live
                ) {
                    Ok(())
                } else {
                    Err(EffectJournalPersistenceRefusal::Cancelled)
                }
            }),
        )
        .map_err(NativeRecoveredRefTransactionAbortRefusal::Journal)?;
        let binding = prefix
            .ref_transactions()
            .get(&effect)
            .ok_or(NativeRecoveredRefTransactionAbortRefusal::Binding)?;
        if binding.seal().tenant_id != self.tenant_id
            || binding.seal().repository_id != self.repository_id
            || binding.custody_commitment().is_none()
            || binding.seal().authenticated_principal_id != expected_principal
        {
            return Err(NativeRecoveredRefTransactionAbortRefusal::Binding);
        }
        let prepared = prepare_recovered_ref_transaction_abort(&run, &prefix, effect, observed_at)
            .map_err(NativeRecoveredRefTransactionAbortRefusal::Preparation)?;
        let settled = prepared
            .persist(&mut file)
            .map_err(NativeRecoveredRefTransactionAbortRefusal::Persistence)?;
        let binding = settled.binding().clone();
        let already_aborted = settled.already_aborted();
        Ok(NativeRecoveredRefTransactionAbort {
            binding,
            recovered: RecoveredAgentJournal::from_settled(run, settled.into_journal()),
            already_aborted,
        })
    }
}
