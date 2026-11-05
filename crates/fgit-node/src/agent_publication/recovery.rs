//! Cold cleanup of canonical submission responsibility, without an issuing
//! broker, renewed capability, or another repository admission attempt.

use core::fmt;
use std::path::Path;

use fgit_agent::{
    EffectId, LogicalTime, RunId,
    effect_journal::{EffectJournalPersistenceRefusal, EffectJournalPosition},
    ref_publication::{
        ObservedRefTransaction, RefTransactionObservationRefusal,
        RefTransactionRecoveryPersistenceRefused, RefTransactionRecoveryRefusal,
        observe_ref_transaction_async, prepare_recovered_ref_transaction_acknowledgement,
    },
};
use fgit_types::TxId;

use crate::{
    NodeRequestContext, OneNode,
    agent_journal::{
        AgentJournalHostRefusal, RecoveredAgentJournal, settlement::FileRefTransactionSettlement,
    },
};

/// A cleanup result never authorizes another submission. Acknowledgement
/// settles only this effect; inspect the ordinary terminal and whole-run report
/// before claiming a successful ref update or run quiescence.
#[must_use]
#[derive(Debug)]
pub enum NativeRecoveredRefTransactionSettlement {
    /// Ordinary authority has no terminal yet. The file is unchanged and any
    /// suffix remains unclassified; no incomplete inventory escapes as complete.
    Undecided { effect_id: EffectId, tx_id: TxId },
    /// The original terminal is authenticated and its exact ACK is durable.
    /// Retain `recovered.journal().position()` independently for later recovery.
    Acknowledged {
        observation: ObservedRefTransaction,
        recovered: RecoveredAgentJournal,
        already_acknowledged: bool,
    },
}

/// Cleanup could not durably settle the selected responsibility. Persistence
/// errors retain the authenticated terminal and exact candidate retry bytes;
/// they do not turn the old private prefix into a complete recovered inventory.
#[must_use]
#[derive(Debug)]
pub enum NativeRecoveredRefTransactionRefusal {
    Journal(AgentJournalHostRefusal),
    Observation(RefTransactionObservationRefusal),
    Preparation {
        observation: Box<ObservedRefTransaction>,
        reason: RefTransactionRecoveryRefusal,
    },
    Persistence(RefTransactionRecoveryPersistenceRefused),
}

impl fmt::Display for NativeRecoveredRefTransactionRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(reason) => write!(formatter, "recovered ref cleanup: {reason}"),
            Self::Observation(reason) => {
                write!(
                    formatter,
                    "recovered ref cleanup observation refused: {reason:?}"
                )
            }
            Self::Preparation { reason, .. } => {
                write!(formatter, "recovered ref cleanup: {reason}")
            }
            Self::Persistence(reason) => write!(formatter, "recovered ref cleanup: {reason}"),
        }
    }
}
impl core::error::Error for NativeRecoveredRefTransactionRefusal {}

impl OneNode {
    /// Reauthenticate the immutable original run, observe its original canonical
    /// submission and durably acknowledge only that terminal under exclusive
    /// journal custody. Works after the run expires or capability is revoked;
    /// no broker, new grant, budget reservation or admission is created.
    ///
    /// The complete-run commitment and old tail must be retained independently
    /// of the files. A prior attempt may have left a partial or complete copy of
    /// the exact ACK after that tail. Only that suffix can be completed; any
    /// different or extra bytes refuse without truncation. General journal
    /// recovery remains strict. `observed_at` dates cleanup inspection only and
    /// cannot renew authority. Synchronous file work has the same owned-lane,
    /// bounded-I/O and drained-sync contract as the ordinary native journal.
    pub async fn settle_recovered_agent_ref_transaction_in(
        &self,
        request: &NodeRequestContext,
        directory: &Path,
        run_id: RunId,
        expected_run: &[u8; 32],
        expected_tail: EffectJournalPosition,
        effect: EffectId,
        observed_at: LogicalTime,
    ) -> Result<NativeRecoveredRefTransactionSettlement, NativeRecoveredRefTransactionRefusal> {
        let run = self
            .restore_original_agent_run_in(request, directory, run_id, expected_run)
            .await
            .map_err(NativeRecoveredRefTransactionRefusal::Journal)?;
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
        .map_err(NativeRecoveredRefTransactionRefusal::Journal)?;
        let binding = prefix.ref_transactions().get(&effect).ok_or(
            NativeRecoveredRefTransactionRefusal::Observation(
                RefTransactionObservationRefusal::Binding,
            ),
        )?;
        if binding.seal().tenant_id != self.tenant_id
            || binding.seal().repository_id != self.repository_id
            || binding.custody_commitment().is_none()
        {
            return Err(NativeRecoveredRefTransactionRefusal::Observation(
                RefTransactionObservationRefusal::Binding,
            ));
        }
        let observation = observe_ref_transaction_async(
            &self.authority,
            request.authority(),
            &self.head_key,
            &run,
            binding,
        )
        .await
        .map_err(NativeRecoveredRefTransactionRefusal::Observation)?;
        let Some(observation) = observation else {
            return Ok(NativeRecoveredRefTransactionSettlement::Undecided {
                effect_id: effect,
                tx_id: binding.tx_id(),
            });
        };
        let prepared = prepare_recovered_ref_transaction_acknowledgement(
            &run,
            &prefix,
            &observation,
            observed_at,
        )
        .map_err(|reason| NativeRecoveredRefTransactionRefusal::Preparation {
            observation: Box::new(observation),
            reason,
        })?;
        let settled = prepared
            .persist(&mut file)
            .map_err(NativeRecoveredRefTransactionRefusal::Persistence)?;
        let already_acknowledged = settled.already_acknowledged();
        let (observation, journal) = settled.into_parts();
        Ok(NativeRecoveredRefTransactionSettlement::Acknowledged {
            observation,
            recovered: RecoveredAgentJournal::from_settled(run, journal),
            already_acknowledged,
        })
    }
}
