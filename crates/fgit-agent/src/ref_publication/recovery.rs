//! Cleanup-only acknowledgement of a recovered canonical submission.
//!
//! A known ordinary terminal outcome can settle the original journal debt
//! without recreating its issuing broker or resource ledger. The exact old
//! prefix remains independently anchored, the observation is authenticated by
//! the ordinary authority reader, and the only candidate event is the existing
//! acknowledgement lifecycle event. No candidate inventory escapes before the
//! host confirms its durability under exclusive journal custody.

use core::fmt;

use fgit_resource::{LifecycleEvent, ObligationClass, ObligationState};

use super::ObservedRefTransaction;
use crate::{
    EffectClass, EffectJournalEntry, EffectJournalEvent, EffectTerminalOutcome, IntentRun,
    IntentRunCommitment, LogicalTime, OperationClass,
    effect_journal::{
        EffectJournalCodecRefusal, EffectJournalPersistenceRefusal, EffectJournalPosition,
        RecoveredEffectJournal,
    },
};

/// Why an authenticated terminal cannot acknowledge this recovered inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefTransactionRecoveryRefusal {
    /// The complete run, original submission, effect, or obligation differs.
    Binding,
    /// The retained state does not permit acknowledgement.
    State(ObligationState),
    /// An existing acknowledgement retained another terminal commitment.
    TerminalCommitment,
    /// The prefix, inventory, or candidate fails the ordinary journal contract.
    Journal(EffectJournalCodecRefusal),
}

impl fmt::Display for RefTransactionRecoveryRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "recovered ref transaction acknowledgement refused: {self:?}"
        )
    }
}
impl core::error::Error for RefTransactionRecoveryRefusal {}

/// The exact acknowledgement a host may persist after verifying its old prefix.
///
/// All fields are private. In particular, the candidate successor is unavailable
/// until [`Self::persist`] confirms the exact resulting durable position. This
/// object supplies no authority to issue effects or retry repository admission.
#[must_use = "persist this exact acknowledgement or retain it as cleanup debt"]
#[derive(Debug)]
pub struct PreparedRefTransactionAcknowledgement {
    run_commitment: IntentRunCommitment,
    before: EffectJournalPosition,
    observation: ObservedRefTransaction,
    frame: Vec<u8>,
    successor: RecoveredEffectJournal,
    already_acknowledged: bool,
}

impl PreparedRefTransactionAcknowledgement {
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// The independently pinned complete prefix used for this preparation.
    #[must_use]
    pub const fn before_position(&self) -> EffectJournalPosition {
        self.before
    }

    /// Candidate position, not a persistence receipt until `persist` succeeds.
    #[must_use]
    pub const fn after_position(&self) -> EffectJournalPosition {
        self.successor.position()
    }

    /// The only bytes permitted after the pinned prefix. An empty frame means
    /// that the prefix already contains the exact authenticated acknowledgement.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    #[must_use]
    pub const fn observation(&self) -> &ObservedRefTransaction {
        &self.observation
    }

    #[must_use]
    pub const fn already_acknowledged(&self) -> bool {
        self.already_acknowledged
    }

    /// Invoke the cleanup-specific storage boundary once. A failed or
    /// inconsistent acknowledgement retains the complete candidate and terminal
    /// observation; it exposes no settled successor inventory.
    pub fn persist<S: RefTransactionAcknowledgementSink + ?Sized>(
        self,
        sink: &mut S,
    ) -> Result<RecoveredRefTransactionAcknowledgement, RefTransactionRecoveryPersistenceRefused>
    {
        let position = match sink.persist_acknowledgement(&self) {
            Ok(position) => position,
            Err(reason) => {
                return Err(RefTransactionRecoveryPersistenceRefused {
                    prepared: self,
                    reason,
                });
            }
        };
        if position != self.after_position() {
            return Err(RefTransactionRecoveryPersistenceRefused {
                prepared: self,
                reason: EffectJournalPersistenceRefusal::Binding,
            });
        }
        Ok(RecoveredRefTransactionAcknowledgement {
            before: self.before,
            observation: self.observation,
            journal: self.successor,
            already_acknowledged: self.already_acknowledged,
        })
    }
}

/// Durable host boundary accepting only checked canonical cleanup.
///
/// The host must retain exclusive custody from reading the independently
/// anchored prefix through authority observation, preparation, and sync. It
/// verifies the original complete run and every prefix byte. Existing suffix
/// bytes must be an exact prefix of `prepared.frame()`; any other bytes refuse
/// without truncation or overwrite. The host may append only the missing bytes,
/// then must synchronize the file and check cancellation before acknowledging
/// `prepared.after_position()`. A complete matching frame is synchronized
/// without appending a duplicate. An empty frame requires no suffix at all.
///
/// Every failure retains cleanup debt, including cancellation after a successful
/// write. This is deliberately separate from an issuing broker's journal sink.
pub trait RefTransactionAcknowledgementSink {
    fn persist_acknowledgement(
        &mut self,
        prepared: &PreparedRefTransactionAcknowledgement,
    ) -> Result<EffectJournalPosition, EffectJournalPersistenceRefusal>;
}

/// Successful durability confirmation of the exact original terminal outcome.
///
/// The returned history is suitable for the existing reconciliation report.
/// Other effects keep their original state and charged budget; this one
/// acknowledgement does not establish process or whole-run quiescence.
#[must_use]
#[derive(Debug)]
pub struct RecoveredRefTransactionAcknowledgement {
    before: EffectJournalPosition,
    observation: ObservedRefTransaction,
    journal: RecoveredEffectJournal,
    already_acknowledged: bool,
}

impl RecoveredRefTransactionAcknowledgement {
    #[must_use]
    pub const fn before_position(&self) -> EffectJournalPosition {
        self.before
    }

    #[must_use]
    pub const fn after_position(&self) -> EffectJournalPosition {
        self.journal.position()
    }

    #[must_use]
    pub const fn observation(&self) -> &ObservedRefTransaction {
        &self.observation
    }

    #[must_use]
    pub const fn journal(&self) -> &RecoveredEffectJournal {
        &self.journal
    }

    #[must_use]
    pub const fn already_acknowledged(&self) -> bool {
        self.already_acknowledged
    }

    #[must_use]
    pub fn into_parts(self) -> (ObservedRefTransaction, RecoveredEffectJournal) {
        (self.observation, self.journal)
    }
}

/// Ambiguous or refused persistence, preserving the terminal and exact retry
/// bytes. A later attempt must reacquire custody and verify the original prefix
/// plus only these bytes; it may never resubmit the repository transaction.
#[must_use]
#[derive(Debug)]
pub struct RefTransactionRecoveryPersistenceRefused {
    prepared: PreparedRefTransactionAcknowledgement,
    reason: EffectJournalPersistenceRefusal,
}

impl RefTransactionRecoveryPersistenceRefused {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedRefTransactionAcknowledgement {
        &self.prepared
    }

    #[must_use]
    pub const fn reason(&self) -> EffectJournalPersistenceRefusal {
        self.reason
    }

    #[must_use]
    pub fn into_prepared(self) -> PreparedRefTransactionAcknowledgement {
        self.prepared
    }
}

impl fmt::Display for RefTransactionRecoveryPersistenceRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "recovered ref transaction acknowledgement needs reconciliation: {:?}",
            self.reason
        )
    }
}
impl core::error::Error for RefTransactionRecoveryPersistenceRefused {}

/// Prepare only the ordinary ACK for an exact, authenticated original terminal.
///
/// Both the complete predecessor inventory and candidate are validated through
/// the existing reconciliation and lifecycle engines. Cleanup may follow expiry
/// or revocation; it never renews the run or reserves a new budget. A matching
/// already-recorded ACK is idempotent, but still requires storage confirmation.
pub fn prepare_recovered_ref_transaction_acknowledgement(
    run: &IntentRun,
    journal: &RecoveredEffectJournal,
    observation: &ObservedRefTransaction,
    observed_at: LogicalTime,
) -> Result<PreparedRefTransactionAcknowledgement, RefTransactionRecoveryRefusal> {
    journal
        .reconciliation_report(run, observed_at)
        .map_err(RefTransactionRecoveryRefusal::Journal)?;
    let run_commitment = run
        .commitment()
        .map_err(|_| RefTransactionRecoveryRefusal::Binding)?;
    let binding = observation.binding();
    let effect_id = binding.effect_id();
    if binding.run_commitment() != run_commitment
        || journal.ref_transactions().get(&effect_id) != Some(binding)
    {
        return Err(RefTransactionRecoveryRefusal::Binding);
    }
    let record = journal
        .records()
        .iter()
        .find(|record| record.effect_id == effect_id)
        .ok_or(RefTransactionRecoveryRefusal::Binding)?;
    if record.run_commitment != run_commitment
        || record.run_id != run.run_id()
        || record.source_authority_receipt.as_ref() != run.authority_read_receipt()
        || record.operation != OperationClass::PublishRefTransaction
        || record.effect_class != EffectClass::CanonicalMutation
        || record.obligation_class != Some(ObligationClass::RefTransactionSubmission)
        || record.input_commitment != *binding.input_commitment()
        || record.external_idempotency_key.is_some()
    {
        return Err(RefTransactionRecoveryRefusal::Binding);
    }
    let output: [u8; 32] = observation
        .commitment()
        .bytes()
        .as_bytes()
        .try_into()
        .map_err(|_| RefTransactionRecoveryRefusal::Binding)?;
    let already_acknowledged = record.obligation_state == ObligationState::Acknowledged;
    let (frame, successor) = if already_acknowledged {
        if record.terminal_outcome != Some(EffectTerminalOutcome::Acknowledged)
            || record.output_commitments.as_slice() != [output]
        {
            return Err(RefTransactionRecoveryRefusal::TerminalCommitment);
        }
        (Vec::new(), journal.clone())
    } else {
        if !matches!(
            record.obligation_state,
            ObligationState::Committed
                | ObligationState::DeferredExternally
                | ObligationState::Escalated
        ) {
            return Err(RefTransactionRecoveryRefusal::State(
                record.obligation_state,
            ));
        }
        journal
            .prepare_append(
                run,
                EffectJournalEntry {
                    sequence: journal.position().entries,
                    event: EffectJournalEvent::Lifecycle {
                        effect_id,
                        event: LifecycleEvent::Acknowledge,
                        budget_consumed: record.budget_consumed,
                        output_commitments: vec![output],
                        reconciliation_evidence: None,
                        terminal_outcome: Some(EffectTerminalOutcome::Acknowledged),
                    },
                },
            )
            .map_err(RefTransactionRecoveryRefusal::Journal)?
    };
    successor
        .reconciliation_report(run, observed_at)
        .map_err(RefTransactionRecoveryRefusal::Journal)?;
    Ok(PreparedRefTransactionAcknowledgement {
        run_commitment,
        before: journal.position(),
        observation: observation.clone(),
        frame,
        successor,
        already_acknowledged,
    })
}
