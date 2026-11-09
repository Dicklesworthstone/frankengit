//! Cleanup of an original ref-submission reservation that never started.
//!
//! The independently anchored journal proves only this reservation's lifecycle.
//! Aborting it neither observes nor cancels the ordinary transaction: another
//! caller may have submitted the same TxId. The host must retain exclusive
//! custody of the complete journal, including rejecting any later commit suffix,
//! before it can confirm the deterministic abort frame.

use core::fmt;

use fgit_resource::{LifecycleEvent, ObligationClass, ObligationState};

use crate::{
    EffectClass, EffectId, EffectJournalEntry, EffectJournalEvent, EffectRequest,
    EffectTerminalOutcome, IntentRun, IntentRunCommitment, LogicalTime,
    effect_journal::{
        EffectJournalCodecRefusal, EffectJournalPersistenceRefusal, EffectJournalPosition,
        RecoveredEffectJournal,
    },
    ref_publication::RefTransactionBinding,
};

/// Why this recovered ref-submission reservation cannot be abandoned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefTransactionAbortRefusal {
    /// The complete run, authenticated receipt, exact request, or kind differs.
    Binding,
    /// The obligation has started or otherwise cannot accept a pre-start abort.
    State(ObligationState),
    /// Spend, output, reconciliation, or terminal evidence is not an exact
    /// never-started reservation or its already-recorded abort.
    TerminalCommitment,
    /// The prefix, whole inventory, or candidate fails the journal contract.
    Journal(EffectJournalCodecRefusal),
}

impl fmt::Display for RefTransactionAbortRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "recovered ref transaction reservation abort refused: {self:?}"
        )
    }
}
impl core::error::Error for RefTransactionAbortRefusal {}

/// The exact pre-start abort a host may append under exclusive journal custody.
///
/// The successor inventory stays private until [`Self::persist`] confirms its
/// exact durable position. This value grants no authority to issue or resume an
/// effect, recreate a resource ledger, or cancel the ordinary repository TxId.
#[must_use = "persist this exact abort or retain the original reservation debt"]
#[derive(Debug)]
pub struct PreparedRefTransactionAbort {
    run_commitment: IntentRunCommitment,
    before: EffectJournalPosition,
    binding: RefTransactionBinding,
    frame: Vec<u8>,
    successor: RecoveredEffectJournal,
    already_aborted: bool,
}

impl PreparedRefTransactionAbort {
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }

    /// Independently pinned complete prefix used to prepare this abort.
    #[must_use]
    pub const fn before_position(&self) -> EffectJournalPosition {
        self.before
    }

    /// Candidate position; not a durability receipt until `persist` succeeds.
    #[must_use]
    pub const fn after_position(&self) -> EffectJournalPosition {
        self.successor.position()
    }

    /// Only permitted suffix bytes. Empty means this exact abort is already in
    /// the pinned prefix; the host must still confirm custody and synchronization.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    #[must_use]
    pub const fn binding(&self) -> &RefTransactionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn already_aborted(&self) -> bool {
        self.already_aborted
    }

    /// Invoke storage once. Any refusal or inconsistent position retains the
    /// exact candidate for an explicit custody-checked retry, never a successor.
    pub fn persist<S: RefTransactionAbortSink + ?Sized>(
        self,
        sink: &mut S,
    ) -> Result<RecoveredRefTransactionAbort, RefTransactionAbortPersistenceRefused> {
        let position = match sink.persist_abort(&self) {
            Ok(position) => position,
            Err(reason) => {
                return Err(RefTransactionAbortPersistenceRefused {
                    prepared: self,
                    reason,
                });
            }
        };
        if position != self.after_position() {
            return Err(RefTransactionAbortPersistenceRefused {
                prepared: self,
                reason: EffectJournalPersistenceRefusal::Binding,
            });
        }
        Ok(RecoveredRefTransactionAbort {
            before: self.before,
            binding: self.binding,
            journal: self.successor,
            already_aborted: self.already_aborted,
        })
    }
}

/// Durable storage boundary for an exact, never-started reservation abort.
///
/// The host must retain exclusive custody from reading the independently
/// anchored prefix through preparation, append, and synchronization. It checks
/// the complete original run and every prefix byte. Existing suffix bytes must
/// be an exact prefix of `prepared.frame()`; a later commit, another event, or
/// any mismatching byte refuses without truncation or overwrite. Only missing
/// frame bytes may be appended. A matching complete frame still requires sync;
/// an empty frame permits no suffix at all. Cancellation must be checked after
/// synchronization before confirming `prepared.after_position()`.
///
/// Write or cancellation uncertainty retains debt and the exact retry bytes.
/// This sink cannot accept ACKs, start an obligation, or issue a broker grant.
pub trait RefTransactionAbortSink {
    fn persist_abort(
        &mut self,
        prepared: &PreparedRefTransactionAbort,
    ) -> Result<EffectJournalPosition, EffectJournalPersistenceRefusal>;
}

/// Durable evidence that this reservation was abandoned before its first start.
///
/// Other effects and their consumed budget remain unchanged. The journal is
/// suitable for ordinary reconciliation, but this one abort does not establish
/// whole-run quiescence or any fact about the repository transaction's outcome.
#[must_use]
#[derive(Debug)]
pub struct RecoveredRefTransactionAbort {
    before: EffectJournalPosition,
    binding: RefTransactionBinding,
    journal: RecoveredEffectJournal,
    already_aborted: bool,
}

impl RecoveredRefTransactionAbort {
    #[must_use]
    pub const fn before_position(&self) -> EffectJournalPosition {
        self.before
    }

    #[must_use]
    pub const fn after_position(&self) -> EffectJournalPosition {
        self.journal.position()
    }

    #[must_use]
    pub const fn binding(&self) -> &RefTransactionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn journal(&self) -> &RecoveredEffectJournal {
        &self.journal
    }

    #[must_use]
    pub const fn already_aborted(&self) -> bool {
        self.already_aborted
    }

    #[must_use]
    pub fn into_parts(self) -> (RefTransactionBinding, RecoveredEffectJournal) {
        (self.binding, self.journal)
    }

    #[must_use]
    pub fn into_journal(self) -> RecoveredEffectJournal {
        self.journal
    }
}

/// Persistence was refused or ambiguous. The exact original binding and frame
/// remain available for an explicit retry under freshly acquired file custody.
#[must_use]
#[derive(Debug)]
pub struct RefTransactionAbortPersistenceRefused {
    prepared: PreparedRefTransactionAbort,
    reason: EffectJournalPersistenceRefusal,
}

impl RefTransactionAbortPersistenceRefused {
    #[must_use]
    pub const fn prepared(&self) -> &PreparedRefTransactionAbort {
        &self.prepared
    }

    #[must_use]
    pub const fn reason(&self) -> EffectJournalPersistenceRefusal {
        self.reason
    }

    #[must_use]
    pub fn into_prepared(self) -> PreparedRefTransactionAbort {
        self.prepared
    }
}

impl fmt::Display for RefTransactionAbortPersistenceRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "recovered ref transaction reservation abort needs reconciliation: {:?}",
            self.reason
        )
    }
}
impl core::error::Error for RefTransactionAbortPersistenceRefused {}

/// Prepare the existing deterministic Abort event for one original reservation.
///
/// Expiry or later revocation does not prevent this cleanup: no capability is
/// renewed and no effect is issued. `observed_at` only validates the complete
/// inventory; it is not incorporated into the appended bytes. An exact existing
/// abort is idempotent and still requires host durability confirmation. The
/// selected binding retains the original TxId without observing its outcome.
pub fn prepare_recovered_ref_transaction_abort(
    run: &IntentRun,
    journal: &RecoveredEffectJournal,
    effect_id: EffectId,
    observed_at: LogicalTime,
) -> Result<PreparedRefTransactionAbort, RefTransactionAbortRefusal> {
    journal
        .reconciliation_report(run, observed_at)
        .map_err(RefTransactionAbortRefusal::Journal)?;
    let run_commitment = run
        .commitment()
        .map_err(|_| RefTransactionAbortRefusal::Binding)?;
    let authority = run
        .authority_read_receipt()
        .ok_or(RefTransactionAbortRefusal::Binding)?;
    let binding = journal
        .ref_transactions()
        .get(&effect_id)
        .ok_or(RefTransactionAbortRefusal::Binding)?;
    let record = journal
        .records()
        .iter()
        .find(|record| record.effect_id == effect_id)
        .ok_or(RefTransactionAbortRefusal::Binding)?;
    let recorded_request = EffectRequest {
        effect_id: record.effect_id,
        parent_effect_id: record.parent_effect_id,
        operation: record.operation,
        cost: record.budget_reserved,
        input_commitment: record.input_commitment,
    };
    if binding.run_commitment() != run_commitment
        || binding.seal().repository_id != authority.repository_id()
        || record.run_commitment != run_commitment
        || record.run_id != run.run_id()
        || record.source_authority_receipt.as_ref() != Some(authority)
        || recorded_request != binding.request(record.budget_reserved)
        || record.effect_class != EffectClass::CanonicalMutation
        || record.obligation_class != Some(ObligationClass::RefTransactionSubmission)
        || record.external_idempotency_key.is_some()
    {
        return Err(RefTransactionAbortRefusal::Binding);
    }
    let already_aborted = match record.obligation_state {
        ObligationState::Reserved => false,
        ObligationState::Aborted => true,
        state => return Err(RefTransactionAbortRefusal::State(state)),
    };
    if !record.budget_consumed.is_zero()
        || !record.output_commitments.is_empty()
        || record.reconciliation_evidence.is_some()
        || record.terminal_outcome != already_aborted.then_some(EffectTerminalOutcome::Aborted)
    {
        return Err(RefTransactionAbortRefusal::TerminalCommitment);
    }
    let (frame, successor) = if already_aborted {
        (Vec::new(), journal.clone())
    } else {
        journal
            .prepare_append(
                run,
                EffectJournalEntry {
                    sequence: journal.position().entries,
                    event: EffectJournalEvent::Lifecycle {
                        effect_id,
                        event: LifecycleEvent::Abort,
                        budget_consumed: record.budget_consumed,
                        output_commitments: Vec::new(),
                        reconciliation_evidence: None,
                        terminal_outcome: Some(EffectTerminalOutcome::Aborted),
                    },
                },
            )
            .map_err(RefTransactionAbortRefusal::Journal)?
    };
    successor
        .reconciliation_report(run, observed_at)
        .map_err(RefTransactionAbortRefusal::Journal)?;
    Ok(PreparedRefTransactionAbort {
        run_commitment,
        before: journal.position(),
        binding: binding.clone(),
        frame,
        successor,
        already_aborted,
    })
}
