//! Private shared-ledger mechanics for canonical submission responsibility.

use super::*;
use fgit_resource::kinds::{
    NoCandidateReason, RefTransactionAborted, RefTransactionObserved, RefTransactionRequest,
    RefTransactionSubmission, RefTransactionSubmitted,
};

use crate::ref_publication::{
    ObservedRefTransaction, RefTransactionBinding, RefTransactionEffectRefusal,
};

#[derive(Debug)]
pub(crate) struct ReservedSubmission {
    binding: RefTransactionBinding,
    obligation: ReservedObligation<RefTransactionSubmission>,
    journal: Rc<RefCell<EffectJournal>>,
}

#[derive(Debug)]
pub(crate) struct PendingSubmission {
    binding: RefTransactionBinding,
    obligation: UnacknowledgedEffect<RefTransactionSubmission>,
    journal: Rc<RefCell<EffectJournal>>,
}

pub(crate) enum StartFailure {
    Before {
        reservation: ReservedSubmission,
        reason: RefTransactionEffectRefusal,
    },
    After {
        pending: PendingSubmission,
        reason: EffectJournalRefusal,
    },
}

pub(crate) enum AcknowledgementFailure {
    Before {
        pending: PendingSubmission,
        reason: EffectJournalRefusal,
    },
    After {
        settled: SettledObligation<RefTransactionSubmission>,
        reason: EffectJournalRefusal,
    },
}

impl EffectBroker {
    pub(crate) fn owns_ref_transaction(&self, reservation: &ReservedSubmission) -> bool {
        Rc::ptr_eq(&self.journal, &reservation.journal)
    }

    /// Reconstruct only the already-paid request held by this exact live owner.
    /// No grant, reservation, journal event or resource transition occurs here.
    pub(crate) fn retained_ref_transaction_request(
        &self,
        pending: &PendingSubmission,
    ) -> Result<EffectRequest, RefTransactionEffectRefusal> {
        if !Rc::ptr_eq(&self.journal, &pending.journal) {
            return Err(RefTransactionEffectRefusal::Binding);
        }
        let journal = self.journal.borrow();
        journal
            .ensure_writable()
            .map_err(RefTransactionEffectRefusal::Journal)?;
        if journal.sink.is_none() {
            return Err(RefTransactionEffectRefusal::DurableJournalRequired);
        }
        let binding = pending.binding();
        let effect_id = binding.effect_id();
        let record = journal
            .positions
            .get(&effect_id)
            .and_then(|position| journal.records.get(*position))
            .ok_or(RefTransactionEffectRefusal::Binding)?;
        let ledger = self.ledger.handle();
        let obligation_id = pending.obligation.id();
        if journal.ref_transactions.get(&effect_id) != Some(binding)
            || record.effect_id != effect_id
            || record.operation != OperationClass::PublishRefTransaction
            || record.effect_class != EffectClass::CanonicalMutation
            || record.run_commitment != binding.run_commitment()
            || record.input_commitment != *binding.input_commitment()
            || record.obligation_class != Some(ObligationClass::RefTransactionSubmission)
            || record.obligation_state != ObligationState::DeferredExternally
            || record.terminal_outcome.is_some()
            || record.budget_consumed != record.budget_reserved
            || pending.obligation.receipt().transaction != binding.tx_id()
            || ledger.state_of(obligation_id) != Some(ObligationState::DeferredExternally)
            || ledger.reserved_for(obligation_id) != Some(ResourceVector::ZERO)
            || ledger.charged_to(obligation_id)
                != Some(
                    record
                        .budget_consumed
                        .mask(fgit_resource::GradeDisposition::Consumable),
                )
        {
            return Err(RefTransactionEffectRefusal::Binding);
        }
        Ok(binding.request(record.budget_consumed))
    }

    /// All refusal branches release an unstarted grant explicitly. No raw
    /// reservation escapes without its complete sealed-submission binding.
    pub(crate) fn reserve_ref_transaction(
        &mut self,
        grant: EffectGrant,
        binding: RefTransactionBinding,
    ) -> Result<ReservedSubmission, RefTransactionEffectRefusal> {
        let record = grant.record();
        if !Rc::ptr_eq(&self.journal, &grant.journal)
            || record.operation != OperationClass::PublishRefTransaction
            || record.effect_class != EffectClass::CanonicalMutation
            || record.effect_id != binding.effect_id()
            || record.run_commitment != binding.run_commitment()
            || &record.input_commitment != binding.input_commitment()
        {
            let _released = self
                .abort(grant)
                .map_err(RefTransactionEffectRefusal::Journal)?;
            return Err(RefTransactionEffectRefusal::Binding);
        }
        let seal_bytes = match fgit_codec::wire::encode_body(binding.seal()) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _released = self
                    .abort(grant)
                    .map_err(RefTransactionEffectRefusal::Journal)?;
                return Err(RefTransactionEffectRefusal::Codec(error));
            }
        };
        let binding_result = self
            .journal
            .borrow_mut()
            .bind_ref_transaction(record.effect_id, binding.clone());
        if let Err(reason) = binding_result {
            let _cleanup = self.abort(grant);
            return Err(RefTransactionEffectRefusal::Journal(reason));
        }
        let (record, budget, journal) = grant.into_parts();
        let bound = journal.borrow_mut().bind(
            record.effect_id,
            ObligationClass::RefTransactionSubmission,
            None,
        );
        if let Err(reason) = bound {
            let _cleanup = self.abort(EffectGrant {
                record,
                budget,
                journal,
            });
            return Err(RefTransactionEffectRefusal::Journal(reason));
        }
        let obligation = match self.ledger.reserve(
            RefTransactionRequest {
                transaction: binding.tx_id(),
                seal_commitment: fgit_crypto::sha256_digest(&seal_bytes),
            },
            budget,
        ) {
            Ok(obligation) => obligation,
            Err(error) => {
                let _cleanup = journal.borrow_mut().lifecycle(
                    record.effect_id,
                    LifecycleEvent::Abort,
                    ResourceVector::ZERO,
                    Vec::new(),
                    None,
                    Some(EffectTerminalOutcome::Aborted),
                );
                return Err(RefTransactionEffectRefusal::Resource(Box::new(error)));
            }
        };
        Ok(ReservedSubmission {
            binding,
            obligation,
            journal,
        })
    }
}

impl ReservedSubmission {
    pub(crate) const fn binding(&self) -> &RefTransactionBinding {
        &self.binding
    }

    pub(crate) fn abort(
        self,
        reason: NoCandidateReason,
    ) -> Result<SettledObligation<RefTransactionSubmission>, EffectJournalRefusal> {
        let settled = self
            .obligation
            .abort_unused(RefTransactionAborted { reason });
        self.journal.borrow_mut().lifecycle(
            self.binding.effect_id(),
            LifecycleEvent::Abort,
            ResourceVector::ZERO,
            Vec::new(),
            None,
            Some(EffectTerminalOutcome::Aborted),
        )?;
        Ok(settled)
    }

    pub(crate) fn start(self, actual: &ResourceVector) -> Result<PendingSubmission, StartFailure> {
        let writable = self.journal.borrow().ensure_writable();
        if let Err(reason) = writable {
            return Err(StartFailure::Before {
                reservation: self,
                reason: RefTransactionEffectRefusal::Journal(reason),
            });
        }
        let Self {
            binding,
            obligation,
            journal,
        } = self;
        let committed = match obligation.commit(
            RefTransactionSubmitted {
                transaction: binding.tx_id(),
            },
            actual,
        ) {
            Ok(committed) => committed,
            Err(error) => {
                let reason = RefTransactionEffectRefusal::Settlement(error.error());
                return Err(StartFailure::Before {
                    reservation: Self {
                        binding,
                        obligation: error.into_obligation(),
                        journal,
                    },
                    reason,
                });
            }
        };
        let committed_record = journal.borrow_mut().lifecycle(
            binding.effect_id(),
            LifecycleEvent::Commit,
            *actual,
            Vec::new(),
            None,
            None,
        );
        let obligation = committed.defer_acknowledgement(DeferralReason::AwaitingObservation);
        let deferred_record = journal.borrow_mut().lifecycle(
            binding.effect_id(),
            LifecycleEvent::Defer,
            *actual,
            Vec::new(),
            None,
            None,
        );
        let pending = PendingSubmission {
            binding,
            obligation,
            journal,
        };
        match committed_record.and(deferred_record) {
            Ok(()) => Ok(pending),
            Err(reason) => Err(StartFailure::After { pending, reason }),
        }
    }
}

impl PendingSubmission {
    pub(crate) const fn binding(&self) -> &RefTransactionBinding {
        &self.binding
    }

    pub(crate) fn acknowledge(
        self,
        observation: &ObservedRefTransaction,
    ) -> Result<SettledObligation<RefTransactionSubmission>, AcknowledgementFailure> {
        // Only the authenticated observation constructor can create this value.
        if observation.binding() != &self.binding {
            return Err(AcknowledgementFailure::Before {
                reason: EffectJournalRefusal::RefTransactionBinding {
                    effect_id: self.binding.effect_id(),
                },
                pending: self,
            });
        }
        let writable = self.journal.borrow().ensure_writable();
        if let Err(reason) = writable {
            return Err(AcknowledgementFailure::Before {
                pending: self,
                reason,
            });
        }
        let output: [u8; 32] = match observation.commitment().bytes().as_bytes().try_into() {
            Ok(output) => output,
            Err(_) => {
                return Err(AcknowledgementFailure::Before {
                    reason: EffectJournalRefusal::RefTransactionBinding {
                        effect_id: self.binding.effect_id(),
                    },
                    pending: self,
                });
            }
        };
        let settled = self.obligation.acknowledge(RefTransactionObserved {
            transaction: self.binding.tx_id(),
            outcome_commitment: observation.commitment(),
        });
        let recorded = self.journal.borrow_mut().lifecycle(
            self.binding.effect_id(),
            LifecycleEvent::Acknowledge,
            ResourceVector::ZERO,
            vec![output],
            None,
            Some(EffectTerminalOutcome::Acknowledged),
        );
        match recorded {
            Ok(()) => Ok(settled),
            Err(reason) => Err(AcknowledgementFailure::After { settled, reason }),
        }
    }
}
