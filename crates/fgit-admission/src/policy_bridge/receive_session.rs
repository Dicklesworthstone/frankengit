//! Exact-basis continuation for a production receive session.
//!
//! A non-atomic push must continue after either a committed OR refused command.
//! Both decisions advance the authority head. Clearing the validation witness
//! after a commit, or keeping the original head after a refusal, is not enough:
//! the former admits unrelated successors and the latter rejects valid later
//! commands. This driver advances only across its own verified one-decision
//! publication. Every actual decision still uses the shared admission planner,
//! lowerer, seal, CAS loop, and authoritative outcome resolver.
//!
//! The conservative profile deliberately does not walk arbitrary descendants.
//! An intervening publication requires a newly validated request on retry.

pub mod recovery;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use fgit_authority::{
    AsyncAuthorityStore, IdempotencyKey, SealAttempt, SemanticRequest, TerminalOutcome,
    bind_idempotency_key_async, read_authority_head_body_async, read_decision_batch_body_async,
};
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{CryptoBodyIdentity, RepositoryDecisionBatchBody};
use fgit_types::{DecisionOutcome, RepositoryAuthorityHeadId, TxId};

use crate::{
    AdmissionContext, AdmissionError, AdmissionInput, AdmissionLimits, AdmissionResult,
    AsyncAdmissionProjection, BasisBoundValidatedReceive, CommandOutcome, SessionMapping,
    SessionPlan, SessionTerminals, admit_one_async, assemble_result, basis_bound_receive_input,
    lower_ref_update, plan_session, read_basis_async, seal_attempt,
};

/// Select one non-atomic receive command for read-only lost-response recovery.
///
/// `index` is its zero-based position in the ORIGINAL wire command list, not
/// canonical ref-name order. This calls the admission lowerer's only key
/// derivation; transports and CLIs must not duplicate that identity protocol.
/// Pass the returned key to the existing authority key-recovery API under the
/// original authenticated tenant/repository/principal scope. A key is not a
/// credential. No storage is read or written here.
///
/// A missing observation at one index does not establish the command count,
/// session completion, or non-commit. Atomic receives use their original key
/// directly, even when they contain several ref commands.
pub fn non_atomic_command_key(
    original: &IdempotencyKey,
    index: usize,
) -> Result<IdempotencyKey, AdmissionError> {
    let limit = AdmissionLimits::default().max_commands;
    if index >= limit {
        return Err(AdmissionError::CommandLimitExceeded { limit });
    }
    crate::non_atomic_key(original, index)
}

/// An interrupted session may already have canonical outcomes for a prefix.
///
/// Remaining commands are UNKNOWN, not rejected: an interrupted store call may
/// have published. Retrying the same session key and semantic command list uses
/// the same transaction identities and recovers their authenticated outcomes.
#[derive(Debug)]
pub struct InterruptedSession {
    source: Box<AdmissionError>,
    session: Option<SessionMapping>,
    completed: Vec<CommandOutcome>,
}

const _: () = assert!(std::mem::size_of::<InterruptedSession>() <= 128);

impl InterruptedSession {
    /// Stable transaction mapping, present once the entire request was lowered.
    #[must_use]
    pub const fn session(&self) -> Option<&SessionMapping> {
        self.session.as_ref()
    }

    /// Only outcomes already returned by the authoritative resolver, in order.
    #[must_use]
    pub fn completed_commands(&self) -> &[CommandOutcome] {
        &self.completed
    }

    /// The exact underlying failure; no timeout is rewritten as non-commit.
    #[must_use]
    pub fn admission_error(&self) -> &AdmissionError {
        self.source.as_ref()
    }
}

impl Display for InterruptedSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "receive interrupted after {} authenticated command outcomes; remaining outcomes unknown: {}",
            self.completed.len(),
            self.source,
        )
    }
}

impl Error for InterruptedSession {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Admit a basis-bound receive while retaining the witness for every command.
///
/// This is a session coordinator, not a second publication implementation.
/// Atomic input enters the same one-transaction decision core. Non-atomic input
/// retains the existing per-command retry keys and original report order.
/// The transport owns authentication, quota, and cell-publication gates.
pub async fn admit<S, P>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    validated: &BasisBoundValidatedReceive,
    limits: AdmissionLimits,
    projection: &P,
) -> Result<AdmissionResult, InterruptedSession>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
{
    let input = basis_bound_receive_input(validated);
    let plan = plan_session(context, &input, limits).map_err(|source| InterruptedSession {
        source: Box::new(source),
        session: None,
        completed: Vec::new(),
    })?;
    let mapping = SessionMapping {
        atomic: plan.atomic,
        tx_ids: plan.tx_ids.clone(),
    };
    // Bind the WHOLE request before admitting any child. Per-index bindings
    // alone permit appending commands to an already used session key. Bind all
    // child keys up front too, so a changed wire-order mapping cannot publish a
    // new prefix before encountering a conflicting existing child binding.
    bind_session_keys(store, cx, context, &input, &plan)
        .await
        .map_err(|source| InterruptedSession {
            source: Box::new(source),
            session: Some(mapping.clone()),
            completed: Vec::new(),
        })?;
    let mut outcomes = Vec::with_capacity(plan.lowered.len());
    let mut permitted = validated.validation_basis();

    for (index, lowered) in plan.lowered.iter().enumerate() {
        let attempt = async {
            if let Some(previous) = outcomes.last().copied() {
                permitted = advance_over_own_decision(
                    store,
                    cx,
                    context,
                    permitted,
                    plan.tx_ids[index - 1],
                    previous,
                    input.closure.object_closure_root,
                )
                .await?;
            }
            // Always Some, including after a recovered or newly committed ref.
            // A race after continuation verification meets this guard again at
            // every CAS plan; this read cannot authorize a later foreign head.
            admit_one_async(
                store,
                cx,
                context,
                input.closure,
                Some(permitted),
                lowered,
                projection,
                limits,
            )
            .await
        }
        .await;
        match attempt {
            Ok(terminal) => outcomes.push(terminal),
            Err(source) => {
                let completed = outcomes
                    .into_iter()
                    .zip(plan.tx_ids.iter().copied())
                    .map(|(terminal, tx_id)| CommandOutcome { tx_id, terminal })
                    .collect();
                return Err(InterruptedSession {
                    source: Box::new(source),
                    session: Some(mapping),
                    completed,
                });
            }
        }
    }
    // No extra authority read after the final outcome. A successful admission
    // cannot be turned into an error by optional continuation work or cleanup.
    let terminals = if plan.atomic {
        SessionTerminals::Atomic(outcomes[0])
    } else {
        SessionTerminals::PerCommand(outcomes)
    };
    Ok(assemble_result(plan, terminals))
}

async fn bind_session_keys<S>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    input: &AdmissionInput<'_>,
    plan: &SessionPlan,
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let whole = if plan.atomic {
        None
    } else {
        let commands = input
            .updates
            .iter()
            .map(|update| lower_ref_update(update.old, update.new, update.ref_name))
            .collect::<Result<Vec<_>, _>>()?;
        let options = input
            .push_options
            .iter()
            .cloned()
            .map(fgit_authority::PushOption::new)
            .collect::<Result<Vec<_>, _>>()?;
        let whole = SealAttempt {
            tenant_id: context.tenant_id,
            repository_id: context.repository_id,
            authenticated_principal_id: context.principal_id,
            idempotency_key: context.idempotency_key.clone(),
            request: SemanticRequest::build(
                fgit_authority::RECEIVE_ADMISSION_SCHEMA,
                context.object_format,
                false,
                commands,
                options,
                Vec::new(),
            )?,
        };
        let (identity, _) = whole.derive()?;
        // This reserves the caller's original key; it does NOT seal or publish
        // another transaction. Only the unchanged child TxIds in SessionMapping
        // acquire terminal decisions. Pack bytes and validation basis remain
        // excluded by the existing canonical SemanticRequest/SealAttempt rules.
        bind_idempotency_key_async(store, cx, &whole, identity).await?;
        Some(whole)
    };
    for (lowered, identity) in plan.lowered.iter().zip(&plan.tx_ids) {
        bind_idempotency_key_async(store, cx, &seal_attempt(context, lowered), *identity).await?;
    }
    if let Some(whole) = whole {
        // This recovery carrier is checked against all of those bindings on
        // read. It neither creates another seal nor authorizes publication.
        // Persist before the first child so interruption cannot leave committed
        // commands whose original session shape was never recorded.
        recovery::stage(store, cx, context, &whole, plan).await?;
    }
    Ok(())
}

async fn advance_over_own_decision<S>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    permitted: RepositoryAuthorityHeadId,
    tx_id: TxId,
    terminal: TerminalOutcome,
    closure_root: fgit_types::Digest,
) -> Result<RepositoryAuthorityHeadId, AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
{
    let (observed, _, _) = read_basis_async(store, cx, &context.head_key).await?;
    if observed.body().repository_id != context.repository_id {
        return Err(AdmissionError::MaterializationMismatch(
            "receive continuation repository",
        ));
    }
    if observed.id() == permitted {
        // Common retry case: earlier commands were already terminal before this
        // request's fresh quarantine validation selected its current basis.
        return Ok(permitted);
    }
    if observed.body().predecessor_head_id != Some(permitted) {
        // Never treat an arbitrary newer head as authorization for old evidence.
        // Keep the witness; the shared planner produces the typed stale refusal.
        return Ok(permitted);
    }
    let predecessor = read_authority_head_body_async(store, cx, permitted).await?;
    let Some(tail) = observed.body().decision_tail_id else {
        return Err(AdmissionError::MaterializationMismatch(
            "receive continuation decision tail",
        ));
    };
    let batch = read_decision_batch_body_async(store, cx, tail).await?;
    let basis = PublicationBasis::new(permitted, predecessor);
    verify_pair(&CryptoBodyIdentity, &basis, &batch, observed.body())?;
    if !is_own_decision(&batch, tx_id, terminal, closure_root)
        || observed.body().configuration_root != basis.body().configuration_root
        || observed.body().policy_epoch != basis.body().policy_epoch
        || observed.body().format_registry_epoch != basis.body().format_registry_epoch
        || observed.body().last_checkpoint_id != basis.body().last_checkpoint_id
    {
        return Ok(permitted);
    }
    Ok(observed.id())
}

fn is_own_decision(
    batch: &RepositoryDecisionBatchBody,
    tx_id: TxId,
    terminal: TerminalOutcome,
    closure_root: fgit_types::Digest,
) -> bool {
    let [decision] = batch.decisions.as_slice() else {
        return false;
    };
    if decision.tx_id != tx_id
        || decision.decision_sequence != terminal.decision_sequence
        || decision.outcome != terminal.outcome
        || batch.compaction_generation_link.is_some()
    {
        return false;
    }
    match terminal.outcome {
        DecisionOutcome::Refused { .. } => batch.committed_rcrs.is_empty(),
        DecisionOutcome::Committed { .. } => {
            let [record] = batch.committed_rcrs.as_slice() else {
                return false;
            };
            record.tx_id == tx_id && record.object_closure_root == closure_root
        }
    }
}

#[cfg(test)]
mod recovery_selector_tests {
    use super::*;

    #[test]
    fn recovery_uses_the_admission_key_for_every_permitted_wire_index() {
        for bytes in [Vec::new(), b"opaque\0key\n\xff".to_vec(), vec![b'k'; 256]] {
            let original = IdempotencyKey::new(bytes).unwrap();
            let mut previous = None;
            for index in 0..64 {
                let selected = non_atomic_command_key(&original, index).unwrap();
                assert_eq!(selected, crate::non_atomic_key(&original, index).unwrap());
                assert_ne!(selected, original);
                assert_ne!(previous.as_ref(), Some(&selected));
                previous = Some(selected);
            }
        }
    }

    #[test]
    fn an_out_of_range_command_is_not_coerced_into_a_different_key() {
        let key = IdempotencyKey::new(b"original".to_vec()).unwrap();
        for index in [64, 65, usize::MAX] {
            assert!(matches!(
                non_atomic_command_key(&key, index),
                Err(AdmissionError::CommandLimitExceeded { limit: 64 })
            ));
        }
    }
}
