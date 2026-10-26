//! Exact-basis continuation for a production receive session.
//!
//! A non-atomic push must continue after either a committed OR refused command.
//! Both decisions advance the authority head. Clearing the validation witness
//! after a commit, or keeping the original head after a refusal, is not enough:
//! the former admits unrelated successors and the latter rejects valid later
//! commands. This driver advances only across verified publications whose
//! complete decision lists belong to this session. Opt-in projections combine
//! independent commands through the shared bounded microbatch driver; other
//! projections retain one decision per publication. Every decision still uses
//! the shared admission planner, lowerer, seal, and authority-head CAS.
//!
//! The conservative profile deliberately does not walk arbitrary descendants.
//! An intervening publication requires a newly validated request on retry.

pub mod recovery;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use fgit_authority::{
    AsyncAuthorityStore, IdempotencyKey, TerminalOutcome, bind_idempotency_key_async,
    bind_idempotency_keys_async, read_authority_head_body_async, read_decision_batch_body_async,
};
use fgit_chronicle::{PublicationBasis, verify_pair};
use fgit_codec::{CryptoBodyIdentity, RepositoryDecisionBatchBody};
use fgit_types::{DecisionOutcome, RefusalCode, RepositoryAuthorityHeadId, TxId};

use crate::{
    AdmissionContext, AdmissionError, AdmissionInput, AdmissionLimits, AdmissionResult,
    AsyncAdmissionProjection, BasisBoundValidatedReceive, CommandOutcome, SessionMapping,
    SessionPlan, SessionTerminals, admit_one_async, assemble_result, basis_bound_receive_input,
    plan_session_checked, read_basis_async, seal_attempt,
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
    let limit = crate::MAX_RECEIVE_SESSION_COMMANDS;
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

    /// Only authenticated canonical terminal outcomes, in original wire order.
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
    admit_with_checkpoint(
        store,
        cx,
        context,
        validated,
        limits,
        projection,
        &|| Ok(()),
    )
    .await
}

/// Admit with bounded cancellation/budget probes during CPU preflight and key
/// binding. The callback never converts an authenticated final outcome into an
/// interruption; after publication, the existing decision core owns completion.
pub async fn admit_with_checkpoint<S, P, C>(
    store: &S,
    cx: &S::Context,
    context: &AdmissionContext,
    validated: &BasisBoundValidatedReceive,
    limits: AdmissionLimits,
    projection: &P,
    checkpoint: &C,
) -> Result<AdmissionResult, InterruptedSession>
where
    S: AsyncAuthorityStore + ?Sized,
    P: AsyncAdmissionProjection<S> + ?Sized,
    C: Fn() -> Result<(), RefusalCode> + Sync,
{
    let input = basis_bound_receive_input(validated);
    let plan = plan_session_checked(context, &input, limits, checkpoint).map_err(|source| {
        InterruptedSession {
            source: Box::new(source),
            session: None,
            completed: Vec::new(),
        }
    })?;
    let mapping = SessionMapping {
        atomic: plan.atomic,
        tx_ids: plan.tx_ids.clone(),
    };
    // Bind the WHOLE request before admitting any child. Per-index bindings
    // alone permit appending commands to an already used session key. Bind all
    // child keys up front too, so a changed wire-order mapping cannot publish a
    // new prefix before encountering a conflicting existing child binding.
    bind_session_keys(store, cx, context, &input, &plan, checkpoint)
        .await
        .map_err(|source| InterruptedSession {
            source: Box::new(source),
            session: Some(mapping.clone()),
            completed: Vec::new(),
        })?;
    let mut outcomes = Vec::with_capacity(plan.lowered.len());
    if !plan.atomic && projection.supports_ref_microbatching() {
        if let Err(source) = crate::microbatch::admit_non_atomic_async(
            store,
            cx,
            context,
            &input,
            &plan,
            limits,
            projection,
            &mut outcomes,
        )
        .await
        {
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
        return Ok(assemble_result(
            plan,
            SessionTerminals::PerCommand(outcomes),
        ));
    }
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
                // The original validator's commitment stays sound at any later
                // head: equal authority means identical validator inputs.
                Some(crate::ValidationBasis {
                    head: permitted,
                    authority: validated.validation_authority(),
                }),
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
    checkpoint: &(impl Fn() -> Result<(), RefusalCode> + Sync),
) -> Result<(), AdmissionError>
where
    S: AsyncAuthorityStore + ?Sized,
{
    // Validate the entire carrier, canonical whole-session binding and exact
    // child correspondence before reserving any original or derived key.
    let prepared = if plan.atomic {
        None
    } else {
        Some(recovery::prepare_session(context, input, plan, checkpoint)?)
    };
    if let Some(prepared) = &prepared {
        // A narrower backend profile must refuse deterministically before the
        // original key is reserved for a carrier it can never retain.
        if prepared.bytes.len() > store.limits().body_bytes {
            return Err(AdmissionError::SessionDescriptorBytesExceeded {
                limit: store.limits().body_bytes,
                observed: prepared.bytes.len(),
            });
        }
        checkpoint().map_err(AdmissionError::AsyncProjectionUnavailable)?;
        let (identity, _) = prepared.whole.derive()?;
        // The original key binds an unsealed session identity, never a second
        // logical transaction or publication authority.
        bind_idempotency_key_async(store, cx, &prepared.whole, identity).await?;
    }
    for (lowered, identities) in plan
        .lowered
        .chunks(fgit_authority::MAX_IMMUTABLE_BATCH_ITEMS)
        .zip(
            plan.tx_ids
                .chunks(fgit_authority::MAX_IMMUTABLE_BATCH_ITEMS),
        )
    {
        let mut attempts = Vec::with_capacity(lowered.len());
        for request in lowered {
            checkpoint().map_err(AdmissionError::AsyncProjectionUnavailable)?;
            attempts.push(seal_attempt(context, request));
        }
        // The original whole-session key above settles separately before any
        // child write. The bounded group here only changes physical storage:
        // each child still has its exact key and independent identity. The
        // backend checks the same request context inside its transaction.
        let bindings = bind_idempotency_keys_async(store, cx, &attempts).await?;
        for (binding, identity) in bindings.iter().zip(identities) {
            checkpoint().map_err(AdmissionError::AsyncProjectionUnavailable)?;
            if binding.tx_id() != *identity {
                return Err(AdmissionError::MaterializationMismatch(
                    "receive child binding identity",
                ));
            }
        }
    }
    if let Some(prepared) = prepared {
        checkpoint().map_err(AdmissionError::AsyncProjectionUnavailable)?;
        // All original/child bindings precede this immutable recovery carrier,
        // and the complete carrier precedes the first child seal or decision.
        recovery::stage(store, cx, context, &prepared.bytes).await?;
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
            for index in 0..crate::MAX_RECEIVE_SESSION_COMMANDS {
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
        for index in [
            crate::MAX_RECEIVE_SESSION_COMMANDS,
            crate::MAX_RECEIVE_SESSION_COMMANDS + 1,
            usize::MAX,
        ] {
            assert!(matches!(
                non_atomic_command_key(&key, index),
                Err(AdmissionError::CommandLimitExceeded { limit })
                    if limit == crate::MAX_RECEIVE_SESSION_COMMANDS
            ));
        }
    }
}
