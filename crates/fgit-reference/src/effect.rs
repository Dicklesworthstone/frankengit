//! The target-disjoint net-effect normal form, and the reference folder that
//! produces it.
//!
//! Plan §15.4 requires finalization to evaluate statements in source order
//! against scratch state that already contains earlier same-transaction
//! effects, then diff the basis against the final scratch state and emit
//! target-disjoint canonical effects. Every source intent must map to one
//! surviving effect, an identity/inverse/absorbed no-op, a statement failure,
//! or a transaction abort.
//!
//! Two of those requirements are structural here rather than checked:
//!
//! * **target-disjointness** — [`NetEffects`] stores each effect family in a
//!   `BTreeMap` keyed by its target, so two surviving effects for one target
//!   cannot be represented;
//! * **totality of the intent map** — [`FoldReport::mappings`] holds one entry
//!   per source intent, and [`FoldReport::is_total_for`] checks the count
//!   against the request it came from.
//!
//! ## Ownership boundary
//!
//! This module owns the normal-form **types** and one deliberately trivial
//! reference folder. The full folding rules — absorption lattices, cascades,
//! and the value-of-information refinement around them — belong to FG-008a,
//! which differential-tests its optimized folder against [`ReferenceFolder`].
//! Keeping one obviously-correct folder here is what makes that comparison
//! meaningful; making this one clever would only create proof debt.
//!
//! ## Ordering is never map iteration order
//!
//! Plan §16.3: "Hash-map iteration order is never publication semantics." Every
//! collection here is a `BTreeMap` or `BTreeSet` over a totally ordered key, so
//! iteration order is the key order and nothing else.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::hash::Digest;
use fgit_types::native::GitOid;
use fgit_types::vocabulary::{MismatchPolicy, RefusalCode};

use crate::intent::{
    ForgeEventKind, ForgeStreamId, ForgeStreamPosition, Intent, IntentAddress, OutboxDeliveryKey,
    RefIntent, RetentionIntent, RetentionRoot, TransactionRequest,
};
use fgit_types::refs::RefName;

/// The surviving effect on one ref.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefEffect {
    /// The ref ends the transaction holding this object.
    Set(GitOid),
    /// The ref ends the transaction absent.
    Delete,
}

/// The surviving effect on one retention root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RetentionEffect {
    /// The root ends the transaction present.
    Add,
    /// The root ends the transaction absent.
    Remove,
}

/// The target one intent acted on.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EffectTarget {
    /// One ref.
    Ref(RefName),
    /// One forge stream.
    ForgeStream(ForgeStreamId),
    /// One retention root.
    Retention(RetentionRoot),
    /// One outbox delivery key.
    Outbox(OutboxDeliveryKey),
}

/// Why an intent produced no surviving effect.
///
/// Plan §15.4 requires an *explicit* disposition rather than silent
/// disappearance, so each absorption has a named cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AbsorptionReason {
    /// The intent asked for the value the basis already held.
    IdentityEffect,
    /// A later intent in the same transaction overwrote this target.
    OverwrittenBySucceedingIntent,
    /// A later intent restored the basis value, cancelling this one.
    InverseCancelled,
    /// The precondition did not match and the statement policy is
    /// [`MismatchPolicy::NoOp`].
    PreconditionMismatchNoOp,
    /// The intent requested an outbox delivery already bound to identical
    /// canonical parameters, so no new external effect is owed.
    DuplicateIdenticalDelivery,
}

/// What became of one source intent.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IntentDisposition {
    /// The intent contributed the surviving effect on this target.
    Surviving(EffectTarget),
    /// The intent produced no effect, for a named reason.
    Absorbed(AbsorptionReason),
    /// The intent failed locally under [`MismatchPolicy::StatementError`].
    StatementError(RefusalCode),
    /// The transaction aborted, so this intent produced nothing.
    TransactionAborted,
}

/// One source intent and its disposition.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IntentMapping {
    /// Where the intent sat in the request.
    pub address: IntentAddress,
    /// What became of it.
    pub disposition: IntentDisposition,
}

/// The target-disjoint canonical effects of one transaction.
///
/// Emptiness is meaningful: a transaction whose intents all absorb is a
/// committed no-op, not a refusal.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetEffects {
    /// Surviving ref effects, keyed by ref name.
    pub refs: BTreeMap<RefName, RefEffect>,
    /// Forge events appended per stream, in append order.
    pub forge: BTreeMap<ForgeStreamId, Vec<ForgeEventKind>>,
    /// Surviving retention effects, keyed by root.
    pub retention: BTreeMap<RetentionRoot, RetentionEffect>,
    /// Outbox deliveries owed, keyed by delivery key.
    pub outbox: BTreeMap<OutboxDeliveryKey, Digest>,
}

impl NetEffects {
    /// True when no target is affected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
            && self.forge.is_empty()
            && self.retention.is_empty()
            && self.outbox.is_empty()
    }

    /// Total number of affected targets.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.refs.len() + self.forge.len() + self.retention.len() + self.outbox.len()
    }

    /// Every ref this transaction moves or deletes.
    pub fn moved_refs(&self) -> impl Iterator<Item = &RefName> {
        self.refs.keys()
    }
}

/// The result of folding one transaction's intents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FoldOutcome {
    /// The fold produced a normal form.
    Folded(NetEffects),
    /// The transaction aborted at a named intent.
    Aborted {
        /// The terminal refusal the abort produces.
        code: RefusalCode,
        /// The intent that aborted the transaction.
        at: IntentAddress,
    },
}

/// A fold result together with the total intent map that explains it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldReport {
    /// Whether a normal form was produced, or where the abort happened.
    pub outcome: FoldOutcome,
    /// One entry per source intent, in source order.
    pub mappings: Vec<IntentMapping>,
}

impl FoldReport {
    /// True when every source intent of `request` has exactly one mapping.
    ///
    /// This is plan §15.4's totality requirement, checkable rather than
    /// asserted.
    #[must_use]
    pub fn is_total_for(&self, request: &TransactionRequest) -> bool {
        self.mappings.len() == request.intent_count()
    }

    /// The effects, when the fold did not abort.
    #[must_use]
    pub const fn effects(&self) -> Option<&NetEffects> {
        match &self.outcome {
            FoldOutcome::Folded(effects) => Some(effects),
            FoldOutcome::Aborted { .. } => None,
        }
    }
}

/// The basis state a fold evaluates preconditions against.
///
/// The fold reads this and never the live model state, which is what makes it
/// a pure function of `(basis, request)`.
#[derive(Clone, Copy, Debug)]
pub struct FoldBasis<'a> {
    /// Ref values at the pinned basis.
    pub refs: &'a BTreeMap<RefName, GitOid>,
    /// Forge stream positions at the pinned basis.
    pub forge_positions: &'a BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    /// Retention roots at the pinned basis.
    pub retention: &'a BTreeSet<RetentionRoot>,
    /// Outbox deliveries already bound at the pinned basis.
    pub outbox: &'a BTreeMap<OutboxDeliveryKey, Digest>,
}

/// A component that folds ordered intents into a net-effect normal form.
///
/// The trait exists so FG-008a's production folder and [`ReferenceFolder`] can
/// be run against identical inputs and compared. Implementations must be pure:
/// the same `(basis, request)` must always produce the same [`FoldReport`].
pub trait NetEffectFolder {
    /// Folds `request` against `basis`.
    fn fold(&self, basis: FoldBasis<'_>, request: &TransactionRequest) -> FoldReport;
}

/// The deliberately trivial reference folder.
///
/// It evaluates intents in source order against a scratch copy of the basis
/// with read-your-own-writes, then diffs the basis against the final scratch
/// state. It has no absorption lattice, no cascade rules, and no refinement:
/// absorption is discovered by the diff, which is the simplest rule that
/// satisfies plan §15.4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferenceFolder;

/// Mutable scratch state a fold evaluates against.
#[derive(Clone, Debug)]
struct Scratch {
    refs: BTreeMap<RefName, GitOid>,
    forge_positions: BTreeMap<ForgeStreamId, ForgeStreamPosition>,
    forge_events: BTreeMap<ForgeStreamId, Vec<ForgeEventKind>>,
    retention: BTreeSet<RetentionRoot>,
    outbox: BTreeMap<OutboxDeliveryKey, Digest>,
}

impl Scratch {
    fn from_basis(basis: FoldBasis<'_>) -> Self {
        Self {
            refs: basis.refs.clone(),
            forge_positions: basis.forge_positions.clone(),
            forge_events: BTreeMap::new(),
            retention: basis.retention.clone(),
            outbox: basis.outbox.clone(),
        }
    }
}

/// What applying one intent to scratch state produced.
enum Applied {
    /// The intent applied; the named target may or may not still differ from
    /// the basis once later intents run.
    Changed(EffectTarget),
    /// The intent was absorbed immediately, for a reason the diff cannot
    /// discover on its own.
    Absorbed(AbsorptionReason),
    /// The intent's precondition did not match the scratch state.
    Mismatch(RefusalCode),
}

impl NetEffectFolder for ReferenceFolder {
    fn fold(&self, basis: FoldBasis<'_>, request: &TransactionRequest) -> FoldReport {
        let mut scratch = Scratch::from_basis(basis);
        let mut mappings = Vec::with_capacity(request.intent_count());
        let mut contributed: BTreeMap<EffectTarget, usize> = BTreeMap::new();

        for (address, intent) in request.addressed_intents() {
            let policy = request
                .statements
                .get(address.statement.0)
                .map(|statement| statement.mismatch_policy)
                .unwrap_or(MismatchPolicy::TxnAbort);

            match apply_intent(&mut scratch, intent) {
                Applied::Changed(target) => {
                    contributed.insert(target.clone(), mappings.len());
                    mappings.push(IntentMapping {
                        address,
                        disposition: IntentDisposition::Surviving(target),
                    });
                }
                Applied::Absorbed(reason) => mappings.push(IntentMapping {
                    address,
                    disposition: IntentDisposition::Absorbed(reason),
                }),
                Applied::Mismatch(code) => match policy {
                    MismatchPolicy::NoOp => mappings.push(IntentMapping {
                        address,
                        disposition: IntentDisposition::Absorbed(
                            AbsorptionReason::PreconditionMismatchNoOp,
                        ),
                    }),
                    MismatchPolicy::StatementError => mappings.push(IntentMapping {
                        address,
                        disposition: IntentDisposition::StatementError(code),
                    }),
                    MismatchPolicy::TxnAbort => {
                        // An abort emits no canonical effect, so every source
                        // intent — those already evaluated, the aborting one,
                        // and those never reached — maps to
                        // `TransactionAborted`. The map stays total.
                        let aborted = request
                            .addressed_intents()
                            .map(|(address, _)| IntentMapping {
                                address,
                                disposition: IntentDisposition::TransactionAborted,
                            })
                            .collect();
                        return FoldReport {
                            outcome: FoldOutcome::Aborted { code, at: address },
                            mappings: aborted,
                        };
                    }
                },
            }
        }

        let effects = diff(basis, &scratch);
        retire_absorbed(&effects, &contributed, &mut mappings);
        FoldReport {
            outcome: FoldOutcome::Folded(effects),
            mappings,
        }
    }
}

/// Applies one intent to scratch state with read-your-own-writes.
fn apply_intent(scratch: &mut Scratch, intent: &Intent) -> Applied {
    match intent {
        Intent::Ref(RefIntent::Update {
            name,
            expected,
            new,
            ..
        }) => {
            if !expected.is_satisfied_by(scratch.refs.get(name)) {
                return Applied::Mismatch(RefusalCode::ExpectedOldRefMismatch);
            }
            scratch.refs.insert(name.clone(), *new);
            Applied::Changed(EffectTarget::Ref(name.clone()))
        }
        Intent::Ref(RefIntent::Delete { name, expected }) => {
            if !expected.is_satisfied_by(scratch.refs.get(name)) {
                return Applied::Mismatch(RefusalCode::ExpectedOldRefMismatch);
            }
            scratch.refs.remove(name);
            Applied::Changed(EffectTarget::Ref(name.clone()))
        }
        Intent::Forge(forge) => {
            let current = scratch
                .forge_positions
                .get(&forge.stream)
                .copied()
                .unwrap_or(ForgeStreamPosition::GENESIS);
            if current != forge.expected_position {
                return Applied::Mismatch(RefusalCode::ForgeTransitionInvalid);
            }
            if current.is_exhausted() {
                return Applied::Mismatch(RefusalCode::ResourceBudgetExceeded);
            }
            scratch
                .forge_positions
                .insert(forge.stream, current.successor());
            scratch
                .forge_events
                .entry(forge.stream)
                .or_default()
                .push(forge.event.clone());
            Applied::Changed(EffectTarget::ForgeStream(forge.stream))
        }
        Intent::Retention(RetentionIntent::AddRoot(root)) => {
            if scratch.retention.contains(root) {
                return Applied::Absorbed(AbsorptionReason::IdentityEffect);
            }
            scratch.retention.insert(*root);
            Applied::Changed(EffectTarget::Retention(*root))
        }
        Intent::Retention(RetentionIntent::RemoveRoot(root)) => {
            if scratch.retention.remove(root) {
                Applied::Changed(EffectTarget::Retention(*root))
            } else {
                Applied::Absorbed(AbsorptionReason::IdentityEffect)
            }
        }
        Intent::Outbox(outbox) => {
            match scratch.outbox.get(&outbox.delivery_key) {
                // Same key, identical canonical parameters: the effect is
                // already owed, so nothing new is owed. This is the permitted
                // twin of the refusal below, and it is what keeps an outbox
                // retry from duplicating a canonical event (release-blocking
                // invariant 22).
                Some(bound) if *bound == outbox.parameters => {
                    Applied::Absorbed(AbsorptionReason::DuplicateIdenticalDelivery)
                }
                // Same key, different canonical parameters: two contradictory
                // values for one target, which plan §15.4 refuses rather than
                // normalizing into an invented policy.
                //
                // `AtomicTransactionAborted` is the closest published code and
                // classifies as `RefusalClass::ConflictingEffects`. A request
                // to `fgit-types` for a dedicated effect-scoped idempotency
                // code is open; if it lands, this refines to that code and the
                // class becomes `IdempotencyReuse`. The condition detected and
                // the behaviour are unaffected either way.
                Some(_) => Applied::Mismatch(RefusalCode::AtomicTransactionAborted),
                None => {
                    scratch
                        .outbox
                        .insert(outbox.delivery_key, outbox.parameters);
                    Applied::Changed(EffectTarget::Outbox(outbox.delivery_key))
                }
            }
        }
    }
}

/// Diffs the basis against the final scratch state.
fn diff(basis: FoldBasis<'_>, scratch: &Scratch) -> NetEffects {
    let mut effects = NetEffects::default();

    for (name, value) in &scratch.refs {
        if basis.refs.get(name) != Some(value) {
            effects.refs.insert(name.clone(), RefEffect::Set(*value));
        }
    }
    for name in basis.refs.keys() {
        if !scratch.refs.contains_key(name) {
            effects.refs.insert(name.clone(), RefEffect::Delete);
        }
    }
    for (stream, events) in &scratch.forge_events {
        if !events.is_empty() {
            effects.forge.insert(*stream, events.clone());
        }
    }
    for root in &scratch.retention {
        if !basis.retention.contains(root) {
            effects.retention.insert(*root, RetentionEffect::Add);
        }
    }
    for root in basis.retention {
        if !scratch.retention.contains(root) {
            effects.retention.insert(*root, RetentionEffect::Remove);
        }
    }
    for (key, parameters) in &scratch.outbox {
        if basis.outbox.get(key) != Some(parameters) {
            effects.outbox.insert(*key, *parameters);
        }
    }

    effects
}

/// Resolves each provisionally-surviving intent against the diff.
///
/// The four outcomes are exactly plan §15.4's, decided by two independent
/// questions — did the target end up different from the basis, and was this
/// intent the last one to write that target?
///
/// | target changed | last writer | disposition |
/// |---|---|---|
/// | yes | yes | `Surviving` |
/// | yes | no  | `Absorbed(OverwrittenBySucceedingIntent)` |
/// | no  | yes | `Absorbed(IdentityEffect)` |
/// | no  | no  | `Absorbed(InverseCancelled)` |
///
/// Forge streams accumulate rather than overwrite, so every forge intent that
/// appended an event keeps its surviving disposition.
fn retire_absorbed(
    effects: &NetEffects,
    contributed: &BTreeMap<EffectTarget, usize>,
    mappings: &mut [IntentMapping],
) {
    for (index, mapping) in mappings.iter_mut().enumerate() {
        let IntentDisposition::Surviving(target) = &mapping.disposition else {
            continue;
        };
        let target_changed = match target {
            EffectTarget::Ref(name) => effects.refs.contains_key(name),
            EffectTarget::ForgeStream(stream) => effects.forge.contains_key(stream),
            EffectTarget::Retention(root) => effects.retention.contains_key(root),
            EffectTarget::Outbox(key) => effects.outbox.contains_key(key),
        };
        if matches!(target, EffectTarget::ForgeStream(_)) {
            if !target_changed {
                mapping.disposition =
                    IntentDisposition::Absorbed(AbsorptionReason::IdentityEffect);
            }
            continue;
        }
        let is_last_writer = contributed.get(target) == Some(&index);
        mapping.disposition = match (target_changed, is_last_writer) {
            (true, true) => continue,
            (true, false) => {
                IntentDisposition::Absorbed(AbsorptionReason::OverwrittenBySucceedingIntent)
            }
            (false, true) => IntentDisposition::Absorbed(AbsorptionReason::IdentityEffect),
            (false, false) => IntentDisposition::Absorbed(AbsorptionReason::InverseCancelled),
        };
    }
}
