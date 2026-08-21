#![forbid(unsafe_code)]
//! Typed transaction-intent evaluation and target-disjoint normal-form folding.
//!
//! A client submits [`fgit_reference::intent::TransactionRequest`] values: typed
//! intents and their asserted preconditions, never caller-computed effects or
//! resulting roots. [`IntentEvaluator`] evaluates those intents in source order
//! against one pinned basis, applying read-your-own-writes to a private scratch
//! state. It then emits the target-disjoint [`NetEffects`] normal form required
//! by protocol contract §13 and plan §15.4.
//!
//! ## Mismatch and refusal vocabulary
//!
//! * A ref precondition mismatch is
//!   [`RefusalCode::ExpectedOldRefMismatch`].
//! * A forge position mismatch is [`RefusalCode::ForgeTransitionInvalid`]; an
//!   exhausted position is [`RefusalCode::ResourceBudgetExceeded`].
//! * Reusing an outbox delivery key with different canonical parameters is
//!   [`RefusalCode::EffectIdempotencyKeyReuse`].
//! * An impossible ambiguous final-effect candidate is
//!   [`RefusalCode::ConflictingSemanticEffects`].
//!
//! The statement's [`MismatchPolicy`] decides whether an ordinary precondition
//! mismatch becomes an explicit absorbed no-op, a statement-local error, or a
//! transaction abort. A transaction abort has no effects and maps every source
//! intent, including intents after the triggering one, to
//! [`IntentDisposition::TransactionAborted`].
//!
//! The production evaluator is independently implemented here and is compared
//! in tests with `fgit-reference`'s deliberately simple `ReferenceFolder`.

pub mod combiner;
pub mod lanes;

use std::collections::{BTreeMap, BTreeSet};

use fgit_codec::{CodecRefusal, Encoder};
use fgit_reference::effect::{
    AbsorptionReason, EffectTarget, FoldBasis, FoldOutcome, FoldReport, IntentDisposition,
    IntentMapping, NetEffectFolder, NetEffects, RefEffect, RetentionEffect,
};
use fgit_reference::intent::{
    ForgeEventKind, ForgeStreamId, ForgeStreamPosition, Intent, IntentAddress, IntentIndex,
    OutboxDeliveryKey, RefIntent, RetentionClass, RetentionIntent, RetentionRoot, StatementIndex,
    TransactionRequest,
};
use fgit_reference::state::RepositoryState;
use fgit_types::hash::Digest;
use fgit_types::native::GitOid;
use fgit_types::refs::RefName;
use fgit_types::vocabulary::{MismatchPolicy, RefusalCode};

pub use fgit_reference::effect::{
    FoldOutcome as TransactionFoldOutcome, FoldReport as TransactionFoldReport,
};

/// Wire revision of [`canonical_fold_bytes`]'s normal-form payload.
pub const NORMAL_FORM_FORMAT_VERSION: u16 = 1;

/// Pure evaluator for typed transaction intents.
///
/// The evaluator contains no mutable state, reads no ambient state, and has no
/// API that accepts caller-computed [`NetEffects`]. Its result is therefore a
/// deterministic function of the pinned basis and source-ordered request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntentEvaluator;

impl IntentEvaluator {
    /// Creates a pure intent evaluator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Folds a request against its pinned root projection.
    #[must_use]
    pub fn evaluate(&self, basis: FoldBasis<'_>, request: &TransactionRequest) -> FoldReport {
        let mut scratch = Scratch::from_basis(basis);
        let mut mappings = Vec::with_capacity(request.intent_count());
        let mut contributed = BTreeMap::new();

        for (statement_offset, statement) in request.statements.iter().enumerate() {
            for (intent_offset, intent) in statement.intents.iter().enumerate() {
                let address = IntentAddress {
                    statement: StatementIndex(statement_offset),
                    intent: IntentIndex(intent_offset),
                };
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
                    Applied::Mismatch(code) => match statement.mismatch_policy {
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
                        MismatchPolicy::TxnAbort => return aborted_report(request, code, address),
                    },
                }
            }
        }

        let effects = match normal_form_from_scratch(basis, &scratch) {
            Ok(effects) => effects,
            Err(code) => {
                let Some((address, _)) = request.addressed_intents().next() else {
                    return FoldReport {
                        outcome: FoldOutcome::Folded(NetEffects::default()),
                        mappings,
                    };
                };
                return aborted_report(request, code, address);
            }
        };
        retire_absorbed(&effects, &contributed, &mut mappings);
        FoldReport {
            outcome: FoldOutcome::Folded(effects),
            mappings,
        }
    }

    /// Folds against the current authority-head roots of the reference-model
    /// state. This is a projection of the one canonical head, not a second
    /// mutable source of truth.
    #[must_use]
    pub fn evaluate_state(
        &self,
        state: &RepositoryState,
        request: &TransactionRequest,
    ) -> FoldReport {
        let roots = state.roots();
        self.evaluate(
            FoldBasis {
                refs: &roots.refs,
                forge_positions: &roots.forge_positions,
                retention: &roots.retention,
                outbox: &roots.outbox,
            },
            request,
        )
    }

    /// Validates that a report is a total, source-ordered, target-disjoint
    /// normal form for `request`.
    ///
    /// This is intentionally an invariant check rather than a way to submit
    /// effects. Only [`Self::evaluate`] creates effects from client commands.
    pub fn validate_report(
        &self,
        request: &TransactionRequest,
        report: &FoldReport,
    ) -> Result<(), RefusalCode> {
        validate_report(request, report)
    }
}

impl NetEffectFolder for IntentEvaluator {
    fn fold(&self, basis: FoldBasis<'_>, request: &TransactionRequest) -> FoldReport {
        self.evaluate(basis, request)
    }
}

/// Why canonical normal-form bytes could not be produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalFoldRefusal {
    /// The supplied report does not satisfy the normal-form invariant.
    Semantic(RefusalCode),
    /// A component could not be represented in the canonical codec.
    Codec(CodecRefusal),
}

impl From<CodecRefusal> for CanonicalFoldRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Encodes one validated fold report into its deterministic canonical payload.
///
/// The payload is deliberately not a client request format. It is evidence of
/// how a request folded, domain-labelled by the `fgit-txn/normal-form` marker
/// and versioned by [`NORMAL_FORM_FORMAT_VERSION`]. Map-like effect families
/// are passed through `fgit-codec`'s canonical-map writer, which refuses an
/// ambiguous duplicate key before writing bytes.
pub fn canonical_fold_bytes(
    request: &TransactionRequest,
    report: &FoldReport,
) -> Result<Vec<u8>, CanonicalFoldRefusal> {
    IntentEvaluator
        .validate_report(request, report)
        .map_err(CanonicalFoldRefusal::Semantic)?;

    let mut out = Encoder::new();
    out.write_raw(b"fgit-txn/normal-form");
    out.write_scalar(NORMAL_FORM_FORMAT_VERSION);
    match &report.outcome {
        FoldOutcome::Folded(effects) => {
            out.write_raw_byte(1);
            write_effects(&mut out, effects)?;
        }
        FoldOutcome::Aborted { code, at } => {
            out.write_raw_byte(2);
            write_refusal_code(&mut out, *code);
            write_address(&mut out, *at)?;
        }
    }
    out.write_sequence("intent-mappings", &report.mappings, write_mapping)?;
    Ok(out.into_bytes())
}

/// Encodes target-disjoint normal effects without source-attribution entries.
///
/// This is the stable byte representation for consumers that need to compare
/// the folded effect set across equivalent input orderings. It intentionally
/// excludes [`FoldReport::mappings`], whose source order is evidence and must
/// remain in the caller's original command order.
pub fn canonical_effect_bytes(effects: &NetEffects) -> Result<Vec<u8>, CodecRefusal> {
    let mut out = Encoder::new();
    out.write_raw(b"fgit-txn/net-effects");
    out.write_scalar(NORMAL_FORM_FORMAT_VERSION);
    write_effects(&mut out, effects)?;
    Ok(out.into_bytes())
}

/// The private basis copy used to provide read-your-own-writes semantics.
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

/// Result of applying one typed intent to scratch state.
enum Applied {
    Changed(EffectTarget),
    Absorbed(AbsorptionReason),
    Mismatch(RefusalCode),
}

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
        Intent::Outbox(outbox) => match scratch.outbox.get(&outbox.delivery_key) {
            Some(bound) if *bound == outbox.parameters => {
                Applied::Absorbed(AbsorptionReason::DuplicateIdenticalDelivery)
            }
            Some(_) => Applied::Mismatch(RefusalCode::EffectIdempotencyKeyReuse),
            None => {
                scratch
                    .outbox
                    .insert(outbox.delivery_key, outbox.parameters);
                Applied::Changed(EffectTarget::Outbox(outbox.delivery_key))
            }
        },
    }
}

fn aborted_report(
    request: &TransactionRequest,
    code: RefusalCode,
    at: IntentAddress,
) -> FoldReport {
    FoldReport {
        outcome: FoldOutcome::Aborted { code, at },
        mappings: request
            .addressed_intents()
            .map(|(address, _)| IntentMapping {
                address,
                disposition: IntentDisposition::TransactionAborted,
            })
            .collect(),
    }
}

/// A private final-effect candidate. It is intentionally not part of the
/// public API: callers cannot smuggle a derived effect past intent evaluation.
#[derive(Clone)]
enum CandidateEffect {
    Ref(RefName, RefEffect),
    Forge(ForgeStreamId, Vec<ForgeEventKind>),
    Retention(RetentionRoot, RetentionEffect),
    Outbox(OutboxDeliveryKey, Digest),
}

impl CandidateEffect {
    fn target(&self) -> EffectTarget {
        match self {
            Self::Ref(name, _) => EffectTarget::Ref(name.clone()),
            Self::Forge(stream, _) => EffectTarget::ForgeStream(*stream),
            Self::Retention(root, _) => EffectTarget::Retention(*root),
            Self::Outbox(key, _) => EffectTarget::Outbox(*key),
        }
    }
}

/// Constructs a normal form while refusing ambiguous duplicate targets before
/// a map could silently choose a value by insertion order.
#[derive(Default)]
struct NormalFormCollector {
    targets: BTreeSet<EffectTarget>,
    effects: NetEffects,
}

impl NormalFormCollector {
    fn insert(&mut self, candidate: CandidateEffect) -> Result<(), RefusalCode> {
        if !self.targets.insert(candidate.target()) {
            return Err(RefusalCode::ConflictingSemanticEffects);
        }
        match candidate {
            CandidateEffect::Ref(name, effect) => {
                self.effects.refs.insert(name, effect);
            }
            CandidateEffect::Forge(stream, events) => {
                self.effects.forge.insert(stream, events);
            }
            CandidateEffect::Retention(root, effect) => {
                self.effects.retention.insert(root, effect);
            }
            CandidateEffect::Outbox(key, parameters) => {
                self.effects.outbox.insert(key, parameters);
            }
        }
        Ok(())
    }

    fn finish(self) -> NetEffects {
        self.effects
    }
}

fn normal_form_from_scratch(
    basis: FoldBasis<'_>,
    scratch: &Scratch,
) -> Result<NetEffects, RefusalCode> {
    let mut collector = NormalFormCollector::default();

    for (name, value) in &scratch.refs {
        if basis.refs.get(name) != Some(value) {
            collector.insert(CandidateEffect::Ref(name.clone(), RefEffect::Set(*value)))?;
        }
    }
    for name in basis.refs.keys() {
        if !scratch.refs.contains_key(name) {
            collector.insert(CandidateEffect::Ref(name.clone(), RefEffect::Delete))?;
        }
    }
    for (stream, events) in &scratch.forge_events {
        if !events.is_empty() {
            collector.insert(CandidateEffect::Forge(*stream, events.clone()))?;
        }
    }
    for root in &scratch.retention {
        if !basis.retention.contains(root) {
            collector.insert(CandidateEffect::Retention(*root, RetentionEffect::Add))?;
        }
    }
    for root in basis.retention {
        if !scratch.retention.contains(root) {
            collector.insert(CandidateEffect::Retention(*root, RetentionEffect::Remove))?;
        }
    }
    for (key, parameters) in &scratch.outbox {
        if basis.outbox.get(key) != Some(parameters) {
            collector.insert(CandidateEffect::Outbox(*key, *parameters))?;
        }
    }

    Ok(collector.finish())
}

fn retire_absorbed(
    effects: &NetEffects,
    contributed: &BTreeMap<EffectTarget, usize>,
    mappings: &mut [IntentMapping],
) {
    for (index, mapping) in mappings.iter_mut().enumerate() {
        let IntentDisposition::Surviving(target) = &mapping.disposition else {
            continue;
        };
        let target_changed = target_is_surviving(effects, target);
        if matches!(target, EffectTarget::ForgeStream(_)) {
            if !target_changed {
                mapping.disposition = IntentDisposition::Absorbed(AbsorptionReason::IdentityEffect);
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

fn target_is_surviving(effects: &NetEffects, target: &EffectTarget) -> bool {
    match target {
        EffectTarget::Ref(name) => effects.refs.contains_key(name),
        EffectTarget::ForgeStream(stream) => effects.forge.contains_key(stream),
        EffectTarget::Retention(root) => effects.retention.contains_key(root),
        EffectTarget::Outbox(key) => effects.outbox.contains_key(key),
    }
}

fn validate_report(request: &TransactionRequest, report: &FoldReport) -> Result<(), RefusalCode> {
    if !report.is_total_for(request) {
        return Err(RefusalCode::InternalInvariantBreach);
    }
    if !report
        .mappings
        .iter()
        .map(|mapping| mapping.address)
        .eq(request.addressed_intents().map(|(address, _)| address))
    {
        return Err(RefusalCode::InternalInvariantBreach);
    }

    match &report.outcome {
        FoldOutcome::Aborted { at, .. } => {
            if !request
                .addressed_intents()
                .any(|(address, _)| address == *at)
                || !report.mappings.iter().all(|mapping| {
                    matches!(mapping.disposition, IntentDisposition::TransactionAborted)
                })
            {
                return Err(RefusalCode::InternalInvariantBreach);
            }
        }
        FoldOutcome::Folded(effects) => {
            let mut survivors = BTreeSet::new();
            let mut single_writer_targets = BTreeSet::new();
            for mapping in &report.mappings {
                if let IntentDisposition::Surviving(target) = &mapping.disposition {
                    if !target_is_surviving(effects, target) {
                        return Err(RefusalCode::InternalInvariantBreach);
                    }
                    if !matches!(target, EffectTarget::ForgeStream(_))
                        && !single_writer_targets.insert(target.clone())
                    {
                        return Err(RefusalCode::ConflictingSemanticEffects);
                    }
                    survivors.insert(target.clone());
                }
            }
            if !effect_targets(effects).is_subset(&survivors) {
                return Err(RefusalCode::InternalInvariantBreach);
            }
            canonicalize_effects(effects)?;
        }
    }
    Ok(())
}

fn effect_targets(effects: &NetEffects) -> BTreeSet<EffectTarget> {
    effects
        .refs
        .keys()
        .cloned()
        .map(EffectTarget::Ref)
        .chain(effects.forge.keys().copied().map(EffectTarget::ForgeStream))
        .chain(
            effects
                .retention
                .keys()
                .copied()
                .map(EffectTarget::Retention),
        )
        .chain(effects.outbox.keys().copied().map(EffectTarget::Outbox))
        .collect()
}

fn canonicalize_effects(effects: &NetEffects) -> Result<NetEffects, RefusalCode> {
    let mut collector = NormalFormCollector::default();
    for (name, effect) in &effects.refs {
        collector.insert(CandidateEffect::Ref(name.clone(), *effect))?;
    }
    for (stream, events) in &effects.forge {
        collector.insert(CandidateEffect::Forge(*stream, events.clone()))?;
    }
    for (root, effect) in &effects.retention {
        collector.insert(CandidateEffect::Retention(*root, *effect))?;
    }
    for (key, parameters) in &effects.outbox {
        collector.insert(CandidateEffect::Outbox(*key, *parameters))?;
    }
    Ok(collector.finish())
}

fn write_effects(out: &mut Encoder, effects: &NetEffects) -> Result<(), CodecRefusal> {
    let refs: Vec<_> = effects
        .refs
        .iter()
        .map(|(name, effect)| (name.clone(), *effect))
        .collect();
    out.write_canonical_map(
        "normal-form.refs",
        &refs,
        |writer, name| writer.write_ref_name(name),
        |writer, effect| {
            write_ref_effect(writer, *effect);
            Ok(())
        },
    )?;

    let forge: Vec<_> = effects
        .forge
        .iter()
        .map(|(stream, events)| (*stream, events.clone()))
        .collect();
    out.write_canonical_map(
        "normal-form.forge",
        &forge,
        |writer, stream| write_stream_id(writer, *stream),
        |writer, events| writer.write_sequence("forge-events", events, write_forge_event),
    )?;

    let retention: Vec<_> = effects
        .retention
        .iter()
        .map(|(root, effect)| (*root, *effect))
        .collect();
    out.write_canonical_map(
        "normal-form.retention",
        &retention,
        |writer, root| {
            write_retention_root(writer, *root);
            Ok(())
        },
        |writer, effect| {
            write_retention_effect(writer, *effect);
            Ok(())
        },
    )?;

    let outbox: Vec<_> = effects
        .outbox
        .iter()
        .map(|(key, parameters)| (*key, *parameters))
        .collect();
    out.write_canonical_map(
        "normal-form.outbox",
        &outbox,
        |writer, key| write_outbox_key(writer, *key),
        |writer, parameters| writer.write_digest(parameters),
    )
}

fn write_ref_effect(out: &mut Encoder, effect: RefEffect) {
    match effect {
        RefEffect::Set(oid) => {
            out.write_raw_byte(1);
            out.write_git_oid(&oid);
        }
        RefEffect::Delete => out.write_raw_byte(2),
    }
}

fn write_retention_effect(out: &mut Encoder, effect: RetentionEffect) {
    out.write_raw_byte(match effect {
        RetentionEffect::Add => 1,
        RetentionEffect::Remove => 2,
    });
}

fn write_mapping(out: &mut Encoder, mapping: &IntentMapping) -> Result<(), CodecRefusal> {
    write_address(out, mapping.address)?;
    match &mapping.disposition {
        IntentDisposition::Surviving(target) => {
            out.write_raw_byte(1);
            write_target(out, target)?;
        }
        IntentDisposition::Absorbed(reason) => {
            out.write_raw_byte(2);
            out.write_raw_byte(absorption_code(*reason));
        }
        IntentDisposition::StatementError(code) => {
            out.write_raw_byte(3);
            write_refusal_code(out, *code);
        }
        IntentDisposition::TransactionAborted => out.write_raw_byte(4),
    }
    Ok(())
}

fn write_address(out: &mut Encoder, address: IntentAddress) -> Result<(), CodecRefusal> {
    write_index(out, "statement-index", address.statement.0)?;
    write_index(out, "intent-index", address.intent.0)
}

fn write_index(out: &mut Encoder, field: &'static str, index: usize) -> Result<(), CodecRefusal> {
    let index = u32::try_from(index).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(index).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    out.write_scalar(index);
    Ok(())
}

fn write_target(out: &mut Encoder, target: &EffectTarget) -> Result<(), CodecRefusal> {
    match target {
        EffectTarget::Ref(name) => {
            out.write_raw_byte(1);
            out.write_ref_name(name)?;
        }
        EffectTarget::ForgeStream(stream) => {
            out.write_raw_byte(2);
            write_stream_id(out, *stream)?;
        }
        EffectTarget::Retention(root) => {
            out.write_raw_byte(3);
            write_retention_root(out, *root);
        }
        EffectTarget::Outbox(key) => {
            out.write_raw_byte(4);
            write_outbox_key(out, *key)?;
        }
    }
    Ok(())
}

fn write_stream_id(out: &mut Encoder, stream: ForgeStreamId) -> Result<(), CodecRefusal> {
    out.write_text("ForgeStreamId", stream.label().as_str())
}

fn write_outbox_key(out: &mut Encoder, key: OutboxDeliveryKey) -> Result<(), CodecRefusal> {
    out.write_text("OutboxDeliveryKey", key.label().as_str())
}

fn write_retention_root(out: &mut Encoder, root: RetentionRoot) {
    out.write_git_oid(&root.object);
    out.write_raw_byte(match root.class {
        RetentionClass::ReferencedByRef => 1,
        RetentionClass::LegalHold => 2,
        RetentionClass::GraceTombstone => 3,
    });
}

fn write_forge_event(out: &mut Encoder, event: &ForgeEventKind) -> Result<(), CodecRefusal> {
    match event {
        ForgeEventKind::PullRequestOpened {
            pull_request,
            target,
        } => {
            out.write_raw_byte(1);
            out.write_text("ForgeEntityId", pull_request.label().as_str())?;
            out.write_ref_name(target)?;
        }
        ForgeEventKind::PullRequestMerged {
            pull_request,
            target,
        } => {
            out.write_raw_byte(2);
            out.write_text("ForgeEntityId", pull_request.label().as_str())?;
            out.write_ref_name(target)?;
        }
        ForgeEventKind::PullRequestClosed { pull_request } => {
            out.write_raw_byte(3);
            out.write_text("ForgeEntityId", pull_request.label().as_str())?;
        }
    }
    Ok(())
}

fn write_refusal_code(out: &mut Encoder, code: RefusalCode) {
    out.write_scalar(code.code_point());
}

const fn absorption_code(reason: AbsorptionReason) -> u8 {
    match reason {
        AbsorptionReason::IdentityEffect => 1,
        AbsorptionReason::OverwrittenBySucceedingIntent => 2,
        AbsorptionReason::InverseCancelled => 3,
        AbsorptionReason::PreconditionMismatchNoOp => 4,
        AbsorptionReason::DuplicateIdenticalDelivery => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fgit_reference::effect::ReferenceFolder;
    use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
    use fgit_reference::intent::{
        ForgeEntityId, ForgeIntent, IdempotencyKey, OutboxIntent, Statement,
    };
    use fgit_reference::refs::ExpectedRefState;
    use fgit_reference::state::{
        GenesisConfiguration, PolicySnapshot, PrincipalCapabilities, RepositoryState,
    };
    use fgit_types::label::{SchemaFamily, SchemaId};
    use fgit_types::native::{GitHashAlgorithm, GitOidSha1};
    use fgit_types::numeric::{PolicyEpoch, RegistryEpoch};

    const fn oid(seed: u8) -> GitOid {
        GitOid::Sha1(GitOidSha1::from_bytes([seed; GitOidSha1::LEN]))
    }

    const fn schema() -> SchemaId {
        SchemaId::new(SchemaFamily::from_static("fgit/txn-test"), 1, 0)
    }

    fn name(value: &str) -> RefName {
        RefName::try_new(value.as_bytes())
            .unwrap_or_else(|error| panic!("test ref name {value:?} was invalid: {error}"))
    }

    fn request(statements: Vec<Statement>) -> TransactionRequest {
        let mut mint = IdentityMint::new(91);
        let tenant = mint.tenant();
        let repository = mint.repository();
        let principal = mint.principal();
        let mut builder = RequestBuilder::new(
            tenant,
            repository,
            principal,
            schema(),
            IdempotencyKey::new(label("txn-test")),
        );
        for statement in statements {
            builder = builder.statement(statement.mismatch_policy, statement.intents);
        }
        builder.build(&mut mint)
    }

    fn empty_basis() -> (
        BTreeMap<RefName, GitOid>,
        BTreeMap<ForgeStreamId, ForgeStreamPosition>,
        BTreeSet<RetentionRoot>,
        BTreeMap<OutboxDeliveryKey, Digest>,
    ) {
        (
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeMap::new(),
        )
    }

    fn basis_of<'a>(
        refs: &'a BTreeMap<RefName, GitOid>,
        forge: &'a BTreeMap<ForgeStreamId, ForgeStreamPosition>,
        retention: &'a BTreeSet<RetentionRoot>,
        outbox: &'a BTreeMap<OutboxDeliveryKey, Digest>,
    ) -> FoldBasis<'a> {
        FoldBasis {
            refs,
            forge_positions: forge,
            retention,
            outbox,
        }
    }

    fn update(target: &str, expected: ExpectedRefState, new: GitOid) -> Intent {
        Intent::Ref(RefIntent::Update {
            name: name(target),
            expected,
            new,
            force: false,
        })
    }

    fn simple_request() -> TransactionRequest {
        request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![update("refs/heads/main", ExpectedRefState::Absent, oid(2))],
        }])
    }

    fn folded(report: FoldReport) -> NetEffects {
        match report.outcome {
            FoldOutcome::Folded(effects) => effects,
            FoldOutcome::Aborted { code, .. } => panic!("unexpected aborted report: {code:?}"),
        }
    }

    #[test]
    fn folds_read_your_own_writes_to_one_target_disjoint_effect() {
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![
                update("refs/heads/main", ExpectedRefState::Absent, oid(2)),
                update("refs/heads/main", ExpectedRefState::Exact(oid(2)), oid(3)),
            ],
        }]);
        let (refs, forge, retention, outbox) = empty_basis();
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        let effects = folded(report.clone());

        assert_eq!(
            effects.refs,
            BTreeMap::from([(name("refs/heads/main"), RefEffect::Set(oid(3)))])
        );
        assert_eq!(effects.target_count(), 1);
        assert_eq!(
            report.mappings[0].disposition,
            IntentDisposition::Absorbed(AbsorptionReason::OverwrittenBySucceedingIntent)
        );
        assert_eq!(
            report.mappings[1].disposition,
            IntentDisposition::Surviving(EffectTarget::Ref(name("refs/heads/main")))
        );
        assert!(report.is_total_for(&request));
    }

    #[test]
    fn normal_form_is_idempotent() {
        let request = simple_request();
        let (refs, forge, retention, outbox) = empty_basis();
        let effects = folded(
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request),
        );
        let once = canonicalize_effects(&effects).expect("folded effects are canonical");
        let twice = canonicalize_effects(&once).expect("canonical normal form remains valid");
        assert_eq!(twice, once, "fold(fold(x)) must equal fold(x)");
    }

    #[test]
    fn independent_input_orders_have_identical_canonical_normal_form() {
        let intents = vec![
            update("refs/heads/main", ExpectedRefState::Absent, oid(1)),
            update("refs/heads/dev", ExpectedRefState::Absent, oid(2)),
            update("refs/heads/release", ExpectedRefState::Absent, oid(3)),
        ];
        let left = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: intents.clone(),
        }]);
        let right = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![intents[2].clone(), intents[0].clone(), intents[1].clone()],
        }]);
        let (refs, forge, retention, outbox) = empty_basis();
        let evaluator = IntentEvaluator;
        let left_report = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &left);
        let right_report = evaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &right);

        assert_eq!(left_report.effects(), right_report.effects());
        assert_eq!(
            canonical_effect_bytes(left_report.effects().expect("left report folded"))
                .expect("left effects are canonical"),
            canonical_effect_bytes(right_report.effects().expect("right report folded"))
                .expect("right effects are canonical"),
            "canonical effect bytes may not depend on input map construction order"
        );
    }

    #[test]
    fn no_op_mismatch_has_an_explicit_absorption() {
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::NoOp,
            intents: vec![update(
                "refs/heads/main",
                ExpectedRefState::Exact(oid(9)),
                oid(2),
            )],
        }]);
        let (mut refs, forge, retention, outbox) = empty_basis();
        refs.insert(name("refs/heads/main"), oid(1));
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_eq!(report.effects(), Some(&NetEffects::default()));
        assert_eq!(
            report.mappings[0].disposition,
            IntentDisposition::Absorbed(AbsorptionReason::PreconditionMismatchNoOp)
        );
    }

    #[test]
    fn statement_error_mismatch_is_local_and_later_intents_continue() {
        let request = request(vec![
            Statement {
                mismatch_policy: MismatchPolicy::StatementError,
                intents: vec![update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(9)),
                    oid(2),
                )],
            },
            Statement {
                mismatch_policy: MismatchPolicy::TxnAbort,
                intents: vec![update("refs/heads/dev", ExpectedRefState::Absent, oid(3))],
            },
        ]);
        let (mut refs, forge, retention, outbox) = empty_basis();
        refs.insert(name("refs/heads/main"), oid(1));
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_eq!(
            report.mappings[0].disposition,
            IntentDisposition::StatementError(RefusalCode::ExpectedOldRefMismatch)
        );
        assert_eq!(
            report
                .effects()
                .and_then(|effects| effects.refs.get(&name("refs/heads/dev"))),
            Some(&RefEffect::Set(oid(3)))
        );
    }

    #[test]
    fn transaction_abort_maps_every_source_intent() {
        let request = request(vec![
            Statement {
                mismatch_policy: MismatchPolicy::TxnAbort,
                intents: vec![update(
                    "refs/heads/main",
                    ExpectedRefState::Exact(oid(9)),
                    oid(2),
                )],
            },
            Statement {
                mismatch_policy: MismatchPolicy::TxnAbort,
                intents: vec![update("refs/heads/dev", ExpectedRefState::Absent, oid(3))],
            },
        ]);
        let (mut refs, forge, retention, outbox) = empty_basis();
        refs.insert(name("refs/heads/main"), oid(1));
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_eq!(
            report.outcome,
            FoldOutcome::Aborted {
                code: RefusalCode::ExpectedOldRefMismatch,
                at: IntentAddress {
                    statement: StatementIndex(0),
                    intent: IntentIndex(0),
                },
            }
        );
        assert!(
            report.mappings.iter().all(|mapping| matches!(
                mapping.disposition,
                IntentDisposition::TransactionAborted
            ))
        );
        assert!(report.is_total_for(&request));
    }

    #[test]
    fn forge_position_mismatch_obeys_every_statement_policy() {
        let stream = ForgeStreamId::new(label("forge-mismatch"));
        let event = ForgeEventKind::PullRequestClosed {
            pull_request: ForgeEntityId::new(label("pr-mismatch")),
        };
        for policy in MismatchPolicy::ALL {
            let request = request(vec![Statement {
                mismatch_policy: *policy,
                intents: vec![Intent::Forge(ForgeIntent {
                    stream,
                    expected_position: ForgeStreamPosition::GENESIS,
                    event: event.clone(),
                })],
            }]);
            let (refs, mut forge, retention, outbox) = empty_basis();
            forge.insert(stream, ForgeStreamPosition::new(1));
            let report =
                IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);

            match policy {
                MismatchPolicy::NoOp => assert_eq!(
                    report.mappings[0].disposition,
                    IntentDisposition::Absorbed(AbsorptionReason::PreconditionMismatchNoOp)
                ),
                MismatchPolicy::StatementError => assert_eq!(
                    report.mappings[0].disposition,
                    IntentDisposition::StatementError(RefusalCode::ForgeTransitionInvalid)
                ),
                MismatchPolicy::TxnAbort => assert!(matches!(
                    report.outcome,
                    FoldOutcome::Aborted {
                        code: RefusalCode::ForgeTransitionInvalid,
                        ..
                    }
                )),
            }
        }
    }

    #[test]
    fn outbox_key_conflict_obeys_every_statement_policy() {
        let key = OutboxDeliveryKey::new(label("outbox-mismatch"));
        let mut mint = IdentityMint::new(72);
        let first_parameters = mint.digest();
        let replacement_parameters = mint.digest();
        for policy in MismatchPolicy::ALL {
            let request = request(vec![Statement {
                mismatch_policy: *policy,
                intents: vec![Intent::Outbox(OutboxIntent {
                    delivery_key: key,
                    parameters: replacement_parameters,
                })],
            }]);
            let (refs, forge, retention, mut outbox) = empty_basis();
            outbox.insert(key, first_parameters);
            let report =
                IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);

            match policy {
                MismatchPolicy::NoOp => assert_eq!(
                    report.mappings[0].disposition,
                    IntentDisposition::Absorbed(AbsorptionReason::PreconditionMismatchNoOp)
                ),
                MismatchPolicy::StatementError => assert_eq!(
                    report.mappings[0].disposition,
                    IntentDisposition::StatementError(RefusalCode::EffectIdempotencyKeyReuse)
                ),
                MismatchPolicy::TxnAbort => assert!(matches!(
                    report.outcome,
                    FoldOutcome::Aborted {
                        code: RefusalCode::EffectIdempotencyKeyReuse,
                        ..
                    }
                )),
            }
        }
    }

    #[test]
    fn duplicate_surviving_target_is_refused_not_overwritten() {
        let target = name("refs/heads/main");
        let mut collector = NormalFormCollector::default();
        collector
            .insert(CandidateEffect::Ref(target.clone(), RefEffect::Set(oid(1))))
            .expect("first target is unique");
        assert_eq!(
            collector.insert(CandidateEffect::Ref(target, RefEffect::Set(oid(2)))),
            Err(RefusalCode::ConflictingSemanticEffects)
        );
    }

    #[test]
    fn ambiguous_duplicate_outbox_value_is_refused() {
        let mut mint = IdentityMint::new(81);
        let key = OutboxDeliveryKey::new(label("delivery"));
        let mut collector = NormalFormCollector::default();
        collector
            .insert(CandidateEffect::Outbox(key, mint.digest()))
            .expect("first delivery key is unique");
        assert_eq!(
            collector.insert(CandidateEffect::Outbox(key, mint.digest())),
            Err(RefusalCode::ConflictingSemanticEffects)
        );
    }

    #[test]
    fn candidate_insertion_order_does_not_change_normal_form() {
        let first = CandidateEffect::Ref(name("refs/heads/main"), RefEffect::Set(oid(1)));
        let second = CandidateEffect::Ref(name("refs/heads/dev"), RefEffect::Set(oid(2)));
        let mut left = NormalFormCollector::default();
        left.insert(first.clone()).expect("unique target");
        left.insert(second.clone()).expect("unique target");
        let mut right = NormalFormCollector::default();
        right.insert(second).expect("unique target");
        right.insert(first).expect("unique target");
        assert_eq!(left.finish(), right.finish());
    }

    #[test]
    fn outbox_identical_delivery_is_permitted_twin_of_conflict() {
        let mut mint = IdentityMint::new(77);
        let key = OutboxDeliveryKey::new(label("delivery"));
        let parameters = mint.digest();
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![Intent::Outbox(OutboxIntent {
                delivery_key: key,
                parameters,
            })],
        }]);
        let (refs, forge, retention, mut outbox) = empty_basis();
        outbox.insert(key, parameters);
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_eq!(report.effects(), Some(&NetEffects::default()));
        assert_eq!(
            report.mappings[0].disposition,
            IntentDisposition::Absorbed(AbsorptionReason::DuplicateIdenticalDelivery)
        );
    }

    #[test]
    fn model_state_projection_agrees_with_reference_folder() {
        let mut mint = IdentityMint::new(31);
        let tenant = mint.tenant();
        let repository = mint.repository();
        let principal = mint.principal();
        let state = RepositoryState::genesis(GenesisConfiguration {
            tenant,
            repository,
            object_format: GitHashAlgorithm::Sha1,
            genesis_head_id: mint.head(),
            policy: PolicySnapshot {
                epoch: PolicyEpoch::FIRST,
                protected_scopes: BTreeSet::new(),
                principals: BTreeMap::from([(principal, PrincipalCapabilities::default())]),
                max_intents_per_transaction: 64,
                supported_schemas: BTreeSet::from([schema()]),
                supported_durability: BTreeSet::new(),
            },
            format_registry_epoch: RegistryEpoch::FIRST,
        });
        let request = RequestBuilder::new(
            tenant,
            repository,
            principal,
            schema(),
            IdempotencyKey::new(label("state-projection")),
        )
        .statement(
            MismatchPolicy::TxnAbort,
            vec![update("refs/heads/main", ExpectedRefState::Absent, oid(1))],
        )
        .build(&mut mint);
        let roots = state.roots();
        let reference = ReferenceFolder.fold(
            FoldBasis {
                refs: &roots.refs,
                forge_positions: &roots.forge_positions,
                retention: &roots.retention,
                outbox: &roots.outbox,
            },
            &request,
        );
        assert_eq!(IntentEvaluator.evaluate_state(&state, &request), reference);
    }

    #[test]
    fn bounded_generated_intents_agree_with_reference_oracle() {
        for seed in 0_u8..64 {
            let initial = oid(seed.wrapping_add(1));
            let replacement = oid(seed.wrapping_add(65));
            let expected = if seed & 1 == 0 {
                ExpectedRefState::Exact(initial)
            } else {
                ExpectedRefState::Absent
            };
            let request = request(vec![Statement {
                mismatch_policy: match seed % 3 {
                    0 => MismatchPolicy::NoOp,
                    1 => MismatchPolicy::StatementError,
                    _ => MismatchPolicy::TxnAbort,
                },
                intents: vec![
                    update("refs/heads/main", expected, replacement),
                    Intent::Forge(ForgeIntent {
                        stream: ForgeStreamId::new(label("stream")),
                        expected_position: ForgeStreamPosition::GENESIS,
                        event: ForgeEventKind::PullRequestOpened {
                            pull_request: ForgeEntityId::new(label("pr")),
                            target: name("refs/heads/main"),
                        },
                    }),
                ],
            }]);
            let (mut refs, forge, retention, outbox) = empty_basis();
            refs.insert(name("refs/heads/main"), initial);
            let basis = basis_of(&refs, &forge, &retention, &outbox);
            let reference = ReferenceFolder.fold(basis, &request);
            let production =
                IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
            assert_eq!(production, reference, "oracle mismatch for seed {seed}");
        }
    }
}
