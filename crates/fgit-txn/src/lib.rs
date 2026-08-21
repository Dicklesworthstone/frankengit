#![forbid(unsafe_code)]
//! Typed transaction-intent evaluation and target-disjoint normal-form folding.
//!
//! A client submits [`fgit_reference::intent::TransactionRequest`] values: typed
//! intents and their asserted preconditions, never caller-computed effects or
//! resulting roots. [`IntentEvaluator`] evaluates those intents in source order
//! against one pinned basis. [`IntentEvaluator`] deliberately delegates the
//! read-your-own-writes evaluation and target-disjoint [`NetEffects`] normal
//! form to `fgit-reference`'s single source of truth; this crate owns the
//! stable application-facing facade plus canonical normal-form bytes.
//!
//! ## Mismatch and refusal vocabulary
//!
//! * A ref precondition mismatch is
//!   [`RefusalCode::ExpectedOldRefMismatch`].
//! * A forge position mismatch is [`RefusalCode::ForgeTransitionInvalid`]; an
//!   exhausted position is [`RefusalCode::ResourceBudgetExceeded`].
//! * Reusing an outbox delivery key with different canonical parameters is
//!   [`RefusalCode::EffectIdempotencyKeyReuse`].
//! * [`RefusalCode::ConflictingSemanticEffects`] is reserved for validation of
//!   a caller-supplied malformed report with two surviving non-forge mappings
//!   for one target. It cannot arise from typed intent evaluation: the
//!   reference normal-form types are target-disjoint by construction.
//!
//! The statement's [`fgit_types::vocabulary::MismatchPolicy`] decides whether an ordinary precondition
//! mismatch becomes an explicit absorbed no-op, a statement-local error, or a
//! transaction abort. A transaction abort has no effects and maps every source
//! intent, including intents after the triggering one, to
//! [`IntentDisposition::TransactionAborted`].
//!
//! This is intentionally not an independent evaluator or differential claim.
//! A later optimized folder must be separately implemented and tested against
//! the reference folder before it may replace this delegation.

pub mod combiner;
pub mod lanes;

use std::collections::BTreeSet;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_reference::effect::{
    AbsorptionReason, EffectTarget, FoldBasis, FoldOutcome, FoldReport, IntentDisposition,
    IntentMapping, NetEffectFolder, NetEffects, RefEffect, ReferenceFolder, RetentionEffect,
};
use fgit_reference::intent::{
    ForgeEventKind, ForgeStreamId, IntentAddress, OutboxDeliveryKey, RetentionClass, RetentionRoot,
    TransactionRequest,
};
use fgit_reference::state::RepositoryState;
use fgit_types::vocabulary::RefusalCode;

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

    /// Folds a request against its pinned root projection through the reference
    /// folder. Keeping this call explicit prevents this facade from silently
    /// becoming a second evaluator with diverging normal-form semantics.
    #[must_use]
    pub fn evaluate(&self, basis: FoldBasis<'_>, request: &TransactionRequest) -> FoldReport {
        ReferenceFolder.fold(basis, request)
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

    use std::collections::BTreeMap;

    use fgit_reference::harness::{IdentityMint, RequestBuilder, label};
    use fgit_reference::intent::{
        ForgeEntityId, ForgeIntent, ForgeStreamPosition, IdempotencyKey, Intent, IntentIndex,
        OutboxIntent, RefIntent, Statement, StatementIndex,
    };
    use fgit_reference::refs::ExpectedRefState;
    use fgit_reference::state::{
        GenesisConfiguration, PolicySnapshot, PrincipalCapabilities, RepositoryState,
    };
    use fgit_types::hash::Digest;
    use fgit_types::label::{SchemaFamily, SchemaId};
    use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
    use fgit_types::numeric::{PolicyEpoch, RegistryEpoch};
    use fgit_types::refs::RefName;
    use fgit_types::vocabulary::MismatchPolicy;

    type EmptyBasis = (
        BTreeMap<RefName, GitOid>,
        BTreeMap<ForgeStreamId, ForgeStreamPosition>,
        BTreeSet<RetentionRoot>,
        BTreeMap<OutboxDeliveryKey, Digest>,
    );

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

    fn empty_basis() -> EmptyBasis {
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
    fn repeated_evaluation_produces_identical_normal_form() {
        let request = simple_request();
        let (refs, forge, retention, outbox) = empty_basis();
        let basis = basis_of(&refs, &forge, &retention, &outbox);
        let first = IntentEvaluator.evaluate(basis, &request);
        let second =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);

        assert_eq!(first, second, "a pinned normal-form fold must be pure");
        assert_eq!(
            canonical_fold_bytes(&request, &first).expect("first report is valid"),
            canonical_fold_bytes(&request, &second).expect("second report is valid"),
            "canonical normal form must be idempotent under repeated evaluation"
        );
    }

    #[test]
    fn shuffled_independent_intents_have_identical_canonical_normal_form() {
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
    fn public_report_validator_refuses_duplicate_surviving_target() {
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![
                update("refs/heads/main", ExpectedRefState::Absent, oid(1)),
                update("refs/heads/main", ExpectedRefState::Exact(oid(1)), oid(2)),
            ],
        }]);
        let (refs, forge, retention, outbox) = empty_basis();
        let mut report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        report.mappings[0].disposition =
            IntentDisposition::Surviving(EffectTarget::Ref(name("refs/heads/main")));

        assert_eq!(
            IntentEvaluator.validate_report(&request, &report),
            Err(RefusalCode::ConflictingSemanticEffects)
        );
    }

    #[test]
    fn ambiguous_duplicate_outbox_value_aborts_through_public_evaluator() {
        let mut mint = IdentityMint::new(81);
        let key = OutboxDeliveryKey::new(label("delivery"));
        let first_parameters = mint.digest();
        let replacement_parameters = mint.digest();
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![
                Intent::Outbox(OutboxIntent {
                    delivery_key: key,
                    parameters: first_parameters,
                }),
                Intent::Outbox(OutboxIntent {
                    delivery_key: key,
                    parameters: replacement_parameters,
                }),
            ],
        }]);
        let (refs, forge, retention, outbox) = empty_basis();
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);

        assert_eq!(
            report.outcome,
            FoldOutcome::Aborted {
                code: RefusalCode::EffectIdempotencyKeyReuse,
                at: IntentAddress {
                    statement: StatementIndex(0),
                    intent: IntentIndex(1),
                },
            }
        );
    }

    #[test]
    fn outbox_identical_delivery_is_permitted_twin_of_conflict() {
        let mut mint = IdentityMint::new(77);
        let key = OutboxDeliveryKey::new(label("delivery"));
        let parameters = mint.digest();
        let request = request(vec![Statement {
            mismatch_policy: MismatchPolicy::TxnAbort,
            intents: vec![
                Intent::Outbox(OutboxIntent {
                    delivery_key: key,
                    parameters,
                }),
                Intent::Outbox(OutboxIntent {
                    delivery_key: key,
                    parameters,
                }),
            ],
        }]);
        let (refs, forge, retention, outbox) = empty_basis();
        let report =
            IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
        assert_eq!(
            report
                .effects()
                .and_then(|effects| effects.outbox.get(&key)),
            Some(&parameters)
        );
        assert_eq!(
            report.mappings[1].disposition,
            IntentDisposition::Absorbed(AbsorptionReason::DuplicateIdenticalDelivery)
        );
    }

    #[test]
    fn evaluate_state_reads_the_authority_head_projection() {
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
        let report = IntentEvaluator.evaluate_state(&state, &request);
        assert_eq!(
            report
                .effects()
                .and_then(|effects| effects.refs.get(&name("refs/heads/main"))),
            Some(&RefEffect::Set(oid(1)))
        );
        assert_eq!(IntentEvaluator.validate_report(&request, &report), Ok(()));
    }

    #[test]
    fn bounded_generated_intents_produce_total_deterministic_reports() {
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
            let first =
                IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
            let second =
                IntentEvaluator.evaluate(basis_of(&refs, &forge, &retention, &outbox), &request);
            assert_eq!(first, second, "nondeterministic result for seed {seed}");
            assert!(
                first.is_total_for(&request),
                "incomplete result for seed {seed}"
            );
            assert_eq!(
                IntentEvaluator.validate_report(&request, &first),
                Ok(()),
                "invalid normal form for seed {seed}"
            );
        }
    }
}
