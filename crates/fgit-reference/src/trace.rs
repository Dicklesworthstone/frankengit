//! Golden traces: canonical serialization of a model history, replay, and
//! diffing.
//!
//! Plan §40.5 makes trace refinement the discipline that connects an optimized
//! implementation to this oracle: implementation traces map to reference
//! intents, effects, and decisions. That needs a stable interchange format
//! **now**, before optimized implementations exist — otherwise each one invents
//! its own and the comparisons rot.
//!
//! A [`GoldenTrace`] is a genesis configuration plus an ordered list of steps.
//! Each step records the input that was applied and what the model observed
//! afterwards. Replaying a trace re-runs every input against a fresh model and
//! checks the observations still hold; the first place they stop holding is the
//! divergence.
//!
//! ## What a "root" is here
//!
//! `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §8.2 names digests for the head's
//! roots. This crate computes no digests, so a trace records the **canonical
//! encoding of the roots** instead — the exact bytes `fgit-codec` produces for
//! [`crate::state::RepositoryRoots`]. That is a faithful stand-in for the
//! purpose at hand: canonical encoding is injective over root content, so two
//! states have equal recorded roots exactly when they have equal roots. When a
//! digest is wanted, it is `fgit_crypto`'s digest of these same bytes, and
//! nothing about the trace has to change.
//!
//! ## A trace is not a canonical repository body
//!
//! It carries its own domain separation tag, `frankengit/model-trace/v1`, and
//! never enters the authenticated decision stream. It is a differential-testing
//! artifact that happens to use the same codec, which is what buys it platform
//! stability for free: the canonical encoding has no `usize`, no float, no
//! host endianness, and no unordered collection.

use std::collections::{BTreeMap, BTreeSet};

use fgit_codec::error::CodecRefusal;
use fgit_codec::reader::Decoder;
use fgit_codec::wire::{CanonicalBody, canonical_body_bytes};
use fgit_codec::writer::Encoder;
use fgit_types::identity::{
    InternalObjectId, PreparationProfileId, PreparedTxnCapsuleId, PrincipalId, PrincipalSnapshotId,
    RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCommitId, RepositoryDecisionBatchId,
    RepositoryId, TenantId, TransactionSealId, TxId,
};
use fgit_types::label::{AsciiSlug, DomainTag, SchemaFamily, SchemaId};
use fgit_types::numeric::{
    DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositorySequence,
};
use fgit_types::vocabulary::{DecisionOutcome, MismatchPolicy, RefusalCode};

use crate::capsule::WitnessGranularity;
use crate::intent::{
    DurabilityProfile, ForgeEntityId, ForgeEventKind, ForgeIntent, ForgeStreamId,
    ForgeStreamPosition, IdempotencyKey, Intent, OutboxDeliveryKey, OutboxIntent, RefIntent,
    RetentionClass, RetentionIntent, RetentionRoot, Statement, TransactionRequest,
};
use crate::machine::{
    CancellationPhase, CancellationRequest, ModelInput, ModelOutput, ModelStep, step,
};
use crate::refs::ExpectedRefState;
use crate::state::{
    GenesisConfiguration, InvariantBreach, PolicySnapshot, PrincipalCapabilities,
    QuarantinedObject, RepositoryRoots, RepositoryState,
};
use crate::transition::{
    CasOutcome, CasRequest, ConfigurationOutcome, ConfigurationRequest, DecisionBodyIdentity,
    DecisionVerdict, PrepareRequest, QuarantineRequest, SealOutcome, SealRequest, StageRequest,
};

/// Domain separation tag for a model trace body.
pub const TRACE_DOMAIN: &str = "frankengit/model-trace/v1";

/// Schema family for a model trace body.
pub const TRACE_SCHEMA_FAMILY: &str = "fgit/model-trace";

/// Domain separation tag for a standalone roots body.
pub const ROOTS_DOMAIN: &str = "frankengit/model-roots/v1";

/// Schema family for a standalone roots body.
pub const ROOTS_SCHEMA_FAMILY: &str = "fgit/model-roots";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a trace could not be encoded, decoded, or replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TraceError {
    /// The canonical codec refused the bytes.
    Codec(CodecRefusal),
    /// A decoded value was outside the model's own domain, for example a
    /// discriminant that names no variant.
    Malformed {
        /// Which field rejected the value.
        field: &'static str,
        /// The value that was rejected.
        observed: u64,
    },
    /// Replaying the trace broke a model invariant, which a recorded history
    /// never should.
    Invariant(Box<InvariantBreach>),
}

impl From<CodecRefusal> for TraceError {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

impl From<Box<InvariantBreach>> for TraceError {
    fn from(value: Box<InvariantBreach>) -> Self {
        Self::Invariant(value)
    }
}

impl core::fmt::Display for TraceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Codec(refusal) => write!(formatter, "codec refused the trace: {refusal}"),
            Self::Malformed { field, observed } => {
                write!(formatter, "trace field {field} rejected value {observed}")
            }
            Self::Invariant(breach) => {
                write!(formatter, "replay broke a model invariant: {breach}")
            }
        }
    }
}

impl std::error::Error for TraceError {}

fn malformed<T>(field: &'static str, observed: u64) -> Result<T, CodecRefusal> {
    Err(CodecRefusal::from(
        fgit_types::TypeRefusal::CodePointUnknown {
            field,
            observed: u32::try_from(observed).unwrap_or(u32::MAX),
        },
    ))
}

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

fn write_slug(out: &mut Encoder, field: &'static str, slug: AsciiSlug) -> Result<(), CodecRefusal> {
    out.write_bytes(field, slug.as_bytes())
}

fn read_slug(input: &mut Decoder<'_>, field: &'static str) -> Result<AsciiSlug, CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    AsciiSlug::try_new(field, bytes).map_err(CodecRefusal::from)
}

fn write_usize(out: &mut Encoder, value: usize) {
    // `usize` is deliberately not a `CanonicalScalar`: its width is a property
    // of the host, and a canonical encoding may not have one. Widening to a
    // fixed `u64` is the only honest way to put a count on the wire.
    out.write_scalar(u64::try_from(value).unwrap_or(u64::MAX));
}

fn read_usize(input: &mut Decoder<'_>, field: &'static str) -> Result<usize, CodecRefusal> {
    let value = input.read_scalar::<u64>(field)?;
    usize::try_from(value).map_err(|_| {
        CodecRefusal::from(fgit_types::TypeRefusal::ValueOutOfRange {
            field,
            observed: value,
            minimum: 0,
            maximum: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
        })
    })
}

macro_rules! derived_id_codec {
    ($write:ident, $read:ident, $ty:ty, $field:literal) => {
        fn $write(out: &mut Encoder, id: $ty) -> Result<(), CodecRefusal> {
            out.write_internal_object_id(id.as_internal_object_id())
        }

        fn $read(input: &mut Decoder<'_>) -> Result<$ty, CodecRefusal> {
            let id: InternalObjectId = input.read_internal_object_id()?;
            // The domain is re-checked on the way in, so a trace that names a
            // batch identity where a transaction identity belongs is refused
            // rather than silently accepted.
            <$ty>::from_internal_object_id(id).map_err(CodecRefusal::from)
        }
    };
}

derived_id_codec!(write_tx_id, read_tx_id, TxId, "TxId");
derived_id_codec!(write_seal_id, read_seal_id, TransactionSealId, "SealId");
derived_id_codec!(
    write_capsule_id,
    read_capsule_id,
    PreparedTxnCapsuleId,
    "CapsuleId"
);
derived_id_codec!(
    write_commit_id,
    read_commit_id,
    RepositoryCommitId,
    "CommitId"
);
derived_id_codec!(
    write_batch_id,
    read_batch_id,
    RepositoryDecisionBatchId,
    "BatchId"
);
derived_id_codec!(
    write_head_id,
    read_head_id,
    RepositoryAuthorityHeadId,
    "HeadId"
);
derived_id_codec!(
    write_refusal_record_id,
    read_refusal_record_id,
    RefusalRecordId,
    "RefusalRecordId"
);
derived_id_codec!(
    write_principal_snapshot_id,
    read_principal_snapshot_id,
    PrincipalSnapshotId,
    "PrincipalSnapshotId"
);

fn write_tenant(out: &mut Encoder, id: TenantId) {
    out.write_opaque_id(id.as_bytes());
}

fn read_tenant(input: &mut Decoder<'_>) -> Result<TenantId, CodecRefusal> {
    Ok(TenantId::from_bytes(input.read_opaque_id("TenantId")?))
}

fn write_repository(out: &mut Encoder, id: RepositoryId) {
    out.write_opaque_id(id.as_bytes());
}

fn read_repository(input: &mut Decoder<'_>) -> Result<RepositoryId, CodecRefusal> {
    Ok(RepositoryId::from_bytes(
        input.read_opaque_id("RepositoryId")?,
    ))
}

fn write_principal(out: &mut Encoder, id: PrincipalId) {
    out.write_opaque_id(id.as_bytes());
}

fn read_principal(input: &mut Decoder<'_>) -> Result<PrincipalId, CodecRefusal> {
    Ok(PrincipalId::from_bytes(
        input.read_opaque_id("PrincipalId")?,
    ))
}

// ---------------------------------------------------------------------------
// Intent vocabulary
// ---------------------------------------------------------------------------

fn write_expected(out: &mut Encoder, expected: ExpectedRefState) {
    match expected {
        ExpectedRefState::Absent => out.write_raw_byte(1),
        ExpectedRefState::Any => out.write_raw_byte(2),
        ExpectedRefState::Exact(oid) => {
            out.write_raw_byte(3);
            out.write_git_oid(&oid);
        }
    }
}

fn read_expected(input: &mut Decoder<'_>) -> Result<ExpectedRefState, CodecRefusal> {
    match input.read_raw_byte("ExpectedRefState")? {
        1 => Ok(ExpectedRefState::Absent),
        2 => Ok(ExpectedRefState::Any),
        3 => Ok(ExpectedRefState::Exact(input.read_git_oid()?)),
        other => malformed("ExpectedRefState", u64::from(other)),
    }
}

fn write_retention_class(out: &mut Encoder, class: RetentionClass) {
    out.write_raw_byte(match class {
        RetentionClass::ReferencedByRef => 1,
        RetentionClass::LegalHold => 2,
        RetentionClass::GraceTombstone => 3,
    });
}

fn read_retention_class(input: &mut Decoder<'_>) -> Result<RetentionClass, CodecRefusal> {
    match input.read_raw_byte("RetentionClass")? {
        1 => Ok(RetentionClass::ReferencedByRef),
        2 => Ok(RetentionClass::LegalHold),
        3 => Ok(RetentionClass::GraceTombstone),
        other => malformed("RetentionClass", u64::from(other)),
    }
}

fn write_retention_root(out: &mut Encoder, root: RetentionRoot) {
    out.write_git_oid(&root.object);
    write_retention_class(out, root.class);
}

fn read_retention_root(input: &mut Decoder<'_>) -> Result<RetentionRoot, CodecRefusal> {
    let object = input.read_git_oid()?;
    let class = read_retention_class(input)?;
    Ok(RetentionRoot { object, class })
}

fn write_forge_event(out: &mut Encoder, event: &ForgeEventKind) -> Result<(), CodecRefusal> {
    match event {
        ForgeEventKind::PullRequestOpened {
            pull_request,
            target,
        } => {
            out.write_raw_byte(1);
            write_slug(out, "ForgeEntityId", pull_request.label())?;
            out.write_ref_name(target)?;
        }
        ForgeEventKind::PullRequestMerged {
            pull_request,
            target,
        } => {
            out.write_raw_byte(2);
            write_slug(out, "ForgeEntityId", pull_request.label())?;
            out.write_ref_name(target)?;
        }
        ForgeEventKind::PullRequestClosed { pull_request } => {
            out.write_raw_byte(3);
            write_slug(out, "ForgeEntityId", pull_request.label())?;
        }
    }
    Ok(())
}

fn read_forge_event(input: &mut Decoder<'_>) -> Result<ForgeEventKind, CodecRefusal> {
    match input.read_raw_byte("ForgeEventKind")? {
        1 => {
            let pull_request = ForgeEntityId::new(read_slug(input, "ForgeEntityId")?);
            let target = input.read_ref_name()?;
            Ok(ForgeEventKind::PullRequestOpened {
                pull_request,
                target,
            })
        }
        2 => {
            let pull_request = ForgeEntityId::new(read_slug(input, "ForgeEntityId")?);
            let target = input.read_ref_name()?;
            Ok(ForgeEventKind::PullRequestMerged {
                pull_request,
                target,
            })
        }
        3 => {
            let pull_request = ForgeEntityId::new(read_slug(input, "ForgeEntityId")?);
            Ok(ForgeEventKind::PullRequestClosed { pull_request })
        }
        other => malformed("ForgeEventKind", u64::from(other)),
    }
}

fn write_intent(out: &mut Encoder, intent: &Intent) -> Result<(), CodecRefusal> {
    match intent {
        Intent::Ref(RefIntent::Update {
            name,
            expected,
            new,
            force,
        }) => {
            out.write_raw_byte(1);
            out.write_ref_name(name)?;
            write_expected(out, *expected);
            out.write_git_oid(new);
            out.write_bool(*force);
        }
        Intent::Ref(RefIntent::Delete { name, expected }) => {
            out.write_raw_byte(2);
            out.write_ref_name(name)?;
            write_expected(out, *expected);
        }
        Intent::Forge(forge) => {
            out.write_raw_byte(3);
            write_slug(out, "ForgeStreamId", forge.stream.label())?;
            out.write_scalar(forge.expected_position.get());
            write_forge_event(out, &forge.event)?;
        }
        Intent::Retention(RetentionIntent::AddRoot(root)) => {
            out.write_raw_byte(4);
            write_retention_root(out, *root);
        }
        Intent::Retention(RetentionIntent::RemoveRoot(root)) => {
            out.write_raw_byte(5);
            write_retention_root(out, *root);
        }
        Intent::Outbox(outbox) => {
            out.write_raw_byte(6);
            write_slug(out, "OutboxDeliveryKey", outbox.delivery_key.label())?;
            out.write_digest(&outbox.parameters)?;
        }
    }
    Ok(())
}

fn read_intent(input: &mut Decoder<'_>) -> Result<Intent, CodecRefusal> {
    match input.read_raw_byte("Intent")? {
        1 => {
            let name = input.read_ref_name()?;
            let expected = read_expected(input)?;
            let new = input.read_git_oid()?;
            let force = input.read_bool("force")?;
            Ok(Intent::Ref(RefIntent::Update {
                name,
                expected,
                new,
                force,
            }))
        }
        2 => {
            let name = input.read_ref_name()?;
            let expected = read_expected(input)?;
            Ok(Intent::Ref(RefIntent::Delete { name, expected }))
        }
        3 => {
            let stream = ForgeStreamId::new(read_slug(input, "ForgeStreamId")?);
            let expected_position =
                ForgeStreamPosition::new(input.read_scalar::<u64>("ForgeStreamPosition")?);
            let event = read_forge_event(input)?;
            Ok(Intent::Forge(ForgeIntent {
                stream,
                expected_position,
                event,
            }))
        }
        4 => Ok(Intent::Retention(RetentionIntent::AddRoot(
            read_retention_root(input)?,
        ))),
        5 => Ok(Intent::Retention(RetentionIntent::RemoveRoot(
            read_retention_root(input)?,
        ))),
        6 => {
            let delivery_key = OutboxDeliveryKey::new(read_slug(input, "OutboxDeliveryKey")?);
            let parameters = input.read_digest()?;
            Ok(Intent::Outbox(OutboxIntent {
                delivery_key,
                parameters,
            }))
        }
        other => malformed("Intent", u64::from(other)),
    }
}

fn write_mismatch_policy(out: &mut Encoder, policy: MismatchPolicy) {
    out.write_scalar(policy.code_point());
}

fn read_mismatch_policy(input: &mut Decoder<'_>) -> Result<MismatchPolicy, CodecRefusal> {
    let code_point = input.read_scalar::<u16>("MismatchPolicy")?;
    MismatchPolicy::from_code_point(code_point).map_err(CodecRefusal::from)
}

fn write_statement(out: &mut Encoder, statement: &Statement) -> Result<(), CodecRefusal> {
    write_mismatch_policy(out, statement.mismatch_policy);
    // Intent order inside a statement is semantic: evaluation is source-ordered
    // with read-your-own-writes, so this is a sequence and never a set.
    out.write_sequence("intents", &statement.intents, write_intent)
}

fn read_statement(input: &mut Decoder<'_>) -> Result<Statement, CodecRefusal> {
    let mismatch_policy = read_mismatch_policy(input)?;
    let intents = input.read_sequence("intents", read_intent)?;
    Ok(Statement {
        intents,
        mismatch_policy,
    })
}

fn write_durability(out: &mut Encoder, durability: DurabilityProfile) {
    out.write_raw_byte(match durability {
        DurabilityProfile::CanonicalSource => 1,
        DurabilityProfile::DerivedGeneration => 2,
    });
}

fn read_durability(input: &mut Decoder<'_>) -> Result<DurabilityProfile, CodecRefusal> {
    match input.read_raw_byte("DurabilityProfile")? {
        1 => Ok(DurabilityProfile::CanonicalSource),
        2 => Ok(DurabilityProfile::DerivedGeneration),
        other => malformed("DurabilityProfile", u64::from(other)),
    }
}

fn write_request(out: &mut Encoder, request: &TransactionRequest) -> Result<(), CodecRefusal> {
    write_tx_id(out, request.tx_id)?;
    write_tenant(out, request.tenant);
    write_repository(out, request.repository);
    write_principal(out, request.principal);
    out.write_schema_id(request.schema)?;
    write_slug(out, "IdempotencyKey", request.idempotency_key.label())?;
    out.write_digest(&request.canonical_request_digest)?;
    out.write_sequence("statements", &request.statements, write_statement)?;
    let closure = request.promised_closure.iter().copied().collect::<Vec<_>>();
    out.write_canonical_set("promised_closure", &closure, |encoder, oid| {
        encoder.write_git_oid(oid);
        Ok(())
    })?;
    out.write_bool(request.atomic);
    write_durability(out, request.durability);
    Ok(())
}

fn read_request(input: &mut Decoder<'_>) -> Result<TransactionRequest, CodecRefusal> {
    let tx_id = read_tx_id(input)?;
    let tenant = read_tenant(input)?;
    let repository = read_repository(input)?;
    let principal = read_principal(input)?;
    let schema = input.read_schema_id()?;
    let idempotency_key = IdempotencyKey::new(read_slug(input, "IdempotencyKey")?);
    let canonical_request_digest = input.read_digest()?;
    let statements = input.read_sequence("statements", read_statement)?;
    let promised_closure = input
        .read_canonical_set("promised_closure", Decoder::read_git_oid)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let atomic = input.read_bool("atomic")?;
    let durability = read_durability(input)?;
    Ok(TransactionRequest {
        tx_id,
        tenant,
        repository,
        principal,
        schema,
        idempotency_key,
        canonical_request_digest,
        statements,
        promised_closure,
        atomic,
        durability,
    })
}

// ---------------------------------------------------------------------------
// Policy and genesis
// ---------------------------------------------------------------------------

fn write_scope_set(
    out: &mut Encoder,
    field: &'static str,
    scopes: &BTreeSet<Vec<u8>>,
) -> Result<(), CodecRefusal> {
    let scopes = scopes.iter().cloned().collect::<Vec<_>>();
    out.write_canonical_set(field, &scopes, |encoder, scope| {
        encoder.write_bytes("scope", scope)
    })
}

fn read_scope_set(
    input: &mut Decoder<'_>,
    field: &'static str,
) -> Result<BTreeSet<Vec<u8>>, CodecRefusal> {
    let scopes =
        input.read_canonical_set(field, |decoder| Ok(decoder.read_bytes("scope")?.to_vec()))?;
    Ok(scopes.into_iter().collect())
}

fn write_capabilities(
    out: &mut Encoder,
    capabilities: &PrincipalCapabilities,
) -> Result<(), CodecRefusal> {
    write_scope_set(out, "writable_scopes", &capabilities.writable_scopes)?;
    out.write_bool(capabilities.may_force);
    out.write_bool(capabilities.may_publish_forge);
    out.write_bool(capabilities.may_add_legal_hold);
    Ok(())
}

fn read_capabilities(input: &mut Decoder<'_>) -> Result<PrincipalCapabilities, CodecRefusal> {
    let writable_scopes = read_scope_set(input, "writable_scopes")?;
    let may_force = input.read_bool("may_force")?;
    let may_publish_forge = input.read_bool("may_publish_forge")?;
    let may_add_legal_hold = input.read_bool("may_add_legal_hold")?;
    Ok(PrincipalCapabilities {
        writable_scopes,
        may_force,
        may_publish_forge,
        may_add_legal_hold,
    })
}

fn write_policy(out: &mut Encoder, policy: &PolicySnapshot) -> Result<(), CodecRefusal> {
    out.write_scalar(policy.epoch.get());
    write_scope_set(out, "protected_scopes", &policy.protected_scopes)?;
    let principals = policy
        .principals
        .iter()
        .map(|(principal, capabilities)| (*principal, capabilities.clone()))
        .collect::<Vec<_>>();
    out.write_canonical_map(
        "principals",
        &principals,
        |encoder, principal| {
            write_principal(encoder, *principal);
            Ok(())
        },
        write_capabilities,
    )?;
    write_usize(out, policy.max_intents_per_transaction);
    let schemas = policy.supported_schemas.iter().copied().collect::<Vec<_>>();
    out.write_canonical_set("supported_schemas", &schemas, |encoder, schema| {
        encoder.write_schema_id(*schema)
    })?;
    let durability = policy
        .supported_durability
        .iter()
        .copied()
        .collect::<Vec<_>>();
    out.write_canonical_set("supported_durability", &durability, |encoder, profile| {
        write_durability(encoder, *profile);
        Ok(())
    })?;
    Ok(())
}

fn read_policy(input: &mut Decoder<'_>) -> Result<PolicySnapshot, CodecRefusal> {
    let epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("PolicyEpoch")?)
        .map_err(CodecRefusal::from)?;
    let protected_scopes = read_scope_set(input, "protected_scopes")?;
    let principals = input
        .read_canonical_map("principals", read_principal, read_capabilities)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let max_intents_per_transaction = read_usize(input, "max_intents_per_transaction")?;
    let supported_schemas = input
        .read_canonical_set("supported_schemas", Decoder::read_schema_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let supported_durability = input
        .read_canonical_set("supported_durability", read_durability)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    Ok(PolicySnapshot {
        epoch,
        protected_scopes,
        principals,
        max_intents_per_transaction,
        supported_schemas,
        supported_durability,
    })
}

fn write_genesis(out: &mut Encoder, genesis: &GenesisConfiguration) -> Result<(), CodecRefusal> {
    write_tenant(out, genesis.tenant);
    write_repository(out, genesis.repository);
    out.write_git_hash_algorithm(genesis.object_format);
    write_head_id(out, genesis.genesis_head_id)?;
    write_policy(out, &genesis.policy)?;
    out.write_scalar(genesis.format_registry_epoch.get());
    Ok(())
}

fn read_genesis(input: &mut Decoder<'_>) -> Result<GenesisConfiguration, CodecRefusal> {
    let tenant = read_tenant(input)?;
    let repository = read_repository(input)?;
    let object_format = input.read_git_hash_algorithm()?;
    let genesis_head_id = read_head_id(input)?;
    let policy = read_policy(input)?;
    let format_registry_epoch = RegistryEpoch::try_new(input.read_scalar::<u64>("RegistryEpoch")?)
        .map_err(CodecRefusal::from)?;
    Ok(GenesisConfiguration {
        tenant,
        repository,
        object_format,
        genesis_head_id,
        policy,
        format_registry_epoch,
    })
}

// ---------------------------------------------------------------------------
// Roots
// ---------------------------------------------------------------------------

fn write_decision_outcome(out: &mut Encoder, outcome: DecisionOutcome) -> Result<(), CodecRefusal> {
    match outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => {
            out.write_raw_byte(1);
            write_commit_id(out, repository_commit_id)?;
        }
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => {
            out.write_raw_byte(2);
            out.write_scalar(code.code_point());
            write_refusal_record_id(out, refusal_record_id)?;
        }
    }
    Ok(())
}

fn read_decision_outcome(input: &mut Decoder<'_>) -> Result<DecisionOutcome, CodecRefusal> {
    match input.read_raw_byte("DecisionOutcome")? {
        1 => Ok(DecisionOutcome::Committed {
            repository_commit_id: read_commit_id(input)?,
        }),
        2 => {
            let code = RefusalCode::from_code_point(input.read_scalar::<u16>("RefusalCode")?)
                .map_err(CodecRefusal::from)?;
            let refusal_record_id = read_refusal_record_id(input)?;
            Ok(DecisionOutcome::Refused {
                code,
                refusal_record_id,
            })
        }
        other => malformed("DecisionOutcome", u64::from(other)),
    }
}

/// The canonical roots as a body in their own right.
///
/// Roots are framed rather than stored bare so a recorded root is
/// self-describing: it carries its own domain tag and schema version, and a
/// decoder that meets an unknown major refuses instead of guessing. That
/// matters for a golden artifact, which outlives the build that wrote it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootsBody(pub RepositoryRoots);

impl CanonicalBody for RootsBody {
    const DOMAIN: DomainTag = DomainTag::from_static(ROOTS_DOMAIN);
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static(ROOTS_SCHEMA_FAMILY);
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_roots(out, &self.0)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        read_roots(input).map(Self)
    }
}

/// Encodes the canonical roots into their frame.
///
/// This is the function that gives a trace its notion of a "root": the bytes it
/// produces are what a step records and what replay compares.
pub fn encode_roots(roots: &RepositoryRoots) -> Result<Vec<u8>, CodecRefusal> {
    fgit_codec::wire::encode_body(&RootsBody(roots.clone()))
}

/// Decodes canonical roots produced by [`encode_roots`].
///
/// The round trip is what makes the module's injectivity claim checkable: if
/// [`encode_roots`] could map two different root sets to the same bytes, this
/// could not reconstruct them. A test asserts both directions.
pub fn decode_roots(bytes: &[u8]) -> Result<RepositoryRoots, TraceError> {
    let body = fgit_codec::wire::decode_body::<RootsBody>(
        bytes,
        fgit_codec::bounds::DecodeLimits::DEFAULT,
    )?;
    Ok(body.0)
}

fn read_roots(input: &mut Decoder<'_>) -> Result<RepositoryRoots, CodecRefusal> {
    let refs = input
        .read_canonical_map("refs", Decoder::read_ref_name, Decoder::read_git_oid)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let forge_positions = input
        .read_canonical_map(
            "forge_positions",
            |decoder| Ok(ForgeStreamId::new(read_slug(decoder, "ForgeStreamId")?)),
            |decoder| {
                Ok(ForgeStreamPosition::new(
                    decoder.read_scalar::<u64>("ForgeStreamPosition")?,
                ))
            },
        )?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let outcome_index = input
        .read_canonical_map("outcome_index", read_tx_id, read_decision_outcome)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let retention = input
        .read_canonical_set("retention", read_retention_root)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let outbox = input
        .read_canonical_map(
            "outbox",
            |decoder| {
                Ok(OutboxDeliveryKey::new(read_slug(
                    decoder,
                    "OutboxDeliveryKey",
                )?))
            },
            Decoder::read_digest,
        )?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    Ok(RepositoryRoots {
        refs,
        forge_positions,
        outcome_index,
        retention,
        outbox,
    })
}

fn write_roots(out: &mut Encoder, roots: &RepositoryRoots) -> Result<(), CodecRefusal> {
    let refs = roots
        .refs
        .iter()
        .map(|(name, oid)| (name.clone(), *oid))
        .collect::<Vec<_>>();
    out.write_canonical_map(
        "refs",
        &refs,
        |encoder, name| encoder.write_ref_name(name),
        |encoder, oid| {
            encoder.write_git_oid(oid);
            Ok(())
        },
    )?;

    let positions = roots
        .forge_positions
        .iter()
        .map(|(stream, position)| (*stream, *position))
        .collect::<Vec<_>>();
    out.write_canonical_map(
        "forge_positions",
        &positions,
        |encoder, stream| write_slug(encoder, "ForgeStreamId", stream.label()),
        |encoder, position| {
            encoder.write_scalar(position.get());
            Ok(())
        },
    )?;

    let outcomes = roots
        .outcome_index
        .iter()
        .map(|(tx_id, outcome)| (*tx_id, *outcome))
        .collect::<Vec<_>>();
    out.write_canonical_map(
        "outcome_index",
        &outcomes,
        |encoder, tx_id| write_tx_id(encoder, *tx_id),
        |encoder, outcome| write_decision_outcome(encoder, *outcome),
    )?;

    let retention = roots.retention.iter().copied().collect::<Vec<_>>();
    out.write_canonical_set("retention", &retention, |encoder, root| {
        write_retention_root(encoder, *root);
        Ok(())
    })?;

    let outbox = roots
        .outbox
        .iter()
        .map(|(key, digest)| (*key, *digest))
        .collect::<Vec<_>>();
    out.write_canonical_map(
        "outbox",
        &outbox,
        |encoder, key| write_slug(encoder, "OutboxDeliveryKey", key.label()),
        |encoder, digest| encoder.write_digest(digest),
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

fn write_quarantined(out: &mut Encoder, object: &QuarantinedObject) -> Result<(), CodecRefusal> {
    out.write_git_oid(&object.declared);
    out.write_git_oid(&object.recomputed);
    // Parent order is semantic in Git, so this is a sequence.
    out.write_sequence("parents", &object.parents, |encoder, parent| {
        encoder.write_git_oid(parent);
        Ok(())
    })
}

fn read_quarantined(input: &mut Decoder<'_>) -> Result<QuarantinedObject, CodecRefusal> {
    let declared = input.read_git_oid()?;
    let recomputed = input.read_git_oid()?;
    let parents = input.read_sequence("parents", Decoder::read_git_oid)?;
    Ok(QuarantinedObject {
        declared,
        recomputed,
        parents,
    })
}

fn write_granularity(out: &mut Encoder, granularity: WitnessGranularity) {
    out.write_raw_byte(match granularity {
        WitnessGranularity::Coarse => 1,
        WitnessGranularity::Refined => 2,
    });
}

fn read_granularity(input: &mut Decoder<'_>) -> Result<WitnessGranularity, CodecRefusal> {
    match input.read_raw_byte("WitnessGranularity")? {
        1 => Ok(WitnessGranularity::Coarse),
        2 => Ok(WitnessGranularity::Refined),
        other => malformed("WitnessGranularity", u64::from(other)),
    }
}

fn write_phase(out: &mut Encoder, phase: CancellationPhase) {
    out.write_raw_byte(match phase {
        CancellationPhase::BeforeSeal => 1,
        CancellationPhase::AfterSealBeforeCas => 2,
        CancellationPhase::AfterCas => 3,
    });
}

fn read_phase(input: &mut Decoder<'_>) -> Result<CancellationPhase, CodecRefusal> {
    match input.read_raw_byte("CancellationPhase")? {
        1 => Ok(CancellationPhase::BeforeSeal),
        2 => Ok(CancellationPhase::AfterSealBeforeCas),
        3 => Ok(CancellationPhase::AfterCas),
        other => malformed("CancellationPhase", u64::from(other)),
    }
}

fn write_input(out: &mut Encoder, input: &ModelInput) -> Result<(), CodecRefusal> {
    match input {
        ModelInput::Seal(request) => {
            out.write_raw_byte(1);
            write_seal_id(out, request.seal_id)?;
            write_request(out, &request.request)?;
        }
        ModelInput::StageObjects(request) => {
            out.write_raw_byte(2);
            write_tx_id(out, request.tx_id)?;
            out.write_sequence("objects", &request.objects, write_quarantined)?;
        }
        ModelInput::Prepare(request) => {
            out.write_raw_byte(3);
            write_capsule_id(out, request.capsule_id)?;
            write_request(out, &request.request)?;
            write_principal_snapshot_id(out, request.principal_snapshot)?;
            write_slug(out, "PreparationProfileId", profile_slug(request.profile)?)?;
            write_granularity(out, request.granularity);
        }
        ModelInput::Decide { capsule } => {
            out.write_raw_byte(4);
            write_capsule_id(out, *capsule)?;
        }
        ModelInput::Stage(request) => {
            out.write_raw_byte(5);
            write_batch_id(out, request.batch_id)?;
            write_head_id(out, request.candidate_head_id)?;
            // Capsule order is deliberately preserved even though the model
            // sorts by transaction identity before admitting: a trace records
            // what the caller supplied, so a replay can prove the sort is what
            // makes the batch order-independent.
            out.write_sequence("capsules", &request.capsules, |encoder, capsule| {
                write_capsule_id(encoder, *capsule)
            })?;
            let bodies = request
                .bodies
                .iter()
                .map(|(tx_id, identity)| (*tx_id, *identity))
                .collect::<Vec<_>>();
            out.write_canonical_map(
                "bodies",
                &bodies,
                |encoder, tx_id| write_tx_id(encoder, *tx_id),
                |encoder, identity| {
                    write_commit_id(encoder, identity.commit)?;
                    write_refusal_record_id(encoder, identity.refusal_record)
                },
            )?;
            out.write_bool(request.durability_satisfied);
        }
        ModelInput::CompareAndSwap(request) => {
            out.write_raw_byte(6);
            write_head_id(out, request.expected_head)?;
            out.write_scalar(request.expected_generation.get());
            write_batch_id(out, request.batch)?;
        }
        ModelInput::PublishConfiguration(request) => {
            out.write_raw_byte(7);
            write_head_id(out, request.candidate_head_id)?;
            write_head_id(out, request.expected_head)?;
            out.write_scalar(request.expected_generation.get());
            write_policy(out, &request.policy)?;
        }
        ModelInput::Cancel(request) => {
            out.write_raw_byte(8);
            write_tx_id(out, request.tx_id)?;
            write_phase(out, request.phase);
        }
    }
    Ok(())
}

fn profile_slug(profile: PreparationProfileId) -> Result<AsciiSlug, CodecRefusal> {
    AsciiSlug::try_new("PreparationProfileId", profile.as_str().as_bytes())
        .map_err(CodecRefusal::from)
}

fn read_input(input: &mut Decoder<'_>) -> Result<ModelInput, CodecRefusal> {
    match input.read_raw_byte("ModelInput")? {
        1 => {
            let seal_id = read_seal_id(input)?;
            let request = read_request(input)?;
            Ok(ModelInput::Seal(Box::new(SealRequest { seal_id, request })))
        }
        2 => {
            let tx_id = read_tx_id(input)?;
            let objects = input.read_sequence("objects", read_quarantined)?;
            Ok(ModelInput::StageObjects(QuarantineRequest {
                tx_id,
                objects,
            }))
        }
        3 => {
            let capsule_id = read_capsule_id(input)?;
            let request = read_request(input)?;
            let principal_snapshot = read_principal_snapshot_id(input)?;
            let profile_bytes = read_slug(input, "PreparationProfileId")?;
            let profile = PreparationProfileId::try_new(profile_bytes.as_bytes())
                .map_err(CodecRefusal::from)?;
            let granularity = read_granularity(input)?;
            Ok(ModelInput::Prepare(Box::new(PrepareRequest {
                capsule_id,
                request,
                principal_snapshot,
                profile,
                granularity,
            })))
        }
        4 => Ok(ModelInput::Decide {
            capsule: read_capsule_id(input)?,
        }),
        5 => {
            let batch_id = read_batch_id(input)?;
            let candidate_head_id = read_head_id(input)?;
            let capsules = input.read_sequence("capsules", read_capsule_id)?;
            let bodies = input
                .read_canonical_map("bodies", read_tx_id, |decoder| {
                    let commit = read_commit_id(decoder)?;
                    let refusal_record = read_refusal_record_id(decoder)?;
                    Ok(DecisionBodyIdentity {
                        commit,
                        refusal_record,
                    })
                })?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            let durability_satisfied = input.read_bool("durability_satisfied")?;
            Ok(ModelInput::Stage(StageRequest {
                batch_id,
                candidate_head_id,
                capsules,
                bodies,
                durability_satisfied,
            }))
        }
        6 => {
            let expected_head = read_head_id(input)?;
            let expected_generation =
                HeadGeneration::try_new(input.read_scalar::<u64>("HeadGeneration")?)
                    .map_err(CodecRefusal::from)?;
            let batch = read_batch_id(input)?;
            Ok(ModelInput::CompareAndSwap(CasRequest {
                expected_head,
                expected_generation,
                batch,
            }))
        }
        7 => {
            let candidate_head_id = read_head_id(input)?;
            let expected_head = read_head_id(input)?;
            let expected_generation =
                HeadGeneration::try_new(input.read_scalar::<u64>("HeadGeneration")?)
                    .map_err(CodecRefusal::from)?;
            let policy = read_policy(input)?;
            Ok(ModelInput::PublishConfiguration(Box::new(
                ConfigurationRequest {
                    candidate_head_id,
                    expected_head,
                    expected_generation,
                    policy,
                },
            )))
        }
        8 => {
            let tx_id = read_tx_id(input)?;
            let phase = read_phase(input)?;
            Ok(ModelInput::Cancel(CancellationRequest { tx_id, phase }))
        }
        other => malformed("ModelInput", u64::from(other)),
    }
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// A compact, comparable summary of what one step produced.
///
/// The full [`ModelOutput`] carries values a trace has no need to re-check —
/// whole capsules, whole verdicts. What a differential test needs is the part
/// an implementation must agree on: which kind of thing happened, and the
/// terminal outcome if there was one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ObservedOutcome {
    /// A seal was created.
    SealCreated,
    /// An existing seal was matched by a retry.
    SealRetry,
    /// The request was rejected before any seal existed, with this code point.
    SealRejected(u16),
    /// Objects entered a transaction-scoped quarantine.
    ObjectsQuarantined(u64),
    /// A capsule was produced.
    Prepared,
    /// A capsule was decided and would commit.
    DecidedCommit,
    /// A capsule was decided and would be refused, with this code point.
    DecidedRefuse(u16),
    /// The transaction was already terminal when decided.
    DecidedAlreadyTerminal,
    /// A batch was staged, nothing was deferred, and nothing became canonical.
    Staged,
    /// A head compare-and-swap won.
    CasWon,
    /// A head compare-and-swap lost.
    CasLost,
    /// A batch could not become visible under its durability profile.
    CasDurabilityUnsatisfied,
    /// A configuration head transition won.
    ConfigurationWon,
    /// A configuration head transition lost.
    ConfigurationLost,
    /// A capsule could not be decided and must be prepared again, with this
    /// [`crate::transition::RepreparationReason`] code point. Not a decision.
    DecidedRequiresRepreparation(u16),
    /// A batch was staged and this many capsules were deferred for
    /// re-preparation.
    StagedWithDeferrals(u64),
    /// No batch was staged because this many capsules all needed
    /// re-preparation.
    StagedNothing(u64),
    /// A cancellation was processed; the flags are whether the seal survives
    /// and whether the transaction is decided.
    Cancelled {
        /// Whether a seal survives the cancellation.
        seal_survives: bool,
        /// Whether the transaction has a terminal decision.
        decided: bool,
    },
}

impl ObservedOutcome {
    /// Summarizes a model output.
    #[must_use]
    pub fn of(output: &ModelOutput) -> Self {
        match output {
            ModelOutput::Sealed(SealOutcome::Created(_)) => Self::SealCreated,
            ModelOutput::Sealed(SealOutcome::ExistingRetry(_)) => Self::SealRetry,
            ModelOutput::Sealed(SealOutcome::Rejected(code)) => {
                Self::SealRejected(code.code_point())
            }
            ModelOutput::ObjectsQuarantined { held } => {
                Self::ObjectsQuarantined(u64::try_from(*held).unwrap_or(u64::MAX))
            }
            ModelOutput::Prepared(_) => Self::Prepared,
            ModelOutput::Decided(DecisionVerdict::Commit(_)) => Self::DecidedCommit,
            ModelOutput::Decided(DecisionVerdict::Refuse(code)) => {
                Self::DecidedRefuse(code.code_point())
            }
            ModelOutput::Decided(DecisionVerdict::AlreadyTerminal(_)) => {
                Self::DecidedAlreadyTerminal
            }
            ModelOutput::Decided(DecisionVerdict::RequiresRepreparation(reason)) => {
                Self::DecidedRequiresRepreparation(reason.code_point())
            }
            ModelOutput::Staged(outcome) => {
                let deferred = u64::try_from(outcome.deferred.len()).unwrap_or(u64::MAX);
                if outcome.batch.is_none() {
                    Self::StagedNothing(deferred)
                } else if deferred == 0 {
                    Self::Staged
                } else {
                    Self::StagedWithDeferrals(deferred)
                }
            }
            ModelOutput::HeadTransition(CasOutcome::Won { .. }) => Self::CasWon,
            ModelOutput::HeadTransition(CasOutcome::Lost { .. }) => Self::CasLost,
            ModelOutput::HeadTransition(CasOutcome::DurabilityUnsatisfied { .. }) => {
                Self::CasDurabilityUnsatisfied
            }
            ModelOutput::ConfigurationTransition(ConfigurationOutcome::Won { .. }) => {
                Self::ConfigurationWon
            }
            ModelOutput::ConfigurationTransition(ConfigurationOutcome::Lost { .. }) => {
                Self::ConfigurationLost
            }
            ModelOutput::Cancelled(report) => Self::Cancelled {
                seal_survives: report.seal_survives,
                decided: report.is_decided(),
            },
        }
    }

    /// Stable machine-readable name for NDJSON rendering.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::SealCreated => "seal_created",
            Self::SealRetry => "seal_retry",
            Self::SealRejected(_) => "seal_rejected",
            Self::ObjectsQuarantined(_) => "objects_quarantined",
            Self::Prepared => "prepared",
            Self::DecidedCommit => "decided_commit",
            Self::DecidedRefuse(_) => "decided_refuse",
            Self::DecidedAlreadyTerminal => "decided_already_terminal",
            Self::DecidedRequiresRepreparation(_) => "decided_requires_repreparation",
            Self::Staged => "staged",
            Self::StagedWithDeferrals(_) => "staged_with_deferrals",
            Self::StagedNothing(_) => "staged_nothing",
            Self::CasWon => "cas_won",
            Self::CasLost => "cas_lost",
            Self::CasDurabilityUnsatisfied => "cas_durability_unsatisfied",
            Self::ConfigurationWon => "configuration_won",
            Self::ConfigurationLost => "configuration_lost",
            Self::Cancelled { .. } => "cancelled",
        }
    }
}

fn write_observed(out: &mut Encoder, observed: ObservedOutcome) {
    match observed {
        ObservedOutcome::SealCreated => out.write_raw_byte(1),
        ObservedOutcome::SealRetry => out.write_raw_byte(2),
        ObservedOutcome::SealRejected(code) => {
            out.write_raw_byte(3);
            out.write_scalar(code);
        }
        ObservedOutcome::ObjectsQuarantined(held) => {
            out.write_raw_byte(4);
            out.write_scalar(held);
        }
        ObservedOutcome::Prepared => out.write_raw_byte(5),
        ObservedOutcome::DecidedCommit => out.write_raw_byte(6),
        ObservedOutcome::DecidedRefuse(code) => {
            out.write_raw_byte(7);
            out.write_scalar(code);
        }
        ObservedOutcome::DecidedAlreadyTerminal => out.write_raw_byte(8),
        ObservedOutcome::Staged => out.write_raw_byte(9),
        ObservedOutcome::CasWon => out.write_raw_byte(10),
        ObservedOutcome::CasLost => out.write_raw_byte(11),
        ObservedOutcome::CasDurabilityUnsatisfied => out.write_raw_byte(12),
        ObservedOutcome::ConfigurationWon => out.write_raw_byte(13),
        ObservedOutcome::ConfigurationLost => out.write_raw_byte(14),
        ObservedOutcome::DecidedRequiresRepreparation(reason) => {
            out.write_raw_byte(16);
            out.write_scalar(reason);
        }
        ObservedOutcome::StagedWithDeferrals(deferred) => {
            out.write_raw_byte(17);
            out.write_scalar(deferred);
        }
        ObservedOutcome::StagedNothing(deferred) => {
            out.write_raw_byte(18);
            out.write_scalar(deferred);
        }
        ObservedOutcome::Cancelled {
            seal_survives,
            decided,
        } => {
            out.write_raw_byte(15);
            out.write_bool(seal_survives);
            out.write_bool(decided);
        }
    }
}

fn read_observed(input: &mut Decoder<'_>) -> Result<ObservedOutcome, CodecRefusal> {
    match input.read_raw_byte("ObservedOutcome")? {
        1 => Ok(ObservedOutcome::SealCreated),
        2 => Ok(ObservedOutcome::SealRetry),
        3 => Ok(ObservedOutcome::SealRejected(
            input.read_scalar::<u16>("RequestRejectionCode")?,
        )),
        4 => Ok(ObservedOutcome::ObjectsQuarantined(
            input.read_scalar::<u64>("held")?,
        )),
        5 => Ok(ObservedOutcome::Prepared),
        6 => Ok(ObservedOutcome::DecidedCommit),
        7 => Ok(ObservedOutcome::DecidedRefuse(
            input.read_scalar::<u16>("RefusalCode")?,
        )),
        8 => Ok(ObservedOutcome::DecidedAlreadyTerminal),
        9 => Ok(ObservedOutcome::Staged),
        10 => Ok(ObservedOutcome::CasWon),
        11 => Ok(ObservedOutcome::CasLost),
        12 => Ok(ObservedOutcome::CasDurabilityUnsatisfied),
        13 => Ok(ObservedOutcome::ConfigurationWon),
        14 => Ok(ObservedOutcome::ConfigurationLost),
        15 => {
            let seal_survives = input.read_bool("seal_survives")?;
            let decided = input.read_bool("decided")?;
            Ok(ObservedOutcome::Cancelled {
                seal_survives,
                decided,
            })
        }
        16 => Ok(ObservedOutcome::DecidedRequiresRepreparation(
            input.read_scalar::<u16>("RepreparationReason")?,
        )),
        17 => Ok(ObservedOutcome::StagedWithDeferrals(
            input.read_scalar::<u64>("deferred")?,
        )),
        18 => Ok(ObservedOutcome::StagedNothing(
            input.read_scalar::<u64>("deferred")?,
        )),
        other => malformed("ObservedOutcome", u64::from(other)),
    }
}

/// The head positions a step left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeadObservation {
    /// Head generation after the step.
    pub generation: HeadGeneration,
    /// Highest consumed decision sequence, if any.
    pub latest_decision_sequence: Option<DecisionSequence>,
    /// Highest consumed repository sequence, if any.
    pub latest_repository_sequence: Option<RepositorySequence>,
}

impl HeadObservation {
    /// Reads the head positions out of a state.
    #[must_use]
    pub const fn of(state: &RepositoryState) -> Self {
        Self {
            generation: state.head().body.generation,
            latest_decision_sequence: state.head().body.latest_decision_sequence,
            latest_repository_sequence: state.head().body.latest_repository_sequence,
        }
    }
}

fn write_head_observation(out: &mut Encoder, head: HeadObservation) {
    out.write_scalar(head.generation.get());
    out.write_scalar(
        head.latest_decision_sequence
            .map_or(0, DecisionSequence::get),
    );
    out.write_scalar(
        head.latest_repository_sequence
            .map_or(0, RepositorySequence::get),
    );
}

fn read_head_observation(input: &mut Decoder<'_>) -> Result<HeadObservation, CodecRefusal> {
    let generation = HeadGeneration::try_new(input.read_scalar::<u64>("HeadGeneration")?)
        .map_err(CodecRefusal::from)?;
    // Zero is the reserved "no value yet" slot for these counters, which is why
    // they are `Option` here and never a live zero.
    let decision = input.read_scalar::<u64>("DecisionSequence")?;
    let repository = input.read_scalar::<u64>("RepositorySequence")?;
    let latest_decision_sequence = if decision == 0 {
        None
    } else {
        Some(DecisionSequence::try_new(decision).map_err(CodecRefusal::from)?)
    };
    let latest_repository_sequence = if repository == 0 {
        None
    } else {
        Some(RepositorySequence::try_new(repository).map_err(CodecRefusal::from)?)
    };
    Ok(HeadObservation {
        generation,
        latest_decision_sequence,
        latest_repository_sequence,
    })
}

/// One recorded step: what was applied, and what the model showed afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceStep {
    /// The input that was applied.
    pub input: ModelInput,
    /// A summary of what the step produced.
    pub observed: ObservedOutcome,
    /// The canonical encoding of the roots after the step.
    pub roots: Vec<u8>,
    /// The head positions after the step.
    pub head: HeadObservation,
}

/// A complete recorded model history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GoldenTrace {
    /// How the repository began.
    pub genesis: GenesisConfiguration,
    /// The steps, in the order they were applied.
    pub steps: Vec<TraceStep>,
}

impl CanonicalBody for GoldenTrace {
    const DOMAIN: DomainTag = DomainTag::from_static(TRACE_DOMAIN);
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static(TRACE_SCHEMA_FAMILY);
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        write_genesis(out, &self.genesis)?;
        out.write_sequence("steps", &self.steps, |encoder, step| {
            write_input(encoder, &step.input)?;
            write_observed(encoder, step.observed);
            encoder.write_bytes("roots", &step.roots)?;
            write_head_observation(encoder, step.head);
            Ok(())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let genesis = read_genesis(input)?;
        let steps = input.read_sequence("steps", |decoder| {
            let model_input = read_input(decoder)?;
            let observed = read_observed(decoder)?;
            let roots = decoder.read_bytes("roots")?.to_vec();
            let head = read_head_observation(decoder)?;
            Ok(TraceStep {
                input: model_input,
                observed,
                roots,
                head,
            })
        })?;
        Ok(Self { genesis, steps })
    }
}

impl GoldenTrace {
    /// The schema identifier this build writes.
    #[must_use]
    pub fn schema() -> SchemaId {
        <Self as CanonicalBody>::schema_id()
    }
}

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// Records a history by applying inputs to a fresh model.
///
/// The recorder is the only way to build a [`GoldenTrace`] from a run, and it
/// records what the model actually did rather than what the caller expected —
/// there is no argument by which a caller can assert an outcome.
#[derive(Clone, Debug)]
pub struct TraceRecorder {
    genesis: GenesisConfiguration,
    state: RepositoryState,
    steps: Vec<TraceStep>,
}

impl TraceRecorder {
    /// Opens a recorder on a fresh genesis state.
    #[must_use]
    pub fn new(genesis: GenesisConfiguration) -> Self {
        let state = RepositoryState::genesis(genesis.clone());
        Self {
            genesis,
            state,
            steps: Vec::new(),
        }
    }

    /// The state as it currently stands.
    #[must_use]
    pub const fn state(&self) -> &RepositoryState {
        &self.state
    }

    /// Applies one input and records the step.
    pub fn apply(&mut self, input: ModelInput) -> Result<&TraceStep, TraceError> {
        let ModelStep { next, output } = step(&self.state, &input)?;
        let roots = encode_roots(next.roots())?;
        let head = HeadObservation::of(&next);
        self.state = next;
        self.steps.push(TraceStep {
            input,
            observed: ObservedOutcome::of(&output),
            roots,
            head,
        });
        Ok(self
            .steps
            .last()
            .unwrap_or_else(|| unreachable!("a step was just pushed, so the vector is not empty")))
    }

    /// Finishes the recording.
    #[must_use]
    pub fn finish(self) -> GoldenTrace {
        GoldenTrace {
            genesis: self.genesis,
            steps: self.steps,
        }
    }
}

// ---------------------------------------------------------------------------
// Replay and diffing
// ---------------------------------------------------------------------------

/// Which part of a step disagreed on replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DivergenceKind {
    /// The step produced a different outcome.
    Outcome,
    /// The step left different roots behind.
    Roots,
    /// The step left the head in a different position.
    Head,
}

impl DivergenceKind {
    /// Stable machine-readable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outcome => "outcome",
            Self::Roots => "roots",
            Self::Head => "head",
        }
    }
}

/// The first step at which replay stopped agreeing with the trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Divergence {
    /// Zero-based index of the diverging step.
    pub step_index: usize,
    /// What disagreed.
    pub kind: DivergenceKind,
    /// A stable name for the input that was applied.
    pub input_kind: &'static str,
    /// What the trace recorded.
    pub expected_outcome: ObservedOutcome,
    /// What replay produced.
    pub actual_outcome: ObservedOutcome,
    /// The roots the trace recorded, as lowercase hexadecimal.
    pub expected_roots: String,
    /// The roots replay produced, as lowercase hexadecimal.
    pub actual_roots: String,
    /// The head the trace recorded.
    pub expected_head: HeadObservation,
    /// The head replay produced.
    pub actual_head: HeadObservation,
}

impl Divergence {
    /// Renders this divergence as one NDJSON record.
    ///
    /// One object, one line, no trailing newline. The diff output of a whole
    /// replay is these lines concatenated, which is what makes it
    /// NDJSON-parseable by an ordinary line reader.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push('{');
        push_json_field(&mut out, "record", "trace_divergence", true);
        push_json_number(&mut out, "step_index", self.step_index as u64);
        push_json_field(&mut out, "kind", self.kind.as_str(), false);
        push_json_field(&mut out, "input", self.input_kind, false);
        push_json_field(
            &mut out,
            "expected_outcome",
            self.expected_outcome.kind(),
            false,
        );
        push_json_field(
            &mut out,
            "actual_outcome",
            self.actual_outcome.kind(),
            false,
        );
        push_json_field(&mut out, "expected_roots", &self.expected_roots, false);
        push_json_field(&mut out, "actual_roots", &self.actual_roots, false);
        push_json_number(
            &mut out,
            "expected_head_generation",
            self.expected_head.generation.get(),
        );
        push_json_number(
            &mut out,
            "actual_head_generation",
            self.actual_head.generation.get(),
        );
        push_json_number(
            &mut out,
            "expected_decision_sequence",
            self.expected_head
                .latest_decision_sequence
                .map_or(0, DecisionSequence::get),
        );
        push_json_number(
            &mut out,
            "actual_decision_sequence",
            self.actual_head
                .latest_decision_sequence
                .map_or(0, DecisionSequence::get),
        );
        push_json_number(
            &mut out,
            "expected_repository_sequence",
            self.expected_head
                .latest_repository_sequence
                .map_or(0, RepositorySequence::get),
        );
        push_json_number(
            &mut out,
            "actual_repository_sequence",
            self.actual_head
                .latest_repository_sequence
                .map_or(0, RepositorySequence::get),
        );
        out.push('}');
        out
    }
}

/// What replaying a trace produced.
#[derive(Clone, Debug)]
pub struct ReplayReport {
    /// The state after replaying every step.
    pub state: RepositoryState,
    /// How many steps were replayed before stopping.
    pub steps_replayed: usize,
    /// The first divergence, if there was one.
    pub divergence: Option<Divergence>,
}

impl ReplayReport {
    /// True when replay reproduced the trace exactly.
    #[must_use]
    pub const fn is_faithful(&self) -> bool {
        self.divergence.is_none()
    }

    /// The NDJSON diff: empty when the replay was faithful, one record
    /// otherwise.
    #[must_use]
    pub fn to_ndjson(&self) -> String {
        self.divergence
            .as_ref()
            .map_or_else(String::new, Divergence::to_ndjson)
    }
}

/// A stable name for the kind of an input, for diff output.
#[must_use]
pub const fn input_kind(input: &ModelInput) -> &'static str {
    match input {
        ModelInput::Seal(_) => "seal",
        ModelInput::StageObjects(_) => "stage_objects",
        ModelInput::Prepare(_) => "prepare",
        ModelInput::Decide { .. } => "decide",
        ModelInput::Stage(_) => "stage",
        ModelInput::CompareAndSwap(_) => "compare_and_swap",
        ModelInput::PublishConfiguration(_) => "publish_configuration",
        ModelInput::Cancel(_) => "cancel",
    }
}

/// Replays a trace against a fresh model and reports the first divergence.
///
/// Replay stops at the first disagreement rather than continuing: every step
/// after a divergence is evaluated against a state the trace never described,
/// so the disagreements it would report are noise.
pub fn replay(trace: &GoldenTrace) -> Result<ReplayReport, TraceError> {
    let mut state = RepositoryState::genesis(trace.genesis.clone());
    for (index, recorded) in trace.steps.iter().enumerate() {
        let ModelStep { next, output } = step(&state, &recorded.input)?;
        let actual_outcome = ObservedOutcome::of(&output);
        let actual_roots = encode_roots(next.roots())?;
        let actual_head = HeadObservation::of(&next);

        let kind = if actual_outcome == recorded.observed {
            if actual_roots == recorded.roots {
                if actual_head == recorded.head {
                    None
                } else {
                    Some(DivergenceKind::Head)
                }
            } else {
                Some(DivergenceKind::Roots)
            }
        } else {
            Some(DivergenceKind::Outcome)
        };

        if let Some(kind) = kind {
            return Ok(ReplayReport {
                state,
                steps_replayed: index,
                divergence: Some(Divergence {
                    step_index: index,
                    kind,
                    input_kind: input_kind(&recorded.input),
                    expected_outcome: recorded.observed,
                    actual_outcome,
                    expected_roots: hex(&recorded.roots),
                    actual_roots: hex(&actual_roots),
                    expected_head: recorded.head,
                    actual_head,
                }),
            });
        }
        state = next;
    }
    Ok(ReplayReport {
        steps_replayed: trace.steps.len(),
        state,
        divergence: None,
    })
}

/// Compares two traces recorded from the same genesis.
///
/// This is the shape a differential test wants: run an implementation, record
/// its history as a trace, and ask where it first stops agreeing with the
/// reference trace.
#[must_use]
pub fn diff(reference: &GoldenTrace, candidate: &GoldenTrace) -> Option<Divergence> {
    for (index, expected) in reference.steps.iter().enumerate() {
        let Some(actual) = candidate.steps.get(index) else {
            return Some(Divergence {
                step_index: index,
                kind: DivergenceKind::Outcome,
                input_kind: input_kind(&expected.input),
                expected_outcome: expected.observed,
                actual_outcome: expected.observed,
                expected_roots: hex(&expected.roots),
                actual_roots: String::new(),
                expected_head: expected.head,
                actual_head: expected.head,
            });
        };
        let kind = if actual.observed == expected.observed {
            if actual.roots == expected.roots {
                if actual.head == expected.head {
                    continue;
                }
                DivergenceKind::Head
            } else {
                DivergenceKind::Roots
            }
        } else {
            DivergenceKind::Outcome
        };
        return Some(Divergence {
            step_index: index,
            kind,
            input_kind: input_kind(&expected.input),
            expected_outcome: expected.observed,
            actual_outcome: actual.observed,
            expected_roots: hex(&expected.roots),
            actual_roots: hex(&actual.roots),
            expected_head: expected.head,
            actual_head: actual.head,
        });
    }
    None
}

/// The canonical bytes of a trace, framed.
pub fn encode(trace: &GoldenTrace) -> Result<Vec<u8>, TraceError> {
    Ok(fgit_codec::wire::encode_body(trace)?)
}

/// Decodes a trace from its canonical frame.
pub fn decode(bytes: &[u8]) -> Result<GoldenTrace, TraceError> {
    Ok(fgit_codec::wire::decode_body::<GoldenTrace>(
        bytes,
        fgit_codec::bounds::DecodeLimits::DEFAULT,
    )?)
}

/// The unframed canonical payload of a trace.
pub fn payload(trace: &GoldenTrace) -> Result<Vec<u8>, TraceError> {
    Ok(canonical_body_bytes(trace)?)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

fn push_json_field(out: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        out.push(',');
    }
    push_json_string(out, key);
    out.push(':');
    push_json_string(out, value);
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    out.push(',');
    push_json_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

/// Writes a JSON string literal, escaping exactly what RFC 8259 requires.
fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if control < ' ' => {
                out.push_str("\\u");
                let code = u32::from(control);
                for shift in [12_u32, 8, 4, 0] {
                    out.push(char::from_digit((code >> shift) & 0xf, 16).unwrap_or('0'));
                }
            }
            ordinary => out.push(ordinary),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::{
        DivergenceKind, GoldenTrace, ObservedOutcome, TraceRecorder, decode, encode, hex,
        push_json_string, replay,
    };
    use crate::harness::IdentityMint;
    use crate::machine::ModelInput;
    use crate::state::{GenesisConfiguration, PolicySnapshot};
    use crate::transition::{CasRequest, SealRequest};
    use fgit_types::native::GitHashAlgorithm;
    use fgit_types::numeric::{PolicyEpoch, RegistryEpoch};
    use std::collections::{BTreeMap, BTreeSet};

    fn genesis(seed: u64) -> GenesisConfiguration {
        let mut mint = IdentityMint::new(seed);
        GenesisConfiguration {
            tenant: mint.tenant(),
            repository: mint.repository(),
            object_format: GitHashAlgorithm::Sha1,
            genesis_head_id: mint.head(),
            policy: PolicySnapshot {
                epoch: PolicyEpoch::FIRST,
                protected_scopes: BTreeSet::new(),
                principals: BTreeMap::new(),
                max_intents_per_transaction: 8,
                supported_schemas: BTreeSet::new(),
                supported_durability: BTreeSet::new(),
            },
            format_registry_epoch: RegistryEpoch::FIRST,
        }
    }

    #[test]
    fn an_empty_trace_round_trips_through_the_canonical_codec() {
        let trace = TraceRecorder::new(genesis(1)).finish();
        let bytes = encode(&trace).expect("encode");
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded, trace);
        assert_eq!(encode(&decoded).expect("re-encode"), bytes);
    }

    #[test]
    fn replaying_an_empty_trace_reaches_genesis_and_diverges_nowhere() {
        let trace = TraceRecorder::new(genesis(2)).finish();
        let report = replay(&trace).expect("replay");
        assert!(report.is_faithful());
        assert_eq!(report.steps_replayed, 0);
        assert_eq!(report.to_ndjson(), "");
    }

    #[test]
    fn a_tampered_step_is_reported_with_its_index_and_kind() {
        let mut mint = IdentityMint::new(3);
        let configuration = genesis(3);
        let mut recorder = TraceRecorder::new(configuration);
        // A compare-and-swap naming a batch that was never staged is an
        // invariant breach, so use a cancellation: it is always well-defined
        // and changes nothing.
        recorder
            .apply(ModelInput::Cancel(crate::machine::CancellationRequest {
                tx_id: mint.tx(),
                phase: crate::machine::CancellationPhase::BeforeSeal,
            }))
            .expect("cancel");
        let mut trace = recorder.finish();
        assert_eq!(trace.steps.len(), 1);

        // Plant a wrong observation and confirm replay names it.
        trace.steps[0].observed = ObservedOutcome::CasWon;
        let report = replay(&trace).expect("replay");
        let divergence = report.divergence.expect("a planted divergence is found");
        assert_eq!(divergence.step_index, 0);
        assert_eq!(divergence.kind, DivergenceKind::Outcome);
        assert_eq!(divergence.input_kind, "cancel");
        let line = divergence.to_ndjson();
        assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
        assert!(!line.contains('\n'), "an NDJSON record is one line: {line}");
    }

    #[test]
    fn the_schema_identity_is_stable() {
        let schema = GoldenTrace::schema();
        assert_eq!(schema.major(), 1);
        assert_eq!(schema.minor(), 0);
    }

    #[test]
    fn hex_rendering_is_lowercase_and_two_characters_per_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn json_strings_escape_what_the_grammar_requires() {
        let mut out = String::new();
        push_json_string(&mut out, "a\"b\\c\nd\te\u{1}");
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");
    }

    #[test]
    fn an_unstaged_compare_and_swap_is_an_invariant_breach_not_a_recorded_step() {
        let mut mint = IdentityMint::new(4);
        let mut recorder = TraceRecorder::new(genesis(4));
        let error = recorder
            .apply(ModelInput::CompareAndSwap(CasRequest {
                expected_head: recorder.state().head().id,
                expected_generation: recorder.state().head().body.generation,
                batch: mint.batch(),
            }))
            .expect_err("an unstaged batch cannot be published");
        // A recorded history never contains a breach: the recorder refuses to
        // write the step rather than storing a fabricated observation.
        assert!(matches!(error, super::TraceError::Invariant(_)));
    }

    #[test]
    fn a_seal_step_records_what_the_model_did_not_what_a_caller_asserted() {
        let mut mint = IdentityMint::new(5);
        let configuration = genesis(5);
        let mut recorder = TraceRecorder::new(configuration);
        let request = crate::harness::RequestBuilder::new(
            recorder.state().tenant(),
            recorder.state().repository(),
            mint.principal(),
            fgit_types::label::SchemaId::new(
                fgit_types::label::SchemaFamily::from_static("fgit/ref-txn"),
                2,
                0,
            ),
            crate::intent::IdempotencyKey::new(crate::harness::label("k1")),
        )
        .build(&mut mint);
        let step = recorder
            .apply(ModelInput::Seal(Box::new(SealRequest {
                seal_id: mint.seal(),
                request,
            })))
            .expect("seal");
        // The scenario policy supports no schema at all, so the request is
        // rejected pre-seal. The recorder writes the rejection, not a success.
        assert!(matches!(step.observed, ObservedOutcome::SealRejected(_)));
    }
}
