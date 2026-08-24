//! The identity-bearing canonical schemas.
//!
//! These are the bodies whose digests are canonical identities: the
//! transaction seal, the Repository Commit Record, the repository decision and
//! its batch, the authority head, and the refusal record. Their field lists
//! follow `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` sections 5.2, 7, 8.1, and
//! 8.2.
//!
//! They live in `fgit-codec` rather than in a consumer because their *bytes*
//! are the contract. Two crates that each defined their own version of the
//! seal would eventually produce two identities for one transaction, which is
//! precisely the failure the domain separation rule exists to prevent.
//!
//! # One deliberate refinement of the written contract
//!
//! The normative head body types `latest_decision_sequence` and
//! `latest_repository_sequence` as plain sequences, but a repository at
//! genesis has neither. Rather than reserve zero and let a sentinel travel
//! around disguised as a real sequence, both are `Option` here, and the
//! encoding is an explicit presence tag. The gap-free counters in
//! `fgit-types` already refuse zero for the same reason. This is recorded as a
//! non-claim in `docs/ADR-0002-CANONICAL-CODEC.md`.

use fgit_types::hash::Digest;
use fgit_types::identity::{
    PrincipalSnapshotId, RefusalRecordId, RepositoryAuthorityHeadId, RepositoryCapsuleId,
    RepositoryCommitId, RepositoryDecisionBatchId, TransactionSealId, TxId,
};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::numeric::{
    DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositorySequence,
};
use fgit_types::{
    DecisionOutcome, DomainTag, GitHashAlgorithm, PrincipalId, RefusalCode, RepositoryId,
    SchemaFamily, SchemaId, TenantId,
};

use crate::error::CodecRefusal;
use crate::reader::Decoder;
use crate::wire::CanonicalBody;
use crate::writer::Encoder;

/// Largest refusal detail string, in bytes.
pub const MAX_REFUSAL_DETAIL_LEN: usize = 4096;

/// Reads a domain-pinned derived identity, refusing a foreign domain.
macro_rules! read_derived {
    ($input:expr, $type:ty) => {
        <$type>::from_internal_object_id($input.read_internal_object_id()?)
            .map_err(CodecRefusal::from)?
    };
}

/// The immutable body that binds one logical mutation identity to one exact
/// semantic request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionSealBody {
    /// Identity of the sealed logical mutation.
    pub tx_id: TxId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Target repository.
    pub repository_id: RepositoryId,
    /// Principal the gateway authenticated.
    pub authenticated_principal_id: PrincipalId,
    /// Digest of the client's idempotency key.
    pub idempotency_key_digest: Digest,
    /// Digest binding every client-visible semantic field of the request.
    pub canonical_request_digest: Digest,
    /// Schema of the request that was canonicalized.
    pub request_schema: SchemaId,
}

impl CanonicalBody for TransactionSealBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/txn-seal/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("txn-seal");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_internal_object_id(self.tx_id.as_internal_object_id())?;
        out.write_opaque_id(self.tenant_id.as_bytes());
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_opaque_id(self.authenticated_principal_id.as_bytes());
        out.write_digest(&self.idempotency_key_digest)?;
        out.write_digest(&self.canonical_request_digest)?;
        out.write_schema_id(self.request_schema)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            tx_id: read_derived!(input, TxId),
            tenant_id: TenantId::from_bytes(input.read_opaque_id("tenant_id")?),
            repository_id: RepositoryId::from_bytes(input.read_opaque_id("repository_id")?),
            authenticated_principal_id: PrincipalId::from_bytes(
                input.read_opaque_id("authenticated_principal_id")?,
            ),
            idempotency_key_digest: input.read_digest()?,
            canonical_request_digest: input.read_digest()?,
            request_schema: input.read_schema_id()?,
        })
    }
}

/// The canonical source and forge mutation record for one committed logical
/// transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryCommitRecord {
    /// Repository the record belongs to.
    pub repository_id: RepositoryId,
    /// Position in the committed-transition order.
    pub repository_sequence: RepositorySequence,
    /// Previously committed record, absent only at repository creation.
    pub parent_rcr_id: Option<RepositoryCommitId>,
    /// Sealed transaction this record commits.
    pub tx_id: TxId,
    /// Immutable principal and capability snapshot the decision used.
    pub principal_snapshot_id: PrincipalSnapshotId,
    /// Digest binding the client-visible semantic request.
    pub canonical_request_digest: Digest,
    /// Root over the ref changes this record applies.
    pub ref_delta_root: Digest,
    /// Root over the resulting ref state.
    pub resulting_ref_root: Digest,
    /// Root over the validated object closure.
    pub object_closure_root: Digest,
    /// Root over the forge events committed with the ref changes.
    pub forge_event_batch_root: Digest,
    /// Root over the resulting forge position.
    pub resulting_forge_position_root: Digest,
    /// Policy epoch the decision was evaluated under.
    pub policy_epoch: PolicyEpoch,
    /// Root over the policy decision evidence.
    pub policy_decision_root: Digest,
    /// Root over the invariant evidence.
    pub invariant_evidence_root: Digest,
    /// Root over the external-effect obligations this record owes.
    pub outbox_effect_root: Digest,
    /// Root over the retention change this record makes.
    pub retention_delta_root: Digest,
}

impl CanonicalBody for RepositoryCommitRecord {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/rcr/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("rcr");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_scalar(self.repository_sequence.get());
        out.write_option(self.parent_rcr_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_internal_object_id(self.tx_id.as_internal_object_id())?;
        out.write_internal_object_id(self.principal_snapshot_id.as_internal_object_id())?;
        for digest in [
            &self.canonical_request_digest,
            &self.ref_delta_root,
            &self.resulting_ref_root,
            &self.object_closure_root,
            &self.forge_event_batch_root,
            &self.resulting_forge_position_root,
        ] {
            out.write_digest(digest)?;
        }
        out.write_scalar(self.policy_epoch.get());
        for digest in [
            &self.policy_decision_root,
            &self.invariant_evidence_root,
            &self.outbox_effect_root,
            &self.retention_delta_root,
        ] {
            out.write_digest(digest)?;
        }
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let repository_sequence =
            RepositorySequence::try_new(input.read_scalar::<u64>("repository_sequence")?)?;
        let parent_rcr_id = input.read_option("parent_rcr_id", |input| {
            Ok(read_derived!(input, RepositoryCommitId))
        })?;
        let tx_id = read_derived!(input, TxId);
        let principal_snapshot_id = read_derived!(input, PrincipalSnapshotId);
        let canonical_request_digest = input.read_digest()?;
        let ref_delta_root = input.read_digest()?;
        let resulting_ref_root = input.read_digest()?;
        let object_closure_root = input.read_digest()?;
        let forge_event_batch_root = input.read_digest()?;
        let resulting_forge_position_root = input.read_digest()?;
        let policy_epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("policy_epoch")?)?;
        Ok(Self {
            repository_id,
            repository_sequence,
            parent_rcr_id,
            tx_id,
            principal_snapshot_id,
            canonical_request_digest,
            ref_delta_root,
            resulting_ref_root,
            object_closure_root,
            forge_event_batch_root,
            resulting_forge_position_root,
            policy_epoch,
            policy_decision_root: input.read_digest()?,
            invariant_evidence_root: input.read_digest()?,
            outbox_effect_root: input.read_digest()?,
            retention_delta_root: input.read_digest()?,
        })
    }
}

/// One terminal decision for one sealed transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryDecision {
    /// Sealed transaction the decision belongs to.
    pub tx_id: TxId,
    /// Position in the terminal-decision order, refusals included.
    pub decision_sequence: DecisionSequence,
    /// The terminal outcome.
    pub outcome: DecisionOutcome,
}

impl RepositoryDecision {
    /// Writes this terminal decision in the one canonical form shared by
    /// decision batches and retained outcome-index checkpoints.
    ///
    /// A checkpoint stores the same terminal facts as a decision batch. Keeping
    /// this encoder here prevents a second `DecisionOutcome` byte layout from
    /// drifting into the chronicle layer.
    pub fn write_canonical(out: &mut Encoder, value: &Self) -> Result<(), CodecRefusal> {
        Self::write(out, value)
    }

    /// Reads one terminal decision written by [`Self::write_canonical`].
    pub fn read_canonical(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Self::read(input)
    }

    fn write(out: &mut Encoder, value: &Self) -> Result<(), CodecRefusal> {
        out.write_internal_object_id(value.tx_id.as_internal_object_id())?;
        out.write_scalar(value.decision_sequence.get());
        out.write_raw_byte(value.outcome.discriminant());
        match &value.outcome {
            DecisionOutcome::Committed {
                repository_commit_id,
            } => out.write_internal_object_id(repository_commit_id.as_internal_object_id()),
            DecisionOutcome::Refused {
                code,
                refusal_record_id,
            } => {
                out.write_scalar(code.code_point());
                out.write_internal_object_id(refusal_record_id.as_internal_object_id())
            }
        }
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let tx_id = read_derived!(input, TxId);
        let decision_sequence =
            DecisionSequence::try_new(input.read_scalar::<u64>("decision_sequence")?)?;
        let offset = input.offset();
        let discriminant = input.read_raw_byte("outcome")?;
        let outcome = match discriminant {
            1 => DecisionOutcome::Committed {
                repository_commit_id: read_derived!(input, RepositoryCommitId),
            },
            2 => {
                let code = RefusalCode::from_code_point(input.read_scalar::<u16>("refusal_code")?)?;
                DecisionOutcome::Refused {
                    code,
                    refusal_record_id: read_derived!(input, RefusalRecordId),
                }
            }
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "DecisionOutcome",
                    observed: u32::from(observed),
                    offset,
                });
            }
        };
        Ok(Self {
            tx_id,
            decision_sequence,
            outcome,
        })
    }
}

/// The immutable ordered publication body one authority-head replacement makes
/// canonical.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryDecisionBatchBody {
    /// Repository the batch belongs to.
    pub repository_id: RepositoryId,
    /// Head this batch was prepared against.
    pub predecessor_head_id: RepositoryAuthorityHeadId,
    /// Generation of that head, which makes the basis check monotone.
    pub predecessor_head_generation: HeadGeneration,
    /// Decision-sequence position of the first decision in the batch.
    pub first_decision_sequence: DecisionSequence,
    /// Terminal decisions, in deterministic batch order.
    pub decisions: Vec<RepositoryDecision>,
    /// Commit records for the committed decisions, in repository order.
    pub committed_rcrs: Vec<RepositoryCommitRecord>,
    /// Root over the resulting ref state.
    pub resulting_ref_root: Digest,
    /// Root over the resulting forge position.
    pub resulting_forge_position_root: Digest,
    /// Root over the rebuildable outcome index.
    pub resulting_outcome_index_root: Digest,
    /// Root over the resulting retention state.
    pub resulting_retention_root: Digest,
    /// Root over the resulting external-effect outbox.
    pub resulting_outbox_root: Digest,
    /// Policy epoch after the batch.
    pub resulting_policy_epoch: PolicyEpoch,
    /// Merkle commitment over this batch's ordered decision evidence.
    pub batch_evidence_root: Digest,
    /// Compaction generation bound by this publication, when it publishes one.
    ///
    /// Ordinary decision batches carry `None`. The explicit tag keeps an
    /// absent compaction linkage distinct from a digest that happens to have
    /// zero-like bytes, and prevents the generation identity from overloading
    /// [`Self::batch_evidence_root`].
    pub compaction_generation_link: Option<Digest>,
}

impl CanonicalBody for RepositoryDecisionBatchBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/decision-batch/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("decision-batch");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_internal_object_id(self.predecessor_head_id.as_internal_object_id())?;
        out.write_scalar(self.predecessor_head_generation.get());
        out.write_scalar(self.first_decision_sequence.get());
        // Decision order is semantic: each decision is evaluated against the
        // prior decisions in the same batch, so sorting them would change
        // meaning. Sequence gap-freedom is checked by the reference model,
        // not by the codec.
        out.write_sequence("decisions", &self.decisions, RepositoryDecision::write)?;
        out.write_sequence("committed_rcrs", &self.committed_rcrs, |out, record| {
            record.write_payload(out)
        })?;
        for digest in [
            &self.resulting_ref_root,
            &self.resulting_forge_position_root,
            &self.resulting_outcome_index_root,
            &self.resulting_retention_root,
            &self.resulting_outbox_root,
        ] {
            out.write_digest(digest)?;
        }
        out.write_scalar(self.resulting_policy_epoch.get());
        out.write_digest(&self.batch_evidence_root)?;
        out.write_option(self.compaction_generation_link.as_ref(), |out, link| {
            out.write_digest(link)
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let predecessor_head_id = read_derived!(input, RepositoryAuthorityHeadId);
        let predecessor_head_generation =
            HeadGeneration::try_new(input.read_scalar::<u64>("predecessor_head_generation")?)?;
        let first_decision_sequence =
            DecisionSequence::try_new(input.read_scalar::<u64>("first_decision_sequence")?)?;
        let decisions = input.read_sequence("decisions", RepositoryDecision::read)?;
        let committed_rcrs =
            input.read_sequence("committed_rcrs", RepositoryCommitRecord::read_payload)?;
        let resulting_ref_root = input.read_digest()?;
        let resulting_forge_position_root = input.read_digest()?;
        let resulting_outcome_index_root = input.read_digest()?;
        let resulting_retention_root = input.read_digest()?;
        let resulting_outbox_root = input.read_digest()?;
        let resulting_policy_epoch =
            PolicyEpoch::try_new(input.read_scalar::<u64>("resulting_policy_epoch")?)?;
        Ok(Self {
            repository_id,
            predecessor_head_id,
            predecessor_head_generation,
            first_decision_sequence,
            decisions,
            committed_rcrs,
            resulting_ref_root,
            resulting_forge_position_root,
            resulting_outcome_index_root,
            resulting_retention_root,
            resulting_outbox_root,
            resulting_policy_epoch,
            batch_evidence_root: input.read_digest()?,
            compaction_generation_link: input
                .read_option("compaction_generation_link", Decoder::read_digest)?,
        })
    }
}

/// The small authenticated root one linearizable conditional write selects.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepositoryAuthorityHeadBody {
    /// Repository this head governs.
    pub repository_id: RepositoryId,
    /// Monotone head generation.
    pub generation: HeadGeneration,
    /// Exact predecessor head, absent only for the genesis head.
    pub predecessor_head_id: Option<RepositoryAuthorityHeadId>,
    /// Most recent decision batch, absent before the first decision.
    pub decision_tail_id: Option<RepositoryDecisionBatchId>,
    /// Latest terminal-decision position, absent before the first decision.
    pub latest_decision_sequence: Option<DecisionSequence>,
    /// Latest committed record, absent before the first commit.
    pub latest_committed_rcr_id: Option<RepositoryCommitId>,
    /// Latest committed-transition position, absent before the first commit.
    pub latest_repository_sequence: Option<RepositorySequence>,
    /// Root over the current ref state.
    pub ref_root: Digest,
    /// Root over the current forge position.
    pub forge_position_root: Digest,
    /// Root over the rebuildable outcome index.
    pub outcome_index_root: Digest,
    /// Root over the current retention state.
    pub retention_root: Digest,
    /// Root over the current external-effect outbox.
    pub outbox_root: Digest,
    /// Root over the configuration needed to interpret this head.
    pub configuration_root: Digest,
    /// Current policy epoch.
    pub policy_epoch: PolicyEpoch,
    /// Current format and algorithm registry epoch.
    pub format_registry_epoch: RegistryEpoch,
    /// Most recent checkpoint capsule, when one exists.
    pub last_checkpoint_id: Option<RepositoryCapsuleId>,
}

impl CanonicalBody for RepositoryAuthorityHeadBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/authority-head/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("authority-head");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_scalar(self.generation.get());
        out.write_option(self.predecessor_head_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_option(self.decision_tail_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_option(self.latest_decision_sequence.as_ref(), |out, sequence| {
            out.write_scalar(sequence.get());
            Ok(())
        })?;
        out.write_option(self.latest_committed_rcr_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })?;
        out.write_option(self.latest_repository_sequence.as_ref(), |out, sequence| {
            out.write_scalar(sequence.get());
            Ok(())
        })?;
        for digest in [
            &self.ref_root,
            &self.forge_position_root,
            &self.outcome_index_root,
            &self.retention_root,
            &self.outbox_root,
            &self.configuration_root,
        ] {
            out.write_digest(digest)?;
        }
        out.write_scalar(self.policy_epoch.get());
        out.write_scalar(self.format_registry_epoch.get());
        out.write_option(self.last_checkpoint_id.as_ref(), |out, id| {
            out.write_internal_object_id(id.as_internal_object_id())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id = RepositoryId::from_bytes(input.read_opaque_id("repository_id")?);
        let generation = HeadGeneration::try_new(input.read_scalar::<u64>("generation")?)?;
        let predecessor_head_id = input.read_option("predecessor_head_id", |input| {
            Ok(read_derived!(input, RepositoryAuthorityHeadId))
        })?;
        let decision_tail_id = input.read_option("decision_tail_id", |input| {
            Ok(read_derived!(input, RepositoryDecisionBatchId))
        })?;
        let latest_decision_sequence = input.read_option("latest_decision_sequence", |input| {
            DecisionSequence::try_new(input.read_scalar::<u64>("latest_decision_sequence")?)
                .map_err(CodecRefusal::from)
        })?;
        let latest_committed_rcr_id = input.read_option("latest_committed_rcr_id", |input| {
            Ok(read_derived!(input, RepositoryCommitId))
        })?;
        let latest_repository_sequence =
            input.read_option("latest_repository_sequence", |input| {
                RepositorySequence::try_new(input.read_scalar::<u64>("latest_repository_sequence")?)
                    .map_err(CodecRefusal::from)
            })?;
        let ref_root = input.read_digest()?;
        let forge_position_root = input.read_digest()?;
        let outcome_index_root = input.read_digest()?;
        let retention_root = input.read_digest()?;
        let outbox_root = input.read_digest()?;
        let configuration_root = input.read_digest()?;
        let policy_epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("policy_epoch")?)?;
        let format_registry_epoch =
            RegistryEpoch::try_new(input.read_scalar::<u64>("format_registry_epoch")?)?;
        Ok(Self {
            repository_id,
            generation,
            predecessor_head_id,
            decision_tail_id,
            latest_decision_sequence,
            latest_committed_rcr_id,
            latest_repository_sequence,
            ref_root,
            forge_position_root,
            outcome_index_root,
            retention_root,
            outbox_root,
            configuration_root,
            policy_epoch,
            format_registry_epoch,
            last_checkpoint_id: input.read_option("last_checkpoint_id", |input| {
                Ok(read_derived!(input, RepositoryCapsuleId))
            })?,
        })
    }
}

/// The immutable record that explains one terminal refusal.
///
/// A refusal is repository history, so it has a body and an identity like any
/// other canonical decision. Without one, "why was this refused" would live
/// only in a log.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefusalRecordBody {
    /// Sealed transaction that was refused.
    pub tx_id: TxId,
    /// Seal the refusal is bound to.
    pub seal_id: TransactionSealId,
    /// Position in the terminal-decision order.
    pub decision_sequence: DecisionSequence,
    /// Terminal refusal reason.
    pub code: RefusalCode,
    /// Policy epoch the refusal was decided under.
    pub policy_epoch: PolicyEpoch,
    /// Human-readable detail, bounded by [`MAX_REFUSAL_DETAIL_LEN`].
    pub detail: String,
    /// Root over the evidence that supports the refusal.
    pub evidence_root: Digest,
}

impl CanonicalBody for RefusalRecordBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/refusal-record/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("refusal-record");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.detail.len() > MAX_REFUSAL_DETAIL_LEN {
            return Err(CodecRefusal::ValueUnrepresentable {
                field: "RefusalRecordBody.detail",
                observed: u64::try_from(self.detail.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_REFUSAL_DETAIL_LEN).unwrap_or(u64::MAX),
            });
        }
        out.write_internal_object_id(self.tx_id.as_internal_object_id())?;
        out.write_internal_object_id(self.seal_id.as_internal_object_id())?;
        out.write_scalar(self.decision_sequence.get());
        out.write_scalar(self.code.code_point());
        out.write_scalar(self.policy_epoch.get());
        out.write_text("RefusalRecordBody.detail", &self.detail)?;
        out.write_digest(&self.evidence_root)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let tx_id = read_derived!(input, TxId);
        let seal_id = read_derived!(input, TransactionSealId);
        let decision_sequence =
            DecisionSequence::try_new(input.read_scalar::<u64>("decision_sequence")?)?;
        let code = RefusalCode::from_code_point(input.read_scalar::<u16>("code")?)?;
        let policy_epoch = PolicyEpoch::try_new(input.read_scalar::<u64>("policy_epoch")?)?;
        let detail = input.read_text("RefusalRecordBody.detail")?;
        if detail.len() > MAX_REFUSAL_DETAIL_LEN {
            return Err(CodecRefusal::LengthBoundExceeded {
                field: "RefusalRecordBody.detail",
                observed: u64::try_from(detail.len()).unwrap_or(u64::MAX),
                limit: u64::try_from(MAX_REFUSAL_DETAIL_LEN).unwrap_or(u64::MAX),
            });
        }
        Ok(Self {
            tx_id,
            seal_id,
            decision_sequence,
            code,
            policy_epoch,
            detail: detail.to_owned(),
            evidence_root: input.read_digest()?,
        })
    }
}

/// The canonical repository configuration an authority head selects.
///
/// A head already carries `configuration_root`, a commitment to a configuration
/// body that no codec type defined until now. This is that body, and defining
/// it is what lets a repository state **how its authenticated roots are laid
/// out** without the head body growing a field.
///
/// # Why the carrier is `configuration_root` and not a new head field
///
/// `RepositoryAuthorityHeadBody`'s encoding is positional and strict, and
/// `write_option(None)` still emits a byte — so *any* added field shifts every
/// head's canonical bytes, changes every head identity, and makes existing
/// heads undecodable. That would contradict the very requirement the layout
/// version exists to serve: that heads published before it verify unchanged.
///
/// Selecting the version through `configuration_root` costs nothing already
/// published, and migration becomes an ordinary head transition that names a
/// different configuration body. Ruled by the orchestrator on `frankengit-ls44`.
///
/// # This is the canonical home for future repository configuration
///
/// Deliberately narrow: each field is a permanent repository fact with a
/// producer and a consumer. `root_layout` describes authenticated-root
/// interpretation; `object_format` selects the native Git identity domain.
/// `fgit-reference`'s `GenesisConfiguration` and `ConfigurationRequest` are
/// expected to migrate onto this body later, by their owners rather than here.
///
/// # Unknown versions fail closed
///
/// The layout version is decoded through
/// [`RootLayoutVersion::from_code_point`](fgit_types::layout::RootLayoutVersion::from_code_point),
/// which refuses a code point this build does not know rather than falling back
/// to a default. Reading a newer layout as the legacy one would produce a
/// confident wrong answer about what the repository contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepositoryConfigurationBody {
    /// How this repository's authenticated roots are laid out.
    pub root_layout: RootLayoutVersion,
    /// The permanent native Git object identity domain for this repository.
    ///
    /// This is deliberately stored beside the root layout rather than supplied
    /// by a node configuration at reopen time. Interpreting SHA-256 objects as
    /// SHA-1 after a restart is a repository-identity error, not a local
    /// deployment preference. An unrecognised code point is refused by
    /// [`GitHashAlgorithm::from_code_point`] rather than defaulting.
    pub object_format: GitHashAlgorithm,
}

impl Default for RepositoryConfigurationBody {
    fn default() -> Self {
        Self {
            root_layout: RootLayoutVersion::LegacyWholeBody,
            object_format: GitHashAlgorithm::Sha1,
        }
    }
}

impl CanonicalBody for RepositoryConfigurationBody {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/repository-configuration/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("repository-configuration");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.root_layout.code_point());
        out.write_scalar(self.object_format.code_point());
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let root_layout =
            RootLayoutVersion::from_code_point(input.read_scalar::<u16>("root_layout")?)?;
        let object_format =
            GitHashAlgorithm::from_code_point(input.read_scalar::<u16>("object_format")?)?;
        Ok(Self {
            root_layout,
            object_format,
        })
    }
}
