#![forbid(unsafe_code)]
//! Agent identity, capability, context, workspace, effect, evidence, and
//! observation protocols.
//!
//! This crate owns the machine protocol for one sponsored agent run:
//!
//! - an [`IntentRun`] with explicit authority basis, operation classes, and
//!   resource ceilings;
//! - an authenticated [`AuthorityReadReceipt`] and single-generation
//!   [`ContextPacket`] boundaries that keep control metadata separate from
//!   visibly untrusted source bytes;
//! - attenuated [`Capability`] values and brokered [`EffectGrant`]s with
//!   authority refresh;
//! - a two-phase [`EffectLedger`] (`reserve -> commit|abort`) with explicit
//!   external acknowledgement and cancellation drain;
//! - a [`WorkspaceBinding`] over the real `fgit-treefs`
//!   [`fgit_treefs::WorkspaceSnapshotBody`], whose proposal becomes the same
//!   canonical [`fgit_authority::SemanticRequest`] used by non-agent
//!   admission;
//! - an [`EvidenceCarryingChange`] schema that closes every declared
//!   requirement, binds independently produced attestations, records explicit
//!   non-claims, and can carry a same-head authority-refresh receipt;
//! - an [`AgentSituationReceipt`] over one authenticated head and an explicit
//!   observed-or-omitted control-plane component set, plus deterministic
//!   [`SituationDelta`] refreshes.
//!
//! The crate intentionally exposes no authority-head mutation API. TreeFS
//! proposals and agent-originated ref commands become inert
//! [`AgentRefTransaction`] values, then ordinary
//! [`fgit_authority::SealAttempt`]s. Actual sealing, admission, and head CAS
//! remain owned by the existing authority/admission path.

pub mod broker;
pub mod capability;
pub mod classes;
pub mod ecc;
pub mod intent;
pub mod protocol;
pub mod refresh;
pub mod situation;

pub use broker::{
    EffectAbortReason, EffectAction, EffectBroker, EffectGrant, EffectGrantRequest, EffectLedger,
    EffectOutcome, EffectReceipt, EffectRefusal, EffectRequest, EffectState, EvidenceRecordKind,
    ExternalAcknowledgement, ObligationId, ObligationState, ReservedEffect, ReservedEffectMetadata,
};
pub use capability::{
    Capability, CapabilityRefusal, CapabilityScope, Expiry, KeyBrokerCapability,
    KeyOperationClasses, LogicalTime, SecretBrokerCapability, SecretOperationClasses,
};
pub use classes::{
    ClassSet, EffectClass, EvidenceClass, ObjectClass, OperationClass, SecretClass,
};
pub use ecc::{
    AgentClaimedInvariant, AgentRequirement, AuthorityRefreshReceipt, ChangeRequirement,
    EvidenceCarryingChange, EvidenceCarryingChangeId, EvidenceCarryingChangeRefusal,
    RequirementDisposition, VerifierAttestation, VerifierIndependence,
};
pub use intent::{AuthorityBasisRef, IntentRun, IntentRunRefusal, RunId};
pub use protocol::{
    AgentRefTransaction, AuthorityReadReceipt, ContextControl, ContextPacket, ContextPacketId,
    ContextSource, ProtocolRefusal, RetrievalChannel, WorkspaceBinding,
};
pub use refresh::{
    AuthorityBasisPolicy, RefreshReceipt, RefreshRefusal, RefreshTransition, RefreshValidator,
};
pub use situation::{
    AgentSituationReceipt, SITUATION_COMPONENT_COUNT, SituationAuthorityChange,
    SituationComponent, SituationComponentChange, SituationComponentKind,
    SituationComponentTransition, SituationDelta, SituationId, SituationOmissionReason,
    SituationRefusal, SituationWorkspace,
};

/// Current implementation boundary.
///
/// This slice now covers:
///
/// - typed run opening and attenuation;
/// - complete authenticated authority-read receipts at agent ingress;
/// - control/source-separated, single-generation context packets;
/// - real TreeFS workspace binding and ordinary authority-request preparation;
/// - brokered effects with reserve/commit/abort/acknowledge/drain semantics;
/// - ECC finalization with exact requirement closure, explicit non-claims,
///   evidence records, verifier attestations, optional authority refresh, and
///   canonical identity;
/// - authority-bound situation receipts whose full v1 component set is either
///   observed at one head or explicitly omitted, plus anti-rollback,
///   same-generation-fork-refusing situation deltas.
///
/// It does **not** yet implement context retrieval/ranking, capability-token
/// signing, task-frontier ranking, change-plan persistence, handoff capsules,
/// a hostile runner, CI execution, or automatic publication. Those remain
/// separate final-abstraction slices; none is faked here.
pub const IMPLEMENTED_BOUNDARY: &str =
    "intent-run+authenticated-authority-receipt+context-packet+treefs-binding+effect-ledger+ecc+situation-receipt-and-delta";
