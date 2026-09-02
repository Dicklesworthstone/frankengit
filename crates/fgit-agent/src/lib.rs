#![forbid(unsafe_code)]
//! Agent intent runs, attenuated capabilities, task coordination, and effects.
//!
//! This crate implements the authority-bounded Agent Protocol and Agent Control
//! Plane slices owned by `fgit-agent`. Its central rule is that authority only
//! narrows: text, projections, plans, task assignments, evidence, and learning
//! records cannot widen an Intent Run or publish repository state.
//!
//! [`protocol`] binds every run and context packet to a complete authenticated
//! authority read. [`authority_identity`] identifies the exact read event and
//! [`run_identity`] commits the complete machine-enforced run. [`situation`],
//! [`frontier`], [`pulse`], and [`plan`] form the observe/orient/plan tower.
//!
//! Task coordination has two deliberately separate vocabularies. [`task_projection`]
//! remains the multi-row backend-neutral snapshot/mutation protocol used by the
//! earlier adapter surface. [`task_collection`] discovers its current generation
//! and complete rows before an Agent Situation exists, while
//! [`task_projection_read`] re-reads one generation already named by a situation.
//! [`task_collection_bridge`] converts collected unassigned rows into exact claim
//! bases, reconstructs claimed rows only from collection-bound durable lease
//! history, and binds restart activation to the original claim receipt.
//! The crate-private `task_projection_adapter` module is the pure single-task
//! semantic transition kernel for claim, release, and transfer; downstream
//! callers reach it only through [`task_coordination`], which attaches exact
//! repository and authenticated-read provenance plus monotone freshness.
//! [`task_persistence`] freezes complete exact-predecessor mutation envelopes and
//! reconciles authenticated backend rereads. [`task_store`] defines the one-call
//! read/CAS/flush/reread orchestration a concrete Beads or scheduler backend
//! must implement, preserving every post-effect uncertainty as reconciliation
//! debt. [`task_persistence_gate`] validates claim control before I/O and exposes
//! claim or cancellation projections only after the exact durable successor is
//! confirmed. [`task_recovery`] atomically binds restart recovery to the complete
//! run and carries that evidence through conservative persisted release. None of
//! those values is repository authority.
//!
//! [`claim`] and [`action_packet`] bind an admitted task claim to concrete,
//! bounded work without performing effects. [`claim_continuity`] permits only
//! time-only continuation. [`broker`] owns typed effect reservations and the
//! replayable journal. The crate-private `effect_authorization` module
//! authenticates bounded capability ancestry and exact-position revocation
//! reads; [`effect_dispatch`] exposes the production-facing broker, which
//! requires that proof both at high-value request acceptance and again at an
//! irreversible external dispatch. Abort and reconciliation remain available
//! after revocation because they reduce outstanding responsibility.
//! [`reconcile`], the crate-private handoff/cancellation engines and their public
//! facades preserve responsibility through handoff or conservative stop.
//! [`outcome_learning`] records validated retrieval-only learning and grants no
//! authority.
//!
//! Concrete Beads transport/codec mapping, action execution, ECC assembly,
//! canonical publication, concrete revocation transport and durable codecs,
//! later-head ancestry proof, durable control-object codecs, and robot/API
//! surfaces remain outside the current boundary.

pub mod action_packet;
pub mod authority_identity;
pub mod broker;
mod cancellation;
pub mod capability;
pub mod claim;
pub mod claim_continuity;
pub mod classes;
pub mod ecc;
mod effect_authorization;
pub mod effect_dispatch;
pub mod frontier;
mod frontier_policy;
mod handoff;
mod handoff_control;
pub mod handoff_acceptance;
pub mod intent;
mod learning;
pub mod outcome_learning;
pub mod plan;
pub mod protocol;
pub mod pulse;
pub mod reconcile;
pub mod refresh;
mod run_cancellation;
pub mod run_identity;
pub mod situation;
pub mod task_adapter;
pub mod task_collection;
pub mod task_collection_bridge;
pub mod task_coordination;
pub mod task_mutation;
pub mod task_persistence;
pub mod task_persistence_gate;
pub mod task_projection;
mod task_projection_adapter;
pub mod task_projection_read;
pub mod task_recovery;
pub mod task_store;

pub use action_packet::{
    ActionPacketRefusal, ActionPrecondition, ActionPreconditionSet, ActionStep, ActionStepId,
    AgentActionPacket, AgentActionPacketId, AgentActionPacketSpec, MAX_ACTION_CONTEXT_PACKETS,
    MAX_ACTION_PEER_CHANGES, MAX_ACTION_STEPS,
};
pub use authority_identity::{AuthorityReadIdentityRefusal, AuthorityReadReceiptId};
pub use broker::{
    AgentInstanceId, BrokerRefusal, DeferredOutboxEffect, EffectBroker, EffectClass, EffectGrant,
    EffectId, EffectJournalEntry, EffectJournalEvent, EffectJournalRefusal, EffectJournalReplay,
    EffectRecord, EffectRequest, EffectTerminalOutcome, EscalatedOutboxEffect,
    ExternalEffectOutcome, OutboxCommitRefused, OutboxReservationRefused, ReconciliationEvidence,
    ReconciliationRefused, ReservedOutboxEffect,
};
pub use cancellation::{
    CancellationContainmentEvidence, CancellationDebtTransfer,
    MAX_CANCELLATION_EVIDENCE_ENTRIES, RunCancellationRefusal, RunCancellationState,
    TaskClaimCancellationOutcome, TaskClaimCancellationProjection,
};
pub use capability::{
    AttenuationRefused, AttenuationRequest, Capability, CapabilityId, ChainRefused, IssueRefused,
    LogicalTime, SealRefused, SealedCapability, verify_chain,
};
pub use claim::{
    ActiveTaskClaim, ActiveTaskClaimId, MAX_CLAIM_SURFACES, TaskClaimProjection,
    TaskClaimReceipt, TaskClaimReceiptId, TaskClaimRefusal,
};
pub use claim_continuity::{
    ActionPacketContinuationRefusal, ActiveClaimContinuityReceipt,
    ActiveClaimContinuityReceiptId, ActiveClaimContinuityRefusal, AgentActionPacketContinuation,
    AgentActionPacketContinuationId,
};
pub use classes::{CLASS_COUNT, ClassSet, OperationClass, UnknownClassBits};
pub use ecc::{
    EccPolicy, EccRefusal, EvidenceCarryingChange, EvidenceClass, EvidenceRecordRef,
    IndependenceClassification, IndependenceDimension, PartyFacts, RequirementDisposition,
    VerifierAttestation, classify_independence,
};
pub use effect_authorization::{
    AuthorizedOutboxReservationRefused, CapabilityEffectAuthorization,
    CapabilityEffectAuthorizationId, CapabilityEffectAuthorizationRefusal,
    CapabilityRevocationReadAdapterRefusal, CapabilityRevocationReadObservation,
    CapabilityRevocationReadRefusal, CapabilityRevocationReadRequest,
    CapabilityRevocationReadRequestId, CapabilityRevocationReader,
    CapabilityRevocationReceipt, CapabilityRevocationReceiptId, MAX_CAPABILITY_REVOCATIONS,
    MAX_EFFECT_AUTHORIZATIONS, MAX_EFFECT_CAPABILITY_CHAIN, RevocationAuthorizedEffectGrant,
    RevocationCheckedEffectRefusal, VerifiedCapabilityChain, VerifiedCapabilityChainId,
    VerifiedCapabilityChainRefusal, read_capability_revocations,
    requires_effect_time_revocation,
};
pub use effect_dispatch::{
    AuthorizedOutboxDispatchRefused, RevocationAuthorizedDeferredOutboxEffect,
    RevocationAuthorizedOutboxEffect, RevocationCheckedEffectBroker,
};
pub use frontier::{
    ExcludedWorkItem, FrontierExclusionReason, FrontierRefusal, MAX_WORK_ITEMS, TaskPhase,
    WorkAction, WorkCandidate, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkFrontierId,
    WorkItem, WorkRankingInputs, WorkRankingWitness, WorkTaskId,
};
pub use handoff::{
    AgentHandoffCapsuleSpec, HandoffCapabilityAttenuation, HandoffRefusal,
    HandoffWorkspaceSnapshot, MAX_HANDOFF_ENTRIES, MAX_HANDOFF_EVIDENCE_RECORDS,
    MAX_HANDOFF_VERIFIER_ATTESTATIONS,
};
pub use handoff_acceptance::{
    AgentHandoffAcceptance, AgentHandoffAcceptanceId, HandoffAcceptanceRefusal,
    HandoffAuthorityRelation, HandoffEffectResponsibility, HandoffTargetResolution,
};
pub use handoff_control::{
    AgentHandoffCapsule, AgentHandoffCapsuleId, HandoffConstructionRefusal,
};
pub use intent::{AuthorityBasisRef, IntentRun, RunId, RunRefused};
pub use learning::{
    ConfirmedOwnership, FailedHypothesis, LearningPhase, LearningRequirementOutcome,
    LearningResourceObservation, LearningTerminalOutcome, MAX_LEARNING_ENTRIES,
    MAX_LEARNING_EVIDENCE, OutcomeLearningRecordId, OutcomeLearningRefusal, ReusablePattern,
};
pub use outcome_learning::{OutcomeLearningRecord, OutcomeLearningRecordSpec};
pub use plan::{
    AgentChangePlan, AgentChangePlanId, AgentChangePlanSpec, MAX_PLAN_CHECKPOINTS,
    MAX_PLAN_ENTRIES, PlanApproval, PlanCheckpoint, PlanCheckpointId, PlanCheckpointPurpose,
    PlanEvidenceRequirement, PlanRefusal, PlanRequirementId, PlanStopCondition,
    PlanStopConditionSet, PlanSurface, PlanSurfaceKind, RejectedShortcut, RejectedShortcutSet,
};
pub use protocol::{
    AgentRefTransaction, AuthorityReadReceipt, ContextControl, ContextPacket, ContextPacketId,
    ContextSource, MAX_CONTEXT_SOURCE_BYTES, MAX_CONTEXT_SOURCES, MAX_CONTEXT_TOTAL_BYTES,
    ProtocolRefusal, RetrievalChannel, WorkspaceBinding,
};
pub use pulse::{
    AgentControlPulse, AgentControlPulseId, PulseExclusionCounts, PulseRefusal, PulseSelection,
    PulseState,
};
pub use reconcile::{
    EffectResolutionAction, MAX_EFFECT_OUTPUT_COMMITMENTS,
    MAX_EFFECT_RECONCILIATION_TRANSITIONS, MAX_RECONCILIATION_EFFECTS, ReconciledEffect,
    RunReconciliationCounts, RunReconciliationReadiness, RunReconciliationRefusal,
    RunReconciliationReport, RunReconciliationReportId,
};
pub use refresh::{RefreshReceipt, RefreshRelation, RefreshSide};
pub use run_cancellation::{
    RunCancellationCompletion, RunCancellationCompletionId, RunCancellationCompletionRefusal,
    RunCancellationId, RunCancellationIntent, RunCancellationRequestRefusal,
};
pub use run_identity::{
    IntentRunBinding, IntentRunCommitment, IntentRunIdentityRefusal, IntentRunRetry,
};
pub use situation::{
    AgentSituationReceipt, SITUATION_COMPONENT_COUNT, SituationAuthorityChange,
    SituationComponent, SituationComponentChange, SituationComponentKind,
    SituationComponentTransition, SituationDelta, SituationId, SituationOmissionReason,
    SituationRefusal, SituationWorkspace,
};
pub use task_adapter::{
    ClaimIntegrationRefusal, ClaimTaskOutcome, ClaimedTask, ReleaseTaskOutcome, ReleasedTask,
    TaskCoordinatorRefusal, claim_selected_task, release_active_task, task_projection_generation,
};
pub use task_collection::{
    TaskProjectionCollectionAdapterRefusal, TaskProjectionCollectionExecutionRefusal,
    TaskProjectionCollectionObservation, TaskProjectionCollectionReceipt,
    TaskProjectionCollectionReceiptId, TaskProjectionCollectionRefusal,
    TaskProjectionCollectionRequest, TaskProjectionCollectionRequestId, TaskProjectionCollector,
    collect_task_projection,
};
pub use task_collection_bridge::{
    RecoveredActiveTaskClaim, RecoveredActiveTaskClaimId, TaskClaimRecoveryRefusal,
    TaskCollectionBridgeRefusal, TaskLeaseHistoryObservation,
    TaskLeaseReconstructionReceipt, TaskLeaseReconstructionReceiptId,
    activate_reconstructed_task_claim, collected_unclaimed_task,
    reconstruct_collected_task_lease,
};
pub use task_coordination::{
    AuthorityBoundTaskClaimApplication, AuthorityBoundTaskProjectionSnapshot,
    AuthorityBoundTaskProjectionSnapshotId, AuthorityBoundTaskProjectionTransition,
    AuthorityBoundTaskProjectionTransitionId, AuthorityBoundTaskResolutionApplication,
    TaskCoordinationRefusal,
};
pub use task_mutation::{
    TaskMutationAttempt, TaskMutationAttemptRefusal, apply_task_mutation,
};
pub use task_persistence::{
    TaskProjectionMutationEnvelope, TaskProjectionMutationEnvelopeId,
    TaskProjectionPersistedState, TaskProjectionPersistenceDecision,
    TaskProjectionPersistenceReceipt, TaskProjectionPersistenceReceiptId,
    TaskProjectionPersistenceRefusal,
};
pub use task_persistence_gate::{
    PersistedTaskClaim, PersistedTaskResolution, TaskClaimPersistenceOutcome,
    TaskPersistenceGateRefusal, TaskResolutionPersistenceOutcome, persist_task_claim,
    persist_task_resolution,
};
pub use task_projection::{
    MAX_TASK_PROJECTION_ROWS, MAX_TASK_ROW_SURFACES, TaskAdapterRefusal,
    TaskAdapterRejection, TaskMutationObservation, TaskMutationOperation, TaskMutationReceipt,
    TaskMutationReceiptId, TaskMutationRefusal, TaskMutationReplay, TaskMutationRequest,
    TaskMutationRequestId, TaskProjectionAdapter, TaskProjectionGeneration,
    TaskProjectionRefusal, TaskProjectionRow, TaskProjectionSnapshot, TaskProjectionSnapshotId,
};
pub use task_projection_adapter::{
    TaskProjectionAdapterRefusal, TaskProjectionAssignment, TaskProjectionLease,
    TaskProjectionTransitionKind, TaskReleaseDisposition,
};
pub use task_projection_read::{
    TaskProjectionReadAdapterRefusal, TaskProjectionReadExecutionRefusal,
    TaskProjectionReadObservation, TaskProjectionReadReceipt, TaskProjectionReadReceiptId,
    TaskProjectionReadRefusal, TaskProjectionReadRequest, TaskProjectionReadRequestId,
    TaskProjectionReader, read_task_projection,
};
pub use task_recovery::{
    PersistedRecoveredTaskRelease, PersistedRecoveredTaskReleaseId,
    RecoveredTaskReleasePersistenceOutcome, RunBoundRecoveredTaskClaim,
    RunBoundRecoveredTaskClaimId, TaskRecoveryBindingRefusal,
    TaskRecoveryPersistenceRefusal, persist_recovered_task_release,
    recover_task_claim_for_cleanup,
};
pub use task_store::{
    TaskProjectionStore, TaskProjectionStoreExecution, TaskProjectionStoreExecutionRefusal,
    TaskProjectionStoreFlushDisposition, TaskProjectionStoreFlushOutcome,
    TaskProjectionStoreFlushRefusal, TaskProjectionStoreKey, TaskProjectionStoreReadRefusal,
    TaskProjectionStoreReconciliationCause, TaskProjectionStoreStage,
    TaskProjectionStoreWriteDisposition, TaskProjectionStoreWriteOutcome,
    TaskProjectionStoreWriteRefusal, execute_task_projection_store,
};
