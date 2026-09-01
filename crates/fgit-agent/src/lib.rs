#![forbid(unsafe_code)]
//! Agent intent runs, attenuated capabilities, and the effect broker.
//!
//! This crate implements the slice of `docs/AGENT_PROTOCOL.md` that FG-030a
//! names: the capability model of §6 with attenuation-only delegation, the
//! Intent Run of §5 as the machine-enforced scope, and the effect broker of §9
//! that authorizes every consequential operation before it happens.
//!
//! # The one property everything here exists to hold
//!
//! Authority only ever narrows. A run cannot exceed its sponsor's grant, a
//! delegated capability cannot exceed its parent, and an effect cannot exceed
//! either the run or the capability presented for it. §6.2 states the rule for
//! delegation and §5.1 for the objective text; this crate makes both checkable
//! rather than aspirational.
//!
//! [`capability`] discharges that in two places, because it fails in two
//! places: widening is *unrepresentable* through the API, and *refused* by the
//! verifier when it arrives as bytes. Neither substitutes for the other, and
//! the module documents why.
//!
//! # Current boundary
//!
//! [`protocol`] now binds an Intent Run's base to the full authenticated §4.1
//! `AuthorityReadReceipt` and constructs bounded, single-generation §7 Context
//! Packets with structurally separate control and untrusted-source channels.
//! Revocation interpreted at a canonical position (§6.3) remains outside this
//! slice: [`Capability::is_valid_at`] checks a window, which is freshness, not
//! revocation.
//!
//! §4.3's refresh relations ARE here, in [`refresh`] — but only the typed
//! record of a refresh and the constraints on it, not the act. Rebasing,
//! replaying intents and merging are workspace operations owned by
//! `fgit-treefs`; a receipt binds identities, it does not compute them. The
//! module header says which half is which.
//!
//! §10 and §11 are **partly** here, and the boundary matters. [`ecc`] delivers
//! the evidence classes, the requirement dispositions of §10.2, the non-claims
//! of §10.3, the machine-classified verifier independence that normative
//! contract 25 requires be enforced rather than self-declared, and a canonical
//! codec encoding for the bundle checked against a golden corpus this crate did
//! not emit. It does **not**
//! deliver the rest of the §10 bundle — the proposed object/tree closure and
//! diff commitment (they need §8's `TreeFS` export), the effect record from
//! [`broker`] (it is not yet embedded in the ECC body), or context-packet
//! bodies in the ECC itself — nor most of §11: the deterministic verification services
//! of §11.1 and the human review view of §11.3 are absent. [`ecc`]'s own
//! header lists these individually. The separate [`protocol`] module does bind
//! real context packets, `TreeFS` snapshots, and a normal sealed-ref attempt; it
//! does not claim to synthesize those fields into an ECC.
//!
//! [`situation`] implements the first executable slice of the authority-bound
//! Agent Control Plane: one authenticated repository position, an exact optional
//! Intent Run and TreeFS workspace, a closed observed-or-explicitly-omitted
//! component set, and deterministic anti-rollback deltas. It performs no task
//! mutation, ranking, capability grant, or publication.
//!
//! [`frontier`] consumes one such receipt plus a bounded task projection. It
//! fails closed on an unavailable projection, separates hard eligibility from
//! advisory ordering, and preserves a typed exclusion reason for every row
//! that cannot be acted on by the receipt's active Intent Run. The
//! action-scoped builder preserves verifier independence only for verification
//! phases, so a future independent gate cannot prevent implementation or
//! rework by the run that owns the task.
//!
//! [`pulse`] derives the bounded Level-0 view intended for every agent turn.
//! It binds an exact situation/frontier pair, re-checks that the complete
//! Intent Run is still live, and preserves compact counts for every exclusion
//! class before exposing one advisory next action.
//!
//! [`plan`] turns that selected action into an inert execution contract. It
//! binds the acceptance root, authority-matched context, intended and conflict
//! surfaces, coherent checkpoints, evidence obligations, effect classes,
//! resource ceiling, stop conditions, rejected shortcuts, non-claims, and
//! approval state without claiming work or performing an effect.
//!
//! The obligation lifecycle is not reimplemented either. `fgit-resource` owns
//! it, and [`broker`] explains exactly which half of an effect's reservation
//! this crate holds and which half belongs to the component that performs it.

pub mod broker;
pub mod capability;
pub mod classes;
pub mod ecc;
pub mod frontier;
mod frontier_policy;
pub mod intent;
pub mod plan;
pub mod protocol;
pub mod pulse;
pub mod refresh;
pub mod situation;

pub use broker::{
    AgentInstanceId, BrokerRefusal, DeferredOutboxEffect, EffectBroker, EffectClass, EffectGrant,
    EffectId, EffectJournalEntry, EffectJournalEvent, EffectJournalRefusal, EffectJournalReplay,
    EffectRecord, EffectRequest, EffectTerminalOutcome, EscalatedOutboxEffect,
    ExternalEffectOutcome, OutboxCommitRefused, OutboxReservationRefused, ReconciliationEvidence,
    ReconciliationRefused, ReservedOutboxEffect,
};
pub use capability::{
    AttenuationRefused, AttenuationRequest, Capability, CapabilityId, ChainRefused, IssueRefused,
    LogicalTime, SealRefused, SealedCapability, verify_chain,
};
pub use classes::{CLASS_COUNT, ClassSet, OperationClass, UnknownClassBits};
pub use ecc::{
    EccPolicy, EccRefusal, EvidenceCarryingChange, EvidenceClass, EvidenceRecordRef,
    IndependenceClassification, IndependenceDimension, PartyFacts, RequirementDisposition,
    VerifierAttestation, classify_independence,
};
pub use frontier::{
    ExcludedWorkItem, FrontierExclusionReason, FrontierRefusal, MAX_WORK_ITEMS, TaskPhase,
    WorkAction, WorkCandidate, WorkConflict, WorkEligibilityInputs, WorkFrontier, WorkFrontierId,
    WorkItem, WorkRankingInputs, WorkRankingWitness, WorkTaskId,
};
pub use intent::{AuthorityBasisRef, IntentRun, RunId, RunRefused};
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
pub use refresh::{RefreshReceipt, RefreshRelation, RefreshSide};
pub use situation::{
    AgentSituationReceipt, SITUATION_COMPONENT_COUNT, SituationAuthorityChange,
    SituationComponent, SituationComponentChange, SituationComponentKind,
    SituationComponentTransition, SituationDelta, SituationId, SituationOmissionReason,
    SituationRefusal, SituationWorkspace,
};
