//! Authority-bound agent observation and incremental situation deltas.
//!
//! This is the first executable slice of
//! `docs/AGENT_CONTROL_PLANE_ARCHITECTURE.md`. It composes existing authority,
//! Intent Run, and TreeFS identities into a compact observation receipt. It
//! owns no repository truth and exposes no task mutation, capability grant,
//! workspace edit, ranking, or publication operation.
//!
//! The receipt is deliberately closed and bounded: every v1 component class is
//! represented exactly once as either an observation made against the same
//! authenticated head or an explicit typed omission. A refresh produces a
//! deterministic delta and refuses repository changes, time rollback,
//! authority-generation rollback, and two head identities at one generation.
//! The v2 receipt identity also commits the complete machine-enforced Intent
//! Run, so a reused numeric [`crate::RunId`] cannot substitute another scope,
//! budget, expiry, or authenticated read.
//!
//! Observing a higher generation does not itself prove predecessor continuity.
//! That stronger claim requires an authenticated authority-history witness and
//! remains outside this slice.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_treefs::WorkspaceId;
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::{
    AuthorityReadReceipt, IntentRun, IntentRunCommitment, IntentRunIdentityRefusal, LogicalTime,
    RunId, WorkspaceBinding,
};

/// Number of component classes in the v1 situation profile.
pub const SITUATION_COMPONENT_COUNT: usize = 10;
const SITUATION_COMPONENT_COUNT_WIRE: u32 = 10;
const SITUATION_DOMAIN: &[u8] = b"frankengit.agent.situation/v2\0";

/// Stable SHA-256 commitment to one complete situation receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SituationId([u8; 32]);

impl SituationId {
    /// Raw commitment bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SituationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("situation:")?;
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Closed set of derived control-plane components in the v1 profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SituationComponentKind {
    /// Beads/task dependency projection.
    TaskProjection,
    /// Claim/evidence registry generation.
    ClaimRegistry,
    /// Git and forge compatibility registry generation.
    CompatibilityRegistry,
    /// Source/file dependency graph generation.
    SourceGraph,
    /// Symbol and call graph generation.
    SymbolGraph,
    /// Ownership and review-history generation.
    Ownership,
    /// Search/retrieval generation.
    Search,
    /// Revision-bound test and verification evidence generation.
    TestEvidence,
    /// Policy-visible active peer-work set.
    ActivePeers,
    /// Outstanding effect-obligation summary.
    Obligations,
}

impl SituationComponentKind {
    /// Every v1 component in canonical order.
    pub const ALL: [Self; SITUATION_COMPONENT_COUNT] = [
        Self::TaskProjection,
        Self::ClaimRegistry,
        Self::CompatibilityRegistry,
        Self::SourceGraph,
        Self::SymbolGraph,
        Self::Ownership,
        Self::Search,
        Self::TestEvidence,
        Self::ActivePeers,
        Self::Obligations,
    ];

    const fn code_point(self) -> u8 {
        match self {
            Self::TaskProjection => 1,
            Self::ClaimRegistry => 2,
            Self::CompatibilityRegistry => 3,
            Self::SourceGraph => 4,
            Self::SymbolGraph => 5,
            Self::Ownership => 6,
            Self::Search => 7,
            Self::TestEvidence => 8,
            Self::ActivePeers => 9,
            Self::Obligations => 10,
        }
    }

    /// Stable machine label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::TaskProjection => "task_projection",
            Self::ClaimRegistry => "claim_registry",
            Self::CompatibilityRegistry => "compatibility_registry",
            Self::SourceGraph => "source_graph",
            Self::SymbolGraph => "symbol_graph",
            Self::Ownership => "ownership",
            Self::Search => "search",
            Self::TestEvidence => "test_evidence",
            Self::ActivePeers => "active_peers",
            Self::Obligations => "obligations",
        }
    }
}

impl fmt::Display for SituationComponentKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Why one component is explicitly absent from a situation receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SituationOmissionReason {
    /// The deployment profile does not configure the component.
    NotConfigured,
    /// The component is configured but no generation is available.
    NotAvailable,
    /// The active run may not observe the component.
    Unauthorized,
    /// The declared resource budget prevented observation.
    BudgetExceeded,
    /// The available generation is too stale for this observation.
    Stale,
    /// Projection or verification failed.
    ProjectionFailed,
}

impl SituationOmissionReason {
    const fn code_point(self) -> u8 {
        match self {
            Self::NotConfigured => 1,
            Self::NotAvailable => 2,
            Self::Unauthorized => 3,
            Self::BudgetExceeded => 4,
            Self::Stale => 5,
            Self::ProjectionFailed => 6,
        }
    }

    /// Stable machine label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::NotAvailable => "not_available",
            Self::Unauthorized => "unauthorized",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Stale => "stale",
            Self::ProjectionFailed => "projection_failed",
        }
    }
}

impl fmt::Display for SituationOmissionReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SituationComponentState {
    Observed {
        basis_head_id: RepositoryAuthorityHeadId,
        generation_commitment: [u8; 32],
    },
    Omitted {
        reason: SituationOmissionReason,
        detail_commitment: [u8; 32],
    },
}

/// One explicit observed-or-omitted situation component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SituationComponent {
    kind: SituationComponentKind,
    state: SituationComponentState,
}

impl SituationComponent {
    /// Records a generation sampled against an authenticated authority head.
    #[must_use]
    pub const fn observed(
        kind: SituationComponentKind,
        basis_head_id: RepositoryAuthorityHeadId,
        generation_commitment: [u8; 32],
    ) -> Self {
        Self {
            kind,
            state: SituationComponentState::Observed {
                basis_head_id,
                generation_commitment,
            },
        }
    }

    /// Records an explicit omission and a commitment to its detailed evidence.
    #[must_use]
    pub const fn omitted(
        kind: SituationComponentKind,
        reason: SituationOmissionReason,
        detail_commitment: [u8; 32],
    ) -> Self {
        Self {
            kind,
            state: SituationComponentState::Omitted {
                reason,
                detail_commitment,
            },
        }
    }

    /// Component class.
    #[must_use]
    pub const fn kind(&self) -> SituationComponentKind {
        self.kind
    }

    /// Authority head used by an observed component.
    #[must_use]
    pub const fn basis_head_id(&self) -> Option<RepositoryAuthorityHeadId> {
        match self.state {
            SituationComponentState::Observed { basis_head_id, .. } => Some(basis_head_id),
            SituationComponentState::Omitted { .. } => None,
        }
    }

    /// Immutable generation commitment when observed.
    #[must_use]
    pub const fn generation_commitment(&self) -> Option<[u8; 32]> {
        match self.state {
            SituationComponentState::Observed {
                generation_commitment,
                ..
            } => Some(generation_commitment),
            SituationComponentState::Omitted { .. } => None,
        }
    }

    /// Typed omission reason when absent.
    #[must_use]
    pub const fn omission_reason(&self) -> Option<SituationOmissionReason> {
        match self.state {
            SituationComponentState::Observed { .. } => None,
            SituationComponentState::Omitted { reason, .. } => Some(reason),
        }
    }

    /// Commitment to detailed omission evidence when absent.
    #[must_use]
    pub const fn omission_detail_commitment(&self) -> Option<[u8; 32]> {
        match self.state {
            SituationComponentState::Observed { .. } => None,
            SituationComponentState::Omitted {
                detail_commitment, ..
            } => Some(detail_commitment),
        }
    }

    /// Whether this component carries an observed generation.
    #[must_use]
    pub const fn is_observed(&self) -> bool {
        matches!(self.state, SituationComponentState::Observed { .. })
    }
}

/// Authority- and run-bound identity of an attached TreeFS workspace.
///
/// The only public constructor accepts an existing [`WorkspaceBinding`], so a
/// caller cannot independently pair a workspace ID with a chosen manifest,
/// run, or authority head. The summary commits the complete run as well as its
/// coordination ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SituationWorkspace {
    workspace_id: WorkspaceId,
    manifest_commitment: [u8; 32],
    basis_head_id: RepositoryAuthorityHeadId,
    run_id: RunId,
    run_commitment: IntentRunCommitment,
}

impl SituationWorkspace {
    /// Summarizes a real workspace binding without retaining its tree body.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal when the binding's complete Intent Run identity
    /// cannot be committed.
    pub fn from_binding<A: GitHashAlgorithm>(
        binding: &WorkspaceBinding<A>,
    ) -> Result<Self, SituationRefusal> {
        Ok(Self {
            workspace_id: binding.workspace_id(),
            manifest_commitment: binding.manifest_commitment(),
            basis_head_id: binding.authority_read_receipt().authority_head_id(),
            run_id: binding.run().run_id(),
            run_commitment: binding.run().commitment()?,
        })
    }

    /// TreeFS workspace identity.
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    /// Commitment to the immutable TreeFS manifest.
    #[must_use]
    pub const fn manifest_commitment(&self) -> [u8; 32] {
        self.manifest_commitment
    }

    /// Authenticated authority head used by the workspace.
    #[must_use]
    pub const fn basis_head_id(&self) -> RepositoryAuthorityHeadId {
        self.basis_head_id
    }

    /// Intent Run coordination identity that authorized the workspace.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Complete machine-enforced run identity that authorized the workspace.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }
}

/// One complete, authority-bound observation of agent operating state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSituationReceipt {
    situation_id: SituationId,
    authority_read_receipt: AuthorityReadReceipt,
    intent_run_id: Option<RunId>,
    intent_run_commitment: Option<IntentRunCommitment>,
    workspace: Option<SituationWorkspace>,
    observed_at: LogicalTime,
    components: [SituationComponent; SITUATION_COMPONENT_COUNT],
}

impl AgentSituationReceipt {
    /// Builds a complete v2 situation receipt.
    ///
    /// # Errors
    ///
    /// Refuses legacy or mismatched Intent Runs, workspace/run mismatches,
    /// mixed authority bases, duplicate or incomplete component classes,
    /// observation before authority authentication, and an unrepresentable
    /// commitment.
    pub fn build(
        authority_read_receipt: AuthorityReadReceipt,
        intent_run: Option<&IntentRun>,
        workspace: Option<SituationWorkspace>,
        observed_at: LogicalTime,
        mut components: [SituationComponent; SITUATION_COMPONENT_COUNT],
    ) -> Result<Self, SituationRefusal> {
        if observed_at < authority_read_receipt.verified_at_logical_time() {
            return Err(SituationRefusal::ObservationBeforeAuthorityVerification {
                observed: observed_at,
                verified: authority_read_receipt.verified_at_logical_time(),
            });
        }

        let (intent_run_id, intent_run_commitment) = match intent_run {
            Some(run) => {
                let run_receipt = run
                    .authority_read_receipt()
                    .ok_or(SituationRefusal::RunAuthorityReceiptRequired)?;
                if run_receipt != &authority_read_receipt {
                    return Err(SituationRefusal::RunAuthorityMismatch);
                }
                (Some(run.run_id()), Some(run.commitment()?))
            }
            None => (None, None),
        };

        if let Some(workspace) = workspace {
            let run_id = intent_run_id.ok_or(SituationRefusal::WorkspaceRequiresIntentRun)?;
            let run_commitment =
                intent_run_commitment.ok_or(SituationRefusal::WorkspaceRequiresIntentRun)?;
            if workspace.run_id != run_id {
                return Err(SituationRefusal::WorkspaceRunMismatch {
                    expected: run_id,
                    observed: workspace.run_id,
                });
            }
            if workspace.run_commitment != run_commitment {
                return Err(SituationRefusal::WorkspaceRunCommitmentMismatch {
                    expected: run_commitment,
                    observed: workspace.run_commitment,
                });
            }
            if workspace.basis_head_id != authority_read_receipt.authority_head_id() {
                return Err(SituationRefusal::WorkspaceAuthorityMismatch);
            }
        }

        components.sort_unstable_by_key(|component| component.kind.code_point());
        for adjacent in components.windows(2) {
            if adjacent[0].kind == adjacent[1].kind {
                return Err(SituationRefusal::DuplicateComponent {
                    kind: adjacent[0].kind,
                });
            }
        }
        for (expected, observed) in SituationComponentKind::ALL.iter().zip(&components) {
            if *expected != observed.kind {
                return Err(SituationRefusal::InvalidComponentSet {
                    expected: *expected,
                    observed: observed.kind,
                });
            }
        }

        for component in &components {
            if let Some(observed) = component.basis_head_id()
                && observed != authority_read_receipt.authority_head_id()
            {
                return Err(SituationRefusal::ComponentAuthorityMismatch {
                    kind: component.kind,
                });
            }
        }

        let situation_id = SituationId(situation_commitment(
            &authority_read_receipt,
            intent_run_id,
            intent_run_commitment,
            workspace.as_ref(),
            observed_at,
            &components,
        )?);

        Ok(Self {
            situation_id,
            authority_read_receipt,
            intent_run_id,
            intent_run_commitment,
            workspace,
            observed_at,
            components,
        })
    }

    /// Stable commitment to the complete receipt.
    #[must_use]
    pub const fn situation_id(&self) -> SituationId {
        self.situation_id
    }

    /// Exact authenticated repository position.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> &AuthorityReadReceipt {
        &self.authority_read_receipt
    }

    /// Intent Run coordination identity bound to the receipt, when active.
    #[must_use]
    pub const fn intent_run_id(&self) -> Option<RunId> {
        self.intent_run_id
    }

    /// Complete machine-enforced Intent Run identity, when active.
    #[must_use]
    pub const fn intent_run_commitment(&self) -> Option<IntentRunCommitment> {
        self.intent_run_commitment
    }

    /// Bound TreeFS workspace summary, when one exists.
    #[must_use]
    pub const fn workspace(&self) -> Option<SituationWorkspace> {
        self.workspace
    }

    /// Logical time at which component observations were assembled.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// Components in canonical [`SituationComponentKind::ALL`] order.
    #[must_use]
    pub const fn components(&self) -> &[SituationComponent; SITUATION_COMPONENT_COUNT] {
        &self.components
    }

    /// One component by class.
    #[must_use]
    pub fn component(&self, kind: SituationComponentKind) -> &SituationComponent {
        &self.components[usize::from(kind.code_point() - 1)]
    }

    /// Number of observed components.
    #[must_use]
    pub fn observed_component_count(&self) -> usize {
        self.components
            .iter()
            .filter(|component| component.is_observed())
            .count()
    }

    /// Number of explicitly omitted components.
    #[must_use]
    pub fn omitted_component_count(&self) -> usize {
        SITUATION_COMPONENT_COUNT - self.observed_component_count()
    }
}

/// How the authenticated authority position differs across a situation delta.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SituationAuthorityChange {
    /// Both receipts name the same authenticated head identity and generation.
    Unchanged,
    /// A strictly higher authenticated generation was observed.
    ///
    /// This does not by itself prove predecessor continuity.
    LaterGenerationObserved {
        /// Earlier generation.
        from: HeadGeneration,
        /// Later generation.
        to: HeadGeneration,
    },
}

/// Kind of change to one situation component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SituationComponentTransition {
    /// Immutable generation commitment changed.
    GenerationChanged,
    /// Same generation was sampled against a different authority head.
    ObservationRebased,
    /// A formerly omitted component became observable.
    BecameObserved,
    /// A formerly observed component became omitted.
    BecameOmitted,
    /// Omission reason or detailed evidence changed.
    OmissionChanged,
}

/// Deterministic change record for one component class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SituationComponentChange {
    kind: SituationComponentKind,
    transition: SituationComponentTransition,
}

impl SituationComponentChange {
    /// Component class that changed.
    #[must_use]
    pub const fn kind(&self) -> SituationComponentKind {
        self.kind
    }

    /// Typed state transition.
    #[must_use]
    pub const fn transition(&self) -> SituationComponentTransition {
        self.transition
    }
}

/// Minimal deterministic refresh from one situation receipt to another.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SituationDelta {
    from_situation_id: SituationId,
    to_situation_id: SituationId,
    authority_change: SituationAuthorityChange,
    changes: SituationDeltaChanges,
    component_changes: Vec<SituationComponentChange>,
}

/// Which non-component situation facts differ between two receipts.
///
/// A closed bit-set rather than four loose booleans, so the delta names one
/// change surface and a future fact extends it in one place.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SituationDeltaChanges(u8);

impl SituationDeltaChanges {
    const AUTHORITY_RECEIPT: u8 = 1 << 0;
    const INTENT_RUN: u8 = 1 << 1;
    const WORKSPACE: u8 = 1 << 2;
    const OBSERVATION_TIME: u8 = 1 << 3;

    fn between(from: &AgentSituationReceipt, to: &AgentSituationReceipt) -> Self {
        let mut bits = 0;
        if from.authority_read_receipt != to.authority_read_receipt {
            bits |= Self::AUTHORITY_RECEIPT;
        }
        if from.intent_run_id != to.intent_run_id
            || from.intent_run_commitment != to.intent_run_commitment
        {
            bits |= Self::INTENT_RUN;
        }
        if from.workspace != to.workspace {
            bits |= Self::WORKSPACE;
        }
        if from.observed_at != to.observed_at {
            bits |= Self::OBSERVATION_TIME;
        }
        Self(bits)
    }

    const fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
}

impl SituationDelta {
    /// Compares two receipts without claiming authority-chain continuity.
    ///
    /// # Errors
    ///
    /// Refuses cross-repository comparison, authority or logical-time rollback,
    /// same-generation forks, and a changed generation with an unchanged head
    /// identity.
    pub fn between(
        from: &AgentSituationReceipt,
        to: &AgentSituationReceipt,
    ) -> Result<Self, SituationRefusal> {
        if from.authority_read_receipt.repository_id() != to.authority_read_receipt.repository_id()
        {
            return Err(SituationRefusal::DeltaRepositoryMismatch {
                from: from.authority_read_receipt.repository_id(),
                to: to.authority_read_receipt.repository_id(),
            });
        }
        if to.observed_at < from.observed_at {
            return Err(SituationRefusal::ObservationTimeRollback {
                from: from.observed_at,
                to: to.observed_at,
            });
        }
        if to.authority_read_receipt.verified_at_logical_time()
            < from.authority_read_receipt.verified_at_logical_time()
        {
            return Err(SituationRefusal::AuthorityVerificationTimeRollback {
                from: from.authority_read_receipt.verified_at_logical_time(),
                to: to.authority_read_receipt.verified_at_logical_time(),
            });
        }

        let from_generation = from.authority_read_receipt.authority_head_generation();
        let to_generation = to.authority_read_receipt.authority_head_generation();
        let from_head_id = from.authority_read_receipt.authority_head_id();
        let to_head_id = to.authority_read_receipt.authority_head_id();

        let authority_change = match to_generation.cmp(&from_generation) {
            core::cmp::Ordering::Less => {
                return Err(SituationRefusal::AuthorityGenerationRollback {
                    from: from_generation,
                    to: to_generation,
                });
            }
            core::cmp::Ordering::Equal => {
                if to_head_id != from_head_id {
                    return Err(SituationRefusal::AuthorityForkAtSameGeneration {
                        generation: from_generation,
                    });
                }
                SituationAuthorityChange::Unchanged
            }
            core::cmp::Ordering::Greater => {
                if to_head_id == from_head_id {
                    return Err(
                        SituationRefusal::AuthorityGenerationChangedWithoutIdentity {
                            from: from_generation,
                            to: to_generation,
                        },
                    );
                }
                SituationAuthorityChange::LaterGenerationObserved {
                    from: from_generation,
                    to: to_generation,
                }
            }
        };

        let mut component_changes = Vec::with_capacity(SITUATION_COMPONENT_COUNT);
        for (before, after) in from.components.iter().zip(&to.components) {
            if before != after {
                component_changes.push(SituationComponentChange {
                    kind: before.kind,
                    transition: classify_component_transition(before, after),
                });
            }
        }

        Ok(Self {
            from_situation_id: from.situation_id,
            to_situation_id: to.situation_id,
            authority_change,
            changes: SituationDeltaChanges::between(from, to),
            component_changes,
        })
    }

    /// Earlier receipt identity.
    #[must_use]
    pub const fn from_situation_id(&self) -> SituationId {
        self.from_situation_id
    }

    /// Later receipt identity.
    #[must_use]
    pub const fn to_situation_id(&self) -> SituationId {
        self.to_situation_id
    }

    /// Authenticated authority-position change.
    #[must_use]
    pub const fn authority_change(&self) -> SituationAuthorityChange {
        self.authority_change
    }

    /// Whether any authority receipt field changed.
    #[must_use]
    pub const fn authority_receipt_changed(&self) -> bool {
        self.changes
            .contains(SituationDeltaChanges::AUTHORITY_RECEIPT)
    }

    /// Whether the bound Intent Run identity or complete commitment changed.
    #[must_use]
    pub const fn intent_run_changed(&self) -> bool {
        self.changes.contains(SituationDeltaChanges::INTENT_RUN)
    }

    /// Whether the bound workspace identity, manifest, or run changed.
    #[must_use]
    pub const fn workspace_changed(&self) -> bool {
        self.changes.contains(SituationDeltaChanges::WORKSPACE)
    }

    /// Whether the overall observation time advanced.
    #[must_use]
    pub const fn observation_time_advanced(&self) -> bool {
        self.changes
            .contains(SituationDeltaChanges::OBSERVATION_TIME)
    }

    /// Component changes in canonical component order.
    #[must_use]
    pub fn component_changes(&self) -> &[SituationComponentChange] {
        &self.component_changes
    }

    /// True when only the observation instant changed.
    #[must_use]
    pub const fn has_no_context_changes(&self) -> bool {
        matches!(self.authority_change, SituationAuthorityChange::Unchanged)
            && !self.authority_receipt_changed()
            && !self.intent_run_changed()
            && !self.workspace_changed()
            && self.component_changes.is_empty()
    }
}

/// Why an authority-bound situation or delta was refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SituationRefusal {
    /// Observation predates authentication of its authority receipt.
    ObservationBeforeAuthorityVerification {
        /// Proposed observation time.
        observed: LogicalTime,
        /// Receipt verification time.
        verified: LogicalTime,
    },
    /// The run used a legacy basis reference rather than a complete receipt.
    RunAuthorityReceiptRequired,
    /// Run and situation carry different authenticated receipts.
    RunAuthorityMismatch,
    /// Complete run identity could not be produced.
    RunIdentity(IntentRunIdentityRefusal),
    /// A workspace was supplied without its active run.
    WorkspaceRequiresIntentRun,
    /// Workspace and situation name different runs.
    WorkspaceRunMismatch {
        /// Run bound to the situation.
        expected: RunId,
        /// Run bound to the workspace.
        observed: RunId,
    },
    /// Workspace and situation carry different complete run commitments.
    WorkspaceRunCommitmentMismatch {
        /// Situation run commitment.
        expected: IntentRunCommitment,
        /// Workspace run commitment.
        observed: IntentRunCommitment,
    },
    /// Workspace and situation name different authority heads.
    WorkspaceAuthorityMismatch,
    /// One component class appeared more than once.
    DuplicateComponent {
        /// Repeated class.
        kind: SituationComponentKind,
    },
    /// The fixed-size set did not contain the canonical v1 component at one position.
    InvalidComponentSet {
        /// Required class at the canonical position.
        expected: SituationComponentKind,
        /// Class found at that position.
        observed: SituationComponentKind,
    },
    /// An observed component was sampled against another authority head.
    ComponentAuthorityMismatch {
        /// Mismatched component.
        kind: SituationComponentKind,
    },
    /// Delta endpoints belong to different repositories.
    DeltaRepositoryMismatch {
        /// Earlier repository.
        from: RepositoryId,
        /// Later repository.
        to: RepositoryId,
    },
    /// Overall observation time moved backwards.
    ObservationTimeRollback {
        /// Earlier logical time.
        from: LogicalTime,
        /// Proposed later logical time.
        to: LogicalTime,
    },
    /// Authority authentication time moved backwards.
    AuthorityVerificationTimeRollback {
        /// Earlier verification time.
        from: LogicalTime,
        /// Proposed later verification time.
        to: LogicalTime,
    },
    /// Authenticated head generation moved backwards.
    AuthorityGenerationRollback {
        /// Earlier generation.
        from: HeadGeneration,
        /// Proposed later generation.
        to: HeadGeneration,
    },
    /// Two head identities claim the same repository generation.
    AuthorityForkAtSameGeneration {
        /// Conflicting generation.
        generation: HeadGeneration,
    },
    /// Generation changed but content identity did not.
    AuthorityGenerationChangedWithoutIdentity {
        /// Earlier generation.
        from: HeadGeneration,
        /// Proposed later generation.
        to: HeadGeneration,
    },
    /// Canonical commitment framing failed.
    Codec(CodecRefusal),
}

impl fmt::Display for SituationRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObservationBeforeAuthorityVerification { observed, verified } => write!(
                formatter,
                "situation observed at {observed} before authority verification at {verified}"
            ),
            Self::RunAuthorityReceiptRequired => formatter.write_str(
                "agent situation requires an Intent Run with a complete authenticated authority receipt",
            ),
            Self::RunAuthorityMismatch => formatter.write_str(
                "Intent Run authority receipt differs from the situation receipt",
            ),
            Self::RunIdentity(refusal) => {
                write!(formatter, "Intent Run identity refused: {refusal}")
            }
            Self::WorkspaceRequiresIntentRun => formatter.write_str(
                "a workspace situation requires the Intent Run that authorized it",
            ),
            Self::WorkspaceRunMismatch { expected, observed } => write!(
                formatter,
                "workspace run {observed} differs from situation run {expected}"
            ),
            Self::WorkspaceRunCommitmentMismatch { expected, observed } => write!(
                formatter,
                "workspace run commitment {observed} differs from situation run {expected}"
            ),
            Self::WorkspaceAuthorityMismatch => formatter.write_str(
                "workspace authority head differs from the situation receipt",
            ),
            Self::DuplicateComponent { kind } => {
                write!(formatter, "situation repeats component {kind}")
            }
            Self::InvalidComponentSet { expected, observed } => write!(
                formatter,
                "situation expected component {expected} but observed {observed}"
            ),
            Self::ComponentAuthorityMismatch { kind } => write!(
                formatter,
                "situation component {kind} was sampled against another authority head"
            ),
            Self::DeltaRepositoryMismatch { from, to } => write!(
                formatter,
                "cannot compare situations from repositories {from} and {to}"
            ),
            Self::ObservationTimeRollback { from, to } => write!(
                formatter,
                "situation observation time would move backwards from {from} to {to}"
            ),
            Self::AuthorityVerificationTimeRollback { from, to } => write!(
                formatter,
                "authority verification time would move backwards from {from} to {to}"
            ),
            Self::AuthorityGenerationRollback { from, to } => write!(
                formatter,
                "authority generation would move backwards from {from} to {to}"
            ),
            Self::AuthorityForkAtSameGeneration { generation } => write!(
                formatter,
                "different authority heads claim generation {generation}"
            ),
            Self::AuthorityGenerationChangedWithoutIdentity { from, to } => write!(
                formatter,
                "authority generation changed from {from} to {to} without a new head identity"
            ),
            Self::Codec(refusal) => {
                write!(formatter, "agent situation commitment refused: {refusal}")
            }
        }
    }
}

impl core::error::Error for SituationRefusal {}

impl From<IntentRunIdentityRefusal> for SituationRefusal {
    fn from(value: IntentRunIdentityRefusal) -> Self {
        Self::RunIdentity(value)
    }
}

impl From<CodecRefusal> for SituationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

fn classify_component_transition(
    before: &SituationComponent,
    after: &SituationComponent,
) -> SituationComponentTransition {
    match (before.state, after.state) {
        (
            SituationComponentState::Observed {
                basis_head_id: before_basis,
                generation_commitment: before_generation,
            },
            SituationComponentState::Observed {
                basis_head_id: after_basis,
                generation_commitment: after_generation,
            },
        ) => {
            if before_generation == after_generation && before_basis != after_basis {
                SituationComponentTransition::ObservationRebased
            } else {
                SituationComponentTransition::GenerationChanged
            }
        }
        (SituationComponentState::Observed { .. }, SituationComponentState::Omitted { .. }) => {
            SituationComponentTransition::BecameOmitted
        }
        (SituationComponentState::Omitted { .. }, SituationComponentState::Observed { .. }) => {
            SituationComponentTransition::BecameObserved
        }
        (SituationComponentState::Omitted { .. }, SituationComponentState::Omitted { .. }) => {
            SituationComponentTransition::OmissionChanged
        }
    }
}

fn situation_commitment(
    receipt: &AuthorityReadReceipt,
    intent_run_id: Option<RunId>,
    intent_run_commitment: Option<IntentRunCommitment>,
    workspace: Option<&SituationWorkspace>,
    observed_at: LogicalTime,
    components: &[SituationComponent; SITUATION_COMPONENT_COUNT],
) -> Result<[u8; 32], SituationRefusal> {
    let mut encoder = Encoder::with_capacity(832);
    encoder.write_bytes("agent_situation_domain", SITUATION_DOMAIN)?;
    write_authority_receipt(&mut encoder, receipt)?;

    match (intent_run_id, intent_run_commitment) {
        (Some(run_id), Some(run_commitment)) => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
            encoder.write_raw(run_commitment.as_bytes());
        }
        (None, None) => encoder.write_bool(false),
        _ => unreachable!("situation builder preserves the run identity pair"),
    }

    match workspace {
        Some(workspace) => {
            encoder.write_bool(true);
            encoder.write_opaque_id(workspace.workspace_id.as_bytes());
            encoder.write_raw(&workspace.manifest_commitment);
            encoder.write_internal_object_id(workspace.basis_head_id.as_internal_object_id())?;
            encoder.write_raw(&workspace.run_id.value().to_be_bytes());
            encoder.write_raw(workspace.run_commitment.as_bytes());
        }
        None => encoder.write_bool(false),
    }

    encoder.write_scalar(observed_at.value());
    encoder.write_scalar(SITUATION_COMPONENT_COUNT_WIRE);
    for component in components {
        encoder.write_raw_byte(component.kind.code_point());
        match component.state {
            SituationComponentState::Observed {
                basis_head_id,
                generation_commitment,
            } => {
                encoder.write_raw_byte(1);
                encoder.write_internal_object_id(basis_head_id.as_internal_object_id())?;
                encoder.write_raw(&generation_commitment);
            }
            SituationComponentState::Omitted {
                reason,
                detail_commitment,
            } => {
                encoder.write_raw_byte(2);
                encoder.write_raw_byte(reason.code_point());
                encoder.write_raw(&detail_commitment);
            }
        }
    }

    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&encoder.into_bytes());
    Ok(hasher.finish())
}

fn write_authority_receipt(
    encoder: &mut Encoder,
    receipt: &AuthorityReadReceipt,
) -> Result<(), CodecRefusal> {
    encoder.write_opaque_id(receipt.repository_id().as_bytes());
    encoder.write_internal_object_id(receipt.authority_head_id().as_internal_object_id())?;
    encoder.write_scalar(receipt.authority_head_generation().get());
    encoder.write_raw(&receipt.backend_version_token().to_opaque_bytes());

    let latest_decision_batch_id = receipt.latest_decision_batch_id();
    write_optional_identity(
        encoder,
        latest_decision_batch_id
            .as_ref()
            .map(fgit_types::RepositoryDecisionBatchId::as_internal_object_id),
    )?;
    write_optional_scalar(
        encoder,
        receipt
            .latest_repository_sequence()
            .map(fgit_types::RepositorySequence::get),
    );
    let latest_repository_commit_id = receipt.latest_repository_commit_id();
    write_optional_identity(
        encoder,
        latest_repository_commit_id
            .as_ref()
            .map(fgit_types::RepositoryCommitId::as_internal_object_id),
    )?;

    encoder.write_digest(&receipt.ref_root())?;
    encoder.write_digest(&receipt.forge_position_root())?;
    encoder.write_digest(&receipt.retention_root())?;
    encoder.write_scalar(receipt.policy_epoch().get());
    encoder.write_scalar(receipt.format_epoch().get());
    encoder.write_scalar(receipt.verified_at_logical_time().value());
    encoder.write_raw(&receipt.verifier_profile());
    Ok(())
}

fn write_optional_identity(
    encoder: &mut Encoder,
    value: Option<&fgit_types::InternalObjectId>,
) -> Result<(), CodecRefusal> {
    match value {
        Some(identity) => {
            encoder.write_bool(true);
            encoder.write_internal_object_id(identity)?;
        }
        None => encoder.write_bool(false),
    }
    Ok(())
}

fn write_optional_scalar(encoder: &mut Encoder, value: Option<u64>) {
    match value {
        Some(value) => {
            encoder.write_bool(true);
            encoder.write_scalar(value);
        }
        None => encoder.write_bool(false),
    }
}
