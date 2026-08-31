//! Authority-bound observation and incremental situation deltas.
//!
//! `docs/AGENT_CONTROL_PLANE_ARCHITECTURE.md` defines the agent control
//! plane's first executable slice: a compact receipt over one authenticated
//! repository position plus explicit observations or omissions for every
//! derived control-plane component.
//!
//! This module owns no repository truth and performs no task mutation,
//! ranking, capability grant, workspace edit, or publication. It makes the
//! inputs to those future operations exact:
//!
//! * the authority position comes only from [`AuthorityReadReceipt`];
//! * an attached run must carry that exact receipt;
//! * an attached workspace comes only from a real [`WorkspaceBinding`];
//! * every supported component is present exactly once as either observed or
//!   deliberately omitted;
//! * an observed component names the authority head against which it was
//!   sampled, so mixed-generation views fail closed;
//! * the receipt and its delta have deterministic ordering and identities.
//!
//! A higher authority generation in [`SituationDelta`] means only that a later
//! authenticated generation was observed. Proving predecessor continuity is a
//! separate authority-history operation and is not claimed here.

use core::fmt;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, NativeObjectIdentity, Sha256};
use fgit_treefs::WorkspaceId;
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

use crate::capability::LogicalTime;
use crate::intent::{IntentRun, RunId};
use crate::protocol::{AuthorityReadReceipt, WorkspaceBinding};

/// Number of component classes in the v1 situation profile.
///
/// A receipt contains exactly one entry for each class. Missing data is an
/// explicit omission, never an absent vector element whose meaning a client
/// must guess.
pub const SITUATION_COMPONENT_COUNT: usize = 10;

const SITUATION_DOMAIN: &[u8] = b"frankengit.agent.situation/v1\0";

/// Stable SHA-256 commitment to one complete agent situation receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
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

/// Closed set of derived control-plane components observed by the v1 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
    /// Ownership/review-history generation.
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SituationOmissionReason {
    /// The deployment profile does not configure this component.
    NotConfigured,
    /// The component is configured but no generation is currently available.
    NotAvailable,
    /// The active run may not observe this component.
    Unauthorized,
    /// A declared resource budget prevented the observation.
    BudgetExceeded,
    /// The available generation is too stale for the requested observation.
    Stale,
    /// The projection or verification operation failed.
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
    /// Records one generation sampled against `basis_head_id`.
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

    /// Authority head against which an observed generation was sampled.
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

    /// Typed reason when omitted.
    #[must_use]
    pub const fn omission_reason(&self) -> Option<SituationOmissionReason> {
        match self.state {
            SituationComponentState::Observed { .. } => None,
            SituationComponentState::Omitted { reason, .. } => Some(reason),
        }
    }

    /// Commitment to detailed omission evidence when omitted.
    #[must_use]
    pub const fn omission_detail_commitment(&self) -> Option<[u8; 32]> {
        match self.state {
            SituationComponentState::Observed { .. } => None,
            SituationComponentState::Omitted {
                detail_commitment,
                ..
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
/// The public constructor accepts only an existing [`WorkspaceBinding`], so a
/// caller cannot pair a workspace identifier with a chosen manifest, run, or
/// authority head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SituationWorkspace {
    workspace_id: WorkspaceId,
    manifest_commitment: [u8; 32],
    basis_head_id: RepositoryAuthorityHeadId,
    run_id: RunId,
}

impl SituationWorkspace {
    /// Summarizes a real workspace binding without retaining its tree body.
    #[must_use]
    pub fn from_binding<A: GitHashAlgorithm>(binding: &WorkspaceBinding<A>) -> Self {
        Self {
            workspace_id: binding.workspace_id(),
            manifest_commitment: binding.manifest_commitment(),
            basis_head_id: binding.authority_read_receipt().authority_head_id(),
            run_id: binding.run().run_id(),
        }
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

    /// Intent Run that authorized the workspace.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
}

/// One complete, authority-bound observation of the agent operating state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentSituationReceipt {
    situation_id: SituationId,
    authority_read_receipt: AuthorityReadReceipt,
    intent_run_id: Option<RunId>,
    workspace: Option<SituationWorkspace>,
    observed_at: LogicalTime,
    components: Vec<SituationComponent>,
}

impl AgentSituationReceipt {
    /// Builds a complete v1 situation receipt.
    ///
    /// # Errors
    ///
    /// Refuses legacy or mismatched Intent Runs, workspace/run mismatches,
    /// mixed authority bases, duplicate or missing component classes, an
    /// observation time before authority authentication, and an unrepresentable
    /// canonical commitment.
    pub fn build(
        authority_read_receipt: AuthorityReadReceipt,
        intent_run: Option<&IntentRun>,
        workspace: Option<SituationWorkspace>,
        observed_at: LogicalTime,
        mut components: Vec<SituationComponent>,
    ) -> Result<Self, SituationRefusal> {
        if observed_at < authority_read_receipt.verified_at_logical_time() {
            return Err(SituationRefusal::ObservationBeforeAuthorityVerification {
                observed: observed_at,
                verified: authority_read_receipt.verified_at_logical_time(),
            });
        }

        let intent_run_id = match intent_run {
            Some(run) => {
                let run_receipt = run
                    .authority_read_receipt()
                    .ok_or(SituationRefusal::RunAuthorityReceiptRequired)?;
                if run_receipt != &authority_read_receipt {
                    return Err(SituationRefusal::RunAuthorityMismatch);
                }
                Some(run.run_id())
            }
            None => None,
        };

        if let Some(workspace) = workspace {
            let run_id = intent_run_id.ok_or(SituationRefusal::WorkspaceRequiresIntentRun)?;
            if workspace.run_id != run_id {
                return Err(SituationRefusal::WorkspaceRunMismatch {
                    expected: run_id,
                    observed: workspace.run_id,
                });
            }
            if workspace.basis_head_id != authority_read_receipt.authority_head_id() {
                return Err(SituationRefusal::WorkspaceAuthorityMismatch);
            }
        }

        if components.len() > SITUATION_COMPONENT_COUNT {
            return Err(SituationRefusal::TooManyComponents {
                observed: components.len(),
                limit: SITUATION_COMPONENT_COUNT,
            });
        }

        components.sort_unstable_by_key(|component| component.kind.code_point());
        for adjacent in components.windows(2) {
            if adjacent[0].kind == adjacent[1].kind {
                return Err(SituationRefusal::DuplicateComponent {
                    kind: adjacent[0].kind,
                });
            }
        }

        for expected in SituationComponentKind::ALL {
            if components
                .binary_search_by_key(&expected.code_point(), |component| {
                    component.kind.code_point()
                })
                .is_err()
            {
                return Err(SituationRefusal::MissingComponent { kind: expected });
            }
        }

        for component in &components {
            if let Some(observed) = component.basis_head_id() {
                if observed != authority_read_receipt.authority_head_id() {
                    return Err(SituationRefusal::ComponentAuthorityMismatch {
                        kind: component.kind,
                    });
                }
            }
        }

        let situation_id = SituationId(situation_commitment(
            &authority_read_receipt,
            intent_run_id,
            workspace,
            observed_at,
            &components,
        )?);

        Ok(Self {
            situation_id,
            authority_read_receipt,
            intent_run_id,
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

    /// Intent Run bound to the receipt, when an active run exists.
    #[must_use]
    pub const fn intent_run_id(&self) -> Option<RunId> {
        self.intent_run_id
    }

    /// Bound TreeFS workspace summary, when one exists.
    #[must_use]
    pub const fn workspace(&self) -> Option<SituationWorkspace> {
        self.workspace
    }

    /// Logical time at which all component observations were assembled.
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }

    /// All components in canonical [`SituationComponentKind::ALL`] order.
    #[must_use]
    pub fn components(&self) -> &[SituationComponent] {
        &self.components
    }

    /// One component by class.
    #[must_use]
    pub fn component(
        &self,
        kind: SituationComponentKind,
    ) -> Option<&SituationComponent> {
        self.components
            .binary_search_by_key(&kind.code_point(), |component| {
                component.kind.code_point()
            })
            .ok()
            .map(|index| &self.components[index])
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
    /// The immutable generation commitment changed.
    GenerationChanged,
    /// The same generation commitment was sampled against a different head.
    ObservationRebased,
    /// A formerly omitted component became observable.
    BecameObserved,
    /// A formerly observed component became omitted.
    BecameOmitted,
    /// The omission reason or its detailed evidence changed.
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
    authority_receipt_changed: bool,
    intent_run_changed: bool,
    workspace_changed: bool,
    observation_time_advanced: bool,
    component_changes: Vec<SituationComponentChange>,
}

impl SituationDelta {
    /// Compares two receipts without claiming authority-chain continuity.
    ///
    /// # Errors
    ///
    /// Refuses cross-repository comparisons, authority-generation rollback,
    /// same-generation forks, a changed generation with an unchanged head
    /// identity, authority-verification-time rollback, and observation-time
    /// rollback.
    pub fn between(
        from: &AgentSituationReceipt,
        to: &AgentSituationReceipt,
    ) -> Result<Self, SituationRefusal> {
        if from.authority_read_receipt.repository_id()
            != to.authority_read_receipt.repository_id()
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

        let authority_change = if to_generation < from_generation {
            return Err(SituationRefusal::AuthorityGenerationRollback {
                from: from_generation,
                to: to_generation,
            });
        } else if to_generation == from_generation {
            if to_head_id != from_head_id {
                return Err(SituationRefusal::AuthorityForkAtSameGeneration {
                    generation: from_generation,
                });
            }
            SituationAuthorityChange::Unchanged
        } else {
            if to_head_id == from_head_id {
                return Err(SituationRefusal::AuthorityGenerationChangedWithoutIdentity {
                    from: from_generation,
                    to: to_generation,
                });
            }
            SituationAuthorityChange::LaterGenerationObserved {
                from: from_generation,
                to: to_generation,
            }
        };

        let mut component_changes = Vec::with_capacity(SITUATION_COMPONENT_COUNT);
        for (before, after) in from.components.iter().zip(&to.components) {
            debug_assert_eq!(before.kind, after.kind);
            if before == after {
                continue;
            }
            component_changes.push(SituationComponentChange {
                kind: before.kind,
                transition: classify_component_transition(before, after),
            });
        }

        Ok(Self {
            from_situation_id: from.situation_id,
            to_situation_id: to.situation_id,
            authority_change,
            authority_receipt_changed: from.authority_read_receipt
                != to.authority_read_receipt,
            intent_run_changed: from.intent_run_id != to.intent_run_id,
            workspace_changed: from.workspace != to.workspace,
            observation_time_advanced: from.observed_at != to.observed_at,
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

    /// Whether any receipt field changed, including verifier/time/backend token.
    #[must_use]
    pub const fn authority_receipt_changed(&self) -> bool {
        self.authority_receipt_changed
    }

    /// Whether the bound Intent Run changed.
    #[must_use]
    pub const fn intent_run_changed(&self) -> bool {
        self.intent_run_changed
    }

    /// Whether the bound workspace identity or manifest changed.
    #[must_use]
    pub const fn workspace_changed(&self) -> bool {
        self.workspace_changed
    }

    /// Whether the overall observation time advanced.
    #[must_use]
    pub const fn observation_time_advanced(&self) -> bool {
        self.observation_time_advanced
    }

    /// Component changes in canonical component order.
    #[must_use]
    pub fn component_changes(&self) -> &[SituationComponentChange] {
        &self.component_changes
    }

    /// True when only the observation event changed and no reusable context
    /// assumption was invalidated.
    #[must_use]
    pub fn has_no_context_changes(&self) -> bool {
        matches!(self.authority_change, SituationAuthorityChange::Unchanged)
            && !self.authority_receipt_changed
            && !self.intent_run_changed
            && !self.workspace_changed
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
    /// The run used the legacy identifying reference rather than a full receipt.
    RunAuthorityReceiptRequired,
    /// The run's authenticated receipt differs from the situation receipt.
    RunAuthorityMismatch,
    /// A workspace was supplied without an active run.
    WorkspaceRequiresIntentRun,
    /// Workspace and situation name different runs.
    WorkspaceRunMismatch {
        /// Run bound to the situation.
        expected: RunId,
        /// Run bound to the workspace.
        observed: RunId,
    },
    /// Workspace and situation name different authority heads.
    WorkspaceAuthorityMismatch,
    /// More than the closed v1 component set was supplied.
    TooManyComponents {
        /// Entries supplied.
        observed: usize,
        /// Closed v1 limit.
        limit: usize,
    },
    /// One component class appeared more than once.
    DuplicateComponent {
        /// Repeated class.
        kind: SituationComponentKind,
    },
    /// One component class was neither observed nor explicitly omitted.
    MissingComponent {
        /// Missing class.
        kind: SituationComponentKind,
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
    /// Generation changed but the content identity did not.
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
            Self::WorkspaceRequiresIntentRun => formatter.write_str(
                "a workspace situation requires the Intent Run that authorized it",
            ),
            Self::WorkspaceRunMismatch { expected, observed } => write!(
                formatter,
                "workspace run {observed} differs from situation run {expected}"
            ),
            Self::WorkspaceAuthorityMismatch => formatter.write_str(
                "workspace authority head differs from the situation receipt",
            ),
            Self::TooManyComponents { observed, limit } => write!(
                formatter,
                "situation has {observed} components, v1 limit is {limit}"
            ),
            Self::DuplicateComponent { kind } => {
                write!(formatter, "situation repeats component {kind}")
            }
            Self::MissingComponent { kind } => {
                write!(formatter, "situation omits component {kind} without a typed omission")
            }
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
        (
            SituationComponentState::Observed { .. },
            SituationComponentState::Omitted { .. },
        ) => SituationComponentTransition::BecameOmitted,
        (
            SituationComponentState::Omitted { .. },
            SituationComponentState::Observed { .. },
        ) => SituationComponentTransition::BecameObserved,
        (
            SituationComponentState::Omitted { .. },
            SituationComponentState::Omitted { .. },
        ) => SituationComponentTransition::OmissionChanged,
    }
}

fn situation_commitment(
    receipt: &AuthorityReadReceipt,
    intent_run_id: Option<RunId>,
    workspace: Option<SituationWorkspace>,
    observed_at: LogicalTime,
    components: &[SituationComponent],
) -> Result<[u8; 32], SituationRefusal> {
    let mut encoder = Encoder::with_capacity(768);
    encoder.write_bytes("agent_situation_domain", SITUATION_DOMAIN)?;
    write_authority_receipt(&mut encoder, receipt)?;

    match intent_run_id {
        Some(run_id) => {
            encoder.write_bool(true);
            encoder.write_raw(&run_id.value().to_be_bytes());
        }
        None => encoder.write_bool(false),
    }

    match workspace {
        Some(workspace) => {
            encoder.write_bool(true);
            encoder.write_opaque_id(workspace.workspace_id.as_bytes());
            encoder.write_raw(&workspace.manifest_commitment);
            encoder.write_internal_object_id(workspace.basis_head_id.as_internal_object_id())?;
            encoder.write_raw(&workspace.run_id.value().to_be_bytes());
        }
        None => encoder.write_bool(false),
    }

    encoder.write_scalar(observed_at.value());
    write_count(&mut encoder, "situation_components", components.len())?;
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
            .map(|identity| identity.as_internal_object_id()),
    )?;
    write_optional_scalar(
        encoder,
        receipt
            .latest_repository_sequence()
            .map(|sequence| sequence.get()),
    );
    let latest_repository_commit_id = receipt.latest_repository_commit_id();
    write_optional_identity(
        encoder,
        latest_repository_commit_id
            .as_ref()
            .map(|identity| identity.as_internal_object_id()),
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

fn write_count(
    encoder: &mut Encoder,
    field: &'static str,
    count: usize,
) -> Result<(), CodecRefusal> {
    let count = u32::try_from(count).map_err(|_| CodecRefusal::ValueUnrepresentable {
        field,
        observed: u64::try_from(count).unwrap_or(u64::MAX),
        limit: u64::from(u32::MAX),
    })?;
    encoder.write_scalar(count);
    Ok(())
}

#[cfg(test)]
mod tests {
    use fgit_authority::{
        AuthorityStore, MemAuthorityStore, RepositoryAuthorityHeadBody,
        RepositoryIncarnation, RootLayoutVersion, outcome_index_root,
    };
    use fgit_resource::{Grade, ResourceVector};
    use fgit_types::{
        Digest, DigestBytes, HeadGeneration, PolicyEpoch, RegistryEpoch, RepositoryId, TenantId,
    };

    use super::{
        AgentSituationReceipt, SituationAuthorityChange, SituationComponent,
        SituationComponentKind, SituationComponentTransition, SituationDelta,
        SituationOmissionReason, SituationRefusal, SituationWorkspace,
    };
    use crate::{
        AuthorityBasisRef, AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime,
        OperationClass, RunId,
    };

    fn authority_receipt(
        repository_byte: u8,
        root_byte: u8,
        verified_at: u64,
        verifier_byte: u8,
    ) -> AuthorityReadReceipt {
        let tenant_id = TenantId::from_bytes([0x11; 16]);
        let repository_id = RepositoryId::from_bytes([repository_byte; 16]);
        let default_root = outcome_index_root(&[]).expect("empty outcome root");
        let distinct_root = Digest::new(
            default_root.algorithm(),
            DigestBytes::try_new(&[root_byte; 32]).expect("32-byte digest"),
        );
        let body = RepositoryAuthorityHeadBody {
            tenant_id,
            repository_id,
            repository_incarnation: RepositoryIncarnation::first(),
            generation: HeadGeneration::FIRST,
            predecessor_head_id: None,
            decision_tail_id: None,
            latest_repository_sequence: None,
            latest_committed_rcr_id: None,
            ref_root: default_root,
            forge_position_root: default_root,
            outcome_index_root: default_root,
            object_registry_root: default_root,
            retention_root: default_root,
            outbox_root: default_root,
            policy_epoch: PolicyEpoch::FIRST,
            format_registry_epoch: RegistryEpoch::FIRST,
            configuration_root: distinct_root,
            schema_registry_root: default_root,
            root_layout_version: RootLayoutVersion::RefStateMerkleV1,
        };
        let store = MemAuthorityStore::new();
        store
            .initialize_head(body)
            .expect("initialize authority head");
        let authenticated = AuthorityStore::read_head(&store, tenant_id, repository_id)
            .expect("read authority head");
        AuthorityReadReceipt::from_authenticated_head(
            &authenticated,
            LogicalTime::new(verified_at),
            [verifier_byte; 32],
        )
        .expect("authenticated receipt")
    }

    fn resource_budget() -> ResourceVector {
        ResourceVector::single(Grade::Bytes, 4_096)
    }

    fn authenticated_run(receipt: &AuthorityReadReceipt, run: u128) -> IntentRun {
        IntentRun::new_authenticated(
            RunId::new(run),
            receipt.clone(),
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            resource_budget(),
            LogicalTime::new(1_000),
        )
        .expect("authenticated run")
    }

    fn components(head_id: fgit_types::RepositoryAuthorityHeadId) -> Vec<SituationComponent> {
        SituationComponentKind::ALL
            .into_iter()
            .enumerate()
            .map(|(index, kind)| {
                let byte = u8::try_from(index + 1).expect("ten components");
                if index % 3 == 0 {
                    SituationComponent::omitted(
                        kind,
                        SituationOmissionReason::NotAvailable,
                        [byte; 32],
                    )
                } else {
                    SituationComponent::observed(kind, head_id, [byte; 32])
                }
            })
            .collect()
    }

    #[test]
    fn receipt_is_order_independent_and_change_sensitive() {
        let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
        let head_id = receipt.authority_head_id();
        let ordered = components(head_id);
        let mut reversed = ordered.clone();
        reversed.reverse();

        let first = AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(20),
            ordered,
        )
        .expect("ordered situation");
        let second = AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(20),
            reversed,
        )
        .expect("reordered situation");
        assert_eq!(first.situation_id(), second.situation_id());
        let component_order = first
            .components()
            .iter()
            .map(SituationComponent::kind)
            .collect::<Vec<_>>();
        assert_eq!(
            component_order.as_slice(),
            SituationComponentKind::ALL.as_slice()
        );

        let mut changed = components(head_id);
        let search = changed
            .iter_mut()
            .find(|component| component.kind() == SituationComponentKind::Search)
            .expect("search component");
        *search = SituationComponent::observed(
            SituationComponentKind::Search,
            head_id,
            [0xee; 32],
        );
        let third = AgentSituationReceipt::build(
            receipt,
            None,
            None,
            LogicalTime::new(20),
            changed,
        )
        .expect("changed situation");
        assert_ne!(first.situation_id(), third.situation_id());
    }

    #[test]
    fn every_component_must_be_explicit_and_unique() {
        let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
        let head_id = receipt.authority_head_id();
        let mut missing = components(head_id);
        missing.retain(|component| component.kind() != SituationComponentKind::Obligations);
        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                None,
                None,
                LogicalTime::new(20),
                missing,
            )
            .expect_err("implicit omission must fail"),
            SituationRefusal::MissingComponent {
                kind: SituationComponentKind::Obligations,
            }
        );

        let mut duplicate = components(head_id);
        duplicate.retain(|component| component.kind() != SituationComponentKind::Obligations);
        duplicate.push(SituationComponent::observed(
            SituationComponentKind::Search,
            head_id,
            [0xaa; 32],
        ));
        assert_eq!(
            AgentSituationReceipt::build(
                receipt,
                None,
                None,
                LogicalTime::new(20),
                duplicate,
            )
            .expect_err("duplicate component must fail"),
            SituationRefusal::DuplicateComponent {
                kind: SituationComponentKind::Search,
            }
        );
    }

    #[test]
    fn mixed_authority_and_preverification_observations_fail_closed() {
        let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
        let other = authority_receipt(0x33, 0x42, 10, 0x52);
        let mut mixed = components(receipt.authority_head_id());
        let task = mixed
            .iter_mut()
            .find(|component| component.kind() == SituationComponentKind::TaskProjection)
            .expect("task component");
        *task = SituationComponent::observed(
            SituationComponentKind::TaskProjection,
            other.authority_head_id(),
            [0x91; 32],
        );
        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                None,
                None,
                LogicalTime::new(20),
                mixed,
            )
            .expect_err("mixed authority must fail"),
            SituationRefusal::ComponentAuthorityMismatch {
                kind: SituationComponentKind::TaskProjection,
            }
        );

        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                None,
                None,
                LogicalTime::new(9),
                components(receipt.authority_head_id()),
            )
            .expect_err("observation cannot predate verification"),
            SituationRefusal::ObservationBeforeAuthorityVerification {
                observed: LogicalTime::new(9),
                verified: LogicalTime::new(10),
            }
        );
    }

    #[test]
    fn run_and_workspace_must_share_the_exact_receipt() {
        let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
        let other = authority_receipt(0x33, 0x42, 10, 0x52);
        let run = authenticated_run(&receipt, 7);
        let other_run = authenticated_run(&other, 8);

        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                Some(&other_run),
                None,
                LogicalTime::new(20),
                components(receipt.authority_head_id()),
            )
            .expect_err("another run receipt must fail"),
            SituationRefusal::RunAuthorityMismatch
        );

        let legacy = IntentRun::new(
            RunId::new(9),
            AuthorityBasisRef {
                repository_id: u128::from_be_bytes(*receipt.repository_id().as_bytes()),
                authority_head_generation: receipt.authority_head_generation().get(),
                authority_head_digest: [0x61; 32],
                verified_at: LogicalTime::new(10),
            },
            ClassSet::from_classes(&[OperationClass::TreeFsWorkspace]),
            resource_budget(),
            LogicalTime::new(1_000),
        )
        .expect("legacy run");
        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                Some(&legacy),
                None,
                LogicalTime::new(20),
                components(receipt.authority_head_id()),
            )
            .expect_err("legacy run must fail"),
            SituationRefusal::RunAuthorityReceiptRequired
        );

        let workspace = SituationWorkspace {
            workspace_id: fgit_treefs::WorkspaceId::from_bytes([0x71; 16]),
            manifest_commitment: [0x72; 32],
            basis_head_id: receipt.authority_head_id(),
            run_id: run.run_id(),
        };
        AgentSituationReceipt::build(
            receipt.clone(),
            Some(&run),
            Some(workspace),
            LogicalTime::new(20),
            components(receipt.authority_head_id()),
        )
        .expect("matching workspace situation");

        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                None,
                Some(workspace),
                LogicalTime::new(20),
                components(receipt.authority_head_id()),
            )
            .expect_err("workspace needs its run"),
            SituationRefusal::WorkspaceRequiresIntentRun
        );

        let wrong_run_workspace = SituationWorkspace {
            run_id: RunId::new(99),
            ..workspace
        };
        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                Some(&run),
                Some(wrong_run_workspace),
                LogicalTime::new(20),
                components(receipt.authority_head_id()),
            )
            .expect_err("workspace run mismatch must fail"),
            SituationRefusal::WorkspaceRunMismatch {
                expected: run.run_id(),
                observed: RunId::new(99),
            }
        );

        let wrong_head_workspace = SituationWorkspace {
            basis_head_id: other.authority_head_id(),
            ..workspace
        };
        assert_eq!(
            AgentSituationReceipt::build(
                receipt.clone(),
                Some(&run),
                Some(wrong_head_workspace),
                LogicalTime::new(20),
                components(receipt.authority_head_id()),
            )
            .expect_err("workspace authority mismatch must fail"),
            SituationRefusal::WorkspaceAuthorityMismatch
        );
    }

    #[test]
    fn delta_is_minimal_and_same_generation_forks_are_refused() {
        let receipt = authority_receipt(0x22, 0x41, 10, 0x51);
        let head_id = receipt.authority_head_id();
        let before = AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(20),
            components(head_id),
        )
        .expect("before situation");

        let time_only = AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(21),
            components(head_id),
        )
        .expect("time-only situation");
        let time_delta = SituationDelta::between(&before, &time_only).expect("time delta");
        assert!(time_delta.has_no_context_changes());
        assert!(time_delta.observation_time_advanced());
        assert!(time_delta.component_changes().is_empty());

        let mut changed_components = components(head_id);
        let ownership = changed_components
            .iter_mut()
            .find(|component| component.kind() == SituationComponentKind::Ownership)
            .expect("ownership component");
        *ownership = SituationComponent::observed(
            SituationComponentKind::Ownership,
            head_id,
            [0xf1; 32],
        );
        let after = AgentSituationReceipt::build(
            receipt.clone(),
            None,
            None,
            LogicalTime::new(22),
            changed_components,
        )
        .expect("after situation");
        let delta = SituationDelta::between(&before, &after).expect("component delta");
        assert_eq!(
            delta.authority_change(),
            SituationAuthorityChange::Unchanged
        );
        assert_eq!(delta.component_changes().len(), 1);
        assert_eq!(
            delta.component_changes()[0].kind(),
            SituationComponentKind::Ownership
        );
        assert_eq!(
            delta.component_changes()[0].transition(),
            SituationComponentTransition::GenerationChanged
        );

        let other_repository = authority_receipt(0x33, 0x42, 10, 0x52);
        let other_situation = AgentSituationReceipt::build(
            other_repository.clone(),
            None,
            None,
            LogicalTime::new(22),
            components(other_repository.authority_head_id()),
        )
        .expect("other repository situation");
        assert!(matches!(
            SituationDelta::between(&before, &other_situation),
            Err(SituationRefusal::DeltaRepositoryMismatch { .. })
        ));

        let fork_receipt = authority_receipt(0x22, 0x99, 10, 0x51);
        let fork = AgentSituationReceipt::build(
            fork_receipt.clone(),
            None,
            None,
            LogicalTime::new(22),
            components(fork_receipt.authority_head_id()),
        )
        .expect("fork situation");
        assert_eq!(
            SituationDelta::between(&before, &fork).expect_err("same-generation fork must fail"),
            SituationRefusal::AuthorityForkAtSameGeneration {
                generation: HeadGeneration::FIRST,
            }
        );

        assert_eq!(
            SituationDelta::between(&after, &before)
                .expect_err("observation time rollback must fail"),
            SituationRefusal::ObservationTimeRollback {
                from: LogicalTime::new(22),
                to: LogicalTime::new(20),
            }
        );
    }
}
