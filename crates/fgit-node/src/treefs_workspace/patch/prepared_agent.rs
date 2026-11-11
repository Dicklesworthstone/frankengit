//! Real native patch preparation retained for the Agent Protocol publication
//! gate. Candidate construction never supplies policy, evidence or approval.

use super::{
    EXPORT_BYTES, EXPORT_OBJECTS, PatchProfile, WorkspacePatchCandidate, authorize_patch, live,
    patch_error, paths, preflight, prepare_owned_at_base, workspace_request_live,
};
use crate::agent_publication::{MAX_AGENT_PUBLICATION_EXPORT_BYTES, MAX_AGENT_PUBLICATION_OBJECTS};
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_agent::{
    AgentChangePlan, AgentPublicationEvidence, AgentPublicationRefusal, AgentPublicationSubject,
    AgentRefTransaction, ContextPacket, IntentRun, LogicalTime, OperationClass, ProtocolRefusal,
    WorkspaceBinding,
};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, GitOid as NativeOid, NativeObjectIdentity};
use fgit_forge::{patch::PatchLimits, preparation::MergeMetadata};
use fgit_treefs::{
    EpochSet, ExpectedRef, ExportLimits, ExportPlan, Overlay, OverlayRoot, PositionReceipt,
    ProposalRefusal, ProposedRefIntent, ProposedTransaction, TreeCapability, WorkspaceSnapshotBody,
};
use fgit_types::{GitOid, RefName};
use fgit_wire::visibility::RefVisibility;

/// Independently supplied host authorization and exact patch inputs. The run
/// carries operation scope and the authenticated base; the existing capability
/// carries source disclosure, writable paths, expiry and shared fetch limits.
/// Neither repository text nor an agent-selected patch can widen either scope.
///
/// This is an in-memory native host API. The embedding owns sponsorship,
/// revocation and cumulative run-budget reservation, as for native agent source
/// retrieval. Patch/export limits bound this invocation; they are not a fresh
/// whole-run allowance. Sponsored HTTP credentials cannot mint these inputs.
pub struct AgentWorkspacePatchInput<'a> {
    pub run: &'a IntentRun,
    pub reference: &'a RefName,
    pub expected_commit: GitOid,
    pub visibility: &'a RefVisibility,
    pub capability: &'a mut TreeCapability,
    pub patch_bytes: &'a [u8],
    pub metadata: &'a MergeMetadata,
    pub limits: PatchLimits,
}

/// Why native preparation could not retain a complete agent candidate.
#[derive(Debug)]
pub enum AgentWorkspacePatchRefusal {
    /// The run omitted an operation performed by this preparation profile.
    OperationOutsideRun(OperationClass),
    /// Expiry is half-open; no candidate is returned at or beyond this time.
    RunExpired,
    /// The trusted clock predates the authenticated receipt or a prior check.
    ClockRegressed,
    /// The native reader, capability, patch evaluator or exporter refused.
    Workspace(Box<NodeWorkspaceRefusal>),
    /// The run cannot bind the actual selected workspace.
    Binding(Box<ProtocolRefusal>),
    /// The actual export cannot seal the inert, exact-predecessor proposal.
    Proposal(ProposalRefusal),
}

impl core::fmt::Display for AgentWorkspacePatchRefusal {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(out, "native agent patch preparation refused: {self:?}")
    }
}
impl core::error::Error for AgentWorkspacePatchRefusal {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Workspace(error) => Some(error.as_ref()),
            Self::Binding(error) => Some(error.as_ref()),
            Self::Proposal(error) => Some(error),
            Self::OperationOutsideRun(_) | Self::RunExpired | Self::ClockRegressed => None,
        }
    }
}
impl From<NodeWorkspaceRefusal> for AgentWorkspacePatchRefusal {
    fn from(error: NodeWorkspaceRefusal) -> Self {
        Self::Workspace(Box::new(error))
    }
}
impl From<ProtocolRefusal> for AgentWorkspacePatchRefusal {
    fn from(error: ProtocolRefusal) -> Self {
        Self::Binding(Box::new(error))
    }
}
impl From<ProposalRefusal> for AgentWorkspacePatchRefusal {
    fn from(error: ProposalRefusal) -> Self {
        Self::Proposal(error)
    }
}

/// One actual evaluated TreeFS change, its authenticated workspace and the exact
/// native bundle. All components are retained together and exposed immutably.
/// There is no constructor from caller-authored overlays or alleged evidence.
///
/// Retention is process-local and has no crash-durability claim. It does not
/// advance canonical state, authenticate a publisher, execute a check or assert
/// approval. The existing evidence gate and native publication consumer remain
/// responsible for those separate boundaries.
#[derive(Debug)]
pub struct PreparedAgentPatchCandidate<A: GitHashAlgorithm> {
    workspace: WorkspaceBinding<A>,
    overlay: Overlay,
    export: ExportPlan<A>,
    proposal: ProposedTransaction<A>,
    candidate: WorkspacePatchCandidate,
}

impl<A: GitHashAlgorithm> PreparedAgentPatchCandidate<A> {
    #[must_use]
    pub const fn workspace(&self) -> &WorkspaceBinding<A> {
        &self.workspace
    }

    #[must_use]
    pub const fn overlay(&self) -> &Overlay {
        &self.overlay
    }

    #[must_use]
    pub const fn export(&self) -> &ExportPlan<A> {
        &self.export
    }

    #[must_use]
    pub const fn proposal(&self) -> &ProposedTransaction<A> {
        &self.proposal
    }

    #[must_use]
    pub const fn candidate(&self) -> &WorkspacePatchCandidate {
        &self.candidate
    }

    /// Exact commit bytes for the host's independent review or workflow input.
    #[must_use]
    pub fn commit_body(&self) -> &[u8] {
        self.candidate.commit_body()
    }

    /// Bind evidence producers to the actual retained change and caller's plan
    /// and context. Deriving this identity does not claim that evidence exists.
    pub fn publication_subject(
        &self,
        context_packets: &[ContextPacket],
        plan: &AgentChangePlan,
    ) -> Result<AgentPublicationSubject, AgentPublicationRefusal> {
        AgentPublicationSubject::derive(
            &self.workspace,
            &self.proposal,
            context_packets,
            plan,
            &self.overlay,
            &self.export,
        )
    }

    /// Run the existing complete evidence gate for this retained candidate.
    /// The host supplies its actual evidence, reconciliation, policy and
    /// independently resolved approval. The gate checks the subject retained
    /// when that evidence was collected; this method does not invent one.
    ///
    /// The retained overlay/export fill the existing evidence input's change
    /// fields, so callers cannot accidentally substitute another working copy.
    /// The resulting transaction remains inert until ordinary native admission.
    pub fn prepare_ref_transaction(
        &self,
        context_packets: &[ContextPacket],
        evidence: AgentPublicationEvidence<'_, A>,
    ) -> Result<AgentRefTransaction<A>, ProtocolRefusal> {
        self.workspace.prepare_ref_transaction(
            self.proposal.clone(),
            context_packets,
            AgentPublicationEvidence {
                overlay: &self.overlay,
                export: &self.export,
                ..evidence
            },
        )
    }
}

struct PreparationClock<'a, C: ?Sized> {
    run: &'a IntentRun,
    now: &'a C,
    floor: LogicalTime,
}
impl<C: Fn() -> LogicalTime + ?Sized> PreparationClock<'_, C> {
    fn check(
        &mut self,
        request: &NodeRequestContext,
    ) -> Result<LogicalTime, AgentWorkspacePatchRefusal> {
        live(request)?;
        let now = (self.now)();
        live(request)?;
        if now.value() < self.floor.value() {
            return Err(AgentWorkspacePatchRefusal::ClockRegressed);
        }
        if !self.run.is_open_at(now) {
            return Err(AgentWorkspacePatchRefusal::RunExpired);
        }
        self.floor = now;
        Ok(now)
    }
}

impl OneNode {
    /// Apply an exact nonempty patch through the existing native TreeFS path
    /// and retain everything needed by the Agent Protocol evidence gate.
    ///
    /// Both the selected authority head and the branch predecessor must match
    /// the original run/input. This never refreshes a run or falls back to a
    /// newer branch. Hidden source and incomplete directory disclosure refuse
    /// under the caller's unchanged capability. This uses the regular patch
    /// profile (including supported native binary edits and regular renames).
    ///
    /// `now` is the host's monotone logical clock, in the same domain as the run
    /// and capability expiry. It is checked before and after native work. The
    /// host must bind `request` to the run's finite lifetime for cancellation
    /// within a phase; no sibling context or renewed deadline is created here.
    pub async fn prepare_agent_workspace_patch_in<A, C>(
        &self,
        request: &NodeRequestContext,
        input: AgentWorkspacePatchInput<'_>,
        now: &C,
    ) -> Result<PreparedAgentPatchCandidate<A>, AgentWorkspacePatchRefusal>
    where
        A: GitHashAlgorithm,
        C: Fn() -> LogicalTime + ?Sized,
    {
        live(request)?;
        let receipt = input
            .run
            .authority_read_receipt()
            .ok_or(ProtocolRefusal::RunAuthorityReceiptRequired)?;
        if receipt.repository_id() != self.repository_id()
            || input.capability.repository_id() != receipt.repository_id()
        {
            return Err(NodeWorkspaceRefusal::RepositoryMismatch.into());
        }
        if receipt.latest_repository_commit_id().is_none() {
            return Err(ProtocolRefusal::WorkspaceBaseMissing.into());
        }
        for class in [
            OperationClass::ReadCanonicalObject,
            OperationClass::TreeFsWorkspace,
            OperationClass::CreateCandidateObject,
            OperationClass::PreparePublication,
        ] {
            if !input.run.allowed_operation_classes().contains(class) {
                return Err(AgentWorkspacePatchRefusal::OperationOutsideRun(class));
            }
        }
        let mut clock = PreparationClock {
            run: input.run,
            now,
            floor: receipt.verified_at_logical_time(),
        };
        let tick = clock.check(request)?;
        preflight(
            input.reference,
            input.expected_commit,
            self.object_format,
            input.metadata,
        )?;
        let patch = PatchProfile::Regular
            .parse(input.patch_bytes, input.limits, &|| {
                !workspace_request_live(request)
            })
            .map_err(patch_error)?;
        let paths = paths(&patch)?;
        authorize_patch(&patch, input.capability, tick.value())?;
        let tick = clock.check(request)?;
        let workspace_id = input.capability.workspace_id();
        let prepared = self
            .with_workspace_snapshot_in::<A, _>(
                request,
                input.reference,
                input.visibility,
                input.capability,
                tick.value(),
                Some(receipt.authority_head_id()),
                Some(input.expected_commit),
                EXPORT_BYTES,
                |base, source, capability, _head, _metadata_bytes| {
                    prepare_owned_at_base(
                        base,
                        source,
                        capability,
                        request,
                        input.reference,
                        input.expected_commit,
                        &patch,
                        &paths,
                        input.patch_bytes,
                        tick.value(),
                        input.metadata,
                        ExportLimits {
                            max_objects: MAX_AGENT_PUBLICATION_OBJECTS,
                            max_total_bytes: MAX_AGENT_PUBLICATION_EXPORT_BYTES,
                            // Entry traversal can reuse far more base objects
                            // than the native publication profile constructs.
                            max_tree_entries: EXPORT_OBJECTS,
                        },
                    )
                },
            )
            .await?;
        let tick = clock.check(request)?;
        authorize_patch(&patch, input.capability, tick.value())?;
        let epochs = EpochSet::new()
            .stage()
            .publish()
            .map_err(|_| ProtocolRefusal::WorkspaceEpochInvariant)?;
        let workspace = WorkspaceBinding::bind(
            input.run.clone(),
            WorkspaceSnapshotBody::new(
                workspace_id,
                self.repository_id(),
                prepared.export.source_rcr,
                prepared.export.source_commit,
                prepared.base_tree,
                OverlayRoot::of(&prepared.overlay),
                epochs,
            ),
        )?;
        let candidate_commit =
            NativeOid::<A>::of_object(GitObjectKind::Commit, prepared.candidate.commit_body());
        let proposal = ProposedTransaction::seal(
            workspace_id,
            &prepared.export.plan,
            PositionReceipt {
                repository_id: self.repository_id(),
                base_rcr_id: prepared.export.source_rcr,
                base_tree_oid: prepared.base_tree,
                proposed_tree_oid: *prepared.export.plan.root_tree(),
                touched_paths: prepared.overlay.touched_paths(),
            },
            vec![ProposedRefIntent {
                name: input.reference.as_bytes().to_vec(),
                expected: ExpectedRef::Exactly {
                    oid: prepared.export.source_commit,
                },
                new: candidate_commit,
            }],
        )?;
        let tick = clock.check(request)?;
        authorize_patch(&patch, input.capability, tick.value())?;
        Ok(PreparedAgentPatchCandidate {
            workspace,
            overlay: prepared.overlay,
            export: prepared.export.plan,
            proposal,
            candidate: prepared.candidate,
        })
    }
}
