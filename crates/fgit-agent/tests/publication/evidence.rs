//! Shared evidence builders for publication and protocol tests.
//! Reference-provider fixtures do not establish native publication.

use fgit_agent::*;
use fgit_authority::outcome_index_root;
use fgit_crypto::GitHashAlgorithm;
use fgit_resource::{Grade, ResourceVector};
use fgit_treefs::{ExportPlan, Overlay, ProposedTransaction};
use fgit_types::{Digest, DigestBytes};

pub fn digest(byte: u8) -> Digest {
    Digest::new(
        outcome_index_root(&[]).unwrap().algorithm(),
        DigestBytes::try_new(&[byte; 32]).unwrap(),
    )
}

#[derive(Clone)]
pub struct Evidence {
    pub subject: AgentPublicationSubject,
    pub plan: AgentChangePlan,
    pub change: EvidenceCarryingChange,
    pub requirements: Vec<LearningRequirementOutcome>,
    pub report: RunReconciliationReport,
    pub policy: EccPolicy,
    pub approval: PlanApproval,
    pub observed_at: LogicalTime,
}

const fn facts(base: u128) -> PartyFacts {
    PartyFacts {
        workspace: Some(base),
        credentials: Some(base + 1),
        model_harness: Some(base + 2),
        context: Some(base + 3),
        oracle: Some(base + 4),
        sponsor: Some(base + 5),
        human: Some(base + 6),
    }
}

impl Evidence {
    pub fn new<A: GitHashAlgorithm>(
        workspace: &WorkspaceBinding<A>,
        proposal: &ProposedTransaction<A>,
        contexts: &[ContextPacket],
        overlay: &Overlay,
        export: &ExportPlan<A>,
    ) -> Self {
        Self::with_approval(
            workspace,
            proposal,
            contexts,
            overlay,
            export,
            PlanApproval::Granted {
                approval_root: digest(42),
            },
        )
    }
    pub fn with_approval<A: GitHashAlgorithm>(
        workspace: &WorkspaceBinding<A>,
        proposal: &ProposedTransaction<A>,
        contexts: &[ContextPacket],
        overlay: &Overlay,
        export: &ExportPlan<A>,
        approval: PlanApproval,
    ) -> Self {
        let run = workspace.run();
        let receipt = workspace.authority_read_receipt();
        let at = LogicalTime::new(receipt.verified_at_logical_time().value() + 1);
        let components = std::array::from_fn(|i| {
            let kind = SituationComponentKind::ALL[i];
            if kind == SituationComponentKind::TaskProjection {
                SituationComponent::observed(kind, receipt.authority_head_id(), [44; 32])
            } else {
                SituationComponent::omitted(
                    kind,
                    SituationOmissionReason::NotAvailable,
                    [i as u8 + 1; 32],
                )
            }
        });
        let situation =
            AgentSituationReceipt::build(receipt.clone(), Some(run), None, at, components).unwrap();
        let item = WorkItem::new(
            WorkTaskId::from_bytes([31; 32]),
            [44; 32],
            TaskPhase::Open,
            WorkRankingInputs::new(1, 2, 3),
            WorkEligibilityInputs::new(0, Some(run.run_id()), None, true, WorkConflict::Clear),
        );
        let frontier = WorkFrontier::build_action_scoped(&situation, vec![item]).unwrap();
        let pulse = AgentControlPulse::build(&situation, &frontier, Some(run)).unwrap();
        let surface = PlanSurface::new(PlanSurfaceKind::RepositoryPath, digest(61));
        let requirements = [
            PlanRequirementId::from_bytes([10; 32]),
            PlanRequirementId::from_bytes([11; 32]),
        ];
        let spec = AgentChangePlanSpec::new(
            digest(60),
            ClassSet::from_classes(&[
                OperationClass::TreeFsWorkspace,
                OperationClass::PreparePublication,
            ]),
            ResourceVector::single(Grade::Bytes, 1_024),
            PlanStopConditionSet::MANDATORY,
            RejectedShortcutSet::BASELINE,
            approval,
        )
        .with_surfaces(vec![surface], vec![surface])
        .with_checkpoints(vec![PlanCheckpoint::new(
            PlanCheckpointId::from_bytes([65; 32]),
            PlanCheckpointPurpose::ImplementSlice,
            digest(66),
            digest(67),
        )])
        .with_evidence_plan(vec![
            PlanEvidenceRequirement::new(
                requirements[0],
                EvidenceClass::Executed,
                digest(69),
                true,
            ),
            PlanEvidenceRequirement::new(
                requirements[1],
                EvidenceClass::Observed,
                digest(70),
                false,
            ),
        ])
        .with_non_claims(vec![digest(71)]);
        let plan = AgentChangePlan::build(&pulse, run, contexts, spec).unwrap();
        let records = vec![
            EvidenceRecordRef {
                class: EvidenceClass::Executed,
                artifact: 900,
                refresh_side: None,
            },
            EvidenceRecordRef {
                class: EvidenceClass::Observed,
                artifact: 901,
                refresh_side: None,
            },
        ];
        let change = EvidenceCarryingChange {
            intent_run: run.run_id().value(),
            producer: facts(1),
            evidence: records.clone(),
            requirement_dispositions: vec![Some(RequirementDisposition::SatisfiedWithEvidence); 2],
            non_claims: vec![12],
            verifiers: vec![VerifierAttestation {
                verifier: 20,
                facts: facts(100),
                upheld: true,
            }],
            refreshed_authority: None,
        };
        let requirements = vec![
            LearningRequirementOutcome::new(
                requirements[0],
                RequirementDisposition::SatisfiedWithEvidence,
                vec![records[0]],
                vec![20],
                digest(72),
            ),
            LearningRequirementOutcome::new(
                requirements[1],
                RequirementDisposition::SatisfiedWithEvidence,
                vec![records[1]],
                vec![],
                digest(73),
            ),
        ];
        let observed_at = LogicalTime::new(at.value() + 2);
        let report =
            RunReconciliationReport::build(run, vec![], LogicalTime::new(at.value() + 1)).unwrap();
        let subject =
            AgentPublicationSubject::derive(workspace, proposal, contexts, &plan, overlay, export)
                .unwrap();
        Self {
            subject,
            plan,
            change,
            requirements,
            report,
            policy: EccPolicy {
                required_classes: vec![EvidenceClass::Executed],
                required_independence: vec![
                    IndependenceDimension::Workspace,
                    IndependenceDimension::Credentials,
                ],
                requires_verifier: true,
                ..EccPolicy::default()
            },
            approval,
            observed_at,
        }
    }

    pub fn input<'a, A: GitHashAlgorithm>(
        &'a self,
        overlay: &'a Overlay,
        export: &'a ExportPlan<A>,
    ) -> AgentPublicationEvidence<'a, A> {
        AgentPublicationEvidence {
            expected_subject: &self.subject,
            plan: &self.plan,
            overlay,
            export,
            change: &self.change,
            requirements: &self.requirements,
            reconciliation: &self.report,
            policy: &self.policy,
            expected_approval: self.approval,
            observed_at: self.observed_at,
        }
    }
}
