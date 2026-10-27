//! Evidence gates for the existing TreeFS-to-ordinary-ref-transaction path.
//!
//! A publication subject commits the actual run, plan, workspace, overlay,
//! export and requested refs before evidence is collected. Preparation
//! recomputes that subject and consumes the evidence through
//! [`crate::WorkspaceBinding::prepare_ref_transaction`]. Neither a subject nor
//! a successful gate authenticates an artifact, sponsor approval or principal;
//! the host must supply those from their existing trusted owners. The ordinary
//! effect-time capability, revocation, admission and head-CAS boundaries remain.

use core::fmt;
use std::collections::BTreeSet;

use fgit_codec::{CodecRefusal, Encoder, wire::encode_body};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, GitObjectKind, NativeObjectIdentity, Sha256};
use fgit_treefs::{
    ContentId, EntryClass, ExportPlan, Overlay, OverlayEntry, OverlayRoot, ProposedTransaction,
};

use crate::{
    AgentChangePlan, AgentChangePlanId, ContextPacket, ContextPacketId, EccPolicy, EccRefusal,
    EvidenceCarryingChange, EvidenceClass, IndependenceDimension, IntentRunCommitment,
    LearningRequirementOutcome, LogicalTime, OperationClass, PlanApproval, PlanRequirementId,
    RequirementDisposition, RunReconciliationReport, WorkspaceBinding, classify_independence,
};

/// Maximum records, requirement results or verifier facts in one preparation.
pub const MAX_PUBLICATION_EVIDENCE_RECORDS: usize = 256;
/// Aggregate requirement-to-evidence and requirement-to-verifier references.
pub const MAX_PUBLICATION_EVIDENCE_REFERENCES: usize = 1_024;
/// Maximum constructed objects checked by this publication profile.
pub const MAX_PUBLICATION_OBJECTS: usize = 100_000;
/// Maximum overlay or export body bytes checked by this profile.
pub const MAX_PUBLICATION_BYTES: usize = 512 * 1024 * 1024;
/// Maximum path, ref-name and overlay metadata bytes checked by this profile.
pub const MAX_PUBLICATION_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// Failure before an agent publication transaction can be constructed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentPublicationRefusal {
    /// A bounded collection or byte envelope was exceeded.
    Limit(&'static str),
    /// The plan or report names another complete run.
    RunBinding,
    /// Preparation is before authenticated observation or after run expiry.
    Time,
    /// The plan does not include publication preparation.
    PlanOperation,
    /// Approval mode or root differs from the host's independent expectation.
    ApprovalBinding,
    /// Context membership, scope or authenticated basis differs.
    ContextBinding,
    /// The proposal or supplied overlay differs from its bound workspace.
    WorkspaceBinding,
    /// The exported object set, tree or proposal does not match.
    ExportBinding,
    /// An unresolved conflict or missing/corrupt overlay body remains.
    OverlayInvalid,
    /// Evidence was collected for another exact change subject.
    EvidenceSubject,
    /// The supplied report is not a settled observation of this exact run.
    Reconciliation,
    /// The exact-basis preparation profile cannot interpret a legacy refresh.
    RefreshRequiresReplan,
    /// A requirement was omitted, duplicated, added, or reordered incorrectly.
    RequirementSet,
    /// A required acceptance line has no complete supported disposition.
    RequirementUnsatisfied(PlanRequirementId),
    /// Supporting records disagree with the ECC or required evidence class.
    RequirementEvidence(PlanRequirementId),
    /// A requirement's named verifier is absent, duplicated or unsuccessful.
    RequirementVerifier(PlanRequirementId),
    /// A requirement lacks an upheld, fully independent named verifier.
    RequirementIndependence(PlanRequirementId),
    /// Artifact or verifier identities are ambiguous within the bundle.
    DuplicateEvidence,
    /// Policy has no successful verifier with its required independence.
    PolicyVerifier,
    /// The existing ECC policy evaluator refused the bundle.
    Ecc(EccRefusal),
    /// Canonical framing could not represent the already bounded inputs.
    Codec(CodecRefusal),
}

impl fmt::Display for AgentPublicationRefusal {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "agent publication preparation refused: {self:?}")
    }
}
impl core::error::Error for AgentPublicationRefusal {}
impl From<CodecRefusal> for AgentPublicationRefusal {
    fn from(value: CodecRefusal) -> Self {
        Self::Codec(value)
    }
}

/// Exact subject given to evidence producers and verifiers before preparation.
/// All fields are derived from real inputs; this is neither approval nor a
/// claim that a check was executed. Keep it with the evidence it scopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPublicationSubject {
    subject_id: [u8; 32],
    run_commitment: IntentRunCommitment,
    plan_id: AgentChangePlanId,
    workspace_manifest: [u8; 32],
    context_packet_ids: Vec<ContextPacketId>,
    overlay_root: [u8; 32],
    export_commitment: [u8; 32],
    proposal_commitment: [u8; 32],
    tree_diff_commitment: [u8; 32],
}

impl AgentPublicationSubject {
    /// Computes the subject for an exact, bounded TreeFS proposal. The tree
    /// diff commitment binds base/result tree identities, actual overlay and
    /// touched paths; it is not a rendered textual diff or a closure proof.
    pub fn derive<A: GitHashAlgorithm>(
        workspace: &WorkspaceBinding<A>,
        proposal: &ProposedTransaction<A>,
        context_packets: &[ContextPacket],
        plan: &AgentChangePlan,
        overlay: &Overlay,
        export: &ExportPlan<A>,
    ) -> Result<Self, AgentPublicationRefusal> {
        let run = workspace.run();
        let run_commitment = run
            .commitment()
            .map_err(|_| AgentPublicationRefusal::RunBinding)?;
        if plan.intent_run_id() != run.run_id() || plan.intent_run_commitment() != run_commitment {
            return Err(AgentPublicationRefusal::RunBinding);
        }
        if !plan
            .effect_plan()
            .contains(OperationClass::PreparePublication)
        {
            return Err(AgentPublicationRefusal::PlanOperation);
        }
        let context_packet_ids = check_context(workspace, context_packets, plan)?;
        check_change_bounds(overlay, export, proposal)?;
        let snapshot = workspace.snapshot();
        let overlay_root = *OverlayRoot::of(overlay).as_bytes();
        if proposal.workspace_id() != workspace.workspace_id()
            || proposal.receipt().repository_id != snapshot.repository_id()
            || proposal.receipt().base_rcr_id != snapshot.base_rcr_id()
            || &proposal.receipt().base_tree_oid != snapshot.base_tree_oid()
            || &overlay_root != snapshot.overlay_root().as_bytes()
            || proposal.receipt().touched_paths != overlay.touched_paths()
        {
            return Err(AgentPublicationRefusal::WorkspaceBinding);
        }
        if &proposal.receipt().proposed_tree_oid != export.root_tree()
            || proposal.object_count() != export.object_count()
            || export.get(export.root_tree()).is_none()
        {
            return Err(AgentPublicationRefusal::ExportBinding);
        }
        let export_commitment = export_commitment(export)?;
        let mut proposal_frame = Encoder::new();
        proposal_frame.write_bytes("publication.proposal", &proposal.canonical_request_bytes())?;
        // The TreeFS request frame does not include its RCR or object count.
        // Both remain part of this complete evidence subject.
        proposal_frame
            .write_internal_object_id(proposal.receipt().base_rcr_id.as_internal_object_id())?;
        proposal_frame.write_scalar(proposal.object_count() as u64);
        proposal_frame.write_git_hash_algorithm(A::OBJECT_FORMAT);
        let proposal_commitment = hash(
            b"frankengit.agent.publication-proposal/v1\0",
            &proposal_frame.into_bytes(),
        );

        let mut diff = Encoder::new();
        diff.write_git_oid(&snapshot.base_tree_oid().erase());
        diff.write_git_oid(&export.root_tree().erase());
        diff.write_raw(&overlay_root);
        diff.write_scalar(proposal.receipt().touched_paths.len() as u64);
        for path in &proposal.receipt().touched_paths {
            diff.write_bytes("publication.path", path.as_bytes())?;
        }
        let tree_diff_commitment = hash(
            b"frankengit.agent.publication-tree-diff/v1\0",
            &diff.into_bytes(),
        );
        let workspace_manifest = workspace.manifest_commitment();
        let mut frame = Encoder::new();
        frame.write_raw(run_commitment.as_bytes());
        frame.write_raw(plan.plan_id().as_bytes());
        frame.write_raw(&workspace_manifest);
        frame.write_raw(&overlay_root);
        frame.write_raw(&export_commitment);
        frame.write_raw(&proposal_commitment);
        frame.write_raw(&tree_diff_commitment);
        frame.write_scalar(context_packet_ids.len() as u64);
        for id in &context_packet_ids {
            frame.write_raw(id.as_bytes());
        }
        Ok(Self {
            subject_id: hash(
                b"frankengit.agent.publication-subject/v1\0",
                &frame.into_bytes(),
            ),
            run_commitment,
            plan_id: plan.plan_id(),
            workspace_manifest,
            context_packet_ids,
            overlay_root,
            export_commitment,
            proposal_commitment,
            tree_diff_commitment,
        })
    }

    /// Complete evidence-subject identity, retained independently with checks.
    #[must_use]
    pub const fn subject_id(&self) -> &[u8; 32] {
        &self.subject_id
    }
    /// Every machine-enforced run field participates in this commitment.
    #[must_use]
    pub const fn run_commitment(&self) -> IntentRunCommitment {
        self.run_commitment
    }
    /// Exact approved plan, including its acceptance contract and non-claims.
    #[must_use]
    pub const fn plan_id(&self) -> AgentChangePlanId {
        self.plan_id
    }
    /// Actual exported object bodies and identities, in deterministic order.
    #[must_use]
    pub const fn export_commitment(&self) -> &[u8; 32] {
        &self.export_commitment
    }
    /// Base/result trees, exact overlay and touched-path sequence.
    #[must_use]
    pub const fn tree_diff_commitment(&self) -> &[u8; 32] {
        &self.tree_diff_commitment
    }
    /// Exact requested refs and their preconditions plus TreeFS provenance.
    #[must_use]
    pub const fn proposal_commitment(&self) -> &[u8; 32] {
        &self.proposal_commitment
    }
}

/// Evidence supplied to the existing publication preparation method.
///
/// `expected_subject` must be the subject retained when the supplied evidence
/// was collected, not a replacement computed merely to pass this call. The
/// host independently resolves `expected_approval` and the publication policy.
/// This boundary checks those bindings; it does not authenticate their origin.
pub struct AgentPublicationEvidence<'a, A: GitHashAlgorithm> {
    pub expected_subject: &'a AgentPublicationSubject,
    pub plan: &'a AgentChangePlan,
    pub overlay: &'a Overlay,
    pub export: &'a ExportPlan<A>,
    pub change: &'a EvidenceCarryingChange,
    /// Existing requirement-result vocabulary, in any order. The ECC's
    /// positional disposition list must follow the plan's canonical ID order.
    pub requirements: &'a [LearningRequirementOutcome],
    pub reconciliation: &'a RunReconciliationReport,
    pub policy: &'a EccPolicy,
    pub expected_approval: PlanApproval,
    pub observed_at: LogicalTime,
}

/// Checked, immutable evidence retained by an ordinary agent ref transaction.
/// It is constructible only inside the mandatory preparation gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPublicationBinding {
    binding_id: [u8; 32],
    subject: AgentPublicationSubject,
    plan: AgentChangePlan,
    change: EvidenceCarryingChange,
    requirements: Vec<LearningRequirementOutcome>,
    reconciliation: RunReconciliationReport,
    policy: EccPolicy,
    observed_at: LogicalTime,
}

impl AgentPublicationBinding {
    #[must_use]
    pub const fn binding_id(&self) -> &[u8; 32] {
        &self.binding_id
    }
    #[must_use]
    pub const fn subject(&self) -> &AgentPublicationSubject {
        &self.subject
    }
    #[must_use]
    pub const fn plan(&self) -> &AgentChangePlan {
        &self.plan
    }
    #[must_use]
    pub const fn change(&self) -> &EvidenceCarryingChange {
        &self.change
    }
    #[must_use]
    pub fn requirements(&self) -> &[LearningRequirementOutcome] {
        &self.requirements
    }
    #[must_use]
    pub const fn reconciliation(&self) -> &RunReconciliationReport {
        &self.reconciliation
    }
    #[must_use]
    pub const fn policy(&self) -> &EccPolicy {
        &self.policy
    }
    #[must_use]
    pub const fn observed_at(&self) -> LogicalTime {
        self.observed_at
    }
}

pub(crate) fn validate<A: GitHashAlgorithm>(
    workspace: &WorkspaceBinding<A>,
    proposal: &ProposedTransaction<A>,
    context_packets: &[ContextPacket],
    input: AgentPublicationEvidence<'_, A>,
) -> Result<AgentPublicationBinding, AgentPublicationRefusal> {
    check_evidence_bounds(&input)?;
    let subject = AgentPublicationSubject::derive(
        workspace,
        proposal,
        context_packets,
        input.plan,
        input.overlay,
        input.export,
    )?;
    if &subject != input.expected_subject {
        return Err(AgentPublicationRefusal::EvidenceSubject);
    }
    if input.plan.approval() != input.expected_approval {
        return Err(AgentPublicationRefusal::ApprovalBinding);
    }
    let run = workspace.run();
    if input.observed_at
        < workspace
            .authority_read_receipt()
            .verified_at_logical_time()
        || !run.is_open_at(input.observed_at)
    {
        return Err(AgentPublicationRefusal::Time);
    }
    let report = input.reconciliation;
    if report.run_commitment() != subject.run_commitment
        || report.run_id() != run.run_id()
        || report.authority_read_receipt() != workspace.authority_read_receipt()
        || report.observed_at() > input.observed_at
        || report.has_unsettled_effects()
    {
        return Err(AgentPublicationRefusal::Reconciliation);
    }
    if input.change.intent_run != run.run_id().value() {
        return Err(AgentPublicationRefusal::RunBinding);
    }
    // Legacy refresh receipts contain numeric bases, not authenticated heads.
    // This exact-basis gate cannot use them to relabel old evidence as current.
    if input.change.refreshed_authority.is_some() {
        return Err(AgentPublicationRefusal::RefreshRequiresReplan);
    }
    if input.policy.requires_completed_refresh {
        return Err(AgentPublicationRefusal::Ecc(
            EccRefusal::MissingRefreshReceipt,
        ));
    }
    let requirements = validate_requirements(input.plan, input.change, input.requirements)?;
    input
        .change
        .evaluate(input.policy)
        .map_err(AgentPublicationRefusal::Ecc)?;
    check_policy_verifiers(input.change, input.policy)?;

    let mut frame = Encoder::new();
    frame.write_raw(subject.subject_id());
    frame.write_bytes("publication.ecc", &encode_body(input.change)?)?;
    frame.write_raw(report.report_id().as_bytes());
    frame.write_scalar(input.observed_at.value());
    write_policy(&mut frame, input.policy);
    frame.write_scalar(requirements.len() as u64);
    for result in &requirements {
        frame.write_raw(result.requirement_id().as_bytes());
        frame.write_scalar(result.disposition().code_point());
        frame.write_digest(&result.reason_root())?;
        frame.write_scalar(result.evidence().len() as u64);
        for record in result.evidence() {
            frame.write_scalar(record.class.code_point());
            frame.write_raw(&record.artifact.to_be_bytes());
            frame.write_raw_byte(match record.refresh_side {
                None => 0,
                Some(crate::RefreshSide::BeforeRefresh) => 1,
                Some(crate::RefreshSide::AfterRefresh) => 2,
            });
        }
        frame.write_scalar(result.verifier_ids().len() as u64);
        for verifier in result.verifier_ids() {
            frame.write_raw(&verifier.to_be_bytes());
        }
    }
    Ok(AgentPublicationBinding {
        binding_id: hash(
            b"frankengit.agent.publication-binding/v1\0",
            &frame.into_bytes(),
        ),
        subject,
        plan: input.plan.clone(),
        change: input.change.clone(),
        requirements,
        reconciliation: report.clone(),
        policy: input.policy.clone(),
        observed_at: input.observed_at,
    })
}

fn check_context<A: GitHashAlgorithm>(
    workspace: &WorkspaceBinding<A>,
    packets: &[ContextPacket],
    plan: &AgentChangePlan,
) -> Result<Vec<ContextPacketId>, AgentPublicationRefusal> {
    if packets.len() > crate::MAX_PLAN_ENTRIES {
        return Err(AgentPublicationRefusal::Limit("context_packets"));
    }
    let mut ids = Vec::with_capacity(packets.len());
    for packet in packets {
        if packet.authority_read_receipt() != workspace.authority_read_receipt()
            || !packet
                .control()
                .authorization_scope()
                .is_subset_of(workspace.run().allowed_operation_classes())
        {
            return Err(AgentPublicationRefusal::ContextBinding);
        }
        ids.push(packet.packet_id());
    }
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) || ids != plan.input_context_packets() {
        return Err(AgentPublicationRefusal::ContextBinding);
    }
    Ok(ids)
}

fn bounded_add(
    total: &mut usize,
    amount: usize,
    limit: usize,
    field: &'static str,
) -> Result<(), AgentPublicationRefusal> {
    *total = total
        .checked_add(amount)
        .filter(|sum| *sum <= limit)
        .ok_or(AgentPublicationRefusal::Limit(field))?;
    Ok(())
}

fn check_change_bounds<A: GitHashAlgorithm>(
    overlay: &Overlay,
    export: &ExportPlan<A>,
    proposal: &ProposedTransaction<A>,
) -> Result<(), AgentPublicationRefusal> {
    if overlay.entries().len() > MAX_PUBLICATION_OBJECTS
        || export.object_count() > MAX_PUBLICATION_OBJECTS
        || proposal.receipt().touched_paths.len() > MAX_PUBLICATION_OBJECTS
        || proposal.ref_intents().len() > fgit_authority::MAX_REF_COMMANDS
    {
        return Err(AgentPublicationRefusal::Limit("change_entries"));
    }
    let mut metadata = 0;
    let mut bodies = 0;
    for (path, entry) in overlay.entries() {
        bounded_add(
            &mut metadata,
            path.as_bytes().len(),
            MAX_PUBLICATION_METADATA_BYTES,
            "change_metadata",
        )?;
        if let Some(id) = entry.content_id() {
            let body = overlay
                .content()
                .get(id)
                .ok_or(AgentPublicationRefusal::OverlayInvalid)?;
            bounded_add(
                &mut bodies,
                body.len(),
                MAX_PUBLICATION_BYTES,
                "overlay_bodies",
            )?;
            if ContentId::of(body) != id {
                return Err(AgentPublicationRefusal::OverlayInvalid);
            }
        }
        match entry {
            OverlayEntry::File { class, .. } => {
                if let Some((oid, from)) = entry.base_carry() {
                    bounded_add(
                        &mut metadata,
                        oid.len(),
                        MAX_PUBLICATION_METADATA_BYTES,
                        "change_metadata",
                    )?;
                    bounded_add(
                        &mut metadata,
                        from.as_bytes().len(),
                        MAX_PUBLICATION_METADATA_BYTES,
                        "change_metadata",
                    )?;
                }
                if let EntryClass::Generated { producer } = class {
                    bounded_add(
                        &mut metadata,
                        producer.len(),
                        MAX_PUBLICATION_METADATA_BYTES,
                        "change_metadata",
                    )?;
                }
            }
            OverlayEntry::Submodule { commit } => bounded_add(
                &mut metadata,
                commit.len(),
                MAX_PUBLICATION_METADATA_BYTES,
                "change_metadata",
            )?,
            OverlayEntry::Conflict { .. } => return Err(AgentPublicationRefusal::OverlayInvalid),
            OverlayEntry::Symlink { .. } | OverlayEntry::Directory | OverlayEntry::Whiteout => {}
        }
    }
    for path in &proposal.receipt().touched_paths {
        bounded_add(
            &mut metadata,
            path.as_bytes().len(),
            MAX_PUBLICATION_METADATA_BYTES,
            "change_metadata",
        )?;
    }
    for intent in proposal.ref_intents() {
        bounded_add(
            &mut metadata,
            intent.name.len(),
            MAX_PUBLICATION_METADATA_BYTES,
            "change_metadata",
        )?;
    }
    let mut bytes = 0;
    for object in export.objects() {
        bounded_add(
            &mut bytes,
            object.body().len(),
            MAX_PUBLICATION_BYTES,
            "export_bodies",
        )?;
    }
    Ok(())
}

fn export_commitment<A: GitHashAlgorithm>(
    export: &ExportPlan<A>,
) -> Result<[u8; 32], AgentPublicationRefusal> {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(b"frankengit.agent.publication-export/v1\0");
    let mut header = Encoder::new();
    header.write_git_hash_algorithm(A::OBJECT_FORMAT);
    header.write_git_oid(&export.root_tree().erase());
    header.write_scalar(export.object_count() as u64);
    header.write_scalar(export.reused_base_objects() as u64);
    hasher.update(&header.into_bytes());
    for object in export.objects() {
        if !object.verify() {
            return Err(AgentPublicationRefusal::ExportBinding);
        }
        hasher.update(&[match object.kind() {
            GitObjectKind::Blob => 1,
            GitObjectKind::Tree => 2,
            GitObjectKind::Commit => 3,
            GitObjectKind::Tag => 4,
        }]);
        hasher.update(&(object.oid().digest_bytes().len() as u64).to_be_bytes());
        hasher.update(object.oid().digest_bytes());
        hasher.update(&(object.body().len() as u64).to_be_bytes());
        hasher.update(object.body());
    }
    Ok(hasher.finish())
}

fn check_evidence_bounds<A: GitHashAlgorithm>(
    input: &AgentPublicationEvidence<'_, A>,
) -> Result<(), AgentPublicationRefusal> {
    let change = input.change;
    for (field, count) in [
        ("evidence", change.evidence.len()),
        ("verifiers", change.verifiers.len()),
        ("dispositions", change.requirement_dispositions.len()),
        ("non_claims", change.non_claims.len()),
        ("requirements", input.requirements.len()),
    ] {
        if count > MAX_PUBLICATION_EVIDENCE_RECORDS {
            return Err(AgentPublicationRefusal::Limit(field));
        }
    }
    if input.policy.required_classes.len() > EvidenceClass::ALL.len()
        || input.policy.required_independence.len() > IndependenceDimension::ALL.len()
    {
        return Err(AgentPublicationRefusal::Limit("policy"));
    }
    let mut references = 0;
    for result in input.requirements {
        bounded_add(
            &mut references,
            result.evidence().len(),
            MAX_PUBLICATION_EVIDENCE_REFERENCES,
            "evidence_references",
        )?;
        bounded_add(
            &mut references,
            result.verifier_ids().len(),
            MAX_PUBLICATION_EVIDENCE_REFERENCES,
            "evidence_references",
        )?;
    }
    Ok(())
}

fn validate_requirements(
    plan: &AgentChangePlan,
    change: &EvidenceCarryingChange,
    results: &[LearningRequirementOutcome],
) -> Result<Vec<LearningRequirementOutcome>, AgentPublicationRefusal> {
    if results.len() != plan.evidence_plan().len()
        || change.requirement_dispositions.len() != plan.evidence_plan().len()
    {
        return Err(AgentPublicationRefusal::RequirementSet);
    }
    let mut artifacts = BTreeSet::new();
    let mut verifiers = BTreeSet::new();
    if change
        .evidence
        .iter()
        .any(|record| !artifacts.insert(record.artifact))
        || change
            .verifiers
            .iter()
            .any(|attestation| !verifiers.insert(attestation.verifier))
    {
        return Err(AgentPublicationRefusal::DuplicateEvidence);
    }
    let mut ordered: Vec<_> = results.iter().collect();
    ordered.sort_unstable_by_key(|result| result.requirement_id());
    let mut canonical = Vec::with_capacity(ordered.len());
    for ((requirement, result), disposition) in plan
        .evidence_plan()
        .iter()
        .zip(ordered)
        .zip(&change.requirement_dispositions)
    {
        let id = requirement.requirement_id();
        if result.requirement_id() != id {
            return Err(AgentPublicationRefusal::RequirementSet);
        }
        if *disposition != Some(result.disposition())
            || result.disposition() != RequirementDisposition::SatisfiedWithEvidence
        {
            return Err(AgentPublicationRefusal::RequirementUnsatisfied(id));
        }
        let mut evidence = result.evidence().to_vec();
        evidence.sort_unstable_by_key(|record| record.artifact);
        if evidence
            .windows(2)
            .any(|pair| pair[0].artifact == pair[1].artifact)
            || evidence
                .iter()
                .any(|record| !record.class.supports_a_claim() || !change.evidence.contains(record))
            || !evidence
                .iter()
                .any(|record| record.class == requirement.evidence_class())
        {
            return Err(AgentPublicationRefusal::RequirementEvidence(id));
        }
        let mut ids = result.verifier_ids().to_vec();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1])
            || ids.iter().any(|id| {
                !change
                    .verifiers
                    .iter()
                    .any(|attestation| attestation.verifier == *id && attestation.upheld)
            })
        {
            return Err(AgentPublicationRefusal::RequirementVerifier(id));
        }
        if requirement.requires_independent_verifier()
            && !ids.iter().any(|id| {
                change.verifiers.iter().any(|attestation| {
                    attestation.verifier == *id
                        && attestation.upheld
                        && classify_independence(&change.producer, attestation)
                            .is_fully_independent()
                })
            })
        {
            return Err(AgentPublicationRefusal::RequirementIndependence(id));
        }
        canonical.push(LearningRequirementOutcome::new(
            id,
            result.disposition(),
            evidence,
            ids,
            result.reason_root(),
        ));
    }
    Ok(canonical)
}

fn check_policy_verifiers(
    change: &EvidenceCarryingChange,
    policy: &EccPolicy,
) -> Result<(), AgentPublicationRefusal> {
    if policy.requires_verifier
        && !change
            .verifiers
            .iter()
            .any(|attestation| attestation.upheld)
    {
        return Err(AgentPublicationRefusal::PolicyVerifier);
    }
    for dimension in &policy.required_independence {
        if !change.verifiers.iter().any(|attestation| {
            attestation.upheld
                && classify_independence(&change.producer, attestation)
                    .is_independent_on(*dimension)
        }) {
            return Err(AgentPublicationRefusal::PolicyVerifier);
        }
    }
    Ok(())
}

fn write_policy(out: &mut Encoder, policy: &EccPolicy) {
    // Membership is set-valued even when the caller repeats or reorders it.
    for class in EvidenceClass::ALL {
        out.write_bool(policy.required_classes.contains(class));
    }
    for dimension in IndependenceDimension::ALL {
        out.write_bool(policy.required_independence.contains(dimension));
    }
    out.write_bool(policy.requires_verifier);
    out.write_bool(policy.requires_refreshed_authority);
    out.write_bool(policy.requires_completed_refresh);
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finish()
}
