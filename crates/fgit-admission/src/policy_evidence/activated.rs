//! Exact schema 1.2: the authority-selected repository DSL and its decision.
use super::*;

/// The review gate is different for direct writes and native merges. Both
/// evaluate the same activated repository policy over their exact ref effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefPolicyPublication {
    Direct,
    NativeMerge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivatedPolicyDecisionEvidence {
    pub(super) references: EvaluatedPolicyDecisionEvidence,
    publication: RefPolicyPublication,
    evaluation: RefPolicyEvaluation,
}
impl ActivatedPolicyDecisionEvidence {
    #[must_use]
    pub const fn publication(&self) -> RefPolicyPublication {
        self.publication
    }
    #[must_use]
    pub const fn evaluation(&self) -> &RefPolicyEvaluation {
        &self.evaluation
    }
    #[must_use]
    pub const fn references(&self) -> &EvaluatedPolicyDecisionEvidence {
        &self.references
    }

    pub(crate) fn evaluate(
        base: PolicyDecisionEvidence,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        current: &CanonicalRefState,
        layout: RootLayoutVersion,
        fold: &TransactionFoldReport,
        review_branches: Vec<RefName>,
        snapshot: PolicySnapshot,
        publication: RefPolicyPublication,
    ) -> Result<Self, RefusalCode> {
        let references = EvaluatedPolicyDecisionEvidence::evaluate(
            base,
            context,
            basis,
            current,
            layout,
            fold,
            match publication {
                RefPolicyPublication::Direct => review_branches,
                RefPolicyPublication::NativeMerge => Vec::new(),
            },
        )?;
        let evaluation = RefPolicyEvaluation::evaluate(
            Profile::RepositoryRefV1,
            snapshot,
            references.principal,
            references.base.principal_snapshot_id,
            references.subjects(Profile::RepositoryRefV1)?,
        )?;
        let value = Self {
            references,
            publication,
            evaluation,
        };
        value.verify_decision(context, basis, fold)?;
        let bytes = encode_body(&value).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(value)
    }

    pub fn replay(&self) -> Result<(), RefusalCode> {
        self.references.replay()?;
        if self.evaluation.profile != Profile::RepositoryRefV1
            || (self.publication == RefPolicyPublication::NativeMerge
                && !self.references.review_branches.is_empty())
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let actual = RefPolicyEvaluation::evaluate(
            Profile::RepositoryRefV1,
            self.evaluation.snapshot.clone(),
            self.references.principal,
            self.references.base.principal_snapshot_id,
            self.references.subjects(Profile::RepositoryRefV1)?,
        )?;
        if actual != self.evaluation {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }

    /// A self-consistent allowing snapshot is insufficient: it must be the
    /// exact snapshot selected by the original authenticated forge frontier.
    pub fn verify_provenance(
        &self,
        basis: &PublicationBasis,
        current: &CanonicalRefState,
        layout: RootLayoutVersion,
        review_branches: &[RefName],
        selected: &PolicySnapshot,
    ) -> Result<(), RefusalCode> {
        if selected != &self.evaluation.snapshot {
            return Err(RefusalCode::EvidenceInvalid);
        }
        self.references.verify_provenance(
            basis,
            current,
            layout,
            match self.publication {
                RefPolicyPublication::Direct => review_branches,
                RefPolicyPublication::NativeMerge => &[],
            },
        )?;
        self.replay()
    }

    pub(super) fn verify_decision(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        fold: &TransactionFoldReport,
    ) -> Result<(), RefusalCode> {
        self.references.verify_decision(context, basis, fold)?;
        if self.publication == RefPolicyPublication::NativeMerge {
            let effects = fold.effects().ok_or(RefusalCode::EvidenceInvalid)?;
            let mut events = effects.forge.values().flatten();
            let Some(fgit_reference::intent::ForgeEventKind::PullRequestMerged { target, .. }) =
                events.next()
            else {
                return Err(RefusalCode::EvidenceInvalid);
            };
            if events.next().is_some()
                || self.references.inputs.len() != 1
                || self.references.inputs[0].name() != target
                || self.references.inputs[0].next.is_none()
            {
                return Err(RefusalCode::EvidenceInvalid);
            }
        }
        self.replay()
    }
}

impl CanonicalBody for ActivatedPolicyDecisionEvidence {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 2;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        let references = encode_body(&self.references)?;
        bound(
            "policy_decision.references",
            references.len(),
            MAX_FRAME_BYTES,
        )?;
        out.write_bytes("policy_decision.references", &references)?;
        out.write_raw_byte(match self.publication {
            RefPolicyPublication::Direct => 1,
            RefPolicyPublication::NativeMerge => 2,
        });
        out.write_internal_object_id(self.evaluation.snapshot_id().as_internal_object_id())?;
        let frame = self.evaluation.snapshot.encode()?;
        bound("policy_decision.snapshot", frame.len(), MAX_SNAPSHOT_BYTES)?;
        out.write_bytes("policy_decision.snapshot", &frame)?;
        out.write_raw_byte(self.evaluation.decision.code_point());
        bound(
            "policy_decision.trace",
            self.evaluation.trace.len(),
            MAX_TRACE_BYTES,
        )?;
        out.write_text("policy_decision.trace", &self.evaluation.trace)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let frame = input.read_bytes("policy_decision.references")?;
        bound("policy_decision.references", frame.len(), MAX_FRAME_BYTES)?;
        let mut limits = input.limits();
        limits.depth = limits.depth.saturating_sub(1);
        let references = decode_body::<EvaluatedPolicyDecisionEvidence>(frame, limits)?;
        if encode_body(&references)? != frame {
            return Err(invalid("policy_decision.references"));
        }
        let publication = match input.read_raw_byte("policy_decision.publication")? {
            1 => RefPolicyPublication::Direct,
            2 => RefPolicyPublication::NativeMerge,
            _ => return Err(invalid("policy_decision.publication")),
        };
        let id = PolicySnapshotId::from_internal_object_id(input.read_internal_object_id()?)?;
        let frame = input.read_bytes("policy_decision.snapshot")?;
        bound("policy_decision.snapshot", frame.len(), MAX_SNAPSHOT_BYTES)?;
        let snapshot = PolicySnapshot::decode(
            frame,
            DecodeLimits {
                frame_bytes: (MAX_SNAPSHOT_BYTES as u64).min(limits.frame_bytes),
                // Canonical framing counts the complete snapshot payload as
                // one byte string; replay independently bounds its literals.
                byte_string_bytes: (MAX_SNAPSHOT_BYTES as u64).min(limits.byte_string_bytes),
                elements: 4096.min(limits.elements),
                depth: 32.min(limits.depth),
            },
        )?;
        if snapshot.id() != id || snapshot.encode()? != frame {
            return Err(invalid("policy_decision.snapshot_identity"));
        }
        let decision = Decision::from_code_point(input.read_raw_byte("policy_decision.verdict")?)
            .ok_or_else(|| invalid("policy_decision.verdict"))?;
        let trace = input.read_text("policy_decision.trace")?;
        bound("policy_decision.trace", trace.len(), MAX_TRACE_BYTES)?;
        let value = Self {
            references,
            publication,
            evaluation: RefPolicyEvaluation {
                profile: Profile::RepositoryRefV1,
                snapshot,
                decision,
                trace: trace.to_owned(),
            },
        };
        value
            .replay()
            .map_err(|_| invalid("policy_decision.activated_replay"))?;
        Ok(value)
    }
}
