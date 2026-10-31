//! Exact-version policy evidence. Schema 1.0 remains byte-stable; schema 1.1
//! retains the evaluated snapshot and native ref facts inside the RCR's body.
//!
//! The two version-one profiles below are deliberately reference-only. Native
//! authority-selected names select subjects before the policy engine runs, so
//! byte-oriented refs never become source text or wildcard patterns. No actor
//! strength, ancestry, clock, required-check receipt or merge approval is
//! invented by this profile.

use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    CanonicalBody, CodecRefusal, DecodeLimits, Decoder, Encoder, decode_body, encode_body,
    read_frame_header,
};
use fgit_policy::program::{
    CompiledPolicy, CompiledRule, DenyReason, PolicyName, Predicate, RuleId, RuleOutcome,
};
use fgit_policy::{
    Decision, PolicyInstant, PolicySnapshot, PolicySnapshotBody, PolicySnapshotId, RefUpdateFact,
    RefUpdateKind,
};
use fgit_reference::effect::RefEffect;
use fgit_txn::TransactionFoldReport;
use fgit_types::{
    Digest, DomainTag, GitOid, PrincipalId, RefName, RefusalCode, RepositoryAuthorityHeadId,
    RootLayoutVersion, SchemaFamily,
};

use super::{AdmissionAuthentication, PolicyDecisionEvidence, evidence_root};
use crate::{AdmissionContext, CanonicalRefState};

const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_TRACE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024;
const MAX_SUBJECTS: usize = fgit_policy::basis::MAX_SUBJECTS;

#[path = "policy_evidence/activated.rs"]
mod activated;
pub use activated::{ActivatedPolicyDecisionEvidence, RefPolicyPublication};
#[path = "policy_evidence/actor.rs"]
mod actor;
pub use actor::ActorPolicyDecisionEvidence;
#[path = "policy_evidence/authentication.rs"]
mod authentication;
pub use authentication::AuthenticationPolicyDecisionEvidence;

/// Exact supported policy-evidence minor. The legacy variant is not a claim
/// that the historical record retained an evaluated compiled snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecisionRecord {
    Legacy(PolicyDecisionEvidence),
    Evaluated(Box<EvaluatedPolicyDecisionEvidence>),
    Activated(Box<ActivatedPolicyDecisionEvidence>),
    ActorActivated(Box<ActorPolicyDecisionEvidence>),
    AuthenticationActivated(Box<AuthenticationPolicyDecisionEvidence>),
}

impl PolicyDecisionRecord {
    #[must_use]
    pub fn base(&self) -> &PolicyDecisionEvidence {
        match self {
            Self::Legacy(body) => body,
            Self::Evaluated(body) => &body.base,
            Self::Activated(body) => &body.references.base,
            Self::ActorActivated(body) => &body.0.references.base,
            Self::AuthenticationActivated(body) => &body.0.references.base,
        }
    }

    pub fn root(&self) -> Result<Digest, RefusalCode> {
        match self {
            Self::Legacy(body) => evidence_root(body),
            Self::Evaluated(body) => evidence_root(body.as_ref()),
            Self::Activated(body) => evidence_root(body.as_ref()),
            Self::ActorActivated(body) => evidence_root(body.as_ref()),
            Self::AuthenticationActivated(body) => evidence_root(body.as_ref()),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecRefusal> {
        match self {
            Self::Legacy(body) => encode_body(body),
            Self::Evaluated(body) => {
                let bytes = encode_body(body.as_ref())?;
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Ok(bytes)
            }
            Self::Activated(body) => {
                let bytes = encode_body(body.as_ref())?;
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Ok(bytes)
            }
            Self::ActorActivated(body) => {
                let bytes = encode_body(body.as_ref())?;
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Ok(bytes)
            }
            Self::AuthenticationActivated(body) => {
                let bytes = encode_body(body.as_ref())?;
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Ok(bytes)
            }
        }
    }

    /// Decode the exact declared minor, verify its complete canonical encoding,
    /// and replay an evaluated profile before returning it. Unknown minors,
    /// trailing data and substituted snapshot/trace bytes fail closed.
    pub fn decode(bytes: &[u8], limits: DecodeLimits) -> Result<Self, CodecRefusal> {
        let (header, _) = read_frame_header(bytes, limits)?;
        if header.domain != PolicyDecisionEvidence::DOMAIN {
            return Err(CodecRefusal::domain_unexpected(
                PolicyDecisionEvidence::DOMAIN,
                header.domain,
            ));
        }
        let value = match header.schema.minor() {
            0 => Self::Legacy(decode_body::<PolicyDecisionEvidence>(bytes, limits)?),
            1 => {
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Self::Evaluated(Box::new(decode_body::<EvaluatedPolicyDecisionEvidence>(
                    bytes, limits,
                )?))
            }
            2 => {
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Self::Activated(Box::new(decode_body::<ActivatedPolicyDecisionEvidence>(
                    bytes, limits,
                )?))
            }
            3 => {
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Self::ActorActivated(Box::new(decode_body::<ActorPolicyDecisionEvidence>(
                    bytes, limits,
                )?))
            }
            4 => {
                bound("policy_decision.frame", bytes.len(), MAX_FRAME_BYTES)?;
                Self::AuthenticationActivated(Box::new(decode_body::<
                    AuthenticationPolicyDecisionEvidence,
                >(bytes, limits)?))
            }
            minor => {
                return Err(CodecRefusal::schema_minor_unsupported(
                    PolicyDecisionEvidence::DOMAIN,
                    minor,
                    4,
                ));
            }
        };
        if value.encode()? != bytes {
            return Err(invalid("policy_decision.noncanonical"));
        }
        Ok(value)
    }

    /// Structural provenance shared by both evaluated evidence versions.
    #[must_use]
    pub fn evaluated(&self) -> Option<&EvaluatedPolicyDecisionEvidence> {
        match self {
            Self::Legacy(_) => None,
            Self::Evaluated(body) => Some(body),
            Self::Activated(body) => Some(&body.references),
            Self::ActorActivated(body) => Some(&body.0.references),
            Self::AuthenticationActivated(body) => Some(&body.0.references),
        }
    }

    /// Authentication recorded by the exact evidence schema. Old records do
    /// not acquire facts from the current request or a later credential.
    #[must_use]
    pub fn authentication(&self) -> Option<AdmissionAuthentication> {
        match self {
            Self::AuthenticationActivated(body) => Some(body.authentication()),
            _ => None,
        }
    }

    pub(super) fn verify_decision(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        fold: &TransactionFoldReport,
    ) -> Result<(), RefusalCode> {
        match self {
            Self::Legacy(_) => Ok(()),
            Self::Evaluated(body) => body.verify_decision(context, basis, fold),
            Self::Activated(body) => body.verify_decision(context, basis, fold),
            Self::ActorActivated(body) => body.verify_decision(context, basis, fold),
            Self::AuthenticationActivated(body) => body.verify_decision(context, basis, fold),
        }
    }
}

/// One actual engine evaluation. The immutable snapshot bytes are embedded so
/// retention/export of this policy body cannot leave its named policy behind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefPolicyEvaluation {
    profile: Profile,
    snapshot: PolicySnapshot,
    decision: Decision,
    trace: String,
}

/// The native facts actually known by a ref-only gate. Ancestry and the wire
/// force intent are deliberately absent, rather than encoded as invented facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefPolicyInput {
    name: RefName,
    previous: Option<GitOid>,
    next: Option<GitOid>,
}

impl RefPolicyInput {
    #[must_use]
    pub const fn name(&self) -> &RefName {
        &self.name
    }
    #[must_use]
    pub const fn previous(&self) -> Option<&GitOid> {
        self.previous.as_ref()
    }
    #[must_use]
    pub const fn next(&self) -> Option<&GitOid> {
        self.next.as_ref()
    }

    fn evaluator_fact(&self) -> Result<RefUpdateFact, RefusalCode> {
        let kind = match (self.previous, self.next) {
            (None, Some(_)) => RefUpdateKind::Create,
            (Some(_), Some(_)) => RefUpdateKind::UnclassifiedUpdate,
            (Some(_), None) => RefUpdateKind::Delete,
            (None, None) => return Err(RefusalCode::EvidenceInvalid),
        };
        RefUpdateFact::try_new(self.name.clone(), self.previous, self.next, kind, false)
            .map_err(|_| RefusalCode::EvidenceInvalid)
    }
}

impl RefPolicyEvaluation {
    #[must_use]
    pub const fn snapshot_id(&self) -> PolicySnapshotId {
        self.snapshot.id()
    }
    #[must_use]
    pub const fn snapshot(&self) -> &PolicySnapshot {
        &self.snapshot
    }
    #[must_use]
    pub const fn decision(&self) -> Decision {
        self.decision
    }
    #[must_use]
    pub fn trace(&self) -> &str {
        &self.trace
    }

    fn evaluate(
        profile: Profile,
        snapshot: PolicySnapshot,
        principal: PrincipalId,
        principal_snapshot: fgit_types::PrincipalSnapshotId,
        inputs: Vec<RefUpdateFact>,
    ) -> Result<Self, RefusalCode> {
        Self::evaluate_with_authentication(
            profile,
            snapshot,
            principal,
            principal_snapshot,
            inputs,
            None,
        )
    }

    fn evaluate_with_authentication(
        profile: Profile,
        snapshot: PolicySnapshot,
        principal: PrincipalId,
        principal_snapshot: fgit_types::PrincipalSnapshotId,
        inputs: Vec<RefUpdateFact>,
        authentication: Option<AdmissionAuthentication>,
    ) -> Result<Self, RefusalCode> {
        // Bound work and possible trace growth BEFORE allocating the evaluator's
        // subject/visit graph. Frozen profiles have one rule; installed policies
        // also reserve their bounded rule/predicate multiplicity.
        if let Some(reference_profile) = profile.reference_profile() {
            fgit_policy::reference_profile::validate_evaluation_for(
                reference_profile,
                &snapshot,
                inputs.iter().map(RefUpdateFact::name),
            )
            .map_err(|_| RefusalCode::ResourceBudgetExceeded)?;
        }
        let estimate = inputs
            .iter()
            .try_fold(0_usize, |used, fact| {
                used.checked_add(
                    fact.name()
                        .as_bytes()
                        .len()
                        .saturating_mul(4)
                        .saturating_add(1024),
                )
            })
            .ok_or(RefusalCode::ResourceBudgetExceeded)?;
        if estimate > MAX_TRACE_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        if !profile.accepts(&snapshot) {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let evaluation = match (profile, authentication) {
            (Profile::RepositoryAuthenticationV1, Some(authentication)) => {
                let input = fgit_policy::reference_profile::AuthenticatedReferenceInput::try_new(
                    principal,
                    authentication.authentication_strength(),
                    inputs,
                )
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
                fgit_policy::reference_profile::evaluate_authenticated(&snapshot, &input)
                    .map_err(|_| RefusalCode::ProtectedRefTransitionDenied)?
            }
            (Profile::RepositoryAuthenticationV1, None) | (_, Some(_)) => {
                return Err(RefusalCode::EvidenceInvalid);
            }
            (_, None) => {
                // Frozen historical profiles retain their exact evaluation.
                // Their complete program validation excludes every unavailable
                // compatibility field, including authentication.
                let input = crate::policy_bridge::build_input_root(
                    principal,
                    principal_snapshot,
                    inputs,
                    PolicyInstant::from_seconds(0),
                )
                .map_err(|_| RefusalCode::EvidenceInvalid)?;
                fgit_policy::evaluate(&snapshot, &input)
                    .map_err(|_| RefusalCode::ProtectedRefTransitionDenied)?
            }
        };
        if evaluation.decision() != Decision::Allow {
            return Err(RefusalCode::ProtectedRefTransitionDenied);
        }
        let trace = fgit_policy::render_trace(&evaluation);
        if trace.len() > MAX_TRACE_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(Self {
            profile,
            snapshot,
            decision: evaluation.decision(),
            trace,
        })
    }
}

/// Reference-only decision evidence produced at the real final publication
/// gate. Its provenance is the authenticated head and the driver's exact ref
/// overlay. Required-check and merge-review proofs remain their existing gates;
/// this body never claims that either was evaluated by these two snapshots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedPolicyDecisionEvidence {
    base: PolicyDecisionEvidence,
    basis: RepositoryAuthorityHeadId,
    principal: PrincipalId,
    ref_basis_root: Digest,
    head_target: Option<RefName>,
    review_branches: Vec<RefName>,
    inputs: Vec<RefPolicyInput>,
    evaluations: Vec<RefPolicyEvaluation>,
}

impl EvaluatedPolicyDecisionEvidence {
    #[must_use]
    pub const fn basis(&self) -> RepositoryAuthorityHeadId {
        self.basis
    }
    #[must_use]
    pub const fn ref_basis_root(&self) -> Digest {
        self.ref_basis_root
    }
    #[must_use]
    pub fn evaluations(&self) -> &[RefPolicyEvaluation] {
        &self.evaluations
    }
    #[must_use]
    pub fn inputs(&self) -> &[RefPolicyInput] {
        &self.inputs
    }

    pub(super) fn evaluate(
        base: PolicyDecisionEvidence,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        current: &CanonicalRefState,
        layout: RootLayoutVersion,
        fold: &TransactionFoldReport,
        mut review_branches: Vec<RefName>,
    ) -> Result<Self, RefusalCode> {
        let effects = fold.effects().ok_or(RefusalCode::EvidenceInvalid)?;
        if effects.refs.len() > MAX_SUBJECTS {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        review_branches.sort();
        review_branches.dedup();
        let inputs = effects
            .refs
            .iter()
            .map(|(name, effect)| RefPolicyInput {
                name: name.clone(),
                previous: current.refs().get(name).copied(),
                next: match effect {
                    RefEffect::Set(oid) => Some(*oid),
                    RefEffect::Delete => None,
                },
            })
            .collect();
        let mut value = Self {
            base,
            basis: basis.id(),
            principal: context.principal_id,
            ref_basis_root: crate::ref_state_root(layout, current)?,
            head_target: current.head_target().cloned(),
            review_branches,
            inputs,
            evaluations: Vec::new(),
        };
        value.check_bounds()?;
        for profile in value.profiles() {
            value.evaluations.push(RefPolicyEvaluation::evaluate(
                profile,
                profile
                    .snapshot()
                    .map_err(|_| RefusalCode::CanonicalFramingInvalid)?,
                value.principal,
                value.base.principal_snapshot_id,
                value.subjects(profile)?,
            )?);
        }
        // Refuse oversized output before it can be staged or named by an RCR.
        let bytes = encode_body(&value).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(value)
    }

    /// Verify provenance against the authority-selected repository policy and
    /// the exact materialized overlay, rather than trusting embedded selectors.
    pub fn verify_provenance(
        &self,
        basis: &PublicationBasis,
        current: &CanonicalRefState,
        layout: RootLayoutVersion,
        review_branches: &[RefName],
    ) -> Result<(), RefusalCode> {
        let mut selected = review_branches.to_vec();
        selected.sort();
        selected.dedup();
        if basis.id() != self.basis
            || basis.body().policy_epoch != self.base.policy_epoch
            || current.head_target() != self.head_target.as_ref()
            || crate::ref_state_root(layout, current)? != self.ref_basis_root
            || selected != self.review_branches
            || self
                .inputs
                .iter()
                .any(|fact| current.refs().get(fact.name()) != fact.previous())
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        self.replay()
    }

    pub(super) fn verify_decision(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        fold: &TransactionFoldReport,
    ) -> Result<(), RefusalCode> {
        if context.principal_id != self.principal
            || basis.id() != self.basis
            || basis.body().policy_epoch != self.base.policy_epoch
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let effects = fold.effects().ok_or(RefusalCode::EvidenceInvalid)?;
        if self.inputs.len() != effects.refs.len()
            || self
                .inputs
                .iter()
                .any(|fact| match effects.refs.get(fact.name()) {
                    Some(RefEffect::Set(oid)) => fact.next() != Some(oid),
                    Some(RefEffect::Delete) => fact.next().is_some(),
                    None => true,
                })
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        self.replay()
    }

    /// Replay the stored snapshot bytes and exact recorded native inputs.
    /// Neither policy source text nor today's compiler is consulted.
    pub fn replay(&self) -> Result<(), RefusalCode> {
        self.check_bounds()?;
        let profiles = self.profiles();
        if profiles.len() != self.evaluations.len() {
            return Err(RefusalCode::EvidenceInvalid);
        }
        for (profile, recorded) in profiles.into_iter().zip(&self.evaluations) {
            if profile != recorded.profile {
                return Err(RefusalCode::EvidenceInvalid);
            }
            let replayed = RefPolicyEvaluation::evaluate(
                profile,
                recorded.snapshot.clone(),
                self.principal,
                self.base.principal_snapshot_id,
                self.subjects(profile)?,
            )?;
            if replayed != *recorded {
                return Err(RefusalCode::EvidenceInvalid);
            }
        }
        Ok(())
    }

    fn profiles(&self) -> Vec<Profile> {
        let mut profiles = Vec::with_capacity(2);
        if self.head_target.is_some() {
            profiles.push(Profile::HeadDeletionV1);
        }
        profiles.push(Profile::DirectReviewV1);
        profiles
    }

    fn subjects(&self, profile: Profile) -> Result<Vec<RefUpdateFact>, RefusalCode> {
        self.inputs
            .iter()
            .filter(|fact| match profile {
                Profile::HeadDeletionV1 => self.head_target.as_ref() == Some(fact.name()),
                Profile::DirectReviewV1 => self.review_branches.binary_search(fact.name()).is_ok(),
                Profile::RepositoryRefV1
                | Profile::RepositoryActorIdV1
                | Profile::RepositoryAuthenticationV1 => true,
            })
            .map(RefPolicyInput::evaluator_fact)
            .collect()
    }

    fn check_bounds(&self) -> Result<(), RefusalCode> {
        if self.inputs.len() > MAX_SUBJECTS
            || self.review_branches.len() > MAX_SUBJECTS
            || !self
                .inputs
                .windows(2)
                .all(|pair| pair[0].name() < pair[1].name())
            || !self
                .review_branches
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self
                .inputs
                .iter()
                .any(|fact| fact.previous.is_none() && fact.next.is_none())
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let bytes = self
            .inputs
            .iter()
            .map(|fact| fact.name().as_bytes().len().saturating_add(80))
            .fold(0_usize, usize::saturating_add)
            .saturating_add(
                self.review_branches
                    .iter()
                    .map(|name| name.as_bytes().len().saturating_add(4))
                    .sum::<usize>(),
            );
        if bytes > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(())
    }
}

// These are frozen evidence-profile semantics, not a call to the evolving
// source compiler. Changing either requires a new profile/schema, never a new
// interpretation of a stored 1.1 record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    HeadDeletionV1,
    DirectReviewV1,
    RepositoryRefV1,
    RepositoryActorIdV1,
    RepositoryAuthenticationV1,
}

impl Profile {
    const fn reference_profile(
        self,
    ) -> Option<fgit_policy::reference_profile::ReferencePolicyProfile> {
        use fgit_policy::reference_profile::ReferencePolicyProfile;
        match self {
            Self::RepositoryRefV1 => Some(ReferencePolicyProfile::ReferenceFactsV1),
            Self::RepositoryActorIdV1 => Some(ReferencePolicyProfile::ReferenceActorIdV1),
            Self::RepositoryAuthenticationV1 => {
                Some(ReferencePolicyProfile::ReferenceAuthenticationV1)
            }
            Self::HeadDeletionV1 | Self::DirectReviewV1 => None,
        }
    }
    const fn code(self) -> u8 {
        match self {
            Self::HeadDeletionV1 => 1,
            Self::DirectReviewV1 => 2,
            Self::RepositoryRefV1 => 3,
            Self::RepositoryActorIdV1 => 4,
            Self::RepositoryAuthenticationV1 => 5,
        }
    }
    const fn name(self) -> &'static str {
        match self {
            Self::HeadDeletionV1 => "admission_head_deletion_v1",
            Self::DirectReviewV1 => "admission_direct_review_v1",
            Self::RepositoryRefV1 => "repository_ref_v1",
            Self::RepositoryActorIdV1 => "repository_ref_actor_id_v1",
            Self::RepositoryAuthenticationV1 => "repository_ref_authentication_v1",
        }
    }
    const fn reason(self) -> &'static str {
        match self {
            Self::HeadDeletionV1 => "default branch deletion is prohibited",
            Self::DirectReviewV1 => "direct update requires canonical review",
            Self::RepositoryRefV1
            | Self::RepositoryActorIdV1
            | Self::RepositoryAuthenticationV1 => "repository policy",
        }
    }
    const fn predicate(self) -> Predicate {
        match self {
            Self::HeadDeletionV1 => Predicate::UpdateKindEquals(RefUpdateKind::Delete),
            Self::DirectReviewV1 => Predicate::Always,
            Self::RepositoryRefV1
            | Self::RepositoryActorIdV1
            | Self::RepositoryAuthenticationV1 => Predicate::Never,
        }
    }

    fn snapshot(self) -> Result<PolicySnapshot, CodecRefusal> {
        if self.reference_profile().is_some() {
            return Err(invalid("policy_decision.repository_snapshot_required"));
        }
        let rule = CompiledRule::new(
            RuleId::try_new(b"protect")?,
            self.predicate(),
            RuleOutcome::Deny(DenyReason::new_truncating(self.reason())),
        );
        PolicySnapshot::seal(PolicySnapshotBody::new(CompiledPolicy::new(
            PolicyName::try_new(self.name().as_bytes())?,
            Vec::new(),
            Vec::new(),
            vec![rule],
            RuleOutcome::Allow,
        )))
    }

    fn accepts(self, snapshot: &PolicySnapshot) -> bool {
        if let Some(profile) = self.reference_profile() {
            return fgit_policy::reference_profile::classify(snapshot).ok() == Some(profile);
        }
        let policy = snapshot.policy();
        let rules = policy.rules();
        policy.name().as_str() == self.name()
            && policy.aggregates().is_empty()
            && policy.evidence().is_empty()
            && *policy.default_outcome() == RuleOutcome::Allow
            && rules.len() == 1
            && rules[0].id().as_str() == "protect"
            && *rules[0].predicate() == self.predicate()
            && rules[0].outcome().decision() == Decision::Deny
            && rules[0]
                .outcome()
                .reason()
                .is_some_and(|reason| reason.as_str() == self.reason())
    }
}

impl CanonicalBody for EvaluatedPolicyDecisionEvidence {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.base.write_payload(out)?;
        out.write_internal_object_id(self.basis.as_internal_object_id())?;
        out.write_opaque_id(self.principal.as_bytes());
        out.write_digest(&self.ref_basis_root)?;
        out.write_option(self.head_target.as_ref(), Encoder::write_ref_name)?;
        out.write_sequence(
            "policy_decision.review_branches",
            &self.review_branches,
            Encoder::write_ref_name,
        )?;
        out.write_sequence("policy_decision.inputs", &self.inputs, write_input)?;
        out.write_sequence(
            "policy_decision.evaluations",
            &self.evaluations,
            |out, value| {
                out.write_raw_byte(value.profile.code());
                out.write_internal_object_id(value.snapshot.id().as_internal_object_id())?;
                let frame = value.snapshot.encode()?;
                bound("policy_decision.snapshot", frame.len(), MAX_SNAPSHOT_BYTES)?;
                out.write_bytes("policy_decision.snapshot", &frame)?;
                out.write_raw_byte(value.decision.code_point());
                out.write_text("policy_decision.trace", &value.trace)
            },
        )
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let base = PolicyDecisionEvidence::read_payload(input)?;
        let basis =
            RepositoryAuthorityHeadId::from_internal_object_id(input.read_internal_object_id()?)?;
        let principal = PrincipalId::from_bytes(input.read_opaque_id("policy_decision.principal")?);
        let ref_basis_root = input.read_digest()?;
        let head_target =
            input.read_option("policy_decision.head_target", Decoder::read_ref_name)?;
        let review_branches = read_bounded_sequence(
            input,
            "policy_decision.review_branches",
            MAX_SUBJECTS,
            Decoder::read_ref_name,
        )?;
        let inputs =
            read_bounded_sequence(input, "policy_decision.inputs", MAX_SUBJECTS, read_input)?;
        let evaluations =
            read_bounded_sequence(input, "policy_decision.evaluations", 2, |input| {
                let profile = match input.read_raw_byte("policy_decision.profile")? {
                    1 => Profile::HeadDeletionV1,
                    2 => Profile::DirectReviewV1,
                    _ => return Err(invalid("policy_decision.profile")),
                };
                let id =
                    PolicySnapshotId::from_internal_object_id(input.read_internal_object_id()?)?;
                let frame = input.read_bytes("policy_decision.snapshot")?;
                bound("policy_decision.snapshot", frame.len(), MAX_SNAPSHOT_BYTES)?;
                let inherited = input.limits();
                let snapshot = PolicySnapshot::decode(
                    frame,
                    DecodeLimits {
                        frame_bytes: (MAX_SNAPSHOT_BYTES as u64).min(inherited.frame_bytes),
                        // This bound also covers the canonical payload envelope.
                        byte_string_bytes: (MAX_SNAPSHOT_BYTES as u64)
                            .min(inherited.byte_string_bytes),
                        elements: 16.min(inherited.elements),
                        depth: 8.min(inherited.depth.saturating_sub(1)),
                    },
                )?;
                if snapshot.id() != id || snapshot.encode()? != frame {
                    return Err(invalid("policy_decision.snapshot_identity"));
                }
                let decision =
                    Decision::from_code_point(input.read_raw_byte("policy_decision.verdict")?)
                        .ok_or_else(|| invalid("policy_decision.verdict"))?;
                let trace = input.read_text("policy_decision.trace")?;
                bound("policy_decision.trace", trace.len(), MAX_TRACE_BYTES)?;
                Ok(RefPolicyEvaluation {
                    profile,
                    snapshot,
                    decision,
                    trace: trace.to_owned(),
                })
            })?;
        let value = Self {
            base,
            basis,
            principal,
            ref_basis_root,
            head_target,
            review_branches,
            inputs,
            evaluations,
        };
        value
            .replay()
            .map_err(|_| invalid("policy_decision.replay"))?;
        Ok(value)
    }
}

fn write_input(out: &mut Encoder, fact: &RefPolicyInput) -> Result<(), CodecRefusal> {
    out.write_ref_name(fact.name())?;
    out.write_option(fact.previous(), |out, oid| {
        out.write_git_oid(oid);
        Ok(())
    })?;
    out.write_option(fact.next(), |out, oid| {
        out.write_git_oid(oid);
        Ok(())
    })?;
    Ok(())
}

fn read_input(input: &mut Decoder<'_>) -> Result<RefPolicyInput, CodecRefusal> {
    let name = input.read_ref_name()?;
    let previous = input.read_option("policy_decision.previous", Decoder::read_git_oid)?;
    let next = input.read_option("policy_decision.next", Decoder::read_git_oid)?;
    if previous.is_none() && next.is_none() {
        return Err(invalid("policy_decision.ref_shape"));
    }
    Ok(RefPolicyInput {
        name,
        previous,
        next,
    })
}

fn read_bounded_sequence<'a, T>(
    input: &mut Decoder<'a>,
    field: &'static str,
    maximum: usize,
    mut read: impl FnMut(&mut Decoder<'a>) -> Result<T, CodecRefusal>,
) -> Result<Vec<T>, CodecRefusal> {
    if input.limits().depth == 0 {
        return Err(CodecRefusal::DepthBoundExceeded {
            limit: 0,
            offset: input.offset(),
        });
    }
    let count = input.read_scalar::<u32>(field)? as usize;
    let limit = (maximum as u64).min(input.limits().elements);
    if count as u64 > limit {
        return Err(CodecRefusal::CountBoundExceeded {
            field,
            observed: count as u64,
            limit,
        });
    }
    if count > input.remaining() {
        return Err(CodecRefusal::InputTruncated {
            field,
            needed: count as u64,
            available: input.remaining() as u64,
            offset: input.offset(),
        });
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(read(input)?);
    }
    Ok(values)
}

const fn bound(field: &'static str, bytes: usize, maximum: usize) -> Result<(), CodecRefusal> {
    if bytes > maximum {
        Err(CodecRefusal::LengthBoundExceeded {
            field,
            observed: bytes as u64,
            limit: maximum as u64,
        })
    } else {
        Ok(())
    }
}

const fn invalid(field: &'static str) -> CodecRefusal {
    CodecRefusal::VariantUnknown {
        field,
        observed: 0,
        offset: 0,
    }
}

#[cfg(test)]
#[path = "policy_evidence/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "policy_evidence/authentication_tests.rs"]
mod authentication_tests;
