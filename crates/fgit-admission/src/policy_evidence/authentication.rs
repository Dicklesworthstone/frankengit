//! Exact authentication receipts: schema 1.4 retains historical transport
//! methods; schema 1.5 additionally retains a complete sponsored-agent witness.

use super::{
    ActivatedPolicyDecisionEvidence, AdmissionAuthentication, EvaluatedPolicyDecisionEvidence,
    MAX_FRAME_BYTES, PolicyDecisionEvidence, Profile, RefPolicyEvaluation, RefPolicyPublication,
    invalid,
};
use crate::evidence::AgentAuthentication;
use crate::{AdmissionContext, CanonicalRefState};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalBody, CodecRefusal, Decoder, Encoder, encode_body};
use fgit_policy::PolicySnapshot;
use fgit_txn::TransactionFoldReport;
use fgit_types::{DomainTag, RefName, RefusalCode, RootLayoutVersion, SchemaFamily};

/// The authentication provenance is immutable evidence, not a current request
/// lookup. The enclosing decision additionally checks it against the principal
/// snapshot named by the original RCR. Historical minors remain unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationPolicyDecisionEvidence(
    pub(super) ActivatedPolicyDecisionEvidence,
    AdmissionAuthentication,
);

impl AuthenticationPolicyDecisionEvidence {
    #[must_use]
    pub const fn authentication(&self) -> AdmissionAuthentication {
        self.1
    }

    #[must_use]
    pub const fn publication(&self) -> RefPolicyPublication {
        self.0.publication()
    }

    #[must_use]
    pub const fn evaluation(&self) -> &RefPolicyEvaluation {
        self.0.evaluation()
    }

    #[must_use]
    pub const fn references(&self) -> &EvaluatedPolicyDecisionEvidence {
        self.0.references()
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
        authentication: AdmissionAuthentication,
    ) -> Result<Self, RefusalCode> {
        if authentication.agent_provenance().is_some() {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let value = Self(
            ActivatedPolicyDecisionEvidence::evaluate_for(
                Profile::RepositoryAuthenticationV1,
                base,
                context,
                basis,
                current,
                layout,
                fold,
                review_branches,
                snapshot,
                publication,
                Some(authentication),
            )?,
            authentication,
        );
        let bytes = encode_body(&value).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(value)
    }

    pub fn replay(&self) -> Result<(), RefusalCode> {
        if self.0.evaluation().profile != Profile::RepositoryAuthenticationV1
            || self.0.authentication != Some(self.authentication())
            || self.authentication().agent_provenance().is_some()
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        self.0.replay()
    }

    pub fn verify_provenance(
        &self,
        basis: &PublicationBasis,
        current: &CanonicalRefState,
        layout: RootLayoutVersion,
        review_branches: &[RefName],
        selected: &PolicySnapshot,
    ) -> Result<(), RefusalCode> {
        self.0
            .verify_provenance(basis, current, layout, review_branches, selected)?;
        self.replay()
    }

    pub(super) fn verify_decision(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        fold: &TransactionFoldReport,
    ) -> Result<(), RefusalCode> {
        self.0.verify_decision(context, basis, fold)?;
        self.replay()
    }
}

impl CanonicalBody for AuthenticationPolicyDecisionEvidence {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 4;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.0.authentication != Some(self.authentication())
            || self.authentication().agent_provenance().is_some()
        {
            return Err(invalid("policy_decision.authentication"));
        }
        self.0
            .write_fields(out, Profile::RepositoryAuthenticationV1)?;
        out.write_scalar(self.authentication().code_point());
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let mut fields = ActivatedPolicyDecisionEvidence::read_fields_unverified(
            input,
            Profile::RepositoryAuthenticationV1,
        )?;
        let authentication = AdmissionAuthentication::from_code_point(
            input.read_scalar::<u64>("policy_decision.authentication")?,
        )?;
        fields.authentication = Some(authentication);
        let value = Self(fields, authentication);
        value
            .replay()
            .map_err(|_| invalid("policy_decision.authentication_replay"))?;
        Ok(value)
    }
}

/// Schema 1.5 evaluates the unchanged authentication-only policy profile while
/// preserving the complete sponsored credential and real run witness. The
/// profile does not acquire actor-kind, sponsor, membership or clock selectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentAuthenticationPolicyDecisionEvidence(
    pub(super) ActivatedPolicyDecisionEvidence,
    AgentAuthentication,
);

impl AgentAuthenticationPolicyDecisionEvidence {
    #[must_use]
    pub const fn authentication(&self) -> AdmissionAuthentication {
        AdmissionAuthentication::AgentCredential(self.1)
    }

    #[must_use]
    pub const fn agent_provenance(&self) -> &AgentAuthentication {
        &self.1
    }

    #[must_use]
    pub const fn publication(&self) -> RefPolicyPublication {
        self.0.publication()
    }
    #[must_use]
    pub const fn evaluation(&self) -> &RefPolicyEvaluation {
        self.0.evaluation()
    }
    #[must_use]
    pub const fn references(&self) -> &EvaluatedPolicyDecisionEvidence {
        self.0.references()
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
        agent: AgentAuthentication,
    ) -> Result<Self, RefusalCode> {
        agent.validate()?;
        if agent.agent() != context.principal_id {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let value = Self(
            ActivatedPolicyDecisionEvidence::evaluate_for(
                Profile::RepositoryAuthenticationV1,
                base,
                context,
                basis,
                current,
                layout,
                fold,
                review_branches,
                snapshot,
                publication,
                Some(AdmissionAuthentication::AgentCredential(agent)),
            )?,
            agent,
        );
        let bytes = encode_body(&value).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(value)
    }

    pub fn replay(&self) -> Result<(), RefusalCode> {
        self.1.validate()?;
        if self.0.evaluation().profile != Profile::RepositoryAuthenticationV1
            || self.0.authentication != Some(self.authentication())
            || self.0.references.principal != self.1.agent()
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        self.0.replay()
    }

    pub fn verify_provenance(
        &self,
        basis: &PublicationBasis,
        current: &CanonicalRefState,
        layout: RootLayoutVersion,
        review_branches: &[RefName],
        selected: &PolicySnapshot,
    ) -> Result<(), RefusalCode> {
        self.0
            .verify_provenance(basis, current, layout, review_branches, selected)?;
        self.replay()
    }

    pub(super) fn verify_decision(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
        fold: &TransactionFoldReport,
    ) -> Result<(), RefusalCode> {
        self.0.verify_decision(context, basis, fold)?;
        self.replay()
    }
}

impl CanonicalBody for AgentAuthenticationPolicyDecisionEvidence {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 5;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.replay()
            .map_err(|_| invalid("policy_decision.agent_authentication"))?;
        self.0
            .write_fields(out, Profile::RepositoryAuthenticationV1)?;
        self.1.write_fields(out)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let mut fields = ActivatedPolicyDecisionEvidence::read_fields_unverified(
            input,
            Profile::RepositoryAuthenticationV1,
        )?;
        let agent = AgentAuthentication::read_fields(input)?;
        fields.authentication = Some(AdmissionAuthentication::AgentCredential(agent));
        let value = Self(fields, agent);
        value
            .replay()
            .map_err(|_| invalid("policy_decision.agent_authentication_replay"))?;
        Ok(value)
    }
}
