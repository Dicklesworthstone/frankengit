//! Exact schema 1.3: ref facts plus the sealed principal identifier.
use super::{
    ActivatedPolicyDecisionEvidence, EvaluatedPolicyDecisionEvidence, MAX_FRAME_BYTES,
    PolicyDecisionEvidence, Profile, RefPolicyEvaluation, RefPolicyPublication,
};
use crate::{AdmissionContext, CanonicalRefState};
use fgit_chronicle::PublicationBasis;
use fgit_codec::{CanonicalBody, CodecRefusal, Decoder, Encoder, encode_body};
use fgit_policy::PolicySnapshot;
use fgit_txn::TransactionFoldReport;
use fgit_types::{DomainTag, RefName, RefusalCode, RootLayoutVersion, SchemaFamily};

/// An actor-aware policy receipt. The new minor is required: schema 1.2 keeps
/// its closed ref-only semantics and must refuse a policy observing actor.id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorPolicyDecisionEvidence(pub(super) ActivatedPolicyDecisionEvidence);

impl ActorPolicyDecisionEvidence {
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
    ) -> Result<Self, RefusalCode> {
        let value = Self(ActivatedPolicyDecisionEvidence::evaluate_for(
            Profile::RepositoryActorIdV1,
            base,
            context,
            basis,
            current,
            layout,
            fold,
            review_branches,
            snapshot,
            publication,
        )?);
        let bytes = encode_body(&value).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        Ok(value)
    }

    pub fn replay(&self) -> Result<(), RefusalCode> {
        if self.0.evaluation().profile != Profile::RepositoryActorIdV1 {
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

impl CanonicalBody for ActorPolicyDecisionEvidence {
    const DOMAIN: DomainTag = PolicyDecisionEvidence::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PolicyDecisionEvidence::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 3;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.0.write_fields(out, Profile::RepositoryActorIdV1)
    }
    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self(ActivatedPolicyDecisionEvidence::read_fields(
            input,
            Profile::RepositoryActorIdV1,
        )?))
    }
}
