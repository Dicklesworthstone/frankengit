//! Ordinary principal/policy and empty non-ref partitions for a symbolic HEAD
//! decision. Its actual invariant witness is CanonicalHeadChange, not an empty
//! direct-ref transaction fold.

use super::{
    AdmissionAuthentication, AdmissionContext, ForgeEventBatch, OutboxEffectBatch,
    PolicyDecisionEvidence, PrincipalSnapshotRecord, PublicationBasis, RetentionDelta,
    canonical_forge_effect_bytes, canonical_outbox_effect_bytes, canonical_retention_effect_bytes,
    principal_snapshot_id,
};
use fgit_types::{Digest, RefusalCode, TxId};

pub(crate) struct HeadChangeEvidence {
    pub principal: PrincipalSnapshotRecord,
    pub policy: PolicyDecisionEvidence,
    pub forge: ForgeEventBatch,
    pub outbox: OutboxEffectBatch,
    pub retention: RetentionDelta,
}

impl HeadChangeEvidence {
    pub fn derive(
        context: &AdmissionContext,
        basis: &PublicationBasis,
        tx_id: TxId,
        request_digest: Digest,
    ) -> Result<Self, RefusalCode> {
        let principal = PrincipalSnapshotRecord::from_context(
            context,
            basis,
            Some(AdmissionAuthentication::OperatorAssertion),
        );
        principal.verify_context(context, basis)?;
        let empty = fgit_reference::effect::NetEffects::default();
        Ok(Self {
            policy: PolicyDecisionEvidence {
                tx_id,
                request_digest,
                principal_snapshot_id: principal_snapshot_id(&principal)?,
                policy_epoch: basis.body().policy_epoch,
            },
            principal,
            forge: ForgeEventBatch {
                effect_bytes: canonical_forge_effect_bytes(&empty)
                    .map_err(|_| RefusalCode::CanonicalFramingInvalid)?,
            },
            outbox: OutboxEffectBatch {
                effect_bytes: canonical_outbox_effect_bytes(&empty)
                    .map_err(|_| RefusalCode::CanonicalFramingInvalid)?,
            },
            retention: RetentionDelta {
                effect_bytes: canonical_retention_effect_bytes(&empty)
                    .map_err(|_| RefusalCode::CanonicalFramingInvalid)?,
            },
        })
    }
}
