//! Original principal receipts selected by an already authenticated outcome.
//! Missing retained evidence never changes knowledge of the terminal decision.

use super::{RecoveryFailure, RequestRecovery, recovery_checkpoint};
use crate::{LoopbackReceiveSession, NodeRequestContext, OneNode};
use fgit_admission::AdmissionContext;
use fgit_admission::evidence::{PrincipalSnapshotRecord, RefusalEvidence, evidence_root};
use fgit_authority::{AsyncAuthorityStore, HeadRead, ImmutableKey, ImmutableRead};
use fgit_codec::{
    CanonicalBody, CryptoBodyIdentity, DecodeLimits, RefusalRecordBody, body_id, decode_body,
};
use fgit_types::{DecisionOutcome, Digest, InternalObjectId};

const MAX_EVIDENCE_FRAME: usize = 64 * 1024;

impl OneNode {
    /// Load the principal receipt retained by this original committed/refused
    /// request. The caller's current authentication method and current grant
    /// registry are deliberately irrelevant: rotation and revocation cannot
    /// rewrite historical provenance.
    ///
    /// The report's scope/key must match this authenticated session. A bounded
    /// authenticated history walk binds the exact decision and its original
    /// basis; every quoted body is re-identified before use. Missing/pruned,
    /// corrupt or unavailable evidence returns an error, while the caller must
    /// retain the report's already established terminal outcome. `None` means
    /// the supplied report is nonterminal, not that an old principal is human.
    pub async fn recover_transaction_principal_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        report: &RequestRecovery,
    ) -> Result<Option<PrincipalSnapshotRecord>, RecoveryFailure> {
        let authenticated = session
            .authenticated_session()
            .ok_or(RecoveryFailure::AuthenticationRequired)?;
        let RequestRecovery::Recovered(recovered) = report else {
            return Ok(None);
        };
        let seal = recovered.seal();
        if seal.tenant_id != self.tenant_id
            || seal.repository_id != self.repository_id
            || seal.authenticated_principal_id != authenticated.principal_id()
            || seal.idempotency_key_digest != authenticated.client_idempotency_key().digest()
        {
            return Err(invalid("principal recovery scope/key"));
        }
        let Some(terminal) = report.terminal() else {
            return Ok(None);
        };
        recovery_checkpoint(request).map_err(RecoveryFailure::Interrupted)?;
        // The concrete engine has same-named inherent methods. Select the
        // authority adapter so retries and typed AuthorityFailure stay intact.
        let HeadRead::Present(receipt) =
            AsyncAuthorityStore::read_head(&self.authority, request.authority(), &self.head_key)
                .await?
        else {
            return Err(RecoveryFailure::HeadNotObserved);
        };
        let head = AsyncAuthorityStore::authenticate_head_receipt(
            &self.authority,
            request.authority(),
            &receipt,
        )
        .await?;
        let mut successor = head
            .body()
            .map_err(|_| invalid("principal recovery head"))?;
        if successor.repository_id != self.repository_id {
            return Err(invalid("principal recovery repository"));
        }
        let mut walked = 0;
        let cancelled = || recovery_checkpoint(request).is_err();
        let (snapshot_id, basis) = loop {
            recovery_checkpoint(request).map_err(RecoveryFailure::Interrupted)?;
            let (basis, batch) = match crate::capsule_history::predecessor_in(
                &self.authority,
                request.authority(),
                &successor,
                &mut walked,
                &cancelled,
            )
            .await
            .map_err(|_| invalid("original decision history unavailable"))?
            {
                crate::capsule_history::HistoryStep::Genesis => {
                    return Err(invalid("original decision not retained"));
                }
                crate::capsule_history::HistoryStep::Checkpoint { predecessor } => {
                    successor = predecessor.body().clone();
                    continue;
                }
                crate::capsule_history::HistoryStep::Decision { predecessor, batch } => {
                    (predecessor, batch)
                }
            };
            if let Some(decision) = batch
                .decisions
                .iter()
                .find(|decision| decision.tx_id == recovered.tx_id())
            {
                if decision.decision_sequence != terminal.decision_sequence
                    || decision.outcome != terminal.outcome
                {
                    return Err(invalid("original terminal decision"));
                }
                let snapshot_id = match terminal.outcome {
                    DecisionOutcome::Committed {
                        repository_commit_id,
                    } => {
                        let record = batch
                            .committed_rcrs
                            .iter()
                            .find(|record| record.tx_id == recovered.tx_id())
                            .ok_or_else(|| invalid("original repository commit"))?;
                        if body_id(&CryptoBodyIdentity, record).map_err(RecoveryFailure::Codec)?
                            != *repository_commit_id.as_internal_object_id()
                            || record.repository_id != self.repository_id
                            || record.canonical_request_digest != seal.canonical_request_digest
                        {
                            return Err(invalid("original repository commit binding"));
                        }
                        record.principal_snapshot_id
                    }
                    DecisionOutcome::Refused {
                        code,
                        refusal_record_id,
                    } => {
                        let record: RefusalRecordBody = read_identified(
                            self,
                            request,
                            refusal_record_id.as_internal_object_id(),
                        )
                        .await?;
                        if record.tx_id != recovered.tx_id()
                            || record.seal_id != recovered.seal_id()
                            || record.decision_sequence != terminal.decision_sequence
                            || record.code != code
                        {
                            return Err(invalid("original refusal binding"));
                        }
                        let key = crate::admission_immutable_key(
                            crate::ADMISSION_REFUSAL_EVIDENCE_KEY_PREFIX,
                            self.repository_id,
                            record.evidence_root,
                        )
                        .map_err(|_| invalid("refusal evidence key"))?;
                        let bytes = read_frame(self, request, &key).await?;
                        let evidence: RefusalEvidence = decode_body(&bytes, DecodeLimits::DEFAULT)?;
                        if evidence_root(&evidence)
                            .map_err(|_| invalid("refusal evidence identity"))?
                            != record.evidence_root
                            || evidence.tx_id() != record.tx_id
                            || evidence.code() != record.code
                            || evidence.policy_epoch() != record.policy_epoch
                            || evidence.basis_head_id() != basis.id()
                        {
                            return Err(invalid("original refusal evidence binding"));
                        }
                        evidence.principal_snapshot_id()
                    }
                };
                break (snapshot_id, basis);
            }
            if batch.first_decision_sequence <= terminal.decision_sequence {
                return Err(invalid("original decision sequence"));
            }
            successor = basis.body().clone();
        };
        let id = snapshot_id.as_internal_object_id();
        let root = Digest::new(id.algorithm(), *id.digest());
        let key = crate::admission_immutable_key(
            crate::ADMISSION_PRINCIPAL_SNAPSHOT_KEY_PREFIX,
            self.repository_id,
            root,
        )
        .map_err(|_| invalid("principal evidence key"))?;
        let bytes = read_frame(self, request, &key).await?;
        let snapshot = PrincipalSnapshotRecord::decode(&bytes, DecodeLimits::DEFAULT)?;
        if snapshot
            .id()
            .map_err(|_| invalid("principal evidence identity"))?
            != snapshot_id
        {
            return Err(invalid("principal evidence identity"));
        }
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        snapshot
            .verify_context(&context, &basis)
            .map_err(|_| invalid("original principal binding"))?;
        recovery_checkpoint(request).map_err(RecoveryFailure::Interrupted)?;
        Ok(Some(snapshot))
    }
}

async fn read_frame(
    node: &OneNode,
    request: &NodeRequestContext,
    key: &ImmutableKey,
) -> Result<Vec<u8>, RecoveryFailure> {
    recovery_checkpoint(request).map_err(RecoveryFailure::Interrupted)?;
    let ImmutableRead::Present(bytes) =
        AsyncAuthorityStore::read_immutable(&node.authority, request.authority(), key).await?
    else {
        return Err(invalid("original principal evidence missing"));
    };
    if bytes.len() > MAX_EVIDENCE_FRAME {
        return Err(RecoveryFailure::BoundExceeded {
            field: "principal evidence",
            limit: MAX_EVIDENCE_FRAME,
            observed: bytes.len(),
        });
    }
    recovery_checkpoint(request).map_err(RecoveryFailure::Interrupted)?;
    Ok(bytes)
}

async fn read_identified<B: CanonicalBody>(
    node: &OneNode,
    request: &NodeRequestContext,
    id: &InternalObjectId,
) -> Result<B, RecoveryFailure> {
    let key = fgit_authority::body_key_for_id(id)?;
    let bytes = read_frame(node, request, &key).await?;
    let body = decode_body::<B>(&bytes, DecodeLimits::DEFAULT)?;
    if body_id(&CryptoBodyIdentity, &body).map_err(RecoveryFailure::Codec)? != *id {
        return Err(invalid("original refusal identity"));
    }
    Ok(body)
}

const fn invalid(field: &'static str) -> RecoveryFailure {
    RecoveryFailure::Integrity { field }
}
