//! Explicit publication of an independently reviewed linear rebase artifact.
//! Pack prerequisites describe object availability; the source branch lease
//! describes the mutation. Neither is a substitute for the other.

use super::{CandidateEnvelope, MAX_BUNDLE_BYTES, MAX_CANDIDATE_BYTES, invalid, receive_error};
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode, VerifiedFabricPackSource};
use fgit_admission::{AdmissionContext, AdmissionLimits, AdmissionResult, CommandOutcome, SessionMapping};
use fgit_authority::{ExpectedOld, IdempotencyKey, OutcomeLookup, ProposedNew, RefCommand,
    SealAttempt, SemanticRequest, RECEIVE_ADMISSION_SCHEMA};
use fgit_git_object::{AcceptanceProfile, ObjectType, ParsedObject, parse_object_body};
use fgit_types::{GitOid, PrincipalId, RefName};
use std::cell::Cell;
use std::collections::BTreeSet;

const MAX_REBASE_COMMITS: usize = 256;

impl OneNode {
    /// Publish a reviewed, bounded single-parent series using ordinary atomic
    /// receive admission. The caller's trusted authentication boundary supplies
    /// the principal. The explicit old SOURCE tip is the ref lease; `onto` is
    /// the only bundle prerequisite, never the expected old source value.
    ///
    /// The bundle branch, native hash domain, prerequisite and reviewed tip
    /// must match the independent inputs. Native bytes prove a single-parent
    /// chain from the candidate to onto (at most 256 commits). A zero-commit
    /// series may move the branch directly to onto, including an empty pack.
    /// Existing workspace apply remains exactly one commit/one prerequisite.
    ///
    /// Ref protection, current disclosure, quota, closure verification, and
    /// exact-basis CAS remain the production receive path. This method does not
    /// infer authorization from a preparation receipt, set a force bit, invent
    /// review approvals, or update PR metadata. Rebase preparation itself still
    /// has no publication authority.
    ///
    /// The immutable semantic request is the same ref transaction as native
    /// receive-pack. A terminal retry validates its bounded input envelope and
    /// recovers that request before current serving, quota or object checks.
    /// An uncertain return never establishes non-commit: use the original
    /// principal/key with `recover_transaction_in`, or retry identical inputs.
    pub async fn apply_rebase_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        principal_id: PrincipalId,
        idempotency_key: &[u8],
        reference: &RefName,
        expected_source: GitOid,
        onto: GitOid,
        expected_candidate: GitOid,
        input: &[u8],
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let envelope = CandidateEnvelope::parse_profile(input, 1, true)?;
        envelope.bind(self.object_format, reference, onto, expected_candidate)?;
        if expected_source.is_zero() || expected_source.algorithm() != self.object_format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        let key = IdempotencyKey::new(idempotency_key.to_vec())
            .map_err(|_| invalid("invalid bounded rebase idempotency key"))?;
        let semantic = SemanticRequest::build(RECEIVE_ADMISSION_SCHEMA, self.object_format,
            true, vec![RefCommand { name: reference.clone(),
                expected_old: ExpectedOld::Exactly(expected_source),
                proposed_new: ProposedNew::Update(expected_candidate), force: false }],
            vec![], vec![]).map_err(|_| invalid("invalid rebase ref transaction"))?;
        let attempt = SealAttempt { tenant_id: self.tenant_id, repository_id: self.repository_id,
            authenticated_principal_id: principal_id, idempotency_key: key.clone(), request: semantic };
        let admission_error = |error| receive_error(crate::NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let (tx_id, _) = attempt.derive().map_err(|error| admission_error(error.into()))?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id,
            self.repository_id, tx_id,
        ).await.map_err(|error| admission_error(error.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| admission_error(error.into()))?;
            return Ok(AdmissionResult { session: SessionMapping { atomic: true, tx_ids: vec![tx_id] },
                commands: vec![CommandOutcome { tx_id, terminal }] });
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&principal_id).map_err(receive_error)?;
        let (validated, mut parse_limits) = self.quarantine_bound_envelope_in(
            request, reference, expected_source, &envelope, &[],
        ).await?;
        parse_limits.max_object_bytes = parse_limits.max_object_bytes.min(MAX_CANDIDATE_BYTES);
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource { fabric: &self.fabric, object_format: self.object_format,
            maximum_object_bytes: parse_limits.max_object_bytes, database_context: request.authority(),
            database_exhaustion: &exhaustion, session_is_live: None };
        let mut cursor = expected_candidate;
        let mut seen = BTreeSet::new();
        let mut bytes = 0_usize;
        while cursor != onto {
            if !super::super::workspace_request_live(request) {
                return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: exhaustion.get() });
            }
            if seen.len() == MAX_REBASE_COMMITS || !seen.insert(cursor) {
                return Err(invalid("rebase candidate exceeds the bounded linear series"));
            }
            let read = source.read_object(&cursor);
            if !super::super::workspace_request_live(request) || exhaustion.get().is_some() {
                return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: exhaustion.get() });
            }
            let (kind, body) = read.map_err(|_| invalid("rebase commit bytes could not be verified"))?;
            bytes = bytes.checked_add(body.len())
                .filter(|total| *total <= MAX_BUNDLE_BYTES)
                .ok_or_else(|| invalid("rebase commit traversal exceeds its byte budget"))?;
            if kind != ObjectType::Commit {
                return Err(invalid("rebase candidate ancestry must contain commits"));
            }
            let ParsedObject::Commit(commit) = parse_object_body(kind, &body,
                AcceptanceProfile::GitCompatibleImport, &parse_limits)
                .map_err(|_| invalid("rebase candidate is not a bounded native commit"))?
            else { return Err(invalid("rebase candidate ancestry must contain commits")); };
            let mut parents = commit.parent_references();
            let parent = parents.next().ok_or_else(|| invalid("rebase series does not reach its onto prerequisite"))?;
            if parents.next().is_some() {
                return Err(invalid("rebase publication accepts only a single-parent series"));
            }
            cursor = std::str::from_utf8(parent).ok()
                .and_then(|text| GitOid::from_hex(self.object_format, &text.to_ascii_lowercase()).ok())
                .filter(|id| !id.is_zero())
                .ok_or_else(|| invalid("invalid rebase parent identity"))?;
        }
        if !super::super::workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: exhaustion.get() });
        }
        let context = AdmissionContext { head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id, idempotency_key: key,
            object_format: self.object_format };
        self.admit_basis_bound_validated_receive_durable_in(
            request, &context, &validated, AdmissionLimits::default(),
        ).await.map_err(admission_error)
    }
}
