//! Canonical sponsored agent credentials and bounded request authentication.
//!
//! Issuance is an explicit trusted-local administration operation. Credential
//! holders receive finite metadata, source reads and explicit candidate scopes,
//! never source publication, review, merge, process execution or administration.

use crate::source_retrieval::authorization::SourceReadContext;
use crate::treefs_workspace::native_merge::NodeNativeMergeProjection;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::evidence::{AdmissionAuthentication, AgentAuthentication};
use fgit_admission::merge::native::agent_credentials::{self as ledger, AgentCredentialState};
use fgit_admission::{AdmissionContext, AdmissionError, AdmissionLimits};
use fgit_agent::{AuthorityReadReceipt, ClassSet, IntentRun, LogicalTime, OperationClass, RunId};
use fgit_authority::{IdempotencyKey, OutcomeLookup, TerminalOutcome};
use fgit_crypto::sha256_digest;
use fgit_graph::lexical::LexicalNamespace;
use fgit_identity::agent::{ALL_OPERATIONS, AgentCredentialCommand, AgentCredentialId};
use fgit_resource::{ResourceVector, algebra::Grade};
use fgit_types::{RefusalCode, TxId};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const TOKEN_PREFIX: &str = "fgagent_";
pub const MAX_REQUEST_SECONDS: u64 = 300;
pub const MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;

/// Generate a cryptographically random bearer. The caller must write this once
/// to a private file; only its digest belongs in canonical repository state.
#[must_use]
pub fn generate_agent_credential_token() -> String {
    use asupersync::util::{EntropySource, OsEntropy};
    use std::fmt::Write;
    let mut secret = [0u8; 32];
    OsEntropy.fill_bytes(&mut secret);
    let mut token = String::with_capacity(TOKEN_PREFIX.len() + 64);
    token.push_str(TOKEN_PREFIX);
    for byte in secret {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

#[must_use]
pub fn valid_agent_credential_token(token: &[u8]) -> bool {
    token.len() == TOKEN_PREFIX.len() + 64
        && token.starts_with(TOKEN_PREFIX.as_bytes())
        && token[TOKEN_PREFIX.len()..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

pub(crate) fn epoch_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|time| time.as_secs())
}

fn refused(code: RefusalCode) -> NodeReceiveTransportRefusal {
    NodeReceiveTransportRefusal::Admission(Box::new(AdmissionError::AsyncProjectionUnavailable(
        code,
    )))
}

fn materialization_refused(
    error: crate::AdmissionMaterializationRefusal,
) -> NodeReceiveTransportRefusal {
    // Selection has not authorized a request or published a decision. Preserve
    // the materializer's interruption, availability and integrity distinctions
    // instead of reporting every failed read as a stale authority receipt.
    match crate::async_projection_unavailable(error) {
        fgit_admission::ProjectionFailure::Unavailable(code)
        | fgit_admission::ProjectionFailure::Refuse(code) => refused(code),
    }
}

fn checkpoint(request: &NodeRequestContext) -> Result<(), NodeReceiveTransportRefusal> {
    match crate::checkpoint_pack_context(request.authority()) {
        crate::PackContextCheckpoint::Live => Ok(()),
        crate::PackContextCheckpoint::Stopped {
            budget_exhaustion: Some(_),
        } => Err(refused(RefusalCode::ResourceBudgetExceeded)),
        crate::PackContextCheckpoint::Stopped {
            budget_exhaustion: None,
        } => Err(refused(RefusalCode::CancellationInProgress)),
    }
}

impl OneNode {
    /// Issue or revoke a canonical credential through the shared sealed
    /// metadata transaction. A retry recovers the original outcome first.
    pub async fn admit_agent_credential_durable_in(
        &self,
        request: &NodeRequestContext,
        session: &LoopbackReceiveSession,
        command: &AgentCredentialCommand,
        limits: AdmissionLimits,
    ) -> Result<(TxId, TerminalOutcome), NodeReceiveTransportRefusal> {
        let authenticated = session
            .authenticated_session()
            .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        if authenticated.authentication() != AdmissionAuthentication::OperatorAssertion {
            return Err(refused(RefusalCode::CapabilityScopeViolation));
        }
        let context = AdmissionContext {
            head_key: self.head_key.clone(),
            tenant_id: self.tenant_id,
            repository_id: self.repository_id,
            principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(),
            object_format: self.object_format,
        };
        let (_, attempt) = ledger::proposal(&context, command)
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        let tx = attempt
            .derive()
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e.into())))?
            .0;
        checkpoint(request)?;
        if let OutcomeLookup::Decided(outcome) = self
            .resolve_outcome_checkpointed_in(request, tx)
            .await
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e.into())))?
        {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await
                .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e.into())))?;
            return Ok((tx, outcome));
        }
        self.receive_publication_admitted()?;
        self.push_quota.evaluate(&context.principal_id)?;
        let projection = NodeNativeMergeProjection::metadata(self, &context, authenticated)
            .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        let terminal = Box::pin(ledger::admit_async(
            &self.authority,
            request.authority(),
            &context,
            command,
            limits,
            &projection,
        ))
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        Ok((tx, terminal))
    }

    /// Read current issuance and revocation from one authenticated frontier.
    pub async fn read_agent_credentials_in(
        &self,
        request: &NodeRequestContext,
    ) -> Result<Vec<AgentCredentialState>, NodeReceiveTransportRefusal> {
        checkpoint(request)?;
        fgit_types::cell::admits_read(self.cell_state(), fgit_types::cell::ReadMode::Current)
            .map_err(NodeReceiveTransportRefusal::CellState)?;
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(materialization_refused)?;
        let states = ledger::read_all_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            &|| !request.is_live(),
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?;
        checkpoint(request)?;
        Ok(states)
    }

    pub async fn read_agent_credential_in(
        &self,
        request: &NodeRequestContext,
        id: AgentCredentialId,
    ) -> Result<Option<AgentCredentialState>, NodeReceiveTransportRefusal> {
        Ok(self
            .read_agent_credentials_in(request)
            .await?
            .into_iter()
            .find(|state| state.id == id))
    }

    /// Authenticate one host-bounded request. The transport adapter supplies the
    /// actual operation class, retry key, complete request commitment and enforced
    /// byte ceilings. No credential
    /// or run survives as a cache for a subsequent request.
    pub async fn authenticate_agent_request_in(
        &self,
        request: &NodeRequestContext,
        bearer: &[u8],
        key: &IdempotencyKey,
        operation: u16,
        request_commitment: [u8; 32],
        input_limit: u64,
        output_limit: u64,
    ) -> Result<AgentRequest, NodeReceiveTransportRefusal> {
        use fgit_identity::agent::{
            DISCUSSIONS_WRITE, ISSUES_WRITE, PULLS_WRITE, SOURCE_CANDIDATES, SOURCE_READ,
            agent_credential_id, authenticate_agent_credential,
        };
        if !valid_agent_credential_token(bearer)
            || operation.count_ones() != 1
            || operation & !ALL_OPERATIONS != 0
        {
            return Err(NodeReceiveTransportRefusal::Unauthenticated);
        }
        if input_limit > MAX_REQUEST_BYTES || output_limit == 0 || output_limit > MAX_REQUEST_BYTES
        {
            return Err(refused(RefusalCode::ResourceBudgetExceeded));
        }
        checkpoint(request)?;
        let origin = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| refused(RefusalCode::CapabilityExpired))?;
        let now = wall.as_secs();
        let selected = self
            .materialize_admission_in(request)
            .await
            .map_err(materialization_refused)?;
        let id = agent_credential_id(bearer)
            .map_err(|_| NodeReceiveTransportRefusal::Unauthenticated)?;
        let state = ledger::read_at(
            &self.authority,
            request.authority(),
            selected.basis(),
            id,
            &|| !request.is_live(),
        )
        .await
        .map_err(|e| NodeReceiveTransportRefusal::Admission(Box::new(e)))?
        .ok_or(NodeReceiveTransportRefusal::Unauthenticated)?;
        let credential = authenticate_agent_credential(
            id,
            &state.grant,
            bearer,
            self.tenant_id,
            self.repository_id,
            self.repository_incarnation_id,
            now,
            if state.revoked {
                fgit_identity::RevocationEvidence::Revoked
            } else {
                fgit_identity::RevocationEvidence::Live
            },
        )
        .map_err(|_| NodeReceiveTransportRefusal::Unauthenticated)?;
        credential
            .authorize(operation)
            .map_err(|_| refused(RefusalCode::CapabilityScopeViolation))?;
        let expiry = now
            .saturating_add(MAX_REQUEST_SECONDS)
            .min(state.grant.expires_at);
        let class = if operation & (ISSUES_WRITE | PULLS_WRITE | DISCUSSIONS_WRITE) != 0 {
            OperationClass::MutateForgeEntity
        } else {
            OperationClass::ReadCanonicalObject
        };
        let classes = if operation == SOURCE_READ {
            ClassSet::from_classes(&[
                OperationClass::ReadCanonicalObject,
                OperationClass::ReadDerivedGeneration,
            ])
        } else if operation == SOURCE_CANDIDATES {
            ClassSet::from_classes(&[
                OperationClass::ReadCanonicalObject,
                OperationClass::TreeFsWorkspace,
                OperationClass::CreateCandidateObject,
            ])
        } else {
            ClassSet::from_classes(&[class])
        };
        let budget = ResourceVector::single(Grade::Bytes, input_limit)
            .with(Grade::EgressBytes, output_limit);
        let receipt = AuthorityReadReceipt::from_authenticated_head(
            selected.authenticated(),
            LogicalTime::new(now),
            sha256_digest(b"frankengit/agent-metadata/authority/v1\0"),
        )
        .map_err(|_| refused(RefusalCode::EvidenceInvalid))?;
        let seed = IntentRun::new_authenticated(
            RunId::new(0),
            receipt.clone(),
            classes,
            budget,
            LogicalTime::new(expiry),
        )
        .map_err(|_| refused(RefusalCode::EvidenceInvalid))?;
        let mut identity = Vec::from(b"frankengit/agent-metadata/run-id/v1\0".as_slice());
        identity.extend_from_slice(
            seed.commitment()
                .map_err(|_| refused(RefusalCode::EvidenceInvalid))?
                .as_bytes(),
        );
        identity.extend_from_slice(id.as_bytes());
        identity.extend_from_slice(state.grant.agent.as_bytes());
        identity.extend_from_slice(state.grant.sponsor.as_bytes());
        identity.extend_from_slice(&operation.to_be_bytes());
        identity.extend_from_slice(&request_commitment);
        identity.extend_from_slice(key.as_bytes());
        let hash = sha256_digest(&identity);
        let mut run_id = [0; 16];
        run_id.copy_from_slice(&hash[..16]);
        let run = IntentRun::new_authenticated(
            RunId::new(u128::from_be_bytes(run_id)),
            receipt,
            classes,
            budget,
            LogicalTime::new(expiry),
        )
        .map_err(|_| refused(RefusalCode::EvidenceInvalid))?;
        let authentication = AgentAuthentication::try_new(
            state.grant.agent,
            state.grant.sponsor,
            state.grant.sponsor_kind,
            id,
            state.grant_root,
            *run.commitment()
                .map_err(|_| refused(RefusalCode::EvidenceInvalid))?
                .as_bytes(),
            now,
            expiry,
        )
        .map_err(refused)?;
        let result = AgentRequest {
            run,
            authentication,
            operation,
            namespace: LexicalNamespace {
                tenant: state.grant.tenant,
                repository: state.grant.repository,
                incarnation: state.grant.incarnation,
                object_format: self.object_format,
            },
            key: key.clone(),
            deadline: origin
                + std::time::Duration::from_secs(expiry)
                    .checked_sub(wall)
                    .ok_or_else(|| refused(RefusalCode::CapabilityExpired))?,
        };
        result.check(input_limit, 0)?;
        checkpoint(request)?;
        Ok(result)
    }
}

/// A single request reservation. Its bytes bound the transport input/output
/// envelopes, not total CPU, memory, storage or billing. Adapters must enforce
/// those envelopes, check expiry before disclosure, and discard this reservation
/// after the request. This type intentionally has no secret-bearing `Debug`.
pub struct AgentRequest {
    pub(crate) authentication: AgentAuthentication,
    run: IntentRun,
    pub(crate) operation: u16,
    namespace: LexicalNamespace,
    key: IdempotencyKey,
    deadline: Instant,
}

impl AgentRequest {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Attenuate the request to the adapter's original transport deadline.
    /// A host may shorten this ceiling but cannot extend the verified grant.
    pub fn constrain_deadline(&mut self, deadline: Instant) {
        self.deadline = self.deadline.min(deadline);
    }

    /// Retain independently granted candidate authority for this request only.
    /// A public provenance record, source-read grant or metadata grant cannot
    /// construct this boundary. Native adapters still enforce the exact source
    /// selection, canonical visibility, path limits and original deadline.
    /// The host must account for its full input and response envelopes against
    /// this request and authenticate again for the next tool or HTTP operation.
    pub fn source_candidates(
        &self,
        node: &OneNode,
    ) -> Result<SourceCandidateRequest<'_>, NodeReceiveTransportRefusal> {
        if self.operation != fgit_identity::agent::SOURCE_CANDIDATES
            || !self.matches_namespace(node)
        {
            return Err(refused(RefusalCode::CapabilityScopeViolation));
        }
        self.check(0, 0)?;
        Ok(SourceCandidateRequest(self))
    }

    fn matches_namespace(&self, node: &OneNode) -> bool {
        self.namespace
            == (LexicalNamespace {
                tenant: node.tenant_id,
                repository: node.repository_id,
                incarnation: node.repository_incarnation_id,
                object_format: node.object_format,
            })
    }

    /// Retain this request's verified source-read authority for one MCP tool
    /// invocation. The host must independently enable the tool, enforce this
    /// reservation's byte ceilings, check it before disclosure, and discard both
    /// the request and context afterward. A metadata scope or public provenance
    /// record alone cannot construct this authenticated read context.
    ///
    /// The context keeps the original agent, sponsor, repository namespace and
    /// deadline. It never refreshes the credential or substitutes local operator
    /// attribution. Canonical authentication must run again for the next tool.
    pub fn mcp_source_read_context(
        &self,
        node: &OneNode,
    ) -> Result<SourceReadContext, NodeReceiveTransportRefusal> {
        if self.operation != fgit_identity::agent::SOURCE_READ
            || self.namespace
                != (LexicalNamespace {
                    tenant: node.tenant_id,
                    repository: node.repository_id,
                    incarnation: node.repository_incarnation_id,
                    object_format: node.object_format,
                })
        {
            return Err(refused(RefusalCode::CapabilityScopeViolation));
        }
        self.check(0, 0)?;
        Ok(SourceReadContext::mcp_agent_credential(
            node,
            self.authentication,
            self.deadline,
        ))
    }

    /// Carry the verified principal, sponsor, original retry key and monotonic
    /// expiry into native metadata admission or own-principal outcome recovery.
    /// The caller cannot replace the key used to authenticate this request.
    #[must_use]
    pub fn authenticated_session(&self) -> LoopbackReceiveSession {
        LoopbackReceiveSession::Authenticated(
            crate::AuthenticatedReceiveSession::new(self.authentication.agent(), self.key.clone())
                .with_authentication(AdmissionAuthentication::AgentCredential(
                    self.authentication,
                ))
                .with_agent_deadline(Some(self.deadline)),
        )
    }

    /// Mint awaited authority work under the remaining request deadline. A new
    /// adapter phase never refreshes the lifetime of a verified agent request.
    #[must_use]
    pub fn context(&self, node: &OneNode) -> NodeRequestContext {
        node.session_request_context_with_timeout(
            self.deadline
                .saturating_duration_since(Instant::now())
                .min(node.git_daemon_session_timeout.duration()),
        )
    }

    #[cfg(test)]
    pub(crate) fn session(&self, key: IdempotencyKey) -> LoopbackReceiveSession {
        LoopbackReceiveSession::Authenticated(
            crate::AuthenticatedReceiveSession::new(self.authentication.agent(), key)
                .with_authentication(AdmissionAuthentication::AgentCredential(
                    self.authentication,
                ))
                .with_agent_deadline(Some(self.deadline())),
        )
    }

    pub fn check(
        &self,
        input_bytes: u64,
        output_bytes: u64,
    ) -> Result<(), NodeReceiveTransportRefusal> {
        let now = epoch_seconds().ok_or_else(|| refused(RefusalCode::CapabilityExpired))?;
        if Instant::now() >= self.deadline
            || now < self.authentication.authenticated_at()
            || !self.run.is_open_at(LogicalTime::new(now))
        {
            return Err(refused(RefusalCode::CapabilityExpired));
        }
        if !self.run.resource_budget().dominates(
            &ResourceVector::single(Grade::Bytes, input_bytes)
                .with(Grade::EgressBytes, output_bytes),
        ) {
            return Err(refused(RefusalCode::ResourceBudgetExceeded));
        }
        Ok(())
    }
}

/// Unforgeable, request-borrowed authority for ephemeral source candidates.
/// It has no session, publication, credential-refresh or current-source API.
/// Native entrypoints bound raw inputs; adapters retain responsibility for the
/// complete serialized request/response reservation and disclosure checkpoints.
pub struct SourceCandidateRequest<'a>(&'a AgentRequest);

impl SourceCandidateRequest<'_> {
    pub(crate) fn context(
        &self,
        node: &OneNode,
    ) -> Result<NodeRequestContext, crate::NodeWorkspaceRefusal> {
        if !self.0.matches_namespace(node) {
            return Err(crate::NodeWorkspaceRefusal::RepositoryMismatch);
        }
        self.check()?;
        Ok(self.0.context(node))
    }

    pub(crate) fn check(&self) -> Result<(), crate::NodeWorkspaceRefusal> {
        self.0
            .check(0, 0)
            .map_err(|_| crate::NodeWorkspaceRefusal::Cancelled { exhaustion: None })
    }

    /// The public native boundary retains at least the raw input reservation.
    /// Each transport separately accounts for its complete framing and output.
    pub(crate) fn check_input(&self, bytes: usize) -> Result<(), crate::NodeWorkspaceRefusal> {
        self.check()?;
        let bytes =
            u64::try_from(bytes).map_err(|_| crate::NodeWorkspaceRefusal::WorkspaceCapacity)?;
        if !self
            .0
            .run
            .resource_budget()
            .dominates(&ResourceVector::single(Grade::Bytes, bytes))
        {
            return Err(crate::NodeWorkspaceRefusal::WorkspaceCapacity);
        }
        Ok(())
    }

    pub(crate) fn workspace_id(&self) -> [u8; 16] {
        *self.0.authentication.agent().as_bytes()
    }

    pub(crate) fn authenticated_at(&self) -> u64 {
        self.0.authentication.authenticated_at()
    }

    pub(crate) fn expires_at(&self) -> u64 {
        self.0.authentication.expires_at()
    }
}

#[cfg(test)]
mod tests;
