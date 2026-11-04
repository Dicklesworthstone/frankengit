//! Shared bounded Agent Protocol document for native, CLI, MCP and HTTP hosts.
//! Hosts supply independent source-read authorization. Credential sponsorship is
//! bound to that read credential, while trusted-local sponsorship is explicit
//! operator attribution. These profiles create no durable run or write right.
mod render;

use super::{
    AgentContextRead, AgentContextReadError, context_packet_for_revalidated_run,
    context_packet_for_run,
};
use crate::source_retrieval::authorization::SourceReadContext;
use crate::source_retrieval::context::{
    ContextFile, ContextLimits, InitialContext, RevalidatedInitialContext,
};
use crate::source_retrieval::{Checkpoints, InitialLimits, InitialQuery};
use crate::{NodeRefusal, NodeRequestContext, OneNode};
use fgit_agent::{
    AuthorityReadReceipt, ClassSet, ContextControl, ContextPacket, IntentRun, LogicalTime,
    OperationClass, RunId,
};
use fgit_crypto::sha256_digest;
use fgit_resource::{ResourceVector, algebra::Grade};
use fgit_types::{PrincipalId, RefName, RepositoryAuthorityHeadId};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Explicit local sponsor attribution, not remote IAM or agent execution.
pub const PROFILE: &str = "agent-context-trusted-local-v1";
/// Repository source-read authentication from the existing HTTP credential host.
pub const HTTP_PROFILE: &str = "agent-context-http-credential-v1";
/// Canonical sponsored agent authentication, retaining the original request's
/// principal, sponsor and finite lifetime through this read-only context.
pub const HTTP_AGENT_PROFILE: &str = "agent-context-http-sponsored-agent-v1";
/// Canonical sponsored MCP authentication, distinct from trusted-local MCP
/// attribution and retaining the verified request's original finite lifetime.
pub const MCP_AGENT_PROFILE: &str = "agent-context-mcp-sponsored-agent-v1";
/// Explicit index-source selection; independent of the authenticated host.
pub const CURRENT_NATIVE_INDEX_SOURCE: &str = "current-native-v1";
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LIFETIME: Duration = Duration::from_secs(300);
const VERIFIER: &[u8] = b"frankengit/native-agent-context/authenticated-head/v1\0";
const RANKING: &[u8] = b"source-initial-retrieval-v1/raw-path-prefix/v1\0";

/// Preserve transport-independent refusals without flattening native resource,
/// source, authority or cancellation failures into an empty successful packet.
#[derive(Debug)]
pub enum AgentContextDocumentError {
    SponsorAuthorization,
    InvalidInput(&'static str),
    AuthorityHeadChanged,
    Interrupted,
    Expired,
    OutputLimit,
    Authority(NodeRefusal),
    Native(AgentContextReadError),
    Evidence(String),
}
impl core::fmt::Display for AgentContextDocumentError {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SponsorAuthorization => {
                out.write_str("agent context sponsor does not match source authorization")
            }
            Self::InvalidInput(reason) => out.write_str(reason),
            Self::AuthorityHeadChanged => {
                out.write_str("agent context expected authority head changed")
            }
            Self::Interrupted => out.write_str("agent context request interrupted"),
            Self::Expired => out.write_str("agent context run expired"),
            Self::OutputLimit => out.write_str("agent context output exceeds its byte bound"),
            Self::Authority(error) => write!(out, "{error}"),
            Self::Native(error) => write!(out, "{error}"),
            Self::Evidence(error) => out.write_str(error),
        }
    }
}
impl core::error::Error for AgentContextDocumentError {}
impl From<String> for AgentContextDocumentError {
    fn from(error: String) -> Self {
        Self::Evidence(error)
    }
}
impl From<&'static str> for AgentContextDocumentError {
    fn from(error: &'static str) -> Self {
        Self::Evidence(error.into())
    }
}

const fn profile(input: &AgentContextRequest<'_>) -> &'static str {
    if input.authorization.is_mcp_agent_credential() {
        MCP_AGENT_PROFILE
    } else if input.authorization.agent_authentication().is_some() {
        HTTP_AGENT_PROFILE
    } else if input.authorization.principal().is_some() {
        HTTP_PROFILE
    } else {
        PROFILE
    }
}
const fn sponsor_authentication(input: &AgentContextRequest<'_>) -> &'static str {
    if input.authorization.agent_authentication().is_some() {
        "canonical-agent-credential"
    } else if input.authorization.principal().is_some() {
        "http-repository-read-credential"
    } else {
        "operator-asserted"
    }
}

/// Inputs shared by independently authorized source-read hosts. The sponsor
/// must match the read credential's verified sponsor, or be explicit local
/// operator attribution. An agent remains distinct from its sponsor. A sponsor
/// identifier alone never grants read permission.
pub struct AgentContextRequest<'a> {
    pub authorization: &'a SourceReadContext,
    pub reference: &'a RefName,
    pub query: &'a InitialQuery,
    pub checkpoints: &'a Checkpoints,
    pub retrieval_limits: InitialLimits,
    pub context_limits: ContextLimits,
    pub sponsor: PrincipalId,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expires_after: Duration,
    pub max_output_bytes: usize,
}

/// A complete buffered answer. No excerpt is released on a failed read.
pub struct AgentContextDocument {
    pub json: String,
    pub complete: bool,
}

#[derive(Clone, Copy)]
enum IndexSource {
    Strict,
    CurrentNative,
}

// Keep the native result types distinct all the way through packet binding.
// In particular, a current observation never becomes fictitious index source.
enum NativeContext {
    Strict(InitialContext),
    Revalidated(RevalidatedInitialContext),
}
impl NativeContext {
    fn files(&self) -> &[ContextFile] {
        match self {
            Self::Strict(context) => context.files(),
            Self::Revalidated(context) => context.files(),
        }
    }
    fn complete(&self) -> bool {
        match self {
            Self::Strict(context) => context.complete(),
            Self::Revalidated(context) => context.complete(),
        }
    }
    fn evidence(
        &self,
        live: &mut impl FnMut() -> Result<(), String>,
    ) -> Result<fgit_schema::json::Value, String> {
        match self {
            Self::Strict(context) => render::evidence(context, live),
            Self::Revalidated(context) => render::revalidated_evidence(context, live),
        }
    }
    fn packet(
        &self,
        run: &IntentRun,
        control: ContextControl,
    ) -> Result<ContextPacket, super::AgentContextRefusal> {
        match self {
            Self::Strict(context) => context_packet_for_run(run, context, control),
            Self::Revalidated(context) => context_packet_for_revalidated_run(run, context, control),
        }
    }
}

fn validate_lifetime(lifetime: Duration) -> Result<(), AgentContextDocumentError> {
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        Err(AgentContextDocumentError::InvalidInput(
            "agent context lifetime must be positive and at most 300 seconds",
        ))
    } else {
        Ok(())
    }
}

fn read_scope() -> ClassSet {
    ClassSet::from_classes(&[
        OperationClass::ReadCanonicalObject,
        OperationClass::ReadDerivedGeneration,
    ])
}

struct Clock<'a> {
    authorization: &'a SourceReadContext,
    origin: Instant,
    logical_origin: u64,
    expiry: LogicalTime,
}
impl<'a> Clock<'a> {
    fn start(
        lifetime: Duration,
        authorization: &'a SourceReadContext,
    ) -> Result<Self, AgentContextDocumentError> {
        let origin = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "agent context clock is outside its supported epoch")?;
        Self::start_at(lifetime, authorization, origin, wall)
    }
    fn start_at(
        mut lifetime: Duration,
        authorization: &'a SourceReadContext,
        origin: Instant,
        wall: Duration,
    ) -> Result<Self, AgentContextDocumentError> {
        validate_lifetime(lifetime)?;
        if let Some(authentication) = authorization.agent_authentication() {
            if wall < Duration::from_secs(authentication.authenticated_at()) {
                return Err(AgentContextDocumentError::Expired);
            }
            let remaining_wall = Duration::from_secs(authentication.expires_at())
                .checked_sub(wall)
                .unwrap_or(Duration::ZERO);
            let remaining_monotonic = authorization
                .agent_deadline()
                .map_or(Duration::ZERO, |deadline| {
                    deadline.saturating_duration_since(origin)
                });
            lifetime = lifetime.min(remaining_wall).min(remaining_monotonic);
            if lifetime.is_zero() {
                return Err(AgentContextDocumentError::Expired);
            }
        }
        let logical_origin = u64::try_from(wall.as_nanos())
            .map_err(|_| "agent context clock is outside its supported epoch")?;
        let nanos = u64::try_from(lifetime.as_nanos()).map_err(|_| "agent lifetime overflow")?;
        let expiry = logical_origin
            .checked_add(nanos)
            .ok_or("agent context expiry overflow")?;
        Ok(Self {
            authorization,
            origin,
            logical_origin,
            expiry: LogicalTime::new(expiry),
        })
    }
    fn now(&self) -> LogicalTime {
        LogicalTime::new(
            self.logical_origin.saturating_add(
                u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
            ),
        )
    }
    fn check(&self, request: &NodeRequestContext) -> Result<(), AgentContextDocumentError> {
        match crate::source_retrieval::live(request) {
            Ok(()) => {}
            Err(crate::source_retrieval::RetrievalError::Source(
                crate::NodeWorkspaceRefusal::Cancelled { exhaustion: None },
            )) => return Err(AgentContextDocumentError::Interrupted),
            Err(error) => {
                return Err(AgentContextDocumentError::Native(
                    AgentContextReadError::Retrieval(error),
                ));
            }
        }
        if self.now() >= self.expiry || !self.authorization.is_live() {
            return Err(AgentContextDocumentError::Expired);
        }
        Ok(())
    }
}

fn check_sponsor(
    authorization: &SourceReadContext,
    sponsor: PrincipalId,
) -> Result<(), AgentContextDocumentError> {
    match authorization.sponsor() {
        Some(expected) if expected == sponsor => Ok(()),
        None if matches!(
            authorization.host(),
            "trusted-local-cli" | "trusted-local-mcp" | "trusted-local-native"
        ) =>
        {
            Ok(())
        }
        _ => Err(AgentContextDocumentError::SponsorAuthorization),
    }
}

fn commitment(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(domain.len() + 8 + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    input.extend_from_slice(bytes);
    sha256_digest(&input)
}

/// Execute one authenticated, bounded context read. The caller's request must
/// have a deadline no later than `expires_after`; use
/// a bounded native request context selected by the host.
///
/// The native API owns disclosure, index integrity, exact source hydration,
/// cancellation and query bounds. This adapter constructs a real IntentRun and
/// binds the returned generation, coverage and lineage evidence into its final
/// ContextPacket. A read receipt is not a sponsor credential or publication key.
pub async fn read_agent_context_in(
    node: &OneNode,
    request: &NodeRequestContext,
    input: AgentContextRequest<'_>,
) -> Result<AgentContextDocument, AgentContextDocumentError> {
    read_agent_context_with_source_in(node, request, input, IndexSource::Strict).await
}

/// Explicitly read existing indexes revalidated against the current native
/// source. The request commitment includes `index_source=current-native-v1`;
/// the host authentication profile and original index provenance are retained.
///
/// This sibling never changes the strict entrypoint's source joins, intent
/// bytes or rendered shape. Both modes share the same sponsor, run, lifetime,
/// resource, packet binding and all-or-nothing output enforcement below.
pub async fn read_agent_context_revalidated_in(
    node: &OneNode,
    request: &NodeRequestContext,
    input: AgentContextRequest<'_>,
) -> Result<AgentContextDocument, AgentContextDocumentError> {
    read_agent_context_with_source_in(node, request, input, IndexSource::CurrentNative).await
}

async fn read_agent_context_with_source_in(
    node: &OneNode,
    request: &NodeRequestContext,
    input: AgentContextRequest<'_>,
    index_source: IndexSource,
) -> Result<AgentContextDocument, AgentContextDocumentError> {
    input
        .authorization
        .check_node(node)
        .map_err(|_| AgentContextDocumentError::SponsorAuthorization)?;
    check_sponsor(input.authorization, input.sponsor)?;
    if input.max_output_bytes == 0 || input.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err(AgentContextDocumentError::InvalidInput(
            "agent context output bound is outside the supported profile",
        ));
    }
    input
        .retrieval_limits
        .validate(input.query)
        .map_err(|error| error.to_string())?;
    input
        .context_limits
        .validate()
        .map_err(|error| error.to_string())?;
    let clock = Clock::start(input.expires_after, input.authorization)?;
    clock.check(request)?;
    let authenticated = node
        .authenticate_authority_head_in(request)
        .await
        .map_err(AgentContextDocumentError::Authority)?;
    clock.check(request)?;
    let receipt = AuthorityReadReceipt::from_authenticated_head(
        &authenticated,
        clock.now(),
        sha256_digest(VERIFIER),
    )
    .map_err(|error| error.to_string())?;
    if input
        .expected_head
        .is_some_and(|expected| expected != receipt.authority_head_id())
    {
        return Err(AgentContextDocumentError::AuthorityHeadChanged);
    }
    let intent = match index_source {
        IndexSource::Strict => render::intent(&input),
        IndexSource::CurrentNative => render::revalidated_intent(&input),
    };
    let intent_bytes = intent.encode(128 * 1024).map_err(str::to_owned)?;
    let request_commitment = commitment(
        b"frankengit/agent-context-request/v1\0",
        intent_bytes.as_bytes(),
    );
    // There is exactly one read in this invocation. These are the actual
    // retrieval/hydration byte envelopes, not measured CPU/RSS or billing.
    let bytes = (input.retrieval_limits.max_payload_bytes as u64)
        .checked_add(input.context_limits.max_source_bytes as u64)
        .and_then(|n| n.checked_add(input.retrieval_limits.max_result_bytes as u64))
        .and_then(|n| n.checked_add(input.context_limits.max_excerpt_bytes as u64))
        .ok_or("agent context byte reservation overflow")?;
    let budget = ResourceVector::single(Grade::Bytes, bytes)
        .with(Grade::EgressBytes, input.max_output_bytes as u64);
    // Run IDs are derived, not supplied by the caller. Bind the exact read,
    // run budget/expiry and complete request so changed semantics cannot reuse
    // an arbitrary coordination ID in this nonpersistent profile.
    let seed = IntentRun::new_authenticated(
        RunId::new(0),
        receipt.clone(),
        read_scope(),
        budget,
        clock.expiry,
    )
    .map_err(|error| error.to_string())?;
    let mut identity = Vec::from(
        *seed
            .commitment()
            .map_err(|error| error.to_string())?
            .as_bytes(),
    );
    identity.extend_from_slice(&request_commitment);
    let digest = commitment(b"frankengit/agent-context-run-id/v1\0", &identity);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    let run = IntentRun::new_authenticated(
        RunId::new(u128::from_be_bytes(id)),
        receipt,
        read_scope(),
        budget,
        clock.expiry,
    )
    .map_err(|error| error.to_string())?;
    let ranking = sha256_digest(RANKING);
    let control = ContextControl::new(request_commitment, read_scope(), ranking, vec![], vec![]);
    let read = AgentContextRead {
        run: &run,
        authorization: input.authorization,
        reference: input.reference,
        query: input.query,
        checkpoints: input.checkpoints,
        retrieval_limits: input.retrieval_limits,
        context_limits: input.context_limits,
        control,
    };
    let context = match index_source {
        IndexSource::Strict => NativeContext::Strict(
            node.retrieve_agent_context_local_in(request, read, &|| clock.now())
                .await
                .map_err(AgentContextDocumentError::Native)?
                .into_parts()
                .0,
        ),
        IndexSource::CurrentNative => NativeContext::Revalidated(
            node.retrieve_agent_context_revalidated_local_in(request, read, &|| clock.now())
                .await
                .map_err(AgentContextDocumentError::Native)?
                .into_parts()
                .0,
        ),
    };
    clock.check(request)?;
    let evidence = context
        .evidence(&mut || clock.check(request).map_err(|error| error.to_string()))
        .map_err(|error| {
            clock
                .check(request)
                .err()
                .unwrap_or(AgentContextDocumentError::Evidence(error))
        })?;
    let evidence_bytes = evidence
        .encode(input.max_output_bytes)
        .map_err(|_| AgentContextDocumentError::OutputLimit)?;
    let evidence_commitment = commitment(
        b"frankengit/agent-context-evidence/v1\0",
        evidence_bytes.as_bytes(),
    );
    // Actual omissions and generation positions are available only after the
    // native read. Rebind the same native context with that immutable evidence;
    // do not fabricate an empty completeness claim before retrieval.
    let packet = context
        .packet(
            &run,
            ContextControl::new(
                request_commitment,
                read_scope(),
                ranking,
                vec![],
                vec![evidence_commitment],
            ),
        )
        .map_err(|error| error.to_string())?;
    clock.check(request)?;
    let document = render::document(
        &input,
        &run,
        &packet,
        intent,
        evidence,
        evidence_commitment,
        context.files(),
        context.complete(),
        &mut || clock.check(request).map_err(|error| error.to_string()),
    )
    .map_err(|error| {
        clock
            .check(request)
            .err()
            .unwrap_or(AgentContextDocumentError::Evidence(error))
    })?;
    let json = document
        .encode(input.max_output_bytes)
        .map_err(|_| AgentContextDocumentError::OutputLimit)?;
    clock.check(request)?;
    Ok(AgentContextDocument {
        json,
        complete: context.complete(),
    })
}

#[cfg(test)]
mod tests;
