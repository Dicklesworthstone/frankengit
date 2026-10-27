//! One real, read-only Agent Protocol invocation over the native node.
//!
//! Sponsorship is an explicit trusted-local operator assertion. The command
//! authenticates repository state, not a remote sponsor credential. It creates
//! no durable run, capability, workspace, task claim, or publication right.
mod options;
mod render;

use fgit_agent::{
    AuthorityReadReceipt, ClassSet, ContextControl, IntentRun, LogicalTime, OperationClass, RunId,
};
use fgit_crypto::sha256_digest;
use fgit_node::source_retrieval::agent_context::{AgentContextRead, context_packet_for_run};
use fgit_node::source_retrieval::authorization::SourceReadContext;
use fgit_node::source_retrieval::context::ContextLimits;
use fgit_node::source_retrieval::{Checkpoints, InitialLimits, InitialQuery};
use fgit_node::{GitDaemonSessionTimeout, NodeConfig, NodeRequestContext, OneNode};
use fgit_resource::{ResourceVector, algebra::Grade};
use fgit_schema::json::{Value, number, object, text};
use fgit_types::{PrincipalId, RefName, RepositoryAuthorityHeadId};
use std::io::Write;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// This profile identifies local assertion, not remote IAM or agent execution.
pub const PROFILE: &str = "agent-context-trusted-local-v1";
pub const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LIFETIME: Duration = Duration::from_secs(300);
const VERIFIER: &[u8] = b"frankengit/native-agent-context/authenticated-head/v1\0";
const RANKING: &[u8] = b"source-initial-retrieval-v1/raw-path-prefix/v1\0";

const USAGE: &str = "usage: fg agent context <storage-root> <tenant-id> <repository-id> <full-ref>
  --trusted-local --sponsor <principal-id> --term <complete-token>...
  [--object-format sha1|sha256] [--path <prefix> | --path-hex <bytes>]...
  [--symbol <Rust-name> --symbol-match exact|prefix --symbol-policy required|optional]
  [--expected-head alg:<algorithm>:<digest>] [--expires-after-secs <1..300>]
  [--max-results <1..1024>] [--max-work <units>] [--max-index-bytes <bytes>]
  [--max-files <1..32>] [--radius-bytes <0..4096>]
  [--max-source-bytes <1..67108864>] [--max-excerpt-bytes <1..1048576>]
  [--max-output-bytes <1..16777216>]

Opens a fresh read-only IntentRun at an authenticated authority head and returns
its ContextPacket plus exact source/index/omission evidence as JSON. Requires
existing lexical indexes (and symbol indexes when required). The sponsor is an
operator assertion; path prefixes narrow selection, not repository authority.
Repository excerpts are untrusted data. No task, durable run, effect, index,
workspace or repository mutation is created. Global --timeout-secs can shorten
the run's 30-second default lifetime. Exit 0: complete bounded context; 3: explicit
coverage or selection omissions; 2: refusal, with no context on stdout.";

/// Inputs shared by trusted-local CLI and MCP hosts. The host must obtain the
/// read authorization independently, before calling this function. A sponsor
/// identifier alone is never permission to read.
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

/// Cap the one command policy by the run lifetime. Hosts should pass this same
/// context through authority selection, retrieval, and hydration; no phase
/// receives a fresh deadline. The native context handles intra-phase expiry.
pub fn bounded_request_context(
    node: &OneNode,
    expires_after: Duration,
) -> Result<NodeRequestContext, String> {
    validate_lifetime(expires_after)?;
    let bound = expires_after.min(crate::command_timeout_duration());
    let timeout = GitDaemonSessionTimeout::try_new(bound).map_err(|error| error.to_string())?;
    Ok(node.command_request_context(Some(timeout)))
}

fn validate_lifetime(lifetime: Duration) -> Result<(), String> {
    if lifetime.is_zero() || lifetime > MAX_LIFETIME {
        Err("agent context lifetime must be positive and at most 300 seconds".into())
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

struct Clock {
    origin: Instant,
    logical_origin: u64,
    expiry: LogicalTime,
}
impl Clock {
    fn start(lifetime: Duration) -> Result<Self, String> {
        validate_lifetime(lifetime)?;
        let origin = Instant::now();
        let logical_origin = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or("agent context clock is outside its supported epoch")?;
        let nanos = u64::try_from(lifetime.as_nanos()).map_err(|_| "agent lifetime overflow")?;
        let expiry = logical_origin
            .checked_add(nanos)
            .ok_or("agent context expiry overflow")?;
        Ok(Self {
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
    fn check(&self, request: &NodeRequestContext) -> Result<(), String> {
        if !request.is_live() {
            return Err("agent context request interrupted".into());
        }
        if self.now() >= self.expiry {
            return Err("agent context run expired".into());
        }
        Ok(())
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
/// [`bounded_request_context`] for the trusted-local command hosts.
///
/// The native API owns disclosure, index integrity, exact source hydration,
/// cancellation and query bounds. This adapter constructs a real IntentRun and
/// binds the returned generation, coverage and lineage evidence into its final
/// ContextPacket. A read receipt is not a sponsor credential or publication key.
pub async fn read_agent_context_in(
    node: &OneNode,
    request: &NodeRequestContext,
    input: AgentContextRequest<'_>,
) -> Result<AgentContextDocument, String> {
    if !matches!(
        input.authorization.host(),
        "trusted-local-cli" | "trusted-local-mcp" | "trusted-local-native"
    ) {
        return Err("agent context requires independently authorized trusted-local reads".into());
    }
    if input.max_output_bytes == 0 || input.max_output_bytes > MAX_OUTPUT_BYTES {
        return Err("agent context output bound is outside the supported profile".into());
    }
    input
        .retrieval_limits
        .validate(input.query)
        .map_err(|error| error.to_string())?;
    input
        .context_limits
        .validate()
        .map_err(|error| error.to_string())?;
    let clock = Clock::start(input.expires_after)?;
    clock.check(request)?;
    let authenticated = node
        .authenticate_authority_head_in(request)
        .await
        .map_err(|error| error.to_string())?;
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
        return Err("agent context expected authority head changed".into());
    }
    let intent = render::intent(&input);
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
    let native = node
        .retrieve_agent_context_local_in(
            request,
            AgentContextRead {
                run: &run,
                authorization: input.authorization,
                reference: input.reference,
                query: input.query,
                checkpoints: input.checkpoints,
                retrieval_limits: input.retrieval_limits,
                context_limits: input.context_limits,
                control,
            },
            &|| clock.now(),
        )
        .await
        .map_err(|error| error.to_string())?;
    clock.check(request)?;
    let context = native.context();
    let evidence = render::evidence(context, &mut || clock.check(request))?;
    let evidence_bytes = evidence
        .encode(input.max_output_bytes)
        .map_err(str::to_owned)?;
    let evidence_commitment = commitment(
        b"frankengit/agent-context-evidence/v1\0",
        evidence_bytes.as_bytes(),
    );
    // Actual omissions and generation positions are available only after the
    // native read. Rebind the same native context with that immutable evidence;
    // do not fabricate an empty completeness claim before retrieval.
    let packet = context_packet_for_run(
        &run,
        context,
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
        context,
        &mut || clock.check(request),
    )?;
    let json = document
        .encode(input.max_output_bytes)
        .map_err(str::to_owned)?;
    clock.check(request)?;
    Ok(AgentContextDocument {
        json,
        complete: context.complete(),
    })
}

/// Actual `fg agent context` command. Success is buffered until the local node
/// has shut down, so a failed read or cleanup never discloses a partial packet.
pub fn run(arguments: &[String]) -> Result<u8, String> {
    run_with(arguments, &mut std::io::stdout().lock())
}

fn run_with(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["--help"] || arguments == ["context", "--help"] {
        writeln!(output, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let Some((operation, arguments)) = arguments.split_first() else {
        return Err(USAGE.into());
    };
    if operation != "context" {
        return Err(USAGE.into());
    }
    let options = options::parse(arguments)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| error.to_string())?;
    let operation = (|| {
        let expires_after = options.expires_after.min(crate::command_timeout_duration());
        let request = bounded_request_context(&node, expires_after)?;
        let authenticated = node
            .runtime()
            .block_on(node.authenticate_authority_head_in(&request))
            .map_err(|error| error.to_string())?;
        node.bring_into_service(authenticated.receipt().generation())
            .map_err(|error| error.to_string())?;
        let authorization = SourceReadContext::trusted_local_cli(&node);
        let checkpoints = Checkpoints::default();
        node.runtime().block_on(read_agent_context_in(
            &node,
            &request,
            AgentContextRequest {
                authorization: &authorization,
                reference: &options.reference,
                query: &options.query,
                checkpoints: &checkpoints,
                retrieval_limits: options.retrieval_limits,
                context_limits: options.context_limits,
                sponsor: options.sponsor,
                expected_head: options.expected_head,
                expires_after,
                max_output_bytes: options.max_output_bytes,
            },
        ))
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let document = match (operation, cleanup) {
        (Ok(document), None) => document,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("agent context node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    output
        .write_all(document.json.as_bytes())
        .map_err(|error| error.to_string())?;
    // Count the usual line terminator against the same egress envelope. A
    // document exactly at the bound remains valid JSON without that byte.
    if document.json.len() < options.max_output_bytes {
        output.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())?;
    Ok(if document.complete { 0 } else { 3 })
}

/// Machine-readable stderr refusal. No source excerpt accompanies an error.
pub fn error_json(error: &str) -> String {
    object([
        ("type", text("agent_context_error")),
        ("schema_version", number(1)),
        ("complete", Value::Bool(false)),
        ("error", text(error)),
    ])
    .encode(MAX_OUTPUT_BYTES)
    .unwrap_or_else(|_| "{\"type\":\"agent_context_error\",\"error\":\"response_limit\"}".into())
}
