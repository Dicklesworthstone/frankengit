//! Trusted-local CLI adapter for the native Agent Protocol document reader.
//! Sponsorship remains an explicit operator assertion, not a remote credential.
mod options;

pub use fgit_node::source_retrieval::agent_context::document::{
    AgentContextDocument, AgentContextRequest, MAX_LIFETIME, MAX_OUTPUT_BYTES, PROFILE,
};
use fgit_node::source_retrieval::authorization::SourceReadContext;
use fgit_node::source_retrieval::context::ContextLimits;
use fgit_node::source_retrieval::{Checkpoints, InitialLimits, InitialQuery};
use fgit_node::{GitDaemonSessionTimeout, NodeConfig, NodeRequestContext, OneNode};
use fgit_schema::json::{Value, number, object, text};
use std::io::Write;
use std::time::Duration;

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

/// Preserve the trusted-local CLI/embedding API; HTTP uses the native core
/// through the authenticated source gateway, never this local opt-in wrapper.
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
    fgit_node::source_retrieval::agent_context::document::read_agent_context_in(
        node, request, input,
    )
    .await
    .map_err(|error| error.to_string())
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
