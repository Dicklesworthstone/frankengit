//! Authenticated, read-only recovery of one native agent publication.
//! Original run/tail expectations are supplied independently by the operator;
//! journal bytes never select their own anti-rollback anchor or principal.

mod options;
mod output;

use fgit_agent::ref_publication::ObservedRefTransaction;
use fgit_node::agent_journal::RecoveredAgentJournal;
use fgit_node::{
    GitDaemonSessionTimeout, NodeConfig, NodeRequestContext, OneNode, TerminationSignals,
};
use fgit_schema::json::{Value, number, object, text};
use std::io::Write;
use std::time::Duration;

const PROFILE: &str = "native-agent-publication-recovery-v1";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const USAGE: &str = "usage: fg agent recover <storage-root> <tenant-id> <repository-id> <absolute-journal-directory>
  --trusted-local --principal <original-principal-id>
  --run-id <32-lowercase-hex> --effect-id <32-lowercase-hex>
  --expected-run <64-lowercase-hex>
  --expected-tail-entries <canonical-decimal>
  --expected-tail-bytes <canonical-decimal>
  --expected-tail-digest <64-lowercase-hex>
  [--object-format sha1|sha256] [--max-output-bytes <1..1048576>]

Authenticates the persisted original IntentRun and its complete journal, then
observes exactly one native checked publication's original seal and TxId.
The principal must match that original seal. This is an explicit trusted-local
operator read, not a bearer credential or an issuing/resumed agent broker.
Supply the run commitment and acknowledged tail retained by the original host
OUTSIDE the files being recovered. Never copy an anchor from those same files.
Both original files must be regular nonsymlinks in the explicit nonsymlink
directory; a live writer, corrupt/truncated journal or changed anchor refuses.
Native recovery is bounded to 16 MiB and 32768 journal events. Default JSON
ceiling: 64 KiB. One finite request is capped at 30 seconds; global
--timeout-secs can shorten it. In-flight filesystem calls are drained.

JSON separates the canonical committed/refused/undecided observation from the
retained journal lifecycle and debt. A terminal never implies a journal ACK or
run quiescence. This command does not create a run/receipt, append an ACK,
refresh capability, resume execution, resubmit, cancel or repair anything.
No bundle, raw idempotency key or replacement mutation is accepted.
Exit 0: committed; 3: canonical refusal; 4: undecided; 2: error.
Missing/undecided outcome or failed output does not establish rollback.";

struct RecoveryObservation {
    recovered: RecoveredAgentJournal,
    canonical: Option<ObservedRefTransaction>,
}

/// Read the independently anchored original journal and its selected outcome.
pub fn run(arguments: &[String]) -> Result<u8, String> {
    run_with(arguments, &mut std::io::stdout().lock())
}

fn run_with(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["--help"] {
        writeln!(output, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = options::parse(arguments)?;
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| error.to_string())?;
    // Historical recovery does not bring the node into serving state or grant
    // mutation admission. The original run's logical clock is not reinterpreted.
    let request = node.command_request_context(Some(
        GitDaemonSessionTimeout::try_new(
            crate::command_timeout_duration().min(Duration::from_secs(30)),
        )
        .map_err(|error| error.to_string())?,
    ));
    let monitored = signals
        .run_request(node.runtime(), &request, |request| {
            node.runtime().block_on(observe(&node, request, &options))
        })
        .map_err(|error| error.to_string());
    let (operation, monitor_cleanup) = match monitored {
        Ok((operation, cleanup)) => (
            operation,
            cleanup
                .err()
                .map(|error| format!("signal cleanup failed: {error}")),
        ),
        Err(error) => (Err(error), None),
    };
    let node_cleanup = node
        .shutdown()
        .err()
        .map(|error| format!("node shutdown failed: {error}"));
    let cleanup = match (monitor_cleanup, node_cleanup) {
        (None, None) => None,
        (Some(error), None) | (None, Some(error)) => Some(error),
        (Some(monitor), Some(node)) => Some(format!("{monitor}; {node}")),
    };
    let observation = operation.map_err(|error| match &cleanup {
        None => error,
        Some(cleanup) => format!("{error}; {cleanup}"),
    })?;
    // Keep established canonical knowledge in the receipt even if shutdown
    // fails; cleanup failure changes completion/status, never the original fact.
    let (document, status) =
        output::render(&options, &observation, cleanup.as_deref()).map_err(|error| {
            format!(
                "{error}; original transaction {} was observed as {}",
                observation.recovered.journal().ref_transactions()[&options.effect].tx_id(),
                output::canonical_status(observation.canonical.as_ref())
            )
        })?;
    writeln!(output, "{document}")
        .and_then(|()| output.flush())
        .map_err(|error| {
            format!(
                "agent recovery output incomplete: {error}; original transaction {} remains {}, not proof of rollback",
                observation.recovered.journal().ref_transactions()[&options.effect].tx_id(),
                output::canonical_status(observation.canonical.as_ref()),
            )
        })?;
    Ok(status)
}

async fn observe(
    node: &OneNode,
    request: &NodeRequestContext,
    options: &options::Options,
) -> Result<RecoveryObservation, String> {
    if !request.is_live() {
        return Err("agent recovery cancelled or its finite request expired".into());
    }
    let recovered = node
        .recover_agent_journal_in(
            request,
            &options.directory,
            options.run,
            &options.expected_run,
            options.expected_tail,
        )
        .await
        .map_err(|error| error.to_string())?;
    let binding = recovered
        .journal()
        .ref_transactions()
        .get(&options.effect)
        .ok_or("selected effect is not a retained native publication")?;
    if binding.seal().authenticated_principal_id != options.principal {
        return Err("selected publication belongs to a different original principal".into());
    }
    if !recovered
        .journal()
        .records()
        .iter()
        .any(|record| record.effect_id == options.effect)
    {
        return Err("selected publication has no retained responsibility record".into());
    }
    let canonical = node
        .observe_recovered_agent_ref_transaction_in(request, &recovered, options.effect)
        .await
        .map_err(|error| error.to_string())?;
    if !request.is_live() && canonical.is_none() {
        return Err("agent recovery cancelled or its finite request expired".into());
    }
    Ok(RecoveryObservation {
        recovered,
        canonical,
    })
}

#[must_use]
pub fn error_json(error: &str) -> String {
    object([
        ("type", text("agent_recovery_error")),
        ("schema_version", number(1)),
        ("complete", Value::Bool(false)),
        ("read_only", Value::Bool(true)),
        ("error", text(error)),
    ])
    .encode(8192)
    .unwrap_or_else(|_| "{\"type\":\"agent_recovery_error\",\"schema_version\":1,\"complete\":false,\"read_only\":true,\"error\":\"response_limit\"}".into())
}
