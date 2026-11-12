//! Trusted-local cleanup of one recovered native agent publication obligation.
//!
//! The independently retained run and journal anchors identify old responsibility.
//! This command cannot issue effects or resubmit a repository transaction.

mod options;
mod output;

use fgit_agent::ref_publication::ObservedRefTransaction;
use fgit_node::agent_publication::{
    NativeRecoveredRefTransactionAbort, NativeRecoveredRefTransactionAbortRefusal,
    NativeRecoveredRefTransactionRefusal, NativeRecoveredRefTransactionSettlement,
};
use fgit_node::{GitDaemonSessionTimeout, NodeConfig, OneNode, TerminationSignals};
use fgit_schema::json::{Value, number, object, text};
use std::io::Write;
use std::time::Duration;

const PROFILE: &str = "native-agent-publication-settlement-v1";
const ABORT_PROFILE: &str = "native-agent-reservation-abort-v1";
const MIN_OUTPUT_BYTES: usize = 8192;
const USAGE: &str =
    "usage: fg agent settle <storage-root> <tenant-id> <repository-id> <absolute-journal-directory>
  --trusted-local --principal <original-principal-id>
  --run-id <32-lowercase-hex> --effect-id <32-lowercase-hex>
  --expected-run <64-lowercase-hex>
  --expected-tail-entries <canonical-decimal>
  --expected-tail-bytes <canonical-decimal>
  --expected-tail-digest <64-lowercase-hex>
  --observed-at <canonical-logical-time>
  [--action acknowledge|abort-reserved]
  [--object-format sha1|sha256] [--max-output-bytes <8192..1048576>]

The default action, acknowledge, authenticates an original native publication
and durably acknowledges its committed or refused canonical outcome. An
undecided outcome writes nothing. Explicit --action abort-reserved instead
aborts only a bound reservation whose journal proves it never reached start.
Started responsibilities and unknown suffixes refuse. Aborting a reservation
does not observe or cancel the canonical transaction; identical work may have
been submitted independently. Its canonical_status is not_observed.

The principal must match the original seal under exclusive journal custody.
Both actions write only their deterministic lifecycle frame. Neither submits a
transaction, moves refs, resumes a broker, renews capability, or proves
whole-run/process quiescence. There is no automatic fallback between actions.
Use fg agent recover for read-only inspection.

Supply the original complete-run commitment and acknowledged journal tail
retained OUTSIDE the files being recovered. Never infer these pins from those
files. --observed-at dates cleanup in the original host's logical-time domain;
it is not Unix time and does not refresh the run. Expired runs can be settled.
Retain journal.current_tail from a confirmed receipt independently afterward.

Retry the SAME action and original anchors after a lost receipt or interrupted
write. Only an exact prefix of that action's frame may follow the supplied tail;
other suffixes refuse without truncation. A complete matching frame is synced
without duplication. input_already_acknowledged or input_already_aborted describes
the supplied prefix, not a frame written by an uncertain cleanup after it.
Native custody is bounded
to 16 MiB and 32768 events. One finite request is capped at 30 seconds; a
leading --timeout-secs can shorten it. In-flight filesystem calls are drained.

JSON ceiling defaults to 64 KiB. Values below 8 KiB refuse before journal I/O.
Exit 0: committed and ACK confirmed; 3: refused and ACK confirmed;
4: undecided, unchanged journal; 2: error or incomplete cleanup/output.
For abort-reserved, exit 0 means only the reservation's Abort is confirmed.
A missing receipt or timeout proves neither rollback nor absence of a frame.";

enum SettlementResult {
    Acknowledgement(NativeRecoveredRefTransactionSettlement),
    Aborted(NativeRecoveredRefTransactionAbort),
}

/// Settle only the original selected publication under independently pinned custody.
pub fn run(arguments: &[String]) -> Result<u8, String> {
    run_with(arguments, &mut std::io::stdout().lock())
}

fn run_with(arguments: &[String], output: &mut impl Write) -> Result<u8, String> {
    if arguments == ["--help"] {
        writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = options::parse(arguments)?;
    let original = &options.original;
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let node = OneNode::open_existing(
        NodeConfig::new(
            original.storage.clone(),
            original.tenant,
            original.repository,
        )
        .with_object_format(original.format),
    )
    .map_err(|error| error.to_string())?;
    // Cleanup requires historical authentication, not serving state or permission
    // to admit fresh work. Never bring this node into mutation service here.
    let request = node.command_request_context(Some(
        GitDaemonSessionTimeout::try_new(
            crate::command_timeout_duration().min(Duration::from_secs(30)),
        )
        .map_err(|error| error.to_string())?,
    ));
    let monitored = signals
        .run_request(node.runtime(), &request, |request| match options.action {
            options::Action::Acknowledge => node
                .runtime()
                .block_on(
                    node.settle_recovered_agent_ref_transaction_for_principal_in(
                        request,
                        &original.directory,
                        original.run,
                        &original.expected_run,
                        original.expected_tail,
                        original.effect,
                        original.principal,
                        options.observed_at,
                    ),
                )
                .map(SettlementResult::Acknowledgement)
                .map_err(operation_error),
            options::Action::AbortReserved => node
                .runtime()
                .block_on(node.abort_recovered_agent_ref_transaction_for_principal_in(
                    request,
                    &original.directory,
                    original.run,
                    &original.expected_run,
                    original.expected_tail,
                    original.effect,
                    original.principal,
                    options.observed_at,
                ))
                .map(SettlementResult::Aborted)
                .map_err(abort_error),
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
    finish(output, &options, operation, cleanup.as_deref())
}

fn abort_error(error: NativeRecoveredRefTransactionAbortRefusal) -> String {
    format!(
        "{}; reservation abort durability is unconfirmed; retry abort-reserved with the original independent anchors; canonical transaction status was not observed and no resubmission is authorized",
        bounded_diagnostic(&error.to_string())
    )
}

fn operation_error(error: NativeRecoveredRefTransactionRefusal) -> String {
    let observed = match &error {
        NativeRecoveredRefTransactionRefusal::Preparation { observation, .. } => {
            Some(observation.as_ref())
        }
        NativeRecoveredRefTransactionRefusal::Persistence(failure) => {
            Some(failure.prepared().observation())
        }
        _ => None,
    };
    let known = observed.map_or_else(String::new, |observed| {
        format!("; {}", observation_fact(observed))
    });
    let diagnostic = bounded_diagnostic(&error.to_string());
    format!(
        "{diagnostic}{known}; journal acknowledgement is not confirmed; retry cleanup with the original independent anchors, never resubmit the transaction"
    )
}

fn bounded_diagnostic(error: &str) -> String {
    // JSON can expand each control character to six bytes. Keep arbitrary
    // diagnostics below the minimum receipt ceiling without shortening facts
    // about the original transaction or synchronized journal tail.
    let summary: String = error.chars().take(512).collect();
    if summary.len() == error.len() {
        summary
    } else {
        format!("{summary} [diagnostic truncated]")
    }
}

fn observation_fact(observed: &ObservedRefTransaction) -> String {
    format!(
        "original transaction {} was observed as {}",
        observed.binding().tx_id(),
        output::canonical_status(Some(observed))
    )
}

fn result_fact(result: &SettlementResult) -> String {
    match result {
        SettlementResult::Acknowledgement(NativeRecoveredRefTransactionSettlement::Undecided {
            tx_id,
            ..
        }) => {
            format!("original transaction {tx_id} is undecided; no ACK was written")
        }
        SettlementResult::Acknowledgement(
            NativeRecoveredRefTransactionSettlement::Acknowledged {
                observation,
                recovered,
                ..
            },
        ) => {
            let tail = recovered.journal().position();
            format!(
                "{}; ACK was synchronized at journal tail entries={}, bytes={}, digest={}; retry cleanup with the original independent anchors if the receipt was lost",
                observation_fact(observation),
                tail.entries,
                tail.bytes,
                output::hex(&tail.digest)
            )
        }
        SettlementResult::Aborted(result) => {
            let tail = result.recovered.journal().position();
            format!(
                "reservation for original transaction {} was aborted at synchronized journal tail entries={}, bytes={}, digest={}; canonical transaction status was not observed; retry abort-reserved with the original independent anchors if the receipt was lost",
                result.binding.tx_id(),
                tail.entries,
                tail.bytes,
                output::hex(&tail.digest)
            )
        }
    }
}

fn finish(
    output: &mut impl Write,
    options: &options::Options,
    operation: Result<SettlementResult, String>,
    cleanup_error: Option<&str>,
) -> Result<u8, String> {
    let result = operation.map_err(|error| match cleanup_error {
        None => error,
        Some(cleanup) => format!("{error}; {}", bounded_diagnostic(cleanup)),
    })?;
    // A cleanup or output failure must preserve established canonical/durability
    // knowledge. It cannot retroactively undo a synchronized lifecycle frame.
    let rendered = match &result {
        SettlementResult::Acknowledgement(result) => output::render(options, result, cleanup_error),
        SettlementResult::Aborted(result) => output::render_abort(options, result, cleanup_error),
    };
    let (document, status) =
        rendered.map_err(|error| format!("{error}; {}", result_fact(&result)))?;
    writeln!(output, "{document}")
        .and_then(|()| output.flush())
        .map_err(|error| {
            format!(
                "agent settlement output incomplete: {error}; {}",
                result_fact(&result)
            )
        })?;
    Ok(status)
}

#[must_use]
pub fn error_json(error: &str) -> String {
    object([
        ("type", text("agent_settlement_error")),
        ("schema_version", number(1)),
        ("complete", Value::Bool(false)),
        ("read_only", Value::Bool(false)),
        ("publication_authorized", Value::Bool(false)),
        ("resumption_authorized", Value::Bool(false)),
        ("error", text(error)),
    ])
    .encode(8192)
    .unwrap_or_else(|_| "{\"type\":\"agent_settlement_error\",\"schema_version\":1,\"complete\":false,\"read_only\":false,\"publication_authorized\":false,\"resumption_authorized\":false,\"error\":\"response_limit; cleanup may already be durable; retry the same action with original anchors\"}".into())
}
