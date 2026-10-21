//! One import budget, one request-local stop owner, and independent finalization.
//! A cleanup failure never erases an authenticated terminal publication result.
use super::{Options, receipt};
use crate::publication_support::{describe, write_terminal_receipt};
use fgit_node::{NodeRequestContext, OneNode};
use fgit_types::{DecisionOutcome, RepositoryIncarnationId};
use std::io::Write;

pub(super) fn execute(
    node: &OneNode,
    options: &Options,
    #[cfg(unix)] signals: fgit_node::TerminationSignals,
) -> (
    Result<receipt::AtomicImportDecision, String>,
    Option<String>,
) {
    // Preserve the import's byte/work profile and absolute deadline. The signal
    // relay derives from THIS request, never a new default Database request.
    let parent = match options.maximum_bytes {
        None => Ok(node.import_request_context(options.timeout)),
        Some(maximum) => node.import_request_context_with_byte_limit(options.timeout, maximum),
    };
    let parent = match parent {
        Ok(parent) => parent,
        Err(error) => return (Err(error.to_string()), None),
    };
    let work = |request: &NodeRequestContext| -> Result<receipt::AtomicImportDecision, String> {
        let admission = match options.maximum_bytes {
            None => node
                .runtime()
                .block_on(node.import_loose_git_directory_durable_in(
                    request,
                    &options.source,
                    options.principal,
                    &options.key,
                )),
            Some(maximum) => {
                node.runtime()
                    .block_on(node.import_loose_git_directory_with_byte_limit_durable_in(
                        request,
                        &options.source,
                        options.principal,
                        &options.key,
                        maximum,
                    ))
            }
        }
        .map_err(|error| error.to_string())?;
        // A source import is atomic. Validate its complete returned mapping,
        // not an empty or mixed collection mistaken for successful publication.
        receipt::checked_atomic(
            admission.session.atomic,
            &admission.session.tx_ids,
            &admission
                .commands
                .iter()
                .map(|c| (c.tx_id, c.terminal))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| {
            format!("{error}; publication may already have occurred; recover with fg outcome")
        })
    };
    #[cfg(unix)]
    {
        match signals.run_request(node.runtime(), &parent, work) {
            Ok((result, cleanup)) => (result, cleanup.err().map(|error| error.to_string())),
            // The observer acknowledges readiness before invoking work. A failed
            // startup admits no import; the caller still shuts down its node.
            Err(error) => (
                Err(format!("import signal observer startup failed: {error}")),
                None,
            ),
        }
    }
    #[cfg(not(unix))]
    {
        (work(&parent), None)
    }
}

pub(super) fn finish(
    output: &mut impl Write,
    options: &Options,
    incarnation: RepositoryIncarnationId,
    decision: &receipt::AtomicImportDecision,
    node_error: Option<&str>,
    observer_error: Option<&str>,
) -> Result<u8, String> {
    // The existing JSON describes canonical knowledge and actual node shutdown.
    // Observer failure is a separate command failure, not a fabricated rollback
    // or a claim that a successfully closed node remained open. Keep the normal
    // v1 receipt byte-for-byte stable for current consumers.
    if options.json {
        write_terminal_receipt(
            output,
            &receipt::render(options, incarnation, decision, node_error),
            decision.tx_id,
            &decision.terminal,
        )
        .map_err(|error| {
            format!(
                "{error}; signal observer error: {observer_error:?}; shutdown error: {node_error:?}"
            )
        })?;
    } else if let DecisionOutcome::Refused { code, .. } = decision.terminal.outcome {
        return Err(format!(
            "source import reached terminal refusal: {code:?}; {}; signal observer error: {observer_error:?}; shutdown error: {node_error:?}",
            describe(decision.tx_id, &decision.terminal),
        ));
    } else {
        write_terminal_receipt(
            output,
            &format!(
                "published {} source-import ref commands",
                decision.command_count
            ),
            decision.tx_id,
            &decision.terminal,
        )
        .map_err(|error| {
            format!(
                "{error}; signal observer error: {observer_error:?}; shutdown error: {node_error:?}"
            )
        })?;
    }
    if observer_error.is_some() || node_error.is_some() {
        return Err(format!(
            "{}; signal observer error: {observer_error:?}; shutdown error: {node_error:?}; do not assume rollback",
            describe(decision.tx_id, &decision.terminal),
        ));
    }
    Ok(match decision.terminal.outcome {
        DecisionOutcome::Committed { .. } => 0,
        DecisionOutcome::Refused { .. } => 3,
    })
}

#[cfg(test)]
mod tests;
