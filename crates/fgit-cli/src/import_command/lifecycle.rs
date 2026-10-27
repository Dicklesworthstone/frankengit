//! One import budget, one request-local stop owner, and independent finalization.
//! A cleanup failure never erases an authenticated terminal publication result.
use super::{MAX_EXPANDED_MIB, Options, receipt};
use crate::publication_support::{describe, write_terminal_receipt};
use fgit_node::{NodeRequestContext, NodeSourceImportRefusal, OneNode};
use fgit_types::{DecisionOutcome, RepositoryIncarnationId};
use std::io::Write;

/// Why an import produced no terminal decision (frankengit-6sl7).
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Failure {
    /// Refused before the source import was sealed: nothing was published.
    Refused(String),
    /// Admission had begun, so the outcome is unknown until it is resolved.
    Uncertain(String),
}

/// Classify a node refusal by the boundary that produced it. Only admission
/// can leave the outcome unknown: staging, validation, closure, identity and
/// cell-state refusals all precede sealing.
pub(super) fn failure(error: &NodeSourceImportRefusal, maximum_bytes: Option<u64>) -> Failure {
    match error {
        NodeSourceImportRefusal::Admission(_) => Failure::Uncertain(error.to_string()),
        NodeSourceImportRefusal::Staging(staging) => {
            let hint = staging
                .expanded_bytes_exceeded()
                .map_or_else(String::new, |(limit, observed)| {
                    profile_hint(limit, observed, maximum_bytes)
                });
            Failure::Refused(format!("{error}{hint}"))
        }
        NodeSourceImportRefusal::Idempotency(_)
        | NodeSourceImportRefusal::ObjectCountOutOfRange { .. }
        | NodeSourceImportRefusal::ClosureRoot(_)
        | NodeSourceImportRefusal::Validation(_)
        | NodeSourceImportRefusal::CellState(_) => Failure::Refused(error.to_string()),
    }
}

/// Name the profile flag after a byte-limit refusal. The import stops at the
/// first object past the limit, so `observed` is a lower bound on what the
/// source needs, not its size.
fn profile_hint(limit: u64, observed: u64, maximum_bytes: Option<u64>) -> String {
    const MIB: u64 = 1024 * 1024;
    let profile = match maximum_bytes {
        None => format!("the default import profile admits {} MiB", limit / MIB),
        Some(_) => format!("the selected profile admits {} MiB", limit / MIB),
    };
    let at_least = observed.div_ceil(MIB);
    if at_least > MAX_EXPANDED_MIB {
        return format!(
            "; {profile}, and this source needs more than the largest profile (--max-expanded-mib {MAX_EXPANDED_MIB})"
        );
    }
    format!(
        "; {profile}: rerun with --max-expanded-mib {at_least} or more (at most {MAX_EXPANDED_MIB}) to select a bounded disk-backed profile. The import stops counting at the first object past the limit, so the source may need more than {at_least} MiB"
    )
}

pub(super) fn execute(
    node: &OneNode,
    options: &Options,
    #[cfg(unix)] signals: fgit_node::TerminationSignals,
) -> (
    Result<receipt::AtomicImportDecision, Failure>,
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
        Err(error) => return (Err(Failure::Refused(error.to_string())), None),
    };
    let work = |request: &NodeRequestContext| -> Result<receipt::AtomicImportDecision, Failure> {
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
        .map_err(|error| failure(&error, options.maximum_bytes))?;
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
            Failure::Uncertain(format!(
                "{error}; publication may already have occurred; recover with fg outcome"
            ))
        })
    };
    #[cfg(unix)]
    {
        match signals.run_request(node.runtime(), &parent, work) {
            Ok((result, cleanup)) => (result, cleanup.err().map(|error| error.to_string())),
            // The observer acknowledges readiness before invoking work. A failed
            // startup admits no import; the caller still shuts down its node.
            Err(error) => (
                Err(Failure::Refused(format!(
                    "import signal observer startup failed: {error}"
                ))),
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
