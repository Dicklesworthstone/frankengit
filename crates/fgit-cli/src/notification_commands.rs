//! Trusted-local self inbox operations through the same native node owners as HTTP.
mod options;
mod output;
#[cfg(test)]
mod tests;
use crate::publication_support::{describe, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use options::Operation;
use std::io::Write;

const USAGE: &str = "\
usage: fg inbox list <storage-root> <tenant-id> <repository-id>
  --trusted-local --principal <id> [--limit <1..100>] [--unread-only] [--include-muted]
  [--after <thread-number> --expected-head <snapshot-token>]
usage: fg inbox show <storage-root> <tenant-id> <repository-id> <thread-number>
  --trusted-local --principal <id> [--expected-head <snapshot-token>]
usage: fg inbox <subscribe|mute|automatic|read|unread> <storage-root> <tenant-id> <repository-id> <thread-number>
  --trusted-local --principal <id> --expected-version <preference-version>
  --idempotency-key <original-key> [--read-through <observed-thread-version>]
All commands accept [--kind issue|discussion|pull_request] (default issue),
[--object-format sha1|sha256] and [--expected-incarnation <id>].

The principal is this trusted local operator's identity, not a selected recipient.
Issue, discussion and pull request inboxes have separate preferences at the same number.
Reasons, read state and delivery preferences come
from the exact canonical source named by the response's snapshot token.
Preference version 0 creates your own preference stream. All other versions are exact.
read requires a positive --read-through from a previously observed thread version;
For pull requests, use activity_version: it counts lifecycle events, comments and reviews.
Newer activity stays unread. unread clears the read prefix. Neither changes mode.
subscribe selects the thread, mute suppresses it, automatic restores participation rules.
List continuation requires the original snapshot token and unchanged kind/filters/principal.
Retry uncertain mutations with the identical kind, number, action, version, read prefix and key,
or recover with fg outcome. Never refresh a retry's expected version.
Exit 0: read/committed; 3: canonical refusal; 4: missing thread; 2: input/I/O failure.";

pub fn run(args: &[String]) -> Result<u8, String> {
    run_to(args, &mut std::io::stdout().lock())
}
fn run_to(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(
                args[0].as_str(),
                "list" | "show" | "subscribe" | "mute" | "automatic" | "read" | "unread"
            ))
    {
        write_read(out, USAGE)?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| format!("cannot open inbox node: {error}"))?;
    let incarnation = node.repository_incarnation_id();
    let result = (|| {
        if options
            .incarnation
            .is_some_and(|expected| expected != incarnation)
        {
            return Err("inbox repository incarnation does not match the explicit binding".into());
        }
        let service = node
            .bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string());
        let request = fgit_cli::command_request_context(&node);
        match &options.operation {
            Operation::Mutate(mutation) => {
                let session = LoopbackReceiveSession::authenticated(
                    options.principal,
                    IdempotencyKey::new(mutation.key.clone()).map_err(|_| "invalid retry key")?,
                );
                // Recover an identical terminal command before fresh-intake checks.
                node.runtime()
                    .block_on(node.admit_notification_durable_in(
                        &request,
                        &session,
                        &mutation.command,
                        Default::default(),
                    ))
                    .map(Completed::Mutation)
                    .map_err(|error| match service {
                        Ok(()) => error.to_string(),
                        Err(service) => format!("{error}; service intake also refused: {service}"),
                    })
            }
            Operation::Read(read) => {
                service?;
                let session = LoopbackReceiveSession::authenticated(
                    options.principal,
                    IdempotencyKey::new(b"inbox-read-no-publication".to_vec())
                        .map_err(|_| "invalid read session")?,
                );
                let page = if let Some(target) = read.target {
                    node.runtime().block_on(node.read_notification_target_in(
                        &request,
                        &session,
                        target,
                        read.expected_head,
                    ))
                } else {
                    node.runtime()
                        .block_on(node.read_notification_inbox_for_kind_in(
                            &request,
                            &session,
                            options.kind,
                            read.after,
                            read.limit,
                            read.expected_head,
                            read.unread_only,
                            read.include_muted,
                        ))
                }
                .map_err(|error| error.to_string())?;
                output::page(&options, read, &page).map(|(body, exit)| Completed::Read(body, exit))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match (&options.operation, result) {
        (Operation::Mutate(mutation), Ok(Completed::Mutation((tx, terminal)))) => {
            let receipt = output::mutation(
                &options,
                incarnation,
                mutation,
                tx,
                &terminal,
                cleanup.as_deref(),
            )?;
            write_terminal_receipt(out, &receipt, tx, &terminal).map_err(|error| {
                format!(
                    "{error}{}",
                    cleanup
                        .as_ref()
                        .map_or_else(String::new, |e| format!("; shutdown also failed: {e}"))
                )
            })?;
            if let Some(error) = cleanup {
                return Err(format!(
                    "{}; node shutdown failed: {error}",
                    describe(tx, &terminal)
                ));
            }
            Ok(match terminal.outcome {
                DecisionOutcome::Committed { .. } => 0,
                DecisionOutcome::Refused { .. } => 3,
            })
        }
        (Operation::Read(_), Ok(Completed::Read(body, exit))) => {
            if let Some(error) = cleanup {
                return Err(format!("inbox read shutdown failed: {error}"));
            }
            write_read(out, &body)?;
            Ok(exit)
        }
        (operation, Err(error)) => {
            let cleanup =
                cleanup.map_or_else(String::new, |e| format!("; shutdown also failed: {e}"));
            if matches!(operation, Operation::Mutate(_)) {
                Err(format!(
                    "no terminal inbox outcome returned: {error}{cleanup}; this is not evidence of non-commit. Recover with fg outcome using the same principal and original key, or retry the identical action, preference version and read prefix. Do not refresh the version or replace the key"
                ))
            } else {
                Err(format!("{error}{cleanup}"))
            }
        }
        _ => Err("inbox operation returned an inconsistent result".into()),
    }
}
enum Completed {
    Mutation((TxId, TerminalOutcome)),
    Read(String, u8),
}
fn write_read(out: &mut impl Write, body: &str) -> Result<(), String> {
    writeln!(out, "{body}")
        .and_then(|()| out.flush())
        .map_err(|error| format!("inbox output failed: {error}"))
}
