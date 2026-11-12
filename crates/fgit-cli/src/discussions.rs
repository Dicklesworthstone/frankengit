//! Repository discussions through canonical native admission and snapshot reads.
mod options;
mod output;
#[cfg(test)]
mod tests;

use crate::publication_support::{describe, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use options::{MutationCommand, Operation};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

const MAX_BODY_BYTES: usize = 64 * 1024;
const USAGE: &str = "\
usage: fg discussion <open|edit|comment|close|reopen|lock|unlock> <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key> --expected-version <version>
  [--object-format sha1|sha256]
  open: --expected-version 0 --title <text> (--body <text> | --body-file <file>)
  edit: positive version; one or both of --title and --body/--body-file
  comment: positive version; --body <text> or --body-file <file>
  close/reopen/lock/unlock: positive version; no metadata options

usage: fg discussion append-comment <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key>
  (--body <text> | --body-file <file>) [--object-format sha1|sha256]
  Appends across concurrent changes; no expected version. Current locks still apply.

usage: fg discussion list <storage-root> <tenant-id> <repository-id> --trusted-local
  [--limit <1..100>] [--after <number> --expected-head <snapshot-token>] [--object-format sha1|sha256]
usage: fg discussion show <storage-root> <tenant-id> <repository-id> <number> --trusted-local
  [--limit <1..100>] [--after-version <version> --expected-head <snapshot-token>] [--object-format sha1|sha256]

Discussions are independent repository aggregates. Strict mutations bind exact versions;
append-comment binds the actor, number and exact body and replans only its position.
Edits preserve omitted fields; --body '' explicitly clears the description.
Locking blocks comments independently of open/closed state. History preserves exact text.
Continue reads with the original snapshot token. Retry uncertain mutations with
identical content, expected version and key, or recover using fg outcome.
This trusted local interface does not grant remote access. Remote discussion reads
and writes require their independent authenticated discussion scopes.
Exit 0: committed/read; 3: canonical refusal; 4: missing discussion; 2: input/infrastructure/output error.";

pub fn run(args: &[String]) -> Result<u8, String> {
    run_to(args, &mut std::io::stdout().lock())
}

fn run_to(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(
                args[0].as_str(),
                "open"
                    | "edit"
                    | "comment"
                    | "append-comment"
                    | "close"
                    | "reopen"
                    | "lock"
                    | "unlock"
                    | "list"
                    | "show"
            ))
    {
        write_read(out, USAGE)?;
        return Ok(0);
    }
    let mut options = options::parse(args)?;
    if let Operation::Mutate(mutation) = &mut options.operation {
        if let Some(path) = &mutation.body_file {
            let body = read_body_file(path)?;
            *options::body_slot(&mut mutation.command)? = body;
        }
        mutation.command.validate(mutation.principal)?;
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| format!("cannot open discussion node: {error}"))?;
    let result = (|| {
        let service = node
            .bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string());
        let request = fgit_cli::command_request_context(&node);
        match &options.operation {
            Operation::Mutate(mutation) => {
                // Known terminal recovery belongs before fresh intake admission.
                let session = LoopbackReceiveSession::authenticated(
                    mutation.principal,
                    IdempotencyKey::new(mutation.key.clone()).map_err(|_| "invalid retry key")?,
                );
                let result = match &mutation.command {
                    MutationCommand::Exact(command) => {
                        node.runtime().block_on(node.admit_discussion_durable_in(
                            &request,
                            &session,
                            command,
                            Default::default(),
                        ))
                    }
                    MutationCommand::Append(intent) => {
                        node.runtime()
                            .block_on(node.admit_discussion_comment_durable_in(
                                &request,
                                &session,
                                intent,
                                Default::default(),
                            ))
                    }
                };
                result
                    .map(Completed::Mutation)
                    .map_err(|error| match service {
                        Ok(()) => error.to_string(),
                        Err(service) => format!("{error}; service intake also refused: {service}"),
                    })
            }
            Operation::Read(read) => {
                service?;
                let (body, exit) = if let Some(number) = read.number {
                    let page = node
                        .runtime()
                        .block_on(node.read_discussion_history_in(
                            &request,
                            number,
                            read.after,
                            read.limit,
                            read.expected_head,
                        ))
                        .map_err(|error| error.to_string())?;
                    output::history(
                        &options,
                        read,
                        page.source_head,
                        page.discussion.as_ref(),
                        &page.events,
                        page.next_after,
                    )?
                } else {
                    let page = node
                        .runtime()
                        .block_on(node.read_discussions_in(
                            &request,
                            read.after,
                            read.limit,
                            read.expected_head,
                        ))
                        .map_err(|error| error.to_string())?;
                    output::list(
                        &options,
                        read,
                        page.source_head,
                        &page.discussions,
                        page.next_after,
                    )?
                };
                Ok(Completed::Read(body, exit))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match (&options.operation, result) {
        (Operation::Mutate(mutation), Ok(Completed::Mutation((tx, terminal)))) => {
            let receipt = output::mutation(&options, mutation, tx, &terminal, cleanup.as_deref());
            finish_receipt(out, &receipt, tx, &terminal, cleanup.as_deref())
        }
        (Operation::Read(_), Ok(Completed::Read(body, exit))) => {
            if let Some(error) = cleanup {
                return Err(format!("discussion read shutdown failed: {error}"));
            }
            write_read(out, &body)?;
            Ok(exit)
        }
        (operation, Err(error)) => {
            let cleanup = cleanup.map_or_else(String::new, |error| {
                format!("; shutdown also failed: {error}")
            });
            if matches!(operation, Operation::Mutate(_)) {
                Err(format!(
                    "no terminal discussion outcome returned: {error}{cleanup}; this is not evidence of non-commit. Recover using fg outcome with the same principal and key, or retry the identical command and content, including the expected version when supplied. Do not replace the key or change the original preconditions"
                ))
            } else {
                Err(format!("{error}{cleanup}"))
            }
        }
        _ => Err("discussion command returned an inconsistent result".into()),
    }
}

enum Completed {
    Mutation((TxId, TerminalOutcome)),
    Read(String, u8),
}

fn finish_receipt(
    out: &mut impl Write,
    receipt: &str,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    write_terminal_receipt(out, receipt, tx, terminal).map_err(|error| {
        format!(
            "{error}{}",
            cleanup.map_or_else(String::new, |error| format!(
                "; shutdown also failed: {error}"
            ))
        )
    })?;
    if let Some(error) = cleanup {
        return Err(format!(
            "{}; node shutdown failed: {error}",
            describe(tx, terminal)
        ));
    }
    Ok(match terminal.outcome {
        DecisionOutcome::Committed { .. } => 0,
        DecisionOutcome::Refused { .. } => 3,
    })
}

fn write_read(out: &mut impl Write, report: &str) -> Result<(), String> {
    writeln!(out, "{report}")
        .and_then(|()| out.flush())
        .map_err(|error| format!("discussion report output failed: {error}"))
}

fn read_body_file(path: &Path) -> Result<String, String> {
    // Stable, operator-controlled files; this interface does not claim hostile host isolation.
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("discussion body metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BODY_BYTES as u64 {
        return Err(
            "discussion body must be a regular file of at most 65536 bytes, not a symlink or device"
                .into(),
        );
    }
    let file = File::open(path).map_err(|error| format!("discussion body open: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("discussion body metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BODY_BYTES as u64 {
        return Err("discussion body changed to a non-regular or oversized file".into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve(MAX_BODY_BYTES + 1)
        .map_err(|_| "discussion body allocation refused")?;
    file.take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("discussion body read: {error}"))?;
    if bytes.len() > MAX_BODY_BYTES || bytes.contains(&0) {
        return Err("discussion body exceeds 65536 bytes or contains NUL".into());
    }
    String::from_utf8(bytes)
        .map_err(|_| "discussion body must be UTF-8; no lossy conversion is performed".into())
}
