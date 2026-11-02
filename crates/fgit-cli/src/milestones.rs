//! Repository milestones through canonical native admission and snapshot reads.
mod options;
mod output;
#[cfg(test)]
mod tests;

use crate::publication_support::{describe, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use options::Operation;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

const MAX_BODY_BYTES: usize = 64 * 1024;
const USAGE: &str = "\
usage: fg milestone <open|edit|close|reopen> <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key> --expected-version <version>
  [--object-format sha1|sha256]
  open: --expected-version 0 --title <text> (--body <text> | --body-file <file>) [--due-at <unix-seconds>]
  edit: positive version; --title, --body/--body-file, --due-at or --clear-due-at
  close/reopen: positive version; no metadata options

usage: fg milestone list <storage-root> <tenant-id> <repository-id> --trusted-local
  [--limit <1..100>] [--after <number> --expected-head <snapshot-token>] [--object-format sha1|sha256]
usage: fg milestone show <storage-root> <tenant-id> <repository-id> <number> --trusted-local
  [--limit <1..100>] [--after-version <version> --expected-head <snapshot-token>] [--object-format sha1|sha256]

Milestones have repository-local positive numbers and one exact aggregate version.
Dates are optional UTC Unix seconds, from 0 through 253402300799 (year 9999).
Edits preserve omitted fields; --body '' clears text and --clear-due-at removes the date.
Issue memberships survive milestone edits and close/reopen. Progress counts are derived
from issues at the same snapshot as the milestone; closing a milestone does not close issues.
Attach issues using fg issue set-milestone with both exact predecessor versions.
Use fg issue clear-milestone to remove membership, including from a closed milestone.
Use fg issue search --milestone <number|none> to select assigned or unassigned issues.
Retry an uncertain mutation with the identical command, expected version and key, or fg outcome.
Do not refresh a retry's predecessor. Receipts describe the original terminal decision.
This is a trusted local repository interface. Remote access requires authenticated issue grants.
Exit 0: committed/read; 3: canonical refusal; 4: missing milestone; 2: input/infrastructure/output error.";

pub fn run(args: &[String]) -> Result<u8, String> {
    run_to(args, &mut std::io::stdout().lock())
}

fn run_to(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(
                args[0].as_str(),
                "open" | "edit" | "close" | "reopen" | "list" | "show"
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
        mutation
            .command
            .proposed_event(mutation.principal)
            .map_err(|_| "invalid milestone command or file contents")?;
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| format!("cannot open milestone node: {error}"))?;
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
                node.runtime()
                    .block_on(node.admit_milestone_durable_in(
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
                let (body, exit) = if let Some(number) = read.number {
                    let page = node
                        .runtime()
                        .block_on(node.read_milestone_history_in(
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
                        page.milestone.as_ref(),
                        &page.events,
                        page.next_after,
                    )?
                } else {
                    let page = node
                        .runtime()
                        .block_on(node.read_milestones_in(
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
                        &page.milestones,
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
                return Err(format!("milestone read shutdown failed: {error}"));
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
                    "no terminal milestone outcome returned: {error}{cleanup}; this is not evidence of non-commit. Recover using fg outcome with the same principal and key, or retry the identical command, version and content. Do not replace the key or refresh the expected version"
                ))
            } else {
                Err(format!("{error}{cleanup}"))
            }
        }
        _ => Err("milestone command returned an inconsistent result".into()),
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
        .map_err(|error| format!("milestone report output failed: {error}"))
}

fn read_body_file(path: &Path) -> Result<String, String> {
    // Stable, operator-controlled files; this interface does not claim hostile host isolation.
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("milestone body metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BODY_BYTES as u64 {
        return Err(
            "milestone body must be a regular file of at most 65536 bytes, not a symlink or device"
                .into(),
        );
    }
    let file = File::open(path).map_err(|error| format!("milestone body open: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("milestone body metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BODY_BYTES as u64 {
        return Err("milestone body changed to a non-regular or oversized file".into());
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve(MAX_BODY_BYTES + 1)
        .map_err(|_| "milestone body allocation refused")?;
    file.take((MAX_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("milestone body read: {error}"))?;
    if bytes.len() > MAX_BODY_BYTES || bytes.contains(&0) {
        return Err("milestone body exceeds 65536 bytes or contains NUL".into());
    }
    String::from_utf8(bytes)
        .map_err(|_| "milestone body must be UTF-8; no lossy conversion is performed".into())
}
