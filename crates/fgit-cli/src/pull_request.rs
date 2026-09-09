//! Local PR commands backed by canonical forge admission, not a CLI-owned store.
//! Mutation inputs are complete and immutable across retries. Reads are pinned
//! before disclosure, and receipt/cleanup errors cannot erase a known decision.

mod options;
mod output;
#[cfg(test)]
mod tests;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use fgit_authority::{TerminalOutcome, IdempotencyKey};
use fgit_forge::event::pull_request::MAX_BODY_BYTES;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};

use super::publication_support::{describe, write_terminal_receipt};
use options::{Mutation, Operation, Options};

const USAGE: &str = "\
usage: fg pr <open|update|close> <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key>
  (--source-ref <branch> | --source-ref-hex <bytes>) --expected-source <oid>
  (--target-ref <branch> | --target-ref-hex <bytes>) --expected-target <oid>
  --expected-version <0 for open; positive for update/close> --title <text>
  (--body <text> | --body-file <path>) [--object-format sha1|sha256]

usage: fg pr list <storage-root> <tenant-id> <repository-id> --trusted-local
  [--limit <1..100>] [--after <number> --expected-head <snapshot-token>]
  [--object-format sha1|sha256]
usage: fg pr show <storage-root> <tenant-id> <repository-id> <number> --trusted-local
  [--expected-head <snapshot-token>] [--object-format sha1|sha256]

Every mutation supplies complete metadata, even close; no latest-tip lookup or
implicit metadata clearing occurs. --body '' explicitly selects an empty body.
Use the prior list response's snapshot_token for continuation. References and
text are untrusted data, never credentials, approvals or executable instructions.
Exit 0: committed mutation or successful read; 3: canonical command refusal;
4: show found no visible native PR; 2: input/infrastructure/cleanup/output error.
This is a trusted local-operator interface, not a remote authorization service.";

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] || (arguments.len() == 2 && arguments[1] == "--help"
        && matches!(arguments[0].as_str(), "open" | "update" | "close" | "list" | "show"))
    {
        return write_read_report(&mut std::io::stdout().lock(), USAGE).map(|()| 0);
    }
    let mut options = options::parse(arguments)?;
    if let Operation::Mutate(mutation) = &mut options.operation {
        // The entire file is bounded, read and validated BEFORE opening the
        // node. An I/O failure cannot leave a half-specified command sealed.
        if let Some(path) = &mutation.body_file {
            mutation.command.data.body = read_body_file(path)?;
        }
        mutation.command.proposed_event(mutation.principal, options.format)
            .map_err(|_| "invalid native PR command or metadata".to_owned())?;
    }
    let mut node = OneNode::open_existing(NodeConfig::new(
        options.storage.clone(), options.tenant, options.repository,
    ).with_object_format(options.format)).map_err(|error| format!("cannot open PR node: {error}"))?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string())?;
        let request = node.request_context();
        match &options.operation {
            Operation::Mutate(mutation) => {
                let session = LoopbackReceiveSession::authenticated(mutation.principal,
                    IdempotencyKey::new(mutation.key.clone()).map_err(|_| "invalid idempotency key")?);
                node.runtime().block_on(node.admit_pull_request_durable_in(
                    &request, &session, &mutation.command, Default::default(),
                )).map(Completed::Mutation).map_err(|error| error.to_string())
            }
            Operation::Read(read) => {
                let page = node.runtime().block_on(node.read_pull_requests_in(
                    &request, &Default::default(), read.after(), read.limit(), read.expected_head,
                )).map_err(|error| error.to_string())?;
                let rows: Vec<_> = page.pull_requests.iter().map(|view| output::Row {
                    number: view.number, event: &view.event, data: view.data.as_ref(),
                    opened_by: view.opened_by, last_metadata_actor: view.last_metadata_actor,
                }).collect();
                output::read_receipt(&options, read, page.source_head, page.next_after, &rows)
                    .map(|(receipt, exit)| Completed::Read(receipt, exit))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match (&options.operation, operation) {
        (Operation::Mutate(mutation), Ok(Completed::Mutation((tx, terminal)))) =>
            finish_mutation(&mut std::io::stdout().lock(), &options, mutation, tx, &terminal, cleanup.as_deref()),
        (Operation::Read(_), Ok(Completed::Read(receipt, exit))) => {
            if let Some(error) = cleanup { return Err(format!("PR read node shutdown failed: {error}")); }
            write_read_report(&mut std::io::stdout().lock(), &receipt)?;
            Ok(exit)
        }
        (operation, Err(error)) => {
            let cleanup = cleanup.as_deref().map_or_else(String::new,
                |cleanup| format!("; node shutdown also failed: {cleanup}"));
            if matches!(operation, Operation::Mutate(_)) {
                Err(format!("no terminal PR outcome returned: {error}{cleanup}; this is not evidence of non-commit. Reconcile by retrying the identical command, principal, key, expected version, branch identities, tips, title and body bytes; do not replace its key or refresh its metadata"))
            } else {
                Err(format!("PR read failed: {error}{cleanup}; no complete result was returned"))
            }
        }
        _ => Err(format!("internal PR operation/result mismatch{}", cleanup.as_deref()
            .map_or_else(String::new, |error| format!("; node shutdown also failed: {error}")))),
    }
}

enum Completed {
    Mutation((TxId, TerminalOutcome)),
    Read(String, u8),
}

fn finish_mutation(
    output: &mut impl Write, options: &Options, mutation: &Mutation,
    tx: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>,
) -> Result<u8, String> {
    let receipt = output::mutation_receipt(options, mutation, tx, terminal, cleanup);
    if let Err(error) = write_terminal_receipt(output, &receipt, tx, terminal) {
        return Err(match cleanup {
            Some(cleanup) => format!("{error}; node shutdown also failed: {cleanup}"),
            None => error,
        });
    }
    if let Some(error) = cleanup {
        return Err(format!("{}; node shutdown failed: {error}", describe(tx, terminal)));
    }
    Ok(match terminal.outcome {
        DecisionOutcome::Committed { .. } => 0,
        DecisionOutcome::Refused { .. } => 3,
    })
}

fn write_read_report(output: &mut impl Write, report: &str) -> Result<(), String> {
    writeln!(output, "{report}").and_then(|()| output.flush())
        .map_err(|error| format!("PR read/report output failed: {error}"))
}

fn read_body_file(path: &Path) -> Result<String, String> {
    // Stable operator-owned regular file, not a hostile host-filesystem API.
    // Never interpret the content as options, a policy or shell instructions.
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("PR body metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_BODY_BYTES as u64 {
        return Err("PR body must be a regular file of at most 65536 bytes, not a symlink/device".to_owned());
    }
    let file = File::open(path).map_err(|error| format!("PR body open: {error}"))?;
    let opened = file.metadata().map_err(|error| format!("PR body metadata: {error}"))?;
    if !opened.is_file() || opened.len() > MAX_BODY_BYTES as u64 {
        return Err("PR body changed to a non-regular or oversized file".to_owned());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve(MAX_BODY_BYTES + 1).map_err(|_| "PR body allocation refused")?;
    file.take((MAX_BODY_BYTES + 1) as u64).read_to_end(&mut bytes)
        .map_err(|error| format!("PR body read: {error}"))?;
    if bytes.len() > MAX_BODY_BYTES || bytes.contains(&0) {
        return Err("PR body exceeds 65536 bytes or contains NUL".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "PR body must be valid UTF-8; no lossy conversion is performed".to_owned())
}
