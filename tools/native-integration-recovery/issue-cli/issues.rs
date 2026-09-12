//! Native issue lifecycle through canonical node admission, not a CLI-owned DB.
mod options;
mod output;
#[cfg(test)]
mod tests;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::event::issue::MAX_BODY_BYTES;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use crate::publication_support::{describe, write_terminal_receipt};
use options::{Mutation, Operation, Options};

const USAGE: &str = "\
usage: fg issue <open|edit|close|reopen|comment> <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key> --expected-version <version>
  [--object-format sha1|sha256]
  open: --expected-version 0 --title <text> (--body <text> | --body-file <file>) [--label <text> ...]
  edit: positive version; one or more of --title, --body/--body-file, --label ... or --clear-labels
  comment: positive version; --body <text> or --body-file <file>
  close/reopen: positive version; no title, body or label options

usage: fg issue list <storage-root> <tenant-id> <repository-id> --trusted-local
  [--limit <1..100>] [--after <number> --expected-head <snapshot-token>] [--object-format sha1|sha256]
usage: fg issue show <storage-root> <tenant-id> <repository-id> <number> --trusted-local
  [--limit <1..100>] [--after-version <version> --expected-head <snapshot-token>] [--object-format sha1|sha256]

Edits preserve omitted fields; --body '' clears a body; --clear-labels clears labels.
Show returns current issue state plus paged, exact actions/comments at one snapshot.
Every mutation requires a stable retry key and explicit predecessor. No latest-version refresh.
Exit 0: committed/read; 3: canonical refusal; 4: missing issue; 2: input/infrastructure/output error.
This is a trusted local repository interface, not remote authentication or an issue ACL.";

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] || (arguments.len() == 2 && arguments[1] == "--help"
        && matches!(arguments[0].as_str(), "open" | "edit" | "close" | "reopen" | "comment" | "list" | "show"))
    { return write_read(&mut std::io::stdout().lock(), USAGE).map(|()| 0); }
    let mut options = options::parse(arguments)?;
    if let Operation::Mutate(mutation) = &mut options.operation {
        if let Some(path) = &mutation.body_file {
            let bytes = read_body_file(path)?;
            *options::body_slot(&mut mutation.command)? = bytes;
        }
        mutation.command.proposed_event(mutation.principal).map_err(|_| "invalid issue command or file contents")?;
    }
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)).map_err(|error| format!("cannot open issue node: {error}"))?;
    let result = (|| {
        let service = node.bring_into_service(HeadGeneration::FIRST).map_err(|error| error.to_string());
        let request = node.request_context();
        match &options.operation {
            Operation::Mutate(mutation) => {
                // A historical decision precedes new-publication eligibility
                // inside the node API. Do not discard it because service intake
                // now refuses. Unknown commands still hit that same intake gate.
                let session = LoopbackReceiveSession::authenticated(mutation.principal,
                    IdempotencyKey::new(mutation.key.clone()).map_err(|_| "invalid retry key")?);
                node.runtime().block_on(node.admit_issue_durable_in(&request, &session, &mutation.command, Default::default()))
                    .map(Completed::Mutation).map_err(|error| match service {
                        Ok(()) => error.to_string(),
                        Err(service) => format!("{error}; service intake also refused: {service}"),
                    })
            }
            Operation::Read(read) => {
                service?;
                let (receipt, exit) = if let Some(number) = read.number {
                    let page = node.runtime().block_on(node.read_issue_history_in(&request, number, read.after, read.limit, read.expected_head))
                        .map_err(|error| error.to_string())?;
                    output::history(&options, read, page.source_head, page.issue.as_ref(), &page.events, page.next_after)?
                } else {
                    let page = node.runtime().block_on(node.read_issues_in(&request, read.after, read.limit, read.expected_head))
                        .map_err(|error| error.to_string())?;
                    output::list(&options, read, page.source_head, &page.issues, page.next_after)?
                };
                Ok(Completed::Read(receipt, exit))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match (&options.operation, result) {
        (Operation::Mutate(mutation), Ok(Completed::Mutation((tx, terminal)))) =>
            finish_mutation(&mut std::io::stdout().lock(), &options, mutation, tx, &terminal, cleanup.as_deref()),
        (Operation::Read(_), Ok(Completed::Read(receipt, exit))) => {
            if let Some(error) = cleanup { return Err(format!("issue read shutdown failed: {error}")); }
            write_read(&mut std::io::stdout().lock(), &receipt)?; Ok(exit)
        }
        (operation, Err(error)) => {
            let cleanup = cleanup.map_or_else(String::new, |value| format!("; shutdown also failed: {value}"));
            if matches!(operation, Operation::Mutate(_)) {
                Err(format!("no terminal issue outcome returned: {error}{cleanup}; this is not evidence of non-commit. Recover using fg outcome with the same principal and key, or retry the identical command, version and content. Do not replace the key or refresh the expected version"))
            } else { Err(format!("issue read failed: {error}{cleanup}; no complete result returned")) }
        }
        _ => Err(format!("issue operation/result mismatch; cleanup: {cleanup:?}")),
    }
}
enum Completed { Mutation((TxId, TerminalOutcome)), Read(String, u8) }
fn finish_mutation(output: &mut impl Write, options: &Options, mutation: &Mutation, tx: TxId,
    terminal: &TerminalOutcome, cleanup: Option<&str>) -> Result<u8, String> {
    let receipt = output::mutation(options, mutation, tx, terminal, cleanup);
    if let Err(error) = write_terminal_receipt(output, &receipt, tx, terminal) {
        return Err(format!("{error}{}", cleanup.map_or_else(String::new, |value| format!("; shutdown also failed: {value}"))));
    }
    if let Some(error) = cleanup { return Err(format!("{}; node shutdown failed: {error}", describe(tx, terminal))); }
    Ok(match terminal.outcome { DecisionOutcome::Committed { .. } => 0, DecisionOutcome::Refused { .. } => 3 })
}
fn write_read(output: &mut impl Write, report: &str) -> Result<(), String> {
    writeln!(output, "{report}").and_then(|()| output.flush()).map_err(|error| format!("issue report output failed: {error}"))
}
fn read_body_file(path: &Path) -> Result<String, String> {
    // Stable operator-controlled regular files; not a hostile-filesystem API.
    let before = fs::symlink_metadata(path).map_err(|error| format!("issue body metadata: {error}"))?;
    if !before.is_file() || before.len() > MAX_BODY_BYTES as u64 { return Err("issue body must be a regular file of at most 65536 bytes, not a symlink or device".to_owned()); }
    let file = File::open(path).map_err(|error| format!("issue body open: {error}"))?;
    let opened = file.metadata().map_err(|error| format!("issue body metadata: {error}"))?;
    if !opened.is_file() || opened.len() > MAX_BODY_BYTES as u64 { return Err("issue body changed to a non-regular or oversized file".to_owned()); }
    let mut bytes = Vec::new();
    bytes.try_reserve(MAX_BODY_BYTES + 1).map_err(|_| "issue body allocation refused")?;
    file.take((MAX_BODY_BYTES + 1) as u64).read_to_end(&mut bytes).map_err(|error| format!("issue body read: {error}"))?;
    if bytes.len() > MAX_BODY_BYTES || bytes.contains(&0) { return Err("issue body exceeds 65536 bytes or contains NUL".to_owned()); }
    String::from_utf8(bytes).map_err(|_| "issue body must be UTF-8; no lossy conversion is performed".to_owned())
}
