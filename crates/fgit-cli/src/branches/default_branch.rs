//! Explicit operator management of the authority-selected symbolic HEAD.
//! Inspection never guesses a branch; publication retains original retry identity.

mod options;

use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode, TerminationSignals};
use fgit_schema::json::{Value, number, object, text};
use fgit_types::{
    DecisionOutcome, GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId, TxId,
};
use std::io::Write;

use super::options::{KeyInput, head_token, hex};
use super::{describe, read_key, write_terminal_receipt};
use options::{Operation, Options};

const USAGE: &str = "usage: fg branch default <storage-root> <tenant-id> <repository-id>
  --trusted-local [--object-format sha1|sha256]

usage: fg branch set-default <storage-root> <tenant-id> <repository-id>
  --trusted-local --principal <id> (--idempotency-key <key> | --key-stdin)
  (--expected-default <refs/heads/name> | --expected-default-hex <bytes> | --expect-no-default)
  (--ref <refs/heads/name> | --ref-hex <bytes>) --expected-tip <existing-commit-oid>
  [--object-format sha1|sha256]

default reads the exact canonical symbolic HEAD and its current tip. A null
default_reference_hex means no canonical target; unborn=true means a target
exists but its direct branch does not. No conventional branch name is inferred.

set-default publishes one ordinary sealed transaction. The old symbolic target
and new branch tip must match exactly at admission. The new branch must already
exist as a visible, verified native commit. It changes no direct ref or PR base.
The first trusted-local operator may act when no review-protection policy is
installed; otherwise the current canonical administrators authorize the action.
Agent, remote and narrowed ref-write sessions do not acquire this authority.

Use the independently read old target and exact target tip. No force, implicit
tip lookup, automatic expectation refresh, unset, or unborn destination is accepted.
An exact same-target request is an audited no-op, still subject to authorization.
Retry identical inputs with the original key, or use fg outcome for read-only
recovery. A timeout or missing receipt cannot prove non-commit. Stdin keys retain
every byte, including newlines, and are never printed. A leading --timeout-secs
selects the finite command deadline; signal cancellation drains admitted work.
Exit 0: committed/read; 3: canonical refusal; 2: input, infrastructure or cleanup error.";

enum Completed {
    Read(RepositoryAuthorityHeadId, Option<RefName>, Option<GitOid>),
    Published(TxId, TerminalOutcome),
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    run_with(args, &mut std::io::stdout().lock())
}

fn run_with(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    if args.len() == 2 && args[1] == "--help" {
        writeln!(output, "{USAGE}")
            .and_then(|()| output.flush())
            .map_err(|error| format!("default-branch help output failed: {error}"))?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    let session = match &options.operation {
        Operation::Read => None,
        Operation::Set { principal, key, .. } => {
            let bytes = match key {
                KeyInput::Bytes(bytes) => bytes.clone(),
                KeyInput::Stdin => read_key(&mut std::io::stdin().lock())?,
            };
            Some(LoopbackReceiveSession::authenticated(
                *principal,
                IdempotencyKey::new(bytes).map_err(|_| "invalid idempotency key")?,
            ))
        }
    };
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| format!("cannot open default-branch node: {error}"))?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        let request = fgit_cli::command_request_context(&node);
        signals
            .run_request(node.runtime(), &request, |request| {
                match &options.operation {
                    Operation::Read => node
                        .runtime()
                        .block_on(node.read_default_branch_in(request, &Default::default()))
                        .map(|(head, target, tip)| Completed::Read(head, target, tip))
                        .map_err(|error| error.to_string()),
                    Operation::Set { command, .. } => {
                        let session = session
                            .as_ref()
                            .ok_or("original operator session missing")?;
                        node.runtime()
                            .block_on(node.admit_default_branch_trusted_local_in(
                                request,
                                session,
                                command,
                                Default::default(),
                            ))
                            .map(|(tx, terminal)| Completed::Published(tx, terminal))
                            .map_err(|error| error.to_string())
                    }
                }
            })
            .map_err(|error| error.to_string())
    })();
    let (operation, monitor_cleanup) = match operation {
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
    match operation {
        Ok(Completed::Read(head, target, tip)) => {
            if let Some(error) = cleanup {
                return Err(format!("default-branch read cleanup failed: {error}"));
            }
            let receipt = read_receipt(&options, head, target.as_ref(), tip)?;
            writeln!(output, "{receipt}")
                .and_then(|()| output.flush())
                .map_err(|error| format!("default-branch read output incomplete: {error}"))?;
            Ok(0)
        }
        Ok(Completed::Published(tx, terminal)) => {
            finish_publication(output, &options, tx, &terminal, cleanup.as_deref())
        }
        Err(error) => {
            let cleanup = cleanup.map_or_else(String::new, |error| format!("; {error}"));
            if matches!(options.operation, Operation::Set { .. }) {
                Err(format!(
                    "no terminal default-branch outcome returned: {error}{cleanup}; this does not establish non-commit. Recover with fg outcome or retry the identical command and original scoped key; do not refresh the expected default or target tip"
                ))
            } else {
                Err(format!("default-branch read failed: {error}{cleanup}"))
            }
        }
    }
}

fn reference(name: Option<&RefName>) -> Value {
    name.map_or(Value::Null, |name| text(hex(name.as_bytes())))
}

fn read_receipt(
    options: &Options,
    head: RepositoryAuthorityHeadId,
    target: Option<&RefName>,
    tip: Option<GitOid>,
) -> Result<String, String> {
    if !matches!(options.operation, Operation::Read) || (target.is_none() && tip.is_some()) {
        return Err("inconsistent default-branch read receipt".into());
    }
    object([
        ("type", text("default_branch")),
        ("schema_version", number(1)),
        ("read_only", Value::Bool(true)),
        ("tenant_id", text(options.tenant.to_string())),
        ("repository_id", text(options.repository.to_string())),
        ("object_format", text(options.format.as_str())),
        ("source_head", text(head.to_string())),
        ("snapshot_token", text(head_token(head))),
        ("default_reference_hex", reference(target)),
        ("tip", tip.map_or(Value::Null, |oid| text(oid.to_string()))),
        ("unborn", Value::Bool(target.is_some() && tip.is_none())),
        ("node_closed", Value::Bool(true)),
    ])
    .encode(65535)
    .map_err(str::to_owned)
}

fn finish_publication(
    output: &mut impl Write,
    options: &Options,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let rendered = publication_receipt(options, tx, terminal, cleanup)
        .map_err(|error| format!("{error}; {}", describe(tx, terminal)))?;
    write_terminal_receipt(output, &rendered.0, tx, terminal)
        .map_err(|error| cleanup.map_or(error.clone(), |cleanup| format!("{error}; {cleanup}")))?;
    if let Some(error) = cleanup {
        return Err(format!("{}; {error}", describe(tx, terminal)));
    }
    Ok(rendered.1)
}

fn publication_receipt(
    options: &Options,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> Result<(String, u8), String> {
    let Operation::Set {
        principal, command, ..
    } = &options.operation
    else {
        return Err("default-branch publication receipt operation mismatch".into());
    };
    let (state, status, rcr, code, refusal) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            0,
            text(repository_commit_id.to_string()),
            Value::Null,
            Value::Null,
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            3,
            Value::Null,
            text(format!("{code:?}")),
            text(refusal_record_id.to_string()),
        ),
    };
    let document = object([
        ("type", text("default_branch_publication")),
        ("schema_version", number(1)),
        ("action", text("set-default")),
        ("outcome", text(state)),
        ("command_committed", Value::Bool(status == 0)),
        ("tx_id", text(tx.to_string())),
        (
            "decision_sequence",
            number(terminal.decision_sequence.get()),
        ),
        ("repository_commit_id", rcr),
        ("refusal_code", code),
        ("refusal_record_id", refusal),
        ("tenant_id", text(options.tenant.to_string())),
        ("repository_id", text(options.repository.to_string())),
        ("principal_id", text(principal.to_string())),
        ("authentication", text("operator-asserted")),
        ("object_format", text(options.format.as_str())),
        (
            "expected_default_reference_hex",
            reference(command.expected_head.as_ref()),
        ),
        ("default_reference_hex", reference(Some(&command.target))),
        (
            "expected_tip",
            text(command.expected_target_tip.to_string()),
        ),
        (
            "head_changed_by_transaction",
            Value::Bool(status == 0 && command.expected_head.as_ref() != Some(&command.target)),
        ),
        ("direct_refs_changed", Value::Bool(false)),
        ("delivery_acknowledged", Value::Null),
        ("node_closed", Value::Bool(cleanup.is_none())),
        ("cleanup_error", cleanup.map_or(Value::Null, text)),
    ]);
    Ok((document.encode(65535).map_err(str::to_owned)?, status))
}

#[cfg(test)]
mod tests;
