//! Append-only PR conversations through canonical admission and pinned reads.
mod options;
#[cfg(test)]
mod tests;

use super::options::head_token;
use crate::publication_support::{describe, quote, write_terminal_receipt};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::ExpectedVersion;
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode, PullRequestCommentsPage};
use fgit_types::{DecisionOutcome, PrincipalId, TxId};
use options::{Operation, Options};
use std::io::Write;

const MAX_REPLY_BYTES: usize = 40 * 1024 * 1024;
const USAGE: &str = "\
usage: fg pr comment <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local --principal <id> --idempotency-key <key>
  --expected-version <discussion version, 0 for first comment>
  (--body <text> | --body-file <path>) [--object-format sha1|sha256]

usage: fg pr comments <storage-root> <tenant-id> <repository-id> <number>
  --trusted-local [--object-format sha1|sha256] [--limit <1..100>]
  [--after <comment version> --expected-head <snapshot-token>]

Comments append to an independent conversation stream. The expected version is
the discussion_version from a complete or paginated comments read, not the PR
metadata version. Comments do not change branch tips, PR versions or approvals.
Open, closed and merged native PRs can be discussed. There are no line anchors,
edits or deletions in this profile. Bodies are literal nonblank UTF-8, up to 64 KiB.
Retry an uncertain append using the identical principal, key, number, discussion
version and body bytes. Never refresh an uncertain request or replace its key.
Exit 0: committed append or complete page; 3: canonical refusal;
4: PR absent or hidden; 2: input/infrastructure/cleanup/output failure.";

pub(super) fn run(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args.len() == 2 && args[1] == "--help" {
        return super::write_read_report(out, USAGE).map(|()| 0);
    }
    let mut options = options::parse(args)?;
    if let Operation::Append {
        command, body_file, ..
    } = &mut options.operation
    {
        if let Some(path) = body_file {
            command.body = super::read_body_file(path)?;
        }
        options::validate_body(&command.body)?;
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| format!("cannot open comments node: {error}"))?;
    let incarnation = node.repository_incarnation_id().to_string();
    let operation = (|| -> Result<Completed, String> {
        let authority = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|error| error.to_string())?;
        if let Err(error) = node.bring_into_service(authority.receipt().generation()) {
            if matches!(options.operation, Operation::Read { .. }) {
                return Err(error.to_string());
            }
            // Exact historical retries precede intake inside OneNode. New
            // commands still meet its native intake gate.
        }
        let request = fgit_cli::command_request_context(&node);
        match &options.operation {
            Operation::Append {
                principal,
                key,
                command,
                ..
            } => {
                let session = LoopbackReceiveSession::authenticated(
                    *principal,
                    IdempotencyKey::new(key.clone()).map_err(|_| "invalid key")?,
                );
                node.runtime()
                    .block_on(node.admit_pull_request_comment_durable_in(
                        &request,
                        &session,
                        command,
                        Default::default(),
                    ))
                    .map(Completed::Append)
                    .map_err(|error| error.to_string())
            }
            Operation::Read {
                after,
                limit,
                expected_head,
            } => {
                let page = node
                    .runtime()
                    .block_on(node.read_pull_request_comments_in(
                        &request,
                        &Default::default(),
                        options.number,
                        *after,
                        *limit,
                        *expected_head,
                    ))
                    .map_err(|error| error.to_string())?;
                let report = read_report(&options, &incarnation, page.as_ref())?;
                Ok(Completed::Read(report, if page.is_some() { 0 } else { 4 }))
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok(Completed::Append((tx, terminal))) => {
            let Operation::Append {
                principal, command, ..
            } = &options.operation
            else {
                return Err("internal comment operation mismatch".into());
            };
            let report = append_report(
                &options,
                &incarnation,
                *principal,
                command.expected_version,
                tx,
                &terminal,
                cleanup.as_deref(),
            );
            if let Err(error) = write_terminal_receipt(out, &report, tx, &terminal) {
                return Err(with_cleanup(error, cleanup.as_deref()));
            }
            if let Some(error) = cleanup {
                return Err(format!(
                    "{}; comments node shutdown failed: {error}",
                    describe(tx, &terminal)
                ));
            }
            Ok(
                if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) {
                    0
                } else {
                    3
                },
            )
        }
        Ok(Completed::Read(report, exit)) => {
            if let Some(error) = cleanup {
                return Err(format!("comments node shutdown failed: {error}"));
            }
            super::write_read_report(out, &report)?;
            Ok(exit)
        }
        Err(error) => {
            let error = with_cleanup(error, cleanup.as_deref());
            if matches!(options.operation, Operation::Append { .. }) {
                Err(format!(
                    "no terminal comment outcome returned: {error}; this does not prove non-commit. Retry the identical principal, key, number, discussion version and body bytes"
                ))
            } else {
                Err(format!(
                    "comments read failed: {error}; no complete page returned"
                ))
            }
        }
    }
}

enum Completed {
    Append((TxId, TerminalOutcome)),
    Read(String, u8),
}

fn with_cleanup(error: String, cleanup: Option<&str>) -> String {
    cleanup.map_or_else(
        || error.clone(),
        |cleanup| format!("{error}; node shutdown also failed: {cleanup}"),
    )
}

fn scope(options: &Options, incarnation: &str) -> String {
    format!(
        "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"number\":{}",
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(incarnation),
        quote(options.format.as_str()),
        quote(&options.number.get().to_string())
    )
}

fn read_report(
    options: &Options,
    incarnation: &str,
    page: Option<&PullRequestCommentsPage>,
) -> Result<String, String> {
    let Operation::Read {
        after,
        limit,
        expected_head,
    } = &options.operation
    else {
        return Err("internal comment read mismatch".into());
    };
    if let Some(page) = page {
        if page.number != options.number
            || expected_head.is_some_and(|head| head != page.source_head)
        {
            return Err("comments page does not match its requested PR or snapshot".into());
        }
        page.validate_window(*after, *limit)
            .map_err(|_| "comments page does not match its pinned window")?;
    }
    let rows = page.map_or_else(Vec::new, |page| {
        page.comments
            .iter()
            .map(|comment| {
                format!(
                    "{{\"version\":{},\"actor\":{},\"body\":{}}}",
                    quote(&comment.version.get().to_string()),
                    quote(&comment.actor.to_string()),
                    quote(&comment.body)
                )
            })
            .collect::<Vec<_>>()
    });
    let report = format!(
        "{{\"type\":\"pull_request_comments\",{},\"read_only\":true,\"found\":{},\"source_head\":{},\"snapshot_token\":{},\"discussion_version\":{},\"after\":{},\"limit\":{},\"next_after\":{},\"complete\":{},\"comments\":[{}],\"node_closed\":true}}",
        scope(options, incarnation),
        page.is_some(),
        page.map_or_else(
            || "null".into(),
            |page| quote(&page.source_head.to_string())
        ),
        page.map_or_else(
            || "null".into(),
            |page| quote(&head_token(page.source_head))
        ),
        page.map_or_else(
            || "null".into(),
            |page| quote(
                &page
                    .discussion_version
                    .map_or(0, |version| version.get())
                    .to_string()
            )
        ),
        quote(&after.to_string()),
        limit,
        page.and_then(|page| page.next_after)
            .map_or_else(|| "null".into(), |version| quote(&version.to_string())),
        page.is_none_or(|page| page.next_after.is_none()),
        rows.join(",")
    );
    if report.len() > MAX_REPLY_BYTES {
        return Err("comments response exceeds its output budget".into());
    }
    Ok(report)
}

fn append_report(
    options: &Options,
    incarnation: &str,
    principal: PrincipalId,
    expected: ExpectedVersion,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> String {
    let (outcome, rcr, refusal, code, committed) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            quote(&repository_commit_id.to_string()),
            "null".into(),
            "null".into(),
            true,
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            "null".into(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            false,
        ),
    };
    let version = match expected {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    format!(
        "{{\"type\":\"pull_request_comment_publication\",{},\"action\":\"comment\",\"principal_id\":{},\"expected_version\":{},\"outcome\":{},\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_record_id\":{},\"refusal_code\":{},\"terminal\":true,\"historical_outcome\":true,\"refs_changed\":false,\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}",
        scope(options, incarnation),
        quote(&principal.to_string()),
        quote(&version.to_string()),
        quote(outcome),
        committed,
        quote(&tx.to_string()),
        quote(&terminal.decision_sequence.get().to_string()),
        rcr,
        refusal,
        code,
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote)
    )
}
