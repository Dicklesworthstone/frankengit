//! Trusted-local issuance and revocation of canonical sponsored credentials.
mod options;
mod output;
#[cfg(test)]
mod tests;
mod token;

use crate::publication_support::{describe, write_terminal_receipt};
use fgit_authority::TerminalOutcome;
use fgit_identity::{AgentCredentialAction, AgentCredentialCommand, agent_credential_id};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{DecisionOutcome, HeadGeneration, TxId};
use options::{Operation, Options};
use std::io::Write;

const USAGE: &str = "\
usage: fg agent-credential generate-token --output <new-private-file>
usage: fg agent-credential issue <storage-root> <tenant-id> <repository-id>
  --trusted-local --incarnation <id> --principal <sponsor-id> --agent <agent-id>
  --sponsor-kind human|service --token-file <private-file>
  --issued-at <unix-seconds> --expires-at <unix-seconds>
  --operations <comma-separated-scopes> --idempotency-key <key>
  [--object-format sha1|sha256]
usage: fg agent-credential revoke <storage-root> <tenant-id> <repository-id>
  --trusted-local --incarnation <id> --principal <administrator-id>
  --credential-id <64-lowercase-hex> --expected-version 1 --idempotency-key <key>
  [--object-format sha1|sha256]
usage: fg agent-credential show <storage-root> <tenant-id> <repository-id>
  --trusted-local --incarnation <id> [--credential-id <64-lowercase-hex>]
  [--object-format sha1|sha256]

Scopes: issues-read, issues-write, pulls-read, pulls-write,
        discussions-read, discussions-write, outcomes-read, source-read.
source-read permits current source browsing, ref/tag discovery, search and context.
Every scope is independent. This initial profile cannot grant source/Git writes,
reviews, merges, policy administration, secrets or external effects.
Canonical credentials authenticate an agent and its explicitly attested sponsor;
the request host must additionally enforce a bounded sponsored IntentRun.
Without an installed administrator policy, issuance/revocation trusts the explicit
local repository operator. Once canonical review protection exists, its current
administrators must authorize both operations. An administrator can revoke another
sponsor's credential; revocation permanently retains the original grant.
Times are Unix seconds; maximum lifetime is 30 days. Keep both times and the retry
key unchanged when retrying. A new token requires a new issuance, never replacement.
Token files contain fgagent_ followed by 64 lowercase hex digits and optionally one LF.
Tokens are accepted only from files, never command arguments or printed receipts.
On Unix token files must have no group/world permissions; generated files use 0600.
show without --credential-id lists all retained grants, including revoked credentials.
Exit 0: committed/read; 3: canonical refusal; 4: missing credential; 2: other error.";

pub fn run(args: &[String]) -> Result<u8, String> {
    run_to(args, &mut std::io::stdout().lock())
}

fn run_to(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"]
        || (args.len() == 2
            && args[1] == "--help"
            && matches!(
                args[0].as_str(),
                "generate-token" | "issue" | "revoke" | "show"
            ))
    {
        writeln!(out, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = match options::parse(args)? {
        Options::Generate { output } => return token::generate(&output, out),
        Options::Repository(options) => options,
    };
    // Validate secret input before opening repository resources. The secret is
    // immediately reduced to its digest and never enters command receipts.
    let issue = if let Operation::Issue {
        grant, token_file, ..
    } = &options.operation
    {
        let bearer = token::read(token_file)?;
        Some(AgentCredentialCommand {
            id: agent_credential_id(&bearer).map_err(|error| error.to_string())?,
            expected_version: fgit_forge::ExpectedVersion::NewStream,
            action: AgentCredentialAction::Issue(*grant),
        })
    } else {
        None
    };
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_expected_repository_incarnation(options.incarnation),
    )
    .map_err(|error| error.to_string())?;
    let service = node
        .bring_into_service(HeadGeneration::FIRST)
        .map_err(|error| error.to_string());
    let request = fgit_cli::command_request_context(&node);
    let result: Result<Completed, String> = (|| {
        match &options.operation {
            Operation::Show { id } => {
                service?;
                if let Some(id) = id {
                    let state = node
                        .runtime()
                        .block_on(node.read_agent_credential_in(&request, *id))
                        .map_err(|error| error.to_string())?;
                    Ok(Completed::Read(
                        output::single(*id, state.as_ref()),
                        if state.is_some() { 0 } else { 4 },
                    ))
                } else {
                    let states = node
                        .runtime()
                        .block_on(node.read_agent_credentials_in(&request))
                        .map_err(|error| error.to_string())?;
                    Ok(Completed::Read(output::list(&states), 0))
                }
            }
            Operation::Issue { principal, key, .. } | Operation::Revoke { principal, key, .. } => {
                let command = match &options.operation {
                    Operation::Issue { .. } => issue.ok_or("missing prepared issuance")?,
                    Operation::Revoke {
                        id,
                        expected_version,
                        ..
                    } => {
                        // Revocation carries the immutable original grant, so
                        // this read is identical even after a successful retry.
                        let state = node
                            .runtime()
                            .block_on(node.read_agent_credential_in(&request, *id))
                            .map_err(|error| error.to_string())?
                            .ok_or("credential does not exist")?;
                        AgentCredentialCommand {
                            id: *id,
                            expected_version: *expected_version,
                            action: AgentCredentialAction::Revoke(state.grant),
                        }
                    }
                    Operation::Show { .. } => return Err("credential operation mismatch".into()),
                };
                let session = LoopbackReceiveSession::authenticated(*principal, key.clone());
                node.runtime()
                    .block_on(node.admit_agent_credential_durable_in(
                        &request,
                        &session,
                        &command,
                        Default::default(),
                    ))
                    .map(|(tx, terminal)| Completed::Mutation {
                        command,
                        tx,
                        terminal,
                    })
                    .map_err(|error| match service {
                        Ok(()) => error.to_string(),
                        Err(service) => format!("{error}; service intake also refused: {service}"),
                    })
            }
        }
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match result {
        Ok(Completed::Read(body, exit)) => {
            if let Some(error) = cleanup {
                return Err(format!("credential read shutdown failed: {error}"));
            }
            writeln!(out, "{body}")
                .and_then(|()| out.flush())
                .map_err(|error| error.to_string())?;
            Ok(exit)
        }
        Ok(Completed::Mutation {
            command,
            tx,
            terminal,
        }) => {
            let body = output::mutation(&command, tx, &terminal, cleanup.as_deref());
            write_terminal_receipt(out, &body, tx, &terminal)?;
            if let Some(error) = cleanup {
                return Err(format!(
                    "{}; shutdown failed: {error}",
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
        Err(error)
            if matches!(
                options.operation,
                Operation::Issue { .. } | Operation::Revoke { .. }
            ) =>
        {
            Err(format!(
                "no terminal credential outcome returned: {error}; shutdown error: {cleanup:?}; this is not evidence of non-commit. Recover with fg outcome using the same principal and key, or retry the identical command, dates and expected version"
            ))
        }
        Err(error) => Err(format!("{error}; shutdown error: {cleanup:?}")),
    }
}

enum Completed {
    Read(String, u8),
    Mutation {
        command: AgentCredentialCommand,
        tx: TxId,
        terminal: TerminalOutcome,
    },
}
