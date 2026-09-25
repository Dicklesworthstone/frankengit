//! Bounded local import through the existing native admission path.
mod receipt;

use crate::publication_support::{describe, write_terminal_receipt};
use fgit_authority::IdempotencyKey;
use fgit_node::{GitDaemonSessionTimeout, NodeConfig, OneNode, RepositoryResolutionInput};
use fgit_types::{
    DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "usage: fg import <storage-root> <tenant-id-hex> <repository-id-hex> <principal-id-hex> <idempotency-key> <source-git-directory>\n\
  [--expected-incarnation <id>] [--timeout-secs <positive-integer>] [--json]\n\
Without --timeout-secs, reserve the bounded import profile using the node's receive work budget.\n\
With --timeout-secs, use that strict ceiling for source reading, validation, staging and publication.\n\
No timeout changes the import's byte/object limits or proves that an interrupted publication did not commit.\n\
With --json, emit the exact atomic terminal decision and transaction ID; refusal exits 3, errors exit 2.\n\
The original principal and key also recover the decision through fg outcome without rereading the source.\n\
The principal is supplied by the trusted local operator, not authenticated by this CLI.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    principal: PrincipalId,
    key: Vec<u8>,
    source: PathBuf,
    incarnation: Option<RepositoryIncarnationId>,
    timeout: Option<GitDaemonSessionTimeout>,
    json: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=11).contains(&args.len())
        || args.iter().any(|value| value.len() > 4096)
        || args[0].is_empty()
        || args[5].is_empty()
    {
        return Err(USAGE.into());
    }
    let mut options = Options {
        storage: args[0].clone().into(),
        tenant: TenantId::from_hex(&args[1]).map_err(|e| e.to_string())?,
        repository: RepositoryId::from_hex(&args[2]).map_err(|e| e.to_string())?,
        principal: PrincipalId::from_hex(&args[3]).map_err(|e| e.to_string())?,
        key: args[4].as_bytes().to_vec(),
        source: args[5].clone().into(),
        incarnation: None,
        timeout: None,
        json: false,
    };
    // Reject a bad retry identity before opening storage or reading a source.
    IdempotencyKey::new(options.key.clone()).map_err(|e| e.to_string())?;
    let mut index = 6;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        if flag == "--json" {
            if options.json {
                return Err("duplicate --json".into());
            }
            options.json = true;
            continue;
        }
        let value = args
            .get(index)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        index += 1;
        match flag {
            "--expected-incarnation" if options.incarnation.is_none() => {
                options.incarnation = Some(
                    RepositoryIncarnationId::from_hex(value).map_err(|e| e.to_string())?,
                );
            }
            "--timeout-secs" if options.timeout.is_none() => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("--timeout-secs requires a positive decimal integer".into());
                }
                let seconds = value
                    .parse::<u64>()
                    .map_err(|_| "--timeout-secs is outside the supported integer range")?;
                options.timeout = Some(
                    GitDaemonSessionTimeout::try_new(Duration::from_secs(seconds))
                        .map_err(|e| e.to_string())?,
                );
            }
            _ => return Err(format!("unknown or duplicate import option {flag:?}")),
        }
    }
    Ok(options)
}

pub fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        return writeln!(io::stdout().lock(), "{USAGE}")
            .map(|()| 0)
            .map_err(|e| e.to_string());
    }
    let options = parse(args)?;
    let mut config = NodeConfig::new(options.storage.clone(), options.tenant, options.repository);
    if let Some(incarnation) = options.incarnation {
        config = config
            .with_resolution_input(RepositoryResolutionInput::CapabilityToken(incarnation));
    }
    // No object-format default here: an existing repository's authenticated
    // incarnation selects SHA-1 or SHA-256 exactly as the legacy import did.
    let mut node = OneNode::open_existing(config).map_err(|e| e.to_string())?;
    if let Err(error) = node.bring_into_service(HeadGeneration::FIRST) {
        let cleanup = node.shutdown().err().map(|e| e.to_string());
        return Err(format!(
            "cannot admit source import: {error}; shutdown error: {cleanup:?}"
        ));
    }
    // Mint ONCE before any source I/O. In particular, do not replace this with
    // request_context() after the expensive staging half has spent its budget.
    let incarnation = node.repository_incarnation_id();
    let request = node.import_request_context(options.timeout);
    let result = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &options.source,
            options.principal,
            &options.key,
        ));
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let admission = result.map_err(|error| {
        format!(
            "{error}; shutdown error: {cleanup:?}. An interrupted publication is not proof of non-commit; retry the identical source refs and key or use fg outcome."
        )
    })?;
    // Native source import is atomic. Verify the complete returned mapping
    // before reducing it to one receipt; never infer success from an empty or
    // mixed command list. This is output validation, not a publication gate.
    let decision = receipt::checked_atomic(
        admission.session.atomic,
        &admission.session.tx_ids,
        &admission
            .commands
            .iter()
            .map(|command| (command.tx_id, command.terminal))
            .collect::<Vec<_>>(),
    )
    .map_err(|error| {
        format!(
            "{error}; shutdown error: {cleanup:?}; publication may already have occurred; recover with fg outcome"
        )
    })?;
    if options.json {
        let report = receipt::render(&options, incarnation, &decision, cleanup.as_deref());
        write_terminal_receipt(
            &mut io::stdout().lock(),
            &report,
            decision.tx_id,
            &decision.terminal,
        )
        .map_err(|error| format!("{error}; shutdown error: {cleanup:?}"))?;
        if let Some(error) = cleanup {
            return Err(format!(
                "{}; node shutdown failed: {error}",
                describe(decision.tx_id, &decision.terminal)
            ));
        }
        return Ok(match decision.terminal.outcome {
            DecisionOutcome::Committed { .. } => 0,
            DecisionOutcome::Refused { .. } => 3,
        });
    }
    if let DecisionOutcome::Refused { code, .. } = decision.terminal.outcome {
        return Err(format!(
            "source import reached terminal refusal: {code:?}; {}; shutdown error: {cleanup:?}",
            describe(decision.tx_id, &decision.terminal)
        ));
    }
    if let Some(error) = cleanup {
        return Err(format!(
            "{}; node shutdown failed: {error}; do not assume rollback",
            describe(decision.tx_id, &decision.terminal)
        ));
    }
    // Preserve the old text output. The shared writer retains the exact
    // transaction and terminal record even if stdout fails after publication.
    write_terminal_receipt(
        &mut io::stdout().lock(),
        &format!(
            "published {} source-import ref commands",
            decision.command_count
        ),
        decision.tx_id,
        &decision.terminal,
    )?;
    Ok(0)
}

#[cfg(test)]
mod tests;
