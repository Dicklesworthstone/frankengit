//! Bounded local import through the existing native admission path.
use fgit_authority::IdempotencyKey;
use fgit_node::{
    GitDaemonSessionTimeout, NodeConfig, OneNode, RepositoryResolutionInput,
};
use fgit_types::{
    DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "usage: fg import <storage-root> <tenant-id-hex> <repository-id-hex> <principal-id-hex> <idempotency-key> <source-git-directory>\n\
  [--expected-incarnation <id>] [--timeout-secs <positive-integer>]\n\
Without --timeout-secs, reserve the bounded import profile using the node's receive work budget.\n\
With --timeout-secs, use that strict ceiling for source reading, validation, staging and publication.\n\
No timeout changes the import's byte/object limits or proves that an interrupted publication did not commit.\n\
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
}

fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=10).contains(&args.len())
        || (args.len() - 6) % 2 != 0
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
    };
    // Reject a bad retry identity before opening storage or reading a source.
    IdempotencyKey::new(options.key.clone()).map_err(|e| e.to_string())?;
    for pair in args[6..].chunks_exact(2) {
        match pair[0].as_str() {
            "--expected-incarnation" if options.incarnation.is_none() => {
                options.incarnation = Some(
                    RepositoryIncarnationId::from_hex(&pair[1]).map_err(|e| e.to_string())?,
                );
            }
            "--timeout-secs" if options.timeout.is_none() => {
                let token = &pair[1];
                if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("--timeout-secs requires a positive decimal integer".into());
                }
                let seconds = token.parse::<u64>()
                    .map_err(|_| "--timeout-secs is outside the supported integer range")?;
                options.timeout = Some(
                    GitDaemonSessionTimeout::try_new(Duration::from_secs(seconds))
                        .map_err(|e| e.to_string())?,
                );
            }
            _ => return Err(format!("unknown or duplicate import option {:?}", pair[0])),
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
    let mut config = NodeConfig::new(options.storage, options.tenant, options.repository);
    if let Some(incarnation) = options.incarnation {
        config = config.with_resolution_input(RepositoryResolutionInput::CapabilityToken(incarnation));
    }
    // No object-format default here: an existing repository's authenticated
    // incarnation selects SHA-1 or SHA-256 exactly as the legacy import did.
    let mut node = OneNode::open_existing(config).map_err(|e| e.to_string())?;
    if let Err(error) = node.bring_into_service(HeadGeneration::FIRST) {
        let cleanup = node.shutdown().err().map(|e| e.to_string());
        return Err(format!("cannot admit source import: {error}; shutdown error: {cleanup:?}"));
    }
    // Mint ONCE before any source I/O. In particular, do not replace this with
    // request_context() after the expensive staging half has spent its budget.
    let request = node.import_request_context(options.timeout);
    let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(
        &request,
        &options.source,
        options.principal,
        &options.key,
    ));
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let admission = result.map_err(|error| format!(
        "{error}; shutdown error: {cleanup:?}. An interrupted publication is not proof of non-commit; retry the identical source refs and key or use fg outcome."
    ))?;
    if let Some(code) = admission.commands.iter().find_map(|command| {
        match command.terminal.outcome {
            DecisionOutcome::Refused { code, .. } => Some(code),
            DecisionOutcome::Committed { .. } => None,
        }
    }) {
        return Err(format!("source import reached terminal refusal: {code:?}; shutdown error: {cleanup:?}"));
    }
    let count = admission.commands.len();
    if let Some(error) = cleanup {
        return Err(format!("published {count} source-import ref commands, but node shutdown failed: {error}; do not assume rollback"));
    }
    let mut out = io::stdout().lock();
    writeln!(out, "published {count} source-import ref commands")
        .and_then(|()| out.flush())
        .map_err(|error| format!("source import is committed, but writing its receipt failed: {error}; do not assume rollback"))?;
    Ok(0)
}

#[cfg(test)]
mod tests;
