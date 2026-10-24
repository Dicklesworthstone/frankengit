//! Bounded local import through the existing native admission path.
mod lifecycle;
mod receipt;

use fgit_authority::IdempotencyKey;
use fgit_node::{GitDaemonSessionTimeout, NodeConfig, OneNode, RepositoryResolutionInput};
use fgit_types::{HeadGeneration, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

/// The largest `--max-expanded-mib` profile.
const MAX_EXPANDED_MIB: u64 = 16_384;

const USAGE: &str = "usage: fg import <storage-root> <tenant-id-hex> <repository-id-hex> <principal-id-hex> <idempotency-key> <source-git-directory>\n\
  [--expected-incarnation <id>] [--timeout-secs <positive-integer>] [--max-expanded-mib <1..16384>] [--json]\n\
Without a local or leading global --timeout-secs, reserve the bounded import profile using the node's receive work budget.\n\
A local or leading global --timeout-secs bounds source reading, validation, staging and publication; when both are supplied, the smaller ceiling wins.\n\
The default reachable-body limit is 512 MiB; --max-expanded-mib selects a bounded disk-backed profile.\n\
Packed-source, per-object and graph-work bounds remain independent.\n\
No timeout changes the import's byte/object limits or proves that an interrupted publication did not commit.\n\
On Unix, SIGTERM/SIGINT request cooperative cancellation under that same budget, then join the observer and shut down the node.\n\
Repeated signals do not skip cleanup. Already-entered OS I/O is not preemptible; SIGKILL cannot drain.\n\
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
    maximum_bytes: Option<u64>,
    json: bool,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if !(6..=13).contains(&args.len())
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
        maximum_bytes: None,
        json: false,
    };
    // Reject a bad retry identity before opening storage or reading a source.
    // An empty key would give every such import the same identity.
    if options.key.is_empty() {
        return Err("the idempotency key must not be empty".into());
    }
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
                options.incarnation =
                    Some(RepositoryIncarnationId::from_hex(value).map_err(|e| e.to_string())?);
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
            "--max-expanded-mib" if options.maximum_bytes.is_none() => {
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("--max-expanded-mib requires an integer in 1..=16384".into());
                }
                let mib = value
                    .parse::<u64>()
                    .ok()
                    .filter(|mib| (1..=MAX_EXPANDED_MIB).contains(mib))
                    .ok_or("--max-expanded-mib requires an integer in 1..=16384")?;
                options.maximum_bytes = Some(mib * 1024 * 1024);
            }
            _ => return Err(format!("unknown or duplicate import option {flag:?}")),
        }
    }
    Ok(options)
}

fn effective_timeout(
    local: Option<GitDaemonSessionTimeout>,
    global: Option<Duration>,
) -> Result<Option<GitDaemonSessionTimeout>, String> {
    let duration = match (local.map(GitDaemonSessionTimeout::duration), global) {
        (Some(local), Some(global)) => Some(local.min(global)),
        (local, global) => local.or(global),
    };
    duration
        .map(GitDaemonSessionTimeout::try_new)
        .transpose()
        .map_err(|e| e.to_string())
}

pub fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        return writeln!(io::stdout().lock(), "{USAGE}")
            .map(|()| 0)
            .map_err(|e| e.to_string());
    }
    let mut options = parse(args)?;
    options.timeout = effective_timeout(
        options.timeout,
        fgit_cli::command_timeout_override_duration(),
    )?;
    #[cfg(unix)]
    let signals = fgit_node::TerminationSignals::install()
        .map_err(|error| format!("cannot own import interruption: {error}; source not read"))?;
    let mut config = NodeConfig::new(options.storage.clone(), options.tenant, options.repository);
    if let Some(incarnation) = options.incarnation {
        config =
            config.with_resolution_input(RepositoryResolutionInput::CapabilityToken(incarnation));
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
    let (result, observer_error) = lifecycle::execute(
        &node,
        &options,
        #[cfg(unix)]
        signals,
    );
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let decision = result.map_err(|failure| {
        describe_failure(failure, observer_error.as_deref(), cleanup.as_deref())
    })?;
    lifecycle::finish(
        &mut io::stdout().lock(),
        &options,
        incarnation,
        &decision,
        cleanup.as_deref(),
        observer_error.as_deref(),
    )
}

/// The command's error text for an import with no terminal decision. Only a
/// failure after admission began carries the non-commit caveat; a refusal
/// before the import was sealed published nothing (frankengit-6sl7).
fn describe_failure(
    failure: lifecycle::Failure,
    observer_error: Option<&str>,
    cleanup: Option<&str>,
) -> String {
    match failure {
        lifecycle::Failure::Refused(error) => format!(
            "{error}; signal observer error: {observer_error:?}; shutdown error: {cleanup:?}. Refused before the import was sealed: nothing was published."
        ),
        lifecycle::Failure::Uncertain(error) => format!(
            "{error}; signal observer error: {observer_error:?}; shutdown error: {cleanup:?}. An interrupted publication is not proof of non-commit; retry the identical source refs and key or use fg outcome."
        ),
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod profile_tests;
