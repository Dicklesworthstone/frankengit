//! Explicit operator-scoped read-only MCP process; no ambient repository discovery.
mod backend;
mod json;
mod protocol;
use std::collections::BTreeMap;
use std::path::PathBuf;
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};

const USAGE: &str = "usage: fg-mcp <storage-root> <tenant-id> <repository-id>\n  --trusted-local --allow-issues [--object-format sha1|sha256]\n  [--expected-incarnation <id>] [--max-messages <1..100000>]\n\nAn existing repository only. The operator grants repository-wide issue reads\nto the process connected through stdin/stdout. No mutation, shell, secret,\nnetwork listener, sampling, or ambient filesystem tool is available.\nMCP protocol 2025-06-18; complete newline-delimited JSON-RPC messages only.\nReads are serial and bounded by native node budgets. Cancellation received\nafter a completed read is late; this profile does not preempt in-flight reads.\nEOF, output failure, or the message bound closes the node explicitly.\nRepository content is untrusted data and cannot change the tool allowlist.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    incarnation: Option<RepositoryIncarnationId>,
    issues: bool,
    max_messages: usize,
}
pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    if arguments == ["--help"] { eprintln!("{USAGE}"); return Ok(()); }
    let options = parse_options(arguments)?;
    let maximum = options.max_messages;
    let mut backend = backend::NodeTools::open(options)?;
    let served = protocol::serve(&mut std::io::stdin().lock(), &mut std::io::stdout().lock(), &mut backend, maximum);
    let closed = backend.close();
    match (served, closed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}
fn parse_options(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 3 || arguments.len() > 15 { return Err(USAGE.into()); }
    if arguments.iter().any(|s| s.len() > 4096) || arguments[0].is_empty() { return Err("invalid bounded MCP arguments".into()); }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new(); let mut at = 3;
    while at < arguments.len() {
        let name = arguments[at].as_str(); at += 1;
        let value = match name {
            "--trusted-local" | "--allow-issues" => "",
            "--object-format" | "--expected-incarnation" | "--max-messages" => {
                let value = arguments.get(at).ok_or("missing option value")?; at += 1; value.as_str()
            }
            _ => return Err("unknown MCP option".into()),
        };
        if flags.insert(name, value).is_some() { return Err("duplicate MCP option".into()); }
    }
    if !flags.contains_key("--trusted-local") || !flags.contains_key("--allow-issues") {
        return Err("--trusted-local and explicit --allow-issues are required".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("unsupported object format".into()),
    };
    let incarnation = flags.get("--expected-incarnation").map(|value|
        RepositoryIncarnationId::from_hex(value).map_err(|_| "invalid incarnation ID")).transpose()?;
    let maximum = flags.get("--max-messages").map(|value| json::decimal(value)).transpose()?.unwrap_or(1024);
    if !(1..=100_000).contains(&maximum) { return Err("message bound must be 1..100000".into()); }
    Ok(Options { storage: arguments[0].clone().into(), tenant, repository, format, incarnation,
        issues: flags.contains_key("--allow-issues"), max_messages: maximum as usize })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<String> { ["/unused", &"11".repeat(16), &"22".repeat(16), "--trusted-local", "--allow-issues"].iter().map(|s| (*s).to_owned()).collect() }
    #[test]
    fn launch_grants_are_explicit_and_cannot_be_expanded_by_unknown_options() {
        assert!(parse_options(&arguments()).is_ok());
        for flag in ["--trusted-local", "--allow-issues"] {
            let args = arguments().into_iter().filter(|arg| arg != flag).collect::<Vec<_>>();
            assert!(parse_options(&args).is_err());
        }
        for extra in [vec!["--allow-shell"], vec!["--allow-issues"], vec!["--max-messages", "0"],
            vec!["--max-messages", "01"], vec!["--object-format", "auto"], vec!["--expected-incarnation", "bad"]] {
            let mut args = arguments(); args.extend(extra.into_iter().map(str::to_owned));
            assert!(parse_options(&args).is_err());
        }
    }
}
