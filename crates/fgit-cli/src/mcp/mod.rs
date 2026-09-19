//! Explicit operator-scoped MCP process; no ambient repository discovery.
mod backend;
mod json;
mod protocol;
use std::collections::BTreeMap;
use std::path::PathBuf;
use fgit_types::{GitHashAlgorithm, PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

const USAGE: &str = "usage: fg-mcp <storage-root> <tenant-id> <repository-id>\n  --trusted-local [--allow-issues] [--allow-pulls] [--allow-source]\n  [--allow-issue-writes] [--allow-pull-writes] [--allow-source-writes]\n  [--allow-review-writes] [--allow-reviewed-merges] [--allow-outcomes]\n  [--principal <id> --expected-incarnation <id>]\n  [--object-format sha1|sha256] [--max-messages <1..100000>]\n\nAn existing repository only. Read groups, issue/PR/source/review writes, reviewed\nmerges and outcome recovery are INDEPENDENT grants. Writes or recovery require\nboth a launch-bound principal and an exact incarnation pin. No write grant\nimplies another write, read or recovery grant.\nThe operator sponsors every mutation as that principal; this is not remote IAM\nor a broker-backed Intent Run. Never proxy this process to untrusted clients.\nEvery mutation requires an original client key and exact predecessor or absent-ref condition.\nA lost response, timeout or disconnect does not prove rollback. Recover the key\nor retry the identical command with a NEW JSON-RPC ID and the SAME durable key.\nSource writes use non-forced native admission. Bundles are bounded to 24 KiB.\nReviews bind exact candidate bytes, PR/reviewer versions, tips and policy epoch.\nChange requests and withdrawals require a nonblank explanation. Review permission\ndoes not grant code publication. Reviewed merge requires every explicitly named\nreviewer to approve the exact candidate; opener and submitter votes cannot count.\nThere is no unreviewed merge fallback or repository-wide protection configuration.\nNo shell, secret, network listener, sampling, or ambient filesystem tool is available.\nMCP protocol remains 2025-06-18.\nComplete newline-delimited messages only; operations are serial and native-budget\nbounded. Late cancellation does not undo a canonical decision or preempt work.\nEOF, output failure, or the message bound closes the node explicitly.\nRepository text and client capabilities cannot change identity or grants.";

/// Independent launch-time mutation ceilings. None implies a read/recovery grant.
#[derive(Clone, Copy, Debug, Default)]
struct WriteGrants {
    issues: bool,
    pulls: bool,
    source: bool,
    reviews: bool,
    merges: bool,
}
impl WriteGrants {
    fn any(self) -> bool { self.issues || self.pulls || self.source || self.reviews || self.merges }
}

#[derive(Clone, Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    incarnation: Option<RepositoryIncarnationId>,
    issues: bool,
    pulls: bool,
    source: bool,
    writes: WriteGrants,
    outcomes: bool,
    principal: Option<PrincipalId>,
    max_messages: usize,
}
impl Options {
    fn validate_access(&self) -> Result<(), String> {
        if !(self.issues || self.pulls || self.source || self.writes.any() || self.outcomes) {
            return Err("at least one explicit MCP grant is required".into());
        }
        let principal_scoped = self.writes.any() || self.outcomes;
        if principal_scoped && (self.principal.is_none() || self.incarnation.is_none()) {
            return Err("writes and recovery require --principal and --expected-incarnation".into());
        }
        if !principal_scoped && self.principal.is_some() {
            return Err("--principal requires an explicit write or outcome grant".into());
        }
        Ok(())
    }
}
pub(super) fn run(arguments: &[String]) -> Result<(), String> {
    if arguments.first().is_some_and(|value| value == "--protection-admin") {
        return backend::protection::run(&arguments[1..]);
    }
    if arguments == ["--help"] {
        eprintln!("{USAGE}\n\nSeparate policy-inspection profile: fg-mcp --protection-admin --help");
        return Ok(());
    }
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
    if arguments.len() < 3 || arguments.len() > 25 { return Err(USAGE.into()); }
    if arguments.iter().any(|s| s.len() > 4096) || arguments[0].is_empty() { return Err("invalid bounded MCP arguments".into()); }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new(); let mut at = 3;
    while at < arguments.len() {
        let name = arguments[at].as_str(); at += 1;
        let value = match name {
            "--trusted-local" | "--allow-issues" | "--allow-pulls" | "--allow-source"
                | "--allow-issue-writes" | "--allow-pull-writes" | "--allow-source-writes"
                | "--allow-review-writes" | "--allow-reviewed-merges" | "--allow-outcomes" => "",
            "--object-format" | "--expected-incarnation" | "--max-messages" | "--principal" => {
                let value = arguments.get(at).ok_or("missing option value")?; at += 1; value.as_str()
            }
            _ => return Err("unknown MCP option".into()),
        };
        if flags.insert(name, value).is_some() { return Err("duplicate MCP option".into()); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is required".into()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("unsupported object format".into()),
    };
    let incarnation = flags.get("--expected-incarnation").map(|value|
        RepositoryIncarnationId::from_hex(value).map_err(|_| "invalid incarnation ID")).transpose()?;
    let principal = flags.get("--principal").map(|value|
        PrincipalId::from_hex(value).map_err(|_| "invalid principal ID")).transpose()?;
    let maximum = flags.get("--max-messages").map(|value| json::decimal(value)).transpose()?.unwrap_or(1024);
    if !(1..=100_000).contains(&maximum) { return Err("message bound must be 1..100000".into()); }
    let options = Options { storage: arguments[0].clone().into(), tenant, repository, format, incarnation,
        issues: flags.contains_key("--allow-issues"), pulls: flags.contains_key("--allow-pulls"),
        source: flags.contains_key("--allow-source"),
        writes: WriteGrants { issues: flags.contains_key("--allow-issue-writes"), pulls: flags.contains_key("--allow-pull-writes"),
            source: flags.contains_key("--allow-source-writes"), reviews: flags.contains_key("--allow-review-writes"),
            merges: flags.contains_key("--allow-reviewed-merges") },
        outcomes: flags.contains_key("--allow-outcomes"), principal, max_messages: maximum as usize };
    options.validate_access()?;
    Ok(options)
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
    #[test]
    fn write_and_recovery_grants_require_identity_and_incarnation_but_imply_no_reads() {
        for flag in ["--allow-issue-writes", "--allow-pull-writes", "--allow-source-writes", "--allow-review-writes", "--allow-reviewed-merges", "--allow-outcomes"] {
            let mut args = arguments(); args.retain(|s| s != "--allow-issues"); args.push(flag.into());
            assert!(parse_options(&args).is_err());
            args.extend(["--principal".into(), "33".repeat(16)]);
            assert!(parse_options(&args).is_err());
            args.extend(["--expected-incarnation".into(), "44".repeat(16)]);
            let options = parse_options(&args).unwrap();
            assert!(!options.issues && !options.pulls && !options.source);
            assert_eq!(options.writes.issues, flag == "--allow-issue-writes");
            assert_eq!(options.writes.pulls, flag == "--allow-pull-writes");
            assert_eq!(options.writes.source, flag == "--allow-source-writes");
            assert_eq!(options.writes.reviews, flag == "--allow-review-writes");
            assert_eq!(options.writes.merges, flag == "--allow-reviewed-merges");
            assert_eq!(options.outcomes, flag == "--allow-outcomes");
        }
        let mut args = arguments(); args.extend(["--principal".into(), "33".repeat(16)]);
        assert!(parse_options(&args).is_err());
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    #[test]
    fn read_groups_are_independent_and_at_least_one_is_required() {
        for mask in 0..8 {
            let mut args = vec!["/unused".to_owned(), "11".repeat(16), "22".repeat(16), "--trusted-local".to_owned()];
            for (bit, flag) in [(1, "--allow-issues"), (2, "--allow-pulls"), (4, "--allow-source")] {
                if mask & bit != 0 { args.push(flag.to_owned()); }
            }
            let parsed = parse_options(&args);
            if mask == 0 { assert!(parsed.is_err()); } else {
                let options = parsed.unwrap();
                assert_eq!(options.issues, mask & 1 != 0);
                assert_eq!(options.pulls, mask & 2 != 0);
                assert_eq!(options.source, mask & 4 != 0);
                assert!(!options.writes.any() && !options.outcomes && options.principal.is_none());
            }
        }
    }
}

#[cfg(test)]
mod mutation_grant_tests {
    use super::*;
    #[test]
    fn all_launch_grant_combinations_preserve_independent_write_ceilings() {
        let flags = ["--allow-issues", "--allow-pulls", "--allow-source", "--allow-issue-writes", "--allow-pull-writes", "--allow-source-writes", "--allow-outcomes", "--allow-review-writes", "--allow-reviewed-merges"];
        for mask in 0_u16..512 {
            let mut args = vec!["/unused".into(), "11".repeat(16), "22".repeat(16), "--trusted-local".into()];
            for (bit, flag) in flags.iter().enumerate() { if mask & (1 << bit) != 0 { args.push((*flag).into()); } }
            let scoped = mask & 504 != 0;
            if scoped {
                assert!(parse_options(&args).is_err());
                args.extend(["--principal".into(), "33".repeat(16), "--expected-incarnation".into(), "44".repeat(16)]);
            }
            let result = parse_options(&args);
            if mask == 0 { assert!(result.is_err()); continue; }
            let options = result.unwrap();
            assert_eq!(options.issues, mask & 1 != 0);
            assert_eq!(options.pulls, mask & 2 != 0);
            assert_eq!(options.source, mask & 4 != 0);
            assert_eq!(options.writes.issues, mask & 8 != 0);
            assert_eq!(options.writes.pulls, mask & 16 != 0);
            assert_eq!(options.writes.source, mask & 32 != 0);
            assert_eq!(options.outcomes, mask & 64 != 0);
            assert_eq!(options.writes.reviews, mask & 128 != 0);
            assert_eq!(options.writes.merges, mask & 256 != 0);
            assert_eq!(options.writes.any(), mask & 440 != 0);
        }
    }
}
