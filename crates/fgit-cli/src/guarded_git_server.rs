//! Executable `fg serve` binding for the guarded raw Git service. Other CLI
//! commands keep the existing library dispatcher. No repository is initialized
//! implicitly, and a receive principal is never inferred from the peer.

use fgit_cli::CliOutcome;
use fgit_node::{
    GitDaemonServerLimits, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling, NodeConfig,
    OneNode, RepositoryResolutionInput,
};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};
use std::collections::BTreeMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

const USAGE: &str = "usage: fg serve <storage-root> <tenant-id-hex> <repository-id-hex> <listen-address> [--expected-incarnation <id>] [--max-sessions <1..1000000> --max-in-flight <1..16>] [--receive-principal <principal-id-hex>] [--session-timeout-secs <non-zero>] [--session-secs-per-mib <n>] [--session-max-extension-secs <n>] [--receive-max-input-mib <non-zero>] [--receive-max-expanded-mib <non-zero>] [--pack-max-expanded-mib <non-zero>]";

struct Prepared {
    configuration: NodeConfig,
    listen: String,
    limits: GitDaemonServerLimits,
}
fn integer(value: &str, flag: &str, zero: bool) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid {flag}: expected a decimal integer"));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|n| zero || *n != 0)
        .ok_or_else(|| format!("invalid {flag}: integer is zero or out of range"))
}
fn mib(value: &str, flag: &str) -> Result<usize, String> {
    integer(value, flag, false)?
        .checked_mul(1_048_576)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| format!("{flag} exceeds the platform byte envelope"))
}
fn parse(arguments: &[String]) -> Result<Prepared, String> {
    if arguments.first().map(String::as_str) != Some("serve") {
        return Err(USAGE.into());
    }
    let mut flags = BTreeMap::new();
    let mut positional = Vec::new();
    let mut index = 1;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument.starts_with("--") {
            if !matches!(
                argument,
                "--expected-incarnation"
                    | "--receive-principal"
                    | "--max-sessions"
                    | "--max-in-flight"
                    | "--session-timeout-secs"
                    | "--session-secs-per-mib"
                    | "--session-max-extension-secs"
                    | "--receive-max-input-mib"
                    | "--receive-max-expanded-mib"
                    | "--pack-max-expanded-mib"
            ) {
                return Err(USAGE.into());
            }
            let value = arguments
                .get(index + 1)
                .ok_or_else(|| USAGE.to_owned())?
                .as_str();
            if flags.insert(argument, value).is_some() {
                return Err(format!("duplicate {argument}"));
            }
            index += 2;
        } else {
            positional.push(argument);
            index += 1;
        }
    }
    let [root, tenant, repository, listen] = positional.as_slice() else {
        return Err(USAGE.into());
    };
    if flags.contains_key("--max-sessions") != flags.contains_key("--max-in-flight") {
        return Err("--max-sessions and --max-in-flight must be selected together".into());
    }
    let sessions = flags
        .get("--max-sessions")
        .map(|v| integer(v, "--max-sessions", false))
        .transpose()?
        .unwrap_or(1);
    let in_flight = flags
        .get("--max-in-flight")
        .map(|v| integer(v, "--max-in-flight", false))
        .transpose()?
        .unwrap_or(1);
    if sessions > 1_000_000 || in_flight > 16 {
        return Err(
            "guarded serve supports at most 1000000 sessions and 16 concurrent connections".into(),
        );
    }
    let limits = GitDaemonServerLimits::try_new(sessions as usize, in_flight as usize)
        .map_err(|_| "invalid guarded daemon service limits".to_owned())?;
    let tenant = TenantId::from_hex(tenant).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(repository).map_err(|e| e.to_string())?;
    let mut configuration = NodeConfig::new(PathBuf::from(*root), tenant, repository);
    if let Some(value) = flags.get("--expected-incarnation") {
        configuration =
            configuration.with_resolution_input(RepositoryResolutionInput::TransportTarget(
                RepositoryIncarnationId::from_hex(value).map_err(|e| e.to_string())?,
            ));
    }
    if let Some(value) = flags.get("--receive-principal") {
        configuration = configuration.with_git_daemon_receive_principal(
            PrincipalId::from_hex(value).map_err(|e| e.to_string())?,
        );
    }
    if let Some(value) = flags.get("--session-timeout-secs") {
        let seconds = integer(value, "--session-timeout-secs", false)?;
        configuration = configuration.with_git_daemon_session_timeout(
            GitDaemonSessionTimeout::try_new(Duration::from_secs(seconds))
                .map_err(|_| "invalid session timeout".to_owned())?,
        );
    }
    if flags.contains_key("--session-secs-per-mib")
        || flags.contains_key("--session-max-extension-secs")
    {
        let rate = flags
            .get("--session-secs-per-mib")
            .map(|v| integer(v, "--session-secs-per-mib", true))
            .transpose()?
            .unwrap_or(1);
        let extension = flags
            .get("--session-max-extension-secs")
            .map(|v| integer(v, "--session-max-extension-secs", true))
            .transpose()?
            .unwrap_or(if rate == 0 {
                0
            } else {
                GitDaemonSessionWorkScaling::DEFAULT
                    .max_extension()
                    .as_secs()
            });
        let scaling = GitDaemonSessionWorkScaling::try_new(
            Duration::from_secs(rate) / 1_048_576,
            Duration::from_secs(extension),
        )
        .map_err(|_| "invalid session work scaling".to_owned())?;
        configuration = configuration.with_git_daemon_session_work_scaling(scaling);
    }
    let input = flags
        .get("--receive-max-input-mib")
        .map(|v| mib(v, "--receive-max-input-mib"))
        .transpose()?;
    let expanded = flags
        .get("--receive-max-expanded-mib")
        .map(|v| mib(v, "--receive-max-expanded-mib"))
        .transpose()?;
    if input.is_some() || expanded.is_some() {
        configuration = configuration.with_git_daemon_receive_byte_envelope(input, expanded);
    }
    if let Some(value) = flags.get("--pack-max-expanded-mib") {
        configuration =
            configuration.with_selected_pack_byte_envelope(mib(value, "--pack-max-expanded-mib")?);
    }
    Ok(Prepared {
        configuration,
        listen: (*listen).to_owned(),
        limits,
    })
}

pub(crate) fn run(arguments: &[String]) -> Result<CliOutcome, String> {
    let prepared = parse(arguments)?;
    let listener = TcpListener::bind(&prepared.listen).map_err(|e| e.to_string())?;
    let listen_address = listener.local_addr().map_err(|e| e.to_string())?;
    let mut node = OneNode::open_existing(prepared.configuration).map_err(|e| e.to_string())?;
    let serving: Result<_, String> = (|| {
        let selected = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(selected.receipt().generation())
            .map_err(|e| e.to_string())?;
        node.serve_guarded_git_daemon_bounded(&listener, prepared.limits)
            .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown();
    match (serving, cleanup) {
        (Ok(service), Ok(())) => Ok(CliOutcome::Served {
            listen_address,
            service,
        }),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(format!(
            "guarded serve completed but node shutdown failed: {error}"
        )),
        (Err(error), Err(cleanup)) => Err(format!(
            "guarded serve failed ({error}); node shutdown also failed ({cleanup})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments(extra: &[&str]) -> Vec<String> {
        [
            "serve",
            "not-opened",
            "11111111111111111111111111111111",
            "22222222222222222222222222222222",
            "127.0.0.1:0",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn defaults_remain_single_session_and_all_existing_envelope_flags_are_explicit() {
        let default = parse(&arguments(&[])).unwrap();
        assert_eq!(default.limits.max_sessions(), 1);
        assert_eq!(default.limits.max_in_flight(), 1);
        let selected = parse(&arguments(&[
            "--max-sessions",
            "7",
            "--max-in-flight",
            "2",
            "--receive-principal",
            "33333333333333333333333333333333",
            "--expected-incarnation",
            "44444444444444444444444444444444",
            "--session-timeout-secs",
            "30",
            "--session-secs-per-mib",
            "0",
            "--session-max-extension-secs",
            "0",
            "--receive-max-input-mib",
            "4",
            "--receive-max-expanded-mib",
            "8",
            "--pack-max-expanded-mib",
            "16",
        ]))
        .unwrap();
        assert_eq!(selected.limits.max_sessions(), 7);
        assert_eq!(selected.limits.max_in_flight(), 2);
    }
    #[test]
    fn malformed_duplicate_overflow_and_unknown_flags_refuse_before_any_open() {
        for flags in [
            vec!["--max-sessions", "2"],
            vec!["--max-in-flight", "2"],
            vec!["--max-sessions", "2", "--max-in-flight", "17"],
            vec!["--session-timeout-secs", "0"],
            vec!["--session-timeout-secs", "1", "--session-timeout-secs", "2"],
            vec!["--receive-max-input-mib", "18446744073709551615"],
            vec!["--receive-principal", "not-a-principal"],
            vec!["--unknown", "true"],
            vec!["--receive-principal"],
        ] {
            assert!(parse(&arguments(&flags)).is_err(), "{flags:?}");
        }
    }
}
