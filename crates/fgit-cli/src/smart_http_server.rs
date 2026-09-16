//! Explicit loopback Smart HTTP service for the single-principal local profile.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fgit_crypto::sha256_digest;
use fgit_node::{
    GitDaemonReceiveProcessingTimeout, GitDaemonServerLimits, GitDaemonServerReceipt,
    GitDaemonSessionTimeout, NodeConfig, OneNode,
};
use fgit_types::{PrincipalId, RepositoryId, RepositoryIncarnationId, TenantId};

use crate::publication_support::quote;

const USAGE: &str = "usage: fg serve-http <storage-root> <tenant-id> <repository-id> <loopback-address> --trusted-local --token-file <path> --principal <id> [--allow-receive] [--expected-incarnation <id>] [--max-sessions <1..1000000>] [--max-in-flight <1..16>] [--idle-timeout-secs <1..86400>] [--session-timeout-secs <1..3600>] [--processing-timeout-secs <1..3600>] [--receive-max-input-mib <1..1024>] [--receive-max-expanded-mib <1..1024>] [--pack-max-expanded-mib <1..1024>]\n\nRequires an existing repository. Read-only by default; --allow-receive enables pushes. The token file must contain 64 lowercase hexadecimal characters, optionally followed by a newline, and must be private on Unix (mode 0600 or stricter). Every HTTP request must carry Authorization: Bearer <token>. Each push RPC must also carry a unique client-selected Idempotency-Key; reuse that key only to retry the identical push. This single-principal loopback profile does not provide multi-user IAM or TLS. Forwarded headers are never credentials. Default bounds: 1024 requests, 4 in flight, 300-second idle/network/processing phases, 128 MiB input/expanded/pack envelopes.\n";

struct Options {
    config: NodeConfig,
    listen: SocketAddr,
    principal: PrincipalId,
    token_file: PathBuf,
    allow_receive: bool,
    limits: GitDaemonServerLimits,
    idle_timeout: Duration,
}

fn number(flags: &BTreeMap<&str, &str>, name: &str, default: u64, maximum: u64) -> Result<u64, String> {
    let Some(value) = flags.get(name) else { return Ok(default); };
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("{name} requires a canonical positive decimal"));
    }
    let value: u64 = value.parse().map_err(|_| format!("{name} is out of range"))?;
    if value == 0 || value > maximum { return Err(format!("{name} must be in 1..={maximum}")); }
    Ok(value)
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 { return Err(USAGE.into()); }
    if arguments.len() > 36 || arguments.iter().any(|arg| arg.len() > 4096)
        || arguments.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err("serve-http arguments exceed the bounded profile".into());
    }
    if arguments[0].is_empty() { return Err("storage root must not be empty".into()); }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let listen: SocketAddr = arguments[3].parse().map_err(|_| "expected a numeric loopback socket address")?;
    if !listen.ip().is_loopback() { return Err("serve-http refuses non-loopback plaintext listeners".into()); }
    let mut flags = BTreeMap::new();
    let mut index = 4;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        index += 1;
        let boolean = matches!(name, "--trusted-local" | "--allow-receive");
        if !boolean && !matches!(name, "--token-file" | "--principal" | "--expected-incarnation"
            | "--max-sessions" | "--max-in-flight" | "--idle-timeout-secs"
            | "--session-timeout-secs" | "--processing-timeout-secs"
            | "--receive-max-input-mib" | "--receive-max-expanded-mib" | "--pack-max-expanded-mib")
        {
            return Err("unknown serve-http option".into());
        }
        let value = if boolean { "" } else {
            let value = arguments.get(index).ok_or_else(|| format!("missing value for {name}"))?;
            index += 1;
            if value.is_empty() || value.starts_with("--") { return Err(format!("missing value for {name}")); }
            value.as_str()
        };
        if flags.insert(name, value).is_some() { return Err(format!("duplicate serve-http option {name}")); }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("--trusted-local is required for this single-principal capability profile".into());
    }
    let token_file = PathBuf::from(*flags.get("--token-file").ok_or("--token-file is required")?);
    let principal = PrincipalId::from_hex(flags.get("--principal").copied().ok_or("--principal is required")?)
        .map_err(|_| "invalid principal ID")?;
    let sessions = number(&flags, "--max-sessions", 1024, 1_000_000)? as usize;
    let in_flight = number(&flags, "--max-in-flight", 4, 16)? as usize;
    let limits = GitDaemonServerLimits::try_new(sessions, in_flight).map_err(|e| e.to_string())?;
    let idle_timeout = Duration::from_secs(number(&flags, "--idle-timeout-secs", 300, 86400)?);
    let timeout = GitDaemonSessionTimeout::try_new(Duration::from_secs(number(&flags, "--session-timeout-secs", 300, 3600)?))
        .map_err(|e| e.to_string())?;
    let processing = GitDaemonReceiveProcessingTimeout::try_new(Duration::from_secs(number(&flags, "--processing-timeout-secs", 300, 3600)?))
        .map_err(|e| e.to_string())?;
    let bytes = |name| -> Result<usize, String> {
        usize::try_from(number(&flags, name, 128, 1024)? * 1024 * 1024)
            .map_err(|_| "byte envelope is not supported on this platform".into())
    };
    let mut config = NodeConfig::new(arguments[0].clone().into(), tenant, repository)
        .with_git_daemon_session_timeout(timeout)
        .with_git_daemon_receive_processing_timeout(processing)
        .with_git_daemon_receive_byte_envelope(Some(bytes("--receive-max-input-mib")?), Some(bytes("--receive-max-expanded-mib")?))
        .with_selected_pack_byte_envelope(bytes("--pack-max-expanded-mib")?);
    if let Some(incarnation) = flags.get("--expected-incarnation") {
        config = config.with_expected_repository_incarnation(
            RepositoryIncarnationId::from_hex(incarnation).map_err(|_| "invalid repository incarnation")?,
        );
    }
    Ok(Options { config, listen, principal, token_file, allow_receive: flags.contains_key("--allow-receive"), limits, idle_timeout })
}

fn token_digest(bytes: &[u8]) -> Result<[u8; 32], String> {
    let token = bytes.strip_suffix(b"\r\n").or_else(|| bytes.strip_suffix(b"\n")).unwrap_or(bytes);
    if token.len() != 64 || !token.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
        return Err("token file must contain exactly 64 lowercase hexadecimal characters and at most one final newline".into());
    }
    Ok(sha256_digest(token))
}

fn read_token(path: &Path) -> Result<[u8; 32], String> {
    // This file belongs to the trusted local operator, not a remote request.
    // Both pre-open and opened metadata are checked before any secret bytes.
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("cannot inspect token file: {e}"))?;
    if !metadata.is_file() || metadata.len() > 66 { return Err("token must be a bounded regular file, not a symlink or device".into()); }
    let mut file = File::open(path).map_err(|e| format!("cannot open token file: {e}"))?;
    let opened = file.metadata().map_err(|e| format!("cannot inspect opened token file: {e}"))?;
    if !opened.is_file() || opened.len() > 66 { return Err("opened token file is not a bounded regular file".into()); }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino()
            || metadata.mode() & 0o077 != 0 || opened.mode() & 0o077 != 0
        {
            return Err("token file must be stable and private: remove all group/other permissions".into());
        }
    }
    let mut bytes = Vec::new();
    (&mut file).take(67).read_to_end(&mut bytes).map_err(|e| format!("cannot read token file: {e}"))?;
    token_digest(&bytes)
}

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] {
        println!("{USAGE}");
        return Ok(0);
    }
    let options = parse(arguments)?;
    // Refuse bad or public credentials before opening a node or binding a port.
    let credential = read_token(&options.token_file)?;
    let mut node = OneNode::open_existing(options.config).map_err(|e| e.to_string())?;
    let serving = (|| -> Result<GitDaemonServerReceipt, String> {
        let head = node.runtime().block_on(node.authenticate_authority_head()).map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation()).map_err(|e| e.to_string())?;
        let listener = TcpListener::bind(options.listen).map_err(|e| format!("cannot bind HTTP listener: {e}"))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).map_err(|_| "invalid canonical route")?;
        let url = format!("http://{address}{route}");
        let mut output = io::stdout().lock();
        writeln!(output, "{{\"type\":\"smart_http_listening\",\"schema_version\":1,\"url\":{},\"receive_enabled\":{},\"repository_incarnation\":{}}}",
            quote(&url), options.allow_receive, quote(&node.repository_incarnation_id().to_string()))
            .and_then(|()| output.flush()).map_err(|e| format!("cannot report HTTP readiness: {e}"))?;
        drop(output);
        node.serve_smart_http_bounded(&listener, options.limits, credential, options.principal,
            options.allow_receive, options.idle_timeout).map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().map_err(|e| e.to_string());
    let receipt = match (serving, cleanup) {
        (Ok(receipt), Ok(())) => receipt,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(format!("HTTP service drained but node shutdown failed: {error}")),
        (Err(error), Err(cleanup)) => return Err(format!("HTTP service failed ({error}); node shutdown also failed ({cleanup})")),
    };
    println!("{{\"type\":\"smart_http_drained\",\"schema_version\":1,\"accepted\":{},\"completed_transports\":{},\"refused_transports\":{}}}",
        receipt.accepted_sessions(), receipt.completed_sessions(), receipt.refused_sessions());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<String> {
        ["state", &"11".repeat(16), &"22".repeat(16), "127.0.0.1:0", "--trusted-local", "--token-file", "token", "--principal", &"33".repeat(16)]
            .into_iter().map(str::to_owned).collect()
    }
    #[test]
    fn safe_defaults_require_credentials_and_do_not_enable_receive() {
        let options = parse(&arguments()).unwrap();
        assert!(!options.allow_receive);
        assert_eq!(options.limits.max_sessions(), 1024);
        assert_eq!(options.limits.max_in_flight(), 4);
        let mut args = arguments();
        args.retain(|arg| arg != "--trusted-local");
        assert!(parse(&args).is_err());
    }
    #[test]
    fn non_loopback_and_unbounded_limits_are_refused_before_side_effects() {
        let mut args = arguments(); args[3] = "0.0.0.0:8080".into(); assert!(parse(&args).is_err());
        for (flag, value) in [("--max-in-flight", "17"), ("--max-sessions", "0"), ("--idle-timeout-secs", "0"), ("--session-timeout-secs", "3601"), ("--receive-max-input-mib", "1025")] {
            let mut args = arguments(); args.extend([flag.into(), value.into()]); assert!(parse(&args).is_err(), "{flag}");
        }
    }
    #[test]
    fn duplicate_flags_cannot_change_the_security_profile() {
        let mut args = arguments(); args.extend(["--principal".into(), "44".repeat(16)]); assert!(parse(&args).is_err());
        let mut args = arguments(); args.extend(["--allow-receive".into(), "--allow-receive".into()]); assert!(parse(&args).is_err());
        let mut args = arguments(); args.push("--allow-receive".into()); assert!(parse(&args).unwrap().allow_receive);
    }
    #[test]
    fn token_encoding_is_exact_and_errors_do_not_echo_secrets() {
        let token = "a".repeat(64);
        for ending in ["", "\n", "\r\n"] {
            assert_eq!(token_digest(format!("{token}{ending}").as_bytes()).unwrap(), sha256_digest(token.as_bytes()));
        }
        for bytes in [b"".as_slice(), b"short", b"secret token", &[b'A'; 64], &[b'a'; 65]] {
            let error = token_digest(bytes).unwrap_err(); assert!(!error.contains("secret token"));
        }
        assert!(token_digest(format!("{token}\n\n").as_bytes()).is_err());
    }
}
