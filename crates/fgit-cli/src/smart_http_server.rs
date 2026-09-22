//! Explicit loopback repository HTTP service with operator credentials.

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

const USAGE: &str = "usage: fg serve-http <storage-root> <tenant-id> <repository-id> <loopback-address>
  --trusted-local (--token-file <path> --principal <id> | --credentials-file <path>)
  [--allow-receive] [--allow-issues] [--allow-outcomes] [--allow-pulls] [--allow-source]
  [--expected-incarnation <id>] [--max-sessions <1..1000000>] [--max-in-flight <1..16>]
  [--idle-timeout-secs <1..86400>] [--session-timeout-secs <1..3600>]
  [--processing-timeout-secs <1..3600>] [--receive-max-input-mib <1..1024>]
  [--receive-max-expanded-mib <1..1024>] [--pack-max-expanded-mib <1..1024>]

Provisioning (reads/authenticates the repository, opens no listener):
  fg serve-http <storage-root> <tenant-id> <repository-id> 127.0.0.1:0
    --trusted-local --print-credentials-header [--expected-incarnation <id>]

Requires an existing repository. Git pushes, issue APIs, PR APIs, source APIs
and outcome queries are disabled by default. --allow-receive enables Git pushes
for receive-scoped tokens. --allow-issues, --allow-outcomes, --allow-pulls and
--allow-source require --credentials-file and the token's appropriate scopes.
No switch enables another service. --allow-source exposes read-only source
queries to read-scoped tokens; it does not grant any mutation permission.

--token-file keeps the static Git-only profile and contains 64 lowercase hex
characters, optionally followed by one newline. --credentials-file is reloaded
for every request and contains token HASHES, never plaintext bearer secrets:
  frankengit-http-credentials-v1 <tenant-id> <repository-id> <incarnation-id>
  <sha256-of-64-character-token> <principal-id> <comma-separated-scopes>
Choose scopes once in this order:
  read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write
No scope implies another. The header must match the exact repository incarnation.
At most 256 entries and 64 KiB are accepted; a header alone revokes all tokens.
Duplicate hashes or malformed rows refuse the entire table. Files must be private
regular files on Unix (0600 or stricter), not symlinks. Atomically replace the
table to rotate/revoke credentials without restarting. Already authenticated
in-flight requests retain their bounded grant.

Every request carries Authorization: Bearer <token>. Each mutation RPC needs a
client-selected Idempotency-Key; reuse it only for the identical command.
Rotation to a new token for the same principal preserves its retry identity.
The opt-in issue API is at <repository-url>/api/v1/issues:
  GET /api/v1/issues[?limit=50&after=N&expected_head=TOKEN]
  GET /api/v1/issues/N[?limit=50&after_version=V&expected_head=TOKEN]
  POST /api/v1/issues/N/<open|edit|close|reopen|comment>
POST bodies use application/x-www-form-urlencoded and require expected_version
(0 for open, a positive exact predecessor otherwise). Open needs title and body;
comment needs body; edit accepts title/body/label or clear_labels=true. Repeated
label fields form a set. Replies are bounded JSON. Continuation requires the
first page's snapshot_token and uses that retained head across ordinary writes.
Unavailable snapshots return 409; they are never replaced with a different head.

The independently enabled native PR API is at <repository-url>/api/v1/pulls:
  GET /api/v1/pulls[?limit=50&after=N&expected_head=TOKEN]
  GET /api/v1/pulls/N[?expected_head=TOKEN]
  POST /api/v1/pulls/N/<open|update|close>
Each metadata POST is a complete URL-encoded command containing expected_version,
object_format (sha1 or sha256), source_ref, target_ref, source_tip, target_tip,
title and body. Closing preserves the exact prior data. No latest-tip lookup,
implicit partial edit, automatic issue number or cross-repository PR is supplied.
PR pages retain snapshots and current hidden-ref policy. Use pulls-read/pulls-write
grants; write does not imply read. Candidate preparation/resolution/inspection
require read AND pulls-read on one token. Review and merge endpoints use their
own reviews-read/reviews-write/merges-write grants; see docs/HTTP_REVIEW_MERGE_API.md.

Read-only source queries use body-bearing POSTs with NO Idempotency-Key:
  POST /api/v1/source/tree    (ref, object_format; optional path_hex, limit, after_hex)
  POST /api/v1/source/blob    (ref, object_format, path_hex; optional offset, limit)
  POST /api/v1/source/search  (ref, object_format, needle_hex; optional case, path_prefix_hex)
Bodies use application/x-www-form-urlencoded, not URL query parameters. Raw paths,
file bytes and search excerpts use hexadecimal byte encoding. Every response names
its source commit and exact snapshot_token. Supply expected_head for continuation;
source browsing uses strict current-head pins, not retained historical pagination.
expected_commit can additionally compare the selected ref tip. Source reads never
stage objects or create transactions. Search match limits are explicitly partial,
not complete no-match results. See docs/HTTP_SOURCE_API.md for limits and examples.

Outcome lookup uses a bodyless POST and the ORIGINAL Idempotency-Key:
  POST /api/v1/outcomes                 (metadata transaction or atomic push)
  POST /api/v1/outcomes/receive         (whole recorded non-atomic session)
  POST /api/v1/outcomes/receive/INDEX   (non-atomic push; zero-based index 0..63)
No original command body, transaction ID or pack is needed. The authenticated
principal can inspect only its own key scope. These queries never re-seal,
resubmit or cancel work. Missing/undecided observations do not prove rollback;
a single receive-command result does not prove completion of the whole session.

Forwarded identity headers never authenticate. This is an operator credential
profile, not organization/team IAM, per-ref/per-item ACLs, account lifecycle or
TLS. Use an authenticated external TLS terminator for nonlocal access.
Default bounds: 1024 requests, 4 in flight, 300-second phases, 128 MiB Git envelopes;
metadata forms have a separate 256 KiB ceiling and pages contain at most 100 entries.
Outcome replies have a separate per-principal quota; single-transaction replies
are capped at 16 KiB and whole-session replies at 1 MiB. Source reads have another
independent quota, 1 MiB maximum file slices, and an 8 MiB JSON response ceiling.
";

enum CredentialInput {
    Static {
        token_file: PathBuf,
        principal: PrincipalId,
    },
    Reloadable(PathBuf),
    HeaderOnly,
}
struct Options {
    config: NodeConfig,
    tenant: TenantId,
    repository: RepositoryId,
    listen: SocketAddr,
    credentials: CredentialInput,
    allow_receive: bool,
    allow_issues: bool,
    allow_outcomes: bool,
    allow_pulls: bool,
    allow_source: bool,
    limits: GitDaemonServerLimits,
    idle_timeout: Duration,
}

fn number(
    flags: &BTreeMap<&str, &str>,
    name: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, String> {
    let Some(value) = flags.get(name) else {
        return Ok(default);
    };
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("{name} requires a canonical positive decimal"));
    }
    let value: u64 = value
        .parse()
        .map_err(|_| format!("{name} is out of range"))?;
    if value == 0 || value > maximum {
        return Err(format!("{name} must be in 1..={maximum}"));
    }
    Ok(value)
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 4 {
        return Err(USAGE.into());
    }
    if arguments.len() > 41
        || arguments.iter().any(|arg| arg.len() > 4096)
        || arguments.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err("serve-http arguments exceed the bounded profile".into());
    }
    if arguments[0].is_empty() {
        return Err("storage root must not be empty".into());
    }
    let tenant = TenantId::from_hex(&arguments[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&arguments[2]).map_err(|_| "invalid repository ID")?;
    let listen: SocketAddr = arguments[3]
        .parse()
        .map_err(|_| "expected a numeric loopback socket address")?;
    if !listen.ip().is_loopback() {
        return Err("serve-http refuses non-loopback plaintext listeners".into());
    }
    let mut flags = BTreeMap::new();
    let mut index = 4;
    while index < arguments.len() {
        let name = arguments[index].as_str();
        index += 1;
        let boolean = matches!(
            name,
            "--trusted-local"
                | "--allow-receive"
                | "--allow-issues"
                | "--allow-outcomes"
                | "--allow-pulls"
                | "--allow-source"
                | "--print-credentials-header"
        );
        if !boolean
            && !matches!(
                name,
                "--token-file"
                    | "--principal"
                    | "--credentials-file"
                    | "--expected-incarnation"
                    | "--max-sessions"
                    | "--max-in-flight"
                    | "--idle-timeout-secs"
                    | "--session-timeout-secs"
                    | "--processing-timeout-secs"
                    | "--receive-max-input-mib"
                    | "--receive-max-expanded-mib"
                    | "--pack-max-expanded-mib"
            )
        {
            return Err("unknown serve-http option".into());
        }
        let value = if boolean {
            ""
        } else {
            let value = arguments
                .get(index)
                .ok_or_else(|| format!("missing value for {name}"))?;
            index += 1;
            if value.is_empty() || value.starts_with("--") {
                return Err(format!("missing value for {name}"));
            }
            value.as_str()
        };
        if flags.insert(name, value).is_some() {
            return Err(format!("duplicate serve-http option {name}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err(
            "--trusted-local is required for this operator-owned capability profile".into(),
        );
    }
    let credentials = if flags.contains_key("--print-credentials-header") {
        if flags.keys().any(|name| {
            !matches!(
                *name,
                "--trusted-local" | "--print-credentials-header" | "--expected-incarnation"
            )
        }) {
            return Err(
                "header provisioning cannot be combined with serving or credential options".into(),
            );
        }
        CredentialInput::HeaderOnly
    } else if let Some(path) = flags.get("--credentials-file") {
        if flags.contains_key("--token-file") || flags.contains_key("--principal") {
            return Err(
                "--credentials-file cannot be combined with --token-file or --principal".into(),
            );
        }
        CredentialInput::Reloadable(PathBuf::from(*path))
    } else {
        let token_file = PathBuf::from(
            *flags
                .get("--token-file")
                .ok_or("supply --credentials-file or --token-file with --principal")?,
        );
        let principal = PrincipalId::from_hex(
            flags
                .get("--principal")
                .copied()
                .ok_or("--principal is required with --token-file")?,
        )
        .map_err(|_| "invalid principal ID")?;
        CredentialInput::Static {
            token_file,
            principal,
        }
    };
    let allow_issues = flags.contains_key("--allow-issues");
    let allow_outcomes = flags.contains_key("--allow-outcomes");
    let allow_pulls = flags.contains_key("--allow-pulls");
    let allow_source = flags.contains_key("--allow-source");
    if (allow_issues || allow_outcomes || allow_pulls || allow_source)
        && !matches!(&credentials, CredentialInput::Reloadable(_))
    {
        return Err(
            "issue/PR/source/outcome endpoints require explicit scopes in --credentials-file"
                .into(),
        );
    }
    let sessions = number(&flags, "--max-sessions", 1024, 1_000_000)? as usize;
    let in_flight = number(&flags, "--max-in-flight", 4, 16)? as usize;
    let limits = GitDaemonServerLimits::try_new(sessions, in_flight).map_err(|e| e.to_string())?;
    let idle_timeout = Duration::from_secs(number(&flags, "--idle-timeout-secs", 300, 86400)?);
    let timeout = GitDaemonSessionTimeout::try_new(Duration::from_secs(number(
        &flags,
        "--session-timeout-secs",
        300,
        3600,
    )?))
    .map_err(|e| e.to_string())?;
    let processing = GitDaemonReceiveProcessingTimeout::try_new(Duration::from_secs(number(
        &flags,
        "--processing-timeout-secs",
        300,
        3600,
    )?))
    .map_err(|e| e.to_string())?;
    let bytes = |name| -> Result<usize, String> {
        usize::try_from(number(&flags, name, 128, 1024)? * 1024 * 1024)
            .map_err(|_| "byte envelope is not supported on this platform".into())
    };
    let mut config = NodeConfig::new(arguments[0].clone().into(), tenant, repository)
        .with_git_daemon_session_timeout(timeout)
        .with_git_daemon_receive_processing_timeout(processing)
        .with_git_daemon_receive_byte_envelope(
            Some(bytes("--receive-max-input-mib")?),
            Some(bytes("--receive-max-expanded-mib")?),
        )
        .with_selected_pack_byte_envelope(bytes("--pack-max-expanded-mib")?);
    if let Some(incarnation) = flags.get("--expected-incarnation") {
        config = config.with_expected_repository_incarnation(
            RepositoryIncarnationId::from_hex(incarnation)
                .map_err(|_| "invalid repository incarnation")?,
        );
    }
    Ok(Options {
        config,
        tenant,
        repository,
        listen,
        credentials,
        allow_receive: flags.contains_key("--allow-receive"),
        allow_issues,
        allow_outcomes,
        allow_pulls,
        allow_source,
        limits,
        idle_timeout,
    })
}

fn token_digest(bytes: &[u8]) -> Result<[u8; 32], String> {
    let token = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(bytes);
    if token.len() != 64
        || !token
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err("token file must contain exactly 64 lowercase hexadecimal characters and at most one final newline".into());
    }
    Ok(sha256_digest(token))
}

fn read_token(path: &Path) -> Result<[u8; 32], String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("cannot inspect token file: {e}"))?;
    if !metadata.is_file() || metadata.len() > 66 {
        return Err("token must be a bounded regular file, not a symlink or device".into());
    }
    let mut file = File::open(path).map_err(|e| format!("cannot open token file: {e}"))?;
    let opened = file
        .metadata()
        .map_err(|e| format!("cannot inspect opened token file: {e}"))?;
    if !opened.is_file() || opened.len() > 66 {
        return Err("opened token file is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened.dev()
            || metadata.ino() != opened.ino()
            || metadata.mode() & 0o077 != 0
            || opened.mode() & 0o077 != 0
        {
            return Err(
                "token file must be stable and private: remove all group/other permissions".into(),
            );
        }
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(67)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read token file: {e}"))?;
    token_digest(&bytes)
}

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] {
        println!("{USAGE}");
        return Ok(0);
    }
    let options = parse(arguments)?;
    let credential = match &options.credentials {
        CredentialInput::Static { token_file, .. } => Some(read_token(token_file)?),
        _ => None,
    };
    let mut node = OneNode::open_existing(options.config).map_err(|e| e.to_string())?;
    if matches!(&options.credentials, CredentialInput::HeaderOnly) {
        let authentication = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string());
        let header = format!(
            "frankengit-http-credentials-v1 {} {} {}",
            options.tenant,
            options.repository,
            node.repository_incarnation_id()
        );
        let cleanup = node.shutdown().map_err(|e| e.to_string());
        authentication?;
        cleanup?;
        let mut out = io::stdout().lock();
        writeln!(out, "{header}")
            .and_then(|()| out.flush())
            .map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let serving = (|| -> Result<GitDaemonServerReceipt, String> {
        if let CredentialInput::Reloadable(path) = &options.credentials {
            node.validate_smart_http_credentials_file(path)
                .map_err(|e| e.to_string())?;
        }
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|e| e.to_string())?;
        let listener = TcpListener::bind(options.listen)
            .map_err(|e| format!("cannot bind HTTP listener: {e}"))?;
        let address = listener.local_addr().map_err(|e| e.to_string())?;
        let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes())
            .map_err(|_| "invalid canonical route")?;
        let url = format!("http://{address}{route}");
        let mode = match &options.credentials {
            CredentialInput::Reloadable(_) => "reloadable",
            _ => "static",
        };
        let mut output = io::stdout().lock();
        writeln!(output, "{{\"type\":\"smart_http_listening\",\"schema_version\":1,\"url\":{},\"receive_enabled\":{},\"issues_enabled\":{},\"outcomes_enabled\":{},\"pulls_enabled\":{},\"source_enabled\":{},\"repository_incarnation\":{},\"credential_mode\":{}}}",
            quote(&url), options.allow_receive, options.allow_issues, options.allow_outcomes, options.allow_pulls,
            options.allow_source, quote(&node.repository_incarnation_id().to_string()), quote(mode))
            .and_then(|()| output.flush()).map_err(|e| format!("cannot report HTTP readiness: {e}"))?;
        drop(output);
        match &options.credentials {
            CredentialInput::Static { principal, .. } => node.serve_smart_http_bounded(
                &listener,
                options.limits,
                credential.ok_or("static credential missing")?,
                *principal,
                options.allow_receive,
                options.idle_timeout,
            ),
            CredentialInput::Reloadable(path) if options.allow_source => node
                .serve_repository_http_with_source_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.allow_pulls,
                    options.idle_timeout,
                ),
            CredentialInput::Reloadable(path) if options.allow_pulls => node
                .serve_repository_http_with_pull_requests_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.idle_timeout,
                ),
            CredentialInput::Reloadable(path) => node
                .serve_repository_http_with_credentials_file_bounded(
                    &listener,
                    options.limits,
                    path,
                    options.allow_receive,
                    options.allow_issues,
                    options.allow_outcomes,
                    options.idle_timeout,
                ),
            CredentialInput::HeaderOnly => return Err("header-only operation cannot serve".into()),
        }
        .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().map_err(|e| e.to_string());
    let receipt = match (serving, cleanup) {
        (Ok(receipt), Ok(())) => receipt,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => {
            return Err(format!(
                "HTTP service drained but node shutdown failed: {error}"
            ));
        }
        (Err(error), Err(cleanup)) => {
            return Err(format!(
                "HTTP service failed ({error}); node shutdown also failed ({cleanup})"
            ));
        }
    };
    println!(
        "{{\"type\":\"smart_http_drained\",\"schema_version\":1,\"accepted\":{},\"completed_transports\":{},\"refused_transports\":{}}}",
        receipt.accepted_sessions(),
        receipt.completed_sessions(),
        receipt.refused_sessions()
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments() -> Vec<String> {
        [
            "state",
            &"11".repeat(16),
            &"22".repeat(16),
            "127.0.0.1:0",
            "--trusted-local",
            "--token-file",
            "token",
            "--principal",
            &"33".repeat(16),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn safe_defaults_require_credentials_and_do_not_enable_receive() {
        let options = parse(&arguments()).unwrap();
        assert!(!options.allow_receive);
        assert!(!options.allow_issues);
        assert!(!options.allow_outcomes);
        assert!(!options.allow_pulls);
        assert!(!options.allow_source);
        assert_eq!(options.limits.max_sessions(), 1024);
        assert_eq!(options.limits.max_in_flight(), 4);
        let mut args = arguments();
        args.retain(|arg| arg != "--trusted-local");
        assert!(parse(&args).is_err());
    }
    #[test]
    fn non_loopback_and_unbounded_limits_are_refused_before_side_effects() {
        let mut args = arguments();
        args[3] = "0.0.0.0:8080".into();
        assert!(parse(&args).is_err());
        for (flag, value) in [
            ("--max-in-flight", "17"),
            ("--max-sessions", "0"),
            ("--idle-timeout-secs", "0"),
            ("--session-timeout-secs", "3601"),
            ("--receive-max-input-mib", "1025"),
        ] {
            let mut args = arguments();
            args.extend([flag.into(), value.into()]);
            assert!(parse(&args).is_err(), "{flag}");
        }
    }
    #[test]
    fn duplicate_flags_cannot_change_the_security_profile() {
        let mut args = arguments();
        args.extend(["--principal".into(), "44".repeat(16)]);
        assert!(parse(&args).is_err());
        let mut args = arguments();
        args.extend(["--allow-receive".into(), "--allow-receive".into()]);
        assert!(parse(&args).is_err());
        let mut args = arguments();
        args.push("--allow-receive".into());
        assert!(parse(&args).unwrap().allow_receive);
    }
    #[test]
    fn token_encoding_is_exact_and_errors_do_not_echo_secrets() {
        let token = "a".repeat(64);
        for ending in ["", "\n", "\r\n"] {
            assert_eq!(
                token_digest(format!("{token}{ending}").as_bytes()).unwrap(),
                sha256_digest(token.as_bytes())
            );
        }
        for bytes in [
            b"".as_slice(),
            b"short",
            b"secret token",
            &[b'A'; 64],
            &[b'a'; 65],
        ] {
            let error = token_digest(bytes).unwrap_err();
            assert!(!error.contains("secret token"));
        }
        assert!(token_digest(format!("{token}\n\n").as_bytes()).is_err());
    }
    #[test]
    fn reloadable_mode_never_accepts_a_static_principal_override() {
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(matches!(
            parse(&args).unwrap().credentials,
            CredentialInput::Reloadable(_)
        ));
        assert!(!parse(&args).unwrap().allow_receive);
        for extra in [
            vec!["--principal".into(), "33".repeat(16)],
            vec!["--token-file".into(), "token".into()],
        ] {
            let mut invalid = args.clone();
            invalid.extend(extra);
            assert!(parse(&invalid).is_err());
        }
    }
    #[test]
    fn issue_api_requires_explicit_opt_in_and_file_scopes() {
        let mut static_args = arguments();
        static_args.push("--allow-issues".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_issues);
        args.push("--allow-issues".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_issues);
        assert!(!options.allow_receive);
        assert!(!options.allow_outcomes);
        assert!(!options.allow_pulls);
        args.push("--allow-issues".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn outcome_recovery_is_opt_in_and_does_not_enable_either_write_service() {
        let mut static_args = arguments();
        static_args.push("--allow-outcomes".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_outcomes);
        args.push("--allow-outcomes".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_outcomes);
        assert!(!options.allow_receive && !options.allow_issues && !options.allow_pulls);
        args.push("--allow-outcomes".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn pull_requests_require_explicit_file_grants_and_do_not_enable_other_services() {
        let mut static_args = arguments();
        static_args.push("--allow-pulls".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_pulls);
        args.push("--allow-pulls".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_pulls);
        assert!(!options.allow_receive && !options.allow_issues && !options.allow_outcomes);
        args.push("--allow-pulls".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn source_reads_are_opt_in_and_do_not_enable_publication_or_other_apis() {
        let mut static_args = arguments();
        static_args.push("--allow-source".into());
        assert!(parse(&static_args).is_err());
        let mut args = arguments()[..5].to_vec();
        args.extend(["--credentials-file".into(), "grants".into()]);
        assert!(!parse(&args).unwrap().allow_source);
        args.push("--allow-source".into());
        let options = parse(&args).unwrap();
        assert!(options.allow_source);
        assert!(
            !options.allow_receive
                && !options.allow_issues
                && !options.allow_outcomes
                && !options.allow_pulls
        );
        let mut all = args.clone();
        all.extend([
            "--allow-pulls".into(),
            "--allow-issues".into(),
            "--allow-outcomes".into(),
            "--allow-receive".into(),
        ]);
        let all = parse(&all).unwrap();
        assert!(
            all.allow_source
                && all.allow_pulls
                && all.allow_issues
                && all.allow_outcomes
                && all.allow_receive
        );
        args.push("--allow-source".into());
        assert!(parse(&args).is_err());
    }
    #[test]
    fn header_provisioning_is_a_separate_read_only_operation() {
        let mut args = arguments()[..5].to_vec();
        args.push("--print-credentials-header".into());
        assert!(matches!(
            parse(&args).unwrap().credentials,
            CredentialInput::HeaderOnly
        ));
        args.push("--allow-receive".into());
        assert!(parse(&args).is_err());
    }
}
