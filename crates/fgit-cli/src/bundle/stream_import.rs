//! Native full-bundle import with private file custody and atomic publication.

use std::collections::BTreeSet;
use std::io::Write;
use std::time::{Duration, Instant};

use fgit_authority::IdempotencyKey;
use fgit_node::{
    GitDaemonSessionTimeout, LoopbackReceiveSession, NodeConfig, OneNode, StreamBundleImportQuery,
    TerminationSignals,
};

use super::verify::local_files::StableInput;

const MIB: u64 = 1024 * 1024;
pub(super) const USAGE: &str =
    "usage: fg bundle import <storage-root> <tenant-id> <repository-id> <bundle-file>
  --file-backed --trusted-local --principal <id>
  (--idempotency-key <key> | --key-stdin) [--object-format sha1|sha256]
  [--max-input-mib N] [--max-expanded-mib N] [--max-blob-mib N]
  [--max-object-mib N] [--max-objects N] [--max-refs N] [--max-edges N]
  [--timeout-secs N]

Imports a self-contained full native bundle into an initialized destination.
Every advertised direct ref is created in one atomic transaction; an existing
destination name refuses all updates. HEAD remains an advertisement. Native
SHA-1 and SHA-256, internal OFS/REF deltas and forward REF bases are supported.
Prerequisites, external bases, filtered bundles and implicit force are refused.
Mapped fetch and incremental sync-import also accept --file-backed.
Mapped incremental fetch additionally requires --incremental.

Input and expanded-byte defaults are 128 MiB; each accepts 1..16384 MiB.
The independent blob allowance defaults to 32 MiB and accepts 1..16384 MiB.
The metadata/delta-program allocation limit defaults to 32 MiB, accepts 1..32,
and does not grow when the blob allowance grows. Object count defaults to
100000 (ceiling 1000000), ref headers to 4096 (including HEAD, ceiling 4096),
and graph edges to 1000000 (ceiling 8000000). Independent work limits remain.
Native processing timeout defaults to 300 seconds, accepts 1..3600, and is
narrowed by an explicit global timeout. It begins after stdin credentials are
collected. Cancellation is cooperative at native checkpoints.

The Unix input must be an ordinary non-symlink regular file whose components
remain under the local operator's control. Verified payloads use private
scratch and synced staging under the node; allow disk space for both. Metadata
is buffered within its own limit; blobs are read and authenticated in chunks.
Raw verification scratch is removed before admission. Permanent object names
are linked only when ordinary admission prepares a commit, before its head CAS.

The receipt uses the existing git_bundle_import schema. An exact retry key and
semantic ref set recover the same terminal decision across buffered/file-backed
profiles, before fresh payload checks. An error after publication starts does
not establish non-commit: retry the original inputs/key or use fg outcome.
Keys from stdin are byte-exact, including newlines, and are never printed.
Exit 0: committed; 3: canonical refusal; 2: input/infrastructure/cleanup error.";

#[derive(Debug)]
struct Options {
    common: super::Options,
    query: StreamBundleImportQuery,
}

// Retry keys are opaque values and may themselves spell an option. Inspect
// only option positions so existing buffered retries keep their exact identity.
pub(super) fn requested(args: &[String]) -> bool {
    let mut at = 5;
    while let Some(flag) = args.get(at) {
        match flag.as_str() {
            "--file-backed" => return true,
            "--trusted-local" | "--key-stdin" => at += 1,
            _ => at += 2,
        }
    }
    false
}

fn number(flag: &str, value: &str, maximum: u64) -> Result<u64, String> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!(
            "{flag} requires a positive canonical decimal integer"
        ));
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value <= maximum)
        .ok_or_else(|| format!("{flag} must be in 1..={maximum}"))
}

pub(super) fn mib(flag: &str, value: &str, maximum: u64) -> Result<usize, String> {
    let bytes = number(flag, value, maximum)?
        .checked_mul(MIB)
        .ok_or_else(|| format!("{flag} byte limit overflow"))?;
    usize::try_from(bytes).map_err(|_| format!("{flag} exceeds this platform"))
}

/// Resource parsing shared by full import, mapped fetch and incremental sync.
/// Payload, metadata and graph allowances stay independent across profiles.
pub(super) fn apply_limit(
    flag: &str,
    value: &str,
    query: &mut StreamBundleImportQuery,
) -> Result<bool, String> {
    match flag {
        "--max-input-mib" => {
            let bytes = mib(flag, value, 16_384)?;
            query.limits.envelope.max_bundle_bytes = bytes;
            query.limits.pack.max_input_bytes = bytes;
        }
        "--max-expanded-mib" => {
            let bytes = mib(flag, value, 16_384)?;
            query.limits.pack.max_total_expanded_bytes = bytes;
            query.limits.graph.max_payload_bytes = bytes as u64;
        }
        "--max-blob-mib" => {
            query.limits.max_streamed_blob_bytes = mib(flag, value, 16_384)?;
        }
        "--max-object-mib" => {
            let bytes = mib(flag, value, 32)?;
            query.limits.pack.max_object_bytes = bytes;
            query.limits.graph.max_object_bytes = bytes;
        }
        "--max-objects" => {
            let count = number(flag, value, 1_000_000)? as usize;
            query.limits.pack.max_entries = count as u32;
            query.limits.pack.max_index_entries = count;
            query.limits.graph.max_objects = count;
        }
        "--max-refs" => {
            let count = number(flag, value, 4096)? as usize;
            query.limits.envelope.max_references = count;
            query.limits.graph.max_references = count;
        }
        "--max-edges" => {
            query.limits.graph.max_edges = number(flag, value, 8_000_000)? as usize;
        }
        "--timeout-secs" => {
            query.timeout = Duration::from_secs(number(flag, value, 3600)?);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 7
        || args.len() > 48
        || args.first().map(String::as_str) != Some("import")
        || args
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains('\0'))
        || args
            .iter()
            .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()))
            .is_none_or(|bytes| bytes > 64 * 1024)
    {
        return Err(USAGE.into());
    }
    let mut common = args[..5].to_vec();
    let mut query = StreamBundleImportQuery::default();
    query.limits.pack.max_index_entries = query.limits.pack.max_entries as usize;
    let mut seen = BTreeSet::new();
    let mut at = 5;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        if !seen.insert(flag) {
            return Err(format!("duplicate file-backed import option {flag}"));
        }
        if flag == "--file-backed" {
            continue;
        }
        if matches!(flag, "--trusted-local" | "--key-stdin") {
            common.push(flag.into());
            continue;
        }
        let value = args
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        match flag {
            "--object-format" | "--principal" | "--idempotency-key" => {
                common.push(flag.into());
                common.push(value.clone());
            }
            _ if apply_limit(flag, value, &mut query)? => {}
            _ => return Err(format!("unknown file-backed import option {flag}")),
        }
    }
    if !seen.contains("--file-backed") {
        return Err("file-backed import requires --file-backed".into());
    }
    Ok(Options {
        common: super::parse(&common)?,
        query,
    })
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    run_with_output(args, &mut std::io::stdout().lock())
}

fn run_with_output(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    if args.len() == 3
        && args[0] == "import"
        && ((args[1] == "--file-backed" && args[2] == "--help")
            || (args[1] == "--help" && args[2] == "--file-backed"))
    {
        writeln!(output, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let mut options = parse(args)?;
    // Credential input retains ordinary process signal behavior. Native
    // cancellable work begins after the exact key has been collected.
    let principal = options.common.principal.ok_or("missing import principal")?;
    let key = options
        .common
        .key
        .as_ref()
        .ok_or("missing exact import key")?;
    let session = LoopbackReceiveSession::authenticated(
        principal,
        IdempotencyKey::new(super::key_bytes(key, &mut std::io::stdin().lock())?)
            .map_err(|error| error.to_string())?,
    );
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let timeout = fgit_cli::command_timeout_override_duration()
        .map_or(options.query.timeout, |global| {
            global.min(options.query.timeout)
        });
    let started = Instant::now();
    let mut stopped = false;
    let mut live = || {
        stopped |= signals.requested() || started.elapsed() >= timeout;
        !stopped
    };
    let mut input = StableInput::open(
        &options.common.path,
        options.query.limits.envelope.max_bundle_bytes as u64,
        &mut live,
    )?;
    if !live() {
        return Err("file-backed import stopped before opening the destination".into());
    }
    let session_timeout =
        GitDaemonSessionTimeout::try_new(timeout).map_err(|error| error.to_string())?;
    let config = NodeConfig::new(
        options.common.storage.clone(),
        options.common.tenant,
        options.common.repository,
    )
    .with_object_format(options.common.format)
    .with_max_object_bytes(options.query.limits.pack.max_object_bytes as u64)
    .with_bundle_import_blob_limit(options.query.limits.max_streamed_blob_bytes)
    .with_git_daemon_session_timeout(session_timeout);
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let operation = (|| {
        if !live() {
            return Err("file-backed import stopped while opening the destination".into());
        }
        let remaining = timeout
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or("file-backed import deadline expired while opening the destination")?;
        let request = node
            .import_request_context_with_byte_limit(
                Some(
                    GitDaemonSessionTimeout::try_new(remaining)
                        .map_err(|error| error.to_string())?,
                ),
                options
                    .query
                    .limits
                    .envelope
                    .max_bundle_bytes
                    .max(options.query.limits.pack.max_total_expanded_bytes) as u64,
            )
            .map_err(|error| error.to_string())?;
        let current = node
            .runtime()
            .block_on(node.authenticate_authority_head_in(&request))
            .map_err(|error| error.to_string())?;
        node.bring_into_service(current.receipt().generation())
            .map_err(|error| error.to_string())?;
        options.query.timeout = timeout
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or("file-backed import deadline expired before source verification")?;
        let mut allow_work = || {
            let allowed = live();
            if !allowed {
                request.cancel();
            }
            allowed
        };
        // The node retains and drains the original pending admission future on
        // stop. Preserve a terminal decision if cancellation arrives after CAS.
        let result = node
            .runtime()
            .block_on(node.import_full_git_bundle_reader_controlled_in(
                &request,
                &session,
                &mut input,
                options.query,
                Default::default(),
                &mut allow_work,
            ))
            .map_err(|error| error.to_string())?;
        let first = result
            .commands
            .first()
            .ok_or("bundle admission returned no terminal outcome")?;
        if !result.session.atomic
            || result.session.tx_ids != vec![first.tx_id]
            || result.commands.iter().any(|command| command != first)
        {
            return Err(format!(
                "inconsistent atomic bundle result; {}",
                super::describe(first.tx_id, &first.terminal)
            ));
        }
        Ok((first.tx_id, first.terminal, result.commands.len()))
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok((tx, terminal, count)) => super::finish_import(
            output,
            &options.common,
            tx,
            &terminal,
            count,
            cleanup.as_deref(),
        ),
        Err(error) => {
            let cleanup = cleanup.map_or_else(String::new, |error| {
                format!("; node shutdown also failed: {error}")
            });
            Err(format!(
                "file-backed bundle import returned no terminal outcome: {error}{cleanup}; canonical outcome is not established; retry the identical inputs/key or use fg outcome with the original key"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "import".into(),
            "node".into(),
            "01".repeat(16),
            "02".repeat(16),
            "source.bundle".into(),
            "--file-backed".into(),
            "--trusted-local".into(),
            "--principal".into(),
            "03".repeat(16),
            "--idempotency-key".into(),
            "exact-key".into(),
        ];
        args.extend(extra.iter().map(|value| (*value).into()));
        args
    }

    #[test]
    fn limits_are_independent_and_metadata_stays_bounded() {
        let default = parse(&args(&[])).unwrap();
        let enlarged = parse(&args(&["--max-blob-mib", "1024"])).unwrap();
        assert_eq!(
            enlarged.query.limits.max_streamed_blob_bytes,
            1024 * MIB as usize
        );
        assert_eq!(
            enlarged.query.limits.pack.max_object_bytes,
            default.query.limits.pack.max_object_bytes
        );
        assert_eq!(
            enlarged.query.limits.pack.max_total_expanded_bytes,
            default.query.limits.pack.max_total_expanded_bytes
        );
        let chosen = parse(&args(&[
            "--max-input-mib",
            "512",
            "--max-expanded-mib",
            "2048",
            "--max-object-mib",
            "1",
            "--max-blob-mib",
            "1024",
            "--max-objects",
            "5000",
            "--max-refs",
            "64",
            "--max-edges",
            "50000",
            "--timeout-secs",
            "600",
            "--object-format",
            "sha256",
        ]))
        .unwrap();
        assert_eq!(chosen.query.limits.pack.max_input_bytes, 512 * MIB as usize);
        assert_eq!(chosen.query.limits.graph.max_payload_bytes, 2048 * MIB);
        assert_eq!(
            chosen.query.limits.pack.max_total_expanded_bytes,
            2048 * MIB as usize
        );
        assert_eq!(chosen.query.limits.graph.max_object_bytes, MIB as usize);
        assert_eq!(chosen.query.limits.pack.max_index_entries, 5000);
        assert_eq!(chosen.query.limits.graph.max_objects, 5000);
        assert_eq!(chosen.query.limits.graph.max_references, 64);
        assert_eq!(chosen.query.limits.graph.max_edges, 50000);
        assert_eq!(chosen.query.timeout, Duration::from_secs(600));
        assert_eq!(chosen.common.format, fgit_types::GitHashAlgorithm::Sha256);
    }

    #[test]
    fn profile_dispatch_does_not_interpret_an_opaque_retry_key_as_a_flag() {
        let mut buffered = args(&[]);
        buffered.retain(|arg| arg != "--file-backed");
        *buffered.last_mut().unwrap() = "--file-backed".into();
        assert!(super::super::parse(&buffered).is_ok());
        assert!(!requested(&buffered));
        buffered.push("--file-backed".into());
        assert!(requested(&buffered));
        assert!(parse(&buffered).is_ok());
        assert!(requested(&args(&[])));
    }

    #[test]
    fn unsafe_or_ambiguous_profiles_refuse_before_opening_a_node() {
        for extra in [
            vec!["--max-blob-mib", "0"],
            vec!["--max-blob-mib", "01"],
            vec!["--max-blob-mib", "16385"],
            vec!["--max-object-mib", "33"],
            vec!["--max-expanded-mib", "18446744073709551615"],
            vec!["--max-objects", "1000001"],
            vec!["--max-refs", "4097"],
            vec!["--max-edges", "8000001"],
            vec!["--timeout-secs", "3601"],
            vec!["--max-input-mib"],
            vec!["--force"],
            vec!["--scratch-dir", "elsewhere"],
            vec!["--key-stdin"],
            vec!["--file-backed"],
            vec!["--max-blob-mib", "64", "--max-blob-mib", "64"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "accepted {extra:?}");
        }
        for missing in ["--file-backed", "--trusted-local"] {
            let mut absent = args(&[]);
            absent.retain(|arg| arg != missing);
            assert!(parse(&absent).is_err());
        }
        let mut incremental = args(&[]);
        incremental[0] = "sync-import".into();
        assert!(parse(&incremental).is_err());
        let mut no_principal = args(&[]);
        no_principal.drain(7..9);
        assert!(parse(&no_principal).is_err());
    }

    #[test]
    fn help_is_available_without_credentials_or_filesystem_work() {
        for flags in [["--file-backed", "--help"], ["--help", "--file-backed"]] {
            let mut output = Vec::new();
            let args = ["import", flags[0], flags[1]].map(String::from);
            assert_eq!(run_with_output(&args, &mut output).unwrap(), 0);
            let help = String::from_utf8(output).unwrap();
            assert!(help.contains("--max-blob-mib"));
            assert!(help.contains("git_bundle_import"));
        }
    }
}
