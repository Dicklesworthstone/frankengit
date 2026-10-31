//! File-backed incremental receive with complete, basis-bound prerequisite custody.

use std::collections::BTreeSet;
use std::io::Write;
use std::time::Instant;

use fgit_authority::IdempotencyKey;
use fgit_node::{
    GitDaemonSessionTimeout, LoopbackReceiveSession, NodeConfig, OneNode,
    StreamIncrementalBundleImportQuery, TerminationSignals,
};

use super::super::stream_import::{apply_limit, mib};
use super::super::verify::local_files::StableInput;

const USAGE: &str = "usage: fg bundle sync-import <storage> <tenant> <repository> <bundle>
  --file-backed --trusted-local --principal <id>
  (--idempotency-key <key> | --key-stdin) [--object-format sha1|sha256]
  --allow-ref-updates --expect <refs/name=old-oid|refs/name=absent>...
  [--max-input-mib N] [--max-expanded-mib N] [--max-original-mib N]
  [--max-blob-mib N] [--max-object-mib N] [--max-objects N]
  [--max-refs N] [--max-edges N] [--timeout-secs N]

Synchronizes every advertised direct ref in one atomic transaction. Each needs
an exact old-tip or absent expectation. Explicit update consent permits rewrites
subject to current repository policy. No implicit tip lookup, force, deletion,
HEAD rewrite, or hidden-ref access is performed. Maximum 64 destinations.

Declared prerequisites must be complete, currently visible native commit history.
Every byte of their complete closure is authenticated into private file custody.
Only that closure can provide omitted objects or external REF_DELTA bases.
Uploaded objects cannot repair incomplete original history. Native SHA-1/SHA-256,
internal OFS/REF deltas and forward bases are supported. A full bundle has no
borrowed originals. Filtered bundles are refused.

Input and uploaded expansion defaults are 128 MiB, independently 1..16384 MiB.
Original-source reads have their own 128 MiB default and 1..16384 MiB allowance,
covering metadata discovery and complete body capture. This allowance does not
increase uploaded expansion. Blobs default to 32 MiB, independently 1..16384 MiB.
Metadata and delta programs default to 32 MiB, accept 1..32 MiB, and remain
bounded in memory even when blob limits grow. Object inventory defaults to
100000 (ceiling 1000000); graph edges to 1000000 (ceiling 8000000).
The --max-refs header allowance accepts 1..4096 and is also bounded by the
atomic command capacity. Original visible-root discovery has a separate finite
inventory bound. Native work limits remain in force.

Native processing timeout defaults to 300 seconds, accepts 1..3600, and is
narrowed by an explicit global timeout. It starts after exact stdin credentials
are collected. Cancellation is cooperative and pending authority work drains.
The Unix input must be an ordinary non-symlink regular file whose components
remain under the local operator's control. Allow disk for original/uploaded
verification scratch and selected uploaded staging. Scratch is removed before
admission; only selected uploaded objects enter synced publication staging.
Borrowed evidence binds to the exact selecting authority head and refuses if
that head changes before publication.

The existing git_bundle_import receipt and exact canonical commands/key share
terminal recovery with buffered sync-import, before fresh payload checks.
An error does not prove non-commit: retry identical inputs/key or use fg outcome.
Stdin keys preserve every byte, including newlines, and are never printed.
Exit 0: committed; 3: canonical refusal; 2: input/infrastructure/cleanup error.";

struct Options {
    sync: super::SyncOptions,
    query: StreamIncrementalBundleImportQuery,
}

/// Inspect option positions only: keys and expectation values are opaque here.
pub(super) fn requested(args: &[String]) -> bool {
    if args.first().map(String::as_str) != Some("sync-import") {
        return false;
    }
    let mut at = 5;
    while let Some(flag) = args.get(at) {
        match flag.as_str() {
            "--file-backed" => return true,
            "--trusted-local" | "--key-stdin" | "--allow-ref-updates" => at += 1,
            _ => at += 2,
        }
    }
    false
}

pub(super) fn help_requested(args: &[String]) -> bool {
    args.len() == 3
        && args[0] == "sync-import"
        && ((args[1] == "--file-backed" && args[2] == "--help")
            || (args[1] == "--help" && args[2] == "--file-backed"))
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5
        || args.len() > 1044
        || args.first().map(String::as_str) != Some("sync-import")
        || args
            .iter()
            .any(|arg| arg.len() > 64 * 1024 || arg.contains('\0'))
        || args
            .iter()
            .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()))
            .is_none_or(|bytes| bytes > 1024 * 1024)
    {
        return Err(USAGE.into());
    }
    let mut common = args[..5].to_vec();
    let mut query = StreamIncrementalBundleImportQuery::default();
    query.bundle.limits.pack.max_index_entries = query.bundle.limits.pack.max_entries as usize;
    let mut seen = BTreeSet::new();
    let mut at = 5;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        match flag {
            "--file-backed" => {
                if !seen.insert(flag) {
                    return Err(format!("duplicate file-backed sync option {flag}"));
                }
            }
            "--trusted-local" | "--key-stdin" | "--allow-ref-updates" => {
                common.push(flag.into());
            }
            "--expect" | "--principal" | "--idempotency-key" | "--object-format" => {
                let value = args
                    .get(at)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                at += 1;
                common.push(flag.into());
                common.push(value.clone());
            }
            _ => {
                let value = args
                    .get(at)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                at += 1;
                if !seen.insert(flag) {
                    return Err(format!("duplicate file-backed sync option {flag}"));
                }
                if flag == "--max-original-mib" {
                    query.max_original_bytes = mib(flag, value, 16_384)?;
                } else if !apply_limit(flag, value, &mut query.bundle)? {
                    return Err(format!("unsupported file-backed sync option {flag}"));
                }
            }
        }
    }
    if !seen.contains("--file-backed") {
        return Err("file-backed sync-import requires --file-backed".into());
    }
    Ok(Options {
        sync: super::parse_sync(&common)?,
        query,
    })
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    run_with_output(args, &mut std::io::stdout().lock())
}

fn run_with_output(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    if help_requested(args) {
        writeln!(output, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let mut options = parse(args)?;
    // Credential input retains ordinary process signal behavior. Native
    // cancellable work begins after the exact key has been collected.
    let principal = options
        .sync
        .common
        .principal
        .ok_or("missing import principal")?;
    let key = options
        .sync
        .common
        .key
        .as_ref()
        .ok_or("missing exact import key")?;
    let session = LoopbackReceiveSession::authenticated(
        principal,
        IdempotencyKey::new(super::super::key_bytes(key, &mut std::io::stdin().lock())?)
            .map_err(|error| error.to_string())?,
    );
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let timeout = fgit_cli::command_timeout_override_duration()
        .map_or(options.query.bundle.timeout, |global| {
            global.min(options.query.bundle.timeout)
        });
    let started = Instant::now();
    let mut stopped = false;
    let mut live = || {
        stopped |= signals.requested() || started.elapsed() >= timeout;
        !stopped
    };
    let mut input = StableInput::open(
        &options.sync.common.path,
        options.query.bundle.limits.envelope.max_bundle_bytes as u64,
        &mut live,
    )?;
    if !live() {
        return Err("file-backed incremental import stopped before opening the destination".into());
    }
    let session_timeout =
        GitDaemonSessionTimeout::try_new(timeout).map_err(|error| error.to_string())?;
    let config = NodeConfig::new(
        options.sync.common.storage.clone(),
        options.sync.common.tenant,
        options.sync.common.repository,
    )
    .with_object_format(options.sync.common.format)
    .with_max_object_bytes(options.query.bundle.limits.pack.max_object_bytes as u64)
    .with_bundle_import_blob_limit(options.query.bundle.limits.max_streamed_blob_bytes)
    .with_git_daemon_session_timeout(session_timeout);
    let mut node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let operation = (|| {
        if !live() {
            return Err(
                "file-backed incremental import stopped while opening the destination".into(),
            );
        }
        let remaining = timeout
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or(
                "file-backed incremental import deadline expired while opening the destination",
            )?;
        let request = node
            .import_request_context_with_byte_limit(
                Some(
                    GitDaemonSessionTimeout::try_new(remaining)
                        .map_err(|error| error.to_string())?,
                ),
                options
                    .query
                    .bundle
                    .limits
                    .envelope
                    .max_bundle_bytes
                    .max(options.query.bundle.limits.pack.max_total_expanded_bytes)
                    .max(options.query.max_original_bytes) as u64,
            )
            .map_err(|error| error.to_string())?;
        let current = node
            .runtime()
            .block_on(node.authenticate_authority_head_in(&request))
            .map_err(|error| error.to_string())?;
        node.bring_into_service(current.receipt().generation())
            .map_err(|error| error.to_string())?;
        options.query.bundle.timeout = timeout
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or("file-backed incremental import deadline expired before source verification")?;
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
            .block_on(node.import_incremental_git_bundle_reader_controlled_in(
                &request,
                &session,
                &mut input,
                &options.sync.expected,
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
            || result.commands.len() != options.sync.expected.len()
            || result.commands.iter().any(|command| command != first)
        {
            return Err(format!(
                "inconsistent atomic bundle result; {}",
                super::super::describe(first.tx_id, &first.terminal)
            ));
        }
        Ok((first.tx_id, first.terminal, result.commands.len()))
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok((tx, terminal, count)) => super::super::finish_import(
            output,
            &options.sync.common,
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
                "file-backed incremental bundle import returned no terminal outcome: {error}{cleanup}; canonical outcome is not established; retry the identical inputs/key or use fg outcome with the original key"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::GitHashAlgorithm;
    use std::time::Duration;

    const MIB: usize = 1024 * 1024;

    fn args(extra: &[&str]) -> Vec<String> {
        let mut input = vec![
            "sync-import".into(),
            "node".into(),
            "01".repeat(16),
            "02".repeat(16),
            "changes.bundle".into(),
            "--file-backed".into(),
            "--trusted-local".into(),
            "--principal".into(),
            "03".repeat(16),
            "--idempotency-key".into(),
            "exact-key".into(),
            "--allow-ref-updates".into(),
            "--expect".into(),
            "refs/heads/main=absent".into(),
        ];
        input.extend(extra.iter().map(|value| (*value).into()));
        input
    }

    #[test]
    fn original_blob_and_uploaded_allowances_are_independent() {
        let defaults = parse(&args(&[])).unwrap();
        let enlarged = parse(&args(&["--max-original-mib", "1024"])).unwrap();
        assert_eq!(enlarged.query.max_original_bytes, 1024 * MIB);
        assert_eq!(
            enlarged.query.bundle.limits.pack.max_total_expanded_bytes,
            defaults.query.bundle.limits.pack.max_total_expanded_bytes
        );
        assert_eq!(
            enlarged.query.bundle.limits.max_streamed_blob_bytes,
            defaults.query.bundle.limits.max_streamed_blob_bytes
        );
        assert_eq!(enlarged.query.bundle.limits.pack.max_object_bytes, 32 * MIB);
        let chosen = parse(&args(&[
            "--max-input-mib",
            "512",
            "--max-expanded-mib",
            "2048",
            "--max-original-mib",
            "4096",
            "--max-blob-mib",
            "1024",
            "--max-object-mib",
            "1",
            "--max-objects",
            "5000",
            "--max-refs",
            "64",
            "--max-edges",
            "50000",
            "--timeout-secs",
            "600",
        ]))
        .unwrap();
        assert_eq!(
            chosen.query.bundle.limits.envelope.max_bundle_bytes,
            512 * MIB
        );
        assert_eq!(chosen.query.bundle.limits.pack.max_input_bytes, 512 * MIB);
        assert_eq!(
            chosen.query.bundle.limits.pack.max_total_expanded_bytes,
            2048 * MIB
        );
        assert_eq!(
            chosen.query.bundle.limits.graph.max_payload_bytes,
            (2048 * MIB) as u64
        );
        assert_eq!(chosen.query.max_original_bytes, 4096 * MIB);
        assert_eq!(
            chosen.query.bundle.limits.max_streamed_blob_bytes,
            1024 * MIB
        );
        assert_eq!(chosen.query.bundle.limits.pack.max_object_bytes, MIB);
        assert_eq!(chosen.query.bundle.limits.graph.max_object_bytes, MIB);
        assert_eq!(chosen.query.bundle.limits.pack.max_entries, 5000);
        assert_eq!(chosen.query.bundle.limits.pack.max_index_entries, 5000);
        assert_eq!(chosen.query.bundle.limits.graph.max_objects, 5000);
        assert_eq!(chosen.query.bundle.limits.envelope.max_references, 64);
        assert_eq!(chosen.query.bundle.limits.graph.max_edges, 50000);
        assert_eq!(chosen.query.bundle.timeout, Duration::from_secs(600));
    }

    #[test]
    fn exact_lease_domains_consent_and_stdin_key_bytes_survive_profile_selection() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut input = args(&["--object-format", format.as_str()]);
            input[13] = format!("refs/heads/main={}", "ab".repeat(format.digest_len()));
            let key = input
                .iter()
                .position(|arg| arg == "--idempotency-key")
                .unwrap();
            input.splice(key..key + 2, ["--key-stdin".into()]);
            let parsed = parse(&input).unwrap();
            assert_eq!(parsed.sync.expected[0].1.unwrap().algorithm(), format);
            assert_eq!(
                super::super::super::key_bytes(
                    parsed.sync.common.key.as_ref().unwrap(),
                    &mut b"exact\nkey\n".as_slice(),
                )
                .unwrap(),
                b"exact\nkey\n"
            );
        }
        for required in ["--allow-ref-updates", "--trusted-local", "--file-backed"] {
            let mut input = args(&[]);
            input.retain(|arg| arg != required);
            assert!(parse(&input).is_err());
        }
        for value in [
            "main=absent".to_owned(),
            "refs/heads/main".to_owned(),
            format!("refs/heads/main={}", "00".repeat(20)),
            format!("refs/heads/main={}", "aa".repeat(32)),
        ] {
            let mut input = args(&[]);
            input[13] = value;
            assert!(parse(&input).is_err());
        }
        let duplicate = args(&["--expect", "refs/heads/main=absent"]);
        assert!(parse(&duplicate).is_err());
        let mut equals = args(&[]);
        equals[13] = "refs/heads/name=with=equals=absent".into();
        assert_eq!(
            parse(&equals).unwrap().sync.expected[0].0.as_bytes(),
            b"refs/heads/name=with=equals"
        );
    }

    #[test]
    fn retry_keys_and_option_values_cannot_change_dispatch() {
        for value in ["--file-backed", "--expect", "--help", "--max-original-mib"] {
            let mut input = args(&[]);
            input.remove(5);
            let at = input
                .iter()
                .position(|arg| arg == "--idempotency-key")
                .unwrap();
            input[at + 1] = value.into();
            assert!(!requested(&input), "key changed profile: {value}");
            assert!(super::super::parse_sync(&input).is_ok());
            input.push("--file-backed".into());
            assert!(requested(&input));
            let parsed = parse(&input).unwrap();
            let Some(super::super::super::Key::Bytes(key)) = parsed.sync.common.key else {
                panic!("literal key representation changed");
            };
            assert_eq!(key, value.as_bytes());
        }
        for flag in ["--expect", "--max-original-mib"] {
            let mut input = args(&[]);
            input.remove(5);
            input.extend([flag.into(), "--file-backed".into()]);
            assert!(!requested(&input));
            input.push("--file-backed".into());
            assert!(requested(&input));
            assert!(parse(&input).is_err());
        }
        let mut export = args(&[]);
        export[0] = "sync-export".into();
        assert!(!requested(&export));
        assert!(parse(&export).is_err());
    }

    #[test]
    fn ambiguous_or_unbounded_profiles_refuse_before_io() {
        for extra in [
            vec!["--max-original-mib", "0"],
            vec!["--max-original-mib", "01"],
            vec!["--max-original-mib", "16385"],
            vec!["--max-original-mib", "18446744073709551615"],
            vec!["--max-original-mib"],
            vec!["--max-blob-mib", "16385"],
            vec!["--max-object-mib", "33"],
            vec!["--max-objects", "1000001"],
            vec!["--max-refs", "4097"],
            vec!["--max-edges", "8000001"],
            vec!["--timeout-secs", "3601"],
            vec!["--file-backed"],
            vec!["--max-original-mib", "64", "--max-original-mib", "64"],
            vec!["--allow-ref-updates"],
            vec!["--trusted-local"],
            vec!["--key-stdin"],
            vec!["--force"],
            vec!["--prune"],
            vec!["--scratch-dir", "elsewhere"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "accepted {extra:?}");
        }
        let mut no_expectations = args(&[]);
        no_expectations.truncate(12);
        assert!(parse(&no_expectations).is_err());
        let mut nul = args(&[]);
        nul[10].push('\0');
        assert!(parse(&nul).is_err());
    }

    #[test]
    fn full_reference_capacity_and_resource_options_have_separate_argument_budgets() {
        let mut input = args(&[
            "--max-original-mib",
            "512",
            "--max-input-mib",
            "512",
            "--max-expanded-mib",
            "1024",
            "--max-blob-mib",
            "40",
            "--max-object-mib",
            "1",
            "--max-objects",
            "100000",
            "--max-refs",
            "64",
            "--max-edges",
            "1000000",
            "--timeout-secs",
            "600",
        ]);
        for index in 1..64 {
            input.extend(["--expect".into(), format!("refs/heads/copy-{index}=absent")]);
        }
        assert_eq!(parse(&input).unwrap().sync.expected.len(), 64);
        input.extend(["--expect".into(), "refs/heads/overflow=absent".into()]);
        assert!(parse(&input).is_err());
    }

    #[test]
    fn both_help_orders_avoid_credentials_and_filesystem_work() {
        for flags in [
            ["sync-import", "--file-backed", "--help"],
            ["sync-import", "--help", "--file-backed"],
        ] {
            let input = flags.map(String::from);
            assert!(help_requested(&input));
            let mut output = Vec::new();
            assert_eq!(run_with_output(&input, &mut output).unwrap(), 0);
            let help = String::from_utf8(output).unwrap();
            assert!(help.contains("--max-original-mib"));
            assert!(help.contains("--allow-ref-updates"));
            assert!(help.contains("git_bundle_import"));
        }
        assert!(!help_requested(&["sync-import".into(), "--help".into()]));
        assert!(!help_requested(&[
            "sync-export".into(),
            "--file-backed".into(),
            "--help".into(),
        ]));
    }
}
