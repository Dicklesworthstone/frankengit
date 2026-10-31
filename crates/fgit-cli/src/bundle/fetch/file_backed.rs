//! File-backed mapped fetch shares the buffered command and receipt semantics.

use std::collections::BTreeSet;
use std::io::Write;
use std::time::Instant;

use fgit_authority::IdempotencyKey;
use fgit_node::{
    GitDaemonSessionTimeout, LoopbackReceiveSession, NodeConfig, OneNode, StreamBundleImportQuery,
    StreamIncrementalBundleImportQuery, TerminationSignals,
};

use super::super::stream_import::{apply_limit, mib};
use super::super::verify::local_files::StableInput;

const USAGE: &str =
    "usage: fg bundle fetch <storage-root> <tenant-id> <repository-id> <bundle-file>
  --file-backed [--incremental] --trusted-local --principal <id>
  (--idempotency-key <key> | --key-stdin) [--object-format sha1|sha256]
  --map <advertised-source-ref> <destination-ref> <absent|exact-old-oid> ...
  --map-hex <source-ref-bytes-hex> <destination-ref-bytes-hex> <absent|exact-old-oid> ...
  [--max-input-mib N] [--max-expanded-mib N] [--max-blob-mib N]
  [--max-original-mib N (requires --incremental)]
  [--max-object-mib N] [--max-objects N] [--max-refs N] [--max-edges N]
  [--timeout-secs N]

Fetches only explicitly mapped references from a native bundle. The default
requires self-contained input; --incremental also permits declared prerequisites.
All updates publish atomically under absent or exact-old leases. Branches and
remote-tracking refs require commit targets and native commit-parent fast-forwards.
Tags may be created or reasserted. One source may feed several unique destinations.
There is no force, wildcard, prune, implicit current-tip lookup, or HEAD rewrite.
Incremental input borrows only the complete, physically authenticated closure of
declared visible prerequisite commits at one authority snapshot. Only those
originals may supply omitted objects or external REF_DELTA bases. Internal
OFS/REF deltas and forward REF bases are supported in both native hash domains.
Filtered bundles are refused. The ordinary profile refuses prerequisites and
external delta bases.

Input and expanded-byte defaults are 128 MiB; each accepts 1..16384 MiB.
Incremental original reads independently default to 128 MiB and accept
1..16384 MiB via --max-original-mib; visible metadata discovery and complete
original capture share that allowance. Raising it does not raise uploaded
expansion, metadata allocation, or per-blob limits.
The independent blob allowance defaults to 32 MiB and accepts 1..16384 MiB.
Metadata and delta programs default to 32 MiB and accept 1..32 MiB; raising the
blob allowance does not raise their allocation limit. Object count defaults to
100000 (ceiling 1000000), ref headers to 4096 (including HEAD, ceiling 4096),
and graph edges to 1000000 (ceiling 8000000). Header records and destination
commands have independent limits. Native work limits remain in force.
Native processing timeout defaults to 300 seconds, accepts 1..3600, and is
narrowed by an explicit global timeout. It begins after stdin credentials are
collected. Cancellation is cooperative at native checkpoints.

The Unix input must be an ordinary non-symlink regular file with stable components
under the local operator's control. Every supplied object is verified; only mapped
closures and required transport bases enter private synced staging. Large blobs
are authenticated in chunks, with metadata buffered within its separate limit.
Allow disk space for raw verification scratch, authenticated original spans
when incremental, and private staged uploads. Originals are never staged as
uploaded entries. Incremental admission refuses a changed selecting authority
head; borrowed history cannot silently move onto a different snapshot.
Scratch is removed before admission. Permanent names are linked only when
ordinary admission prepares a commit, before authority-head publication.

The output uses the existing git_bundle_fetch receipt. The exact principal,
retry key and canonical destination/old/new commands share terminal recovery
with buffered fetch. Mapping order does not create another operation. A returned
error does not prove non-commit: retry the same commands/key or use fg outcome.
Keys from stdin preserve every byte, including newlines, and are never printed.
Exit 0: committed; 3: canonical refusal; 2: input/infrastructure/cleanup error.";

struct Options {
    common: super::Options,
    query: StreamBundleImportQuery,
    profile: SourceProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceProfile {
    Full,
    Incremental { max_original_bytes: usize },
}

impl SourceProfile {
    fn original_byte_limit(self) -> usize {
        match self {
            Self::Full => 0,
            Self::Incremental { max_original_bytes } => max_original_bytes,
        }
    }
}

/// Inspect only option positions. A retry key or any of a mapping's three
/// values may spell an option without selecting a different intake profile.
pub(super) fn requested(args: &[String]) -> bool {
    let mut at = 4;
    while let Some(flag) = args.get(at) {
        match flag.as_str() {
            "--file-backed" => return true,
            "--map" | "--map-hex" => at += 4,
            "--trusted-local" | "--key-stdin" | "--incremental" => at += 1,
            _ => at += 2,
        }
    }
    false
}

pub(super) fn help_requested(args: &[String]) -> bool {
    (args.len() == 2 || args.len() == 3)
        && args.iter().filter(|arg| *arg == "--file-backed").count() == 1
        && args.iter().filter(|arg| *arg == "--help").count() == 1
        && args.iter().filter(|arg| *arg == "--incremental").count() == args.len() - 2
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 16_404 + 21
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
    let mut common = args[..4].to_vec();
    let mut query = StreamBundleImportQuery::default();
    query.limits.pack.max_index_entries = query.limits.pack.max_entries as usize;
    let mut max_original_bytes = StreamIncrementalBundleImportQuery::default().max_original_bytes;
    let mut seen = BTreeSet::new();
    let mut at = 4;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        match flag {
            "--file-backed" | "--incremental" => {
                if !seen.insert(flag) {
                    return Err(format!("duplicate file-backed fetch option {flag}"));
                }
            }
            "--map" | "--map-hex" => {
                if args.len() - at < 3 {
                    return Err("fetch requires complete source/destination/old mappings".into());
                }
                common.push(flag.into());
                common.extend_from_slice(&args[at..at + 3]);
                at += 3;
            }
            "--trusted-local" | "--key-stdin" => common.push(flag.into()),
            "--principal" | "--idempotency-key" | "--object-format" => {
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
                    return Err(format!("duplicate file-backed fetch option {flag}"));
                }
                if flag == "--max-original-mib" {
                    max_original_bytes = mib(flag, value, 16_384)?;
                } else if !apply_limit(flag, value, &mut query)? {
                    return Err(format!("unsupported file-backed fetch option {flag}"));
                }
            }
        }
    }
    if !seen.contains("--file-backed") {
        return Err("file-backed fetch requires --file-backed".into());
    }
    let profile = if seen.contains("--incremental") {
        SourceProfile::Incremental { max_original_bytes }
    } else {
        if seen.contains("--max-original-mib") {
            return Err("--max-original-mib requires --incremental".into());
        }
        SourceProfile::Full
    };
    Ok(Options {
        common: super::parse(&common)?,
        query,
        profile,
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
    let session = LoopbackReceiveSession::authenticated(
        options.common.principal,
        IdempotencyKey::new(super::key_bytes(
            &options.common.key,
            &mut std::io::stdin().lock(),
        )?)
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
        &options.common.bundle,
        options.query.limits.envelope.max_bundle_bytes as u64,
        &mut live,
    )?;
    if !live() {
        return Err("file-backed fetch stopped before opening the destination".into());
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
    let mut node = OneNode::open_existing(config)
        .map_err(|error| format!("cannot open file-backed fetch node: {error}"))?;
    let operation = (|| {
        if !live() {
            return Err("file-backed fetch stopped while opening the destination".into());
        }
        let remaining = timeout
            .checked_sub(started.elapsed())
            .filter(|time| !time.is_zero())
            .ok_or("file-backed fetch deadline expired while opening the destination")?;
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
                    .max(options.query.limits.pack.max_total_expanded_bytes)
                    .max(options.profile.original_byte_limit()) as u64,
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
            .ok_or("file-backed fetch deadline expired before source verification")?;
        let mut allow_work = || {
            let allowed = live();
            if !allowed {
                request.cancel();
            }
            allowed
        };
        // Keep the original pending admission future until it drains; a stop
        // after its CAS cannot erase the completed terminal decision.
        let result = match options.profile {
            SourceProfile::Full => {
                node.runtime()
                    .block_on(node.fetch_full_git_bundle_reader_controlled_in(
                        &request,
                        &session,
                        &mut input,
                        &options.common.mappings,
                        options.query,
                        Default::default(),
                        &mut allow_work,
                    ))
            }
            SourceProfile::Incremental { max_original_bytes } => {
                node.runtime()
                    .block_on(node.fetch_incremental_git_bundle_reader_controlled_in(
                        &request,
                        &session,
                        &mut input,
                        &options.common.mappings,
                        StreamIncrementalBundleImportQuery {
                            bundle: options.query,
                            max_original_bytes,
                        },
                        Default::default(),
                        &mut allow_work,
                    ))
            }
        }
        .map_err(|error| error.to_string())?;
        let first = result
            .commands
            .first()
            .ok_or("no terminal fetch commands returned")?;
        if !result.session.atomic
            || result.session.tx_ids != vec![first.tx_id]
            || result.commands.len() != options.common.mappings.len()
            || result.commands.iter().any(|command| command != first)
        {
            return Err(format!(
                "inconsistent atomic fetch receipt; {}",
                super::describe(first.tx_id, &first.terminal)
            ));
        }
        Ok((first.tx_id, first.terminal))
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match operation {
        Ok((tx, terminal)) => {
            super::finish(output, &options.common, tx, &terminal, cleanup.as_deref())
        }
        Err(error) => {
            let cleanup = cleanup.map_or_else(String::new, |error| {
                format!("; node shutdown also failed: {error}")
            });
            Err(format!(
                "file-backed bundle fetch returned no terminal outcome: {error}{cleanup}; this is not evidence of non-commit. Retry the same canonical updates and key, or use fg outcome"
            ))
        }
    }
}

#[cfg(test)]
mod incremental_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MIB: usize = 1024 * 1024;

    fn args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
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
            "--map".into(),
            "refs/heads/main".into(),
            "refs/remotes/upstream/main".into(),
            "absent".into(),
        ];
        args.extend(extra.iter().map(|value| (*value).into()));
        args
    }

    #[test]
    fn file_fetch_limits_are_independent_and_share_the_import_parser() {
        let default = parse(&args(&[])).unwrap();
        let enlarged = parse(&args(&["--max-blob-mib", "1024"])).unwrap();
        assert_eq!(enlarged.query.limits.max_streamed_blob_bytes, 1024 * MIB);
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
        assert_eq!(chosen.query.limits.envelope.max_bundle_bytes, 512 * MIB);
        assert_eq!(chosen.query.limits.pack.max_input_bytes, 512 * MIB);
        assert_eq!(
            chosen.query.limits.pack.max_total_expanded_bytes,
            2048 * MIB
        );
        assert_eq!(
            chosen.query.limits.graph.max_payload_bytes,
            (2048 * MIB) as u64
        );
        assert_eq!(chosen.query.limits.pack.max_object_bytes, MIB);
        assert_eq!(chosen.query.limits.graph.max_object_bytes, MIB);
        assert_eq!(chosen.query.limits.pack.max_entries, 5000);
        assert_eq!(chosen.query.limits.pack.max_index_entries, 5000);
        assert_eq!(chosen.query.limits.graph.max_objects, 5000);
        assert_eq!(chosen.query.limits.envelope.max_references, 64);
        assert_eq!(chosen.query.limits.graph.max_references, 64);
        assert_eq!(chosen.query.limits.graph.max_edges, 50000);
        assert_eq!(chosen.query.timeout, Duration::from_secs(600));
        assert_eq!(chosen.common.format, fgit_types::GitHashAlgorithm::Sha256);
    }

    #[test]
    fn file_fetch_delegates_byte_names_fanout_and_exact_old_domains() {
        for format in [
            fgit_types::GitHashAlgorithm::Sha1,
            fgit_types::GitHashAlgorithm::Sha256,
        ] {
            let old = "1a".repeat(format.digest_len());
            let mut input = args(&["--max-refs", "1", "--object-format", format.as_str()]);
            input.extend([
                "--map-hex".into(),
                super::super::hex(b"refs/heads/main"),
                super::super::hex(b"refs/remotes/upstream/\xff"),
                old.clone(),
            ]);
            let parsed = parse(&input).unwrap();
            assert_eq!(parsed.query.limits.envelope.max_references, 1);
            assert_eq!(parsed.common.mappings.len(), 2);
            let byte_mapping = parsed
                .common
                .mappings
                .iter()
                .find(|mapping| mapping.destination.as_bytes() == b"refs/remotes/upstream/\xff")
                .unwrap();
            assert_eq!(byte_mapping.source.as_bytes(), b"refs/heads/main");
            assert_eq!(
                byte_mapping.expected_old,
                Some(fgit_types::GitOid::from_hex(format, &old).unwrap())
            );
        }
        let mut duplicate = args(&[]);
        duplicate.extend([
            "--map-hex".into(),
            super::super::hex(b"refs/heads/main"),
            super::super::hex(b"refs/remotes/upstream/main"),
            "absent".into(),
        ]);
        assert!(parse(&duplicate).is_err());
        let invalid = args(&["--object-format", "sha256"]);
        let mut wrong_domain = invalid;
        let at = wrong_domain.iter().position(|arg| arg == "--map").unwrap();
        wrong_domain[at + 3] = "1a".repeat(20);
        assert!(parse(&wrong_domain).is_err());
    }

    #[test]
    fn profile_dispatch_preserves_opaque_values_and_mapping_argument_ownership() {
        for value in [
            "--file-backed",
            "--map",
            "--map-hex",
            "--max-blob-mib",
            "--help",
        ] {
            let mut buffered = args(&[]);
            buffered.remove(4);
            let key = buffered
                .iter()
                .position(|arg| arg == "--idempotency-key")
                .unwrap();
            buffered[key + 1] = value.into();
            assert!(super::super::parse(&buffered).is_ok());
            assert!(!requested(&buffered), "key changed dispatch: {value}");
            buffered.push("--file-backed".into());
            assert!(requested(&buffered));
            let parsed = parse(&buffered).unwrap();
            let super::super::Key::Bytes(key) = parsed.common.key else {
                panic!("literal key changed representation");
            };
            assert_eq!(key, value.as_bytes());
            assert_eq!(parsed.query.limits.max_streamed_blob_bytes, 32 * MIB);
        }
        for value_index in 1..=3 {
            let mut buffered = args(&[]);
            buffered.remove(4);
            let mapping = buffered.iter().position(|arg| arg == "--map").unwrap();
            buffered[mapping + value_index] = "--file-backed".into();
            assert!(!requested(&buffered));
            buffered.push("--file-backed".into());
            assert!(requested(&buffered));
            assert!(parse(&buffered).is_err());
        }
        let mut resource_value = args(&[]);
        resource_value.remove(4);
        resource_value.extend(["--max-blob-mib".into(), "--file-backed".into()]);
        assert!(!requested(&resource_value));
        let mut path_value = args(&[]);
        path_value.remove(4);
        path_value[0] = "--file-backed".into();
        path_value[3] = "--file-backed".into();
        assert!(!requested(&path_value));
        assert!(super::super::parse(&path_value).is_ok());
    }

    #[test]
    fn ambiguous_or_unbounded_file_fetch_profiles_refuse_before_io() {
        for extra in [
            vec!["--max-input-mib", "0"],
            vec!["--max-input-mib", "01"],
            vec!["--max-blob-mib", "16385"],
            vec!["--max-object-mib", "33"],
            vec!["--max-expanded-mib", "18446744073709551615"],
            vec!["--max-objects", "1000001"],
            vec!["--max-refs", "4097"],
            vec!["--max-edges", "8000001"],
            vec!["--timeout-secs", "3601"],
            vec!["--max-input-mib"],
            vec!["--file-backed"],
            vec!["--max-blob-mib", "40", "--max-blob-mib", "40"],
            vec!["--force"],
            vec!["--prune"],
            vec!["--scratch-dir", "elsewhere"],
            vec!["--key-stdin"],
            vec!["--trusted-local"],
            vec!["--map", "refs/heads/main", "refs/remotes/other"],
            vec!["--map", "refs/heads/main", "refs/internal/policy", "absent"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "accepted {extra:?}");
        }
        for missing in ["--file-backed", "--trusted-local"] {
            let mut absent = args(&[]);
            absent.retain(|arg| arg != missing);
            assert!(parse(&absent).is_err());
        }
        let mut no_maps = args(&[]);
        no_maps.truncate(10);
        assert!(parse(&no_maps).is_err());
        let mut too_long = args(&[]);
        too_long[0] = "x".repeat(64 * 1024 + 1);
        assert!(parse(&too_long).is_err());
    }

    #[test]
    fn full_mapping_capacity_and_all_resource_flags_keep_separate_argument_budgets() {
        let mut input = args(&[
            "--max-input-mib",
            "512",
            "--max-expanded-mib",
            "1024",
            "--max-object-mib",
            "1",
            "--max-blob-mib",
            "40",
            "--max-objects",
            "100000",
            "--max-refs",
            "1",
            "--max-edges",
            "1000000",
            "--timeout-secs",
            "600",
        ]);
        for index in 1..4096 {
            input.extend([
                "--map".into(),
                "refs/heads/main".into(),
                format!("refs/remotes/upstream/copy-{index}"),
                "absent".into(),
            ]);
        }
        assert!(input.len() > 16_404);
        let parsed = parse(&input).unwrap();
        assert_eq!(parsed.common.mappings.len(), 4096);
        assert_eq!(parsed.query.limits.envelope.max_references, 1);
        input.extend([
            "--map".into(),
            "refs/heads/main".into(),
            "refs/remotes/upstream/overflow".into(),
            "absent".into(),
        ]);
        assert!(parse(&input).is_err());
    }

    #[test]
    fn both_file_fetch_help_orders_avoid_credentials_and_filesystem_work() {
        for flags in [["--file-backed", "--help"], ["--help", "--file-backed"]] {
            let input = flags.map(String::from);
            assert!(help_requested(&input));
            let mut output = Vec::new();
            assert_eq!(run_with_output(&input, &mut output).unwrap(), 0);
            let help = String::from_utf8(output).unwrap();
            assert!(help.contains("--map-hex"));
            assert!(help.contains("--max-blob-mib"));
            assert!(help.contains("git_bundle_fetch"));
        }
        assert!(!help_requested(&["--help".into()]));
        assert!(!help_requested(&[
            "--file-backed".into(),
            "--help".into(),
            "extra".into()
        ]));
    }
}
