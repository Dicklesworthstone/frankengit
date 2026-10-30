//! Explicit streaming Git-only export with caller-owned local publication.
mod incremental;
mod local_file;

use std::collections::BTreeSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use fgit_node::{GitDaemonSessionTimeout, NodeConfig, OneNode, TerminationSignals};
use fgit_node::{SelectedStreamBundleExport, StreamBundleExportQuery};
use fgit_types::{GitHashAlgorithm, HeadGeneration, RepositoryId, TenantId};

use super::quote;
use local_file::OwnedExport;

const MIB: u64 = 1024 * 1024;
pub(super) const USAGE: &str =
    "usage: fg bundle export <storage-root> <tenant-id> <repository-id> <new-bundle-file>
  --streaming --trusted-local [--object-format sha1|sha256]
  [--max-output-mib N] [--max-expanded-mib N] [--max-object-mib N]
  [--max-blob-mib N]
  [--max-objects N] [--max-refs N] [--max-edges N]
  [--max-compression-work N] [--timeout-secs N]

The streaming profile retains bounded native metadata, a blob input chunk and
compressor state plus bounded object/edge metadata. It writes V2/SHA-1 or V3/SHA-256 full bundles in
deterministic native object-ID order with whole objects and no delta window.
Only current visible refs and their complete verified graph are exported.

Output and expanded-byte defaults are 128 MiB; each can be set to 1..16384 MiB.
The buffered object-byte default and ceiling are 32 MiB. The independent blob
allowance defaults to 32 MiB and accepts 1..16384 MiB. A larger blob allowance
does not widen metadata allocation or aggregate expanded bytes. Object count defaults to 100000,
and ref-header count to 4096 (including HEAD); both have a ceiling of 1000000.
Graph edges default to 1000000 (ceiling 8000000); compression work defaults to
1000000000 (ceiling 1000000000000). Limits are independent; raising a byte limit
does not raise work, object, header or graph limits. Timeout defaults to 300
seconds, accepts 1..3600, and is narrowed by an explicit global timeout.

The Unix output parent must already exist, use ordinary non-symlink components,
and stay under the local operator's control. A fresh private file is staged
there; no output name is published until native completion and node shutdown.
File sync, a create-only hard link, and parent sync complete local publication.
An existing destination is never replaced. This transfers Git source, not
forge metadata, policy, credentials or repository authority.
Cancellation is cooperative and cannot interrupt a blocking operating-system call.
Exit 0: complete locally durable export; 2: input, source, output or cleanup
failure. An error after publication says the file became visible; preserve it.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    path: PathBuf,
    format: GitHashAlgorithm,
    query: StreamBundleExportQuery,
    incremental: Option<incremental::Selection>,
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

fn mib(flag: &str, value: &str, maximum: u64) -> Result<usize, String> {
    let bytes = number(flag, value, maximum)?
        .checked_mul(MIB)
        .ok_or_else(|| format!("{flag} byte limit overflow"))?;
    usize::try_from(bytes).map_err(|_| format!("{flag} byte limit exceeds this platform"))
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args
        .first()
        .is_some_and(|operation| operation == "sync-export")
    {
        return incremental::parse(args);
    }
    parse_full(args)
}

fn parse_full(args: &[String]) -> Result<Options, String> {
    if args.len() < 7
        || args.len() > 40
        || args.first().map(String::as_str) != Some("export")
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
    if args[1].is_empty() || args[4].is_empty() {
        return Err("storage and output paths must be nonempty".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|error| error.to_string())?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|error| error.to_string())?;
    let mut query = StreamBundleExportQuery::default();
    query.limits.pack.max_index_entries = query.limits.pack.max_entries as usize;
    let mut format = GitHashAlgorithm::Sha1;
    let mut seen = BTreeSet::new();
    let mut at = 5;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        if !seen.insert(flag) {
            return Err(format!("duplicate streaming export option {flag}"));
        }
        if matches!(flag, "--streaming" | "--trusted-local") {
            continue;
        }
        let value = args
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        match flag {
            "--object-format" => {
                format = match value.as_str() {
                    "sha1" => GitHashAlgorithm::Sha1,
                    "sha256" => GitHashAlgorithm::Sha256,
                    _ => return Err("object format must be sha1 or sha256".into()),
                };
            }
            "--max-output-mib" => {
                let bytes = mib(flag, value, 16_384)?;
                query.limits.envelope.max_bundle_bytes = bytes;
                query.limits.pack.max_input_bytes = bytes;
            }
            "--max-expanded-mib" => {
                query.limits.pack.max_total_expanded_bytes = mib(flag, value, 16_384)?;
            }
            "--max-object-mib" => {
                query.limits.pack.max_object_bytes = mib(flag, value, 32)?;
            }
            "--max-blob-mib" => {
                query.limits.max_streamed_blob_bytes = mib(flag, value, 16_384)?;
            }
            "--max-objects" => {
                let count = number(flag, value, 1_000_000)? as u32;
                query.limits.pack.max_entries = count;
                query.limits.pack.max_index_entries = count as usize;
            }
            "--max-refs" => {
                query.limits.envelope.max_references = number(flag, value, 1_000_000)? as usize;
            }
            "--max-edges" => {
                query.limits.max_graph_edges = number(flag, value, 8_000_000)? as usize;
            }
            "--max-compression-work" => {
                query.limits.max_compression_work = number(flag, value, 1_000_000_000_000)?;
            }
            "--timeout-secs" => {
                query.timeout = Duration::from_secs(number(flag, value, 3600)?);
            }
            _ => return Err(format!("unknown streaming export option {flag}")),
        }
    }
    if !seen.contains("--streaming") || !seen.contains("--trusted-local") {
        return Err("streaming export requires both --streaming and --trusted-local".into());
    }
    let path = PathBuf::from(&args[4]);
    if path.file_name().is_none() {
        return Err("export output must name a new regular file".into());
    }
    Ok(Options {
        storage: PathBuf::from(&args[1]),
        tenant,
        repository,
        path,
        format,
        query,
        incremental: None,
    })
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    run_with_output(args, &mut std::io::stdout().lock())
}

fn abort(stage: &mut OwnedExport, cause: impl std::fmt::Display) -> String {
    let cleanup = stage
        .cleanup()
        .err()
        .map_or_else(String::new, |error| format!("; {error}"));
    format!(
        "streaming bundle export failed: {cause}; publication_state={} bundle_created={}{}",
        stage.state().as_str(),
        stage.state().published(),
        cleanup,
    )
}

fn run_with_output(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    if args.len() == 3
        && matches!(args[0].as_str(), "export" | "sync-export")
        && ((args[1] == "--streaming" && args[2] == "--help")
            || (args[1] == "--help" && args[2] == "--streaming"))
    {
        let usage = if args[0] == "sync-export" {
            incremental::USAGE
        } else {
            USAGE
        };
        writeln!(output, "{usage}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let mut options = parse(args)?;
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
    if !live() {
        return Err("streaming export stopped before staging; publication_state=staged bundle_created=false".into());
    }
    let mut stage = OwnedExport::create(
        &options.path,
        options.query.limits.envelope.max_bundle_bytes as u64,
    )
    .map_err(|error| error.to_string())?;
    if !live() {
        return Err(abort(
            &mut stage,
            "export stopped before opening the source",
        ));
    }
    let session_timeout =
        GitDaemonSessionTimeout::try_new(timeout).map_err(|error| abort(&mut stage, error))?;
    let config = NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
        .with_object_format(options.format)
        .with_max_object_bytes(options.query.limits.pack.max_object_bytes as u64)
        .with_selected_pack_blob_limit(options.query.limits.max_streamed_blob_bytes)
        .with_git_daemon_session_timeout(session_timeout);
    let mut node = OneNode::open_existing(config).map_err(|error| abort(&mut stage, error))?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        options.query.timeout = timeout
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or("streaming export deadline expired while opening the source")?;
        // A larger global override must not widen this leaf's limit. Give the
        // one authority request only the remaining effective budget, so async
        // source reads are bounded before the next synchronous stop probe.
        let remaining = GitDaemonSessionTimeout::try_new(options.query.timeout)
            .map_err(|error| error.to_string())?;
        let request = node.command_request_context(Some(remaining));
        let mut allow_work = || {
            let allowed = live();
            if !allowed {
                request.cancel();
            }
            allowed
        };
        // Keep the native future through completion after requesting stop.
        // Dropping it would not finish the node's cleanup obligations.
        let exported = if let Some(selection) = &options.incremental {
            node.runtime()
                .block_on(node.export_incremental_git_bundle_stream_controlled_in(
                    &request,
                    &selection.references,
                    &selection.prerequisites,
                    &Default::default(),
                    options.query.clone(),
                    &mut stage,
                    &mut allow_work,
                ))
        } else {
            node.runtime()
                .block_on(node.export_full_git_bundle_stream_controlled_in(
                    &request,
                    &Default::default(),
                    options.query.clone(),
                    &mut stage,
                    &mut allow_work,
                ))
        };
        exported.map_err(|error| error.to_string())
    })();
    // Every successfully opened node closes, including after failed reads.
    let shutdown = node.shutdown().map_err(|error| error.to_string());
    let report = match (operation, shutdown) {
        (Ok(report), Ok(())) => report,
        (Err(error), Ok(())) => return Err(abort(&mut stage, error)),
        (Ok(_), Err(error)) => {
            return Err(abort(&mut stage, format!("node shutdown failed: {error}")));
        }
        (Err(error), Err(cleanup)) => {
            return Err(abort(
                &mut stage,
                format!("{error}; node shutdown also failed: {cleanup}"),
            ));
        }
    };
    stage
        .publish(report.receipt().bundle_bytes() as u64, &mut live)
        .map_err(|error| abort(&mut stage, error))?;
    write_receipt(output, &options, &report)?;
    Ok(0)
}

fn write_receipt(
    output: &mut impl Write,
    options: &Options,
    report: &SelectedStreamBundleExport,
) -> Result<(), String> {
    let receipt = report.receipt();
    let (kind, incremental_fields) = if let Some(selection) = &options.incremental {
        (
            "git_bundle_incremental_export",
            format!(
                ",\"reference_count\":{},\"prerequisite_count\":{},\"external_object_count\":{}",
                selection.references.len(),
                receipt.prerequisite_count(),
                receipt.external_object_count(),
            ),
        )
    } else {
        ("git_bundle_export", String::new())
    };
    let line = format!(
        "{{\"type\":{},\"schema_version\":1,\"streaming\":true,\"profile\":{},\"source_head\":{},\"source_generation\":{},\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"object_count\":{},\"total_object_bytes\":{},\"pack_checksum\":{},\"pack_bytes\":{},\"header_bytes\":{},\"bundle_bytes\":{},\"bundle_sha256\":{},\"compression_work\":{},\"publication_state\":\"durable\",\"bundle_created\":true,\"node_closed\":true,\"repository_changed\":false,\"includes_forge_metadata\":false{incremental_fields}}}",
        quote(kind),
        quote(receipt.profile_id()),
        quote(&report.head().to_string()),
        report.generation().get(),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(receipt.format().as_str()),
        receipt.object_count(),
        receipt.total_object_bytes(),
        quote(&receipt.pack_checksum().to_string()),
        receipt.pack_bytes(),
        receipt.header_bytes(),
        receipt.bundle_bytes(),
        quote(&fgit_crypto::lowercase_hex(&receipt.bundle_sha256())),
        receipt.compression_work(),
    );
    emit_receipt(output, &line)
}

fn emit_receipt(output: &mut impl Write, line: &str) -> Result<(), String> {
    writeln!(output, "{line}")
        .and_then(|()| output.flush())
        .map_err(|error| {
            format!(
                "complete bundle file was created and locally synced, but receipt output failed: {error}; publication_state=durable bundle_created=true"
            )
        })
}

#[cfg(test)]
mod tests;
