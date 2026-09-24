//! Offline saved-result recovery. Parsing never opens source or executes work.
#[cfg(target_os = "linux")]
use super::quote;
use super::unhex;
use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
use fgit_types::{RepositoryId, TenantId};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
mod publication;

const USAGE: &str =
    "usage: fg workflow recover <absolute-run-directory> <tenant-id> <repository-id>
  --journal-id <64-lowercase-hex-original-attempt-marker-sha256>
  [--minimum-pin <bytes>:<tail-sha256>] [--timeout-ms <1..60000>]

History (default, includes acknowledged batches; never dequeues or redelivers):
  [--limit <1..128>] [--page-bytes <1..8388608>]
  [--at-pin <bytes>:<tail-sha256> [--after-batch <batch-sha256>]]
  Defaults: 32 batches, 1 MiB encoded batch/acknowledgement bytes, 30 seconds.
  Continue with the returned snapshot as --at-pin and next_after as --after-batch.
  A changed journal snapshot refuses continuation; restart traversal explicitly.

Exact-byte export (does not acknowledge custody or delete saved history):
  --batch <batch-sha256> [--evidence <referenced-evidence-sha256>]
  --output <absolute-new-file-in-private-directory>
  Without --evidence, export the exact encoded proposal batch. Otherwise export
  only an evidence body actually referenced by that batch. Paging flags cannot
  be combined with export. The output must not exist, including a symlink.

Linux only. The source run directory must be stable, private (0700), and contain
its original 0600 attempt.json and check-proposals.journal. The journal ID is the
retained SHA-256 of the original attempt marker, NOT of report.json. Retain scope
and minimum pins independently for trust/anti-rollback; recomputing a digest from
untrusted storage is not authentication. No repository database, source checkout,
workflow compilation, final report or execution retry is involved.

An empty pending queue, a completed job proposal or a delivery acknowledgement
is NOT proof of workflow completion, process reaping or a canonical green check.
No files are recreated or repaired. Incomplete execution requires reconciliation,
not replay. Exact exports use private staging, readback and no-overwrite linking;
errors may leave a named staging file or a published output whose response failed.
Reinspect that artifact; never rerun the workflow because a read/output failed.

Stdout is one bounded JSON observation. Exit 0 means recovery READ succeeded,
not that any job passed. Invalid input, storage, lock, corruption, cancellation
or output failure returns exit 2. Time limits are cooperative between bounded
operations; filesystem calls and stdout do not have hard latency guarantees.";

#[derive(Debug)]
enum Selection {
    History {
        at: Option<(u64, Digest)>,
        after: Option<Digest>,
        count: usize,
        bytes: usize,
    },
    Export {
        batch: Digest,
        evidence: Option<Digest>,
        output: PathBuf,
    },
}
#[derive(Debug)]
struct Options {
    directory: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    marker: Digest,
    minimum: Option<(u64, Digest)>,
    timeout_ms: u64,
    selection: Selection,
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["recover", "--help"] {
        return write_reply(&mut std::io::stdout().lock(), USAGE);
    }
    let options = parse(args)?;
    #[cfg(target_os = "linux")]
    {
        let started = std::time::Instant::now();
        let budget = std::time::Duration::from_millis(options.timeout_ms);
        execute(options, &mut std::io::stdout().lock(), &|| {
            started.elapsed() < budget
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err("saved node workflow recovery requires Linux; no fallback is selected".into())
    }
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 6 || args.len() > 32 || args.first().map(String::as_str) != Some("recover") {
        return Err(USAGE.into());
    }
    if args.iter().any(|s| s.len() > 4096 || s.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > 32 * 1024
    {
        return Err("recovery arguments exceed the bounded profile".into());
    }
    let directory = absolute_path(&args[1])?;
    if unhex(&args[2], 16)?.len() != 16 || unhex(&args[3], 16)?.len() != 16 {
        return Err("recovery scope IDs must have 32 lowercase hex digits".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid recovery tenant")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid recovery repository")?;
    let mut flags = BTreeMap::new();
    let mut cursor = 4;
    while cursor < args.len() {
        let name = args[cursor].as_str();
        cursor += 1;
        if !matches!(
            name,
            "--journal-id"
                | "--minimum-pin"
                | "--timeout-ms"
                | "--limit"
                | "--page-bytes"
                | "--at-pin"
                | "--after-batch"
                | "--batch"
                | "--evidence"
                | "--output"
        ) {
            return Err(format!("unknown recovery option {name:?}"));
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {name}"))?;
        cursor += 1;
        if flags.insert(name, value.as_str()).is_some() {
            return Err(format!("duplicate {name}"));
        }
    }
    let marker = digest(
        flags
            .get("--journal-id")
            .ok_or("--journal-id is mandatory")?,
    )?;
    let minimum = flags.get("--minimum-pin").map(|s| pin(s)).transpose()?;
    let timeout_ms = flags
        .get("--timeout-ms")
        .map_or(Ok(30_000), |s| decimal(s, 1, 60_000))?;
    let selection = if let Some(batch) = flags.get("--batch") {
        if ["--at-pin", "--after-batch", "--limit", "--page-bytes"]
            .iter()
            .any(|f| flags.contains_key(f))
        {
            return Err("history paging options cannot be combined with artifact export".into());
        }
        Selection::Export {
            batch: digest(batch)?,
            evidence: flags.get("--evidence").map(|s| digest(s)).transpose()?,
            output: absolute_path(
                flags
                    .get("--output")
                    .ok_or("artifact export requires --output")?,
            )?,
        }
    } else {
        if flags.contains_key("--output") || flags.contains_key("--evidence") {
            return Err("artifact export requires an exact --batch selector".into());
        }
        let at = flags.get("--at-pin").map(|s| pin(s)).transpose()?;
        let after = flags.get("--after-batch").map(|s| digest(s)).transpose()?;
        if after.is_some() && at.is_none() {
            return Err("--after-batch requires the exact --at-pin snapshot".into());
        }
        Selection::History {
            at,
            after,
            count: flags
                .get("--limit")
                .map_or(Ok(32), |s| decimal(s, 1, 128))? as usize,
            bytes: flags
                .get("--page-bytes")
                .map_or(Ok(1024 * 1024), |s| decimal(s, 1, 8 * 1024 * 1024))?
                as usize,
        }
    };
    Ok(Options {
        directory,
        tenant,
        repository,
        marker,
        minimum,
        timeout_ms,
        selection,
    })
}
fn absolute_path(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if value.is_empty()
        || value.ends_with('/')
        || !path.is_absolute()
        || path.file_name().is_none()
        || path
            .components()
            .any(|p| matches!(p, std::path::Component::ParentDir))
    {
        return Err("recovery paths must be absolute and cannot contain parent traversal".into());
    }
    Ok(path)
}
fn digest(value: &str) -> Result<Digest, String> {
    let bytes = unhex(value, 32)?;
    if bytes.len() != 32 {
        return Err("recovery commitment must have 64 lowercase hex digits".into());
    }
    Ok(Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&bytes).map_err(|_| "invalid recovery digest")?,
    ))
}
fn pin(value: &str) -> Result<(u64, Digest), String> {
    let (length, tail) = value
        .split_once(':')
        .ok_or("pin must be <byte-length>:<sha256>")?;
    Ok((decimal(length, 72, 4 * 1024 * 1024 * 1024)?, digest(tail)?))
}
fn decimal(value: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("recovery limit must be canonical unsigned decimal".into());
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "recovery limit overflow")?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err("recovery limit is outside the bounded profile".into());
    }
    Ok(parsed)
}

#[cfg(target_os = "linux")]
fn execute(
    options: Options,
    output: &mut impl Write,
    live: &dyn Fn() -> bool,
) -> Result<u8, String> {
    let scope = (options.tenant, options.repository, options.marker);
    let reply = match options.selection {
        Selection::History {
            at,
            after,
            count,
            bytes,
        } => fgit_node::OneNode::trusted_workflow_history_json(
            &options.directory,
            scope,
            options.minimum,
            at,
            after,
            (count, bytes),
            live,
        )
        .map_err(|e| e.to_string())?,
        Selection::Export {
            batch,
            evidence,
            output: destination,
        } => {
            let (bytes, metadata) = fgit_node::OneNode::trusted_workflow_artifact(
                &options.directory,
                scope,
                options.minimum,
                batch,
                evidence,
                live,
            )
            .map_err(|e| e.to_string())?;
            publication::publish(&destination, &bytes, live)?;
            let reply = format!(
                "{{\"type\":\"workflow_recovery_export\",\"schema_version\":1,\"output\":{},\"artifact\":{metadata}}}",
                quote(&destination.to_string_lossy())
            );
            return write_reply(output, &reply).map_err(|e| format!(
                "{e}; exact recovered bytes remain at {}; inspect that file, do not replay the workflow", destination.display(),
            ));
        }
    };
    write_reply(output, &reply)
}
fn write_reply(output: &mut impl Write, text: &str) -> Result<u8, String> {
    writeln!(output, "{text}")
        .and_then(|()| output.flush())
        .map_err(|e| format!("workflow recovery output incomplete: {e}"))?;
    Ok(0)
}

#[cfg(test)]
mod tests;
