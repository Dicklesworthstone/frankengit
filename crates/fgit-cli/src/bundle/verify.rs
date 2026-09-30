//! Read-only offline native bundle verification. No OneNode or credential exists here.
mod anchors;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fgit_crypto::lowercase_hex;
use fgit_node::TerminationSignals;
use fgit_node::source_retrieval::integrity::bundle_verify::{
    BundleExpectations, BundleVerifyLimits, MAX_EXPECTED_REFS, VerifiedGitBundle,
    verify_git_bundle, verify_git_bundle_against,
};
use fgit_types::GitHashAlgorithm;

pub(super) const USAGE: &str = "usage: fg bundle verify <bundle-file> [OPTIONS]
  --max-input-mib N       Whole input ceiling, 1..128 (default 128)
  --max-expanded-mib N    Native resolution and graph payload ceilings, 1..128
  --max-objects N         Included object count, 1..100000 (default 100000)
  --max-refs N            Direct refs plus optional HEAD, 1..4096 (default 4096)
  --timeout-secs N        Whole read/verification deadline, 1..3600 (default 300)
  --expect-sha256 HEX     Separately trusted whole-bundle SHA-256 (64 lowercase hex)
  --expect-format FORMAT Explicit sha1|sha256 domain, required for reference pins
  --expect-ref REF=OID    Repeat for known full native branch/tag/reference tips
  --expect-ref-hex HEX=OID Lossless raw-byte-name alternative
  --exact-refs            Require precisely the supplied direct-reference set
  --                     Treat the remaining argument as a literal file path

Uses the native Rust bundle, pack/DEFLATE/delta, object and graph implementations.
No storage directory, node, tenant, principal, retry key, network or Git executable
is used. Every included object's local dependencies must be present and correctly
typed; submodule gitlinks are external and are not fetched. Full v2/v3 SHA-1/SHA-256
bundles only; prerequisites/filters/borrowed bases refuse. Input is retained in
memory under the selected ceiling; this is not a streaming large-repository reader.

Success emits one JSON content-verification report. It does not authenticate the
origin, prove branch freshness, verify signatures or restore forge/authority state.
Identity pins must come from a separately trusted record, not an adjacent unsigned
manifest. A format alone is not an identity pin. Ref IDs must be full, not abbreviated;
a matching sha1: or sha256: prefix is accepted. Without --exact-refs, additional refs
are allowed but every included object still undergoes complete graph verification.
Malformed pins refuse before input reads; mismatches refuse before decompression.
Matching pins never skip native verification or imply freshness/signature authority.
The input path must be a quiescent regular local file, not a symlink. Cancellation
and deadlines are cooperative and cannot interrupt a blocking operating-system read.
Exit 0: fully verified; 2: invalid/incomplete/unsupported input or interrupted work.";

#[derive(Debug)]
struct Options {
    path: PathBuf,
    limits: BundleVerifyLimits,
    timeout: Duration,
    expectations: Option<BundleExpectations>,
}
fn number(value: &str, maximum: usize) -> Result<usize, String> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("bundle verify limits require positive canonical decimal integers".into());
    }
    let value = value
        .parse::<usize>()
        .map_err(|_| "bundle verify limit overflow")?;
    if value > maximum {
        return Err("bundle verify limit exceeds this bounded profile".into());
    }
    Ok(value)
}
fn parse(args: &[String]) -> Result<Options, String> {
    if args.is_empty()
        || args.len() > 2 * MAX_EXPECTED_REFS + 32
        || args.iter().try_fold(0_usize, |sum, arg| sum.checked_add(arg.len()))
            .is_none_or(|sum| sum > 2 * 1024 * 1024)
        || args
            .iter()
            .any(|arg| arg.len() > 8300 || arg.contains('\0'))
    {
        return Err(USAGE.into());
    }
    let mut path = None;
    let mut limits = BundleVerifyLimits::default();
    let mut timeout = Duration::from_secs(300);
    let mut seen = BTreeSet::new();
    let mut expected_hash = None;
    let mut expected_format = None;
    let mut expected_refs = Vec::new();
    let mut exact_refs = false;
    let mut literal = false;
    let mut at = 0;
    while at < args.len() {
        let argument = args[at].as_str();
        at += 1;
        if !literal && argument == "--" {
            literal = true;
            continue;
        }
        if !literal && argument.starts_with('-') {
            if !matches!(argument, "--expect-ref" | "--expect-ref-hex") && !seen.insert(argument) {
                return Err("duplicate bundle verify option".into());
            }
            if argument == "--exact-refs" {
                exact_refs = true;
                continue;
            }
            let value = args.get(at).ok_or("missing bundle verify option value")?;
            at += 1;
            match argument {
                "--expect-sha256" => {
                    expected_hash = Some(anchors::unhex(value, 32)?.try_into()
                        .map_err(|_| "expected exactly 32 SHA-256 bytes")?);
                }
                "--expect-format" => {
                    expected_format = Some(match value.as_str() {
                        "sha1" => GitHashAlgorithm::Sha1,
                        "sha256" => GitHashAlgorithm::Sha256,
                        _ => return Err("expected native format must be sha1 or sha256".into()),
                    });
                }
                "--expect-ref" | "--expect-ref-hex" => {
                    if expected_refs.len() == MAX_EXPECTED_REFS {
                        return Err("too many expected references".into());
                    }
                    expected_refs.try_reserve(1).map_err(|_| "expectation allocation refused")?;
                    expected_refs.push((value.as_str(), argument == "--expect-ref-hex"));
                }
                "--max-input-mib" => {
                    let bytes = number(value, 128)? * 1024 * 1024;
                    limits.envelope.max_bundle_bytes = bytes;
                    limits.pack.max_input_bytes = bytes;
                }
                "--max-expanded-mib" => {
                    let bytes = number(value, 128)? * 1024 * 1024;
                    limits.pack.max_total_expanded_bytes = bytes;
                    limits.pack.max_cached_bytes = bytes;
                    limits.pack.max_object_bytes = limits.pack.max_object_bytes.min(bytes);
                    limits.graph.max_object_bytes = limits.pack.max_object_bytes;
                    limits.graph.max_payload_bytes = bytes as u64;
                }
                "--max-objects" => {
                    let count = number(value, 100_000)?;
                    limits.pack.max_entries =
                        u32::try_from(count).map_err(|_| "object count overflow")?;
                    limits.graph.max_objects = count;
                }
                "--max-refs" => {
                    let count = number(value, 4096)?;
                    limits.envelope.max_references = count;
                    limits.graph.max_references = count;
                }
                "--timeout-secs" => timeout = Duration::from_secs(number(value, 3600)? as u64),
                _ => return Err("unknown bundle verify option".into()),
            }
        } else if argument.is_empty() || path.replace(PathBuf::from(argument)).is_some() {
            return Err("bundle verify requires exactly one nonempty input path".into());
        }
    }
    // Complete validation uses final limits, independent of option order,
    // before opening the input or installing any runtime resources.
    let expectations = anchors::assemble(expected_hash, expected_format, &expected_refs, exact_refs, &limits)?;
    Ok(Options {
        expectations,
        path: path.ok_or("bundle verify requires an input path")?,
        limits,
        timeout,
    })
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), String> {
    if live() {
        Ok(())
    } else {
        Err("bundle_verification_stopped".into())
    }
}
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.size() == right.size()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.nlink() == right.nlink()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
            && left.permissions().readonly() == right.permissions().readonly()
    }
}
fn read_input(
    path: &Path,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, String> {
    checkpoint(live)?;
    let named = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file() || named.len() == 0 || named.len() > maximum as u64 {
        return Err(
            "bundle input must be a nonempty regular non-symlink file within the byte limit".into(),
        );
    }
    // Trusted-local path, not a descriptor-relative sandbox against namespace
    // races. Object verification always consumes this one immutable owned copy.
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || !same_file(&named, &before) {
        return Err("bundle input changed while opening".into());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        checkpoint(live)?;
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        };
        checkpoint(live)?;
        if count == 0 {
            break;
        }
        let total = bytes
            .len()
            .checked_add(count)
            .filter(|total| *total <= maximum)
            .ok_or("bundle input grew beyond the byte limit")?;
        bytes
            .try_reserve(count)
            .map_err(|_| "bundle input allocation refused")?;
        bytes.extend_from_slice(&buffer[..count]);
        if total as u64 > before.len() {
            return Err("bundle input length changed".into());
        }
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file()
        || bytes.len() as u64 != before.len()
        || !same_file(&before, &after)
        || !same_file(&after, &named)
    {
        return Err("bundle input changed while reading".into());
    }
    checkpoint(live)?;
    Ok(bytes)
}
fn report(result: &VerifiedGitBundle) -> Result<String, String> {
    let graph = result.graph();
    let mut out = format!(
        "{{\"type\":\"git_bundle_verification\",\"schema_version\":1,\"profile\":\"native-full-bundle-graph-v1\",\"object_format\":\"{}\",\"bundle_bytes\":{},\"artifact_sha256\":\"{}\",\"pack_bytes\":{},\"pack_checksum\":\"{}\",\"object_count\":{},\"reference_count\":{},\"payload_bytes\":{},\"local_edges\":{},\"external_gitlinks\":{},\"delta_objects\":{},\"resolution_passes\":{},\"advertised_head\":{},\"references\":[",
        result.format().as_str(),
        result.bytes(),
        lowercase_hex(result.sha256()),
        result.pack_bytes(),
        lowercase_hex(result.pack_checksum().as_bytes()),
        graph.objects,
        graph.references,
        graph.payload_bytes,
        graph.local_edges,
        graph.external_gitlinks,
        result.delta_objects(),
        result.resolution_passes(),
        result.advertised_head().map_or_else(
            || "null".into(),
            |id| format!("\"{}\"", lowercase_hex(id.as_bytes()))
        )
    );
    for (index, (name, id)) in result.references().iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"ref_hex\":\"{}\",\"object_id\":\"{}\"}}",
            lowercase_hex(name.as_bytes()),
            lowercase_hex(id.as_bytes())
        )
        .map_err(|error| error.to_string())?;
    }
    out.push_str("],\"pack_checksum_verified\":true,\"objects_verified\":true,\"object_graph_verified\":true,\"graph_scope\":\"all-included-objects-and-advertised-direct-refs\",\"gitlink_targets_verified\":false,\"signatures_verified\":false,\"origin_authenticated\":false,\"current_branch_verified\":false,\"strict_fsck_equivalent\":false,\"repository_opened\":false,\"repository_changed\":false,\"forge_state_verified\":false}");
    Ok(out)
}
fn execute(options: &Options, live: &mut impl FnMut() -> bool) -> Result<String, String> {
    let bytes = read_input(
        &options.path,
        options.limits.envelope.max_bundle_bytes,
        live,
    )?;
    match &options.expectations {
        Some(expected) => {
            let result = verify_git_bundle_against(&bytes, &options.limits, expected, live)
                .map_err(|error| error.to_string())?;
            checkpoint(live)?;
            anchors::report(&result)
        }
        None => {
            let result = verify_git_bundle(&bytes, &options.limits, live)
                .map_err(|error| error.to_string())?;
            checkpoint(live)?;
            report(&result)
        }
    }
}
pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut live = || !signals.requested() && started.elapsed() < options.timeout;
    let output = execute(&options, &mut live)?;
    checkpoint(&mut live)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{output}")
        .and_then(|()| stdout.flush())
        .map_err(|error| error.to_string())?;
    Ok(0)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod anchor_tests;
