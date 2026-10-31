//! Reconstruct an original signed source archive from surviving fixed ranges.
//! Catalogs are bounded hints; only the original signature, whole-file pin and
//! complete native preflight can authorize create-only output publication.

#[cfg(any(unix, test))]
mod catalog;
#[cfg(unix)]
mod engine;
#[cfg(unix)]
mod io;

use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use fgit_authority::StoreInstanceId;

use super::super::emit;
use super::approval::{ApprovalFlags, ApprovalOptions};
use super::profile::{Deadline, Profile, ProfileFlags};

const MAX_REPLICAS: usize = 64;
const MAX_REPLICA_PATH_BYTES: usize = 256 * 1024;
// At most 64 attempted source reads plus three complete native output passes.
// Actual reads, including rejected candidates, share this one finite ledger.
const MAX_READ_BYTES: u64 = (MAX_REPLICAS as u64 + 3) * (1_u64 << 40);

pub(super) const USAGE: &str =
    "usage: fg backup catalog <backup-file> <new-catalog-file>
       fg backup reconstruct <catalog-file> <new-backup-file> --replica <file> [--replica <file> ...]
         --verification-root <new-scratch-root> --verification-instance <positive-integer>
         --trusted-local --expected-sha256 <64-lowercase-hex>
         --approval <original-approval-file> --trust-key <independently-trusted-public-PEM>
         --tenant-id <hex> --repository-id <hex> --incarnation-id <hex>
         --object-format sha1|sha256 --minimum-head-generation <positive-u64>
         [--max-archive-bytes <1..1099511627776>] [--max-blob-bytes <1..1099511627776>]
         [--max-objects <1..1000000>] [--timeout-secs <1..86400>]
         [--max-read-bytes <1..73667279060992>]

Catalog creation first authenticates the original approval and verifies the
complete native archive, then emits the interoperable FGCHNK01 catalog of 4 MiB
range hashes. Reconstruction tries 1..64 explicitly named local copies in sorted
absolute lexical path order. Missing, damaged and short copies may contribute
surviving ranges; symlinks are refused and source copies are never modified.

Catalog checksums and range hashes are hints. The reconstructed private file
must match the ORIGINAL approved whole-file SHA-256 and length, pass complete
native object, original-commitment, authority and graph verification, and match
the independently supplied namespace, incarnation, format and generation floor.
The original approval remains the approval for the recovered bytes; no new
signature, live placement, canonical authority, routing or Capsule is created.

One original deadline covers authentication, copying, native verification and
publication. The actual-byte read allowance defaults to four times the explicit
archive-byte limit. It includes rejected candidate reads and all three native
archive passes. Catalog metadata is separately bounded to 8388696 bytes. An
exhausted allowance still performs a real EOF probe and refuses any extra byte.
I/O failures outside the documented unavailable-copy cases, expiry, cancellation
and exhausted budgets abort the entire operation, without trying another copy.

The output must be new, with an existing owner-private parent. The verification
root must be new and disjoint from inputs and output. Unix stable trusted parent
paths are required; this is not a hostile same-user namespace sandbox. After
private-file synchronization and verification, publication is create-only and
directory-synchronized. A visible or uncertain publication failure preserves
the output; inspect it before retrying. Exit 0 means durable publication; exit 2
means refusal or an incomplete operation, including receipt-output failure.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operation {
    Catalog,
    Reconstruct,
}

#[derive(Debug)]
pub(super) struct Options {
    operation: Operation,
    input: PathBuf,
    output: PathBuf,
    scratch: PathBuf,
    replicas: Vec<PathBuf>,
    expected: [u8; 32],
    instance: StoreInstanceId,
    approval: ApprovalOptions,
    profile: Profile,
    max_read_bytes: u64,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if !(24..=162).contains(&args.len())
        || args
            .iter()
            .any(|value| value.is_empty() || value.len() > 8192 || value.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > MAX_REPLICA_PATH_BYTES + 32768
    {
        return Err(USAGE.into());
    }
    let operation = match args[0].as_str() {
        "catalog" => Operation::Catalog,
        "reconstruct" => Operation::Reconstruct,
        _ => return Err(USAGE.into()),
    };
    let base = std::env::current_dir().map_err(|error| error.to_string())?;
    let input = normalized(&base, Path::new(&args[1]));
    let output = normalized(&base, Path::new(&args[2]));
    let (mut trusted, mut scratch, mut expected, mut instance, mut max_read_bytes) =
        (false, None, None, None, None);
    let mut profile = ProfileFlags::default();
    let mut approval = ApprovalFlags::default();
    let mut controls = Vec::new();
    let mut replicas = Vec::new();
    let mut replica_path_bytes = 0_usize;
    let mut cursor = 3;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted {
            trusted = true;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--verification-root" if scratch.is_none() => {
                scratch = Some(normalized(&base, Path::new(value)));
            }
            "--expected-sha256" if expected.is_none() => {
                expected = Some(super::restore::digest(value)?);
            }
            "--verification-instance" if instance.is_none() => {
                instance = Some(StoreInstanceId::from_raw(positive_decimal(
                    flag,
                    value,
                    i64::MAX as u64,
                )?));
            }
            "--max-read-bytes" if max_read_bytes.is_none() => {
                max_read_bytes = Some(positive_decimal(flag, value, MAX_READ_BYTES)?);
            }
            "--replica" if operation == Operation::Reconstruct => {
                if replicas.len() == MAX_REPLICAS {
                    return Err("backup reconstruction permits at most 64 explicit replicas".into());
                }
                let path = normalized(&base, Path::new(value));
                replica_path_bytes = replica_path_bytes
                    .checked_add(path.as_os_str().len())
                    .filter(|total| *total <= MAX_REPLICA_PATH_BYTES)
                    .ok_or("backup replica path-byte limit exceeded")?;
                replicas.push(path);
            }
            "--max-archive-bytes" | "--max-blob-bytes" | "--max-objects" | "--timeout-secs" => {
                profile.set(flag, value)?;
            }
            "--approval" | "--trust-key" => {
                let path = normalized(&base, Path::new(value));
                approval.set(
                    flag,
                    path.to_str().ok_or("backup control path must be UTF-8")?,
                )?;
                controls.push(path);
            }
            _ if ApprovalFlags::accepts(flag) => approval.set(flag, value)?,
            _ => {
                return Err(format!(
                    "unknown or duplicate backup reconstruction option: {flag}"
                ));
            }
        }
    }
    if !trusted {
        return Err("backup catalog and reconstruction require --trusted-local".into());
    }
    if operation == Operation::Reconstruct && replicas.is_empty() {
        return Err("backup reconstruction requires at least one explicit --replica".into());
    }
    replicas.sort();
    if replicas.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("backup reconstruction requires distinct normalized replica paths".into());
    }
    let scratch = scratch.ok_or("backup reconstruction requires --verification-root")?;
    if output.file_name().is_none() || scratch.file_name().is_none() {
        return Err("backup reconstruction requires named new output and scratch paths".into());
    }
    for source in std::iter::once(&input).chain(&controls).chain(&replicas) {
        if &output == source {
            return Err("backup output must be distinct from every input and control file".into());
        }
    }
    for path in std::iter::once(&input)
        .chain(std::iter::once(&output))
        .chain(&controls)
        .chain(&replicas)
    {
        if path.starts_with(&scratch) || scratch.starts_with(path) {
            return Err("backup verification root must be disjoint from inputs and output".into());
        }
    }
    let profile = profile.finish();
    Ok(Options {
        operation,
        input,
        output,
        scratch,
        replicas,
        expected: expected.ok_or("backup reconstruction requires --expected-sha256")?,
        instance: instance.ok_or("backup reconstruction requires --verification-instance")?,
        approval: approval.finish()?.ok_or("backup reconstruction requires an original signed approval and independent trust policy")?,
        profile,
        max_read_bytes: max_read_bytes.unwrap_or(4 * profile.transfer.max_archive_bytes),
    })
}

fn positive_decimal(flag: &str, text: &str, maximum: u64) -> Result<u64, String> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{flag} requires canonical positive decimal"));
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= maximum)
        .ok_or_else(|| format!("{flag} must be in 1..={maximum}"))
}

/// Match path.resolve's lexical behavior without dereferencing a symlink.
/// The actual final source component is opened with NOFOLLOW later.
fn normalized(base: &Path, path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut result = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            other => result.push(other.as_os_str()),
        }
    }
    result
}

#[derive(Debug)]
pub(super) struct Receipt {
    json: String,
}
impl Receipt {
    pub(super) fn json(&self) -> &str {
        &self.json
    }
}

pub(super) fn execute_in(options: &Options, deadline: Deadline) -> Result<Receipt, String> {
    #[cfg(unix)]
    {
        engine::execute_with_checkpoints(options, deadline, |_| Ok(()))
    }
    #[cfg(not(unix))]
    {
        let _ = (options, deadline);
        Err("backup reconstruction requires the Unix stable-source and synchronized no-replace publication profile".into())
    }
}

pub(super) fn run(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), String> {
    if args == ["catalog", "--help"] || args == ["reconstruct", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.profile = options.profile.with_timeout_cap(timeout)?;
    let receipt = execute_in(&options, options.profile.start())?;
    emit(output, receipt.json()).map_err(|error| format!(
        "backup reconstruction publication_state=durable; output published; receipt output failed: {error}"
    ))
}

#[cfg(all(test, unix))]
mod native_tests;
#[cfg(test)]
mod parse_tests;
