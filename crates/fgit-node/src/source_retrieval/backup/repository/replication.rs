//! Native verified replica publication. The original signed checkpoint is
//! selected once, natively verified, then copied with its original approval last.

mod engine;
#[cfg(unix)]
mod filesystem;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::emit;
use super::profile::Deadline;
use super::selection;

const MAX_READ_BYTES: u64 = 68 * (1_u64 << 40);

pub(super) const USAGE: &str = "usage: fg backup replicate <existing-private-replica-directory>
         --candidate <archive> <approval> [--candidate <archive> <approval> ...]
         --verification-root <new-scratch-root> --verification-instance <positive-integer>
         --trusted-local --expected-sha256 <64-lowercase-hex>
         --trust-key <independently-trusted-public-PEM>
         --tenant-id <hex> --repository-id <hex> --incarnation-id <hex>
         --object-format sha1|sha256 --minimum-head-generation <positive-u64>
         [--witness <existing-independent-witness-directory>] [--replica-failover]
         [--max-read-bytes <1..74766790688768>]
         [--max-archive-bytes <1..1099511627776>] [--max-blob-bytes <1..1099511627776>]
         [--max-objects <1..1000000>] [--timeout-secs <1..86400>]

Authenticate all 1..64 explicit approvals before payload access. Select the
highest unique canonical statement, retaining the first lexical pair's original
approval bytes. A higher expired, unavailable or invalid checkpoint never permits
older-state fallback. Explicit --replica-failover may acquire another copy of the
SAME statement before pinned input admission; native failures never try again.

The selected source passes native archive, authority, inventory, original payload
commitment and complete graph verification before any replica file is staged.
One original deadline, approval, source descriptor and actual-byte ledger cover
preflight, copy and destination readback. This command creates no new signature.

Publish the exact archive under archive-sha256-<digest>.fgbackup, verify/read back
and synchronize that body, then publish the EXACT originally captured approval
under checkpoint-sha256-<envelope-digest>.approval.json LAST. Exact retries verify
and synchronize existing files without rewriting their inodes. Conflicting,
symlinked or changed files refuse. An identical concurrent publisher may win;
its bytes must still verify. Sources and existing destination files are never
overwritten or deleted. There is no directory scan or mutable latest pointer.

The destination must already exist, be owner-private, and be physically separate
from every source, approval, key, verification root and witness. Stable trusted
parent paths are required; this is not a hostile same-user filesystem sandbox.
The returned candidate pair can enter native verify-selected or recover. This
publishes backup files, not a repository authority head, routing or a Capsule.

--max-read-bytes defaults to six times --max-archive-bytes, with a 68 TiB ceiling.
A healthy fresh publication reads 5N archive bytes: intake 2N, native preflight N,
source copy N and destination readback N. An exact body retry needs 4N. Acquisition
reserves 3N; after native preflight, publication reserves its remaining 1N or 2N
before staging. Failed candidates remain charged. Actual EOF probes remain real
reads and any extra byte is charged. Individual archive/blob/object/metadata and
runtime limits remain independent. Approval and key metadata stay separately bounded.

An optional witness persists authenticated higher/conflicting observations before
eligibility or payload checks and stays leased through native work and publication.
Unresolved native failures retain its lease; settled filesystem errors preserve
known publication state and release a healthy lease after owned work ends.
Cancellation can leave a valid unadvertised body for exact retry. Unknown or
visible publication errors retain their files and report the boundary reached.
A late observer, witness release or stdout failure cannot erase known completion.
Exit 0 means the original approved replica pair is durably published; exit 2 means
refusal or incomplete operation, including receipt failure after completion.";

#[derive(Debug)]
pub(super) struct Options {
    selection: selection::Options,
    directory: PathBuf,
    max_read_bytes: u64,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if !(24..=226).contains(&args.len())
        || args.first().is_none_or(|value| value != "replicate")
        || args
            .iter()
            .any(|value| value.is_empty() || value.len() > 8192 || value.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > 256 * 1024 + 49152
    {
        return Err(USAGE.into());
    }
    let base = std::env::current_dir().map_err(|error| error.to_string())?;
    let directory = selection::normalized(&base, Path::new(&args[1]))?;
    if directory.file_name().is_none() {
        return Err("replica publication requires a named existing private directory".into());
    }
    let mut verification_root = None;
    let mut max_read_bytes = None;
    let mut selected = vec!["verify-selected".to_owned(), String::new()];
    let mut cursor = 2;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if matches!(flag.as_str(), "--trusted-local" | "--replica-failover") {
            selected.push(flag.clone());
            continue;
        }
        if matches!(
            flag.as_str(),
            "--resume" | "--reconstruct-catalog" | "--reconstruction-root"
        ) {
            return Err(format!("unsupported replica publication option: {flag}"));
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--verification-root" if verification_root.is_none() => {
                verification_root = Some(selection::normalized(&base, Path::new(value))?);
            }
            "--max-read-bytes" if max_read_bytes.is_none() => {
                if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(
                        "replica --max-read-bytes requires canonical positive decimal".into(),
                    );
                }
                max_read_bytes = Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value > 0 && *value <= MAX_READ_BYTES)
                        .ok_or("replica --max-read-bytes exceeds the finite 68 TiB profile")?,
                );
            }
            "--verification-root" | "--max-read-bytes" => {
                return Err(format!("duplicate replica publication option: {flag}"));
            }
            "--candidate" => {
                let approval = args
                    .get(cursor)
                    .ok_or("--candidate requires archive and approval paths")?;
                cursor += 1;
                selected.extend([flag.clone(), value.clone(), approval.clone()]);
            }
            _ => selected.extend([flag.clone(), value.clone()]),
        }
    }
    let verification_root =
        verification_root.ok_or("replica publication requires --verification-root")?;
    selected[1] = verification_root
        .to_str()
        .ok_or("replica paths must be UTF-8")?
        .to_owned();
    let selection = selection::parse(&selected)?;
    let paths = std::iter::once(selection.destination.as_path())
        .chain(std::iter::once(selection.trust.trust_key_path()))
        .chain(selection.witness.as_deref())
        .chain(
            selection
                .candidates
                .iter()
                .flat_map(|candidate| [candidate.input.as_path(), candidate.approval.as_path()]),
        );
    if paths
        .into_iter()
        .any(|path| directory.starts_with(path) || path.starts_with(&directory))
    {
        return Err(
            "replica directory must be separate from all inputs, controls and verification scratch"
                .into(),
        );
    }
    let max_read_bytes = max_read_bytes.unwrap_or(6 * selection.profile.transfer.max_archive_bytes);
    Ok(Options {
        selection,
        directory,
        max_read_bytes,
    })
}

#[derive(Clone, Debug)]
pub(super) struct Receipt {
    json: String,
}

impl Receipt {
    pub(super) fn json(&self) -> &str {
        &self.json
    }
}

pub(super) fn execute_in(options: &Options, deadline: Deadline) -> Result<Receipt, String> {
    engine::execute_with_checkpoints(options, deadline, |_| Ok(()))
}

pub(super) fn run(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), String> {
    if args == ["replicate", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.selection.profile = options.selection.profile.with_timeout_cap(timeout)?;
    let receipt = execute_in(&options, options.selection.profile.start())?;
    emit(output, receipt.json()).map_err(|error| format!(
        "replica publication complete=true; publication_state=durable; preserve completed replica; receipt output failed: {error}; completed_result={}", receipt.json()
    ))
}

#[cfg(test)]
use engine::{Checkpoint, execute_with_checkpoints};
#[cfg(all(test, unix))]
mod native_tests;
#[cfg(test)]
mod parse_tests;
