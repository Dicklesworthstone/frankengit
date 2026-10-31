//! Select a signed checkpoint before opening payloads, then enter the existing
//! native recovery engine with the exact captured approval and one deadline.
//! An unusable higher checkpoint never licenses recovery of an older one.

mod engine;

use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use fgit_authority::StoreInstanceId;

use super::super::emit;
use super::approval::{SelectionTrustFlags, SelectionTrustOptions};
use super::profile::{Deadline, Profile, ProfileFlags};

const MAX_CANDIDATES: usize = 64;
const MAX_CANDIDATE_PATH_BYTES: usize = 256 * 1024;

pub(super) const USAGE: &str = "usage: fg backup verify-selected <new-scratch-root>
         --verification-instance <positive-integer>
       fg backup recover <new-destination-root>
         --destination-instance <positive-integer> [--resume]
         --candidate <archive> <approval> [--candidate <archive> <approval> ...]
         --trusted-local --expected-sha256 <64-lowercase-hex>
         --trust-key <independently-trusted-public-PEM>
         --tenant-id <hex> --repository-id <hex> --incarnation-id <hex>
         --object-format sha1|sha256 --minimum-head-generation <positive-u64>
         [--max-archive-bytes <1..1099511627776>] [--max-blob-bytes <1..1099511627776>]
         [--max-objects <1..1000000>] [--timeout-secs <1..86400>]

Authenticate ALL 1..64 explicitly supplied approvals against one captured public
key and namespace before opening any archive or reserving native scratch/state.
Select the highest full-width signed generation. Distinct canonical statements
at that generation are ambiguous and refuse. Equal statements are aliases; the
first absolute lexical (archive, approval) pair wins deterministically. There is
no automatic alias failover. Exact duplicate candidate pairs refuse.

Only after selection are the winner's expiry, future issue time, independent
generation floor, archive-byte limit and independently supplied digest applied.
A missing, corrupt, expired, over-budget or natively invalid highest checkpoint
NEVER causes selection of an older checkpoint. Lower archive files are not opened.
The same opened winner and captured approval enter native checksum, decoding,
original-commitment, authority and complete-graph verification. One original
deadline and unchanged independent resource limits cover selection and native work.

verify-selected closes and removes successful private verification scratch.
recover uses the existing authority-last restore; --resume requires the original
archive digest, signed approval/key/policy, destination and instance. Selection
is repeated before resume and may refuse a newly observed higher checkpoint.
Control-file replacement cannot switch the captured approval or trusted key.
Existing restore publication, retained diagnostics and uncertain-outcome rules
remain in force. An output failure after native completion preserves that result.

Trusted stable parent paths and whole-repository local authority are required.
Destination/scratch must be disjoint from every archive, approval and key path.
This selects the highest SUPPLIED checkpoint, not the newest global checkpoint;
there is no persistent high-water witness in this operation. This is source
recovery, not a complete signed Capsule, external-artifact restore, routing
publication or permission to replay external effects.
Exit 0: selected checkpoint and native operation completed; 2: refusal or an
incomplete operation, including failed receipt delivery after native completion.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Verify,
    Recover,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Candidate {
    input: PathBuf,
    approval: PathBuf,
}

#[derive(Debug)]
pub(super) struct Options {
    operation: Operation,
    destination: PathBuf,
    candidates: Vec<Candidate>,
    expected: [u8; 32],
    instance: StoreInstanceId,
    trust: SelectionTrustOptions,
    profile: Profile,
    resume: bool,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if !(22..=220).contains(&args.len())
        || args
            .iter()
            .any(|value| value.is_empty() || value.len() > 8192 || value.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > MAX_CANDIDATE_PATH_BYTES + 32768
    {
        return Err(USAGE.into());
    }
    let operation = match args[0].as_str() {
        "verify-selected" => Operation::Verify,
        "recover" => Operation::Recover,
        _ => return Err(USAGE.into()),
    };
    let base = std::env::current_dir().map_err(|error| error.to_string())?;
    let destination = normalized(&base, Path::new(&args[1]))?;
    if destination.file_name().is_none() {
        return Err("selected recovery requires a named destination or scratch root".into());
    }
    let (mut trusted, mut expected, mut instance, mut resume) = (false, None, None, false);
    let mut profile = ProfileFlags::default();
    let mut trust = SelectionTrustFlags::default();
    let mut candidates = Vec::new();
    let mut path_bytes = 0_usize;
    let mut cursor = 2;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted {
            trusted = true;
            continue;
        }
        if flag == "--resume" && operation == Operation::Recover && !resume {
            resume = true;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--candidate" => {
                if candidates.len() == MAX_CANDIDATES {
                    return Err("selected recovery permits at most 64 explicit candidates".into());
                }
                let approval = args
                    .get(cursor)
                    .ok_or("--candidate requires archive and approval paths")?;
                cursor += 1;
                let input = normalized(&base, Path::new(value))?;
                let approval = normalized(&base, Path::new(approval))?;
                path_bytes = path_bytes
                    .checked_add(input.as_os_str().len())
                    .and_then(|sum| sum.checked_add(approval.as_os_str().len()))
                    .filter(|sum| *sum <= MAX_CANDIDATE_PATH_BYTES)
                    .ok_or("selected recovery candidate path-byte limit exceeded")?;
                candidates.push(Candidate { input, approval });
            }
            "--expected-sha256" if expected.is_none() => {
                expected = Some(super::restore::digest(value)?);
            }
            "--verification-instance" if operation == Operation::Verify && instance.is_none() => {
                instance = Some(parse_instance(value)?);
            }
            "--destination-instance" if operation == Operation::Recover && instance.is_none() => {
                instance = Some(parse_instance(value)?);
            }
            "--trust-key" => {
                let path = normalized(&base, Path::new(value))?;
                trust.set(
                    flag,
                    path.to_str()
                        .ok_or("selected recovery paths must be UTF-8")?,
                )?;
            }
            "--max-archive-bytes" | "--max-blob-bytes" | "--max-objects" | "--timeout-secs" => {
                profile.set(flag, value)?;
            }
            _ if SelectionTrustFlags::accepts(flag) => trust.set(flag, value)?,
            _ => {
                return Err(format!(
                    "unknown or duplicate selected recovery option: {flag}"
                ));
            }
        }
    }
    if !trusted {
        return Err(
            "selected recovery requires --trusted-local and whole-repository authority".into(),
        );
    }
    if candidates.is_empty() {
        return Err("selected recovery requires 1..64 explicit --candidate pairs".into());
    }
    candidates.sort();
    if candidates.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("selected recovery requires distinct normalized candidate pairs".into());
    }
    let trust = trust.finish()?;
    for path in candidates
        .iter()
        .flat_map(|candidate| [&candidate.input, &candidate.approval])
        .map(PathBuf::as_path)
        .chain(std::iter::once(trust.trust_key_path()))
    {
        if destination.starts_with(path) || path.starts_with(&destination) {
            return Err(
                "selected recovery destination must be disjoint from every input and control path"
                    .into(),
            );
        }
    }
    Ok(Options {
        operation,
        destination,
        candidates,
        expected: expected
            .ok_or("selected recovery requires independently trusted --expected-sha256")?,
        instance: instance.ok_or(match operation {
            Operation::Verify => "verify-selected requires --verification-instance",
            Operation::Recover => "recover requires --destination-instance",
        })?,
        trust,
        profile: profile.finish(),
        resume,
    })
}

fn parse_instance(text: &str) -> Result<StoreInstanceId, String> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("selected recovery instance must be canonical positive decimal".into());
    }
    let value = text
        .parse::<u64>()
        .ok()
        .filter(|value| i64::try_from(*value).is_ok())
        .ok_or("selected recovery instance must fit a positive SQL integer")?;
    Ok(StoreInstanceId::from_raw(value))
}

/// Normalize explicit names without following a source or control symlink.
fn normalized(base: &Path, path: &Path) -> Result<PathBuf, String> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            part => normalized.push(part.as_os_str()),
        }
    }
    if normalized.to_str().is_none_or(|text| text.len() > 8192) {
        return Err("selected recovery requires bounded UTF-8 paths".into());
    }
    Ok(normalized)
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
    engine::execute_with_checkpoints(options, deadline, |_| Ok(()))
}

pub(super) fn run(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), String> {
    if args == ["verify-selected", "--help"] || args == ["recover", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.profile = options.profile.with_timeout_cap(timeout)?;
    let receipt = execute_in(&options, options.profile.start())?;
    emit(output, receipt.json()).map_err(|error| format!(
        "selected recovery native_operation_complete=true; preserve completed result and destination; receipt output failed: {error}"
    ))
}

#[cfg(all(test, unix))]
mod native_tests;
#[cfg(test)]
mod parse_tests;
