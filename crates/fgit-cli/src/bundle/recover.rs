//! Offline native source recovery. The verifier owns all Git semantics; this
//! command owns only an explicit new local materialization and its lifetime.
mod filesystem;

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use super::verify;
use fgit_crypto::{lowercase_hex, sha256_digest};
use fgit_node::TerminationSignals;
use fgit_node::source_retrieval::integrity::bundle_verify::prepare_git_bundle_recovery;

pub(super) const USAGE: &str =
    "usage: fg bundle recover <bundle-file> <new-bare-directory> [OPTIONS]
  --trusted-local        Required consent to write this operator-owned directory
  --head-ref REF         Explicit advertised refs/heads/... branch for HEAD
  --head-ref-hex HEX     Lossless lowercase-hex alternative; choose exactly one
  --resume               Resume only an exact identified native recovery directory
  --max-input-mib N       1..128, default 128
  --max-expanded-mib N    1..128, default 128
  --max-objects N         1..100000, default 100000
  --max-refs N            1..4096, default 4096
  --timeout-secs N        Whole read, verification and filesystem deadline, 1..3600
  --expect-sha256 HEX     Independently trusted whole-bundle SHA-256
  --expect-format FORMAT Explicit sha1|sha256 domain, required for reference pins
  --expect-ref REF=OID    Repeat independent full native reference pins
  --expect-ref-hex HEX=OID Lossless raw-byte-name alternative
  --exact-refs            Require exactly the supplied direct-reference set
  --                     Treat the remaining two arguments as literal paths

The full native bundle, pack, deltas, object graph, index and selected branch are
verified before creating a destination. No Git executable, JavaScript engine,
network, FrankenGit node, authority mutation or credential is used. Requires a
quiescent operator-controlled Unix filesystem with file/directory synchronization
and create-only hard links; this is not a hostile local-namespace sandbox.

Fresh recovery requires a nonexistent destination beneath an existing directory.
Destination components must not be . or ..; use its direct relative/absolute path.
An exact retained recovery record binds the original artifact, format and HEAD.
Resume requires the SAME verified input and branch. Existing final files must
match exactly. A private staging file may contain only an exact expected prefix;
its remaining bytes are appended, never overwritten. Unrelated entries, symlinks,
modified bodies, missing published dependencies and unowned hard links refuse.
HEAD is published last after synchronized pack, index, refs and configuration.

Keep the destination after any interruption. Errors distinguish unchanged,
staged, publication_uncertain, published and durable states. After publication
an error never means rollback. --resume revalidates and synchronizes all bodies.
A crash before the recovery record is installed leaves an unidentified directory;
resume refuses it, and a different new destination can be used. Nothing is
recursively removed. Completed recovery retains its identity record for replay.

This restores ordinary bare Git SOURCE, not forge events, authority, credentials,
signatures, gitlink targets or a complete capsule. It does not attest freshness.
Input and expanded payload retain the bounded native verifier's 128 MiB ceilings;
there is no streaming or large-repository claim. Independent identity pins must
come from a trusted record, not the unsigned input or recovery record itself.
Cancellation is cooperative and cannot interrupt a blocking operating-system call.
The global fg --timeout-secs policy can further tighten this command's deadline.
Exit 0: all bodies and publication directories synchronized; 2: error/interruption.";

#[derive(Debug)]
struct Options {
    destination: PathBuf,
    resume: bool,
    verification: verify::Options,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4
        || args.len() > 2 * 4096 + 40
        || args
            .iter()
            .any(|arg| arg.len() > 8300 || arg.contains('\0'))
        || args
            .iter()
            .try_fold(0_usize, |n, arg| n.checked_add(arg.len()))
            .is_none_or(|n| n > 2 * 1024 * 1024)
    {
        return Err(USAGE.into());
    }
    let mut common = Vec::new();
    let mut paths = Vec::new();
    let (mut trusted, mut resume, mut head, mut literal) = (false, false, None, false);
    let mut at = 0;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        if !literal && flag == "--" {
            literal = true;
            continue;
        }
        if literal || !flag.starts_with('-') {
            if flag.is_empty() || paths.len() == 2 {
                return Err("bundle recover requires exactly two nonempty paths".into());
            }
            paths.push(flag.to_owned());
            continue;
        }
        match flag {
            "--trusted-local" => {
                if trusted {
                    return Err("duplicate --trusted-local".into());
                }
                trusted = true;
            }
            "--resume" => {
                if resume {
                    return Err("duplicate --resume".into());
                }
                resume = true;
            }
            "--head-ref" | "--head-ref-hex" => {
                if head.is_some() {
                    return Err("choose exactly one --head-ref or --head-ref-hex".into());
                }
                let value = args.get(at).ok_or("missing recovery head")?;
                at += 1;
                head = Some(if flag == "--head-ref" {
                    lowercase_hex(value.as_bytes())
                } else {
                    value.clone()
                });
            }
            "--exact-refs" => common.push(flag.to_owned()),
            "--max-input-mib" | "--max-expanded-mib" | "--max-objects" | "--max-refs"
            | "--timeout-secs" | "--expect-sha256" | "--expect-format" | "--expect-ref"
            | "--expect-ref-hex" => {
                let value = args.get(at).ok_or("missing bundle recovery option value")?;
                at += 1;
                common.push(flag.to_owned());
                common.push(value.clone());
            }
            _ => return Err(format!("unknown bundle recovery option {flag}")),
        }
    }
    if !trusted {
        return Err("--trusted-local is required for local source materialization".into());
    }
    if paths.len() != 2 {
        return Err("bundle recover requires an input and a destination".into());
    }
    let destination = PathBuf::from(paths.pop().ok_or("missing recovery destination")?);
    if destination.file_name().is_none() {
        return Err("recovery destination must name a directory".into());
    }
    common.push("--recovery-head-hex".into());
    common.push(head.ok_or("an explicit advertised recovery branch is required")?);
    common.push("--".into());
    common.push(paths.pop().ok_or("missing recovery input")?);
    let verification = verify::parse(&common)?;
    Ok(Options {
        destination,
        resume,
        verification,
    })
}

fn execute(options: &Options, live: &mut impl FnMut() -> bool) -> Result<String, String> {
    let verify = &options.verification;
    // Verification deliberately precedes destination inspection. A resume may
    // already have a visible HEAD, even if this attempt never reaches the writer.
    let uninspected_state = if options.resume {
        filesystem::State::PublicationUncertain
    } else {
        filesystem::State::Unchanged
    };
    let input_refusal = |phase: &str, error: String| {
        format!(
            "native_bundle_recovery_refused: state={} no_destination_write_this_attempt=true {phase}={error}",
            uninspected_state.as_str()
        )
    };
    let bytes = verify::read_input(&verify.path, verify.limits.envelope.max_bundle_bytes, live)
        .map_err(|error| input_refusal("input", error))?;
    let head = verify
        .recovery_head
        .as_ref()
        .ok_or_else(|| input_refusal("verification", "missing native recovery head".into()))?;
    let plan = prepare_git_bundle_recovery(
        &bytes,
        &verify.limits,
        verify.expectations.as_ref(),
        head,
        live,
    )
    .map_err(|error| input_refusal("verification", error.to_string()))?;
    let verified = plan.verified();
    let digest = lowercase_hex(verified.sha256());
    let head_hex = lowercase_hex(plan.head_ref().as_bytes());
    let pack_stem = format!(
        "pack-{}",
        lowercase_hex(verified.pack_checksum().as_bytes())
    );
    // The record is an exact local ownership/retry binding, never a signature,
    // trust anchor, source of object bytes, or alternate Git verification path.
    let record = format!(
        "frankengit-native-bare-recovery-v1\nartifact-sha256 {digest}\nobject-format {}\nhead-ref-hex {head_hex}\npack-checksum {}\n",
        verified.format().as_str(),
        lowercase_hex(verified.pack_checksum().as_bytes())
    );
    let layout = filesystem::Layout {
        record: record.as_bytes(),
        pack_stem: &pack_stem,
        pack: plan.pack(),
        index: plan.index(),
        packed_refs: plan.packed_refs(),
        config: plan.config(),
        head: plan.head(),
    };
    // Finish fallible report construction before any destination mutation.
    let mut output = format!(
        "{{\"type\":\"git_bundle_recovery\",\"schema_version\":1,\"profile\":\"native-bare-source-recovery-v1\",\"state\":\"durable\",\"object_format\":\"{}\",\"artifact_sha256\":\"{digest}\",\"bundle_bytes\":{},\"pack_checksum\":\"{}\",\"object_count\":{},\"reference_count\":{},\"head_ref_hex\":\"{head_hex}\",\"recovery_record_sha256\":\"{}\",\"resumed\":{},\"caller_expectations_matched\":{},\"object_graph_verified\":true,\"head_published\":true,\"files_synchronized\":true,\"publication_directories_synchronized\":true,\"authority_changed\":false,\"forge_state_restored\":false,\"signatures_verified\":false,\"origin_authenticated\":false,\"current_branch_verified\":false,\"gitlink_targets_verified\":false,\"references\":[",
        verified.format().as_str(),
        verified.bytes(),
        lowercase_hex(verified.pack_checksum().as_bytes()),
        verified.graph().objects,
        verified.graph().references,
        lowercase_hex(&sha256_digest(record.as_bytes())),
        options.resume,
        verify.expectations.is_some()
    );
    for (at, (name, id)) in verified.references().iter().enumerate() {
        if at > 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"ref_hex\":\"{}\",\"object_id\":\"{}\"}}",
            lowercase_hex(name.as_bytes()),
            lowercase_hex(id.as_bytes())
        )
        .map_err(|error| error.to_string())?;
    }
    output.push_str("],\"already_published\":");
    output
        .try_reserve(6)
        .map_err(|_| "recovery report allocation refused")?;
    let completed = filesystem::materialize(&options.destination, &layout, options.resume, live)
        .map_err(|error| error.to_string())?;
    output.push_str(if completed.already_published {
        "true}"
    } else {
        "false}"
    });
    Ok(output)
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let started = Instant::now();
    let timeout = fgit_cli::command_timeout_override_duration()
        .map_or(options.verification.timeout, |global| {
            global.min(options.verification.timeout)
        });
    let mut stopped = false;
    let mut live = || {
        if !stopped && (signals.requested() || started.elapsed() >= timeout) {
            stopped = true;
        }
        !stopped
    };
    let output = execute(&options, &mut live)?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{output}").and_then(|()| stdout.flush())
        .map_err(|error| format!("native_bundle_recovery_output_error: state=durable; source is published and synchronized; use explicit --resume to recover the report; {error}"))?;
    Ok(0)
}

#[cfg(test)]
mod tests;
