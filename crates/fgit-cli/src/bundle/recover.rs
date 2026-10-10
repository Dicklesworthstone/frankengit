//! Offline native source recovery. The verifier owns all Git semantics; this
//! command owns only an explicit new local materialization and its lifetime.
mod engine;
mod filesystem;
mod options;
mod pack_source;

use engine::execute;
use options::{Options, parse};

use std::io::Write as _;
#[cfg(test)]
use std::path::PathBuf;
use std::time::Instant;

use super::verify;
use fgit_node::TerminationSignals;

pub(super) const USAGE: &str =
    "usage: fg bundle recover <bundle-file> <new-bare-directory> [OPTIONS]
  --trusted-local        Required consent to write this operator-owned directory
  --head-ref REF         Explicit advertised refs/heads/... branch for HEAD
  --head-ref-hex HEX     Lossless lowercase-hex alternative; choose exactly one
  --resume               Resume only an exact identified native recovery directory
  --file-backed          Verify with bounded memory and replay the original pack
  --scratch-dir DIR      Existing private directory outside the destination;
                         required exactly with --file-backed
  --max-input-mib N       1..128, or 1..16384 with --file-backed; default 128
  --max-expanded-mib N    1..128, or 1..16384 with --file-backed; default 128
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
The in-memory profile retains its 128 MiB ceilings. Explicit file-backed mode
allows input and expanded limits up to 16 GiB without holding complete pack or
expanded payloads in memory. Per-object, count, metadata and work limits remain.
Scratch may use twice the expanded limit; it is removed before destination writes.
Read-only path separation precedes verification. Source paths and scratch parents
must not contain symlinks. Every pack replay checks length, SHA-256 and the opened
input's identity before publication. Independent identity pins must come from a
trusted record, not the unsigned input or recovery record itself.
Cancellation is cooperative and cannot interrupt a blocking operating-system call.
The global fg --timeout-secs policy can further tighten this command's deadline.
Exit 0: all bodies and publication directories synchronized; 2: error/interruption.";

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
