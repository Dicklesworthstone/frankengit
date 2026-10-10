//! Read-only offline native bundle verification. No OneNode or credential exists here.
mod anchors;
mod engine;
pub(super) mod local_files;
mod options;
mod recovery;

pub(super) use engine::read_input;
use engine::{checkpoint, execute, report};
pub(super) use options::{Options, parse};

use std::io::Write;
use std::time::Instant;
#[cfg(test)]
use std::{path::PathBuf, time::Duration};

use fgit_crypto::lowercase_hex;
use fgit_node::TerminationSignals;
#[cfg(test)]
use fgit_node::source_retrieval::integrity::bundle_verify::verify_git_bundle;
use fgit_node::source_retrieval::integrity::bundle_verify::{
    BundleExpectations, BundleVerifyLimits, VerifiedGitBundle,
};
use fgit_types::RefName;

pub(super) const USAGE: &str = "usage: fg bundle verify <bundle-file> [OPTIONS]
  --file-backed          Keep resolved objects in an owned temporary scratch file
  --scratch-dir DIR      Existing private Unix directory; required with --file-backed
  --max-input-mib N       Whole input ceiling, default 128; file-backed max 16384
  --max-expanded-mib N    Expanded payload ceiling, default 128; file-backed max 16384
  --max-objects N         Included object count, 1..100000 (default 100000)
  --max-refs N            Direct refs plus optional HEAD, 1..4096 (default 4096)
  --timeout-secs N        Whole read/verification deadline, 1..3600 (default 300)
  --expect-sha256 HEX     Separately trusted whole-bundle SHA-256 (64 lowercase hex)
  --expect-format FORMAT Explicit sha1|sha256 domain, required for reference pins
  --expect-ref REF=OID    Repeat for known full native branch/tag/reference tips
  --expect-ref-hex HEX=OID Lossless raw-byte-name alternative
  --exact-refs            Require precisely the supplied direct-reference set
  --recovery-head-hex HEX Add a native bare-source layout for this advertised branch
  --                     Treat the remaining argument as a literal file path

Uses the native Rust bundle, pack/DEFLATE/delta, object and graph implementations.
No node store, tenant, principal, retry key, network or Git executable
is used. Every included object's local dependencies must be present and correctly
typed; submodule gitlinks are external and are not fetched. Full v2/v3 SHA-1/SHA-256
bundles only; prerequisites/filters/borrowed bases refuse. The default profile
retains input and resolved payloads in memory with ceilings of 128 MiB.
--file-backed explicitly selects seekable input and private disk-backed resolution.
Only input and total expanded ceilings may increase, to 16384 MiB each. Object,
metadata, graph, delta depth and resolution-work caps remain independently bounded.
Scratch can require up to twice the expanded ceiling; it must fit on local storage.
No complete input or complete resolved-payload set is retained in memory in that
profile. Individual objects and bounded metadata/indexes still use memory.

Success emits one JSON content-verification report. It does not authenticate the
origin, prove branch freshness, verify signatures or restore forge/authority state.
Identity pins must come from a separately trusted record, not an adjacent unsigned
manifest. A format alone is not an identity pin. Ref IDs must be full, not abbreviated;
a matching sha1: or sha256: prefix is accepted. Without --exact-refs, additional refs
are allowed but every included object still undergoes complete graph verification.
Malformed pins refuse before input reads; mismatches refuse before decompression.
Matching pins never skip native verification or imply freshness/signature authority.
The input path must be a quiescent regular local file, not a symlink. File-backed
paths must not contain symlink components or parent traversal. Scratch directory
must already exist, belong to the invoking user, and allow no group/other access.
Only this invocation's fresh scratch file is removed on success/error/cancellation;
a process crash may leave a private residue for the operator to remove. No earlier
scratch file is reused or removed. Cancellation
and deadlines are cooperative and cannot interrupt a blocking operating-system read.
Recovery layout output is opt-in, bounded to 16 MiB, and writes no repository.
It preserves the input pack and derives idx-v2, packed-refs, config and HEAD.
The filesystem owner must stage and synchronize all bodies, then publish HEAD last.
Exit 0: fully verified; 2: invalid/incomplete/unsupported input or interrupted work.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let signals = TerminationSignals::install().map_err(|error| error.to_string())?;
    let started = Instant::now();
    let timeout = fgit_cli::command_timeout_override_duration()
        .map_or(options.timeout, |global| global.min(options.timeout));
    let mut stopped = false;
    let mut live = || {
        if !stopped && (signals.requested() || started.elapsed() >= timeout) {
            stopped = true;
        }
        !stopped
    };
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
