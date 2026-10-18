//! Explicit local immutable payload custody; object-fabric owns storage semantics.
#[cfg(target_os = "linux")]
mod execute;
mod options;
mod output;
mod retention;
#[cfg(test)]
mod tests;
use std::io::Write;

const USAGE: &str = "usage: fg [--timeout-secs <seconds>] artifact <put|inspect|export>
  <private-artifact-root> <tenant-id> <repository-id> <incarnation-id>
  --trusted-local --trust-domain <label> [--max-payload-mib <1..512>]
put: --source <absolute-regular-file> --payload-sha256 <sha256> --payload-bytes <decimal>
  --kind <ci_artifact|build_log|release_asset|sbom|signature|provenance|git_lfs>
  --media-type <type> [--expected-id <artifact-sha256>]
  [--ttl-secs <positive-u64> | --retain-days <positive-u32> | --release-permanent
   | --legal-hold-id <positive-u64> --legal-hold-reason <1..1024-UTF8-bytes>]
  [--source-rcr <sha256>] [--build-capsule <sha256>] [--check-receipt <sha256>]
inspect: --id <artifact-sha256>
export: --id <artifact-sha256> --output <absolute-new-file>

Digests are exactly 64 lowercase hexadecimal digits. Linux trusted-local only.
Put verifies supplied length/digest and retained bytes before immutable install.
Inspect and export verify the entire stored payload, not just a metadata record.
Existing export destinations are never replaced. A lost reply does not prove absence.
The root and export parent must exist with mode 0700; their ancestors and source
must remain protected from concurrent replacement. This is not hostile isolation.
Scope/provenance fields are operator assertions, not authorization or a check grant.
Retention defaults to 86400-second TTL: metadata only, not deletion/hold enforcement.
No refs change.
One cooperative deadline covers storage phases; filesystem calls/output may block.
Default 64 MiB; maximum 512 MiB and one hour. Argument refusals create no namespace.
Exit 0: completed; 2: refused; 3: local publication uncertain; 4: completed but output
failed. Inspect/retry the original identity; never rerun a producing job to recover.";

pub(super) fn run(args: &[String]) -> u8 {
    let out = &mut std::io::stdout().lock();
    let err = &mut std::io::stderr().lock();
    if args == ["--help"] {
        return if writeln!(out, "{USAGE}").and_then(|()| out.flush()).is_ok() {
            0
        } else {
            4
        };
    }
    let options = match options::parse(args) {
        Ok(value) => value,
        Err(error) => return output::error(err, "invalid_input", &error, 2),
    };
    #[cfg(target_os = "linux")]
    {
        let signals = match fgit_node::TerminationSignals::install() {
            Ok(value) => value,
            Err(error) => return output::error(err, "signal_setup", &error.to_string(), 2),
        };
        execute::run(
            &options,
            fgit_cli::command_timeout_duration(),
            &|| !signals.requested(),
            out,
            err,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        output::error(
            err,
            "unsupported_platform",
            "artifact custody requires Linux; no fallback selected",
            2,
        )
    }
}
