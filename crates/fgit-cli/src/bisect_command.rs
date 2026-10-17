//! Trusted-local read-only forge-state search; no shell predicate execution.
use fgit_node::source_retrieval::bisection::{Query, Report};
use fgit_node::{NodeConfig, OneNode, RepositoryResolutionInput};
use std::io::{self, Write};
mod options;
#[cfg(test)]
mod tests;
const USAGE: &str = "usage: fg [--timeout-secs <seconds>] bisect <storage-root> <tenant-id> <repository-id> --trusted-local
  [--start <positive-decision>] [--end <positive-decision|latest>] [--max-probes <1..4096>]
  (--ref <full-ref> --equals <native-oid> | --ref <full-ref> --absent |
   --policy-at-least <epoch> | --issue <number> --state open|closed |
   --pull <number> --state open|closed|merged)
  [--expected-head <source_head-token>] [--expected-incarnation <id>]

Find the first matching PUBLISHED state in the inclusive range (default: 1..latest).
Endpoints must be publication-batch ends. No imaginary state inside an atomic batch.
Refs, issues and PRs use bounded exhaustive search; no monotonicity is assumed.
Policy-threshold search validates nondecreasing epochs before logarithmic probes.
Loading/authenticating/folding history remains linear, not logarithmic I/O.
This profile admits 4096 batches and 65536 events AFTER the existing bounded history
reader loads them. Missing/pruned history refuses; no offline/capsule fallback.
The same finite command context covers all reads and final head revalidation.
Output is deterministic JSON bound to query, incarnation, observed head and probes.
It is a diagnostic digest, not a signed proof, permission grant or retention pin.
Requires whole-repository local operator access, including hidden refs; no remote
identity is authenticated. No subprocess, checkout, write or code test is run.
Exit 0: match; 1: complete no-match; 2: refused, invalid, incomplete or output error.";

pub fn run(args: &[String]) -> Result<u8, String> {
    run_to(args, &mut io::stdout().lock())
}
fn run_to(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(out, "{USAGE}")
            .and_then(|()| out.flush())
            .map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = options::parse(args)?;
    let mut config = NodeConfig::new(options.storage, options.tenant, options.repository);
    if let Some(incarnation) = options.incarnation {
        config =
            config.with_resolution_input(RepositoryResolutionInput::CapabilityToken(incarnation));
    }
    let node = OneNode::open_existing(config).map_err(|error| error.to_string())?;
    let request = fgit_cli::command_request_context(&node);
    let result = node
        .runtime()
        .block_on(node.bisect_forge_trusted_local_in(&request, &options.query));
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let report = result.map_err(|error| format!("{error}; shutdown error: {cleanup:?}"))?;
    if let Some(error) = cleanup {
        return Err(format!("node shutdown failed: {error}"));
    }
    write_report(&report, out)
}
fn write_report(report: &Report, out: &mut impl Write) -> Result<u8, String> {
    let text = report.to_json();
    if text.len() > 2 * 1024 * 1024 {
        return Err("bisection output exceeds 2 MiB".into());
    }
    writeln!(out, "{text}")
        .and_then(|()| out.flush())
        .map_err(|error| format!("cannot emit complete bisection receipt: {error}"))?;
    Ok(if !report.complete() {
        2
    } else if report.matched() {
        0
    } else {
        1
    })
}
