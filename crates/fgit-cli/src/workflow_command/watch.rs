//! Native latest-state polling with one owned signal and finite command lifetime.
use super::Options;
use std::io::Write;
use std::time::{Duration, Instant};

const USAGE: &str = "usage: fg workflow watch <storage-root> <tenant-id> <repository-id> <branch>
  --trusted-local --workflow <repository-directory> --input <top-level-path> [--input ...]
  --run-parent <absolute-private-directory> [--object-format sha1|sha256]
  [--expected-incarnation <id>] [--polls <1..10000>] [--interval-ms <10..60000>]
  [--ref-hex] [--workflow-hex <hex> instead of --workflow] [--input-hex <hex>]
  Artifact capture/input flags have the same meaning as workflow dispatch.

Default: one poll, 1000 ms between repeated polls. The global --timeout-secs
bounds the whole command, including idle waits; no poll renews that budget.
Trust ALL future selected workflow scripts with host-user privileges. This is
Linux trusted-local execution, not a hostile-code sandbox or a remote listener.
Canonical import, receive and merge ref changes qualify. Intermediate tips missed
between polls are coalesced. Unrelated forge updates do not create a new event.
The engine derives immutable event/run IDs; --event, --run-id, --expected-head and
--expected-commit are not accepted. Retain the run parent across restart/restore.
An unresolved event blocks later events; no script is automatically retried.
SIGTERM/SIGINT stop new polls and drain active execution before node shutdown.
Output: one flushed JSON poll per iteration, followed by a node-close summary.
No checks are published by this command. Use workflow recover/publish for saved jobs.
Exit 0: requested polls settled (not proof of green checks); 1: non-green/stopped/
unresolved work; 2: input, infrastructure, cleanup or output failure.";

#[derive(Debug)]
struct WatchOptions {
    execution: Options,
    polls: u32,
    interval: Duration,
}
fn number(text: &str, minimum: u32, maximum: u32) -> Result<u32, String> {
    if text.is_empty()
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err("expected canonical unsigned watch limit".into());
    }
    text.parse::<u32>()
        .ok()
        .filter(|n| (minimum..=maximum).contains(n))
        .ok_or_else(|| "watch limit outside its bounded profile".into())
}
fn options(args: &[String]) -> Result<WatchOptions, String> {
    if args.len() < 5
        || args[0] != "watch"
        || args.len() > 2104
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    let mut ordinary = args[..5].to_vec();
    let (mut polls, mut interval) = (None, None);
    let mut i = 5;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        if matches!(flag.as_str(), "--polls" | "--interval-ms") {
            let value = args.get(i).ok_or("missing watch limit")?;
            i += 1;
            let (slot, value) = if flag == "--polls" {
                (&mut polls, number(value, 1, 10000)?)
            } else {
                (&mut interval, number(value, 10, 60000)?)
            };
            if slot.replace(value).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else {
            ordinary.push(flag.clone());
            if !matches!(flag.as_str(), "--trusted-local" | "--ref-hex") {
                ordinary.push(args.get(i).ok_or("missing workflow option value")?.clone());
                i += 1;
            }
        }
    }
    let execution = super::parse(&ordinary)?;
    if !execution.reference.as_bytes().starts_with(b"refs/heads/") {
        return Err("watch requires a branch ref".into());
    }
    Ok(WatchOptions {
        execution,
        polls: polls.unwrap_or(1),
        interval: Duration::from_millis(u64::from(interval.unwrap_or(1000))),
    })
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["watch", "--help"] {
        writeln!(std::io::stdout().lock(), "{USAGE}").map_err(|e| e.to_string())?;
        return Ok(0);
    }
    let options = options(args)?;
    #[cfg(target_os = "linux")]
    {
        execute(options, &mut std::io::stdout().lock())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = options;
        Err("native workflow watch requires Linux".into())
    }
}

#[derive(Default)]
struct Summary {
    polls: u32,
    dispatched: u32,
    non_green: bool,
    stopped: bool,
    reconcile: bool,
}
#[cfg(target_os = "linux")]
fn execute(options: WatchOptions, output: &mut impl Write) -> Result<u8, String> {
    use fgit_node::{NodeConfig, OneNode, TerminationSignals};
    let config = options
        .execution
        .artifacts
        .as_ref()
        .map(super::artifacts::Options::node_config)
        .transpose()?;
    let opt = &options.execution;
    let signals = TerminationSignals::install().map_err(|e| e.to_string())?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(opt.storage.clone(), opt.tenant, opt.repository)
            .with_object_format(opt.format),
    )
    .map_err(|e| e.to_string())?;
    let mut summary = Summary::default();
    let mut monitor = None;
    let operation = (|| {
        if opt
            .incarnation
            .is_some_and(|id| id != node.repository_incarnation_id())
        {
            return Err("repository incarnation changed; no watcher started".into());
        }
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|e| e.to_string())?;
        let (result, cleanup) =
            super::with_signal_request(&node, signals, |request| -> Result<(), String> {
                for index in 0..options.polls {
                    if !request.checkpoint_is_live() {
                        summary.stopped = true;
                        break;
                    }
                    let poll = node
                        .runtime()
                        .block_on(node.poll_trusted_ref_workflows_in(
                            request,
                            &opt.reference,
                            &opt.workflow,
                            &opt.parent,
                            &opt.inputs,
                            Default::default(),
                            config.as_ref(),
                        ))
                        .map_err(|e| e.to_string())?;
                    summary.polls += 1;
                    summary.dispatched += u32::from(poll.dispatch().is_some());
                    summary.non_green |= poll.dispatch().is_some_and(|d| !d.succeeded());
                    summary.reconcile |= poll.requires_reconciliation();
                    writeln!(
                        output,
                        "{{\"type\":\"workflow_watch_poll\",\"index\":{},\"poll\":{}}}",
                        summary.polls,
                        poll.to_json()
                    )
                    .and_then(|()| output.flush())
                    .map_err(|e| {
                        format!("watch output failed; preserve original event custody: {e}")
                    })?;
                    if !request.checkpoint_is_live() {
                        summary.stopped = true;
                        summary.reconcile |= poll.dispatch().is_some();
                        break;
                    }
                    if summary.reconcile {
                        break;
                    }
                    if index + 1 < options.polls
                        && !wait_interval(options.interval, &|| request.checkpoint_is_live())
                    {
                        summary.stopped = true;
                        break;
                    }
                }
                Ok(())
            })?;
        monitor = cleanup;
        result
    })();
    let cleanup = super::workflow_cleanup(monitor, node.shutdown().err().map(|e| e.to_string()));
    finish(
        output,
        &summary,
        operation.err().as_deref(),
        cleanup.as_deref(),
    )
}
fn wait_interval(interval: Duration, live: &dyn Fn() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < interval {
        if !live() {
            return false;
        }
        std::thread::sleep(
            interval
                .saturating_sub(started.elapsed())
                .min(Duration::from_millis(10)),
        );
    }
    live()
}
fn finish(
    output: &mut impl Write,
    summary: &Summary,
    operation: Option<&str>,
    cleanup: Option<&str>,
) -> Result<u8, String> {
    let optional = |value: Option<&str>| value.map_or_else(|| "null".into(), super::quote);
    writeln!(output,"{{\"type\":\"workflow_watch_result\",\"schema_version\":1,\"polls\":{},\"dispatched\":{},\"non_green\":{},\"request_stopped\":{},\"requires_reconciliation\":{},\"node_closed\":{},\"operation_error\":{},\"cleanup_error\":{}}}",summary.polls,summary.dispatched,summary.non_green,summary.stopped,summary.reconcile,cleanup.is_none(),optional(operation),optional(cleanup)).and_then(|()|output.flush()).map_err(|e|format!("watch summary output incomplete: {e}"))?;
    Ok(if operation.is_some() || cleanup.is_some() {
        2
    } else {
        u8::from(summary.non_green || summary.stopped || summary.reconcile)
    })
}
#[cfg(test)]
mod tests;
