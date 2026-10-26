//! Native latest-state polling with one owned signal and finite command lifetime.
use super::Options;
use std::io::Write;
use std::time::{Duration, Instant};

const USAGE: &str = "usage: fg workflow watch <storage-root> <tenant-id> <repository-id> <branch>
  --trusted-local --workflow <repository-directory> --input <top-level-path> [--input ...]
  --run-parent <absolute-private-directory> [--object-format sha1|sha256]
  [--pull-request <positive-native-pr-number>]
  [--expected-incarnation <id>] [--polls <1..10000>] [--interval-ms <10..60000>]
  [--ref-hex] [--workflow-hex <hex> instead of --workflow] [--input-hex <hex>]
  [--artifact-root <absolute-private-directory>] [--artifact-logs]
  Artifact capture/input flags have the same meaning as workflow dispatch.
  --artifact-logs retains bounded raw step stdout/stderr, including failed-step
  diagnostics, for each executed event; --artifact-root is required, files optional.

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
No checks are published by default. Opt in with --publish-checks --principal-id
  <publisher> --expected-incarnation <id> to report settled events through ordinary
  canonical check admission. Pending publication reconciles before later polling;
  source scripts never rerun. The first reporting identity is permanent per scope.
  Missing legacy handoffs, corrupt custody and incomplete admission stop the watch.
  A committed failure/skipped observation is not a passing build. Preserve all
  event custody across restart/restore. No force reset or replacement keys exist.
Optional --pull-request selects on: pull_request definitions only when the named
native same-repository PR is open and its source branch matches the explicit branch.
It executes the current SOURCE HEAD, not a synthetic merge or the recorded old tip.
PR metadata versions (including reopen), source decisions and observed target tips
select distinct events; unrelated comments/checks do not. Closed/merged/missing
PRs execute nothing. Old reporting can recover after closure without rerunning code.
Push and PR custody namespaces are separate. This is a latest-state trusted-host
profile, not GitHub event/filter compatibility, fork isolation or an all-events queue.

Exit 0: requested polls settled (not proof of green checks); 1: non-green/stopped/
unresolved work; 2: input, infrastructure, cleanup or output failure.";

#[derive(Debug)]
struct WatchOptions {
    execution: Options,
    polls: u32,
    interval: Duration,
    publisher: Option<fgit_types::PrincipalId>,
    pull_request: Option<u64>,
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
        || args.len() > 2109
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    let mut ordinary = args[..5].to_vec();
    let (mut polls, mut interval) = (None, None);
    let mut publish = false;
    let mut publisher = None;
    let mut pull_request = None;
    let mut i = 5;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        if flag == "--pull-request" {
            let value = args.get(i).ok_or("missing --pull-request number")?;
            i += 1;
            let number = super::publish::decimal(value, 1, u64::MAX)?;
            if pull_request.replace(number).is_some() {
                return Err("duplicate --pull-request".into());
            }
        } else if flag == "--publish-checks" {
            if publish {
                return Err("duplicate --publish-checks".into());
            }
            publish = true;
        } else if flag == "--principal-id" {
            let value = args.get(i).ok_or("missing --principal-id")?;
            i += 1;
            super::publish::fixed_hex(value, 16)?;
            let id =
                fgit_types::PrincipalId::from_hex(value).map_err(|_| "invalid check publisher")?;
            if publisher.replace(id).is_some() {
                return Err("duplicate --principal-id".into());
            }
        } else if matches!(flag.as_str(), "--polls" | "--interval-ms") {
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
            if !matches!(
                flag.as_str(),
                "--trusted-local" | "--ref-hex" | "--artifact-logs"
            ) {
                ordinary.push(args.get(i).ok_or("missing workflow option value")?.clone());
                i += 1;
            }
        }
    }
    let execution = super::parse(&ordinary)?;
    if !execution.reference.as_bytes().starts_with(b"refs/heads/") {
        return Err("watch requires a branch ref".into());
    }
    if publish != publisher.is_some() {
        return Err("--publish-checks and --principal-id must be supplied together".into());
    }
    if publish && execution.incarnation.is_none() {
        return Err("automatic check publication requires --expected-incarnation".into());
    }
    Ok(WatchOptions {
        publisher,
        pull_request,
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
    publication_enabled: bool,
    checks_committed: usize,
    checks_refused: usize,
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
    let mut summary = Summary {
        publication_enabled: options.publisher.is_some(),
        ..Summary::default()
    };
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
                    if let Some(publisher) = options.publisher {
                        publish_pending(
                            &node,
                            request,
                            opt,
                            publisher,
                            options.pull_request,
                            &mut summary,
                            output,
                        )?;
                    }
                    let poll = node
                        .runtime()
                        .block_on(async {
                            match options.pull_request {
                                Some(number) => {
                                    node.poll_trusted_pull_request_workflows_in(
                                        request,
                                        &opt.reference,
                                        number,
                                        &opt.workflow,
                                        &opt.parent,
                                        &opt.inputs,
                                        Default::default(),
                                        config.as_ref(),
                                    )
                                    .await
                                }
                                None => {
                                    node.poll_trusted_ref_workflows_in(
                                        request,
                                        &opt.reference,
                                        &opt.workflow,
                                        &opt.parent,
                                        &opt.inputs,
                                        Default::default(),
                                        config.as_ref(),
                                    )
                                    .await
                                }
                            }
                        })
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
                    if let Some(publisher) = options.publisher {
                        publish_pending(
                            &node,
                            request,
                            opt,
                            publisher,
                            options.pull_request,
                            &mut summary,
                            output,
                        )?;
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
#[cfg(target_os = "linux")]
fn publish_pending(
    node: &fgit_node::OneNode,
    request: &fgit_node::NodeRequestContext,
    options: &Options,
    publisher: fgit_types::PrincipalId,
    pull_number: Option<u64>,
    summary: &mut Summary,
    output: &mut impl Write,
) -> Result<(), String> {
    let observe = |text: &str| {
        writeln!(output, "{text}")
            .and_then(|()| output.flush())
            .map_err(|e| e.to_string())
    };
    let result = node.runtime().block_on(async {
        match pull_number {
            Some(number) => {
                node.publish_trusted_pull_request_workflow_checks_in(
                    request,
                    &options.reference,
                    number,
                    &options.workflow,
                    &options.parent,
                    publisher,
                    observe,
                )
                .await
            }
            None => {
                node.publish_trusted_ref_workflow_checks_in(
                    request,
                    &options.reference,
                    &options.workflow,
                    &options.parent,
                    publisher,
                    observe,
                )
                .await
            }
        }
    });
    summary.checks_committed += result.committed;
    summary.checks_refused += result.refused;
    summary.non_green |= result.refused != 0;
    summary.reconcile |= result.error.is_some();
    writeln!(output, "{}", result.to_json())
        .and_then(|()| output.flush())
        .map_err(|e| format!("watch publication receipt failed; preserve original custody: {e}"))?;
    if let Some(error) = result.error {
        return Err(error);
    }
    Ok(())
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
    writeln!(output,"{{\"type\":\"workflow_watch_result\",\"schema_version\":1,\"polls\":{},\"dispatched\":{},\"non_green\":{},\"request_stopped\":{},\"requires_reconciliation\":{},\"publication_enabled\":{},\"committed_check_decisions\":{},\"refused_check_decisions\":{},\"node_closed\":{},\"operation_error\":{},\"cleanup_error\":{}}}",summary.polls,summary.dispatched,summary.non_green,summary.stopped,summary.reconcile,summary.publication_enabled,summary.checks_committed,summary.checks_refused,cleanup.is_none(),optional(operation),optional(cleanup)).and_then(|()|output.flush()).map_err(|e|format!("watch summary output incomplete: {e}"))?;
    Ok(if operation.is_some() || cleanup.is_some() {
        2
    } else {
        u8::from(summary.non_green || summary.stopped || summary.reconcile)
    })
}
#[cfg(test)]
mod tests;
