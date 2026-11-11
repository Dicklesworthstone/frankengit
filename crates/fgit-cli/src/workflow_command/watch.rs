//! Native latest-state polling with finite attempts and explicit service lifetime.
#[cfg(target_os = "linux")]
mod continuous;

use super::Options;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const USAGE: &str =
    "usage: fg workflow watch <storage-root> <tenant-id> <repository-id> <branch-or-tag>
  --trusted-local --workflow <repository-directory> --input <repository-path> [--input ...]
  --run-parent <absolute-private-directory> [--object-format sha1|sha256]
  [--pull-request <positive-native-pr-number> | --merge-queue <positive-queue-number>]
  [--merge-candidate-ref <separate-ci-branch> --merge-principal <id>
   --merge-author <name-and-email> --merge-committer <name-and-email>
   --merge-timestamp <positive-unix-seconds> --merge-message <text>
   [--merge-profile path|exact-renames] [--merge-method merge-commit|squash]]
  [--expected-incarnation <id>] [--polls <1..10000>] [--interval-ms <10..60000>]
  [--land-queue-head --landing-principal <id>]
  [--refresh-queue-head --refresh-principal <id>]
  [--continuous --stop-file <initially-absent-path> [--attempt-timeout-secs <1..3600>]]
  [--ref-hex] [--workflow-hex <hex> instead of --workflow] [--input-hex <hex>]
  [--artifact-root <absolute-private-directory>] [--artifact-logs]
  Artifact capture/input flags have the same meaning as workflow dispatch.
  --artifact-logs retains bounded raw step stdout/stderr, including failed-step
  diagnostics, for each executed event; --artifact-root is required, files optional.

Default: one poll, 1000 ms between repeated polls. The global --timeout-secs
bounds the whole command, including idle waits; no poll renews that budget.
Continuous mode replaces --polls with an explicitly owned service lifetime.
Each attempt (pending publication, one poll, and resulting publication) has a
fresh finite deadline: 300 seconds by default, or --attempt-timeout-secs.
An explicit global --timeout-secs still bounds the WHOLE service, including idle
waits, and caps each attempt's remaining time. No live attempt renews its budget.
Create the initially absent regular stop file, or send SIGTERM/SIGINT, to drain.
The stop file is never removed. A failed stop-file observation also stops work.
Continuous readiness is emitted before polling; an idle operator stop exits 0.
Custody remains bounded to 1024 distinct events per scope; retain it on restart.
Trust ALL future selected workflow scripts with host-user privileges. This is
Linux trusted-local execution, not a hostile-code sandbox or a remote listener.
Canonical import, receive and merge ref changes qualify. Intermediate tips missed
between polls are coalesced. Unrelated forge updates do not create a new event.
Ordinary push watches accept explicit refs/heads/* or refs/tags/* references.
Commit tags execute their peeled commit; a tag does not select a PR, merge queue
or merge candidate and cannot publish canonical checks in this profile.
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
By default it executes the current SOURCE HEAD, not the recorded old tip.
The explicit merge-candidate option group instead prepares the actual combined tree,
publishes it on the selected CI branch through ordinary exact-old admission, and
executes that exact candidate. It requires --pull-request or --merge-queue, plus
--expected-incarnation.
The CI branch must differ from both PR branches; this operator configuration permits
its create/rewrite, without modifying either PR branch. Use --merge-candidate-ref-hex
instead of --merge-candidate-ref for exact raw branch bytes. All commit metadata is
explicit and stable; no ambient identity or time is used. Conflicts execute nothing.
Optional --publish-checks binds results to the CI branch and candidate, so existing
exact-candidate protection can require that fixed CI branch. Source-head PR check
views remain source-head views. The exact bundle is retained for review/publication.
Retain the same merge configuration across restart; changed configuration refuses.
With --merge-queue, the positional branch is the fixed queue TARGET. The current
canonical head selects its PR and source branch. Queue mode requires the complete
merge-candidate group and merge-commit style; --pull-request and squash are refused.
It prepares and runs only the exact current head, retaining queue version, tips,
PR version and policy epoch. Queue changes select new events; unresolved custody
blocks the entire queue scope, even if its head changes or disappears. Original
settled checks can still publish after removal without rerunning scripts. The watch
retains landing.bundle for guarded queue landing of the exact tested commit.
Target landing is disabled by default. --land-queue-head --landing-principal <id>
explicitly authorizes automatic landing through ordinary queue admission, and
requires --merge-queue, --publish-checks and --expected-incarnation. This principal
is configured independently from the CI branch writer and check publisher. Only
verified successful executions qualify; current checks, reviews, queue membership,
tips and policy still govern publication. Missing approval waits without sealing
a refusal. Pending original landing outcomes reconcile before another candidate;
an unknown outcome stops the watch. Retain the same landing identity on restart.
Target refresh is also disabled by default. --refresh-queue-head --refresh-principal
<id> additionally authorizes a target-only PR update before preparing a stale queue
head. It requires automatic queue landing and its complete configuration. This
separate principal does not inherit authority from any execution or publication role.
The complete original metadata, guards, key and transaction are retained before
submission. Recovery precedes later work; only the recorded target can change.
Queue order, priority and source content stay unchanged, while the new PR version
requires a freshly prepared candidate and current review/check evidence. No script
is retried. Keep the same refresh identity and all custody across restart.
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
    landing_principal: Option<fgit_types::PrincipalId>,
    queue_refresh_principal: Option<fgit_types::PrincipalId>,
    pull_request: Option<u64>,
    merge_queue: Option<u64>,
    merge_candidate: Option<crate::workflow_merge_watch::Options>,
    stop_file: Option<PathBuf>,
    attempt_timeout: Duration,
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
        || args.len() > 2114
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err(USAGE.into());
    }
    let mut ordinary = args[..5].to_vec();
    let (mut polls, mut interval) = (None, None);
    let mut publish = false;
    let mut publisher = None;
    let mut land = false;
    let mut landing_principal = None;
    let mut refresh = false;
    let mut queue_refresh_principal = None;
    let mut pull_request = None;
    let mut merge_queue = None;
    let mut merge_fields = std::collections::BTreeMap::new();
    let mut continuous = false;
    let mut stop_file = None;
    let mut attempt_timeout = None;
    let mut i = 5;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        if crate::workflow_merge_watch::is_option(flag) {
            let value = args.get(i).ok_or_else(|| format!("missing {flag} value"))?;
            i += 1;
            if merge_fields.insert(flag.as_str(), value.as_str()).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else if flag == "--continuous" {
            if continuous {
                return Err("duplicate --continuous".into());
            }
            continuous = true;
        } else if flag == "--stop-file" {
            let value = args.get(i).ok_or("missing --stop-file path")?;
            i += 1;
            if value.is_empty() || value.len() > 4096 {
                return Err("invalid --stop-file path".into());
            }
            if stop_file.replace(PathBuf::from(value)).is_some() {
                return Err("duplicate --stop-file".into());
            }
        } else if flag == "--attempt-timeout-secs" {
            let value = args.get(i).ok_or("missing --attempt-timeout-secs")?;
            i += 1;
            if attempt_timeout.replace(number(value, 1, 3600)?).is_some() {
                return Err("duplicate --attempt-timeout-secs".into());
            }
        } else if matches!(flag.as_str(), "--pull-request" | "--merge-queue") {
            let value = args
                .get(i)
                .ok_or_else(|| format!("missing {flag} number"))?;
            i += 1;
            let number = super::publish::decimal(value, 1, u64::MAX)?;
            let slot = if flag == "--pull-request" {
                &mut pull_request
            } else {
                &mut merge_queue
            };
            if slot.replace(number).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else if flag == "--publish-checks" {
            if publish {
                return Err("duplicate --publish-checks".into());
            }
            publish = true;
        } else if flag == "--land-queue-head" {
            if land {
                return Err("duplicate --land-queue-head".into());
            }
            land = true;
        } else if flag == "--landing-principal" {
            let value = args.get(i).ok_or("missing --landing-principal")?;
            i += 1;
            super::publish::fixed_hex(value, 16)?;
            let id = fgit_types::PrincipalId::from_hex(value)
                .map_err(|_| "invalid queue landing principal")?;
            if landing_principal.replace(id).is_some() {
                return Err("duplicate --landing-principal".into());
            }
        } else if flag == "--refresh-queue-head" {
            if refresh {
                return Err("duplicate --refresh-queue-head".into());
            }
            refresh = true;
        } else if flag == "--refresh-principal" {
            let value = args.get(i).ok_or("missing --refresh-principal")?;
            i += 1;
            super::publish::fixed_hex(value, 16)?;
            let principal = fgit_types::PrincipalId::from_hex(value)
                .map_err(|_| "invalid queue refresh principal")?;
            if queue_refresh_principal.replace(principal).is_some() {
                return Err("duplicate --refresh-principal".into());
            }
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
    let branch = execution.reference.as_bytes().starts_with(b"refs/heads/");
    let tag = execution.reference.as_bytes().starts_with(b"refs/tags/");
    if !branch && !tag {
        return Err("watch requires an explicit branch or tag ref".into());
    }
    let merge_candidate = crate::workflow_merge_watch::parse(&merge_fields)?;
    if tag
        && (publish
            || publisher.is_some()
            || land
            || landing_principal.is_some()
            || refresh
            || queue_refresh_principal.is_some()
            || pull_request.is_some()
            || merge_queue.is_some()
            || merge_candidate.is_some())
    {
        return Err(
            "tag watches support ordinary execution only; check publication, PR and queue modes require a branch"
                .into(),
        );
    }
    if merge_queue.is_some() && pull_request.is_some() {
        return Err("--merge-queue and --pull-request are mutually exclusive".into());
    }
    if merge_queue.is_some() && merge_candidate.is_none() {
        return Err("--merge-queue requires the complete merge-candidate option group".into());
    }
    if let Some(merge) = &merge_candidate {
        if merge_queue.is_some() {
            merge
                .validate_queue_selection(&execution.reference, execution.incarnation.is_some())?;
        } else {
            merge.validate_selection(
                &execution.reference,
                pull_request,
                execution.incarnation.is_some(),
            )?;
        }
    }
    if publish != publisher.is_some() {
        return Err("--publish-checks and --principal-id must be supplied together".into());
    }
    if publish && execution.incarnation.is_none() {
        return Err("automatic check publication requires --expected-incarnation".into());
    }
    if land != landing_principal.is_some() {
        return Err("--land-queue-head and --landing-principal must be supplied together".into());
    }
    if land
        && (merge_queue.is_none()
            || merge_candidate.is_none()
            || !publish
            || execution.incarnation.is_none())
    {
        return Err(concat!(
            "automatic queue landing requires --merge-queue, the complete merge-candidate group, ",
            "--publish-checks and --expected-incarnation",
        )
        .into());
    }
    if refresh != queue_refresh_principal.is_some() {
        return Err(
            "--refresh-queue-head and --refresh-principal must be supplied together".into(),
        );
    }
    if refresh && !land {
        return Err("automatic queue target refresh requires --land-queue-head and its complete queue, candidate and check-publication configuration".into());
    }
    if continuous != stop_file.is_some() {
        return Err("--continuous and --stop-file must be supplied together".into());
    }
    if continuous && polls.is_some() {
        return Err("--continuous cannot be combined with --polls".into());
    }
    if !continuous && attempt_timeout.is_some() {
        return Err("--attempt-timeout-secs requires --continuous".into());
    }
    Ok(WatchOptions {
        publisher,
        landing_principal,
        queue_refresh_principal,
        pull_request,
        merge_queue,
        merge_candidate,
        execution,
        polls: polls.unwrap_or(1),
        interval: Duration::from_millis(u64::from(interval.unwrap_or(1000))),
        stop_file,
        attempt_timeout: Duration::from_secs(u64::from(attempt_timeout.unwrap_or(300))),
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
    polls: u64,
    dispatched: u64,
    non_green: bool,
    stopped: bool,
    reconcile: bool,
    publication_enabled: bool,
    checks_committed: usize,
    checks_refused: usize,
    queue_landing_enabled: bool,
    landings_committed: usize,
    landings_refused: usize,
    landings_previously_decided: usize,
    landings_waiting: usize,
    landings_stale: usize,
    queue_refresh_enabled: bool,
    refreshes_committed: usize,
    refreshes_refused: usize,
    refreshes_previously_decided: usize,
    refreshes_waiting: usize,
    refresh_pending: bool,
    continuous: bool,
    operator_stopped: bool,
    lifetime_expired: bool,
}
#[cfg(target_os = "linux")]
fn execute(options: WatchOptions, output: &mut impl Write) -> Result<u8, String> {
    use fgit_node::{NodeConfig, OneNode, TerminationSignals};
    let started = Instant::now();
    let config = options
        .execution
        .artifacts
        .as_ref()
        .map(super::artifacts::Options::node_config)
        .transpose()?;
    let opt = &options.execution;
    // Refuse a stale control before opening canonical state or reporting ready.
    let stop_file = options
        .stop_file
        .as_deref()
        .map(crate::service_stop::StopFile::arm)
        .transpose()
        .map_err(|e| e.to_string())?;
    let signals = TerminationSignals::install().map_err(|e| e.to_string())?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(opt.storage.clone(), opt.tenant, opt.repository)
            .with_object_format(opt.format),
    )
    .map_err(|e| e.to_string())?;
    let mut summary = Summary {
        publication_enabled: options.publisher.is_some(),
        queue_landing_enabled: options.landing_principal.is_some(),
        queue_refresh_enabled: options.queue_refresh_principal.is_some(),
        continuous: stop_file.is_some(),
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
        if let Some(stop_file) = stop_file {
            return continuous::run(
                &node,
                &options,
                config.as_ref(),
                signals,
                stop_file,
                started,
                &mut summary,
                &mut monitor,
                output,
            );
        }
        let (result, cleanup) =
            super::with_signal_request(&node, signals, |request| -> Result<(), String> {
                for index in 0..options.polls {
                    poll_once(
                        &node,
                        request,
                        &options,
                        config.as_ref(),
                        &mut summary,
                        output,
                    )?;
                    if summary.stopped || summary.reconcile {
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
#[cfg(target_os = "linux")]
fn poll_once(
    node: &fgit_node::OneNode,
    request: &fgit_node::NodeRequestContext,
    options: &WatchOptions,
    config: Option<&fgit_node::TrustedWorkflowArtifactConfig>,
    summary: &mut Summary,
    output: &mut impl Write,
) -> Result<(), String> {
    let opt = &options.execution;
    if summary.reconcile {
        return Ok(());
    }
    if summary.stopped || !request.checkpoint_is_live() {
        summary.stopped = true;
        return Ok(());
    }
    let merge = options
        .merge_candidate
        .as_ref()
        .map(crate::workflow_merge_watch::Options::node_config)
        .transpose()?;
    let queue = options
        .merge_queue
        .map(|number| {
            merge
                .as_ref()
                .map(|config| (number, config))
                .ok_or("queue watch requires merge candidate configuration")
        })
        .transpose()?;
    if options.queue_refresh_principal.is_none() {
        validate_refresh_custody(node, request, options, summary)?;
    }
    refresh_pending(
        node,
        request,
        options,
        merge.as_ref(),
        fgit_node::workflow_watch::QueueRefreshMode::RecoverOnly,
        summary,
        output,
    )?;
    if summary.stopped || summary.reconcile || !request.checkpoint_is_live() {
        summary.stopped |= !request.checkpoint_is_live();
        return Ok(());
    }
    if let Some(publisher) = options.publisher {
        publish_pending(
            node,
            request,
            opt,
            publisher,
            options.pull_request,
            options.merge_queue,
            merge.as_ref(),
            summary,
            output,
        )?;
    }
    if summary.stopped || !request.checkpoint_is_live() {
        summary.stopped = true;
        return Ok(());
    }
    land_pending(node, request, options, merge.as_ref(), summary, output)?;
    if summary.stopped || !request.checkpoint_is_live() {
        summary.stopped = true;
        return Ok(());
    }
    refresh_pending(
        node,
        request,
        options,
        merge.as_ref(),
        fgit_node::workflow_watch::QueueRefreshMode::RecoverAndSelect,
        summary,
        output,
    )?;
    if summary.stopped || summary.reconcile || !request.checkpoint_is_live() {
        summary.stopped |= !request.checkpoint_is_live();
        return Ok(());
    }
    let poll = node
        .runtime()
        .block_on(async {
            if let Some((number, merge)) = queue {
                return node
                    .poll_trusted_queue_head_merge_workflows_in(
                        request,
                        &opt.reference,
                        number,
                        &opt.workflow,
                        &opt.parent,
                        &opt.inputs,
                        Default::default(),
                        config,
                        merge,
                    )
                    .await;
            }
            match (options.pull_request, merge.as_ref()) {
                (Some(number), Some(merge)) => {
                    node.poll_trusted_pull_request_merge_workflows_in(
                        request,
                        &opt.reference,
                        number,
                        &opt.workflow,
                        &opt.parent,
                        &opt.inputs,
                        Default::default(),
                        config,
                        merge,
                    )
                    .await
                }
                (Some(number), None) => {
                    node.poll_trusted_pull_request_workflows_in(
                        request,
                        &opt.reference,
                        number,
                        &opt.workflow,
                        &opt.parent,
                        &opt.inputs,
                        Default::default(),
                        config,
                    )
                    .await
                }
                (None, _) => {
                    node.poll_trusted_ref_workflows_in(
                        request,
                        &opt.reference,
                        &opt.workflow,
                        &opt.parent,
                        &opt.inputs,
                        Default::default(),
                        config,
                    )
                    .await
                }
            }
        })
        .map_err(|error| {
            summary.reconcile |=
                matches!(&error, fgit_node::TrustedWorkflowFailure::Journal { .. });
            error.to_string()
        })?;
    summary.polls = summary
        .polls
        .checked_add(1)
        .ok_or("watch poll counter exhausted")?;
    summary.dispatched += u64::from(poll.dispatch().is_some());
    summary.non_green |= poll.non_green();
    summary.reconcile |= poll.requires_reconciliation();
    summary.stopped |= poll.stopped_before_reservation();
    writeln!(
        output,
        "{{\"type\":\"workflow_watch_poll\",\"index\":{},\"poll\":{}}}",
        summary.polls,
        poll.to_json()
    )
    .and_then(|()| output.flush())
    .map_err(|e| format!("watch output failed; preserve original event custody: {e}"))?;
    if summary.stopped || !request.checkpoint_is_live() {
        summary.stopped = true;
        summary.reconcile |= poll.dispatch().is_some();
        return Ok(());
    }
    if summary.reconcile {
        return Ok(());
    }
    if let Some(publisher) = options.publisher {
        publish_pending(
            node,
            request,
            opt,
            publisher,
            options.pull_request,
            options.merge_queue,
            merge.as_ref(),
            summary,
            output,
        )?;
    }
    land_pending(node, request, options, merge.as_ref(), summary, output)?;
    if !request.checkpoint_is_live() {
        summary.stopped = true;
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn validate_refresh_custody(
    node: &fgit_node::OneNode,
    request: &fgit_node::NodeRequestContext,
    options: &WatchOptions,
    summary: &mut Summary,
) -> Result<(), String> {
    let Some(number) = options.merge_queue else {
        return Ok(());
    };
    if !request.checkpoint_is_live() {
        summary.stopped = true;
        return Ok(());
    }
    let merge = options
        .merge_candidate
        .as_ref()
        .ok_or("queue watch requires merge candidate configuration")?
        .node_config()?;
    let opt = &options.execution;
    let pending = node
        .runtime()
        .block_on(node.validate_trusted_queue_head_refresh_custody_in(
            request,
            &opt.reference,
            number,
            &opt.workflow,
            &opt.parent,
            &merge,
            options.queue_refresh_principal,
        ))
        .map_err(|error| {
            summary.reconcile = true;
            summary.stopped |= !request.checkpoint_is_live();
            error.to_string()
        })?;
    // Startup validation observes responsibility without submitting it. Only a
    // later complete recovery pass may clear this observation.
    summary.refresh_pending |= pending;
    Ok(())
}
#[cfg(target_os = "linux")]
fn refresh_pending(
    node: &fgit_node::OneNode,
    request: &fgit_node::NodeRequestContext,
    options: &WatchOptions,
    merge: Option<&fgit_node::workflow_watch::PullRequestMergeWatchConfig>,
    mode: fgit_node::workflow_watch::QueueRefreshMode,
    summary: &mut Summary,
    output: &mut impl Write,
) -> Result<(), String> {
    let Some(refresher) = options.queue_refresh_principal else {
        return Ok(());
    };
    if summary.stopped || summary.reconcile || !request.checkpoint_is_live() {
        summary.stopped |= !request.checkpoint_is_live();
        return Ok(());
    }
    let (Some(number), Some(merge), Some(publisher), Some(lander)) = (
        options.merge_queue,
        merge,
        options.publisher,
        options.landing_principal,
    ) else {
        return Err("automatic queue refresh requires its complete operator configuration".into());
    };
    let opt = &options.execution;
    let result = node
        .runtime()
        .block_on(node.refresh_trusted_queue_head_merge_workflows_in(
            request,
            &opt.reference,
            number,
            &opt.workflow,
            &opt.parent,
            merge,
            publisher,
            lander,
            refresher,
            mode,
            |text| {
                writeln!(output, "{text}")
                    .and_then(|()| output.flush())
                    .map_err(|error| error.to_string())
            },
        ));
    summary.non_green |= result.refused != 0;
    if result.error.is_none() && !result.request_stopped {
        summary.refresh_pending = result.pending;
    } else {
        summary.refresh_pending |= result.pending;
    }
    summary.reconcile |= result.error.is_some() || summary.refresh_pending;
    summary.stopped |= result.request_stopped;
    for (counter, amount) in [
        (&mut summary.refreshes_committed, result.committed),
        (&mut summary.refreshes_refused, result.refused),
        (
            &mut summary.refreshes_previously_decided,
            result.previously_decided,
        ),
        (&mut summary.refreshes_waiting, result.waiting),
    ] {
        *counter = counter
            .checked_add(amount)
            .ok_or("queue refresh observation counter exhausted")?;
    }
    writeln!(output, "{}", result.to_json())
        .and_then(|()| output.flush())
        .map_err(|error| {
            format!("watch refresh receipt failed; preserve original custody: {error}")
        })?;
    if let Some(error) = result.error {
        return Err(error);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn land_pending(
    node: &fgit_node::OneNode,
    request: &fgit_node::NodeRequestContext,
    options: &WatchOptions,
    merge: Option<&fgit_node::workflow_watch::PullRequestMergeWatchConfig>,
    summary: &mut Summary,
    output: &mut impl Write,
) -> Result<(), String> {
    let Some(lander) = options.landing_principal else {
        return Ok(());
    };
    if summary.stopped || summary.reconcile || !request.checkpoint_is_live() {
        summary.stopped |= !request.checkpoint_is_live();
        return Ok(());
    }
    let (Some(number), Some(publisher), Some(merge)) =
        (options.merge_queue, options.publisher, merge)
    else {
        return Err("automatic queue landing requires its complete operator configuration".into());
    };
    let opt = &options.execution;
    let result = node
        .runtime()
        .block_on(node.land_trusted_queue_head_merge_workflows_in(
            request,
            &opt.reference,
            number,
            &opt.workflow,
            &opt.parent,
            publisher,
            merge,
            lander,
            |text| {
                writeln!(output, "{text}")
                    .and_then(|()| output.flush())
                    .map_err(|error| error.to_string())
            },
        ));
    summary.non_green |= result.refused != 0;
    summary.reconcile |= result.error.is_some();
    summary.stopped |= result.request_stopped;
    // These are observed canonical outcomes, including recovered attempts.
    // Waiting for approvals and stale candidates do not grant a passing check.
    for (counter, amount) in [
        (&mut summary.landings_committed, result.committed),
        (&mut summary.landings_refused, result.refused),
        (
            &mut summary.landings_previously_decided,
            result.previously_decided,
        ),
        (&mut summary.landings_waiting, result.waiting),
        (&mut summary.landings_stale, result.stale),
    ] {
        *counter = counter
            .checked_add(amount)
            .ok_or("queue landing observation counter exhausted")?;
    }
    writeln!(output, "{}", result.to_json())
        .and_then(|()| output.flush())
        .map_err(|error| {
            format!("watch landing receipt failed; preserve original custody: {error}")
        })?;
    if let Some(error) = result.error {
        return Err(error);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn publish_pending(
    node: &fgit_node::OneNode,
    request: &fgit_node::NodeRequestContext,
    options: &Options,
    publisher: fgit_types::PrincipalId,
    pull_number: Option<u64>,
    queue_number: Option<u64>,
    merge: Option<&fgit_node::workflow_watch::PullRequestMergeWatchConfig>,
    summary: &mut Summary,
    output: &mut impl Write,
) -> Result<(), String> {
    let queue = queue_number
        .map(|number| {
            merge
                .map(|config| (number, config))
                .ok_or("queue reporting requires merge candidate configuration")
        })
        .transpose()?;
    let observe = |text: &str| {
        writeln!(output, "{text}")
            .and_then(|()| output.flush())
            .map_err(|e| e.to_string())
    };
    let result = node.runtime().block_on(async {
        if let Some((number, merge)) = queue {
            return node
                .publish_trusted_queue_head_merge_workflow_checks_in(
                    request,
                    &options.reference,
                    number,
                    &options.workflow,
                    &options.parent,
                    publisher,
                    merge,
                    observe,
                )
                .await;
        }
        match (pull_number, merge) {
            (Some(number), Some(merge)) => {
                node.publish_trusted_pull_request_merge_workflow_checks_in(
                    request,
                    &options.reference,
                    number,
                    &options.workflow,
                    &options.parent,
                    publisher,
                    merge,
                    observe,
                )
                .await
            }
            (Some(number), None) => {
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
            (None, _) => {
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
    summary.stopped |= result.request_stopped;
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
    writeln!(
        output,
        concat!(
            "{{\"type\":\"workflow_watch_result\",\"schema_version\":1,",
            "\"continuous\":{},\"operator_stopped\":{},\"polls\":{},\"dispatched\":{},",
            "\"non_green\":{},\"request_stopped\":{},\"requires_reconciliation\":{},",
            "\"publication_enabled\":{},\"committed_check_decisions\":{},",
            "\"refused_check_decisions\":{},",
            "\"queue_landing_enabled\":{},\"landings_committed\":{},\"landings_refused\":{},",
            "\"landings_previously_decided\":{},\"landings_waiting\":{},\"landings_stale\":{},",
            "\"queue_refresh_enabled\":{},\"refreshes_committed\":{},\"refreshes_refused\":{},",
            "\"refreshes_previously_decided\":{},\"refreshes_waiting\":{},\"refresh_pending\":{},",
            "\"node_closed\":{},\"operation_error\":{},\"cleanup_error\":{}}}"
        ),
        summary.continuous,
        summary.operator_stopped,
        summary.polls,
        summary.dispatched,
        summary.non_green,
        summary.stopped,
        summary.reconcile,
        summary.publication_enabled,
        summary.checks_committed,
        summary.checks_refused,
        summary.queue_landing_enabled,
        summary.landings_committed,
        summary.landings_refused,
        summary.landings_previously_decided,
        summary.landings_waiting,
        summary.landings_stale,
        summary.queue_refresh_enabled,
        summary.refreshes_committed,
        summary.refreshes_refused,
        summary.refreshes_previously_decided,
        summary.refreshes_waiting,
        summary.refresh_pending,
        cleanup.is_none(),
        optional(operation),
        optional(cleanup),
    )
    .and_then(|()| output.flush())
    .map_err(|error| format!("watch summary output incomplete: {error}"))?;
    Ok(if operation.is_some() || cleanup.is_some() {
        2
    } else {
        u8::from(
            summary.non_green
                || summary.reconcile
                || summary.refresh_pending
                || summary.lifetime_expired
                || (summary.stopped && !(summary.continuous && summary.operator_stopped)),
        )
    })
}
#[cfg(test)]
mod tests;
