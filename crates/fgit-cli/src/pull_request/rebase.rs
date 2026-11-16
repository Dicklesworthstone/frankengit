//! Exact-subject PR rebase preparation and complete, read-only series inspection.
//! Publication and durable review remain separate commands owned by the node.

use crate::commit_replay::{decimal, hex, parse_head, token, unhex, write_receipt};
use crate::merge_apply::preparation::{publish_new_bundle, render_conflict, require_absent};
use crate::publication_support::{parse_oid, quote, read_bundle};
use fgit_crypto::sha256_digest;
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::preparation::PreparationLimits;
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, RebaseCommitter, RebasePreparation, RebaseRequest, RebaseStep,
    RebaseStepKind, RebaseStop,
};
use fgit_forge::review::{ComparisonMode, ReviewOptions, SourceComparison};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_node::{NodeConfig, OneNode, PreparedPullRequestRebaseBundle, RebaseBundleInspection};
use fgit_types::{
    GitOid, HeadGeneration, PolicyEpoch, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;

const MAX_COMMITS: usize = 256;
const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 64 * 1024 * 1024;
const USAGE: &str = "\
usage: fg pr prepare-rebase <storage-root> <tenant-id> <repository-id> <number> <new-bundle>
  --trusted-local --profile path-v1 --expected-version <positive-pr-version>
  (--source-ref <branch> | --source-ref-hex <bytes>) --expected-source <oid>
  (--target-ref <branch> | --target-ref-hex <bytes>) --expected-target <oid>
  --policy-epoch <n> --upstream <exclusive-common-ancestor>
  --committer <name-and-email> --timestamp <unix-seconds> [--empty stop|drop|keep]
  [--max-commits <1..256>] [--max-edges <n>] [--max-output-bytes <n>]
usage: fg pr inspect-rebase <storage-root> <tenant-id> <repository-id> <number> <bundle>
  --trusted-local --expected-version <positive-pr-version>
  (--source-ref <branch> | --source-ref-hex <bytes>) --expected-source <oid>
  (--target-ref <branch> | --target-ref-hex <bytes>) --expected-target <oid>
  --policy-epoch <n> --upstream <exclusive-common-ancestor> --candidate <oid>
  [--expected-head <snapshot-token>] [--context-lines <0..20>]
  [--max-changes <n>] [--max-blob-bytes <n>] [--max-output-bytes <n>]
  [--max-diff-work <n>]

Prepare replays a nonempty linear source suffix onto the exact current PR target.
The upstream must be a common ancestor. Original author and message bytes are
preserved; the supplied committer/time replaces old signatures. A conflict or
newly-empty stop creates no bundle. The output names the TARGET branch and has
the target tip as its sole prerequisite; preparation never updates either ref.
Inspect verifies the entire uploaded series and reports exact commit bodies,
the old-source-to-candidate diff, and EVERY parent-to-child diff, including
transient changes. Inspection permits no path filters and grants no approval.
Then use fg pr review --method rebase for a durable exact-candidate review and
fg merge apply-reviewed --method rebase, or fg merge apply --method rebase,
to publish separately. Source refs remain unchanged when the PR is merged.
Exit 0: complete prepared/inspected result; 3: preparation stopped;
2: input/infrastructure/cleanup/output error. Existing output files are refused.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    path: PathBuf,
    subject: ReviewSubject,
    upstream: GitOid,
    operation: Operation,
}

#[derive(Debug)]
enum Operation {
    Prepare {
        committer: RebaseCommitter,
        limits: PreparationLimits,
        empty: EmptyCommitPolicy,
    },
    Inspect {
        candidate: GitOid,
        head: Option<RepositoryAuthorityHeadId>,
        review: ReviewOptions,
    },
}

pub fn run(args: &[String], output: &mut impl Write) -> Result<u8, String> {
    if args.len() == 2 && args[1] == "--help" {
        write_receipt(output, USAGE, false)?;
        return Ok(0);
    }
    let options = parse(args)?;
    match &options.operation {
        Operation::Prepare {
            committer,
            limits,
            empty,
        } => {
            require_absent(&options.path)?;
            let mut node = open(&options)?;
            let result = (|| {
                node.bring_into_service(HeadGeneration::FIRST)
                    .map_err(|error| error.to_string())?;
                let request = fgit_cli::command_request_context(&node);
                node.runtime()
                    .block_on(node.prepare_pull_request_rebase_bundle_in(
                        &request,
                        &options.subject,
                        &Default::default(),
                        options.upstream,
                        committer,
                        *limits,
                        *empty,
                    ))
                    .map_err(|error| error.to_string())
            })();
            let artifact = after_close(result, node.shutdown().err().map(|e| e.to_string()))?;
            let (receipt, code) = render_preparation(&options, &artifact)?;
            if let Some(bundle) = artifact.preparation.bundle.as_deref() {
                publish_new_bundle(&options.path, bundle)?;
            }
            write_receipt(output, &receipt, artifact.preparation.bundle.is_some())?;
            Ok(code)
        }
        Operation::Inspect {
            candidate,
            head,
            review,
        } => {
            let bytes = read_bundle(&options.path, MAX_BUNDLE_BYTES)?;
            let mut node = open(&options)?;
            let result = (|| {
                node.bring_into_service(HeadGeneration::FIRST)
                    .map_err(|error| error.to_string())?;
                let request = fgit_cli::command_request_context(&node);
                node.runtime()
                    .block_on(node.inspect_pull_request_rebase_bundle_in(
                        &request,
                        &options.subject,
                        options.upstream,
                        *candidate,
                        &bytes,
                        &Default::default(),
                        *head,
                        review,
                    ))
                    .map_err(|error| error.to_string())
            })();
            let report = after_close(result, node.shutdown().err().map(|e| e.to_string()))?;
            let receipt = render_inspection(&options, &bytes, &report)?;
            write_receipt(output, &receipt, false)?;
            Ok(0)
        }
    }
}

fn open(options: &Options) -> Result<OneNode, String> {
    OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.subject.source_tip.algorithm()),
    )
    .map_err(|error| error.to_string())
}

fn after_close<T>(result: Result<T, String>, cleanup: Option<String>) -> Result<T, String> {
    match (result, cleanup) {
        (Ok(result), None) => Ok(result),
        (Err(error), None) => Err(error),
        (Ok(_), Some(error)) => Err(format!(
            "rebase node shutdown failed: {error}; no successful artifact or report returned"
        )),
        (Err(error), Some(cleanup)) => {
            Err(format!("{error}; node shutdown also failed: {cleanup}"))
        }
    }
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 6 || !matches!(args[0].as_str(), "prepare-rebase" | "inspect-rebase") {
        return Err(USAGE.into());
    }
    if args.len() > 64
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("PR rebase arguments exceed the bounded profile".into());
    }
    if [args[1].as_str(), args[5].as_str()]
        .iter()
        .any(|value| value.is_empty() || value.len() > 4096)
    {
        return Err("storage and bundle paths must be nonempty and bounded".into());
    }
    let preparing = args[0] == "prepare-rebase";
    let mut flags = BTreeMap::new();
    let mut at = 6;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        let allowed = matches!(
            flag,
            "--trusted-local"
                | "--expected-version"
                | "--source-ref"
                | "--source-ref-hex"
                | "--expected-source"
                | "--target-ref"
                | "--target-ref-hex"
                | "--expected-target"
                | "--policy-epoch"
                | "--upstream"
                | "--max-output-bytes"
        ) || (preparing
            && matches!(
                flag,
                "--profile"
                    | "--committer"
                    | "--timestamp"
                    | "--empty"
                    | "--max-commits"
                    | "--max-edges"
            ))
            || (!preparing
                && matches!(
                    flag,
                    "--candidate"
                        | "--expected-head"
                        | "--context-lines"
                        | "--max-changes"
                        | "--max-blob-bytes"
                        | "--max-diff-work"
                ));
        if !allowed {
            return Err(format!("unknown or inapplicable PR rebase option {flag:?}"));
        }
        let value = if flag == "--trusted-local" {
            ""
        } else {
            let value = args
                .get(at)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1;
            value.as_str()
        };
        if flags.insert(flag, value).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !flags.contains_key("--trusted-local") {
        return Err("--trusted-local is required".into());
    }
    let required = |name| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required"))
    };
    let branch = |plain, encoded| {
        let bytes = match (flags.get(plain), flags.get(encoded)) {
            (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
            (None, Some(value)) => unhex(value, 4096)?,
            _ => {
                return Err(format!(
                    "exactly one bounded {plain} or {encoded} is required"
                ));
            }
        };
        if !bytes.starts_with(b"refs/heads/") {
            return Err("PR source and target must be fully qualified branches".into());
        }
        RefName::try_new(&bytes).map_err(|_| "invalid branch reference".into())
    };
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::try_new(decimal(&args[4])?)
            .ok_or("PR number must be positive")?,
        pull_request_version: AggregateVersion::try_new(decimal(required("--expected-version")?)?)
            .ok_or("PR version must be positive")?,
        source_ref: branch("--source-ref", "--source-ref-hex")?,
        target_ref: branch("--target-ref", "--target-ref-hex")?,
        source_tip: parse_oid(required("--expected-source")?)?,
        target_tip: parse_oid(required("--expected-target")?)?,
        policy_epoch: PolicyEpoch::try_new(decimal(required("--policy-epoch")?)?)
            .map_err(|_| "invalid policy epoch")?,
    };
    subject
        .pull_request_version
        .next()
        .map_err(|_| "PR version exhausted")?;
    let upstream = parse_oid(required("--upstream")?)?;
    if subject.source_ref == subject.target_ref
        || subject.source_tip == subject.target_tip
        || subject.source_tip == upstream
        || [subject.source_tip, subject.target_tip, upstream]
            .iter()
            .any(|oid| oid.is_zero() || oid.algorithm() != subject.source_tip.algorithm())
    {
        return Err(
            "PR rebase requires distinct source/target and a nonempty, same-format suffix".into(),
        );
    }
    let operation = if preparing {
        if flags.get("--profile") != Some(&"path-v1") {
            return Err("explicit --profile path-v1 is required".into());
        }
        let committer = RebaseCommitter {
            identity: required("--committer")?.to_owned(),
            timestamp: decimal(required("--timestamp")?)?,
        };
        committer.validate().map_err(|error| error.to_string())?;
        let empty = match flags.get("--empty").copied().unwrap_or("stop") {
            "stop" => EmptyCommitPolicy::Stop,
            "drop" => EmptyCommitPolicy::Drop,
            "keep" => EmptyCommitPolicy::Keep,
            _ => return Err("--empty must be stop, drop, or keep".into()),
        };
        let mut limits = PreparationLimits {
            max_commits: MAX_COMMITS,
            ..PreparationLimits::default()
        };
        for (name, field) in [
            ("--max-commits", &mut limits.max_commits),
            ("--max-edges", &mut limits.max_edges),
            ("--max-output-bytes", &mut limits.max_output_bytes),
        ] {
            if let Some(value) = flags.get(name) {
                *field = size(value)?;
            }
        }
        limits.validate().map_err(|error| error.to_string())?;
        if limits.max_commits > MAX_COMMITS {
            return Err("PR rebases accept at most 256 original commits".into());
        }
        Operation::Prepare {
            committer,
            limits,
            empty,
        }
    } else {
        let candidate = parse_oid(required("--candidate")?)?;
        CandidateBinding {
            merge_base: upstream,
            commit: candidate,
        }
        .validate(&subject)
        .map_err(|error| error.to_string())?;
        let mut review = ReviewOptions::default();
        for (name, field) in [
            ("--context-lines", &mut review.context_lines),
            ("--max-changes", &mut review.limits.max_changes),
            ("--max-blob-bytes", &mut review.limits.max_blob_bytes),
            ("--max-output-bytes", &mut review.limits.max_output_bytes),
            ("--max-diff-work", &mut review.limits.max_diff_work),
        ] {
            if let Some(value) = flags.get(name) {
                *field = size(value)?;
            }
        }
        review.validate().map_err(|error| error.to_string())?;
        Operation::Inspect {
            candidate,
            head: flags
                .get("--expected-head")
                .map(|value| parse_head(value))
                .transpose()?,
            review,
        }
    };
    let path = PathBuf::from(&args[5]);
    if path.file_name().is_none() {
        return Err("bundle path must name a file".into());
    }
    Ok(Options {
        storage: args[1].clone().into(),
        tenant: TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?,
        repository: RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?,
        path,
        subject,
        upstream,
        operation,
    })
}

fn size(value: &str) -> Result<usize, String> {
    usize::try_from(decimal(value)?).map_err(|_| "limit exceeds target width".into())
}

fn subject_fields(options: &Options) -> String {
    let subject = &options.subject;
    format!(
        concat!(
            "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},",
            "\"pull_request\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
            "\"source_reference_hex\":{},\"target_reference_hex\":{},",
            "\"expected_source\":{},\"expected_target\":{},\"upstream\":{}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(subject.source_tip.algorithm().as_str()),
        subject.pull_request.get(),
        subject.pull_request_version.get(),
        subject.policy_epoch.get(),
        quote(&hex(subject.source_ref.as_bytes())),
        quote(&hex(subject.target_ref.as_bytes())),
        quote(&subject.source_tip.to_string()),
        quote(&subject.target_tip.to_string()),
        quote(&options.upstream.to_string()),
    )
}

fn render_preparation(
    options: &Options,
    artifact: &PreparedPullRequestRebaseBundle,
) -> Result<(String, u8), String> {
    let Operation::Prepare {
        committer,
        limits,
        empty,
    } = &options.operation
    else {
        return Err("preparation response used for inspection".into());
    };
    let preparation = &artifact.preparation;
    if artifact.subject != options.subject || artifact.source_head != preparation.source_head {
        return Err("PR rebase subject/snapshot binding mismatch".into());
    }
    let expected = RebaseRequest {
        source_tip: options.subject.source_tip,
        upstream: options.upstream,
        onto: options.subject.target_tip,
        empty: *empty,
    };
    let (request, steps, label, code, details) = match &preparation.outcome {
        RebasePreparation::Clean(plan) => {
            let bytes = preparation
                .bundle
                .as_deref()
                .filter(|bytes| !bytes.is_empty())
                .ok_or("clean PR rebase omitted its bundle")?;
            if plan.steps.is_empty()
                || plan.steps.len() > limits.max_commits
                || plan
                    .steps
                    .iter()
                    .all(|step| step.kind == RebaseStepKind::DroppedEmpty)
                || plan.objects.len() > limits.max_objects
                || preparation.borrowed_objects > preparation.pack_objects
                || plan.commit == expected.onto
                || plan.steps.last().is_none_or(|step| {
                    step.original != expected.source_tip
                        || step.rewritten != plan.commit
                        || step.tree != plan.tree
                })
            {
                return Err("PR rebase candidate/step accounting mismatch".into());
            }
            (
                &plan.request,
                plan.steps.as_slice(),
                "prepared",
                0,
                format!(
                    concat!(
                        "\"candidate_commit\":{},\"root_tree\":{},\"generated_objects\":{},",
                        "\"pack_objects\":{},\"borrowed_objects\":{},\"bundle_bytes\":{},\"bundle_sha256\":{}"
                    ),
                    quote(&plan.commit.to_string()),
                    quote(&plan.tree.to_string()),
                    plan.objects.len(),
                    preparation.pack_objects,
                    preparation.borrowed_objects,
                    bytes.len(),
                    quote(&hex(&sha256_digest(bytes))),
                ),
            )
        }
        RebasePreparation::Stopped {
            request,
            original,
            completed,
            reason,
        } => {
            if preparation.bundle.is_some()
                || preparation.pack_objects != 0
                || preparation.borrowed_objects != 0
                || completed.len() >= limits.max_commits
                || original.is_zero()
                || original.algorithm() != expected.source_tip.algorithm()
            {
                return Err("stopped PR rebase carried an artifact or invalid step count".into());
            }
            let (label, details) = match reason {
                RebaseStop::Conflicted(conflicts)
                    if !conflicts.is_empty() && conflicts.len() <= limits.max_conflicts =>
                {
                    (
                        "conflicted",
                        format!(
                            "\"conflicts\":[{}]",
                            conflicts
                                .iter()
                                .map(render_conflict)
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    )
                }
                RebaseStop::BecameEmpty => {
                    ("became_empty", "\"requires_empty_policy\":true".into())
                }
                _ => return Err("invalid PR rebase stop report".into()),
            };
            (
                request,
                completed.as_slice(),
                label,
                3,
                format!(
                    "\"candidate_commit\":null,\"stopped_commit\":{},{details}",
                    quote(&original.to_string())
                ),
            )
        }
    };
    if *request != expected {
        return Err("PR rebase input binding mismatch".into());
    }
    let mut originals = BTreeSet::new();
    for step in steps {
        if !originals.insert(step.original)
            || [step.original, step.rewritten, step.tree]
                .iter()
                .any(|oid| oid.is_zero() || oid.algorithm() != expected.source_tip.algorithm())
        {
            return Err("PR rebase step identity mismatch".into());
        }
    }
    let receipt = format!(
        concat!(
            "{{\"type\":\"pull_request_rebase_preparation\",\"schema_version\":1,\"profile\":\"path-v1\",",
            "\"method\":\"rebase\",\"outcome\":{},{},\"snapshot_token\":{},",
            "\"committer\":{},\"timestamp\":{},\"empty_policy\":{},\"steps\":[{}],",
            "\"bundle_created\":{},\"bundle_path\":{},\"published_to_repository\":false,",
            "\"objects_staged\":false,\"approval_granted\":false,\"node_closed\":true,{}}}"
        ),
        quote(label),
        subject_fields(options),
        quote(&token(artifact.source_head)),
        quote(&committer.identity),
        committer.timestamp,
        quote(match empty {
            EmptyCommitPolicy::Stop => "stop",
            EmptyCommitPolicy::Drop => "drop",
            EmptyCommitPolicy::Keep => "keep",
        }),
        steps.iter().map(render_step).collect::<Vec<_>>().join(","),
        preparation.bundle.is_some(),
        preparation
            .bundle
            .as_ref()
            .map_or_else(|| "null".into(), |_| quote(&options.path.to_string_lossy())),
        details,
    );
    if receipt.len() > 4 * 1024 * 1024 {
        return Err("PR rebase preparation receipt exceeds output bound".into());
    }
    Ok((receipt, code))
}

fn render_step(step: &RebaseStep) -> String {
    format!(
        "{{\"original\":{},\"rewritten\":{},\"tree\":{},\"kind\":{}}}",
        quote(&step.original.to_string()),
        quote(&step.rewritten.to_string()),
        quote(&step.tree.to_string()),
        quote(match step.kind {
            RebaseStepKind::Replayed => "replayed",
            RebaseStepKind::PreservedEmpty => "preserved_empty",
            RebaseStepKind::DroppedEmpty => "dropped_empty",
        }),
    )
}

fn render_inspection(
    options: &Options,
    bytes: &[u8],
    report: &RebaseBundleInspection,
) -> Result<String, String> {
    let Operation::Inspect {
        candidate,
        head,
        review,
    } = &options.operation
    else {
        return Err("inspection response used for preparation".into());
    };
    if report.repository_id != options.repository
        || head.is_some_and(|head| head != report.source_head)
        || report.source_reference != options.subject.source_ref
        || report.onto_reference != options.subject.target_ref
        || report.expected_source != options.subject.source_tip
        || report.onto != options.subject.target_tip
        || report.candidate != *candidate
        || report.commits.is_empty()
        || report.commits.len() > MAX_COMMITS
        || report.comparisons.len() != report.commits.len() + 1
        || report.bundle.bytes != bytes.len()
        || report.bundle.sha256 != sha256_digest(bytes)
    {
        return Err("PR rebase inspection subject/bundle binding mismatch".into());
    }
    let format = options.subject.source_tip.algorithm();
    let mut previous = options.subject.target_tip;
    let mut previous_tree = None;
    let mut body_bytes = 0usize;
    let mut changes = 0usize;
    for (index, comparison) in report.comparisons.iter().enumerate() {
        let (before, after) = if index == 0 {
            (options.subject.source_tip, *candidate)
        } else {
            let commit = &report.commits[index - 1];
            body_bytes = body_bytes.saturating_add(commit.body.len());
            if commit.parent != previous
                || commit.body.is_empty()
                || body_bytes > 16 * 1024 * 1024
                || commit.tree != comparison.after_tree
                || previous_tree.is_some_and(|tree| tree != comparison.before_tree)
            {
                return Err("PR rebase inspection commit/parent binding mismatch".into());
            }
            previous = commit.id;
            previous_tree = Some(commit.tree);
            (commit.parent, commit.id)
        };
        changes = changes.saturating_add(comparison.entries.len());
        if comparison.mode != ComparisonMode::Direct
            || comparison.requested_before != before
            || comparison.compared_before != before
            || comparison.requested_after != after
            || [before, after, comparison.before_tree, comparison.after_tree]
                .iter()
                .any(|oid| oid.is_zero() || oid.algorithm() != format)
            || !comparison
                .entries
                .windows(2)
                .all(|pair| pair[0].path < pair[1].path)
            || changes > review.limits.max_changes
        {
            return Err("PR rebase inspection comparison binding/order/budget mismatch".into());
        }
    }
    if previous != *candidate || previous_tree != Some(report.comparisons[0].after_tree) {
        return Err("PR rebase inspection tip/tree binding mismatch".into());
    }
    let mut out = format!(
        concat!(
            "{{\"type\":\"pull_request_rebase_inspection\",\"schema_version\":1,",
            "\"profile\":\"verified-linear-series-v1\",\"method\":\"rebase\",\"complete\":true,",
            "\"scope\":\"all_paths_all_commits\",{},\"snapshot_token\":{},\"candidate_commit\":{},",
            "\"candidate_origin\":\"untrusted_bundle\",\"bundle_sha256\":{},\"bundle_bytes\":{},",
            "\"pack_bytes\":{},\"pack_objects\":{},\"expanded_bytes\":{},\"closure_objects\":{},",
            "\"transport_only_objects\":{},\"context_lines\":{},\"line_origin\":0,",
            "\"published_to_repository\":false,\"objects_staged\":false,\"approval_granted\":false,",
            "\"node_closed\":true,\"source_comparison\":{},\"commits\":["
        ),
        subject_fields(options),
        quote(&token(report.source_head)),
        quote(&candidate.to_string()),
        quote(&hex(&report.bundle.sha256)),
        report.bundle.bytes,
        report.bundle.pack_bytes,
        report.bundle.pack_objects,
        report.bundle.expanded_bytes,
        report.bundle.closure_objects,
        report.bundle.transport_only_objects,
        review.context_lines,
        render_comparison(&report.comparisons[0])?,
    );
    for (index, commit) in report.commits.iter().enumerate() {
        let row = format!(
            "{{\"commit\":{},\"parent\":{},\"tree\":{},\"commit_hex\":{},\"commit_text\":{},\"comparison\":{}}}",
            quote(&commit.id.to_string()),
            quote(&commit.parent.to_string()),
            quote(&commit.tree.to_string()),
            quote(&hex(&commit.body)),
            std::str::from_utf8(&commit.body).map_or_else(|_| "null".into(), quote),
            render_comparison(&report.comparisons[index + 1])?,
        );
        if out.len().saturating_add(row.len()).saturating_add(3) > MAX_JSON_BYTES {
            return Err("PR rebase inspection JSON exceeds output bound".into());
        }
        if index != 0 {
            out.push(',');
        }
        out.push_str(&row);
    }
    out.push_str("]}");
    Ok(out)
}

fn render_comparison(comparison: &SourceComparison) -> Result<String, String> {
    let mut out = format!(
        "{{\"comparison\":\"direct\",\"requested_before\":{},\"requested_after\":{},\"compared_before\":{},\"before_tree\":{},\"after_tree\":{},\"entry_count\":{},\"entries\":[",
        quote(&comparison.requested_before.to_string()),
        quote(&comparison.requested_after.to_string()),
        quote(&comparison.compared_before.to_string()),
        quote(&comparison.before_tree.to_string()),
        quote(&comparison.after_tree.to_string()),
        comparison.entries.len(),
    );
    for (index, entry) in comparison.entries.iter().enumerate() {
        let row = crate::source_review::render_entry(entry);
        if out.len().saturating_add(row.len()).saturating_add(3) > MAX_JSON_BYTES {
            return Err("PR rebase comparison JSON exceeds output bound".into());
        }
        if index != 0 {
            out.push(',');
        }
        out.push_str(&row);
    }
    out.push_str("]}");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(width: usize, prepare: bool) -> Vec<String> {
        let mut args: Vec<_> = [
            if prepare {
                "prepare-rebase"
            } else {
                "inspect-rebase"
            },
            "node",
            &"11".repeat(16),
            &"22".repeat(16),
            "17",
            "candidate.bundle",
            "--trusted-local",
            "--expected-version",
            "4",
            "--source-ref",
            "refs/heads/topic",
            "--expected-source",
            &"a".repeat(width),
            "--target-ref",
            "refs/heads/main",
            "--expected-target",
            &"b".repeat(width),
            "--policy-epoch",
            "1",
            "--upstream",
            &"c".repeat(width),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if prepare {
            args.extend(
                [
                    "--profile",
                    "path-v1",
                    "--committer",
                    "T <t@x>",
                    "--timestamp",
                    "2",
                ]
                .map(str::to_owned),
            );
        } else {
            args.extend(["--candidate".into(), "d".repeat(width)]);
        }
        args
    }

    fn change(args: &mut [String], flag: &str, value: String) {
        let at = args.iter().position(|value| value == flag).unwrap();
        args[at + 1] = value;
    }

    #[test]
    fn exact_pr_subject_and_native_domain_are_required_before_io() {
        for width in [40, 64] {
            for prepare in [false, true] {
                let input = args(width, prepare);
                assert!(parse(&input).is_ok());
                for flag in [
                    "--expected-version",
                    "--source-ref",
                    "--expected-source",
                    "--target-ref",
                    "--expected-target",
                    "--policy-epoch",
                    "--upstream",
                ] {
                    let mut bad = input.clone();
                    let at = bad.iter().position(|value| value == flag).unwrap();
                    bad.drain(at..at + 2);
                    assert!(parse(&bad).is_err(), "missing {flag}");
                    let mut bad = input.clone();
                    bad.extend([flag.into(), input[at + 1].clone()]);
                    assert!(parse(&bad).is_err(), "duplicate {flag}");
                }
                for (flag, value) in [
                    ("--expected-version", "0".into()),
                    ("--source-ref", "refs/heads/main".into()),
                    ("--upstream", "a".repeat(width)),
                    ("--expected-target", "a".repeat(width)),
                    ("--expected-source", "0".repeat(width)),
                    (
                        "--expected-target",
                        "b".repeat(if width == 40 { 64 } else { 40 }),
                    ),
                ] {
                    let mut bad = input.clone();
                    change(&mut bad, flag, value);
                    assert!(parse(&bad).is_err(), "{flag}");
                }
                let mut bad = input;
                bad.retain(|value| value != "--trusted-local");
                assert!(parse(&bad).is_err());
            }
        }
    }

    #[test]
    fn preparation_is_explicit_and_limits_cannot_exceed_inspectable_series() {
        let input = args(40, true);
        let options = parse(&input).unwrap();
        assert!(
            matches!(options.operation, Operation::Prepare { limits, empty: EmptyCommitPolicy::Stop, .. } if limits.max_commits == 256)
        );
        for flag in ["--profile", "--committer", "--timestamp"] {
            let mut bad = input.clone();
            let at = bad.iter().position(|value| value == flag).unwrap();
            bad.drain(at..at + 2);
            assert!(parse(&bad).is_err());
        }
        for (flag, value) in [
            ("--max-commits", "257"),
            ("--max-commits", "0"),
            ("--empty", "auto"),
            ("--candidate", "dddd"),
        ] {
            let mut bad = input.clone();
            bad.extend([flag.into(), value.into()]);
            assert!(parse(&bad).is_err());
        }
        for empty in ["stop", "drop", "keep"] {
            let mut good = input.clone();
            good.extend([
                "--empty".into(),
                empty.into(),
                "--max-commits".into(),
                "2".into(),
            ]);
            assert!(parse(&good).is_ok());
        }
    }

    #[test]
    fn inspection_requires_complete_scope_and_the_exact_candidate() {
        for width in [40, 64] {
            let input = args(width, false);
            for (flag, value) in [
                ("--path", "hidden.txt"),
                ("--comparison", "merge-base"),
                ("--context-lines", "21"),
                ("--max-output-bytes", "0"),
                ("--profile", "path-v1"),
            ] {
                let mut bad = input.clone();
                bad.extend([flag.into(), value.into()]);
                assert!(parse(&bad).is_err());
            }
            let mut bad = input.clone();
            change(&mut bad, "--candidate", "b".repeat(width));
            assert!(parse(&bad).is_err());
            let mut bad = input;
            bad.truncate(bad.len() - 2);
            assert!(parse(&bad).is_err());
        }
    }

    #[test]
    fn byte_refs_have_one_unambiguous_spelling() {
        for prepare in [false, true] {
            let mut good = args(40, prepare);
            let at = good
                .iter()
                .position(|value| value == "--source-ref")
                .unwrap();
            good[at] = "--source-ref-hex".into();
            good[at + 1] = hex(b"refs/heads/topic-\xff");
            assert_eq!(
                parse(&good).unwrap().subject.source_ref.as_bytes(),
                b"refs/heads/topic-\xff"
            );
            good.extend(["--source-ref".into(), "refs/heads/other".into()]);
            assert!(parse(&good).is_err());
        }
    }

    fn head() -> RepositoryAuthorityHeadId {
        RepositoryAuthorityHeadId::from_digest(
            fgit_types::DigestAlgorithmId::try_new(2).unwrap(),
            fgit_types::CANONICAL_CODEC_VERSION,
            fgit_types::DigestBytes::try_new(&[7; 32]).unwrap(),
        )
    }

    #[test]
    fn stopped_preparation_never_claims_a_candidate_or_allows_a_partial_bundle() {
        let options = parse(&args(40, true)).unwrap();
        let mut artifact = PreparedPullRequestRebaseBundle {
            source_head: head(),
            subject: options.subject.clone(),
            preparation: fgit_node::PreparedRebaseBundle {
                source_head: head(),
                outcome: RebasePreparation::Stopped {
                    request: RebaseRequest {
                        source_tip: options.subject.source_tip,
                        upstream: options.upstream,
                        onto: options.subject.target_tip,
                        empty: EmptyCommitPolicy::Stop,
                    },
                    original: options.subject.source_tip,
                    completed: vec![],
                    reason: RebaseStop::BecameEmpty,
                },
                bundle: None,
                pack_objects: 0,
                borrowed_objects: 0,
            },
        };
        let (receipt, code) = render_preparation(&options, &artifact).unwrap();
        assert_eq!(code, 3);
        assert!(receipt.contains("\"outcome\":\"became_empty\""));
        assert!(receipt.contains("\"candidate_commit\":null"));
        assert!(receipt.contains("\"bundle_created\":false"));
        assert!(receipt.contains("\"published_to_repository\":false"));
        artifact.preparation.bundle = Some(b"partial".to_vec());
        assert!(render_preparation(&options, &artifact).is_err());
        artifact.preparation.bundle = None;
        artifact.subject.pull_request_version = AggregateVersion::try_new(5).unwrap();
        assert!(render_preparation(&options, &artifact).is_err());
    }

    #[test]
    fn full_inspection_retains_transient_changes_and_non_utf8_commit_bodies() {
        use fgit_forge::review::{ChangeKind, EntryIdentity, ReviewContent, ReviewedEntry};
        for width in [40, 64] {
            let options = parse(&args(width, false)).unwrap();
            let Operation::Inspect { candidate, .. } = &options.operation else {
                unreachable!()
            };
            let id = |byte: &str| parse_oid(&byte.repeat(width)).unwrap();
            let first = id("e");
            let old_tree = id("1");
            let intermediate_tree = id("2");
            let tree = id("3");
            let entry = EntryIdentity {
                mode: 0o100644,
                oid: id("4"),
            };
            let comparison = |before, after, before_tree, after_tree, entries| SourceComparison {
                mode: ComparisonMode::Direct,
                requested_before: before,
                requested_after: after,
                compared_before: before,
                before_tree,
                after_tree,
                entries,
            };
            let bytes = b"untrusted serialized bundle";
            let mut report = RebaseBundleInspection {
                repository_id: options.repository,
                source_head: head(),
                source_reference: options.subject.source_ref.clone(),
                onto_reference: options.subject.target_ref.clone(),
                expected_source: options.subject.source_tip,
                onto: options.subject.target_tip,
                candidate: *candidate,
                commits: vec![
                    fgit_node::InspectedRebaseCommit {
                        id: first,
                        parent: options.subject.target_tip,
                        tree: intermediate_tree,
                        body: b"first commit body\xff\n".to_vec(),
                    },
                    fgit_node::InspectedRebaseCommit {
                        id: *candidate,
                        parent: first,
                        tree,
                        body: b"second commit body\n".to_vec(),
                    },
                ],
                comparisons: vec![
                    comparison(
                        options.subject.source_tip,
                        *candidate,
                        old_tree,
                        tree,
                        vec![],
                    ),
                    comparison(
                        options.subject.target_tip,
                        first,
                        old_tree,
                        intermediate_tree,
                        vec![ReviewedEntry {
                            path: b"transient.bin".to_vec(),
                            before: None,
                            after: Some(entry),
                            kind: ChangeKind::Added,
                            content: ReviewContent::Binary {
                                before_bytes: 0,
                                after_bytes: 2,
                            },
                        }],
                    ),
                    comparison(
                        first,
                        *candidate,
                        intermediate_tree,
                        tree,
                        vec![ReviewedEntry {
                            path: b"transient.bin".to_vec(),
                            before: Some(entry),
                            after: None,
                            kind: ChangeKind::Deleted,
                            content: ReviewContent::Binary {
                                before_bytes: 2,
                                after_bytes: 0,
                            },
                        }],
                    ),
                ],
                bundle: fgit_node::InspectedBundle {
                    sha256: sha256_digest(bytes),
                    bytes: bytes.len(),
                    pack_bytes: bytes.len(),
                    pack_objects: 2,
                    expanded_bytes: 30,
                    closure_objects: 5,
                    transport_only_objects: 0,
                },
            };
            let receipt = render_inspection(&options, bytes, &report).unwrap();
            assert!(receipt.contains("\"scope\":\"all_paths_all_commits\""));
            assert_eq!(receipt.matches(&hex(b"transient.bin")).count(), 2);
            assert!(receipt.contains(&hex(b"first commit body\xff\n")));
            assert!(receipt.contains("\"commit_text\":null"));
            assert!(receipt.contains("\"change\":\"Added\""));
            assert!(receipt.contains("\"change\":\"Deleted\""));
            assert!(receipt.contains("\"approval_granted\":false"));
            report.comparisons.swap(1, 2);
            assert!(render_inspection(&options, bytes, &report).is_err());
            report.comparisons.swap(1, 2);
            report.commits[1].parent = options.subject.target_tip;
            assert!(render_inspection(&options, bytes, &report).is_err());
        }
    }
}
