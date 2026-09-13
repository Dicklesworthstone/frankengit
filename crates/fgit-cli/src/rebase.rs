//! Native branch rebase preparation, with a separate publication boundary.
use crate::commit_replay::{decimal, hex, parse_head, token, unhex, write_receipt};
use crate::merge_apply::preparation::{publish_new_bundle, render_conflict, require_absent};
use crate::publication_support::{parse_oid, quote};
use fgit_crypto::sha256_digest;
use fgit_forge::preparation::PreparationLimits;
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, RebaseCommitter, RebasePreparation, RebaseRequest, RebaseStep,
    RebaseStepKind, RebaseStop,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{HeadGeneration, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use std::collections::BTreeMap;
use std::path::PathBuf;

const USAGE: &str = "usage: fg rebase prepare <storage-root> <tenant-id> <repository-id> <source-ref> <output-bundle>\n  --trusted-local --profile path-v1 --onto-ref <visible-branch>\n  --expected-source <tip> --expected-onto <tip> --upstream <exclusive-old-base>\n  --committer <name-and-email> --timestamp <unix-seconds>\n  [--empty stop|drop|keep] [--expected-head <snapshot-token>]\n  [--source-ref-hex] [--onto-ref-hex <bytes>]\n  [--max-commits <n>] [--max-edges <n>] [--max-output-bytes <n>]\n\nReplay the linear suffix (upstream, source] onto the exact target, oldest first.\nOriginal author/time/timezone, message bytes and encoding are preserved; old\nsignatures are not reused. Merge commits in the suffix refuse. A conflict or\nnewly-empty stop creates no partial bundle. Original empty commits are kept.\nThe output has onto as its sole prerequisite. Preparation moves no ref and\nstages no objects. Review and publish separately with an exact expected-old\nreceive operation; workspace apply is single-commit and is not this operation.\nExit 0: prepared; 3: conflict or newly-empty stop; 2: input/infrastructure error.";

struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    source: RefName,
    onto: RefName,
    output: PathBuf,
    inputs: RebaseRequest,
    head: Option<RepositoryAuthorityHeadId>,
    committer: RebaseCommitter,
    limits: PreparationLimits,
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] || args == ["prepare", "--help"] {
        write_receipt(&mut std::io::stdout().lock(), USAGE, false)?;
        return Ok(0);
    }
    let options = parse(args)?;
    require_absent(&options.output)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.inputs.source_tip.algorithm()),
    )
    .map_err(|e| e.to_string())?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|e| e.to_string())?;
        let request = node.request_context();
        node.runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &request,
                &options.source,
                &options.onto,
                options.inputs,
                &Default::default(),
                options.head,
                &options.committer,
                options.limits,
            ))
            .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let artifact = match (result, cleanup) {
        (Ok(artifact), None) => artifact,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => {
            return Err(format!(
                "node shutdown failed: {error}; no bundle published"
            ));
        }
        (Err(error), Some(cleanup)) => {
            return Err(format!(
                "{error}; node shutdown failed: {cleanup}; no bundle published"
            ));
        }
    };
    let (receipt, code) = render(
        &options,
        artifact.source_head,
        &artifact.outcome,
        artifact.bundle.as_deref(),
        artifact.pack_objects,
        artifact.borrowed_objects,
    )?;
    if let Some(bundle) = artifact.bundle.as_ref() {
        publish_new_bundle(&options.output, bundle)?;
    }
    write_receipt(
        &mut std::io::stdout().lock(),
        &receipt,
        artifact.bundle.is_some(),
    )?;
    Ok(code)
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 6 || args[0] != "prepare" {
        return Err(USAGE.into());
    }
    if args.len() > 48
        || args.iter().any(|s| s.len() > 64 * 1024)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    {
        return Err("rebase arguments exceed the bounded profile".into());
    }
    if [args[1].as_str(), args[5].as_str()]
        .iter()
        .any(|s| s.is_empty() || s.len() > 4096)
    {
        return Err("storage and output paths must be nonempty and bounded".into());
    }
    let tenant = TenantId::from_hex(&args[2]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[3]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new();
    let mut at = 6;
    while at < args.len() {
        let flag = args[at].as_str();
        at += 1;
        let switch = matches!(flag, "--trusted-local" | "--source-ref-hex");
        if !switch
            && !matches!(
                flag,
                "--profile"
                    | "--onto-ref"
                    | "--onto-ref-hex"
                    | "--expected-source"
                    | "--expected-onto"
                    | "--upstream"
                    | "--committer"
                    | "--timestamp"
                    | "--empty"
                    | "--expected-head"
                    | "--max-commits"
                    | "--max-edges"
                    | "--max-output-bytes"
            )
        {
            return Err(format!("unknown rebase option {flag:?}"));
        }
        let value = if switch {
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
    if flags.get("--profile") != Some(&"path-v1") {
        return Err("explicit --profile path-v1 is required".into());
    }
    let required = |name| {
        flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is required"))
    };
    let source = if flags.contains_key("--source-ref-hex") {
        unhex(&args[4], 4096)?
    } else {
        args[4].as_bytes().to_vec()
    };
    let onto = match (flags.get("--onto-ref"), flags.get("--onto-ref-hex")) {
        (Some(value), None) if value.len() <= 4096 => value.as_bytes().to_vec(),
        (None, Some(value)) => unhex(value, 4096)?,
        _ => return Err("exactly one bounded --onto-ref or --onto-ref-hex is required".into()),
    };
    if [source.as_slice(), onto.as_slice()]
        .iter()
        .any(|r| r.len() > 4096 || !r.starts_with(b"refs/heads/"))
        || source == onto
    {
        return Err("source and onto must be distinct fully qualified bounded branches".into());
    }
    let source = RefName::try_new(&source).map_err(|_| "invalid source reference")?;
    let onto = RefName::try_new(&onto).map_err(|_| "invalid onto reference")?;
    let source_tip = parse_oid(required("--expected-source")?)?;
    let onto_tip = parse_oid(required("--expected-onto")?)?;
    let upstream = parse_oid(required("--upstream")?)?;
    if [source_tip, onto_tip, upstream]
        .iter()
        .any(|id| id.is_zero() || id.algorithm() != source_tip.algorithm())
    {
        return Err("all native identities must be nonzero and use the same format".into());
    }
    let empty = match flags.get("--empty").copied().unwrap_or("stop") {
        "stop" => EmptyCommitPolicy::Stop,
        "drop" => EmptyCommitPolicy::Drop,
        "keep" => EmptyCommitPolicy::Keep,
        _ => return Err("--empty must be stop, drop, or keep".into()),
    };
    let committer = RebaseCommitter {
        identity: required("--committer")?.to_owned(),
        timestamp: decimal(required("--timestamp")?)?,
    };
    committer.validate().map_err(|e| e.to_string())?;
    let mut limits = PreparationLimits::default();
    for (name, field) in [
        ("--max-commits", &mut limits.max_commits),
        ("--max-edges", &mut limits.max_edges),
        ("--max-output-bytes", &mut limits.max_output_bytes),
    ] {
        if let Some(value) = flags.get(name) {
            *field = usize::try_from(decimal(value)?).map_err(|_| "limit exceeds target width")?;
        }
    }
    limits.validate().map_err(|e| e.to_string())?;
    let head = flags
        .get("--expected-head")
        .map(|s| parse_head(s))
        .transpose()?;
    let output = PathBuf::from(&args[5]);
    if output.file_name().is_none() {
        return Err("output must name a new file".into());
    }
    Ok(Options {
        storage: args[1].clone().into(),
        tenant,
        repository,
        source,
        onto,
        output,
        inputs: RebaseRequest {
            source_tip,
            upstream,
            onto: onto_tip,
            empty,
        },
        head,
        committer,
        limits,
    })
}

fn render(
    options: &Options,
    head: RepositoryAuthorityHeadId,
    outcome: &RebasePreparation,
    bundle: Option<&[u8]>,
    pack_objects: usize,
    borrowed_objects: usize,
) -> Result<(String, u8), String> {
    if options.head.is_some_and(|h| h != head) {
        return Err("rebase snapshot binding mismatch".into());
    }
    let (request, steps, label, code, detail) = match outcome {
        RebasePreparation::Clean(plan) => {
            let bytes = bundle
                .filter(|b| !b.is_empty())
                .ok_or("clean rebase omitted the bundle")?;
            if borrowed_objects > pack_objects
                || plan.steps.len() > options.limits.max_commits
                || plan.objects.len() > options.limits.max_objects
                || plan.commit.is_zero()
                || plan.commit.algorithm() != options.inputs.source_tip.algorithm()
                || (plan.steps.is_empty() && plan.commit != options.inputs.onto)
                || plan.steps.last().is_some_and(|s| {
                    s.rewritten != plan.commit
                        || s.tree != plan.tree
                        || s.original != options.inputs.source_tip
                })
            {
                return Err("rebase candidate/step accounting mismatch".into());
            }
            (
                &plan.request,
                plan.steps.as_slice(),
                "prepared",
                0,
                format!(
                    concat!(
                        "\"candidate_commit\":{},\"root_tree\":{},",
                        "\"generated_objects\":{},\"pack_objects\":{},\"borrowed_objects\":{},\"bundle_bytes\":{},\"bundle_sha256\":{}"
                    ),
                    quote(&plan.commit.to_string()),
                    quote(&plan.tree.to_string()),
                    plan.objects.len(),
                    pack_objects,
                    borrowed_objects,
                    bytes.len(),
                    quote(&hex(&sha256_digest(bytes)))
                ),
            )
        }
        RebasePreparation::Stopped {
            request,
            original,
            completed,
            reason,
        } => {
            if bundle.is_some()
                || pack_objects != 0
                || borrowed_objects != 0
                || completed.len() >= options.limits.max_commits
            {
                return Err("stopped rebase carried an artifact or invalid step count".into());
            }
            let (label, details) = match reason {
                RebaseStop::Conflicted(conflicts) if !conflicts.is_empty() => (
                    "conflicted",
                    format!(
                        "\"conflicts\":[{}]",
                        conflicts
                            .iter()
                            .map(render_conflict)
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                ),
                RebaseStop::BecameEmpty => {
                    ("became_empty", "\"requires_empty_policy\":true".into())
                }
                _ => return Err("empty conflict report".into()),
            };
            (
                request,
                completed.as_slice(),
                label,
                3,
                format!(
                    "\"candidate_commit\":null,\"stopped_commit\":{},{}",
                    quote(&original.to_string()),
                    details
                ),
            )
        }
    };
    if *request != options.inputs {
        return Err("rebase input binding mismatch".into());
    }
    let mut unique = std::collections::BTreeSet::new();
    for step in steps {
        if !unique.insert(step.original)
            || [step.original, step.rewritten, step.tree]
                .iter()
                .any(|id| id.is_zero() || id.algorithm() != request.source_tip.algorithm())
        {
            return Err("rebase step identity mismatch".into());
        }
    }
    let receipt = format!(
        concat!(
            "{{\"type\":\"rebase_preparation\",\"schema_version\":1,\"profile\":\"path-v1\",",
            "\"outcome\":{},\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"snapshot_token\":{},",
            "\"source_reference_hex\":{},\"onto_reference_hex\":{},\"expected_source\":{},\"expected_onto\":{},\"upstream\":{},",
            "\"committer\":{},\"timestamp\":{},\"empty_policy\":{},\"steps\":[{}],",
            "\"bundle_created\":{},\"bundle_path\":{},\"published_to_repository\":false,\"objects_staged\":false,",
            "\"approval_granted\":false,\"node_closed\":true,{}}}"
        ),
        quote(label),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(request.source_tip.algorithm().as_str()),
        quote(&token(head)),
        quote(&hex(options.source.as_bytes())),
        quote(&hex(options.onto.as_bytes())),
        quote(&request.source_tip.to_string()),
        quote(&request.onto.to_string()),
        quote(&request.upstream.to_string()),
        quote(&options.committer.identity),
        options.committer.timestamp,
        quote(match request.empty {
            EmptyCommitPolicy::Stop => "stop",
            EmptyCommitPolicy::Drop => "drop",
            EmptyCommitPolicy::Keep => "keep",
        }),
        steps.iter().map(render_step).collect::<Vec<_>>().join(","),
        bundle.is_some(),
        bundle.map_or_else(
            || "null".into(),
            |_| quote(&options.output.to_string_lossy())
        ),
        detail
    );
    if receipt.len() > 4 * 1024 * 1024 {
        return Err("rebase receipt exceeds output bound".into());
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
        })
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(width: usize) -> Vec<String> {
        [
            "prepare",
            "node",
            &"11".repeat(16),
            &"22".repeat(16),
            "refs/heads/topic",
            "out.bundle",
            "--trusted-local",
            "--profile",
            "path-v1",
            "--onto-ref",
            "refs/heads/main",
            "--expected-source",
            &"a".repeat(width),
            "--expected-onto",
            &"b".repeat(width),
            "--upstream",
            &"c".repeat(width),
            "--committer",
            "T <t@x>",
            "--timestamp",
            "2",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }
    #[test]
    fn exact_pins_profile_and_new_committer_are_required_and_unique() {
        for width in [40, 64] {
            let input = args(width);
            let o = parse(&input).unwrap();
            assert_eq!(o.inputs.empty, EmptyCommitPolicy::Stop);
            for flag in [
                "--profile",
                "--onto-ref",
                "--expected-source",
                "--expected-onto",
                "--upstream",
                "--committer",
                "--timestamp",
            ] {
                let at = input.iter().position(|s| s == flag).unwrap();
                let mut missing = input.clone();
                missing.drain(at..at + 2);
                assert!(parse(&missing).is_err());
                let mut dup = input.clone();
                dup.extend([flag.into(), input[at + 1].clone()]);
                assert!(parse(&dup).is_err());
            }
            let mut missing = input;
            missing.retain(|s| s != "--trusted-local");
            assert!(parse(&missing).is_err());
        }
    }
    #[test]
    fn unsupported_mutation_options_domains_and_budget_expansions_refuse() {
        for extra in [
            ["--force", "true"],
            ["--empty", "guess"],
            ["--author", "Somebody"],
            ["--message", "rewrite"],
            ["--max-commits", "0"],
            ["--max-output-bytes", "33554433"],
            ["--timestamp", "02"],
        ] {
            let mut input = args(40);
            input.extend(extra.map(str::to_owned));
            assert!(parse(&input).is_err());
        }
        let mut mixed = args(40);
        let at = mixed.iter().position(|s| s == "--upstream").unwrap();
        mixed[at + 1] = "a".repeat(64);
        assert!(parse(&mixed).is_err());
        let mut same = args(40);
        same[4] = "refs/heads/main".into();
        assert!(parse(&same).is_err());
    }
    #[test]
    fn raw_branch_names_head_tokens_and_empty_policies_are_preserved() {
        for policy in ["stop", "drop", "keep"] {
            let mut input = args(64);
            input[4] = hex(b"refs/heads/\xff");
            input.push("--source-ref-hex".into());
            let at = input.iter().position(|s| s == "--onto-ref").unwrap();
            input[at] = "--onto-ref-hex".into();
            input[at + 1] = hex(b"refs/heads/\xfe");
            input.extend([
                "--empty".into(),
                policy.into(),
                "--expected-head".into(),
                format!("alg:1:{}", "ab".repeat(32)),
            ]);
            let o = parse(&input).unwrap();
            assert_eq!(o.source.as_bytes(), b"refs/heads/\xff");
            assert_eq!(o.onto.as_bytes(), b"refs/heads/\xfe");
            assert_eq!(token(o.head.unwrap()), format!("alg:1:{}", "ab".repeat(32)));
        }
    }
    #[test]
    fn stopped_receipts_never_advertise_a_partial_candidate_or_bundle() {
        let o = parse(&args(40)).unwrap();
        let head = parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap();
        let stopped = RebasePreparation::Stopped {
            request: o.inputs,
            original: o.inputs.source_tip,
            completed: vec![],
            reason: RebaseStop::BecameEmpty,
        };
        let (text, code) = render(&o, head, &stopped, None, 0, 0).unwrap();
        assert_eq!(code, 3);
        assert!(
            text.contains("\"candidate_commit\":null")
                && text.contains("\"bundle_created\":false")
                && text.contains("\"objects_staged\":false")
        );
        assert!(render(&o, head, &stopped, Some(b"bad"), 1, 0).is_err());
    }
    #[test]
    fn malformed_options_refuse_without_opening_a_repository() {
        assert!(run(&["continue".into()]).is_err());
        let mut input = args(40);
        input.push("--onto-ref".into());
        assert!(run(&input).is_err());
        let mut input = args(40);
        input[5].clear();
        assert!(parse(&input).is_err());
    }
}
