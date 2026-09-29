//! Read canonical workflow observations without opening an execution or write path.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use fgit_forge::PullRequestNumber;
use fgit_forge::event::workflow_check::{WorkflowCheckConclusion, WorkflowCheckId};
use fgit_node::{NodeConfig, OneNode, PullRequestChecksPage, WorkflowCheckSummary};
use fgit_types::{GitHashAlgorithm, RepositoryAuthorityHeadId, RepositoryId, TenantId};

use super::options::{decimal, head_token, hex, parse_head};
use crate::publication_support::quote;

const USAGE: &str = "\
usage: fg pr checks <storage-root> <tenant-id> <repository-id> <number> --trusted-local
  [--object-format sha1|sha256] [--limit <1..100>]
  [--after <check/id> --expected-head <snapshot-token>]

Read immutable workflow observations for the PR's recorded source commit at one
authenticated snapshot. Continue with both next_after and snapshot_token.
source_current=false means the source branch moved without a matching PR refresh;
that page contains no current checks. Local success is action_required, not an
independent successful check or permission to merge. Evidence is summarized by
SHA-256 and byte length; raw execution evidence is not included.
Exit 0: complete page; 4: PR absent or hidden; 2: input/read/cleanup/output error.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    number: PullRequestNumber,
    format: GitHashAlgorithm,
    after: Option<WorkflowCheckId>,
    limit: u16,
    head: Option<RepositoryAuthorityHeadId>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 5 || args.len() > 15 {
        return Err(USAGE.into());
    }
    if args.iter().any(|arg| arg.len() > 4096) || args[0].is_empty() {
        return Err("check arguments exceed the bounded local profile".into());
    }
    let mut flags = BTreeMap::new();
    let mut trusted = false;
    let mut cursor = 4;
    while cursor < args.len() {
        let flag = args[cursor].as_str();
        cursor += 1;
        if flag == "--trusted-local" {
            if trusted {
                return Err("duplicate --trusted-local".into());
            }
            trusted = true;
            continue;
        }
        if !matches!(
            flag,
            "--object-format" | "--after" | "--limit" | "--expected-head"
        ) {
            return Err(format!("unsupported check option: {flag}"));
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        if flags.insert(flag, value.as_str()).is_some() {
            return Err(format!("duplicate {flag}"));
        }
    }
    if !trusted {
        return Err("local checks read requires --trusted-local".into());
    }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1,
        "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("unsupported object format".into()),
    };
    let limit = decimal(flags.get("--limit").copied().unwrap_or("20"))?;
    if !(1..=100).contains(&limit) {
        return Err("check limit must be 1..100".into());
    }
    let after = flags
        .get("--after")
        .map(|text| {
            WorkflowCheckId::from_label(text).ok_or("invalid canonical check cursor".to_owned())
        })
        .transpose()?;
    let head = flags
        .get("--expected-head")
        .map(|text| parse_head(text))
        .transpose()?;
    if after.is_some() && head.is_none() {
        return Err("check continuation requires --expected-head".into());
    }
    Ok(Options {
        storage: args[0].clone().into(),
        tenant: TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?,
        repository: RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?,
        number: PullRequestNumber::try_new(decimal(&args[3])?)
            .ok_or("positive PR number required")?,
        format,
        after,
        limit: u16::try_from(limit).map_err(|_| "invalid limit")?,
        head,
    })
}

pub(super) fn run(args: &[String], out: &mut impl Write) -> Result<u8, String> {
    if args == ["--help"] {
        writeln!(out, "{USAGE}").map_err(|e| format!("check help output failed: {e}"))?;
        return Ok(0);
    }
    let options = parse(args)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|e| format!("cannot open checks node: {e}"))?;
    let incarnation = node.repository_incarnation_id();
    let operation = (|| -> Result<_, String> {
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .map_err(|e| e.to_string())?;
        node.bring_into_service(head.receipt().generation())
            .map_err(|e| e.to_string())?;
        let request = fgit_cli::command_request_context(&node);
        node.runtime()
            .block_on(node.read_pull_request_checks_in(
                &request,
                &Default::default(),
                options.number,
                options.after,
                options.limit,
                options.head,
            ))
            .map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown();
    let page = match (operation, cleanup) {
        (Ok(page), Ok(())) => page,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(format!("checks node shutdown failed: {error}")),
        (Err(error), Err(cleanup)) => {
            return Err(format!("{error}; node shutdown also failed: {cleanup}"));
        }
    };
    let receipt = render(&options, &incarnation.to_string(), page.as_ref())?;
    writeln!(out, "{receipt}")
        .map_err(|e| format!("checks output failed: {e}; no complete page returned"))?;
    out.flush()
        .map_err(|e| format!("checks output flush failed: {e}"))?;
    Ok(if page.is_some() { 0 } else { 4 })
}

fn render(
    options: &Options,
    incarnation: &str,
    page: Option<&PullRequestChecksPage>,
) -> Result<String, String> {
    let scope = format!(
        "\"type\":\"pull_request_checks\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"number\":{},\"scope\":\"trusted_workflow_observations\",\"merge_permission\":null,\"node_closed\":true,\"after\":{},\"limit\":{}",
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(incarnation),
        quote(options.format.as_str()),
        quote(&options.number.get().to_string()),
        options
            .after
            .map_or_else(|| "null".into(), |id| quote(&id.to_string())),
        options.limit,
    );
    let Some(page) = page else {
        return Ok(format!(
            "{{{scope},\"found\":false,\"source_head\":null,\"snapshot_token\":null,\"pull_request_version\":null,\"source_ref_hex\":null,\"target_ref_hex\":null,\"source_tip\":null,\"target_tip\":null,\"source_current\":null,\"next_after\":null,\"complete\":true,\"checks\":[]}}"
        ));
    };
    page.validate_window(options.number, options.after, options.limit, options.head)
        .map_err(|_| "workflow check page binding/order mismatch")?;
    if page.source_tip.algorithm() != options.format
        || page.target_tip.algorithm() != options.format
    {
        return Err("workflow check page binding/order mismatch".into());
    }
    let rows = page
        .checks
        .iter()
        .map(render_check)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{{scope},\"found\":true,\"source_head\":{},\"snapshot_token\":{},\"pull_request_version\":{},\"source_ref_hex\":{},\"target_ref_hex\":{},\"source_tip\":{},\"target_tip\":{},\"source_current\":{},\"next_after\":{},\"complete\":{},\"checks\":[{rows}]}}",
        quote(&page.source_head.to_string()),
        quote(&head_token(page.source_head)),
        quote(&page.pull_request_version.get().to_string()),
        quote(&hex(page.source_ref.as_bytes())),
        quote(&hex(page.target_ref.as_bytes())),
        quote(&page.source_tip.to_string()),
        quote(&page.target_tip.to_string()),
        page.source_current,
        page.next_after
            .map_or_else(|| "null".into(), |id| quote(&id.to_string())),
        page.next_after.is_none(),
    ))
}

fn render_check(row: &WorkflowCheckSummary) -> String {
    let conclusion = match row.conclusion {
        WorkflowCheckConclusion::ActionRequired => "action_required",
        WorkflowCheckConclusion::Failure => "failure",
        WorkflowCheckConclusion::Cancelled => "cancelled",
        WorkflowCheckConclusion::TimedOut => "timed_out",
    };
    format!(
        "{{\"id\":{},\"publisher\":{},\"run_id\":{},\"attempt_id\":{},\"graph_root\":{},\"job\":{},\"conclusion\":{},\"evidence_sha256\":{},\"evidence_bytes\":{}}}",
        quote(&row.id.to_string()),
        quote(&row.publisher.to_string()),
        quote(&hex(&row.run_id)),
        quote(&hex(&row.attempt_id)),
        quote(&hex(&row.graph_root)),
        quote(&row.job),
        quote(conclusion),
        quote(&hex(&row.evidence_sha256)),
        quote(&row.evidence_bytes.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        vec![
            "node".into(),
            "11".repeat(16),
            "22".repeat(16),
            "1".into(),
            "--trusted-local".into(),
        ]
    }
    #[test]
    fn checks_refuse_ambiguous_cursors_limits_and_mutation_flags_before_io() {
        assert_eq!(parse(&args()).unwrap().limit, 20);
        for extra in [
            vec![
                "--after".into(),
                WorkflowCheckId::from_bytes([1; 32]).to_string(),
            ],
            vec!["--limit".into(), "0".into()],
            vec!["--limit".into(), "101".into()],
            vec!["--limit".into(), "01".into()],
            vec!["--principal".into(), "33".repeat(16)],
            vec!["--trusted-local".into()],
            vec!["--expected-head".into(), "latest".into()],
        ] {
            let mut input = args();
            input.extend(extra);
            assert!(parse(&input).is_err());
        }
        let mut input = args();
        input.pop();
        assert!(parse(&input).is_err());
        let mut input = args();
        input.extend([
            "--after".into(),
            WorkflowCheckId::from_bytes([1; 32]).to_string(),
            "--expected-head".into(),
            format!("alg:2:{}", "44".repeat(32)),
        ]);
        assert!(parse(&input).is_ok());
    }
    #[test]
    fn checks_output_escapes_untrusted_job_names_without_disclosing_evidence() {
        let row = WorkflowCheckSummary {
            id: WorkflowCheckId::from_bytes([1; 32]),
            publisher: fgit_types::PrincipalId::from_bytes([2; 16]),
            run_id: [3; 32],
            attempt_id: [4; 32],
            graph_root: [5; 32],
            job: "build\"<script>é</script>".into(),
            conclusion: WorkflowCheckConclusion::ActionRequired,
            evidence_sha256: [6; 32],
            evidence_bytes: 123,
        };
        let encoded = render_check(&row);
        assert!(encoded.contains(r#""job":"build\"<script>é</script>""#));
        assert!(encoded.contains(r#""conclusion":"action_required""#));
        assert!(encoded.contains(r#""evidence_bytes":"123""#));
        assert!(!encoded.contains(r#""evidence":"#));
    }
}
