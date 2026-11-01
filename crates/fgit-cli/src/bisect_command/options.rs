use super::{Query, USAGE};
use fgit_forge::event::issue::IssueState;
use fgit_forge::event::workflow_check::{MAX_CHECK_JOB_BYTES, WorkflowCheckConclusion};
use fgit_forge::{IssueNumber, PullRequestNumber};
use fgit_node::source_retrieval::bisection::{MAX_PROBES, Predicate, PullState};
use fgit_types::{
    CodecVersion, DecisionSequence, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    PolicyEpoch, PrincipalId, RefName, RepositoryAuthorityHeadId, RepositoryId,
    RepositoryIncarnationId, TenantId,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
#[cfg(test)]
mod tests;
pub(super) struct Options {
    pub storage: PathBuf,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub incarnation: Option<RepositoryIncarnationId>,
    pub query: Query,
}
fn positive(text: &str, max: u64) -> Result<u64, String> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected canonical positive integer".into());
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= max)
        .ok_or_else(|| "integer outside supported range".into())
}
fn head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let fields: Vec<_> = text.split(':').collect();
    if fields.len() != 6 || fields[0] != "head" || fields[1] != "alg" || fields[3] != "codec" {
        return Err("expected exact source_head token from fg bisect".into());
    }
    let algorithm = DigestAlgorithmId::try_new(positive(fields[2], u16::MAX as u64)? as u16)
        .map_err(|e| e.to_string())?;
    let (major, minor) = fields[4].split_once('.').ok_or("invalid codec version")?;
    let number = |s: &str| {
        s.parse::<u16>()
            .ok()
            .filter(|n| n.to_string() == s)
            .ok_or("invalid codec version")
    };
    let version = CodecVersion::new(number(major)?, number(minor)?);
    let h = fields[5];
    if h.is_empty()
        || h.len() > 128
        || h.len() % 2 != 0
        || !h
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid snapshot digest".into());
    }
    let bytes = (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("validated hex"))
        .collect::<Vec<_>>();
    let digest = DigestBytes::try_new(&bytes).map_err(|e| e.to_string())?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm, version, digest,
    ))
}
fn native_oid(text: &str) -> Result<GitOid, String> {
    let format = match text.len() {
        40 => GitHashAlgorithm::Sha1,
        64 => GitHashAlgorithm::Sha256,
        _ => return Err("native OID must be 40 or 64 lowercase hex characters".into()),
    };
    GitOid::from_hex(format, text).map_err(|e| e.to_string())
}
fn graph_root(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("workflow graph root must be 64 lowercase hex characters".into());
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("validated hex");
    }
    Ok(bytes)
}
fn workflow_check(job: &str, flags: &mut BTreeMap<&str, &str>) -> Result<Predicate, String> {
    if job.is_empty() || job.len() > MAX_CHECK_JOB_BYTES || job.chars().any(char::is_control) {
        return Err("workflow job must be 1..=1024 UTF-8 bytes without control characters".into());
    }
    let mut required = |flag| {
        flags
            .remove(flag)
            .ok_or_else(|| format!("--check-job requires {flag}"))
    };
    let source_ref =
        RefName::try_new(required("--check-ref")?.as_bytes()).map_err(|e| e.to_string())?;
    if !source_ref.as_bytes().starts_with(b"refs/heads/") {
        return Err("workflow check source must be a full refs/heads/ branch name".into());
    }
    let source_commit = native_oid(required("--check-commit")?)?;
    if source_commit.is_zero() {
        return Err("workflow check source commit must be a nonzero native OID".into());
    }
    let publisher =
        PrincipalId::from_hex(required("--check-publisher")?).map_err(|e| e.to_string())?;
    let graph_root = graph_root(required("--check-graph")?)?;
    let conclusion = match required("--check-conclusion")? {
        "action_required" => WorkflowCheckConclusion::ActionRequired,
        "success" => WorkflowCheckConclusion::Success,
        "failure" => WorkflowCheckConclusion::Failure,
        "cancelled" => WorkflowCheckConclusion::Cancelled,
        "timed_out" => WorkflowCheckConclusion::TimedOut,
        _ => {
            return Err(
                "workflow conclusion must be action_required, success, failure, cancelled or timed_out"
                    .into(),
            );
        }
    };
    Ok(Predicate::WorkflowCheck {
        source_ref,
        source_commit,
        publisher,
        graph_root,
        job: job.to_owned(),
        conclusion,
    })
}
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 6
        || args.len() > 26
        || args[0].is_empty()
        || args.iter().any(|s| s.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let tenant = TenantId::from_hex(&args[1]).map_err(|e| e.to_string())?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|e| e.to_string())?;
    let mut flags = BTreeMap::new();
    let mut i = 3;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        let value = match flag {
            "--trusted-local" | "--absent" => "",
            "--start"
            | "--end"
            | "--max-probes"
            | "--expected-head"
            | "--expected-incarnation"
            | "--ref"
            | "--equals"
            | "--issue"
            | "--pull"
            | "--state"
            | "--check-job"
            | "--check-ref"
            | "--check-commit"
            | "--check-publisher"
            | "--check-graph"
            | "--check-conclusion"
            | "--policy-at-least" => {
                let value = args
                    .get(i)
                    .ok_or_else(|| format!("missing value for {flag}"))?;
                i += 1;
                value.as_str()
            }
            _ => return Err(format!("unknown bisection option {flag}")),
        };
        if flags.insert(flag, value).is_some() {
            return Err(format!("duplicate option {flag}"));
        }
    }
    if flags.remove("--trusted-local").is_none() {
        return Err("whole-repository --trusted-local authorization is required".into());
    }
    let start =
        DecisionSequence::try_new(positive(flags.remove("--start").unwrap_or("1"), u64::MAX)?)
            .map_err(|e| e.to_string())?;
    let end = match flags.remove("--end") {
        None | Some("latest") => None,
        Some(value) => {
            Some(DecisionSequence::try_new(positive(value, u64::MAX)?).map_err(|e| e.to_string())?)
        }
    };
    if end.is_some_and(|end| end < start) {
        return Err("start exceeds end".into());
    }
    let max_probes = positive(
        flags.remove("--max-probes").unwrap_or("4096"),
        MAX_PROBES as u64,
    )? as usize;
    let expected_head = flags.remove("--expected-head").map(head).transpose()?;
    let incarnation = flags
        .remove("--expected-incarnation")
        .map(RepositoryIncarnationId::from_hex)
        .transpose()
        .map_err(|e| e.to_string())?;
    let predicate = if let Some(reference) = flags.remove("--ref") {
        let name = RefName::try_new(reference.as_bytes()).map_err(|e| e.to_string())?;
        if let Some(oid) = flags.remove("--equals") {
            let target = native_oid(oid)?;
            if target.is_zero() {
                return Err("use --absent, not a zero OID".into());
            }
            Predicate::RefEquals { name, target }
        } else if flags.remove("--absent").is_some() {
            Predicate::RefAbsent { name }
        } else {
            return Err("--ref needs --equals or --absent".into());
        }
    } else if let Some(epoch) = flags.remove("--policy-at-least") {
        Predicate::PolicyAtLeast(
            PolicyEpoch::try_new(positive(epoch, u64::MAX)?).map_err(|e| e.to_string())?,
        )
    } else if let Some(number) = flags.remove("--issue") {
        let number =
            IssueNumber::try_new(positive(number, u64::MAX)?).ok_or("invalid issue number")?;
        let state = match flags.remove("--state") {
            Some("open") => IssueState::Open,
            Some("closed") => IssueState::Closed,
            _ => return Err("issue state must be open or closed".into()),
        };
        Predicate::IssueState { number, state }
    } else if let Some(number) = flags.remove("--pull") {
        let number = PullRequestNumber::try_new(positive(number, u64::MAX)?)
            .ok_or("invalid pull request number")?;
        let state = match flags.remove("--state") {
            Some("open") => PullState::Open,
            Some("closed") => PullState::Closed,
            Some("merged") => PullState::Merged,
            _ => return Err("pull state must be open, closed or merged".into()),
        };
        Predicate::PullRequestState { number, state }
    } else if let Some(job) = flags.remove("--check-job") {
        workflow_check(job, &mut flags)?
    } else {
        return Err("one typed predicate is required".into());
    };
    if !flags.is_empty() {
        return Err("conflicting or unused predicate options".into());
    }
    Ok(Options {
        storage: args[0].clone().into(),
        tenant,
        repository,
        incarnation,
        query: Query {
            start,
            end,
            predicate,
            max_probes,
            expected_head,
        },
    })
}
