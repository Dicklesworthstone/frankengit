use super::{Query, USAGE};
use fgit_forge::event::issue::IssueState;
use fgit_forge::{IssueNumber, PullRequestNumber};
use fgit_node::source_retrieval::bisection::{MAX_PROBES, Predicate, PullState};
use fgit_types::{
    CodecVersion, DecisionSequence, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    PolicyEpoch, RefName, RepositoryAuthorityHeadId, RepositoryId, RepositoryIncarnationId,
    TenantId,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
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
pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 6
        || args.len() > 24
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
            let format = match oid.len() {
                40 => GitHashAlgorithm::Sha1,
                64 => GitHashAlgorithm::Sha256,
                _ => return Err("native OID must be 40 or 64 lowercase hex characters".into()),
            };
            let target = GitOid::from_hex(format, oid).map_err(|e| e.to_string())?;
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
