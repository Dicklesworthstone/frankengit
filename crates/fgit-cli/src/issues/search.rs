//! Snapshot-pinned issue search using canonical issue pages, not a local index.
use super::options::{self, Operation};
use fgit_forge::event::issue::{
    CompiledIssueQuery, IssueQuery, IssueState, MAX_BODY_BYTES, MAX_LABELS,
};
use fgit_forge::issue_search::{self, MAX_SCAN, SearchRequest, SourcePage};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{HeadGeneration, PrincipalId};
use std::collections::BTreeMap;

const USAGE: &str =
    "usage: fg issue search <storage-root> <tenant-id> <repository-id> --trusted-local
  [--query <literal>] [--case-sensitive] [--state open|closed|all]
  [--opened-by <principal-id>] [--label <exact-label>]...
  [--limit <1..100>] [--max-scan <1..1000>]
  [--after <number> --expected-head <snapshot-token>] [--object-format sha1|sha256]

Filters are conjunctive; every label must be present. Text searches the title OR
body, not comments, with ASCII-only case folding unless --case-sensitive is set.
There is no regex, Unicode normalization, fuzzy matching or implicit open filter.
Defaults: 50 results, 1000 scanned issues. Result and scan limits are independent.
complete=false means unexamined candidates remain, NOT that another match exists.
An empty partial page is not a complete no-match result. Continue using next_after,
snapshot_token and the same filters, including after an empty partial page.
The cursor names the last SCANNED issue. Retained snapshots never refresh to latest.
Search moves no refs and creates no transaction. No output is emitted before the
node closes successfully. Exit 0: bounded search result; 2: input/source/output error.
This is an operator-trusted local interface, not remote authentication or issue ACLs.";

struct Options {
    base: options::Options,
    query: CompiledIssueQuery,
    max_scan: u16,
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 3 {
        return Err(USAGE.to_owned());
    }
    if arguments.len() > 96
        || arguments.iter().any(|arg| arg.len() > MAX_BODY_BYTES)
        || arguments
            .iter()
            .try_fold(0usize, |n, arg| n.checked_add(arg.len()))
            .is_none_or(|n| n > 128 * 1024)
    {
        return Err("issue search arguments exceed the bounded local profile".into());
    }
    // Reuse the owning parser for repository identity, trust, object format,
    // canonical decimals, page size and algorithm-qualified snapshot tokens.
    let mut base = vec!["list".to_owned()];
    base.extend_from_slice(&arguments[..3]);
    let mut flags = BTreeMap::new();
    let mut labels = Vec::new();
    let mut case_sensitive = false;
    let mut at = 3;
    while at < arguments.len() {
        let flag = arguments[at].as_str();
        at += 1;
        if flag == "--case-sensitive" {
            if case_sensitive {
                return Err("duplicate --case-sensitive".into());
            }
            case_sensitive = true;
            continue;
        }
        if flag == "--trusted-local" {
            base.push(flag.to_owned());
            continue;
        }
        let filter = matches!(
            flag,
            "--query" | "--state" | "--opened-by" | "--label" | "--max-scan"
        );
        if !filter
            && !matches!(
                flag,
                "--limit" | "--after" | "--expected-head" | "--object-format"
            )
        {
            return Err(format!(
                "unknown or inapplicable issue search option {flag:?}"
            ));
        }
        let value = arguments
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        if flag == "--label" {
            if labels.len() == MAX_LABELS {
                return Err("at most 32 issue search labels may be supplied".into());
            }
            labels.push(value.clone());
        } else if filter {
            if flags.insert(flag, value.as_str()).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else {
            base.push(flag.to_owned());
            base.push(value.clone());
        }
    }
    let base = options::parse(&base)?;
    let state = match flags.get("--state").copied().unwrap_or("all") {
        "all" => None,
        "open" => Some(IssueState::Open),
        "closed" => Some(IssueState::Closed),
        _ => return Err("--state must be open, closed or all".into()),
    };
    let opened_by = flags
        .get("--opened-by")
        .map(|value| PrincipalId::from_hex(value).map_err(|_| "invalid opener principal ID"))
        .transpose()?;
    let text = flags.get("--query").map(|value| (*value).to_owned());
    if case_sensitive && text.is_none() {
        return Err("--case-sensitive requires --query".into());
    }
    labels.sort();
    let query = IssueQuery { state, opened_by, labels, text, case_sensitive }.compile()
        .map_err(|_| "invalid issue search query or labels (labels must be unique; text is 1..256 UTF-8 bytes without NUL)")?;
    let max_scan = flags
        .get("--max-scan")
        .map(|value| options::decimal(value))
        .transpose()?
        .unwrap_or(u64::from(MAX_SCAN));
    if !(1..=u64::from(MAX_SCAN)).contains(&max_scan) {
        return Err("--max-scan must be 1..1000".into());
    }
    Ok(Options {
        base,
        query,
        max_scan: u16::try_from(max_scan).map_err(|_| "scan limit overflow")?,
    })
}

pub(super) fn run(arguments: &[String]) -> Result<u8, String> {
    if arguments == ["--help"] {
        return super::write_read(&mut std::io::stdout().lock(), USAGE).map(|()| 0);
    }
    let options = parse(arguments)?;
    let Operation::Read(read) = &options.base.operation else {
        return Err("search requires a read operation".into());
    };
    let mut node = OneNode::open_existing(
        NodeConfig::new(
            options.base.storage.clone(),
            options.base.tenant,
            options.base.repository,
        )
        .with_object_format(options.base.format),
    )
    .map_err(|error| format!("cannot open issue search node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        let context = node.request_context();
        let page = issue_search::search(
            &options.query,
            SearchRequest {
                after: read.after,
                limit: read.limit,
                max_scan: options.max_scan,
                expected_head: read.expected_head,
            },
            |after, limit, expected_head| {
                let page = node
                    .runtime()
                    .block_on(node.read_issues_in(&context, after, limit, expected_head))
                    .map_err(|error| error.to_string())?;
                Ok::<_, String>(SourcePage {
                    source_head: page.source_head,
                    issues: page.issues,
                    next_after: page.next_after,
                })
            },
        )
        .map_err(|error| error.to_string())?;
        super::output::search(&options.base, read, &options.query, options.max_scan, &page)
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let report = match (result, cleanup) {
        (Ok(report), None) => report,
        (Ok(_), Some(error)) => {
            return Err(format!(
                "issue search shutdown failed: {error}; no result returned"
            ));
        }
        (Err(error), None) => {
            return Err(format!("issue search failed: {error}; no result returned"));
        }
        (Err(error), Some(cleanup)) => {
            return Err(format!(
                "issue search failed: {error}; shutdown also failed: {cleanup}; no result returned"
            ));
        }
    };
    super::write_read(&mut std::io::stdout().lock(), &report)?;
    Ok(0)
}

#[cfg(test)]
mod tests;
