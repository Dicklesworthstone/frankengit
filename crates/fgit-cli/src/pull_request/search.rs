//! Bounded native PR search; the node owns snapshot selection and disclosure.
use super::{options, output};
use crate::publication_support::quote;
use fgit_forge::pull_request_search::{
    CompiledPullRequestQuery, MAX_SCAN, PullRequestQuery, PullRequestState, SearchRequest,
};
use fgit_node::{NodeConfig, OneNode, PullRequestSearchPage};
use fgit_types::{HeadGeneration, PrincipalId};
use std::collections::BTreeMap;
use std::io::Write;

const USAGE: &str = "usage: fg pr search <storage-root> <tenant-id> <repository-id> --trusted-local
  [--query <literal>] [--case-sensitive] [--state open|closed|merged|all]
  [--opened-by <principal-id>]
  [--source-ref <branch> | --source-ref-hex <bytes>]
  [--target-ref <branch> | --target-ref-hex <bytes>]
  [--limit <1..100>] [--max-scan <1..1000>]
  [--after <number> --expected-head <snapshot-token>] [--object-format sha1|sha256]

Filters are conjunctive. Text is a literal title OR body match, with ASCII case
folding unless --case-sensitive is set; comments are not searched. There is no
implicit open filter. Merge-only receipts have no invented title, body or author.
Defaults: 50 results and 1000 visible candidates scanned. A partial page may be
empty: continue with next_after, snapshot_token and the same filters. The cursor
names the last SCANNED PR, not necessarily a match. complete=false means there
are unexamined candidates, not that another match exists. Current hidden-ref
policy applies even to retained snapshots. No refs or transactions are changed.
No output is emitted before successful node shutdown. Exit 0: bounded result;
2: input/source/output error. This is a trusted local-operator interface.";

#[derive(Debug)]
struct Options {
    base: options::Options,
    query: CompiledPullRequestQuery,
    request: SearchRequest,
}

fn parse(arguments: &[String]) -> Result<Options, String> {
    if arguments.len() < 3 {
        return Err(USAGE.into());
    }
    if arguments.len() > 48
        || arguments.iter().any(|value| value.len() > 8192)
        || arguments.iter().map(String::len).sum::<usize>() > 64 * 1024
    {
        return Err("PR search arguments exceed the bounded local profile".into());
    }
    let mut base = vec!["list".to_owned()];
    base.extend_from_slice(&arguments[..3]);
    let mut flags = BTreeMap::new();
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
            "--query"
                | "--state"
                | "--opened-by"
                | "--source-ref"
                | "--source-ref-hex"
                | "--target-ref"
                | "--target-ref-hex"
                | "--max-scan"
        );
        if !filter
            && !matches!(
                flag,
                "--limit" | "--after" | "--expected-head" | "--object-format"
            )
        {
            return Err(format!("unknown or inapplicable PR search option {flag:?}"));
        }
        let value = arguments
            .get(at)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        if filter {
            if flags.insert(flag, value.as_str()).is_some() {
                return Err(format!("duplicate {flag}"));
            }
        } else {
            base.extend([flag.to_owned(), value.clone()]);
        }
    }
    let base = options::parse(&base)?;
    let state = match flags.get("--state").copied().unwrap_or("all") {
        "all" => None,
        "open" => Some(PullRequestState::Open),
        "closed" => Some(PullRequestState::Closed),
        "merged" => Some(PullRequestState::Merged),
        _ => return Err("--state must be open, closed, merged or all".into()),
    };
    let reference = |plain, encoded| {
        if flags.contains_key(plain) || flags.contains_key(encoded) {
            options::reference(&flags, plain, encoded).map(Some)
        } else {
            Ok(None)
        }
    };
    let query = PullRequestQuery {
        state,
        opened_by: flags.get("--opened-by")
            .map(|value| PrincipalId::from_hex(value).map_err(|_| "invalid opener principal ID"))
            .transpose()?,
        source_ref: reference("--source-ref", "--source-ref-hex")?,
        target_ref: reference("--target-ref", "--target-ref-hex")?,
        text: flags.get("--query").map(|value| (*value).to_owned()),
        case_sensitive,
    }.compile().map_err(|_| "invalid PR query: use complete branch refs and 1..256 UTF-8 text bytes without NUL; case-sensitive requires query")?;
    let max_scan = flags
        .get("--max-scan")
        .map(|value| options::decimal(value))
        .transpose()?
        .unwrap_or(u64::from(MAX_SCAN));
    let options::Operation::Read(read) = &base.operation else {
        return Err("search requires a read operation".into());
    };
    let request = SearchRequest {
        after: read.after(),
        limit: read.limit(),
        expected_head: read.expected_head,
        max_scan: u16::try_from(max_scan).map_err(|_| "invalid scan limit")?,
    };
    request
        .validate::<String>()
        .map_err(|error| error.to_string())?;
    Ok(Options {
        base,
        query,
        request,
    })
}

pub(super) fn run(arguments: &[String], writer: &mut impl Write) -> Result<u8, String> {
    if arguments == ["--help"] {
        return super::write_read_report(writer, USAGE).map(|()| 0);
    }
    let options = parse(arguments)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(
            options.base.storage.clone(),
            options.base.tenant,
            options.base.repository,
        )
        .with_object_format(options.base.format),
    )
    .map_err(|error| format!("cannot open PR search node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        let context = fgit_cli::command_request_context(&node);
        let page = node
            .runtime()
            .block_on(node.search_pull_requests_in(
                &context,
                &Default::default(),
                &options.query,
                options.request,
            ))
            .map_err(|error| error.to_string())?;
        receipt(&options, &page)
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let report = match (result, cleanup) {
        (Ok(report), None) => report,
        (Ok(_), Some(error)) => {
            return Err(format!(
                "PR search shutdown failed: {error}; no result returned"
            ));
        }
        (Err(error), None) => return Err(format!("PR search failed: {error}; no result returned")),
        (Err(error), Some(cleanup)) => {
            return Err(format!(
                "PR search failed: {error}; shutdown also failed: {cleanup}; no result returned"
            ));
        }
    };
    super::write_read_report(writer, &report)?;
    Ok(0)
}

fn receipt(options: &Options, page: &PullRequestSearchPage) -> Result<String, String> {
    let query = options.query.query();
    let mut out = format!(
        concat!(
            "{{\"type\":\"pull_request_search\",\"schema_version\":1,\"tenant_id\":{},",
            "\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
            "\"after\":{},\"limit\":{},\"max_scan\":{},\"scanned\":{},\"count\":{},",
            "\"complete\":{},\"stop_reason\":{},\"next_after\":{},\"node_closed\":true,",
            "\"filters\":{{\"state\":{},\"opened_by\":{},\"source_ref_hex\":{},\"target_ref_hex\":{},\"query\":{},\"case_sensitive\":{}}},",
            "\"pull_requests\":["
        ),
        quote(&options.base.tenant.to_string()),
        quote(&options.base.repository.to_string()),
        quote(options.base.format.as_str()),
        quote(&page.source_head.to_string()),
        quote(&options::head_token(page.source_head)),
        options.request.after,
        options.request.limit,
        options.request.max_scan,
        page.scanned,
        page.pull_requests.len(),
        page.is_complete(),
        quote(page.stop.as_str()),
        page.next_after
            .map_or_else(|| "null".into(), |n| n.to_string()),
        quote(query.state.map_or("all", PullRequestState::as_str)),
        query
            .opened_by
            .map_or_else(|| "null".into(), |id| quote(&id.to_string())),
        query
            .source_ref
            .as_ref()
            .map_or_else(|| "null".into(), |r| quote(&options::hex(r.as_bytes()))),
        query
            .target_ref
            .as_ref()
            .map_or_else(|| "null".into(), |r| quote(&options::hex(r.as_bytes()))),
        query.text.as_deref().map_or_else(|| "null".into(), quote),
        query.case_sensitive,
    );
    for (index, view) in page.pull_requests.iter().enumerate() {
        let row = output::render_view(&output::Row {
            number: view.number,
            event: &view.event,
            data: view.data.as_ref(),
            opened_by: view.opened_by,
            last_metadata_actor: view.last_metadata_actor,
            labels: &view.labels,
            labels_version: view.labels_version,
            labels_actor: view.labels_actor,
        })?;
        if out.len().saturating_add(row.len()).saturating_add(3) > output::MAX_REPLY_BYTES {
            return Err("PR search exceeds the output ceiling; reduce --limit".into());
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
mod tests;
