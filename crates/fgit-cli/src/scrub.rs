#![forbid(unsafe_code)]
//! Trusted-local, bounded native object inventories. No sidecar authority.

mod sweep;

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use fgit_node::source_retrieval::integrity::scrub::{
    ScrubCursor, ScrubFindingCause, ScrubQuery, ScrubStop, SelectedObjectScrub,
};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{GitHashAlgorithm, GitOid, HeadGeneration, RepositoryId, TenantId};

use super::fsck::{head_token, parse_head};
use super::publication_support::quote;

const MIB: u64 = 1024 * 1024;
const USAGE: &str = "usage: fg scrub <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256] [--expected-generation <non-zero>]
  [--expected-head <snapshot-token>] [--resume-after <native-oid>]
  [--max-selected-objects <1..1000000>] [--max-page-objects <1..100000>]
  [--max-findings <1..1000>] [--max-bytes <1..17179869184>]
  [--max-object-bytes <1..268435456>] [--timeout-secs <1..3600>]
  [--all [--max-pages <1..1000000>] [--max-sweep-bytes <1..17179869184>]]

--all walks all pages with one request budget and one exact authority head.
It streams provisional page records, then a complete sweep receipt only after
all pages, final head revalidation and node shutdown succeed. Earlier findings
remain findings even when the last page is clean. --all cannot resume a cursor.
Defaults: at most 10000 pages and 16 GiB cumulative accounted payload.
--timeout-secs is the WHOLE sweep deadline, not a fresh allowance per page.
A limit, sink or authority failure emits no terminal certificate; exit status is 2.

Inventory missing, damaged or otherwise unverifiable native objects in one
bounded page of the authenticated selected closure, including hidden/history
objects. Individual object-read failures are findings, not early termination.
Authority failure, cancellation, timeout or failed shutdown emits no page receipt.
A finding is NOT necessarily corruption: it may be a permission or size refusal.

Resume using BOTH next_cursor.snapshot_token as --expected-head and
next_cursor.after as --resume-after. Head movement refuses; restart from the
beginning after a write. A cursor proves nothing about earlier pages. Even the
last resumed page does not claim entire-repository byte integrity. Inspect every
page's findings. A fresh complete page alone can verify all selected object bytes.
This does not verify graph connectivity, repair objects, grant retention, inspect
physical orphans, or change authority. Use fg fsck for the separate graph audit.

Defaults: 1000 objects/page, 100 findings/page, 64 MiB accounted payload/page,
32 MiB per object, 1000000 selected objects, 300 seconds. The payload budget
counts verified bytes included in a page, not physical I/O. One extra bounded
object may be read at a page boundary; the node's per-object ceiling still applies.
Timeouts are cooperative and cannot interrupt a blocking filesystem operation.
Exit 0: all selected object bytes verified in a complete page or --all sweep;
3: this page has findings; 4: a clean page without a whole-selection certificate;
2: invalid input, systemic failure, incomplete shutdown, or output failure.";

#[derive(Debug)]
struct Options {
    storage: PathBuf,
    tenant: TenantId,
    repository: RepositoryId,
    format: GitHashAlgorithm,
    object_bytes: u64,
    query: ScrubQuery,
    sweep: Option<sweep::Limits>,
}

fn positive(value: &str, maximum: u64, field: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{field} requires a positive decimal integer"));
    }
    value.parse::<u64>().ok().filter(|value| *value > 0 && *value <= maximum)
        .ok_or_else(|| format!("{field} must be in 1..={maximum}"))
}

fn parse(args: &[String]) -> Result<Options, String> {
    if args.len() < 4 || args.len() > 29 || args[0].is_empty()
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let mut query = ScrubQuery::default();
    let mut format = GitHashAlgorithm::Sha1;
    let mut object_bytes = 32 * MIB;
    let mut after = None;
    let mut sweep_limits = sweep::Limits::default();
    let mut seen = BTreeSet::new();
    let mut at = 3;
    while let Some(flag) = args.get(at) {
        if !seen.insert(flag.as_str()) {
            return Err(format!("duplicate option: {flag}"));
        }
        at += 1;
        if flag == "--trusted-local" || flag == "--all" {
            continue;
        }
        let value = args.get(at).ok_or_else(|| format!("missing value for {flag}"))?;
        at += 1;
        match flag.as_str() {
            "--object-format" => format = match value.as_str() {
                "sha1" => GitHashAlgorithm::Sha1,
                "sha256" => GitHashAlgorithm::Sha256,
                _ => return Err("object format must be sha1 or sha256".into()),
            },
            "--expected-head" => query.expected_head = Some(parse_head(value)?),
            "--expected-generation" => query.expected_generation = Some(
                HeadGeneration::try_new(positive(value, u64::MAX, flag)?).map_err(|error| error.to_string())?
            ),
            "--resume-after" => after = Some(value),
            "--max-selected-objects" => query.max_selected_objects = positive(value, 1_000_000, flag)? as usize,
            "--max-page-objects" => query.max_page_objects = positive(value, 100_000, flag)? as usize,
            "--max-findings" => query.max_findings = positive(value, 1_000, flag)? as usize,
            "--max-bytes" => query.max_payload_bytes = positive(value, 16 * 1024 * MIB, flag)?,
            "--max-object-bytes" => object_bytes = positive(value, 256 * MIB, flag)?,
            "--timeout-secs" => query.timeout = Duration::from_secs(positive(value, 3600, flag)?),
            "--max-pages" => sweep_limits.pages = positive(value, 1_000_000, flag)? as usize,
            "--max-sweep-bytes" => sweep_limits.payload_bytes = positive(value, 16 * 1024 * MIB, flag)?,
            _ => return Err(format!("unsupported scrub option: {flag}")),
        }
    }
    if !seen.contains("--trusted-local") {
        return Err("scrub requires --trusted-local and authorization to inspect the entire repository".into());
    }
    if !seen.contains("--all") && (seen.contains("--max-pages") || seen.contains("--max-sweep-bytes")) {
        return Err("--max-pages and --max-sweep-bytes require --all".into());
    }
    if seen.contains("--all") && after.is_some() {
        return Err("--all must start at the beginning; --resume-after is not permitted".into());
    }
    // Defaults shrink with a narrower explicitly requested page/selection.
    // Explicit contradictory bounds refuse instead of being silently clamped.
    if !seen.contains("--max-page-objects") {
        query.max_page_objects = query.max_page_objects.min(query.max_selected_objects);
    }
    if !seen.contains("--max-findings") {
        query.max_findings = query.max_findings.min(query.max_page_objects);
    }
    if query.max_page_objects > query.max_selected_objects || query.max_findings > query.max_page_objects {
        return Err("require max-findings <= max-page-objects <= max-selected-objects".into());
    }
    if let Some(value) = after {
        let head = query.expected_head.ok_or("--resume-after requires --expected-head")?;
        let oid = GitOid::from_hex(format, value).map_err(|error| error.to_string())?;
        if oid.is_zero() || oid.to_string() != *value {
            return Err("--resume-after requires a nonzero canonical lowercase native OID".into());
        }
        query.cursor = Some(ScrubCursor::new(head, oid));
    }
    Ok(Options {
        storage: PathBuf::from(&args[0]),
        tenant: TenantId::from_hex(&args[1]).map_err(|error| error.to_string())?,
        repository: RepositoryId::from_hex(&args[2]).map_err(|error| error.to_string())?,
        format, object_bytes, query,
        sweep: seen.contains("--all").then_some(sweep_limits),
    })
}

/// Bound diagnostic output without first allocating an unbounded Display string.
struct Diagnostic {
    text: String,
    truncated: bool,
}
impl fmt::Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if self.truncated { return Ok(()); }
        let mut end = value.len().min(1024 - self.text.len());
        while !value.is_char_boundary(end) { end -= 1; }
        self.text.push_str(&value[..end]);
        self.truncated |= end < value.len();
        Ok(())
    }
}
fn diagnostic(cause: &ScrubFindingCause) -> Diagnostic {
    let mut out = Diagnostic { text: String::new(), truncated: false };
    if write!(&mut out, "{cause}").is_err() {
        out.truncated = true;
    }
    out
}
fn nullable_oid(oid: Option<GitOid>) -> String {
    oid.map_or_else(|| "null".into(), |oid| quote(&oid.to_string()))
}
fn receipt(options: &Options, report: &SelectedObjectScrub) -> String {
    render_page(options, report, true)
}
fn render_page(options: &Options, report: &SelectedObjectScrub, closed: bool) -> String {
    let findings = report.findings().iter().map(|finding| {
        let code = match &finding.cause {
            ScrubFindingCause::ObjectRead(_) => "object_unverifiable",
            ScrubFindingCause::NonGitObject => "non_git_object",
        };
        let detail = diagnostic(&finding.cause);
        format!("{{\"oid\":{},\"code\":{},\"detail\":{},\"detail_truncated\":{}}}",
            quote(&finding.oid.to_string()), quote(code), quote(&detail.text), detail.truncated)
    }).collect::<Vec<_>>().join(",");
    let next = report.next_cursor().map_or_else(|| "null".into(), |cursor| {
        format!("{{\"snapshot_token\":{},\"after\":{}}}",
            quote(&head_token(cursor.head())), quote(&cursor.after().to_string()))
    });
    let stop = match report.stop() {
        ScrubStop::SelectionExhausted => "selection_exhausted",
        ScrubStop::ObjectLimit => "object_limit",
        ScrubStop::FindingLimit => "finding_limit",
        ScrubStop::PayloadLimit => "payload_limit",
    };
    format!(concat!(
        "{{\"type\":{},\"schema_version\":1,",
        "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation_id\":{},",
        "\"object_format\":{},\"authority_generation\":{},\"snapshot_token\":{},",
        "\"selected_closure_root\":{},\"selected_objects\":{},\"start_after\":{},",
        "\"objects_checked\":{},\"objects_verified\":{},\"object_read_attempts\":{},",
        "\"payload_bytes_accounted\":{},\"findings\":[{}],\"next_cursor\":{},\"stop\":{},",
        "\"page_complete\":{},\"complete\":{},\"all_selected_object_bytes_verified\":{},",
        "\"scope\":\"authority_selected_native_object_bytes\",\"head_revalidated\":true,",
        "\"object_graph_verified\":false,\"physical_orphans_scanned\":false,",
        "\"objects_repaired\":false,\"repository_changed\":false,\"node_closed\":{}}}"
    ),
        quote(if closed { "repository_scrub_page" } else { "repository_scrub_sweep_page" }),
        quote(&options.tenant.to_string()), quote(&report.repository_id().to_string()),
        quote(&report.repository_incarnation_id().to_string()), quote(options.format.as_str()),
        report.generation().get(), quote(&head_token(report.head())),
        quote(&report.closure_root().to_string()), report.selected_objects(), nullable_oid(report.start_after()),
        report.checked_objects(), report.verified_objects(), report.read_attempts(), report.payload_bytes(),
        findings, next, quote(stop), closed, closed && report.entire_selection_checked(),
        closed && report.entire_selection_verified(), closed,
    )
}
fn finish(
    output: &mut impl Write,
    options: &Options,
    result: Result<SelectedObjectScrub, String>,
    cleanup: Option<String>,
) -> Result<u8, String> {
    let report = match (result, cleanup) {
        (Ok(report), None) => report,
        (result, cleanup) => {
            return Err(format!("no scrub page returned; audit: {}; shutdown: {}",
                result.err().unwrap_or_else(|| "completed".into()),
                cleanup.unwrap_or_else(|| "completed".into())));
        }
    };
    let code = if !report.findings().is_empty() { 3 }
        else if report.entire_selection_verified() { 0 } else { 4 };
    writeln!(output, "{}", receipt(options, &report)).and_then(|()| output.flush())
        .map_err(|error| format!("scrub receipt output incomplete: {error}"))?;
    Ok(code)
}

pub fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{USAGE}").and_then(|()| out.flush()).map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    if options.sweep.is_some() {
        return sweep::run(options);
    }
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format)
            .with_max_object_bytes(options.object_bytes),
    ).map_err(|error| format!("cannot open scrub node: {error}"))?;
    let result = node.bring_into_service(HeadGeneration::FIRST)
        .map_err(|error| error.to_string())
        .and_then(|()| {
            let request = fgit_cli::command_request_context(&node);
            node.runtime().block_on(node.scrub_selected_objects_local_in(&request, options.query))
                .map_err(|error| error.to_string())
        });
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    finish(&mut std::io::stdout().lock(), &options, result, cleanup)
}

#[cfg(test)]
mod tests;
