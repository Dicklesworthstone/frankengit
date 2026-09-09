//! Native log/blame commands. Input is bounded before repository opening;
//! complete, snapshot-bound results are rendered only after explicit shutdown.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use fgit_forge::history::{BlameOptions, BlameResult, HistoryCommit, HistoryLimits, HistoryPage, LogOptions};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm,
    GitOid, HeadGeneration, RefName, RepositoryAuthorityHeadId, RepositoryId, TenantId};
use super::publication_support::quote;

const USAGE: &str = "\
usage: fg log <storage-root> <tenant-id> <repository-id> <ref> --trusted-local
  [--limit <1..100>] [--after <offset> --expected-head <snapshot-token>]
usage: fg blame <storage-root> <tenant-id> <repository-id> <ref> --trusted-local
  (--path <raw-path> | --path-hex <hex>) [--line-start <n>] [--line-end <n>]

Both: [--object-format sha1|sha256] [--ref-hex] [--expected-head <snapshot-token>]
  [--max-commits <1..4096>] [--max-edges <1..16384>]
Blame: [--max-blob-bytes <1..1048576>] [--max-lines <1..20000>]
  [--max-comparisons <1..128>] [--max-diff-work <1..1000000>]

Log is child-before-parent, with native-ID ties, NOT timestamp order.
Blame traces exact same-path lines through ALL parents; the first stored parent
with a matching line wins. No rename/copy guessing or whitespace normalization.
Line intervals are zero-based and half-open. Raw bytes and commit bodies remain
lossless. Author headers are claims, not authenticated identities or approvals.
Missing history, binary content, failed limits and cancellation refuse; no partial
success is returned. Exit 0: complete requested result; exit 2: no successful result.";
const MAX_JSON: usize = 64 * 1024 * 1024;

#[derive(Debug)]
struct Options {
    storage: PathBuf, tenant: TenantId, repository: RepositoryId,
    format: GitHashAlgorithm, reference: RefName,
    head: Option<RepositoryAuthorityHeadId>, query: Query,
}
#[derive(Debug)]
enum Query { Log(LogOptions), Blame(BlameOptions) }
enum Answer { Log(HistoryPage), Blame(BlameResult) }

pub(super) fn run(arguments: &[String], is_blame: bool) -> Result<(), String> {
    if arguments == ["--help"] { return emit(&mut std::io::stdout().lock(), USAGE); }
    let options = parse(arguments, is_blame)?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.storage.clone(), options.tenant,
        options.repository).with_object_format(options.format)).map_err(|e| e.to_string())?;
    let operation = (|| -> Result<_, String> {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|e| e.to_string())?;
        let request = node.request_context();
        match &options.query {
            Query::Log(query) => node.runtime().block_on(node.read_commit_history_in(&request,
                &options.reference, &Default::default(), options.head, *query))
                .map(|(head, result)| (head, Answer::Log(result))).map_err(|e| e.to_string()),
            Query::Blame(query) => node.runtime().block_on(node.blame_source_in(&request,
                &options.reference, &Default::default(), options.head, query))
                .map(|(head, result)| (head, Answer::Blame(result))).map_err(|e| e.to_string()),
        }
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let (head, answer) = match (operation, cleanup) {
        (Ok(answer), None) => answer,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("history node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let rendered = match answer {
        Answer::Log(page) => render_log(&options, head, &page)?,
        Answer::Blame(result) => render_blame(&options, head, &result)?,
    };
    emit(&mut std::io::stdout().lock(), &rendered)
}
fn emit(output: &mut impl Write, text: &str) -> Result<(), String> {
    writeln!(output, "{text}").and_then(|()| output.flush()).map_err(|e| format!("history output incomplete: {e}"))
}
fn parse(args: &[String], is_blame: bool) -> Result<Options, String> {
    if args.len() < 4 { return Err(USAGE.into()); }
    if args.len() > 48 || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    { return Err("history arguments exceed the bounded profile".into()); }
    if args[0].is_empty() || args[0].len() > 4096 { return Err("invalid storage path".into()); }
    let tenant = TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant ID")?;
    let repository = RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository ID")?;
    let mut flags = BTreeMap::new(); let mut at = 4;
    while at < args.len() {
        let flag = args[at].as_str(); at += 1;
        let switch = matches!(flag, "--trusted-local" | "--ref-hex");
        let allowed = switch || matches!(flag, "--object-format" | "--expected-head" | "--max-commits" | "--max-edges")
            || if is_blame { matches!(flag, "--path" | "--path-hex" | "--line-start" | "--line-end"
                | "--max-blob-bytes" | "--max-lines" | "--max-comparisons" | "--max-diff-work") }
            else { matches!(flag, "--after" | "--limit") };
        if !allowed { return Err(format!("unknown or inapplicable history option {flag:?}")); }
        let value = if switch { "" } else {
            let value = args.get(at).ok_or_else(|| format!("missing value for {flag}"))?;
            at += 1; value.as_str()
        };
        if flags.insert(flag, value).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is required for local/ref-authorized history".into()); }
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256,
        _ => return Err("object format must be sha1 or sha256".into()),
    };
    let reference = if flags.contains_key("--ref-hex") { unhex(&args[3], 4096)? } else { args[3].as_bytes().to_vec() };
    let reference = RefName::try_new(&reference).map_err(|_| "invalid reference bytes")?;
    let head = flags.get("--expected-head").map(|text| parse_head(text)).transpose()?;
    let number = |flag: &str, fallback: usize| -> Result<usize, String> { flags.get(flag).map_or(Ok(fallback), |text| size(text)) };
    let mut limits = HistoryLimits::default();
    limits.max_commits = number("--max-commits", limits.max_commits)?;
    limits.max_edges = number("--max-edges", limits.max_edges)?;
    let query = if is_blame {
        limits.max_blob_bytes = number("--max-blob-bytes", limits.max_blob_bytes)?;
        limits.max_lines = number("--max-lines", limits.max_lines)?;
        limits.max_comparisons = number("--max-comparisons", limits.max_comparisons)?;
        limits.max_diff_work = number("--max-diff-work", limits.max_diff_work)?;
        let path = match (flags.get("--path"), flags.get("--path-hex")) {
            (Some(path), None) => path.as_bytes().to_vec(),
            (None, Some(path)) => unhex(path, 4096)?,
            _ => return Err("supply exactly one of --path or --path-hex".into()),
        };
        let query = BlameOptions { path, first_line: number("--line-start", 0)?,
            end_line: flags.get("--line-end").map(|text| size(text)).transpose()?, limits };
        query.validate().map_err(|e| e.to_string())?; Query::Blame(query)
    } else {
        let query = LogOptions { after: number("--after", 0)?, limit: number("--limit", 50)?, limits };
        query.validate().map_err(|e| e.to_string())?;
        if query.after != 0 && head.is_none() { return Err("log continuation requires the original --expected-head snapshot_token".into()); }
        Query::Log(query)
    };
    Ok(Options { storage: args[0].clone().into(), tenant, repository, format, reference, head, query })
}
fn decimal(text: &str) -> Result<u64, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len() > 1 && text.starts_with('0')) {
        return Err("expected canonical unsigned decimal".into());
    }
    text.parse().map_err(|_| "integer overflow".into())
}
fn size(text: &str) -> Result<usize, String> { usize::try_from(decimal(text)?).map_err(|_| "integer exceeds target width".into()) }
fn unhex(text: &str, limit: usize) -> Result<Vec<u8>, String> {
    if text.is_empty() || text.len() > limit * 2 || text.len() % 2 != 0
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err("expected bounded lowercase hex".into()); }
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| digit(pair[0]) * 16 + digit(pair[1])).collect())
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn text(bytes: &[u8]) -> String { std::str::from_utf8(bytes).map_or_else(|_| "null".into(), quote) }
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()))
}
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId, String> {
    let (algorithm, digest) = text.strip_prefix("head:").unwrap_or(text).strip_prefix("alg:")
        .and_then(|value| value.split_once(':')).ok_or("expected algorithm-qualified authority head")?;
    let algorithm = DigestAlgorithmId::try_new(u16::try_from(decimal(algorithm)?).map_err(|_| "algorithm overflow")?)
        .map_err(|_| "invalid digest algorithm")?;
    let digest = DigestBytes::try_new(&unhex(digest, 64)?).map_err(|_| "invalid head digest")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}
fn valid_id(id: GitOid, options: &Options) -> bool { !id.is_zero() && id.algorithm() == options.format }
fn header(options: &Options, head: RepositoryAuthorityHeadId, tip: GitOid) -> Result<String, String> {
    if options.head.is_some_and(|expected| expected != head) || !valid_id(tip, options) { return Err("history source binding mismatch".into()); }
    Ok(format!(concat!("\"schema_version\":1,\"complete\":true,\"node_closed\":true,",
        "\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},\"reference_hex\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"source_commit\":{},\"author_headers_authenticated\":false"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(options.format.as_str()),
        quote(&hex(options.reference.as_bytes())), quote(&head.to_string()), quote(&head_token(head)), quote(&tip.to_string())))
}
fn append(out: &mut String, row: &str) -> Result<(), String> {
    if out.len().saturating_add(row.len()).saturating_add(2) > MAX_JSON { return Err("history JSON limit exceeded".into()); }
    out.push_str(row); Ok(())
}
fn records(options: &Options, commits: &[HistoryCommit]) -> Result<String, String> {
    let mut seen = BTreeSet::new(); let mut bytes = 0_usize; let mut out = "[".to_owned();
    for (i, commit) in commits.iter().enumerate() {
        bytes = bytes.checked_add(commit.body.len()).ok_or("metadata length overflow")?;
        if commit.body.len() > 64 * 1024 || bytes > HistoryLimits::default().max_metadata_bytes
            || !valid_id(commit.id, options) || !valid_id(commit.tree, options) || !seen.insert(commit.id)
            || commit.parents.len() > HistoryLimits::default().max_edges
            || commit.parents.iter().any(|id| !valid_id(*id, options))
        { return Err("invalid history metadata response".into()); }
        if i != 0 { append(&mut out, ",")?; }
        let parents = commit.parents.iter().map(|id| quote(&id.to_string())).collect::<Vec<_>>().join(",");
        append(&mut out, &format!("{{\"commit\":{},\"tree\":{},\"parents\":[{parents}],\"body_hex\":{},\"body_text\":{}}}",
            quote(&commit.id.to_string()), quote(&commit.tree.to_string()), quote(&hex(&commit.body)), text(&commit.body)))?;
    }
    out.push(']'); Ok(out)
}
fn render_log(options: &Options, head: RepositoryAuthorityHeadId, page: &HistoryPage) -> Result<String, String> {
    let Query::Log(query) = &options.query else { return Err("history operation mismatch".into()); };
    let end = page.after.checked_add(page.commits.len()).ok_or("page overflow")?;
    if page.after != query.after || page.total_commits > query.limits.max_commits || end > page.total_commits
        || page.commits.len() != query.limit.min(page.total_commits.saturating_sub(page.after))
        || page.next_after != (end < page.total_commits).then_some(end)
        || (page.after == 0 && page.commits.first().is_none_or(|commit| commit.id != page.tip))
    { return Err("history pagination response mismatch".into()); }
    let header = header(options, head, page.tip)?;
    let entries = records(options, &page.commits)?;
    let mut out = format!("{{\"type\":\"commit_history\",\"profile\":\"topo-oid-v1\",\"scope\":\"reachable_commit_dag\",{header},\"total_commits\":{},\"after\":{},\"limit\":{},\"next_after\":{},\"commits\":",
        page.total_commits, page.after, query.limit, page.next_after.map_or_else(|| "null".into(), |n| n.to_string()));
    append(&mut out, &entries)?; out.push('}'); Ok(out)
}
fn render_blame(options: &Options, head: RepositoryAuthorityHeadId, result: &BlameResult) -> Result<String, String> {
    let Query::Blame(query) = &options.query else { return Err("blame operation mismatch".into()); };
    if result.path != query.path || result.first_line != query.first_line
        || result.end_line != query.end_line.unwrap_or(result.total_lines) || result.end_line < result.first_line
        || result.end_line > result.total_lines || result.total_lines > query.limits.max_lines
        || result.lines.len() != result.end_line - result.first_line || result.content.len() > query.limits.max_blob_bytes
        || !valid_id(result.tree, options) || !valid_id(result.blob, options)
        || result.graph_commits > query.limits.max_commits || result.comparisons > query.limits.max_comparisons
    { return Err("blame scope response mismatch".into()); }
    let header = header(options, head, result.tip)?;
    let origin_ids: BTreeSet<_> = result.origins.iter().map(|commit| commit.id).collect();
    if origin_ids != result.lines.iter().map(|line| line.origin_commit).collect::<BTreeSet<_>>() {
        return Err("blame origin binding mismatch".into());
    }
    let origins = records(options, &result.origins)?;
    let algorithms = result.algorithms.iter().map(|a| quote(&format!("{a:?}"))).collect::<Vec<_>>().join(",");
    let mut out = format!(concat!("{{\"type\":\"source_blame\",\"profile\":\"exact-lines-all-parents-v1\",",
        "\"scope\":\"same_path\",{},\"tree\":{},\"blob\":{},\"path_hex\":{},\"line_origin\":0,",
        "\"total_lines\":{},\"first_line\":{},\"end_line\":{},\"content_byte_start\":{},",
        "\"content_hex\":{},\"content_text\":{},\"graph_commits\":{},\"comparisons\":{},",
        "\"max_diff_work\":{},\"algorithms\":[{}],\"origins\":"),
        header, quote(&result.tree.to_string()), quote(&result.blob.to_string()), quote(&hex(&result.path)),
        result.total_lines, result.first_line, result.end_line, result.content_byte_start,
        quote(&hex(&result.content)), text(&result.content), result.graph_commits, result.comparisons,
        query.limits.max_diff_work, algorithms);
    append(&mut out, &origins)?; append(&mut out, ",\"lines\":[")?;
    let mut cursor = result.content_byte_start;
    for (i, line) in result.lines.iter().enumerate() {
        if line.line != result.first_line + i || line.byte_start != cursor || line.byte_end <= line.byte_start
            || line.origin_byte_end <= line.origin_byte_start || !valid_id(line.origin_blob, options)
            || line.byte_end - line.byte_start != line.origin_byte_end - line.origin_byte_start
        { return Err("blame line span mismatch".into()); }
        cursor = line.byte_end;
        if i != 0 { append(&mut out, ",")?; }
        append(&mut out, &format!(concat!("{{\"line\":{},\"byte_start\":{},\"byte_end\":{},",
            "\"origin_commit\":{},\"origin_blob\":{},\"origin_line\":{},\"origin_byte_start\":{},\"origin_byte_end\":{}}}"),
            line.line, line.byte_start, line.byte_end, quote(&line.origin_commit.to_string()), quote(&line.origin_blob.to_string()),
            line.origin_line, line.origin_byte_start, line.origin_byte_end))?;
    }
    if cursor.checked_sub(result.content_byte_start) != Some(result.content.len()) { return Err("blame content span mismatch".into()); }
    out.push_str("]}"); Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> { vec!["node".into(), "11".repeat(16), "22".repeat(16), "refs/heads/main".into(), "--trusted-local".into()] }
    #[test]
    fn modes_raw_names_ranges_and_pinned_continuations_parse_without_repository_io() {
        let input = args(); assert!(matches!(parse(&input, false).unwrap().query, Query::Log(_)));
        let mut input = args(); input.extend(["--after".into(), "1".into()]);
        assert!(parse(&input, false).is_err());
        input.extend(["--expected-head".into(), format!("head:alg:1:{}", "ab".repeat(32))]);
        let options = parse(&input, false).unwrap(); assert_eq!(parse_head(&head_token(options.head.unwrap())).unwrap(), options.head.unwrap());
        let mut input = args(); input[3] = hex(b"refs/heads/\xff");
        input.extend(["--ref-hex".into(), "--path-hex".into(), "6469722fff".into(), "--line-start".into(), "1".into(), "--line-end".into(), "3".into()]);
        let options = parse(&input, true).unwrap(); assert_eq!(options.reference.as_bytes(), b"refs/heads/\xff");
        let Query::Blame(query) = options.query else { panic!("blame"); }; assert_eq!(query.path, b"dir/\xff");
        assert_eq!((query.first_line, query.end_line), (1, Some(3)));
    }
    #[test]
    fn malformed_or_inapplicable_options_refuse_instead_of_changing_the_query() {
        for extra in [vec!["--limit", "0"], vec!["--max-commits", "4097"], vec!["--path", "file"], vec!["--trusted-local"], vec!["--after", "01"]] {
            let mut input = args(); input.extend(extra.into_iter().map(str::to_owned)); assert!(parse(&input, false).is_err());
        }
        for extra in [vec!["--path", "../file"], vec!["--path", "file", "--path-hex", "66"],
            vec!["--path", "file", "--line-start", "5", "--line-end", "4"], vec!["--path", "file", "--limit", "2"]] {
            let mut input = args(); input.extend(extra.into_iter().map(str::to_owned)); assert!(parse(&input, true).is_err());
        }
        let mut no_trust = args(); no_trust.pop(); assert!(parse(&no_trust, false).is_err());
        assert_eq!(text(b"\xff"), "null"); assert_eq!(text(b"\x1b[2J"), "\"\\u001b[2J\"");
    }
    #[test]
    fn report_output_errors_never_return_success() {
        struct Broken(bool);
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.0 { Err(std::io::Error::other("write")) } else { Ok(bytes.len()) }
            }
            fn flush(&mut self) -> std::io::Result<()> { Err(std::io::Error::other("flush")) }
        }
        assert!(emit(&mut Broken(true), "{}").is_err()); assert!(emit(&mut Broken(false), "{}").is_err());
        let mut bytes = Vec::new(); emit(&mut bytes, "{}").unwrap(); assert_eq!(bytes, b"{}\n");
    }

    #[test]
    fn rendering_preserves_raw_metadata_and_rejects_inconsistent_pages_and_line_origins() {
        let options = parse(&args(), false).unwrap();
        let head = parse_head(&format!("alg:1:{}", "ab".repeat(32))).unwrap();
        let tip = GitOid::from_hex(GitHashAlgorithm::Sha1, &"11".repeat(20)).unwrap();
        let tree = GitOid::from_hex(GitHashAlgorithm::Sha1, &"22".repeat(20)).unwrap();
        let record = HistoryCommit { id: tip, tree, parents: Vec::new(), body: b"claim\x1b[2J".to_vec() };
        let mut page = HistoryPage { tip, total_commits: 1, after: 0, next_after: None, commits: vec![record.clone()] };
        let json = render_log(&options, head, &page).unwrap();
        assert!(!json.contains('\x1b')); assert!(json.contains("body_hex"));
        page.next_after = Some(1); assert!(render_log(&options, head, &page).is_err());
        let mut input = args(); input.extend(["--path".into(), "file".into()]);
        let options = parse(&input, true).unwrap();
        let mut result = BlameResult { tip, tree, blob: tree, path: b"file".to_vec(), total_lines: 1,
            first_line: 0, end_line: 1, content_byte_start: 0, content: b"a\n".to_vec(),
            lines: vec![fgit_forge::history::BlameLine { line: 0, byte_start: 0, byte_end: 2,
                origin_commit: tip, origin_blob: tree, origin_line: 0, origin_byte_start: 0, origin_byte_end: 2 }],
            origins: vec![record], graph_commits: 1, comparisons: 0, algorithms: Vec::new() };
        assert!(render_blame(&options, head, &result).is_ok());
        result.lines[0].origin_byte_end = 1;
        assert!(render_blame(&options, head, &result).is_err());
    }
}
