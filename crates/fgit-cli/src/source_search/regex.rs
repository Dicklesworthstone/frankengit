//! Explicit byte-regex CLI profile over the node's existing snapshot reader.
use super::{Options, SearchCase, SearchCompletion, hex, quote, set_once, write_report};
use fgit_forge::source_search::regex::{MAX_REGEX_STEPS, RegexQuery, RegexSearchReport};
use fgit_node::{NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitOid, RepositoryAuthorityHeadId};
use std::io::Write;

const USAGE: &str = "usage: fg search --regex <storage-root> <tenant-id> <repository-id> <full-ref>
  --trusted-local (--pattern <byte-regex> | --pattern-hex <bytes>)
  [--object-format sha1|sha256] [--ignore-ascii-case]
  [--path <prefix> | --path-hex <bytes>]... [--max-matches <1..4096>]
  [--max-files <1..20000>] [--max-file-bytes <1..8388608>]
  [--max-bytes <1..67108864>] [--max-regex-steps <1..67108864>]
  [--expected-head <alg:N:hex>] [--expected-commit <native-oid>]

One leftmost-longest byte span per matching LF line, not all occurrences.
CR is preserved; empty lines and zero-width spans are supported. No captures,
backreferences, lookaround, Unicode normalization, source execution or indexes.
Patterns: at most 256 bytes; the native compiler bounds states and compile work.
Exit 0: complete (including no matches); 3: match-limit prefix; 2: error.
Work exhaustion fails the whole read. A long match may exceed its excerpt.";

struct Input {
    source: Options,
    query: RegexQuery,
    head: Option<RepositoryAuthorityHeadId>,
    commit: Option<GitOid>,
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        write_report(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let input = parse(args)?;
    let mut node = OneNode::open_existing(NodeConfig::new(
        input.source.storage.clone(), input.source.tenant, input.source.repository,
    ).with_object_format(input.source.format)).map_err(|e| e.to_string())?;
    let operation = (|| {
        let selected = node.runtime().block_on(node.authenticate_authority_head()).map_err(|e| e.to_string())?;
        node.bring_into_service(selected.receipt().generation()).map_err(|e| e.to_string())?;
        let request = fgit_cli::command_request_context(&node);
        node.runtime().block_on(node.search_source_regex_snapshot_local_in(
            &request, &input.source.reference, input.head, input.commit, &input.query, input.source.limits,
        )).map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    finish(&mut std::io::stdout().lock(), &input, operation, cleanup)
}

fn parse(args: &[String]) -> Result<Input, String> {
    if args.len() < 4 || args.len() > 296 || args.iter().any(|a| a.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
    { return Err(USAGE.into()); }
    let mut common = args[..4].to_vec();
    let (mut pattern, mut steps, mut expected_head, mut expected_commit) = (None, None, None, None);
    let mut cursor = 4;
    while cursor < args.len() {
        let flag = args[cursor].as_str(); cursor += 1;
        if matches!(flag, "--trusted-local" | "--ignore-ascii-case") {
            common.push(flag.into());
            continue;
        }
        let value = args.get(cursor).ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag {
            "--pattern" => {
                if value.is_empty() || value.len() > 256 { return Err("pattern must contain 1..256 bytes".into()); }
                set_once(&mut pattern, value.as_bytes().to_vec(), "pattern")?;
            }
            "--pattern-hex" => set_once(&mut pattern, super::unhex(value, 256)?, "pattern")?,
            "--max-regex-steps" => set_once(&mut steps, super::decimal(value)? as u64, flag)?,
            "--expected-head" => set_once(&mut expected_head, parse_head(value)?, flag)?,
            "--expected-commit" => set_once(&mut expected_commit, value.clone(), flag)?,
            "--path" | "--path-hex" | "--object-format" | "--max-matches" | "--max-files"
            | "--max-file-bytes" | "--max-bytes" => common.extend([flag.into(), value.clone()]),
            _ => return Err(format!("unsupported regex search option {flag}")),
        }
    }
    // Reuse the existing trust/format/scope/source-limit parser. This sentinel
    // only constructs its scope, exactly as RegexQuery does internally. Neither
    // a literal matcher nor an alternate query is ever executed or reported.
    common.extend(["--literal".into(), "regex-scope".into()]);
    let source = super::parse(&common)?;
    if !source.reference.as_bytes().starts_with(b"refs/") { return Err("a full refs/ reference is required".into()); }
    let prefixes = source.query.prefixes().iter().map(|p| p.as_bytes().to_vec()).collect::<Vec<_>>();
    let query = RegexQuery::new(&pattern.ok_or("--pattern or --pattern-hex is required")?,
        source.query.case(), &prefixes, steps.unwrap_or(MAX_REGEX_STEPS)).map_err(|e| e.to_string())?;
    let commit = expected_commit.map(|value| {
        if value.len() != source.format.digest_len() * 2
            || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        { return Err("invalid expected commit".to_owned()); }
        let oid = GitOid::from_hex(source.format, &value).map_err(|e| e.to_string())?;
        if oid.is_zero() { return Err("expected commit must be nonzero".into()); }
        Ok(oid)
    }).transpose()?;
    Ok(Input { source, query, head: expected_head, commit })
}
fn parse_head(value: &str) -> Result<RepositoryAuthorityHeadId, String> {
    if value.len() > 140 { return Err("snapshot token is too long".into()); }
    let (algorithm, digest) = value.strip_prefix("alg:").and_then(|s| s.split_once(':'))
        .ok_or("expected alg:N:hex snapshot token")?;
    let algorithm = u16::try_from(super::decimal(algorithm)?).map_err(|_| "algorithm overflow")?;
    let algorithm = DigestAlgorithmId::try_new(algorithm).map_err(|e| e.to_string())?;
    if !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("snapshot digest must be lowercase hex".into());
    }
    let digest = DigestBytes::try_new(&super::unhex(digest, 64)?).map_err(|e| e.to_string())?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm, CANONICAL_CODEC_VERSION, digest))
}
fn head_token(value: RepositoryAuthorityHeadId) -> String {
    let value = value.as_internal_object_id();
    format!("alg:{}:{}", value.algorithm().code_point(), hex(value.digest().as_bytes()))
}
fn finish(output: &mut impl Write, input: &Input,
    operation: Result<(RepositoryAuthorityHeadId, RegexSearchReport), String>, cleanup: Option<String>) -> Result<u8, String>
{
    let (head, report) = match (operation, cleanup) {
        (Ok(report), None) => report,
        (Err(error), None) => return Err(error),
        (Ok(_), Some(error)) => return Err(format!("regex node shutdown failed: {error}")),
        (Err(error), Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let text = render(input, head, &report)?;
    write_report(output, &text)?;
    Ok(if report.source.completion == SearchCompletion::Complete { 0 } else { 3 })
}
fn render(input: &Input, head: RepositoryAuthorityHeadId, report: &RegexSearchReport) -> Result<String, String> {
    let source = &report.source;
    let complete = source.completion == SearchCompletion::Complete;
    let limits = input.source.limits;
    if input.head.is_some_and(|h| h != head) || input.commit.is_some_and(|c| c != source.source_commit)
        || source.repository != input.source.repository
        || [source.source_commit, source.source_tree].iter().any(|id| id.is_zero() || id.algorithm() != input.source.format)
        || report.program_states != input.query.state_count() || report.steps > input.query.maximum_steps()
        || source.files_read > source.files_selected || source.files_selected > limits.max_files
        || source.bytes_read > limits.max_total_bytes || source.bytes_searched > source.bytes_read
        || report.lines_searched > source.bytes_searched || source.matches.len() > report.lines_searched
        || source.matches.len() > limits.max_matches
        || (complete && (source.files_read != source.files_selected || source.bytes_read != source.bytes_searched))
        || (!complete && (source.matches.len() != limits.max_matches || report.lines_searched <= source.matches.len()))
        || source.matches.windows(2).any(|p| (&p[0].path, p[0].byte_offset) >= (&p[1].path, p[1].byte_offset)
            || (p[0].path == p[1].path && (p[0].line >= p[1].line || p[0].blob != p[1].blob)))
    { return Err("invalid native regex report".into()); }
    let paths = input.query.prefixes().iter().map(|p| quote(&hex(p.as_bytes()))).collect::<Vec<_>>().join(",");
    let mut out = format!(concat!(
        "{{\"type\":\"source_regex_search\",\"profile\":\"line-byte-regex-v1\",",
        "\"match_semantics\":\"one_leftmost_longest_span_per_matching_lf_line\",",
        "\"snapshot_token\":{},\"repository_id\":{},\"source_rcr\":{},\"source_commit\":{},\"source_tree\":{},",
        "\"reference_hex\":{},\"pattern_hex\":{},\"case\":{},\"path_prefixes_hex\":[{}],",
        "\"complete\":{},\"truncated_reason\":{},\"program_states\":{},\"regex_steps\":{},",
        "\"max_regex_steps\":{},\"lines_searched\":{},\"files_selected\":{},\"files_read\":{},",
        "\"bytes_read\":{},\"bytes_searched\":{},\"non_regular_entries\":{},\"match_count\":{},",
        "\"node_closed\":true,\"repository_changed\":false,\"matches\":["),
        quote(&head_token(head)), quote(&source.repository.to_string()), quote(&source.source_rcr.to_string()),
        quote(&source.source_commit.to_string()), quote(&source.source_tree.to_string()),
        quote(&hex(input.source.reference.as_bytes())), quote(&hex(input.query.pattern())),
        quote(match input.query.case() { SearchCase::Exact => "exact", SearchCase::AsciiInsensitive => "ascii_insensitive" }),
        paths, complete, if complete { "null" } else { "\"match_limit\"" }, report.program_states,
        report.steps, input.query.maximum_steps(), report.lines_searched, source.files_selected,
        source.files_read, source.bytes_read, source.bytes_searched, source.non_regular_entries, source.matches.len());
    for (ordinal, hit) in source.matches.iter().enumerate() {
        let invalid = || "invalid native regex span".to_owned();
        let column = hit.byte_column.checked_sub(1).ok_or_else(invalid)?;
        let line_start = hit.byte_offset.checked_sub(column).ok_or_else(invalid)?;
        let end = hit.byte_offset.checked_add(hit.match_length).ok_or_else(invalid)?;
        let excerpt_end = hit.excerpt_offset.checked_add(hit.excerpt.len()).ok_or_else(invalid)?;
        if hit.line == 0 || hit.path.is_empty() || hit.path.len() > 4096 || hit.path.contains(&0)
            || hit.path.split(|b| *b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
            || hit.blob.is_zero() || hit.blob.algorithm() != input.source.format
            || hit.excerpt.len() > 416 || hit.excerpt.contains(&b'\n')
            || end > limits.max_file_bytes || excerpt_end > limits.max_file_bytes || hit.byte_offset > excerpt_end
            || hit.excerpt_offset != line_start + column.saturating_sub(80)
            || (!input.query.prefixes().is_empty() && !input.query.prefixes().iter().any(|p| {
                hit.path == p.as_bytes() || hit.path.strip_prefix(p.as_bytes()).is_some_and(|tail| tail.starts_with(b"/"))
            }))
        { return Err(invalid()); }
        let full = end <= excerpt_end;
        let matched = if full {
            let start = hit.byte_offset.checked_sub(hit.excerpt_offset).ok_or_else(invalid)?;
            let stop = start.checked_add(hit.match_length).ok_or_else(invalid)?;
            quote(&hex(hit.excerpt.get(start..stop).ok_or_else(invalid)?))
        } else { "null".into() };
        if ordinal != 0 { out.push(','); }
        out.push_str(&format!(concat!("{{\"path_hex\":{},\"blob\":{},\"byte_offset\":{},\"match_length\":{},",
            "\"line\":{},\"byte_column\":{},\"excerpt_offset\":{},\"excerpt_hex\":{},",
            "\"match_fully_in_excerpt\":{},\"match_bytes_hex\":{}}}"),
            quote(&hex(&hit.path)), quote(&hit.blob.to_string()), hit.byte_offset, hit.match_length,
            hit.line, hit.byte_column, hit.excerpt_offset, quote(&hex(&hit.excerpt)), full, matched));
        if out.len() > 48 * 1024 * 1024 { return Err("regex response exceeds output limit".into()); }
    }
    out.push_str("]}");
    Ok(out)
}

#[cfg(test)]
mod tests;
