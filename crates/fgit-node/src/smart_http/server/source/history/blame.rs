//! Exact same-path line provenance over the authenticated native history
//! reader. Ranges limit disclosure; they never select arbitrary Git objects.

use std::collections::{BTreeMap, BTreeSet};

use fgit_forge::history::{BlameOptions, BlameResult, HistoryLimits};
use fgit_types::{GitHashAlgorithm, RepositoryAuthorityHeadId};
use fgit_wire::visibility::RefVisibility;

use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, OneNode};
use crate::smart_http::drive_request_while;
use super::{Output, Selection, checkpoint, commit, failure, identity, number, selection, take, valid_oid};
use super::super::super::{Status, issues::{ApiError, Reply, parse_form, quote}};

#[derive(Debug)]
struct Command { selection: Selection, options: BlameOptions }
impl Command {
    fn parse(bytes: &[u8], format: GitHashAlgorithm) -> Result<Self, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 32)? {
            if !matches!(name.as_str(), "ref" | "object_format" | "expected_head" | "expected_commit"
                | "path_hex" | "line_start" | "line_end" | "max_commits" | "max_edges"
                | "max_tree_entries" | "max_blob_bytes" | "max_lines" | "max_cached_bytes"
                | "max_comparisons" | "max_diff_work" | "max_metadata_bytes")
            { return Err(ApiError::bad("unknown_or_inapplicable_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        let selection = selection(&mut fields, format)?;
        let text = take(&mut fields, "path_hex")?;
        if text.is_empty() || text.len() > 8192 || text.len() % 2 != 0
            || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        { return Err(ApiError::bad("invalid_history_path")); }
        let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        let path = text.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect();
        let mut limits = HistoryLimits::default();
        limits.max_commits = number(&mut fields, "max_commits", limits.max_commits)?;
        limits.max_edges = number(&mut fields, "max_edges", limits.max_edges)?;
        limits.max_tree_entries = number(&mut fields, "max_tree_entries", limits.max_tree_entries)?;
        limits.max_blob_bytes = number(&mut fields, "max_blob_bytes", limits.max_blob_bytes)?;
        limits.max_lines = number(&mut fields, "max_lines", limits.max_lines)?;
        limits.max_cached_bytes = number(&mut fields, "max_cached_bytes", limits.max_cached_bytes)?;
        limits.max_comparisons = number(&mut fields, "max_comparisons", limits.max_comparisons)?;
        limits.max_diff_work = number(&mut fields, "max_diff_work", limits.max_diff_work)?;
        limits.max_metadata_bytes = number(&mut fields, "max_metadata_bytes", limits.max_metadata_bytes)?;
        let first_line = number(&mut fields, "line_start", 0)?;
        let end_line = if fields.contains_key("line_end") { Some(number(&mut fields, "line_end", 0)?) } else { None };
        let options = BlameOptions { path, first_line, end_line, limits };
        options.validate().map_err(|_| ApiError::bad("invalid_blame_range_path_or_limits"))?;
        Ok(Self { selection, options })
    }
}

/// The parent has authenticated the request and fully decoded its bounded
/// form. This helper never receives a write key or calls an admission method.
pub(super) fn execute(node: &OneNode, bytes: &[u8], maximum_response: u64) -> Result<Reply, ApiError> {
    let command = Command::parse(bytes, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let (head, result) = drive_request_while(node, &context,
        node.blame_source_in(&context, &command.selection.reference, &RefVisibility::new(),
            command.selection.expected_head, &command.options), &mut live).map_err(|error| {
                failure(error.is_snapshot_moved(), error.is_unavailable(),
                    error.is_unpinned_continuation(), error.history_error())
            })?;
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX);
    let body = render(node, &command, head, &result, maximum, &mut live)?;
    Ok(Reply { status: Status::Success, body, terminal: None })
}

fn validate(result: &BlameResult, query: &BlameOptions, format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    checkpoint(live)?;
    if result.path != query.path || result.first_line != query.first_line
        || result.end_line != query.end_line.unwrap_or(result.total_lines)
        || result.end_line < result.first_line || result.end_line > result.total_lines
        || result.total_lines > query.limits.max_lines
        || result.lines.len() != result.end_line - result.first_line
        || result.content.len() > query.limits.max_blob_bytes
        || result.content_byte_start.checked_add(result.content.len()).is_none_or(|n| n > query.limits.max_blob_bytes)
        || !valid_oid(format, result.tip) || !valid_oid(format, result.tree) || !valid_oid(format, result.blob)
        || result.graph_commits == 0 || result.graph_commits > query.limits.max_commits
        || result.comparisons > query.limits.max_comparisons || result.algorithms.len() > query.limits.max_comparisons
        || result.origins.len() > query.limits.max_commits
        || result.origins.windows(2).any(|pair| pair[0].id >= pair[1].id)
    { return Err(ApiError::unavailable()); }
    let mut origin_ids = BTreeSet::new();
    let mut metadata = 0_usize;
    for origin in &result.origins {
        checkpoint(live)?;
        if !valid_oid(format, origin.id) || !origin_ids.insert(origin.id) { return Err(ApiError::unavailable()); }
        metadata = metadata.checked_add(origin.body.len()).ok_or_else(ApiError::too_large)?;
        if metadata > query.limits.max_metadata_bytes { return Err(ApiError::too_large()); }
    }
    let mut used_origins = BTreeSet::new();
    let mut cursor = result.content_byte_start;
    for (index, line) in result.lines.iter().enumerate() {
        checkpoint(live)?;
        if line.line != result.first_line + index || line.byte_start != cursor || line.byte_end <= line.byte_start
            || line.origin_byte_end <= line.origin_byte_start || line.origin_byte_end > query.limits.max_blob_bytes
            || line.origin_line >= query.limits.max_lines || !valid_oid(format, line.origin_blob)
            || !origin_ids.contains(&line.origin_commit)
            || line.byte_end - line.byte_start != line.origin_byte_end - line.origin_byte_start
        { return Err(ApiError::unavailable()); }
        let start = line.byte_start.checked_sub(result.content_byte_start).ok_or_else(ApiError::unavailable)?;
        let end = line.byte_end.checked_sub(result.content_byte_start).ok_or_else(ApiError::unavailable)?;
        let bytes = result.content.get(start..end).ok_or_else(ApiError::unavailable)?;
        // Exactly one newline-inclusive line per row; CRLF and non-UTF-8
        // bytes stay unchanged. Only the final file line may lack a newline.
        if bytes.is_empty() || bytes[..bytes.len() - 1].contains(&b'\n')
            || (line.line + 1 < result.total_lines && bytes.last() != Some(&b'\n'))
        { return Err(ApiError::unavailable()); }
        cursor = line.byte_end;
        used_origins.insert(line.origin_commit);
    }
    if cursor.checked_sub(result.content_byte_start) != Some(result.content.len()) || used_origins != origin_ids {
        return Err(ApiError::unavailable());
    }
    checkpoint(live)
}

fn render(node: &OneNode, command: &Command, head: RepositoryAuthorityHeadId, result: &BlameResult,
    maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    validate(result, &command.options, node.object_format, live)?;
    let mut out = Output::new(maximum);
    identity(&mut out, node, &command.selection, head, result.tip, "source_blame", live)?;
    out.append(&format!(concat!(",\"profile\":\"exact-lines-all-parents-v1\",\"scope\":\"same_path\",",
        "\"range_complete\":true,\"line_origin\":0,\"tree\":{},\"blob\":{},\"path_hex\":"),
        quote(&result.tree.to_string()), quote(&result.blob.to_string())))?;
    out.hex(&result.path, live)?;
    out.append(&format!(concat!(",\"total_lines\":{},\"first_line\":{},\"end_line\":{},",
        "\"content_byte_start\":{},\"content_hex\":"), result.total_lines, result.first_line,
        result.end_line, result.content_byte_start))?;
    out.hex(&result.content, live)?;
    out.append(&format!(",\"graph_commits\":{},\"comparisons\":{},\"max_diff_work\":{},\"algorithms\":[",
        result.graph_commits, result.comparisons, command.options.limits.max_diff_work))?;
    for (index, algorithm) in result.algorithms.iter().enumerate() {
        checkpoint(live)?;
        if index != 0 { out.append(",")?; }
        out.append(&quote(&format!("{algorithm:?}")))?;
    }
    out.append("],\"origins\":[")?;
    for (index, origin) in result.origins.iter().enumerate() {
        if index != 0 { out.append(",")?; }
        commit(&mut out, origin, node.object_format, live)?;
    }
    out.append("],\"lines\":[")?;
    for (index, line) in result.lines.iter().enumerate() {
        checkpoint(live)?;
        if index != 0 { out.append(",")?; }
        out.append(&format!(concat!("{{\"line\":{},\"byte_start\":{},\"byte_end\":{},\"origin_commit\":{},",
            "\"origin_blob\":{},\"origin_line\":{},\"origin_byte_start\":{},\"origin_byte_end\":{}}}"),
            line.line, line.byte_start, line.byte_end, quote(&line.origin_commit.to_string()),
            quote(&line.origin_blob.to_string()), line.origin_line, line.origin_byte_start, line.origin_byte_end))?;
    }
    out.append("]}")?;
    out.finish(live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_crypto::{GitObjectKind, git_object_id};
    use fgit_forge::history::{BlameLine, HistoryCommit};

    #[test]
    fn blame_forms_preserve_byte_paths_and_bound_every_requested_dimension() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let base = format!("object_format={}&ref=refs/heads/main&path_hex=6469722fff", format.as_str());
            let query = Command::parse((base.clone() + "&line_start=1&line_end=3").as_bytes(), format).unwrap();
            assert_eq!(query.options.path, b"dir/\xff");
            assert_eq!((query.options.first_line, query.options.end_line), (1, Some(3)));
            for extra in ["&path_hex=61", "&after=1", "&limit=2", "&principal=admin", "&line_start=-1",
                "&line_start=3&line_end=2", "&max_commits=0", "&max_edges=16385", "&max_tree_entries=100001",
                "&max_blob_bytes=1048577", "&max_lines=20001", "&max_cached_bytes=33554433",
                "&max_comparisons=129", "&max_diff_work=1000001", "&max_metadata_bytes=4194305"]
            { assert!(Command::parse((base.clone() + extra).as_bytes(), format).is_err(), "{extra}"); }
            for path in ["", "FF", "0", "00", "2e2e2f61", "2f61", "612f2f62"] {
                let input = format!("object_format={}&ref=refs/heads/main&path_hex={path}", format.as_str());
                assert!(Command::parse(input.as_bytes(), format).is_err(), "{path}");
            }
        }
    }

    fn fixture() -> (BlameOptions, BlameResult) {
        let format = GitHashAlgorithm::Sha1;
        let tree = git_object_id(format, GitObjectKind::Tree, &[]);
        let blob = git_object_id(format, GitObjectKind::Blob, b"one\r\ntwo");
        let body = format!("tree {tree}\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nsource\n").into_bytes();
        let tip = git_object_id(format, GitObjectKind::Commit, &body);
        let options = BlameOptions { path: b"file".to_vec(), first_line: 1, end_line: Some(2), limits: HistoryLimits::default() };
        let result = BlameResult { tip, tree, blob, path: options.path.clone(), total_lines: 2, first_line: 1,
            end_line: 2, content_byte_start: 5, content: b"two".to_vec(), graph_commits: 1, comparisons: 0,
            algorithms: vec![], origins: vec![HistoryCommit { id: tip, tree, parents: vec![], body }],
            lines: vec![BlameLine { line: 1, byte_start: 5, byte_end: 8, origin_commit: tip, origin_blob: blob,
                origin_line: 1, origin_byte_start: 5, origin_byte_end: 8 }] };
        (options, result)
    }

    #[test]
    fn line_ranges_and_origin_records_are_checked_before_disclosure() {
        let (options, result) = fixture();
        assert!(validate(&result, &options, GitHashAlgorithm::Sha1, &mut || true).is_ok());
        for mutation in 0..7 {
            let mut broken = result.clone();
            match mutation {
                0 => broken.content.extend_from_slice(b"secret"),
                1 => broken.lines[0].byte_start += 1,
                2 => broken.lines[0].origin_byte_end += 1,
                3 => broken.origins.clear(),
                4 => broken.origins.push(broken.origins[0].clone()),
                5 => broken.lines[0].line = 0,
                _ => broken.content = b"t\no".to_vec(),
            }
            assert!(validate(&broken, &options, GitHashAlgorithm::Sha1, &mut || true).is_err());
        }
        assert!(validate(&result, &options, GitHashAlgorithm::Sha256, &mut || true).is_err());
        assert!(validate(&result, &options, GitHashAlgorithm::Sha1, &mut || false).is_err());
    }

    #[test]
    fn cancellation_during_hex_output_cannot_escape_as_a_complete_body() {
        let mut output = Output::new(32 * 1024);
        let mut calls = 0;
        assert!(output.hex(&vec![b'x'; 8192], &mut || { calls += 1; calls < 3 }).is_err());
        assert_eq!(calls, 3);
        let mut permitted = Output::new(32 * 1024);
        permitted.hex(&vec![b'x'; 8192], &mut || true).unwrap();
        assert_eq!(permitted.finish(&mut || true).unwrap().len(), 2 + 8192 * 2);
    }

    #[test]
    fn blame_route_is_read_only_and_shares_the_same_outer_authorization() {
        let bytes = b"POST /r.git/api/v1/source/blame HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
        let envelope = fgit_wire::smart_http::head::parse(bytes, fgit_wire::smart_http::HttpLimits::default()).unwrap().unwrap();
        let request = super::super::super::Request::parse(&envelope).unwrap();
        assert!(!request.is_mutation());
    }
}
