//! Source bytes are JSON data, never executable HTML or inferred UTF-8. The
//! complete bounded response is checked before the listener emits success.

use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseContent, SourceBrowseQuery,
    SourceBrowseReport, SourceEntryKind};
use fgit_forge::source_search::{SearchCase, SearchCompletion, SearchLimits, SourceQuery, SourceSearchReport};
use fgit_types::{GitOid, RepositoryAuthorityHeadId, RepositoryCommitId};
use crate::OneNode;
use super::request::Selection;
use super::super::issues::{ApiError, quote, ref_fields};

pub(super) const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
fn append(out: &mut String, part: &str, maximum: usize) -> Result<(), ApiError> {
    if out.len().checked_add(part.len()).is_none_or(|n| n > maximum.min(MAX_REPLY_BYTES)) {
        return Err(ApiError::too_large());
    }
    out.try_reserve(part.len()).map_err(|_| ApiError::unavailable())?;
    out.push_str(part);
    Ok(())
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn optional_bytes(bytes: Option<&[u8]>) -> String { bytes.map_or_else(|| "null".into(), |v| quote(&hex(v))) }
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() { Ok(()) } else { Err(ApiError::from_status(super::super::Status::Timeout, false)) }
}
fn selection(node: &OneNode, requested: &Selection, head: RepositoryAuthorityHeadId,
    rcr: RepositoryCommitId, commit: GitOid, tree: GitOid,
) -> Result<String, ApiError> {
    if requested.expected_head.is_some_and(|expected| expected != head)
        || requested.expected_commit.is_some_and(|expected| expected != commit)
        || [commit, tree].iter().any(|id| id.is_zero() || id.algorithm() != node.object_format)
    { return Err(ApiError::unavailable()); }
    let internal = head.as_internal_object_id();
    let token = format!("alg:{}:{}", internal.algorithm().code_point(), hex(internal.digest().as_bytes()));
    Ok(format!(concat!("\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{},{},\"source_head\":{},",
        "\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},",
        "\"read_only\":true,\"transaction_created\":false,\"published\":false"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()),
        ref_fields("ref", &requested.reference), quote(&head.to_string()), quote(&token),
        quote(&rcr.to_string()), quote(&commit.to_string()), quote(&tree.to_string())))
}

pub(super) fn browse(node: &OneNode, requested: &Selection, query: &SourceBrowseQuery,
    report: &SourceBrowseReport, maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    if report.repository_id != node.repository_id || report.path != query.path
        || report.object_id.is_zero() || report.object_id.algorithm() != node.object_format
    { return Err(ApiError::unavailable()); }
    let identity = selection(node, requested, report.source_head, report.source_rcr,
        report.source_commit, report.root_tree)?;
    let mut out = String::new();
    match (&query.action, &report.content) {
        (SourceBrowseAction::List { after, limit }, SourceBrowseContent::Directory { entries, next_after }) => {
            if entries.len() > usize::from(*limit)
                || entries.windows(2).any(|pair| pair[0].name >= pair[1].name)
                || entries.iter().any(|row| row.name.is_empty() || row.name.len() > 4096
                    || row.name.contains(&b'/') || row.name.contains(&0)
                    || after.as_ref().is_some_and(|after| row.name <= *after)
                    || row.oid.is_zero() || row.oid.algorithm() != node.object_format)
                || next_after.as_ref().is_some_and(|next| entries.len() != usize::from(*limit)
                    || entries.last().map(|row| &row.name) != Some(next))
            { return Err(ApiError::unavailable()); }
            append(&mut out, &format!(concat!("{{\"type\":\"source_tree\",{},\"object_id\":{},",
                "\"path_hex\":{},\"after_hex\":{},\"limit\":{},\"next_after_hex\":{},\"entries\":["),
                identity, quote(&report.object_id.to_string()), optional_bytes(report.path.as_deref()),
                optional_bytes(after.as_deref()), limit, optional_bytes(next_after.as_deref())), maximum)?;
            for (index, row) in entries.iter().enumerate() {
                checkpoint(live)?;
                append(&mut out, &format!("{}{{\"name_hex\":{},\"object_id\":{},\"kind\":{}}}",
                    if index == 0 { "" } else { "," }, quote(&hex(&row.name)),
                    quote(&row.oid.to_string()), quote(row.kind.as_str())), maximum)?;
            }
            append(&mut out, "]}", maximum)?;
        }
        (SourceBrowseAction::Read { offset, limit }, SourceBrowseContent::Blob {
            kind, bytes, total_bytes, offset: actual_offset, next_offset,
        }) => {
            let end = offset.checked_add(bytes.len() as u64).ok_or_else(ApiError::unavailable)?;
            if actual_offset != offset || end > *total_bytes || bytes.len() > *limit as usize
                || *offset > *total_bytes || bytes.len() as u64 != u64::from(*limit).min(total_bytes - offset)
                || *next_offset != (end < *total_bytes).then_some(end)
                || !matches!(kind, SourceEntryKind::File | SourceEntryKind::Executable | SourceEntryKind::Symlink)
            { return Err(ApiError::unavailable()); }
            append(&mut out, &format!(concat!("{{\"type\":\"source_blob\",{},\"object_id\":{},",
                "\"path_hex\":{},\"kind\":{},\"total_bytes\":{},\"offset\":{},\"returned_bytes\":{},",
                "\"next_offset\":{},\"content_hex\":{},\"symlink_followed\":false}}"),
                identity, quote(&report.object_id.to_string()), optional_bytes(report.path.as_deref()),
                quote(kind.as_str()), total_bytes, offset, bytes.len(),
                next_offset.map_or_else(|| "null".into(), |n| n.to_string()), quote(&hex(bytes))), maximum)?;
        }
        _ => return Err(ApiError::unavailable()),
    }
    checkpoint(live)?;
    Ok(out)
}

pub(super) fn search(node: &OneNode, requested: &Selection, query: &SourceQuery,
    limits: SearchLimits, head: RepositoryAuthorityHeadId, report: &SourceSearchReport,
    maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    if report.repository != node.repository_id || report.matches.len() > limits.max_matches
        || report.files_read > report.files_selected || report.bytes_searched > report.bytes_read
        || (report.completion == SearchCompletion::Complete && report.files_read != report.files_selected)
        || (report.completion == SearchCompletion::MatchLimit && report.matches.len() != limits.max_matches)
        || report.matches.windows(2).any(|pair| (&pair[0].path, pair[0].byte_offset) >= (&pair[1].path, pair[1].byte_offset))
    { return Err(ApiError::unavailable()); }
    let identity = selection(node, requested, head, report.source_rcr, report.source_commit, report.source_tree)?;
    let completion = match report.completion { SearchCompletion::Complete => "complete", SearchCompletion::MatchLimit => "match_limit" };
    let case = match query.case() { SearchCase::Exact => "exact", SearchCase::AsciiInsensitive => "ascii-insensitive" };
    let mut out = String::new();
    append(&mut out, &format!(concat!("{{\"type\":\"source_search\",{},\"profile\":\"literal-bytes-v1\",",
        "\"case\":{},\"completion\":{},\"complete\":{},\"max_matches\":{},\"returned_matches\":{},",
        "\"files_selected\":{},\"files_read\":{},\"bytes_read\":{},\"bytes_searched\":{},",
        "\"non_regular_entries\":{},\"matches\":["),
        identity, quote(case), quote(completion), report.completion == SearchCompletion::Complete,
        limits.max_matches, report.matches.len(), report.files_selected, report.files_read,
        report.bytes_read, report.bytes_searched, report.non_regular_entries), maximum)?;
    for (index, row) in report.matches.iter().enumerate() {
        checkpoint(live)?;
        let excerpt_end = row.excerpt_offset.checked_add(row.excerpt.len()).ok_or_else(ApiError::unavailable)?;
        let match_end = row.byte_offset.checked_add(row.match_length).ok_or_else(ApiError::unavailable)?;
        if row.path.is_empty() || row.path.len() > 4096 || row.excerpt.len() > 416
            || row.match_length != query.needle().len() || row.line == 0 || row.byte_column == 0
            || row.byte_offset < row.excerpt_offset || match_end > excerpt_end
            || row.blob.is_zero() || row.blob.algorithm() != node.object_format
        { return Err(ApiError::unavailable()); }
        append(&mut out, &format!(concat!("{}{{\"path_hex\":{},\"blob\":{},\"byte_offset\":{},",
            "\"line\":{},\"byte_column\":{},\"match_length\":{},\"excerpt_offset\":{},\"excerpt_hex\":{}}}"),
            if index == 0 { "" } else { "," }, quote(&hex(&row.path)), quote(&row.blob.to_string()),
            row.byte_offset, row.line, row.byte_column, row.match_length, row.excerpt_offset,
            quote(&hex(&row.excerpt))), maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    checkpoint(live)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_excerpts_and_file_payloads_have_one_lossless_byte_encoding() {
        assert_eq!(hex(b"\0\xff\r\n<script>"), "00ff0d0a3c7363726970743e");
        assert_eq!(optional_bytes(None), "null");
        assert_eq!(optional_bytes(Some(b"")), "\"\"");
        assert_ne!(optional_bytes(None), optional_bytes(Some(b"")));
    }
    #[test]
    fn response_limit_and_cancellation_cannot_produce_a_partial_success() {
        let mut out = String::from("abc");
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        append(&mut out, "d", 4).unwrap();
        assert_eq!(out, "abcd");
        assert!(checkpoint(&mut || false).is_err());
    }
}
