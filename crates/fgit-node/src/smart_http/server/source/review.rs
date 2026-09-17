//! Read-only comparison of two authority-selected refs. The source gateway
//! authenticates before body intake; neither form fields nor returned diffs
//! authorize publication, an approval, or an arbitrary-object lookup.

mod output;

use std::collections::BTreeMap;
use std::io::Read;

use fgit_forge::review::{ComparisonMode, ReviewError, ReviewOptions, ReviewSelection};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode};
use crate::smart_http::drive_request_while;
use super::super::{Status, issues::{ApiError, MAX_FORM_BYTES, Reply, parse_decimal, parse_form, parse_snapshot, read_form}};

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head.target.split_once('?').map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else { return Ok(None); };
        if action != "diff" { return Ok(None); }
        if repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)))
        { return Err(ApiError::not_found()); }
        if head.method != "POST" { return Err(ApiError::method()); }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_diff_envelope"));
        }
        if !head.content_type.is_some_and(|media| media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8"))
        { return Err(ApiError::media()); }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self { repository_route }))
    }
}

#[derive(Debug)]
struct Command {
    selection: ReviewSelection,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_before: Option<GitOid>,
    expected_after: Option<GitOid>,
    options: ReviewOptions,
}
impl Command {
    fn parse(bytes: &[u8], format: GitHashAlgorithm) -> Result<Self, ApiError> {
        let mut fields = BTreeMap::new();
        let mut paths = Vec::new();
        for (name, value) in parse_form(bytes, 80)? {
            if name == "path_prefix_hex" {
                if paths.len() == 64 { return Err(ApiError::too_large()); }
                paths.push(unhex(&value, 4096)?);
                continue;
            }
            if !matches!(name.as_str(), "object_format" | "before_ref" | "after_ref" | "mode"
                | "expected_head" | "expected_before" | "expected_after" | "context_lines"
                | "max_tree_entries" | "max_changes" | "max_text_files" | "max_blob_bytes"
                | "max_output_bytes" | "max_hunks" | "max_diff_work")
            { return Err(ApiError::bad("unknown_or_inapplicable_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let before = RefName::try_new(take(&mut fields, "before_ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        let after = RefName::try_new(take(&mut fields, "after_ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        let expected_head = fields.remove("expected_head").map(|text| parse_snapshot(&text)).transpose()?;
        let expected_before = fields.remove("expected_before").map(|text| oid(&text, format)).transpose()?;
        let expected_after = fields.remove("expected_after").map(|text| oid(&text, format)).transpose()?;
        let mut options = ReviewOptions::default();
        options.paths = paths;
        options.mode = match fields.remove("mode").as_deref().unwrap_or("direct") {
            "direct" => ComparisonMode::Direct,
            "merge-base" => ComparisonMode::MergeBase,
            _ => return Err(ApiError::bad("invalid_diff_mode")),
        };
        options.context_lines = number(&mut fields, "context_lines", options.context_lines)?;
        let limits = &mut options.limits;
        limits.max_tree_entries = number(&mut fields, "max_tree_entries", limits.max_tree_entries)?;
        limits.max_changes = number(&mut fields, "max_changes", limits.max_changes)?;
        limits.max_text_files = number(&mut fields, "max_text_files", limits.max_text_files)?;
        limits.max_blob_bytes = number(&mut fields, "max_blob_bytes", limits.max_blob_bytes)?;
        limits.max_output_bytes = number(&mut fields, "max_output_bytes", limits.max_output_bytes)?;
        limits.max_hunks = number(&mut fields, "max_hunks", limits.max_hunks)?;
        limits.max_diff_work = number(&mut fields, "max_diff_work", limits.max_diff_work)?;
        options.validate().map_err(|_| ApiError::bad("invalid_diff_options"))?;
        Ok(Self { selection: ReviewSelection::References { before, after }, expected_head,
            expected_before, expected_after, options })
    }
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields.remove(name).ok_or_else(|| ApiError::bad("missing_diff_field"))
}
fn number(fields: &mut BTreeMap<String, String>, name: &str, fallback: usize) -> Result<usize, ApiError> {
    fields.remove(name).map_or(Ok(fallback), |text| {
        usize::try_from(parse_decimal(&text)?).map_err(|_| ApiError::bad("invalid_diff_number"))
    })
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > maximum * 2
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err(ApiError::bad("invalid_hex_bytes")); }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect())
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if unhex(text, format.digest_len())?.len() != format.digest_len() {
        return Err(ApiError::bad("invalid_expected_commit"));
    }
    let id = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_expected_commit"))?;
    if id.is_zero() { return Err(ApiError::bad("invalid_expected_commit")); }
    Ok(id)
}

pub(super) fn execute(node: &OneNode, _request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, http: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() { return Err(ApiError::new(Status::Unauthorized, "unauthorized")); }
    let command = Command::parse(&read_form(reader, framing, http)?, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let report = drive_request_while(node, &context,
        node.review_source_in(&context, &command.selection, &RefVisibility::new(), command.expected_head, &command.options),
        &mut live).map_err(|error| {
            failure(error.is_snapshot_moved(), error.is_version_moved(), error.is_unavailable(), error.review_error())
        })?;
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX);
    let body = output::render(node, &command, &report, maximum, &mut live)?;
    Ok(Reply { status: Status::Success, body, terminal: None })
}
fn failure(snapshot: bool, version: bool, unavailable: bool, cause: Option<&ReviewError>) -> ApiError {
    if snapshot { return ApiError::new(Status::Conflict, "source_snapshot_moved"); }
    if version { return ApiError::new(Status::Conflict, "pull_request_version_moved"); }
    if unavailable { return ApiError::not_found(); }
    match cause {
        Some(ReviewError::InvalidOptions) => ApiError::bad("invalid_diff_options"),
        Some(ReviewError::NoCommonAncestor) => ApiError::new(Status::Conflict, "no_common_ancestor"),
        Some(ReviewError::MultipleMergeBases(_)) => ApiError::new(Status::Conflict, "multiple_merge_bases"),
        Some(ReviewError::Budget(_)) => ApiError::too_large(),
        // Source failure is not proof that two trees are equal. Never return
        // internal IDs, backend details, or a fabricated successful empty diff.
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::head;
    fn form() -> String { "object_format=sha1&before_ref=refs/heads/base&after_ref=refs/heads/main".into() }
    #[test]
    fn native_modes_byte_prefixes_and_downward_limits_parse() {
        let command = Command::parse((form() + "&mode=merge-base&context_lines=0&path_prefix_hex=6469722fff&max_changes=1").as_bytes(), GitHashAlgorithm::Sha1).unwrap();
        assert_eq!(command.options.mode, ComparisonMode::MergeBase);
        assert_eq!(command.options.context_lines, 0);
        assert_eq!(command.options.paths, vec![b"dir/\xff".to_vec()]);
        assert_eq!(command.options.limits.max_changes, 1);
        assert!(matches!(command.selection, ReviewSelection::References { .. }));
    }
    #[test]
    fn selectors_and_limits_never_gain_authority_from_unrecognized_fields() {
        for extra in ["&before_oid=aaaa", "&principal=admin", "&force=true", "&expected_version=1",
            "&before_ref=refs/heads/other", "&context_lines=21", "&max_changes=0", "&max_changes=513",
            "&mode=recursive", "&max_diff_work=1000001", "&max_blob_bytes=01",
            "&path_prefix_hex=2e2e2f736563726574", "&path_prefix_hex=612f0062", "&path_prefix_hex=FF"]
        { assert!(Command::parse((form() + extra).as_bytes(), GitHashAlgorithm::Sha1).is_err(), "{extra}"); }
        assert!(Command::parse(form().as_bytes(), GitHashAlgorithm::Sha256).is_err());
        for expected in ["0".repeat(40), "a".repeat(64), "A".repeat(40)] {
            assert!(Command::parse((form() + "&expected_before=" + &expected).as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
        assert!(Command::parse((form() + "&expected_before=" + &"a".repeat(40)).as_bytes(), GitHashAlgorithm::Sha1).is_ok());
    }
    #[test]
    fn diff_envelopes_are_closed_body_bearing_read_queries() {
        for (method, target, extra, accepted) in [
            ("POST", "/r.git/api/v1/source/diff", "", true),
            ("GET", "/r.git/api/v1/source/diff", "", false),
            ("POST", "/r.git/api/v1/source/diff?mode=direct", "", false),
            ("POST", "/../r.git/api/v1/source/diff", "", false),
            ("POST", "/r.git/api/v1/source/diff", "Git-Protocol: version=2\r\n", false),
        ] {
            let bytes = format!("{method} {target} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert_eq!(Request::parse(&envelope).is_ok_and(|request| request.is_some()), accepted);
        }
    }
}
