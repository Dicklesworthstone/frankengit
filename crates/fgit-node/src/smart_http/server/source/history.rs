//! Authenticated native commit history. POST is a bounded query, not a write:
//! the outer source gateway grants reads before consuming the form. The only
//! object selector is a current visible ref; pagination binds its exact head.

mod blame;

#[cfg(test)]
mod path_tests;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::history::path::PathLogOptions;
use fgit_forge::history::{HistoryCommit, HistoryError, HistoryLimits, HistoryPage, LogOptions};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use super::super::{
    Status,
    issues::{
        ApiError, MAX_FORM_BYTES, Reply, parse_decimal, parse_form, parse_snapshot, quote,
        read_form,
    },
};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
    blame: bool,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else {
            return Ok(None);
        };
        if !matches!(action, "log" | "blame") {
            return Ok(None);
        }
        if repository_route.len() < 2
            || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | "..")
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
            })
        {
            return Err(ApiError::not_found());
        }
        if head.method != "POST" {
            return Err(ApiError::method());
        }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_history_envelope"));
        }
        if !head.content_type.is_some_and(|media| {
            media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        }) {
            return Err(ApiError::media());
        }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self {
            repository_route,
            blame: action == "blame",
        }))
    }
}

#[derive(Debug)]
struct Selection {
    reference: RefName,
    expected_head: Option<RepositoryAuthorityHeadId>,
    expected_commit: Option<GitOid>,
}
#[derive(Debug)]
struct Command {
    selection: Selection,
    options: LogOptions,
    path: Option<Vec<u8>>,
}
impl Command {
    fn parse(bytes: &[u8], format: GitHashAlgorithm) -> Result<Self, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 16)? {
            if !matches!(
                name.as_str(),
                "ref"
                    | "object_format"
                    | "expected_head"
                    | "expected_commit"
                    | "after"
                    | "limit"
                    | "max_commits"
                    | "max_edges"
                    | "max_metadata_bytes"
                    | "path_hex"
                    | "max_tree_entries"
                    | "max_cached_bytes"
            ) {
                return Err(ApiError::bad("unknown_or_inapplicable_field"));
            }
            if fields.insert(name, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        let selection = selection(&mut fields, format)?;
        let path = fields
            .remove("path_hex")
            .map(|text| path_hex(&text))
            .transpose()?;
        if path.is_none()
            && (fields.contains_key("max_tree_entries") || fields.contains_key("max_cached_bytes"))
        {
            return Err(ApiError::bad("unknown_or_inapplicable_field"));
        }
        let mut limits = HistoryLimits::default();
        limits.max_commits = number(&mut fields, "max_commits", limits.max_commits)?;
        limits.max_edges = number(&mut fields, "max_edges", limits.max_edges)?;
        limits.max_metadata_bytes =
            number(&mut fields, "max_metadata_bytes", limits.max_metadata_bytes)?;
        limits.max_tree_entries = number(&mut fields, "max_tree_entries", limits.max_tree_entries)?;
        limits.max_cached_bytes = number(&mut fields, "max_cached_bytes", limits.max_cached_bytes)?;
        let options = LogOptions {
            after: number(&mut fields, "after", 0)?,
            limit: number(&mut fields, "limit", LogOptions::default().limit)?,
            limits,
        };
        options
            .validate()
            .map_err(|_| ApiError::bad("invalid_history_limits"))?;
        if options.after != 0 && selection.expected_head.is_none() {
            return Err(ApiError::bad("history_continuation_requires_snapshot"));
        }
        if let Some(path) = &path {
            PathLogOptions {
                path: path.clone(),
                log: options,
            }
            .validate()
            .map_err(|_| ApiError::bad("invalid_history_path"))?;
        }
        Ok(Self {
            selection,
            options,
            path,
        })
    }
}
// Canonical hex carries arbitrary Git name bytes, without UTF-8 conversion or
// URI/host-path normalization. Bound expansion before allocating the path.
fn path_hex(text: &str) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || text.len() > 8192
        || !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_history_path"));
    }
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect())
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_history_field"))
}
fn number(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    fallback: usize,
) -> Result<usize, ApiError> {
    fields.remove(name).map_or(Ok(fallback), |text| {
        usize::try_from(parse_decimal(&text)?).map_err(|_| ApiError::bad("invalid_history_number"))
    })
}
fn selection(
    fields: &mut BTreeMap<String, String>,
    format: GitHashAlgorithm,
) -> Result<Selection, ApiError> {
    if take(fields, "object_format")? != format.as_str() {
        return Err(ApiError::bad("object_format_mismatch"));
    }
    let reference = RefName::try_new(take(fields, "ref")?.as_bytes())
        .map_err(|_| ApiError::bad("invalid_ref"))?;
    let expected_head = fields
        .remove("expected_head")
        .map(|text| parse_snapshot(&text))
        .transpose()?;
    let expected_commit = fields
        .remove("expected_commit")
        .map(|text| {
            if text.len() != format.digest_len() * 2
                || !text
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(ApiError::bad("invalid_expected_commit"));
            }
            let oid = GitOid::from_hex(format, &text)
                .map_err(|_| ApiError::bad("invalid_expected_commit"))?;
            if oid.is_zero() {
                return Err(ApiError::bad("invalid_expected_commit"));
            }
            Ok(oid)
        })
        .transpose()?;
    Ok(Selection {
        reference,
        expected_head,
        expected_commit,
    })
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let bytes = read_form(reader, framing, http)?;
    if request.blame {
        return blame::execute(node, &bytes, maximum_response);
    }
    let command = Command::parse(&bytes, node.object_format)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let result = if let Some(path) = &command.path {
        let options = PathLogOptions {
            path: path.clone(),
            log: command.options,
        };
        drive_request_while(
            node,
            &context,
            node.read_path_history_in(
                &context,
                &command.selection.reference,
                &RefVisibility::new(),
                command.selection.expected_head,
                &options,
            ),
            &mut live,
        )
    } else {
        drive_request_while(
            node,
            &context,
            node.read_commit_history_in(
                &context,
                &command.selection.reference,
                &RefVisibility::new(),
                command.selection.expected_head,
                command.options,
            ),
            &mut live,
        )
    };
    let (head, page) = result.map_err(|error| {
        failure(
            error.is_snapshot_moved(),
            error.is_unavailable(),
            error.is_unpinned_continuation(),
            error.history_error(),
        )
    })?;
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(MAX_REPLY_BYTES);
    let body = render_log(node, &command, head, &page, maximum, &mut live)?;
    Ok(Reply {
        status: Status::Success,
        body,
        terminal: None,
    })
}

fn failure(
    snapshot_moved: bool,
    unavailable: bool,
    unpinned: bool,
    cause: Option<&HistoryError>,
) -> ApiError {
    if snapshot_moved {
        return ApiError::new(Status::Conflict, "source_snapshot_moved");
    }
    if unavailable {
        return ApiError::not_found();
    }
    if unpinned {
        return ApiError::bad("history_continuation_requires_snapshot");
    }
    match cause {
        Some(HistoryError::InvalidOptions | HistoryError::LineRange) => {
            ApiError::bad("invalid_history_range_or_limits")
        }
        Some(HistoryError::PathUnavailable) => ApiError::not_found(),
        Some(HistoryError::BinaryContent) => {
            ApiError::new(Status::Conflict, "binary_blame_unsupported")
        }
        Some(HistoryError::Budget(_)) => ApiError::too_large(),
        // Never return internal object IDs, backend details or a fake empty
        // history when a required object is missing/corrupt or work failed.
        _ => ApiError::unavailable(),
    }
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
fn valid_oid(format: GitHashAlgorithm, oid: GitOid) -> bool {
    !oid.is_zero() && oid.algorithm() == format
}
fn check_selection(
    request: &Selection,
    head: RepositoryAuthorityHeadId,
    tip: GitOid,
    format: GitHashAlgorithm,
) -> Result<(), ApiError> {
    if request
        .expected_head
        .is_some_and(|expected| expected != head)
    {
        return Err(ApiError::new(Status::Conflict, "source_snapshot_moved"));
    }
    if request
        .expected_commit
        .is_some_and(|expected| expected != tip)
    {
        return Err(ApiError::new(Status::Conflict, "source_commit_moved"));
    }
    if !valid_oid(format, tip) {
        return Err(ApiError::unavailable());
    }
    Ok(())
}

/// Incremental bounded JSON construction. In particular hex output is charged
/// before expansion, not after allocating an unbounded temporary String.
struct Output {
    body: String,
    maximum: usize,
}
impl Output {
    fn new(maximum: usize) -> Self {
        Self {
            body: String::new(),
            maximum: maximum.min(MAX_REPLY_BYTES),
        }
    }
    fn reserve(&mut self, amount: usize) -> Result<(), ApiError> {
        if self
            .body
            .len()
            .checked_add(amount)
            .is_none_or(|n| n > self.maximum)
        {
            return Err(ApiError::too_large());
        }
        self.body
            .try_reserve(amount)
            .map_err(|_| ApiError::unavailable())
    }
    fn append(&mut self, text: &str) -> Result<(), ApiError> {
        self.reserve(text.len())?;
        self.body.push_str(text);
        Ok(())
    }
    fn hex(&mut self, bytes: &[u8], live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
        let expanded = bytes
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(2))
            .ok_or_else(ApiError::too_large)?;
        checkpoint(live)?;
        self.reserve(expanded)?;
        self.body.push('"');
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for chunk in bytes.chunks(4096) {
            checkpoint(live)?;
            for byte in chunk {
                self.body.push(char::from(HEX[usize::from(*byte >> 4)]));
                self.body.push(char::from(HEX[usize::from(*byte & 15)]));
            }
        }
        self.body.push('"');
        Ok(())
    }
    fn finish(self, live: &mut impl FnMut() -> bool) -> Result<String, ApiError> {
        checkpoint(live)?;
        Ok(self.body)
    }
}
fn identity(
    out: &mut Output,
    node: &OneNode,
    request: &Selection,
    head: RepositoryAuthorityHeadId,
    tip: GitOid,
    kind: &str,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    checkpoint(live)?;
    check_selection(request, head, tip, node.object_format)?;
    let internal = head.as_internal_object_id();
    let digest: String = internal
        .digest()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let token = format!("alg:{}:{digest}", internal.algorithm().code_point());
    out.append(&format!(concat!("{{\"type\":{},\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},",
        "\"source_commit\":{},\"read_only\":true,\"transaction_created\":false,\"published\":false,",
        "\"author_identity_verified\":false,\"ref_hex\":"), quote(kind), quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()), quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()), quote(&head.to_string()), quote(&token), quote(&tip.to_string())))?;
    out.hex(request.reference.as_bytes(), live)
}
fn commit(
    out: &mut Output,
    row: &HistoryCommit,
    format: GitHashAlgorithm,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    checkpoint(live)?;
    if !valid_oid(format, row.id)
        || !valid_oid(format, row.tree)
        || row.body.len() > 64 * 1024
        || row.parents.len() > HistoryLimits::default().max_edges
        || row.parents.iter().any(|id| !valid_oid(format, *id))
        || git_object_id(format, GitObjectKind::Commit, &row.body) != row.id
    {
        return Err(ApiError::unavailable());
    }
    out.append(&format!(
        "{{\"object_id\":{},\"tree\":{},\"parents\":[",
        quote(&row.id.to_string()),
        quote(&row.tree.to_string())
    ))?;
    for (index, parent) in row.parents.iter().enumerate() {
        checkpoint(live)?;
        if index != 0 {
            out.append(",")?;
        }
        out.append(&quote(&parent.to_string()))?;
    }
    out.append("],\"body_hex\":")?;
    out.hex(&row.body, live)?;
    out.append("}")
}
// Filtered pages may have no matches or omit the selected tip. Keep the
// stronger whole-graph invariants in validate_page rather than weakening them.
fn validate_page_bounds(
    page: &HistoryPage,
    options: LogOptions,
    format: GitHashAlgorithm,
) -> Result<(), ApiError> {
    options.validate().map_err(|_| ApiError::unavailable())?;
    let end = page
        .after
        .checked_add(page.commits.len())
        .ok_or_else(ApiError::unavailable)?;
    if !valid_oid(format, page.tip)
        || page.total_commits > options.limits.max_commits
        || page.after != options.after
        || page.after > page.total_commits
        || end > page.total_commits
        || page.commits.len() != options.limit.min(page.total_commits - page.after)
        || page.next_after != (end < page.total_commits).then_some(end)
    {
        return Err(ApiError::unavailable());
    }
    let mut ids = BTreeSet::new();
    let mut bytes = 0_usize;
    for row in &page.commits {
        if !ids.insert(row.id) {
            return Err(ApiError::unavailable());
        }
        bytes = bytes
            .checked_add(row.body.len())
            .ok_or_else(ApiError::unavailable)?;
        if bytes > options.limits.max_metadata_bytes {
            return Err(ApiError::too_large());
        }
    }
    Ok(())
}
fn validate_page(
    page: &HistoryPage,
    options: LogOptions,
    format: GitHashAlgorithm,
) -> Result<(), ApiError> {
    validate_page_bounds(page, options, format)?;
    if page.total_commits == 0
        || (page.after == 0 && page.commits.first().map(|row| row.id) != Some(page.tip))
    {
        return Err(ApiError::unavailable());
    }
    Ok(())
}
fn render_log(
    node: &OneNode,
    command: &Command,
    head: RepositoryAuthorityHeadId,
    page: &HistoryPage,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    let kind = if command.path.is_some() {
        validate_page_bounds(page, command.options, node.object_format)?;
        "source_path_log"
    } else {
        validate_page(page, command.options, node.object_format)?;
        "source_log"
    };
    let mut out = Output::new(maximum);
    identity(
        &mut out,
        node,
        &command.selection,
        head,
        page.tip,
        kind,
        live,
    )?;
    if let Some(path) = &command.path {
        render_path_selection(&mut out, path, live)?;
    }
    out.append(&format!(
        concat!(
            ",\"ordering\":\"child-before-parent-native-id-v1\",\"page_complete\":true,",
            "\"after\":{},\"limit\":{},\"total_commits\":{},\"next_after\":{},\"commits\":["
        ),
        page.after,
        command.options.limit,
        page.total_commits,
        page.next_after
            .map_or_else(|| "null".into(), |n| n.to_string())
    ))?;
    for (index, row) in page.commits.iter().enumerate() {
        if index != 0 {
            out.append(",")?;
        }
        commit(&mut out, row, node.object_format, live)?;
    }
    out.append("]}")?;
    out.finish(live)
}

fn render_path_selection(
    out: &mut Output,
    path: &[u8],
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    out.append(",\"path_hex\":")?;
    out.hex(path, live)?;
    out.append(concat!(",\"path_selection\":\"changed-against-any-parent-v1\",",
        "\"total_commits_scope\":\"matching-path\",\"history_simplified\":false,\"renames_followed\":false"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::head;

    fn form(format: GitHashAlgorithm) -> String {
        format!("object_format={}&ref=refs/heads/main", format.as_str())
    }
    #[test]
    fn history_forms_are_closed_and_continuations_require_the_original_snapshot() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let base = form(format);
            assert!(Command::parse(base.as_bytes(), format).is_ok());
            for extra in [
                "&after=1",
                "&after=-1",
                "&limit=0",
                "&limit=101",
                "&max_commits=4097",
                "&max_edges=0",
                "&max_metadata_bytes=4194305",
                "&ref=refs/heads/other",
                "&commit=abcd",
                "&principal=admin",
                "&first_parent=true",
                "&path_prefix_hex=61",
            ] {
                assert!(
                    Command::parse((base.clone() + extra).as_bytes(), format).is_err(),
                    "{extra}"
                );
            }
            let valid = format!("{base}&after=1&expected_head=alg:1:{}", "a".repeat(64));
            assert_eq!(
                Command::parse(valid.as_bytes(), format)
                    .unwrap()
                    .options
                    .after,
                1
            );
            assert!(
                Command::parse(
                    (base + "&expected_commit=" + &"0".repeat(format.digest_len() * 2)).as_bytes(),
                    format
                )
                .is_err()
            );
        }
    }
    #[test]
    fn log_envelope_reuses_the_source_post_profile_without_accepting_queries() {
        for (method, target, extra, valid) in [
            ("POST", "/r.git/api/v1/source/log", "", true),
            ("GET", "/r.git/api/v1/source/log", "", false),
            ("POST", "/r.git/api/v1/source/log?after=1", "", false),
            ("POST", "/../r.git/api/v1/source/log", "", false),
            (
                "POST",
                "/r.git/api/v1/source/log",
                "Git-Protocol: version=2\r\n",
                false,
            ),
            ("POST", "/r.git/api/v1/source/blame", "", true),
            ("GET", "/r.git/api/v1/source/blame", "", false),
            ("POST", "/r.git/api/v1/source/blame?path=secret", "", false),
        ] {
            let bytes = format!(
                "{method} {target} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(Request::parse(&envelope).is_ok(), valid);
        }
    }
    #[test]
    fn hex_expansion_is_bounded_before_allocation_and_preserves_non_utf8() {
        let mut out = Output::new(8);
        assert!(out.hex(b"abcd", &mut || true).is_err());
        assert!(out.body.is_empty());
        out.hex(b"\0\xff\n", &mut || true).unwrap();
        assert_eq!(out.body, "\"00ff0a\"");
        assert!(out.append("x").is_err());
        assert!(out.finish(&mut || false).is_err());
    }
    #[test]
    fn partial_or_duplicate_history_pages_and_forged_native_records_refuse() {
        let format = GitHashAlgorithm::Sha1;
        let tree = git_object_id(format, GitObjectKind::Tree, &[]);
        let body = format!("tree {tree}\nauthor A <a@invalid> 1 +0000\ncommitter A <a@invalid> 1 +0000\n\nmessage\n").into_bytes();
        let id = git_object_id(format, GitObjectKind::Commit, &body);
        let row = HistoryCommit {
            id,
            tree,
            parents: vec![],
            body,
        };
        let page = HistoryPage {
            tip: id,
            total_commits: 1,
            after: 0,
            next_after: None,
            commits: vec![row.clone()],
        };
        assert!(validate_page(&page, LogOptions::default(), format).is_ok());
        let mut out = Output::new(4096);
        commit(&mut out, &row, format, &mut || true).unwrap();
        assert!(out.body.contains("\"body_hex\":"));
        let mut forged = row.clone();
        forged.body.push(b'x');
        assert!(commit(&mut Output::new(4096), &forged, format, &mut || true).is_err());
        let mut partial = page.clone();
        partial.total_commits = 2;
        assert!(validate_page(&partial, LogOptions::default(), format).is_err());
        partial.commits.push(row);
        assert!(validate_page(&partial, LogOptions::default(), format).is_err());
    }
    #[test]
    fn internal_failures_are_not_empty_successes_or_transaction_outcomes() {
        for cause in [
            HistoryError::CyclicHistory,
            HistoryError::Budget("commits"),
            HistoryError::InvalidTree,
        ] {
            let failure = failure(false, false, false, Some(&cause));
            assert!(!failure.outcome_unknown);
            let mut bytes = Vec::new();
            failure
                .send_named(
                    &mut bytes,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "source_error",
                )
                .unwrap();
            let text = String::from_utf8(bytes).unwrap();
            assert!(!text.contains("\"commits\":[]") && !text.contains("\"outcome\":"));
        }
    }
}
