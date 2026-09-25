//! Closed byte-regex source requests. The common source gateway retains
//! credentials, read quotas, idempotency-key rejection and service switches.
use super::super::issues::{
    ApiError, MAX_FORM_BYTES, parse_decimal, parse_form, parse_snapshot, quote, ref_fields,
};
use super::request::Selection;
use super::{JsonReply, Status, read_error, read_form};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};
use fgit_forge::source_search::regex::{
    MAX_REGEX_STEPS, RegexQuery, RegexQueryError, RegexSearchReport,
};
use fgit_forge::source_search::{SearchCase, SearchCompletion, SearchLimits, SourceMatch};
use fgit_treefs::TreePath;
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some(route) = path.strip_suffix("/api/v1/source/search-regex") else {
            return Ok(None);
        };
        if route.len() < 2
            || !route.starts_with('/')
            || route[1..].split('/').any(|part| {
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
        if query.is_some()
            || matches!(
                head.body,
                BodyFraming::Empty | BodyFraming::ContentLength(0)
            )
            || head.git_protocol.is_some()
        {
            return Err(ApiError::bad("invalid_regex_envelope"));
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
            repository_route: route,
        }))
    }
}
#[derive(Debug)]
struct Command {
    selection: Selection,
    query: RegexQuery,
    limits: SearchLimits,
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_regex_field"))
}
fn positive(
    fields: &mut BTreeMap<String, String>,
    name: &str,
    default: u64,
    maximum: u64,
) -> Result<u64, ApiError> {
    let value = fields
        .remove(name)
        .map(|v| parse_decimal(&v))
        .transpose()?
        .unwrap_or(default);
    if value == 0 || value > maximum {
        return Err(ApiError::bad("invalid_regex_limit"));
    }
    Ok(value)
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty()
        || !text.len().is_multiple_of(2)
        || text.len() > maximum * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ApiError::bad("invalid_hex_bytes"));
    }
    let digit = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| digit(pair[0]) * 16 + digit(pair[1]))
        .collect())
}
fn command(bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
    let mut fields = BTreeMap::new();
    let mut prefixes = Vec::new();
    for (name, value) in parse_form(bytes, 140)? {
        if name == "path_prefix_hex" {
            if prefixes.len() == 128 {
                return Err(ApiError::too_large());
            }
            prefixes.push(unhex(&value, 4096)?);
            continue;
        }
        if !matches!(
            name.as_str(),
            "ref"
                | "object_format"
                | "expected_head"
                | "expected_commit"
                | "pattern_hex"
                | "case"
                | "max_matches"
                | "max_bytes"
                | "max_file_bytes"
                | "max_steps"
        ) {
            return Err(ApiError::bad("unknown_regex_field"));
        }
        if fields.insert(name, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    if take(&mut fields, "object_format")? != format.as_str() {
        return Err(ApiError::bad("object_format_mismatch"));
    }
    let reference = RefName::try_new(take(&mut fields, "ref")?.as_bytes())
        .map_err(|_| ApiError::bad("invalid_ref"))?;
    let expected_head = fields
        .remove("expected_head")
        .map(|v| parse_snapshot(&v))
        .transpose()?;
    let expected_commit = fields
        .remove("expected_commit")
        .map(|value| {
            let raw = unhex(&value, format.digest_len())?;
            if raw.len() != format.digest_len() {
                return Err(ApiError::bad("invalid_expected_commit"));
            }
            let id = GitOid::from_hex(format, &value)
                .map_err(|_| ApiError::bad("invalid_expected_commit"))?;
            if id.is_zero() {
                return Err(ApiError::bad("invalid_expected_commit"));
            }
            Ok(id)
        })
        .transpose()?;
    let pattern = unhex(&take(&mut fields, "pattern_hex")?, 256)?;
    let case = match fields.remove("case").as_deref().unwrap_or("exact") {
        "exact" => SearchCase::Exact,
        "ascii-insensitive" => SearchCase::AsciiInsensitive,
        _ => return Err(ApiError::bad("unsupported_search_case")),
    };
    let steps = positive(&mut fields, "max_steps", MAX_REGEX_STEPS, MAX_REGEX_STEPS)?;
    let query = RegexQuery::new(&pattern, case, &prefixes, steps).map_err(|error| match error {
        RegexQueryError::Expression(_) => ApiError::bad("invalid_regex_pattern"),
        RegexQueryError::InvalidScope => ApiError::bad("invalid_search_scope"),
        RegexQueryError::InvalidWorkLimit => ApiError::bad("invalid_regex_limit"),
    })?;
    let defaults = SearchLimits::default();
    let limits = SearchLimits {
        max_matches: positive(
            &mut fields,
            "max_matches",
            defaults.max_matches as u64,
            4096,
        )? as usize,
        max_total_bytes: positive(
            &mut fields,
            "max_bytes",
            defaults.max_total_bytes as u64,
            defaults.max_total_bytes as u64,
        )? as usize,
        max_file_bytes: positive(
            &mut fields,
            "max_file_bytes",
            defaults.max_file_bytes as u64,
            defaults.max_file_bytes as u64,
        )? as usize,
        ..defaults
    };
    limits
        .validate()
        .map_err(|_| ApiError::bad("invalid_search_limits"))?;
    Ok(Command {
        selection: Selection {
            reference,
            expected_head,
            expected_commit,
        },
        query,
        limits,
    })
}

pub(super) fn execute(
    node: &OneNode,
    _request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum: u64,
) -> Result<JsonReply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let command = command(&read_form(reader, framing, http)?, node.object_format)?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let (head, report) = drive_request_while(
        node,
        &context,
        node.search_source_regex_snapshot_local_in(
            &context,
            &command.selection.reference,
            command.selection.expected_head,
            command.selection.expected_commit,
            &command.query,
            command.limits,
        ),
        &mut live,
    )
    .map_err(read_error)?;
    let body = render(
        node,
        &command,
        head,
        &report,
        usize::try_from(maximum).unwrap_or(usize::MAX),
        &mut live,
    )?;
    Ok(JsonReply {
        status: Status::Success,
        body,
        terminal: None,
    })
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn append(out: &mut String, value: &str, maximum: usize) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|n| n > maximum.min(super::output::MAX_REPLY_BYTES))
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(value.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(value);
    Ok(())
}
fn check(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
fn match_json(
    row: &SourceMatch,
    query: &RegexQuery,
    format: GitHashAlgorithm,
    maximum_file: usize,
) -> Result<String, ApiError> {
    let path = TreePath::parse_default(&row.path).map_err(|_| ApiError::unavailable())?;
    let end = row
        .byte_offset
        .checked_add(row.match_length)
        .ok_or_else(ApiError::unavailable)?;
    let excerpt_end = row
        .excerpt_offset
        .checked_add(row.excerpt.len())
        .ok_or_else(ApiError::unavailable)?;
    let column = row
        .byte_column
        .checked_sub(1)
        .ok_or_else(ApiError::unavailable)?;
    let line_start = row
        .byte_offset
        .checked_sub(column)
        .ok_or_else(ApiError::unavailable)?;
    if row.line == 0
        || end > maximum_file
        || excerpt_end > maximum_file
        || row.excerpt.len() > 416
        || row.excerpt.contains(&b'\n')
        || row.excerpt_offset < line_start
        || row.excerpt_offset > row.byte_offset
        || row.byte_offset > excerpt_end
        || row.blob.is_zero()
        || row.blob.algorithm() != format
        || (!query.prefixes().is_empty() && !query.prefixes().iter().any(|p| path.starts_with(p)))
    {
        return Err(ApiError::unavailable());
    }
    Ok(format!(
        concat!(
            "{{\"path_hex\":{},\"blob\":{},\"byte_offset\":{},\"line\":{},",
            "\"byte_column\":{},\"match_length\":{},\"excerpt_offset\":{},\"excerpt_hex\":{},",
            "\"match_truncated_in_excerpt\":{}}}"
        ),
        quote(&hex(&row.path)),
        quote(&row.blob.to_string()),
        row.byte_offset,
        row.line,
        row.byte_column,
        row.match_length,
        row.excerpt_offset,
        quote(&hex(&row.excerpt)),
        end > excerpt_end
    ))
}
fn render(
    node: &OneNode,
    command: &Command,
    head: RepositoryAuthorityHeadId,
    report: &RegexSearchReport,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let source = &report.source;
    let limits = command.limits;
    let query = &command.query;
    if source.repository != node.repository_id
        || report.program_states != query.state_count()
        || report.steps > query.maximum_steps()
        || source.matches.len() > limits.max_matches
        || source.files_read > source.files_selected
        || source.files_selected > limits.max_files
        || source.bytes_read > limits.max_total_bytes
        || source.bytes_searched > source.bytes_read
        || report.lines_searched > source.bytes_searched
        || source.matches.len() > report.lines_searched
        || (source.completion == SearchCompletion::Complete
            && (source.files_read != source.files_selected
                || source.bytes_searched != source.bytes_read))
        || (source.completion == SearchCompletion::MatchLimit
            && (source.matches.len() != limits.max_matches
                || report.lines_searched <= source.matches.len()))
        || source.matches.windows(2).any(|p| {
            (&p[0].path, p[0].line) >= (&p[1].path, p[1].line)
                || (p[0].path == p[1].path && p[0].byte_offset >= p[1].byte_offset)
        })
        || [source.source_commit, source.source_tree]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != node.object_format)
        || command.selection.expected_head.is_some_and(|id| id != head)
        || command
            .selection
            .expected_commit
            .is_some_and(|id| id != source.source_commit)
    {
        return Err(ApiError::unavailable());
    }
    let internal = head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        internal.algorithm().code_point(),
        hex(internal.digest().as_bytes())
    );
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_search_regex\",\"schema_version\":1,",
                "\"profile\":\"byte-regex-lines-v1\",\"match_policy\":\"leftmost-longest-per-line\",",
                "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},{},",
                "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},",
                "\"read_only\":true,\"transaction_created\":false,\"published\":false,",
                "\"pattern_hex\":{},\"case\":{},\"max_steps\":{},\"vm_steps\":{},\"program_states\":{},",
                "\"lines_searched\":{},\"max_matches\":{},\"returned_matches\":{},",
                "\"completion\":{},\"complete\":{},\"files_selected\":{},\"files_read\":{},",
                "\"bytes_read\":{},\"bytes_searched\":{},\"non_regular_entries\":{},\"path_prefix_hex\":["
            ),
            quote(&node.tenant_id.to_string()),
            quote(&node.repository_id.to_string()),
            quote(&node.repository_incarnation_id().to_string()),
            quote(node.object_format.as_str()),
            ref_fields("ref", &command.selection.reference),
            quote(&head.to_string()),
            quote(&token),
            quote(&source.source_rcr.to_string()),
            quote(&source.source_commit.to_string()),
            quote(&source.source_tree.to_string()),
            quote(&hex(query.pattern())),
            quote(match query.case() {
                SearchCase::Exact => "exact",
                SearchCase::AsciiInsensitive => "ascii-insensitive",
            }),
            query.maximum_steps(),
            report.steps,
            report.program_states,
            report.lines_searched,
            limits.max_matches,
            source.matches.len(),
            quote(match source.completion {
                SearchCompletion::Complete => "complete",
                SearchCompletion::MatchLimit => "match_limit",
            }),
            source.completion == SearchCompletion::Complete,
            source.files_selected,
            source.files_read,
            source.bytes_read,
            source.bytes_searched,
            source.non_regular_entries
        ),
        maximum,
    )?;
    for (index, path) in query.prefixes().iter().enumerate() {
        check(live)?;
        append(
            &mut out,
            &format!(
                "{}{}",
                if index == 0 { "" } else { "," },
                quote(&hex(path.as_bytes()))
            ),
            maximum,
        )?;
    }
    append(&mut out, "],\"matches\":[", maximum)?;
    for (index, row) in source.matches.iter().enumerate() {
        check(live)?;
        if index != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(
            &mut out,
            &match_json(row, query, node.object_format, limits.max_file_bytes)?,
            maximum,
        )?;
    }
    append(&mut out, "]}", maximum)?;
    check(live)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn form() -> String {
        "object_format=sha1&ref=refs/heads/main&pattern_hex=5e612b24".to_owned()
    }
    #[test]
    fn regex_fields_do_not_change_literal_grammar_or_grant_authority() {
        let parsed = command(form().as_bytes(), GitHashAlgorithm::Sha1).unwrap();
        assert_eq!(parsed.query.pattern(), b"^a+$");
        for suffix in [
            "&pattern_hex=61",
            "&needle_hex=61",
            "&principal=admin",
            "&case=unicode",
            "&max_steps=0",
            "&max_steps=67108865",
            "&max_matches=4097",
            "&expected_commit=0000000000000000000000000000000000000000",
            "&path_prefix_hex=2e2e2f736563726574",
        ] {
            assert!(command((form() + suffix).as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
        for pattern in [
            "28",
            "283f3d6129",
            "615c31",
            "615c7830",
            "615c707b4c7d",
            "61ff5A",
        ] {
            let input = form().replace("5e612b24", pattern);
            assert!(command(input.as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
        assert!(
            command(
                (form() + "&max_steps=1&path_prefix_hex=646972").as_bytes(),
                GitHashAlgorithm::Sha1
            )
            .is_ok()
        );
        assert!(command(form().as_bytes(), GitHashAlgorithm::Sha256).is_err());
    }
    #[test]
    fn strict_route_and_envelope_precede_regex_execution() {
        for (method, path, extra) in [
            ("GET", "/r.git/api/v1/source/search-regex", ""),
            ("POST", "/r.git/api/v1/source/search-regex?q=a", ""),
            ("POST", "/../r.git/api/v1/source/search-regex", ""),
            (
                "POST",
                "/r.git/api/v1/source/search-regex",
                "Git-Protocol: version=2\r\n",
            ),
        ] {
            let bytes = format!(
                "{method} {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n"
            );
            let head = fgit_wire::smart_http::head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&head).is_err());
        }
        let bytes = b"POST /r.git/api/v1/source/search-regex HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
        let head = fgit_wire::smart_http::head::parse(bytes, HttpLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            Request::parse(&head).unwrap().unwrap().repository_route,
            "/r.git"
        );
    }
    #[test]
    fn long_and_zero_length_matches_preserve_spans_without_unbounded_excerpts() {
        let query = RegexQuery::new(b"a*", SearchCase::Exact, &[], MAX_REGEX_STEPS).unwrap();
        let mut row = SourceMatch {
            path: b"file".to_vec(),
            blob: GitOid::from_hex(GitHashAlgorithm::Sha1, &"1".repeat(40)).unwrap(),
            byte_offset: 0,
            line: 1,
            byte_column: 1,
            match_length: 1000,
            excerpt: vec![b'a'; 416],
            excerpt_offset: 0,
        };
        let json = match_json(&row, &query, GitHashAlgorithm::Sha1, 2000).unwrap();
        assert!(json.contains("\"match_length\":1000"));
        assert!(json.contains("\"match_truncated_in_excerpt\":true"));
        row.match_length = 0;
        row.excerpt.clear();
        assert!(
            match_json(&row, &query, GitHashAlgorithm::Sha1, 2000)
                .unwrap()
                .contains("\"match_truncated_in_excerpt\":false")
        );
        row.byte_column = 0;
        assert!(match_json(&row, &query, GitHashAlgorithm::Sha1, 2000).is_err());
        row.byte_column = 1;
        row.match_length = usize::MAX;
        row.byte_offset = 1;
        assert!(match_json(&row, &query, GitHashAlgorithm::Sha1, 2000).is_err());
    }
    #[test]
    fn output_budget_and_cancellation_do_not_emit_partial_success() {
        let mut out = String::from("abc");
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        append(&mut out, "d", 4).unwrap();
        assert_eq!(out, "abcd");
        assert!(!check(&mut || false).unwrap_err().outcome_unknown);
    }
}
