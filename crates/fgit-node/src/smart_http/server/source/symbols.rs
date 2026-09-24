//! Closed, read-only Rust declaration HTTP profile. Credentials, service gates,
//! request quotas and transaction-key refusal remain in the source gateway.
pub(super) mod indexed;
use super::super::issues::{
    ApiError, MAX_FORM_BYTES, parse_decimal, parse_form, parse_snapshot, quote, ref_fields,
};
use super::request::Selection;
use super::{JsonReply, Status, read_error, read_form};
use crate::smart_http::drive_request_while;
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode,
};
use fgit_forge::source_search::{SearchCompletion, SearchLimits};
use fgit_forge::source_symbols::{
    MAX_SYMBOL_WORK, PROFILE, SymbolKind, SymbolMatch, SymbolMatchMode, SymbolQuery,
    SymbolReadError, SymbolSearchReport, SymbolSyntaxErrorKind,
};
use fgit_treefs::TreePath;
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
    indexed: bool,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(p, q)| (p, Some(q)));
        let Some((route, indexed)) = path
            .strip_suffix("/api/v1/source/search-symbols-index")
            .map(|route| (route, true))
            .or_else(|| {
                path.strip_suffix("/api/v1/source/search-symbols")
                    .map(|route| (route, false))
            })
        else {
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
            return Err(ApiError::bad("invalid_symbol_envelope"));
        }
        if !head.content_type.is_some_and(|media| {
            media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        }) {
            return Err(ApiError::media());
        }
        if matches!(head.body,BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self {
            repository_route: route,
            indexed,
        }))
    }
}
struct Command {
    selection: Selection,
    query: SymbolQuery,
    limits: SearchLimits,
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
    let nibble = |b| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| nibble(p[0]) * 16 + nibble(p[1]))
        .collect())
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_symbol_field"))
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
        return Err(ApiError::bad("invalid_symbol_limit"));
    }
    Ok(value)
}
pub(super) fn kind(value: &str) -> Result<SymbolKind, ApiError> {
    match value {
        "function" => Ok(SymbolKind::Function),
        "struct" => Ok(SymbolKind::Struct),
        "enum" => Ok(SymbolKind::Enum),
        "trait" => Ok(SymbolKind::Trait),
        "type" => Ok(SymbolKind::Type),
        "module" => Ok(SymbolKind::Module),
        "union" => Ok(SymbolKind::Union),
        "macro" => Ok(SymbolKind::Macro),
        _ => Err(ApiError::bad("unsupported_symbol_kind")),
    }
}
fn command(bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
    command_fields(parse_form(bytes, 148)?, format)
}
fn command_fields(
    parsed: Vec<(String, String)>,
    format: GitHashAlgorithm,
) -> Result<Command, ApiError> {
    let mut fields = BTreeMap::new();
    let mut prefixes = Vec::new();
    let mut kinds = Vec::new();
    for (name, value) in parsed {
        match name.as_str() {
            "path_prefix_hex" => {
                if prefixes.len() == 128 {
                    return Err(ApiError::too_large());
                }
                prefixes.push(unhex(&value, 4096)?);
                continue;
            }
            "kind" => {
                if kinds.len() == 8 {
                    return Err(ApiError::bad("too_many_symbol_kinds"));
                }
                kinds.push(kind(&value)?);
                continue;
            }
            "object_format" | "ref" | "expected_head" | "expected_commit" | "name_hex"
            | "match" | "max_matches" | "max_bytes" | "max_file_bytes" | "max_work" => {}
            _ => return Err(ApiError::bad("unknown_symbol_field")),
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
        .map(|s| parse_snapshot(&s))
        .transpose()?;
    let expected_commit = fields
        .remove("expected_commit")
        .map(|s| {
            if unhex(&s, format.digest_len())?.len() != format.digest_len() {
                return Err(ApiError::bad("invalid_expected_commit"));
            }
            let id = GitOid::from_hex(format, &s)
                .map_err(|_| ApiError::bad("invalid_expected_commit"))?;
            if id.is_zero() {
                return Err(ApiError::bad("invalid_expected_commit"));
            }
            Ok(id)
        })
        .transpose()?;
    let name = unhex(&take(&mut fields, "name_hex")?, 128)?;
    let mode = match fields.remove("match").as_deref().unwrap_or("exact") {
        "exact" => SymbolMatchMode::Exact,
        "prefix" => SymbolMatchMode::Prefix,
        _ => return Err(ApiError::bad("unsupported_symbol_match")),
    };
    let work = positive(&mut fields, "max_work", MAX_SYMBOL_WORK, MAX_SYMBOL_WORK)?;
    let query = SymbolQuery::new(&name, mode, &kinds, &prefixes, work)
        .map_err(|_| ApiError::bad("invalid_symbol_query"))?;
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
        .map_err(|_| ApiError::bad("invalid_symbol_limit"))?;
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
fn refusal(error: SymbolReadError<NodeWorkspaceRefusal>) -> ApiError {
    match error {
        SymbolReadError::Source(error) => read_error(error),
        SymbolReadError::Syntax { error, .. } => match error.kind {
            SymbolSyntaxErrorKind::Cancelled => ApiError::from_status(Status::Timeout, false),
            SymbolSyntaxErrorKind::WorkLimit
            | SymbolSyntaxErrorKind::FileLimit
            | SymbolSyntaxErrorKind::DepthLimit
            | SymbolSyntaxErrorKind::DeclarationLimit
            | SymbolSyntaxErrorKind::NameLimit => ApiError::too_large(),
            _ => ApiError::new(Status::Conflict, "symbol_source_unsupported"),
        },
    }
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
    if _request.indexed {
        return indexed::execute(node, session, framing, reader, http, maximum);
    }
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let command = command(&read_form(reader, framing, http)?, node.object_format)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let mut live = || !deadline.expired();
    let (head, report) = drive_request_while(
        node,
        &context,
        node.search_source_symbols_snapshot_local_in(
            &context,
            &command.selection.reference,
            command.selection.expected_head,
            command.selection.expected_commit,
            &command.query,
            command.limits,
        ),
        &mut live,
    )
    .map_err(refusal)?;
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
fn row_json(
    row: &SymbolMatch,
    query: &SymbolQuery,
    format: GitHashAlgorithm,
    maximum_file: usize,
) -> Result<String, ApiError> {
    let at = &row.location;
    let path = TreePath::parse_default(&at.path).map_err(|_| ApiError::unavailable())?;
    let name = &row.name;
    let name_valid = !name.is_empty()
        && name.len() <= 128
        && (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_');
    let accepts = match query.mode() {
        SymbolMatchMode::Exact => name == query.name(),
        SymbolMatchMode::Prefix => name.starts_with(query.name()),
    };
    let end = at
        .byte_offset
        .checked_add(at.match_length)
        .ok_or_else(ApiError::unavailable)?;
    let excerpt_end = at
        .excerpt_offset
        .checked_add(at.excerpt.len())
        .ok_or_else(ApiError::unavailable)?;
    if !name_valid
        || !accepts
        || (!query.kinds().is_empty() && !query.kinds().contains(&row.kind))
        || !at.path.ends_with(b".rs")
        || (!query.source_scope().prefixes().is_empty()
            && !query
                .source_scope()
                .prefixes()
                .iter()
                .any(|prefix| path.starts_with(prefix)))
        || at.blob.is_zero()
        || at.blob.algorithm() != format
        || at.match_length != name.len()
        || at.line == 0
        || at.byte_column == 0
        || at.byte_column - 1 > at.byte_offset
        || end > maximum_file
        || at.excerpt.len() > 416
        || at.excerpt.contains(&b'\n')
        || excerpt_end > maximum_file
        || at.excerpt_offset > at.byte_offset
        || excerpt_end < end
        || at.excerpt_offset < at.byte_offset - (at.byte_column - 1)
    {
        return Err(ApiError::unavailable());
    }
    let relative = at.byte_offset - at.excerpt_offset;
    if at.excerpt.get(relative..relative + name.len()) != Some(name.as_slice()) {
        return Err(ApiError::unavailable());
    }
    if row.raw_identifier && (relative < 2 || at.excerpt.get(relative - 2..relative) != Some(b"r#"))
    {
        return Err(ApiError::unavailable());
    }
    Ok(format!(
        concat!(
            "{{\"name_hex\":{},\"kind\":{},\"raw_identifier\":{},",
            "\"path_hex\":{},\"blob\":{},\"byte_offset\":{},\"line\":{},\"byte_column\":{},",
            "\"match_length\":{},\"excerpt_hex\":{},\"excerpt_offset\":{},\"match_truncated_in_excerpt\":false}}"
        ),
        quote(&hex(name)),
        quote(row.kind.as_str()),
        row.raw_identifier,
        quote(&hex(&at.path)),
        quote(&at.blob.to_string()),
        at.byte_offset,
        at.line,
        at.byte_column,
        at.match_length,
        quote(&hex(&at.excerpt)),
        at.excerpt_offset
    ))
}
fn render(
    node: &OneNode,
    command: &Command,
    head: RepositoryAuthorityHeadId,
    report: &SymbolSearchReport,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let query = &command.query;
    let limits = command.limits;
    if report.repository != node.repository_id
        || report.matches.len() > limits.max_matches
        || report.files_selected > limits.max_files
        || report.files_read > report.files_selected
        || report.unsupported_language_files > report.files_selected - report.files_read
        || report.bytes_read > limits.max_total_bytes
        || report.bytes_searched != report.bytes_read
        || report.work_units > query.maximum_work()
        || report.declarations_examined > 20_000
        || report.matches.len() > report.declarations_examined
        || (report.completion == SearchCompletion::Complete
            && report.files_read + report.unsupported_language_files != report.files_selected)
        || (report.completion == SearchCompletion::MatchLimit
            && (report.matches.len() != limits.max_matches
                || report.declarations_examined <= report.matches.len()))
        || report.matches.windows(2).any(|p| {
            (&p[0].location.path, p[0].location.byte_offset)
                >= (&p[1].location.path, p[1].location.byte_offset)
        })
        || [report.source_commit, report.source_tree]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != node.object_format)
        || command.selection.expected_head.is_some_and(|id| id != head)
        || command
            .selection
            .expected_commit
            .is_some_and(|id| id != report.source_commit)
    {
        return Err(ApiError::unavailable());
    }
    let id = head.as_internal_object_id();
    let token = format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    );
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_search_symbols\",\"schema_version\":1,\"profile\":{},",
                "\"authority_class\":\"deterministic-derived\",\"language\":\"rust\",",
                "\"compiler_resolved\":false,\"macro_expansion\":false,\"cfg_evaluated\":false,",
                "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},{},",
                "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},",
                "\"read_only\":true,\"transaction_created\":false,\"published\":false,",
                "\"name_hex\":{},\"match\":{},\"max_matches\":{},\"returned_matches\":{},\"completion\":{},\"complete\":{},",
                "\"files_selected\":{},\"files_read\":{},\"bytes_read\":{},\"bytes_searched\":{},\"non_regular_entries\":{},",
                "\"unsupported_language_files\":{},\"declarations_examined\":{},\"macro_bodies_skipped\":{},\"attributes_skipped\":{},",
                "\"max_work\":{},\"work_units\":{},\"kinds\":["
            ),
            quote(PROFILE),
            quote(&node.tenant_id.to_string()),
            quote(&node.repository_id.to_string()),
            quote(&node.repository_incarnation_id().to_string()),
            quote(node.object_format.as_str()),
            ref_fields("ref", &command.selection.reference),
            quote(&head.to_string()),
            quote(&token),
            quote(&report.source_rcr.to_string()),
            quote(&report.source_commit.to_string()),
            quote(&report.source_tree.to_string()),
            quote(&hex(query.name())),
            quote(match query.mode() {
                SymbolMatchMode::Exact => "exact",
                SymbolMatchMode::Prefix => "prefix",
            }),
            limits.max_matches,
            report.matches.len(),
            quote(match report.completion {
                SearchCompletion::Complete => "complete",
                SearchCompletion::MatchLimit => "match_limit",
            }),
            report.completion == SearchCompletion::Complete,
            report.files_selected,
            report.files_read,
            report.bytes_read,
            report.bytes_searched,
            report.non_regular_entries,
            report.unsupported_language_files,
            report.declarations_examined,
            report.macro_bodies_skipped,
            report.attributes_skipped,
            query.maximum_work(),
            report.work_units
        ),
        maximum,
    )?;
    for (i, kind) in query.kinds().iter().enumerate() {
        check(live)?;
        append(
            &mut out,
            &format!("{}{}", if i == 0 { "" } else { "," }, quote(kind.as_str())),
            maximum,
        )?;
    }
    append(&mut out, "],\"path_prefix_hex\":[", maximum)?;
    for (i, path) in query.source_scope().prefixes().iter().enumerate() {
        check(live)?;
        append(
            &mut out,
            &format!(
                "{}{}",
                if i == 0 { "" } else { "," },
                quote(&hex(path.as_bytes()))
            ),
            maximum,
        )?;
    }
    append(&mut out, "],\"matches\":[", maximum)?;
    for (i, row) in report.matches.iter().enumerate() {
        check(live)?;
        if i != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(
            &mut out,
            &row_json(row, query, node.object_format, limits.max_file_bytes)?,
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
        "object_format=sha1&ref=refs/heads/main&name_hex=5468696e67".to_owned()
    }
    #[test]
    fn closed_form_never_reinterprets_language_query_pins_or_resource_controls() {
        let cmd = command(
            (form() + "&match=prefix&kind=struct&kind=struct&path_prefix_hex=737263").as_bytes(),
            GitHashAlgorithm::Sha1,
        )
        .unwrap();
        assert_eq!(cmd.query.name(), b"Thing");
        assert_eq!(cmd.query.kinds(), &[SymbolKind::Struct]);
        for extra in [
            "&name_hex=61",
            "&principal=root",
            "&match=regex",
            "&kind=call",
            "&max_work=0",
            "&max_work=67108865",
            "&max_matches=4097",
            "&path_prefix_hex=2e2e2f736563726574",
            "&after=1",
            "&case=ascii-insensitive",
            "&expected_commit=0000000000000000000000000000000000000000",
        ] {
            assert!(command((form() + extra).as_bytes(), GitHashAlgorithm::Sha1).is_err());
        }
        assert!(command(form().as_bytes(), GitHashAlgorithm::Sha256).is_err());
        for name in ["", "0", "FF", "612e62", "31", "722374797065"] {
            assert!(
                command(
                    form().replace("5468696e67", name).as_bytes(),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
            );
        }
    }
    #[test]
    fn route_and_read_semantics_reject_ambiguous_envelopes() {
        for (method, path, extra) in [
            ("GET", "/r.git/api/v1/source/search-symbols", ""),
            ("POST", "/r.git/api/v1/source/search-symbols?q=a", ""),
            ("POST", "/../r.git/api/v1/source/search-symbols", ""),
            (
                "POST",
                "/r.git/api/v1/source/search-symbols",
                "Git-Protocol: version=2\r\n",
            ),
        ] {
            let raw = format!(
                "{method} {path} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n"
            );
            let head = fgit_wire::smart_http::head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(Request::parse(&head).is_err());
        }
        let raw=b"POST /r.git/api/v1/source/search-symbols HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n";
        let head = fgit_wire::smart_http::head::parse(raw, HttpLimits::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            Request::parse(&head).unwrap().unwrap().repository_route,
            "/r.git"
        );
        assert!(!super::super::Request::parse(&head).unwrap().is_mutation());
    }
    #[test]
    fn row_validation_requires_exact_name_bytes_coordinates_kind_and_scope() {
        let query = SymbolQuery::new(
            b"type",
            SymbolMatchMode::Exact,
            &[SymbolKind::Function],
            &[],
            MAX_SYMBOL_WORK,
        )
        .unwrap();
        let row = SymbolMatch {
            name: b"type".to_vec(),
            kind: SymbolKind::Function,
            raw_identifier: true,
            location: fgit_forge::source_search::SourceMatch {
                path: b"src/a.rs".to_vec(),
                blob: GitOid::from_hex(GitHashAlgorithm::Sha1, &"a".repeat(40)).unwrap(),
                byte_offset: 5,
                line: 1,
                byte_column: 6,
                match_length: 4,
                excerpt: b"fn r#type(){}".to_vec(),
                excerpt_offset: 0,
            },
        };
        assert!(
            row_json(&row, &query, GitHashAlgorithm::Sha1, 128)
                .unwrap()
                .contains("\"raw_identifier\":true")
        );
        let mut bad = row.clone();
        bad.name = b"fake".to_vec();
        assert!(row_json(&bad, &query, GitHashAlgorithm::Sha1, 128).is_err());
        let mut bad = row.clone();
        bad.location.byte_offset = usize::MAX;
        assert!(row_json(&bad, &query, GitHashAlgorithm::Sha1, 128).is_err());
        let mut bad = row.clone();
        bad.location.byte_column = 0;
        assert!(row_json(&bad, &query, GitHashAlgorithm::Sha1, 128).is_err());
        let mut bad = row.clone();
        bad.location.excerpt[4] = b'x';
        assert!(row_json(&bad, &query, GitHashAlgorithm::Sha1, 128).is_err());
        let mut bad = row.clone();
        bad.kind = SymbolKind::Type;
        assert!(row_json(&bad, &query, GitHashAlgorithm::Sha1, 128).is_err());
        assert!(row_json(&row, &query, GitHashAlgorithm::Sha256, 128).is_err());
        let narrowed = SymbolQuery::new(
            b"type",
            SymbolMatchMode::Exact,
            &[],
            &[b"src2".to_vec()],
            MAX_SYMBOL_WORK,
        )
        .unwrap();
        assert!(row_json(&row, &narrowed, GitHashAlgorithm::Sha1, 128).is_err());
    }
    #[test]
    fn unsupported_source_budget_and_cancel_are_not_success_or_publication_ambiguity() {
        for kind in [
            SymbolSyntaxErrorKind::UnsupportedIdentifier,
            SymbolSyntaxErrorKind::InvalidUtf8,
            SymbolSyntaxErrorKind::WorkLimit,
            SymbolSyntaxErrorKind::Cancelled,
            SymbolSyntaxErrorKind::UnbalancedDelimiter,
        ] {
            let error = refusal(SymbolReadError::Syntax {
                path: b"private.rs".to_vec(),
                error: fgit_forge::source_symbols::SymbolSyntaxError {
                    kind,
                    byte_offset: 12,
                },
            });
            assert!(!error.outcome_unknown);
            let mut raw = Vec::new();
            error
                .send_named(
                    &mut raw,
                    fgit_wire::smart_http::HttpVersion::Http11,
                    "source_error",
                )
                .unwrap();
            let text = String::from_utf8(raw).unwrap();
            assert!(!text.contains("private.rs"));
            assert!(!text.contains("\"matches\""));
        }
        let mut out = String::from("abc");
        assert!(append(&mut out, "x", 3).is_err());
        assert_eq!(out, "abc");
        assert!(check(&mut || false).is_err());
    }
}
