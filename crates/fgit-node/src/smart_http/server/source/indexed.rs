//! Read-only persisted lexical search. Builds are a trusted-local operation;
//! an HTTP query cannot stage a payload or acquire generation-write authority.
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
use fgit_graph::lexical::{
    IndexError, IndexedLexicalReport, LexicalChannel, LexicalError, LexicalQuery,
    LexicalQueryLimits, LexicalReadLimits, MAX_WORK, PROFILE,
};
use fgit_graph::{GenerationActivation, GenerationAuthorityError, GraphGenerationId};
use fgit_treefs::TreePath;
use fgit_types::{
    CANONICAL_CODEC_VERSION, DigestBytes, GitHashAlgorithm, GitOid, HeadGeneration,
    InternalObjectId, RefName,
};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        read_route(head, "/api/v1/source/search-index")
            .map(|route| route.map(|repository_route| Self { repository_route }))
    }
}
/// Shared bounded read envelope; the source gateway still owns credentials,
/// service scope, route binding, and transaction-key refusal.
pub(super) fn read_route<'a>(
    head: &Envelope<'a>,
    suffix: &str,
) -> Result<Option<&'a str>, ApiError> {
    let (path, query) = head
        .target
        .split_once('?')
        .map_or((head.target, None), |(p, q)| (p, Some(q)));
    let Some(route) = path.strip_suffix(suffix) else {
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
        return Err(ApiError::bad("invalid_index_envelope"));
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
    Ok(Some(route))
}

#[derive(Debug)]
struct Command {
    selection: Selection,
    generation: Option<GenerationActivation>,
    minimum: Option<GenerationActivation>,
    query: LexicalQuery,
    after: Option<u64>,
    limits: LexicalQueryLimits,
    reads: LexicalReadLimits,
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_index_field"))
}
pub(super) fn positive(
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
        return Err(ApiError::bad("invalid_index_limit"));
    }
    Ok(value)
}
pub(super) fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
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
        .map(|p| digit(p[0]) * 16 + digit(p[1]))
        .collect())
}
fn generation_id(text: &str) -> Result<GraphGenerationId, ApiError> {
    let algorithm = fgit_crypto::internal_algorithm_id(fgit_crypto::IdentityDomain::Generation);
    let prefix = format!("alg:{}:", algorithm.code_point());
    let raw = text
        .strip_prefix(&prefix)
        .ok_or_else(|| ApiError::bad("invalid_index_generation"))?;
    let width = fgit_crypto::DigestAlgorithm::from_id(algorithm)
        .ok_or_else(ApiError::unavailable)?
        .digest_len();
    let bytes = unhex(raw, width)?;
    if bytes.len() != width || bytes.iter().all(|byte| *byte == 0) {
        return Err(ApiError::bad("invalid_index_generation"));
    }
    let digest =
        DigestBytes::try_new(&bytes).map_err(|_| ApiError::bad("invalid_index_generation"))?;
    GraphGenerationId::from_internal_object_id(InternalObjectId::new(
        algorithm,
        GraphGenerationId::DOMAIN_TAG,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
    .map_err(|_| ApiError::bad("invalid_index_generation"))
}
pub(super) fn activation(
    fields: &mut BTreeMap<String, String>,
    token: &str,
    number: &str,
) -> Result<Option<GenerationActivation>, ApiError> {
    match (fields.remove(token), fields.remove(number)) {
        (None, None) => Ok(None),
        (Some(token), Some(number)) => Ok(Some(GenerationActivation {
            generation_id: generation_id(&token)?,
            authority_generation: HeadGeneration::try_new(parse_decimal(&number)?)
                .map_err(|_| ApiError::bad("invalid_index_generation"))?,
        })),
        _ => Err(ApiError::bad("incomplete_index_generation")),
    }
}
fn command(bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
    let mut fields = BTreeMap::new();
    let (mut terms, mut prefixes) = (Vec::new(), Vec::new());
    for (name, value) in parse_form(bytes, 180)? {
        match name.as_str() {
            "term_hex" => {
                if terms.len() == 32 {
                    return Err(ApiError::too_large());
                }
                terms.push(unhex(&value, 128)?);
                continue;
            }
            "path_prefix_hex" => {
                if prefixes.len() == 128 {
                    return Err(ApiError::too_large());
                }
                prefixes.push(unhex(&value, 4096)?);
                continue;
            }
            "ref"
            | "object_format"
            | "expected_head"
            | "expected_commit"
            | "channel"
            | "index_token"
            | "index_number"
            | "minimum_index_token"
            | "minimum_index_number"
            | "after"
            | "limit"
            | "max_work"
            | "max_payload_bytes" => {}
            _ => return Err(ApiError::bad("unknown_index_field")),
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
            if unhex(&value, format.digest_len())?.len() != format.digest_len() {
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
    let channel = match fields.remove("channel").as_deref().unwrap_or("content") {
        "content" => LexicalChannel::Content,
        "path" => LexicalChannel::Path,
        _ => return Err(ApiError::bad("unsupported_index_channel")),
    };
    // Apply the same path policy as native TreeFS, before index reads.
    for prefix in &prefixes {
        TreePath::parse_default(prefix).map_err(|_| ApiError::bad("invalid_search_scope"))?;
    }
    let query = LexicalQuery::new(channel, &terms, &prefixes)
        .map_err(|_| ApiError::bad("invalid_index_query"))?;
    let generation = activation(&mut fields, "index_token", "index_number")?;
    let minimum = activation(&mut fields, "minimum_index_token", "minimum_index_number")?;
    let after = fields
        .remove("after")
        .map(|v| parse_decimal(&v))
        .transpose()?;
    if after == Some(0)
        || (after.is_some()
            && (generation.is_none() || expected_head.is_none() || expected_commit.is_none()))
    {
        return Err(ApiError::bad("index_continuation_requires_pins"));
    }
    let limits = LexicalQueryLimits {
        max_results: positive(&mut fields, "limit", 100, 4096)? as usize,
        max_work: positive(&mut fields, "max_work", MAX_WORK, MAX_WORK)?,
    };
    let defaults = LexicalReadLimits::default();
    let reads = LexicalReadLimits {
        max_payload_bytes: positive(
            &mut fields,
            "max_payload_bytes",
            defaults.max_payload_bytes as u64,
            defaults.max_payload_bytes as u64,
        )? as usize,
        ..defaults
    };
    Ok(Command {
        selection: Selection {
            reference,
            expected_head,
            expected_commit,
        },
        generation,
        minimum,
        query,
        after,
        limits,
        reads,
    })
}

pub(super) fn failure(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::SourceIndexStale => {
            ApiError::new(Status::Conflict, "source_index_stale")
        }
        NodeWorkspaceRefusal::SourceIndex(error) => match *error {
            IndexError::Uninitialized => {
                ApiError::new(Status::Conflict, "source_index_uninitialized")
            }
            IndexError::Lexical(LexicalError::Invalid(_)) => ApiError::bad("invalid_index_query"),
            IndexError::Lexical(LexicalError::Limit(_)) => ApiError::too_large(),
            IndexError::Lexical(LexicalError::Cancelled)
            | IndexError::Generation(GenerationAuthorityError::ReadCancelled) => {
                ApiError::from_status(Status::Timeout, false)
            }
            IndexError::Generation(GenerationAuthorityError::CheckpointUnresolved) => {
                ApiError::new(Status::Conflict, "index_checkpoint_unavailable")
            }
            IndexError::Generation(GenerationAuthorityError::InvalidReadLimits) => {
                ApiError::bad("invalid_index_limits")
            }
            IndexError::Generation(GenerationAuthorityError::ReadBudgetExceeded(_)) => {
                ApiError::too_large()
            }
            _ => ApiError::unavailable(),
        },
        error => read_error(error),
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
    let report = drive_request_while(
        node,
        &context,
        node.search_source_index_local_in(
            &context,
            &command.selection.reference,
            command.selection.expected_head,
            command.selection.expected_commit,
            command.generation.as_ref(),
            command.minimum.as_ref(),
            &command.query,
            command.after,
            command.limits,
            command.reads,
        ),
        &mut live,
    )
    .map_err(failure)?;
    let body = render(
        node,
        &command,
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
pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn token(id: &InternalObjectId) -> String {
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
pub(super) fn check(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}
pub(super) fn append(out: &mut String, value: &str, maximum: usize) -> Result<(), ApiError> {
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
fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |n| n.to_string())
}
fn rows(
    command: &Command,
    report: &IndexedLexicalReport,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    let hits = &report.results.hits;
    if report.query != command.query
        || hits.len() > command.limits.max_results
        || report.results.work_units > command.limits.max_work
        || hits.len() > report.indexed_documents
        || report.indexed_documents > 20_000
        || report.indexed_source_bytes > 64 * 1024 * 1024
        || report.non_regular_entries > 50_000
        || report.segments_read > command.reads.max_segments
        || report.payload_bytes_read > command.reads.max_payload_bytes
        || report.generation_bytes_read > command.reads.generation.max_total_bytes
        || (report.results.complete && report.results.next_after.is_some())
        || (!report.results.complete
            && (hits.len() != command.limits.max_results
                || report.results.next_after != hits.last().map(|h| h.document_id)))
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    let (mut previous_id, mut previous_path) = (command.after.unwrap_or(0), None::<&[u8]>);
    for (index, hit) in hits.iter().enumerate() {
        check(live)?;
        TreePath::parse_default(&hit.path).map_err(|_| ApiError::unavailable())?;
        if hit.document_id <= previous_id
            || previous_path.is_some_and(|p| p >= hit.path.as_slice())
            || hit.blob.is_zero()
            || hit.blob.algorithm() != report.source.namespace.object_format
            || hit.content_bytes as usize > 8 * 1024 * 1024
            || hit.spans.len() != command.query.terms().len()
            || (!command.query.prefixes().is_empty()
                && !command.query.prefixes().iter().any(|prefix| {
                    hit.path == *prefix
                        || (hit.path.starts_with(prefix)
                            && hit.path.get(prefix.len()) == Some(&b'/'))
                }))
        {
            return Err(ApiError::unavailable());
        }
        previous_id = hit.document_id;
        previous_path = Some(&hit.path);
        append(
            &mut out,
            &format!(
                "{}{{\"document_id\":{},\"path_hex\":{},\"blob\":{},\"content_bytes\":{},\"spans\":[",
                if index == 0 { "" } else { "," },
                hit.document_id,
                quote(&hex(&hit.path)),
                quote(&hit.blob.to_string()),
                hit.content_bytes
            ),
            maximum,
        )?;
        for (i, span) in hit.spans.iter().enumerate() {
            let bound = match command.query.channel() {
                LexicalChannel::Content => hit.content_bytes as usize,
                LexicalChannel::Path => hit.path.len(),
            };
            if span.query_index != i
                || usize::from(span.byte_length) != command.query.terms()[i].len()
                || (span.byte_offset as usize)
                    .checked_add(usize::from(span.byte_length))
                    .is_none_or(|end| end > bound)
            {
                return Err(ApiError::unavailable());
            }
            append(
                &mut out,
                &format!(
                    "{}{{\"query_index\":{},\"byte_offset\":{},\"byte_length\":{}}}",
                    if i == 0 { "" } else { "," },
                    i,
                    span.byte_offset,
                    span.byte_length
                ),
                maximum,
            )?;
        }
        append(&mut out, "]}", maximum)?;
    }
    check(live)?;
    Ok(out)
}
/// Reuse the complete single-channel validator for a joined Initial response.
/// The caller has already validated the complete source/generation vector.
pub(super) fn render_initial(
    node: &OneNode,
    report: &IndexedLexicalReport,
    query: &LexicalQuery,
    budget: (LexicalQueryLimits, LexicalReadLimits),
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    let command = Command {
        selection: Selection {
            reference: report.source.reference.clone(),
            expected_head: Some(report.source.source_head),
            expected_commit: Some(report.source.commit),
        },
        generation: Some(report.generation.clone()),
        minimum: None,
        query: query.clone(),
        after: None,
        limits: budget.0,
        reads: budget.1,
    };
    render(node, &command, report, maximum, live)
}

fn render(
    node: &OneNode,
    command: &Command,
    report: &IndexedLexicalReport,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let source = &report.source;
    if source.namespace.tenant != node.tenant_id
        || source.namespace.repository != node.repository_id
        || source.namespace.incarnation != node.repository_incarnation_id()
        || source.namespace.object_format != node.object_format
        || source.reference != command.selection.reference
        || [source.commit, source.tree]
            .iter()
            .any(|id| id.is_zero() || id.algorithm() != node.object_format)
        || command
            .selection
            .expected_head
            .is_some_and(|head| head != source.source_head)
        || command
            .selection
            .expected_commit
            .is_some_and(|commit| commit != source.commit)
        || command
            .generation
            .as_ref()
            .is_some_and(|value| value != &report.generation)
        || report.selected_generation_head.authority_generation
            < report.generation.authority_generation
        || command.minimum.as_ref().is_some_and(|floor| {
            floor.authority_generation > report.selected_generation_head.authority_generation
        })
    {
        return Err(ApiError::unavailable());
    }
    let hits = rows(command, report, maximum, live)?;
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_search_index\",\"schema_version\":1,\"profile\":{},",
                "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},{},",
                "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},",
                "\"index_token\":{},\"index_number\":{},\"selected_index_token\":{},\"selected_index_number\":{},",
                "\"read_only\":true,\"transaction_created\":false,\"published\":false,\"channel\":{},",
                "\"after\":{},\"limit\":{},\"returned_hits\":{},\"complete\":{},\"next_after\":{},",
                "\"indexed_documents\":{},\"indexed_source_bytes\":{},\"non_regular_entries\":{},",
                "\"segments_read\":{},\"payload_bytes_read\":{},\"generation_bytes_read\":{},\"work_units\":{},\"terms_hex\":["
            ),
            quote(PROFILE),
            quote(&node.tenant_id.to_string()),
            quote(&node.repository_id.to_string()),
            quote(&node.repository_incarnation_id().to_string()),
            quote(node.object_format.as_str()),
            ref_fields("ref", &source.reference),
            quote(&source.source_head.to_string()),
            quote(&token(source.source_head.as_internal_object_id())),
            quote(&source.source_rcr.to_string()),
            quote(&source.commit.to_string()),
            quote(&source.tree.to_string()),
            quote(&token(
                report.generation.generation_id.as_internal_object_id()
            )),
            report.generation.authority_generation.get(),
            quote(&token(
                report
                    .selected_generation_head
                    .generation_id
                    .as_internal_object_id()
            )),
            report.selected_generation_head.authority_generation.get(),
            quote(match command.query.channel() {
                LexicalChannel::Content => "content",
                LexicalChannel::Path => "path",
            }),
            optional(command.after),
            command.limits.max_results,
            report.results.hits.len(),
            report.results.complete,
            optional(report.results.next_after),
            report.indexed_documents,
            report.indexed_source_bytes,
            report.non_regular_entries,
            report.segments_read,
            report.payload_bytes_read,
            report.generation_bytes_read,
            report.results.work_units
        ),
        maximum,
    )?;
    for (i, term) in command.query.terms().iter().enumerate() {
        append(
            &mut out,
            &format!("{}{}", if i == 0 { "" } else { "," }, quote(&hex(term))),
            maximum,
        )?;
    }
    append(&mut out, "],\"path_prefix_hex\":[", maximum)?;
    for (i, prefix) in command.query.prefixes().iter().enumerate() {
        check(live)?;
        append(
            &mut out,
            &format!("{}{}", if i == 0 { "" } else { "," }, quote(&hex(prefix))),
            maximum,
        )?;
    }
    append(&mut out, "],\"hits\":[", maximum)?;
    append(&mut out, &hits, maximum)?;
    append(&mut out, "]}", maximum)?;
    check(live)?;
    Ok(out)
}

#[cfg(test)]
mod tests;
