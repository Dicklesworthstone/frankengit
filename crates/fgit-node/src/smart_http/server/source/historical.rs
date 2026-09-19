//! Read historical source through a current visible ref, never arbitrary OIDs.
//! Outer source routing authenticates the existing independent read grant and
//! rejects transaction keys before this module consumes any request body.

use std::collections::BTreeMap;
use std::io::Read;

use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseQuery};
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};

use super::{ApiError, JsonReply, LoopbackReceiveSession, OneNode, Status,
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, drive_request_while,
    output, read_error, read_form};
use super::request::Selection;
use super::super::issues::{MAX_FORM_BYTES, parse_decimal, parse_form, parse_snapshot, quote};

#[derive(Clone, Copy, Debug)]
enum Operation { Tree, Blob }

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub(super) repository_route: &'a str,
    operation: Operation,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let (path, query) = head.target.split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let Some((repository_route, action)) = path.split_once("/api/v1/source/") else { return Ok(None); };
        let operation = match action {
            "historical-tree" => Operation::Tree,
            "historical-blob" => Operation::Blob,
            _ => return Ok(None),
        };
        if repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)))
        {
            return Err(ApiError::not_found());
        }
        if head.method != "POST" { return Err(ApiError::method()); }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_historical_source_envelope"));
        }
        if !head.content_type.is_some_and(|media| media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8"))
        {
            return Err(ApiError::media());
        }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self { repository_route, operation }))
    }

    fn command(&self, bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        for (name, value) in parse_form(bytes, 12)? {
            let common = matches!(name.as_str(), "ref" | "object_format" | "expected_head"
                | "expected_ref_tip" | "at_commit" | "path_hex" | "limit");
            let applicable = match self.operation {
                Operation::Tree => name == "after_hex",
                Operation::Blob => name == "offset",
            };
            if !common && !applicable { return Err(ApiError::bad("unknown_or_inapplicable_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let reference = RefName::try_new(take(&mut fields, "ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        let expected_head = parse_snapshot(&take(&mut fields, "expected_head")?)?;
        let expected_ref_tip = oid(&take(&mut fields, "expected_ref_tip")?, format)?;
        let commit = oid(&take(&mut fields, "at_commit")?, format)?;
        let path = fields.remove("path_hex").map(|value| unhex(&value, 4096)).transpose()?;
        let action = match self.operation {
            Operation::Tree => SourceBrowseAction::List {
                after: fields.remove("after_hex").map(|value| unhex(&value, 4096)).transpose()?,
                limit: positive(&mut fields, "limit", 100, 1000)? as u16,
            },
            Operation::Blob => SourceBrowseAction::Read {
                offset: fields.remove("offset").map(|value| parse_decimal(&value)).transpose()?.unwrap_or(0),
                limit: positive(&mut fields, "limit", 64 * 1024, 1024 * 1024)? as u32,
            },
        };
        let query = SourceBrowseQuery { path, expected_head: Some(expected_head),
            expected_commit: Some(commit), action };
        query.validate(format).map_err(|_| ApiError::bad("invalid_historical_browse_query"))?;
        let selection = Selection { reference, expected_head: Some(expected_head), expected_commit: Some(commit) };
        Ok(Command { selection, expected_ref_tip, commit, query })
    }
}

#[derive(Debug)]
struct Command {
    selection: Selection,
    expected_ref_tip: GitOid,
    commit: GitOid,
    query: SourceBrowseQuery,
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields.remove(name).ok_or_else(|| ApiError::bad("historical_source_selection_required"))
}
fn positive(fields: &mut BTreeMap<String, String>, name: &str, default: u64, maximum: u64)
    -> Result<u64, ApiError>
{
    let value = fields.remove(name).map(|text| parse_decimal(&text)).transpose()?.unwrap_or(default);
    if value == 0 || value > maximum { return Err(ApiError::bad("invalid_source_limit")); }
    Ok(value)
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > maximum * 2
        || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_hex_bytes"));
    }
    let digit = |byte: u8| if byte <= b'9' { byte - b'0' } else { byte - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| digit(pair[0]) << 4 | digit(pair[1])).collect())
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if unhex(text, format.digest_len())?.len() != format.digest_len() {
        return Err(ApiError::bad("invalid_historical_commit"));
    }
    let id = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_historical_commit"))?;
    if id.is_zero() { return Err(ApiError::bad("invalid_historical_commit")); }
    Ok(id)
}

pub(super) fn execute(
    node: &OneNode,
    request: &Request<'_>,
    session: &LoopbackReceiveSession,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum_response: u64,
) -> Result<JsonReply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    // Reuse complete fixed-length/chunked framing and the small form envelope.
    // This request does not create a seal, acquire a mutation key or publish.
    let command = request.command(&read_form(reader, framing, http)?, node.object_format)?;
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(output::MAX_REPLY_BYTES);
    let prefix = prefix(&command);
    let source_maximum = maximum.checked_sub(prefix.len() + 1).ok_or_else(ApiError::too_large)?;
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    let mut live = || !deadline.expired();
    let report = drive_request_while(node, &context,
        node.browse_source_ancestor_local_in(&context, &command.selection.reference,
            command.expected_ref_tip, command.commit, &command.query), &mut live).map_err(read_error)?;
    // The established output validator rechecks target/hash/head, ordering and
    // exact byte-range semantics before any successful response is emitted.
    let source = output::browse(node, &command.selection, &command.query, &report, source_maximum, &mut live)?;
    let body = wrap(prefix, &source, maximum, &mut live)?;
    Ok(JsonReply { status: Status::Success, body, terminal: None })
}

fn prefix(command: &Command) -> String {
    format!(concat!("{{\"type\":\"historical_source\",\"schema_version\":1,",
        "\"selection\":\"visible-ref-ancestor-v1\",\"source_ref_tip\":{},\"at_commit\":{},",
        "\"read_only\":true,\"transaction_created\":false,\"published\":false,\"source\":"),
        quote(&command.expected_ref_tip.to_string()), quote(&command.commit.to_string()))
}
fn wrap(mut prefix: String, source: &str, maximum: usize, live: &mut impl FnMut() -> bool)
    -> Result<String, ApiError>
{
    if !live() { return Err(ApiError::from_status(Status::Timeout, false)); }
    let additional = source.len().checked_add(1).ok_or_else(ApiError::too_large)?;
    if prefix.len().checked_add(additional).is_none_or(|total| total > maximum) {
        return Err(ApiError::too_large());
    }
    prefix.try_reserve(additional).map_err(|_| ApiError::unavailable())?;
    prefix.push_str(source);
    prefix.push('}');
    if !live() { return Err(ApiError::from_status(Status::Timeout, false)); }
    Ok(prefix)
}

#[cfg(test)]
mod tests;
