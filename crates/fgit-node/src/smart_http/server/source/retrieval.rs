//! Authenticated read-only model-free Initial retrieval. This route composes
//! existing persisted content/path/symbol readers; it does not build indexes.
use super::super::issues::{ApiError, parse_form, parse_snapshot, quote, ref_fields};
use super::indexed::{activation, append, check, positive, read_route, token, unhex};
use super::request::Selection;
use super::*;
use crate::source_retrieval::{
    Checkpoints, InitialLimits, InitialQuery, InitialReport, PROFILE, RetrievalError,
    SymbolChannel, SymbolPolicy, SymbolUnavailable,
};
use fgit_forge::source_symbols::SymbolMatchMode;
use fgit_graph::lexical::{LexicalQueryLimits, LexicalReadLimits};
use fgit_treefs::TreePath;
use fgit_types::{GitHashAlgorithm, GitOid, RefName};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, head::Envelope};
use std::collections::BTreeMap;
use std::io::Read;

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub repository_route: &'a str,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        read_route(head, "/api/v1/source/search-initial")
            .map(|route| route.map(|repository_route| Self { repository_route }))
    }
}

struct Command {
    selection: Selection,
    query: InitialQuery,
    checkpoints: Checkpoints,
    limits: InitialLimits,
}

fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields
        .remove(name)
        .ok_or_else(|| ApiError::bad("missing_initial_field"))
}
fn command(bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
    let mut fields = BTreeMap::new();
    let (mut terms, mut prefixes, mut kinds) = (Vec::new(), Vec::new(), Vec::new());
    for (name, value) in parse_form(bytes, 192)? {
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
                let p = unhex(&value, 4096)?;
                TreePath::parse_default(&p).map_err(|_| ApiError::bad("invalid_search_scope"))?;
                prefixes.push(p);
                continue;
            }
            "symbol_kind" => {
                if kinds.len() == 8 {
                    return Err(ApiError::bad("too_many_symbol_kinds"));
                }
                kinds.push(super::symbols::kind(&value)?);
                continue;
            }
            "object_format"
            | "ref"
            | "expected_head"
            | "expected_commit"
            | "symbol_name_hex"
            | "symbol_match"
            | "symbol_policy"
            | "minimum_lexical_token"
            | "minimum_lexical_number"
            | "minimum_symbol_token"
            | "minimum_symbol_number"
            | "max_results_per_channel"
            | "max_work"
            | "max_payload_bytes"
            | "max_result_bytes" => {}
            _ => return Err(ApiError::bad("unknown_initial_field")),
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
    if !reference.as_bytes().starts_with(b"refs/") {
        return Err(ApiError::bad("invalid_ref"));
    }
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
    let checkpoints = Checkpoints {
        lexical: activation(
            &mut fields,
            "minimum_lexical_token",
            "minimum_lexical_number",
        )?,
        symbols: activation(&mut fields, "minimum_symbol_token", "minimum_symbol_number")?,
    };
    let mut query =
        InitialQuery::new(&terms, &prefixes).map_err(|_| ApiError::bad("invalid_initial_query"))?;
    match fields.remove("symbol_name_hex") {
        None => {
            if fields.contains_key("symbol_match")
                || fields.contains_key("symbol_policy")
                || !kinds.is_empty()
                || checkpoints.symbols.is_some()
            {
                return Err(ApiError::bad("symbol_options_without_name"));
            }
        }
        Some(name) => {
            let name = unhex(&name, 128)?;
            let mode = match fields.remove("symbol_match").as_deref().unwrap_or("exact") {
                "exact" => SymbolMatchMode::Exact,
                "prefix" => SymbolMatchMode::Prefix,
                _ => return Err(ApiError::bad("unsupported_symbol_match")),
            };
            let policy = match fields
                .remove("symbol_policy")
                .as_deref()
                .unwrap_or("optional")
            {
                "optional" => SymbolPolicy::Optional,
                "required" => SymbolPolicy::Required,
                _ => return Err(ApiError::bad("unsupported_symbol_policy")),
            };
            query = query
                .with_symbols(&name, mode, &kinds, policy)
                .map_err(|_| ApiError::bad("invalid_symbol_query"))?;
        }
    }
    let defaults = InitialLimits::default();
    let limits = InitialLimits {
        max_results_per_channel: positive(
            &mut fields,
            "max_results_per_channel",
            defaults.max_results_per_channel as u64,
            1024,
        )? as usize,
        max_work: positive(
            &mut fields,
            "max_work",
            defaults.max_work,
            defaults.max_work,
        )?,
        max_payload_bytes: positive(
            &mut fields,
            "max_payload_bytes",
            defaults.max_payload_bytes as u64,
            defaults.max_payload_bytes as u64,
        )? as usize,
        max_result_bytes: positive(
            &mut fields,
            "max_result_bytes",
            defaults.max_result_bytes as u64,
            defaults.max_result_bytes as u64,
        )? as usize,
    };
    limits
        .validate(&query)
        .map_err(|_| ApiError::bad("invalid_initial_limits"))?;
    if !fields.is_empty() {
        return Err(ApiError::bad("unused_initial_field"));
    }
    Ok(Command {
        selection: Selection {
            reference,
            expected_head,
            expected_commit,
        },
        query,
        checkpoints,
        limits,
    })
}

fn failure(error: RetrievalError) -> ApiError {
    match error {
        RetrievalError::Source(error) => super::indexed::failure(error),
        RetrievalError::Symbols(error) => super::symbols::indexed::refusal(error),
        RetrievalError::Invalid(_) => ApiError::bad("invalid_initial_query"),
        RetrievalError::Limit(_) => ApiError::too_large(),
        RetrievalError::MixedSource => ApiError::new(Status::Conflict, "source_snapshot_mismatch"),
        RetrievalError::MixedGeneration => {
            ApiError::new(Status::Conflict, "index_generation_mismatch")
        }
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
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let report = drive_request_while(
        node,
        &context,
        node.search_source_initial_local_in(
            &context,
            &command.selection.reference,
            command.selection.expected_head,
            command.selection.expected_commit,
            &command.checkpoints,
            &command.query,
            command.limits,
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

fn generation_json(value: &fgit_graph::GenerationActivation) -> String {
    format!(
        "{{\"index_token\":{},\"index_number\":{}}}",
        quote(&token(value.generation_id.as_internal_object_id())),
        value.authority_generation.get()
    )
}
fn render(
    node: &OneNode,
    command: &Command,
    report: &InitialReport,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let source = report.source();
    let count = command.query.channels();
    let work = |i| crate::source_retrieval::share(command.limits.max_work, count, i);
    let bytes = |i| {
        crate::source_retrieval::share(command.limits.max_payload_bytes as u64, count, i) as usize
    };
    let lex = |i| {
        (
            LexicalQueryLimits {
                max_results: command.limits.max_results_per_channel,
                max_work: work(i),
            },
            LexicalReadLimits {
                max_payload_bytes: bytes(i),
                ..Default::default()
            },
        )
    };
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_search_initial\",\"schema_version\":1,\"profile\":{},",
                "\"phase\":\"Initial\",\"streaming\":false,\"semantic_refinement\":false,\"read_only\":true,",
                "\"transaction_created\":false,\"source_blobs_read\":0,\"source_bytes_read\":0,\"complete\":{},",
                "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},{},",
                "\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},\"root_tree\":{},",
                "\"generation_vector\":{{\"lexical\":{},\"symbols\":{}}},",
                "\"max_results_per_channel\":{},\"max_work\":{},\"max_payload_bytes\":{},\"max_result_bytes\":{},",
                "\"retained_result_bytes\":{},\"completed_payload_bytes_read\":{},\"completed_work_units\":{},\"content\":"
            ),
            quote(PROFILE),
            report.complete(),
            quote(&source.namespace.tenant.to_string()),
            quote(&source.namespace.repository.to_string()),
            quote(&source.namespace.incarnation.to_string()),
            quote(source.namespace.object_format.as_str()),
            ref_fields("ref", &source.reference),
            quote(&token(source.source_head.as_internal_object_id())),
            quote(&source.source_rcr.to_string()),
            quote(&source.commit.to_string()),
            quote(&source.tree.to_string()),
            generation_json(&report.generations().lexical),
            report
                .generations()
                .symbols
                .as_ref()
                .map_or_else(|| "null".into(), generation_json),
            command.limits.max_results_per_channel,
            command.limits.max_work,
            command.limits.max_payload_bytes,
            command.limits.max_result_bytes,
            report.result_bytes(),
            report.completed_payload_bytes_read(),
            report.completed_work_units()
        ),
        maximum,
    )?;
    let content = super::indexed::render_initial(
        node,
        report.content(),
        command.query.content(),
        lex(0),
        maximum
            .min(super::output::MAX_REPLY_BYTES)
            .saturating_sub(out.len()),
        live,
    )?;
    append(&mut out, &content, maximum)?;
    append(&mut out, ",\"path\":", maximum)?;
    let path = super::indexed::render_initial(
        node,
        report.path(),
        command.query.path(),
        lex(1),
        maximum
            .min(super::output::MAX_REPLY_BYTES)
            .saturating_sub(out.len()),
        live,
    )?;
    append(&mut out, &path, maximum)?;
    append(&mut out, ",\"symbols\":", maximum)?;
    match report.symbols() {
        SymbolChannel::NotRequested => append(&mut out, "{\"state\":\"not_requested\"}", maximum)?,
        SymbolChannel::Unavailable(reason) => append(
            &mut out,
            &format!(
                "{{\"state\":\"unavailable\",\"reason\":{},\"result\":null}}",
                quote(match reason {
                    SymbolUnavailable::Uninitialized => "uninitialized",
                    SymbolUnavailable::Stale => "stale",
                })
            ),
            maximum,
        )?,
        SymbolChannel::Available(symbols) => {
            let (query, _) = command.query.symbols().ok_or_else(ApiError::unavailable)?;
            append(&mut out, "{\"state\":\"available\",\"result\":", maximum)?;
            let rendered = super::symbols::indexed::render_initial(
                node,
                symbols,
                query,
                (command.limits.max_results_per_channel, bytes(2)),
                maximum
                    .min(super::output::MAX_REPLY_BYTES)
                    .saturating_sub(out.len()),
                live,
            )?;
            append(&mut out, &rendered, maximum)?;
            append(&mut out, "}", maximum)?;
        }
    }
    append(&mut out, "}", maximum)?;
    check(live)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    const BASE: &str = "object_format=sha1&ref=refs/heads/main&term_hex=5468696e67";
    #[test]
    fn parser_keeps_symbol_case_and_scope() {
        let c=command((BASE.to_owned()+"&path_prefix_hex=737263&symbol_name_hex=5468696e67&symbol_match=prefix&symbol_policy=required").as_bytes(),
            GitHashAlgorithm::Sha1).unwrap();
        assert_eq!(c.query.content().terms(), &[b"thing".to_vec()]);
        assert_eq!(c.query.path().prefixes(), &[b"src".to_vec()]);
        let (s, p) = c.query.symbols().unwrap();
        assert_eq!(s.name(), b"Thing");
        assert_eq!(p, SymbolPolicy::Required);
    }
    #[test]
    fn parser_refuses_writes_and_detached_symbol_options() {
        for suffix in [
            "&force=true",
            "&after=1",
            "&symbol_policy=required",
            "&symbol_kind=function",
        ] {
            assert!(
                command(
                    (BASE.to_owned() + suffix).as_bytes(),
                    GitHashAlgorithm::Sha1
                )
                .is_err()
            );
        }
    }
}
