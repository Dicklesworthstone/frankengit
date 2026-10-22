//! Exact source excerpts use the same credentialed read gateway and the same
//! Initial grammar. No caller-supplied OID, report, or path list is trusted.
use super::super::super::issues::parse_decimal;
use super::super::indexed::hex;
use super::evidence_failure as failure;
use super::*;
use crate::source_retrieval::context::{ContextLimits, InitialContext, PROFILE as CONTEXT_PROFILE};

use crate::source_retrieval::context::ranked::{self, ContextRanking};

pub(super) struct ContextCommand {
    initial: Command,
    limits: ContextLimits,
    ranked: bool,
}
fn command(bytes: &[u8], format: GitHashAlgorithm) -> Result<ContextCommand, ApiError> {
    command_fields(parse_form(bytes, 197)?, format)
}
pub(super) fn command_fields(
    parsed: Vec<(String, String)>,
    format: GitHashAlgorithm,
) -> Result<ContextCommand, ApiError> {
    if parsed.len() > 197 {
        return Err(ApiError::too_large());
    }
    let mut fields = BTreeMap::new();
    let mut initial = Vec::new();
    for (name, value) in parsed {
        match name.as_str() {
            "context_max_files"
            | "context_radius_bytes"
            | "context_max_source_bytes"
            | "context_max_excerpt_bytes"
            | "context_selection" => {
                if fields.insert(name, value).is_some() {
                    return Err(ApiError::bad("duplicate_field"));
                }
            }
            _ => initial.push((name, value)),
        }
    }
    let ranked = match fields
        .remove("context_selection")
        .as_deref()
        .unwrap_or("raw-path-prefix")
    {
        "raw-path-prefix" => false,
        ranked::PROFILE => true,
        _ => return Err(ApiError::bad("unsupported_context_selection")),
    };
    let defaults = ContextLimits::default();
    // A zero radius is intentional: return just matched bytes (or a tiny
    // preamble for path-only hits), not a request for an unbounded default.
    let radius_bytes = fields
        .remove("context_radius_bytes")
        .map(|v| parse_decimal(&v))
        .transpose()?
        .unwrap_or(defaults.radius_bytes as u64);
    if radius_bytes > 4096 {
        return Err(ApiError::bad("invalid_context_limits"));
    }
    let limits = ContextLimits {
        max_files: positive(
            &mut fields,
            "context_max_files",
            defaults.max_files as u64,
            32,
        )? as usize,
        radius_bytes: radius_bytes as usize,
        max_source_bytes: positive(
            &mut fields,
            "context_max_source_bytes",
            defaults.max_source_bytes as u64,
            defaults.max_source_bytes as u64,
        )? as usize,
        max_excerpt_bytes: positive(
            &mut fields,
            "context_max_excerpt_bytes",
            defaults.max_excerpt_bytes as u64,
            1024 * 1024,
        )? as usize,
    };
    limits
        .validate()
        .map_err(|_| ApiError::bad("invalid_context_limits"))?;
    let initial = super::command_fields(initial, format)?;
    Ok(ContextCommand {
        initial,
        limits,
        ranked,
    })
}
pub(super) fn execute(
    node: &OneNode,
    session: &LoopbackReceiveSession,
    read: &SourceReadContext,
    framing: BodyFraming,
    reader: &mut impl Read,
    http: HttpLimits,
    maximum: u64,
) -> Result<JsonReply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    let command = command(&read_form(reader, framing, http)?, node.object_format)?;
    Ok(JsonReply {
        status: Status::Success,
        body: run(
            node,
            read,
            &command,
            usize::try_from(maximum).unwrap_or(usize::MAX),
        )?,
        terminal: None,
    })
}
pub(super) fn run(
    node: &OneNode,
    read: &SourceReadContext,
    command: &ContextCommand,
    maximum: usize,
) -> Result<String, ApiError> {
    read.check_node(node)
        .map_err(|_| ApiError::new(Status::Forbidden, "source_read_context_mismatch"))?;
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let request = node.session_request_context(&deadline);
    let mut live = || !deadline.expired();
    let (context, ranking) = drive_request_while(
        node,
        &request,
        async {
            let report = node
                .search_source_initial_local_in(
                    &request,
                    read,
                    &command.initial.selection.reference,
                    command.initial.selection.expected_head,
                    command.initial.selection.expected_commit,
                    &command.initial.checkpoints,
                    &command.initial.query,
                    command.initial.limits,
                )
                .await?;
            // One request and deadline span retrieval AND hydration. A source move
            // between them refuses; no new allowance or alternative source is tried.
            if command.ranked {
                let selected = node
                    .hydrate_source_initial_ranked_local_in(&request, read, report, command.limits)
                    .await?;
                let (context, ranking) = selected.into_parts();
                Ok((context, Some(ranking)))
            } else {
                node.hydrate_source_initial_local_in(&request, read, report, command.limits)
                    .await
                    .map(|context| (context, None))
            }
        },
        &mut live,
    )
    .map_err(failure)?;
    render(
        node,
        read,
        command,
        &context,
        ranking.as_ref(),
        maximum,
        &mut live,
    )
}
fn append_hex(
    out: &mut String,
    bytes: &[u8],
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    check(live)?;
    if bytes
        .len()
        .checked_mul(2)
        .and_then(|n| out.len().checked_add(n))
        .is_none_or(|n| n > maximum)
    {
        return Err(ApiError::too_large());
    }
    // Bound temporary conversions and checkpoint during every large excerpt.
    for chunk in bytes.chunks(4096) {
        check(live)?;
        append(out, &hex(chunk), maximum)?;
    }
    check(live)
}
fn render(
    node: &OneNode,
    read: &SourceReadContext,
    command: &ContextCommand,
    context: &InitialContext,
    ranking: Option<&ContextRanking>,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    check(live)?;
    let maximum = maximum.min(super::super::output::MAX_REPLY_BYTES);
    let limits = command.limits;
    if context.files().len() > limits.max_files
        || context.source_bytes_read() > limits.max_source_bytes
        || context.excerpt_bytes() > limits.max_excerpt_bytes
        || command.ranked != ranking.is_some()
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"source_context_initial\",\"schema_version\":1,\"profile\":{},",
                "\"read_only\":true,\"transaction_created\":false,\"source_material_untrusted\":true,\"complete\":{},",
                "\"candidate_files\":{},\"returned_files\":{},\"omitted_files\":{},\"selection\":{},",
                "\"source_blobs_read\":{},\"source_bytes_read\":{},\"excerpt_bytes\":{},\"source_file_limit\":{},\"lineage_metadata_bytes\":{},",
                "\"context_max_files\":{},\"context_radius_bytes\":{},\"context_max_source_bytes\":{},\"context_max_excerpt_bytes\":{},",
                "\"retrieval\":"
            ),
            quote(CONTEXT_PROFILE),
            context.complete(),
            context.candidate_files(),
            context.files().len(),
            context.omitted_files(),
            quote(if command.ranked {
                ranked::PROFILE
            } else {
                "raw-path-prefix"
            }),
            context.source_blobs_read(),
            context.source_bytes_read(),
            context.excerpt_bytes(),
            context.source_file_limit(),
            context.lineage_metadata_bytes(),
            limits.max_files,
            limits.radius_bytes,
            limits.max_source_bytes,
            limits.max_excerpt_bytes
        ),
        maximum,
    )?;
    // Do not duplicate or weaken the original channel and coverage validators.
    let retrieval = super::render(
        node,
        read,
        &command.initial,
        context.retrieval(),
        context.retrieval().authorization(),
        maximum.saturating_sub(out.len()),
        live,
    )?;
    append(&mut out, &retrieval, maximum)?;
    append(&mut out, ",\"files\":[", maximum)?;
    for (ordinal, file) in context.files().iter().enumerate() {
        check(live)?;
        if file.source_bytes() > context.source_file_limit() {
            return Err(ApiError::unavailable());
        }
        file.validate_lineage(context.retrieval(), &mut || {
            if live() {
                Ok(())
            } else {
                Err(RetrievalError::Source(NodeWorkspaceRefusal::Cancelled {
                    exhaustion: None,
                }))
            }
        })
        .map_err(failure)?;
        append(
            &mut out,
            &format!(
                "{}{{\"path_hex\":{},\"blob\":{},\"source_bytes\":{},\"position_domain\":\"source-blob-bytes\",\"lineage_commitment\":{},\"authorization_labels\":[",
                if ordinal == 0 { "" } else { "," },
                quote(&hex(file.path())),
                quote(&file.blob().to_string()),
                file.source_bytes(),
                quote(&hex(file.lineage_commitment()))
            ),
            maximum,
        )?;
        for (ordinal, label) in file.authorization_labels().iter().enumerate() {
            check(live)?;
            append(
                &mut out,
                &format!(
                    "{}{}",
                    if ordinal == 0 { "" } else { "," },
                    quote(&hex(label))
                ),
                maximum,
            )?;
        }
        append(&mut out, "],\"anchors\":[", maximum)?;
        for (ordinal, (anchor, origin)) in file
            .anchors()
            .iter()
            .zip(file.anchor_authorization_labels())
            .enumerate()
        {
            check(live)?;
            append(
                &mut out,
                &format!(
                    "{}{{\"channel\":{},\"byte_offset\":{},\"byte_length\":{},\"authorization_label\":{},\"position_domain\":{}}}",
                    if ordinal == 0 { "" } else { "," },
                    quote(anchor.channel.as_str()),
                    anchor.byte_offset,
                    anchor.byte_length,
                    quote(&hex(origin)),
                    quote(anchor.channel.position_domain())
                ),
                maximum,
            )?;
        }
        append(&mut out, "],\"excerpts\":[", maximum)?;
        for (ordinal, excerpt) in file.excerpts().iter().enumerate() {
            check(live)?;
            append(
                &mut out,
                &format!(
                    "{}{{\"byte_offset\":{},\"position_domain\":\"source-blob-bytes\",\"lineage_commitment\":{},\"untrusted_bytes_hex\":\"",
                    if ordinal == 0 { "" } else { "," },
                    excerpt.offset(),
                    quote(&hex(file.lineage_commitment()))
                ),
                maximum,
            )?;
            append_hex(&mut out, excerpt.untrusted_bytes(), maximum, live)?;
            append(&mut out, "\"}", maximum)?;
        }
        append(&mut out, "]}", maximum)?;
    }
    append(&mut out, "]", maximum)?;
    if let Some(ranking) = ranking {
        append_ranking(&mut out, context, ranking, maximum, live)?;
    }
    append(&mut out, "}", maximum)?;
    check(live)?;
    Ok(out)
}

#[cfg(test)]
mod tests;

/// A bounded receipt for selection, not a signed proof or a relevance estimate.
/// Validate its identity join and arithmetic before the buffered response is sent.
fn append_ranking(
    out: &mut String,
    context: &InitialContext,
    ranking: &ContextRanking,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ApiError> {
    check(live)?;
    if ranking.candidate_files() != context.candidate_files()
        || ranking.selected().len() != context.files().len()
    {
        return Err(ApiError::unavailable());
    }
    append(
        out,
        &format!(
            concat!(
                ",\"ranking\":{{\"profile\":{},\"rank_constant\":{},\"score_scale\":{},",
                "\"input_order\":\"raw-path-distinct-documents\",\"tie_break\":\"raw-path-ascending\",",
                "\"ranked_over\":\"returned-channel-hits\",\"semantic_relevance\":false,\"selected\":["
            ),
            quote(ranked::PROFILE),
            ranked::RANK_CONSTANT,
            ranked::SCORE_SCALE
        ),
        maximum,
    )?;
    let mut previous: Option<(u32, &[u8])> = None;
    for (ordinal, selected) in ranking.selected().iter().enumerate() {
        check(live)?;
        if previous.is_some_and(|(score, path)| {
            selected.score_q16() > score
                || (selected.score_q16() == score && selected.path() <= path)
        }) {
            return Err(ApiError::unavailable());
        }
        previous = Some((selected.score_q16(), selected.path()));
        let at = context
            .files()
            .binary_search_by(|file| file.path().cmp(selected.path()))
            .map_err(|_| ApiError::unavailable())?;
        if context.files()[at].blob() != selected.blob() {
            return Err(ApiError::unavailable());
        }
        append(
            out,
            &format!(
                "{}{{\"position\":{},\"path_hex\":{},\"blob\":{},\"score_q16\":{},\"contributions\":[",
                if ordinal == 0 { "" } else { "," },
                ordinal + 1,
                quote(&hex(selected.path())),
                quote(&selected.blob().to_string()),
                selected.score_q16()
            ),
            maximum,
        )?;
        let mut score = 0u32;
        let mut previous_channel = None;
        for (index, contribution) in selected.contributions().iter().enumerate() {
            check(live)?;
            let rank = contribution.document_rank();
            let channel = contribution.channel();
            if !(1..=1024).contains(&rank) || previous_channel.is_some_and(|prior| prior >= channel)
            {
                return Err(ApiError::unavailable());
            }
            previous_channel = Some(channel);
            let weight = ranked::channel_weight(channel);
            let expected = weight * ranked::SCORE_SCALE / (ranked::RANK_CONSTANT + rank);
            if contribution.score_q16() != expected {
                return Err(ApiError::unavailable());
            }
            score = score
                .checked_add(expected)
                .ok_or_else(ApiError::unavailable)?;
            append(
                out,
                &format!(
                    "{}{{\"channel\":{},\"document_rank\":{},\"weight\":{},\"score_q16\":{}}}",
                    if index == 0 { "" } else { "," },
                    quote(channel.as_str()),
                    rank,
                    weight,
                    expected
                ),
                maximum,
            )?;
        }
        if score == 0 || score != selected.score_q16() {
            return Err(ApiError::unavailable());
        }
        append(out, "]}", maximum)?;
    }
    append(out, "]}", maximum)?;
    check(live)
}

#[cfg(test)]
mod ranking_tests;
