//! Bounded JSON over an exact canonical discussion page or immutable receipt.

use fgit_authority::TerminalOutcome;
use fgit_forge::event::pull_request_comment::{
    PullRequestAppendCommentCommand, PullRequestCommentCommand, SOURCE_COMMENT_PROFILE,
    SourceCommentAnchor,
};
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryAuthorityHeadId, TxId};

use super::super::super::Status;
use super::super::super::issues::{ApiError, quote, render_body};
use super::Request;
use crate::{OneNode, PullRequestCommentsPage};

pub(super) const MAX_REPLY_BYTES: usize = 1024 * 1024;

fn binding(node: &OneNode) -> String {
    format!(
        concat!(
            "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"repository_incarnation\":{},\"object_format\":{}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
    )
}

fn token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    let hex = id
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("alg:{}:{hex}", id.algorithm().code_point())
}

fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn append(out: &mut String, value: &str, maximum: usize) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(value.len())
        .is_none_or(|length| length > maximum)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(value.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(value);
    Ok(())
}

pub(super) fn page(
    node: &OneNode,
    request: &Request<'_>,
    result: Option<&PullRequestCommentsPage>,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    page_with_binding(&binding(node), request, result, maximum, live)
}

fn page_with_binding(
    scope: &str,
    request: &Request<'_>,
    result: Option<&PullRequestCommentsPage>,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    if let Some(page) = result {
        if page.number != request.number
            || request
                .page
                .expected_head
                .is_some_and(|head| head != page.source_head)
        {
            return Err(ApiError::unavailable());
        }
        page.validate_window(request.page.after, request.page.limit)
            .map_err(|_| ApiError::unavailable())?;
    }
    if !live() {
        return Err(ApiError::from_status(Status::Timeout, false));
    }
    let next = result.and_then(|page| page.next_after);
    let (head, snapshot, version) = result.map_or_else(
        || ("null".into(), "null".into(), "null".into()),
        |page| {
            (
                quote(&page.source_head.to_string()),
                quote(&token(page.source_head)),
                page.discussion_version
                    .map_or(0, |version| version.get())
                    .to_string(),
            )
        },
    );
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"pull_request_comments\",{},\"number\":{},\"found\":{},",
                "\"source_head\":{},\"snapshot_token\":{},\"discussion_version\":{},",
                "\"after\":{},\"limit\":{},\"next_after\":{},\"complete\":{},",
                "\"merge_permission\":null,\"transaction_created\":false,\"comments\":["
            ),
            scope,
            request.number.get(),
            result.is_some(),
            head,
            snapshot,
            version,
            request.page.after,
            request.page.limit,
            optional(next),
            next.is_none(),
        ),
        maximum,
    )?;
    if let Some(page) = result {
        for (index, row) in page.comments.iter().enumerate() {
            if !live() {
                return Err(ApiError::from_status(Status::Timeout, false));
            }
            if index != 0 {
                append(&mut out, ",", maximum)?;
            }
            let rendered = request.page.render.map_or_else(String::new, |rendering| {
                format!(",\"body_rendered\":{}", render_body(&row.body, rendering))
            });
            let anchor = match (&row.anchor, row.anchor_status) {
                (None, None) => String::new(),
                (Some(anchor), Some(status)) => format!(
                    ",\"anchor\":{},\"anchor_status\":{}",
                    anchor_json(anchor),
                    quote(status.as_str()),
                ),
                _ => return Err(ApiError::unavailable()),
            };
            append(
                &mut out,
                &format!(
                    "{{\"version\":{},\"actor\":{},\"body\":{}{}{}}}",
                    row.version.get(),
                    quote(&row.actor.to_string()),
                    quote(&row.body),
                    rendered,
                    anchor,
                ),
                maximum,
            )?;
        }
    }
    if !live() {
        return Err(ApiError::from_status(Status::Timeout, false));
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

pub(super) fn publication(
    node: &OneNode,
    principal: PrincipalId,
    command: &PullRequestCommentCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> Result<String, ApiError> {
    let expected = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    publication_fields(
        node,
        principal,
        Publication {
            number: command.number,
            expected: Some(expected),
            anchor: command.anchor.as_ref(),
        },
        tx,
        terminal,
    )
}

pub(super) fn append_publication(
    node: &OneNode,
    principal: PrincipalId,
    command: &PullRequestAppendCommentCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> Result<String, ApiError> {
    publication_fields(
        node,
        principal,
        Publication {
            number: command.number,
            expected: None,
            anchor: command.anchor.as_ref(),
        },
        tx,
        terminal,
    )
}

struct Publication<'a> {
    number: PullRequestNumber,
    expected: Option<u64>,
    anchor: Option<&'a SourceCommentAnchor>,
}

fn publication_fields(
    node: &OneNode,
    principal: PrincipalId,
    command: Publication<'_>,
    tx: TxId,
    terminal: TerminalOutcome,
) -> Result<String, ApiError> {
    let (outcome, version, rcr, refusal, code, code_point) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            match command.expected {
                Some(expected) => expected
                    .checked_add(1)
                    .ok_or_else(ApiError::unknown)?
                    .to_string(),
                None => "null".to_owned(),
            },
            quote(&repository_commit_id.to_string()),
            "null".to_owned(),
            "null".to_owned(),
            "null".to_owned(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            "null".to_owned(),
            "null".to_owned(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            code.code_point().to_string(),
        ),
    };
    Ok(format!(
        concat!(
            "{{\"type\":\"pull_request_comment_publication\",{},\"principal_id\":{},",
            "\"number\":{},\"action\":{},\"expected_version\":{},\"comment_version\":{},",
            "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"refusal_code_point\":{},",
            "\"refs_changed\":false,\"delivery_acknowledged\":null{}}}"
        ),
        binding(node),
        quote(&principal.to_string()),
        command.number.get(),
        quote(if command.expected.is_some() {
            "comment"
        } else {
            "append-comment"
        }),
        optional(command.expected),
        version,
        quote(&tx.to_string()),
        quote(outcome),
        terminal.decision_sequence.get(),
        rcr,
        refusal,
        code,
        code_point,
        command.anchor.map_or_else(String::new, |anchor| {
            format!(",\"anchor\":{}", anchor_json(anchor))
        }),
    ))
}

fn anchor_json(anchor: &SourceCommentAnchor) -> String {
    use fgit_crypto::lowercase_hex;
    format!(
        concat!(
            "{{\"profile\":{},\"pull_request_version\":{},\"source_ref_hex\":{},",
            "\"target_ref_hex\":{},\"source_tip\":{},\"target_tip\":{},\"compared_base\":{},",
            "\"comparison\":{},\"path_hex\":{},\"side\":{},\"blob\":{},\"mode\":{},",
            "\"byte_start\":{},\"byte_end\":{},\"line_start\":{},\"line_count\":{}}}"
        ),
        quote(SOURCE_COMMENT_PROFILE),
        anchor.pull_request_version.get(),
        quote(&lowercase_hex(anchor.source_ref.as_bytes())),
        quote(&lowercase_hex(anchor.target_ref.as_bytes())),
        quote(&anchor.source_tip.to_string()),
        quote(&anchor.target_tip.to_string()),
        quote(&anchor.compared_base.to_string()),
        quote(anchor.comparison.as_str()),
        quote(&lowercase_hex(&anchor.path)),
        quote(anchor.side.as_str()),
        quote(&anchor.blob.to_string()),
        quote(&format!("{:o}", anchor.mode)),
        anchor.byte_start,
        anchor.byte_end,
        anchor.line_start,
        anchor.line_count,
    )
}

#[cfg(test)]
mod tests;
