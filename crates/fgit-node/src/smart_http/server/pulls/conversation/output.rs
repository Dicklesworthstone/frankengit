//! Bounded JSON over an exact canonical discussion page or immutable receipt.

use fgit_authority::TerminalOutcome;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::pull_request_comment::PullRequestCommentCommand;
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
            append(
                &mut out,
                &format!(
                    "{{\"version\":{},\"actor\":{},\"body\":{}{}}}",
                    row.version.get(),
                    quote(&row.actor.to_string()),
                    quote(&row.body),
                    rendered,
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
    let (outcome, version, rcr, refusal, code, code_point) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            expected
                .checked_add(1)
                .ok_or_else(ApiError::unknown)?
                .to_string(),
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
            "\"number\":{},\"action\":\"comment\",\"expected_version\":{},\"comment_version\":{},",
            "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"refusal_code_point\":{},",
            "\"refs_changed\":false,\"delivery_acknowledged\":null}}"
        ),
        binding(node),
        quote(&principal.to_string()),
        command.number.get(),
        expected,
        version,
        quote(&tx.to_string()),
        quote(outcome),
        terminal.decision_sequence.get(),
        rcr,
        refusal,
        code,
        code_point,
    ))
}

#[cfg(test)]
mod tests;
