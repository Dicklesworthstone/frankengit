//! Label snapshots and receipts retain their own version and authenticated
//! actor. A retry never reads current labels to manufacture its old receipt.

use fgit_admission::merge::native::pull_request::{PullRequestPage, PullRequestView};
use fgit_authority::TerminalOutcome;
use fgit_forge::ExpectedVersion;
use fgit_forge::event::pull_request_labels::{PullRequestLabelsCommand, validate_labels};
use fgit_types::{DecisionOutcome, PrincipalId, TxId};

use super::super::super::issues::{ApiError, Page, quote};
use super::Request;
use crate::OneNode;

pub(super) const MAX_REPLY_BYTES: usize = 32 * 1024;

pub(in crate::smart_http::server::pulls) fn array(labels: &[String]) -> String {
    format!(
        "[{}]",
        labels
            .iter()
            .map(|label| quote(label))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub(in crate::smart_http::server::pulls) fn fields(
    row: &PullRequestView,
) -> Result<String, ApiError> {
    validate_labels(&row.labels).map_err(|_| ApiError::unavailable())?;
    if row.labels_version.is_some() != row.labels_actor.is_some()
        || row.labels_version.is_none() && !row.labels.is_empty()
        || row.data.is_none() && row.labels_version.is_some()
    {
        return Err(ApiError::unavailable());
    }
    Ok(format!(
        "\"labels\":{},\"labels_version\":{},\"labels_actor\":{}",
        array(&row.labels),
        row.labels_version.map_or(0, |version| version.get()),
        row.labels_actor
            .map_or_else(|| "null".into(), |actor| quote(&actor.to_string())),
    ))
}

pub(super) fn read(
    node: &OneNode,
    request: &Request<'_>,
    result: &PullRequestPage,
    maximum: usize,
) -> Result<(bool, String), ApiError> {
    super::super::output::validate_page(
        Page {
            after: request.number.get() - 1,
            limit: 1,
            expected_head: request.expected_head,
            render: None,
        },
        result,
    )?;
    // A subsequent visible number is not evidence about the requested PR.
    // Legacy/merge-only records have no native metadata to label.
    let row = result
        .pull_requests
        .first()
        .filter(|row| row.number == request.number && row.data.is_some());
    let labels = row
        .map(fields)
        .transpose()?
        .unwrap_or_else(|| "\"labels\":null,\"labels_version\":null,\"labels_actor\":null".into());
    let body = format!(
        concat!(
            "{{\"type\":\"pull_request_labels\",{},\"number\":{},\"found\":{},",
            "\"pull_request_version\":{},{},\"read_only\":true,\"transaction_created\":false}}"
        ),
        super::super::output::header(node, result.source_head, request.expected_head)?,
        request.number.get(),
        row.is_some(),
        row.map_or_else(|| "null".into(), |row| row.event.version.get().to_string()),
        labels,
    );
    if body.len() > maximum {
        return Err(ApiError::too_large());
    }
    Ok((row.is_some(), body))
}

pub(super) fn publication(
    node: &OneNode,
    principal: PrincipalId,
    command: &PullRequestLabelsCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> Result<String, ApiError> {
    let binding = format!(
        concat!(
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},",
            "\"object_format\":{},\"principal_id\":{}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&principal.to_string()),
    );
    publication_with_binding(&binding, command, tx, terminal)
}

fn publication_with_binding(
    binding: &str,
    command: &PullRequestLabelsCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> Result<String, ApiError> {
    validate_labels(&command.labels).map_err(|_| ApiError::unknown())?;
    let expected = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    let (outcome, version, commit, refusal, code, code_point) = match terminal.outcome {
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
            "{{\"type\":\"pull_request_labels_publication\",\"schema_version\":1,{},",
            "\"number\":{},\"action\":\"set-labels\",\"expected_version\":{},",
            "\"labels\":{},\"labels_version\":{},\"tx_id\":{},\"outcome\":{},",
            "\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_record_id\":{},",
            "\"refusal_code\":{},\"refusal_code_point\":{},\"refs_changed\":false,",
            "\"pull_request_version_changed\":false,\"delivery_acknowledged\":null}}"
        ),
        binding,
        command.number.get(),
        expected,
        array(&command.labels),
        version,
        quote(&tx.to_string()),
        quote(outcome),
        terminal.decision_sequence.get(),
        commit,
        refusal,
        code,
        code_point,
    ))
}

#[cfg(test)]
mod tests;
