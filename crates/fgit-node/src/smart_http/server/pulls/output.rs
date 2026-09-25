//! Native PR JSON is data, not HTML. Build and check the entire bounded reply
//! before emitting success; never turn a truncated page into a complete one.

use fgit_admission::merge::native::pull_request::{PullRequestPage, PullRequestView};
use fgit_authority::TerminalOutcome;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::{AggregateId, ExpectedVersion, ForgeEventPayload, PullRequestNumber};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryAuthorityHeadId, TxId};

use super::super::issues::{ApiError, Page, quote, ref_fields};
use crate::OneNode;

pub(super) const MAX_REPLY_BYTES: usize = 48 * 1024 * 1024;

pub(super) const fn action(value: PullRequestAction) -> &'static str {
    match value {
        PullRequestAction::Open => "open",
        PullRequestAction::Update => "update",
        PullRequestAction::Close => "close",
        PullRequestAction::Reopen => "reopen",
    }
}
fn data(value: &PullRequestData) -> Result<String, ApiError> {
    value.validate().map_err(|_| ApiError::unavailable())?;
    Ok(format!(
        concat!(
            "{{{},{},\"object_format\":{},",
            "\"source_tip\":{},\"target_tip\":{},\"title\":{},\"body\":{}}}"
        ),
        ref_fields("source_ref", &value.source_ref),
        ref_fields("target_ref", &value.target_ref),
        quote(value.source_tip.algorithm().as_str()),
        quote(&value.source_tip.to_string()),
        quote(&value.target_tip.to_string()),
        quote(&value.title),
        quote(&value.body)
    ))
}
fn view(value: &PullRequestView) -> Result<String, ApiError> {
    if value.event.aggregate != AggregateId::PullRequest(value.number) {
        return Err(ApiError::unavailable());
    }
    let (state, merge) = match &value.event.payload {
        ForgeEventPayload::PullRequestChangedNative(change) => {
            if value.data.as_ref() != Some(&change.data) {
                return Err(ApiError::unavailable());
            }
            (
                if change.action == PullRequestAction::Close {
                    "closed"
                } else {
                    "open"
                },
                "null".to_owned(),
            )
        }
        ForgeEventPayload::MergeCommittedNative(merge) => {
            merge.validate().map_err(|_| ApiError::unavailable())?;
            if value
                .data
                .as_ref()
                .is_some_and(|data| !data.matches_merge(merge))
            {
                return Err(ApiError::unavailable());
            }
            (
                "merged",
                format!(
                    concat!(
                        "{{\"object_format\":{},{},{},",
                        "\"source_tip\":{},\"target_tip_before\":{},\"base_tip\":{},\"merge_commit\":{}}}"
                    ),
                    quote(merge.merge_commit.algorithm().as_str()),
                    ref_fields("source_ref", &merge.source_ref),
                    ref_fields("target_ref", &merge.target_ref),
                    quote(&merge.source_tip.to_string()),
                    quote(&merge.target_tip_before.to_string()),
                    quote(&merge.base_tip.to_string()),
                    quote(&merge.merge_commit.to_string())
                ),
            )
        }
        _ => return Err(ApiError::unavailable()),
    };
    Ok(format!(
        concat!(
            "{{\"number\":{},\"version\":{},\"state\":{},\"data\":{},",
            "\"opened_by\":{},\"last_metadata_actor\":{},\"merge_only\":{},\"merge\":{}}}"
        ),
        value.number.get(),
        value.event.version.get(),
        quote(state),
        value
            .data
            .as_ref()
            .map(data)
            .transpose()?
            .unwrap_or_else(|| "null".to_owned()),
        value
            .opened_by
            .map_or_else(|| "null".to_owned(), |id| quote(&id.to_string())),
        value
            .last_metadata_actor
            .map_or_else(|| "null".to_owned(), |id| quote(&id.to_string())),
        value.data.is_none(),
        merge
    ))
}
fn header(
    node: &OneNode,
    head: RepositoryAuthorityHeadId,
    expected: Option<RepositoryAuthorityHeadId>,
) -> Result<String, ApiError> {
    if expected.is_some_and(|expected| expected != head) {
        return Err(ApiError::snapshot_moved());
    }
    let id = head.as_internal_object_id();
    let digest = id
        .digest()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let token = format!("alg:{}:{digest}", id.algorithm().code_point());
    Ok(format!(
        concat!(
            "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"repository_incarnation\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&head.to_string()),
        quote(&token)
    ))
}
fn append(out: &mut String, part: &str, maximum: usize) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(part.len())
        .is_none_or(|size| size > maximum)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(part.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(part);
    Ok(())
}
fn validate_page(page: Page, result: &PullRequestPage) -> Result<(), ApiError> {
    let rows = &result.pull_requests;
    if rows.len() > usize::from(page.limit)
        || rows.iter().any(|row| row.number.get() <= page.after)
        || rows.windows(2).any(|rows| rows[0].number >= rows[1].number)
        || result.next_after.is_some_and(|next| {
            rows.len() != usize::from(page.limit)
                || rows.last().map(|row| row.number.get()) != Some(next)
        })
    {
        return Err(ApiError::unavailable());
    }
    Ok(())
}

pub(super) fn list(
    node: &OneNode,
    page: Page,
    result: &PullRequestPage,
    maximum: usize,
) -> Result<String, ApiError> {
    validate_page(page, result)?;
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"type\":\"pull_request_page\",{},\"after\":{},\"limit\":{},\"next_after\":{},\"pull_requests\":[",
            header(node, result.source_head, page.expected_head)?,
            page.after,
            page.limit,
            result
                .next_after
                .map_or_else(|| "null".to_owned(), |number| number.to_string())
        ),
        maximum,
    )?;
    for (index, row) in result.pull_requests.iter().enumerate() {
        if index != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(&mut out, &view(row)?, maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

pub(super) fn show(
    node: &OneNode,
    number: PullRequestNumber,
    expected: Option<RepositoryAuthorityHeadId>,
    result: &PullRequestPage,
    maximum: usize,
) -> Result<(bool, String), ApiError> {
    validate_page(
        Page {
            after: number.get() - 1,
            limit: 1,
            expected_head: expected,
            render: false,
        },
        result,
    )?;
    // The bounded reader may return the next visible number. Never disclose
    // that row in a lookup of a missing/hidden number, or pretend it is a match.
    let row = result
        .pull_requests
        .first()
        .filter(|row| row.number == number);
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"type\":\"pull_request\",{},\"number\":{},\"found\":{},\"pull_request\":{} }}",
            header(node, result.source_head, expected)?,
            number.get(),
            row.is_some(),
            row.map(view)
                .transpose()?
                .unwrap_or_else(|| "null".to_owned())
        ),
        maximum,
    )?;
    Ok((row.is_some(), out))
}

pub(super) fn mutation(
    node: &OneNode,
    principal: PrincipalId,
    command: &PullRequestCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
    let (outcome, commit, refusal, code, code_point) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
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
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
            code.code_point().to_string(),
        ),
    };
    let expected = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    format!(
        concat!(
            "{{\"type\":\"pull_request_publication\",\"schema_version\":1,\"tenant_id\":{},",
            "\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{},\"principal_id\":{},",
            "\"number\":{},\"expected_version\":{},\"action\":{},\"tx_id\":{},\"outcome\":{},",
            "\"decision_sequence\":{},\"repository_commit_id\":{},\"refusal_record_id\":{},",
            "\"refusal_code\":{},\"refusal_code_point\":{},\"delivery_acknowledged\":null}}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
        quote(&principal.to_string()),
        command.number.get(),
        expected,
        quote(action(command.action)),
        quote(&tx.to_string()),
        quote(outcome),
        terminal.decision_sequence.get(),
        commit,
        refusal,
        code,
        code_point
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{GitHashAlgorithm, GitOid, RefName};

    #[test]
    fn snapshots_preserve_untrusted_text_without_inventing_lifecycle_state() {
        let format = GitHashAlgorithm::Sha1;
        let actor = PrincipalId::from_bytes([7; 16]);
        let command = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
                target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
                source_tip: GitOid::from_hex(format, &"a".repeat(40)).unwrap(),
                target_tip: GitOid::from_hex(format, &"b".repeat(40)).unwrap(),
                title: "Untrusted <script>".into(),
                body: "é\n\"\\\u{202e}".into(),
            },
        };
        let mut row = PullRequestView {
            number: command.number,
            event: command.proposed_event(actor, format).unwrap(),
            data: Some(command.data.clone()),
            opened_by: Some(actor),
            last_metadata_actor: Some(actor),
        };
        let encoded = view(&row).unwrap();
        assert!(encoded.contains("\"state\":\"open\""));
        assert!(encoded.contains("\"merge_only\":false,\"merge\":null"));
        assert!(encoded.contains("\\u000a\\\"\\\\\\u202e"));
        row.data = None;
        assert!(
            view(&row).is_err(),
            "metadata events cannot lose their matching content"
        );
    }
    #[test]
    fn native_reference_identity_survives_non_utf8_and_text_stays_compatible() {
        let mut value = PullRequestData {
            source_ref: RefName::try_new(b"refs/heads/topic\xff").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"a".repeat(40)).unwrap(),
            target_tip: GitOid::from_hex(GitHashAlgorithm::Sha1, &"b".repeat(40)).unwrap(),
            title: "Native refs".into(),
            body: String::new(),
        };
        let encoded = data(&value).unwrap();
        assert!(encoded.contains(
            "\"source_ref\":null,\"source_ref_hex\":\"726566732f68656164732f746f706963ff\""
        ));
        assert!(encoded.contains("\"target_ref\":\"refs/heads/main\",\"target_ref_hex\":\"726566732f68656164732f6d61696e\""));
        value.source_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        let encoded = data(&value).unwrap();
        assert!(encoded.contains("\"source_ref\":\"refs/heads/topic\",\"source_ref_hex\":\"726566732f68656164732f746f706963\""));
    }
    #[test]
    fn reply_limit_never_leaves_a_partially_appended_record() {
        let mut out = String::from("abc");
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        append(&mut out, "d", 4).unwrap();
        assert_eq!(out, "abcd");
    }
}
