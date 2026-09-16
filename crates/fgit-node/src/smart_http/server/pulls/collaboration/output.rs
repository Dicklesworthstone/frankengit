//! Complete bounded JSON receipts. Review pages never imply merge permission;
//! even a retained Current vote is display evidence, not current CAS authority.

use fgit_admission::merge::native::pull_request::reviews::ReviewPage;
use fgit_authority::TerminalOutcome;
use fgit_forge::{ExpectedVersion, PullRequestNumber};
use fgit_forge::event::review::{ReviewDecision, ReviewFreshness, ReviewSubject};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryAuthorityHeadId, TxId};
use crate::OneNode;
use super::{ApiError, request::{Command, Page}};
use super::super::super::issues::quote;

pub(super) const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;
fn append(out: &mut String, part: &str, maximum: usize) -> Result<(), ApiError> {
    if out.len().checked_add(part.len()).is_none_or(|size| size > maximum) { return Err(ApiError::too_large()); }
    out.try_reserve(part.len()).map_err(|_| ApiError::unavailable())?;
    out.push_str(part);
    Ok(())
}
fn scope(node: &OneNode) -> String {
    format!("\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()))
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    let hex: String = id.digest().as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
    format!("alg:{}:{hex}", id.algorithm().code_point())
}
fn subject(value: &ReviewSubject) -> String {
    format!(concat!("{{\"number\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
        "\"source_ref\":{},\"target_ref\":{},\"source_tip\":{},\"target_tip\":{}}}"),
        value.pull_request.get(), value.pull_request_version.get(), value.policy_epoch.get(),
        quote(value.source_ref.as_str()), quote(value.target_ref.as_str()),
        quote(&value.source_tip.to_string()), quote(&value.target_tip.to_string()))
}
fn decision(value: ReviewDecision) -> &'static str {
    match value { ReviewDecision::Approve => "approve", ReviewDecision::RequestChanges => "request-changes",
        ReviewDecision::Withdraw => "withdraw" }
}
fn freshness(value: ReviewFreshness) -> &'static str {
    match value {
        ReviewFreshness::Current => "current", ReviewFreshness::Withdrawn => "withdrawn",
        ReviewFreshness::PullRequestUnavailable => "pull_request_unavailable",
        ReviewFreshness::PullRequestClosed => "pull_request_closed",
        ReviewFreshness::PullRequestChanged => "pull_request_changed",
        ReviewFreshness::SourceMoved => "source_moved", ReviewFreshness::TargetMoved => "target_moved",
        ReviewFreshness::PolicyChanged => "policy_changed",
    }
}
fn principal(value: Option<PrincipalId>) -> String {
    value.map_or_else(|| "null".into(), |value| quote(&value.to_string()))
}

pub(super) fn page(node: &OneNode, number: PullRequestNumber, requested: Page,
    result: Option<&ReviewPage>, maximum: usize,
) -> Result<String, ApiError> {
    if let Some(result) = result {
        if result.pull_request != number || result.reviews.len() > usize::from(requested.limit)
            || requested.expected_head.is_some_and(|head| head != result.source_head)
            || result.reviews.iter().any(|row| requested.after.is_some_and(|after| row.event.reviewer <= after))
            || result.reviews.windows(2).any(|rows| rows[0].event.reviewer >= rows[1].event.reviewer)
            || result.next_after.is_some_and(|next| result.reviews.len() != usize::from(requested.limit)
                || result.reviews.last().map(|row| row.event.reviewer) != Some(next))
        { return Err(ApiError::unavailable()); }
    }
    let mut out = String::new();
    append(&mut out, &format!(concat!("{{\"type\":\"review_page\",{},\"number\":{},\"found\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
        "\"after\":{},\"limit\":{},\"next_after\":{},\"merge_authorized\":false,\"reviews\":["),
        scope(node), number.get(), result.is_some(),
        result.map_or_else(|| "null".into(), |page| quote(&page.source_head.to_string())),
        result.map_or_else(|| "null".into(), |page| quote(&head_token(page.source_head))),
        result.map_or_else(|| "null".into(), |page| page.pull_request_version.get().to_string()),
        result.map_or_else(|| "null".into(), |page| page.policy_epoch.get().to_string()),
        principal(requested.after), requested.limit, principal(result.and_then(|page| page.next_after))), maximum)?;
    if let Some(page) = result {
        for (index, row) in page.reviews.iter().enumerate() {
            let event = &row.event;
            event.validate().map_err(|_| ApiError::unavailable())?;
            if event.subject.pull_request != number || event.subject.source_tip.algorithm() != node.object_format {
                return Err(ApiError::unavailable());
            }
            let candidate = event.candidate.map_or_else(|| "null".into(), |binding| format!(
                "{{\"merge_base\":{},\"candidate_commit\":{}}}", quote(&binding.merge_base.to_string()), quote(&binding.commit.to_string())));
            append(&mut out, &format!(concat!("{}{{\"reviewer\":{},\"version\":{},\"subject\":{},",
                "\"candidate\":{},\"decision\":{},\"reason\":{},\"freshness\":{},\"reviewer_is_opener\":{}}}"),
                if index == 0 { "" } else { "," }, quote(&event.reviewer.to_string()), row.version.get(),
                subject(&event.subject), candidate, quote(decision(event.decision)), quote(&event.reason),
                quote(freshness(row.freshness)), row.reviewer_is_opener.map_or_else(|| "null".into(), |value| value.to_string())), maximum)?;
        }
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

pub(super) fn mutation(node: &OneNode, actor: PrincipalId, command: &Command,
    tx: TxId, terminal: TerminalOutcome,
) -> String {
    let (family, action, version, submitted, binding, reviewers) = match command {
        Command::Review(command) => ("candidate_review_publication", decision(command.review.decision),
            match command.review.expected_version { ExpectedVersion::NewStream => "0".into(),
                ExpectedVersion::Exactly(version) => version.get().to_string() },
            &command.review.subject, command.candidate, "null".to_owned()),
        Command::Merge { subject, candidate, required } => ("reviewed_merge_publication", "merge", "null".into(),
            subject, *candidate, format!("[{}]", required.reviewers().iter()
                .map(|id| quote(&id.to_string())).collect::<Vec<_>>().join(","))),
    };
    let (outcome, commit, refusal, code, code_point) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed", quote(&repository_commit_id.to_string()),
            "null".to_owned(), "null".to_owned(), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } => ("refused", "null".to_owned(),
            quote(&refusal_record_id.to_string()), quote(&format!("{code:?}")), code.code_point().to_string()),
    };
    format!(concat!("{{\"type\":{}, {},\"principal_id\":{},\"action\":{},\"review_expected_version\":{},",
        "\"subject\":{},\"merge_base\":{},\"candidate_commit\":{},\"required_reviewers\":{},",
        "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
        "\"refusal_record_id\":{},\"refusal_code\":{},\"refusal_code_point\":{},\"delivery_acknowledged\":null}}"),
        quote(family), scope(node), quote(&actor.to_string()), quote(action), version, subject(submitted),
        quote(&binding.merge_base.to_string()), quote(&binding.commit.to_string()), reviewers,
        quote(&tx.to_string()), quote(outcome), terminal.decision_sequence.get(), commit, refusal, code, code_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_ceiling_never_retains_a_truncated_record() {
        let mut out = "abc".to_owned();
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        append(&mut out, "d", 4).unwrap();
        assert_eq!(out, "abcd");
    }
    #[test]
    fn every_review_state_has_an_explicit_non_authorizing_display_label() {
        assert_eq!(freshness(ReviewFreshness::Current), "current");
        assert_eq!(freshness(ReviewFreshness::PolicyChanged), "policy_changed");
        assert_eq!(decision(ReviewDecision::RequestChanges), "request-changes");
        assert_eq!(quote("<script>\n\u{202e}"), "\"<script>\\u000a\\u202e\"");
    }
}
