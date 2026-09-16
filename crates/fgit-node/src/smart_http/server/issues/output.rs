//! Complete bounded JSON replies, prepared before the first HTTP success byte.

use fgit_admission::merge::native::issues::{IssueHistoryPage, IssuePage};
use fgit_authority::TerminalOutcome;
use fgit_forge::event::issue::{IssueAction, IssueCommand, IssueSnapshot, IssueState};
use fgit_forge::{AggregateId, ForgeEventPayload, IssueNumber};
use fgit_types::{DecisionOutcome, PrincipalId, RepositoryAuthorityHeadId, TxId};

use crate::OneNode;
use super::{ApiError, request::Page};

pub(super) const MAX_REPLY_BYTES: usize = 48 * 1024 * 1024;

pub(super) fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}'
                | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn labels(values: &[String]) -> String {
    format!("[{}]", values.iter().map(|value| quote(value)).collect::<Vec<_>>().join(","))
}
fn action(value: &IssueAction) -> String {
    match value {
        IssueAction::Open { title, body, labels: values } => format!(
            "{{\"name\":\"open\",\"title\":{},\"body\":{},\"labels\":{}}}", quote(title), quote(body), labels(values)),
        IssueAction::Edit(edit) => {
            let mut fields = vec!["\"name\":\"edit\"".to_owned()];
            if let Some(title) = &edit.title { fields.push(format!("\"title\":{}", quote(title))); }
            if let Some(body) = &edit.body { fields.push(format!("\"body\":{}", quote(body))); }
            if let Some(values) = &edit.labels { fields.push(format!("\"labels\":{}", labels(values))); }
            format!("{{{}}}", fields.join(","))
        }
        IssueAction::Comment { body } => format!("{{\"name\":\"comment\",\"body\":{}}}", quote(body)),
        IssueAction::Close => "{\"name\":\"close\"}".to_owned(),
        IssueAction::Reopen => "{\"name\":\"reopen\"}".to_owned(),
    }
}

pub(super) fn mutation(node: &OneNode, principal: PrincipalId, command: &IssueCommand,
    tx: TxId, terminal: TerminalOutcome,
) -> String {
    let (outcome, rcr, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } =>
            ("committed", quote(&repository_commit_id.to_string()), "null".to_owned(), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } =>
            ("refused", "null".to_owned(), quote(&refusal_record_id.to_string()), quote(&format!("{code:?}"))),
    };
    let expected = match command.expected_version {
        fgit_forge::ExpectedVersion::NewStream => 0,
        fgit_forge::ExpectedVersion::Exactly(version) => version.get(),
    };
    format!(concat!(
        "{{\"type\":\"issue_publication\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"principal_id\":{},\"number\":{},\"expected_version\":{},\"action\":{},",
        "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
        "\"refusal_record_id\":{},\"refusal_code\":{},\"delivery_acknowledged\":null}}"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()), quote(&principal.to_string()),
        command.number.get(), expected, quote(command.action.name()), quote(&tx.to_string()), quote(outcome),
        terminal.decision_sequence.get(), rcr, refusal, code)
}

fn snapshot(value: &IssueSnapshot) -> Result<String, ApiError> {
    IssueAction::Open { title: value.title.clone(), body: value.body.clone(), labels: value.labels.clone() }
        .validate().map_err(|_| ApiError::unavailable())?;
    if value.comments >= value.version.get() { return Err(ApiError::unavailable()); }
    Ok(format!(concat!(
        "{{\"number\":{},\"version\":{},\"title\":{},\"body\":{},\"labels\":{},",
        "\"state\":{},\"opened_by\":{},\"last_actor\":{},\"comments\":{}}}"),
        value.number.get(), value.version.get(), quote(&value.title), quote(&value.body), labels(&value.labels),
        quote(match value.state { IssueState::Open => "open", IssueState::Closed => "closed" }),
        quote(&value.opened_by.to_string()), quote(&value.last_actor.to_string()), value.comments))
}
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    let digest = id.digest().as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("alg:{}:{digest}", id.algorithm().code_point())
}
fn header(node: &OneNode, page: Page, head: RepositoryAuthorityHeadId) -> Result<String, ApiError> {
    if page.expected_head.is_some_and(|expected| expected != head) { return Err(ApiError::snapshot_moved()); }
    Ok(format!(concat!(
        "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"object_format\":{},",
        "\"source_head\":{},\"snapshot_token\":{}"), quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()), quote(node.object_format.as_str()), quote(&head.to_string()), quote(&head_token(head))))
}
fn append(out: &mut String, value: &str, maximum: usize) -> Result<(), ApiError> {
    if out.len().checked_add(value.len()).is_none_or(|n| n > maximum) { return Err(ApiError::too_large()); }
    out.try_reserve_exact(value.len()).map_err(|_| ApiError::unavailable())?;
    out.push_str(value);
    Ok(())
}
fn optional(value: Option<u64>) -> String { value.map_or_else(|| "null".to_owned(), |n| n.to_string()) }

pub(super) fn list(node: &OneNode, page: Page, result: &IssuePage, maximum: usize) -> Result<String, ApiError> {
    let rows = &result.issues;
    if rows.len() > usize::from(page.limit)
        || rows.iter().any(|row| row.number.get() <= page.after)
        || rows.windows(2).any(|pair| pair[0].number >= pair[1].number)
        || result.next_after.is_some_and(|next| rows.len() != usize::from(page.limit)
            || rows.last().map(|row| row.number.get()) != Some(next))
    { return Err(ApiError::unavailable()); }
    let mut out = String::new();
    append(&mut out, &format!(
        "{{\"type\":\"issue_page\",{},\"after\":{},\"limit\":{},\"next_after\":{},\"issues\":[",
        header(node, page, result.source_head)?, page.after, page.limit, optional(result.next_after)), maximum)?;
    for (index, row) in rows.iter().enumerate() {
        if index != 0 { append(&mut out, ",", maximum)?; }
        append(&mut out, &snapshot(row)?, maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

pub(super) fn history(node: &OneNode, number: IssueNumber, page: Page,
    result: &IssueHistoryPage, maximum: usize,
) -> Result<String, ApiError> {
    if result.events.len() > usize::from(page.limit)
        || result.issue.as_ref().is_some_and(|issue| issue.number != number)
        || (result.issue.is_none() && (!result.events.is_empty() || result.next_after.is_some()))
    { return Err(ApiError::unavailable()); }
    if let Some(issue) = &result.issue {
        let remaining = issue.version.get().saturating_sub(page.after);
        let count = remaining.min(u64::from(page.limit));
        let next = if remaining > count { page.after.checked_add(count) } else { None };
        if result.events.len() as u64 != count || result.next_after != next { return Err(ApiError::unavailable()); }
    }
    let mut out = String::new();
    append(&mut out, &format!(
        "{{\"type\":\"issue_history\",{},\"found\":{},\"issue\":{},\"after_version\":{},\"limit\":{},\"next_after_version\":{},\"events\":[",
        header(node, page, result.source_head)?, result.issue.is_some(),
        result.issue.as_ref().map(snapshot).transpose()?.unwrap_or_else(|| "null".to_owned()),
        page.after, page.limit, optional(result.next_after)), maximum)?;
    for (index, event) in result.events.iter().enumerate() {
        if event.aggregate != AggregateId::Issue(number)
            || page.after.checked_add(index as u64).and_then(|n| n.checked_add(1)) != Some(event.version.get())
        { return Err(ApiError::unavailable()); }
        let ForgeEventPayload::IssueChangedNative(change) = &event.payload else { return Err(ApiError::unavailable()); };
        change.action.validate().map_err(|_| ApiError::unavailable())?;
        if index != 0 { append(&mut out, ",", maximum)?; }
        append(&mut out, &format!("{{\"version\":{},\"actor\":{},\"action\":{}}}",
            event.version.get(), quote(&change.actor.to_string()), action(&change.action)), maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn json_preserves_unicode_and_escapes_controls_and_directional_text() {
        assert_eq!(quote("é 🦀\n\"\\\u{202e}"), "\"é 🦀\\u000a\\\"\\\\\\u202e\"");
        assert_eq!(quote("literal \\u202e"), "\"literal \\\\u202e\"");
    }
    #[test]
    fn output_ceiling_refuses_before_retaining_an_oversized_fragment() {
        let mut out = String::from("123");
        assert!(append(&mut out, "45", 4).is_err());
        assert_eq!(out, "123");
        append(&mut out, "4", 4).unwrap();
        assert_eq!(out, "1234");
    }
}
