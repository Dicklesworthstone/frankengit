//! Bounded JSON, explicit historical outcomes and checked snapshot pagination.
use fgit_authority::TerminalOutcome;
use fgit_forge::{AggregateId, ForgeEvent, ForgeEventPayload};
use fgit_forge::event::issue::{IssueAction, IssueSnapshot, IssueState};
use fgit_types::{DecisionOutcome, RepositoryAuthorityHeadId, TxId};
use crate::publication_support::quote;
use super::options::{Mutation, Options, ReadOptions, expected_version, head_token};
const MAX_REPLY_BYTES: usize = 48 * 1024 * 1024;
fn labels(values: &[String]) -> String { format!("[{}]", values.iter().map(|value| quote(value)).collect::<Vec<_>>().join(",")) }
fn action(value: &IssueAction) -> String {
    match value {
        IssueAction::Open { title, body, labels: values } => format!("{{\"name\":\"open\",\"title\":{},\"body\":{},\"labels\":{}}}", quote(title), quote(body), labels(values)),
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
pub(super) fn mutation(options: &Options, mutation: &Mutation, tx: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>) -> String {
    let (outcome, committed, rcr, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed", true, quote(&repository_commit_id.to_string()), "null".to_owned(), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } => ("refused", false, "null".to_owned(), quote(&refusal_record_id.to_string()), quote(&format!("{code:?}"))),
    };
    format!(concat!("{{\"type\":\"issue_publication\",\"schema_version\":1,\"outcome\":{},",
        "\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
        "\"refusal_record_id\":{},\"refusal_code\":{},\"tenant_id\":{},\"repository_id\":{},",
        "\"principal_id\":{},\"object_format\":{},\"number\":{},\"expected_version\":{},\"action\":{},",
        "\"refs_changed\":false,\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"),
        quote(outcome), committed, quote(&tx.to_string()), terminal.decision_sequence.get(), rcr, refusal, code,
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(&mutation.principal.to_string()), quote(options.format.as_str()),
        mutation.command.number.get(), expected_version(&mutation.command), action(&mutation.command.action),
        cleanup.is_none(), cleanup.map_or_else(|| "null".to_owned(), quote))
}
fn snapshot(value: &IssueSnapshot) -> Result<String, String> {
    IssueAction::Open { title: value.title.clone(), body: value.body.clone(), labels: value.labels.clone() }
        .validate().map_err(|_| "invalid issue snapshot metadata")?;
    if value.comments >= value.version.get() { return Err("invalid issue comment count".to_owned()); }
    Ok(format!(concat!("{{\"number\":{},\"version\":{},\"title\":{},\"body\":{},\"labels\":{},",
        "\"state\":{},\"opened_by\":{},\"last_actor\":{},\"comments\":{}}}"),
        value.number.get(), value.version.get(), quote(&value.title), quote(&value.body), labels(&value.labels),
        quote(match value.state { IssueState::Open => "open", IssueState::Closed => "closed" }),
        quote(&value.opened_by.to_string()), quote(&value.last_actor.to_string()), value.comments))
}
fn header(options: &Options, read: &ReadOptions, head: RepositoryAuthorityHeadId) -> Result<String, String> {
    if read.expected_head.is_some_and(|expected| expected != head) { return Err("issue response moved from the pinned snapshot".to_owned()); }
    Ok(format!(concat!("\"schema_version\":1,\"scope\":\"repository_issues\",\"tenant_id\":{},",
        "\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"node_closed\":true"),
        quote(&options.tenant.to_string()), quote(&options.repository.to_string()), quote(options.format.as_str()),
        quote(&head.to_string()), quote(&head_token(head))))
}
fn append(out: &mut String, value: &str, comma: bool) -> Result<(), String> {
    if out.len().saturating_add(value.len()).saturating_add(3) > MAX_REPLY_BYTES { return Err("issue response exceeds output ceiling; use a smaller page".to_owned()); }
    out.try_reserve(value.len() + 1).map_err(|_| "issue response allocation refused")?;
    if comma { out.push(','); }
    out.push_str(value); Ok(())
}
pub(super) fn list(options: &Options, read: &ReadOptions, head: RepositoryAuthorityHeadId,
    rows: &[IssueSnapshot], next: Option<u64>) -> Result<(String, u8), String> {
    if read.number.is_some() || rows.len() > usize::from(read.limit)
        || rows.iter().any(|row| row.number.get() <= read.after)
        || rows.windows(2).any(|pair| pair[0].number >= pair[1].number)
        || next.is_some_and(|n| rows.len() != usize::from(read.limit) || rows.last().map(|row| row.number.get()) != Some(n))
    { return Err("issue list violates its pagination contract".to_owned()); }
    let header = header(options, read, head)?;
    let mut out = format!("{{\"type\":\"issue_page\",{header},\"after\":{},\"limit\":{},\"count\":{},\"has_more\":{},\"next_after\":{},\"issues\":[",
        read.after, read.limit, rows.len(), next.is_some(), next.map_or_else(|| "null".to_owned(), |n| n.to_string()));
    for (index, row) in rows.iter().enumerate() { append(&mut out, &snapshot(row)?, index != 0)?; }
    out.push_str("]}"); Ok((out, 0))
}
pub(super) fn history(options: &Options, read: &ReadOptions, head: RepositoryAuthorityHeadId,
    issue: Option<&IssueSnapshot>, events: &[ForgeEvent], next: Option<u64>) -> Result<(String, u8), String> {
    let number = read.number.ok_or("issue show requires a number")?;
    let header = header(options, read, head)?;
    if events.len() > usize::from(read.limit) || issue.is_some_and(|issue| issue.number != number)
        || (issue.is_none() && (!events.is_empty() || next.is_some()))
    { return Err("issue history violates its aggregate binding".to_owned()); }
    if let Some(issue) = issue {
        let remaining = issue.version.get().saturating_sub(read.after);
        let expected_count = remaining.min(u64::from(read.limit));
        if events.len() as u64 != expected_count { return Err("issue history is incomplete for its pinned range".to_owned()); }
        let expected_next = if remaining > u64::from(read.limit) { read.after.checked_add(expected_count) } else { None };
        if next != expected_next { return Err("issue history cursor does not match its pinned range".to_owned()); }
    }
    let mut out = format!("{{\"type\":\"issue_history\",{header},\"requested_number\":{},\"found\":{},\"issue\":{},\"after_version\":{},\"limit\":{},\"has_more\":{},\"next_after_version\":{},\"events\":[",
        number.get(), issue.is_some(), issue.map(snapshot).transpose()?.unwrap_or_else(|| "null".to_owned()),
        read.after, read.limit, next.is_some(), next.map_or_else(|| "null".to_owned(), |n| n.to_string()));
    for (index, event) in events.iter().enumerate() {
        if event.aggregate != AggregateId::Issue(number)
            || read.after.checked_add(index as u64).and_then(|n| n.checked_add(1)) != Some(event.version.get())
        { return Err("issue history events are not the requested contiguous versions".to_owned()); }
        let ForgeEventPayload::IssueChangedNative(change) = &event.payload else { return Err("unexpected issue event payload".to_owned()); };
        change.action.validate().map_err(|_| "invalid issue history action")?;
        let row = format!("{{\"number\":{},\"version\":{},\"actor\":{},\"action\":{}}}",
            number.get(), event.version.get(), quote(&change.actor.to_string()), action(&change.action));
        append(&mut out, &row, index != 0)?;
    }
    out.push_str("]}"); Ok((out, if issue.is_some() { 0 } else { 4 }))
}
