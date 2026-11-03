//! Canonical publication receipts and bounded, snapshot-bound discussion JSON.
use super::options::{Mutation, Options, ReadOptions, expected_version};
use crate::issues::options::head_token;
use crate::publication_support::quote;
use fgit_authority::TerminalOutcome;
use fgit_forge::event::discussion::DiscussionSnapshot;
use fgit_forge::event::discussion::{DiscussionAction, DiscussionState};
use fgit_forge::{AggregateId, ForgeEvent, ForgeEventPayload};
use fgit_types::{DecisionOutcome, RepositoryAuthorityHeadId, TxId};

const MAX_REPLY_BYTES: usize = 48 * 1024 * 1024;

fn optional_number(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |n| n.to_string())
}

pub(super) fn action(action: &DiscussionAction) -> String {
    match action {
        DiscussionAction::Open { title, body } => format!(
            "{{\"name\":\"open\",\"title\":{},\"body\":{}}}",
            quote(title),
            quote(body)
        ),
        DiscussionAction::Edit(edit) => {
            let mut fields = vec!["\"name\":\"edit\"".to_owned()];
            if let Some(title) = &edit.title {
                fields.push(format!("\"title\":{}", quote(title)));
            }
            if let Some(body) = &edit.body {
                fields.push(format!("\"body\":{}", quote(body)));
            }
            format!("{{{}}}", fields.join(","))
        }
        DiscussionAction::Comment { body } => {
            format!("{{\"name\":\"comment\",\"body\":{}}}", quote(body))
        }
        DiscussionAction::Close => "{\"name\":\"close\"}".into(),
        DiscussionAction::Reopen => "{\"name\":\"reopen\"}".into(),
        DiscussionAction::Lock => "{\"name\":\"lock\"}".into(),
        DiscussionAction::Unlock => "{\"name\":\"unlock\"}".into(),
    }
}

pub(super) fn mutation(
    options: &Options,
    mutation: &Mutation,
    tx: TxId,
    terminal: &TerminalOutcome,
    cleanup: Option<&str>,
) -> String {
    let (outcome, committed, rcr, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            true,
            quote(&repository_commit_id.to_string()),
            "null".into(),
            "null".into(),
        ),
        DecisionOutcome::Refused {
            code,
            refusal_record_id,
        } => (
            "refused",
            false,
            "null".into(),
            quote(&refusal_record_id.to_string()),
            quote(&format!("{code:?}")),
        ),
    };
    format!(
        concat!(
            "{{\"type\":\"discussion_publication\",\"schema_version\":1,\"outcome\":{},",
            "\"command_committed\":{},\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"tenant_id\":{},\"repository_id\":{},",
            "\"principal_id\":{},\"object_format\":{},\"number\":{},\"expected_version\":{},\"action\":{},",
            "\"refs_changed\":false,\"delivery_acknowledged\":null,\"node_closed\":{},\"cleanup_error\":{}}}"
        ),
        quote(outcome),
        committed,
        quote(&tx.to_string()),
        terminal.decision_sequence.get(),
        rcr,
        refusal,
        code,
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&mutation.principal.to_string()),
        quote(options.format.as_str()),
        mutation.command.number.get(),
        expected_version(&mutation.command),
        action(&mutation.command.action),
        cleanup.is_none(),
        cleanup.map_or_else(|| "null".into(), quote),
    )
}

fn summary(value: &DiscussionSnapshot) -> Result<String, String> {
    DiscussionAction::Open {
        title: value.title.clone(),
        body: value.body.clone(),
    }
    .validate()
    .map_err(|_| "invalid discussion snapshot metadata")?;
    if value.comments >= value.version.get() {
        return Err("invalid discussion comment count".into());
    }
    Ok(format!(
        concat!(
            "{{\"number\":{},\"version\":{},\"title\":{},\"body\":{},",
            "\"state\":{},\"opened_by\":{},\"last_actor\":{},\"comments\":{},\"locked\":{}}}"
        ),
        value.number.get(),
        value.version.get(),
        quote(&value.title),
        quote(&value.body),
        quote(match value.state {
            DiscussionState::Open => "open",
            DiscussionState::Closed => "closed",
        }),
        quote(&value.opened_by.to_string()),
        quote(&value.last_actor.to_string()),
        value.comments,
        value.locked
    ))
}

fn header(
    options: &Options,
    read: &ReadOptions,
    head: RepositoryAuthorityHeadId,
) -> Result<String, String> {
    if read.expected_head.is_some_and(|expected| expected != head) {
        return Err("discussion response moved from the pinned snapshot".into());
    }
    Ok(format!(
        concat!(
            "\"schema_version\":1,\"scope\":\"repository_discussions\",\"tenant_id\":{},",
            "\"repository_id\":{},\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"node_closed\":true"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(options.format.as_str()),
        quote(&head.to_string()),
        quote(&head_token(head)),
    ))
}

fn append(out: &mut String, value: &str, comma: bool) -> Result<(), String> {
    if out.len().saturating_add(value.len()).saturating_add(3) > MAX_REPLY_BYTES {
        return Err("discussion response exceeds output ceiling; use a smaller page".into());
    }
    out.try_reserve(value.len() + 1)
        .map_err(|_| "discussion response allocation refused")?;
    if comma {
        out.push(',');
    }
    out.push_str(value);
    Ok(())
}

pub(super) fn list(
    options: &Options,
    read: &ReadOptions,
    head: RepositoryAuthorityHeadId,
    rows: &[DiscussionSnapshot],
    next: Option<u64>,
) -> Result<(String, u8), String> {
    if read.number.is_some()
        || rows.len() > usize::from(read.limit)
        || rows.iter().any(|row| row.number.get() <= read.after)
        || rows.windows(2).any(|pair| pair[0].number >= pair[1].number)
        || next.is_some_and(|n| {
            rows.len() != usize::from(read.limit)
                || rows.last().map(|row| row.number.get()) != Some(n)
        })
    {
        return Err("discussion list violates its pagination contract".into());
    }
    let header = header(options, read, head)?;
    let mut out = format!(
        "{{\"type\":\"discussion_page\",{header},\"after\":{},\"limit\":{},\"count\":{},\"has_more\":{},\"next_after\":{},\"discussions\":[",
        read.after,
        read.limit,
        rows.len(),
        next.is_some(),
        optional_number(next),
    );
    for (index, row) in rows.iter().enumerate() {
        append(&mut out, &summary(row)?, index != 0)?;
    }
    out.push_str("]}");
    Ok((out, 0))
}

pub(super) fn history(
    options: &Options,
    read: &ReadOptions,
    head: RepositoryAuthorityHeadId,
    discussion: Option<&DiscussionSnapshot>,
    events: &[ForgeEvent],
    next: Option<u64>,
) -> Result<(String, u8), String> {
    let number = read.number.ok_or("discussion show requires a number")?;
    let header = header(options, read, head)?;
    if events.len() > usize::from(read.limit)
        || discussion.is_some_and(|row| row.number != number)
        || (discussion.is_none() && (!events.is_empty() || next.is_some()))
    {
        return Err("discussion history violates its aggregate binding".into());
    }
    if let Some(row) = discussion {
        let remaining = row.version.get().saturating_sub(read.after);
        let count = remaining.min(u64::from(read.limit));
        let expected_next = if remaining > u64::from(read.limit) {
            read.after.checked_add(count)
        } else {
            None
        };
        if events.len() as u64 != count || next != expected_next {
            return Err("discussion history is incomplete for its pinned range".into());
        }
    }
    let mut out = format!(
        "{{\"type\":\"discussion_history\",{header},\"requested_number\":{},\"found\":{},\"discussion\":{},\"after_version\":{},\"limit\":{},\"has_more\":{},\"next_after_version\":{},\"events\":[",
        number.get(),
        discussion.is_some(),
        discussion
            .map(summary)
            .transpose()?
            .unwrap_or_else(|| "null".into()),
        read.after,
        read.limit,
        next.is_some(),
        optional_number(next),
    );
    for (index, event) in events.iter().enumerate() {
        if event.aggregate != AggregateId::Discussion(number)
            || read
                .after
                .checked_add(index as u64)
                .and_then(|v| v.checked_add(1))
                != Some(event.version.get())
        {
            return Err(
                "discussion history events are not the requested contiguous versions".into(),
            );
        }
        let ForgeEventPayload::DiscussionChangedNative(change) = &event.payload else {
            return Err("unexpected discussion event payload".into());
        };
        change
            .action
            .validate()
            .map_err(|_| "invalid discussion history action")?;
        let row = format!(
            "{{\"number\":{},\"version\":{},\"actor\":{},\"action\":{}}}",
            number.get(),
            event.version.get(),
            quote(&change.actor.to_string()),
            action(&change.action),
        );
        append(&mut out, &row, index != 0)?;
    }
    out.push_str("]}");
    Ok((out, if discussion.is_some() { 0 } else { 4 }))
}
