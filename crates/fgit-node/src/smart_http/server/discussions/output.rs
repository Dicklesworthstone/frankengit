//! Bounded canonical discussion projections; derived HTML uses the shared safe renderer.
use super::super::issues::{
    self, ApiError, Page, Rendering, append_json as append, optional_number as optional, quote,
    response_header as header,
};
use crate::OneNode;
use fgit_admission::merge::native::discussions::{DiscussionHistoryPage, DiscussionPage};
use fgit_authority::TerminalOutcome;
use fgit_forge::event::discussion::{
    DiscussionAction, DiscussionCommand, DiscussionSnapshot, DiscussionState,
};
use fgit_forge::{AggregateId, DiscussionNumber, ExpectedVersion, ForgeEventPayload};
use fgit_types::{DecisionOutcome, PrincipalId, TxId};

fn rendered(body: &str, render: Option<Rendering>) -> String {
    render.map_or_else(String::new, |render| {
        format!(",\"body_rendered\":{}", issues::render_body(body, render))
    })
}
fn snapshot(row: &DiscussionSnapshot, render: Option<Rendering>) -> Result<String, ApiError> {
    DiscussionAction::Open {
        title: row.title.clone(),
        body: row.body.clone(),
    }
    .validate()
    .map_err(|_| ApiError::unavailable())?;
    if row.comments >= row.version.get() {
        return Err(ApiError::unavailable());
    }
    Ok(format!(
        concat!(
            "{{\"number\":{},\"version\":{},\"title\":{},\"body\":{}{},",
            "\"state\":{},\"opened_by\":{},\"last_actor\":{},\"comments\":{},\"locked\":{}}}"
        ),
        row.number.get(),
        row.version.get(),
        quote(&row.title),
        quote(&row.body),
        rendered(&row.body, render),
        quote(match row.state {
            DiscussionState::Open => "open",
            DiscussionState::Closed => "closed",
        }),
        quote(&row.opened_by.to_string()),
        quote(&row.last_actor.to_string()),
        row.comments,
        row.locked,
    ))
}
pub(super) fn action(value: &DiscussionAction, render: Option<Rendering>) -> String {
    match value {
        DiscussionAction::Open { title, body } => format!(
            "{{\"name\":\"open\",\"title\":{},\"body\":{}{}}}",
            quote(title),
            quote(body),
            rendered(body, render),
        ),
        DiscussionAction::Edit(edit) => {
            let mut fields = vec!["\"name\":\"edit\"".to_owned()];
            if let Some(title) = &edit.title {
                fields.push(format!("\"title\":{}", quote(title)));
            }
            if let Some(body) = &edit.body {
                fields.push(format!(
                    "\"body\":{}{}",
                    quote(body),
                    rendered(body, render)
                ));
            }
            format!("{{{}}}", fields.join(","))
        }
        DiscussionAction::Comment { body } => format!(
            "{{\"name\":\"comment\",\"body\":{}{}}}",
            quote(body),
            rendered(body, render),
        ),
        DiscussionAction::Close => "{\"name\":\"close\"}".into(),
        DiscussionAction::Reopen => "{\"name\":\"reopen\"}".into(),
        DiscussionAction::Lock => "{\"name\":\"lock\"}".into(),
        DiscussionAction::Unlock => "{\"name\":\"unlock\"}".into(),
    }
}
pub(super) fn mutation(
    node: &OneNode,
    principal: PrincipalId,
    command: &DiscussionCommand,
    tx: TxId,
    terminal: TerminalOutcome,
) -> String {
    let (outcome, rcr, refusal, code) = match terminal.outcome {
        DecisionOutcome::Committed {
            repository_commit_id,
        } => (
            "committed",
            quote(&repository_commit_id.to_string()),
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
        ),
    };
    let expected = match command.expected_version {
        ExpectedVersion::NewStream => 0,
        ExpectedVersion::Exactly(version) => version.get(),
    };
    format!(
        concat!(
            "{{\"type\":\"discussion_publication\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"principal_id\":{},\"number\":{},\"expected_version\":{},\"action\":{},",
            "\"tx_id\":{},\"outcome\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
            "\"refusal_record_id\":{},\"refusal_code\":{},\"delivery_acknowledged\":null}}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&principal.to_string()),
        command.number.get(),
        expected,
        quote(command.action.name()),
        quote(&tx.to_string()),
        quote(outcome),
        terminal.decision_sequence.get(),
        rcr,
        refusal,
        code,
    )
}
pub(super) fn list(
    node: &OneNode,
    page: Page,
    result: &DiscussionPage,
    maximum: usize,
) -> Result<String, ApiError> {
    let rows = &result.discussions;
    if rows.len() > usize::from(page.limit)
        || rows.iter().any(|row| row.number.get() <= page.after)
        || rows.windows(2).any(|pair| pair[0].number >= pair[1].number)
        || result.next_after.is_some_and(|next| {
            rows.len() != usize::from(page.limit)
                || rows.last().map(|row| row.number.get()) != Some(next)
        })
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"type\":\"discussion_page\",{},\"scope\":\"repository_discussions\",\"after\":{},\"limit\":{},\"next_after\":{},\"discussions\":[",
            header(node, page, result.source_head)?,
            page.after,
            page.limit,
            optional(result.next_after),
        ),
        maximum,
    )?;
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(&mut out, &snapshot(row, page.render)?, maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}
pub(super) fn history(
    node: &OneNode,
    number: DiscussionNumber,
    page: Page,
    result: &DiscussionHistoryPage,
    maximum: usize,
) -> Result<String, ApiError> {
    if result.events.len() > usize::from(page.limit)
        || result
            .discussion
            .as_ref()
            .is_some_and(|row| row.number != number)
        || (result.discussion.is_none()
            && (!result.events.is_empty() || result.next_after.is_some()))
    {
        return Err(ApiError::unavailable());
    }
    if let Some(row) = &result.discussion {
        let remaining = row.version.get().saturating_sub(page.after);
        let count = remaining.min(u64::from(page.limit));
        let next = if remaining > count {
            page.after.checked_add(count)
        } else {
            None
        };
        if result.events.len() as u64 != count || result.next_after != next {
            return Err(ApiError::unavailable());
        }
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"type\":\"discussion_history\",{},\"scope\":\"repository_discussions\",\"found\":{},\"discussion\":{},\"after_version\":{},\"limit\":{},\"next_after_version\":{},\"events\":[",
            header(node, page, result.source_head)?,
            result.discussion.is_some(),
            result
                .discussion
                .as_ref()
                .map(|row| snapshot(row, page.render))
                .transpose()?
                .unwrap_or_else(|| "null".into()),
            page.after,
            page.limit,
            optional(result.next_after),
        ),
        maximum,
    )?;
    for (index, event) in result.events.iter().enumerate() {
        if event.aggregate != AggregateId::Discussion(number)
            || page
                .after
                .checked_add(index as u64)
                .and_then(|n| n.checked_add(1))
                != Some(event.version.get())
        {
            return Err(ApiError::unavailable());
        }
        let ForgeEventPayload::DiscussionChangedNative(change) = &event.payload else {
            return Err(ApiError::unavailable());
        };
        change
            .action
            .validate()
            .map_err(|_| ApiError::unavailable())?;
        if index != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(
            &mut out,
            &format!(
                "{{\"version\":{},\"actor\":{},\"action\":{}}}",
                event.version.get(),
                quote(&change.actor.to_string()),
                action(&change.action, page.render),
            ),
            maximum,
        )?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}
