//! Milestones share the issue-service ceiling; sponsored credentials additionally
//! require independent milestones-read/milestones-write operations.
//! Membership is planning metadata; it grants no principal or ref authority.

use super::{
    ApiError, OneNode, Rendering,
    output::{append, header, optional, quote},
    request::{self, Operation, Page, Request},
};
use fgit_admission::merge::native::milestones::{
    MilestoneHistoryPage, MilestonePage, MilestoneSummary,
};
use fgit_forge::event::milestone::{
    MilestoneAction, MilestoneCommand, MilestoneEdit, MilestoneState,
};
use fgit_forge::{
    AggregateId, AggregateVersion, ExpectedVersion, ForgeEventPayload, MilestoneNumber,
};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

pub(super) fn read_error(error: crate::MilestoneReadRefusal) -> ApiError {
    match error {
        crate::MilestoneReadRefusal::SnapshotMoved => ApiError::snapshot_moved(),
        crate::MilestoneReadRefusal::SnapshotRequired => ApiError::bad("snapshot_required"),
        crate::MilestoneReadRefusal::InvalidLimit => ApiError::bad("invalid_page_limit"),
        _ => ApiError::unavailable(),
    }
}

pub(super) fn parse<'a>(head: &Envelope<'a>) -> Result<Option<Request<'a>>, ApiError> {
    let (path, query) = head
        .target
        .split_once('?')
        .map_or((head.target, None), |(p, q)| (p, Some(q)));
    let Some((repository_route, suffix)) = path.split_once("/api/v1/milestones") else {
        return Ok(None);
    };
    if repository_route.len() < 2
        || !repository_route.starts_with('/')
        || repository_route[1..].split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        })
    {
        return Err(ApiError::not_found());
    }
    let operation = if head.method == "GET" {
        if !matches!(
            head.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        ) || head.expect_continue
        {
            return Err(ApiError::bad("body_not_allowed"));
        }
        if suffix.is_empty() {
            Operation::MilestoneList(request::page(query, "after")?)
        } else {
            Operation::MilestoneShow {
                number: number(suffix.strip_prefix('/').ok_or_else(ApiError::not_found)?)?,
                page: request::page(query, "after_version")?,
            }
        }
    } else if head.method == "POST" {
        if query.is_some() || head.body == BodyFraming::Empty {
            return Err(ApiError::bad("invalid_mutation_envelope"));
        }
        if !head.content_type.is_some_and(|value| {
            value.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                || value.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
        }) {
            return Err(ApiError::media());
        }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > request::MAX_FORM_BYTES as u64)
        {
            return Err(ApiError::too_large());
        }
        let (id, action) = suffix
            .strip_prefix('/')
            .and_then(|s| s.split_once('/'))
            .ok_or_else(ApiError::not_found)?;
        if !matches!(action, "open" | "edit" | "close" | "reopen") {
            return Err(ApiError::not_found());
        }
        Operation::MilestoneMutate {
            number: number(id)?,
            action,
        }
    } else {
        return Err(ApiError::method());
    };
    Ok(Some(Request {
        repository_route,
        operation,
    }))
}

fn number(value: &str) -> Result<MilestoneNumber, ApiError> {
    MilestoneNumber::try_new(request::decimal(value)?)
        .ok_or_else(|| ApiError::bad("invalid_milestone_number"))
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), ApiError> {
    if slot.replace(value).is_some() {
        Err(ApiError::bad("duplicate_field"))
    } else {
        Ok(())
    }
}
pub(super) fn command(
    number: MilestoneNumber,
    name: &str,
    body: &[u8],
) -> Result<MilestoneCommand, ApiError> {
    let (mut version, mut title, mut text, mut due_at, mut clear_due_at) =
        (None, None, None, None, None);
    for (key, value) in request::form(body, 5)? {
        match key.as_str() {
            "expected_version" => once(&mut version, request::decimal(&value)?)?,
            "title" if matches!(name, "open" | "edit") => once(&mut title, value)?,
            "body" if matches!(name, "open" | "edit") => once(&mut text, value)?,
            "due_at" if matches!(name, "open" | "edit") => {
                once(&mut due_at, request::decimal(&value)?)?
            }
            "clear_due_at" if name == "edit" && value == "true" => once(&mut clear_due_at, true)?,
            _ => return Err(ApiError::bad("unknown_or_inapplicable_field")),
        }
    }
    if due_at.is_some() && clear_due_at.is_some() {
        return Err(ApiError::bad("conflicting_due_at_fields"));
    }
    let version = version.ok_or_else(|| ApiError::bad("expected_version_required"))?;
    if (name == "open") != (version == 0) {
        return Err(ApiError::bad("invalid_expected_version"));
    }
    let expected_version = if version == 0 {
        ExpectedVersion::NewStream
    } else {
        let version = AggregateVersion::try_new(version)
            .ok_or_else(|| ApiError::bad("invalid_expected_version"))?;
        version
            .next()
            .map_err(|_| ApiError::bad("version_exhausted"))?;
        ExpectedVersion::Exactly(version)
    };
    let action = match name {
        "open" => MilestoneAction::Open {
            title: title.ok_or_else(|| ApiError::bad("title_required"))?,
            body: text.ok_or_else(|| ApiError::bad("body_required"))?,
            due_at,
        },
        "edit" => MilestoneAction::Edit(MilestoneEdit {
            title,
            body: text,
            due_at: if clear_due_at.is_some() {
                Some(None)
            } else {
                due_at.map(Some)
            },
        }),
        "close" => MilestoneAction::Close,
        "reopen" => MilestoneAction::Reopen,
        _ => return Err(ApiError::not_found()),
    };
    action
        .validate()
        .map_err(|_| ApiError::bad("invalid_milestone_content"))?;
    Ok(MilestoneCommand {
        number,
        expected_version,
        action,
    })
}

fn rendered(body: &str, render: Option<Rendering>) -> String {
    render.map_or_else(String::new, |render| {
        format!(",\"body_rendered\":{}", super::render_body(body, render))
    })
}
fn summary(value: &MilestoneSummary, render: Option<Rendering>) -> Result<String, ApiError> {
    let row = &value.milestone;
    MilestoneAction::Open {
        title: row.title.clone(),
        body: row.body.clone(),
        due_at: row.due_at,
    }
    .validate()
    .map_err(|_| ApiError::unavailable())?;
    value
        .open_issues
        .checked_add(value.closed_issues)
        .ok_or_else(ApiError::unavailable)?;
    Ok(format!(
        concat!(
            "{{\"number\":{},\"version\":{},\"title\":{},\"body\":{}{},\"due_at\":{},",
            "\"state\":{},\"opened_by\":{},\"last_actor\":{},\"open_issues\":{},\"closed_issues\":{}}}"
        ),
        row.number.get(),
        row.version.get(),
        quote(&row.title),
        quote(&row.body),
        rendered(&row.body, render),
        optional(row.due_at),
        quote(match row.state {
            MilestoneState::Open => "open",
            MilestoneState::Closed => "closed",
        }),
        quote(&row.opened_by.to_string()),
        quote(&row.last_actor.to_string()),
        value.open_issues,
        value.closed_issues
    ))
}
fn action(value: &MilestoneAction, render: Option<Rendering>) -> String {
    match value {
        MilestoneAction::Open {
            title,
            body,
            due_at,
        } => format!(
            "{{\"name\":\"open\",\"title\":{},\"body\":{}{},\"due_at\":{}}}",
            quote(title),
            quote(body),
            rendered(body, render),
            optional(*due_at)
        ),
        MilestoneAction::Edit(edit) => {
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
            if let Some(due) = edit.due_at {
                fields.push(format!("\"due_at\":{}", optional(due)));
            }
            format!("{{{}}}", fields.join(","))
        }
        MilestoneAction::Close => "{\"name\":\"close\"}".into(),
        MilestoneAction::Reopen => "{\"name\":\"reopen\"}".into(),
    }
}

pub(super) fn list(
    node: &OneNode,
    page: Page,
    result: &MilestonePage,
    maximum: usize,
) -> Result<String, ApiError> {
    let rows = &result.milestones;
    if rows.len() > usize::from(page.limit)
        || rows
            .iter()
            .any(|row| row.milestone.number.get() <= page.after)
        || rows
            .windows(2)
            .any(|pair| pair[0].milestone.number >= pair[1].milestone.number)
        || result.next_after.is_some_and(|next| {
            rows.len() != usize::from(page.limit)
                || rows.last().map(|row| row.milestone.number.get()) != Some(next)
        })
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"type\":\"milestone_page\",{},\"scope\":\"repository_milestones\",\"after\":{},\"limit\":{},\"next_after\":{},\"milestones\":[",
            header(node, page, result.source_head)?,
            page.after,
            page.limit,
            optional(result.next_after)
        ),
        maximum,
    )?;
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(&mut out, &summary(row, page.render)?, maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}
pub(super) fn history(
    node: &OneNode,
    number: MilestoneNumber,
    page: Page,
    result: &MilestoneHistoryPage,
    maximum: usize,
) -> Result<String, ApiError> {
    if result.events.len() > usize::from(page.limit)
        || result
            .milestone
            .as_ref()
            .is_some_and(|row| row.milestone.number != number)
        || (result.milestone.is_none()
            && (!result.events.is_empty() || result.next_after.is_some()))
    {
        return Err(ApiError::unavailable());
    }
    if let Some(row) = &result.milestone {
        let remaining = row.milestone.version.get().saturating_sub(page.after);
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
            "{{\"type\":\"milestone_history\",{},\"scope\":\"repository_milestones\",\"found\":{},\"milestone\":{},\"after_version\":{},\"limit\":{},\"next_after_version\":{},\"events\":[",
            header(node, page, result.source_head)?,
            result.milestone.is_some(),
            result
                .milestone
                .as_ref()
                .map(|row| summary(row, page.render))
                .transpose()?
                .unwrap_or_else(|| "null".into()),
            page.after,
            page.limit,
            optional(result.next_after)
        ),
        maximum,
    )?;
    for (index, event) in result.events.iter().enumerate() {
        if event.aggregate != AggregateId::Milestone(number)
            || page
                .after
                .checked_add(index as u64)
                .and_then(|n| n.checked_add(1))
                != Some(event.version.get())
        {
            return Err(ApiError::unavailable());
        }
        let ForgeEventPayload::MilestoneChangedNative(change) = &event.payload else {
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
                action(&change.action, page.render)
            ),
            maximum,
        )?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_bind_versions_and_distinguish_omitted_due_date_from_clear() {
        let id = MilestoneNumber::try_new(7).unwrap();
        let open = command(
            id,
            "open",
            b"expected_version=0&title=Release&body=&due_at=253402300799",
        )
        .unwrap();
        assert!(matches!(
            open.action,
            MilestoneAction::Open {
                due_at: Some(253402300799),
                ..
            }
        ));
        let edit = command(id, "edit", b"expected_version=1&body=").unwrap();
        assert!(
            matches!(edit.action, MilestoneAction::Edit(MilestoneEdit { body: Some(body), due_at: None, .. }) if body.is_empty())
        );
        let clear = command(id, "edit", b"expected_version=1&clear_due_at=true").unwrap();
        assert!(matches!(
            clear.action,
            MilestoneAction::Edit(MilestoneEdit {
                due_at: Some(None),
                ..
            })
        ));
        for (name, bytes) in [
            ("open", "expected_version=1&title=x&body="),
            ("close", "expected_version=0"),
            ("edit", "expected_version=1"),
            ("edit", "expected_version=1&due_at=1&clear_due_at=true"),
            ("edit", "expected_version=1&due_at=253402300800"),
            ("edit", "expected_version=1&due_at=01"),
            ("edit", "expected_version=1&due_at=1&due_at=2"),
            ("edit", "expected_version=1&clear_due_at=false"),
            ("close", "expected_version=1&title=x"),
            ("close", "expected_version=1&principal=attacker"),
            ("close", "expected_version=18446744073709551615"),
        ] {
            assert!(
                command(id, name, bytes.as_bytes()).is_err(),
                "{name}: {bytes}"
            );
        }
    }
    #[test]
    fn all_due_date_actions_preserve_omission_or_null_in_history() {
        assert_eq!(
            action(
                &MilestoneAction::Edit(MilestoneEdit {
                    title: None,
                    body: None,
                    due_at: Some(None)
                }),
                None
            ),
            "{\"name\":\"edit\",\"due_at\":null}"
        );
        assert_eq!(
            action(
                &MilestoneAction::Edit(MilestoneEdit {
                    title: Some("release".into()),
                    body: None,
                    due_at: None
                }),
                None
            ),
            "{\"name\":\"edit\",\"title\":\"release\"}"
        );
        assert_eq!(
            action(&MilestoneAction::Close, None),
            "{\"name\":\"close\"}"
        );
        assert_eq!(
            action(&MilestoneAction::Reopen, None),
            "{\"name\":\"reopen\"}"
        );
    }
}
