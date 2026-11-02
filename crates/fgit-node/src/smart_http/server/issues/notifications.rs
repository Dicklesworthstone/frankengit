//! Authenticated self-only inbox routes. Recipient identity is never selected by a form.
use super::{
    ApiError, OneNode,
    output::{append, header, optional, quote},
    request::{self, Operation, Page, Request},
};
use crate::{NotificationInboxPage, NotificationReadRefusal, NotificationThreadView};
use fgit_forge::event::issue::IssueState;
use fgit_forge::event::notification::{NotificationAction, NotificationCommand, NotificationMode};
use fgit_forge::{AggregateVersion, ExpectedVersion, IssueNumber};
use fgit_types::{PrincipalId, RepositoryIncarnationId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

pub(super) fn read_error(error: NotificationReadRefusal) -> ApiError {
    match error {
        NotificationReadRefusal::SnapshotMoved => ApiError::snapshot_moved(),
        NotificationReadRefusal::SnapshotRequired => ApiError::bad("snapshot_required"),
        NotificationReadRefusal::InvalidLimit => ApiError::bad("invalid_page_limit"),
        NotificationReadRefusal::Unauthenticated => {
            ApiError::new(super::Status::Unauthorized, "unauthorized")
        }
        _ => ApiError::unavailable(),
    }
}
pub(super) fn parse<'a>(head: &Envelope<'a>) -> Result<Option<Request<'a>>, ApiError> {
    let (path, query) = head
        .target
        .split_once('?')
        .map_or((head.target, None), |(p, q)| (p, Some(q)));
    let Some((repository_route, suffix)) = path.split_once("/api/v1/notifications") else {
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
            let (page, unread_only, include_muted) = inbox_page(query)?;
            Operation::NotificationList {
                page,
                unread_only,
                include_muted,
            }
        } else {
            let page = request::page(query, "after_version")?;
            if page.after != 0 || page.render.is_some() {
                return Err(ApiError::bad("invalid_thread_query"));
            }
            Operation::NotificationShow {
                number: number(suffix.strip_prefix('/').ok_or_else(ApiError::not_found)?)?,
                page,
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
        if !matches!(
            action,
            "subscribe" | "mute" | "automatic" | "read" | "unread"
        ) {
            return Err(ApiError::not_found());
        }
        Operation::NotificationMutate {
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
fn number(value: &str) -> Result<IssueNumber, ApiError> {
    IssueNumber::try_new(request::decimal(value)?)
        .ok_or_else(|| ApiError::bad("invalid_issue_number"))
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), ApiError> {
    if slot.replace(value).is_some() {
        Err(ApiError::bad("duplicate_field"))
    } else {
        Ok(())
    }
}
fn boolean(value: &str) -> Result<bool, ApiError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ApiError::bad("invalid_boolean")),
    }
}
fn inbox_page(query: Option<&str>) -> Result<(Page, bool, bool), ApiError> {
    let (mut after, mut limit, mut expected_head, mut unread, mut muted) =
        (None, None, None, None, None);
    if let Some(query) = query {
        for (key, value) in request::form(query.as_bytes(), 5)? {
            match key.as_str() {
                "after" => once(&mut after, request::decimal(&value)?)?,
                "limit" => once(&mut limit, request::decimal(&value)?)?,
                "expected_head" => once(&mut expected_head, request::parse_head_token(&value)?)?,
                "unread_only" => once(&mut unread, boolean(&value)?)?,
                "include_muted" => once(&mut muted, boolean(&value)?)?,
                _ => return Err(ApiError::bad("unknown_query_field")),
            }
        }
    }
    let limit = limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(ApiError::bad("invalid_page_limit"));
    }
    let after = after.unwrap_or(0);
    if after != 0 && expected_head.is_none() {
        return Err(ApiError::bad("snapshot_required"));
    }
    Ok((
        Page {
            after,
            limit: limit as u16,
            expected_head,
            render: None,
        },
        unread.unwrap_or(false),
        muted.unwrap_or(false),
    ))
}
#[derive(Debug)]
pub(super) struct BoundNotificationCommand {
    pub canonical: NotificationCommand,
    pub expected_principal: PrincipalId,
    pub expected_incarnation: RepositoryIncarnationId,
}
pub(super) fn command(
    number: IssueNumber,
    name: &str,
    body: &[u8],
) -> Result<BoundNotificationCommand, ApiError> {
    let (mut version, mut read_through, mut expected_principal, mut expected_incarnation) =
        (None, None, None, None);
    for (key, value) in request::form(body, 4)? {
        match key.as_str() {
            "expected_version" => once(&mut version, request::decimal(&value)?)?,
            "expected_principal" => once(
                &mut expected_principal,
                PrincipalId::from_hex(&value)
                    .map_err(|_| ApiError::bad("invalid_principal_guard"))?,
            )?,
            "expected_incarnation" => once(
                &mut expected_incarnation,
                RepositoryIncarnationId::from_hex(&value)
                    .map_err(|_| ApiError::bad("invalid_incarnation_guard"))?,
            )?,
            "read_through" if name == "read" => once(
                &mut read_through,
                AggregateVersion::try_new(request::decimal(&value)?)
                    .ok_or_else(|| ApiError::bad("invalid_read_version"))?,
            )?,
            _ => return Err(ApiError::bad("unknown_or_inapplicable_field")),
        }
    }
    let expected_version =
        match version.ok_or_else(|| ApiError::bad("expected_version_required"))? {
            0 => ExpectedVersion::NewStream,
            value => ExpectedVersion::Exactly(
                AggregateVersion::try_new(value)
                    .ok_or_else(|| ApiError::bad("invalid_preference_version"))?,
            ),
        };
    let action = match name {
        "subscribe" => NotificationAction::SetMode(NotificationMode::Subscribed),
        "mute" => NotificationAction::SetMode(NotificationMode::Muted),
        "automatic" => NotificationAction::SetMode(NotificationMode::Participating),
        "read" => NotificationAction::SetReadThrough(Some(
            read_through.ok_or_else(|| ApiError::bad("read_through_required"))?,
        )),
        "unread" => NotificationAction::SetReadThrough(None),
        _ => return Err(ApiError::not_found()),
    };
    Ok(BoundNotificationCommand {
        canonical: NotificationCommand {
            number,
            expected_version,
            action,
        },
        expected_principal: expected_principal
            .ok_or_else(|| ApiError::bad("principal_guard_required"))?,
        expected_incarnation: expected_incarnation
            .ok_or_else(|| ApiError::bad("incarnation_guard_required"))?,
    })
}
pub(super) const fn action_name(action: &NotificationAction) -> &'static str {
    match action {
        NotificationAction::SetMode(NotificationMode::Subscribed) => "subscribe",
        NotificationAction::SetMode(NotificationMode::Muted) => "mute",
        NotificationAction::SetMode(NotificationMode::Participating) => "automatic",
        NotificationAction::SetReadThrough(Some(_)) => "read",
        NotificationAction::SetReadThrough(None) => "unread",
    }
}
fn thread(row: &NotificationThreadView) -> String {
    let reasons = row
        .reasons
        .iter()
        .map(|reason| quote(reason.as_str()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"number\":{},\"issue_version\":{},\"title\":{},\"state\":{},",
            "\"preference_version\":{},\"mode\":{},\"read_through\":{},\"latest_other_version\":{},\"unread\":{},\"reasons\":[{}]}}"
        ),
        row.number.get(),
        row.issue_version.get(),
        quote(&row.title),
        quote(match row.state {
            IssueState::Open => "open",
            IssueState::Closed => "closed",
        }),
        optional(row.preference_version.map(AggregateVersion::get)),
        quote(match row.mode {
            NotificationMode::Participating => "automatic",
            NotificationMode::Subscribed => "subscribed",
            NotificationMode::Muted => "muted",
        }),
        optional(row.read_through.map(AggregateVersion::get)),
        optional(row.latest_other_version.map(AggregateVersion::get)),
        row.unread,
        reasons
    )
}
fn source(result: &NotificationInboxPage) -> String {
    format!(
        concat!(
            "\"principal_id\":{},\"repository_incarnation\":{},\"source_positions\":{{",
            "\"authority_head_generation\":{},\"forge_position_root\":{},\"outbox_root\":{},\"complete\":true}}"
        ),
        quote(&result.binding.principal.to_string()),
        quote(&result.binding.incarnation.to_string()),
        result.binding.authority_head_generation,
        quote(&result.binding.forge_position_root.to_string()),
        quote(&result.binding.outbox_root.to_string())
    )
}
pub(super) fn list(
    node: &OneNode,
    page: Page,
    unread_only: bool,
    include_muted: bool,
    result: &NotificationInboxPage,
    maximum: usize,
) -> Result<String, ApiError> {
    if result.threads.len() > usize::from(page.limit)
        || result.threads.iter().any(|r| {
            r.number.get() <= page.after
                || (unread_only && !r.unread)
                || (!include_muted && r.mode == NotificationMode::Muted)
        })
        || result
            .threads
            .windows(2)
            .any(|p| p[0].number >= p[1].number)
        || result.next_after.is_some_and(|next| {
            result.threads.len() != usize::from(page.limit)
                || result.threads.last().map(|r| r.number.get()) != Some(next)
        })
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"notification_page\",{},{},\"after\":{},\"limit\":{},",
                "\"unread_only\":{},\"include_muted\":{},\"next_after\":{},\"threads\":["
            ),
            header(node, page, result.binding.authority_head)?,
            source(result),
            page.after,
            page.limit,
            unread_only,
            include_muted,
            optional(result.next_after)
        ),
        maximum,
    )?;
    for (index, row) in result.threads.iter().enumerate() {
        if index != 0 {
            append(&mut out, ",", maximum)?;
        }
        append(&mut out, &thread(row), maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}
pub(super) fn show(
    node: &OneNode,
    number: IssueNumber,
    page: Page,
    result: &NotificationInboxPage,
    maximum: usize,
) -> Result<String, ApiError> {
    if result.threads.len() > 1
        || result.threads.iter().any(|r| r.number != number)
        || result.next_after.is_some()
    {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"type\":\"notification_thread\",{},{},\"found\":{},\"thread\":{}}}",
            header(node, page, result.binding.authority_head)?,
            source(result),
            !result.threads.is_empty(),
            result.threads.first().map_or_else(|| "null".into(), thread)
        ),
        maximum,
    )?;
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forms_cannot_select_a_recipient_or_invent_a_read_prefix() {
        for body in [
            "expected_version=0&principal=0011",
            "expected_version=0&read_through=0",
            "expected_version=0&expected_version=0",
            "read_through=1",
        ] {
            assert!(command(IssueNumber::FIRST, "read", body.as_bytes()).is_err());
        }
        assert!(
            command(
                IssueNumber::FIRST,
                "unread",
                b"expected_version=1&read_through=1"
            )
            .is_err()
        );
        let form = format!(
            "expected_version=0&read_through=3&expected_principal={}&expected_incarnation={}",
            "11".repeat(16),
            "22".repeat(16)
        );
        assert_eq!(
            command(IssueNumber::FIRST, "read", form.as_bytes())
                .unwrap()
                .canonical
                .action,
            NotificationAction::SetReadThrough(AggregateVersion::try_new(3))
        );
        assert!(inbox_page(Some("after=2")).is_err());
        assert!(inbox_page(Some("include_muted=true&include_muted=false")).is_err());
        assert!(inbox_page(Some("principal=other")).is_err());
    }
}
