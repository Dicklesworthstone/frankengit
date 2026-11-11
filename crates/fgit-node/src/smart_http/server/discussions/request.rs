//! Bounded discussion routes preserve strict commands and explicit append intents.
//! No actor comes from text, and an append form cannot discard a supplied version.
use super::super::issues::{self, ApiError, Page};
use fgit_forge::event::discussion::{
    DiscussionAction, DiscussionCommand, DiscussionCommentIntent, DiscussionEdit,
};
use fgit_forge::{AggregateVersion, DiscussionNumber, ExpectedVersion};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

#[derive(Debug)]
pub(super) enum Operation<'a> {
    List(Page),
    Show {
        number: DiscussionNumber,
        page: Page,
    },
    Mutate {
        number: DiscussionNumber,
        action: &'a str,
    },
}

#[derive(Debug)]
pub(super) enum Command {
    Versioned(DiscussionCommand),
    AppendComment(DiscussionCommentIntent),
}

#[derive(Debug)]
pub(in crate::smart_http::server) struct Request<'a> {
    pub(super) repository_route: &'a str,
    pub(super) operation: Operation<'a>,
}
impl<'a> Request<'a> {
    pub(in crate::smart_http::server) fn parse(head: &Envelope<'a>) -> Result<Self, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let (repository_route, suffix) = path
            .split_once(super::ROUTE)
            .ok_or_else(ApiError::not_found)?;
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
                Operation::List(issues::parse_page(query, "after")?)
            } else {
                Operation::Show {
                    number: number(suffix.strip_prefix('/').ok_or_else(ApiError::not_found)?)?,
                    page: issues::parse_page(query, "after_version")?,
                }
            }
        } else if head.method == "POST" {
            if query.is_some() || head.body == BodyFraming::Empty {
                return Err(ApiError::bad("invalid_mutation_envelope"));
            }
            if !head.content_type.is_some_and(|value| {
                value.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                    || value
                        .eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8")
            }) {
                return Err(ApiError::media());
            }
            if matches!(head.body, BodyFraming::ContentLength(n) if n > issues::MAX_FORM_BYTES as u64)
            {
                return Err(ApiError::too_large());
            }
            let (id, action) = suffix
                .strip_prefix('/')
                .and_then(|s| s.split_once('/'))
                .ok_or_else(ApiError::not_found)?;
            if !matches!(
                action,
                "open"
                    | "edit"
                    | "comment"
                    | "append-comment"
                    | "close"
                    | "reopen"
                    | "lock"
                    | "unlock"
            ) {
                return Err(ApiError::not_found());
            }
            Operation::Mutate {
                number: number(id)?,
                action,
            }
        } else {
            return Err(ApiError::method());
        };
        Ok(Self {
            repository_route,
            operation,
        })
    }
    pub(in crate::smart_http::server) const fn is_mutation(&self) -> bool {
        matches!(self.operation, Operation::Mutate { .. })
    }
    pub(in crate::smart_http::server) const fn accepts_body(&self) -> bool {
        self.is_mutation()
    }
    pub(super) fn command(&self, body: &[u8]) -> Result<Command, ApiError> {
        let Operation::Mutate { number, action } = self.operation else {
            return Err(ApiError::bad("not_a_mutation"));
        };
        if action == "append-comment" {
            append_comment(number, body).map(Command::AppendComment)
        } else {
            command(number, action, body).map(Command::Versioned)
        }
    }
}
fn number(value: &str) -> Result<DiscussionNumber, ApiError> {
    DiscussionNumber::try_new(issues::parse_decimal(value)?)
        .ok_or_else(|| ApiError::bad("invalid_discussion_number"))
}
fn once<T>(slot: &mut Option<T>, value: T) -> Result<(), ApiError> {
    if slot.replace(value).is_some() {
        Err(ApiError::bad("duplicate_field"))
    } else {
        Ok(())
    }
}

fn append_comment(
    number: DiscussionNumber,
    body: &[u8],
) -> Result<DiscussionCommentIntent, ApiError> {
    let mut text = None;
    for (key, value) in issues::parse_form(body, 1)? {
        match key.as_str() {
            "body" => once(&mut text, value)?,
            _ => return Err(ApiError::bad("unknown_or_inapplicable_field")),
        }
    }
    let intent = DiscussionCommentIntent {
        number,
        body: text.ok_or_else(|| ApiError::bad("body_required"))?,
    };
    intent
        .validate()
        .map_err(|_| ApiError::bad("invalid_discussion_content"))?;
    Ok(intent)
}

pub(super) fn command(
    number: DiscussionNumber,
    name: &str,
    body: &[u8],
) -> Result<DiscussionCommand, ApiError> {
    let (mut version, mut title, mut text) = (None, None, None);
    for (key, value) in issues::parse_form(body, 3)? {
        match key.as_str() {
            "expected_version" => once(&mut version, issues::parse_decimal(&value)?)?,
            "title" if matches!(name, "open" | "edit") => once(&mut title, value)?,
            "body" if matches!(name, "open" | "edit" | "comment") => once(&mut text, value)?,
            _ => return Err(ApiError::bad("unknown_or_inapplicable_field")),
        }
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
        "open" => DiscussionAction::Open {
            title: title.ok_or_else(|| ApiError::bad("title_required"))?,
            body: text.ok_or_else(|| ApiError::bad("body_required"))?,
        },
        "edit" => DiscussionAction::Edit(DiscussionEdit { title, body: text }),
        "comment" => DiscussionAction::Comment {
            body: text.ok_or_else(|| ApiError::bad("body_required"))?,
        },
        "close" => DiscussionAction::Close,
        "reopen" => DiscussionAction::Reopen,
        "lock" => DiscussionAction::Lock,
        "unlock" => DiscussionAction::Unlock,
        _ => return Err(ApiError::not_found()),
    };
    action
        .validate()
        .map_err(|_| ApiError::bad("invalid_discussion_content"))?;
    Ok(DiscussionCommand {
        number,
        expected_version,
        action,
    })
}
