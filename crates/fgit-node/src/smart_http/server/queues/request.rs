//! Closed queue grammar: every write coordinate is supplied by the client.
use std::collections::{BTreeMap, BTreeSet};

use fgit_forge::event::queue::MAX_QUEUE_ENTRIES;
use fgit_forge::merge_queue::{DequeueReason, QueueCommand, QueueCommandAction};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_types::{
    GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId, RepositoryIncarnationId,
};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};

use super::super::issues::{ApiError, Page, parse_decimal, parse_form, parse_page, parse_snapshot};
use super::{MAX_COMMAND_BYTES, ROUTE, Status};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Action {
    Enqueue,
    Dequeue,
    Reorder,
}

#[derive(Debug)]
pub(super) enum Operation {
    List(Page),
    Show {
        number: QueueNumber,
        expected_head: Option<RepositoryAuthorityHeadId>,
    },
    Mutate {
        number: QueueNumber,
        action: Action,
    },
}

#[derive(Debug)]
pub(in crate::smart_http::server) struct Request<'a> {
    pub(super) repository_route: &'a str,
    pub(super) operation: Operation,
}

impl<'a> Request<'a> {
    pub(in crate::smart_http::server) fn parse(head: &Envelope<'a>) -> Result<Self, ApiError> {
        let (path, query) = head
            .target
            .split_once('?')
            .map_or((head.target, None), |(path, query)| (path, Some(query)));
        let (repository_route, suffix) = path.rsplit_once(ROUTE).ok_or_else(ApiError::not_found)?;
        if repository_route.len() < 2
            || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| {
                part.is_empty()
                    || matches!(part, "." | "..")
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
            })
        {
            return Err(ApiError::not_found());
        }
        if head.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        let operation = match head.method {
            "GET" => {
                if !matches!(
                    head.body,
                    BodyFraming::Empty | BodyFraming::ContentLength(0)
                ) || head.expect_continue
                {
                    return Err(ApiError::bad("body_not_allowed"));
                }
                if suffix.is_empty() {
                    let page = parse_page(query, "after")?;
                    if page.render.is_some() {
                        return Err(ApiError::bad("unknown_query_field"));
                    }
                    Operation::List(page)
                } else {
                    let number = number(suffix.strip_prefix('/').ok_or_else(ApiError::not_found)?)?;
                    let mut expected_head = None;
                    for (key, value) in parse_form(query.unwrap_or("").as_bytes(), 1)? {
                        if key != "expected_head" {
                            return Err(ApiError::bad("unknown_query_field"));
                        }
                        expected_head = Some(parse_snapshot(&value)?);
                    }
                    Operation::Show {
                        number,
                        expected_head,
                    }
                }
            }
            "POST" => {
                if query.is_some()
                    || matches!(
                        head.body,
                        BodyFraming::Empty | BodyFraming::ContentLength(0)
                    )
                {
                    return Err(ApiError::bad("invalid_mutation_envelope"));
                }
                if !head.content_type.is_some_and(|media| {
                    media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                        || media.eq_ignore_ascii_case(
                            "application/x-www-form-urlencoded; charset=utf-8",
                        )
                }) {
                    return Err(ApiError::media());
                }
                if matches!(head.body, BodyFraming::ContentLength(size) if size > MAX_COMMAND_BYTES as u64)
                {
                    return Err(ApiError::too_large());
                }
                let (number_text, action) = suffix
                    .strip_prefix('/')
                    .and_then(|text| text.split_once('/'))
                    .ok_or_else(ApiError::not_found)?;
                let action = match action {
                    "enqueue" => Action::Enqueue,
                    "dequeue" => Action::Dequeue,
                    "reorder" => Action::Reorder,
                    _ => return Err(ApiError::not_found()),
                };
                Operation::Mutate {
                    number: number(number_text)?,
                    action,
                }
            }
            _ => return Err(ApiError::method()),
        };
        Ok(Self {
            repository_route,
            operation,
        })
    }

    pub(in crate::smart_http::server) const fn is_mutation(&self) -> bool {
        matches!(self.operation, Operation::Mutate { .. })
    }

    pub(super) fn command(
        &self,
        bytes: &[u8],
        format: GitHashAlgorithm,
        incarnation: RepositoryIncarnationId,
    ) -> Result<QueueCommand, ApiError> {
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(ApiError::too_large());
        }
        let Operation::Mutate { number, action } = self.operation else {
            return Err(ApiError::bad("not_a_mutation"));
        };
        let mut fields = BTreeMap::new();
        let mut order = Vec::new();
        let mut seen = BTreeSet::new();
        for (key, value) in parse_form(bytes, MAX_QUEUE_ENTRIES + 12)? {
            let allowed = matches!(
                key.as_str(),
                "expected_version"
                    | "expected_incarnation"
                    | "object_format"
                    | "target_ref"
                    | "target_ref_hex"
            ) || match action {
                Action::Enqueue => matches!(
                    key.as_str(),
                    "pull_request"
                        | "expected_pull_request_version"
                        | "source_ref"
                        | "source_ref_hex"
                        | "expected_source_tip"
                        | "expected_target_tip"
                        | "priority"
                ),
                Action::Dequeue => matches!(key.as_str(), "pull_request" | "reason"),
                Action::Reorder => key == "entry",
            };
            if !allowed {
                return Err(ApiError::bad("unknown_or_inapplicable_field"));
            }
            if key == "entry" {
                if order.len() >= MAX_QUEUE_ENTRIES {
                    return Err(ApiError::too_large());
                }
                let entry = pull_number(&value)?;
                if !seen.insert(entry) {
                    return Err(ApiError::bad("duplicate_queue_entry"));
                }
                order.push(entry);
            } else if fields.insert(key, value).is_some() {
                return Err(ApiError::bad("duplicate_field"));
            }
        }
        let pinned = take(&mut fields, "expected_incarnation")?;
        let pinned_id = RepositoryIncarnationId::from_hex(&pinned)
            .map_err(|_| ApiError::bad("invalid_repository_incarnation"))?;
        if pinned_id.to_string() != pinned {
            return Err(ApiError::bad("invalid_repository_incarnation"));
        }
        if pinned_id != incarnation {
            return Err(ApiError::new(
                Status::Conflict,
                "repository_incarnation_mismatch",
            ));
        }
        if take(&mut fields, "object_format")? != format.as_str() {
            return Err(ApiError::bad("object_format_mismatch"));
        }
        let version = parse_decimal(&take(&mut fields, "expected_version")?)?;
        let expected_version = if version == 0 {
            if action != Action::Enqueue {
                return Err(ApiError::bad("invalid_expected_version"));
            }
            ExpectedVersion::NewStream
        } else {
            let version = AggregateVersion::try_new(version)
                .ok_or_else(|| ApiError::bad("invalid_expected_version"))?;
            version
                .next()
                .map_err(|_| ApiError::bad("version_exhausted"))?;
            ExpectedVersion::Exactly(version)
        };
        let target_ref = branch(&mut fields, "target_ref", "target_ref_hex")?;
        let action = match action {
            Action::Enqueue => QueueCommandAction::Enqueue {
                pull_request: pull_number(&take(&mut fields, "pull_request")?)?,
                expected_pull_request_version: AggregateVersion::try_new(parse_decimal(&take(
                    &mut fields,
                    "expected_pull_request_version",
                )?)?)
                .ok_or_else(|| ApiError::bad("positive_pull_version_required"))?,
                source_ref: branch(&mut fields, "source_ref", "source_ref_hex")?,
                head_tip: oid(&take(&mut fields, "expected_source_tip")?, format)?,
                expected_target_tip: oid(&take(&mut fields, "expected_target_tip")?, format)?,
                priority: u32::try_from(parse_decimal(
                    &fields.remove("priority").unwrap_or_else(|| "0".into()),
                )?)
                .map_err(|_| ApiError::bad("invalid_priority"))?,
            },
            Action::Dequeue => QueueCommandAction::Dequeue {
                pull_request: pull_number(&take(&mut fields, "pull_request")?)?,
                reason: match take(&mut fields, "reason")?.as_str() {
                    "withdrawn" => DequeueReason::Withdrawn,
                    "conflict" => DequeueReason::Conflict,
                    "check-failed" => DequeueReason::CheckFailed,
                    "base-moved" => DequeueReason::BaseMoved,
                    "evicted" => DequeueReason::Evicted,
                    "admin-override" => DequeueReason::AdminOverride,
                    _ => return Err(ApiError::bad("invalid_dequeue_reason")),
                },
            },
            Action::Reorder => {
                if order.is_empty() {
                    return Err(ApiError::bad("queue_order_required"));
                }
                QueueCommandAction::Reorder { order }
            }
        };
        Ok(QueueCommand {
            number,
            target_ref,
            expected_version,
            action,
        })
    }
}

fn take(fields: &mut BTreeMap<String, String>, key: &str) -> Result<String, ApiError> {
    fields
        .remove(key)
        .ok_or_else(|| ApiError::bad("required_field_missing"))
}
fn number(text: &str) -> Result<QueueNumber, ApiError> {
    QueueNumber::try_new(parse_decimal(text)?).ok_or_else(|| ApiError::bad("invalid_queue_number"))
}
fn pull_number(text: &str) -> Result<PullRequestNumber, ApiError> {
    PullRequestNumber::try_new(parse_decimal(text)?)
        .ok_or_else(|| ApiError::bad("invalid_pull_request_number"))
}
fn branch(
    fields: &mut BTreeMap<String, String>,
    plain: &str,
    hex: &str,
) -> Result<RefName, ApiError> {
    let bytes = match (fields.remove(plain), fields.remove(hex)) {
        (Some(value), None) if value.len() <= 1024 => value.into_bytes(),
        (None, Some(value))
            if !value.is_empty()
                && value.len() <= 2048
                && value.len() % 2 == 0
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let digit = |byte: u8| {
                        if byte.is_ascii_digit() {
                            byte - b'0'
                        } else {
                            byte - b'a' + 10
                        }
                    };
                    (digit(pair[0]) << 4) | digit(pair[1])
                })
                .collect()
        }
        _ => return Err(ApiError::bad("exactly_one_branch_encoding_required")),
    };
    if !bytes.starts_with(b"refs/heads/") {
        return Err(ApiError::bad("full_branch_required"));
    }
    RefName::try_new(&bytes).map_err(|_| ApiError::bad("invalid_ref"))
}
fn oid(value: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    if value.len() != format.digest_len() * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad("invalid_native_oid"));
    }
    GitOid::from_hex(format, value)
        .ok()
        .filter(|id| !id.is_zero())
        .ok_or_else(|| ApiError::bad("invalid_native_oid"))
}
