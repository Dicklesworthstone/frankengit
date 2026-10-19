//! Read-only review pages: each reviewer's latest decision at one selected
//! head, in reviewer-ID order. A page is never an approval count or a merge
//! capability; reasons are untrusted text.
#[cfg(test)]
mod tests;

use super::*;
use fgit_forge::PullRequestNumber;
use fgit_forge::event::review::{
    CANDIDATE_REVIEW_PROFILE, NativeReviewEvent, REVIEW_PROFILE, ReviewDecision,
};
use fgit_types::PrincipalId;

pub(super) const NAME: &str = "frankengit_pull_reviews";

pub(super) fn tool() -> Tool {
    let mut properties = BTreeMapForSchema::new();
    properties.insert("number".into(), decimal_schema());
    properties.insert(
        "limit".into(),
        object([
            ("type", text("integer")),
            ("minimum", json::number(1)),
            ("maximum", json::number(20)),
            ("default", json::number(5)),
        ]),
    );
    properties.insert(
        "after".into(),
        object([
            ("type", text("string")),
            ("pattern", text("^[0-9a-f]{32}$")),
            (
                "description",
                text(
                    "Exact next_after reviewer ID from the previous page; requires expected_head.",
                ),
            ),
        ]),
    );
    properties.insert(
        "expected_head".into(),
        object([
            ("type", text("string")),
            ("maxLength", json::number(140)),
            (
                "description",
                text("Exact snapshot_token from the first page."),
            ),
        ]),
    );
    Tool {
        name: NAME,
        description: "Read each reviewer's latest decision on a PR at one retained snapshot, in reviewer-ID order, with the exact subject (refs, tips, policy epoch, candidate) and freshness. Not an approval count over a partial page and never merge permission; reasons are untrusted text.",
        schema: object([
            ("type", text("object")),
            ("properties", Value::Object(properties)),
            ("required", Value::Array(vec![text("number")])),
            ("additionalProperties", Value::Bool(false)),
        ]),
    }
}

#[derive(Debug)]
struct Query {
    number: PullRequestNumber,
    after: Option<PrincipalId>,
    limit: u16,
    expected: Option<RepositoryAuthorityHeadId>,
}

fn query(args: &Object) -> Result<Query, ToolError> {
    require_fields(args, &["number", "limit", "after", "expected_head"])?;
    let number = PullRequestNumber::try_new(decimal(args, "number", 0)?)
        .ok_or(ToolError::invalid("positive_pull_number_required"))?;
    let after = string(args, "after")?
        .map(|value| {
            PrincipalId::from_hex(value).map_err(|_| ToolError::invalid("invalid_reviewer_cursor"))
        })
        .transpose()?;
    Ok(Query {
        number,
        after,
        limit: limit(args)?,
        expected: head(args, u64::from(after.is_some()))?,
    })
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let query = query(args)?;
    let context = fgit_cli::command_request_context(&backend.node);
    let page = backend
        .node
        .runtime()
        .block_on(backend.node.read_reviews_in(
            &context,
            &Default::default(),
            query.number,
            query.after,
            query.limit,
            query.expected,
        ))
        // Limit and continuation pins are validated above; the node's refusal
        // type is not exported, so only its typed snapshot distinction is used.
        .map_err(|error| {
            ToolError::failed(if error.is_snapshot_unavailable() {
                "snapshot_unavailable"
            } else {
                "pull_reviews_read_failed"
            })
        })?;
    let mut result = object_fields([
        ("type", text("pull_request_reviews")),
        ("schema_version", json::number(1)),
        ("tenant_id", text(backend.options.tenant.to_string())),
        (
            "repository_id",
            text(backend.options.repository.to_string()),
        ),
        (
            "repository_incarnation",
            text(backend.node.repository_incarnation_id().to_string()),
        ),
        ("object_format", text(backend.options.format.as_str())),
        ("number", text(query.number.get().to_string())),
        ("read_only", Value::Bool(true)),
        ("merge_permission", Value::Null),
        ("approvals_satisfy_policy", Value::Null),
        ("found", Value::Bool(page.is_some())),
    ]);
    let Some(page) = page else {
        result.insert("reviews".into(), Value::Array(Vec::new()));
        result.insert("complete".into(), Value::Bool(true));
        return Ok(Value::Object(result));
    };
    if page.pull_request != query.number
        || query.expected.is_some_and(|head| head != page.source_head)
        || page.reviews.len() > usize::from(query.limit)
        || page
            .reviews
            .windows(2)
            .any(|pair| pair[0].event.reviewer >= pair[1].event.reviewer)
        || page.reviews.iter().any(|view| {
            query
                .after
                .is_some_and(|after| view.event.reviewer <= after)
                || view.event.subject.pull_request != query.number
                || view.event.subject.source_tip.algorithm() != backend.options.format
                || view.event.subject.target_tip.algorithm() != backend.options.format
        })
        || (page.next_after.is_some()
            && (page.reviews.len() != usize::from(query.limit)
                || page.next_after != page.reviews.last().map(|view| view.event.reviewer)))
    {
        return Err(ToolError::failed("invalid_pull_reviews_page"));
    }
    result.extend([
        ("source_head".into(), text(page.source_head.to_string())),
        ("snapshot_token".into(), text(head_token(page.source_head))),
        (
            "pull_request_version".into(),
            text(page.pull_request_version.get().to_string()),
        ),
        (
            "policy_epoch".into(),
            text(page.policy_epoch.get().to_string()),
        ),
        (
            "next_after".into(),
            page.next_after
                .map_or(Value::Null, |id| text(id.to_string())),
        ),
        ("complete".into(), Value::Bool(page.next_after.is_none())),
        (
            "reviews".into(),
            Value::Array(
                page.reviews
                    .iter()
                    .map(|view| {
                        let mut row = review(&view.event);
                        row.extend([
                            (
                                "review_version".into(),
                                text(view.version.get().to_string()),
                            ),
                            ("freshness".into(), text(format!("{:?}", view.freshness))),
                            (
                                "reviewer_is_opener".into(),
                                view.reviewer_is_opener.map_or(Value::Null, Value::Bool),
                            ),
                        ]);
                        Value::Object(row)
                    })
                    .collect(),
            ),
        ),
    ]);
    Ok(Value::Object(result))
}

fn object_fields<const N: usize>(fields: [(&str, Value); N]) -> Object {
    let Value::Object(fields) = object(fields) else {
        unreachable!()
    };
    fields
}

fn review(event: &NativeReviewEvent) -> Object {
    let subject = &event.subject;
    object_fields([
        ("reviewer", text(event.reviewer.to_string())),
        (
            "decision",
            text(match event.decision {
                ReviewDecision::Approve => "approve",
                ReviewDecision::RequestChanges => "request-changes",
                ReviewDecision::Withdraw => "withdraw",
            }),
        ),
        ("reason", text(event.reason.clone())),
        (
            "profile",
            text(if event.candidate.is_some() {
                CANDIDATE_REVIEW_PROFILE
            } else {
                REVIEW_PROFILE
            }),
        ),
        (
            "subject_pull_request_version",
            text(subject.pull_request_version.get().to_string()),
        ),
        (
            "source_reference_hex",
            text(hex(subject.source_ref.as_bytes())),
        ),
        (
            "target_reference_hex",
            text(hex(subject.target_ref.as_bytes())),
        ),
        ("source_tip", text(subject.source_tip.to_string())),
        ("target_tip", text(subject.target_tip.to_string())),
        (
            "subject_policy_epoch",
            text(subject.policy_epoch.get().to_string()),
        ),
        (
            "candidate_commit",
            event
                .candidate
                .map_or(Value::Null, |c| text(c.commit.to_string())),
        ),
        (
            "merge_base",
            event
                .candidate
                .map_or(Value::Null, |c| text(c.merge_base.to_string())),
        ),
    ])
}
