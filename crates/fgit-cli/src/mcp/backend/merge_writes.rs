//! Independently granted, candidate-review-gated coupled publication.
//! Only the native merge driver may publish the PR event and target ref. The
//! named-reviewer set is an immutable request precondition, not cached policy.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::{NodeTools, require_fields};
use super::{mutations as common, review_writes as candidate};
use fgit_forge::ExpectedVersion;
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId};
use std::collections::BTreeSet;

pub(super) const NAME: &str = "frankengit_pull_merge_reviewed";
const MAX_REVIEWERS: usize = 32;

pub(super) fn tools() -> Vec<Tool> {
    vec![Tool {
        name: NAME,
        description: "Atomically publish an exact native merge candidate AND its PR merge event, requiring every explicitly named reviewer to have approved that exact candidate at current PR/policy versions. Requires the independent reviewed-merge grant. Opener/submitter votes cannot satisfy the gate. No unreviewed fallback, force push, latest-tip refresh or repository-wide protection configuration.",
        schema: schema(),
    }]
}

struct Input {
    subject: ReviewSubject,
    candidate: CandidateBinding,
    bundle: Vec<u8>,
    reviewers: Vec<PrincipalId>,
}
fn parse(
    args: &Object,
    format: GitHashAlgorithm,
    principal: PrincipalId,
) -> Result<Input, ToolError> {
    let mut allowed = candidate::CANDIDATE_FIELDS.to_vec();
    allowed.push("required_reviewers");
    require_fields(args, &allowed)?;
    common::key(args)?;
    let (subject, candidate) = candidate::subject(args, format)?;
    subject
        .pull_request_version
        .next()
        .map_err(|_| ToolError::invalid("pr_version_exhausted"))?;
    let Some(Value::Array(reviewers)) = args.get("required_reviewers") else {
        return Err(ToolError::invalid("required_reviewers_missing"));
    };
    if reviewers.is_empty() || reviewers.len() > MAX_REVIEWERS {
        return Err(ToolError::invalid("required_reviewer_limit"));
    }
    let mut required = BTreeSet::new();
    for reviewer in reviewers {
        let value = reviewer
            .text()
            .ok_or(ToolError::invalid("invalid_reviewer_id"))?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ToolError::invalid("invalid_reviewer_id"));
        }
        let reviewer =
            PrincipalId::from_hex(value).map_err(|_| ToolError::invalid("invalid_reviewer_id"))?;
        if reviewer == principal {
            return Err(ToolError::invalid("submitter_cannot_satisfy_review_gate"));
        }
        if !required.insert(reviewer) {
            return Err(ToolError::invalid("duplicate_required_reviewer"));
        }
    }
    Ok(Input {
        subject,
        candidate,
        bundle: candidate::bundle(args)?,
        reviewers: required.into_iter().collect(),
    })
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.merges {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let principal = backend
        .options
        .principal
        .ok_or(ToolError::invalid("principal_not_bound"))?;
    let input = parse(args, backend.options.format, principal)?;
    let context = backend.node.request_context();
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.apply_reviewed_merge_bundle_durable_in(
            &context,
            principal,
            common::required(args, "idempotency_key")?.as_bytes(),
            input.subject.pull_request,
            ExpectedVersion::Exactly(input.subject.pull_request_version),
            &input.candidate.merge(&input.subject),
            &input.bundle,
            input.subject.policy_epoch,
            &input.reviewers,
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    // No post-commit metadata query: a moved ref, stopped service, or lost
    // response cannot change the historical decision for this exact key.
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.extend(candidate::subject_fields(&input.subject, input.candidate));
    result.insert("type".into(), text("reviewed_merge_publication"));
    result.insert("profile".into(), text("named-candidate-reviewers-v1"));
    result.insert(
        "required_reviewers".into(),
        Value::Array(
            input
                .reviewers
                .iter()
                .map(|id| text(id.to_string()))
                .collect(),
        ),
    );
    result.insert("complete".into(), Value::Bool(true));
    result.insert("atomic".into(), Value::Bool(true));
    result.insert("coupled_pr_and_ref".into(), Value::Bool(true));
    result.insert(
        "ref_transaction_committed".into(),
        Value::Bool(matches!(
            terminal.outcome,
            DecisionOutcome::Committed { .. }
        )),
    );
    result.insert("current_refs_asserted".into(), Value::Bool(false));
    result.insert("historical_outcome".into(), Value::Bool(true));
    result.insert(
        "repository_wide_branch_protection".into(),
        Value::Bool(false),
    );
    result.insert("delivery_acknowledged".into(), Value::Null);
    Ok(Value::Object(result))
}

fn schema() -> Value {
    let mut properties = candidate::properties();
    properties.insert("required_reviewers".into(), object([("type", text("array")),
        ("minItems", json::number(1)), ("maxItems", json::number(MAX_REVIEWERS as u64)),
        ("uniqueItems", Value::Bool(true)),
        ("items", object([("type", text("string")), ("pattern", text("^[0-9a-f]{32}$"))])),
        ("description", text("Every listed principal must currently approve the exact candidate. Distinct, at most 32; neither PR opener nor submitting principal can satisfy the gate. The set is sealed into retry identity."))]));
    candidate::candidate_schema(
        properties,
        &[
            "number",
            "expected_version",
            "idempotency_key",
            "expected_source",
            "expected_target",
            "merge_base",
            "candidate_commit",
            "policy_epoch",
            "bundle_hex_chunks",
            "required_reviewers",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn principal(byte: u8) -> PrincipalId {
        PrincipalId::from_bytes([byte; 16])
    }
    fn args(format: GitHashAlgorithm) -> Object {
        let Value::Object(args) = object([
            ("number", text("7")),
            ("expected_version", text("1")),
            ("idempotency_key", text("merge-key")),
            ("source_reference", text("refs/heads/topic")),
            ("target_reference", text("refs/heads/main")),
            ("expected_source", text("11".repeat(format.digest_len()))),
            ("expected_target", text("22".repeat(format.digest_len()))),
            ("merge_base", text("33".repeat(format.digest_len()))),
            ("candidate_commit", text("44".repeat(format.digest_len()))),
            ("policy_epoch", text("1")),
            ("bundle_hex_chunks", Value::Array(vec![text("abcd")])),
            (
                "required_reviewers",
                Value::Array(vec![
                    text(principal(0x52).to_string()),
                    text(principal(0x51).to_string()),
                ]),
            ),
        ]) else {
            unreachable!()
        };
        args
    }
    #[test]
    fn every_merge_coordinate_and_an_explicit_nonempty_reviewer_set_are_required() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let good = args(format);
            let parsed = parse(&good, format, principal(0x50)).unwrap();
            assert_eq!(parsed.reviewers, vec![principal(0x51), principal(0x52)]);
            assert_eq!(parsed.bundle, vec![0xab, 0xcd]);
            for field in good.keys() {
                let mut bad = good.clone();
                bad.remove(field);
                assert!(
                    parse(&bad, format, principal(0x50)).is_err(),
                    "missing {field}"
                );
            }
            for field in [
                "principal",
                "reviewer",
                "review_version",
                "decision",
                "reason",
                "force",
                "bundle_path",
            ] {
                let mut bad = good.clone();
                bad.insert(field.into(), text("no implicit authority"));
                assert!(
                    parse(&bad, format, principal(0x50)).is_err(),
                    "injected {field}"
                );
            }
        }
    }
    #[test]
    fn missing_duplicate_self_malformed_and_over_limit_reviewers_fail_closed() {
        let format = GitHashAlgorithm::Sha1;
        let good = args(format);
        for reviewers in [
            Value::Null,
            text("all"),
            Value::Array(vec![]),
            Value::Array(vec![text(principal(0x50).to_string())]),
            Value::Array(vec![text(principal(0x51).to_string()); 2]),
            Value::Array(vec![text("AB".repeat(16))]),
            Value::Array(vec![json::number(1)]),
            Value::Array(vec![text("bad")]),
            Value::Array((1..=33).map(|n| text(principal(n).to_string())).collect()),
        ] {
            let mut bad = good.clone();
            bad.insert("required_reviewers".into(), reviewers);
            assert!(parse(&bad, format, principal(0x50)).is_err());
        }
        let mut edge = good.clone();
        edge.insert(
            "required_reviewers".into(),
            Value::Array((1..=32).map(|n| text(principal(n).to_string())).collect()),
        );
        assert_eq!(
            parse(&edge, format, principal(0x50))
                .unwrap()
                .reviewers
                .len(),
            MAX_REVIEWERS
        );
        let mut exhausted = good;
        exhausted.insert("expected_version".into(), text(u64::MAX.to_string()));
        assert!(parse(&exhausted, format, principal(0x50)).is_err());
    }
    #[test]
    fn reviewer_order_is_not_identity_but_changing_the_set_is_not_silently_discarded() {
        let format = GitHashAlgorithm::Sha256;
        let first = args(format);
        let mut second = first.clone();
        let Value::Array(reviewers) = second.get_mut("required_reviewers").unwrap() else {
            unreachable!()
        };
        reviewers.reverse();
        assert_eq!(
            parse(&first, format, principal(0x50)).unwrap().reviewers,
            parse(&second, format, principal(0x50)).unwrap().reviewers
        );
        second.insert(
            "required_reviewers".into(),
            Value::Array(vec![text(principal(0x53).to_string())]),
        );
        assert_ne!(
            parse(&first, format, principal(0x50)).unwrap().reviewers,
            parse(&second, format, principal(0x50)).unwrap().reviewers
        );
        let encoded = schema().encode(16 * 1024).unwrap();
        assert!(json::parse(encoded.as_bytes()).is_ok());
        let descriptor = schema();
        let fields = descriptor.object().unwrap();
        assert_eq!(fields["additionalProperties"], Value::Bool(false));
        let Value::Array(required) = &fields["required"] else {
            unreachable!()
        };
        assert!(
            required.contains(&text("required_reviewers"))
                && required.contains(&text("bundle_hex_chunks"))
        );
    }
}
