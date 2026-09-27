//! Independently granted, candidate-review-gated coupled publication.
//! Only the native merge driver may publish the PR event and target ref. The
//! named-reviewer set is an immutable request precondition, not cached policy.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::{NodeTools, require_fields};
use super::{mutations as common, pull_writes, review_writes as candidate};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, PrincipalId};
use std::collections::BTreeSet;

pub(super) const NAME: &str = "frankengit_pull_merge_reviewed";
pub(super) const FAST_FORWARD_NAME: &str = "frankengit_pull_fast_forward";
const MAX_REVIEWERS: usize = 32;

pub(super) fn is_tool(name: &str) -> bool {
    name == NAME || name == FAST_FORWARD_NAME
}

pub(super) fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: NAME,
            description: "Atomically publish an exact native merge candidate AND its PR merge event, requiring every explicitly named reviewer to have approved that exact candidate at current PR/policy versions. Requires the independent reviewed-merge grant. Opener/submitter votes cannot satisfy the gate. No unreviewed fallback, force push, latest-tip refresh or repository-wide protection configuration.",
            schema: schema(),
        },
        Tool {
            name: FAST_FORWARD_NAME,
            description: "Fast-forward an existing exact-version PR to its already-admitted source tip under the independent merge grant. Current repository branch protection is enforced by native admission. Requires exact source/target refs and tips; creates no commit or approval, accepts no bundle, does not refresh coordinates, force push, or fall back to another merge method.",
            schema: fast_forward_schema(),
        },
    ]
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

pub(super) fn call(
    backend: &NodeTools,
    name: &str,
    args: &Object,
) -> Result<Value, ToolError> {
    if name == FAST_FORWARD_NAME {
        return call_fast_forward(backend, args);
    }
    if name != NAME {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    call_reviewed(backend, args)
}

fn call_reviewed(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
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


struct FastForwardInput {
    number: PullRequestNumber,
    version: AggregateVersion,
    source_ref: fgit_types::RefName,
    source_tip: fgit_types::GitOid,
    target_ref: fgit_types::RefName,
    target_tip: fgit_types::GitOid,
}

fn parse_fast_forward(
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<FastForwardInput, ToolError> {
    require_fields(
        args,
        &[
            "number",
            "expected_version",
            "idempotency_key",
            "source_reference",
            "source_reference_hex",
            "target_reference",
            "target_reference_hex",
            "expected_source",
            "expected_target",
        ],
    )?;
    common::key(args)?;
    let number = PullRequestNumber::try_new(common::number(args, "number")?)
        .ok_or(ToolError::invalid("positive_pull_number_required"))?;
    let ExpectedVersion::Exactly(version) = common::version(args, false)? else {
        return Err(ToolError::invalid("positive_pr_version_required"));
    };
    Ok(FastForwardInput {
        number,
        version,
        source_ref: pull_writes::branch(args, "source_reference", "source_reference_hex")?,
        source_tip: pull_writes::oid(args, "expected_source", format)?,
        target_ref: pull_writes::branch(args, "target_reference", "target_reference_hex")?,
        target_tip: pull_writes::oid(args, "expected_target", format)?,
    })
}

fn call_fast_forward(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    if !backend.options.writes.merges {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let input = parse_fast_forward(args, backend.options.format)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    let context = backend.node.request_context();
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.fast_forward_pull_request_durable_in(
            &context,
            &session,
            input.number,
            input.version,
            &input.source_ref,
            input.source_tip,
            &input.target_ref,
            input.target_tip,
            Default::default(),
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.insert("type".into(), text("fast_forward_publication"));
    result.insert("method".into(), text("fast-forward-only/v1"));
    result.insert("number".into(), text(input.number.get().to_string()));
    result.insert("expected_version".into(), text(input.version.get().to_string()));
    result.insert("source_reference_hex".into(), text(super::hex(input.source_ref.as_bytes())));
    result.insert("target_reference_hex".into(), text(super::hex(input.target_ref.as_bytes())));
    result.insert("expected_source".into(), text(input.source_tip.to_string()));
    result.insert("expected_target".into(), text(input.target_tip.to_string()));
    result.insert("complete".into(), Value::Bool(true));
    result.insert("atomic".into(), Value::Bool(true));
    result.insert("coupled_pr_and_ref".into(), Value::Bool(true));
    result.insert("creates_commit".into(), Value::Bool(false));
    result.insert("creates_approval".into(), Value::Bool(false));
    result.insert("current_protection_enforced".into(), Value::Bool(true));
    result.insert("current_refs_asserted".into(), Value::Bool(false));
    result.insert("delivery_acknowledged".into(), Value::Null);
    Ok(Value::Object(result))
}

fn fast_forward_schema() -> Value {
    let mut properties = candidate::properties();
    for name in ["policy_epoch", "merge_base", "candidate_commit", "bundle_hex_chunks"] {
        properties.remove(name);
    }
    candidate::candidate_schema(
        properties,
        &[
            "number",
            "expected_version",
            "idempotency_key",
            "expected_source",
            "expected_target",
        ],
    )
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
    #[test]
    fn fast_forward_is_exact_bundle_free_and_separate_from_reviewed_merge() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let Value::Object(mut input) = object([
                ("number", text("7")),
                ("expected_version", text("3")),
                ("idempotency_key", text("ff-key")),
                ("source_reference", text("refs/heads/topic")),
                ("target_reference", text("refs/heads/main")),
                ("expected_source", text("11".repeat(format.digest_len()))),
                ("expected_target", text("22".repeat(format.digest_len()))),
            ]) else {
                unreachable!()
            };
            let parsed = parse_fast_forward(&input, format).unwrap();
            assert_eq!(parsed.number, PullRequestNumber::try_new(7).unwrap());
            assert_eq!(parsed.version, AggregateVersion::try_new(3).unwrap());
            assert_ne!(FAST_FORWARD_NAME, NAME);
            for forbidden in [
                "bundle_hex_chunks",
                "candidate_commit",
                "merge_base",
                "policy_epoch",
                "required_reviewers",
                "force",
                "principal",
            ] {
                let mut bad = input.clone();
                bad.insert(forbidden.into(), text("not-authority"));
                assert!(parse_fast_forward(&bad, format).is_err(), "{forbidden}");
            }
            input.insert("expected_version".into(), text("0"));
            assert!(parse_fast_forward(&input, format).is_err());
            let encoded = fast_forward_schema().encode(16 * 1024).unwrap();
            assert!(json::parse(encoded.as_bytes()).is_ok());
            assert!(!encoded.contains("bundle_hex_chunks"));
            assert!(!encoded.contains("candidate_commit"));
            assert!(!encoded.contains("required_reviewers"));
        }
        assert!(is_tool(NAME));
        assert!(is_tool(FAST_FORWARD_NAME));
        assert!(!is_tool("frankengit_pull_force"));
    }

}
