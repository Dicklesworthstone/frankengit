//! Candidate-bound reviews through canonical admission, never a cached approval.
//! A launch grant sponsors only its own principal's review stream. Source/PR
//! reads, metadata writes, outcome recovery and merge publication are separate.
use super::super::json::{self, Object, Value, object, text};
use super::super::protocol::{Tool, ToolError};
use super::{NodeTools, decimal_schema, hex, require_fields, unhex};
use super::{mutations as common, pull_writes};
use fgit_forge::event::review::{
    CANDIDATE_REVIEW_PROFILE, CandidateBinding, CandidateReviewCommand, ReviewCommand,
    ReviewDecision, ReviewSubject,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_types::{GitHashAlgorithm, PolicyEpoch};

pub(super) const NAME: &str = "frankengit_pull_review";
const MAX_CHUNKS: usize = 3;
const CHUNK_BYTES: usize = 8 * 1024;
pub(super) const MAX_BUNDLE_BYTES: usize = MAX_CHUNKS * CHUNK_BYTES;
pub(super) const CANDIDATE_FIELDS: &[&str] = &[
    "number",
    "expected_version",
    "idempotency_key",
    "source_reference",
    "source_reference_hex",
    "target_reference",
    "target_reference_hex",
    "expected_source",
    "expected_target",
    "merge_base",
    "candidate_commit",
    "policy_epoch",
    "bundle_hex_chunks",
];

pub(super) fn tools() -> Vec<Tool> {
    vec![Tool {
        name: NAME,
        description: "Approve, request changes, or withdraw your launch-bound principal's exact candidate review. Requires its independent review-write grant, exact PR and reviewer versions, tips, policy epoch and candidate. Approval/change requests verify an inline native bundle; withdrawal uses the exact prior subject without a bundle. Does not move refs or merge code.",
        schema: schema(),
    }]
}

/// Complete candidate coordinates are client input, not a latest-tip query.
/// These byte/type adapters confer neither a review nor publication authority.
pub(super) fn subject(
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<(ReviewSubject, CandidateBinding), ToolError> {
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::try_new(common::number(args, "number")?)
            .ok_or(ToolError::invalid("positive_pull_number_required"))?,
        pull_request_version: AggregateVersion::try_new(common::number(args, "expected_version")?)
            .ok_or(ToolError::invalid("positive_pr_version_required"))?,
        source_ref: pull_writes::branch(args, "source_reference", "source_reference_hex")?,
        target_ref: pull_writes::branch(args, "target_reference", "target_reference_hex")?,
        source_tip: pull_writes::oid(args, "expected_source", format)?,
        target_tip: pull_writes::oid(args, "expected_target", format)?,
        policy_epoch: PolicyEpoch::try_new(common::number(args, "policy_epoch")?)
            .map_err(|_| ToolError::invalid("invalid_policy_epoch"))?,
    };
    let candidate = CandidateBinding {
        merge_base: pull_writes::oid(args, "merge_base", format)?,
        commit: pull_writes::oid(args, "candidate_commit", format)?,
    };
    candidate
        .validate(&subject)
        .map_err(|_| ToolError::invalid("invalid_candidate_binding"))?;
    Ok((subject, candidate))
}

/// The existing MCP source-publication envelope: three ordered 8 KiB chunks.
/// Splitting preserves the 16 KiB JSON string ceiling without widening it.
pub(super) fn bundle(args: &Object) -> Result<Vec<u8>, ToolError> {
    let Some(Value::Array(chunks)) = args.get("bundle_hex_chunks") else {
        return Err(ToolError::invalid("bundle_chunks_required"));
    };
    if chunks.is_empty() || chunks.len() > MAX_CHUNKS {
        return Err(ToolError::invalid("bundle_chunk_limit"));
    }
    let mut length = 0_usize;
    for chunk in chunks {
        let value = chunk
            .text()
            .ok_or(ToolError::invalid("bundle_chunk_must_be_hex"))?;
        if value.is_empty()
            || value.len() % 2 != 0
            || value.len() > CHUNK_BYTES * 2
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ToolError::invalid("invalid_bundle_chunk"));
        }
        length = length
            .checked_add(value.len() / 2)
            .filter(|n| *n <= MAX_BUNDLE_BYTES)
            .ok_or(ToolError::invalid("bundle_byte_limit"))?;
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ToolError::failed("allocation_refused"))?;
    for chunk in chunks {
        let value = chunk
            .text()
            .ok_or(ToolError::invalid("bundle_chunk_must_be_hex"))?;
        bytes.extend_from_slice(&unhex(value, CHUNK_BYTES)?);
    }
    Ok(bytes)
}

fn parse(
    args: &Object,
    format: GitHashAlgorithm,
) -> Result<(CandidateReviewCommand, Option<Vec<u8>>), ToolError> {
    let mut allowed = CANDIDATE_FIELDS.to_vec();
    allowed.extend(["review_version", "decision", "reason"]);
    require_fields(args, &allowed)?;
    common::key(args)?;
    let (subject, candidate) = subject(args, format)?;
    let version = common::number(args, "review_version")?;
    let expected_version = if version == 0 {
        ExpectedVersion::NewStream
    } else {
        let version = AggregateVersion::try_new(version)
            .ok_or(ToolError::invalid("invalid_review_version"))?;
        version
            .next()
            .map_err(|_| ToolError::invalid("review_version_exhausted"))?;
        ExpectedVersion::Exactly(version)
    };
    let decision = match common::required(args, "decision")? {
        "approve" => ReviewDecision::Approve,
        "request-changes" => ReviewDecision::RequestChanges,
        "withdraw" => ReviewDecision::Withdraw,
        _ => return Err(ToolError::invalid("invalid_review_decision")),
    };
    let bundle = if decision == ReviewDecision::Withdraw {
        if version == 0 || args.contains_key("bundle_hex_chunks") {
            return Err(ToolError::invalid(
                "withdraw_requires_prior_review_without_bundle",
            ));
        }
        None
    } else {
        Some(bundle(args)?)
    };
    let reason = common::body(args, "reason")?.unwrap_or_default();
    Ok((
        CandidateReviewCommand {
            candidate,
            review: ReviewCommand {
                expected_version,
                subject,
                decision,
                reason,
            },
        },
        bundle,
    ))
}

pub(super) fn decision_name(decision: ReviewDecision) -> &'static str {
    match decision {
        ReviewDecision::Approve => "approve",
        ReviewDecision::RequestChanges => "request-changes",
        ReviewDecision::Withdraw => "withdraw",
    }
}
pub(super) fn subject_fields(subject: &ReviewSubject, candidate: CandidateBinding) -> Object {
    let Value::Object(fields) = object([
        ("number", text(subject.pull_request.get().to_string())),
        (
            "expected_version",
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
        ("expected_source", text(subject.source_tip.to_string())),
        ("expected_target", text(subject.target_tip.to_string())),
        ("policy_epoch", text(subject.policy_epoch.get().to_string())),
        ("candidate_commit", text(candidate.commit.to_string())),
        ("merge_base", text(candidate.merge_base.to_string())),
    ]) else {
        unreachable!()
    };
    fields
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    // Direct adapter callers have the same ceiling as discovery and dispatch.
    if !backend.options.writes.reviews {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    let (command, bundle) = parse(args, backend.options.format)?;
    let session = common::session(backend, common::key(args)?)?;
    let principal = session
        .authenticated_session()
        .ok_or(ToolError::invalid("principal_not_bound"))?
        .principal_id();
    command
        .proposed_event(principal, backend.options.format)
        .map_err(|_| ToolError::invalid("invalid_candidate_review"))?;
    let context = backend.node.request_context();
    let (tx, terminal) = backend
        .node
        .runtime()
        .block_on(backend.node.admit_candidate_review_durable_in(
            &context,
            &session,
            &command,
            bundle.as_deref(),
            Default::default(),
        ))
        .map_err(|_| ToolError::uncertain("mutation_outcome_unknown"))?;
    // This is a verified historical decision, not a claim that today's policy
    // is satisfied. In particular, do not read latest reviews after committing.
    let mut result = common::binding(backend, principal, false);
    result.extend(common::terminal(tx, &terminal));
    result.extend(subject_fields(&command.review.subject, command.candidate));
    result.insert("type".into(), text("candidate_review_publication"));
    result.insert("profile".into(), text(CANDIDATE_REVIEW_PROFILE));
    result.insert(
        "decision".into(),
        text(decision_name(command.review.decision)),
    );
    result.insert(
        "expected_review_version".into(),
        text(
            match command.review.expected_version {
                ExpectedVersion::NewStream => 0,
                ExpectedVersion::Exactly(version) => version.get(),
            }
            .to_string(),
        ),
    );
    result.insert("complete".into(), Value::Bool(true));
    result.insert("refs_changed".into(), Value::Bool(false));
    result.insert("approvals_satisfy_policy".into(), Value::Null);
    result.insert("delivery_acknowledged".into(), Value::Null);
    result.insert("historical_outcome".into(), Value::Bool(true));
    Ok(Value::Object(result))
}

pub(super) fn properties() -> Object {
    let mut properties = common::base_properties();
    properties.insert("policy_epoch".into(), decimal_schema());
    for name in ["source_reference", "target_reference"] {
        properties.insert(
            name.into(),
            object([
                ("type", text("string")),
                ("maxLength", json::number(4096)),
                ("pattern", text("^refs/heads/")),
            ]),
        );
    }
    for name in ["source_reference_hex", "target_reference_hex"] {
        properties.insert(
            name.into(),
            object([
                ("type", text("string")),
                ("maxLength", json::number(8192)),
                ("pattern", text("^(?:[0-9a-f]{2})+$")),
            ]),
        );
    }
    for name in [
        "expected_source",
        "expected_target",
        "merge_base",
        "candidate_commit",
    ] {
        properties.insert(name.into(), object([("type", text("string")),
            ("pattern", text("^(?:[0-9a-f]{40}|[0-9a-f]{64})$")),
            ("description", text("Explicit nonzero native OID in the launch-bound repository format. No current-tip substitution."))]));
    }
    properties.insert("bundle_hex_chunks".into(), object([("type", text("array")),
        ("minItems", json::number(1)), ("maxItems", json::number(MAX_CHUNKS as u64)),
        ("items", object([("type", text("string")), ("minLength", json::number(2)),
            ("maxLength", json::number((CHUNK_BYTES * 2) as u64)), ("pattern", text("^(?:[0-9a-f]{2})+$"))])),
        ("description", text("Ordered chunks of ONE complete native candidate bundle. At most three nonempty 8192-byte chunks, 24 KiB total. No host paths or URLs; whole-message bounds still apply."))]));
    properties
}
pub(super) fn candidate_schema(properties: Object, required: &[&str]) -> Value {
    let mut schema = common::input_schema(properties, required);
    if let Value::Object(fields) = &mut schema {
        fields.insert(
            "allOf".into(),
            Value::Array(
                [
                    ("source_reference", "source_reference_hex"),
                    ("target_reference", "target_reference_hex"),
                ]
                .into_iter()
                .map(|(plain, encoded)| {
                    object([(
                        "oneOf",
                        Value::Array(vec![
                            object([("required", Value::Array(vec![text(plain)]))]),
                            object([("required", Value::Array(vec![text(encoded)]))]),
                        ]),
                    )])
                })
                .collect(),
            ),
        );
    }
    schema
}
fn schema() -> Value {
    let mut properties = properties();
    properties.insert("review_version".into(), decimal_schema());
    properties.insert(
        "decision".into(),
        object([
            ("type", text("string")),
            (
                "enum",
                Value::Array(vec![
                    text("approve"),
                    text("request-changes"),
                    text("withdraw"),
                ]),
            ),
        ]),
    );
    properties.insert(
        "reason".into(),
        common::text_schema(common::MAX_TEXT_BYTES as u64),
    );
    let mut schema = candidate_schema(
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
            "review_version",
            "decision",
        ],
    );
    if let Value::Object(fields) = &mut schema {
        fields.insert(
            "oneOf".into(),
            Value::Array(vec![
                object([
                    (
                        "properties",
                        object([(
                            "decision",
                            object([(
                                "enum",
                                Value::Array(vec![text("approve"), text("request-changes")]),
                            )]),
                        )]),
                    ),
                    ("required", Value::Array(vec![text("bundle_hex_chunks")])),
                ]),
                object([
                    (
                        "properties",
                        object([("decision", object([("const", text("withdraw"))]))]),
                    ),
                    (
                        "not",
                        object([("required", Value::Array(vec![text("bundle_hex_chunks")]))]),
                    ),
                ]),
            ]),
        );
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(format: GitHashAlgorithm) -> Object {
        let Value::Object(args) = object([
            ("number", text("7")),
            ("expected_version", text("1")),
            ("idempotency_key", text("private-key")),
            ("source_reference", text("refs/heads/topic")),
            ("target_reference", text("refs/heads/main")),
            ("expected_source", text("11".repeat(format.digest_len()))),
            ("expected_target", text("22".repeat(format.digest_len()))),
            ("merge_base", text("33".repeat(format.digest_len()))),
            ("candidate_commit", text("44".repeat(format.digest_len()))),
            ("policy_epoch", text("1")),
            ("review_version", text("0")),
            ("decision", text("approve")),
            ("bundle_hex_chunks", Value::Array(vec![text("abcd")])),
        ]) else {
            unreachable!()
        };
        args
    }
    #[test]
    fn review_requires_all_coordinates_and_never_accepts_an_injected_principal() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let good = args(format);
            let (command, bytes) = parse(&good, format).unwrap();
            assert_eq!(bytes.unwrap(), vec![0xab, 0xcd]);
            assert_eq!(command.review.expected_version, ExpectedVersion::NewStream);
            for field in good.keys() {
                let mut bad = good.clone();
                bad.remove(field);
                assert!(parse(&bad, format).is_err(), "missing {field}");
            }
            for field in [
                "principal",
                "reviewer",
                "tenant_id",
                "repository_id",
                "bundle_path",
                "force",
                "required_reviewers",
            ] {
                let mut bad = good.clone();
                bad.insert(field.into(), text("not-authority"));
                assert!(parse(&bad, format).is_err(), "injected {field}");
            }
            let mut bad = good.clone();
            bad.insert(
                "source_reference_hex".into(),
                text(hex(b"refs/heads/topic")),
            );
            assert!(parse(&bad, format).is_err());
            let mut raw = good.clone();
            raw.remove("source_reference");
            raw.insert(
                "source_reference_hex".into(),
                text(hex(b"refs/heads/topic-\xff")),
            );
            assert!(parse(&raw, format).is_ok());
        }
    }
    #[test]
    fn withdrawals_require_a_prior_exact_review_and_never_revalidate_a_new_bundle() {
        let format = GitHashAlgorithm::Sha1;
        let mut input = args(format);
        input.insert("decision".into(), text("withdraw"));
        assert!(parse(&input, format).is_err());
        input.remove("bundle_hex_chunks");
        assert!(parse(&input, format).is_err());
        input.insert("review_version".into(), text("1"));
        let (command, bytes) = parse(&input, format).unwrap();
        assert!(bytes.is_none());
        assert_eq!(command.review.decision, ReviewDecision::Withdraw);
        input.insert("decision".into(), text("request-changes"));
        assert!(parse(&input, format).is_err());
    }
    #[test]
    fn integer_hash_and_text_bounds_fail_before_admission() {
        let format = GitHashAlgorithm::Sha256;
        let good = args(format);
        for field in [
            "number",
            "expected_version",
            "policy_epoch",
            "review_version",
        ] {
            for value in [
                text("01"),
                text("-1"),
                text("18446744073709551616"),
                json::number(1),
            ] {
                let mut bad = good.clone();
                bad.insert(field.into(), value);
                assert!(parse(&bad, format).is_err());
            }
        }
        let mut bad = good.clone();
        bad.insert("review_version".into(), text(u64::MAX.to_string()));
        assert!(parse(&bad, format).is_err());
        for field in [
            "expected_source",
            "expected_target",
            "merge_base",
            "candidate_commit",
        ] {
            for value in ["00".repeat(32), "11".repeat(20), "AA".repeat(32)] {
                let mut bad = good.clone();
                bad.insert(field.into(), text(value));
                assert!(parse(&bad, format).is_err());
            }
        }
        for reason in ["x\0y".into(), "é".repeat(common::MAX_TEXT_BYTES)] {
            let mut bad = good.clone();
            bad.insert("reason".into(), text(reason));
            assert!(parse(&bad, format).is_err());
        }
    }
    #[test]
    fn complete_maximum_bundle_fits_unchanged_json_limits_and_bad_chunks_refuse() {
        let format = GitHashAlgorithm::Sha1;
        let mut input = args(format);
        let chunks = vec![text("ab".repeat(CHUNK_BYTES)); MAX_CHUNKS];
        input.insert("bundle_hex_chunks".into(), Value::Array(chunks));
        let encoded = Value::Object(input.clone())
            .encode(json::MAX_INPUT)
            .unwrap();
        let decoded = json::parse(encoded.as_bytes()).unwrap();
        let (_, bundle) = parse(decoded.object().unwrap(), format).unwrap();
        assert_eq!(bundle.unwrap(), vec![0xab; MAX_BUNDLE_BYTES]);
        for value in [
            Value::Null,
            text("abcd"),
            Value::Array(vec![]),
            Value::Array(vec![text("ab"); MAX_CHUNKS + 1]),
            Value::Array(vec![text("ab".repeat(CHUNK_BYTES + 1))]),
            Value::Array(vec![text("")]),
            Value::Array(vec![text("a")]),
            Value::Array(vec![text("AB")]),
            Value::Array(vec![json::number(1)]),
        ] {
            let mut bad = input.clone();
            bad.insert("bundle_hex_chunks".into(), value);
            assert!(parse(&bad, format).is_err());
        }
    }
    #[test]
    fn discovery_describes_conditional_bundle_and_lossless_reference_requirements() {
        let descriptor = schema();
        let fields = descriptor.object().unwrap();
        assert_eq!(fields["additionalProperties"], Value::Bool(false));
        assert!(fields.contains_key("allOf") && fields.contains_key("oneOf"));
        let properties = fields["properties"].object().unwrap();
        assert!(!properties.contains_key("principal") && !properties.contains_key("bundle_path"));
        assert_eq!(
            properties["bundle_hex_chunks"].object().unwrap()["maxItems"].unsigned(),
            Some(3)
        );
    }
}
