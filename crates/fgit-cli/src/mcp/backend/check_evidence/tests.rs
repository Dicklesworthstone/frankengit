use super::*;
use fgit_forge::AggregateVersion;
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_node::{PullRequestCheckEvidence, PullRequestChecksPage, WorkflowCheckSummary};
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName};
use std::collections::BTreeSet;

fn args<const N: usize>(values: [(&str, Value); N]) -> Object {
    object(values).object().unwrap().clone()
}

fn observation(format: GitHashAlgorithm, bytes: &[u8]) -> PullRequestCheckEvidence {
    let oid = |byte: &str| {
        GitOid::from_hex(
            format,
            &byte.repeat(if format == GitHashAlgorithm::Sha1 {
                20
            } else {
                32
            }),
        )
        .unwrap()
    };
    PullRequestCheckEvidence {
        page: PullRequestChecksPage {
            source_head: parse_head(&format!("alg:2:{}", "31".repeat(32))).unwrap(),
            number: PullRequestNumber::try_new(7).unwrap(),
            pull_request_version: AggregateVersion::FIRST,
            source_ref: RefName::try_new(b"refs/heads/topic\xff").unwrap(),
            target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            source_tip: oid("11"),
            target_tip: oid("22"),
            source_current: true,
            checks: vec![WorkflowCheckSummary {
                id: WorkflowCheckId::from_bytes([1; 32]),
                publisher: PrincipalId::from_bytes([2; 16]),
                run_id: [3; 32],
                attempt_id: [4; 32],
                graph_root: [5; 32],
                job: "<script>\"diagnose\"é".into(),
                conclusion: WorkflowCheckConclusion::Failure,
                evidence_sha256: fgit_crypto::sha256_digest(bytes),
                evidence_bytes: bytes.len() as u64,
            }],
            next_after: None,
        },
        evidence: bytes.to_vec(),
    }
}

fn selection(result: &PullRequestCheckEvidence) -> Object {
    args([
        ("number", text(result.page.number.get().to_string())),
        ("check", text(result.page.checks[0].id.to_string())),
        ("expected_head", text(head_token(result.page.source_head))),
        (
            "expected_evidence_sha256",
            text(hex(&result.page.checks[0].evidence_sha256)),
        ),
    ])
}

#[test]
fn evidence_catalog_and_served_schema_agree_on_exact_required_selection() {
    let served = tool();
    let names = all_registered_tool_names();
    assert_eq!(names.iter().filter(|name| **name == NAME).count(), 1);
    let contract = fgit_schema::mcp::find_tool(NAME).unwrap();
    let schema = served.schema.object().unwrap();
    let properties = schema["properties"].object().unwrap();
    assert_eq!(
        properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        contract
            .input_fields
            .iter()
            .map(|field| field.name)
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(schema["additionalProperties"], Value::Bool(false));
    assert_eq!(
        schema["required"],
        Value::Array(REQUIRED.iter().map(|name| text(*name)).collect())
    );
    assert_eq!(
        contract
            .input_fields
            .iter()
            .filter(|field| field.required)
            .map(|field| field.name)
            .collect::<BTreeSet<_>>(),
        REQUIRED.iter().copied().collect::<BTreeSet<_>>()
    );
    for field in contract.input_fields {
        let property = properties[field.name].object().unwrap();
        assert_eq!(property["type"].text(), Some(field.field_type));
        if let Some(max) = field.max_bytes {
            assert_eq!(property["maxLength"].unsigned(), Some(u64::from(max)));
        }
        assert_eq!(property.get("pattern").and_then(Value::text), field.pattern);
    }
    let limit = properties["limit"].object().unwrap();
    assert_eq!(limit["minimum"].unsigned(), Some(1));
    assert_eq!(limit["maximum"].unsigned(), Some(MAX_SNIPPET_BYTES));
    assert_eq!(limit["default"].unsigned(), Some(MAX_SNIPPET_BYTES));
    assert_eq!(contract.description, served.description);
}

#[test]
fn evidence_arguments_refuse_ambient_identity_unbounded_ranges_and_aliases() {
    let result = observation(GitHashAlgorithm::Sha1, b"evidence");
    let valid = selection(&result);
    let query = parse(&valid).unwrap();
    assert_eq!(query.offset, 0);
    assert_eq!(query.limit, 65536);
    for required in REQUIRED {
        let mut absent = valid.clone();
        absent.remove(*required);
        assert!(parse(&absent).is_err(), "{required}");
    }
    for extra in [
        "artifact_id",
        "path",
        "artifact_root",
        "tenant_id",
        "repository_id",
        "incarnation",
        "principal",
        "idempotency_key",
        "source_ref",
        "evidence",
    ] {
        let mut invalid = valid.clone();
        invalid.insert(extra.into(), text("caller-controlled"));
        assert_eq!(parse(&invalid).unwrap_err().code, "unknown_argument");
    }
    for name in ["number", "offset"] {
        for value in [
            text("01"),
            text("-1"),
            text(" 1"),
            text("18446744073709551616"),
            json::number(1),
            Value::Null,
        ] {
            let mut invalid = valid.clone();
            invalid.insert(name.into(), value);
            assert!(parse(&invalid).is_err(), "{name}");
        }
    }
    for label in [
        "check/".into(),
        result.page.checks[0].id.to_string().to_uppercase(),
        format!("{}x", result.page.checks[0].id),
        format!("check/{}1", "0".repeat(51)),
        "latest".into(),
    ] {
        let mut invalid = valid.clone();
        invalid.insert("check".into(), text(label));
        assert_eq!(parse(&invalid).unwrap_err().code, "invalid_check_id");
    }
    for token in [
        "latest".into(),
        format!("alg:02:{}", "31".repeat(32)),
        format!("alg:2:{}", "AB".repeat(32)),
        "alg:2:".into(),
        format!("alg:2:{}", "31".repeat(65)),
    ] {
        let mut invalid = valid.clone();
        invalid.insert("expected_head".into(), text(token));
        assert_eq!(parse(&invalid).unwrap_err().code, "invalid_snapshot_token");
    }
    for digest in [
        "ab".repeat(31),
        "AB".repeat(32),
        format!("sha256:{}", "ab".repeat(32)),
        "../evidence".into(),
    ] {
        let mut invalid = valid.clone();
        invalid.insert("expected_evidence_sha256".into(), text(digest));
        assert_eq!(parse(&invalid).unwrap_err().code, "invalid_evidence_digest");
    }
    for value in [json::number(0), json::number(65537), text("1"), Value::Null] {
        let mut invalid = valid.clone();
        invalid.insert("limit".into(), value);
        assert_eq!(
            parse(&invalid).unwrap_err().code,
            "invalid_check_evidence_limit"
        );
    }
    let mut boundary = valid;
    boundary.insert("offset".into(), text(u64::MAX.to_string()));
    boundary.insert("limit".into(), json::number(1));
    assert_eq!(parse(&boundary).unwrap().offset, u64::MAX);
}

#[test]
fn canonical_selection_checks_the_complete_body_before_any_prefix_can_be_disclosed() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let result = observation(format, b"\0prefix\xfftrailing-data");
        let mut arguments = selection(&result);
        arguments.insert("limit".into(), json::number(1));
        let query = parse(&arguments).unwrap();
        assert!(output::Selected::new(&query, &result, format).is_ok());
        let mut invalid = result.clone();
        *invalid.evidence.last_mut().unwrap() ^= 1;
        assert_eq!(
            output::Selected::new(&query, &invalid, format)
                .unwrap_err()
                .code,
            "check_evidence_invalid"
        );
        let mut invalid = result.clone();
        invalid.page.checks[0].evidence_bytes += 1;
        assert!(output::Selected::new(&query, &invalid, format).is_err());
        let mut wrong_digest = query.clone();
        wrong_digest.expected_evidence[0] ^= 1;
        assert_eq!(
            output::Selected::new(&wrong_digest, &result, format)
                .unwrap_err()
                .code,
            "check_evidence_identity_mismatch"
        );
        let wrong_format = if format == GitHashAlgorithm::Sha1 {
            GitHashAlgorithm::Sha256
        } else {
            GitHashAlgorithm::Sha1
        };
        assert_eq!(
            output::Selected::new(&query, &result, wrong_format)
                .unwrap_err()
                .code,
            "check_evidence_identity_mismatch"
        );
    }
}

#[test]
fn wrong_or_stale_page_coordinates_never_become_empty_success() {
    let format = GitHashAlgorithm::Sha256;
    let original = observation(format, b"selected observation");
    let query = parse(&selection(&original)).unwrap();
    let mut cases = Vec::new();
    let mut changed = original.clone();
    changed.page.source_head = parse_head(&format!("alg:2:{}", "32".repeat(32))).unwrap();
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.number = PullRequestNumber::try_new(8).unwrap();
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.source_current = false;
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.checks.clear();
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.checks.push(changed.page.checks[0].clone());
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.next_after = Some(changed.page.checks[0].id);
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.checks[0].id = WorkflowCheckId::from_bytes([9; 32]);
    cases.push(changed);
    let mut changed = original.clone();
    changed.page.target_ref = changed.page.source_ref.clone();
    cases.push(changed);
    for invalid in cases {
        assert_eq!(
            output::Selected::new(&query, &invalid, format)
                .unwrap_err()
                .code,
            "check_evidence_invalid"
        );
    }
}

#[test]
fn empty_native_evidence_refuses_and_exact_eof_is_distinct_from_beyond_eof() {
    let format = GitHashAlgorithm::Sha256;
    let empty = observation(format, b"");
    let query = parse(&selection(&empty)).unwrap();
    assert_eq!(
        output::Selected::new(&query, &empty, format)
            .unwrap_err()
            .code,
        "check_evidence_invalid"
    );
    let oversize = observation(
        format,
        &vec![1; fgit_forge::event::workflow_check::MAX_CHECK_EVIDENCE_BYTES + 1],
    );
    let query = parse(&selection(&oversize)).unwrap();
    assert!(output::Selected::new(&query, &oversize, format).is_err());
    let result = observation(format, b"\0\xff\x1b");
    let mut query = parse(&selection(&result)).unwrap();
    query.offset = result.evidence.len() as u64;
    assert!(output::Selected::new(&query, &result, format).is_ok());
    for offset in [query.offset + 1, u64::MAX] {
        query.offset = offset;
        assert_eq!(
            output::Selected::new(&query, &result, format)
                .unwrap_err()
                .code,
            "check_evidence_offset_out_of_bounds"
        );
    }
}

#[cfg(target_os = "linux")]
mod persisted;
