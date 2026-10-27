//! Exact read summaries and separately authorized, bounded evidence bodies.
//! Neither response establishes independent execution truth or merge authority.

use super::super::super::issues::{ApiError, quote};
use super::request::Page;
use crate::{OneNode, PullRequestCheckEvidence, PullRequestChecksPage, WorkflowCheckSummary};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::workflow_check::{WorkflowCheckConclusion, WorkflowCheckId};
use fgit_types::RepositoryAuthorityHeadId;

pub(super) const MAX_REPLY_BYTES: usize = 1024 * 1024;
pub(super) const MAX_EVIDENCE_REPLY_BYTES: usize = 8 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn cursor(value: Option<WorkflowCheckId>) -> String {
    value.map_or_else(|| "null".into(), |id| quote(&id.to_string()))
}
fn token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id();
    format!(
        "alg:{}:{}",
        id.algorithm().code_point(),
        hex(id.digest().as_bytes())
    )
}
fn append(out: &mut String, bytes: &str, maximum: usize) -> Result<(), ApiError> {
    if out
        .len()
        .checked_add(bytes.len())
        .is_none_or(|length| length > maximum)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(bytes.len())
        .map_err(|_| ApiError::unavailable())?;
    out.push_str(bytes);
    Ok(())
}
const fn conclusion(value: WorkflowCheckConclusion) -> &'static str {
    match value {
        WorkflowCheckConclusion::ActionRequired => "action_required",
        WorkflowCheckConclusion::Success => "success",
        WorkflowCheckConclusion::Failure => "failure",
        WorkflowCheckConclusion::Cancelled => "cancelled",
        WorkflowCheckConclusion::TimedOut => "timed_out",
    }
}
fn record(value: &WorkflowCheckSummary) -> String {
    format!(
        concat!(
            "{{\"id\":{},\"publisher\":{},\"run_id\":{},\"attempt_id\":{},\"graph_root\":{},",
            "\"job\":{},\"conclusion\":{},\"evidence_sha256\":{},\"evidence_bytes\":{}}}"
        ),
        quote(&value.id.to_string()),
        quote(&value.publisher.to_string()),
        quote(&hex(&value.run_id)),
        quote(&hex(&value.attempt_id)),
        quote(&hex(&value.graph_root)),
        quote(&value.job),
        quote(conclusion(value.conclusion)),
        quote(&hex(&value.evidence_sha256)),
        quote(&value.evidence_bytes.to_string()),
    )
}

pub(super) fn page(
    node: &OneNode,
    number: PullRequestNumber,
    requested: Page,
    result: Option<&PullRequestChecksPage>,
    maximum: usize,
) -> Result<String, ApiError> {
    if let Some(result) = result {
        result
            .validate_window(
                number,
                requested.after,
                requested.limit,
                requested.expected_head,
            )
            .map_err(|_| ApiError::unavailable())?;
        if result.source_tip.algorithm() != node.object_format
            || result.target_tip.algorithm() != node.object_format
        {
            return Err(ApiError::unavailable());
        }
    }
    let scope = format!(
        concat!(
            "\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"repository_incarnation\":{},\"object_format\":{}"
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(node.object_format.as_str()),
    );
    let selected = result.map_or_else(
        || {
            concat!(
                "\"source_head\":null,\"snapshot_token\":null,\"pull_request_version\":null,",
                "\"source_ref_hex\":null,\"target_ref_hex\":null,\"source_tip\":null,",
                "\"target_tip\":null,\"source_current\":null"
            )
            .into()
        },
        |page| {
            format!(
                concat!(
                    "\"source_head\":{},\"snapshot_token\":{},\"pull_request_version\":{},",
                    "\"source_ref_hex\":{},\"target_ref_hex\":{},\"source_tip\":{},",
                    "\"target_tip\":{},\"source_current\":{}"
                ),
                quote(&page.source_head.to_string()),
                quote(&token(page.source_head)),
                quote(&page.pull_request_version.get().to_string()),
                quote(&hex(page.source_ref.as_bytes())),
                quote(&hex(page.target_ref.as_bytes())),
                quote(&page.source_tip.to_string()),
                quote(&page.target_tip.to_string()),
                page.source_current,
            )
        },
    );
    let next = result.and_then(|page| page.next_after);
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            concat!(
                "{{\"type\":\"pull_request_checks\",{},\"number\":{},\"found\":{},{},",
                "\"after\":{},\"limit\":{},\"next_after\":{},\"complete\":{},",
                "\"scope\":\"trusted_workflow_observations\",\"merge_permission\":null,\"checks\":["
            ),
            scope,
            quote(&number.get().to_string()),
            result.is_some(),
            selected,
            cursor(requested.after),
            requested.limit,
            cursor(next),
            next.is_none(),
        ),
        maximum,
    )?;
    if let Some(page) = result {
        for (index, row) in page.checks.iter().enumerate() {
            if index != 0 {
                append(&mut out, ",", maximum)?;
            }
            append(&mut out, &record(row), maximum)?;
        }
    }
    append(&mut out, "]}", maximum)?;
    Ok(out)
}

/// This envelope is constructed only after the evidence route has authorized
/// both pulls-read and artifact-read. The SHA-256 identifies inline canonical
/// event evidence; it is not a workflow-artifact address.
pub(super) fn evidence(
    node: &OneNode,
    number: PullRequestNumber,
    check: WorkflowCheckId,
    expected_head: RepositoryAuthorityHeadId,
    result: &PullRequestCheckEvidence,
    maximum: usize,
    live: &dyn Fn() -> bool,
) -> Result<String, ApiError> {
    if !live() {
        return Err(ApiError::unavailable());
    }
    result
        .validate(number, check, expected_head)
        .map_err(|_| ApiError::unavailable())?;
    let selected = page(
        node,
        number,
        Page {
            after: None,
            limit: 1,
            expected_head: Some(expected_head),
        },
        Some(&result.page),
        maximum,
    )?;
    let report = trusted_report(node, result, live);
    if !live() {
        return Err(ApiError::unavailable());
    }
    let mut out = String::new();
    append(
        &mut out,
        "{\"type\":\"pull_request_check_evidence\",\"schema_version\":1,\"read_only\":true,\"page\":",
        maximum,
    )?;
    append(&mut out, &selected, maximum)?;
    append(&mut out, ",\"evidence_hex\":\"", maximum)?;
    append_hex(&mut out, &result.evidence, maximum, live)?;
    append(&mut out, "\",\"report\":", maximum)?;
    if let Some((offset, json)) = report {
        append(
            &mut out,
            &format!("{{\"offset\":{offset},\"bytes\":{},\"json\":", json.len()),
            maximum,
        )?;
        append(&mut out, &quote(&json), maximum)?;
        append(&mut out, "}", maximum)?;
    } else {
        append(&mut out, "null", maximum)?;
    }
    append(&mut out, "}", maximum)?;
    if !live() {
        return Err(ApiError::unavailable());
    }
    Ok(out)
}

fn append_hex(
    out: &mut String,
    bytes: &[u8],
    maximum: usize,
    live: &dyn Fn() -> bool,
) -> Result<(), ApiError> {
    let length = bytes.len().checked_mul(2).ok_or_else(ApiError::too_large)?;
    if out
        .len()
        .checked_add(length)
        .is_none_or(|size| size > maximum)
    {
        return Err(ApiError::too_large());
    }
    out.try_reserve(length)
        .map_err(|_| ApiError::unavailable())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for chunk in bytes.chunks(4096) {
        if !live() {
            return Err(ApiError::unavailable());
        }
        for byte in chunk {
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn trusted_report(
    node: &OneNode,
    result: &PullRequestCheckEvidence,
    live: &dyn Fn() -> bool,
) -> Option<(usize, String)> {
    use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
    use fgit_runner::Commitment;
    use fgit_runner::coordinator::delivery::journal::history::decode_trusted_observation;

    let row = result.page.checks.first()?;
    let expected = Commitment::try_from_digest(Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&row.evidence_sha256).ok()?,
    ))
    .ok()?;
    let decoded = decode_trusted_observation(
        &result.evidence,
        expected,
        fgit_forge::event::workflow_check::MAX_CHECK_EVIDENCE_BYTES,
        live,
    )
    .ok()?;
    let report = decoded.report();
    if decoded.tenant() != node.tenant_id
        || decoded.repository() != node.repository_id
        || decoded.source_commit() != result.page.source_tip
        || decoded.run_id().commitment().digest().bytes().as_bytes() != row.run_id
        || decoded
            .attempt_id()
            .commitment()
            .digest()
            .bytes()
            .as_bytes()
            != row.attempt_id
        || report.graph.digest().bytes().as_bytes() != row.graph_root
        || report.jobs.len() != 1
        || report.jobs[0].id != row.job
        || (report_conclusion(report.jobs[0].outcome) != row.conclusion
            // Older trusted-local publishers retained successful reports as
            // ActionRequired. Display their logs without upgrading that fact.
            && !(row.conclusion == WorkflowCheckConclusion::ActionRequired
                && report.jobs[0].outcome == fgit_runner::workflow::JobOutcome::Succeeded))
    {
        return None;
    }
    // The decoder round-trips the entire canonical frame. Retain an explicit
    // byte-span check as well: clients can prove this display JSON is the exact
    // final length-framed field of the selected evidence, not detached output.
    let json = decoded.report_json();
    let offset = result.evidence.len().checked_sub(json.len())?;
    let prefix = offset.checked_sub(8)?;
    if result.evidence.get(offset..)? != json.as_bytes()
        || result.evidence.get(prefix..offset)? != (json.len() as u64).to_be_bytes()
    {
        return None;
    }
    Some((offset, json))
}

#[cfg(target_os = "linux")]
const fn report_conclusion(value: fgit_runner::workflow::JobOutcome) -> WorkflowCheckConclusion {
    use fgit_runner::workflow::JobOutcome;
    match value {
        JobOutcome::Succeeded => WorkflowCheckConclusion::Success,
        JobOutcome::Skipped => WorkflowCheckConclusion::ActionRequired,
        JobOutcome::Failed | JobOutcome::Refused | JobOutcome::OutputLimit => {
            WorkflowCheckConclusion::Failure
        }
        JobOutcome::Cancelled => WorkflowCheckConclusion::Cancelled,
        JobOutcome::TimedOut => WorkflowCheckConclusion::TimedOut,
    }
}

#[cfg(not(target_os = "linux"))]
fn trusted_report(
    _node: &OneNode,
    _result: &PullRequestCheckEvidence,
    _live: &dyn Fn() -> bool,
) -> Option<(usize, String)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::PrincipalId;

    fn row() -> WorkflowCheckSummary {
        WorkflowCheckSummary {
            id: WorkflowCheckId::from_bytes([1; 32]),
            publisher: PrincipalId::from_bytes([0x12; 16]),
            run_id: [0x23; 32],
            attempt_id: [0x34; 32],
            graph_root: [0x45; 32],
            job: "<script>\"build\"\u{202e}".into(),
            conclusion: WorkflowCheckConclusion::ActionRequired,
            evidence_sha256: [0x56; 32],
            evidence_bytes: 1024,
        }
    }
    #[test]
    fn every_actual_conclusion_is_explicit_and_never_inferred_success() {
        for (value, label) in [
            (WorkflowCheckConclusion::ActionRequired, "action_required"),
            (WorkflowCheckConclusion::Success, "success"),
            (WorkflowCheckConclusion::Failure, "failure"),
            (WorkflowCheckConclusion::Cancelled, "cancelled"),
            (WorkflowCheckConclusion::TimedOut, "timed_out"),
        ] {
            let mut row = row();
            row.conclusion = value;
            let json = record(&row);
            assert!(json.contains(&format!("\"conclusion\":\"{label}\"")));
            assert!(json.contains("<script>\\\"build\\\"\\u202e"));
            assert!(json.contains("\"evidence_bytes\":\"1024\""));
            assert!(json.contains(&format!("\"evidence_sha256\":\"{}\"", "56".repeat(32))));
            assert!(!json.contains("\"evidence\":"));
        }
    }
    #[test]
    fn output_ceiling_never_returns_a_truncated_record() {
        let mut out = "abc".to_owned();
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        append(&mut out, "d", 4).unwrap();
        assert_eq!(out, "abcd");
    }
    #[test]
    fn evidence_encoding_checks_expansion_and_cancellation_before_disclosure() {
        let bytes = [0, 31, 255];
        let mut out = String::from("x");
        assert!(append_hex(&mut out, &bytes, 6, &|| true).is_err());
        assert_eq!(out, "x");
        assert!(append_hex(&mut out, &bytes, 7, &|| false).is_err());
        assert_eq!(out, "x");
        append_hex(&mut out, &bytes, 7, &|| true).unwrap();
        assert_eq!(out, "x001fff");
    }
}
