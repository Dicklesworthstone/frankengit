//! Exact read summaries. No evidence body, implicit success or merge authority.

use super::super::super::issues::{ApiError, quote};
use super::request::Page;
use crate::{OneNode, PullRequestChecksPage, WorkflowCheckSummary};
use fgit_forge::PullRequestNumber;
use fgit_forge::event::workflow_check::{WorkflowCheckConclusion, WorkflowCheckId};
use fgit_types::RepositoryAuthorityHeadId;

pub(super) const MAX_REPLY_BYTES: usize = 1024 * 1024;

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
}
