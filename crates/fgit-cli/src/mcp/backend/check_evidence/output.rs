//! Only a completely validated canonical observation may enter this renderer.
use super::*;
use fgit_forge::event::workflow_check::WorkflowCheckConclusion;
use fgit_node::{PullRequestCheckEvidence, PullRequestChecksPage, WorkflowCheckSummary};
use fgit_types::GitHashAlgorithm;

#[derive(Debug)]
pub(super) struct Selected<'a> {
    pub(super) result: &'a PullRequestCheckEvidence,
    query: &'a Query,
    start: usize,
    end: usize,
}

impl<'a> Selected<'a> {
    pub(super) fn new(
        query: &'a Query,
        result: &'a PullRequestCheckEvidence,
        format: GitHashAlgorithm,
    ) -> Result<Self, ToolError> {
        result
            .validate(query.number, query.check, query.expected_head)
            .map_err(|_| ToolError::failed("check_evidence_invalid"))?;
        if result.page.source_tip.algorithm() != format
            || result.page.target_tip.algorithm() != format
            || result.page.checks[0].evidence_sha256 != query.expected_evidence
        {
            return Err(ToolError::failed("check_evidence_identity_mismatch"));
        }
        if query.offset > result.evidence.len() as u64 {
            return Err(ToolError::invalid("check_evidence_offset_out_of_bounds"));
        }
        let start = usize::try_from(query.offset)
            .map_err(|_| ToolError::invalid("check_evidence_offset_out_of_bounds"))?;
        let end = start + query.limit.min(result.evidence.len() - start);
        Ok(Self {
            result,
            query,
            start,
            end,
        })
    }
}

pub(super) fn render(
    backend: &NodeTools,
    selected: &Selected<'_>,
    report_span: Option<report::Span>,
) -> Value {
    object([
        ("type", text("pull_request_check_evidence_read")),
        ("schema_version", json::number(1)),
        ("page", page(backend, &selected.result.page)),
        ("offset", text(selected.query.offset.to_string())),
        (
            "byte_count",
            text((selected.end - selected.start).to_string()),
        ),
        (
            "content_hex",
            text(hex(&selected.result.evidence[selected.start..selected.end])),
        ),
        (
            "next_offset",
            if selected.end < selected.result.evidence.len() {
                text(selected.end.to_string())
            } else {
                Value::Null
            },
        ),
        (
            "report_span",
            report_span.map_or(Value::Null, |span| {
                object([
                    ("offset", text(span.offset.to_string())),
                    ("bytes", text(span.bytes.to_string())),
                ])
            }),
        ),
        ("read_only", Value::Bool(true)),
        ("transaction_created", Value::Bool(false)),
        ("evidence_verified", Value::Bool(true)),
        ("content_is_untrusted", Value::Bool(true)),
        ("approval_granted", Value::Bool(false)),
        ("merge_permission", Value::Null),
    ])
}

fn page(backend: &NodeTools, page: &PullRequestChecksPage) -> Value {
    object([
        ("type", text("pull_request_checks")),
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
        ("number", text(page.number.get().to_string())),
        ("source_head", text(page.source_head.to_string())),
        ("snapshot_token", text(head_token(page.source_head))),
        (
            "pull_request_version",
            text(page.pull_request_version.get().to_string()),
        ),
        ("source_ref_hex", text(hex(page.source_ref.as_bytes()))),
        ("target_ref_hex", text(hex(page.target_ref.as_bytes()))),
        ("source_tip", text(page.source_tip.to_string())),
        ("target_tip", text(page.target_tip.to_string())),
        ("source_current", Value::Bool(page.source_current)),
        ("found", Value::Bool(true)),
        ("after", Value::Null),
        ("limit", json::number(1)),
        ("next_after", Value::Null),
        ("complete", Value::Bool(true)),
        ("scope", text("trusted_workflow_observations")),
        ("merge_permission", Value::Null),
        ("read_only", Value::Bool(true)),
        (
            "checks",
            Value::Array(page.checks.iter().map(row).collect()),
        ),
    ])
}

fn row(row: &WorkflowCheckSummary) -> Value {
    object([
        ("id", text(row.id.to_string())),
        ("publisher", text(row.publisher.to_string())),
        ("run_id", text(hex(&row.run_id))),
        ("attempt_id", text(hex(&row.attempt_id))),
        ("graph_root", text(hex(&row.graph_root))),
        ("job", text(row.job.clone())),
        (
            "conclusion",
            text(match row.conclusion {
                WorkflowCheckConclusion::ActionRequired => "action_required",
                WorkflowCheckConclusion::Success => "success",
                WorkflowCheckConclusion::Failure => "failure",
                WorkflowCheckConclusion::Cancelled => "cancelled",
                WorkflowCheckConclusion::TimedOut => "timed_out",
            }),
        ),
        ("evidence_sha256", text(hex(&row.evidence_sha256))),
        ("evidence_bytes", text(row.evidence_bytes.to_string())),
    ])
}
