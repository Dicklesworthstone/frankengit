//! Read-only canonical workflow observations, bound to the PR's recorded commit.
use super::*;
use fgit_forge::PullRequestNumber;
use fgit_forge::event::workflow_check::{WorkflowCheckConclusion, WorkflowCheckId};
use fgit_node::{PullRequestChecksPage, WorkflowCheckSummary};

pub(super) const NAME: &str = "frankengit_pull_checks";

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
            ("maxLength", json::number(100)),
            (
                "description",
                text("Exact next_after check ID from the previous page; requires expected_head."),
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
        description: "Read immutable workflow observations for the exact recorded PR source commit. Current disclosure rules apply to both branches. action_required is a local execution observation, never an independent success or permission to merge. Evidence bodies are not returned.",
        schema: object([
            ("type", text("object")),
            ("properties", Value::Object(properties)),
            ("required", Value::Array(vec![text("number")])),
            ("additionalProperties", Value::Bool(false)),
        ]),
    }
}

struct Query {
    number: PullRequestNumber,
    after: Option<WorkflowCheckId>,
    limit: u16,
    expected: Option<RepositoryAuthorityHeadId>,
}
fn query(args: &Object) -> Result<Query, ToolError> {
    require_fields(args, &["number", "limit", "after", "expected_head"])?;
    let number = PullRequestNumber::try_new(decimal(args, "number", 0)?)
        .ok_or(ToolError::invalid("positive_pull_number_required"))?;
    let after = string(args, "after")?
        .map(|value| {
            WorkflowCheckId::from_label(value).ok_or(ToolError::invalid("invalid_check_cursor"))
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
    let context = backend.node.request_context();
    let page = backend
        .node
        .runtime()
        .block_on(backend.node.read_pull_request_checks_in(
            &context,
            &Default::default(),
            query.number,
            query.after,
            query.limit,
            query.expected,
        ))
        .map_err(|error| {
            ToolError::failed(if error.is_snapshot_unavailable() {
                "snapshot_unavailable"
            } else {
                "pull_checks_read_failed"
            })
        })?;
    if let Some(page) = &page {
        page.validate_window(query.number, query.after, query.limit, query.expected)
            .map_err(|_| ToolError::failed("invalid_pull_checks_page"))?;
        if page.source_tip.algorithm() != backend.options.format
            || page.target_tip.algorithm() != backend.options.format
        {
            return Err(ToolError::failed("invalid_pull_checks_page"));
        }
    }
    Ok(render(backend, &query, page.as_ref()))
}

fn render(backend: &NodeTools, query: &Query, page: Option<&PullRequestChecksPage>) -> Value {
    let Value::Object(mut result) = object([
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
        ("number", text(query.number.get().to_string())),
        ("read_only", Value::Bool(true)),
        ("found", Value::Bool(page.is_some())),
        ("scope", text("trusted_workflow_observations")),
        ("merge_permission", Value::Null),
        (
            "after",
            query.after.map_or(Value::Null, |id| text(id.to_string())),
        ),
        ("limit", json::number(u64::from(query.limit))),
        (
            "source_head",
            page.map_or(Value::Null, |p| text(p.source_head.to_string())),
        ),
        (
            "snapshot_token",
            page.map_or(Value::Null, |p| text(head_token(p.source_head))),
        ),
        (
            "pull_request_version",
            page.map_or(Value::Null, |p| {
                text(p.pull_request_version.get().to_string())
            }),
        ),
        (
            "source_ref_hex",
            page.map_or(Value::Null, |p| text(hex(p.source_ref.as_bytes()))),
        ),
        (
            "target_ref_hex",
            page.map_or(Value::Null, |p| text(hex(p.target_ref.as_bytes()))),
        ),
        (
            "source_tip",
            page.map_or(Value::Null, |p| text(p.source_tip.to_string())),
        ),
        (
            "target_tip",
            page.map_or(Value::Null, |p| text(p.target_tip.to_string())),
        ),
        (
            "source_current",
            page.map_or(Value::Null, |p| Value::Bool(p.source_current)),
        ),
        (
            "next_after",
            page.and_then(|p| p.next_after)
                .map_or(Value::Null, |id| text(id.to_string())),
        ),
        (
            "complete",
            Value::Bool(page.is_none_or(|p| p.next_after.is_none())),
        ),
    ]) else {
        unreachable!()
    };
    result.insert(
        "checks".into(),
        Value::Array(page.map_or_else(Vec::new, |p| p.checks.iter().map(row).collect())),
    );
    Value::Object(result)
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
                WorkflowCheckConclusion::Failure => "failure",
                WorkflowCheckConclusion::Cancelled => "cancelled",
                WorkflowCheckConclusion::TimedOut => "timed_out",
            }),
        ),
        ("evidence_sha256", text(hex(&row.evidence_sha256))),
        ("evidence_bytes", text(row.evidence_bytes.to_string())),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn check_queries_require_exact_numbers_pinned_cursors_and_read_only_arguments() {
        for input in [
            r#"{}"#,
            r#"{"number":1}"#,
            r#"{"number":"01"}"#,
            r#"{"number":"0"}"#,
            r#"{"number":"1","limit":0}"#,
            r#"{"number":"1","limit":21}"#,
            r#"{"number":"1","after":"latest"}"#,
            r#"{"number":"1","principal":"operator"}"#,
            r#"{"number":"1","execute":true}"#,
        ] {
            assert!(
                query(json::parse(input.as_bytes()).unwrap().object().unwrap()).is_err(),
                "{input}"
            );
        }
        let Value::Object(mut args) = object([("number", text("1"))]) else {
            unreachable!()
        };
        assert_eq!(query(&args).unwrap().limit, 5);
        args.insert(
            "after".into(),
            text(WorkflowCheckId::from_bytes([1; 32]).to_string()),
        );
        assert!(query(&args).is_err());
        args.insert(
            "expected_head".into(),
            text(format!("alg:2:{}", "44".repeat(32))),
        );
        assert!(query(&args).is_ok());
    }
    #[test]
    fn observations_preserve_negative_conclusions_and_escape_untrusted_jobs() {
        let value = row(&WorkflowCheckSummary {
            id: WorkflowCheckId::from_bytes([1; 32]),
            publisher: fgit_types::PrincipalId::from_bytes([2; 16]),
            run_id: [3; 32],
            attempt_id: [4; 32],
            graph_root: [5; 32],
            job: "build\"<script>é</script>".into(),
            conclusion: WorkflowCheckConclusion::ActionRequired,
            evidence_sha256: [6; 32],
            evidence_bytes: 123,
        });
        let encoded = value.encode(8192).unwrap();
        assert_eq!(json::parse(encoded.as_bytes()).unwrap(), value);
        let fields = value.object().unwrap();
        assert_eq!(fields["conclusion"].text(), Some("action_required"));
        assert_eq!(fields["evidence_bytes"].text(), Some("123"));
        assert!(!fields.contains_key("evidence"));
    }
}
