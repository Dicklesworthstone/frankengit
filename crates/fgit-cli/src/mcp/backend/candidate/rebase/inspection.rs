//! Inspect every uploaded native commit plus the old-source-to-result change.
//! Native validation owns the onto-only prerequisite; shared MCP review owns
//! every path, hunk and span. Series counters never renew at the next step;
//! native blob/diff-work bounds retain their per-blob/per-text contract.
use super::*;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::review::{
    ComparisonMode, ReviewContent, ReviewError, ReviewOptions, SourceComparison, SourceReview,
};
use fgit_node::BundleInspectionRefusal;
use std::collections::BTreeSet;

const MAX_COMMIT_BODIES: usize = 128 * 1024;
const LIMITS: &[(&str, usize, usize, usize)] = &[
    ("context_lines", 3, 0, 20),
    ("max_changes", 64, 1, 64),
    ("max_blob_bytes", 1024 * 1024, 1, 1024 * 1024),
    ("max_output_bytes", 64 * 1024, 1, 128 * 1024),
    ("max_diff_work", 1_000_000, 1, 1_000_000),
];
#[derive(Debug)]
pub(super) struct Input {
    pub selection: input::Selection,
    pub candidate: GitOid,
    pub bundle: Vec<u8>,
    pub digest: [u8; 32],
    pub options: ReviewOptions,
}
pub(super) fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut fields = input::SELECTION_FIELDS.to_vec();
    fields.extend([
        "expected_candidate",
        "bundle_hex_chunks",
        "expected_bundle_sha256",
    ]);
    fields.extend(LIMITS.iter().map(|row| row.0));
    require_fields(args, &fields)?;
    if required(args, "operation")? != INSPECT {
        return Err(ToolError::invalid("unsupported_candidate_operation"));
    }
    let selection = input::selection(args, format)?;
    let candidate = oid(args, "expected_candidate", format)?;
    let bundle = chunks(args, "bundle_hex_chunks")?;
    let digest = sha256_digest(&bundle);
    if let Some(expected) = string(args, "expected_bundle_sha256")?
        && (expected.len() != 64 || unhex(expected, 32)?.as_slice() != digest.as_slice())
    {
        return Err(ToolError::invalid("bundle_digest_mismatch"));
    }
    let bound = |name| {
        let &(_, default, minimum, maximum) = LIMITS
            .iter()
            .find(|row| row.0 == name)
            .ok_or(ToolError::invalid("invalid_rebase_limit"))?;
        input::bound(args, name, default, minimum, maximum)
    };
    let mut options = ReviewOptions {
        mode: ComparisonMode::Direct,
        ..ReviewOptions::default()
    };
    options.context_lines = bound("context_lines")?;
    options.limits.max_changes = bound("max_changes")?;
    options.limits.max_blob_bytes = bound("max_blob_bytes")?;
    options.limits.max_output_bytes = bound("max_output_bytes")?;
    options.limits.max_diff_work = bound("max_diff_work")?;
    options.limits.max_hunks = 256;
    options.limits.max_text_files = 32;
    options
        .validate()
        .map_err(|_| ToolError::invalid("invalid_rebase_limit"))?;
    Ok(Input {
        selection,
        candidate,
        bundle,
        digest,
        options,
    })
}
pub(super) fn schema() -> Value {
    let mut properties = input::properties(INSPECT);
    properties.insert("expected_candidate".into(), oid_schema());
    properties.insert("bundle_hex_chunks".into(), chunk_schema());
    properties.insert(
        "expected_bundle_sha256".into(),
        object([
            ("type", text("string")),
            ("pattern", text("^[0-9a-f]{64}$")),
        ]),
    );
    for &(name, default, minimum, maximum) in LIMITS {
        properties.insert(
            name.into(),
            object([
                ("type", text("integer")),
                ("minimum", json::number(minimum as u64)),
                ("maximum", json::number(maximum as u64)),
                ("default", json::number(default as u64)),
            ]),
        );
    }
    input::closed_schema(
        properties,
        &[
            "operation",
            "profile",
            "expected_source",
            "expected_onto",
            "expected_candidate",
            "bundle_hex_chunks",
        ],
    )
}
fn refusal(error: BundleInspectionRefusal) -> ToolError {
    match error {
        BundleInspectionRefusal::RefUnavailable => ToolError::failed("reference_unavailable"),
        BundleInspectionRefusal::SnapshotMoved => ToolError::failed("source_snapshot_moved"),
        BundleInspectionRefusal::ParentMoved => ToolError::failed("rebase_tip_moved"),
        BundleInspectionRefusal::InvalidCandidate(_) | BundleInspectionRefusal::Envelope(_) => {
            ToolError::failed("invalid_rebase_candidate")
        }
        BundleInspectionRefusal::BudgetExceeded => ToolError::failed("resource_limit"),
        BundleInspectionRefusal::Source(error) => source_error(&error),
        BundleInspectionRefusal::Review(error) => match *error {
            ReviewError::InvalidOptions => ToolError::invalid("invalid_rebase_limit"),
            ReviewError::Budget(_) => ToolError::failed("resource_limit"),
            ReviewError::Source(error) => source_error(&error),
            _ => ToolError::failed("rebase_inspection_failed"),
        },
        _ => ToolError::failed("rebase_inspection_failed"),
    }
}
fn coordinates(comparison: &SourceComparison, before: GitOid, after: GitOid) -> bool {
    comparison.mode == ComparisonMode::Direct
        && comparison.requested_before == before
        && comparison.compared_before == before
        && comparison.requested_after == after
}
fn charge(total: &mut usize, amount: usize, maximum: usize) -> Result<(), ToolError> {
    *total = total
        .checked_add(amount)
        .filter(|value| *value <= maximum)
        .ok_or(ToolError::failed("rebase_result_limit"))?;
    Ok(())
}
pub(super) fn aggregate(
    comparisons: &[SourceComparison],
    options: &ReviewOptions,
    live: &mut impl FnMut() -> bool,
) -> Result<(), ToolError> {
    let (mut changes, mut texts, mut hunks, mut bytes) = (0, 0, 0, 0);
    let limits = options.limits;
    for comparison in comparisons {
        checkpoint(live)?;
        charge(&mut changes, comparison.entries.len(), limits.max_changes)?;
        for entry in &comparison.entries {
            checkpoint(live)?;
            charge(&mut bytes, entry.path.len(), limits.max_output_bytes)?;
            if let ReviewContent::Text { hunks: spans, .. } = &entry.content {
                charge(&mut texts, 1, limits.max_text_files)?;
                charge(&mut hunks, spans.len(), limits.max_hunks)?;
                for span in spans {
                    charge(&mut bytes, span.before.len(), limits.max_output_bytes)?;
                    charge(&mut bytes, span.after.len(), limits.max_output_bytes)?;
                }
            }
        }
    }
    checkpoint(live)
}
fn comparison(
    backend: &NodeTools,
    selection: &input::Selection,
    head: RepositoryAuthorityHeadId,
    options: &ReviewOptions,
    comparison: SourceComparison,
) -> Result<Value, ToolError> {
    let before = comparison.requested_before;
    let after = comparison.requested_after;
    let report = SourceReview {
        repository_id: backend.options.repository,
        source_head: head,
        before_reference: selection.reference.clone(),
        after_reference: selection.reference.clone(),
        pull_request: None,
        comparison,
    };
    super::super::super::review::render_candidate(
        backend,
        &selection.reference,
        before,
        after,
        Some(head),
        options.clone(),
        &report,
    )
    .map(Value::Object)
}
pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    let input = parse(args, backend.options.format)?;
    let request = backend.command_context();
    checkpoint(&mut || request.is_live())?;
    let report = backend
        .node
        .runtime()
        .block_on(backend.node.inspect_rebase_bundle_in(
            &request,
            &input.selection.reference,
            &input.selection.onto_reference,
            input.selection.source,
            input.selection.onto,
            input.candidate,
            &input.bundle,
            &Default::default(),
            input.selection.head,
            &input.options,
        ))
        .map_err(|error| {
            if request.is_live() {
                refusal(error)
            } else {
                ToolError::failed("rebase_cancelled")
            }
        })?;
    checkpoint(&mut || request.is_live())?;
    if report.repository_id != backend.options.repository
        || report.source_reference != input.selection.reference
        || report.onto_reference != input.selection.onto_reference
        || report.expected_source != input.selection.source
        || report.onto != input.selection.onto
        || report.candidate != input.candidate
        || input
            .selection
            .head
            .is_some_and(|head| head != report.source_head)
        || report.commits.len() > MAX_COMMITS
        || report.comparisons.len() != report.commits.len() + 1
        || report.bundle.sha256 != input.digest
        || report.bundle.bytes != input.bundle.len()
        || report.bundle.pack_bytes == 0
        || report.bundle.pack_bytes > report.bundle.bytes
        || report.bundle.transport_only_objects > report.bundle.pack_objects
        || !coordinates(
            &report.comparisons[0],
            input.selection.source,
            input.candidate,
        )
    {
        return Err(invalid_report());
    }
    let mut parent = input.selection.onto;
    let mut previous_tree = None;
    let mut seen = BTreeSet::new();
    let mut bodies = 0_usize;
    for (commit, comparison) in report.commits.iter().zip(&report.comparisons[1..]) {
        checkpoint(&mut || request.is_live())?;
        charge(&mut bodies, commit.body.len(), MAX_COMMIT_BODIES)?;
        if commit.parent != parent
            || !seen.insert(commit.id)
            || commit.id == input.selection.onto
            || git_object_id(backend.options.format, GitObjectKind::Commit, &commit.body)
                != commit.id
            || !coordinates(comparison, parent, commit.id)
            || comparison.after_tree != commit.tree
            || previous_tree.is_some_and(|tree| tree != comparison.before_tree)
        {
            return Err(invalid_report());
        }
        parent = commit.id;
        previous_tree = Some(commit.tree);
    }
    if parent != input.candidate
        || previous_tree.is_some_and(|tree| tree != report.comparisons[0].after_tree)
    {
        return Err(invalid_report());
    }
    aggregate(&report.comparisons, &input.options, &mut || {
        request.is_live()
    })?;
    // All aggregate native bodies and diff bytes were charged before any hex or
    // JSON expansion. Move each comparison into the shared renderer once.
    let mut fields = backend.header(report.source_head);
    fields.extend(binding(backend));
    fields.extend([
        ("type".into(), text("source_rebase_inspection")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(INSPECT)),
        ("profile".into(), text("linear-v1")),
        ("source_head".into(), text(report.source_head.to_string())),
        (
            "reference_hex".into(),
            text(hex(input.selection.reference.as_bytes())),
        ),
        (
            "onto_reference_hex".into(),
            text(hex(input.selection.onto_reference.as_bytes())),
        ),
        (
            "expected_source".into(),
            text(raw_oid(input.selection.source)),
        ),
        ("onto".into(), text(raw_oid(input.selection.onto))),
        ("expected_candidate".into(), text(raw_oid(input.candidate))),
        ("candidate_commit".into(), text(raw_oid(input.candidate))),
        ("counter_encoding".into(), text("decimal-strings-v1")),
        ("bundle_sha256".into(), text(hex(&input.digest))),
        ("bundle_bytes".into(), text(report.bundle.bytes.to_string())),
        (
            "pack_bytes".into(),
            text(report.bundle.pack_bytes.to_string()),
        ),
        (
            "pack_objects".into(),
            text(report.bundle.pack_objects.to_string()),
        ),
        (
            "expanded_bytes".into(),
            text(report.bundle.expanded_bytes.to_string()),
        ),
        (
            "closure_objects".into(),
            text(report.bundle.closure_objects.to_string()),
        ),
        (
            "transport_only_objects".into(),
            text(report.bundle.transport_only_objects.to_string()),
        ),
        (
            "commit_count".into(),
            text(report.commits.len().to_string()),
        ),
        ("commit_body_bytes".into(), text(bodies.to_string())),
        ("complete".into(), Value::Bool(true)),
        (
            "completion_scope".into(),
            text("entire_rebase_series_and_net_tree"),
        ),
        ("all_changed_paths".into(), Value::Bool(true)),
        ("all_rewritten_commits".into(), Value::Bool(true)),
        ("binary_bodies_included".into(), Value::Bool(false)),
        ("objects_staged".into(), Value::Bool(false)),
        ("transaction_created".into(), Value::Bool(false)),
        ("inspection_performed".into(), Value::Bool(true)),
        ("publication_authorized".into(), Value::Bool(false)),
        ("replay_equivalence_verified".into(), Value::Bool(false)),
        ("author_identity_verified".into(), Value::Bool(false)),
        ("publication_tool".into(), text(PUBLICATION_TOOL)),
        (
            "publication_arguments".into(),
            publication(
                &input.selection.reference,
                input.selection.source,
                input.selection.onto,
                input.candidate,
                &input.bundle,
            )?,
        ),
    ]);
    let mut comparisons = report.comparisons.into_iter();
    fields.insert(
        "net_change".into(),
        comparison(
            backend,
            &input.selection,
            report.source_head,
            &input.options,
            comparisons.next().ok_or_else(invalid_report)?,
        )?,
    );
    let mut commits = Vec::with_capacity(report.commits.len());
    for (index, (commit, diff)) in report.commits.into_iter().zip(comparisons).enumerate() {
        checkpoint(&mut || request.is_live())?;
        commits.push(object([
            ("index", text(index.to_string())),
            ("commit", text(raw_oid(commit.id))),
            ("parent", text(raw_oid(commit.parent))),
            ("tree", text(raw_oid(commit.tree))),
            ("body_hex", text(hex(&commit.body))),
            (
                "diff",
                comparison(
                    backend,
                    &input.selection,
                    report.source_head,
                    &input.options,
                    diff,
                )?,
            ),
        ]));
    }
    fields.insert("commits".into(), Value::Array(commits));
    bounded(Value::Object(fields), &mut || request.is_live())
}
