//! Whole-series PR inspection shares the ordinary source diff renderer and one
//! cumulative budget. A net-tree comparison cannot hide intermediate changes.
use super::*;
use fgit_forge::review::{
    ComparisonMode, ReviewContent, ReviewOptions, SourceComparison, SourceReview,
};
use fgit_node::BundleInspectionRefusal;

const MAX_COMMIT_BODIES: usize = 128 * 1024;

struct Input {
    selection: Selection,
    candidate: CandidateBinding,
    bundle: Vec<u8>,
    digest: [u8; 32],
    options: ReviewOptions,
}

fn parse(args: &Object, format: GitHashAlgorithm) -> Result<Input, ToolError> {
    let mut fields = SUBJECT_FIELDS.to_vec();
    fields.extend([
        "candidate_commit",
        "merge_base",
        "bundle_hex_chunks",
        "expected_bundle_sha256",
        "method",
    ]);
    fields.extend(super::super::inspect::LIMITS.iter().map(|row| row.0));
    require_fields(args, &fields)?;
    if required(args, "operation")? != REBASE_INSPECT || required(args, "method")? != "rebase" {
        return Err(ToolError::invalid("unsupported_rebase_profile"));
    }
    let selection = selection(args, format)?;
    let (subject, candidate) = reviews::subject(args, format)?;
    if subject != selection.subject
        || candidate.commit == subject.target_tip
        || candidate.merge_base == subject.source_tip
    {
        return Err(ToolError::invalid("nonempty_distinct_pr_rebase_required"));
    }
    let bundle = chunks(args, "bundle_hex_chunks")?;
    let digest = sha256_digest(&bundle);
    if let Some(expected) = string(args, "expected_bundle_sha256")?
        && (expected.len() != 64 || unhex(expected, 32)?.as_slice() != digest.as_slice())
    {
        return Err(ToolError::invalid("bundle_digest_mismatch"));
    }
    let bound = |name| super::super::inspect::bound(args, name);
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
        .map_err(|_| ToolError::invalid("invalid_inspection_limit"))?;
    Ok(Input {
        selection,
        candidate,
        bundle,
        digest,
        options,
    })
}

pub(super) fn schema() -> Value {
    let mut properties = subject_properties(REBASE_INSPECT);
    properties.insert("method".into(), object([("const", text("rebase"))]));
    for field in ["merge_base", "candidate_commit"] {
        properties.insert(field.into(), oid_schema());
    }
    properties.insert("bundle_hex_chunks".into(), chunk_schema());
    properties.insert(
        "expected_bundle_sha256".into(),
        object([
            ("type", text("string")),
            ("pattern", text("^[0-9a-f]{64}$")),
        ]),
    );
    for &(name, default, minimum, maximum) in super::super::inspect::LIMITS {
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
    reviews::candidate_schema(
        properties,
        &[
            "operation",
            "method",
            "number",
            "expected_version",
            "expected_source",
            "expected_target",
            "policy_epoch",
            "merge_base",
            "candidate_commit",
            "bundle_hex_chunks",
        ],
    )
}

fn coordinates(comparison: &SourceComparison, before: GitOid, after: GitOid) -> bool {
    comparison.mode == ComparisonMode::Direct
        && comparison.requested_before == before
        && comparison.compared_before == before
        && comparison.requested_after == after
}

fn charge(total: &mut usize, value: usize, maximum: usize) -> Result<(), ToolError> {
    *total = total
        .checked_add(value)
        .filter(|value| *value <= maximum)
        .ok_or(ToolError::failed("rebase_result_limit"))?;
    Ok(())
}

fn aggregate(
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
    subject: &ReviewSubject,
    head: RepositoryAuthorityHeadId,
    options: &ReviewOptions,
    comparison: SourceComparison,
) -> Result<Value, ToolError> {
    let (before, after) = (comparison.requested_before, comparison.requested_after);
    let report = SourceReview {
        repository_id: backend.options.repository,
        source_head: head,
        before_reference: subject.source_ref.clone(),
        after_reference: subject.source_ref.clone(),
        pull_request: None,
        comparison,
    };
    super::super::super::super::review::render_candidate(
        backend,
        &subject.source_ref,
        before,
        after,
        Some(head),
        options.clone(),
        &report,
    )
    .map(Value::Object)
}

pub(super) fn call(backend: &NodeTools, args: &Object) -> Result<Value, ToolError> {
    permitted(backend)?;
    let input = parse(args, backend.options.format)?;
    let request = backend.command_context();
    checkpoint(&mut || request.is_live())?;
    let subject = &input.selection.subject;
    let report = backend
        .node
        .runtime()
        .block_on(backend.node.inspect_pull_request_rebase_bundle_in(
            &request,
            subject,
            input.candidate.merge_base,
            input.candidate.commit,
            &input.bundle,
            &Default::default(),
            input.selection.expected_head,
            &input.options,
        ))
        .map_err(|error| {
            if !request.is_live() {
                return ToolError::failed("rebase_cancelled");
            }
            match error {
                BundleInspectionRefusal::SnapshotMoved | BundleInspectionRefusal::ParentMoved => {
                    ToolError::failed("pull_subject_moved")
                }
                BundleInspectionRefusal::RefUnavailable => {
                    ToolError::failed("reference_unavailable")
                }
                BundleInspectionRefusal::BudgetExceeded => ToolError::failed("resource_limit"),
                BundleInspectionRefusal::InvalidCandidate(_)
                | BundleInspectionRefusal::Envelope(_) => {
                    ToolError::failed("invalid_rebase_candidate")
                }
                _ => ToolError::failed("rebase_inspection_failed"),
            }
        })?;
    checkpoint(&mut || request.is_live())?;
    if report.repository_id != backend.options.repository
        || report.source_reference != subject.source_ref
        || report.onto_reference != subject.target_ref
        || report.expected_source != subject.source_tip
        || report.onto != subject.target_tip
        || report.candidate != input.candidate.commit
        || input
            .selection
            .expected_head
            .is_some_and(|head| head != report.source_head)
        || report.commits.is_empty()
        || report.commits.len() > MAX_COMMITS
        || report.comparisons.len() != report.commits.len() + 1
        || report.bundle.sha256 != input.digest
        || report.bundle.bytes != input.bundle.len()
        || report.bundle.pack_bytes == 0
        || report.bundle.pack_bytes > report.bundle.bytes
        || report.bundle.transport_only_objects > report.bundle.pack_objects
        || !coordinates(
            &report.comparisons[0],
            subject.source_tip,
            input.candidate.commit,
        )
    {
        return Err(invalid_report());
    }
    let mut parent = subject.target_tip;
    let mut previous_tree = None;
    let mut seen = BTreeSet::new();
    let mut bodies = 0;
    for (commit, diff) in report.commits.iter().zip(&report.comparisons[1..]) {
        checkpoint(&mut || request.is_live())?;
        charge(&mut bodies, commit.body.len(), MAX_COMMIT_BODIES)?;
        if commit.parent != parent
            || !seen.insert(commit.id)
            || commit.id == subject.target_tip
            || git_object_id(backend.options.format, GitObjectKind::Commit, &commit.body)
                != commit.id
            || !coordinates(diff, parent, commit.id)
            || diff.after_tree != commit.tree
            || previous_tree.is_some_and(|tree| tree != diff.before_tree)
        {
            return Err(invalid_report());
        }
        parent = commit.id;
        previous_tree = Some(commit.tree);
    }
    if parent != input.candidate.commit || previous_tree != Some(report.comparisons[0].after_tree) {
        return Err(invalid_report());
    }
    aggregate(&report.comparisons, &input.options, &mut || {
        request.is_live()
    })?;
    let handoff = arguments(subject, input.candidate, &input.bundle)?;
    let mut fields = backend.header(report.source_head);
    fields.extend(binding(backend));
    fields.extend(subject_fields(subject));
    fields.extend([
        ("type".into(), text("pull_rebase_inspection")),
        ("schema_version".into(), json::number(1)),
        ("operation".into(), text(REBASE_INSPECT)),
        ("method".into(), text("rebase")),
        ("profile".into(), text("verified-linear-series-v1")),
        (
            "candidate_commit".into(),
            text(raw_oid(input.candidate.commit)),
        ),
        (
            "merge_base".into(),
            text(raw_oid(input.candidate.merge_base)),
        ),
        ("bundle_sha256".into(), text(hex(&input.digest))),
        ("bundle_bytes".into(), text(report.bundle.bytes.to_string())),
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
        ("candidate_arguments".into(), handoff.clone()),
        ("publication_arguments".into(), handoff),
        ("review_tool".into(), text(reviews::NAME)),
        (
            "publication_tool".into(),
            text(super::super::super::super::merge_writes::NAME),
        ),
    ]);
    let mut comparisons = report.comparisons.into_iter();
    fields.insert(
        "net_change".into(),
        comparison(
            backend,
            subject,
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
                comparison(backend, subject, report.source_head, &input.options, diff)?,
            ),
        ]));
    }
    fields.insert("commits".into(), Value::Array(commits));
    bounded(Value::Object(fields), &mut || request.is_live())
}
