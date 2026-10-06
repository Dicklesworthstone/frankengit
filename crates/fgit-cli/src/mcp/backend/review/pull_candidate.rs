//! The actual target-before -> uploaded PR result is not the source-side diff.
//! Retain the native PR association while sharing the ordinary span validator.
use super::*;
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};

pub(in super::super) fn render(
    backend: &NodeTools,
    subject: &ReviewSubject,
    candidate: CandidateBinding,
    expected_head: Option<RepositoryAuthorityHeadId>,
    options: ReviewOptions,
    report: &SourceReview,
) -> Result<Object, ToolError> {
    if !backend.options.source || !backend.options.pulls {
        return Err(ToolError::invalid("tool_not_granted"));
    }
    if options.mode != ComparisonMode::Direct || !options.paths.is_empty() {
        return Err(ToolError::invalid("full_candidate_review_required"));
    }
    candidate
        .validate(subject)
        .map_err(|_| ToolError::failed("invalid_pull_candidate_report"))?;
    // Both comparison labels are the target: the after side is an uploaded
    // candidate, not a claim that the source branch currently names its tip.
    if report.before_reference != subject.target_ref
        || report.after_reference != subject.target_ref
        || report.pull_request != Some((subject.pull_request, subject.pull_request_version))
    {
        return Err(ToolError::failed("invalid_pull_candidate_report"));
    }
    let query = Query {
        selection: ReviewSelection::PullRequest {
            number: subject.pull_request,
            expected_version: Some(subject.pull_request_version),
        },
        expected_head,
        expected_before: Some(subject.target_tip),
        expected_after: Some(candidate.commit),
        options,
    };
    let mut fields = output::render(
        backend.options.repository, backend.options.format, &query, report,
    )?;
    fields.insert("completion_scope".into(), text("entire_candidate_tree"));
    fields.insert("comparison_subject".into(), text("target_before_to_uploaded_candidate"));
    Ok(fields)
}
