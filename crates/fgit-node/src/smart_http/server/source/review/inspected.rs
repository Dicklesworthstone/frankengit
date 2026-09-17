//! Reuse the public source-diff serializer for an already verified candidate
//! comparison. This adapter reads no objects and grants no authority.

use super::*;
use fgit_forge::review::SourceReview;

pub(in crate::smart_http::server::source) fn render(
    node: &OneNode, report: &SourceReview, options: &ReviewOptions,
    maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    options.validate().map_err(|_| ApiError::bad("invalid_diff_options"))?;
    if options.mode != ComparisonMode::Direct || !options.paths.is_empty()
        || report.pull_request.is_some()
    { return Err(ApiError::bad("full_candidate_comparison_required")); }
    let command = Command {
        selection: ReviewSelection::References {
            before: report.before_reference.clone(), after: report.after_reference.clone(),
        },
        expected_head: Some(report.source_head),
        expected_before: Some(report.comparison.requested_before),
        expected_after: Some(report.comparison.requested_after),
        options: options.clone(),
    };
    output::render(node, &command, report, maximum, live)
}
