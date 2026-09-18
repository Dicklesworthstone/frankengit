//! Read-only issue search forms. Identity comes only from gateway credentials;
//! filters never confer access and HTTP transport never refreshes a snapshot.
use std::collections::BTreeMap;
use fgit_forge::event::issue::{CompiledIssueQuery, IssueQuery, IssueState, MAX_LABELS};
use fgit_forge::issue_search::{MAX_RESULTS, MAX_SCAN, SearchError, SearchRequest};
use fgit_types::PrincipalId;
use super::{ApiError, request};

pub(super) fn parse(body: &[u8]) -> Result<(CompiledIssueQuery, SearchRequest), ApiError> {
    let mut flags = BTreeMap::new();
    let mut labels = Vec::new();
    for (name, value) in request::form(body, MAX_LABELS + 8)? {
        if name == "label" {
            if labels.len() == MAX_LABELS { return Err(ApiError::too_large()); }
            labels.push(value);
        } else {
            if !matches!(name.as_str(), "query" | "state" | "opened_by" | "case_sensitive"
                | "after" | "limit" | "max_scan" | "expected_head")
            { return Err(ApiError::bad("unknown_search_field")); }
            if flags.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
    }
    let state = match flags.get("state").map_or("all", String::as_str) {
        "all" => None, "open" => Some(IssueState::Open), "closed" => Some(IssueState::Closed),
        _ => return Err(ApiError::bad("invalid_issue_state")),
    };
    let opened_by = flags.get("opened_by").map(|text| PrincipalId::from_hex(text)
        .map_err(|_| ApiError::bad("invalid_opener"))).transpose()?;
    let case_sensitive = match flags.get("case_sensitive").map_or("false", String::as_str) {
        "true" => true, "false" => false,
        _ => return Err(ApiError::bad("invalid_case_sensitive")),
    };
    let text = flags.remove("query");
    if case_sensitive && text.is_none() { return Err(ApiError::bad("case_sensitive_requires_query")); }
    labels.sort();
    let query = IssueQuery { state, opened_by, labels, text, case_sensitive }.compile()
        .map_err(|_| ApiError::bad("invalid_issue_query"))?;
    let after = flags.get("after").map(|value| request::decimal(value)).transpose()?.unwrap_or(0);
    let limit = flags.get("limit").map(|value| request::decimal(value)).transpose()?.unwrap_or(50);
    let max_scan = flags.get("max_scan").map(|value| request::decimal(value)).transpose()?.unwrap_or(u64::from(MAX_SCAN));
    if !(1..=u64::from(MAX_RESULTS)).contains(&limit) || !(1..=u64::from(MAX_SCAN)).contains(&max_scan) {
        return Err(ApiError::bad("invalid_search_limits"));
    }
    let expected_head = flags.get("expected_head").map(|value| request::parse_head_token(value)).transpose()?;
    if after != 0 && expected_head.is_none() { return Err(ApiError::bad("snapshot_required")); }
    Ok((query, SearchRequest { after,
        limit: u16::try_from(limit).map_err(|_| ApiError::bad("invalid_search_limits"))?,
        max_scan: u16::try_from(max_scan).map_err(|_| ApiError::bad("invalid_search_limits"))?, expected_head }))
}

pub(super) fn error(error: SearchError<ApiError>) -> ApiError {
    match error {
        SearchError::InvalidLimits => ApiError::bad("invalid_search_limits"),
        SearchError::SnapshotRequired => ApiError::bad("snapshot_required"),
        SearchError::SnapshotMoved => ApiError::snapshot_moved(),
        SearchError::Source(error) => error,
        SearchError::InvalidSourcePage | SearchError::InvalidSnapshot(_) | SearchError::Allocation => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests;
