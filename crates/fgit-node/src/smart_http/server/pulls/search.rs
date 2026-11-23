//! Literal PR filters are data. The metadata route retains its read grant.
use super::super::issues::{ApiError, Rendering, parse_decimal, parse_form, parse_snapshot};
use fgit_forge::pull_request_search::{
    CompiledPullRequestQuery, MAX_SCAN, PullRequestQuery, PullRequestState, SearchError,
    SearchRequest,
};
use fgit_types::PrincipalId;
use std::collections::BTreeMap;

#[derive(Debug)]
pub(super) struct Search {
    pub query: CompiledPullRequestQuery,
    pub request: SearchRequest,
    pub render: Option<Rendering>,
}

pub(super) fn parse(bytes: &[u8]) -> Result<Search, ApiError> {
    let mut fields = BTreeMap::new();
    for (name, value) in parse_form(bytes, 13)? {
        if !matches!(
            name.as_str(),
            "query"
                | "state"
                | "opened_by"
                | "source_ref"
                | "source_ref_hex"
                | "target_ref"
                | "target_ref_hex"
                | "case_sensitive"
                | "after"
                | "limit"
                | "max_scan"
                | "expected_head"
                | "render"
        ) {
            return Err(ApiError::bad("unknown_search_field"));
        }
        if fields.insert(name, value).is_some() {
            return Err(ApiError::bad("duplicate_field"));
        }
    }
    let state = match fields.get("state").map_or("all", String::as_str) {
        "all" => None,
        "open" => Some(PullRequestState::Open),
        "closed" => Some(PullRequestState::Closed),
        "merged" => Some(PullRequestState::Merged),
        _ => return Err(ApiError::bad("invalid_pull_state")),
    };
    let opened_by = fields
        .get("opened_by")
        .map(|value| PrincipalId::from_hex(value).map_err(|_| ApiError::bad("invalid_opener")))
        .transpose()?;
    let case_sensitive = match fields.get("case_sensitive").map_or("false", String::as_str) {
        "true" => true,
        "false" => false,
        _ => return Err(ApiError::bad("invalid_case_sensitive")),
    };
    let reference = |fields: &mut BTreeMap<String, String>, plain, encoded| {
        if fields.contains_key(plain) || fields.contains_key(encoded) {
            super::subject::reference(fields, plain, encoded).map(Some)
        } else {
            Ok(None)
        }
    };
    let query = PullRequestQuery {
        state,
        opened_by,
        case_sensitive,
        source_ref: reference(&mut fields, "source_ref", "source_ref_hex")?,
        target_ref: reference(&mut fields, "target_ref", "target_ref_hex")?,
        text: fields.remove("query"),
    }
    .compile()
    .map_err(|_| ApiError::bad("invalid_pull_query"))?;
    let number = |name: &str, default| {
        fields
            .get(name)
            .map(|s| parse_decimal(s))
            .transpose()
            .map(|n| n.unwrap_or(default))
    };
    let request = SearchRequest {
        after: number("after", 0)?,
        limit: u16::try_from(number("limit", 50)?)
            .map_err(|_| ApiError::bad("invalid_search_limits"))?,
        max_scan: u16::try_from(number("max_scan", u64::from(MAX_SCAN))?)
            .map_err(|_| ApiError::bad("invalid_search_limits"))?,
        expected_head: fields
            .get("expected_head")
            .map(|s| parse_snapshot(s))
            .transpose()?,
    };
    request.validate().map_err(error)?;
    let render = fields
        .get("render")
        .map(|s| Rendering::from_query(s).ok_or_else(|| ApiError::bad("unsupported_rendering")))
        .transpose()?;
    Ok(Search {
        query,
        request,
        render,
    })
}

pub(super) fn error(error: crate::PullRequestSearchRefusal) -> ApiError {
    match error {
        SearchError::InvalidLimits => ApiError::bad("invalid_search_limits"),
        SearchError::SnapshotRequired => ApiError::bad("snapshot_required"),
        SearchError::SnapshotMoved => ApiError::snapshot_moved(),
        SearchError::Source(error) if error.is_snapshot_unavailable() => ApiError::snapshot_moved(),
        _ => ApiError::unavailable(),
    }
}

#[cfg(test)]
mod tests;
