//! Explicit bounded first-parent queries over the existing source-read route.
//! Cursors bind a visible reference; they never supply an arbitrary read root.

use super::*;
use fgit_forge::history::first_parent::{FirstParentCursor, FirstParentPage};

pub(super) fn parse(
    fields: &mut BTreeMap<String, String>,
    selection: &Selection,
    format: GitHashAlgorithm,
) -> Result<Option<FirstParentOptions>, ApiError> {
    let Some(mode) = fields.remove("first_parent") else {
        if fields.contains_key("cursor") {
            return Err(ApiError::bad("first_parent_cursor_requires_profile"));
        }
        return Ok(None);
    };
    if mode != "true"
        || ["after", "path_hex", "max_tree_entries", "max_cached_bytes"]
            .iter()
            .any(|name| fields.contains_key(*name))
    {
        return Err(ApiError::bad("invalid_first_parent_profile"));
    }
    let cursor = fields
        .remove("cursor")
        .map(|value| {
            FirstParentCursor::decode(&value)
                .map_err(|_| ApiError::bad("invalid_first_parent_cursor"))
        })
        .transpose()?;
    if cursor.as_ref().is_some_and(|cursor| {
        cursor.reference != selection.reference
            || cursor.tip.algorithm() != format
            || selection
                .expected_head
                .is_some_and(|head| head != cursor.source_head)
            || selection
                .expected_commit
                .is_some_and(|tip| tip != cursor.tip)
    }) {
        return Err(ApiError::bad("first_parent_cursor_selection_mismatch"));
    }
    let mut limits = HistoryLimits::default();
    limits.max_commits = number(fields, "max_commits", limits.max_commits)?;
    limits.max_edges = number(fields, "max_edges", limits.max_edges)?;
    limits.max_metadata_bytes = number(fields, "max_metadata_bytes", limits.max_metadata_bytes)?;
    let options = FirstParentOptions {
        cursor,
        limit: number(fields, "limit", FirstParentOptions::default().limit)?,
        limits,
    };
    options
        .validate()
        .map_err(|_| ApiError::bad("invalid_history_limits"))?;
    if !fields.is_empty() {
        return Err(ApiError::bad("unknown_or_inapplicable_field"));
    }
    Ok(Some(options))
}

fn validate_page(
    selection: &Selection,
    options: &FirstParentOptions,
    head: RepositoryAuthorityHeadId,
    page: &FirstParentPage,
    format: GitHashAlgorithm,
) -> Result<(), ApiError> {
    options.validate().map_err(|_| ApiError::unavailable())?;
    check_selection(selection, head, page.tip, format)?;
    let after = options.log_options().after;
    let end = after
        .checked_add(page.commits.len())
        .ok_or_else(ApiError::unavailable)?;
    let minimum_edges = end
        .checked_sub(usize::from(page.root_reached))
        .ok_or_else(ApiError::unavailable)?;
    if page.after != after
        || page.visited_commits == 0
        || page.visited_commits != end
        || page.visited_commits > options.limits.max_commits
        || page.visited_parent_edges < minimum_edges
        || page.visited_parent_edges > options.limits.max_edges
        || page.metadata_bytes == 0
        || page.metadata_bytes > options.limits.max_metadata_bytes
        || page.commits.len() > options.limit
        || (!page.root_reached && page.commits.len() != options.limit)
        || page.next_after != (!page.root_reached).then_some(end)
        || (after == 0 && page.commits.first().map(|row| row.id) != Some(page.tip))
        || options.cursor.as_ref().is_some_and(|cursor| {
            cursor.reference != selection.reference
                || cursor.source_head != head
                || cursor.tip != page.tip
        })
        || page
            .commits
            .windows(2)
            .any(|pair| pair[0].parents.first() != Some(&pair[1].id))
        || page
            .commits
            .last()
            .is_some_and(|last| last.parents.is_empty() != page.root_reached)
    {
        return Err(ApiError::unavailable());
    }
    let mut ids = BTreeSet::new();
    let mut returned_bytes = 0_usize;
    let mut returned_edges = 0_usize;
    for row in &page.commits {
        if !ids.insert(row.id) {
            return Err(ApiError::unavailable());
        }
        returned_bytes = returned_bytes
            .checked_add(row.body.len())
            .ok_or_else(ApiError::unavailable)?;
        returned_edges = returned_edges
            .checked_add(row.parents.len())
            .ok_or_else(ApiError::unavailable)?;
    }
    if returned_bytes > page.metadata_bytes
        || returned_edges > page.visited_parent_edges
        || page
            .commits
            .last()
            .and_then(|last| last.parents.first())
            .is_some_and(|next| ids.contains(next))
        || (after == 0
            && (returned_bytes != page.metadata_bytes
                || returned_edges != page.visited_parent_edges))
    {
        return Err(ApiError::unavailable());
    }
    Ok(())
}

pub(super) fn render(
    node: &OneNode,
    command: &Command,
    head: RepositoryAuthorityHeadId,
    page: &FirstParentPage,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    let options = command
        .first_parent
        .as_ref()
        .ok_or_else(ApiError::unavailable)?;
    validate_page(&command.selection, options, head, page, node.object_format)?;
    let mut out = Output::new(maximum);
    identity(
        &mut out,
        node,
        &command.selection,
        head,
        page.tip,
        "source_first_parent_log",
        live,
    )?;
    let cursor = page
        .continuation(head, &command.selection.reference)
        .map_or_else(|| "null".to_owned(), |cursor| quote(&cursor.encode()));
    out.append(&format!(
        concat!(
            ",\"profile\":\"first-parent-prefix-v1\",\"ordering\":\"stored-first-parent-v1\",",
            "\"page_complete\":true,\"after\":{},\"limit\":{},\"root_reached\":{},",
            "\"visited_commits\":{},\"visited_parent_edges\":{},\"metadata_bytes\":{},",
            "\"next_cursor\":{},\"commits\":["
        ),
        page.after,
        options.limit,
        page.root_reached,
        page.visited_commits,
        page.visited_parent_edges,
        page.metadata_bytes,
        cursor,
    ))?;
    for (index, row) in page.commits.iter().enumerate() {
        if index != 0 {
            out.append(",")?;
        }
        commit(&mut out, row, node.object_format, live)?;
    }
    out.append("]}")?;
    out.finish(live)
}

#[cfg(test)]
mod tests;
