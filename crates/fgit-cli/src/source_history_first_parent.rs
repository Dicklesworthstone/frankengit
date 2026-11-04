//! CLI selection and reporting for bounded first-parent history.
use super::*;
use fgit_forge::history::first_parent::FirstParentCursor;

pub(super) fn parse(
    flags: &BTreeMap<&str, &str>,
    reference: &RefName,
    format: GitHashAlgorithm,
    head: Option<RepositoryAuthorityHeadId>,
    limits: HistoryLimits,
    limit: usize,
) -> Result<Query, String> {
    if ["--after", "--path", "--path-hex"]
        .iter()
        .any(|flag| flags.contains_key(flag))
    {
        return Err("--first-parent cannot combine with --after or a path filter".into());
    }
    let cursor = flags
        .get("--cursor")
        .map(|value| parse_cursor(value))
        .transpose()?;
    if let Some(cursor) = &cursor {
        if cursor.reference != *reference || cursor.tip.algorithm() != format {
            return Err("first-parent cursor reference or object format mismatch".into());
        }
        if head.is_some_and(|head| head != cursor.source_head) {
            return Err("first-parent cursor authority head mismatch".into());
        }
    }
    let options = FirstParentOptions {
        cursor,
        limit,
        limits,
    };
    options.validate().map_err(|error| error.to_string())?;
    Ok(Query::FirstParent(options))
}

fn encode_cursor(cursor: &FirstParentCursor) -> String {
    cursor.encode()
}

fn parse_cursor(value: &str) -> Result<FirstParentCursor, String> {
    FirstParentCursor::decode(value)
        .map_err(|_| "invalid or noncanonical first-parent cursor".into())
}

pub(super) fn render(
    options: &Options,
    head: RepositoryAuthorityHeadId,
    page: &FirstParentPage,
) -> Result<String, String> {
    let Query::FirstParent(query) = &options.query else {
        return Err("first-parent history operation mismatch".into());
    };
    let after = query.log_options().after;
    let end = after
        .checked_add(page.commits.len())
        .ok_or("history page overflow")?;
    if page.after != after
        || page.visited_commits != end
        || page.visited_commits > query.limits.max_commits
        || page.visited_parent_edges > query.limits.max_edges
        || page.metadata_bytes > query.limits.max_metadata_bytes
        || page.commits.len() > query.limit
        || (!page.root_reached && page.commits.len() != query.limit)
        || page.next_after != (!page.root_reached).then_some(end)
        || (after == 0
            && page
                .commits
                .first()
                .is_none_or(|commit| commit.id != page.tip))
        || query.cursor.as_ref().is_some_and(|cursor| {
            cursor.source_head != head
                || cursor.tip != page.tip
                || cursor.reference != options.reference
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
        return Err("first-parent pagination response mismatch".into());
    }
    let returned_bytes = page
        .commits
        .iter()
        .try_fold(0usize, |bytes, commit| bytes.checked_add(commit.body.len()))
        .ok_or("history metadata length overflow")?;
    if returned_bytes > page.metadata_bytes {
        return Err("first-parent metadata accounting mismatch".into());
    }
    let header = header(options, head, page.tip)?;
    let entries = records(options, &page.commits)?;
    let cursor = page.continuation(head, &options.reference).map_or_else(
        || "null".to_owned(),
        |cursor| quote(&encode_cursor(&cursor)),
    );
    let mut out = format!(
        concat!(
            "{{\"type\":\"commit_history\",\"profile\":\"first-parent-prefix-v1\",",
            "\"scope\":\"first_parent_chain\",{header},\"after\":{after},\"limit\":{},",
            "\"root_reached\":{},\"visited_commits\":{},\"visited_parent_edges\":{},",
            "\"metadata_bytes\":{},\"next_cursor\":{cursor},\"commits\":"
        ),
        query.limit,
        page.root_reached,
        page.visited_commits,
        page.visited_parent_edges,
        page.metadata_bytes,
        header = header,
        after = after,
        cursor = cursor,
    );
    append(&mut out, &entries)?;
    out.push('}');
    Ok(out)
}

#[cfg(test)]
#[path = "source_history_first_parent_tests.rs"]
mod tests;
