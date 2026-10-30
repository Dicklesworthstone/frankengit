//! Explicit first-parent history under the existing per-call history budgets.
//! Continuations re-walk the selected tip's prefix, rather than trusting a
//! caller-supplied starting object. No total-history count is inferred.

use super::{
    HistoryCommit, HistoryError, HistoryLimits, HistorySource, LogOptions, charge, check_oid,
};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use std::collections::BTreeSet;

/// A selection precondition, not an authentication credential. The node must
/// check all bindings and traverse from its authenticated visible reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstParentCursor {
    pub source_head: RepositoryAuthorityHeadId,
    pub reference: RefName,
    pub tip: GitOid,
    pub after: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstParentOptions {
    pub cursor: Option<FirstParentCursor>,
    pub limit: usize,
    pub limits: HistoryLimits,
}

impl Default for FirstParentOptions {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: 50,
            limits: HistoryLimits::default(),
        }
    }
}

impl FirstParentOptions {
    pub fn validate(&self) -> Result<(), HistoryError> {
        self.log_options().validate()?;
        if self
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.after == 0 || cursor.tip.is_zero())
        {
            return Err(HistoryError::InvalidOptions);
        }
        Ok(())
    }

    #[must_use]
    pub fn log_options(&self) -> LogOptions {
        LogOptions {
            after: self.cursor.as_ref().map_or(0, |cursor| cursor.after),
            limit: self.limit,
            limits: self.limits,
        }
    }
}

/// A complete requested page, which may leave older ancestry unread. Every
/// visited parent header is charged, but only the first parent's body is read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FirstParentPage {
    pub tip: GitOid,
    pub after: usize,
    pub next_after: Option<usize>,
    pub root_reached: bool,
    pub commits: Vec<HistoryCommit>,
    pub visited_commits: usize,
    pub visited_parent_edges: usize,
    /// Logical native-body bytes visited, including the skipped prefix.
    pub metadata_bytes: usize,
}

impl FirstParentPage {
    #[must_use]
    pub fn continuation(
        &self,
        source_head: RepositoryAuthorityHeadId,
        reference: &RefName,
    ) -> Option<FirstParentCursor> {
        self.next_after.map(|after| FirstParentCursor {
            source_head,
            reference: reference.clone(),
            tip: self.tip,
            after,
        })
    }
}

/// Walk only the first-parent prefix needed for this page. Skipped commits,
/// every original parent header, and all visited bodies consume the caller's
/// unchanged limits. A deep continuation can therefore exhaust a per-call
/// budget even when an earlier page succeeded. No unvisited ancestor is read
/// merely to compute a total count or prove the next page will succeed.
pub fn first_parent_history(
    source: &impl HistorySource,
    format: GitHashAlgorithm,
    tip: GitOid,
    options: LogOptions,
) -> Result<FirstParentPage, HistoryError> {
    options.validate()?;
    check_oid(format, tip)?;
    let end = options
        .after
        .checked_add(options.limit)
        .ok_or(HistoryError::InvalidOptions)?;
    let mut current = Some(tip);
    let mut seen = BTreeSet::new();
    let mut commits = Vec::with_capacity(options.limit);
    let mut edges = 0;
    let mut bytes = 0;
    while seen.len() < end {
        source.checkpoint()?;
        let Some(id) = current else {
            if seen.len() < options.after {
                return Err(HistoryError::LineRange);
            }
            break;
        };
        if seen.contains(&id) {
            return Err(HistoryError::CyclicHistory);
        }
        if seen.len() >= options.limits.max_commits {
            return Err(HistoryError::Budget("commits"));
        }
        check_oid(format, id)?;
        let body = source.commit_body(id)?;
        source.checkpoint()?;
        if body.len() > 64 * 1024 {
            return Err(HistoryError::Budget("commit metadata"));
        }
        charge(
            &mut bytes,
            body.len(),
            options.limits.max_metadata_bytes,
            "metadata bytes",
        )?;
        if git_object_id(format, GitObjectKind::Commit, &body) != id {
            return Err(HistoryError::InvalidObject(id));
        }
        let commit = source.commit(id)?;
        source.checkpoint()?;
        check_oid(format, commit.tree)?;
        charge(
            &mut edges,
            commit.parents.len(),
            options.limits.max_edges,
            "commit edges",
        )?;
        for parent in &commit.parents {
            source.checkpoint()?;
            check_oid(format, *parent)?;
        }
        current = commit.parents.first().copied();
        if seen.len() >= options.after {
            commits.push(HistoryCommit {
                id,
                tree: commit.tree,
                parents: commit.parents,
                body,
            });
        }
        seen.insert(id);
        if current.is_some_and(|next| seen.contains(&next)) {
            return Err(HistoryError::CyclicHistory);
        }
    }
    source.checkpoint()?;
    Ok(FirstParentPage {
        tip,
        after: options.after,
        next_after: current.map(|_| seen.len()),
        root_reached: current.is_none(),
        commits,
        visited_commits: seen.len(),
        visited_parent_edges: edges,
        metadata_bytes: bytes,
    })
}

#[cfg(test)]
#[path = "first_parent_tests.rs"]
mod tests;
