//! Bounded branch and tag selection over exact reference bytes. No regex or lookup,
//! scheduling or authorization. The caller supplies authenticated coordinates.
use super::{Node, Span, Trigger, WorkflowGraph, WorkflowRefusal};
mod paths;
pub use paths::PathFilter;
const MAX_MATCH_BYTES: usize = 4096;
pub const MAX_PATTERNS: usize = 32;
pub const MAX_PATTERN_BYTES: usize = 256;
pub const MAX_TOTAL_PATTERN_BYTES: usize = 4096;
pub const MAX_REFERENCE_BYTES: usize = 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Token {
    Byte(u8),
    Star,
    GlobStar,
    Directories,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BranchFilter {
    ignore: bool,
    patterns: Vec<(String, bool, Vec<Token>)>,
}
impl BranchFilter {
    #[must_use]
    pub const fn field(&self) -> &'static str {
        if self.ignore {
            "branches-ignore"
        } else {
            "branches"
        }
    }
    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.patterns.iter().map(|(text, _, _)| text.as_str())
    }
    fn matches(
        &self,
        branch: &[u8],
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool, TriggerSelectionError> {
        let mut selected = self.ignore;
        for (_, negative, tokens) in &self.patterns {
            if matches_pattern(tokens, branch, cancelled)? {
                selected = !self.ignore && !negative;
            }
        }
        Ok(selected)
    }
}

/// An ordered push-tag filter sharing the exact bounded branch-pattern grammar.
/// It applies only to the bytes following `refs/tags/`, never to a peeled commit
/// or a branch with the same short name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TagFilter(BranchFilter);
impl TagFilter {
    #[must_use]
    pub const fn field(&self) -> &'static str {
        if self.0.ignore { "tags-ignore" } else { "tags" }
    }

    pub fn patterns(&self) -> impl Iterator<Item = &str> {
        self.0.patterns()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerSelectionError {
    MissingBranchReference,
    MissingPushReference,
    ReferenceTooLong,
    Cancelled,
    MissingChangedPaths,
    InvalidChangedPaths,
    PathMatchBudget,
}
impl std::fmt::Display for TriggerSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "workflow reference selection refused: {self:?}")
    }
}
impl std::error::Error for TriggerSelectionError {}
impl WorkflowGraph {
    /// Full reference: push source branch/tag or PR TARGET branch. The caller
    /// authenticates it; a tag's direct ref identity must not be replaced by its
    /// peeled commit or by a branch carrying the same short name.
    /// Unfiltered historical graphs do not require additional coordinates.
    pub fn selects_event(
        &self,
        event: &str,
        reference: Option<&[u8]>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool, TriggerSelectionError> {
        self.selects_event_with_paths(event, reference, None, cancelled)
    }
    /// None means unavailable evidence; Some(empty) means a complete empty diff.
    /// The caller authenticates the exact source of the complete changed paths.
    /// Push tag events do not evaluate path filters: a tag push is not a branch
    /// diff. Branch and pull-request path filters keep requiring complete paths.
    pub fn selects_event_with_paths(
        &self,
        event: &str,
        reference: Option<&[u8]>,
        paths: Option<&[Vec<u8>]>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<bool, TriggerSelectionError> {
        if cancelled() {
            return Err(TriggerSelectionError::Cancelled);
        }
        let mut selected = false;
        for trigger in self.triggers.iter().filter(|trigger| trigger.name == event) {
            let tag_reference = if trigger.tag_filter.is_some() {
                let reference = reference.ok_or(TriggerSelectionError::MissingPushReference)?;
                if reference.len() > MAX_REFERENCE_BYTES {
                    return Err(TriggerSelectionError::ReferenceTooLong);
                }
                Some(reference)
            } else {
                None
            };
            let tag_push = event == "push"
                && reference.is_some_and(|reference| {
                    reference
                        .strip_prefix(b"refs/tags/")
                        .is_some_and(|tag| !tag.is_empty())
                });
            let path_selected = if tag_push {
                true
            } else {
                match &trigger.path_filter {
                    Some(filter) => filter.selects(
                        paths.ok_or(TriggerSelectionError::MissingChangedPaths)?,
                        cancelled,
                    )?,
                    None => true,
                }
            };
            let reference_selected = match (&trigger.tag_filter, tag_reference) {
                (Some(filter), Some(reference)) if event == "push" => {
                    if let Some(tag) = reference.strip_prefix(b"refs/tags/") {
                        !tag.is_empty() && filter.0.matches(tag, cancelled)?
                    } else if let Some(branch) = reference.strip_prefix(b"refs/heads/") {
                        match &trigger.branch_filter {
                            Some(filter) if !branch.is_empty() => {
                                filter.matches(branch, cancelled)?
                            }
                            // A tag-only declaration never selects branches.
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
                (Some(_), _) => false,
                (None, _) => match &trigger.branch_filter {
                    None => true,
                    Some(filter) => {
                        let reference =
                            reference.ok_or(TriggerSelectionError::MissingBranchReference)?;
                        if reference.len() > MAX_REFERENCE_BYTES {
                            return Err(TriggerSelectionError::ReferenceTooLong);
                        }
                        match reference.strip_prefix(b"refs/heads/") {
                            Some(branch) if !branch.is_empty() => {
                                filter.matches(branch, cancelled)?
                            }
                            _ => false,
                        }
                    }
                },
            };
            selected |= reference_selected && path_selected;
        }
        if cancelled() {
            return Err(TriggerSelectionError::Cancelled);
        }
        Ok(selected)
    }
    #[must_use]
    pub fn has_path_filters(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| trigger.path_filter.is_some())
    }
    #[must_use]
    pub fn has_branch_filters(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| trigger.branch_filter.is_some())
    }
    #[must_use]
    pub fn has_tag_filters(&self) -> bool {
        self.triggers
            .iter()
            .any(|trigger| trigger.tag_filter.is_some())
    }
}
const fn malformed(span: Span, expected: &'static str) -> WorkflowRefusal {
    WorkflowRefusal::Malformed { expected, span }
}
const fn bounded(
    observed: usize,
    allowed: usize,
    limit: &'static str,
    span: Span,
) -> Result<(), WorkflowRefusal> {
    if observed > allowed {
        Err(WorkflowRefusal::LimitExceeded {
            limit,
            allowed,
            observed,
            span,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PatternScope {
    Branch,
    Tag,
    Path,
}

fn pattern(
    text: &str,
    span: Span,
    ignore: bool,
    scope: PatternScope,
) -> Result<(bool, Vec<Token>), WorkflowRefusal> {
    bounded(
        text.len(),
        MAX_PATTERN_BYTES,
        if scope == PatternScope::Tag {
            "tag pattern bytes"
        } else {
            "branch pattern bytes"
        },
        span,
    )?;
    let path = scope == PatternScope::Path;
    let negative = text.starts_with('!');
    let body = if negative { &text[1..] } else { text };
    if body.is_empty()
        || negative && ignore
        || body
            .chars()
            .any(|c| c.is_control() || !path && c.is_whitespace())
        || body.bytes().any(|b| b"!?+[]{}\\".contains(&b))
    {
        return Err(malformed(
            span,
            if scope == PatternScope::Tag {
                "a literal tag pattern with *, **, or a leading ! in tags"
            } else {
                "a literal branch pattern with *, **, or a leading ! in branches"
            },
        ));
    }
    if path
        && (body.starts_with('/')
            || body
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".."))
    {
        return Err(malformed(
            span,
            "a workspace-relative path pattern without dot components",
        ));
    }
    let bytes = body.as_bytes();
    let mut tokens = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'*' {
            tokens.push(Token::Byte(bytes[at]));
            at += 1;
            continue;
        }
        if bytes.get(at + 1) == Some(&b'*') {
            if bytes.get(at + 2) == Some(&b'*') {
                return Err(malformed(span, "at most two consecutive stars"));
            }
            if (at == 0 || bytes[at - 1] == b'/') && bytes.get(at + 2) == Some(&b'/') {
                tokens.push(Token::Directories);
                at += 3;
            } else {
                tokens.push(Token::GlobStar);
                at += 2;
            }
        } else {
            tokens.push(Token::Star);
            at += 1;
        }
    }
    Ok((negative, tokens))
}
fn filter(node: &Node, ignore: bool, scope: PatternScope) -> Result<BranchFilter, WorkflowRefusal> {
    let field = match scope {
        PatternScope::Branch => "on.branches",
        PatternScope::Tag => "on.tags",
        PatternScope::Path => "on.paths",
    };
    let Node::Sequence { items, span } = node else {
        return Err(WorkflowRefusal::FieldShape {
            path: field,
            expected: "a nonempty sequence of patterns",
            observed: node.shape(),
            span: node.span(),
        });
    };
    bounded(
        items.len(),
        MAX_PATTERNS,
        if scope == PatternScope::Tag {
            "tag patterns"
        } else {
            "branch patterns"
        },
        *span,
    )?;
    if items.is_empty() {
        return Err(malformed(
            *span,
            if scope == PatternScope::Tag {
                "at least one tag pattern"
            } else {
                "at least one branch pattern"
            },
        ));
    }
    let mut patterns = Vec::with_capacity(items.len());
    let mut total = 0;
    for item in items {
        let Node::Scalar { value, span } = item else {
            return Err(WorkflowRefusal::FieldShape {
                path: field,
                expected: "a scalar pattern",
                observed: item.shape(),
                span: item.span(),
            });
        };
        total += value.len();
        bounded(
            total,
            MAX_TOTAL_PATTERN_BYTES,
            if scope == PatternScope::Tag {
                "aggregate tag pattern bytes"
            } else {
                "aggregate branch pattern bytes"
            },
            *span,
        )?;
        let (negative, tokens) = pattern(value, *span, ignore, scope)?;
        patterns.push((value.clone(), negative, tokens));
    }
    if !ignore && patterns.iter().all(|(_, negative, _)| *negative) {
        return Err(malformed(
            *span,
            if scope == PatternScope::Tag {
                "at least one positive tags pattern"
            } else {
                "at least one positive branches pattern"
            },
        ));
    }
    Ok(BranchFilter { ignore, patterns })
}

pub(super) fn lower(node: &Node) -> Result<Vec<Trigger>, WorkflowRefusal> {
    let unfiltered = |name: &str, span| Trigger {
        name: name.to_owned(),
        span,
        branch_filter: None,
        tag_filter: None,
        path_filter: None,
    };
    let mut triggers = match node {
        Node::Scalar { value, span } => vec![unfiltered(value, *span)],
        Node::Sequence { items, .. } => items
            .iter()
            .map(|item| match item {
                Node::Scalar { value, span } => Ok(unfiltered(value, *span)),
                other => Err(WorkflowRefusal::FieldShape {
                    path: "on",
                    expected: "a scalar trigger",
                    observed: other.shape(),
                    span: other.span(),
                }),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Node::Mapping { entries, span } => {
            bounded(entries.len(), 32, "trigger mappings", *span)?;
            let mut triggers = Vec::with_capacity(entries.len());
            for (name, value, span) in entries {
                if !matches!(name.as_str(), "push" | "pull_request" | "workflow_dispatch") {
                    return Err(WorkflowRefusal::FieldUnknown {
                        key: name.clone().into(),
                        parent: "on",
                        span: *span,
                    });
                }
                let mut trigger = unfiltered(name, *span);
                match value {
                    Node::Scalar { value, .. } if value.is_empty() => {}
                    Node::Mapping { entries, .. } => {
                        for (key, value, span) in entries {
                            if matches!(key.as_str(), "paths" | "paths-ignore")
                                && matches!(name.as_str(), "push" | "pull_request")
                            {
                                if trigger.path_filter.is_some() {
                                    return Err(malformed(
                                        *span,
                                        "paths or paths-ignore, never both",
                                    ));
                                }
                                trigger.path_filter = Some(PathFilter(filter(
                                    value,
                                    key == "paths-ignore",
                                    PatternScope::Path,
                                )?));
                                continue;
                            }
                            if matches!(key.as_str(), "tags" | "tags-ignore") && name == "push" {
                                if trigger.tag_filter.is_some() {
                                    return Err(malformed(
                                        *span,
                                        "tags or tags-ignore, never both",
                                    ));
                                }
                                trigger.tag_filter = Some(TagFilter(filter(
                                    value,
                                    key == "tags-ignore",
                                    PatternScope::Tag,
                                )?));
                                continue;
                            }
                            if name == "workflow_dispatch"
                                || !matches!(key.as_str(), "branches" | "branches-ignore")
                            {
                                return Err(WorkflowRefusal::FieldUnknown {
                                    key: key.clone().into(),
                                    parent: "on.event",
                                    span: *span,
                                });
                            }
                            if trigger.branch_filter.is_some() {
                                return Err(malformed(
                                    *span,
                                    "branches or branches-ignore, never both",
                                ));
                            }
                            trigger.branch_filter = Some(filter(
                                value,
                                key == "branches-ignore",
                                PatternScope::Branch,
                            )?);
                        }
                    }
                    other => {
                        return Err(WorkflowRefusal::FieldShape {
                            path: "on.event",
                            expected: "a trigger-filter mapping or an explicitly empty quoted scalar",
                            observed: other.shape(),
                            span: other.span(),
                        });
                    }
                }
                triggers.push(trigger);
            }
            triggers
        }
    };
    triggers.sort_by(|left, right| left.name.cmp(&right.name));
    triggers.dedup_by(|left, right| left.name == right.name);
    Ok(triggers)
}

// Fixed-memory dynamic programming, not recursive/backtracking. **/ at a
// component boundary matches zero or more complete components. Every token
// checks cancellation; at most 1024 reference bytes are examined in between.
fn matches_pattern(
    tokens: &[Token],
    branch: &[u8],
    cancelled: &impl Fn() -> bool,
) -> Result<bool, TriggerSelectionError> {
    let mut state = [false; MAX_MATCH_BYTES + 1];
    state[0] = true;
    let mut next = [false; MAX_MATCH_BYTES + 1];
    for token in tokens {
        if cancelled() {
            return Err(TriggerSelectionError::Cancelled);
        }
        next[..=branch.len()].fill(false);
        match token {
            Token::Byte(byte) => {
                for (i, observed) in branch.iter().enumerate() {
                    next[i + 1] = state[i] && observed == byte;
                }
            }
            Token::Star | Token::GlobStar => {
                next[0] = state[0];
                for (i, byte) in branch.iter().enumerate() {
                    next[i + 1] =
                        state[i + 1] || next[i] && (*token == Token::GlobStar || *byte != b'/');
                }
            }
            Token::Directories => {
                let mut reachable = false;
                for i in 0..=branch.len() {
                    next[i] = state[i] || reachable && i > 0 && branch[i - 1] == b'/';
                    reachable |= state[i];
                }
            }
        }
        std::mem::swap(&mut state, &mut next);
    }
    Ok(state[branch.len()])
}
