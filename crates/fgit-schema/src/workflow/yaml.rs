//! A bounded scanner for the YAML subset the workflow profile accepts.
//!
//! This is not a YAML parser and does not try to be one. It accepts block
//! mappings, block sequences and three scalar forms, and refuses every other
//! construct **by its registry key**, so the refusal a user sees and the
//! published compatibility table are the same fact.
//!
//! # Limits are checked before the allocation they bound
//!
//! `max_bytes` and `max_lines` are checked against the source before a single
//! node is built. `max_depth`, `max_nodes` and `max_entries` are checked at the
//! moment the scanner is about to descend or push, not after. A limit that
//! fires after the allocation has already happened protects nothing, which is
//! the whole reason a hostile-input parser has limits at all.

use crate::workflow::WorkflowRefusal;
use crate::workflow::registry;

use core::fmt;

/// A byte range in the source, with the line and column of its start.
///
/// Byte offsets rather than character offsets because they are what a diff, an
/// editor and a digest all agree on. Line and column are 1-based for humans.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
    /// 1-based line of `start`.
    pub line: u32,
    /// 1-based column of `start`, in bytes.
    pub column: u32,
}

impl Span {
    /// A span covering one byte range on one line.
    #[must_use]
    pub const fn new(start: usize, end: usize, line: u32, column: u32) -> Self {
        Self {
            start,
            end,
            line,
            column,
        }
    }

    /// Number of bytes the span covers.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// Whether the span covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

impl fmt::Display for Span {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "line {}, column {}", self.line, self.column)
    }
}

/// Pre-allocation bounds for a hostile document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Largest source accepted, in bytes.
    pub max_bytes: usize,
    /// Largest number of lines accepted.
    pub max_lines: usize,
    /// Deepest nesting accepted.
    pub max_depth: usize,
    /// Largest number of nodes accepted across the whole document.
    pub max_nodes: usize,
    /// Longest single scalar accepted, in bytes.
    pub max_scalar_bytes: usize,
    /// Largest number of entries in one mapping or sequence.
    pub max_entries: usize,
}

impl Limits {
    /// Bounds sized for a real workflow rather than for a benchmark.
    ///
    /// Every value is small enough that a hostile document hits it long before
    /// it hits memory, and large enough that no plausible workflow does.
    pub const DEFAULT: Self = Self {
        max_bytes: 256 * 1024,
        max_lines: 4096,
        max_depth: 16,
        max_nodes: 4096,
        max_scalar_bytes: 8192,
        max_entries: 256,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A scanned node.
///
/// Mapping entries and sequence items are `Vec`s rather than maps: source order
/// is preserved, and no output can depend on hash iteration order (§5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    /// A scalar value.
    Scalar {
        /// The resolved text, after quote handling.
        value: String,
        /// Where it came from.
        span: Span,
    },
    /// A block mapping, in source order.
    Mapping {
        /// Key, value and the key's span.
        entries: Vec<(String, Self, Span)>,
        /// Where the mapping starts.
        span: Span,
    },
    /// A block sequence, in source order.
    Sequence {
        /// The items.
        items: Vec<Self>,
        /// Where the sequence starts.
        span: Span,
    },
}

impl Node {
    /// Where this node came from.
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Scalar { span, .. }
            | Self::Mapping { span, .. }
            | Self::Sequence { span, .. } => *span,
        }
    }

    /// The shape name, for a refusal that has to say what it found.
    #[must_use]
    pub const fn shape(&self) -> &'static str {
        match self {
            Self::Scalar { .. } => "a scalar",
            Self::Mapping { .. } => "a mapping",
            Self::Sequence { .. } => "a sequence",
        }
    }

    /// The value of a mapping key, if this is a mapping that has one.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Mapping { entries, .. } => entries
                .iter()
                .find(|(name, _, _)| name == key)
                .map(|(_, value, _)| value),
            _ => None,
        }
    }

    /// The span of a mapping key, if this is a mapping that has one.
    #[must_use]
    pub fn key_span(&self, key: &str) -> Option<Span> {
        match self {
            Self::Mapping { entries, .. } => entries
                .iter()
                .find(|(name, _, _)| name == key)
                .map(|(_, _, span)| *span),
            _ => None,
        }
    }

    /// Total node count, used to check the document against `max_nodes`.
    #[must_use]
    pub fn node_count(&self) -> usize {
        match self {
            Self::Scalar { .. } => 1,
            Self::Mapping { entries, .. } => {
                1 + entries
                    .iter()
                    .map(|(_, v, _)| v.node_count())
                    .sum::<usize>()
            }
            Self::Sequence { items, .. } => 1 + items.iter().map(Self::node_count).sum::<usize>(),
        }
    }
}

/// One significant source line, with comments and trailing space removed.
struct Line {
    indent: usize,
    text: String,
    span: Span,
}

/// Refuses a construct by its registry key, so the message and the published
/// table cannot drift apart.
fn refuse(construct: &'static str, span: Span) -> WorkflowRefusal {
    WorkflowRefusal::ConstructUnsupported {
        construct,
        reason: registry::reason_for(construct),
        span,
    }
}

/// Strips a trailing comment, respecting quotes.
///
/// A `#` inside a quoted scalar is content, not a comment. Getting this wrong
/// silently truncates a `run:` line at the first shell comment, which is a
/// silent drop rather than a refusal.
fn strip_comment(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut single = false;
    let mut double = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            // A comment must start the line or follow a space; `a#b` is a
            // plain scalar containing a hash, not a truncated one.
            b'#' if !single && !double && (index == 0 || bytes[index - 1] == b' ') => {
                return &text[..index];
            }
            _ => {}
        }
        index += 1;
    }
    text
}

/// Splits the source into significant lines, refusing tabs and markers.
fn significant_lines(source: &str, limits: &Limits) -> Result<Vec<Line>, WorkflowRefusal> {
    let mut lines = Vec::new();
    let mut offset = 0_usize;
    for (index, raw) in source.split('\n').enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let line_start = offset;
        offset += raw.len() + 1;

        let indent = raw.len() - raw.trim_start_matches(' ').len();
        let after_indent = &raw[indent..];

        // A tab anywhere in the indentation makes depth depend on tab width.
        if let Some(tab_at) = raw[..indent.min(raw.len())].find('\t') {
            return Err(refuse(
                "yaml.tab-indent",
                Span::new(
                    line_start + tab_at,
                    line_start + tab_at + 1,
                    line_number,
                    u32::try_from(tab_at + 1).unwrap_or(u32::MAX),
                ),
            ));
        }
        if after_indent.starts_with('\t') {
            return Err(refuse(
                "yaml.tab-indent",
                Span::new(line_start + indent, line_start + indent + 1, line_number, 1),
            ));
        }

        let content = strip_comment(after_indent).trim_end();
        if content.is_empty() {
            continue;
        }
        if content == "---" || content == "..." || content.starts_with("--- ") {
            return Err(refuse(
                "yaml.document-marker",
                Span::new(
                    line_start + indent,
                    line_start + indent + content.len(),
                    line_number,
                    u32::try_from(indent + 1).unwrap_or(u32::MAX),
                ),
            ));
        }

        lines.push(Line {
            indent,
            text: content.to_owned(),
            span: Span::new(
                line_start + indent,
                line_start + indent + content.len(),
                line_number,
                u32::try_from(indent + 1).unwrap_or(u32::MAX),
            ),
        });
        if lines.len() > limits.max_lines {
            return Err(WorkflowRefusal::LimitExceeded {
                limit: "lines",
                allowed: limits.max_lines,
                observed: lines.len(),
                span: lines[lines.len() - 1].span,
            });
        }
    }
    Ok(lines)
}

/// Resolves one scalar, refusing the forms the subset excludes.
fn scalar(text: &str, span: Span, limits: &Limits) -> Result<String, WorkflowRefusal> {
    if text.len() > limits.max_scalar_bytes {
        return Err(WorkflowRefusal::LimitExceeded {
            limit: "scalar bytes",
            allowed: limits.max_scalar_bytes,
            observed: text.len(),
            span,
        });
    }
    let first = text.as_bytes().first().copied();
    match first {
        Some(b'&') => return Err(refuse("yaml.anchor", span)),
        Some(b'*') => return Err(refuse("yaml.alias", span)),
        Some(b'!') => return Err(refuse("yaml.tag", span)),
        Some(b'{') => return Err(refuse("yaml.flow-mapping", span)),
        Some(b'[') => return Err(refuse("yaml.flow-sequence", span)),
        Some(b'|' | b'>') => return Err(refuse("yaml.block-scalar", span)),
        _ => {}
    }
    if text.len() >= 2 && text.starts_with('\'') && text.ends_with('\'') {
        // Single quotes: the only escape is '' for a literal quote.
        return Ok(text[1..text.len() - 1].replace("''", "'"));
    }
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        let inner = &text[1..text.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut escaped = false;
        for character in inner.chars() {
            if escaped {
                out.push(match character {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    other => other,
                });
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else {
                out.push(character);
            }
        }
        return Ok(out);
    }
    Ok(text.to_owned())
}

/// Splits `key: value` at the first unquoted colon-space (or trailing colon).
fn split_entry(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut single = false;
    let mut double = false;
    for index in 0..bytes.len() {
        match bytes[index] {
            b'\'' if !double => single = !single,
            b'"' if !single => double = !double,
            b':' if !single && !double => {
                let rest = &text[index + 1..];
                if rest.is_empty() {
                    return Some((&text[..index], ""));
                }
                if rest.starts_with(' ') {
                    return Some((&text[..index], rest.trim_start()));
                }
            }
            _ => {}
        }
    }
    None
}

/// Recursive-descent state, carrying the node budget across the whole document.
struct Scanner<'a> {
    lines: &'a [Line],
    limits: &'a Limits,
    nodes: usize,
}

impl Scanner<'_> {
    /// Charges one node against `max_nodes` before it is built.
    const fn charge(&mut self, span: Span) -> Result<(), WorkflowRefusal> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            return Err(WorkflowRefusal::LimitExceeded {
                limit: "nodes",
                allowed: self.limits.max_nodes,
                observed: self.nodes,
                span,
            });
        }
        Ok(())
    }

    /// Checks the depth budget before descending.
    const fn check_depth(&self, depth: usize, span: Span) -> Result<(), WorkflowRefusal> {
        if depth > self.limits.max_depth {
            return Err(WorkflowRefusal::LimitExceeded {
                limit: "depth",
                allowed: self.limits.max_depth,
                observed: depth,
                span,
            });
        }
        Ok(())
    }

    /// Parses the block starting at `at`, whose lines are indented `indent`.
    ///
    /// Returns the node and the index of the first line after the block.
    fn block(
        &mut self,
        at: usize,
        indent: usize,
        depth: usize,
    ) -> Result<(Node, usize), WorkflowRefusal> {
        let first = &self.lines[at];
        self.check_depth(depth, first.span)?;
        if first.text.starts_with("- ") || first.text == "-" {
            self.sequence(at, indent, depth)
        } else {
            self.mapping(at, indent, depth)
        }
    }

    fn mapping(
        &mut self,
        mut at: usize,
        indent: usize,
        depth: usize,
    ) -> Result<(Node, usize), WorkflowRefusal> {
        let start = self.lines[at].span;
        // Checked here rather than only in `block`: `inline_mapping` reaches a
        // mapping directly, so a depth check that lived only in `block` would
        // not cover a `- key: value` step -- which is the deepest node in every
        // real workflow. Found by a limit test, not by reading.
        self.check_depth(depth, start)?;
        self.charge(start)?;
        let mut entries: Vec<(String, Node, Span)> = Vec::new();
        while at < self.lines.len() && self.lines[at].indent == indent {
            let line = &self.lines[at];
            let Some((raw_key, raw_value)) = split_entry(&line.text) else {
                return Err(WorkflowRefusal::Malformed {
                    expected: "a `key: value` entry",
                    span: line.span,
                });
            };
            let key_span = Span::new(
                line.span.start,
                line.span.start + raw_key.len(),
                line.span.line,
                line.span.column,
            );
            if raw_key.trim() == "<<" {
                return Err(refuse("yaml.merge-key", key_span));
            }
            let key = scalar(raw_key.trim(), key_span, self.limits)?;
            if entries.iter().any(|(existing, _, _)| existing == &key) {
                return Err(WorkflowRefusal::DuplicateKey {
                    key: key.into(),
                    span: key_span,
                });
            }
            if entries.len() >= self.limits.max_entries {
                return Err(WorkflowRefusal::LimitExceeded {
                    limit: "mapping entries",
                    allowed: self.limits.max_entries,
                    observed: entries.len() + 1,
                    span: key_span,
                });
            }

            if raw_value.is_empty() {
                // The value is the indented block that follows.
                let next = at + 1;
                if next < self.lines.len() && self.lines[next].indent > indent {
                    let (value, after) = self.block(next, self.lines[next].indent, depth + 1)?;
                    entries.push((key, value, key_span));
                    at = after;
                    continue;
                }
                return Err(WorkflowRefusal::Malformed {
                    expected: "an indented block after a key with no inline value",
                    span: line.span,
                });
            }

            let value_span = Span::new(
                line.span.end - raw_value.len(),
                line.span.end,
                line.span.line,
                line.span.column + u32::try_from(line.text.len() - raw_value.len()).unwrap_or(0),
            );
            self.charge(value_span)?;
            let value = Node::Scalar {
                value: scalar(raw_value, value_span, self.limits)?,
                span: value_span,
            };
            entries.push((key, value, key_span));
            at += 1;
        }
        Ok((
            Node::Mapping {
                entries,
                span: start,
            },
            at,
        ))
    }

    fn sequence(
        &mut self,
        mut at: usize,
        indent: usize,
        depth: usize,
    ) -> Result<(Node, usize), WorkflowRefusal> {
        let start = self.lines[at].span;
        self.check_depth(depth, start)?;
        self.charge(start)?;
        let mut items: Vec<Node> = Vec::new();
        while at < self.lines.len() && self.lines[at].indent == indent {
            let line = &self.lines[at];
            if !(line.text.starts_with("- ") || line.text == "-") {
                break;
            }
            if items.len() >= self.limits.max_entries {
                return Err(WorkflowRefusal::LimitExceeded {
                    limit: "sequence items",
                    allowed: self.limits.max_entries,
                    observed: items.len() + 1,
                    span: line.span,
                });
            }
            let rest = line.text[1..].trim_start();
            let rest_offset = line.text.len() - rest.len();
            let rest_span = Span::new(
                line.span.start + rest_offset,
                line.span.end,
                line.span.line,
                line.span.column + u32::try_from(rest_offset).unwrap_or(0),
            );

            if rest.is_empty() {
                let next = at + 1;
                if next < self.lines.len() && self.lines[next].indent > indent {
                    let (value, after) = self.block(next, self.lines[next].indent, depth + 1)?;
                    items.push(value);
                    at = after;
                    continue;
                }
                return Err(WorkflowRefusal::Malformed {
                    expected: "an item after `-`",
                    span: line.span,
                });
            }

            if split_entry(rest).is_some() {
                // `- key: value` starts a mapping whose indent is the column of
                // the key. Its continuation lines are indented to match.
                let inner_indent = indent + rest_offset;
                let (value, after) =
                    self.inline_mapping(at, inner_indent, rest_offset, depth + 1)?;
                items.push(value);
                at = after;
                continue;
            }

            self.charge(rest_span)?;
            items.push(Node::Scalar {
                value: scalar(rest, rest_span, self.limits)?,
                span: rest_span,
            });
            at += 1;
        }
        Ok((Node::Sequence { items, span: start }, at))
    }

    /// Parses a mapping whose first entry shares a line with a `-`.
    fn inline_mapping(
        &mut self,
        at: usize,
        indent: usize,
        dash_offset: usize,
        depth: usize,
    ) -> Result<(Node, usize), WorkflowRefusal> {
        // Rewrite the first line as if the dash were indentation, then reuse
        // the ordinary mapping parser. Building a temporary line list keeps the
        // dash handling in one place instead of threading a flag through it.
        let first = &self.lines[at];
        let mut rewritten: Vec<Line> = Vec::new();
        rewritten.push(Line {
            indent,
            text: first.text[dash_offset..].to_owned(),
            span: Span::new(
                first.span.start + dash_offset,
                first.span.end,
                first.span.line,
                first.span.column + u32::try_from(dash_offset).unwrap_or(0),
            ),
        });
        let mut consumed = 1;
        while at + consumed < self.lines.len() && self.lines[at + consumed].indent >= indent {
            let line = &self.lines[at + consumed];
            if line.indent == indent && (line.text.starts_with("- ") || line.text == "-") {
                break;
            }
            rewritten.push(Line {
                indent: line.indent,
                text: line.text.clone(),
                span: line.span,
            });
            consumed += 1;
        }
        let mut inner = Scanner {
            lines: &rewritten,
            limits: self.limits,
            nodes: self.nodes,
        };
        let (node, _) = inner.mapping(0, indent, depth)?;
        self.nodes = inner.nodes;
        Ok((node, at + consumed))
    }
}

/// Scans a workflow document into the subset's node tree.
///
/// Byte and line limits are checked against the source before any node exists.
pub fn scan(source: &str, limits: &Limits) -> Result<Node, WorkflowRefusal> {
    let whole = Span::new(0, source.len(), 1, 1);
    if source.len() > limits.max_bytes {
        return Err(WorkflowRefusal::LimitExceeded {
            limit: "bytes",
            allowed: limits.max_bytes,
            observed: source.len(),
            span: whole,
        });
    }
    let lines = significant_lines(source, limits)?;
    if lines.is_empty() {
        return Err(WorkflowRefusal::Malformed {
            expected: "a non-empty workflow document",
            span: whole,
        });
    }
    let base = lines[0].indent;
    let mut scanner = Scanner {
        lines: &lines,
        limits,
        nodes: 0,
    };
    let (node, consumed) = scanner.block(0, base, 1)?;
    if consumed != lines.len() {
        return Err(WorkflowRefusal::Malformed {
            expected: "consistent indentation; a line is indented less than the block it is in",
            span: lines[consumed].span,
        });
    }
    Ok(node)
}
