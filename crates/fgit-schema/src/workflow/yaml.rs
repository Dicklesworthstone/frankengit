//! A bounded scanner for the YAML subset the workflow profile accepts.
//!
//! This is not a YAML parser and does not try to be one. It accepts block
//! mappings, block sequences and bounded scalar forms, and refuses every other
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
            // A comment must start the line or follow YAML separation whitespace; `a#b` is a
            // plain scalar containing a hash, not a truncated one.
            b'#' if !single
                && !double
                && (index == 0 || matches!(bytes[index - 1], b' ' | b'\t')) =>
            {
                return &text[..index];
            }
            _ => {}
        }
        index += 1;
    }
    text
}

/// A physical line borrows the original bytes, preserving spans across LF, CRLF
/// and CR line endings. The final line has no invented line break.
#[derive(Clone, Copy)]
struct SourceLine<'a> {
    text: &'a str,
    start: usize,
    end: usize,
    number: u32,
    line_break: bool,
}

struct SourceLines<'a> {
    remaining: &'a str,
    offset: usize,
    number: u32,
}

impl<'a> SourceLines<'a> {
    const fn new(source: &'a str, offset: usize, number: u32) -> Self {
        Self {
            remaining: source,
            offset,
            number,
        }
    }
}

impl<'a> SourceLines<'a> {
    /// Legacy literal scripts treat only LF as a delimiter; an embedded CR is
    /// command data. Syntax and newly admitted block forms use YAML line breaks.
    fn next_with_mode(&mut self, legacy_literal: bool) -> Option<SourceLine<'a>> {
        if self.remaining.is_empty() {
            return None;
        }
        let width = if legacy_literal {
            self.remaining.find('\n')
        } else {
            self.remaining.find(['\r', '\n'])
        }
        .unwrap_or(self.remaining.len());
        let line_break = width < self.remaining.len();
        let consumed = width
            + if !legacy_literal && self.remaining[width..].starts_with("\r\n") {
                2
            } else {
                usize::from(line_break)
            };
        let line = SourceLine {
            text: &self.remaining[..width],
            start: self.offset,
            end: self.offset + consumed,
            number: self.number,
            line_break,
        };
        let physical_lines = if legacy_literal {
            // Keep subsequent source spans accurate even when command bytes
            // contain CR characters which the legacy decoder does not normalize.
            u32::try_from(Self::new(&self.remaining[..consumed], 0, 1).count()).unwrap_or(u32::MAX)
        } else {
            1
        };
        self.remaining = &self.remaining[consumed..];
        self.offset = line.end;
        self.number = self.number.saturating_add(physical_lines);
        Some(line)
    }
}

impl<'a> Iterator for SourceLines<'a> {
    type Item = SourceLine<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_with_mode(false)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Chomping {
    Clip,
    Strip,
    Keep,
}

#[derive(Clone, Copy)]
struct BlockHeader {
    folded: bool,
    indent: Option<usize>,
    chomping: Chomping,
}

impl BlockHeader {
    /// YAML 1.2.2 section 8.1.1 permits one digit 1..9 and one chomping
    /// indicator, in either order, with no intervening whitespace.
    fn parse(text: &str) -> Option<Self> {
        let mut bytes = text.bytes();
        let folded = match bytes.next()? {
            b'|' => false,
            b'>' => true,
            _ => return None,
        };
        let mut header = Self {
            folded,
            indent: None,
            chomping: Chomping::Clip,
        };
        for byte in bytes {
            match byte {
                b'1'..=b'9' if header.indent.is_none() => {
                    header.indent = Some(usize::from(byte - b'0'));
                }
                b'-' if header.chomping == Chomping::Clip => header.chomping = Chomping::Strip,
                b'+' if header.chomping == Chomping::Clip => header.chomping = Chomping::Keep,
                _ => return None,
            }
        }
        Some(header)
    }
}

struct BlockContext {
    parent: usize,
    content_indent: Option<usize>,
    legacy_literal: bool,
}

fn block_context(text: &str, indent: usize) -> Option<BlockContext> {
    let (candidate, offset, sequence) = if let Some(rest) = text.strip_prefix("- ") {
        let rest = scalar_start(rest);
        (rest, text.len() - rest.len(), true)
    } else {
        (text, 0, false)
    };
    let (parent, value) = if let Some((_, value)) = split_entry(candidate) {
        (indent + offset, value)
    } else if sequence {
        (indent, candidate)
    } else {
        return None;
    };
    if !matches!(value.as_bytes().first(), Some(b'|' | b'>')) {
        return None;
    }
    Some(BlockContext {
        parent,
        content_indent: BlockHeader::parse(value)
            .and_then(|header| header.indent)
            .map(|extra| parent + extra),
        legacy_literal: value == "|",
    })
}

/// Split syntax lines without copying any scalar body. Block contents, including
/// comments and blank lines, are decoded from the original source and covered by
/// their scalar's span. Physical line limits are checked in `scan` first.
fn significant_lines(source: &str, _limits: &Limits) -> Result<Vec<Line>, WorkflowRefusal> {
    let mut lines = Vec::new();
    let mut block: Option<BlockContext> = None;
    let mut source_lines = SourceLines::new(source, 0, 1);
    loop {
        let legacy = block.as_ref().is_some_and(|context| context.legacy_literal);
        let Some(mut raw) = source_lines.next_with_mode(legacy) else {
            break;
        };
        let mut indent = raw.text.len() - raw.text.trim_start_matches(' ').len();
        if let Some(context) = &mut block {
            let empty = if context.legacy_literal {
                raw.text.trim().is_empty()
            } else {
                indent == raw.text.len()
            };
            if empty {
                continue;
            }
            if indent > context.parent {
                let required = *context.content_indent.get_or_insert(indent);
                if context.legacy_literal
                    || indent >= required
                    || !raw.text[indent..].starts_with('#')
                {
                    // Content remains opaque even when its indentation is
                    // invalid. The block decoder owns that precise refusal.
                    continue;
                }
            }
            block = None;
            if legacy {
                // This line is outside the literal. Re-read it with normal
                // syntax delimiters so a following CR-only block header works.
                source_lines = SourceLines::new(&source[raw.start..], raw.start, raw.number);
                raw = source_lines
                    .next()
                    .expect("the unconsumed syntax line exists");
                indent = raw.text.len() - raw.text.trim_start_matches(' ').len();
            }
        }

        let after_indent = &raw.text[indent..];
        if after_indent.starts_with('\t') {
            return Err(refuse(
                "yaml.tab-indent",
                Span::new(
                    raw.start + indent,
                    raw.start + indent + 1,
                    raw.number,
                    u32::try_from(indent + 1).unwrap_or(u32::MAX),
                ),
            ));
        }
        let uncommented = strip_comment(after_indent);
        let trimmed = uncommented.trim_end();
        let content =
            if block_context(trimmed, indent).is_some_and(|context| !context.legacy_literal) {
                // YAML separation is only space/tab. Unicode whitespace after a
                // new block header is invalid content, not another spelling of it.
                uncommented.trim_end_matches([' ', '\t'])
            } else {
                trimmed
            };
        if content.is_empty() {
            continue;
        }
        let span = Span::new(
            raw.start + indent,
            raw.start + indent + content.len(),
            raw.number,
            u32::try_from(indent + 1).unwrap_or(u32::MAX),
        );
        if content == "---" || content == "..." || content.starts_with("--- ") {
            return Err(refuse("yaml.document-marker", span));
        }
        block = block_context(content, indent);
        lines.push(Line {
            indent,
            text: content.to_owned(),
            span,
        });
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

/// Recognizes new block-form lookalikes without consuming any whitespace.
/// Bare `|` retains the legacy decoder's broader whitespace normalization.
fn new_block_form(text: &str) -> bool {
    let candidate = text.trim();
    matches!(candidate.as_bytes().first(), Some(b'|' | b'>')) && candidate != "|"
}

/// Newly admitted block forms use only YAML separation (space/tab). A Unicode
/// prefix is scalar/key data, including before a compact mapping's first key.
/// Lookahead must not itself erase that data or change existing bare-`|` bytes.
fn scalar_start(text: &str) -> &str {
    let legacy = text.trim_start();
    if new_block_form(legacy)
        || split_entry_parts(legacy).is_some_and(|(_, value)| new_block_form(value))
    {
        text.trim_start_matches([' ', '\t'])
    } else {
        legacy
    }
}

/// Splits `key: value` at the first unquoted colon-space (or trailing colon),
/// retaining the raw value prefix for the context-sensitive separation rule.
fn split_entry_parts(text: &str) -> Option<(&str, &str)> {
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
                    return Some((&text[..index], rest));
                }
            }
            _ => {}
        }
    }
    None
}

fn split_entry(text: &str) -> Option<(&str, &str)> {
    split_entry_parts(text).map(|(key, value)| (key, scalar_start(value)))
}

/// Visit resolved fragments without allocation. Folding occurs only between
/// ordinary non-empty lines; whitespace-prefixed lines and their separating
/// breaks remain literal. The final break run is chomped, never folded.
fn block_fragments(
    body: &str,
    indent: usize,
    header: BlockHeader,
    mut emit: impl FnMut(&str, usize) -> Result<(), WorkflowRefusal>,
) -> Result<(), WorkflowRefusal> {
    let mut pending_breaks = 0;
    let mut previous_more_indented = false;
    let mut seen_content = false;
    for raw in SourceLines::new(body, 0, 1) {
        let text = if raw.text.len() <= indent {
            ""
        } else {
            &raw.text[indent..]
        };
        if text.is_empty() {
            pending_breaks += usize::from(raw.line_break);
            continue;
        }
        let more_indented = text.starts_with([' ', '\t']);
        if header.folded && seen_content && !previous_more_indented && !more_indented {
            if pending_breaks == 1 {
                emit(" ", 0)?;
            } else {
                emit("", pending_breaks.saturating_sub(1))?;
            }
        } else {
            emit("", pending_breaks)?;
        }
        emit(text, 0)?;
        seen_content = true;
        previous_more_indented = more_indented;
        pending_breaks = usize::from(raw.line_break);
    }
    let trailing = match header.chomping {
        Chomping::Strip => 0,
        Chomping::Clip => usize::from(seen_content && pending_breaks != 0),
        Chomping::Keep => pending_breaks,
    };
    emit("", trailing)
}

/// Recursive-descent state, carrying the node budget across the whole document.
struct Scanner<'a> {
    source: &'a str,
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
            let key_text = if new_block_form(raw_value) {
                raw_key.trim_matches([' ', '\t'])
            } else {
                raw_key.trim()
            };
            if key_text == "<<" {
                return Err(refuse("yaml.merge-key", key_span));
            }
            let key = scalar(key_text, key_span, self.limits)?;
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
            if matches!(raw_value.as_bytes().first(), Some(b'|' | b'>')) {
                self.charge(value_span)?;
                let (value, after) = if raw_value == "|" {
                    self.literal_block(at, indent, value_span)?
                } else {
                    self.block_scalar(at, indent, raw_value, value_span)?
                };
                entries.push((key, value, key_span));
                at = after;
                continue;
            }
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

    /// Decode newly admitted YAML block forms. Bare `|` retains its historical
    /// decoder below because its resolved bytes already enter graph identities.
    fn block_scalar(
        &self,
        at: usize,
        parent_indent: usize,
        text: &str,
        marker: Span,
    ) -> Result<(Node, usize), WorkflowRefusal> {
        let header = BlockHeader::parse(text).ok_or(WorkflowRefusal::Malformed {
            expected: "a block scalar header with one optional digit 1..9 and one optional + or -",
            span: marker,
        })?;
        let header_end = self.lines[at].span.end;
        let start = SourceLines::new(&self.source[header_end..], header_end, marker.line)
            .next()
            .map_or(header_end, |line| line.end);
        let mut end = start;
        let mut required = header.indent.map(|extra| parent_indent + extra);
        let mut leading_spaces = 0;
        let mut leading_span = marker;
        let mut seen_text = false;
        for raw in SourceLines::new(&self.source[start..], start, marker.line.saturating_add(1)) {
            let indent = raw.text.len() - raw.text.trim_start_matches(' ').len();
            if indent == raw.text.len() {
                if !seen_text && indent > leading_spaces {
                    leading_spaces = indent;
                    leading_span = Span::new(raw.start, raw.end, raw.number, 1);
                }
                end = raw.end;
                continue;
            }
            if indent <= parent_indent {
                break;
            }
            let content_indent = *required.get_or_insert(indent);
            if indent < content_indent {
                // The first comment following scalar content must have less
                // indentation; it is a comment, not part of the script.
                if raw.text[indent..].starts_with('#') {
                    break;
                }
                return Err(WorkflowRefusal::Malformed {
                    expected: "block scalar content at its declared or detected indentation",
                    span: Span::new(
                        raw.start + indent,
                        raw.end,
                        raw.number,
                        u32::try_from(indent + 1).unwrap_or(u32::MAX),
                    ),
                });
            }
            if !seen_text && header.indent.is_none() && leading_spaces > content_indent {
                return Err(WorkflowRefusal::Malformed {
                    expected: "leading empty block lines no more indented than the first content line",
                    span: leading_span,
                });
            }
            if let Some((offset, character)) = raw.text.char_indices().find(|(_, character)| {
                !matches!(*character, '\t' | ' '..='~' | '\u{85}' | '\u{a0}'..='\u{d7ff}' |
                    '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
                    || *character == '\u{feff}'
            }) {
                return Err(WorkflowRefusal::Malformed {
                    expected: "printable YAML block scalar content",
                    span: Span::new(
                        raw.start + offset,
                        raw.start + offset + character.len_utf8(),
                        raw.number,
                        u32::try_from(offset + 1).unwrap_or(u32::MAX),
                    ),
                });
            }
            seen_text = true;
            end = raw.end;
        }
        let required = required.unwrap_or_else(|| leading_spaces.max(parent_indent + 1));
        let body = &self.source[start..end];
        let mut total = 0_usize;
        // Fold/chomp in a counting pass before allocating the resolved script.
        block_fragments(body, required, header, |text, breaks| {
            total = total
                .checked_add(text.len())
                .and_then(|n| n.checked_add(breaks))
                .ok_or(WorkflowRefusal::LimitExceeded {
                    limit: "scalar bytes",
                    allowed: self.limits.max_scalar_bytes,
                    observed: usize::MAX,
                    span: marker,
                })?;
            if total > self.limits.max_scalar_bytes {
                return Err(WorkflowRefusal::LimitExceeded {
                    limit: "scalar bytes",
                    allowed: self.limits.max_scalar_bytes,
                    observed: total,
                    span: marker,
                });
            }
            Ok(())
        })?;
        let mut value = String::with_capacity(total);
        block_fragments(body, required, header, |text, breaks| {
            value.push_str(text);
            value.extend(core::iter::repeat_n('\n', breaks));
            Ok(())
        })?;
        let mut after = at + 1;
        while after < self.lines.len() && self.lines[after].span.start < end {
            after += 1;
        }
        Ok((
            Node::Scalar {
                value,
                span: Span::new(marker.start, end, marker.line, marker.column),
            },
            after,
        ))
    }

    fn literal_block(
        &self,
        at: usize,
        parent_indent: usize,
        marker: Span,
    ) -> Result<(Node, usize), WorkflowRefusal> {
        let line = &self.lines[at];
        let tail = &self.source[line.span.end.min(self.source.len())..];
        let Some(relative_newline) = tail.find('\n') else {
            return Err(WorkflowRefusal::Malformed {
                expected: "an indented line after literal |",
                span: marker,
            });
        };
        let mut cursor = line.span.end + relative_newline + 1;
        let mut content_indent = None;
        let mut end = cursor;
        let mut total = 0_usize;
        while cursor <= self.source.len() {
            let rest = &self.source[cursor..];
            let next = rest.find('\n').map_or(self.source.len(), |n| cursor + n);
            let raw = &self.source[cursor..next];
            // Folded bytes this line contributes, including its newline.
            let line_bytes = if raw.trim().is_empty() {
                1
            } else {
                let indent = raw.len() - raw.trim_start_matches(' ').len();
                if indent <= parent_indent {
                    break;
                }
                let required = *content_indent.get_or_insert(indent);
                if indent < required {
                    return Err(WorkflowRefusal::Malformed {
                        expected: "literal block indentation not less than its first content line",
                        span: Span::new(cursor, next, marker.line.saturating_add(1), 1),
                    });
                }
                raw.len() - required + 1
            };
            total = total
                .checked_add(line_bytes)
                .ok_or(WorkflowRefusal::LimitExceeded {
                    limit: "scalar bytes",
                    allowed: self.limits.max_scalar_bytes,
                    observed: usize::MAX,
                    span: marker,
                })?;
            if total > self.limits.max_scalar_bytes {
                return Err(WorkflowRefusal::LimitExceeded {
                    limit: "scalar bytes",
                    allowed: self.limits.max_scalar_bytes,
                    observed: total,
                    span: marker,
                });
            }
            end = if next < self.source.len() {
                next + 1
            } else {
                next
            };
            if next == self.source.len() {
                break;
            }
            cursor = next + 1;
        }
        let Some(required) = content_indent else {
            return Err(WorkflowRefusal::Malformed {
                expected: "at least one non-empty indented literal line",
                span: marker,
            });
        };

        let tail = &self.source[line.span.end..];
        let relative_newline = tail.find('\n').expect("checked above");
        let mut cursor = line.span.end + relative_newline + 1;
        let mut out = String::with_capacity(total.min(self.limits.max_scalar_bytes));
        while cursor < end {
            let rest = &self.source[cursor..end];
            let next = rest.find('\n').map_or(end, |n| cursor + n);
            let raw = &self.source[cursor..next];
            if !raw.trim().is_empty() {
                if raw.len() < required {
                    return Err(WorkflowRefusal::Malformed {
                        expected: "literal block indentation",
                        span: marker,
                    });
                }
                out.push_str(&raw[required..]);
            }
            out.push('\n');
            if next >= end || next == self.source.len() {
                break;
            }
            cursor = next + 1;
        }
        // Bare | uses clip semantics: internal blank lines remain, while any
        // trailing blank run normalizes to exactly one final newline.
        while out.ends_with("\n\n") {
            out.pop();
        }

        let mut after = at + 1;
        while after < self.lines.len() && self.lines[after].span.start < end {
            after += 1;
        }
        Ok((
            Node::Scalar {
                value: out,
                span: Span::new(marker.start, end, marker.line, marker.column),
            },
            after,
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
            let rest = scalar_start(&line.text[1..]);
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
            if matches!(rest.as_bytes().first(), Some(b'|' | b'>')) {
                let (value, after) = if rest == "|" {
                    self.literal_block(at, indent, rest_span)?
                } else {
                    self.block_scalar(at, indent, rest, rest_span)?
                };
                items.push(value);
                at = after;
                continue;
            }
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
            source: self.source,
            lines: &rewritten,
            limits: self.limits,
            nodes: self.nodes,
        };
        let (node, parsed) = inner.mapping(0, indent, depth)?;
        if parsed != rewritten.len() {
            return Err(WorkflowRefusal::Malformed {
                expected: "consistent indentation after a sequence mapping entry",
                span: rewritten[parsed].span,
            });
        }
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
    for (index, line) in SourceLines::new(source, 0, 1).enumerate() {
        if index >= limits.max_lines {
            return Err(WorkflowRefusal::LimitExceeded {
                limit: "lines",
                allowed: limits.max_lines,
                observed: index.saturating_add(1),
                span: Span::new(line.start, line.end, line.number, 1),
            });
        }
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
        source,
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
