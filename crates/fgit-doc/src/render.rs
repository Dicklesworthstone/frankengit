//! Render profiles: pure functions from one document to one byte string.
//!
//! Every profile reads the same tree and the same source. No profile consults
//! the clock, the environment, a hash map iteration order, or a floating point
//! value, so a fixed document renders to identical bytes on every run and every
//! platform. Output is bounded: the sink refuses as soon as the configured
//! output ceiling is passed, so a small hostile input cannot expand without
//! limit.

use crate::ast::{Document, Heading, ListInfo, NodeId, NodeKind};
use crate::html;
use crate::json;
use crate::limits::{Limits, Refusal, RefusalKind, as_u64, usize_of};

/// Which surface to render.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RenderProfile {
    /// Structural plain text, suitable for search indexing and diffing.
    PlainText,
    /// Escaped markup for a browser surface; raw markup is never passed through.
    HtmlSafe,
    /// A one-line-per-node outline for agents and machine consumers.
    CompactMachine,
    /// Canonical `JSON` of the tree, including every span.
    ApiJson,
}

impl RenderProfile {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::PlainText => "plain_text",
            Self::HtmlSafe => "html_safe",
            Self::CompactMachine => "compact_machine",
            Self::ApiJson => "api_json",
        }
    }

    /// Every profile, in a fixed order, for callers that render all surfaces.
    #[must_use]
    pub const fn all() -> [Self; 4] {
        [
            Self::PlainText,
            Self::HtmlSafe,
            Self::CompactMachine,
            Self::ApiJson,
        ]
    }
}

/// One rendered surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    profile: RenderProfile,
    output: String,
}

impl Rendered {
    /// Which profile produced this output.
    #[must_use]
    pub const fn profile(&self) -> RenderProfile {
        self.profile
    }

    /// The rendered bytes as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.output
    }

    /// Consumes the result and returns the rendered text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.output
    }

    /// Length of the rendered output in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.output.len()
    }

    /// Whether the rendered output is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.output.is_empty()
    }
}

/// A bounded output sink with a line-prefix stack.
///
/// The prefix is emitted lazily, only before real content, so a blank line
/// never acquires trailing prefix whitespace and the output stays stable.
pub(crate) struct Sink {
    output: String,
    limit: usize,
    prefix: String,
    pending: bool,
}

impl Sink {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            output: String::new(),
            limit,
            prefix: String::new(),
            pending: true,
        }
    }

    fn guard(&self, extra: usize) -> Result<(), Refusal> {
        let total = self.output.len().saturating_add(extra);
        if total > self.limit {
            return Err(Refusal::exceeded(
                RefusalKind::OutputTooLarge,
                as_u64(self.limit),
                as_u64(total),
            ));
        }
        Ok(())
    }

    /// Writes text, expanding line prefixes at every line start.
    pub(crate) fn write(&mut self, text: &str) -> Result<(), Refusal> {
        for part in text.split_inclusive('\n') {
            let (content, newline) = part
                .strip_suffix('\n')
                .map_or((part, false), |body| (body, true));
            if !content.is_empty() {
                if self.pending && !self.prefix.is_empty() {
                    self.guard(self.prefix.len())?;
                    let prefix = core::mem::take(&mut self.prefix);
                    self.output.push_str(&prefix);
                    self.prefix = prefix;
                }
                self.pending = false;
                self.guard(content.len())?;
                self.output.push_str(content);
            }
            if newline {
                self.guard(1)?;
                self.output.push('\n');
                self.pending = true;
            }
        }
        Ok(())
    }

    pub(crate) fn push_prefix(&mut self, extra: &str) -> usize {
        let previous = self.prefix.len();
        self.prefix.push_str(extra);
        previous
    }

    pub(crate) fn pop_prefix(&mut self, previous: usize) {
        self.prefix.truncate(previous);
    }

    pub(crate) fn finish(self) -> String {
        self.output
    }
}

/// Renders one surface from one document.
pub fn render(
    document: &Document,
    profile: RenderProfile,
    limits: Limits,
) -> Result<Rendered, Refusal> {
    let mut sink = Sink::new(usize_of(limits.max_output_bytes));
    match profile {
        RenderProfile::PlainText => {
            plain_blocks(document, document.roots(), &mut sink, true)?;
            if !document.roots().is_empty() {
                sink.write("\n")?;
            }
        }
        RenderProfile::HtmlSafe => html::render_html(document, &mut sink)?,
        RenderProfile::CompactMachine => compact_nodes(document, document.roots(), &mut sink)?,
        RenderProfile::ApiJson => json::render_json(document, &mut sink)?,
    }
    Ok(Rendered {
        profile,
        output: sink.finish(),
    })
}

// ------------------------------------------------------------------- helpers

/// The literal source text of a node.
pub(crate) fn literal(document: &Document, id: NodeId) -> &str {
    document.node_text(id).unwrap_or("")
}

/// The character an escape sequence stands for.
pub(crate) fn escaped_char(document: &Document, id: NodeId) -> &str {
    let raw = literal(document, id);
    raw.get(1..).unwrap_or(raw)
}

/// The verbatim content of a code block or captured raw block, line by line.
pub(crate) fn verbatim_lines(document: &Document, id: NodeId) -> Vec<&str> {
    document
        .node(id)
        .map(|node| {
            node.children()
                .iter()
                .map(|child| literal(document, *child))
                .collect()
        })
        .unwrap_or_default()
}

/// The plain text of a subtree, with no structural markers.
///
/// This is the text an anchor identifies and the text a search index consumes.
/// It is defined for every node kind, so anchoring is total.
#[must_use]
pub fn subtree_text(document: &Document, id: NodeId) -> String {
    let mut out = String::new();
    append_subtree_text(document, id, &mut out);
    out
}

fn append_subtree_text(document: &Document, id: NodeId, out: &mut String) {
    let Some(node) = document.node(id) else {
        return;
    };
    match node.kind() {
        NodeKind::Text | NodeKind::RawHtmlInline | NodeKind::VerbatimLine => {
            out.push_str(literal(document, id));
        }
        NodeKind::Escaped => out.push_str(escaped_char(document, id)),
        NodeKind::SoftBreak | NodeKind::HardBreak => out.push('\n'),
        NodeKind::ThematicBreak => {}
        NodeKind::Autolink(info) => {
            out.push_str(document.text(info.destination).unwrap_or(""));
        }
        NodeKind::CodeBlock(_) | NodeKind::RawHtmlBlock => {
            for (position, child) in node.children().iter().enumerate() {
                if position > 0 {
                    out.push('\n');
                }
                out.push_str(literal(document, *child));
            }
        }
        _ => {
            let separator = matches!(
                node.kind(),
                NodeKind::Paragraph
                    | NodeKind::Heading(_)
                    | NodeKind::BlockQuote
                    | NodeKind::List(_)
                    | NodeKind::ListItem
            );
            for (position, child) in node.children().iter().enumerate() {
                if separator && position > 0 && block_child(document, *child) {
                    out.push('\n');
                }
                append_subtree_text(document, *child, out);
            }
        }
    }
}

fn block_child(document: &Document, id: NodeId) -> bool {
    document
        .node(id)
        .is_some_and(|node| node.kind().is_block())
}

/// Collapses every run of whitespace to one space and trims the ends.
#[must_use]
pub fn normalize_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_space = false;
    for value in text.chars() {
        if value.is_whitespace() {
            in_space = true;
            continue;
        }
        if in_space && !out.is_empty() {
            out.push(' ');
        }
        in_space = false;
        out.push(value);
    }
    out
}

// ---------------------------------------------------------------- plain text

fn plain_blocks(
    document: &Document,
    ids: &[NodeId],
    sink: &mut Sink,
    loose: bool,
) -> Result<(), Refusal> {
    for (position, id) in ids.iter().enumerate() {
        if position > 0 {
            sink.write("\n")?;
            if loose {
                sink.write("\n")?;
            }
        }
        plain_block(document, *id, sink)?;
    }
    Ok(())
}

fn plain_block(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    match *node.kind() {
        NodeKind::Heading(Heading { level, .. }) => {
            for _ in 0..level {
                sink.write("#")?;
            }
            sink.write(" ")?;
            plain_inlines(document, node.children(), sink)
        }
        NodeKind::Paragraph => plain_inlines(document, node.children(), sink),
        NodeKind::ThematicBreak => sink.write("---"),
        NodeKind::CodeBlock(_) | NodeKind::RawHtmlBlock => {
            for (position, line) in verbatim_lines(document, id).iter().enumerate() {
                if position > 0 {
                    sink.write("\n")?;
                }
                sink.write(line)?;
            }
            Ok(())
        }
        NodeKind::BlockQuote => {
            let saved = sink.push_prefix("> ");
            let result = plain_blocks(document, node.children(), sink, true);
            sink.pop_prefix(saved);
            result
        }
        NodeKind::List(info) => plain_list(document, id, info, sink),
        _ => plain_inlines(document, node.children(), sink),
    }
}

fn plain_list(
    document: &Document,
    id: NodeId,
    info: ListInfo,
    sink: &mut Sink,
) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    for (position, item) in node.children().iter().enumerate() {
        if position > 0 {
            sink.write("\n")?;
            if !info.tight {
                sink.write("\n")?;
            }
        }
        let marker = if info.ordered {
            let number = info.start.saturating_add(as_u64(position));
            format!("{number}. ")
        } else {
            "- ".to_owned()
        };
        sink.write(&marker)?;
        let indent = " ".repeat(marker.len());
        let saved = sink.push_prefix(&indent);
        let children = document.node(*item).map(|entry| entry.children().to_vec());
        let result = match children {
            Some(list) => plain_blocks(document, &list, sink, !info.tight),
            None => Ok(()),
        };
        sink.pop_prefix(saved);
        result?;
    }
    Ok(())
}

fn plain_inlines(document: &Document, ids: &[NodeId], sink: &mut Sink) -> Result<(), Refusal> {
    for id in ids {
        plain_inline(document, *id, sink)?;
    }
    Ok(())
}

fn plain_inline(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    match *node.kind() {
        NodeKind::Text | NodeKind::RawHtmlInline | NodeKind::VerbatimLine => {
            sink.write(literal(document, id))
        }
        NodeKind::Escaped => sink.write(escaped_char(document, id)),
        NodeKind::SoftBreak | NodeKind::HardBreak => sink.write("\n"),
        NodeKind::CodeSpan => {
            for child in node.children() {
                if matches!(
                    document.node(*child).map(crate::ast::Node::kind),
                    Some(NodeKind::SoftBreak)
                ) {
                    sink.write(" ")?;
                } else {
                    plain_inline(document, *child, sink)?;
                }
            }
            Ok(())
        }
        NodeKind::Autolink(info) => sink.write(document.text(info.destination).unwrap_or("")),
        _ => plain_inlines(document, node.children(), sink),
    }
}

// ------------------------------------------------------------ compact machine

fn compact_nodes(document: &Document, ids: &[NodeId], sink: &mut Sink) -> Result<(), Refusal> {
    for id in ids {
        compact_node(document, *id, sink)?;
    }
    Ok(())
}

fn compact_node(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    match *node.kind() {
        NodeKind::Paragraph => compact_leaf_line(document, id, "p", sink),
        NodeKind::Heading(Heading { level, .. }) => {
            compact_leaf_line(document, id, &format!("h{level}"), sink)
        }
        NodeKind::ThematicBreak => sink.write("hr\n"),
        NodeKind::CodeBlock(info) => {
            let language = info
                .info
                .and_then(|span| document.text(span))
                .map(normalize_text)
                .unwrap_or_default();
            sink.write(&format!(
                "code fenced={} info={}\n",
                info.fenced,
                escape_field(&language)
            ))?;
            compact_verbatim(document, id, sink)
        }
        NodeKind::RawHtmlBlock => {
            sink.write("raw-block neutralised=true\n")?;
            compact_verbatim(document, id, sink)
        }
        NodeKind::BlockQuote => {
            sink.write("quote\n")?;
            let saved = sink.push_prefix("  ");
            let result = compact_nodes(document, node.children(), sink);
            sink.pop_prefix(saved);
            result
        }
        NodeKind::List(info) => {
            sink.write(&format!(
                "list ordered={} start={} tight={}\n",
                info.ordered, info.start, info.tight
            ))?;
            let saved = sink.push_prefix("  ");
            let result = compact_nodes(document, node.children(), sink);
            sink.pop_prefix(saved);
            result
        }
        NodeKind::ListItem => {
            sink.write("item\n")?;
            let saved = sink.push_prefix("  ");
            let result = compact_nodes(document, node.children(), sink);
            sink.pop_prefix(saved);
            result
        }
        _ => compact_leaf_line(document, id, node.kind().tag(), sink),
    }
}

fn compact_verbatim(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    let saved = sink.push_prefix("  ");
    let mut result = Ok(());
    for line in verbatim_lines(document, id) {
        result = sink.write(&format!("| {}\n", escape_field(line)));
        if result.is_err() {
            break;
        }
    }
    sink.pop_prefix(saved);
    result
}

fn compact_leaf_line(
    document: &Document,
    id: NodeId,
    tag: &str,
    sink: &mut Sink,
) -> Result<(), Refusal> {
    let text = normalize_text(&subtree_text(document, id));
    sink.write(&format!("{tag} {}\n", escape_field(&text)))
}

/// Escapes a compact-machine field so one node is always one line.
fn escape_field(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for value in text.chars() {
        match value {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(value),
        }
    }
    out
}
