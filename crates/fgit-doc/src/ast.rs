//! The one document tree every surface renders from.
//!
//! The tree is an arena: nodes live in a flat vector and reference each other
//! by [`NodeId`]. That keeps drop flat (a pathologically nested document does
//! not recurse on drop), makes cross-surface references cheap and stable, and
//! lets traversal use an explicit stack instead of the call stack.
//!
//! Span discipline, which the whole crate depends on:
//!
//! - a **leaf** node's span is exactly the source region of its literal text,
//!   so slicing the source with it round-trips that leaf exactly;
//! - a **container** node's span is the exact source extent of the whole
//!   construct, markers included, so it is the hull of its children widened by
//!   its own syntax;
//! - siblings are ordered and never overlap, and every child span is contained
//!   in its parent's span;
//! - a leaf never crosses a source discontinuity: where a container prefix
//!   (a block quote marker, a list indent) interrupts the text, the parser
//!   emits separate leaves so that no leaf span covers stripped markers.

use crate::limits::{Refusal, RefusalKind, as_u64, usize_of};
use crate::profile::ProfileId;
use crate::span::{LineCol, LineTable, Span};

/// A stable index into a [`Document`]'s node arena.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(u32);

impl NodeId {
    /// The arena index this identifier addresses.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0
    }

    /// Builds an identifier from an arena position.
    pub(crate) fn from_index(index: usize) -> Self {
        Self(crate::limits::offset_u32(index))
    }
}

/// Whether a heading was written with leading hashes or an underline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeadingStyle {
    /// `# Heading`
    Atx,
    /// `Heading` followed by an `=` or `-` underline.
    Setext,
}

/// Heading level and syntax.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Heading {
    /// Heading level, one through six.
    pub level: u8,
    /// Which syntax produced the heading.
    pub style: HeadingStyle,
}

/// List kind, numbering, marker character, and spacing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ListInfo {
    /// Whether the list is numbered.
    pub ordered: bool,
    /// First number of an ordered list; one for a bullet list.
    pub start: u64,
    /// The marker byte: one of `-`, `+`, `*`, `.`, or `)`.
    pub marker: u8,
    /// Whether the list is tight, meaning items render without paragraphs.
    pub tight: bool,
}

/// Code block syntax and info string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CodeBlockInfo {
    /// Whether the block was fenced rather than indented.
    pub fenced: bool,
    /// Span of the raw info string that followed the opening fence.
    pub info: Option<Span>,
    /// Whether the closing fence was missing from the source.
    pub unterminated: bool,
}

/// Why a link or image destination was not accepted for navigation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UrlRejection {
    /// The scheme is not on the navigable allowlist.
    DisallowedScheme,
    /// The destination contains a control character or whitespace.
    ControlCharacter,
    /// The destination is longer than this crate accepts.
    TooLong,
}

impl UrlRejection {
    /// Stable machine-readable tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::DisallowedScheme => "disallowed_scheme",
            Self::ControlCharacter => "control_character",
            Self::TooLong => "too_long",
        }
    }
}

/// The policy decision taken about one destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UrlVerdict {
    /// The destination may be emitted as a navigable target.
    Allowed,
    /// The destination is inert: renderers emit its text, never a target.
    Rejected(UrlRejection),
}

impl UrlVerdict {
    /// Whether the destination may be emitted as a navigable target.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Destination, title, and policy verdict of a link or image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkInfo {
    /// Span of the raw destination text in the source.
    pub destination: Span,
    /// Span of the raw title text in the source, without its quotes.
    pub title: Option<Span>,
    /// Whether the destination survived the link policy.
    pub verdict: UrlVerdict,
}

/// Which autolink syntax was recognised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AutolinkKind {
    /// An absolute `URI` inside angle brackets.
    Uri,
    /// An email address inside angle brackets.
    Email,
}

/// Autolink kind and policy verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AutolinkInfo {
    /// Which autolink syntax was recognised.
    pub kind: AutolinkKind,
    /// Span of the destination text between the angle brackets.
    pub destination: Span,
    /// Whether the destination survived the link policy.
    pub verdict: UrlVerdict,
}

/// What a node is.
///
/// Leaf kinds carry no children and their span is exactly their literal source
/// text. Container kinds carry children and their span is the whole construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    /// A paragraph of inline content.
    Paragraph,
    /// A heading of inline content.
    Heading(Heading),
    /// A block quote containing blocks.
    BlockQuote,
    /// A bullet or ordered list containing items.
    List(ListInfo),
    /// One list item containing blocks.
    ListItem,
    /// A fenced or indented code block containing code lines.
    CodeBlock(CodeBlockInfo),
    /// One contiguous source line of verbatim content.
    ///
    /// Used for code block lines and for the lines of captured raw markup.
    /// A verbatim line never crosses a source discontinuity, so its span
    /// slices the source to exactly the line's content.
    VerbatimLine,
    /// A horizontal rule.
    ThematicBreak,
    /// A run of raw block-level markup, captured verbatim and never emitted raw.
    ///
    /// Its children are the [`NodeKind::VerbatimLine`] leaves holding the
    /// captured bytes.
    RawHtmlBlock,
    /// A contiguous run of literal text.
    Text,
    /// A backslash escape; its span covers both bytes.
    Escaped,
    /// A line break inside a block that renders as a space or newline.
    SoftBreak,
    /// An explicit line break.
    HardBreak,
    /// An inline code span containing text and soft breaks.
    CodeSpan,
    /// Emphasised inline content.
    Emphasis,
    /// Strongly emphasised inline content.
    Strong,
    /// A link whose children are its text.
    Link(LinkInfo),
    /// An image whose children are its alternative text.
    Image(LinkInfo),
    /// A bracketed absolute destination.
    Autolink(AutolinkInfo),
    /// A run of raw inline markup, captured verbatim and never emitted raw.
    RawHtmlInline,
}

impl NodeKind {
    /// Stable machine-readable tag, used by receipts, anchors, and renderers.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Paragraph => "paragraph",
            Self::Heading(_) => "heading",
            Self::BlockQuote => "block_quote",
            Self::List(_) => "list",
            Self::ListItem => "list_item",
            Self::CodeBlock(_) => "code_block",
            Self::VerbatimLine => "verbatim_line",
            Self::ThematicBreak => "thematic_break",
            Self::RawHtmlBlock => "raw_html_block",
            Self::Text => "text",
            Self::Escaped => "escaped",
            Self::SoftBreak => "soft_break",
            Self::HardBreak => "hard_break",
            Self::CodeSpan => "code_span",
            Self::Emphasis => "emphasis",
            Self::Strong => "strong",
            Self::Link(_) => "link",
            Self::Image(_) => "image",
            Self::Autolink(_) => "autolink",
            Self::RawHtmlInline => "raw_html_inline",
        }
    }

    /// Whether this kind is a block-level construct.
    #[must_use]
    pub const fn is_block(&self) -> bool {
        matches!(
            self,
            Self::Paragraph
                | Self::Heading(_)
                | Self::BlockQuote
                | Self::List(_)
                | Self::ListItem
                | Self::CodeBlock(_)
                | Self::ThematicBreak
                | Self::RawHtmlBlock
        )
    }

    /// Whether this kind never carries children.
    #[must_use]
    pub const fn is_leaf(&self) -> bool {
        matches!(
            self,
            Self::VerbatimLine
                | Self::ThematicBreak
                | Self::Text
                | Self::Escaped
                | Self::SoftBreak
                | Self::HardBreak
                | Self::RawHtmlInline
        )
    }
}

/// One node of the document tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    kind: NodeKind,
    span: Span,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
}

impl Node {
    /// What this node is.
    #[must_use]
    pub const fn kind(&self) -> &NodeKind {
        &self.kind
    }

    /// The exact source extent of this node.
    #[must_use]
    pub const fn span(&self) -> Span {
        self.span
    }

    /// The containing node, absent for a document root.
    #[must_use]
    pub const fn parent(&self) -> Option<NodeId> {
        self.parent
    }

    /// Children in source order.
    #[must_use]
    pub fn children(&self) -> &[NodeId] {
        &self.children
    }
}

/// A parsed document: one immutable source and the tree derived from it.
///
/// The document owns its source text, so a span can never be applied to the
/// wrong bytes and every renderer is a pure function of the document alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    source: Box<str>,
    profile: ProfileId,
    nodes: Vec<Node>,
    roots: Vec<NodeId>,
    lines: LineTable,
}

impl Document {
    /// The source text this document was parsed from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The profile identity that produced this document.
    #[must_use]
    pub const fn profile(&self) -> ProfileId {
        self.profile
    }

    /// Top-level blocks in source order.
    #[must_use]
    pub fn roots(&self) -> &[NodeId] {
        &self.roots
    }

    /// Every node in arena order.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Number of nodes in the arena.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Looks a node up, returning `None` for an identifier from another document.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(usize_of(id.0))
    }

    /// The exact source text covered by a span.
    ///
    /// Returns `None` only for a span built against a different source.
    #[must_use]
    pub fn text(&self, span: Span) -> Option<&str> {
        self.source.get(span.byte_range())
    }

    /// The exact source text of a node.
    #[must_use]
    pub fn node_text(&self, id: NodeId) -> Option<&str> {
        self.node(id).and_then(|node| self.text(node.span()))
    }

    /// One-based line and column of a byte offset.
    #[must_use]
    pub fn position(&self, byte_offset: u32) -> LineCol {
        self.lines.position(&self.source, byte_offset)
    }

    /// Number of lines in the source.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.lines.line_count()
    }

    /// Preorder traversal of the whole tree.
    #[must_use]
    pub fn preorder(&self) -> Preorder<'_> {
        Preorder::rooted(self, None)
    }

    /// Preorder traversal of one subtree, starting at `root` itself.
    #[must_use]
    pub fn subtree(&self, root: NodeId) -> Preorder<'_> {
        Preorder::rooted(self, Some(root))
    }

    /// The structural path of a node: child indices from the document root.
    ///
    /// The path is empty for a node that is not reachable, and otherwise ends
    /// with the node's own index within its parent.
    #[must_use]
    pub fn path_of(&self, id: NodeId) -> Vec<u32> {
        let mut reversed = Vec::new();
        let mut current = id;
        loop {
            let Some(node) = self.node(current) else {
                return Vec::new();
            };
            let siblings = node.parent().map_or_else(
                || self.roots.as_slice(),
                |parent| {
                    self.node(parent)
                        .map_or(&[] as &[NodeId], |value| value.children())
                },
            );
            let Some(index) = siblings.iter().position(|entry| *entry == current) else {
                return Vec::new();
            };
            reversed.push(crate::limits::offset_u32(index));
            match node.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }
        reversed.reverse();
        reversed
    }
}

/// Preorder traversal over a document or one of its subtrees.
///
/// Traversal uses an explicit stack, so depth costs heap rather than call
/// frames and a deeply nested document cannot overflow the stack here.
pub struct Preorder<'doc> {
    document: &'doc Document,
    stack: Vec<(NodeId, u32)>,
}

impl<'doc> Preorder<'doc> {
    fn rooted(document: &'doc Document, root: Option<NodeId>) -> Self {
        let mut stack = Vec::new();
        match root {
            Some(id) => stack.push((id, 0)),
            None => {
                for id in document.roots().iter().rev() {
                    stack.push((*id, 0));
                }
            }
        }
        Self { document, stack }
    }
}

impl Iterator for Preorder<'_> {
    /// The visited node and its depth relative to the traversal root.
    type Item = (NodeId, u32);

    fn next(&mut self) -> Option<Self::Item> {
        let (id, depth) = self.stack.pop()?;
        if let Some(node) = self.document.node(id) {
            for child in node.children().iter().rev() {
                self.stack.push((*child, depth.saturating_add(1)));
            }
        }
        Some((id, depth))
    }
}

/// Arena builder used by the parser.
///
/// The node ceiling is enforced on every insertion, before the node is
/// allocated, so a hostile document cannot exhaust memory between checks.
pub(crate) struct Builder {
    nodes: Vec<Node>,
    roots: Vec<NodeId>,
    max_nodes: u32,
}

impl Builder {
    pub(crate) fn new(max_nodes: u32) -> Self {
        Self {
            nodes: Vec::new(),
            roots: Vec::new(),
            max_nodes,
        }
    }

    pub(crate) fn add(
        &mut self,
        kind: NodeKind,
        span: Span,
        parent: Option<NodeId>,
    ) -> Result<NodeId, Refusal> {
        if self.nodes.len() >= usize_of(self.max_nodes) {
            return Err(Refusal::exceeded(
                RefusalKind::TooManyNodes,
                u64::from(self.max_nodes),
                as_u64(self.nodes.len().saturating_add(1)),
            ));
        }
        let id = NodeId::from_index(self.nodes.len());
        self.nodes.push(Node {
            kind,
            span,
            parent,
            children: Vec::new(),
        });
        match parent {
            Some(parent_id) => {
                if let Some(node) = self.nodes.get_mut(usize_of(parent_id.0)) {
                    node.children.push(id);
                }
            }
            None => self.roots.push(id),
        }
        Ok(id)
    }

    pub(crate) fn set_span(&mut self, id: NodeId, span: Span) {
        if let Some(node) = self.nodes.get_mut(usize_of(id.0)) {
            node.span = span;
        }
    }

    pub(crate) fn set_kind(&mut self, id: NodeId, kind: NodeKind) {
        if let Some(node) = self.nodes.get_mut(usize_of(id.0)) {
            node.kind = kind;
        }
    }

    pub(crate) fn span_of(&self, id: NodeId) -> Option<Span> {
        self.nodes.get(usize_of(id.0)).map(|node| node.span)
    }

    pub(crate) fn children_of(&self, id: NodeId) -> &[NodeId] {
        self.nodes
            .get(usize_of(id.0))
            .map_or(&[] as &[NodeId], |node| node.children())
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(crate) fn finish(self, source: &str, profile: ProfileId, lines: LineTable) -> Document {
        Document {
            source: Box::from(source),
            profile,
            nodes: self.nodes,
            roots: self.roots,
            lines,
        }
    }
}
