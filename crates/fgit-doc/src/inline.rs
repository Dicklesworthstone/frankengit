//! Inline phase: text, escapes, code spans, autolinks, links, and emphasis.
//!
//! The phase runs over a *joined buffer* built from the block's content lines,
//! plus a segment table mapping every buffer offset back to the source. Because
//! a container prefix (a block quote marker, a list indent) is stripped before
//! the buffer is built, the buffer is not a contiguous region of the source, so
//! the phase never lets a leaf cross a segment boundary: line breaks become
//! their own leaves and code span content is split per line. Every emitted leaf
//! therefore still slices the source to exactly its own text.
//!
//! Documented deviations from `CommonMark` in this profile:
//!
//! - link destinations, titles, autolinks, and raw inline markup must be on one
//!   line, so that their spans stay exact; a multi-line attempt is left as text;
//! - reference links and reference definitions are not resolved, and produce a
//!   [`DiagnosticCode::UnresolvedReference`] rather than a hidden failure;
//! - entity references are literal text and are escaped by every renderer;
//! - punctuation classification for the flanking rules is `ASCII`; non-`ASCII`
//!   characters count as ordinary text characters.

use crate::ast::{AutolinkInfo, AutolinkKind, LinkInfo, NodeId, NodeKind};
use crate::builder::{Ctx, LineSlice};
use crate::diagnostic::DiagnosticCode;
use crate::limits::{Refusal, RefusalKind, as_u64, usize_of};
use crate::span::Span;
use crate::url;

/// One contiguous run of the joined buffer and where it came from.
#[derive(Clone, Copy)]
struct Segment {
    buf_start: usize,
    buf_len: usize,
    src_start: usize,
    src_len: usize,
}

/// The joined inline buffer and its mapping back to the source.
struct Buffer {
    text: String,
    segments: Vec<Segment>,
}

impl Buffer {
    fn build(ctx: &Ctx<'_>, lines: &[LineSlice]) -> Self {
        let mut text = String::new();
        let mut segments = Vec::with_capacity(lines.len() * 2);
        for (position, line) in lines.iter().enumerate() {
            let content = ctx.line_text(*line);
            if !content.is_empty() {
                segments.push(Segment {
                    buf_start: text.len(),
                    buf_len: content.len(),
                    src_start: line.start,
                    src_len: content.len(),
                });
                text.push_str(content);
            }
            if position + 1 < lines.len() {
                segments.push(Segment {
                    buf_start: text.len(),
                    buf_len: 1,
                    src_start: line.end,
                    src_len: line.term_end.saturating_sub(line.end),
                });
                text.push('\n');
            }
        }
        Self { text, segments }
    }

    fn segment_at(&self, position: usize) -> Option<&Segment> {
        let index = self
            .segments
            .partition_point(|segment| segment.buf_start <= position)
            .checked_sub(1)?;
        self.segments.get(index)
    }

    /// Source offset of the buffer position where a node begins.
    fn map_start(&self, position: usize) -> usize {
        let Some(segment) = self.segment_at(position) else {
            return self.segments.first().map_or(0, |first| first.src_start);
        };
        let offset = position.saturating_sub(segment.buf_start);
        if offset >= segment.buf_len {
            segment.src_start + segment.src_len
        } else if segment.buf_len == segment.src_len {
            segment.src_start + offset
        } else {
            segment.src_start
        }
    }

    /// Source offset one past the buffer position where a node ends.
    fn map_end(&self, position: usize) -> usize {
        let Some(previous) = position.checked_sub(1) else {
            return self.segments.first().map_or(0, |first| first.src_start);
        };
        let Some(segment) = self.segment_at(previous) else {
            return self.map_start(position);
        };
        let offset = position.saturating_sub(segment.buf_start);
        if offset >= segment.buf_len || segment.buf_len != segment.src_len {
            segment.src_start + segment.src_len
        } else {
            segment.src_start + offset
        }
    }

    fn slice(&self, start: usize, end: usize) -> &str {
        self.text.get(start..end).unwrap_or("")
    }
}

/// What one inline node is, before it becomes an AST node.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Piece {
    Text,
    Escaped,
    SoftBreak,
    HardBreak,
    CodeSpan,
    Autolink(AutolinkKind),
    RawHtmlInline,
    Emphasis,
    Strong,
    Link,
    Image,
}

/// Destination and title buffer ranges of a resolved link or image.
#[derive(Clone, Copy)]
struct LinkData {
    dest_start: usize,
    dest_end: usize,
    title: Option<(usize, usize)>,
}

struct InlineNode {
    piece: Piece,
    start: usize,
    end: usize,
    children: Vec<usize>,
    prev: Option<usize>,
    next: Option<usize>,
    link: Option<LinkData>,
}

/// An intrusive doubly linked list over an append-only node arena.
///
/// Indices are stable for the lifetime of the phase, so the delimiter and
/// bracket stacks can hold them without an index-invalidation hazard.
struct Chain {
    nodes: Vec<InlineNode>,
    head: Option<usize>,
    tail: Option<usize>,
}

impl Chain {
    const fn new() -> Self {
        Self {
            nodes: Vec::new(),
            head: None,
            tail: None,
        }
    }

    fn alloc(&mut self, piece: Piece, start: usize, end: usize) -> usize {
        self.nodes.push(InlineNode {
            piece,
            start,
            end,
            children: Vec::new(),
            prev: None,
            next: None,
            link: None,
        });
        self.nodes.len().saturating_sub(1)
    }

    fn push_back(&mut self, index: usize) {
        let previous = self.tail;
        if let Some(node) = self.nodes.get_mut(index) {
            node.prev = previous;
            node.next = None;
        }
        match previous {
            Some(last) => {
                if let Some(node) = self.nodes.get_mut(last) {
                    node.next = Some(index);
                }
            }
            None => self.head = Some(index),
        }
        self.tail = Some(index);
    }

    fn append(&mut self, piece: Piece, start: usize, end: usize) -> usize {
        let index = self.alloc(piece, start, end);
        self.push_back(index);
        index
    }

    fn unlink(&mut self, index: usize) {
        let (previous, following) = match self.nodes.get(index) {
            Some(node) => (node.prev, node.next),
            None => return,
        };
        match previous {
            Some(before) => {
                if let Some(node) = self.nodes.get_mut(before) {
                    node.next = following;
                }
            }
            None => self.head = following,
        }
        match following {
            Some(after) => {
                if let Some(node) = self.nodes.get_mut(after) {
                    node.prev = previous;
                }
            }
            None => self.tail = previous,
        }
        if let Some(node) = self.nodes.get_mut(index) {
            node.prev = None;
            node.next = None;
        }
    }

    fn insert_after(&mut self, anchor: usize, index: usize) {
        let following = self.nodes.get(anchor).and_then(|node| node.next);
        if let Some(node) = self.nodes.get_mut(index) {
            node.prev = Some(anchor);
            node.next = following;
        }
        if let Some(node) = self.nodes.get_mut(anchor) {
            node.next = Some(index);
        }
        match following {
            Some(after) => {
                if let Some(node) = self.nodes.get_mut(after) {
                    node.prev = Some(index);
                }
            }
            None => self.tail = Some(index),
        }
    }

    /// Removes and returns every live node strictly between two anchors.
    fn take_between(&mut self, opener: usize, closer: usize) -> Vec<usize> {
        let mut taken = Vec::new();
        let mut current = self.nodes.get(opener).and_then(|node| node.next);
        while let Some(index) = current {
            if index == closer {
                break;
            }
            current = self.nodes.get(index).and_then(|node| node.next);
            self.unlink(index);
            taken.push(index);
        }
        taken
    }

    /// Removes and returns every live node after an anchor.
    fn take_after(&mut self, anchor: usize) -> Vec<usize> {
        let mut taken = Vec::new();
        let mut current = self.nodes.get(anchor).and_then(|node| node.next);
        while let Some(index) = current {
            current = self.nodes.get(index).and_then(|node| node.next);
            self.unlink(index);
            taken.push(index);
        }
        taken
    }
}

/// One emphasis delimiter run awaiting a partner.
#[derive(Clone, Copy)]
struct Delimiter {
    node: usize,
    character: u8,
    count: usize,
    original: usize,
    can_open: bool,
    can_close: bool,
}

/// One unmatched bracket opener.
#[derive(Clone, Copy)]
struct Bracket {
    node: usize,
    image: bool,
    active: bool,
    delimiters: usize,
}

struct Scanner<'a> {
    buffer: &'a Buffer,
    chain: Chain,
    delimiters: Vec<Delimiter>,
    brackets: Vec<Bracket>,
    delimiter_budget: usize,
    delimiters_seen: usize,
    unresolved_reference: Option<(usize, usize)>,
}

/// Parses the inline content of one block into AST children of `parent`.
pub(crate) fn parse_inlines(
    ctx: &mut Ctx<'_>,
    parent: NodeId,
    lines: &[LineSlice],
    depth: u32,
) -> Result<(), Refusal> {
    ctx.check_depth(depth)?;
    let buffer = Buffer::build(ctx, lines);
    let mut scanner = Scanner {
        buffer: &buffer,
        chain: Chain::new(),
        delimiters: Vec::new(),
        brackets: Vec::new(),
        delimiter_budget: usize_of(ctx.limits.max_inline_delimiters),
        delimiters_seen: 0,
        unresolved_reference: None,
    };
    scanner.scan()?;
    scanner.process_emphasis(0)?;
    let unresolved = scanner.unresolved_reference;
    let chain = scanner.chain;
    if let Some((start, end)) = unresolved {
        let span = ctx.chars.span(buffer.map_start(start), buffer.map_end(end));
        ctx.diagnose(DiagnosticCode::UnresolvedReference, span);
    }
    emit(ctx, &buffer, &chain, parent, depth)
}

impl Scanner<'_> {
    fn text(&self) -> &str {
        &self.buffer.text
    }

    fn byte_at(&self, position: usize) -> Option<u8> {
        self.text().as_bytes().get(position).copied()
    }

    fn flush_text(&mut self, start: usize, end: usize) {
        if start < end {
            self.chain.append(Piece::Text, start, end);
        }
    }

    fn note_delimiter(&mut self) -> Result<(), Refusal> {
        self.delimiters_seen = self.delimiters_seen.saturating_add(1);
        if self.delimiters_seen > self.delimiter_budget {
            return Err(Refusal::exceeded(
                RefusalKind::TooManyInlineDelimiters,
                as_u64(self.delimiter_budget),
                as_u64(self.delimiters_seen),
            ));
        }
        Ok(())
    }

    fn scan(&mut self) -> Result<(), Refusal> {
        let length = self.text().len();
        let mut position = 0_usize;
        let mut text_start = 0_usize;
        while position < length {
            let Some(byte) = self.byte_at(position) else {
                break;
            };
            match byte {
                b'\n' => {
                    let mut content_end = position;
                    while content_end > text_start
                        && self.byte_at(content_end.saturating_sub(1)) == Some(b' ')
                    {
                        content_end -= 1;
                    }
                    self.flush_text(text_start, content_end);
                    if position.saturating_sub(content_end) >= 2 {
                        self.chain
                            .append(Piece::HardBreak, content_end, position + 1);
                    } else {
                        self.chain.append(Piece::SoftBreak, position, position + 1);
                    }
                    position += 1;
                    text_start = position;
                }
                b'\\' => {
                    let next = self.byte_at(position + 1);
                    if next == Some(b'\n') {
                        self.flush_text(text_start, position);
                        self.chain.append(Piece::HardBreak, position, position + 2);
                        position += 2;
                        text_start = position;
                    } else if next.is_some_and(|value| value.is_ascii_punctuation()) {
                        self.flush_text(text_start, position);
                        self.chain.append(Piece::Escaped, position, position + 2);
                        position += 2;
                        text_start = position;
                    } else {
                        position += 1;
                    }
                }
                b'`' => {
                    position = self.scan_code_span(position, &mut text_start);
                }
                b'<' => {
                    position = self.scan_angle(position, &mut text_start);
                }
                b'!' if self.byte_at(position + 1) == Some(b'[') => {
                    self.flush_text(text_start, position);
                    let node = self.chain.append(Piece::Text, position, position + 2);
                    self.brackets.push(Bracket {
                        node,
                        image: true,
                        active: true,
                        delimiters: self.delimiters.len(),
                    });
                    position += 2;
                    text_start = position;
                }
                b'[' => {
                    self.flush_text(text_start, position);
                    let node = self.chain.append(Piece::Text, position, position + 1);
                    self.brackets.push(Bracket {
                        node,
                        image: false,
                        active: true,
                        delimiters: self.delimiters.len(),
                    });
                    position += 1;
                    text_start = position;
                }
                b']' => {
                    self.flush_text(text_start, position);
                    position = self.scan_close_bracket(position)?;
                    text_start = position;
                }
                b'*' | b'_' => {
                    self.flush_text(text_start, position);
                    position = self.scan_delimiter_run(position, byte)?;
                    text_start = position;
                }
                _ => position += 1,
            }
        }
        let mut tail = length;
        while tail > text_start
            && self
                .byte_at(tail.saturating_sub(1))
                .is_some_and(|value| value == b' ' || value == b'\t')
        {
            tail -= 1;
        }
        self.flush_text(text_start, tail);
        Ok(())
    }

    fn scan_delimiter_run(&mut self, position: usize, character: u8) -> Result<usize, Refusal> {
        let mut end = position;
        while self.byte_at(end) == Some(character) {
            end += 1;
        }
        self.note_delimiter()?;
        let before = char_before(self.text(), position);
        let after = char_at(self.text(), end);
        let left = is_left_flanking(before, after);
        let right = is_right_flanking(before, after);
        let (can_open, can_close) = if character == b'_' {
            (
                left && (!right || before.is_some_and(is_punctuation)),
                right && (!left || after.is_some_and(is_punctuation)),
            )
        } else {
            (left, right)
        };
        let node = self.chain.append(Piece::Text, position, end);
        self.delimiters.push(Delimiter {
            node,
            character,
            count: end.saturating_sub(position),
            original: end.saturating_sub(position),
            can_open,
            can_close,
        });
        Ok(end)
    }

    fn scan_code_span(&mut self, position: usize, text_start: &mut usize) -> usize {
        let mut open_end = position;
        while self.byte_at(open_end) == Some(b'`') {
            open_end += 1;
        }
        let fence = open_end.saturating_sub(position);
        let mut cursor = open_end;
        let length = self.text().len();
        while cursor < length {
            if self.byte_at(cursor) == Some(b'`') {
                let mut run_end = cursor;
                while self.byte_at(run_end) == Some(b'`') {
                    run_end += 1;
                }
                if run_end.saturating_sub(cursor) == fence {
                    self.flush_text(*text_start, position);
                    self.build_code_span(position, open_end, cursor, run_end);
                    *text_start = run_end;
                    return run_end;
                }
                cursor = run_end;
            } else {
                cursor += 1;
            }
        }
        open_end
    }

    fn build_code_span(&mut self, outer: usize, open_end: usize, close: usize, end: usize) {
        let mut inner_start = open_end;
        let mut inner_end = close;
        let content = self.buffer.slice(inner_start, inner_end);
        if content.len() >= 2
            && content.starts_with(' ')
            && content.ends_with(' ')
            && !content.bytes().all(|byte| byte == b' ')
        {
            inner_start += 1;
            inner_end -= 1;
        }
        let node = self.chain.append(Piece::CodeSpan, outer, end);
        let mut run_start = inner_start;
        let mut cursor = inner_start;
        let mut children = Vec::new();
        while cursor < inner_end {
            if self.byte_at(cursor) == Some(b'\n') {
                if run_start < cursor {
                    children.push(self.chain.alloc(Piece::Text, run_start, cursor));
                }
                children.push(self.chain.alloc(Piece::SoftBreak, cursor, cursor + 1));
                cursor += 1;
                run_start = cursor;
            } else {
                cursor += 1;
            }
        }
        if run_start < inner_end {
            children.push(self.chain.alloc(Piece::Text, run_start, inner_end));
        }
        if let Some(entry) = self.chain.nodes.get_mut(node) {
            entry.children = children;
        }
    }

    fn scan_angle(&mut self, position: usize, text_start: &mut usize) -> usize {
        let length = self.text().len();
        let mut cursor = position + 1;
        while cursor < length {
            match self.byte_at(cursor) {
                Some(b'>') => break,
                Some(b'<' | b'\n') | None => return position + 1,
                Some(_) => cursor += 1,
            }
        }
        if cursor >= length {
            return position + 1;
        }
        let inner = self.buffer.slice(position + 1, cursor);
        if inner.chars().any(char::is_whitespace) {
            return position + 1;
        }
        let kind = if matches!(
            url::classify_autolink(inner),
            crate::ast::UrlVerdict::Allowed
        ) {
            Some(AutolinkKind::Uri)
        } else if url::is_email_like(inner) {
            Some(AutolinkKind::Email)
        } else {
            None
        };
        if let Some(kind) = kind {
            self.flush_text(*text_start, position);
            let node = self
                .chain
                .append(Piece::Autolink(kind), position, cursor + 1);
            if let Some(entry) = self.chain.nodes.get_mut(node) {
                entry.link = Some(LinkData {
                    dest_start: position + 1,
                    dest_end: cursor,
                    title: None,
                });
            }
            *text_start = cursor + 1;
            return cursor + 1;
        }
        if is_raw_tag(inner) {
            self.flush_text(*text_start, position);
            self.chain
                .append(Piece::RawHtmlInline, position, cursor + 1);
            *text_start = cursor + 1;
            return cursor + 1;
        }
        position + 1
    }

    fn scan_close_bracket(&mut self, position: usize) -> Result<usize, Refusal> {
        let Some(bracket) = self.brackets.pop() else {
            self.chain.append(Piece::Text, position, position + 1);
            return Ok(position + 1);
        };
        if !bracket.active {
            self.chain.append(Piece::Text, position, position + 1);
            return Ok(position + 1);
        }
        let Some(target) = self.parse_inline_target(position + 1) else {
            if self.byte_at(position + 1) == Some(b'[') && self.unresolved_reference.is_none() {
                let opener = self
                    .chain
                    .nodes
                    .get(bracket.node)
                    .map_or(position, |node| node.start);
                self.unresolved_reference = Some((opener, position + 1));
            }
            self.chain.append(Piece::Text, position, position + 1);
            return Ok(position + 1);
        };
        self.process_emphasis(bracket.delimiters)?;
        self.delimiters.truncate(bracket.delimiters);
        let children = self.chain.take_after(bracket.node);
        let opener_start = self
            .chain
            .nodes
            .get(bracket.node)
            .map_or(position, |node| node.start);
        self.chain.unlink(bracket.node);
        let piece = if bracket.image {
            Piece::Image
        } else {
            Piece::Link
        };
        let node = self.chain.append(piece, opener_start, target.end);
        if let Some(entry) = self.chain.nodes.get_mut(node) {
            entry.children = children;
            entry.link = Some(LinkData {
                dest_start: target.dest_start,
                dest_end: target.dest_end,
                title: target.title,
            });
        }
        if !bracket.image {
            // A link may not contain another link, so every remaining bracket
            // opener becomes inert. Image openers are unaffected: an image
            // inside a link is legal.
            for opener in &mut self.brackets {
                if !opener.image {
                    opener.active = false;
                }
            }
        }
        Ok(target.end)
    }

    /// Parses an inline `(destination "title")` tail on a single line.
    fn parse_inline_target(&self, from: usize) -> Option<Target> {
        if self.byte_at(from) != Some(b'(') {
            return None;
        }
        let mut cursor = from + 1;
        cursor = self.skip_spaces(cursor)?;
        let (dest_start, dest_end, after_dest) = self.parse_destination(cursor)?;
        cursor = self.skip_spaces(after_dest)?;
        let mut title = None;
        if let Some(quote) = self.byte_at(cursor)
            && matches!(quote, b'"' | b'\'')
        {
            let mut scan = cursor + 1;
            loop {
                match self.byte_at(scan) {
                    None | Some(b'\n') => return None,
                    Some(b'\\') => scan += 2,
                    Some(value) if value == quote => break,
                    Some(_) => scan += 1,
                }
            }
            title = Some((cursor + 1, scan));
            cursor = self.skip_spaces(scan + 1)?;
        }
        if self.byte_at(cursor) != Some(b')') {
            return None;
        }
        Some(Target {
            dest_start,
            dest_end,
            title,
            end: cursor + 1,
        })
    }

    fn skip_spaces(&self, from: usize) -> Option<usize> {
        let mut cursor = from;
        loop {
            match self.byte_at(cursor) {
                Some(b' ' | b'\t') => cursor += 1,
                Some(b'\n') | None => return None,
                Some(_) => return Some(cursor),
            }
        }
    }

    fn parse_destination(&self, from: usize) -> Option<(usize, usize, usize)> {
        if self.byte_at(from) == Some(b'<') {
            let mut cursor = from + 1;
            loop {
                match self.byte_at(cursor) {
                    Some(b'>') => return Some((from + 1, cursor, cursor + 1)),
                    Some(b'<' | b'\n') | None => return None,
                    Some(b'\\') => cursor += 2,
                    Some(_) => cursor += 1,
                }
            }
        }
        let mut cursor = from;
        let mut depth = 0_usize;
        loop {
            match self.byte_at(cursor) {
                None | Some(b'\n') => return None,
                Some(b'\\') => cursor += 2,
                Some(b'(') => {
                    depth += 1;
                    cursor += 1;
                }
                Some(b')') => {
                    if depth == 0 {
                        return Some((from, cursor, cursor));
                    }
                    depth -= 1;
                    cursor += 1;
                }
                Some(value) if value.is_ascii_whitespace() => return Some((from, cursor, cursor)),
                Some(_) => cursor += 1,
            }
        }
    }

    /// The `CommonMark` emphasis resolution pass, bounded by the delimiter budget.
    fn process_emphasis(&mut self, stack_bottom: usize) -> Result<(), Refusal> {
        let mut closer_index = stack_bottom;
        let mut steps = 0_usize;
        let budget = self.delimiter_budget.saturating_mul(4).saturating_add(16);
        while closer_index < self.delimiters.len() {
            steps = steps.saturating_add(1);
            if steps > budget {
                return Err(Refusal::exceeded(
                    RefusalKind::TooManyInlineDelimiters,
                    as_u64(self.delimiter_budget),
                    as_u64(steps),
                ));
            }
            let Some(closer) = self.delimiters.get(closer_index).copied() else {
                break;
            };
            if !closer.can_close || closer.count == 0 {
                closer_index += 1;
                continue;
            }
            let Some(opener_index) = self.find_opener(stack_bottom, closer_index, closer) else {
                closer_index += 1;
                continue;
            };
            let Some(opener) = self.delimiters.get(opener_index).copied() else {
                closer_index += 1;
                continue;
            };
            let used = if closer.count >= 2 && opener.count >= 2 {
                2
            } else {
                1
            };
            self.wrap_emphasis(opener, closer, used);
            self.shrink(opener_index, used);
            self.shrink(closer_index, used);
            let removed = closer_index.saturating_sub(opener_index).saturating_sub(1);
            if removed > 0 {
                self.delimiters
                    .drain(opener_index + 1..closer_index)
                    .for_each(drop);
                closer_index -= removed;
            }
            if self
                .delimiters
                .get(closer_index)
                .is_some_and(|entry| entry.count == 0)
            {
                closer_index += 1;
            }
        }
        Ok(())
    }

    fn find_opener(
        &self,
        stack_bottom: usize,
        closer_index: usize,
        closer: Delimiter,
    ) -> Option<usize> {
        let mut cursor = closer_index;
        while cursor > stack_bottom {
            cursor -= 1;
            let candidate = self.delimiters.get(cursor)?;
            if candidate.character != closer.character
                || !candidate.can_open
                || candidate.count == 0
            {
                continue;
            }
            // The rule of three: when either run can both open and close, a
            // match whose combined original lengths are a multiple of three is
            // rejected unless both lengths already are.
            let mixed = candidate.can_close || closer.can_open;
            let combined = candidate.original + closer.original;
            if mixed
                && combined % 3 == 0
                && (candidate.original % 3 != 0 || closer.original % 3 != 0)
            {
                continue;
            }
            return Some(cursor);
        }
        None
    }

    fn shrink(&mut self, delimiter_index: usize, used: usize) {
        let Some(entry) = self.delimiters.get_mut(delimiter_index) else {
            return;
        };
        entry.count = entry.count.saturating_sub(used);
        let node = entry.node;
        // A run whose characters are all consumed leaves no literal text, so
        // it stops being part of the inline sequence. Its stack entry stays,
        // with a zero count, and is skipped by both loops.
        if entry.count == 0 {
            self.chain.unlink(node);
        }
    }

    fn wrap_emphasis(&mut self, opener: Delimiter, closer: Delimiter, used: usize) {
        let children = self.chain.take_between(opener.node, closer.node);
        let opener_end = self
            .chain
            .nodes
            .get(opener.node)
            .map_or(0, |node| node.end)
            .saturating_sub(used);
        let closer_start = self
            .chain
            .nodes
            .get(closer.node)
            .map_or(0, |node| node.start)
            .saturating_add(used);
        if let Some(node) = self.chain.nodes.get_mut(opener.node) {
            node.end = opener_end;
        }
        if let Some(node) = self.chain.nodes.get_mut(closer.node) {
            node.start = closer_start;
        }
        let piece = if used >= 2 {
            Piece::Strong
        } else {
            Piece::Emphasis
        };
        let wrapper = self.chain.alloc(piece, opener_end, closer_start);
        if let Some(node) = self.chain.nodes.get_mut(wrapper) {
            node.children = children;
        }
        self.chain.insert_after(opener.node, wrapper);
    }
}

/// A parsed inline link tail.
struct Target {
    dest_start: usize,
    dest_end: usize,
    title: Option<(usize, usize)>,
    end: usize,
}

// -------------------------------------------------------------------- output

fn emit(
    ctx: &mut Ctx<'_>,
    buffer: &Buffer,
    chain: &Chain,
    parent: NodeId,
    depth: u32,
) -> Result<(), Refusal> {
    let mut stack: Vec<(usize, NodeId, u32)> = Vec::new();
    let mut current = chain.head;
    let mut roots = Vec::new();
    while let Some(index) = current {
        roots.push(index);
        current = chain.nodes.get(index).and_then(|node| node.next);
    }
    for index in roots.into_iter().rev() {
        stack.push((index, parent, depth));
    }
    while let Some((index, target, level)) = stack.pop() {
        ctx.check_depth(level)?;
        let Some(node) = chain.nodes.get(index) else {
            continue;
        };
        if node.start >= node.end {
            continue;
        }
        let span = ctx
            .chars
            .span(buffer.map_start(node.start), buffer.map_end(node.end));
        // A node whose kind cannot be reconstructed is transparent rather
        // than fatal: its children are attached to its parent, so no text is
        // dropped on a path that should be unreachable anyway.
        let target = match node_kind(ctx, buffer, node, span) {
            Some(kind) => ctx.add(kind, span, Some(target))?,
            None => target,
        };
        for child in node.children.iter().rev() {
            stack.push((*child, target, level.saturating_add(1)));
        }
    }
    Ok(())
}

fn node_kind(
    ctx: &mut Ctx<'_>,
    buffer: &Buffer,
    node: &InlineNode,
    span: Span,
) -> Option<NodeKind> {
    let kind = match node.piece {
        Piece::Text => NodeKind::Text,
        Piece::Escaped => NodeKind::Escaped,
        Piece::SoftBreak => NodeKind::SoftBreak,
        Piece::HardBreak => NodeKind::HardBreak,
        Piece::CodeSpan => NodeKind::CodeSpan,
        Piece::Emphasis => NodeKind::Emphasis,
        Piece::Strong => NodeKind::Strong,
        Piece::RawHtmlInline => {
            ctx.diagnose(DiagnosticCode::RawMarkupNeutralised, span);
            NodeKind::RawHtmlInline
        }
        Piece::Autolink(autolink) => {
            let data = node.link?;
            let destination = ctx.chars.span(
                buffer.map_start(data.dest_start),
                buffer.map_end(data.dest_end),
            );
            let raw = buffer.slice(data.dest_start, data.dest_end);
            let verdict = if autolink == AutolinkKind::Email {
                crate::ast::UrlVerdict::Allowed
            } else {
                url::classify_autolink(raw)
            };
            if !verdict.is_allowed() {
                ctx.diagnose(DiagnosticCode::RejectedDestination, span);
            }
            NodeKind::Autolink(AutolinkInfo {
                kind: autolink,
                destination,
                verdict,
            })
        }
        Piece::Link | Piece::Image => {
            let data = node.link?;
            let destination = ctx.chars.span(
                buffer.map_start(data.dest_start),
                buffer.map_end(data.dest_end),
            );
            let title = data
                .title
                .map(|(start, end)| ctx.chars.span(buffer.map_start(start), buffer.map_end(end)));
            let decoded = decode_escapes(buffer.slice(data.dest_start, data.dest_end));
            let verdict = url::classify(&decoded);
            if !verdict.is_allowed() {
                ctx.diagnose(DiagnosticCode::RejectedDestination, span);
            }
            let info = LinkInfo {
                destination,
                title,
                verdict,
            };
            if node.piece == Piece::Image {
                NodeKind::Image(info)
            } else {
                NodeKind::Link(info)
            }
        }
    };
    Some(kind)
}

/// Removes backslash escapes from a raw destination before policy checks.
pub(crate) fn decode_escapes(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(value) = characters.next() {
        if value == '\\' {
            match characters.next() {
                Some(next) if next.is_ascii_punctuation() => out.push(next),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(value);
        }
    }
    out
}

// ---------------------------------------------------------------- classifiers

fn char_before(text: &str, position: usize) -> Option<char> {
    text.get(..position)
        .and_then(|prefix| prefix.chars().next_back())
}

fn char_at(text: &str, position: usize) -> Option<char> {
    text.get(position..)
        .and_then(|suffix| suffix.chars().next())
}

fn is_punctuation(value: char) -> bool {
    value.is_ascii_punctuation()
}

fn is_space(value: Option<char>) -> bool {
    value.is_none_or(char::is_whitespace)
}

fn is_left_flanking(before: Option<char>, after: Option<char>) -> bool {
    if is_space(after) {
        return false;
    }
    match after {
        Some(value) if is_punctuation(value) => {
            is_space(before) || before.is_some_and(is_punctuation)
        }
        _ => true,
    }
}

fn is_right_flanking(before: Option<char>, after: Option<char>) -> bool {
    if is_space(before) {
        return false;
    }
    match before {
        Some(value) if is_punctuation(value) => {
            is_space(after) || after.is_some_and(is_punctuation)
        }
        _ => true,
    }
}

/// Whether angle-bracket content looks like a markup tag rather than prose.
fn is_raw_tag(inner: &str) -> bool {
    let bytes = inner.as_bytes();
    if inner.starts_with('!') || inner.starts_with('?') || inner.starts_with('/') {
        return inner.len() > 1;
    }
    let mut cursor = 0_usize;
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        cursor += 1;
    }
    matches!(bytes.get(cursor), None | Some(b'/'))
}
