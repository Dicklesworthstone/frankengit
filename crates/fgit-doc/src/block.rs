//! Block phase: containers and leaf blocks, by recursive descent over lines.
//!
//! Each recursion strips exactly one container prefix and descends, so the
//! recursion depth is bounded by the profile's nesting ceiling, which is
//! checked before every descent.

use crate::ast::{CodeBlockInfo, Heading, HeadingStyle, ListInfo, NodeId, NodeKind};
use crate::builder::{
    Ctx, LineSlice, measure_indent, span_of_lines, strip_columns, trim_trailing_blanks,
};
use crate::diagnostic::DiagnosticCode;
use crate::inline;
use crate::limits::Refusal;

/// Parses a run of lines as the block children of `parent`.
pub fn parse_blocks(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    parent: Option<NodeId>,
    depth: u32,
) -> Result<(), Refusal> {
    ctx.check_depth(depth)?;
    let mut cursor = 0_usize;
    while cursor < lines.len() {
        let Some(line) = lines.get(cursor) else {
            break;
        };
        if ctx.is_blank(*line) {
            cursor += 1;
            continue;
        }
        let next = parse_one_block(ctx, lines, cursor, parent, depth)?;
        // Every branch below consumes at least the current line; the max keeps
        // the loop total even if a future branch forgets to.
        cursor = next.max(cursor.saturating_add(1));
    }
    Ok(())
}

fn parse_one_block(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    parent: Option<NodeId>,
    depth: u32,
) -> Result<usize, Refusal> {
    let Some(line) = lines.get(cursor).copied() else {
        return Ok(cursor.saturating_add(1));
    };
    let (indent_columns, content_start) = measure_indent(ctx.source, line.start);
    if indent_columns >= 4 {
        return indented_code(ctx, lines, cursor, parent);
    }
    let rest = ctx.source.get(content_start..line.end).unwrap_or("");
    if is_thematic_break(rest) {
        let span = ctx.span(content_start, line.end);
        ctx.add(NodeKind::ThematicBreak, span, parent)?;
        return Ok(cursor.saturating_add(1));
    }
    if let Some(heading) = atx_heading(rest) {
        return atx_heading_block(ctx, lines, cursor, content_start, heading, parent, depth);
    }
    if let Some(fence) = fence_open(rest) {
        return fenced_code(
            ctx,
            lines,
            cursor,
            indent_columns,
            content_start,
            fence,
            parent,
        );
    }
    if rest.starts_with('>') {
        return block_quote(ctx, lines, cursor, parent, depth);
    }
    if let Some(marker) = list_marker(rest, indent_columns, content_start) {
        return list(ctx, lines, cursor, marker, parent, depth);
    }
    if is_html_block_start(rest) {
        return html_block(ctx, lines, cursor, parent);
    }
    paragraph(ctx, lines, cursor, parent, depth)
}

// ---------------------------------------------------------------- detectors

/// Whether a line is a thematic break: three or more of one marker character.
fn is_thematic_break(text: &str) -> bool {
    let mut marker = 0_u8;
    let mut count = 0_usize;
    for byte in text.bytes() {
        match byte {
            b' ' | b'\t' => {}
            b'-' | b'_' | b'*' => {
                if marker == 0 {
                    marker = byte;
                } else if marker != byte {
                    return false;
                }
                count += 1;
            }
            _ => return false,
        }
    }
    marker != 0 && count >= 3
}

/// Level and content offsets of an `ATX` heading line, relative to `text`.
struct AtxHeading {
    level: u8,
    content_start: usize,
    content_end: usize,
}

fn atx_heading(text: &str) -> Option<AtxHeading> {
    let bytes = text.as_bytes();
    let mut hashes = 0_usize;
    while bytes.get(hashes) == Some(&b'#') {
        hashes += 1;
    }
    if hashes == 0 || hashes > 6 {
        return None;
    }
    if !matches!(bytes.get(hashes), None | Some(b' ' | b'\t')) {
        return None;
    }
    let mut start = hashes;
    while matches!(bytes.get(start), Some(b' ' | b'\t')) {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && matches!(bytes.get(end - 1), Some(b' ' | b'\t')) {
        end -= 1;
    }
    let mut closing = end;
    while closing > start && bytes.get(closing - 1) == Some(&b'#') {
        closing -= 1;
    }
    if closing < end && (closing == start || matches!(bytes.get(closing - 1), Some(b' ' | b'\t'))) {
        end = closing;
        while end > start && matches!(bytes.get(end - 1), Some(b' ' | b'\t')) {
            end -= 1;
        }
    }
    Some(AtxHeading {
        level: u8::try_from(hashes).unwrap_or(6),
        content_start: start,
        content_end: end,
    })
}

/// Character, length, and info-string offset of an opening code fence.
struct Fence {
    character: u8,
    length: usize,
    info_start: usize,
}

fn fence_open(text: &str) -> Option<Fence> {
    let bytes = text.as_bytes();
    let character = match bytes.first() {
        Some(b'`') => b'`',
        Some(b'~') => b'~',
        _ => return None,
    };
    let mut length = 0_usize;
    while bytes.get(length) == Some(&character) {
        length += 1;
    }
    if length < 3 {
        return None;
    }
    let info = text.get(length..).unwrap_or("");
    if character == b'`' && info.contains('`') {
        return None;
    }
    Some(Fence {
        character,
        length,
        info_start: length,
    })
}

fn is_fence_close(text: &str, character: u8, length: usize) -> bool {
    let bytes = text.as_bytes();
    let mut run = 0_usize;
    while bytes.get(run) == Some(&character) {
        run += 1;
    }
    run >= length
        && text
            .get(run..)
            .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_whitespace()))
}

/// A recognised list marker and the column at which its item content starts.
#[derive(Clone, Copy)]
struct Marker {
    ordered: bool,
    start: u64,
    character: u8,
    content_columns: usize,
    content_start: usize,
    content_is_empty: bool,
}

fn list_marker(text: &str, indent_columns: usize, content_start: usize) -> Option<Marker> {
    let bytes = text.as_bytes();
    let (ordered, start, marker_len, character) = match bytes.first() {
        Some(value @ (b'-' | b'+' | b'*')) => (false, 1_u64, 1_usize, *value),
        Some(value) if value.is_ascii_digit() => {
            let mut digits = 0_usize;
            while bytes.get(digits).is_some_and(u8::is_ascii_digit) {
                digits += 1;
            }
            if digits > 9 {
                return None;
            }
            let punctuation = match bytes.get(digits) {
                Some(value @ (b'.' | b')')) => *value,
                _ => return None,
            };
            let number = text.get(..digits)?.parse::<u64>().ok()?;
            (true, number, digits + 1, punctuation)
        }
        _ => return None,
    };
    let after = text.get(marker_len..).unwrap_or("");
    let (spaces, offset) = measure_indent(after, 0);
    let content_is_empty = offset >= after.len();
    if spaces == 0 && !content_is_empty {
        return None;
    }
    let width = if content_is_empty || spaces > 4 {
        1
    } else {
        spaces
    };
    Some(Marker {
        ordered,
        start,
        character,
        content_columns: indent_columns + marker_len + width,
        content_start: content_start + marker_len + if content_is_empty { 0 } else { offset },
        content_is_empty,
    })
}

/// Whether a line opens a raw markup block.
///
/// The tag name must be followed by whitespace, `>`, `/`, or the line end, so
/// an autolink such as an angle-bracketed destination is not mistaken for one.
fn is_html_block_start(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.first() != Some(&b'<') {
        return false;
    }
    if text.starts_with("<!--") || text.starts_with("<?") || text.starts_with("<![CDATA[") {
        return true;
    }
    let mut cursor = 1_usize;
    if bytes.get(cursor) == Some(&b'!') {
        return bytes.get(cursor + 1).is_some_and(u8::is_ascii_alphabetic);
    }
    if bytes.get(cursor) == Some(&b'/') {
        cursor += 1;
    }
    if !bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    {
        cursor += 1;
    }
    matches!(bytes.get(cursor), None | Some(b' ' | b'\t' | b'>' | b'/'))
}

/// Whether a line matches a setext underline.
fn setext_level(text: &str) -> Option<u8> {
    let bytes = text.as_bytes();
    let character = match bytes.first() {
        Some(b'=') => b'=',
        Some(b'-') => b'-',
        _ => return None,
    };
    let mut run = 0_usize;
    while bytes.get(run) == Some(&character) {
        run += 1;
    }
    let tail_is_blank = text
        .get(run..)
        .is_some_and(|rest| rest.bytes().all(|byte| byte.is_ascii_whitespace()));
    if !tail_is_blank {
        return None;
    }
    Some(if character == b'=' { 1 } else { 2 })
}

/// Whether a line would begin a new block, ending an open paragraph.
fn starts_new_block(ctx: &Ctx<'_>, line: LineSlice) -> bool {
    let (indent_columns, content_start) = measure_indent(ctx.source, line.start);
    if indent_columns >= 4 {
        return false;
    }
    let rest = ctx.source.get(content_start..line.end).unwrap_or("");
    if is_thematic_break(rest)
        || atx_heading(rest).is_some()
        || fence_open(rest).is_some()
        || rest.starts_with('>')
        || is_html_block_start(rest)
    {
        return true;
    }
    // Only a marker with content can interrupt a paragraph, and an ordered
    // marker must start at one; otherwise ordinary prose beginning with a
    // number would be swallowed by a list.
    list_marker(rest, indent_columns, content_start)
        .is_some_and(|marker| !marker.content_is_empty && (!marker.ordered || marker.start == 1))
}

// ------------------------------------------------------------- block builders

fn indented_code(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    parent: Option<NodeId>,
) -> Result<usize, Refusal> {
    let mut end = cursor;
    while let Some(line) = lines.get(end) {
        let (indent_columns, _) = measure_indent(ctx.source, line.start);
        if ctx.is_blank(*line) || indent_columns >= 4 {
            end += 1;
        } else {
            break;
        }
    }
    let collected = lines.get(cursor..end).unwrap_or(&[]);
    let kept = trim_trailing_blanks(ctx, collected);
    let body = collected.get(..kept).unwrap_or(&[]);
    let Some(span) = span_of_lines(ctx, body) else {
        return Ok(cursor.saturating_add(1));
    };
    let info = CodeBlockInfo {
        fenced: false,
        info: None,
        unterminated: false,
    };
    let block = ctx.add(NodeKind::CodeBlock(info), span, parent)?;
    for line in body {
        let stripped = strip_columns(ctx.source, *line, 4);
        let line_span = ctx.span(stripped.start, stripped.end);
        ctx.add(NodeKind::VerbatimLine, line_span, Some(block))?;
    }
    Ok(cursor.saturating_add(kept.max(1)))
}

fn fenced_code(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    indent_columns: usize,
    content_start: usize,
    fence: Fence,
    parent: Option<NodeId>,
) -> Result<usize, Refusal> {
    let Some(open_line) = lines.get(cursor).copied() else {
        return Ok(cursor.saturating_add(1));
    };
    let info_start = content_start + fence.info_start;
    let raw_info = ctx.source.get(info_start..open_line.end).unwrap_or("");
    let leading = raw_info.len() - raw_info.trim_start().len();
    let trimmed = raw_info.trim();
    let info_span = if trimmed.is_empty() {
        None
    } else {
        Some(ctx.span(info_start + leading, info_start + leading + trimmed.len()))
    };

    let mut end = cursor + 1;
    let mut closing = None;
    while let Some(line) = lines.get(end) {
        let (line_indent, line_content) = measure_indent(ctx.source, line.start);
        let text = ctx.source.get(line_content..line.end).unwrap_or("");
        if line_indent < 4 && is_fence_close(text, fence.character, fence.length) {
            closing = Some(end);
            break;
        }
        end += 1;
    }
    let body_end = closing.unwrap_or(end);
    let last_end = closing
        .or_else(|| body_end.checked_sub(1))
        .and_then(|index| lines.get(index))
        .map_or(open_line.end, |line| line.end)
        .max(open_line.end);
    let span = ctx.span(open_line.start, last_end);
    let info = CodeBlockInfo {
        fenced: true,
        info: info_span,
        unterminated: closing.is_none(),
    };
    let block = ctx.add(NodeKind::CodeBlock(info), span, parent)?;
    if closing.is_none() {
        ctx.diagnose(DiagnosticCode::UnterminatedCodeFence, span);
    }
    for line in lines.get(cursor + 1..body_end).unwrap_or(&[]) {
        let stripped = strip_columns(ctx.source, *line, indent_columns);
        let line_span = ctx.span(stripped.start, stripped.end);
        ctx.add(NodeKind::VerbatimLine, line_span, Some(block))?;
    }
    Ok(closing.map_or(body_end, |index| index + 1).max(cursor + 1))
}

fn atx_heading_block(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    content_start: usize,
    heading: AtxHeading,
    parent: Option<NodeId>,
    depth: u32,
) -> Result<usize, Refusal> {
    let Some(line) = lines.get(cursor).copied() else {
        return Ok(cursor.saturating_add(1));
    };
    let span = ctx.span(content_start, line.end);
    let node = ctx.add(
        NodeKind::Heading(Heading {
            level: heading.level,
            style: HeadingStyle::Atx,
        }),
        span,
        parent,
    )?;
    let content = LineSlice {
        start: content_start + heading.content_start,
        end: content_start + heading.content_end,
        term_end: line.term_end,
    };
    if content.start < content.end {
        inline::parse_inlines(ctx, node, &[content], depth + 1)?;
    }
    Ok(cursor.saturating_add(1))
}

fn block_quote(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    parent: Option<NodeId>,
    depth: u32,
) -> Result<usize, Refusal> {
    let mut inner = Vec::new();
    let mut end = cursor;
    let mut in_fence = false;
    let mut previous_is_text = false;
    while let Some(line) = lines.get(end).copied() {
        let (indent_columns, content_start) = measure_indent(ctx.source, line.start);
        let rest = ctx.source.get(content_start..line.end).unwrap_or("");
        if indent_columns < 4 && rest.starts_with('>') {
            let mut start = content_start + 1;
            if matches!(ctx.source.as_bytes().get(start), Some(b' ' | b'\t')) {
                start += 1;
            }
            let stripped = LineSlice {
                start: start.min(line.end),
                end: line.end,
                term_end: line.term_end,
            };
            let stripped_text = ctx.line_text(stripped);
            let (_, stripped_content) = measure_indent(ctx.source, stripped.start);
            let stripped_rest = ctx.source.get(stripped_content..stripped.end).unwrap_or("");
            if fence_open(stripped_rest).is_some() {
                in_fence = !in_fence;
            }
            previous_is_text = !stripped_text.trim().is_empty();
            inner.push(stripped);
            end += 1;
            continue;
        }
        if end == cursor {
            break;
        }
        let is_lazy = previous_is_text
            && !in_fence
            && !ctx.is_blank(line)
            && !starts_new_block(ctx, line)
            && !rest.starts_with('>');
        if !is_lazy {
            break;
        }
        inner.push(line);
        end += 1;
    }
    if inner.is_empty() {
        return Ok(cursor.saturating_add(1));
    }
    let kept = trim_trailing_blanks(ctx, &inner);
    let body = inner.get(..kept).unwrap_or(&[]);
    let Some(open_line) = lines.get(cursor) else {
        return Ok(cursor.saturating_add(1));
    };
    let (_, marker_start) = measure_indent(ctx.source, open_line.start);
    let last_end = body.last().map_or(open_line.end, |line| line.end);
    let span = ctx.span(marker_start, last_end.max(marker_start));
    let node = ctx.add(NodeKind::BlockQuote, span, parent)?;
    parse_blocks(ctx, body, Some(node), depth + 1)?;
    Ok(end.max(cursor + 1))
}

/// Gathers one list item's lines and returns the index after them.
struct ItemScan {
    lines: Vec<LineSlice>,
    next: usize,
    interior_blank: bool,
    trailing_blank: bool,
}

fn scan_item(
    ctx: &Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    marker: Marker,
    line: LineSlice,
) -> ItemScan {
    let mut collected = vec![LineSlice {
        start: marker.content_start.min(line.end),
        end: line.end,
        term_end: line.term_end,
    }];
    let mut end = cursor + 1;
    let mut previous_is_text = !marker.content_is_empty;
    while let Some(candidate) = lines.get(end).copied() {
        if ctx.is_blank(candidate) {
            collected.push(strip_columns(ctx.source, candidate, marker.content_columns));
            previous_is_text = false;
            end += 1;
            continue;
        }
        let (indent_columns, _) = measure_indent(ctx.source, candidate.start);
        if indent_columns >= marker.content_columns {
            collected.push(strip_columns(ctx.source, candidate, marker.content_columns));
            previous_is_text = true;
            end += 1;
            continue;
        }
        if previous_is_text && !starts_new_block(ctx, candidate) {
            collected.push(candidate);
            end += 1;
            continue;
        }
        break;
    }
    let kept = trim_trailing_blanks(ctx, &collected);
    let trailing_blank = kept < collected.len();
    let body = collected.get(..kept).unwrap_or(&[]).to_vec();
    let interior_blank = body.iter().any(|entry| ctx.is_blank(*entry));
    ItemScan {
        lines: body,
        next: end,
        interior_blank,
        trailing_blank,
    }
}

fn list(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    first: Marker,
    parent: Option<NodeId>,
    depth: u32,
) -> Result<usize, Refusal> {
    ctx.check_depth(depth + 1)?;
    let Some(open_line) = lines.get(cursor).copied() else {
        return Ok(cursor.saturating_add(1));
    };
    let (_, list_start) = measure_indent(ctx.source, open_line.start);
    let placeholder = ctx.span(list_start, open_line.end);
    let node = ctx.add(
        NodeKind::List(ListInfo {
            ordered: first.ordered,
            start: first.start,
            marker: first.character,
            tight: true,
        }),
        placeholder,
        parent,
    )?;

    let mut position = cursor;
    let mut marker = first;
    let mut loose = false;
    let mut last_end = open_line.end;
    let mut after = cursor.saturating_add(1);
    while let Some(line) = lines.get(position).copied() {
        let (_, marker_start) = measure_indent(ctx.source, line.start);
        let scan = scan_item(ctx, lines, position, marker, line);
        loose = loose || scan.interior_blank;
        let separated_from_next = scan.trailing_blank;
        let item_end = scan
            .lines
            .last()
            .map_or(line.end, |entry| entry.end)
            .max(line.end);
        let item_span = ctx.span(marker_start, item_end);
        let item = ctx.add(NodeKind::ListItem, item_span, Some(node))?;
        parse_blocks(ctx, &scan.lines, Some(item), depth + 2)?;
        last_end = item_end;
        after = scan.next.max(position.saturating_add(1));

        let mut lookahead = scan.next;
        let mut skipped_blank = false;
        while lines
            .get(lookahead)
            .is_some_and(|entry| ctx.is_blank(*entry))
        {
            skipped_blank = true;
            lookahead += 1;
        }
        let Some(next_line) = lines.get(lookahead).copied() else {
            break;
        };
        let (indent_columns, content_start) = measure_indent(ctx.source, next_line.start);
        if indent_columns >= 4 {
            break;
        }
        let rest = ctx.source.get(content_start..next_line.end).unwrap_or("");
        if is_thematic_break(rest) {
            break;
        }
        let Some(next_marker) = list_marker(rest, indent_columns, content_start) else {
            break;
        };
        if next_marker.ordered != marker.ordered || next_marker.character != marker.character {
            break;
        }
        // A blank line between two items makes the list loose whether the item
        // scan absorbed it as a trailing blank or the lookahead skipped it.
        loose = loose || skipped_blank || separated_from_next;
        marker = next_marker;
        position = lookahead;
    }

    let final_span = ctx.chars.span(list_start, last_end.max(list_start));
    ctx.builder.set_span(node, final_span);
    ctx.builder.set_kind(
        node,
        NodeKind::List(ListInfo {
            ordered: first.ordered,
            start: first.start,
            marker: first.character,
            tight: !loose,
        }),
    );
    Ok(after.max(cursor.saturating_add(1)))
}

fn html_block(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    parent: Option<NodeId>,
) -> Result<usize, Refusal> {
    let mut end = cursor;
    while lines.get(end).is_some_and(|line| !ctx.is_blank(*line)) {
        end += 1;
    }
    let body = lines.get(cursor..end).unwrap_or(&[]);
    let Some(span) = span_of_lines(ctx, body) else {
        return Ok(cursor.saturating_add(1));
    };
    let node = ctx.add(NodeKind::RawHtmlBlock, span, parent)?;
    ctx.diagnose(DiagnosticCode::RawMarkupNeutralised, span);
    for line in body {
        let line_span = ctx.span(line.start, line.end);
        ctx.add(NodeKind::VerbatimLine, line_span, Some(node))?;
    }
    Ok(end.max(cursor + 1))
}

/// Whether a paragraph's first line opens a link reference definition.
fn is_reference_definition(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('[') else {
        return false;
    };
    let Some(close) = rest.find(']') else {
        return false;
    };
    close > 0
        && rest
            .get(close + 1..)
            .is_some_and(|tail| tail.starts_with(':'))
}

fn paragraph(
    ctx: &mut Ctx<'_>,
    lines: &[LineSlice],
    cursor: usize,
    parent: Option<NodeId>,
    depth: u32,
) -> Result<usize, Refusal> {
    let mut content = Vec::new();
    let mut end = cursor;
    let mut setext = None;
    while let Some(line) = lines.get(end).copied() {
        if ctx.is_blank(line) {
            break;
        }
        let (indent_columns, content_start) = measure_indent(ctx.source, line.start);
        let rest = ctx.source.get(content_start..line.end).unwrap_or("");
        if end > cursor {
            if indent_columns < 4
                && let Some(level) = setext_level(rest)
            {
                setext = Some((level, line));
                end += 1;
                break;
            }
            if starts_new_block(ctx, line) {
                break;
            }
        }
        content.push(LineSlice {
            start: content_start,
            end: line.end,
            term_end: line.term_end,
        });
        end += 1;
    }
    if content.is_empty() {
        return Ok(cursor.saturating_add(1));
    }
    let first_text = content.first().map_or("", |line| ctx.line_text(*line));
    let is_definition = is_reference_definition(first_text);
    let body_span = span_of_lines(ctx, &content);
    let (kind, span) = match (setext, body_span) {
        (Some((level, underline)), Some(body)) => (
            NodeKind::Heading(Heading {
                level,
                style: HeadingStyle::Setext,
            }),
            ctx.span(body.byte_range().start, underline.end),
        ),
        (None, Some(body)) => (NodeKind::Paragraph, body),
        (_, None) => return Ok(cursor.saturating_add(1)),
    };
    let node = ctx.add(kind, span, parent)?;
    if is_definition {
        ctx.diagnose(DiagnosticCode::UnresolvedReference, span);
    }
    inline::parse_inlines(ctx, node, &content, depth + 1)?;
    Ok(end.max(cursor + 1))
}
