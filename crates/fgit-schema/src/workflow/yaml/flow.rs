//! Single-physical-line flow collections. The same node/entry/scalar/nesting
//! budgets govern block and flow forms; neither spelling gets an extra budget.
//! Scalars remain strings, and ordinary block spellings keep their old bytes.

use super::{Limits, Node, Span, WorkflowRefusal, charge_node, check_nesting, refuse, scalar};

pub(super) fn starts(text: &str) -> bool {
    matches!(text.as_bytes().first(), Some(b'[' | b'{'))
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// Locate a quoted token without allocating or interpreting its escapes.
/// Single-quote doubling and double-quote escapes affect token boundaries.
fn quoted_end(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let quote = *bytes.first()?;
    if !matches!(quote, b'\'' | b'"') {
        return None;
    }
    let mut at = 1;
    while at < bytes.len() {
        if bytes[at] == quote {
            if quote == b'\'' && bytes.get(at + 1) == Some(&quote) {
                at += 2;
            } else {
                return Some(at + 1);
            }
        } else if quote == b'"' && bytes[at] == b'\\' {
            at += 2;
        } else {
            at += 1;
        }
    }
    None
}

/// Recognize only a block entry whose value begins a new flow collection.
/// Its prefix is read independently of the legacy block quote/comment lexer.
/// Quotation marks inside a plain key are data, not quoted-token delimiters.
pub(super) fn entry(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let colon = if matches!(bytes.first(), Some(b'\'' | b'"')) {
        let mut at = quoted_end(text)?;
        while bytes.get(at).copied().is_some_and(space) {
            at += 1;
        }
        (bytes.get(at) == Some(&b':')).then_some(at)?
    } else {
        let mut found = None;
        for (at, &byte) in bytes.iter().enumerate() {
            if byte == b'#' && (at == 0 || space(bytes[at - 1])) {
                return None;
            }
            if byte == b':' && bytes.get(at + 1).copied().is_some_and(space) {
                found = Some(at);
                break;
            }
        }
        found?
    };
    if !bytes.get(colon + 1).copied().is_some_and(space) {
        return None;
    }
    let value = text[colon + 1..].trim_start_matches([' ', '\t']);
    starts(value).then_some((&text[..colon], value))
}

pub(super) fn line_has_collection(text: &str) -> bool {
    let value = text
        .strip_prefix("- ")
        .map_or(text, |rest| rest.trim_start_matches([' ', '\t']));
    starts(value) || entry(value).is_some()
}

/// New block entries with flow values use the same strict scalar-key spelling
/// as flow mappings. Keys are not nodes and keep the existing node accounting.
pub(super) fn key(text: &str, span: Span, limits: &Limits) -> Result<String, WorkflowRefusal> {
    let mut nodes = 0;
    let mut parser = Parser {
        text,
        span,
        limits,
        nodes: &mut nodes,
        at: 0,
    };
    let (value, _, _) = parser.scalar_token(true)?;
    parser.whitespace();
    if parser.at != text.len() {
        return Err(parser.error("one complete scalar mapping key"));
    }
    Ok(value)
}

pub(super) fn parse(
    text: &str,
    span: Span,
    depth: usize,
    limits: &Limits,
    nodes: &mut usize,
) -> Result<Node, WorkflowRefusal> {
    let mut parser = Parser {
        text,
        span,
        limits,
        nodes,
        at: 0,
    };
    let node = parser.node(depth)?;
    let end = parser.at;
    parser.whitespace();
    if parser.at != text.len() && !(parser.at > end && parser.peek() == Some(b'#')) {
        return Err(parser.error("end of the flow collection or a separated trailing comment"));
    }
    Ok(node)
}

struct Parser<'a, 'b> {
    text: &'a str,
    span: Span,
    limits: &'a Limits,
    nodes: &'b mut usize,
    at: usize,
}

impl Parser<'_, '_> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn span(&self, start: usize, end: usize) -> Span {
        Span::new(
            self.span.start + start,
            self.span.start + end,
            self.span.line,
            self.span
                .column
                .saturating_add(u32::try_from(start).unwrap_or(u32::MAX)),
        )
    }

    fn error(&self, expected: &'static str) -> WorkflowRefusal {
        let width = self.text[self.at..]
            .chars()
            .next()
            .map_or(0, char::len_utf8);
        WorkflowRefusal::Malformed {
            expected,
            span: self.span(self.at, self.at + width),
        }
    }

    fn whitespace(&mut self) {
        while self.peek().is_some_and(space) {
            self.at += 1;
        }
    }

    fn entries(&self, count: usize, mapping: bool) -> Result<(), WorkflowRefusal> {
        if count >= self.limits.max_entries {
            return Err(WorkflowRefusal::LimitExceeded {
                limit: if mapping {
                    "mapping entries"
                } else {
                    "sequence items"
                },
                allowed: self.limits.max_entries,
                observed: count + 1,
                span: self.span(self.at, self.at),
            });
        }
        Ok(())
    }

    fn node(&mut self, depth: usize) -> Result<Node, WorkflowRefusal> {
        let start = self.at;
        let width = self.text[start..].chars().next().map_or(0, char::len_utf8);
        let marker = self.span(start, start + width);
        match self.peek() {
            Some(b'[' | b'{') => {
                check_nesting(depth, self.limits.max_depth, marker)?;
                charge_node(self.nodes, self.limits.max_nodes, marker)?;
                if self.peek() == Some(b'[') {
                    self.sequence(depth)
                } else {
                    self.mapping(depth)
                }
            }
            _ => {
                charge_node(self.nodes, self.limits.max_nodes, marker)?;
                let (value, span, _) = self.scalar_token(false)?;
                Ok(Node::Scalar { value, span })
            }
        }
    }

    fn sequence(&mut self, depth: usize) -> Result<Node, WorkflowRefusal> {
        let start = self.at;
        self.at += 1;
        self.whitespace();
        let mut items = Vec::new();
        if self.peek() != Some(b']') {
            loop {
                self.entries(items.len(), false)?;
                items.push(self.node(depth + 1)?);
                if self.separator(b']')? {
                    break;
                }
            }
        } else {
            self.at += 1;
        }
        Ok(Node::Sequence {
            items,
            span: self.span(start, self.at),
        })
    }

    fn mapping(&mut self, depth: usize) -> Result<Node, WorkflowRefusal> {
        let start = self.at;
        self.at += 1;
        self.whitespace();
        let mut entries: Vec<(String, Node, Span)> = Vec::new();
        if self.peek() != Some(b'}') {
            loop {
                self.entries(entries.len(), true)?;
                let (key, key_span, quoted) = self.scalar_token(true)?;
                if !quoted && key == "<<" {
                    return Err(refuse("yaml.merge-key", key_span));
                }
                if entries.iter().any(|(previous, _, _)| *previous == key) {
                    return Err(WorkflowRefusal::DuplicateKey {
                        key: key.into(),
                        span: key_span,
                    });
                }
                self.whitespace();
                if self.peek() != Some(b':') {
                    return Err(
                        self.error("a colon and explicit value after a scalar flow mapping key")
                    );
                }
                self.at += 1;
                if !quoted && !self.peek().is_some_and(space) {
                    return Err(
                        self.error("space or tab after an unquoted flow mapping key's colon")
                    );
                }
                self.whitespace();
                let value = self.node(depth + 1)?;
                entries.push((key, value, key_span));
                if self.separator(b'}')? {
                    break;
                }
            }
        } else {
            self.at += 1;
        }
        Ok(Node::Mapping {
            entries,
            span: self.span(start, self.at),
        })
    }

    /// Consume a collection separator or terminator. A single trailing comma
    /// is accepted, but a missing item, doubled comma or wrong closer is not.
    fn separator(&mut self, closer: u8) -> Result<bool, WorkflowRefusal> {
        self.whitespace();
        if self.peek() == Some(closer) {
            self.at += 1;
            return Ok(true);
        }
        if self.peek() != Some(b',') {
            return Err(self.error("a comma or matching closer on the same physical line"));
        }
        self.at += 1;
        self.whitespace();
        if self.peek() == Some(closer) {
            self.at += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn scalar_token(&mut self, key: bool) -> Result<(String, Span, bool), WorkflowRefusal> {
        let start = self.at;
        let quoted = matches!(self.peek(), Some(b'\'' | b'"'));
        if quoted {
            let end = quoted_end(&self.text[start..])
                .ok_or_else(|| self.error("a complete quoted scalar on the same physical line"))?;
            self.at += end;
        } else {
            self.plain(key)?;
        }
        let raw = self.text[start..self.at].trim_end_matches([' ', '\t']);
        let span = self.span(start, start + raw.len());
        if raw.is_empty() {
            return Err(
                self.error("an explicit scalar or collection; empty flow nodes are not supported")
            );
        }
        validate_scalar(raw, span, self.limits)?;
        Ok((scalar(raw, span, self.limits)?, span, quoted))
    }

    fn plain(&mut self, key: bool) -> Result<(), WorkflowRefusal> {
        let start = self.at;
        let bytes = self.text.as_bytes();
        let span = self.span(
            start,
            start.min(bytes.len()).saturating_add(1).min(bytes.len()),
        );
        match self.peek() {
            Some(b'&') => return Err(refuse("yaml.anchor", span)),
            Some(b'*') => return Err(refuse("yaml.alias", span)),
            Some(b'!') => return Err(refuse("yaml.tag", span)),
            None
            | Some(b'[' | b'{' | b']' | b'}' | b',' | b'#' | b'|' | b'>' | b'@' | b'`' | b'%') => {
                return Err(self.error("a nonempty scalar; complex keys, directives and block forms are not supported inside flow collections"));
            }
            Some(b'?' | b':' | b'-')
                if bytes
                    .get(start + 1)
                    .copied()
                    .is_none_or(|byte| space(byte) || b"[]{},".contains(&byte)) =>
            {
                return Err(self
                    .error("a plain scalar without an explicit-key or block-sequence indicator"));
            }
            _ => {}
        }
        while let Some(byte) = self.peek() {
            match byte {
                b',' | b']' | b'}' => break,
                b'[' | b'{' => {
                    return Err(self.error("quotes around flow scalar brackets or braces"));
                }
                b'#' if self.at == start || space(bytes[self.at - 1]) => {
                    return Err(
                        self.error("a complete single-line collection before a separated comment")
                    );
                }
                b':' if bytes
                    .get(self.at + 1)
                    .copied()
                    .is_none_or(|next| space(next) || b"[]{},".contains(&next)) =>
                {
                    if key {
                        break;
                    }
                    return Err(self.error("quotes around a flow scalar colon followed by separation or a delimiter; implicit pairs are not supported"));
                }
                _ => self.at += 1,
            }
        }
        Ok(())
    }
}

fn validate_scalar(text: &str, span: Span, limits: &Limits) -> Result<(), WorkflowRefusal> {
    if text.len() > limits.max_scalar_bytes {
        return Err(WorkflowRefusal::LimitExceeded {
            limit: "scalar bytes",
            allowed: limits.max_scalar_bytes,
            observed: text.len(),
            span,
        });
    }
    if let Some((offset, character)) = text.char_indices().find(|(_, character)| {
        !matches!(*character, '\t' | ' '..='~' | '\u{85}' | '\u{a0}'..='\u{d7ff}' |
            '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
            || *character == '\u{feff}'
    }) {
        return Err(WorkflowRefusal::Malformed {
            expected: "printable single-line YAML scalar content",
            span: Span::new(
                span.start + offset,
                span.start + offset + character.len_utf8(),
                span.line,
                span.column
                    .saturating_add(u32::try_from(offset).unwrap_or(u32::MAX)),
            ),
        });
    }
    // These escapes have the same interpretation in the existing scalar codec.
    // Refuse other escapes here instead of inheriting its legacy pass-through.
    if text.starts_with('"') {
        let bytes = text.as_bytes();
        let mut at = 1;
        while at + 1 < bytes.len() {
            if bytes[at] == b'\\' {
                if !matches!(
                    bytes.get(at + 1),
                    Some(b'n' | b'r' | b't' | b'\\' | b'"' | b'/')
                ) {
                    let width = text[at + 1..].chars().next().map_or(0, char::len_utf8);
                    return Err(WorkflowRefusal::Malformed {
                        expected: "a supported flow double-quoted escape (n, r, t, backslash, quote or slash)",
                        span: Span::new(
                            span.start + at,
                            span.start + at + 1 + width,
                            span.line,
                            span.column
                                .saturating_add(u32::try_from(at).unwrap_or(u32::MAX)),
                        ),
                    });
                }
                at += 2;
            } else {
                at += 1;
            }
        }
    }
    Ok(())
}
