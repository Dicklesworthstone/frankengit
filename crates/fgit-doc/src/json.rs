//! The canonical `JSON` render profile.
//!
//! Keys are emitted in a fixed order and every value is derived from the tree,
//! so the output is byte-stable. There are no floating point numbers, no map
//! iteration, and no optional whitespace.

use crate::ast::{Document, NodeId, NodeKind, UrlVerdict};
use crate::limits::Refusal;
use crate::render::{Sink, hex_digit, literal};

pub fn render_json(document: &Document, sink: &mut Sink) -> Result<(), Refusal> {
    let profile = document.profile();
    sink.write("{\"profile\":{\"family\":\"")?;
    sink.write(profile.family.tag())?;
    sink.write(&format!(
        "\",\"version\":{},\"structural\":{{\"max_line_bytes\":{},\"max_nodes\":{},\"max_depth\":{},\"max_inline_delimiters\":{}}}}},",
        profile.version,
        profile.structural.max_line_bytes,
        profile.structural.max_nodes,
        profile.structural.max_depth,
        profile.structural.max_inline_delimiters
    ))?;
    sink.write(&format!(
        "\"source\":{{\"bytes\":{},\"chars\":{},\"lines\":{}}},",
        document.source().len(),
        document.source().chars().count(),
        document.line_count()
    ))?;
    sink.write("\"roots\":")?;
    write_ids(document.roots(), sink)?;
    sink.write(",\"nodes\":[")?;
    for (index, node) in document.nodes().iter().enumerate() {
        if index > 0 {
            sink.write(",")?;
        }
        let id = NodeId::from_index(index);
        let span = node.span();
        let position = document.position(span.byte_start());
        sink.write(&format!(
            "{{\"id\":{index},\"kind\":\"{}\",\"parent\":",
            node.kind().tag()
        ))?;
        match node.parent() {
            Some(parent) => sink.write(&format!("{}", parent.index()))?,
            None => sink.write("null")?,
        }
        sink.write(&format!(
            ",\"span\":{{\"byte_start\":{},\"byte_end\":{},\"char_start\":{},\"char_end\":{}}},\"line\":{},\"column\":{},",
            span.byte_start(),
            span.byte_end(),
            span.char_start(),
            span.char_end(),
            position.line,
            position.column_chars
        ))?;
        sink.write("\"attributes\":")?;
        write_attributes(document, id, node.kind(), sink)?;
        sink.write(",\"children\":")?;
        write_ids(node.children(), sink)?;
        sink.write("}")?;
    }
    sink.write("]}")
}

fn write_ids(ids: &[NodeId], sink: &mut Sink) -> Result<(), Refusal> {
    sink.write("[")?;
    for (position, id) in ids.iter().enumerate() {
        if position > 0 {
            sink.write(",")?;
        }
        sink.write(&format!("{}", id.index()))?;
    }
    sink.write("]")
}

fn write_attributes(
    document: &Document,
    id: NodeId,
    kind: &NodeKind,
    sink: &mut Sink,
) -> Result<(), Refusal> {
    match *kind {
        NodeKind::Heading(heading) => {
            let style = match heading.style {
                crate::ast::HeadingStyle::Atx => "atx",
                crate::ast::HeadingStyle::Setext => "setext",
            };
            sink.write(&format!(
                "{{\"level\":{},\"style\":\"{style}\"}}",
                heading.level
            ))
        }
        NodeKind::List(info) => sink.write(&format!(
            "{{\"ordered\":{},\"start\":{},\"marker\":{},\"tight\":{}}}",
            info.ordered,
            info.start,
            quote(&String::from(char::from(info.marker))),
            info.tight
        )),
        NodeKind::CodeBlock(info) => {
            sink.write(&format!("{{\"fenced\":{},\"info\":", info.fenced))?;
            match info.info.and_then(|span| document.text(span)) {
                Some(value) => sink.write(&quote(value))?,
                None => sink.write("null")?,
            }
            sink.write(&format!(",\"unterminated\":{}}}", info.unterminated))
        }
        NodeKind::Link(info) | NodeKind::Image(info) => {
            sink.write("{\"destination\":")?;
            sink.write(&quote(document.text(info.destination).unwrap_or("")))?;
            sink.write(",\"title\":")?;
            match info.title.and_then(|span| document.text(span)) {
                Some(value) => sink.write(&quote(value))?,
                None => sink.write("null")?,
            }
            sink.write(&format!(",\"verdict\":\"{}\"}}", verdict_tag(info.verdict)))
        }
        NodeKind::Autolink(info) => {
            let kind_tag = match info.kind {
                crate::ast::AutolinkKind::Uri => "uri",
                crate::ast::AutolinkKind::Email => "email",
            };
            sink.write(&format!("{{\"kind\":\"{kind_tag}\",\"destination\":"))?;
            sink.write(&quote(document.text(info.destination).unwrap_or("")))?;
            sink.write(&format!(",\"verdict\":\"{}\"}}", verdict_tag(info.verdict)))
        }
        NodeKind::Text | NodeKind::Escaped | NodeKind::VerbatimLine | NodeKind::RawHtmlInline => {
            sink.write("{\"text\":")?;
            sink.write(&quote(literal(document, id)))?;
            sink.write("}")
        }
        _ => sink.write("{}"),
    }
}

const fn verdict_tag(verdict: UrlVerdict) -> &'static str {
    match verdict {
        UrlVerdict::Allowed => "allowed",
        UrlVerdict::Rejected(reason) => reason.tag(),
    }
}

/// Emits a `JSON` string literal, escaping every character that requires it.
fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for value in text.chars() {
        match value {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            value if value < ' ' || value == '\u{7f}' => {
                let code = u32::from(value);
                out.push_str("\\u00");
                out.push(hex_digit(code >> 4));
                out.push(hex_digit(code));
            }
            value => out.push(value),
        }
    }
    out.push('"');
    out
}
