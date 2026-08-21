//! The `HTML`-safe render profile.
//!
//! Nothing from the source ever reaches the output unescaped. Captured raw
//! markup is emitted as escaped text inside a marked container, and a
//! destination that failed the link policy becomes a marked inert span rather
//! than a navigable target. Neutralisation is therefore visible in the output
//! instead of silent.

use crate::ast::{AutolinkKind, Document, Heading, LinkInfo, ListInfo, NodeId, NodeKind};
use crate::inline::decode_escapes;
use crate::limits::Refusal;
use crate::render::{Sink, escaped_char, literal, subtree_text, verbatim_lines};

/// Marker attribute placed on every construct the link policy refused.
const REJECTED_ATTR: &str = "data-fgit-doc-rejected";

/// Marker attribute placed on content that was rendered inert rather than refused.
const NEUTRALISED_ATTR: &str = "data-fgit-doc-neutralised";

/// Relationship applied to every emitted link, hostile-content default.
const LINK_REL: &str = " rel=\"nofollow noopener noreferrer\"";

pub(crate) fn render_html(document: &Document, sink: &mut Sink) -> Result<(), Refusal> {
    blocks(document, document.roots(), sink)
}

/// Escapes text for `HTML` character data and for double-quoted attributes.
///
/// One escaper covers both positions: quoting `"` and `'` as well as the three
/// structural characters means a value can never break out of either context.
///
/// This is character escaping only. It does **not** neutralise bidirectional
/// formatting characters, because what to do with those depends on whether the
/// destination is character data or an attribute; the renderer decides that
/// through [`escape_text`] and [`escape_attribute`].
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for value in text.chars() {
        push_escaped(&mut out, value);
    }
    out
}

fn push_escaped(out: &mut String, value: char) {
    match value {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#x27;"),
        _ => out.push(value),
    }
}

/// Escapes character data and renders each bidirectional control inertly.
///
/// A right-to-left override in prose, in link text, or inside a code span makes
/// the rendered text read differently from the source it came from. Emitting
/// the character escaped would not help: the browser would still apply it. So
/// each one becomes a marked span naming its code point, which is inert, is
/// visible to a reviewer, and loses no information.
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for value in text.chars() {
        if crate::unicode::is_bidi_control(value) {
            out.push_str(&format!(
                "<span {NEUTRALISED_ATTR}=\"bidi_control\">{}</span>",
                crate::unicode::code_point_label(value)
            ));
        } else {
            push_escaped(&mut out, value);
        }
    }
    out
}

/// Escapes an attribute value, dropping bidirectional controls entirely.
///
/// An attribute cannot carry a marked span, and a bidirectional control has no
/// legitimate role in a title or in alternative text, so it is removed. A
/// destination carrying one never reaches here: the link policy refuses it.
fn escape_attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for value in text.chars() {
        if !crate::unicode::is_bidi_control(value) {
            push_escaped(&mut out, value);
        }
    }
    out
}

fn blocks(document: &Document, ids: &[NodeId], sink: &mut Sink) -> Result<(), Refusal> {
    for id in ids {
        block(document, *id, sink)?;
    }
    Ok(())
}

fn block(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    match *node.kind() {
        NodeKind::Paragraph => {
            sink.write("<p>")?;
            inlines(document, node.children(), sink)?;
            sink.write("</p>\n")
        }
        NodeKind::Heading(Heading { level, .. }) => {
            let level = level.clamp(1, 6);
            sink.write(&format!("<h{level}>"))?;
            inlines(document, node.children(), sink)?;
            sink.write(&format!("</h{level}>\n"))
        }
        NodeKind::ThematicBreak => sink.write("<hr />\n"),
        NodeKind::BlockQuote => {
            sink.write("<blockquote>\n")?;
            blocks(document, node.children(), sink)?;
            sink.write("</blockquote>\n")
        }
        NodeKind::List(info) => list(document, id, info, sink),
        NodeKind::ListItem => item(document, id, true, sink),
        NodeKind::CodeBlock(code) => {
            let language = code
                .info
                .and_then(|span| document.text(span))
                .map(language_class)
                .unwrap_or_default();
            if language.is_empty() {
                sink.write("<pre><code>")?;
            } else {
                sink.write(&format!("<pre><code class=\"language-{language}\">"))?;
            }
            verbatim(document, id, sink)?;
            sink.write("</code></pre>\n")
        }
        NodeKind::RawHtmlBlock => {
            sink.write(&format!("<pre {REJECTED_ATTR}=\"raw_markup\"><code>"))?;
            verbatim(document, id, sink)?;
            sink.write("</code></pre>\n")
        }
        _ => inlines(document, node.children(), sink),
    }
}

fn verbatim(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    for line in verbatim_lines(document, id) {
        sink.write(&escape_text(line))?;
        sink.write("\n")?;
    }
    Ok(())
}

fn list(document: &Document, id: NodeId, info: ListInfo, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    if info.ordered {
        if info.start == 1 {
            sink.write("<ol>\n")?;
        } else {
            sink.write(&format!("<ol start=\"{}\">\n", info.start))?;
        }
    } else {
        sink.write("<ul>\n")?;
    }
    for child in node.children() {
        item(document, *child, info.tight, sink)?;
    }
    if info.ordered {
        sink.write("</ol>\n")
    } else {
        sink.write("</ul>\n")
    }
}

fn item(document: &Document, id: NodeId, tight: bool, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    sink.write("<li>")?;
    if tight {
        for (position, child) in node.children().iter().enumerate() {
            let is_paragraph = matches!(
                document.node(*child).map(crate::ast::Node::kind),
                Some(NodeKind::Paragraph)
            );
            if is_paragraph {
                if position > 0 {
                    sink.write("\n")?;
                }
                let children = document
                    .node(*child)
                    .map(|entry| entry.children().to_vec())
                    .unwrap_or_default();
                inlines(document, &children, sink)?;
            } else {
                sink.write("\n")?;
                block(document, *child, sink)?;
            }
        }
    } else {
        sink.write("\n")?;
        blocks(document, node.children(), sink)?;
    }
    sink.write("</li>\n")
}

fn inlines(document: &Document, ids: &[NodeId], sink: &mut Sink) -> Result<(), Refusal> {
    for id in ids {
        inline_node(document, *id, sink)?;
    }
    Ok(())
}

fn inline_node(document: &Document, id: NodeId, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    match *node.kind() {
        NodeKind::Text | NodeKind::VerbatimLine => sink.write(&escape_text(literal(document, id))),
        NodeKind::RawHtmlInline => sink.write(&format!(
            "<span {REJECTED_ATTR}=\"raw_markup\">{}</span>",
            escape_text(literal(document, id))
        )),
        NodeKind::Escaped => sink.write(&escape_text(escaped_char(document, id))),
        NodeKind::SoftBreak => sink.write("\n"),
        NodeKind::HardBreak => sink.write("<br />\n"),
        NodeKind::Emphasis => {
            sink.write("<em>")?;
            inlines(document, node.children(), sink)?;
            sink.write("</em>")
        }
        NodeKind::Strong => {
            sink.write("<strong>")?;
            inlines(document, node.children(), sink)?;
            sink.write("</strong>")
        }
        NodeKind::CodeSpan => {
            sink.write("<code>")?;
            for child in node.children() {
                if matches!(
                    document.node(*child).map(crate::ast::Node::kind),
                    Some(NodeKind::SoftBreak)
                ) {
                    sink.write(" ")?;
                } else {
                    sink.write(&escape_text(literal(document, *child)))?;
                }
            }
            sink.write("</code>")
        }
        NodeKind::Link(info) => anchor(document, id, info, sink),
        NodeKind::Image(info) => image(document, id, info, sink),
        NodeKind::Autolink(info) => {
            let raw = document.text(info.destination).unwrap_or("");
            if info.verdict.is_allowed() {
                let target = if info.kind == AutolinkKind::Email {
                    format!("mailto:{raw}")
                } else {
                    raw.to_owned()
                };
                sink.write(&format!(
                    "<a href=\"{}\"{LINK_REL}>{}</a>",
                    escape_attribute(&target),
                    escape_text(raw)
                ))
            } else {
                sink.write(&rejected(info.verdict, &escape_text(raw)))
            }
        }
        _ => inlines(document, node.children(), sink),
    }
}

fn anchor(document: &Document, id: NodeId, info: LinkInfo, sink: &mut Sink) -> Result<(), Refusal> {
    let Some(node) = document.node(id) else {
        return Ok(());
    };
    if info.verdict.is_allowed() {
        let target = decode_escapes(document.text(info.destination).unwrap_or(""));
        let title = info
            .title
            .and_then(|span| document.text(span))
            .map(decode_escapes);
        match title {
            Some(value) => sink.write(&format!(
                "<a href=\"{}\" title=\"{}\"{LINK_REL}>",
                escape_attribute(&target),
                escape_attribute(&value)
            ))?,
            None => sink.write(&format!(
                "<a href=\"{}\"{LINK_REL}>",
                escape_attribute(&target)
            ))?,
        }
        inlines(document, node.children(), sink)?;
        sink.write("</a>")
    } else {
        sink.write(&format!(
            "<span {REJECTED_ATTR}=\"{}\">",
            rejection_tag(info.verdict)
        ))?;
        inlines(document, node.children(), sink)?;
        sink.write("</span>")
    }
}

fn image(document: &Document, id: NodeId, info: LinkInfo, sink: &mut Sink) -> Result<(), Refusal> {
    let alternative = escape_attribute(&subtree_text(document, id));
    if info.verdict.is_allowed() {
        let target = decode_escapes(document.text(info.destination).unwrap_or(""));
        let title = info
            .title
            .and_then(|span| document.text(span))
            .map(decode_escapes);
        match title {
            Some(value) => sink.write(&format!(
                "<img src=\"{}\" alt=\"{alternative}\" title=\"{}\" />",
                escape_attribute(&target),
                escape_attribute(&value)
            )),
            None => sink.write(&format!(
                "<img src=\"{}\" alt=\"{alternative}\" />",
                escape_attribute(&target)
            )),
        }
    } else {
        sink.write(&rejected(info.verdict, &alternative))
    }
}

fn rejected(verdict: crate::ast::UrlVerdict, body: &str) -> String {
    format!(
        "<span {REJECTED_ATTR}=\"{}\">{body}</span>",
        rejection_tag(verdict)
    )
}

const fn rejection_tag(verdict: crate::ast::UrlVerdict) -> &'static str {
    match verdict {
        crate::ast::UrlVerdict::Allowed => "none",
        crate::ast::UrlVerdict::Rejected(reason) => reason.tag(),
    }
}

/// The first info-string word, restricted to characters safe in a class name.
fn language_class(info: &str) -> String {
    info.split_whitespace()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|value| value.is_ascii_alphanumeric() || matches!(value, '_' | '+' | '.' | '-'))
        .collect()
}
