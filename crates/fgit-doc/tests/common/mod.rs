//! Shared corpus and structural invariant checks for the `fgit-doc` suites.
//!
//! Every integration test binary compiles this module in full, so helpers used
//! by only some suites are legitimately unused in the others.
#![allow(dead_code)]

use fgit_doc::ast::{Document, NodeKind};
use fgit_doc::{Limits, NodeId, ParseProfile, RenderProfile, Span, parse, render};

/// One named corpus document.
pub struct Case {
    pub name: &'static str,
    pub source: &'static str,
}

/// Documents that exercise every construct the profile implements, plus the
/// hostile shapes that historically break span bookkeeping.
pub fn corpus() -> Vec<Case> {
    vec![
        Case {
            name: "empty",
            source: "",
        },
        Case {
            name: "plain",
            source: "Just a plain paragraph.\n",
        },
        Case {
            name: "two_paragraphs",
            source: "First paragraph.\n\nSecond paragraph.\n",
        },
        Case {
            name: "soft_break",
            source: "line one\nline two\n",
        },
        Case {
            name: "atx_headings",
            source: "# One\n\n## Two ##\n\n###### Six\n",
        },
        Case {
            name: "setext_headings",
            source: "Title here\n==========\n\nSubtitle\n--------\n",
        },
        Case {
            name: "emphasis",
            source: "a *b* c **d** e ***f*** g _h_ i__j__k\n",
        },
        Case {
            name: "fenced_code",
            source: "```rust\nfn main() {}\n```\n",
        },
        Case {
            name: "indented_code",
            source: "text\n\n    indented\n    code\n",
        },
        Case {
            name: "block_quote",
            source: "> quoted one\n> quoted two\n>\n> second para\n",
        },
        Case {
            name: "nested_quote",
            source: "> outer\n> > inner\n",
        },
        Case {
            name: "quote_with_fence",
            source: "> ```\n> code in quote\n> ```\n",
        },
        Case {
            name: "bullet_list",
            source: "- alpha\n- beta\n  - nested\n",
        },
        Case {
            name: "ordered_list",
            source: "1. one\n2. two\n",
        },
        Case {
            name: "loose_list",
            source: "- alpha\n\n- beta\n",
        },
        Case {
            name: "list_with_quote",
            source: "- item\n  > quoted\n",
        },
        Case {
            name: "links",
            source: "[text](https://example.com \"Title\") then ![alt](https://example.com/i.png)\n",
        },
        Case {
            name: "rejected_links",
            source: "[click](javascript:alert&#40;1&#41;) and [fine](/relative/path)\n",
        },
        Case {
            name: "autolinks",
            source: "<https://example.com> and <person@example.com>\n",
        },
        Case {
            name: "raw_markup",
            source: "<div class=\"x\">\nraw content\n</div>\n\ninline <b>bold</b> tag\n",
        },
        Case {
            name: "escapes",
            source: "\\*not emphasis\\* and \\\\ backslash\n",
        },
        Case {
            name: "breaks",
            source: "line one  \nline two\\\nline three\n",
        },
        Case {
            name: "code_spans",
            source: "use `let x = 1;` and ``a ` b`` here\n",
        },
        Case {
            name: "unterminated_fence",
            source: "```\nnever closed\n",
        },
        Case {
            name: "reference_definition",
            source: "[label]: https://example.com\n\nsee [label][] usage\n",
        },
        Case {
            name: "thematic_break",
            source: "above\n\n---\n\nbelow\n",
        },
        Case {
            name: "unicode",
            source: "h\u{e9}llo \u{2014} w\u{f6}rld \u{2713} *\u{e9}mphasis* and `c\u{f3}de`\n",
        },
        Case {
            name: "crlf",
            source: "line one\r\nline two\r\n\r\nsecond\r\n",
        },
        Case {
            name: "no_trailing_newline",
            source: "final line without terminator",
        },
        Case {
            name: "tabs",
            source: "\tindented with a tab\n\n-\titem after tab\n",
        },
        Case {
            name: "mixed_document",
            source: concat!(
                "# Release notes\n",
                "\n",
                "Some *emphasis*, a [link](https://example.com), and `code`.\n",
                "\n",
                "> A quote with **strong** text.\n",
                ">\n",
                "> - a bullet inside a quote\n",
                "> - another\n",
                "\n",
                "```sh\n",
                "echo hello\n",
                "```\n",
                "\n",
                "1. first\n",
                "2. second\n",
            ),
        },
    ]
}

/// Documents whose plain-text rendering must reproduce the source byte for byte.
pub fn prose_round_trip_corpus() -> Vec<Case> {
    vec![
        Case {
            name: "single",
            source: "Just a plain paragraph.\n",
        },
        Case {
            name: "two",
            source: "First paragraph.\n\nSecond paragraph.\n",
        },
        Case {
            name: "soft_break",
            source: "line one\nline two\n",
        },
        Case {
            name: "unicode",
            source: "h\u{e9}llo w\u{f6}rld \u{2713}\n",
        },
    ]
}

/// Parses a corpus document, failing loudly with the case name.
pub fn parse_case(case: &Case) -> Document {
    match parse(case.source) {
        Ok(output) => output.into_document(),
        Err(refusal) => panic!("case {} refused unexpectedly: {refusal}", case.name),
    }
}

/// Independently recomputed codepoint offset of a byte offset.
fn char_offset(source: &str, byte_offset: u32) -> u32 {
    let prefix = source
        .get(..usize::try_from(byte_offset).unwrap_or(usize::MAX))
        .unwrap_or_else(|| panic!("byte offset {byte_offset} is not a character boundary"));
    u32::try_from(prefix.chars().count()).unwrap_or(u32::MAX)
}

/// Asserts every span invariant this crate promises, for one document.
pub fn assert_span_integrity(name: &str, document: &Document) {
    let source = document.source();
    for (id, _) in document.preorder() {
        let node = document
            .node(id)
            .unwrap_or_else(|| panic!("{name}: preorder yielded an unknown node"));
        let span = node.span();
        let start = usize::try_from(span.byte_start()).unwrap_or(usize::MAX);
        let end = usize::try_from(span.byte_end()).unwrap_or(usize::MAX);

        assert!(
            start <= end && end <= source.len(),
            "{name}: node {:?} span {span} is out of bounds of {} bytes",
            node.kind().tag(),
            source.len()
        );
        assert!(
            source.is_char_boundary(start) && source.is_char_boundary(end),
            "{name}: node {:?} span {span} does not land on character boundaries",
            node.kind().tag()
        );
        assert_eq!(
            document.text(span),
            source.get(start..end),
            "{name}: node {:?} span {span} does not slice its own source",
            node.kind().tag()
        );
        assert_eq!(
            span.char_start(),
            char_offset(source, span.byte_start()),
            "{name}: node {:?} span {span} has a wrong codepoint start",
            node.kind().tag()
        );
        assert_eq!(
            span.char_end(),
            char_offset(source, span.byte_end()),
            "{name}: node {:?} span {span} has a wrong codepoint end",
            node.kind().tag()
        );

        let mut previous_end: Option<u32> = None;
        for child in node.children() {
            let child_node = document
                .node(*child)
                .unwrap_or_else(|| panic!("{name}: dangling child identifier"));
            let child_span = child_node.span();
            assert!(
                span.contains(child_span),
                "{name}: child {:?} span {child_span} escapes parent {:?} span {span}",
                child_node.kind().tag(),
                node.kind().tag()
            );
            if let Some(previous) = previous_end {
                assert!(
                    child_span.byte_start() >= previous,
                    "{name}: sibling {:?} span {child_span} overlaps the previous sibling ending at {previous}",
                    child_node.kind().tag()
                );
            }
            previous_end = Some(child_span.byte_end());
        }
    }

    let mut previous_end: Option<u32> = None;
    for root in document.roots() {
        let span = document
            .node(*root)
            .unwrap_or_else(|| panic!("{name}: dangling root identifier"))
            .span();
        if let Some(previous) = previous_end {
            assert!(
                span.byte_start() >= previous,
                "{name}: root span {span} overlaps the previous root ending at {previous}"
            );
        }
        previous_end = Some(span.byte_end());
    }
}

/// Characters permitted to appear in a source region no node covers.
///
/// Every other byte is document content, so finding one outside every recorded
/// span means the parser silently dropped text.
fn is_structural(value: char) -> bool {
    value.is_whitespace()
        || value.is_ascii_digit()
        || matches!(
            value,
            '#' | '*'
                | '_'
                | '-'
                | '+'
                | '>'
                | '~'
                | '='
                | '`'
                | '['
                | ']'
                | '('
                | ')'
                | '!'
                | '<'
                | '\\'
                | '"'
                | '\''
                | '.'
        )
}

/// Every source region a node records, including recorded attribute spans.
fn covered_spans(document: &Document) -> Vec<Span> {
    let mut spans = Vec::new();
    for (id, _) in document.preorder() {
        let Some(node) = document.node(id) else {
            continue;
        };
        if node.children().is_empty() {
            spans.push(node.span());
        }
        match *node.kind() {
            NodeKind::Link(info) | NodeKind::Image(info) => {
                spans.push(info.destination);
                if let Some(title) = info.title {
                    spans.push(title);
                }
            }
            NodeKind::Autolink(info) => spans.push(info.destination),
            NodeKind::CodeBlock(info) => {
                if let Some(value) = info.info {
                    spans.push(value);
                }
            }
            _ => {}
        }
    }
    spans
}

/// Asserts that no textual content is dropped between recorded spans.
pub fn assert_no_content_lost(name: &str, document: &Document) {
    let source = document.source();
    let mut covered = vec![false; source.len()];
    for span in covered_spans(document) {
        let start = usize::try_from(span.byte_start()).unwrap_or(usize::MAX);
        let end = usize::try_from(span.byte_end()).unwrap_or(usize::MAX);
        for flag in covered.get_mut(start..end).unwrap_or(&mut []) {
            *flag = true;
        }
    }
    for (offset, value) in source.char_indices() {
        if covered.get(offset).copied().unwrap_or(false) {
            continue;
        }
        assert!(
            is_structural(value),
            "{name}: content character {value:?} at byte {offset} is covered by no node span"
        );
    }
}

/// Renders every profile, failing loudly with the case name.
pub fn render_all(name: &str, document: &Document) -> Vec<(RenderProfile, String)> {
    RenderProfile::all()
        .into_iter()
        .map(|profile| match render(document, profile, Limits::DEFAULT) {
            Ok(rendered) => (profile, rendered.into_string()),
            Err(refusal) => panic!("{name}: profile {} refused: {refusal}", profile.tag()),
        })
        .collect()
}

/// The first node in document order whose kind tag matches.
pub fn first_node_of_kind(document: &Document, tag: &str) -> Option<NodeId> {
    document.preorder().map(|(id, _)| id).find(|id| {
        document
            .node(*id)
            .is_some_and(|node| node.kind().tag() == tag)
    })
}

/// The default profile, restated so tests do not depend on a literal.
pub fn default_profile() -> ParseProfile {
    ParseProfile::DEFAULT
}
