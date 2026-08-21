//! Span fidelity: every node's span is the exact source region it describes.

use crate::common::{
    assert_no_content_lost, assert_span_integrity, corpus, first_node_of_kind, parse_case,
    prose_round_trip_corpus,
};
use fgit_doc::ast::NodeKind;
use fgit_doc::{Limits, RenderProfile, parse, render};

#[test]
fn every_node_span_slices_its_own_source() {
    for case in corpus() {
        let document = parse_case(&case);
        assert_span_integrity(case.name, &document);
    }
}

#[test]
fn no_document_content_falls_outside_every_span() {
    for case in corpus() {
        let document = parse_case(&case);
        assert_no_content_lost(case.name, &document);
    }
}

#[test]
fn plain_text_render_round_trips_prose() {
    for case in prose_round_trip_corpus() {
        let document = parse_case(&case);
        let rendered = render(&document, RenderProfile::PlainText, Limits::DEFAULT)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", case.name));
        assert_eq!(
            rendered.as_str(),
            case.source,
            "{}: plain text render did not reproduce the source",
            case.name
        );
    }
}

#[test]
fn heading_text_span_excludes_the_marker() {
    let document = parse("## Two ##\n")
        .expect("heading parses")
        .into_document();
    let heading = first_node_of_kind(&document, "heading").expect("a heading node");
    assert_eq!(document.node_text(heading), Some("## Two ##"));
    let text = document
        .node(heading)
        .and_then(|node| node.children().first().copied())
        .expect("heading has inline content");
    assert_eq!(document.node_text(text), Some("Two"));
}

#[test]
fn emphasis_span_covers_its_delimiters_and_text_does_not() {
    let document = parse("a **bold** b\n")
        .expect("emphasis parses")
        .into_document();
    let strong = first_node_of_kind(&document, "strong").expect("a strong node");
    assert_eq!(document.node_text(strong), Some("**bold**"));
    let inner = document
        .node(strong)
        .and_then(|node| node.children().first().copied())
        .expect("strong has inline content");
    assert_eq!(document.node_text(inner), Some("bold"));
}

#[test]
fn code_span_children_exclude_the_backticks() {
    let document = parse("use `let x = 1;` here\n")
        .expect("code span parses")
        .into_document();
    let code = first_node_of_kind(&document, "code_span").expect("a code span node");
    assert_eq!(document.node_text(code), Some("`let x = 1;`"));
    let inner = document
        .node(code)
        .and_then(|node| node.children().first().copied())
        .expect("code span has content");
    assert_eq!(document.node_text(inner), Some("let x = 1;"));
}

#[test]
fn fenced_code_lines_are_separate_contiguous_spans() {
    let document = parse("```rust\nfirst\nsecond\n```\n")
        .expect("fence parses")
        .into_document();
    let block = first_node_of_kind(&document, "code_block").expect("a code block");
    let lines = document
        .node(block)
        .map(|node| {
            node.children()
                .iter()
                .filter_map(|child| document.node_text(*child))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert_eq!(lines, vec!["first", "second"]);
    let NodeKind::CodeBlock(info) = *document
        .node(block)
        .map(fgit_doc::ast::Node::kind)
        .expect("code block kind")
    else {
        panic!("expected a code block");
    };
    assert!(info.fenced);
    assert!(!info.unterminated);
    assert_eq!(info.info.and_then(|span| document.text(span)), Some("rust"));
}

#[test]
fn block_quote_content_spans_never_cover_the_quote_marker() {
    let document = parse("> alpha\n> beta\n")
        .expect("quote parses")
        .into_document();
    for (id, _) in document.preorder() {
        let Some(node) = document.node(id) else {
            continue;
        };
        if *node.kind() != NodeKind::Text {
            continue;
        }
        let text = document.node_text(id).unwrap_or("");
        assert!(
            !text.contains('>'),
            "a text leaf covered the quote marker: {text:?}"
        );
    }
    let texts = document
        .preorder()
        .filter_map(|(id, _)| {
            document
                .node(id)
                .filter(|node| *node.kind() == NodeKind::Text)
                .and_then(|_| document.node_text(id))
        })
        .collect::<Vec<_>>();
    assert_eq!(texts, vec!["alpha", "beta"]);
}

#[test]
fn escape_leaf_covers_both_bytes_and_renders_one() {
    let document = parse("\\*literal\\*\n")
        .expect("escapes parse")
        .into_document();
    let escaped = first_node_of_kind(&document, "escaped").expect("an escaped node");
    assert_eq!(document.node_text(escaped), Some("\\*"));
    let rendered = render(&document, RenderProfile::PlainText, Limits::DEFAULT)
        .expect("plain render succeeds");
    assert_eq!(rendered.as_str(), "*literal*\n");
}

#[test]
fn hard_break_leaf_covers_the_trailing_spaces_and_terminator() {
    let document = parse("one  \ntwo\n")
        .expect("hard break parses")
        .into_document();
    let hard = first_node_of_kind(&document, "hard_break").expect("a hard break node");
    assert_eq!(document.node_text(hard), Some("  \n"));
}

#[test]
fn crlf_soft_break_leaf_covers_both_terminator_bytes() {
    let document = parse("one\r\ntwo\r\n")
        .expect("crlf parses")
        .into_document();
    let soft = first_node_of_kind(&document, "soft_break").expect("a soft break node");
    assert_eq!(document.node_text(soft), Some("\r\n"));
}

#[test]
fn codepoint_offsets_track_multibyte_text() {
    let source = "\u{e9}\u{e9} *x*\n";
    let document = parse(source).expect("unicode parses").into_document();
    let emphasis = first_node_of_kind(&document, "emphasis").expect("an emphasis node");
    let span = document
        .node(emphasis)
        .map(fgit_doc::ast::Node::span)
        .expect("emphasis span");
    assert_eq!(span.byte_start(), 5);
    assert_eq!(span.char_start(), 3);
    assert_eq!(span.byte_len(), 3);
    assert_eq!(span.char_len(), 3);
}

#[test]
fn line_and_column_positions_are_one_based_and_codepoint_aware() {
    let source = "\u{e9}\u{e9}x\nsecond\n";
    let document = parse(source).expect("unicode parses").into_document();
    let start = document.position(0);
    assert_eq!(
        (start.line, start.column_chars, start.column_bytes),
        (1, 1, 1)
    );
    let third = document.position(4);
    assert_eq!(
        (third.line, third.column_chars, third.column_bytes),
        (1, 3, 5)
    );
    let second_line = document.position(6);
    assert_eq!(
        (second_line.line, second_line.column_chars),
        (2, 1),
        "byte 6 is the first byte of line two"
    );
}

#[test]
fn structural_paths_are_stable_and_address_the_right_node() {
    let document = parse("# H\n\npara\n\n- a\n- b\n")
        .expect("document parses")
        .into_document();
    for (id, _) in document.preorder() {
        let path = document.path_of(id);
        assert!(
            !path.is_empty(),
            "every reachable node has a non-empty structural path"
        );
    }
    let list = first_node_of_kind(&document, "list").expect("a list node");
    assert_eq!(document.path_of(list), vec![2]);
    let second_item = document
        .node(list)
        .and_then(|node| node.children().get(1).copied())
        .expect("a second list item");
    assert_eq!(document.path_of(second_item), vec![2, 1]);
}

#[test]
fn blocks_after_the_first_are_parsed_at_their_own_position() {
    // Every block builder returns an absolute line index; a builder that
    // returned a relative one would mis-slice or drop everything after the
    // first block.
    let document = parse("para one\n\n# Heading\n\npara two\n\n---\n\n> quoted\n")
        .expect("document parses")
        .into_document();
    let kinds = document
        .roots()
        .iter()
        .filter_map(|id| document.node(*id).map(|node| node.kind().tag()))
        .collect::<Vec<_>>();
    assert_eq!(
        kinds,
        vec![
            "paragraph",
            "heading",
            "paragraph",
            "thematic_break",
            "block_quote"
        ]
    );
    assert_eq!(document.node_text(document.roots()[1]), Some("# Heading"));
    assert_eq!(document.node_text(document.roots()[2]), Some("para two"));
    assert_eq!(document.node_text(document.roots()[3]), Some("---"));
    assert_eq!(document.node_text(document.roots()[4]), Some("> quoted"));
}

#[test]
fn consecutive_headings_each_get_their_own_node() {
    let document = parse("# One\n## Two\n### Three\n")
        .expect("document parses")
        .into_document();
    let texts = document
        .roots()
        .iter()
        .filter_map(|id| document.node_text(*id))
        .collect::<Vec<_>>();
    assert_eq!(texts, vec!["# One", "## Two", "### Three"]);
}

#[test]
fn leaf_kinds_never_carry_children() {
    for case in corpus() {
        let document = parse_case(&case);
        for (id, _) in document.preorder() {
            let Some(node) = document.node(id) else {
                continue;
            };
            if node.kind().is_leaf() {
                assert!(
                    node.children().is_empty(),
                    "{}: leaf kind {:?} carries {} children",
                    case.name,
                    node.kind().tag(),
                    node.children().len()
                );
            }
        }
    }
}

#[test]
fn a_subtree_traversal_visits_exactly_that_subtree() {
    for case in corpus() {
        let document = parse_case(&case);
        for (root, _) in document.preorder() {
            let Some(node) = document.node(root) else {
                continue;
            };
            let visited = document.subtree(root).map(|(id, _)| id).collect::<Vec<_>>();
            assert_eq!(
                visited.first().copied(),
                Some(root),
                "{}: a subtree traversal starts at its own root",
                case.name
            );
            for id in &visited {
                let span = document
                    .node(*id)
                    .map(fgit_doc::ast::Node::span)
                    .expect("visited nodes exist");
                assert!(
                    node.span().contains(span),
                    "{}: subtree traversal escaped the root span",
                    case.name
                );
            }
            let mut unique = visited.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(
                unique.len(),
                visited.len(),
                "{}: a subtree traversal visited a node twice",
                case.name
            );
        }
    }
}

#[test]
fn span_hull_covers_both_operands() {
    let document = parse("first paragraph\n\nsecond paragraph\n")
        .expect("document parses")
        .into_document();
    let first = document
        .node(document.roots()[0])
        .map(fgit_doc::ast::Node::span)
        .expect("first root");
    let second = document
        .node(document.roots()[1])
        .map(fgit_doc::ast::Node::span)
        .expect("second root");
    let hull = first.hull(second);
    assert!(hull.contains(first) && hull.contains(second));
    assert_eq!(hull.byte_start(), first.byte_start());
    assert_eq!(hull.byte_end(), second.byte_end());
    assert_eq!(hull.char_start(), first.char_start());
    assert_eq!(hull.char_end(), second.char_end());
    assert!(!first.contains(second));
    assert!(first.contains(first));
}
