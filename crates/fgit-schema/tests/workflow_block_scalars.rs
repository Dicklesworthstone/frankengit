#![forbid(unsafe_code)]
//! Byte-level block scalar fixtures derived from YAML 1.2.2 sections 5.4 and 8.1.
//! This tests the bounded native subset, not general YAML conformance.
use fgit_schema::workflow::{Limits, Node, Span, WorkflowRefusal, compile, yaml};

fn scanned(source: &str) -> Node {
    yaml::scan(source, &Limits::DEFAULT).expect("block scalar scans")
}
fn scalar(node: &Node) -> (&str, Span) {
    let Node::Scalar { value, span } = node else {
        panic!("expected a scalar, got {}", node.shape());
    };
    (value, *span)
}
fn value(source: &str) -> String {
    scalar(scanned(source).get("v").expect("v exists"))
        .0
        .to_owned()
}
fn malformed(source: &str) -> WorkflowRefusal {
    let error = yaml::scan(source, &Limits::DEFAULT).expect_err("invalid block refuses");
    assert!(
        matches!(error, WorkflowRefusal::Malformed { .. }),
        "{error:?}"
    );
    assert!(!error.span().is_empty());
    error
}
fn limited(source: &str, limits: &Limits, expected: &str) {
    let error = yaml::scan(source, limits).expect_err("bounded twin refuses");
    assert!(
        matches!(error, WorkflowRefusal::LimitExceeded { limit, .. } if limit == expected),
        "{error:?}"
    );
}
fn workflow(run: &str) -> String {
    format!(
        "name: blocks\non: push\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {run}"
    )
}

#[test]
fn literal_chomping_preserves_content_and_only_changes_trailing_breaks() {
    for (header, expected) in [
        ("|-", "one\ntwo"),
        ("|+", "one\ntwo\n\n"),
        ("|2", "one\ntwo\n"),
    ] {
        let source = format!("v: {header}\n  one\n  two\n\nnext: done\n");
        let doc = scanned(&source);
        assert_eq!(scalar(doc.get("v").unwrap()).0, expected, "{header}");
        assert_eq!(scalar(doc.get("next").unwrap()).0, "done");
    }
}

#[test]
fn folded_paragraphs_preserve_leading_blanks_and_more_indented_sections() {
    let source = "v: >\n\n  alpha\n  beta\n\n  gamma\n    delta\n\n    epsilon\n  zeta\n  eta\n\nnext: done\n";
    assert_eq!(
        value(source),
        "\nalpha beta\ngamma\n  delta\n\n  epsilon\nzeta eta\n"
    );
}

#[test]
fn folded_chomping_does_not_fold_trailing_empty_lines() {
    for (header, expected) in [
        (">-", "one two"),
        (">", "one two\n"),
        (">+", "one two\n\n\n"),
    ] {
        assert_eq!(
            value(&format!("v: {header}\n  one\n  two\n\n\n")),
            expected,
            "{header}"
        );
    }
}

#[test]
fn every_indentation_digit_and_both_indicator_orders_resolve_exact_bytes() {
    for style in ['|', '>'] {
        for digit in 1..=9 {
            for chomp in ["", "-", "+"] {
                for header in [
                    format!("{style}{digit}{chomp}"),
                    format!("{style}{chomp}{digit}"),
                ] {
                    let pad = " ".repeat(digit);
                    let source = format!("v: {header}\n{pad}one\n{pad}two\n\n");
                    let text = if style == '|' { "one\ntwo" } else { "one two" };
                    let tail = match chomp {
                        "-" => "",
                        "+" => "\n\n",
                        _ => "\n",
                    };
                    assert_eq!(value(&source), format!("{text}{tail}"), "{header}");
                }
            }
        }
    }
}

#[test]
fn explicit_indent_is_relative_to_the_mapping_key_or_sequence_dash() {
    let doc = scanned(
        "items:\n  - run: |2-\n      one\n      two\n    name: label\n  - >2-\n    folded\n    words\n",
    );
    let Node::Sequence { items, .. } = doc.get("items").unwrap() else {
        panic!("sequence");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(scalar(items[0].get("run").unwrap()).0, "one\ntwo");
    assert_eq!(scalar(items[0].get("name").unwrap()).0, "label");
    assert_eq!(scalar(&items[1]).0, "folded words");
}

#[test]
fn explicitly_indented_whitespace_is_content_and_never_a_folded_empty_line() {
    assert_eq!(value("v: >2-\n  a\n   \n  b\n"), "a\n \nb");
    assert_eq!(value("v: |2-\n    \n  a\n   \n"), "  \na\n ");
    assert_eq!(value("v: >2+\n   \n\n"), " \n\n");
}

#[test]
fn tabs_after_content_indentation_are_data_including_tab_only_lines() {
    assert_eq!(value("v: >-\n  a\n  \t\n  b\n"), "a\n\t\nb");
    assert_eq!(
        value("v: |-\n  \tcommand\n  \t\n  next\n"),
        "\tcommand\n\t\nnext"
    );
    let error = yaml::scan("v: >2-\n \tbad\n", &Limits::DEFAULT).unwrap_err();
    assert!(matches!(error, WorkflowRefusal::Malformed { .. }));
    assert_eq!(value("v: >2-\n  \tgood\n"), "\tgood");
}

#[test]
fn unicode_space_and_non_ascii_line_separators_are_content() {
    assert_eq!(
        value("v: >-\n  a\n  \u{a0}\n  \u{2028}\n  b\n"),
        "a \u{a0} \u{2028} b"
    );
}

#[test]
fn literal_and_folded_new_forms_normalize_all_yaml_line_endings() {
    for ending in ["\n", "\r\n", "\r"] {
        for (header, expected) in [("|-", "one\ntwo"), (">-", "one two")] {
            let source = format!("v: {header}\n  one\n  two\nnext: done\n").replace('\n', ending);
            let doc = scanned(&source);
            assert_eq!(
                scalar(doc.get("v").unwrap()).0,
                expected,
                "{ending:?} {header}"
            );
            let (_, next_span) = scalar(doc.get("next").unwrap());
            assert_eq!(next_span.line, 4);
            assert_eq!(&source[next_span.start..next_span.end], "done");
        }
    }
}

#[test]
fn no_new_form_invents_a_final_line_break_at_end_of_input() {
    for header in ["|-", "|+", "|1", ">", ">-", ">+"] {
        assert_eq!(value(&format!("v: {header}\n tail")), "tail", "{header}");
    }
}

#[test]
fn empty_blocks_and_empty_line_chomping_have_distinct_values() {
    for header in ["|-", "|+", "|2", ">", ">-", ">+"] {
        assert_eq!(value(&format!("v: {header}")), "", "{header} at EOF");
        assert_eq!(
            value(&format!("v: {header}\nnext: done\n")),
            "",
            "{header} before sibling"
        );
        let expected = if header.ends_with('+') { "\n\n" } else { "" };
        assert_eq!(
            value(&format!("v: {header}\n\n\n")),
            expected,
            "{header} with empty lines"
        );
    }
    assert_eq!(value("v: >+\n  \n    \n"), "\n\n");
}

#[test]
fn scalar_span_covers_header_comments_body_comments_blanks_and_raw_byte_endings() {
    let source = "v: >- # header\r\n  # script comment\r\n  ---\r\n  key: 'value'  \r\n\r\n # outside\r\n    # still outside\r\nnext: done\r\n";
    let doc = scanned(source);
    let (text, span) = scalar(doc.get("v").unwrap());
    assert_eq!(text, "# script comment --- key: 'value'  ");
    assert_eq!(span.start, source.find('>').unwrap());
    assert_eq!(span.end, source.find(" # outside").unwrap());
    assert_eq!((span.line, span.column), (1, 4));
    assert!(source[span.start..span.end].contains("# header\r\n"));
    assert!(source[span.start..span.end].contains("\r\n\r\n"));
    assert_eq!(scalar(doc.get("next").unwrap()).0, "done");
}

#[test]
fn header_comments_accept_yaml_separation_and_opaque_body_does_not_parse_markers() {
    let source = "v: >2-\t# header\n  ---\n  ...\n  &anchor *alias !tag # text\nnext: done\n";
    assert_eq!(value(source), "--- ... &anchor *alias !tag # text");
}

#[test]
fn malformed_indicators_are_refused_before_any_body_is_decoded_as_syntax() {
    for header in [
        "|0",
        "|10",
        "||",
        "|++",
        "|--",
        "|+-",
        "|-+",
        "|1+2",
        ">0",
        ">22",
        ">+x",
        "> 2",
        "> -",
        "|2#comment",
    ] {
        let source = format!("v: {header}\n  ---\n");
        let error = malformed(&source);
        assert_eq!(error.span().line, 1, "{header}");
        assert_eq!(&source[error.span().start..error.span().end], header);
    }
}

#[test]
fn leading_overindent_and_underindented_content_have_precise_refusal_spans() {
    let error = malformed("v: >-\n   \n  text\n");
    assert_eq!((error.span().line, error.span().column), (2, 1));
    assert_eq!(value("v: >-\n  \n  text\n"), "\ntext");
    let source = "v: >-\n  good\n\n bad\n";
    let error = malformed(source);
    assert_eq!((error.span().line, error.span().column), (4, 2));
    assert_eq!(&source[error.span().start..error.span().end], "bad\n");
    assert_eq!(value("v: >-\n  good\n\n  good\n"), "good\ngood");
    malformed("v: |2-\n text\n");
    assert_eq!(value("v: |2-\n  text\n"), "text");
}

#[test]
fn dedented_comment_ends_content_and_following_indented_syntax_cannot_disappear() {
    let source = "items:\n  - run: >2-\n      first\n     # outside scalar\n      silently lost before this fix\n";
    let error = malformed(source);
    assert_eq!(error.span().line, 5);
    let good = "items:\n  - run: >2-\n      first\n     # outside scalar\n    name: retained\n";
    let doc = scanned(good);
    let Node::Sequence { items, .. } = doc.get("items").unwrap() else {
        panic!("sequence");
    };
    assert_eq!(scalar(items[0].get("run").unwrap()).0, "first");
    assert_eq!(scalar(items[0].get("name").unwrap()).0, "retained");
}

#[test]
fn control_characters_are_refused_but_printable_twins_survive() {
    for character in [
        '\0', '\u{b}', '\u{1f}', '\u{7f}', '\u{9f}', '\u{feff}', '\u{ffff}',
    ] {
        let source = format!("v: |-\n  x{character}y\n");
        let error = malformed(&source);
        assert_eq!(
            &source[error.span().start..error.span().end],
            character.to_string()
        );
    }
    assert_eq!(value("v: |-\n  x\u{85}y\t\u{a0}\n"), "x\u{85}y\t\u{a0}");
}

#[test]
fn normalized_scalar_budget_has_an_exact_boundary_for_every_style() {
    for (header, bytes) in [("|-", 9), (">-", 9), ("|+", 11), (">+", 11)] {
        let source = format!("v: {header}\n  1234\n  5678\n\n");
        let mut limits = Limits {
            max_scalar_bytes: bytes,
            ..Limits::DEFAULT
        };
        let doc = yaml::scan(&source, &limits).unwrap();
        assert_eq!(scalar(doc.get("v").unwrap()).0.len(), bytes);
        limits.max_scalar_bytes -= 1;
        limited(&source, &limits, "scalar bytes");
    }
}

#[test]
fn physical_line_budget_counts_body_blanks_and_comment_lines_before_allocation() {
    for source in [
        "v: |+\n\n\n",
        "# ignored\n\nv: >-\n  text\n",
        "v: >-\r\n  one\r\n  two\r\n",
    ] {
        let lines = source.split('\n').count() - 1;
        let mut limits = Limits {
            max_lines: lines,
            ..Limits::DEFAULT
        };
        yaml::scan(source, &limits).unwrap();
        limits.max_lines -= 1;
        limited(source, &limits, "lines");
    }
}

#[test]
fn source_bytes_nodes_depth_and_collection_limits_still_bound_block_forms() {
    let source = "v: >-\n  text\n";
    let mut limits = Limits {
        max_bytes: source.len(),
        max_nodes: 2,
        max_depth: 1,
        max_entries: 1,
        ..Limits::DEFAULT
    };
    yaml::scan(source, &limits).unwrap();
    limits.max_bytes -= 1;
    limited(source, &limits, "bytes");
    limits.max_bytes += 1;
    limits.max_nodes = 1;
    limited(source, &limits, "nodes");
    limits.max_nodes = 2;
    limits.max_depth = 0;
    limited(source, &limits, "depth");

    let nested = "items:\n  - run: >-\n      text\n";
    limits = Limits {
        max_depth: 3,
        ..Limits::DEFAULT
    };
    yaml::scan(nested, &limits).unwrap();
    limits.max_depth = 2;
    limited(nested, &limits, "depth");

    let mapping = "v: >-\n  first\nw: |-\n  second\n";
    limits = Limits {
        max_entries: 2,
        ..Limits::DEFAULT
    };
    yaml::scan(mapping, &limits).unwrap();
    limits.max_entries = 1;
    limited(mapping, &limits, "mapping entries");
    let sequence = "- >-\n  first\n- |-\n  second\n";
    limits.max_entries = 2;
    yaml::scan(sequence, &limits).unwrap();
    limits.max_entries = 1;
    limited(sequence, &limits, "sequence items");
}

#[test]
fn existing_bare_literal_bytes_and_graph_identity_are_retained() {
    let source = workflow("|\n          printf first\n          printf second\n");
    let graph = compile(&source, &Limits::DEFAULT).unwrap();
    assert_eq!(graph.jobs[0].steps[0].run, "printf first\nprintf second\n");
    assert_eq!(
        graph.canonical_bytes(),
        concat!(
            "fgit-workflow/v1\nname\tblocks\ntrigger\tpush\n",
            "job\ttest\tfgit-trusted-local\nstep\ttest\t0\t\tprintf first\\nprintf second\\n\n"
        )
    );
    // Legacy bare | synthesizes an EOF newline and drops whitespace-only body
    // content. Newly admitted explicit indicators deliberately do neither.
    assert_eq!(value("v: |\n  alpha\n   \n  beta"), "alpha\n\nbeta\n");
    assert_eq!(value("v: |2-\n  alpha\n   \n  beta"), "alpha\n \nbeta");
    assert_eq!(value("v: |\n   \n  text\n"), "\ntext\n");
    assert!(yaml::scan("v: |\n\n", &Limits::DEFAULT).is_err());
}

#[test]
fn equivalent_resolved_commands_keep_existing_graph_version_and_identity() {
    let folded = workflow(">-\n          printf\n          '%s\\n'\n          result\n");
    let plain = workflow("printf '%s\\n' result\n");
    let graph = compile(&folded, &Limits::DEFAULT).unwrap();
    assert_eq!(graph.jobs[0].steps[0].run, "printf '%s\\n' result");
    assert_eq!(
        graph.canonical_bytes(),
        compile(&plain, &Limits::DEFAULT).unwrap().canonical_bytes()
    );
    let canonical = graph.canonical_bytes();
    for _ in 0..16 {
        assert_eq!(
            compile(&folded, &Limits::DEFAULT)
                .unwrap()
                .canonical_bytes(),
            canonical
        );
    }
    assert!(canonical.starts_with("fgit-workflow/v1\n"));
}

#[test]
fn bare_literal_lexer_keeps_embedded_carriage_returns_opaque() {
    for fragment in ["---", "...", "\tcontent", "key: value # data"] {
        let source = format!("v: |\n  a\r{fragment}\nnext: done\n");
        let doc = scanned(&source);
        let (text, span) = scalar(doc.get("v").unwrap());
        assert_eq!(text, format!("a\r{fragment}\n"));
        assert_eq!(span.end, source.find("next:").unwrap());
        assert_eq!(scalar(doc.get("next").unwrap()).1.line, 4);
    }
    assert_eq!(value("v: |\r\n  a\r\n"), "a\r\n");
    assert_eq!(value("v: |\n  a\n\t\n  b\n"), "a\n\nb\n");
}

#[test]
fn syntax_after_a_legacy_block_resumes_yaml_line_break_handling() {
    let doc = scanned("v: |\n  a\nnext: >-\r  b\r  c\r");
    assert_eq!(scalar(doc.get("v").unwrap()).0, "a\n");
    assert_eq!(scalar(doc.get("next").unwrap()).0, "b c");
}

#[test]
fn only_ascii_separation_whitespace_may_follow_new_block_headers() {
    for header in [">", ">-", ">2+", "|-", "|+", "|2"] {
        for character in ['\u{85}', '\u{a0}', '\u{2028}'] {
            let source = format!("v: {header}{character}\n  text\n");
            let error = malformed(&source);
            assert_eq!(error.span().line, 1);
            assert_eq!(
                &source[error.span().start..error.span().end],
                format!("{header}{character}")
            );
        }
        let permitted = format!("v: {header} \t\n  text\n");
        assert!(yaml::scan(&permitted, &Limits::DEFAULT).is_ok());
    }
    // Preserve the old bare-| header's whitespace normalization too.
    assert_eq!(value("v: |\u{a0}\n  text\n"), "text\n");
}

#[test]
fn unicode_prefixes_do_not_turn_plain_scalars_into_new_block_headers() {
    for header in [">", ">-", ">2+", "|-", "|+", "|2"] {
        for character in ['\u{85}', '\u{a0}', '\u{2028}'] {
            for source in [
                format!("v: {character}{header}\n  text\n"),
                format!("- {character}{header}\n  text\n"),
                format!("- run: {character}{header}\n    text\n"),
            ] {
                let error = malformed(&source);
                assert_eq!(error.span().line, 2, "{source:?}");
                assert_eq!(&source[error.span().start..error.span().end], "text");
            }
        }
        // Space and tab are actual YAML separation before these headers.
        for source in [
            format!("v:  \t{header}\n  text\n"),
            format!("- \t{header}\n  text\n"),
            format!("- \trun: \t{header}\n      text\n"),
        ] {
            scanned(&source);
        }
    }
}

#[test]
fn unicode_prefixes_remain_scalar_data_with_exact_quoted_twins() {
    for header in [">", ">-", ">2+", "|-", "|+", "|2"] {
        for character in ['\u{85}', '\u{a0}', '\u{2028}'] {
            let expected = format!("{character}{header}");
            let source = format!("v: {expected}\n");
            let doc = scanned(&source);
            let (text, span) = scalar(doc.get("v").unwrap());
            assert_eq!(text, expected);
            assert_eq!(&source[span.start..span.end], expected);
            assert_eq!(value(&format!("v: '{expected}'\n")), expected);

            for source in [format!("- {expected}\n"), format!("- '{expected}'\n")] {
                let Node::Sequence { items, .. } = scanned(&source) else {
                    panic!("sequence");
                };
                assert_eq!(scalar(&items[0]).0, expected);
            }
            for source in [
                format!("- run: {expected}\n"),
                format!("- run: '{expected}'\n"),
            ] {
                let Node::Sequence { items, .. } = scanned(&source) else {
                    panic!("sequence");
                };
                assert_eq!(scalar(items[0].get("run").unwrap()).0, expected);
            }
        }
    }
}

#[test]
fn unicode_on_new_block_mapping_keys_is_preserved_and_unknown_workflow_fields_refuse() {
    for character in ['\u{85}', '\u{a0}', '\u{2028}'] {
        for key in [format!("{character}run"), format!("run{character}")] {
            for header in [">-", "|-"] {
                for source in [
                    format!("- {key}: {header}\n    text\n"),
                    format!("- '{key}': {header}\n    text\n"),
                ] {
                    let Node::Sequence { items, .. } = scanned(&source) else {
                        panic!("sequence");
                    };
                    assert_eq!(scalar(items[0].get(&key).unwrap()).0, "text");
                    assert!(items[0].get("run").is_none());
                }
                let source = workflow(&format!("{header}\n          text\n")).replacen(
                    "- run:",
                    &format!("- {key}:"),
                    1,
                );
                let error = compile(&source, &Limits::DEFAULT).unwrap_err();
                assert!(
                    matches!(&error, WorkflowRefusal::FieldUnknown { key: actual, .. } if &**actual == key),
                    "{error:?}"
                );
            }
        }
    }
}

#[test]
fn bare_literal_keeps_legacy_unicode_prefix_normalization() {
    let canonical = compile(&workflow("|\n                text\n"), &Limits::DEFAULT)
        .unwrap()
        .canonical_bytes();
    for character in ['\u{85}', '\u{a0}', '\u{2028}'] {
        assert_eq!(value(&format!("v: {character}|\n  text\n")), "text\n");
        let Node::Sequence { items, .. } = scanned(&format!("- {character}|\n  text\n")) else {
            panic!("sequence");
        };
        assert_eq!(scalar(&items[0]).0, "text\n");
        for key in [format!("{character}run"), format!("run{character}")] {
            let source = workflow(&format!("{character}|\n                text\n")).replacen(
                "- run:",
                &format!("- {key}:"),
                1,
            );
            assert_eq!(
                compile(&source, &Limits::DEFAULT)
                    .unwrap()
                    .canonical_bytes(),
                canonical
            );
        }
    }
}
