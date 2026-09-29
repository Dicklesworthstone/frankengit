//! Regression tests for the opaque-token boundary shared by scanned and stored
//! declaration retrieval. Opacity is not Unicode declaration-name support.
use super::*;
use std::cell::Cell;

fn run(bytes: &[u8]) -> (Scan, Budget) {
    let mut budget = Budget::new(MAX_WORK).unwrap();
    let scan = extract(bytes, &mut budget, &|| false).unwrap();
    (scan, budget)
}
fn names(bytes: &[u8]) -> Vec<&[u8]> {
    run(bytes)
        .0
        .declarations
        .into_iter()
        .map(|d| &bytes[d.byte_offset..d.byte_offset + d.byte_length])
        .collect()
}
fn refused(text: &str, kind: ErrorKind) {
    assert_eq!(
        extract(
            text.as_bytes(),
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| false
        )
        .unwrap_err()
        .kind,
        kind,
        "{text}"
    );
}

#[test]
fn attributes_accept_opaque_unicode_without_emitting_their_heads() {
    for attribute in [
        "#[名]",
        "#[allow(名, naïve)]",
        "#![custom(r#名, fn Hidden() {}, [struct Hidden;])]",
    ] {
        let text = format!("{attribute}\nfn Keep() {{}}\n");
        assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
        assert_eq!(run(text.as_bytes()).0.attributes_skipped, 1);
    }
}

#[test]
fn macro_rules_retains_its_name_but_not_unicode_transcriber_declarations() {
    let text = "fn Before() {} macro_rules! make { ($名:ident) => { fn Hidden() {} let naïve = $名; }; } fn After() {}";
    let (scan, budget) = run(text.as_bytes());
    assert_eq!(
        names(text.as_bytes()),
        vec![b"Before".as_slice(), b"make", b"After"]
    );
    assert_eq!(scan.declarations[1].kind, Kind::Macro);
    assert_eq!(scan.macro_bodies_skipped, 1);
    assert_eq!(budget.declarations, 3);
}

#[test]
fn every_invocation_delimiter_accepts_unicode_tokens() {
    for (open, close) in [('(', ')'), ('[', ']'), ('{', '}')] {
        let text = format!("crate::m!{open}名 r#名 fn Hidden() {{}}{close}; fn Keep() {{}}");
        assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
        assert_eq!(run(text.as_bytes()).0.macro_bodies_skipped, 1);
    }
}

#[test]
fn nested_token_trees_are_one_opaque_body_not_recursive_declaration_scans() {
    let text = "m!{ 名 inner![r#名 { fn Hidden() {} }] #[opaque(名)] } fn Keep() {}";
    let (scan, _) = run(text.as_bytes());
    assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
    assert_eq!(scan.macro_bodies_skipped, 1);
    assert_eq!(scan.attributes_skipped, 0);
}

#[test]
fn unicode_lifetimes_raw_lifetimes_and_chars_do_not_swallow_group_ends() {
    let text = "m!('寿命 'r#生命 'é' '🦀' r#名); fn Keep() {}";
    assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
}

#[test]
fn opaque_literal_suffixes_do_not_enter_the_ascii_name_profile() {
    let text =
        r####"m!(1名 1.0名 "}"名 r#"]"#名 b'}'名 br#")"#名 c"}"名 cr#"]"#名); fn Keep() {}"####;
    assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
}

#[test]
fn long_opaque_names_do_not_inherit_the_declaration_name_ceiling() {
    for length in [MAX_NAME_BYTES, MAX_NAME_BYTES + 1, 8192] {
        let name = "x".repeat(length);
        for body in [format!("#[custom({name})]"), format!("m!({name});")] {
            let text = format!("{body} fn Keep() {{}}");
            assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
        }
    }
}

#[test]
fn opaque_unicode_never_hides_literal_comment_or_delimiter_boundaries() {
    let text = r####"m! { 名 /* } /* ] */ ) */ "} ] )" r###"} ] )"### '\'' b'}' // }
        [r#名 ("fn Hidden() {}")]
    } fn Keep() {}"####;
    assert_eq!(names(text.as_bytes()), vec![b"Keep".as_slice()]);
}

#[test]
fn unicode_in_ordinary_code_remains_an_explicit_refusal() {
    for suffix in [
        "fn naïve() {}",
        "struct 名;",
        "fn Keep<'寿命>() {}",
        "macro_rules! 名 {}",
    ] {
        for prefix in [
            "m!(名); ",
            "#[custom(名)] ",
            "macro_rules! make { () => {名} } ",
        ] {
            refused(
                &format!("{prefix}{suffix}"),
                ErrorKind::UnsupportedIdentifier,
            );
        }
    }
}

#[test]
fn leaving_an_opaque_group_restores_the_ordinary_name_length_limit() {
    let name = "a".repeat(MAX_NAME_BYTES);
    let yes = format!("m!(名); fn {name}() {{}}");
    assert_eq!(names(yes.as_bytes()), vec![name.as_bytes()]);
    refused(&format!("m!(名); fn {name}a() {{}}"), ErrorKind::NameLimit);
    refused(
        &format!("#[opaque(名)] fn {name}a() {{}}"),
        ErrorKind::NameLimit,
    );
}

#[test]
fn malformed_opaque_groups_still_refuse_the_complete_scan() {
    for text in ["m!(名 [)});", "m!{名", "#[opaque(名] fn Keep() {}"] {
        refused(text, ErrorKind::UnbalancedDelimiter);
    }
    refused("m!(名 /* unfinished)", ErrorKind::UnterminatedComment);
    refused("m!(名 \"unfinished)", ErrorKind::UnterminatedLiteral);
    refused("m!(名 r##\"unfinished\"#)", ErrorKind::UnterminatedLiteral);
}

#[test]
fn invalid_utf8_inside_opaque_tokens_is_not_ignored() {
    for text in [
        b"m!(\xff); fn Keep() {}".as_slice(),
        b"#[x(\xff)] fn Keep() {}",
    ] {
        assert_eq!(
            extract(text, &mut Budget::new(MAX_WORK).unwrap(), &|| false)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidUtf8
        );
    }
}

#[test]
fn opaque_work_limits_have_exact_success_and_failure_twins() {
    let text = format!("#[opaque({})] m!(名); fn Keep() {{}}", "名".repeat(4096));
    let (_, measured) = run(text.as_bytes());
    let mut exact = Budget::new(measured.work).unwrap();
    assert_eq!(
        extract(text.as_bytes(), &mut exact, &|| false)
            .unwrap()
            .declarations
            .len(),
        1
    );
    assert_eq!(exact.work, measured.work);
    assert_eq!(
        extract(
            text.as_bytes(),
            &mut Budget::new(measured.work - 1).unwrap(),
            &|| false
        )
        .unwrap_err()
        .kind,
        ErrorKind::WorkLimit
    );
    let mut shared = Budget::new(measured.work * 2 - 1).unwrap();
    extract(text.as_bytes(), &mut shared, &|| false).unwrap();
    assert_eq!(
        extract(text.as_bytes(), &mut shared, &|| false)
            .unwrap_err()
            .kind,
        ErrorKind::WorkLimit
    );
}

#[test]
fn ignored_heads_do_not_spend_or_bypass_the_shared_declaration_quota() {
    let text = b"m!{ fn Hidden(){} } fn Keep(){}";
    let mut budget = Budget::new(MAX_WORK).unwrap();
    budget.declarations = MAX_DECLARATIONS - 1;
    assert_eq!(
        extract(text, &mut budget, &|| false)
            .unwrap()
            .declarations
            .len(),
        1
    );
    assert_eq!(budget.declarations, MAX_DECLARATIONS);
    assert_eq!(
        extract(b"fn Extra(){}", &mut budget, &|| false)
            .unwrap_err()
            .kind,
        ErrorKind::DeclarationLimit
    );
}

#[test]
fn opaque_delimiter_and_comment_depth_remain_bounded() {
    let accepted = format!(
        "m!{}名{}; fn Keep() {{}}",
        "(".repeat(MAX_DEPTH),
        ")".repeat(MAX_DEPTH)
    );
    assert_eq!(names(accepted.as_bytes()), vec![b"Keep".as_slice()]);
    let refused_tree = format!(
        "m!{}名{}",
        "(".repeat(MAX_DEPTH + 1),
        ")".repeat(MAX_DEPTH + 1)
    );
    refused(&refused_tree, ErrorKind::DepthLimit);
    let comments = format!(
        "m!(名 {}{});",
        "/*".repeat(MAX_DEPTH + 1),
        "*/".repeat(MAX_DEPTH + 1)
    );
    refused(&comments, ErrorKind::DepthLimit);
}

#[test]
fn opaque_source_remains_subject_to_the_complete_file_limit() {
    let text = format!("m!({});", "x".repeat(MAX_FILE_BYTES));
    refused(&text, ErrorKind::FileLimit);
}

#[test]
fn every_checkpoint_can_cancel_opaque_work_without_returning_partial_declarations() {
    let text = format!(
        "fn Before() {{}} m!({}); fn After() {{}}",
        "名".repeat(4096)
    );
    let calls = Cell::new(0);
    extract(
        text.as_bytes(),
        &mut Budget::new(MAX_WORK).unwrap(),
        &|| {
            calls.set(calls.get() + 1);
            false
        },
    )
    .unwrap();
    assert!(calls.get() > 10);
    for stop in 1..=calls.get() {
        let seen = Cell::new(0);
        let error = extract(
            text.as_bytes(),
            &mut Budget::new(MAX_WORK).unwrap(),
            &|| {
                seen.set(seen.get() + 1);
                seen.get() == stop
            },
        )
        .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Cancelled, "checkpoint {stop}");
        assert_eq!(seen.get(), stop);
    }
}

#[test]
fn utf8_bom_and_crlf_coordinates_remain_byte_exact_after_opaque_tokens() {
    let text = "\u{feff}#![opaque(名)]\r\nm!(名\r\n[名]);\r\n  fn r#type() {}\r\n";
    let bytes = text.as_bytes();
    let (scan, _) = run(bytes);
    assert_eq!(scan.declarations.len(), 1);
    let declaration = scan.declarations[0];
    assert_eq!(declaration.line, 4);
    assert_eq!(declaration.byte_column, 8);
    assert!(declaration.raw_identifier);
    assert_eq!(
        &bytes[declaration.byte_offset..declaration.byte_offset + declaration.byte_length],
        b"type"
    );
}

#[test]
fn original_ascii_token_boundaries_and_work_are_identical_in_both_contexts() {
    for input in [
        r####"fn r#type<'a>(x: &'a str) { let x = 12.4_u8; }"####,
        r####"/* comment /* nested */ */ "quote"suffix r##"raw }"## b'}' 'é' cr"C""####,
    ] {
        let lexed = |context| {
            let mut budget = Budget::new(MAX_WORK).unwrap();
            let mut lex = Lexer {
                bytes: input.as_bytes(),
                at: 0,
                line: 1,
                line_start: 0,
                budget: &mut budget,
                cancelled: &|| false,
                look: None,
            };
            let mut spans = Vec::new();
            while let Some(token) = lex.next_in(context).unwrap() {
                let delimiter = match token.kind {
                    TokenKind::Punct(byte) => Some(byte),
                    _ => None,
                };
                spans.push((token.start, token.end, token.line, token.column, delimiter));
            }
            (spans, budget.work)
        };
        assert_eq!(lexed(NameContext::Code), lexed(NameContext::OpaqueGroup));
    }
}
