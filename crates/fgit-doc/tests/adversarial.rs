//! Hostile input: bounded work, typed refusals, and never a panic.
//!
//! Every forbidden case below is paired with a near-identical permitted case,
//! so the suite proves the positive capability as well as the refusal.

mod common;

use fgit_doc::{
    Limits, ParseProfile, RefusalKind, RenderProfile, StructuralLimits, parse, parse_bytes,
    parse_with, render,
};

fn profile_with(structural: StructuralLimits) -> ParseProfile {
    ParseProfile::with_limits(Limits {
        structural,
        ..Limits::DEFAULT
    })
}

#[test]
fn nesting_beyond_the_ceiling_is_refused_and_just_under_it_parses() {
    let structural = StructuralLimits {
        max_depth: 12,
        ..StructuralLimits::DEFAULT
    };
    let profile = profile_with(structural);

    let shallow = format!("{}deep\n", "> ".repeat(6));
    parse_with(&shallow, profile).expect("nesting within the ceiling parses");

    let deep = format!("{}deep\n", "> ".repeat(400));
    let refusal = parse_with(&deep, profile).expect_err("nesting past the ceiling is refused");
    assert_eq!(refusal.kind(), RefusalKind::NestingTooDeep);
    assert_eq!(refusal.limit(), 12);
}

#[test]
fn a_profile_deeper_than_the_hard_cap_is_refused_and_the_cap_itself_is_accepted() {
    let at_cap = profile_with(StructuralLimits {
        max_depth: StructuralLimits::HARD_MAX_DEPTH,
        ..StructuralLimits::DEFAULT
    });
    parse_with("fine\n", at_cap).expect("the hard cap itself is a usable profile");

    let past_cap = profile_with(StructuralLimits {
        max_depth: StructuralLimits::HARD_MAX_DEPTH + 1,
        ..StructuralLimits::DEFAULT
    });
    let refusal =
        parse_with("fine\n", past_cap).expect_err("a profile past the hard cap is refused");
    assert_eq!(refusal.kind(), RefusalKind::NestingTooDeep);
    assert_eq!(refusal.limit(), u64::from(StructuralLimits::HARD_MAX_DEPTH));
}

#[test]
fn an_oversized_input_is_refused_and_the_largest_accepted_one_is_not() {
    let limits = Limits {
        max_input_bytes: 64,
        ..Limits::DEFAULT
    };
    let profile = ParseProfile::with_limits(limits);
    let permitted = "a".repeat(64);
    parse_with(&permitted, profile).expect("exactly the ceiling is accepted");
    let refused = "a".repeat(65);
    let refusal = parse_with(&refused, profile).expect_err("one byte past the ceiling is refused");
    assert_eq!(refusal.kind(), RefusalKind::InputTooLarge);
    assert_eq!(refusal.limit(), 64);
    assert_eq!(refusal.observed(), 65);
}

#[test]
fn an_overlong_line_is_refused_and_a_shorter_one_parses() {
    let profile = profile_with(StructuralLimits {
        max_line_bytes: 32,
        ..StructuralLimits::DEFAULT
    });
    parse_with(&format!("{}\n", "a".repeat(32)), profile).expect("a line at the ceiling parses");
    let refusal = parse_with(&format!("{}\n", "a".repeat(33)), profile)
        .expect_err("a line past the ceiling is refused");
    assert_eq!(refusal.kind(), RefusalKind::LineTooLong);
}

#[test]
fn too_many_nodes_is_refused_and_a_smaller_document_parses() {
    let profile = profile_with(StructuralLimits {
        max_nodes: 8,
        ..StructuralLimits::DEFAULT
    });
    parse_with("one\n\ntwo\n", profile).expect("a small document fits the node ceiling");
    let many = (0..200)
        .map(|index| format!("paragraph {index}\n\n"))
        .collect::<String>();
    let refusal = parse_with(&many, profile).expect_err("too many nodes is refused");
    assert_eq!(refusal.kind(), RefusalKind::TooManyNodes);
    assert_eq!(refusal.limit(), 8);
}

#[test]
fn too_many_inline_delimiters_is_refused_and_a_modest_count_parses() {
    let profile = profile_with(StructuralLimits {
        max_inline_delimiters: 16,
        ..StructuralLimits::DEFAULT
    });
    parse_with("a *b* c *d* e\n", profile).expect("a modest delimiter count parses");
    let hostile = format!("{}\n", "*a".repeat(500));
    let refusal =
        parse_with(&hostile, profile).expect_err("a delimiter storm is refused, not chewed on");
    assert_eq!(refusal.kind(), RefusalKind::TooManyInlineDelimiters);
}

#[test]
fn invalid_utf8_bytes_are_refused_and_valid_bytes_parse() {
    parse_bytes("valid text\n".as_bytes(), ParseProfile::DEFAULT).expect("valid bytes parse");
    let refusal = parse_bytes(&[0x66, 0x6f, 0xff, 0x6f], ParseProfile::DEFAULT)
        .expect_err("invalid bytes are refused");
    assert_eq!(refusal.kind(), RefusalKind::SourceNotUtf8);
}

/// Inputs that have historically broken hand-written markup parsers.
fn hostile_sources() -> Vec<String> {
    let mut sources = vec![
        String::new(),
        "\n".to_owned(),
        "\r".to_owned(),
        "\r\n\r\n".to_owned(),
        "\0\0\0".to_owned(),
        "[".to_owned(),
        "![".to_owned(),
        "]".to_owned(),
        "[]()".to_owned(),
        "[](".to_owned(),
        "[a](b".to_owned(),
        "[a](<b".to_owned(),
        "[a](b \"unterminated".to_owned(),
        "<".to_owned(),
        "<>".to_owned(),
        "<a".to_owned(),
        "`".to_owned(),
        "``".to_owned(),
        "```".to_owned(),
        "~~~".to_owned(),
        "\\".to_owned(),
        "\\\\".to_owned(),
        ">".to_owned(),
        "> ".to_owned(),
        "-".to_owned(),
        "- ".to_owned(),
        "1.".to_owned(),
        "1. ".to_owned(),
        "#".to_owned(),
        "####### too many".to_owned(),
        "=".to_owned(),
        "\t".to_owned(),
        "    ".to_owned(),
        "a\n=".to_owned(),
        "a\n-".to_owned(),
    ];
    sources.push("*".repeat(2000));
    sources.push("_".repeat(2000));
    sources.push("*a".repeat(1000));
    sources.push("**a**".repeat(400));
    sources.push("[".repeat(1000));
    sources.push("![".repeat(1000));
    sources.push("`".repeat(1000));
    sources.push(">".repeat(1000));
    sources.push("- ".repeat(1000));
    sources.push(format!("{}x", "> ".repeat(1000)));
    sources.push(format!("{}x", "- ".repeat(1000)));
    sources.push(format!("{}x{}", "*".repeat(500), "*".repeat(500)));
    sources.push("<a><b><c>".repeat(300));
    sources.push("\u{feff}\u{200b}\u{2028}text\n".to_owned());
    sources.push("\u{e9}".repeat(2000));
    sources
}

#[test]
fn hostile_sources_produce_a_document_or_a_typed_refusal_but_never_a_panic() {
    for source in hostile_sources() {
        match parse(&source) {
            Ok(parsed) => {
                common::assert_span_integrity("hostile", parsed.document());
                for profile in RenderProfile::all() {
                    let _ = render(parsed.document(), profile, Limits::DEFAULT);
                }
            }
            Err(refusal) => {
                assert!(
                    matches!(
                        refusal.kind(),
                        RefusalKind::InputTooLarge
                            | RefusalKind::LineTooLong
                            | RefusalKind::TooManyNodes
                            | RefusalKind::NestingTooDeep
                            | RefusalKind::TooManyInlineDelimiters
                    ),
                    "an unexpected refusal kind for hostile input: {refusal}"
                );
            }
        }
    }
}

/// A deterministic pseudo-random generator, so a failure reproduces exactly.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

#[test]
fn generated_marker_soup_never_panics_and_keeps_its_spans_honest() {
    const ALPHABET: &[u8] = b"*_-+>#`[]()!<>\\\"' \t\n\r=~.0123456789ab";
    let mut generator = Lcg(0x5eed_1234_abcd_ef01);
    for iteration in 0..600_u32 {
        let length = usize::try_from(generator.next() % 240).unwrap_or(0) + 1;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            let index = usize::try_from(generator.next()).unwrap_or(0) % ALPHABET.len();
            bytes.push(ALPHABET.get(index).copied().unwrap_or(b'a'));
        }
        let Ok(source) = core::str::from_utf8(&bytes) else {
            continue;
        };
        if let Ok(parsed) = parse(source) {
            common::assert_span_integrity(&format!("generated-{iteration}"), parsed.document());
            for profile in RenderProfile::all() {
                let _ = render(parsed.document(), profile, Limits::DEFAULT);
            }
        }
    }
}

#[test]
fn a_control_character_destination_is_refused_and_a_clean_one_is_not() {
    let hostile = "[a](java\u{0}script:x)\n";
    let parsed = parse(hostile).expect("the document still parses");
    assert!(
        parsed
            .diagnostics()
            .iter()
            .any(|entry| entry.code.tag() == "rejected_destination"),
        "a control character in a destination must be reported"
    );
    let clean = parse("[a](https://example.com)\n").expect("a clean destination parses");
    assert!(
        clean
            .diagnostics()
            .iter()
            .all(|entry| entry.code.tag() != "rejected_destination"),
        "a clean destination must not be rejected"
    );
}

#[test]
fn an_extremely_long_destination_is_rejected_but_a_long_permitted_one_is_kept() {
    let long = format!("[a](https://example.com/{})\n", "p".repeat(200));
    let parsed = parse(&long).expect("a long but bounded destination parses");
    assert!(
        parsed
            .diagnostics()
            .iter()
            .all(|entry| entry.code.tag() != "rejected_destination"),
        "two hundred path bytes are fine"
    );
    let absurd = format!("[a](https://example.com/{})\n", "p".repeat(8000));
    let refused = parse(&absurd).expect("the document still parses");
    assert!(
        refused
            .diagnostics()
            .iter()
            .any(|entry| entry.code.tag() == "rejected_destination"),
        "an absurd destination is rejected rather than emitted"
    );
}
