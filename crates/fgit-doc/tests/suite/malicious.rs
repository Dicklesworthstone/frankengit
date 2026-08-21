//! The malicious-content corpus.
//!
//! Every case must end in one of exactly two states: a typed refusal naming the
//! bound it hit, or a complete document whose rendered surfaces are bounded and
//! carry no active content. Never a panic, and never a super-linear expansion.
//!
//! The size ceilings below are asserted against the *input size*, not against
//! wall time. A timing assertion would be a flaky proxy for the property that
//! actually matters — that a small hostile input cannot produce a large amount
//! of work or output.

use std::fs;
use std::path::{Path, PathBuf};

use fgit_doc::{
    Limits, ParseProfile, RefusalKind, RenderProfile, StructuralLimits, parse, parse_bytes,
    parse_with, render,
};

/// Rendered output may not exceed this multiple of the input size, plus slack.
///
/// The widest per-character expansion this crate can produce is a neutralised
/// bidirectional control (three source bytes becoming a marked span), which is
/// under twenty. The ceiling is set far above that so it tests the *shape* of
/// the bound — linear — rather than the current constant.
const OUTPUT_BYTES_PER_INPUT_BYTE: usize = 64;

/// Node count may not exceed this multiple of the input size, plus slack.
const NODES_PER_INPUT_BYTE: usize = 8;

/// Slack for documents whose fixed framing dominates a tiny input.
const SIZE_SLACK: usize = 4096;

fn malicious_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("goldens")
        .join("malicious")
}

fn malicious_cases() -> Vec<(String, Vec<u8>)> {
    let mut cases = fs::read_dir(malicious_root())
        .expect("the malicious corpus directory exists")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".md"))
        })
        .map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let bytes = fs::read(entry.path()).expect("a corpus file is readable");
            (name, bytes)
        })
        .collect::<Vec<_>>();
    cases.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(cases.len() >= 12, "the malicious corpus must stay broad");
    cases
}

// ------------------------------------------------------- active content

/// Tags a rendered surface is permitted to emit. Anything else is a defect.
const ALLOWED_TAGS: [&str; 18] = [
    "p",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "br",
    "hr",
    "em",
    "strong",
    "code",
    "pre",
    "blockquote",
    "ul",
    "ol",
    "li",
    "span",
];

/// Tags that carry a destination and are therefore also permitted.
const ALLOWED_TARGET_TAGS: [&str; 2] = ["a", "img"];

/// Attributes a rendered surface is permitted to emit.
const ALLOWED_ATTRIBUTES: [&str; 8] = [
    "href",
    "title",
    "alt",
    "src",
    "rel",
    "class",
    "start",
    "data-fgit-doc-rejected",
];

/// Substrings that must never appear in a rendered surface, in any case.
const FORBIDDEN_SUBSTRINGS: [&str; 12] = [
    "<script",
    "<style",
    "<iframe",
    "<object",
    "<embed",
    "<svg",
    "<base",
    "<meta",
    "<form",
    "srcdoc",
    "formaction",
    "javascript:",
];

/// A conservative allowlist check over one rendered surface.
///
/// The renderer escapes every `<` that came from the source, so any `<` left in
/// the output is a tag the renderer itself chose to emit. That makes a simple
/// scan sufficient and, more importantly, makes any escape visible.
fn assert_no_active_content(case: &str, html: &str) {
    let lowered = html.to_ascii_lowercase();
    for forbidden in FORBIDDEN_SUBSTRINGS {
        assert!(
            !lowered.contains(forbidden),
            "{case}: rendered output contains {forbidden:?}"
        );
    }
    assert!(
        !lowered.contains("data:"),
        "{case}: rendered output contains a data uri"
    );
    assert!(
        !lowered.contains("vbscript:"),
        "{case}: rendered output contains a vbscript uri"
    );

    let mut rest = html;
    while let Some(open) = rest.find('<') {
        let after = rest.get(open + 1..).unwrap_or("");
        let close = after.find('>').unwrap_or_else(|| {
            panic!("{case}: an unterminated tag was emitted");
        });
        let inner = after.get(..close).unwrap_or("");
        let trimmed = inner.trim_start_matches('/').trim_end_matches('/').trim();
        let mut parts = trimmed.split_whitespace();
        let name = parts.next().unwrap_or("").to_ascii_lowercase();
        assert!(
            ALLOWED_TAGS.contains(&name.as_str()) || ALLOWED_TARGET_TAGS.contains(&name.as_str()),
            "{case}: rendered output emitted the tag {name:?}"
        );
        for attribute in attribute_names(inner) {
            assert!(
                !attribute.starts_with("on"),
                "{case}: rendered output emitted the event attribute {attribute:?}"
            );
            assert!(
                ALLOWED_ATTRIBUTES.contains(&attribute.as_str())
                    || attribute == "data-fgit-doc-neutralised",
                "{case}: rendered output emitted the attribute {attribute:?}"
            );
        }
        rest = after.get(close + 1..).unwrap_or("");
    }
}

/// Attribute names inside one tag body, ignoring quoted values.
fn attribute_names(inner: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut current = String::new();
    let mut in_value = false;
    let mut quote = '\0';
    let mut seen_name = false;
    for value in inner.chars() {
        if in_value {
            if value == quote {
                in_value = false;
            }
            continue;
        }
        match value {
            '"' | '\'' => {
                in_value = true;
                quote = value;
            }
            '=' => {
                if seen_name && !current.is_empty() {
                    names.push(current.to_ascii_lowercase());
                }
                current.clear();
            }
            c if c.is_whitespace() => {
                current.clear();
                seen_name = true;
            }
            c => current.push(c),
        }
    }
    names
}

// ------------------------------------------------------------- the corpus

#[test]
fn every_malicious_case_ends_bounded_and_inert_or_refused() {
    for (name, bytes) in malicious_cases() {
        let parsed = match parse_bytes(&bytes, ParseProfile::DEFAULT) {
            Ok(parsed) => parsed,
            Err(refusal) => {
                assert!(
                    RefusalKind::ALL.contains(&refusal.kind()),
                    "{name}: refusal kind must be one this crate declares"
                );
                continue;
            }
        };
        let document = parsed.document();
        let input = bytes.len().max(1);

        assert!(
            document.node_count() <= NODES_PER_INPUT_BYTE * input + SIZE_SLACK,
            "{name}: {} nodes from {input} input bytes is super-linear",
            document.node_count()
        );

        for profile in RenderProfile::all() {
            let rendered = match render(document, profile, Limits::DEFAULT) {
                Ok(rendered) => rendered,
                Err(refusal) => {
                    assert_eq!(
                        refusal.kind(),
                        RefusalKind::OutputTooLarge,
                        "{name}/{}: only the output ceiling may refuse a parsed document",
                        profile.tag()
                    );
                    continue;
                }
            };
            assert!(
                rendered.len() <= OUTPUT_BYTES_PER_INPUT_BYTE * input + SIZE_SLACK,
                "{name}/{}: {} output bytes from {input} input bytes is super-linear",
                profile.tag(),
                rendered.len()
            );
            if profile == RenderProfile::HtmlSafe {
                assert_no_active_content(&name, rendered.as_str());
            }
        }
    }
}

#[test]
fn the_whole_golden_corpus_is_inert_too() {
    // The safe corpus must clear the same allowlist as the hostile one: a
    // renderer that only behaves under attack is not safe by default.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("goldens")
        .join("corpus");
    for entry in fs::read_dir(dir)
        .expect("the corpus directory exists")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".md") {
            continue;
        }
        let source = fs::read_to_string(entry.path()).expect("a corpus file is readable");
        let document = parse(&source)
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"))
            .into_document();
        let html = render(&document, RenderProfile::HtmlSafe, Limits::DEFAULT)
            .unwrap_or_else(|refusal| panic!("{name}: {refusal}"))
            .into_string();
        assert_no_active_content(&name, &html);
    }
}

#[test]
fn the_allowlist_checker_rejects_content_the_renderer_could_never_emit() {
    // A checker that cannot fail proves nothing, so prove it fails. The panic
    // hook is silenced first: these panics are the expected result, and their
    // backtraces would otherwise pollute the run's diagnostics.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for planted in [
        "<p><script>alert(1)</script></p>",
        "<p><a href=\"javascript:alert(1)\">x</a></p>",
        "<p onclick=\"steal()\">x</p>",
        "<p><img src=\"data:text/html,x\" /></p>",
        "<p><iframe srcdoc=\"x\"></iframe></p>",
    ] {
        let outcome = std::panic::catch_unwind(|| assert_no_active_content("planted", planted));
        assert!(
            outcome.is_err(),
            "the allowlist checker accepted planted active content: {planted}"
        );
    }
    std::panic::set_hook(previous);
    // And it accepts what the renderer really does emit.
    assert_no_active_content(
        "permitted",
        "<h1>T</h1>\n<p><a href=\"https://e.com\" rel=\"nofollow noopener noreferrer\">x</a>\
         <span data-fgit-doc-rejected=\"disallowed_scheme\">y</span>\
         <span data-fgit-doc-neutralised=\"bidi_control\">U+202E</span></p>\n\
         <pre><code class=\"language-rust\">fn f() {}\n</code></pre>\n",
    );
}

// --------------------------------------------------------- bound coverage

/// One fixture per refusal, so no bound is declared without being exercised.
fn trip(kind: RefusalKind) -> RefusalKind {
    let tiny = |structural| {
        ParseProfile::with_limits(Limits {
            structural,
            ..Limits::DEFAULT
        })
    };
    match kind {
        RefusalKind::InputTooLarge => parse_with(
            "aa",
            ParseProfile::with_limits(Limits {
                max_input_bytes: 1,
                ..Limits::DEFAULT
            }),
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::LineTooLong => parse_with(
            "aaaa\n",
            tiny(StructuralLimits {
                max_line_bytes: 2,
                ..StructuralLimits::DEFAULT
            }),
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::TooManyNodes => parse_with(
            "a\n\nb\n\nc\n\nd\n",
            tiny(StructuralLimits {
                max_nodes: 2,
                ..StructuralLimits::DEFAULT
            }),
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::NestingTooDeep => parse_with(
            "> > > > x\n",
            tiny(StructuralLimits {
                max_depth: 2,
                ..StructuralLimits::DEFAULT
            }),
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::TooManyInlineDelimiters => parse_with(
            "*a*b*c*d*e*f*\n",
            tiny(StructuralLimits {
                max_inline_delimiters: 2,
                ..StructuralLimits::DEFAULT
            }),
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::OutputTooLarge => render(
            &parse("a long enough paragraph to pass a tiny ceiling\n")
                .expect("parses")
                .into_document(),
            RenderProfile::HtmlSafe,
            Limits {
                max_output_bytes: 4,
                ..Limits::DEFAULT
            },
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::SourceNotUtf8 => parse_bytes(&[0xff, 0xfe], ParseProfile::DEFAULT)
            .expect_err("tripped")
            .kind(),
        RefusalKind::SourceIdTooLong => fgit_doc::SourceObjectId::new(&[0_u8; 65])
            .expect_err("tripped")
            .kind(),
        RefusalKind::ProfileMismatch => trip_profile_mismatch(),
        RefusalKind::UnknownNode => trip_unknown_node(),
        RefusalKind::TooManyBatchInputs => fgit_doc::render_batch(
            &[fgit_doc::BatchInput::render("x\n"); 2],
            ParseProfile::with_limits(Limits {
                max_batch_inputs: 1,
                ..Limits::DEFAULT
            }),
            RenderProfile::PlainText,
            fgit_doc::WorkloadProfile::SERIAL,
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::WorkloadUnusable => fgit_doc::worker_count(
            fgit_doc::WorkloadProfile {
                cpu_cap: 0,
                ..fgit_doc::WorkloadProfile::SERIAL
            },
            RenderProfile::PlainText,
            1,
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::OutputNameInvalid => {
            fgit_doc::OutputRequest::new("../escape", RenderProfile::PlainText)
                .expect_err("tripped")
                .kind()
        }
        RefusalKind::DuplicateOutputName => trip_duplicate_name(),
        RefusalKind::TooManyOutputs => fgit_doc::stage(
            &parse("x\n").expect("parses").into_document(),
            &[],
            Limits::DEFAULT,
        )
        .expect_err("tripped")
        .kind(),
    }
}

fn trip_profile_mismatch() -> RefusalKind {
    let document = parse("alpha\n").expect("parses").into_document();
    let anchor = fgit_doc::Anchor::create(
        &document,
        document.roots()[0],
        fgit_doc::SourceObjectId::new(b"a").expect("identity"),
        Limits::DEFAULT,
    )
    .expect("anchor");
    let other = parse_with(
        "alpha\n",
        ParseProfile::with_limits(Limits {
            structural: StructuralLimits {
                max_depth: 9,
                ..StructuralLimits::DEFAULT
            },
            ..Limits::DEFAULT
        }),
    )
    .expect("parses")
    .into_document();
    anchor
        .remap(&other, Limits::DEFAULT)
        .expect_err("tripped")
        .kind()
}

fn trip_unknown_node() -> RefusalKind {
    let small = parse("a\n").expect("parses").into_document();
    let large = parse("a\n\nb\n\nc\n\nd\n").expect("parses").into_document();
    let stranger = large
        .preorder()
        .map(|(id, _)| id)
        .last()
        .expect("a node id beyond the small document");
    fgit_doc::Anchor::create(
        &small,
        stranger,
        fgit_doc::SourceObjectId::new(b"a").expect("identity"),
        Limits::DEFAULT,
    )
    .expect_err("tripped")
    .kind()
}

fn trip_duplicate_name() -> RefusalKind {
    let document = parse("x\n").expect("parses").into_document();
    let clashing = vec![
        fgit_doc::OutputRequest::new("a.txt", RenderProfile::PlainText).expect("name"),
        fgit_doc::OutputRequest::new("a.txt", RenderProfile::HtmlSafe).expect("name"),
    ];
    fgit_doc::stage(&document, &clashing, Limits::DEFAULT)
        .expect_err("tripped")
        .kind()
}

#[test]
fn every_declared_bound_has_a_fixture_that_trips_it() {
    // Exhaustive over RefusalKind::ALL: adding a bound without a fixture that
    // demonstrates it fails here rather than shipping as an untested claim.
    for kind in RefusalKind::ALL {
        assert_eq!(
            trip(*kind),
            *kind,
            "the fixture for {} tripped a different bound",
            kind.tag()
        );
    }
}
