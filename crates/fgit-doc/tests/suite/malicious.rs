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
    AnchorBasis, Limits, ParseProfile, RefusalKind, RenderProfile, StructuralLimits, parse,
    parse_bytes, parse_with, render,
};

/// Text-surface output may not exceed this multiple of the input size.
///
/// The widest per-character expansion these surfaces produce is a neutralised
/// bidirectional control (three source bytes becoming a marked span), which is
/// under twenty. The ceiling is set far above that so it tests the *shape* of
/// the bound — linear — rather than the current constant.
const OUTPUT_BYTES_PER_INPUT_BYTE: usize = 64;

/// The canonical `JSON` surface is bounded per record, not per input byte.
///
/// Its size is dominated by fixed per-node framing — identifier, kind, parent,
/// four span numbers, line, column, attributes, children — of roughly two
/// hundred bytes, which a short document full of tiny nodes multiplies well
/// past any sensible per-input-byte constant. Bounding it against the node
/// count states the actual mechanism; composed with the node bound below,
/// which is itself linear in the input, the surface stays linear in the input.
/// Choosing a bigger per-input constant instead would have hidden that.
const JSON_BYTES_PER_NODE: usize = 512;

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
                .path()
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("mdin"))
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

/// Schemes a rendered destination may carry. Anything else is inert or absent.
const NAVIGABLE_SCHEMES: [&str; 3] = ["http", "https", "mailto"];

/// One tag the renderer emitted, with its attributes.
struct Tag {
    name: String,
    attributes: Vec<(String, String)>,
}

/// Every tag a rendered surface emitted.
///
/// Source `<` is always escaped, so a `<` surviving into the output is a tag
/// the renderer itself chose to emit. That is what makes scanning for `<` both
/// sufficient and meaningful — and it is why this checker must be structural
/// rather than a substring scan. A document *about* hostile markup renders that
/// markup as escaped text, and escaped text legitimately contains the byte
/// sequences `javascript:` and `onerror=`; only their appearance in a real
/// emitted tag is a defect.
fn emitted_tags(case: &str, html: &str) -> Vec<Tag> {
    let mut tags = Vec::new();
    let mut rest = html;
    while let Some(open) = rest.find('<') {
        let after = rest.get(open + 1..).unwrap_or("");
        let close = after
            .find('>')
            .unwrap_or_else(|| panic!("{case}: an unterminated tag was emitted"));
        let body = after.get(..close).unwrap_or("");
        let trimmed = body.trim_start_matches('/').trim_end_matches('/').trim();
        let name = trimmed
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let attribute_region = trimmed.get(name.len()..).unwrap_or("");
        tags.push(Tag {
            name,
            attributes: parse_attributes(attribute_region),
        });
        rest = after.get(close + 1..).unwrap_or("");
    }
    tags
}

/// Attribute name and value pairs inside one tag body.
fn parse_attributes(region: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut characters = region.chars().peekable();
    let mut name = String::new();
    while let Some(value) = characters.next() {
        match value {
            '=' => {
                let mut text = String::new();
                if matches!(characters.peek(), Some('"' | '\'')) {
                    let quote = characters.next().unwrap_or('"');
                    for inner in characters.by_ref() {
                        if inner == quote {
                            break;
                        }
                        text.push(inner);
                    }
                } else {
                    while let Some(inner) = characters.peek() {
                        if inner.is_whitespace() {
                            break;
                        }
                        text.push(*inner);
                        characters.next();
                    }
                }
                if !name.is_empty() {
                    pairs.push((name.to_ascii_lowercase(), text));
                }
                name.clear();
            }
            c if c.is_whitespace() => {
                if !name.is_empty() {
                    pairs.push((name.to_ascii_lowercase(), String::new()));
                }
                name.clear();
            }
            c => name.push(c),
        }
    }
    if !name.is_empty() {
        pairs.push((name.to_ascii_lowercase(), String::new()));
    }
    pairs
}

/// Whether an emitted destination may be navigated to.
/// One left-to-right `HTML` attribute decode, exactly as a browser performs it.
///
/// This must be a SINGLE pass, and that is the whole subtlety. Sequential
/// `replace` calls simulate a *double* decode: they turn `java&amp;#9;script:`
/// into `java` + tab + `script:` and cry wolf, when a browser scans the value
/// once, consumes `&amp;` into a literal `&`, and resumes *after* it — leaving
/// the inert text `java&#9;script:`. Conversely a RAW `&#106;avascript:`, which
/// the renderer would only emit if its escaping were broken, decodes here to
/// `javascript:` and is then caught by the scheme allowlist. Modelling the
/// browser correctly is what makes both verdicts right, so no ad-hoc refusal of
/// `&#` is needed or wanted.
fn decode_attribute_once(value: &str) -> String {
    const NAMED: [(&str, char); 4] = [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
    ];
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    'outer: while !rest.is_empty() {
        if rest.starts_with('&') {
            for (entity, decoded) in NAMED {
                if let Some(tail) = rest.strip_prefix(entity) {
                    out.push(decoded);
                    rest = tail;
                    continue 'outer;
                }
            }
            if let Some((decoded, tail)) = decode_numeric_reference(rest) {
                out.push(decoded);
                rest = tail;
                continue 'outer;
            }
        }
        let mut characters = rest.chars();
        if let Some(value) = characters.next() {
            out.push(value);
        }
        rest = characters.as_str();
    }
    out
}

/// Decodes one `&#NN;` or `&#xHH;` reference, returning it and the remainder.
fn decode_numeric_reference(rest: &str) -> Option<(char, &str)> {
    let body = rest.strip_prefix("&#")?;
    let (hexadecimal, body) = body
        .strip_prefix(['x', 'X'])
        .map_or((false, body), |tail| (true, tail));
    let end = body.find(';')?;
    let digits = body.get(..end)?;
    if digits.is_empty() || digits.len() > 7 {
        return None;
    }
    let radix = if hexadecimal { 16 } else { 10 };
    let code = u32::from_str_radix(digits, radix).ok()?;
    let decoded = char::from_u32(code)?;
    Some((decoded, body.get(end + 1..)?))
}

/// Whether an emitted destination may be navigated to.
fn destination_is_navigable(value: &str) -> bool {
    let decoded = decode_attribute_once(value);
    let trimmed = decoded.trim();
    // Protocol-relative destinations resolve against the PAGE's scheme and land
    // off-origin, so "carries no scheme" does not make them same-document. The
    // URL standard folds a backslash to a forward slash for special schemes, so
    // `/\host`, `\/host` and `\\host` all resolve exactly like `//host`;
    // matching only `//` would admit the three spellings that matter.
    let mut leading = trimmed.chars();
    if matches!(
        (leading.next(), leading.next()),
        (Some('/' | '\\'), Some('/' | '\\'))
    ) {
        return false;
    }
    let Some((scheme, _)) = trimmed.split_once(':') else {
        return true;
    };
    let looks_like_scheme = scheme
        .chars()
        .next()
        .is_some_and(|value| value.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-'));
    if !looks_like_scheme {
        return true;
    }
    NAVIGABLE_SCHEMES
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
}

/// A conservative allowlist check over one rendered surface.
fn assert_no_active_content(case: &str, html: &str) {
    for tag in emitted_tags(case, html) {
        assert!(
            ALLOWED_TAGS.contains(&tag.name.as_str())
                || ALLOWED_TARGET_TAGS.contains(&tag.name.as_str()),
            "{case}: rendered output emitted the tag <{}>",
            tag.name
        );
        for (name, value) in &tag.attributes {
            assert!(
                !name.starts_with("on"),
                "{case}: <{}> carries the event attribute {name:?}",
                tag.name
            );
            assert!(
                ALLOWED_ATTRIBUTES.contains(&name.as_str()) || name == "data-fgit-doc-neutralised",
                "{case}: <{}> carries the attribute {name:?}",
                tag.name
            );
            if name == "href" || name == "src" {
                assert!(
                    destination_is_navigable(value),
                    "{case}: <{}> carries the destination {value:?}",
                    tag.name
                );
            }
        }
    }
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
            let nodes = document.node_count();
            let ceiling = if profile == RenderProfile::ApiJson {
                JSON_BYTES_PER_NODE * nodes + OUTPUT_BYTES_PER_INPUT_BYTE * input + SIZE_SLACK
            } else {
                OUTPUT_BYTES_PER_INPUT_BYTE * input + SIZE_SLACK
            };
            assert!(
                rendered.len() <= ceiling,
                "{name}/{}: {} output bytes from {input} input bytes and {nodes} nodes exceeds the linear ceiling {ceiling}",
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
        if entry
            .path()
            .extension()
            .is_none_or(|extension| !extension.eq_ignore_ascii_case("mdin"))
        {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
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
        "<p><a href=\"&#106;avascript:alert(1)\">x</a></p>",
        "<p><a href=\"//evil.example/x\">x</a></p>",
        "<p><a href=\"/\\evil.example/x\">x</a></p>",
        "<p><a href=\"\\/evil.example/x\">x</a></p>",
        "<p><a href=\"\\\\evil.example/x\">x</a></p>",
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
        RefusalKind::BasisMismatch => trip_basis_mismatch(),
        RefusalKind::BasisIdTooLong => fgit_doc::BasisId::new(&[0_u8; 65])
            .expect_err("tripped")
            .kind(),
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
        RefusalKind::MemoryBudgetBelowOneJob => fgit_doc::worker_count(
            fgit_doc::WorkloadProfile {
                memory_budget_bytes: 63,
                per_job_bytes: 16,
                variance: fgit_doc::VarianceClass::Skewed,
                ..fgit_doc::WorkloadProfile::SERIAL
            },
            RenderProfile::PlainText,
            1,
        )
        .expect_err("tripped")
        .kind(),
        RefusalKind::WorkloadEstimateOverflow => fgit_doc::worker_count(
            fgit_doc::WorkloadProfile {
                per_job_bytes: u64::MAX / 4 + 1,
                variance: fgit_doc::VarianceClass::Skewed,
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

/// An anchor taken on the removed side of a comparison, offered the added
/// side. The text is identical on both sides, so nothing but the basis binding
/// stands between this and a comment reattaching to code it was never about.
fn trip_basis_mismatch() -> RefusalKind {
    let document = parse("alpha\n").expect("parses").into_document();
    let anchor = fgit_doc::Anchor::create(
        &document,
        document.roots()[0],
        fgit_doc::SourceObjectId::new(b"a").expect("identity"),
        AnchorBasis::diff(b"base-1", fgit_doc::DiffSide::Old).expect("basis accepted"),
        Limits::DEFAULT,
    )
    .expect("anchor");
    anchor
        .remap(
            &document,
            &AnchorBasis::diff(b"base-1", fgit_doc::DiffSide::New).expect("basis accepted"),
            Limits::DEFAULT,
        )
        .expect_err("tripped")
        .kind()
}

fn trip_profile_mismatch() -> RefusalKind {
    let document = parse("alpha\n").expect("parses").into_document();
    let anchor = fgit_doc::Anchor::create(
        &document,
        document.roots()[0],
        fgit_doc::SourceObjectId::new(b"a").expect("identity"),
        AnchorBasis::Whole,
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
        .remap(&other, &AnchorBasis::Whole, Limits::DEFAULT)
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
        AnchorBasis::Whole,
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
