//! Render profiles: safety, structure, and pinnable output.

mod common;

use common::{corpus, parse_case, render_all};
use fgit_doc::{Limits, RefusalKind, RenderProfile, parse, render};

fn html_of(source: &str) -> String {
    let document = parse(source)
        .unwrap_or_else(|refusal| panic!("source refused: {refusal}"))
        .into_document();
    render(&document, RenderProfile::HtmlSafe, Limits::DEFAULT)
        .expect("html render succeeds")
        .into_string()
}

fn plain_of(source: &str) -> String {
    let document = parse(source)
        .unwrap_or_else(|refusal| panic!("source refused: {refusal}"))
        .into_document();
    render(&document, RenderProfile::PlainText, Limits::DEFAULT)
        .expect("plain render succeeds")
        .into_string()
}

#[test]
fn every_profile_renders_every_corpus_document() {
    for case in corpus() {
        let document = parse_case(&case);
        let outputs = render_all(case.name, &document);
        assert_eq!(outputs.len(), 4, "{}: four profiles", case.name);
    }
}

#[test]
fn no_profile_ever_emits_a_markup_tag_from_source_text() {
    // Every angle bracket in the output must come from the renderer, so a
    // document whose only angle brackets are in its text may not produce one.
    let hostile = concat!(
        "<script>alert(1)</script>\n",
        "\n",
        "text with <img onerror=x> inside\n",
        "\n",
        "`<b>in code</b>`\n",
    );
    let document = parse(hostile)
        .expect("hostile source parses")
        .into_document();
    let html = render(&document, RenderProfile::HtmlSafe, Limits::DEFAULT)
        .expect("html render succeeds")
        .into_string();
    assert!(
        !html.contains("<script"),
        "a script tag reached the output: {html}"
    );
    assert!(
        !html.contains("<img"),
        "an image tag reached the output: {html}"
    );
    assert!(
        !html.contains("onerror=x>"),
        "an attribute survived: {html}"
    );
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "the raw markup must appear escaped: {html}"
    );
    assert!(
        html.contains("data-fgit-doc-rejected=\"raw_markup\""),
        "neutralisation must be visible: {html}"
    );
}

#[test]
fn a_rejected_destination_is_inert_and_a_permitted_one_navigates() {
    let rejected = html_of("[click](javascript:alert(1))\n");
    assert!(
        !rejected.contains("href"),
        "a rejected destination must not become a target: {rejected}"
    );
    assert!(
        rejected.contains("data-fgit-doc-rejected=\"disallowed_scheme\""),
        "the rejection reason must be visible: {rejected}"
    );
    assert!(rejected.contains("click"), "the text is still shown");

    let permitted = html_of("[click](https://example.com/a)\n");
    assert_eq!(
        permitted,
        "<p><a href=\"https://example.com/a\" rel=\"nofollow noopener noreferrer\">click</a></p>\n"
    );

    let relative = html_of("[click](/relative/path)\n");
    assert!(
        relative.contains("href=\"/relative/path\""),
        "a relative reference is permitted: {relative}"
    );
}

#[test]
fn an_attribute_cannot_be_broken_out_of() {
    let html = html_of("[x](https://example.com/\"onmouseover=\"alert&#40;1&#41;)\n");
    assert!(
        !html.contains("onmouseover=\"alert"),
        "quotes in a destination must stay escaped: {html}"
    );
    assert!(html.contains("&quot;"), "the quote is escaped: {html}");
}

#[test]
fn html_output_is_pinnable_for_the_core_constructs() {
    assert_eq!(html_of("# Title\n"), "<h1>Title</h1>\n");
    assert_eq!(html_of("plain\n"), "<p>plain</p>\n");
    assert_eq!(html_of("a *b* c\n"), "<p>a <em>b</em> c</p>\n");
    assert_eq!(html_of("a **b** c\n"), "<p>a <strong>b</strong> c</p>\n");
    assert_eq!(html_of("---\n"), "<hr />\n");
    assert_eq!(
        html_of("> quoted\n"),
        "<blockquote>\n<p>quoted</p>\n</blockquote>\n"
    );
    assert_eq!(
        html_of("- a\n- b\n"),
        "<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n"
    );
    assert_eq!(
        html_of("2. a\n3. b\n"),
        "<ol start=\"2\">\n<li>a</li>\n<li>b</li>\n</ol>\n"
    );
    assert_eq!(
        html_of("```rust\nfn f() {}\n```\n"),
        "<pre><code class=\"language-rust\">fn f() {}\n</code></pre>\n"
    );
    assert_eq!(html_of("a `b` c\n"), "<p>a <code>b</code> c</p>\n");
    assert_eq!(html_of("a &amp; b\n"), "<p>a &amp;amp; b</p>\n");
}

#[test]
fn plain_text_output_is_pinnable_for_the_core_constructs() {
    assert_eq!(plain_of("# Title\n"), "# Title\n");
    assert_eq!(plain_of("a *b* c\n"), "a b c\n");
    assert_eq!(plain_of("- a\n- b\n"), "- a\n- b\n");
    assert_eq!(plain_of("> quoted\n"), "> quoted\n");
    assert_eq!(plain_of("[text](https://example.com)\n"), "text\n");
    assert_eq!(plain_of("<https://example.com>\n"), "https://example.com\n");
}

#[test]
fn the_compact_profile_emits_one_line_per_node_with_escaped_fields() {
    let document = parse("# Title\n\nfirst\nsecond\n\n> quoted\n")
        .expect("source parses")
        .into_document();
    let compact = render(&document, RenderProfile::CompactMachine, Limits::DEFAULT)
        .expect("compact render succeeds")
        .into_string();
    assert_eq!(compact, "h1 Title\np first second\nquote\n  p quoted\n");

    let with_newline = parse("```\na\nb\n```\n")
        .expect("source parses")
        .into_document();
    let fenced = render(
        &with_newline,
        RenderProfile::CompactMachine,
        Limits::DEFAULT,
    )
    .expect("compact render succeeds")
    .into_string();
    for line in fenced.lines() {
        assert!(
            !line.trim().is_empty(),
            "the compact profile must not emit blank lines: {fenced:?}"
        );
    }
    assert!(fenced.starts_with("code fenced=true info=\n"));
}

#[test]
fn the_json_profile_is_well_formed_and_escapes_hostile_text() {
    let document = parse("a \"quoted\" \\ backslash\n\ntab\there\n")
        .expect("source parses")
        .into_document();
    let json = render(&document, RenderProfile::ApiJson, Limits::DEFAULT)
        .expect("json render succeeds")
        .into_string();
    assert!(json.starts_with("{\"profile\":{\"family\":\"commonmark-safe\""));
    assert!(json.ends_with("]}"));
    assert!(
        json.contains("\\\"quoted\\\""),
        "quotes are escaped: {json}"
    );
    assert!(json.contains("\\\\"), "backslashes are escaped: {json}");
    assert!(
        !json.contains('\t'),
        "a raw tab must never appear inside a json string: {json}"
    );
    assert!(json.contains("\\t"), "tabs are escaped: {json}");
    let node_entries = json.matches("{\"id\":").count();
    assert_eq!(
        node_entries,
        document.node_count(),
        "every node appears exactly once"
    );
}

#[test]
fn the_json_profile_records_every_span_and_the_link_verdict() {
    let document = parse("[a](javascript:x)\n")
        .expect("source parses")
        .into_document();
    let json = render(&document, RenderProfile::ApiJson, Limits::DEFAULT)
        .expect("json render succeeds")
        .into_string();
    assert!(json.contains("\"verdict\":\"disallowed_scheme\""), "{json}");
    assert!(json.contains("\"byte_start\":"), "{json}");
    assert!(json.contains("\"char_start\":"), "{json}");
}

#[test]
fn an_output_ceiling_refuses_and_a_sufficient_one_proceeds() {
    let document = parse("a paragraph long enough to exceed a tiny ceiling\n")
        .expect("source parses")
        .into_document();
    let mut tight = Limits::DEFAULT;
    tight.max_output_bytes = 8;
    let refusal =
        render(&document, RenderProfile::HtmlSafe, tight).expect_err("a tiny ceiling is refused");
    assert_eq!(refusal.kind(), RefusalKind::OutputTooLarge);
    assert_eq!(refusal.limit(), 8);

    let mut generous = Limits::DEFAULT;
    generous.max_output_bytes = 4096;
    render(&document, RenderProfile::HtmlSafe, generous).expect("a sufficient ceiling proceeds");
}

#[test]
fn diagnostics_report_neutralisation_in_source_order() {
    let parsed = parse("<div>\nraw\n</div>\n\n[a](javascript:x)\n").expect("source parses");
    let codes = parsed
        .diagnostics()
        .iter()
        .map(|entry| entry.code.tag())
        .collect::<Vec<_>>();
    assert!(codes.contains(&"raw_markup_neutralised"), "{codes:?}");
    assert!(codes.contains(&"rejected_destination"), "{codes:?}");
    let mut previous = 0;
    for entry in parsed.diagnostics() {
        assert!(
            entry.span.byte_start() >= previous,
            "diagnostics must be in source order"
        );
        previous = entry.span.byte_start();
    }
}

#[test]
fn an_unterminated_fence_is_reported_and_still_parses() {
    let parsed = parse("```\nnever closed\n").expect("an unterminated fence still parses");
    assert!(
        parsed
            .diagnostics()
            .iter()
            .any(|entry| entry.code.tag() == "unterminated_code_fence"),
        "the unterminated fence must be reported"
    );
    let html = render(parsed.document(), RenderProfile::HtmlSafe, Limits::DEFAULT)
        .expect("html render succeeds")
        .into_string();
    assert_eq!(html, "<pre><code>never closed\n</code></pre>\n");
}

#[test]
fn a_reference_definition_is_reported_rather_than_silently_resolved() {
    let parsed = parse("[label]: https://example.com\n").expect("source parses");
    assert!(
        parsed
            .diagnostics()
            .iter()
            .any(|entry| entry.code.tag() == "unresolved_reference"),
        "an unresolved reference must be visible"
    );
}

#[test]
fn a_blank_line_between_items_makes_the_list_loose() {
    let document = parse("- a\n- b\n")
        .expect("tight list parses")
        .into_document();
    let tight = render(&document, RenderProfile::CompactMachine, Limits::DEFAULT)
        .expect("compact render succeeds")
        .into_string();
    assert!(
        tight.starts_with("list ordered=false start=1 tight=true\n"),
        "{tight}"
    );
    assert_eq!(
        html_of("- a\n- b\n"),
        "<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n"
    );

    let separated = parse("- a\n\n- b\n")
        .expect("loose list parses")
        .into_document();
    let loose = render(&separated, RenderProfile::CompactMachine, Limits::DEFAULT)
        .expect("compact render succeeds")
        .into_string();
    assert!(
        loose.starts_with("list ordered=false start=1 tight=false\n"),
        "a blank line between items makes the list loose: {loose}"
    );
    assert_eq!(
        html_of("- a\n\n- b\n"),
        "<ul>\n<li>\n<p>a</p>\n</li>\n<li>\n<p>b</p>\n</li>\n</ul>\n"
    );
}

#[test]
fn nested_containers_render_with_stable_prefixes() {
    assert_eq!(plain_of("> > deep\n"), "> > deep\n");
    assert_eq!(
        plain_of("- outer\n  - inner\n"),
        "- outer\n  - inner\n",
        "a nested list indents by the marker width"
    );
    assert_eq!(
        html_of("> - a\n> - b\n"),
        "<blockquote>\n<ul>\n<li>a</li>\n<li>b</li>\n</ul>\n</blockquote>\n"
    );
}
