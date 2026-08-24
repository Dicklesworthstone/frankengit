//! Every input byte is accounted for: the acceptance's no-silent-drop clause.
//!
//! The bead requires that *"every input byte maps to a node/source span or
//! explicit ignored-by-version/refusal record; no silent drop"*. That is a
//! property of the scanner, not a slogan, so this file operationalises it:
//!
//! **every significant source line must be covered by at least one node span.**
//!
//! A line the scanner silently ignored would have no node pointing at it, and
//! this test would name the line. Comments and blank lines are the only
//! deliberate exclusions, and `yaml.comment` carries that exclusion as a
//! registry row rather than as an unstated assumption.
//!
//! # Why this file exists at all
//!
//! `workflow/mod.rs` claimed this test existed before it did. That is exactly
//! the defect shape this crate refuses elsewhere — a comment asserting a fact
//! that is not true tells the next reader not to check. Caught by re-reading my
//! own commit rather than by anything failing.

use fgit_schema::workflow::{Limits, Node, Span, compile, yaml};

/// Collects every span in the tree, including mapping key spans.
fn spans(node: &Node, out: &mut Vec<Span>) {
    out.push(node.span());
    match node {
        Node::Scalar { .. } => {}
        Node::Mapping { entries, .. } => {
            for (_, value, key_span) in entries {
                out.push(*key_span);
                spans(value, out);
            }
        }
        Node::Sequence { items, .. } => {
            for item in items {
                spans(item, out);
            }
        }
    }
}

/// Line numbers that carry content the scanner must account for.
///
/// A blank line and a comment-only line are the two deliberate exclusions.
fn significant_lines(source: &str) -> Vec<u32> {
    source
        .split('\n')
        .enumerate()
        .filter_map(|(index, raw)| {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                u32::try_from(index + 1).ok()
            }
        })
        .collect()
}

/// Lines with content that no span covers.
fn uncovered(source: &str, all: &[Span]) -> Vec<u32> {
    significant_lines(source)
        .into_iter()
        .filter(|line| !all.iter().any(|span| span.line == *line))
        .collect()
}

const FIXTURE: &str = "\
# a leading comment, deliberately excluded
name: ci
on:
  - push
  - pull_request

jobs:
  build:
    runs-on: linux
    steps:
      - name: compile
        run: cargo check   # a trailing comment
      - run: cargo test
  lint:
    runs-on: linux
    needs: build
    steps:
      - run: cargo clippy
";

#[test]
fn every_significant_line_is_covered_by_a_node_span() {
    let document = yaml::scan(FIXTURE, &Limits::DEFAULT).expect("the fixture scans");
    let mut all = Vec::new();
    spans(&document, &mut all);

    let missing = uncovered(FIXTURE, &all);
    assert!(
        missing.is_empty(),
        "these lines carry content that no node span covers, which is a silent drop: {missing:?}"
    );
}

#[test]
fn the_coverage_check_can_actually_fail() {
    // PRESENCE CASE. The test above passes; that alone does not show it could
    // notice a dropped line. Withhold the spans from one line and require the
    // checker to name exactly that line.
    let document = yaml::scan(FIXTURE, &Limits::DEFAULT).expect("scans");
    let mut all = Vec::new();
    spans(&document, &mut all);

    // Line 3 is `on:` in the fixture. Remove every span on it.
    let victim = 3_u32;
    assert!(
        all.iter().any(|span| span.line == victim),
        "the fixture must actually have a node on the withheld line"
    );
    let thinned: Vec<Span> = all
        .iter()
        .copied()
        .filter(|span| span.line != victim)
        .collect();

    assert_eq!(
        uncovered(FIXTURE, &thinned),
        vec![victim],
        "the coverage check must name the uncovered line, not merely fail"
    );
}

#[test]
fn every_span_lies_inside_the_source_and_is_well_formed() {
    let document = yaml::scan(FIXTURE, &Limits::DEFAULT).expect("scans");
    let mut all = Vec::new();
    spans(&document, &mut all);
    assert_ne!(all.len(), 0, "the fixture must produce spans to check");

    for span in &all {
        assert!(
            span.start <= span.end,
            "a span must not run backwards: {span:?}"
        );
        assert!(
            span.end <= FIXTURE.len(),
            "a span must not point past the source: {span:?}"
        );
        assert!(span.line >= 1, "lines are 1-based: {span:?}");
        assert!(span.column >= 1, "columns are 1-based: {span:?}");
        // The byte offsets and the line number must agree, or a span is
        // self-inconsistent and an editor would jump to the wrong place.
        let computed = FIXTURE[..span.start].matches('\n').count() + 1;
        assert_eq!(
            u32::try_from(computed).expect("small"),
            span.line,
            "span byte offset and line disagree: {span:?}"
        );
    }
}

#[test]
fn a_scalar_span_selects_the_text_it_reports() {
    // A span that covers the wrong bytes is worse than no span: it sends a
    // reader to a location that looks authoritative and is not.
    let document = yaml::scan(FIXTURE, &Limits::DEFAULT).expect("scans");
    let name = document.get("name").expect("name is present");
    let Node::Scalar { value, span } = name else {
        panic!("name is a scalar");
    };
    assert_eq!(&FIXTURE[span.start..span.end], value);
    assert_eq!(value, "ci");

    // A trailing comment is excluded from the span, so the span selects the
    // value rather than the value plus the comment.
    let jobs = document.get("jobs").expect("jobs");
    let build = jobs.get("build").expect("build");
    let steps = build.get("steps").expect("steps");
    let Node::Sequence { items, .. } = steps else {
        panic!("steps is a sequence");
    };
    let run = items[0].get("run").expect("run");
    let Node::Scalar { value, span } = run else {
        panic!("run is a scalar");
    };
    assert_eq!(
        value, "cargo check",
        "the trailing comment is not part of the value"
    );
    assert_eq!(&FIXTURE[span.start..span.end], "cargo check");
}

#[test]
fn a_refusal_span_points_at_the_offending_construct() {
    // The refusal's own location is part of the no-silent-drop guarantee: a
    // byte that is refused must be identified, not merely rejected.
    let source =
        "name: ci\non: push\njobs:\n  a:\n    runs-on: linux\n    steps:\n      - uses: x\n";
    let refusal = compile(source, &Limits::DEFAULT).expect_err("uses is refused");
    let span = refusal.span();
    assert_eq!(
        span.line, 7,
        "the refusal names the line the construct is on"
    );
    assert_eq!(
        &source[span.start..span.end],
        "uses",
        "and the byte range selects the construct itself"
    );
}
