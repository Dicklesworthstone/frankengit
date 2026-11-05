#![forbid(unsafe_code)]
//! Single-line flow collections through the real scanner and workflow lowerer.
//! Lexical fixtures follow the selected YAML 1.2.2 section 7 productions; this
//! bounded profile deliberately excludes multiline flow and implicit pairs.

use fgit_schema::workflow::{
    ConstructStatus, Limits, Node, Span, WorkflowRefusal, compile, registry, yaml,
};

fn scanned(source: &str) -> Node {
    yaml::scan(source, &Limits::DEFAULT)
        .unwrap_or_else(|error| panic!("{source:?} should scan: {error}"))
}

fn scalar(node: &Node) -> &str {
    let Node::Scalar { value, .. } = node else {
        panic!("expected a scalar, got {}", node.shape());
    };
    value
}

fn items(node: &Node) -> &[Node] {
    let Node::Sequence { items, .. } = node else {
        panic!("expected a sequence, got {}", node.shape());
    };
    items
}

fn malformed(source: &str) -> WorkflowRefusal {
    let error = yaml::scan(source, &Limits::DEFAULT).expect_err("malformed twin refuses");
    assert!(
        matches!(error, WorkflowRefusal::Malformed { .. }),
        "{source:?}: {error:?}"
    );
    assert!(source.get(error.span().start..error.span().end).is_some());
    error
}

fn limited(source: &str, limits: &Limits, expected: &str, observed: usize) -> WorkflowRefusal {
    let error = yaml::scan(source, limits).expect_err("over-budget twin refuses");
    assert!(
        matches!(&error, WorkflowRefusal::LimitExceeded { limit, observed: actual, .. }
            if *limit == expected && *actual == observed),
        "{source:?}: {error:?}"
    );
    assert!(source.get(error.span().start..error.span().end).is_some());
    error
}

const SIMPLE_BLOCK: &str =
    "name: ci\non: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo ok\n";
const SIMPLE_FLOW: &str =
    r#"{name: ci, on: push, jobs: {build: {runs-on: linux, steps: [{run: echo ok}]}}}"#;

#[test]
fn complete_flow_documents_and_mixed_forms_preserve_existing_graph_bytes() {
    let expected = compile(SIMPLE_BLOCK, &Limits::DEFAULT)
        .unwrap()
        .canonical_bytes();
    assert!(expected.starts_with("fgit-workflow/v1\n"));
    for source in [
        SIMPLE_FLOW,
        r#"{"name":"ci","on":["push"],"jobs":{"build":{"runs-on":"linux","steps":[{"run":"echo ok"}]}}}"#,
        "name: ci\non: [push, push,]\njobs:\n  build: {runs-on: linux, steps: [{run: echo ok},],}\n",
        "name: ci\non:\n  [push]\njobs:\n  build:\n    runs-on: linux\n    needs: []\n    env: {}\n    steps:\n      - {run: echo ok, env: {}}\n",
    ] {
        let actual =
            compile(source, &Limits::DEFAULT).unwrap_or_else(|error| panic!("{source:?}: {error}"));
        assert_eq!(actual.canonical_bytes(), expected, "{source}");
    }
}

const MATRIX_BLOCK: &str = r#"name: matrix-ci
on:
  - push
  - pull_request
env:
  SHARED: workflow
  LITERAL: 'a,b # [x] {y}: z'
jobs:
  lint:
    runs-on: linux
    steps:
      - run: echo lint
  build:
    runs-on: linux
    env:
      SHARED: job
      MODE: '${{ matrix.mode }}'
    strategy:
      fail-fast: false
      matrix:
        mode:
          - debug
          - release
        arch:
          - x86
          - arm
        exclude:
          - mode: debug
            arch: arm
        include:
          - mode: debug
            arch: arm
            note: restored
    steps:
      - name: build
        run: echo build
        env:
          SHARED: step
          ARCH: '${{ matrix.arch }}'
      - run: echo next
  package:
    runs-on: linux
    needs:
      - lint
      - build
    steps:
      - run: echo package
"#;

const MATRIX_FLOW: &str = r#"name: matrix-ci
on: [pull_request, push, push]
env: {SHARED: workflow, LITERAL: 'a,b # [x] {y}: z'}
jobs:
  lint: {runs-on: linux, steps: [{run: echo lint}]}
  build:
    runs-on: linux
    env: {SHARED: job, MODE: '${{ matrix.mode }}'}
    strategy: {fail-fast: false, matrix: {mode: [debug, release], arch: [x86, arm], exclude: [{mode: debug, arch: arm}], include: [{mode: debug, arch: arm, note: restored}],}}
    steps:
      - {name: build, run: echo build, env: {SHARED: step, ARCH: '${{ matrix.arch }}'}}
      - run: echo next
  package: {runs-on: linux, needs: [build, lint], steps: [{run: echo package}]}
"#;

#[test]
fn trigger_needs_environment_and_matrix_flows_lower_into_the_same_complete_graph() {
    let block = compile(MATRIX_BLOCK, &Limits::DEFAULT).unwrap();
    let flow = compile(MATRIX_FLOW, &Limits::DEFAULT).unwrap();
    assert_eq!(flow.canonical_bytes(), block.canonical_bytes());
    assert!(flow.canonical_bytes().starts_with("fgit-workflow/v3\n"));
    assert_eq!(flow.jobs.len(), 6);
    let variants = flow
        .jobs
        .iter()
        .filter(|job| job.matrix.is_some())
        .collect::<Vec<_>>();
    assert_eq!(variants.len(), 4);
    for job in variants {
        let values = job.matrix.as_ref().unwrap().values();
        assert_eq!(job.steps[0].context.environment()["MODE"], values["mode"]);
        assert_eq!(job.steps[0].context.environment()["ARCH"], values["arch"]);
        assert_eq!(job.steps[0].context.environment()["SHARED"], "step");
        assert_eq!(job.steps[1].context.environment()["SHARED"], "job");
        assert_eq!(
            job.steps[0].context.environment()["LITERAL"],
            "a,b # [x] {y}: z"
        );
    }
    let package = flow.jobs.iter().find(|job| job.id == "package").unwrap();
    assert_eq!(package.needs.len(), 5);
    assert!(package.needs.iter().any(|id| id == "lint"));
}

#[test]
fn ordered_branch_path_and_tag_filters_keep_their_graph_and_selection_contracts() {
    let jobs = "jobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo ok\n";
    for (block, flow) in [
        (
            "on:\n  pull_request:\n    branches:\n      - main\n      - 'release/**'\n    paths:\n      - 'src/**'\n      - '!src/private/**'\n      - 'src/private/public.rs'\n",
            "on: {pull_request: {branches: [main, 'release/**'], paths: ['src/**', '!src/private/**', 'src/private/public.rs']}}\n",
        ),
        (
            "on:\n  push:\n    tags:\n      - 'v*'\n      - '!v*-rc'\n      - v2-rc\n",
            "on: {push: {tags: ['v*', '!v*-rc', v2-rc]}}\n",
        ),
        (
            "on:\n  push:\n    branches-ignore:\n      - 'scratch/**'\n    paths-ignore:\n      - 'docs/**'\n",
            "on: {push: {branches-ignore: ['scratch/**'], paths-ignore: ['docs/**']}}\n",
        ),
    ] {
        let left = compile(&format!("name: filters\n{block}{jobs}"), &Limits::DEFAULT).unwrap();
        let right = compile(&format!("name: filters\n{flow}{jobs}"), &Limits::DEFAULT).unwrap();
        assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    }
}

#[test]
fn nested_collections_empty_values_and_scalar_types_are_generic() {
    let source = "a: [one, {b: [two, 'three, # [x]'], empty: {}, list: []}, null, false, 01, '',]\nb:\n  - {c: [four, five]}\n  - d: {e: six}\nc:\n  [seven, {f: eight}]\n";
    let document = scanned(source);
    let a = items(document.get("a").unwrap());
    assert_eq!(scalar(&a[0]), "one");
    assert_eq!(
        items(a[1].get("b").unwrap())
            .iter()
            .map(scalar)
            .collect::<Vec<_>>(),
        ["two", "three, # [x]"]
    );
    assert_eq!(a[1].get("empty").unwrap().node_count(), 1);
    assert!(items(a[1].get("list").unwrap()).is_empty());
    assert_eq!(
        a[2..].iter().map(scalar).collect::<Vec<_>>(),
        ["null", "false", "01", ""]
    );
    assert_eq!(
        scalar(
            items(document.get("b").unwrap())[1]
                .get("d")
                .unwrap()
                .get("e")
                .unwrap()
        ),
        "six"
    );
    assert_eq!(
        scalar(items(document.get("c").unwrap())[1].get("f").unwrap()),
        "eight"
    );
}

#[test]
fn quoted_delimiters_comments_escapes_and_plain_embedded_quotes_are_data() {
    let document = scanned(
        r#"v: ['it''s # [a], {b}: c', "say \"hi\" # [x]", "a\nb\tc\rd\\e\/f", isn't, a"b, https://host:443/path#fragment, a#b, :name, -name, ?name] # ignored [ unmatched "#,
    );
    let values = items(document.get("v").unwrap())
        .iter()
        .map(scalar)
        .collect::<Vec<_>>();
    assert_eq!(
        values,
        [
            "it's # [a], {b}: c",
            "say \"hi\" # [x]",
            "a\nb\tc\rd\\e/f",
            "isn't",
            "a\"b",
            "https://host:443/path#fragment",
            "a#b",
            ":name",
            "-name",
            "?name",
        ]
    );
    let key = scanned(r##""quoted\"#key": [one, two] # ignored"##);
    assert_eq!(items(key.get("quoted\"#key").unwrap()).len(), 2);
    let plain_key = scanned("isn't: [one, two] # ignored\n");
    assert_eq!(items(plain_key.get("isn't").unwrap()).len(), 2);
}

#[test]
fn json_style_adjacent_values_require_quoted_keys_and_explicit_values() {
    let document = scanned(r#"{"a":[1,2], 'b':{c: 3}, "empty":"", "url":"https://host"}"#);
    assert_eq!(
        items(document.get("a").unwrap())
            .iter()
            .map(scalar)
            .collect::<Vec<_>>(),
        ["1", "2"]
    );
    assert_eq!(scalar(document.get("b").unwrap().get("c").unwrap()), "3");
    assert_eq!(scalar(document.get("empty").unwrap()), "");
    for bad in ["{a:[1,2]}", "{a:1}", "{a:\"x\"}", "{a:}", "{\"a\":}", "{a}"] {
        malformed(bad);
    }
}

#[test]
fn malformed_collections_refuse_without_accepting_a_partial_prefix() {
    for (bad, good) in [
        ("[a", "[a]"),
        ("{a: b", "{a: b}"),
        ("[a}", "[a]"),
        ("{a: b]", "{a: b}"),
        ("[a] extra", "[a] # extra"),
        ("[a]#comment", "[a] # comment"),
        ("[a,,b]", "[a,b]"),
        ("[,a]", "[a,]"),
        ("{,}", "{}"),
        ("{a: b,,c: d}", "{a: b,c: d,}"),
        ("[a: b]", "['a: b']"),
        ("[a:]", "['a:']"),
        ("[a:[b]]", "['a:[b]']"),
        ("[a{b]", "['a{b']"),
        ("[a[b]", "['a[b']"),
        ("[a # comment]", "['a # comment']"),
        ("[a\"b # comment]", "[a\"b#comment]"),
        ("['unfinished]", "['finished']"),
        ("[\"unfinished]", "[\"finished\"]"),
        ("['a'junk]", "['ajunk']"),
        ("[\"a\"junk]", "[\"ajunk\"]"),
        ("{[a]: b}", "{'[a]': b}"),
        ("{{a: b}: c}", "{'{a: b}': c}"),
        ("{? a: b}", "{'? a': b}"),
        ("{: a}", "{':': a}"),
        ("[- a]", "['- a']"),
        ("[? a]", "['? a']"),
        ("[|]", "['|']"),
        ("[>]", "['>']"),
        ("[%YAML]", "['%YAML']"),
        ("[@reserved]", "['@reserved']"),
        ("[`reserved]", "['`reserved']"),
        ("[a]\n  ignored: value", "[a] # ignored: value"),
        ("[a]\n[b]", "[[a],[b]]"),
    ] {
        malformed(bad);
        scanned(good);
    }
}

#[test]
fn every_physical_line_ending_requires_collections_to_close_on_that_line() {
    for separator in ["\n", "\r\n", "\r"] {
        for (before, after) in [
            ("v: [a,", "  b]"),
            ("v: {a: b,", "  c: d}"),
            ("v: ['a", "b']"),
        ] {
            let source = format!("{before}{separator}{after}{separator}");
            let error = malformed(&source);
            assert_eq!(error.span().line, 1);
        }
        let source = format!("v: [a, b]{separator}next: {{c: d}}{separator}");
        assert_eq!(scanned(&source).get("next").unwrap().span().line, 2);
    }
}

#[test]
fn forbidden_yaml_features_keep_typed_refusals_inside_nested_flows() {
    for (bad, good, expected) in [
        ("[{a: &name value}]", "[{a: '&name value'}]", "yaml.anchor"),
        ("[{a: *name}]", "[{a: '*name'}]", "yaml.alias"),
        ("[{a: !tag value}]", "[{a: '!tag value'}]", "yaml.tag"),
        ("{&key: value}", "{'&key': value}", "yaml.anchor"),
        ("{*key: value}", "{'*key': value}", "yaml.alias"),
        ("{!key: value}", "{'!key': value}", "yaml.tag"),
        ("{<<: {a: value}}", "{'<<': {a: value}}", "yaml.merge-key"),
        ("<<: [a]", "'<<': [a]", "yaml.merge-key"),
    ] {
        let error = yaml::scan(bad, &Limits::DEFAULT).unwrap_err();
        assert!(
            matches!(error, WorkflowRefusal::ConstructUnsupported { construct, .. } if construct == expected),
            "{error:?}"
        );
        scanned(good);
    }
}

#[test]
fn duplicate_decoded_keys_refuse_in_every_new_mapping_position() {
    for (source, repeated) in [
        ("{a: one, 'a': two}", "'a'"),
        ("v: {a: one, \"a\": two}", "\"a\""),
        ("[{\"a\": one, a: two}]", "a"),
        ("'it''s': [one]\n\"it's\": [two]\n", "\"it's\""),
    ] {
        let error = yaml::scan(source, &Limits::DEFAULT).unwrap_err();
        assert!(
            matches!(error, WorkflowRefusal::DuplicateKey { .. }),
            "{error:?}"
        );
        assert_eq!(&source[error.span().start..error.span().end], repeated);
    }
    assert_eq!(scanned("{a: one, b: two}").node_count(), 3);
}

#[test]
fn flow_spelling_does_not_weaken_the_workflow_schema_or_expression_policy() {
    for source in [
        SIMPLE_FLOW.replace("name: ci", "name: ci, mystery: ignored"),
        SIMPLE_FLOW.replace("runs-on: linux", "runs-on: linux, mystery: ignored"),
        SIMPLE_FLOW.replace("run: echo ok", "run: echo ok, mystery: ignored"),
    ] {
        assert!(matches!(
            compile(&source, &Limits::DEFAULT),
            Err(WorkflowRefusal::FieldUnknown { .. })
        ));
    }
    let uses = SIMPLE_FLOW.replace("run: echo ok", "uses: actions/checkout@v4");
    assert!(matches!(
        compile(&uses, &Limits::DEFAULT),
        Err(WorkflowRefusal::ConstructUnsupported {
            construct: "step.uses",
            ..
        })
    ));
    // Script text stays opaque at schema lowering; WorkflowPlan owns the
    // execution-time expression refusal. Flow must preserve that same boundary.
    let flow_script = SIMPLE_FLOW.replace("run: echo ok", "run: '${{ secrets.TOKEN }}'");
    let block_script = SIMPLE_BLOCK.replace("run: echo ok", "run: '${{ secrets.TOKEN }}'");
    assert_eq!(
        compile(&flow_script, &Limits::DEFAULT)
            .unwrap()
            .canonical_bytes(),
        compile(&block_script, &Limits::DEFAULT)
            .unwrap()
            .canonical_bytes()
    );
    let expressions = SIMPLE_FLOW.replace(
        "run: echo ok",
        "run: echo ok, env: {VALUE: '${{ secrets.TOKEN }}'}",
    );
    assert!(compile(&expressions, &Limits::DEFAULT).is_err());
    assert!(compile(SIMPLE_FLOW, &Limits::DEFAULT).is_ok());
}

#[test]
fn node_budget_is_shared_across_block_flow_and_compact_mapping_boundaries() {
    for (source, count) in [
        ("a: [x,y]\nb: {c: [z]}\n", 7),
        ("a:\n  - b: [x,y]\n  - c: [z]\n", 9),
        ("{a: [x,y], b: {c: [z]}}", 7),
    ] {
        let limits = Limits {
            max_nodes: count,
            ..Limits::DEFAULT
        };
        assert_eq!(yaml::scan(source, &limits).unwrap().node_count(), count);
        limited(
            source,
            &Limits {
                max_nodes: count - 1,
                ..limits
            },
            "nodes",
            count,
        );
    }
    let error = limited(
        "[é]",
        &Limits {
            max_nodes: 1,
            ..Limits::DEFAULT
        },
        "nodes",
        2,
    );
    assert_eq!(error.span(), Span::new(1, 3, 1, 2));
}

#[test]
fn nesting_limits_follow_containers_identically_in_block_and_flow_forms() {
    for source in ["v: [{k: [x]}]", "v:\n  - k:\n      - x\n"] {
        let limits = Limits {
            max_depth: 4,
            ..Limits::DEFAULT
        };
        assert!(yaml::scan(source, &limits).is_ok());
        limited(
            source,
            &Limits {
                max_depth: 3,
                ..limits
            },
            "depth",
            4,
        );
    }
    let source = format!("{}x{}", "[".repeat(10_000), "]".repeat(10_000));
    limited(
        &source,
        &Limits::DEFAULT,
        "depth",
        Limits::DEFAULT.max_depth + 1,
    );
    assert!(
        yaml::scan(
            "[x]",
            &Limits {
                max_depth: 1,
                ..Limits::DEFAULT
            }
        )
        .is_ok()
    );
}

#[test]
fn collection_entry_limits_apply_before_parsing_the_extra_member() {
    let limits = Limits {
        max_entries: 2,
        ..Limits::DEFAULT
    };
    assert!(yaml::scan("[a,b,]", &limits).is_ok());
    assert!(yaml::scan("{a: one,b: two,}", &limits).is_ok());
    limited("[a,b,&not-parsed]", &limits, "sequence items", 3);
    limited(
        "{a: one,b: two,!not-parsed: value}",
        &limits,
        "mapping entries",
        3,
    );
    for empty in ["[]", "{}"] {
        assert!(
            yaml::scan(
                empty,
                &Limits {
                    max_entries: 0,
                    ..limits
                }
            )
            .is_ok()
        );
    }
}

#[test]
fn scalar_limits_measure_raw_utf8_tokens_and_do_not_count_whole_containers() {
    let limits = Limits {
        max_scalar_bytes: 4,
        ..Limits::DEFAULT
    };
    for source in ["[abcd,efgh]", "{abcd: efgh}", "['ab']", "[éé]", "{éé: x}"] {
        assert!(yaml::scan(source, &limits).is_ok(), "{source}");
    }
    for source in ["[abcde]", "{abcde: x}", "['abc']", "[ééx]", "{ééx: x}"] {
        limited(source, &limits, "scalar bytes", 5);
    }
}

#[test]
fn source_byte_and_line_limits_still_run_before_flow_scanning() {
    let source = "[a,b]\n";
    let limits = Limits {
        max_bytes: source.len(),
        max_lines: 1,
        ..Limits::DEFAULT
    };
    assert!(yaml::scan(source, &limits).is_ok());
    limited(
        source,
        &Limits {
            max_bytes: source.len() - 1,
            ..limits
        },
        "bytes",
        source.len(),
    );
    limited(
        source,
        &Limits {
            max_lines: 0,
            ..limits
        },
        "lines",
        1,
    );
    let two = "a: []\nb: {}\n";
    limited(
        two,
        &Limits {
            max_lines: 1,
            ..Limits::DEFAULT
        },
        "lines",
        2,
    );
    assert!(
        yaml::scan(
            two,
            &Limits {
                max_lines: 2,
                ..Limits::DEFAULT
            }
        )
        .is_ok()
    );
}

#[test]
fn flow_controls_unsupported_escapes_and_unicode_separation_refuse_precisely() {
    for bad in [
        "[\"\\q\"]",
        "[\"\\u0041\"]",
        "[\"\\é\"]",
        "[a\0b]",
        "['a\u{7f}b']",
        "[a\u{feff}b]",
        "[a]\u{a0}",
        "v: \u{a0}[a]",
        "- \u{a0}[a]",
    ] {
        malformed(bad);
    }
    for good in [
        "[\"\\n\"]",
        "[\"\\\"\"]",
        "[\"\\\\\"]",
        "[é, 😺]",
        "[a\u{a0}b]",
        "v: \t[a]\t # comment",
    ] {
        scanned(good);
    }
    let error = malformed("[\"\\é\"]");
    assert_eq!(error.span(), Span::new(2, 5, 1, 3));
}

fn check_spans(source: &str, node: &Node, enclosing: Option<Span>) {
    let span = node.span();
    assert!(source.get(span.start..span.end).is_some(), "{span:?}");
    let line_start = source[..span.start].rfind('\n').map_or(0, |at| at + 1);
    assert_eq!(span.column as usize, span.start - line_start + 1);
    assert_eq!(
        span.line as usize,
        source[..span.start]
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            + 1
    );
    if let Some(parent) = enclosing {
        assert!(parent.start <= span.start && span.end <= parent.end);
    }
    match node {
        Node::Scalar { .. } => {}
        Node::Sequence { items, .. } => {
            for item in items {
                check_spans(source, item, Some(span));
            }
        }
        Node::Mapping { entries, .. } => {
            for (_, value, key) in entries {
                assert!(source.get(key.start..key.end).is_some());
                assert!(span.start <= key.start && key.end <= span.end);
                check_spans(source, value, Some(span));
            }
        }
    }
}

#[test]
fn nested_unicode_spans_cover_exact_tokens_and_exclude_trailing_comments() {
    let source = "# lead\n  {é: ['😺', {\"名\": \"value\"}], 'it''s': []} # ignored 🐾\n";
    let document = scanned(source);
    check_spans(source, &document, None);
    assert_eq!(
        &source[document.span().start..document.span().end],
        "{é: ['😺', {\"名\": \"value\"}], 'it''s': []}"
    );
    assert_eq!(document.span().line, 2);
    assert_eq!(document.span().column, 3);
    let key = document.key_span("é").unwrap();
    assert_eq!(&source[key.start..key.end], "é");
    let cat = &items(document.get("é").unwrap())[0];
    assert_eq!(&source[cat.span().start..cat.span().end], "'😺'");
    assert_eq!(scalar(cat), "😺");
    let name = items(document.get("é").unwrap())[1].key_span("名").unwrap();
    assert_eq!(&source[name.start..name.end], "\"名\"");
}

#[test]
fn repeated_parsing_preserves_results_diagnostics_and_registry_status() {
    let source = "a: [é, {b: ['c,d', empty]}] # comment\n";
    let expected = scanned(source);
    let refused = malformed("a: [é, {b: [c,,d]}]");
    for _ in 0..8 {
        assert_eq!(scanned(source), expected);
        assert_eq!(malformed("a: [é, {b: [c,,d]}]"), refused);
        assert_eq!(
            compile(MATRIX_FLOW, &Limits::DEFAULT)
                .unwrap()
                .canonical_bytes(),
            compile(MATRIX_BLOCK, &Limits::DEFAULT)
                .unwrap()
                .canonical_bytes()
        );
    }
    for key in ["yaml.flow-sequence", "yaml.flow-mapping"] {
        let construct = registry::CONSTRUCTS
            .iter()
            .find(|construct| construct.key == key)
            .unwrap();
        assert_eq!(construct.status, ConstructStatus::Normalized);
    }
}
