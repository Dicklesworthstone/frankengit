#![forbid(unsafe_code)]

use fgit_schema::workflow::graph::TAG_CANONICAL_VERSION;
use fgit_schema::workflow::triggers::{
    MAX_PATTERN_BYTES, MAX_PATTERNS, MAX_REFERENCE_BYTES, MAX_TOTAL_PATTERN_BYTES, TagFilter,
    TriggerSelectionError as SelectionError,
};
use fgit_schema::workflow::{Limits, WorkflowGraph, WorkflowRefusal, compile};
use std::cell::Cell;

const JOBS: &str =
    "jobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo build\n";

fn source(on: &str) -> String {
    format!("name: tags\non: {on}\n{JOBS}")
}

fn mapping(event: &str, field: &str, patterns: &[&str]) -> String {
    format!(
        "\n  {event}:\n    {field}:\n{}",
        patterns
            .iter()
            .map(|pattern| format!("      - '{pattern}'\n"))
            .collect::<String>()
    )
}

fn graph(on: &str) -> WorkflowGraph {
    compile(&source(on), &Limits::DEFAULT).unwrap()
}

fn filtered(field: &str, patterns: &[&str]) -> WorkflowGraph {
    graph(&mapping("push", field, patterns))
}

fn selects(graph: &WorkflowGraph, reference: &[u8]) -> bool {
    graph
        .selects_event("push", Some(reference), &|| false)
        .unwrap()
}

#[test]
fn tag_filters_have_a_distinct_literal_graph_form_and_inspectable_contract() {
    assert_eq!(TAG_CANONICAL_VERSION, "fgit-workflow/v7");
    let tags = filtered("tags", &["v*", "!v*-rc", "v2-rc"]);
    assert!(tags.has_tag_filters());
    assert!(!tags.has_branch_filters());
    let filter: &TagFilter = tags.triggers[0].tag_filter.as_ref().unwrap();
    assert_eq!(filter.field(), "tags");
    assert_eq!(
        filter.patterns().collect::<Vec<_>>(),
        ["v*", "!v*-rc", "v2-rc"]
    );
    assert_eq!(
        tags.canonical_bytes(),
        concat!(
            "fgit-workflow/v7\nname\ttags\ntrigger\tpush\n",
            "trigger-tag\tpush\ttags\tv*\n",
            "trigger-tag\tpush\ttags\t!v*-rc\n",
            "trigger-tag\tpush\ttags\tv2-rc\n",
            "job\tbuild\tfgit-trusted-local\nstep\tbuild\t0\t\techo build\n"
        )
    );
    let ignored = filtered("tags-ignore", &["nightly/**"]);
    let filter = ignored.triggers[0].tag_filter.as_ref().unwrap();
    assert_eq!(filter.field(), "tags-ignore");
    assert_eq!(filter.patterns().collect::<Vec<_>>(), ["nightly/**"]);
    assert!(
        ignored
            .canonical_bytes()
            .contains("trigger-tag\tpush\ttags-ignore\tnightly/**\n")
    );
}

#[test]
fn ordered_tag_exclusions_and_reinclusions_select_the_exact_release() {
    let tags = filtered("tags", &["v*", "!v*-rc", "v2-rc"]);
    for (reference, expected) in [
        (b"refs/tags/v1".as_slice(), true),
        (b"refs/tags/v2.4.0", true),
        (b"refs/tags/v1-rc", false),
        (b"refs/tags/v2-rc", true),
        (b"refs/tags/v3-rc", false),
        (b"refs/tags/v1/nested", false),
        (b"refs/tags/release-1", false),
    ] {
        assert_eq!(selects(&tags, reference), expected, "{reference:?}");
    }
    let reordered = filtered("tags", &["v*", "v2-rc", "!v*-rc"]);
    assert!(!selects(&reordered, b"refs/tags/v2-rc"));
    assert_ne!(tags.canonical_bytes(), reordered.canonical_bytes());
}

#[test]
fn tag_and_branch_namespaces_have_independent_positive_and_negative_selection() {
    let tags = filtered("tags", &["main", "v*"]);
    let branches = filtered("branches", &["main", "v*"]);
    for name in ["main", "v1"] {
        let tag = format!("refs/tags/{name}");
        let branch = format!("refs/heads/{name}");
        assert!(selects(&tags, tag.as_bytes()));
        assert!(!selects(&tags, branch.as_bytes()));
        assert!(selects(&branches, branch.as_bytes()));
        assert!(!selects(&branches, tag.as_bytes()));
    }
    let ignored = filtered("tags-ignore", &["nightly/**", "scratch"]);
    assert!(selects(&ignored, b"refs/tags/v1"));
    assert!(!selects(&ignored, b"refs/tags/nightly/latest"));
    assert!(!selects(&ignored, b"refs/tags/scratch"));
    assert!(!selects(&ignored, b"refs/heads/v1"));
    for reference in [
        b"v1".as_slice(),
        b"refs/tags/",
        b"refs/heads/",
        b"refs/remotes/origin/v1",
        b"refs/tags-extra/v1",
    ] {
        assert!(!selects(&tags, reference), "{reference:?}");
        assert!(!selects(&ignored, reference), "{reference:?}");
    }
}

#[test]
fn coexistence_applies_only_the_filter_for_the_authenticated_push_namespace() {
    let on = "\n  push:\n    branches:\n      - main\n    tags:\n      - v*";
    let both = graph(on);
    assert!(both.has_tag_filters() && both.has_branch_filters());
    for (reference, expected) in [
        (b"refs/heads/main".as_slice(), true),
        (b"refs/tags/v1", true),
        (b"refs/heads/v1", false),
        (b"refs/tags/main", false),
        (b"refs/heads/other", false),
        (b"refs/tags/other", false),
    ] {
        assert_eq!(selects(&both, reference), expected, "{reference:?}");
    }
    let ignore = graph(
        "\n  push:\n    branches-ignore:\n      - archive/**\n    tags-ignore:\n      - nightly/**",
    );
    for (reference, expected) in [
        (b"refs/heads/archive/old".as_slice(), false),
        (b"refs/heads/nightly/main", true),
        (b"refs/tags/nightly/latest", false),
        (b"refs/tags/archive/release", true),
    ] {
        assert_eq!(selects(&ignore, reference), expected, "{reference:?}");
    }
    let reordered = graph("\n  push:\n    tags:\n      - v*\n    branches:\n      - main");
    assert_eq!(both.canonical_bytes(), reordered.canonical_bytes());
}

#[test]
fn tag_globs_match_exact_raw_bytes_without_case_or_unicode_normalization() {
    let exact = filtered("tags", &["rélease"]);
    assert!(selects(&exact, "refs/tags/rélease".as_bytes()));
    for reference in ["refs/tags/re\u{301}lease", "refs/tags/Rélease"] {
        assert!(!selects(&exact, reference.as_bytes()));
    }
    let raw = filtered("tags", &["raw/*"]);
    assert!(selects(&raw, b"refs/tags/raw/\xff"));
    assert!(!selects(&raw, b"refs/tags/raw/\xff/nested"));
    let nested = filtered("tags", &["releases/**/stable"]);
    for reference in [
        b"refs/tags/releases/stable".as_slice(),
        b"refs/tags/releases/v1/stable",
        b"refs/tags/releases/raw/\xff/stable",
    ] {
        assert!(selects(&nested, reference), "{reference:?}");
    }
    for reference in [
        b"refs/tags/releases/notstable".as_slice(),
        b"refs/tags/Releases/stable",
        b"refs/tags/releases/stable/extra",
    ] {
        assert!(!selects(&nested, reference), "{reference:?}");
    }
}

#[test]
fn absent_push_coordinates_are_a_refusal_and_other_events_do_not_inherit_tag_filters() {
    for tags in [
        filtered("tags", &["v*"]),
        filtered("tags-ignore", &["nightly/**"]),
        graph("\n  push:\n    branches:\n      - main\n    tags:\n      - v*"),
    ] {
        assert_eq!(
            tags.selects_event("push", None, &|| false),
            Err(SelectionError::MissingPushReference)
        );
        for event in ["pull_request", "workflow_dispatch", "schedule"] {
            assert!(!tags.selects_event(event, None, &|| false).unwrap());
            assert!(
                !tags
                    .selects_event(event, Some(b"refs/tags/v1"), &|| false)
                    .unwrap()
            );
        }
    }
    let mixed = graph(
        "\n  push:\n    tags:\n      - v*\n  pull_request:\n    branches:\n      - main\n  workflow_dispatch: ''",
    );
    assert!(
        mixed
            .selects_event("pull_request", Some(b"refs/heads/main"), &|| false)
            .unwrap()
    );
    assert_eq!(
        mixed.selects_event("pull_request", None, &|| false),
        Err(SelectionError::MissingBranchReference)
    );
    assert!(
        mixed
            .selects_event("workflow_dispatch", None, &|| false)
            .unwrap()
    );
}

#[test]
fn tag_pushes_need_no_branch_diff_but_branch_and_pr_paths_remain_mandatory() {
    let both = graph(
        "\n  push:\n    branches:\n      - main\n    tags:\n      - v*\n    paths:\n      - 'src/**'",
    );
    assert!(selects(&both, b"refs/tags/v1"));
    assert!(!selects(&both, b"refs/tags/other"));
    assert_eq!(
        both.selects_event("push", Some(b"refs/heads/main"), &|| false),
        Err(SelectionError::MissingChangedPaths)
    );
    for (changed, expected) in [
        (Vec::new(), false),
        (vec![b"docs/readme.md".to_vec()], false),
        (vec![b"src/lib.rs".to_vec()], true),
    ] {
        assert_eq!(
            both.selects_event_with_paths(
                "push",
                Some(b"refs/heads/main"),
                Some(&changed),
                &|| false
            ),
            Ok(expected)
        );
        assert_eq!(
            both.selects_event_with_paths("push", Some(b"refs/tags/v1"), Some(&changed), &|| false),
            Ok(true)
        );
    }
    let paths_only = graph("\n  push:\n    paths:\n      - 'src/**'");
    assert!(selects(&paths_only, b"refs/tags/v1"));
    assert_eq!(
        paths_only.selects_event("push", Some(b"refs/heads/main"), &|| false),
        Err(SelectionError::MissingChangedPaths)
    );
    let pr = graph("\n  pull_request:\n    branches:\n      - main\n    paths:\n      - 'src/**'");
    assert_eq!(
        pr.selects_event("pull_request", Some(b"refs/heads/main"), &|| false),
        Err(SelectionError::MissingChangedPaths)
    );
}

#[test]
fn historical_scalar_branch_and_path_graph_bytes_remain_frozen() {
    let scalar = graph("push");
    assert!(!scalar.has_tag_filters());
    assert_eq!(
        scalar.canonical_bytes(),
        "fgit-workflow/v1\nname\ttags\ntrigger\tpush\njob\tbuild\tfgit-trusted-local\nstep\tbuild\t0\t\techo build\n"
    );
    for on in ["\n  push: ''", "\n  - push\n  - push"] {
        assert_eq!(graph(on).canonical_bytes(), scalar.canonical_bytes());
    }
    assert!(scalar.selects_event("push", None, &|| false).unwrap());
    assert!(selects(&scalar, b"refs/heads/main"));
    assert!(selects(&scalar, b"refs/tags/v1"));
    let branch = filtered("branches", &["main"]);
    assert!(!branch.has_tag_filters());
    assert_eq!(
        branch.canonical_bytes(),
        concat!(
            "fgit-workflow/v5\nname\ttags\ntrigger\tpush\n",
            "trigger-branch\tpush\tbranches\tmain\n",
            "job\tbuild\tfgit-trusted-local\nstep\tbuild\t0\t\techo build\n"
        )
    );
    assert_eq!(
        branch.selects_event("push", None, &|| false),
        Err(SelectionError::MissingBranchReference)
    );
    let path = graph("\n  push:\n    branches:\n      - main\n    paths:\n      - 'src/**'");
    assert!(!path.has_tag_filters());
    assert_eq!(
        path.canonical_bytes(),
        concat!(
            "fgit-workflow/v6\nname\ttags\ntrigger\tpush\n",
            "trigger-branch\tpush\tbranches\tmain\n",
            "trigger-path\tpush\tpaths\tsrc/**\n",
            "job\tbuild\tfgit-trusted-local\nstep\tbuild\t0\t\techo build\n"
        )
    );
}

#[test]
fn v7_retains_matrix_context_deadlines_branch_and_path_commitments() {
    let original = source(
        "\n  push:\n    branches:\n      - main\n    paths:\n      - 'src/**'\n    tags:\n      - v*",
    )
    .replace(
        "    steps:\n",
        "    timeout-minutes: 3\n    strategy:\n      fail-fast: false\n      matrix:\n        mode:\n          - debug\n          - release\n    steps:\n",
    ) + "        timeout-minutes: 1\n        env:\n          MODE: '${{ matrix.mode }}'\n        working-directory: src\n";
    let combined = compile(&original, &Limits::DEFAULT).unwrap();
    assert_eq!(combined.jobs.len(), 2);
    let encoded = combined.canonical_bytes();
    assert!(encoded.starts_with("fgit-workflow/v7\n"));
    for record in [
        "trigger-branch\tpush\tbranches\tmain\n",
        "trigger-tag\tpush\ttags\tv*\n",
        "trigger-path\tpush\tpaths\tsrc/**\n",
        "matrix-origin\tbuild__matrix_000\tbuild\n",
        "matrix-value\tbuild__matrix_001\tmode\trelease\n",
        "job-timeout-minutes\tbuild__matrix_000\t3\n",
        "step-timeout-minutes\tbuild__matrix_001\t0\t1\n",
        "step-env\tbuild__matrix_000\t0\tMODE\tdebug\n",
        "step-cwd\tbuild__matrix_001\t0\tsrc\n",
    ] {
        assert!(encoded.contains(record), "missing {record}: {encoded}");
    }
    for changed in [
        original.replace("      - v*", "      - release/*"),
        original.replace("    tags:", "    tags-ignore:"),
        original.replace("      - main", "      - stable"),
        original.replace("'src/**'", "'lib/**'"),
        original.replace("timeout-minutes: 3", "timeout-minutes: 2"),
        original.replace("working-directory: src", "working-directory: lib"),
    ] {
        assert_ne!(
            encoded,
            compile(&changed, &Limits::DEFAULT)
                .unwrap()
                .canonical_bytes()
        );
    }
    let no_tags = original.replace("    tags:\n      - v*\n", "");
    assert!(
        compile(&no_tags, &Limits::DEFAULT)
            .unwrap()
            .canonical_bytes()
            .starts_with("fgit-workflow/v6\n")
    );
}

#[test]
fn invalid_tag_patterns_are_refused_with_spans_and_valid_near_twins() {
    for pattern in [
        "",
        "!",
        "!v1",
        "v?",
        "v[12]",
        "v+",
        "v***",
        "v!1",
        "v\\*",
        "v 1",
        "${{ inputs.version }}",
    ] {
        let invalid = source(&mapping("push", "tags", &[pattern]));
        let failure = compile(&invalid, &Limits::DEFAULT).unwrap_err();
        assert!(!failure.span().is_empty(), "{pattern}: {failure:?}");
        assert!(selects(&filtered("tags", &["v*"]), b"refs/tags/v1"));
    }
    let excluded = source(&mapping("push", "tags-ignore", &["!v1"]));
    assert!(compile(&excluded, &Limits::DEFAULT).is_err());
    assert!(!selects(&filtered("tags-ignore", &["v1"]), b"refs/tags/v1"));
    assert!(selects(&filtered("tags-ignore", &["v1"]), b"refs/tags/v2"));
}

#[test]
fn wrong_events_shapes_duplicates_and_conflicting_tag_modes_refuse() {
    for event in ["pull_request", "workflow_dispatch", "schedule"] {
        for field in ["tags", "tags-ignore"] {
            let failure =
                compile(&source(&mapping(event, field, &["v*"])), &Limits::DEFAULT).unwrap_err();
            assert!(!failure.span().is_empty(), "{event} {field}: {failure:?}");
        }
    }
    for on in [
        "\n  push:\n    tags: v1",
        "\n  push:\n    tags: ''",
        "\n  push:\n    tags:\n      nested: v1",
        "\n  push:\n    tags:\n      - name: v1",
        "\n  push:\n    tags:\n      - v1\n    tags:\n      - v2",
        "\n  push:\n    tags-ignore:\n      - v1\n    tags-ignore:\n      - v2",
        "\n  push:\n    tags:\n      - v*\n    tags-ignore:\n      - nightly/**",
        "\n  push:\n    tags-ignore:\n      - nightly/**\n    tags:\n      - v*",
        "\n  push:\n    tag:\n      - v1",
        "\n  push:\n    tag-ignore:\n      - v1",
    ] {
        let failure = compile(&source(on), &Limits::DEFAULT).unwrap_err();
        assert!(!failure.span().is_empty(), "{on}: {failure:?}");
    }
    let valid = graph(
        "\n  push:\n    branches-ignore:\n      - archived/**\n    tags-ignore:\n      - nightly/**",
    );
    assert!(selects(&valid, b"refs/heads/main"));
    assert!(selects(&valid, b"refs/tags/v1"));
}

#[test]
fn tag_pattern_count_and_byte_limits_have_exact_permitted_twins() {
    for field in ["tags", "tags-ignore"] {
        for (count, accepted) in [(MAX_PATTERNS, true), (MAX_PATTERNS + 1, false)] {
            let patterns = vec!["v1"; count];
            assert_eq!(
                compile(
                    &source(&mapping("push", field, &patterns)),
                    &Limits::DEFAULT
                )
                .is_ok(),
                accepted,
                "{field}, {count} patterns"
            );
        }
        for (length, accepted) in [(MAX_PATTERN_BYTES, true), (MAX_PATTERN_BYTES + 1, false)] {
            let pattern = "a".repeat(length);
            assert_eq!(
                compile(
                    &source(&mapping("push", field, &[&pattern])),
                    &Limits::DEFAULT
                )
                .is_ok(),
                accepted,
                "{field}, {length} pattern bytes"
            );
        }
        let pattern = "a".repeat(MAX_PATTERN_BYTES);
        let exact = vec![pattern.as_str(); MAX_TOTAL_PATTERN_BYTES / MAX_PATTERN_BYTES];
        assert!(compile(&source(&mapping("push", field, &exact)), &Limits::DEFAULT).is_ok());
        let mut over = exact;
        over.push("b");
        assert!(matches!(
            compile(&source(&mapping("push", field, &over)), &Limits::DEFAULT),
            Err(WorkflowRefusal::LimitExceeded { .. })
        ));
    }
    let exact_unicode = "é".repeat(MAX_PATTERN_BYTES / 2);
    let over_unicode = format!("{exact_unicode}a");
    assert!(
        compile(
            &source(&mapping("push", "tags", &[&exact_unicode])),
            &Limits::DEFAULT
        )
        .is_ok()
    );
    assert!(
        compile(
            &source(&mapping("push", "tags", &[&over_unicode])),
            &Limits::DEFAULT
        )
        .is_err()
    );
}

#[test]
fn tag_reference_byte_limit_is_checked_before_matching_or_exclusion() {
    let mut reference = b"refs/tags/".to_vec();
    reference.resize(MAX_REFERENCE_BYTES, b'a');
    for tags in [
        filtered("tags", &["**"]),
        filtered("tags-ignore", &["never"]),
    ] {
        assert!(selects(&tags, &reference));
        let mut oversized = reference.clone();
        oversized.push(b'a');
        assert_eq!(
            tags.selects_event("push", Some(&oversized), &|| false),
            Err(SelectionError::ReferenceTooLong)
        );
    }
}

#[test]
fn cancellation_interrupts_tag_matching_and_never_turns_into_nonselection() {
    let pattern = "*a".repeat(120);
    let tags = filtered("tags", &[&pattern]);
    let reference = [b"refs/tags/".as_slice(), &vec![b'a'; 1000]].concat();
    for stop in [1, 2, 20, 120] {
        let calls = Cell::new(0);
        assert_eq!(
            tags.selects_event("push", Some(&reference), &|| {
                calls.set(calls.get() + 1);
                calls.get() >= stop
            }),
            Err(SelectionError::Cancelled)
        );
        assert_eq!(calls.get(), stop);
    }
    assert!(selects(&tags, &reference));
    let with_paths = graph("\n  push:\n    tags:\n      - v*\n    paths:\n      - 'src/**'");
    assert_eq!(
        with_paths.selects_event("push", Some(b"refs/tags/v1"), &|| true),
        Err(SelectionError::Cancelled)
    );
}
