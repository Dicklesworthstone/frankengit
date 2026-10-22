#![forbid(unsafe_code)]
use fgit_schema::workflow::triggers::TriggerSelectionError;
use fgit_schema::workflow::{Limits, WorkflowGraph, WorkflowRefusal, compile};
use std::cell::Cell;
const JOBS: &str =
    "jobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo build\n";
fn source(on: &str) -> String {
    format!("name: branches\non: {on}\n{JOBS}")
}
fn filtered(event: &str, kind: &str, patterns: &[&str]) -> WorkflowGraph {
    compile(&source(&mapping(event, kind, patterns)), &Limits::DEFAULT).unwrap()
}
fn mapping(event: &str, kind: &str, patterns: &[&str]) -> String {
    format!(
        "\n  {event}:\n    {kind}:\n{}",
        patterns
            .iter()
            .map(|p| format!("      - '{p}'\n"))
            .collect::<String>()
    )
}
fn matches(graph: &WorkflowGraph, event: &str, branch: &[u8]) -> bool {
    graph
        .selects_event(
            event,
            Some(&[b"refs/heads/".as_slice(), branch].concat()),
            &|| false,
        )
        .unwrap()
}
#[test]
fn historical_graphs_and_empty_event_mappings_keep_original_bytes() {
    let scalar = compile(&source("push"), &Limits::DEFAULT).unwrap();
    assert_eq!(
        scalar.canonical_bytes(),
        "fgit-workflow/v1\nname\tbranches\ntrigger\tpush\njob\tbuild\tfgit-trusted-local\nstep\tbuild\t0\t\techo build\n"
    );
    for spelling in ["\n  - push\n  - push", "\n  push: ''"] {
        assert_eq!(
            scalar.canonical_bytes(),
            compile(&source(spelling), &Limits::DEFAULT)
                .unwrap()
                .canonical_bytes()
        );
    }
    assert!(scalar.selects_event("push", None, &|| false).unwrap());
    assert!(
        !scalar
            .selects_event("pull_request", None, &|| false)
            .unwrap()
    );
}
#[test]
fn mapping_order_normalizes_but_pattern_order_is_committed() {
    let a = mapping(
        "push",
        "branches",
        &["releases/**", "!releases/**-alpha", "releases/safe-alpha"],
    );
    let b = mapping("pull_request", "branches-ignore", &["archive/**"]);
    let x = compile(&source(&(a.clone() + &b)), &Limits::DEFAULT).unwrap();
    let y = compile(&source(&(b + &a)), &Limits::DEFAULT).unwrap();
    assert_eq!(x.canonical_bytes(), y.canonical_bytes());
    assert!(x.canonical_bytes().starts_with("fgit-workflow/v5\n"));
    assert!(matches(&x, "push", b"releases/2026"));
    assert!(!matches(&x, "push", b"releases/next-alpha"));
    assert!(matches(&x, "push", b"releases/safe-alpha"));
    let reordered = filtered(
        "push",
        "branches",
        &["releases/**", "releases/safe-alpha", "!releases/**-alpha"],
    );
    assert!(!matches(&reordered, "push", b"releases/safe-alpha"));
    assert_ne!(reordered.canonical_bytes(), x.canonical_bytes());
}
#[test]
fn wildcard_scope_and_zero_directory_globstars_are_exact() {
    for (pattern, yes, no) in [
        (
            "feature/*",
            vec!["feature/a"],
            vec!["feature/a/b", "feature"],
        ),
        (
            "feature/**",
            vec!["feature/a", "feature/a/b"],
            vec!["features/a"],
        ),
        (
            "**/main",
            vec!["main", "release/main", "release/next/main"],
            vec!["notmain", "xmain"],
        ),
        (
            "release/**/main",
            vec!["release/main", "release/v1/main"],
            vec!["release/notmain", "releases/main"],
        ),
        ("a**z", vec!["az", "a/x/z"], vec!["a/x/y", "ab"]),
    ] {
        let graph = filtered("push", "branches", &[pattern]);
        for branch in yes {
            assert!(
                matches(&graph, "push", branch.as_bytes()),
                "{pattern} {branch}"
            );
        }
        for branch in no {
            assert!(
                !matches(&graph, "push", branch.as_bytes()),
                "{pattern} {branch}"
            );
        }
    }
}
#[test]
fn exclusion_only_filters_and_event_names_do_not_fall_back() {
    let graph = filtered("push", "branches-ignore", &["archive/**", "main"]);
    assert!(!matches(&graph, "push", b"archive/v1"));
    assert!(!matches(&graph, "push", b"main"));
    assert!(matches(&graph, "push", b"topic"));
    assert!(!matches(&graph, "pull_request", b"topic"));
}
#[test]
fn filters_use_exact_bytes_not_lossy_names_or_tags() {
    let exact = filtered("push", "branches", &["rélease"]);
    assert!(matches(&exact, "push", "rélease".as_bytes()));
    assert!(!matches(&exact, "push", "re\u{301}lease".as_bytes()));
    assert!(!matches(&exact, "push", "Rélease".as_bytes()));
    let all = filtered("push", "branches", &["**"]);
    assert!(matches(&all, "push", b"raw/\xff"));
    for reference in [b"refs/tags/main".as_slice(), b"main", b"refs/heads/"] {
        assert!(
            !all.selects_event("push", Some(reference), &|| false)
                .unwrap()
        );
    }
}
#[test]
fn missing_target_is_an_error_not_a_suppressed_or_started_pr() {
    let graph = filtered("pull_request", "branches", &["main"]);
    assert_eq!(
        graph.selects_event("pull_request", None, &|| false),
        Err(TriggerSelectionError::MissingBranchReference)
    );
    assert!(!graph.selects_event("push", None, &|| false).unwrap());
    assert!(matches(&graph, "pull_request", b"main"));
    assert!(!matches(&graph, "pull_request", b"topic"));
}
#[test]
fn rejected_pattern_operators_have_permitted_twins_and_source_spans() {
    for p in [
        "",
        "!",
        "!main",
        "main?",
        "[ab]",
        "main+",
        "a***b",
        "a!b",
        "a\\*",
        "a b",
        "${{ value }}",
    ] {
        let result = compile(
            &source(&mapping("push", "branches", &[p])),
            &Limits::DEFAULT,
        );
        assert!(result.is_err(), "{p}");
        assert!(!result.unwrap_err().span().is_empty());
        assert!(matches(
            &filtered("push", "branches", &["main"]),
            "push",
            b"main"
        ));
    }
    assert!(
        compile(
            &source(&mapping("push", "branches-ignore", &["!main"])),
            &Limits::DEFAULT
        )
        .is_err()
    );
}
#[test]
fn unknown_filter_fields_and_shapes_never_disappear() {
    for on in [
        "\n  push:\n    tags:\n      - release/**",
        "\n  pull_request:\n    types:\n      - opened",
        "\n  workflow_dispatch:\n    branches:\n      - main",
        "\n  schedule: ''",
        "\n  push:\n    branches: main",
        "\n  push:\n    branches:\n      - main\n    branches-ignore:\n      - old",
        "\n  push: null",
    ] {
        assert!(compile(&source(on), &Limits::DEFAULT).is_err(), "{on}");
    }
    let valid = compile(
        &source("\n  push: ''\n  workflow_dispatch: ''"),
        &Limits::DEFAULT,
    )
    .unwrap();
    assert!(
        valid
            .selects_event("workflow_dispatch", None, &|| false)
            .unwrap()
    );
}
#[test]
fn count_and_byte_limits_are_exact_and_reference_length_is_bounded() {
    for (patterns, ok) in [(vec!["a"; 32], true), (vec!["a"; 33], false)] {
        assert_eq!(
            compile(
                &source(&mapping("push", "branches", &patterns)),
                &Limits::DEFAULT
            )
            .is_ok(),
            ok
        );
    }
    for (size, ok) in [(256, true), (257, false)] {
        let p = "a".repeat(size);
        assert_eq!(
            compile(
                &source(&mapping("push", "branches", &[&p])),
                &Limits::DEFAULT
            )
            .is_ok(),
            ok
        );
    }
    let p = "a".repeat(256);
    assert!(
        compile(
            &source(&mapping("push", "branches", &vec![p.as_str(); 16])),
            &Limits::DEFAULT
        )
        .is_ok()
    );
    assert!(matches!(
        compile(
            &source(&mapping("push", "branches", &vec![p.as_str(); 17])),
            &Limits::DEFAULT
        ),
        Err(WorkflowRefusal::LimitExceeded { .. })
    ));
    let graph = filtered("push", "branches", &["**"]);
    assert!(matches(&graph, "push", &vec![b'a'; 1013]));
    assert_eq!(
        graph.selects_event("push", Some(&vec![b'a'; 1025]), &|| false),
        Err(TriggerSelectionError::ReferenceTooLong)
    );
}
#[test]
fn cancellation_is_checked_inside_worst_case_matching() {
    let pattern = "*a".repeat(120);
    let graph = filtered("push", "branches", &[&pattern]);
    let reference = [b"refs/heads/".as_slice(), &vec![b'a'; 1000]].concat();
    for stop in [1, 2, 20, 120] {
        let calls = Cell::new(0);
        let result = graph.selects_event("push", Some(&reference), &|| {
            calls.set(calls.get() + 1);
            calls.get() >= stop
        });
        assert_eq!(result, Err(TriggerSelectionError::Cancelled));
        assert_eq!(calls.get(), stop);
    }
    assert!(
        graph
            .selects_event("push", Some(&reference), &|| false)
            .unwrap()
    );
}
#[test]
fn new_graph_form_keeps_existing_context_and_deadline_records() {
    let text = source(&mapping("push", "branches", &["main"]))
        .replace("    steps:", "    timeout-minutes: 2\n    steps:")
        + "        env:\n          BUILD_MODE: literal\n        working-directory: src\n";
    let graph = compile(&text, &Limits::DEFAULT).unwrap();
    let bytes = graph.canonical_bytes();
    for record in [
        "fgit-workflow/v5\n",
        "trigger-branch\tpush\tbranches\tmain\n",
        "job-timeout-minutes\tbuild\t2\n",
        "step-env\tbuild\t0\tBUILD_MODE\tliteral\n",
        "step-cwd\tbuild\t0\tsrc\n",
    ] {
        assert!(bytes.contains(record), "{record}: {bytes}");
    }
}
// Independent recursive oracle on a deliberately tiny alphabet/corpus. Production
// uses fixed-memory dynamic programming; this oracle is test-only and bounded.
fn oracle(p: &[u8], s: &[u8]) -> bool {
    if p.is_empty() {
        return s.is_empty();
    }
    if p.starts_with(b"**/") {
        return oracle(&p[3..], s)
            || (0..s.len()).any(|i| s[i] == b'/' && oracle(&p[3..], &s[i + 1..]));
    }
    if p.starts_with(b"**") {
        return (0..=s.len()).any(|n| oracle(&p[2..], &s[n..]));
    }
    if p[0] == b'*' {
        return (0..=s.len())
            .take_while(|&n| !s[..n].contains(&b'/'))
            .any(|n| oracle(&p[1..], &s[n..]));
    }
    !s.is_empty() && p[0] == s[0] && oracle(&p[1..], &s[1..])
}
#[test]
fn exhaustive_small_corpus_matches_independent_recursive_oracle() {
    for pattern in [
        "*", "**", "a*", "*b", "a*b", "a**b", "*/b", "**/b", "a/**/b", "**/a/**", "a*b*a*",
    ] {
        let graph = filtered("push", "branches", &[pattern]);
        for length in 1..=5 {
            for mut code in 0..3_usize.pow(length) {
                let mut branch = Vec::new();
                for _ in 0..length {
                    branch.push(b"ab/"[code % 3]);
                    code /= 3;
                }
                assert_eq!(
                    matches(&graph, "push", &branch),
                    oracle(pattern.as_bytes(), &branch),
                    "{pattern} {branch:?}"
                );
            }
        }
    }
}
