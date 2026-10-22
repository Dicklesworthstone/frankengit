use fgit_schema::workflow::triggers::TriggerSelectionError as E;
use fgit_schema::workflow::{Limits, WorkflowGraph, compile};
fn source(filter: &str) -> String {
    format!(
        "name: paths\non:\n  pull_request:\n{filter}\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n"
    )
}
fn graph(filter: &str) -> WorkflowGraph {
    compile(&source(filter), &Limits::default()).unwrap()
}
fn paths(items: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut p: Vec<_> = items.iter().map(|p| p.to_vec()).collect();
    p.sort();
    p
}
fn selected(g: &WorkflowGraph, p: &[Vec<u8>]) -> bool {
    g.selects_event_with_paths("pull_request", Some(b"refs/heads/main"), Some(p), &|| false)
        .unwrap()
}
#[test]
fn ordered_exclusions_and_reinclusions_apply_per_path_not_to_the_whole_batch() {
    let g = graph(
        "    paths:\n      - 'src/**'\n      - '!src/private/**'\n      - 'src/private/public.rs'",
    );
    assert!(selected(&g, &paths(&[b"src/a.rs"])));
    assert!(!selected(&g, &paths(&[b"src/private/a.rs"])));
    assert!(selected(&g, &paths(&[b"src/private/public.rs"])));
    assert!(selected(&g, &paths(&[b"src/a.rs", b"src/private/a.rs"])));
    assert!(!selected(&g, &paths(&[b"docs/a.rs"])));
}
#[test]
fn ignore_requires_any_nonignored_change_and_empty_is_not_a_match() {
    let g = graph("    paths-ignore:\n      - 'docs/**'\n      - '*.md'");
    assert!(!selected(&g, &[]));
    assert!(!selected(&g, &paths(&[b"docs/a", b"README.md"])));
    assert!(selected(&g, &paths(&[b"docs/a", b"src/a"])));
    assert!(!selected(&graph("    paths:\n      - '**'"), &[]));
}
#[test]
fn branch_and_path_are_both_required_and_unavailable_is_not_empty() {
    let g = graph("    branches:\n      - main\n    paths:\n      - 'src/**'");
    let p = paths(&[b"src/a"]);
    assert!(selected(&g, &p));
    assert!(
        !g.selects_event_with_paths("pull_request", Some(b"refs/heads/other"), Some(&p), &|| {
            false
        })
        .unwrap()
    );
    assert_eq!(
        g.selects_event("pull_request", Some(b"refs/heads/main"), &|| false),
        Err(E::MissingChangedPaths)
    );
    assert_eq!(
        g.selects_event_with_paths("pull_request", None, Some(&p), &|| false),
        Err(E::MissingBranchReference)
    );
    assert!(!g.selects_event("push", None, &|| false).unwrap());
}
#[test]
fn exact_raw_bytes_spaces_and_directory_globs_do_not_normalize_names() {
    let g = graph("    paths:\n      - '**/*.rs'\n      - 'some file.txt'");
    for p in [
        b"a.rs".as_slice(),
        b"src/a.rs",
        b"src/\xff.rs",
        b"some file.txt",
    ] {
        assert!(selected(&g, &paths(&[p])));
    }
    assert!(!selected(&g, &paths(&[b"A.RS"])));
    assert!(!selected(
        &graph("    paths:\n      - 'src/*'"),
        &paths(&[b"src/a/b"])
    ));
}
#[test]
fn path_profiles_bind_order_and_mode_while_historical_graphs_keep_their_version() {
    let a = graph("    paths:\n      - '**'\n      - '!docs/**'");
    let b = graph("    paths:\n      - '!docs/**'\n      - '**'");
    assert!(a.canonical_bytes().starts_with("fgit-workflow/v6\n"));
    assert_ne!(a.canonical_bytes(), b.canonical_bytes());
    assert_ne!(
        a.canonical_bytes(),
        graph("    paths-ignore:\n      - 'docs/**'").canonical_bytes()
    );
    assert_eq!(
        a.canonical_bytes(),
        graph("    paths:\n      - '**'\n      - '!docs/**'").canonical_bytes()
    );
    assert!(
        graph("    branches:\n      - main")
            .canonical_bytes()
            .starts_with("fgit-workflow/v5\n")
    );
}
#[test]
fn malformed_ambiguous_and_unimplemented_events_refuse() {
    for filter in [
        "    paths: src",
        "    paths:\n      - '!docs/**'",
        "    paths-ignore:\n      - '!docs/**'",
        "    paths:\n      - '../a'",
        "    paths:\n      - '/a'",
        "    paths:\n      - 'src/./a'",
        "    paths:\n      - 'a?b'",
        "    paths:\n      - '**'\n    paths-ignore:\n      - docs",
    ] {
        assert!(
            compile(&source(filter), &Limits::default()).is_err(),
            "{filter}"
        );
    }
    assert!(
        compile(
            &source("    paths:\n      - '**'").replace("pull_request:", "push:"),
            &Limits::default()
        )
        .is_err()
    );
    assert!(
        compile(
            &source("    paths:\n      - '**'").replace("pull_request:", "workflow_dispatch:"),
            &Limits::default()
        )
        .is_err()
    );
}
#[test]
fn complete_path_inventory_validates_before_a_matching_prefix_can_hide_bad_tail() {
    let g = graph("    paths:\n      - '**'");
    for p in [
        vec![b"a".to_vec(), b"../bad".to_vec()],
        vec![b"a".to_vec(), b"a".to_vec()],
        vec![b"b".to_vec(), b"a".to_vec()],
        vec![vec![b'a'; 4097]],
        vec![b"x\0y".to_vec()],
    ] {
        assert_eq!(
            g.selects_event_with_paths("pull_request", None, Some(&p), &|| false),
            Err(E::InvalidChangedPaths)
        );
    }
    let p: Vec<_> = (0..512).map(|i| format!("p{i:04}").into_bytes()).collect();
    assert!(selected(&g, &p));
    let mut too_many = p;
    too_many.push(b"z".to_vec());
    assert_eq!(
        g.selects_event_with_paths("pull_request", None, Some(&too_many), &|| false),
        Err(E::InvalidChangedPaths)
    );
}
#[test]
fn matching_work_is_bounded_and_cancellation_remains_a_refusal() {
    let filters = format!(
        "    paths:\n{}",
        (0..16)
            .map(|_| format!("      - '{}'\n", "a*".repeat(128)))
            .collect::<String>()
    );
    let g = graph(&filters);
    let p: Vec<_> = (0..128)
        .map(|i| format!("{i:04}{}", "a".repeat(1000)).into_bytes())
        .collect();
    assert_eq!(
        g.selects_event_with_paths("pull_request", None, Some(&p), &|| false),
        Err(E::PathMatchBudget)
    );
    let g = graph("    paths:\n      - '**'");
    assert_eq!(
        g.selects_event_with_paths("pull_request", None, Some(&paths(&[b"a"])), &|| true),
        Err(E::Cancelled)
    );
}
