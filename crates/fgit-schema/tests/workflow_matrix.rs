#![forbid(unsafe_code)]
use fgit_schema::workflow::{Limits, WorkflowGraph, WorkflowRefusal, compile};

fn workflow(matrix: &str, extra: &str) -> String {
    format!(
        "name: native matrix\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    strategy:\n      fail-fast: false\n      matrix:\n{matrix}    steps:\n      - run: printf '%s' \"$VALUE\"\n        env:\n          VALUE: '${{{{ matrix.mode }}}}'\n{extra}"
    )
}
fn graph(matrix: &str, extra: &str) -> WorkflowGraph {
    compile(&workflow(matrix, extra), &Limits::default()).unwrap()
}
fn values(graph: &WorkflowGraph, name: &str) -> Vec<String> {
    graph
        .jobs
        .iter()
        .filter_map(|j| j.matrix.as_ref())
        .filter_map(|m| m.values().get(name).cloned())
        .collect()
}
fn refused(source: &str) -> WorkflowRefusal {
    let failure = compile(source, &Limits::default()).unwrap_err();
    assert!(!failure.span().is_empty());
    failure
}
const MODES: &str = "        mode:\n          - debug\n          - release\n";

#[test]
fn cartesian_variants_are_exact_and_needs_join_the_entire_original_group() {
    let matrix = format!("{MODES}        arch:\n          - arm\n          - x86\n");
    let after = "  package:\n    runs-on: fgit-trusted-local\n    needs: build\n    steps:\n      - run: echo packaged\n";
    let g = graph(&matrix, after);
    assert_eq!(
        g.job_ids(),
        [
            "build__matrix_000",
            "build__matrix_001",
            "build__matrix_002",
            "build__matrix_003",
            "package"
        ]
    );
    assert_eq!(values(&g, "mode"), ["debug", "release", "debug", "release"]);
    assert_eq!(values(&g, "arch"), ["arm", "arm", "x86", "x86"]);
    assert_eq!(
        g.jobs[4].needs,
        g.jobs[..4].iter().map(|j| j.id.clone()).collect::<Vec<_>>()
    );
    for j in &g.jobs[..4] {
        let binding = j.matrix.as_ref().unwrap();
        assert_eq!(binding.source_job(), "build");
        assert_eq!(
            j.steps[0].context.environment()["VALUE"],
            binding.values()["mode"]
        );
    }
    assert!(g.canonical_bytes().starts_with("fgit-workflow/v3\n"));
    assert!(
        g.canonical_bytes()
            .contains("matrix-value\tbuild__matrix_000\tarch\tarm\n")
    );
    let reordered = format!("        arch:\n          - arm\n          - x86\n{MODES}");
    assert_eq!(
        g.canonical_bytes(),
        graph(&reordered, after).canonical_bytes()
    );
}

#[test]
fn exclusions_then_inclusions_merge_only_compatible_original_rows() {
    let matrix = format!(
        "{MODES}        arch:\n          - arm\n          - x86\n        exclude:\n          - mode: debug\n            arch: arm\n        include:\n          - note: first\n          - mode: release\n            note: last\n          - mode: debug\n            arch: arm\n            note: restored\n          - mode: unusual\n            arch: custom\n            note: new\n"
    );
    let g = graph(&matrix, "");
    let rows = g
        .jobs
        .iter()
        .map(|j| j.matrix.as_ref().unwrap().values())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 5);
    assert_eq!(
        rows.iter().map(|r| r["note"].as_str()).collect::<Vec<_>>(),
        ["last", "first", "last", "restored", "new"]
    );
    assert_eq!(rows[3]["mode"], "debug");
    assert_eq!(rows[4]["mode"], "unusual");
    assert_eq!(rows[4]["arch"], "custom");
    let includes = "        include:\n          - mode: one\n          - mode: two\n";
    assert_eq!(values(&graph(includes, ""), "mode"), ["one", "two"]);
}

#[test]
fn unknown_and_partially_defined_inputs_never_silently_drop_a_variant() {
    for matrix in [
        format!(
            "{MODES}        include:\n          - other: without-mode\n          - mode: new\n            other: only-new\n"
        ),
        format!("{MODES}        exclude:\n          - absent: value\n"),
        "        mode:\n          - duplicate\n          - duplicate\n".into(),
        "        include:\n          - mode: same\n          - mode: same\n".into(),
        "        mode: not-a-sequence\n".into(),
        "        mode:\n          - '${{ secrets.SECRET }}'\n".into(),
        "        mode:\n          - nested:\n              value: no\n".into(),
    ] {
        let text = if matrix.contains("only-new") {
            workflow(&matrix, "").replace("matrix.mode", "matrix.other")
        } else {
            workflow(&matrix, "")
        };
        // The first inclusion adds other to every original, so this case is valid.
        if matrix.contains("without-mode") {
            assert!(compile(&text, &Limits::default()).is_ok());
        } else {
            refused(&text);
        }
    }
    refused(&workflow(
        "        include:\n          - mode: one\n          - different: two\n",
        "",
    ));
    refused(&workflow(
        &format!("{MODES}        exclude:\n          - mode: debug\n          - mode: release\n"),
        "",
    ));
    assert_eq!(graph(MODES, "").jobs.len(), 2);
}

#[test]
fn substitutions_are_whole_value_context_only_and_unused_axes_bind_identity() {
    let source = workflow(
        "        mode:\n          - '$(touch unexpected); literal $HOME'\n",
        "",
    );
    let g = compile(&source, &Limits::default()).unwrap();
    assert_eq!(g.jobs[0].steps[0].run, "printf '%s' \"$VALUE\"");
    assert_eq!(
        g.jobs[0].steps[0].context.environment()["VALUE"],
        "$(touch unexpected); literal $HOME"
    );
    for bad in [
        "prefix-${{ matrix.mode }}",
        "${{ secrets.mode }}",
        "${{ matrix.unknown }}",
        "${{ matrix.mode || 'fallback' }}",
    ] {
        refused(&workflow(MODES, "").replace("${{ matrix.mode }}", bad));
    }
    let g1 = graph(&format!("{MODES}        unused:\n          - one\n"), "");
    let g2 = graph(&format!("{MODES}        unused:\n          - two\n"), "");
    assert_ne!(g1.canonical_bytes(), g2.canonical_bytes());
    let directory = workflow("        mode:\n          - ./src\n", "").replace(
        "        env:\n          VALUE: '${{ matrix.mode }}'",
        "        working-directory: '${{ matrix.mode }}'",
    );
    assert_eq!(
        compile(&directory, &Limits::default()).unwrap().jobs[0].steps[0]
            .context
            .working_directory(),
        Some("src")
    );
    refused(&directory.replace("./src", "../outside"));
}

#[test]
fn variant_names_cannot_alias_declared_jobs_and_needs_cannot_address_hidden_members() {
    let job = "  build__matrix_000:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo conflict\n";
    refused(&workflow(MODES, job));
    let extra = "  after:\n    runs-on: fgit-trusted-local\n    needs: build__matrix_000\n    steps:\n      - run: echo incomplete-group\n";
    assert!(matches!(
        refused(&workflow(MODES, extra)),
        WorkflowRefusal::NeedsUnknown { .. }
    ));
    assert!(matches!(
        refused(&workflow(MODES, "").replace("    strategy:", "    needs: build\n    strategy:")),
        WorkflowRefusal::NeedsCycle { .. }
    ));
}

#[test]
fn explicit_failure_policy_and_unknown_strategy_fields_are_not_ignored() {
    let text = workflow(MODES, "");
    for changed in [
        text.replace("      fail-fast: false\n", ""),
        text.replace("fail-fast: false", "fail-fast: true"),
        text.replace("      matrix:", "      max-parallel: 2\n      matrix:"),
        text.replace("      matrix:", "      typo: false\n      matrix:"),
    ] {
        refused(&changed);
    }
    assert_eq!(graph(MODES, "").jobs.len(), 2);
}

fn dimensions(a: usize, b: usize) -> String {
    let mut matrix = String::from("        mode:\n");
    for n in 0..a {
        matrix.push_str(&format!("          - m{n}\n"));
    }
    matrix.push_str("        target:\n");
    for n in 0..b {
        matrix.push_str(&format!("          - t{n}\n"));
    }
    matrix
}
#[test]
fn exact_expansion_bounds_refuse_before_cloning_oversized_jobs() {
    assert_eq!(graph(&dimensions(16, 8), "").jobs.len(), 128);
    assert!(matches!(
        refused(&workflow(&dimensions(43, 3), "")),
        WorkflowRefusal::LimitExceeded {
            limit: "expanded workflow jobs",
            ..
        }
    ));
    assert!(matches!(
        refused(&workflow(&dimensions(64, 5), "")),
        WorkflowRefusal::LimitExceeded {
            limit: "matrix Cartesian combinations",
            ..
        }
    ));
    let source = workflow(&dimensions(16, 8), "");
    let four = source.replace(
        "      - run: printf",
        "      - run: echo a\n      - run: echo b\n      - run: echo c\n      - run: printf",
    );
    assert_eq!(
        compile(&four, &Limits::default())
            .unwrap()
            .jobs
            .iter()
            .map(|j| j.steps.len())
            .sum::<usize>(),
        512
    );
    assert!(matches!(
        refused(&four.replace(
            "      - run: echo a",
            "      - run: echo x\n      - run: echo a"
        )),
        WorkflowRefusal::LimitExceeded {
            limit: "expanded workflow steps",
            ..
        }
    ));
    let huge = source.replace(
        "      - run: printf",
        &format!(
            "      - run: {}\n      - run: {}\n      - run: {}\n      - run: printf",
            "x".repeat(8192),
            "x".repeat(8192),
            "x".repeat(8192)
        ),
    );
    assert!(compile(&huge, &Limits::default()).is_ok());
    let entries = (0..32)
        .map(|n| format!("          X{n}: {}\n", "z".repeat(2048)))
        .collect::<String>();
    let oversized_env = huge.replace("          VALUE:", &format!("{entries}          VALUE:"));
    assert!(matches!(
        refused(&oversized_env),
        WorkflowRefusal::LimitExceeded {
            limit: "expanded workflow allocation bytes",
            ..
        }
    ));
}

#[test]
fn generated_cross_products_match_an_independent_tuple_oracle() {
    for a in 1..8 {
        for b in 1..8 {
            let g = graph(&dimensions(a, b), "");
            let expected = (0..a)
                .flat_map(|i| (0..b).map(move |j| (format!("m{i}"), format!("t{j}"))))
                .collect::<Vec<_>>();
            let observed = g
                .jobs
                .iter()
                .map(|job| {
                    let values = job.matrix.as_ref().unwrap().values();
                    (values["mode"].clone(), values["target"].clone())
                })
                .collect::<Vec<_>>();
            assert_eq!(observed, expected);
            assert_eq!(
                g.canonical_bytes(),
                graph(&dimensions(a, b), "").canonical_bytes()
            );
        }
    }
}

#[test]
fn no_matrix_workflow_keeps_its_previous_canonical_version() {
    let plain = "name: simple\non: push\njobs:\n  build:\n    runs-on: linux\n    steps:\n      - run: echo exact\n";
    assert!(
        compile(plain, &Limits::default())
            .unwrap()
            .canonical_bytes()
            .starts_with("fgit-workflow/v1\n")
    );
    let context = plain.replace(
        "      - run: echo exact",
        "      - run: echo exact\n        env:\n          VALUE: literal",
    );
    assert!(
        compile(&context, &Limits::default())
            .unwrap()
            .canonical_bytes()
            .starts_with("fgit-workflow/v2\n")
    );
}
