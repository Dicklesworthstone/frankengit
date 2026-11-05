#![forbid(unsafe_code)]
use fgit_schema::workflow::{Limits, WorkflowGraph, WorkflowRefusal, compile, registry};
use std::collections::BTreeMap;
use std::fmt::Write as _;

fn graph(source: &str) -> WorkflowGraph {
    compile(source, &Limits::default()).unwrap()
}
fn refused(source: &str) -> WorkflowRefusal {
    let error = compile(source, &Limits::default()).unwrap_err();
    assert!(!error.span().is_empty());
    error
}
fn workflow(root: &str, job: &str, step: &str) -> String {
    format!(
        "name: inheritance\non: push\n{root}jobs:\n  build:\n    runs-on: fgit-trusted-local\n{job}    steps:\n      - run: echo first\n{step}      - run: echo second\n  other:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo independent\n"
    )
}
fn environment(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(key, value)| ((*key).into(), (*value).into()))
        .collect()
}

#[test]
fn inheritance_lowers_to_exact_step_inputs_with_child_precedence_and_no_sibling_leak() {
    let source = workflow(
        "env:\n  SHARED: workflow\n  WORKFLOW: root\n  EMPTY: base\n",
        "    env:\n      SHARED: job\n      JOB: local\n",
        "        env:\n          SHARED: step\n          EMPTY: ''\n          STEP: only\n        working-directory: ./src\n",
    );
    let g = graph(&source);
    assert_eq!(
        g.jobs[0].steps[0].context.environment(),
        &environment(&[
            ("EMPTY", ""),
            ("JOB", "local"),
            ("SHARED", "step"),
            ("STEP", "only"),
            ("WORKFLOW", "root"),
        ])
    );
    assert_eq!(
        g.jobs[0].steps[1].context.environment(),
        &environment(&[
            ("EMPTY", "base"),
            ("JOB", "local"),
            ("SHARED", "job"),
            ("WORKFLOW", "root"),
        ])
    );
    assert_eq!(
        g.jobs[1].steps[0].context.environment(),
        &environment(&[
            ("EMPTY", "base"),
            ("SHARED", "workflow"),
            ("WORKFLOW", "root")
        ])
    );
    assert_eq!(g.jobs[0].steps[0].context.working_directory(), Some("src"));
    assert_eq!(g.jobs[0].steps[1].context.working_directory(), None);
    assert_eq!(g.jobs[1].steps[0].context.working_directory(), None);
    assert!(g.canonical_bytes().starts_with("fgit-workflow/v2\n"));
    assert_eq!(g.canonical_bytes(), graph(&source).canonical_bytes());

    let reordered = source
        .replace(
            "  SHARED: workflow\n  WORKFLOW: root",
            "  WORKFLOW: root\n  SHARED: workflow",
        )
        .replace(
            "      SHARED: job\n      JOB: local",
            "      JOB: local\n      SHARED: job",
        );
    assert_eq!(g.canonical_bytes(), graph(&reordered).canonical_bytes());
    assert_ne!(
        g.canonical_bytes(),
        graph(&source.replace("WORKFLOW: root", "WORKFLOW: changed")).canonical_bytes()
    );
}

#[test]
fn equivalent_effective_inputs_keep_existing_graph_bytes() {
    let base = "name: inheritance\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo value\n";
    let literal = format!("{base}        env:\n          VALUE: shared\n");
    let top = base.replace("jobs:\n", "env:\n  VALUE: shared\njobs:\n");
    let job = base.replace(
        "    steps:\n",
        "    env:\n      VALUE: shared\n    steps:\n",
    );
    assert!(
        graph(base)
            .canonical_bytes()
            .starts_with("fgit-workflow/v1\n")
    );
    assert_eq!(
        graph(&top).canonical_bytes(),
        graph(&literal).canonical_bytes()
    );
    assert_eq!(
        graph(&job).canonical_bytes(),
        graph(&literal).canonical_bytes()
    );

    // Moving an explicit literal between source levels does not change execution.
    // Source identity remains separately bound by WorkflowPlan and run receipts.
    let redundant = top.replace(
        "    steps:\n",
        "    env:\n      VALUE: replaced\n    steps:\n",
    );
    let redundant = format!("{redundant}        env:\n          VALUE: shared\n");
    assert_eq!(
        graph(&redundant).canonical_bytes(),
        graph(&literal).canonical_bytes()
    );
}

#[test]
fn every_declared_layer_is_validated_before_later_overrides() {
    for rejected in [
        "'${{ secrets.NEVER_PRINT_THIS }}'",
        "'${{ matrix.value }}'",
        "'bad\0NEVER_PRINT_THIS'",
    ] {
        let top = workflow(
            &format!("env:\n  VALUE: {rejected}\n"),
            "    env:\n      VALUE: valid\n",
            "        env:\n          VALUE: valid\n",
        );
        let error = refused(&top);
        assert_eq!(error.span().line, 4);
        assert!(!error.to_string().contains("NEVER_PRINT_THIS"));
        let job = workflow(
            "env:\n  VALUE: valid\n",
            &format!("    env:\n      VALUE: {rejected}\n"),
            "        env:\n          VALUE: valid\n",
        );
        assert!(!refused(&job).to_string().contains("NEVER_PRINT_THIS"));
    }
    for name in [
        "LD_PRELOAD",
        "DYLD_LIBRARY_PATH",
        "FGIT_TOKEN",
        "GITHUB_TOKEN",
        "RUNNER_ID",
        "BASH_ENV",
        "1BAD",
        "BAD-NAME",
    ] {
        refused(&workflow(
            &format!("env:\n  {name}: value\n"),
            "",
            &format!("        env:\n          {name}: value\n"),
        ));
        refused(&workflow(
            "",
            &format!("    env:\n      {name}: value\n"),
            "",
        ));
    }
    for (top, job) in [
        ("env: scalar\n", ""),
        ("env:\n  VALUE:\n    nested: no\n", ""),
        ("env:\n  VALUE: one\n  VALUE: two\n", ""),
        ("", "    env: scalar\n"),
        ("", "    env:\n      VALUE:\n        nested: no\n"),
        ("", "    env:\n      VALUE: one\n      VALUE: two\n"),
    ] {
        refused(&workflow(top, job, ""));
    }
    assert_eq!(
        graph(&workflow("env:\n  VALUE: valid\n", "", ""))
            .jobs
            .len(),
        2
    );
}

#[test]
fn map_entry_and_byte_limits_apply_to_layers_and_effective_unions() {
    let mut top = String::from("env:\n");
    let mut job = String::from("    env:\n");
    for n in 0..32 {
        writeln!(top, "  A{n}: x").unwrap();
        writeln!(job, "      B{n}: x").unwrap();
    }
    let exact = workflow(&top, &job, "");
    assert_eq!(
        graph(&exact).jobs[0].steps[0].context.environment().len(),
        64
    );
    let over = workflow(&top, &job, "        env:\n          EXTRA: x\n");
    assert!(matches!(
        refused(&over),
        WorkflowRefusal::LimitExceeded {
            allowed: 64,
            observed: 65,
            ..
        }
    ));
    let same = workflow(&top, &job, "        env:\n          A0: replaced\n");
    assert_eq!(
        graph(&same).jobs[0].steps[0].context.environment()["A0"],
        "replaced"
    );

    let value = "x".repeat(8190);
    let mut top = String::from("env:\n");
    let mut job = String::from("    env:\n");
    for n in 0..4 {
        writeln!(top, "  A{n}: {value}").unwrap();
        writeln!(job, "      B{n}: {value}").unwrap();
    }
    assert_eq!(
        graph(&workflow(&top, &job, "")).jobs[0].steps[0]
            .context
            .environment()
            .len(),
        8
    );
    let over_job = job.replacen("B0: ", "B0: y", 1);
    assert!(matches!(
        refused(&workflow(&top, &over_job, "")),
        WorkflowRefusal::LimitExceeded {
            allowed: 65536,
            observed: 65537,
            ..
        }
    ));
    let over_step = format!("        env:\n          A0: y{value}\n");
    assert!(matches!(
        refused(&workflow(&top, &job, &over_step)),
        WorkflowRefusal::LimitExceeded {
            allowed: 65536,
            observed: 65537,
            ..
        }
    ));

    let oversized = format!("env:\n  VALUE: {}\n", "x".repeat(8193));
    refused(&workflow(&oversized, "    env:\n      VALUE: valid\n", ""));

    // A later smaller replacement cannot hide an oversized declaration.
    let oversized_top = large_environment(0).replacen("V0: ", "V0: y", 1);
    assert!(matches!(
        refused(&workflow(&oversized_top, "    env:\n      V0: small\n", "")),
        WorkflowRefusal::LimitExceeded {
            limit: "environment bytes",
            allowed: 65536,
            observed: 65537,
            ..
        }
    ));
    let oversized_job = large_environment(4).replacen("V0: ", "V0: y", 1);
    assert!(matches!(
        refused(&workflow(
            "",
            &oversized_job,
            "        env:\n          V0: small\n"
        )),
        WorkflowRefusal::LimitExceeded {
            limit: "environment bytes",
            allowed: 65536,
            observed: 65537,
            ..
        }
    ));
}

fn matrix_source(top: &str, job: &str, step: &str) -> String {
    format!(
        "name: matrix inheritance\non: push\n{top}jobs:\n  build:\n    runs-on: fgit-trusted-local\n    strategy:\n      fail-fast: false\n      matrix:\n        mode:\n          - debug\n          - release\n{job}    steps:\n      - run: echo first\n{step}      - run: echo second\n"
    )
}

#[test]
fn job_matrix_inputs_resolve_before_inheritance_and_bind_every_variant() {
    let source = matrix_source(
        "env:\n  SHARED: root\n  ROOT: literal\n",
        "    env:\n      SHARED: '${{ matrix.mode }}'\n      MODE: '${{ matrix.mode }}'\n",
        "        env:\n          SHARED: step\n          STEP: '${{ matrix.mode }}'\n",
    );
    let g = graph(&source);
    assert_eq!(g.jobs.len(), 2);
    for (job, mode) in g.jobs.iter().zip(["debug", "release"]) {
        assert_eq!(job.steps[0].context.environment()["SHARED"], "step");
        assert_eq!(job.steps[1].context.environment()["SHARED"], mode);
        assert_eq!(job.steps[0].context.environment()["MODE"], mode);
        assert_eq!(job.steps[0].context.environment()["STEP"], mode);
        assert_eq!(job.steps[0].context.environment()["ROOT"], "literal");
        assert!(!job.steps[1].context.environment().contains_key("STEP"));
    }
    assert!(g.canonical_bytes().starts_with("fgit-workflow/v3\n"));
    assert_eq!(g.canonical_bytes(), graph(&source).canonical_bytes());
    for invalid in [
        "${{ matrix.missing }}",
        "prefix ${{ matrix.mode }}",
        "${{ secrets.VALUE }}",
    ] {
        let source = matrix_source(
            "",
            &format!("    env:\n      VALUE: '{invalid}'\n"),
            "        env:\n          VALUE: masks-invalid-job-value\n",
        );
        refused(&source);
    }
    refused(&matrix_source(
        "env:\n  VALUE: '${{ matrix.mode }}'\n",
        "",
        "",
    ));
}

fn large_environment(indent: usize) -> String {
    let mut out = format!("{}env:\n", " ".repeat(indent));
    for n in 0..8 {
        writeln!(out, "{}V{n}: {}", " ".repeat(indent + 2), "x".repeat(8190)).unwrap();
    }
    out
}
fn repeated_steps(top: &str, count: usize, extra: &str) -> String {
    let mut out = format!(
        "name: bounded inheritance\non: push\n{top}jobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n"
    );
    for _ in 0..count {
        writeln!(out, "      - run: echo bounded\n{extra}").unwrap();
    }
    out
}

#[test]
fn nonmatrix_inheritance_has_a_cumulative_preallocation_budget() {
    let env = large_environment(0);
    let admitted = repeated_steps(&env, 120, "");
    assert_eq!(graph(&admitted).jobs[0].steps.len(), 120);
    let rejected = repeated_steps(&env, 128, "");
    assert!(matches!(
        refused(&rejected),
        WorkflowRefusal::LimitExceeded {
            limit: "expanded workflow allocation bytes",
            allowed: 8388608,
            ..
        }
    ));
    // A refusal in one compilation must not consume another invocation's budget.
    assert_eq!(graph(&admitted).jobs[0].steps.len(), 120);
    let mut replacements = String::from("        env:\n");
    for n in 0..8 {
        writeln!(replacements, "          V{n}: small").unwrap();
    }
    assert_eq!(
        graph(&repeated_steps(&env, 128, &replacements)).jobs[0]
            .steps
            .len(),
        128
    );
}

#[test]
fn matrix_and_nonmatrix_jobs_share_the_same_inherited_allocation_budget() {
    fn source(variants: usize) -> String {
        let mut text = format!(
            "name: bounded matrix\non: push\n{}jobs:\n  build:\n    runs-on: fgit-trusted-local\n    strategy:\n      fail-fast: false\n      matrix:\n        mode:\n",
            large_environment(0)
        );
        for n in 0..variants {
            writeln!(text, "          - variant{n}").unwrap();
        }
        text.push_str("    steps:\n      - run: echo first\n      - run: echo second\n  ordinary:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo independent\n");
        text
    }
    assert_eq!(graph(&source(32)).jobs.len(), 33);
    assert!(matches!(
        refused(&source(48)),
        WorkflowRefusal::LimitExceeded {
            limit: "expanded workflow allocation bytes",
            allowed: 8388608,
            ..
        }
    ));
}

#[test]
fn registry_identifies_all_environment_levels_as_normalized_execution_inputs() {
    for key in ["workflow.env", "job.env", "step.env"] {
        assert_eq!(
            registry::lookup(key).unwrap().status,
            registry::ConstructStatus::Normalized
        );
    }
}
