#![forbid(unsafe_code)]

use fgit_schema::workflow::{Limits, StepShell, WorkflowGraph, WorkflowRefusal, compile};
use std::fmt::Write as _;

fn graph(source: &str) -> WorkflowGraph {
    compile(source, &Limits::default()).unwrap()
}

fn refused(source: &str) -> WorkflowRefusal {
    let error = compile(source, &Limits::default()).unwrap_err();
    assert!(!error.span().is_empty(), "{error:?}");
    error
}

fn workflow(root: &str, job: &str, step: &str) -> String {
    format!(
        "name: run defaults\non: push\n{root}jobs:\n  build:\n    runs-on: fgit-trusted-local\n{job}    steps:\n      - run: echo first\n{step}      - run: echo second\n  other:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo independent\n"
    )
}

fn one_step_workflow(root: &str, job: &str, step: &str) -> String {
    format!(
        "name: run defaults\non: push\n{root}jobs:\n  build:\n    runs-on: fgit-trusted-local\n{job}    steps:\n      - run: echo only\n{step}"
    )
}

#[test]
fn defaults_inherit_per_field_and_explicit_steps_do_not_leak_to_siblings() {
    let source = workflow(
        "defaults:\n  run:\n    shell: bash\n    working-directory: ./packages/base\nenv:\n  VALUE: workflow\n",
        "    defaults:\n      run:\n        working-directory: packages/build\n    env:\n      VALUE: job\n",
        "        shell: sh\n        working-directory: ./scripts\n",
    );
    let lowered = graph(&source);
    let first = &lowered.jobs[0].steps[0].context;
    assert_eq!(first.shell(), Some(StepShell::Sh));
    assert_eq!(first.working_directory(), Some("scripts"));
    assert_eq!(first.environment()["VALUE"], "job");
    let second = &lowered.jobs[0].steps[1].context;
    assert_eq!(second.shell(), Some(StepShell::Bash));
    assert_eq!(second.working_directory(), Some("packages/build"));
    assert_eq!(second.environment()["VALUE"], "job");
    let other = &lowered.jobs[1].steps[0].context;
    assert_eq!(other.shell(), Some(StepShell::Bash));
    assert_eq!(other.working_directory(), Some("packages/base"));
    assert_eq!(other.environment()["VALUE"], "workflow");
    assert!(lowered.canonical_bytes().starts_with("fgit-workflow/v8\n"));

    // A job shell override leaves its parent's directory intact.
    let swapped = workflow(
        "defaults:\n  run:\n    shell: bash\n    working-directory: parent\n",
        "    defaults:\n      run:\n        shell: sh\n",
        "",
    );
    let swapped = graph(&swapped);
    for step in &swapped.jobs[0].steps {
        assert_eq!(step.context.shell(), Some(StepShell::Sh));
        assert_eq!(step.context.working_directory(), Some("parent"));
    }
    assert_eq!(
        swapped.jobs[1].steps[0].context.shell(),
        Some(StepShell::Bash)
    );
}

#[test]
fn explicit_root_at_each_child_layer_clears_an_inherited_directory() {
    for root in [".", "./"] {
        let step_override = workflow(
            "defaults:\n  run:\n    shell: bash\n    working-directory: source\n",
            "    defaults:\n      run:\n        shell: sh\n",
            &format!("        working-directory: {root}\n"),
        );
        let lowered = graph(&step_override);
        assert_eq!(lowered.jobs[0].steps[0].context.working_directory(), None);
        assert_eq!(
            lowered.jobs[0].steps[0].context.shell(),
            Some(StepShell::Sh)
        );
        assert_eq!(
            lowered.jobs[0].steps[1].context.working_directory(),
            Some("source")
        );

        let job_override = workflow(
            "defaults:\n  run:\n    shell: bash\n    working-directory: source\n",
            &format!("    defaults:\n      run:\n        working-directory: {root}\n"),
            "",
        );
        let lowered = graph(&job_override);
        for step in &lowered.jobs[0].steps {
            assert_eq!(step.context.working_directory(), None);
            assert_eq!(step.context.shell(), Some(StepShell::Bash));
        }
        assert_eq!(
            lowered.jobs[1].steps[0].context.working_directory(),
            Some("source")
        );
    }
}

#[test]
fn effective_inputs_keep_existing_graph_identity_regardless_of_source_level() {
    let base = "name: run defaults\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo same\n";
    let explicit = format!("{base}        shell: bash\n        working-directory: src\n");
    let root = base.replace(
        "jobs:\n",
        "defaults:\n  run:\n    shell: bash\n    working-directory: ./src\njobs:\n",
    );
    let job = base.replace(
        "    steps:\n",
        "    defaults:\n      run:\n        shell: bash\n        working-directory: src\n    steps:\n",
    );
    let expected = graph(&explicit).canonical_bytes();
    assert_eq!(graph(&root).canonical_bytes(), expected);
    assert_eq!(graph(&job).canonical_bytes(), expected);
    let redundant = root.replace(
        "    steps:\n",
        "    defaults:\n      run:\n        shell: sh\n        working-directory: replaced\n    steps:\n",
    );
    assert_eq!(
        graph(&format!(
            "{redundant}        shell: bash\n        working-directory: src\n"
        ))
        .canonical_bytes(),
        expected
    );

    let original = graph(base).canonical_bytes();
    assert!(original.starts_with("fgit-workflow/v1\n"));
    for empty in [
        "defaults: {}\n",
        "defaults:\n  run: {}\n",
        "defaults:\n  run:\n    working-directory: .\n",
    ] {
        assert_eq!(
            graph(&base.replace("jobs:\n", &format!("{empty}jobs:\n"))).canonical_bytes(),
            original
        );
    }
    assert_eq!(
        graph(&base.replace("    steps:\n", "    defaults: {}\n    steps:\n")).canonical_bytes(),
        original
    );
    let cwd = root.replace("    shell: bash\n", "");
    assert!(
        graph(&cwd)
            .canonical_bytes()
            .starts_with("fgit-workflow/v2\n")
    );
}

#[test]
fn invalid_parent_defaults_refuse_even_when_every_effective_field_is_overridden() {
    let valid_job =
        "    defaults:\n      run:\n        shell: sh\n        working-directory: safe\n";
    let valid_step = "        shell: bash\n        working-directory: safe\n";
    for (field, value) in [
        ("shell", "'bash -c do-not-echo-this'"),
        ("shell", "'${{ matrix.shell }}'"),
        ("shell", "'/bin/bash'"),
        ("shell", "[bash]"),
        ("working-directory", "'../do-not-echo-this'"),
        ("working-directory", "'/do-not-echo-this'"),
        ("working-directory", "'${{ matrix.path }}'"),
        ("working-directory", "[safe]"),
    ] {
        let source = one_step_workflow(
            &format!("defaults:\n  run:\n    {field}: {value}\n"),
            valid_job,
            valid_step,
        );
        assert!(!refused(&source).to_string().contains("do-not-echo-this"));
        let source = one_step_workflow(
            "defaults:\n  run:\n    shell: sh\n    working-directory: safe\n",
            &format!("    defaults:\n      run:\n        {field}: {value}\n"),
            valid_step,
        );
        assert!(!refused(&source).to_string().contains("do-not-echo-this"));
    }
}

#[test]
fn defaults_maps_are_closed_and_directory_values_keep_existing_safety_rules() {
    for defaults in [
        "defaults: scalar\n",
        "defaults: [run]\n",
        "defaults:\n  run: scalar\n",
        "defaults:\n  run: [shell]\n",
        "defaults:\n  shell: bash\n",
        "defaults:\n  env: {}\n",
        "defaults:\n  run:\n    timeout-minutes: 1\n",
        "defaults:\n  run:\n    permissions: read-all\n",
        "defaults:\n  run:\n    shell: bash\n    shell: sh\n",
        "defaults:\n  run: {}\n  run: {}\n",
    ] {
        refused(&workflow(defaults, "", ""));
        let indented: String = defaults
            .lines()
            .map(|line| format!("    {line}\n"))
            .collect();
        refused(&workflow("", &indented, ""));
    }
    for path in [
        "",
        "/tmp",
        "../parent",
        "src/../parent",
        "src//child",
        "src/./child",
        "src/",
        "src\\child",
        "C:drive",
        "src\0child",
        "${{ secrets.path }}",
    ] {
        refused(&workflow(
            &format!("defaults:\n  run:\n    working-directory: '{path}'\n"),
            "",
            "",
        ));
    }
    let longest = "x".repeat(1024);
    assert!(
        compile(
            &workflow(
                &format!("defaults:\n  run:\n    working-directory: {longest}\n"),
                "",
                ""
            ),
            &Limits::default(),
        )
        .is_ok()
    );
    refused(&workflow(
        &format!("defaults:\n  run:\n    working-directory: {longest}x\n"),
        "",
        "",
    ));
}

#[test]
fn matrix_job_default_directories_resolve_before_override_and_stay_variant_local() {
    let source = workflow(
        "defaults:\n  run:\n    shell: bash\n    working-directory: parent\n",
        "    strategy:\n      fail-fast: false\n      matrix:\n        directory: [left, ./right]\n    defaults:\n      run:\n        shell: sh\n        working-directory: '${{ matrix.directory }}'\n",
        "        working-directory: .\n",
    );
    let lowered = graph(&source);
    assert_eq!(lowered.jobs.len(), 3);
    for (job, expected) in lowered.jobs[..2].iter().zip(["left", "right"]) {
        assert_eq!(job.steps[0].context.working_directory(), None);
        assert_eq!(job.steps[0].context.shell(), Some(StepShell::Sh));
        assert_eq!(job.steps[1].context.working_directory(), Some(expected));
        assert_eq!(job.steps[1].context.shell(), Some(StepShell::Sh));
    }
    assert_eq!(
        lowered.jobs[2].steps[0].context.working_directory(),
        Some("parent")
    );
    assert_eq!(
        lowered.jobs[2].steps[0].context.shell(),
        Some(StepShell::Bash)
    );
    for replacement in ["'../unsafe'", "'/unsafe'", "'src//unsafe'"] {
        // Explicit step root overrides cannot launder an invalid source default.
        let invalid = source.replace("./right", replacement).replace(
            "      - run: echo second\n",
            "      - run: echo second\n        working-directory: .\n",
        );
        refused(&invalid);
    }
    for expression in [
        "'prefix/${{ matrix.directory }}'",
        "'${{ matrix.missing }}'",
        "'${{ secrets.PATH }}'",
    ] {
        refused(&source.replace("'${{ matrix.directory }}'", expression));
    }
    refused(&source.replace(
        "        shell: sh\n",
        "        shell: '${{ matrix.directory }}'\n",
    ));
    refused(&source.replace(
        "    working-directory: parent\n",
        "    working-directory: '${{ matrix.directory }}'\n",
    ));
}

#[test]
fn inherited_directories_share_the_cumulative_allocation_budget_with_environment() {
    let mut source = String::from("name: bounded defaults\non: push\nenv:\n");
    for n in 0..8 {
        writeln!(source, "  V{n}: {}", "x".repeat(8190)).unwrap();
    }
    source.push_str("jobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n");
    for _ in 0..123 {
        source.push_str("      - run: echo bounded\n");
    }
    assert_eq!(graph(&source).jobs[0].steps.len(), 123);
    let inherited = source.replace(
        "jobs:\n",
        &format!(
            "defaults:\n  run:\n    working-directory: {}\njobs:\n",
            "x".repeat(1024)
        ),
    );
    assert!(matches!(
        refused(&inherited),
        WorkflowRefusal::LimitExceeded {
            limit: "expanded workflow allocation bytes",
            allowed: 8388608,
            ..
        }
    ));
    // A step choosing the workspace root does not allocate an inherited path.
    let cleared = inherited.replace(
        "      - run: echo bounded\n",
        "      - run: echo bounded\n        working-directory: .\n",
    );
    assert_eq!(graph(&cleared).jobs[0].steps.len(), 123);
    assert!(
        graph(&cleared).jobs[0]
            .steps
            .iter()
            .all(|step| step.context.working_directory().is_none())
    );
    assert_eq!(graph(&source).jobs[0].steps.len(), 123);
}
