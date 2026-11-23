#![forbid(unsafe_code)]

use fgit_schema::workflow::{ContextRefusal, Limits, StepContext, StepShell, compile};

fn source(shell: Option<&str>) -> String {
    let field = shell.map_or_else(String::new, |shell| format!("        shell: {shell}\n"));
    format!(
        "name: shell profiles\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf result\n{field}      - run: printf default\n"
    )
}

#[test]
fn explicit_shells_are_step_local_and_bind_distinct_versioned_graphs() {
    let legacy = compile(&source(None), &Limits::default()).unwrap();
    let original = legacy.canonical_bytes();
    assert!(original.starts_with("fgit-workflow/v1\n"));
    assert_eq!(legacy.jobs[0].steps[0].context.shell(), None);
    let mut representations = vec![original];
    for (name, expected) in [("sh", StepShell::Sh), ("bash", StepShell::Bash)] {
        let text = source(Some(name));
        let graph = compile(&text, &Limits::default()).unwrap();
        assert_eq!(graph.jobs[0].steps[0].context.shell(), Some(expected));
        assert_eq!(graph.jobs[0].steps[1].context.shell(), None);
        assert!(!graph.jobs[0].steps[0].context.is_default());
        let bytes = graph.canonical_bytes();
        assert!(bytes.starts_with("fgit-workflow/v8\n"));
        assert!(bytes.contains(&format!("step-shell\tbuild\t0\t{name}\n")));
        assert_eq!(bytes.matches("step-shell\t").count(), 1);
        assert_eq!(
            bytes,
            compile(&text, &Limits::default())
                .unwrap()
                .canonical_bytes()
        );
        assert!(representations.iter().all(|earlier| earlier != &bytes));
        representations.push(bytes);
    }
}

#[test]
fn shell_context_retains_environment_and_normalized_directory() {
    let context = StepContext::new(
        vec![("VALUE".into(), "literal $(touch unexpected)".into())],
        Some("./src".into()),
    )
    .unwrap()
    .with_shell(StepShell::Bash);
    assert_eq!(context.shell(), Some(StepShell::Bash));
    assert_eq!(context.working_directory(), Some("src"));
    assert_eq!(
        context.environment()["VALUE"],
        "literal $(touch unexpected)"
    );
    assert_eq!(
        context.with_shell(StepShell::Sh).shell(),
        Some(StepShell::Sh)
    );
    for shell in [StepShell::Sh, StepShell::Bash] {
        assert_eq!(StepShell::parse(shell.token()), Ok(shell));
        assert!(!StepContext::default().with_shell(shell).is_default());
    }
}

#[test]
fn arbitrary_programs_templates_expressions_and_wrong_shapes_refuse_before_execution() {
    for shell in [
        "''",
        "' bash '",
        "Bash",
        "zsh",
        "pwsh",
        "python",
        "'/bin/bash'",
        "'bash -e {0}'",
        "'bash; do-not-echo-this'",
        "'${{ matrix.shell }}'",
        "'${{ secrets.SHELL }}'",
        "[sh, bash]",
        "{name: bash}",
    ] {
        let error = compile(&source(Some(shell)), &Limits::default()).unwrap_err();
        assert!(!error.span().is_empty(), "{error:?}");
        assert!(!error.to_string().contains("do-not-echo-this"));
    }
    for value in ["", " sh", "bash ", "/bin/sh", "sh -e", "sh\0bash"] {
        assert_eq!(StepShell::parse(value), Err(ContextRefusal::Shell));
    }
    let duplicate = source(Some("sh\n        shell: bash"));
    assert!(compile(&duplicate, &Limits::default()).is_err());
    assert!(compile(&source(Some("bash")), &Limits::default()).is_ok());
}

#[test]
fn explicit_shell_identity_composes_with_existing_context_matrix_deadline_and_filters() {
    let text = "name: combined\non:\n  push:\n    tags: ['v*']\n    paths: ['src/**']\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    timeout-minutes: 2\n    strategy:\n      fail-fast: false\n      matrix:\n        mode: [debug, release]\n    steps:\n      - run: printf '%s' \"$MODE\"\n        shell: bash\n        timeout-minutes: 1\n        env:\n          MODE: '${{ matrix.mode }}'\n        working-directory: src\n";
    let graph = compile(text, &Limits::default()).unwrap();
    let bytes = graph.canonical_bytes();
    assert!(bytes.starts_with("fgit-workflow/v8\n"));
    assert_eq!(graph.jobs.len(), 2);
    assert_eq!(bytes.matches("step-shell\t").count(), 2);
    for marker in [
        "trigger-tag\t",
        "trigger-path\t",
        "matrix-value\t",
        "job-timeout-minutes\t",
        "step-timeout-minutes\t",
        "step-env\t",
        "step-cwd\t",
    ] {
        assert!(bytes.contains(marker), "missing {marker}");
    }
    let legacy = compile(
        &text.replace("        shell: bash\n", ""),
        &Limits::default(),
    )
    .unwrap();
    assert!(legacy.canonical_bytes().starts_with("fgit-workflow/v7\n"));
}
