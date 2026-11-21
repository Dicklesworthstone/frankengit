#![forbid(unsafe_code)]

use fgit_schema::workflow::graph::CONTINUE_ON_ERROR_CANONICAL_VERSION;
use fgit_schema::workflow::{ConstructStatus, Limits, WorkflowRefusal, compile, registry};

const SOURCE: &str = "name: optional diagnostic\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: exit 7\n      - run: echo required\n";

fn with_policy(source: &str, value: &str) -> String {
    source.replace(
        "      - run: exit 7\n",
        &format!("      - run: exit 7\n        continue-on-error: {value}\n"),
    )
}

#[test]
fn a_true_policy_is_step_local_and_binds_exact_versioned_graph_bytes() {
    let source = with_policy(SOURCE, "true");
    let graph = compile(&source, &Limits::default()).unwrap();
    assert!(graph.has_continue_on_error());
    assert!(graph.jobs[0].steps[0].continue_on_error);
    assert!(!graph.jobs[0].steps[1].continue_on_error);
    let expected = concat!(
        "fgit-workflow/v10\n",
        "name\toptional diagnostic\ntrigger\tpush\n",
        "job\tbuild\tfgit-trusted-local\n",
        "step\tbuild\t0\t\texit 7\n",
        "step-continue-on-error\tbuild\t0\ttrue\n",
        "step\tbuild\t1\t\techo required\n",
    );
    assert_eq!(graph.canonical_bytes(), expected);
    assert_eq!(
        expected.lines().next(),
        Some(CONTINUE_ON_ERROR_CANONICAL_VERSION)
    );
    for _ in 0..8 {
        assert_eq!(
            compile(&source, &Limits::default())
                .unwrap()
                .canonical_bytes(),
            expected
        );
    }
    let other_step = SOURCE.replace(
        "      - run: echo required\n",
        "      - run: echo required\n        continue-on-error: true\n",
    );
    assert_ne!(
        compile(&other_step, &Limits::default())
            .unwrap()
            .canonical_bytes(),
        expected
    );
}

#[test]
fn explicit_false_preserves_every_existing_graph_version() {
    let matrix = SOURCE.replace(
        "    steps:\n",
        "    strategy:\n      fail-fast: false\n      matrix:\n        mode: [first, last]\n    steps:\n",
    );
    let cases = [
        (1, SOURCE.to_owned()),
        (
            2,
            SOURCE.replace(
                "      - run: exit 7\n",
                "      - run: exit 7\n        env:\n          MODE: literal\n",
            ),
        ),
        (3, matrix.clone()),
        (
            4,
            SOURCE.replace(
                "      - run: exit 7\n",
                "      - run: exit 7\n        timeout-minutes: 1\n",
            ),
        ),
        (
            5,
            SOURCE.replace("on: push\n", "on:\n  push:\n    branches: [main]\n"),
        ),
        (
            6,
            SOURCE.replace("on: push\n", "on:\n  push:\n    paths: ['src/**']\n"),
        ),
        (
            7,
            SOURCE.replace("on: push\n", "on:\n  push:\n    tags: ['v*']\n"),
        ),
        (
            8,
            SOURCE.replace(
                "      - run: exit 7\n",
                "      - run: exit 7\n        shell: bash\n",
            ),
        ),
        (9, matrix.replace("      fail-fast: false\n", "")),
    ];
    for (version, source) in cases {
        let legacy = compile(&source, &Limits::default()).unwrap();
        let explicit = compile(&with_policy(&source, "false"), &Limits::default()).unwrap();
        assert!(!legacy.has_continue_on_error());
        assert!(!explicit.has_continue_on_error());
        assert!(
            legacy
                .canonical_bytes()
                .starts_with(&format!("fgit-workflow/v{version}\n"))
        );
        assert_eq!(legacy.canonical_bytes(), explicit.canonical_bytes());
        let tolerant = compile(&with_policy(&source, "true"), &Limits::default()).unwrap();
        assert!(
            tolerant
                .canonical_bytes()
                .starts_with("fgit-workflow/v10\n")
        );
        let without_policy = tolerant
            .canonical_bytes()
            .lines()
            .skip(1)
            .filter(|line| !line.starts_with("step-continue-on-error\t"))
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            without_policy,
            legacy.canonical_bytes().lines().skip(1).collect::<Vec<_>>()
        );
    }
}

#[test]
fn closed_booleans_refuse_expressions_truthiness_and_malformed_shapes() {
    for value in [
        "yes",
        "no",
        "TRUE",
        "False",
        "1",
        "0",
        "null",
        "''",
        "' true '",
        "'${{ true }}'",
        "'${{ matrix.optional }}'",
        "'${{ secrets.DO_NOT_DISCLOSE }}'",
        "[true]",
        "{value: true}",
    ] {
        let error = compile(&with_policy(SOURCE, value), &Limits::default()).unwrap_err();
        assert!(
            matches!(
                error,
                WorkflowRefusal::Malformed { .. } | WorkflowRefusal::FieldShape { .. }
            ),
            "{error:?}"
        );
        assert!(!error.span().is_empty());
        assert_eq!(error.span().line, 8);
        assert!(!error.to_string().contains("DO_NOT_DISCLOSE"));
        assert!(compile(&with_policy(SOURCE, "true"), &Limits::default()).is_ok());
    }
    let duplicate = with_policy(SOURCE, "true\n        continue-on-error: false");
    assert!(matches!(
        compile(&duplicate, &Limits::default()),
        Err(WorkflowRefusal::DuplicateKey { .. })
    ));
}

#[test]
fn matrix_copies_the_literal_policy_but_never_resolves_a_policy_expression() {
    let source = SOURCE.replace(
        "    steps:\n",
        "    strategy:\n      matrix:\n        optional: [true, false]\n    steps:\n",
    );
    let graph = compile(&with_policy(&source, "true"), &Limits::default()).unwrap();
    assert_eq!(graph.jobs.len(), 2);
    for job in &graph.jobs {
        assert!(job.steps[0].continue_on_error);
        assert!(!job.steps[1].continue_on_error);
        assert!(job.matrix.as_ref().unwrap().fail_fast());
    }
    let bytes = graph.canonical_bytes();
    assert_eq!(bytes.matches("step-continue-on-error\t").count(), 2);
    assert_eq!(bytes.matches("matrix-fail-fast\t").count(), 2);
    assert!(matches!(
        compile(
            &with_policy(&source, "'${{ matrix.optional }}'"),
            &Limits::default()
        ),
        Err(WorkflowRefusal::Malformed { .. })
    ));
}

#[test]
fn step_tolerance_does_not_admit_job_policy_or_hide_later_invalid_steps() {
    for value in ["false", "true"] {
        let job_policy = SOURCE.replace(
            "    steps:\n",
            &format!("    continue-on-error: {value}\n    steps:\n"),
        );
        assert!(matches!(
            compile(&job_policy, &Limits::default()),
            Err(WorkflowRefusal::ConstructUnsupported {
                construct: "job.continue-on-error",
                ..
            })
        ));
    }
    let invalid = with_policy(SOURCE, "true").replace(
        "      - run: echo required\n",
        "      - run: echo required\n        uses: unknown/action\n",
    );
    assert!(matches!(
        compile(&invalid, &Limits::default()),
        Err(WorkflowRefusal::ConstructUnsupported {
            construct: "step.uses",
            ..
        })
    ));
    assert!(compile(&with_policy(SOURCE, "true"), &Limits::default()).is_ok());
}

#[test]
fn the_registry_and_generated_contract_expose_the_closed_step_policy() {
    let entry = registry::CONSTRUCTS
        .iter()
        .find(|entry| entry.key == "step.continue-on-error")
        .unwrap();
    assert_eq!(entry.status, ConstructStatus::Normalized);
    assert!(!entry.status.refuses());
    assert_eq!(
        fgit_schema::emit::workflow_registry(),
        include_str!("../generated/workflow-constructs.json")
    );
}
