#![forbid(unsafe_code)]
use fgit_schema::workflow::{Limits, WorkflowGraph, WorkflowRefusal, compile};

const SOURCE: &str = "name: fail fast\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    strategy:\n      fail-fast: false\n      matrix:\n        mode: [first, last]\n    steps:\n      - run: echo build\n";

fn graph(source: &str) -> WorkflowGraph {
    compile(source, &Limits::default()).unwrap()
}

#[test]
fn explicit_false_keeps_the_exact_original_matrix_bytes() {
    let lowered = graph(SOURCE);
    assert!(!lowered.has_matrix_fail_fast());
    assert!(
        lowered
            .jobs
            .iter()
            .all(|job| !job.matrix.as_ref().unwrap().fail_fast())
    );
    assert_eq!(
        lowered.canonical_bytes(),
        concat!(
            "fgit-workflow/v3\nname\tfail fast\ntrigger\tpush\n",
            "job\tbuild__matrix_000\tfgit-trusted-local\n",
            "matrix-origin\tbuild__matrix_000\tbuild\n",
            "matrix-value\tbuild__matrix_000\tmode\tfirst\n",
            "step\tbuild__matrix_000\t0\t\techo build\n",
            "job\tbuild__matrix_001\tfgit-trusted-local\n",
            "matrix-origin\tbuild__matrix_001\tbuild\n",
            "matrix-value\tbuild__matrix_001\tmode\tlast\n",
            "step\tbuild__matrix_001\t0\t\techo build\n",
        )
    );
}

#[test]
fn default_and_true_select_the_same_explicit_versioned_policy() {
    let omitted = SOURCE.replace("      fail-fast: false\n", "");
    let explicit = SOURCE.replace("fail-fast: false", "fail-fast: true");
    let expected = graph(&explicit).canonical_bytes();
    assert!(expected.starts_with("fgit-workflow/v9\n"));
    assert_eq!(
        expected
            .lines()
            .filter(|line| line.starts_with("matrix-fail-fast\t"))
            .collect::<Vec<_>>(),
        [
            "matrix-fail-fast\tbuild__matrix_000\ttrue",
            "matrix-fail-fast\tbuild__matrix_001\ttrue",
        ]
    );
    for source in [&omitted, &explicit] {
        let lowered = graph(source);
        assert!(lowered.has_matrix_fail_fast());
        assert!(
            lowered
                .jobs
                .iter()
                .all(|job| job.matrix.as_ref().unwrap().fail_fast())
        );
        assert_eq!(lowered.canonical_bytes(), expected);
        assert_eq!(graph(source).canonical_bytes(), expected);
    }
    assert_ne!(graph(SOURCE).canonical_bytes(), expected);
}

#[test]
fn mixed_groups_bind_only_selected_fail_fast_without_losing_newer_context_fields() {
    let source = format!(
        "{SOURCE}{}",
        SOURCE
            .split_once("jobs:\n")
            .unwrap()
            .1
            .replace("build", "other")
            .replace("fail-fast: false", "fail-fast: true")
            .replace(
                "      - run: echo other",
                "      - run: echo other\n        shell: bash\n        timeout-minutes: 1"
            )
    );
    let lowered = graph(&source);
    assert_eq!(lowered.jobs.len(), 4);
    assert!(!lowered.jobs[0].matrix.as_ref().unwrap().fail_fast());
    assert!(lowered.jobs[2].matrix.as_ref().unwrap().fail_fast());
    let bytes = lowered.canonical_bytes();
    assert!(bytes.starts_with("fgit-workflow/v9\n"));
    assert!(!bytes.contains("matrix-fail-fast\tbuild__"));
    assert!(bytes.contains("matrix-fail-fast\tother__matrix_000\ttrue\n"));
    assert!(bytes.contains("step-shell\tother__matrix_000\t0\tbash\n"));
    assert!(bytes.contains("step-timeout-minutes\tother__matrix_000\t0\t1\n"));
}

#[test]
fn unknown_and_nonliteral_policies_refuse_with_a_source_span() {
    for policy in [
        "yes",
        "TRUE",
        "0",
        "[true]",
        "{value: true}",
        "'${{ matrix.mode }}'",
    ] {
        let source = SOURCE.replace("fail-fast: false", &format!("fail-fast: {policy}"));
        let error = compile(&source, &Limits::default()).unwrap_err();
        assert!(
            matches!(error, WorkflowRefusal::Malformed { .. }),
            "{error:?}"
        );
        assert!(!error.span().is_empty());
    }
    let duplicate = SOURCE.replace("      matrix:", "      fail-fast: true\n      matrix:");
    assert!(matches!(
        compile(&duplicate, &Limits::default()),
        Err(WorkflowRefusal::DuplicateKey { .. })
    ));
    assert_eq!(graph(SOURCE).jobs.len(), 2);
}

#[test]
fn fail_fast_never_shrinks_preflight_work_or_admits_an_oversized_matrix() {
    for policy in ["", "      fail-fast: true\n", "      fail-fast: false\n"] {
        let source = SOURCE.replace("      fail-fast: false\n", policy).replace(
            "mode: [first, last]",
            &format!(
                "mode: [{}]\n        target: [a, b]",
                (0..64)
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        assert_eq!(graph(&source).jobs.len(), 128);
        let too_many = source.replace("target: [a, b]", "target: [a, b, c]");
        assert!(matches!(
            compile(&too_many, &Limits::default()),
            Err(WorkflowRefusal::LimitExceeded {
                limit: "expanded workflow jobs",
                ..
            })
        ));
        let late_invalid = source.replace("target: [a, b]", "target: [a, '${{ secrets.SECRET }}']");
        assert!(compile(&late_invalid, &Limits::default()).is_err());
    }
}
