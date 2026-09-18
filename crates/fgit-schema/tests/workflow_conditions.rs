#![forbid(unsafe_code)]
use fgit_schema::workflow::{compile, Condition, Limits, WorkflowRefusal};

fn source(job_if: &str, step_if: &str) -> String {
    format!("name: conditions\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: false\n  diagnose:\n    runs-on: fgit-trusted-local\n    needs: build\n    if: {job_if}\n    steps:\n      - name: collect\n        if: {step_if}\n        run: printf diagnostic\n")
}

#[test]
fn closed_conditions_lower_and_bind_canonical_identity() {
    for (text, expected) in [
        ("success()", Condition::Success),
        ("failure()", Condition::Failure),
        ("always()", Condition::Always),
    ] {
        let graph = compile(&source(text, text), &Limits::default()).unwrap();
        let diagnose = graph.jobs.iter().find(|job| job.id == "diagnose").unwrap();
        assert_eq!(diagnose.condition, expected);
        assert_eq!(diagnose.steps[0].condition, expected);
        let canonical = graph.canonical_bytes();
        if expected == Condition::Success {
            assert!(!canonical.contains("job-if") && !canonical.contains("step-if"));
        } else {
            assert!(canonical.contains(&format!("job-if\tdiagnose\t{text}")));
            assert!(canonical.contains(&format!("step-if\tdiagnose\t0\t{text}")));
        }
    }
}

#[test]
fn unsupported_expressions_refuse_at_the_condition_span() {
    for bad in [
        "cancelled()", "true", "needs.build.result == 'failure'",
        "${{ always() }}", "always() || success()",
    ] {
        let input = source(bad, "success()");
        let error = compile(&input, &Limits::default()).unwrap_err();
        assert!(matches!(error, WorkflowRefusal::Malformed { expected: "one of success(), failure(), or always()", .. }));
        assert!(error.span().line >= 9);
    }
}

#[test]
fn default_condition_preserves_existing_graph_bytes() {
    let implicit = "name: x\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf x\n";
    let explicit = "name: x\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    if: success()\n    steps:\n      - if: success()\n        run: printf x\n";
    assert_eq!(
        compile(implicit, &Limits::default()).unwrap().canonical_bytes(),
        compile(explicit, &Limits::default()).unwrap().canonical_bytes()
    );
}
