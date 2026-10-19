#![forbid(unsafe_code)]

use fgit_schema::workflow::{Limits, TimeoutMinutes, WorkflowRefusal, compile};

const SOURCE: &str = "name: deadlines\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo build\n";

#[test]
fn legacy_graph_bytes_are_unchanged_and_each_cap_changes_identity() {
    let original = compile(SOURCE, &Limits::DEFAULT).unwrap();
    assert_eq!(
        original.canonical_bytes(),
        "fgit-workflow/v1\nname\tdeadlines\ntrigger\tpush\njob\tbuild\tfgit-trusted-local\nstep\tbuild\t0\t\techo build\n"
    );
    assert!(!original.has_deadlines());
    let job = SOURCE.replace("    steps:\n", "    timeout-minutes: 5\n    steps:\n");
    let step = format!("{SOURCE}        timeout-minutes: 2\n");
    let both = format!("{job}        timeout-minutes: 2\n");
    let graphs: Vec<_> = [job, step, both]
        .iter()
        .map(|source| compile(source, &Limits::DEFAULT).unwrap())
        .collect();
    for graph in &graphs {
        assert!(graph.has_deadlines());
        assert!(graph.canonical_bytes().starts_with("fgit-workflow/v4\n"));
        assert_ne!(graph.canonical_bytes(), original.canonical_bytes());
    }
    assert_eq!(graphs[0].jobs[0].timeout_minutes.unwrap().minutes(), 5);
    assert_eq!(
        graphs[1].jobs[0].steps[0]
            .timeout_minutes
            .unwrap()
            .minutes(),
        2
    );
    assert_eq!(
        graphs[2].canonical_bytes(),
        "fgit-workflow/v4\nname\tdeadlines\ntrigger\tpush\njob\tbuild\tfgit-trusted-local\njob-timeout-minutes\tbuild\t5\nstep\tbuild\t0\t\techo build\nstep-timeout-minutes\tbuild\t0\t2\n"
    );
    assert_ne!(graphs[2].canonical_bytes(), graphs[0].canonical_bytes());
    assert_ne!(graphs[2].canonical_bytes(), graphs[1].canonical_bytes());
}

#[test]
fn timeout_values_are_bounded_positive_decimal_integers_with_source_spans() {
    for value in [
        "0",
        "61",
        "65536",
        "999999999999999999999999",
        "-1",
        "+1",
        "1.5",
        "1e1",
        "0x10",
        "true",
        "' 1 '",
        "'01'",
        "'١'",
        "'${{ matrix.minutes }}'",
        "''",
    ] {
        for source in [
            SOURCE.replace(
                "    steps:\n",
                &format!("    timeout-minutes: {value}\n    steps:\n"),
            ),
            format!("{SOURCE}        timeout-minutes: {value}\n"),
        ] {
            let error = compile(&source, &Limits::DEFAULT).unwrap_err();
            assert!(
                matches!(error, WorkflowRefusal::Malformed { .. }),
                "{value}: {error:?}"
            );
            let span = error.span();
            assert!(!span.is_empty(), "{value}: {error:?}");
        }
    }
    for value in ["1", "60", "'2'", "\"3\""] {
        let source = SOURCE.replace(
            "    steps:\n",
            &format!("    timeout-minutes: {value}\n    steps:\n"),
        );
        compile(&source, &Limits::DEFAULT).unwrap();
    }
    assert!(TimeoutMinutes::from_minutes(0).is_none());
    assert_eq!(TimeoutMinutes::from_minutes(1).unwrap().seconds(), 60);
    assert_eq!(TimeoutMinutes::from_minutes(60).unwrap().seconds(), 3600);
    assert!(TimeoutMinutes::from_minutes(61).is_none());
}

#[test]
fn wrong_shapes_and_duplicate_caps_refuse_the_complete_graph() {
    for extra in [
        "    timeout-minutes:\n      minutes: 1\n",
        "    timeout-minutes:\n      - 1\n",
        "    timeout-minutes: 1\n    timeout-minutes: 2\n",
    ] {
        let source = SOURCE.replace("    steps:\n", &format!("{extra}    steps:\n"));
        assert!(compile(&source, &Limits::DEFAULT).is_err());
    }
    let source = format!("{SOURCE}        timeout-minutes: 1\n        timeout-minutes: 2\n");
    assert!(matches!(
        compile(&source, &Limits::DEFAULT),
        Err(WorkflowRefusal::DuplicateKey { .. })
    ));
    let source = format!(
        "{SOURCE}  later:\n    runs-on: fgit-trusted-local\n    timeout-minutes: 0\n    steps:\n      - run: forbidden\n"
    );
    assert!(compile(&source, &Limits::DEFAULT).is_err());
}

#[test]
fn quoted_caps_and_field_order_normalize_without_losing_explicit_context() {
    let a = SOURCE.replace("    steps:\n", "    timeout-minutes: 5\n    steps:\n")
        + "        timeout-minutes: 2\n        env:\n          VALUE: exact\n        working-directory: src\n";
    let b = SOURCE.replace(
        "    runs-on: fgit-trusted-local\n",
        "    timeout-minutes: '5'\n    runs-on: fgit-trusted-local\n",
    ) + "        working-directory: src\n        env:\n          VALUE: exact\n        timeout-minutes: '2'\n";
    let a = compile(&a, &Limits::DEFAULT).unwrap().canonical_bytes();
    assert_eq!(a, compile(&b, &Limits::DEFAULT).unwrap().canonical_bytes());
    assert!(a.contains("step-env\tbuild\t0\tVALUE\texact\n"));
    assert!(a.contains("step-cwd\tbuild\t0\tsrc\n"));
}

#[test]
fn matrix_variants_each_retain_the_job_and_step_deadlines() {
    let source = SOURCE.replace("    steps:\n", "    timeout-minutes: 3\n    strategy:\n      fail-fast: false\n      matrix:\n        mode:\n          - debug\n          - release\n    steps:\n")
        + "        timeout-minutes: 1\n";
    let graph = compile(&source, &Limits::DEFAULT).unwrap();
    assert_eq!(graph.jobs.len(), 2);
    for job in &graph.jobs {
        assert!(job.matrix.is_some());
        assert_eq!(job.timeout_minutes.unwrap().minutes(), 3);
        assert_eq!(job.steps[0].timeout_minutes.unwrap().minutes(), 1);
    }
    assert!(graph.canonical_bytes().starts_with("fgit-workflow/v4\n"));
    assert_eq!(
        graph
            .canonical_bytes()
            .matches("job-timeout-minutes\t")
            .count(),
        2
    );
    assert_eq!(
        graph
            .canonical_bytes()
            .matches("step-timeout-minutes\t")
            .count(),
        2
    );
}
