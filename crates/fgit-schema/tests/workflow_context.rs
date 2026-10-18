#![forbid(unsafe_code)]
use fgit_schema::workflow::{ContextRefusal, Limits, StepContext, WorkflowRefusal, compile};

fn workflow(step: &str) -> String {
    format!(
        "name: context\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: echo sample\n{step}"
    )
}
fn graph(step: &str) -> fgit_schema::workflow::WorkflowGraph {
    compile(&workflow(step), &Limits::default()).unwrap()
}

#[test]
fn literals_are_sorted_and_bound_without_changing_default_v1_bytes() {
    let original = graph("").canonical_bytes();
    assert!(original.starts_with("fgit-workflow/v1\n"));
    assert_eq!(
        graph("        working-directory: .\n").canonical_bytes(),
        original
    );
    assert_eq!(
        graph("        working-directory: ./\n").canonical_bytes(),
        original
    );
    let first = graph(
        "        env:\n          Z: '01'\n          A: '$HOME; $(echo literal)'\n          B: true\n        working-directory: ./src/build\n",
    );
    let step = &first.jobs[0].steps[0];
    assert_eq!(step.context.working_directory(), Some("src/build"));
    assert_eq!(step.context.environment()["A"], "$HOME; $(echo literal)");
    assert_eq!(step.context.environment()["B"], "true");
    assert_eq!(step.context.environment()["Z"], "01");
    let encoded = first.canonical_bytes();
    assert!(encoded.starts_with("fgit-workflow/v2\n"));
    assert!(encoded.contains("step-env\tbuild\t0\tA\t$HOME; $(echo literal)\n"));
    assert!(encoded.contains("step-cwd\tbuild\t0\tsrc/build\n"));
    assert_eq!(encoded, graph("        working-directory: src/build\n        env:\n          A: '$HOME; $(echo literal)'\n          Z: '01'\n          B: true\n").canonical_bytes());
    for changed in [
        "        env:\n          A: one\n",
        "        env:\n          A: two\n",
        "        working-directory: src\n",
    ] {
        assert_ne!(graph(changed).canonical_bytes(), original);
    }
    assert_ne!(
        graph("        env:\n          A: one\n").canonical_bytes(),
        graph("        env:\n          A: two\n").canonical_bytes()
    );
}

#[test]
fn malformed_contexts_refuse_at_a_source_span_without_echoing_values() {
    for step in [
        "        env: scalar\n",
        "        env:\n          VALUE:\n            nested: no\n",
        "        env:\n          1NAME: value\n",
        "        env:\n          BAD-NAME: value\n",
        "        env:\n          VALUE: '${{ secrets.VALUE }}'\n",
        "        env:\n          LD_PRELOAD: do-not-echo-this\n",
        "        env:\n          BASH_ENV: do-not-echo-this\n",
        "        env:\n          GITHUB_TOKEN: do-not-echo-this\n",
        "        env:\n          VALUE: first\n          VALUE: second\n",
        "        working-directory: /tmp\n",
        "        working-directory: ../outside\n",
        "        working-directory: src/../outside\n",
        "        working-directory: src//child\n",
        "        working-directory: '${{ matrix.path }}'\n",
        "        working-directory:\n          nested: no\n",
    ] {
        let text = workflow(step);
        let error = compile(&text, &Limits::default()).unwrap_err();
        assert!(!error.span().is_empty(), "{error:?}");
        assert!(!error.to_string().contains("do-not-echo-this"));
    }
    assert!(
        compile(
            &workflow(
                "        env:\n          VALUE: literal\n        working-directory: src/child\n"
            ),
            &Limits::default()
        )
        .is_ok()
    );
}

#[test]
fn typed_context_limits_have_exact_permitted_twins() {
    let entries = (0..64)
        .map(|i| (format!("V{i}"), String::new()))
        .collect::<Vec<_>>();
    assert!(StepContext::new(entries.clone(), None).is_ok());
    let mut over = entries;
    over.push(("EXTRA".into(), String::new()));
    assert_eq!(StepContext::new(over, None), Err(ContextRefusal::Entries));
    assert!(StepContext::new(vec![("V".repeat(64), "x".repeat(8192))], None).is_ok());
    assert_eq!(
        StepContext::new(vec![("V".repeat(65), "x".into())], None),
        Err(ContextRefusal::Name)
    );
    assert_eq!(
        StepContext::new(vec![("V".into(), "x".repeat(8193))], None),
        Err(ContextRefusal::Value)
    );
    let exact = (0..8)
        .map(|i| (format!("V{i}"), "x".repeat(8190)))
        .collect::<Vec<_>>();
    assert!(StepContext::new(exact.clone(), None).is_ok());
    let mut over = exact;
    over[0].1.push('x');
    assert_eq!(StepContext::new(over, None), Err(ContextRefusal::Bytes));
    assert_eq!(
        StepContext::new(
            vec![("V".into(), "one".into()), ("V".into(), "two".into())],
            None
        ),
        Err(ContextRefusal::DuplicateName)
    );
    for value in ["a\0b", "${{ env.A }}"] {
        assert_eq!(
            StepContext::new(vec![("V".into(), value.into())], None),
            Err(ContextRefusal::Value)
        );
    }
    assert!(StepContext::new(Vec::new(), Some("a".repeat(1024))).is_ok());
    assert_eq!(
        StepContext::new(Vec::new(), Some("a".repeat(1025))),
        Err(ContextRefusal::WorkingDirectory)
    );
    for value in [
        "", "..", "src/..", "/abs", "x\\y", "C:drive", "a\nb", "././src",
    ] {
        assert_eq!(
            StepContext::new(Vec::new(), Some(value.into())),
            Err(ContextRefusal::WorkingDirectory)
        );
    }
}

#[test]
fn environments_are_not_promoted_to_workflow_or_job_inheritance() {
    let top = format!("env:\n  VALUE: shared\n{}", workflow(""));
    assert!(matches!(
        compile(&top, &Limits::default()),
        Err(WorkflowRefusal::ConstructUnsupported {
            construct: "workflow.env",
            ..
        })
    ));
    let job = workflow("").replace("    steps:", "    env:\n      VALUE: shared\n    steps:");
    assert!(compile(&job, &Limits::default()).is_err());
    let literal = graph("        env:\n          VALUE: 'a\\tb'\n").canonical_bytes();
    let tab = graph("        env:\n          VALUE: \"a\\tb\"\n").canonical_bytes();
    assert_ne!(literal, tab);
    assert_eq!(
        literal
            .lines()
            .filter(|line| line.starts_with("step-env\t"))
            .count(),
        1
    );
    assert_eq!(
        tab.lines()
            .filter(|line| line.starts_with("step-env\t"))
            .count(),
        1
    );
}

#[test]
fn construct_artifact_matches_the_real_native_emitter() {
    assert_eq!(
        fgit_schema::emit::workflow_registry(),
        include_str!("../generated/workflow-constructs.json")
    );
}
