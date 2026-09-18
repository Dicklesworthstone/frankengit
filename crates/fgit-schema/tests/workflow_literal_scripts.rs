#![forbid(unsafe_code)]
use fgit_schema::workflow::{compile, Limits, WorkflowRefusal};

fn workflow(run: &str) -> String {
    format!("name: literal\non: push\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {run}\n")
}

#[test]
fn bare_literal_run_preserves_shell_comments_colons_tabs_and_internal_blank_lines() {
    let source = "name: literal\non: push\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: |\n          printf '# not yaml comment\\n'\n          value='a: b'\n\n          printf '\\t%s\\n' \"$value\"\n";
    let graph = compile(source, &Limits::default()).unwrap();
    assert_eq!(graph.jobs[0].steps[0].run,
        "printf '# not yaml comment\\n'\nvalue='a: b'\n\nprintf '\\t%s\\n' \"$value\"\n");
    assert!(graph.jobs[0].steps[0].span.start < graph.jobs[0].steps[0].span.end);
}

#[test]
fn literal_body_that_looks_like_yaml_stays_data_and_following_step_stays_syntax() {
    let source = "name: literal\non: push\njobs:\n  test:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: |\n          ---\n          key: value # shell data\n      - run: printf second\n";
    let graph = compile(source, &Limits::default()).unwrap();
    assert_eq!(graph.jobs[0].steps.len(), 2);
    assert_eq!(graph.jobs[0].steps[0].run, "---\nkey: value # shell data\n");
    assert_eq!(graph.jobs[0].steps[1].run, "printf second");
}

#[test]
fn literal_scalar_budget_is_checked_before_retaining_large_script() {
    let mut limits = Limits::default();
    limits.max_scalar_bytes = 8;
    let source = "name: x\non: push\njobs:\n  a:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: |\n          12345678\n";
    assert!(matches!(compile(source, &limits), Err(WorkflowRefusal::LimitExceeded { limit: "scalar bytes", .. })));
}

#[test]
fn folded_and_modified_block_scalars_remain_explicit_refusals() {
    for marker in [">", "|-", "|+", "|2", ">-"] {
        let input = workflow(marker);
        let error = compile(&input, &Limits::default()).unwrap_err();
        assert!(matches!(error, WorkflowRefusal::ConstructUnsupported { construct: "yaml.block-scalar", .. }));
    }
}
