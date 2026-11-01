use super::*;

fn selected(workflow: &[u8], inputs: &[&[u8]]) -> Result<Vec<TreePath>, TrustedWorkflowFailure> {
    validate_inputs(
        workflow,
        [1; 16],
        &std::env::temp_dir(),
        &inputs
            .iter()
            .map(|input| input.to_vec())
            .collect::<Vec<_>>(),
    )
}

#[test]
fn nested_inputs_are_normalized_disjoint_and_cover_the_selected_workflow() {
    let inputs = selected(
        b".github/workflows/component.yml",
        &[
            b"crates/component",
            b".github/workflows/component.yml",
            b"Cargo.toml",
        ],
    )
    .unwrap();
    assert_eq!(
        inputs.iter().map(TreePath::as_bytes).collect::<Vec<_>>(),
        [
            b".github/workflows/component.yml".as_slice(),
            b"Cargo.toml",
            b"crates/component",
        ]
    );
    for prefixes in [
        vec![b".github".as_slice(), b".github/workflows"],
        vec![b".github/workflows".as_slice(), b".github"],
        vec![
            b".github".as_slice(),
            b"crates",
            b"crates-old",
            b"crates/component",
        ],
        vec![b".github/workflows".as_slice(), b".github/workflows"],
        vec![b".github/workflows/../secret".as_slice()],
        vec![b".github//workflows".as_slice()],
        vec![b".github/workflows/".as_slice()],
    ] {
        assert!(
            selected(b".github/workflows/component.yml", &prefixes).is_err(),
            "{prefixes:?}"
        );
    }
    assert!(
        selected(
            b".github/workflows/component.yml",
            &[b".github/workflows-other"]
        )
        .is_err()
    );
    assert!(
        selected(
            b".github/workflows/component.yml",
            &[b".github/workflows/other.yml"]
        )
        .is_err()
    );
    assert!(
        selected(
            b"ci/run.yml",
            &[b"ci", b"crates/component", b"crates/component-old"]
        )
        .is_ok()
    );
    assert!(selected(b"ci/\xff.yml", &[b"ci/\xff.yml"]).is_ok());
}

#[test]
fn workflow_service_applies_the_same_narrow_prefix_contract() {
    use crate::WorkflowWatchConfig;
    let config = |inputs: &[&[u8]]| {
        WorkflowWatchConfig::try_new(
            Format::Sha1,
            RefName::try_new(b"refs/heads/main").unwrap(),
            b".github/workflows".to_vec(),
            std::env::temp_dir(),
            inputs.iter().map(|input| input.to_vec()).collect(),
            std::time::Duration::from_secs(1),
        )
    };
    assert!(config(&[b".github/workflows", b"crates/component"]).is_ok());
    assert!(config(&[b".github", b".github/workflows"]).is_err());
    assert!(
        config(&[b".github/workflows/a.yml"]).is_err(),
        "directory dispatch requires the whole declared workflow directory"
    );
}
