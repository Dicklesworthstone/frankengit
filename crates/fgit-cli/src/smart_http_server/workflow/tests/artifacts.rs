//! The owned HTTP worker uses the same bounded artifact contract as foreground CI.
use super::*;
use crate::workflow_command::artifacts as shared;
use std::path::Path;

fn configured() -> Vec<String> {
    let mut arguments = server_arguments();
    arguments.extend([
        "--artifact-root".into(),
        "/private/artifacts".into(),
        "--workflow-artifact".into(),
        "ci/build.yml:build:out.bin".into(),
        "--workflow-artifact-input".into(),
        "ci/build.yml:test:build:out.bin:package.bin".into(),
    ]);
    arguments
}

#[test]
fn full_server_options_route_file_inputs_logs_and_finite_budgets() {
    let mut arguments = configured();
    arguments.extend([
        "--workflow-artifact-logs".into(),
        "--workflow-artifact-hex".into(),
        "63692fff2e796d6c:build__matrix_007:6f75742fff".into(),
        "--workflow-artifact-input-hex".into(),
        "63692fff2e796d6c:test:build__matrix_007:6f75742fff:696e2fff".into(),
        "--workflow-max-artifact-mib".into(),
        "3".into(),
        "--workflow-max-artifact-total-mib".into(),
        "7".into(),
        "--workflow-max-artifact-input-total-mib".into(),
        "5".into(),
    ]);
    let options = parse_server(&arguments).unwrap();
    assert!(options.workflow_service.is_some());
    assert_eq!(
        options.config.workflow_artifact_root(),
        Some(Path::new("/private/artifacts"))
    );
    let selected = vec![
        shared::selection("ci/build.yml:build:out.bin", false).unwrap(),
        shared::selection("63692fff2e796d6c:build__matrix_007:6f75742fff", true).unwrap(),
    ];
    let inputs = vec![
        shared::input_selection("ci/build.yml:test:build:out.bin:package.bin", false).unwrap(),
        shared::input_selection(
            "63692fff2e796d6c:test:build__matrix_007:6f75742fff:696e2fff",
            true,
        )
        .unwrap(),
    ];
    let flags = BTreeMap::from([
        ("--artifact-root", "/private/artifacts"),
        ("--workflow-artifact-logs", ""),
        ("--workflow-max-artifact-mib", "3"),
        ("--workflow-max-artifact-total-mib", "7"),
        ("--workflow-max-artifact-input-total-mib", "5"),
    ]);
    let contract = artifact_config(&flags, selected, inputs).unwrap().unwrap();
    assert_eq!(contract.root(), Path::new("/private/artifacts"));
    assert!(contract.capture_logs());
    assert_eq!(contract.maximum_bytes(), 3 * 1024 * 1024);
    assert_eq!(contract.total_bytes(), 7 * 1024 * 1024);
    assert_eq!(contract.input_total_bytes(), 5 * 1024 * 1024);
    assert_eq!(contract.selections().len(), 2);
    assert_eq!(contract.selections()[1].workflow_path(), b"ci/\xff.yml");
    assert_eq!(contract.selections()[1].output_path(), b"out/\xff");
    assert_eq!(contract.inputs().len(), 2);
    assert_eq!(contract.inputs()[1].destination(), b"in/\xff");
}

#[test]
fn foreground_defaults_and_download_only_roots_are_preserved() {
    let flags = BTreeMap::from([("--artifact-root", "/private/artifacts")]);
    assert!(
        artifact_config(&flags, Vec::new(), Vec::new())
            .unwrap()
            .is_none()
    );
    let selection = shared::selection("ci/build.yml:build:out.bin", false).unwrap();
    let input =
        shared::input_selection("ci/build.yml:test:build:out.bin:package.bin", false).unwrap();
    let contract = artifact_config(&flags, vec![selection.clone()], vec![input.clone()])
        .unwrap()
        .unwrap();
    let foreground = shared::options_with_inputs(&flags, vec![selection], vec![input])
        .unwrap()
        .unwrap()
        .node_config()
        .unwrap();
    assert_eq!(contract, foreground);
    assert!(!contract.capture_logs());
    assert_eq!(contract.maximum_bytes(), 16 * 1024 * 1024);
    assert_eq!(contract.total_bytes(), 64 * 1024 * 1024);
    assert_eq!(contract.input_total_bytes(), 64 * 1024 * 1024);
    assert!(parse_server(&configured()).is_ok());
}

#[test]
fn missing_capture_contract_unknown_flags_and_duplicate_values_refuse_before_io() {
    for extra in [
        vec!["--workflow-artifact", "ci/build.yml:build:out.bin"],
        vec!["--workflow-max-artifact-mib", "1"],
        vec![
            "--workflow-artifact-input",
            "ci/build.yml:test:build:out.bin:in",
        ],
        vec!["--workflow-artifact-input-hex", "broken"],
    ] {
        let mut arguments = server_arguments();
        arguments.extend(extra.iter().map(|arg| (*arg).to_owned()));
        assert!(parse_server(&arguments).is_err(), "{extra:?}");
    }
    for extra in [
        vec!["--workflow-artifact-log"],
        vec![
            "--workflow-max-artifact-mib",
            "1",
            "--workflow-max-artifact-mib",
            "2",
        ],
        vec!["--workflow-artifact-logs", "--workflow-artifact-logs"],
        vec!["--workflow-artifact-logs", "true"],
        vec!["--artifact", "ci/build.yml:build:out.bin"],
        vec!["--max-artifact-mib", "1"],
        vec![
            "--workflow-artifact-hex",
            "63692f6275696c642e796d6c:build:6f75742e62696e",
        ],
        vec![
            "--workflow-artifact-input",
            "ci/build.yml:test:build:out.bin:package.bin/overlap",
        ],
    ] {
        let mut arguments = configured();
        arguments.extend(extra.iter().map(|arg| (*arg).to_owned()));
        assert!(parse_server(&arguments).is_err(), "{extra:?}");
    }
    let mut without_service = vec![
        "state".into(),
        "11".repeat(16),
        "22".repeat(16),
        "127.0.0.1:0".into(),
        "--trusted-local".into(),
        "--credentials-file".into(),
        "/private/credentials".into(),
        "--artifact-root".into(),
        "/private/artifacts".into(),
    ];
    assert!(
        parse_server(&without_service)
            .unwrap()
            .workflow_service
            .is_none()
    );
    without_service.extend([
        "--workflow-artifact".into(),
        "ci/build.yml:build:out.bin".into(),
    ]);
    assert!(parse_server(&without_service).is_err());
}

#[test]
fn numeric_envelopes_path_safety_and_selection_counts_match_foreground_ci() {
    for (flag, maximum) in [
        ("--workflow-max-artifact-mib", 64),
        ("--workflow-max-artifact-total-mib", 512),
        ("--workflow-max-artifact-input-total-mib", 512),
    ] {
        for value in [
            "0".to_owned(),
            "01".into(),
            "+1".into(),
            "1.5".into(),
            (maximum + 1).to_string(),
        ] {
            let mut arguments = configured();
            arguments.extend([flag.into(), value.clone()]);
            assert!(parse_server(&arguments).is_err(), "{flag}={value}");
        }
        for value in [1, maximum] {
            let mut arguments = configured();
            arguments.extend([flag.into(), value.to_string()]);
            assert!(parse_server(&arguments).is_ok(), "{flag}={value}");
        }
    }
    for selection in [
        "ci/build.yml:build:../outside",
        "ci/build.yml:build:/outside",
        "ci/build.yml:build:.fgit-host-receipt",
        "ci/build.yml::out",
        "ci/build.yml:bad job:out",
    ] {
        let mut arguments = configured();
        arguments.extend(["--workflow-artifact".into(), selection.into()]);
        assert!(parse_server(&arguments).is_err(), "{selection}");
    }
    let mut outputs = server_arguments();
    outputs.extend(["--artifact-root".into(), "/private/artifacts".into()]);
    for index in 0..64 {
        outputs.extend([
            "--workflow-artifact".into(),
            format!("ci/build.yml:build:out-{index}"),
        ]);
    }
    assert!(parse_server(&outputs).is_ok());
    outputs.extend([
        "--workflow-artifact".into(),
        "ci/build.yml:build:out-64".into(),
    ]);
    assert!(parse_server(&outputs).is_err());
    let mut inputs = server_arguments();
    inputs.extend([
        "--artifact-root".into(),
        "/private/artifacts".into(),
        "--workflow-artifact".into(),
        "ci/build.yml:build:out.bin".into(),
    ]);
    for index in 0..64 {
        inputs.extend([
            "--workflow-artifact-input".into(),
            format!("ci/build.yml:test:build:out.bin:copy-{index}"),
        ]);
    }
    assert!(parse_server(&inputs).is_ok());
    inputs.extend([
        "--workflow-artifact-input".into(),
        "ci/build.yml:test:build:out.bin:copy-64".into(),
    ]);
    assert!(parse_server(&inputs).is_err());
}
