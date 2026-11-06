use super::*;
use crate::treefs_workspace::TrustedWorkflowArtifactInput;

fn input(destination: &[u8]) -> TrustedWorkflowRetainedArtifactInput {
    TrustedWorkflowRetainedArtifactInput::new(
        b"workflow.yml",
        "test",
        digest(b"manifest"),
        digest(b"output"),
        b"out",
        destination,
    )
    .unwrap()
}
fn config(
    inputs: Vec<TrustedWorkflowRetainedArtifactInput>,
) -> Result<TrustedWorkflowArtifactConfig, &'static str> {
    TrustedWorkflowArtifactConfig::new_with_retained_inputs(
        "/operator/store".into(),
        Vec::new(),
        1024,
        4096,
        false,
        inputs,
        4096,
    )
}

#[test]
fn retained_input_contract_is_exact_bounded_and_does_not_require_new_capture() {
    let contract = config(vec![input(b"tool")]).unwrap();
    assert!(contract.selections().is_empty());
    assert!(!contract.capture_logs());
    assert!(contract.inputs().is_empty());
    assert_eq!(contract.retained_inputs().len(), 1);
    assert!(contract.has_inputs());
    let identity = contract.to_json();
    assert!(identity.contains("\"retained_input_delivery\":"));
    assert!(identity.contains("\"producer_success_required\":false"));
    assert!(!identity.contains("\"input_delivery\":"));
    let original = input(b"tool");
    for changed in [
        TrustedWorkflowRetainedArtifactInput::new(
            b"other.yml",
            "test",
            original.manifest_id,
            original.artifact_id,
            b"out",
            b"tool",
        ),
        TrustedWorkflowRetainedArtifactInput::new(
            b"workflow.yml",
            "other",
            original.manifest_id,
            original.artifact_id,
            b"out",
            b"tool",
        ),
        TrustedWorkflowRetainedArtifactInput::new(
            b"workflow.yml",
            "test",
            digest(b"other-manifest"),
            original.artifact_id,
            b"out",
            b"tool",
        ),
        TrustedWorkflowRetainedArtifactInput::new(
            b"workflow.yml",
            "test",
            original.manifest_id,
            digest(b"other-artifact"),
            b"out",
            b"tool",
        ),
        TrustedWorkflowRetainedArtifactInput::new(
            b"workflow.yml",
            "test",
            original.manifest_id,
            original.artifact_id,
            b"other",
            b"tool",
        ),
        TrustedWorkflowRetainedArtifactInput::new(
            b"workflow.yml",
            "test",
            original.manifest_id,
            original.artifact_id,
            b"out",
            b"other",
        ),
    ] {
        assert_ne!(identity, config(vec![changed.unwrap()]).unwrap().to_json());
    }
    assert!(config(Vec::new()).is_err());
    for destination in [
        b"../escape".as_slice(),
        b"/escape",
        b".fgit-host-receipt",
        &[b'x'; 4001],
    ] {
        assert!(
            TrustedWorkflowRetainedArtifactInput::new(
                b"workflow.yml",
                "test",
                digest(b"m"),
                digest(b"a"),
                b"out",
                destination
            )
            .is_err()
        );
    }
    let short = Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&[1; 20]).unwrap(),
    );
    assert!(
        TrustedWorkflowRetainedArtifactInput::new(
            b"workflow.yml",
            "test",
            short,
            digest(b"a"),
            b"out",
            b"tool"
        )
        .is_err()
    );
}

#[test]
fn retained_and_dependency_inputs_share_collisions_counts_and_budget() {
    let capture = TrustedWorkflowArtifactSelection::new(b"workflow.yml", "build", b"out").unwrap();
    let create = |retained| {
        TrustedWorkflowArtifactConfig::new_with_retained_inputs(
            "/operator/store".into(),
            vec![capture.clone()],
            1024,
            4096,
            false,
            retained,
            2048,
        )
        .unwrap()
    };
    for destination in [b"tool".as_slice(), b"tool/child", b"tools/../tool"] {
        let retained = input(b"tool");
        let dependent = TrustedWorkflowArtifactInput::new(
            b"workflow.yml",
            "test",
            "build",
            b"out",
            destination,
        );
        assert!(
            dependent
                .and_then(|dependent| create(vec![retained]).with_inputs(vec![dependent], 2048))
                .is_err()
        );
    }
    for destination in [b"tool".as_slice(), b"tool/child"] {
        assert!(config(vec![input(b"tool"), input(destination)]).is_err());
    }
    let both = create(vec![input(b"tool")])
        .with_inputs(
            vec![
                TrustedWorkflowArtifactInput::new(
                    b"workflow.yml",
                    "test",
                    "build",
                    b"out",
                    b"fresh",
                )
                .unwrap(),
            ],
            1234,
        )
        .unwrap();
    assert_eq!(both.input_total_bytes(), 1234);
    assert_eq!(both.inputs().len(), 1);
    assert_eq!(both.retained_inputs().len(), 1);
    assert!(both.to_json().contains("\"total_delivery_bytes\":1234"));
    let many = (0..64)
        .map(|i| input(format!("input-{i}").as_bytes()))
        .collect();
    assert!(
        create(many)
            .with_inputs(
                vec![
                    TrustedWorkflowArtifactInput::new(
                        b"workflow.yml",
                        "test",
                        "build",
                        b"out",
                        b"fresh"
                    )
                    .unwrap()
                ],
                4096
            )
            .is_err()
    );
    let plan = WorkflowPlan::compile("name: jobs\non: push\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: true\n").unwrap();
    assert!(both.validate_workflow(b"workflow.yml", &plan).is_err());
}

#[test]
fn retained_identity_parser_keeps_qualified_rcr_and_refuses_malformed_metadata() {
    let expected = digest(b"rcr");
    let rcr = format!(
        "{}/v1.0/{}/{}",
        RepositoryCommitId::DOMAIN,
        expected.algorithm(),
        digest_hex(expected)
    );
    assert_eq!(source_identity(&rcr).unwrap(), Some(expected));
    for value in [
        rcr.replace("/v1.0/", "/v01.0/"),
        rcr.replace("frankengit/rcr/", "frankengit/other/"),
        rcr.replace("alg:", "hash:"),
        format!("{rcr}00"),
    ] {
        assert!(source_identity(&value).is_err(), "{value}");
    }
    let future = format!(
        "{}/v1.0/alg:65535/{}",
        RepositoryCommitId::DOMAIN,
        "ab".repeat(64)
    );
    assert_eq!(source_identity(&future).unwrap(), None);
}
