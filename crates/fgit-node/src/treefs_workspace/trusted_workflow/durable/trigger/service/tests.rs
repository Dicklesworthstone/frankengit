use super::*;
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
use fgit_types::{RepositoryId, TenantId};

fn config(reference: &[u8]) -> io::Result<WorkflowWatchConfig> {
    WorkflowWatchConfig::try_new(
        GitHashAlgorithm::Sha256,
        RefName::try_new(reference).unwrap(),
        b"ci".to_vec(),
        PathBuf::from("/private/workflow-runs"),
        vec![b"ci".to_vec()],
        Duration::from_millis(20),
    )
}

fn candidate() -> PullRequestMergeWatchConfig {
    PullRequestMergeWatchConfig::try_new(
        RefName::try_new(b"refs/heads/ci/pr-7").unwrap(),
        PrincipalId::from_bytes([3; 16]),
        MergeMetadata {
            author: "CI <ci@example.test>".into(),
            committer: "CI <ci@example.test>".into(),
            timestamp: 1_700_000_000,
            message: b"Check the merged tree\n".to_vec(),
        },
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap()
}

#[test]
fn ordinary_service_selection_accepts_exact_branch_and_tag_bytes_only() {
    for reference in [
        b"refs/heads/main".as_slice(),
        b"refs/tags/releases/v1",
        b"refs/tags/\xff",
    ] {
        let config = config(reference).unwrap();
        assert_eq!(config.reference().as_bytes(), reference);
        assert!(config.validate().is_ok());
        assert!(config.publisher().is_none());
        assert!(config.pull_request().is_none());
        assert!(config.pull_requests().is_none());
        assert!(config.merge_queue().is_none());
        assert!(config.merge_candidate().is_none());
    }
    for reference in [
        b"refs/notes/review".as_slice(),
        b"refs/remotes/origin/main",
        b"refs/heads-other/main",
        b"refs/tags-other/v1",
    ] {
        assert_eq!(
            config(reference).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn tags_refuse_pr_collection_queue_and_candidate_builders_with_or_without_publisher() {
    let tag = config(b"refs/tags/v1").unwrap();
    for selection in [
        tag.clone(),
        tag.with_publisher(PrincipalId::from_bytes([7; 16])),
    ] {
        assert!(selection.clone().with_pull_request(7).is_err());
        assert!(selection.clone().with_pull_requests(16).is_err());
        assert!(selection.clone().with_merge_queue(3).is_err());
        assert!(selection.with_merge_candidate(candidate()).is_err());
    }
}

#[test]
fn tag_publisher_refusal_does_not_depend_on_builder_order() {
    let tag = config(b"refs/tags/v1").unwrap();
    let publisher = PrincipalId::from_bytes([7; 16]);
    for selection in [
        tag.clone()
            .with_publisher(publisher)
            .with_attempt_timeout(Duration::from_secs(30))
            .unwrap(),
        tag.with_attempt_timeout(Duration::from_secs(30))
            .unwrap()
            .with_publisher(publisher),
    ] {
        let error = selection.validate().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("tag workflow service"));
    }
}

#[test]
fn branch_publication_and_selectors_remain_composable_in_either_publisher_order() {
    let publisher = PrincipalId::from_bytes([7; 16]);
    for publisher_first in [false, true] {
        let mut branch = config(b"refs/heads/main").unwrap();
        if publisher_first {
            branch = branch.with_publisher(publisher);
        }
        for selection in [
            Ok(branch.clone()),
            branch.clone().with_pull_request(7),
            branch.clone().with_pull_requests(16),
            branch
                .with_merge_queue(3)
                .and_then(|config| config.with_merge_candidate(candidate())),
        ] {
            let mut selection = selection.unwrap();
            if !publisher_first {
                selection = selection.with_publisher(publisher);
            }
            assert!(selection.validate().is_ok());
            assert_eq!(selection.publisher(), Some(publisher));
        }
    }
    let incomplete_queue = config(b"refs/heads/main")
        .unwrap()
        .with_merge_queue(3)
        .unwrap();
    assert!(incomplete_queue.validate().is_err());
}

#[test]
fn invalid_tag_publication_refuses_before_opening_node_or_readiness() {
    let root = std::env::temp_dir().join(format!(
        "fgit-invalid-tag-workflow-service-{}",
        std::process::id()
    ));
    assert!(!root.exists());
    let mut config = config(b"refs/tags/v1")
        .unwrap()
        .with_publisher(PrincipalId::from_bytes([7; 16]));
    config.run_parent = root.join("runs");
    let node = NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
    );
    let ready = std::cell::Cell::new(false);
    let error = run_service_with_ready(node, config, WorkflowWatchControl::default(), || {
        ready.set(true);
        Ok(())
    })
    .unwrap_err();
    assert!(matches!(error, WorkflowWatchError::Configuration(_)));
    assert!(!ready.get());
    assert!(!root.exists());
}

#[test]
fn automatic_queue_landing_is_disabled_until_separately_configured() {
    let publisher = PrincipalId::from_bytes([7; 16]);
    let lander = PrincipalId::from_bytes([8; 16]);
    let queue = config(b"refs/heads/main")
        .unwrap()
        .with_merge_queue(3)
        .unwrap()
        .with_merge_candidate(candidate())
        .unwrap()
        .with_publisher(publisher);
    assert!(queue.validate().is_ok());
    assert!(queue.landing_principal().is_none());
    assert!(
        config(b"refs/heads/main")
            .unwrap()
            .landing_principal()
            .is_none()
    );

    for landing_first in [false, true] {
        let mut configured = config(b"refs/heads/main").unwrap();
        if landing_first {
            configured = configured.with_landing_principal(lander);
        }
        configured = configured
            .with_publisher(publisher)
            .with_merge_queue(3)
            .unwrap()
            .with_merge_candidate(candidate())
            .unwrap();
        if !landing_first {
            configured = configured.with_landing_principal(lander);
        }
        assert!(configured.validate().is_ok());
        assert_eq!(configured.landing_principal(), Some(lander));
        assert_eq!(configured.publisher(), Some(publisher));
        assert_eq!(
            configured.merge_candidate().unwrap().principal(),
            PrincipalId::from_bytes([3; 16])
        );
    }
}

#[test]
fn incomplete_queue_landing_refuses_before_opening_node_or_readiness() {
    let publisher = PrincipalId::from_bytes([7; 16]);
    let lander = PrincipalId::from_bytes([8; 16]);
    let branch = config(b"refs/heads/main").unwrap();
    let cases = [
        branch.clone(),
        branch.clone().with_publisher(publisher),
        branch
            .clone()
            .with_merge_queue(3)
            .unwrap()
            .with_publisher(publisher),
        branch
            .clone()
            .with_merge_queue(3)
            .unwrap()
            .with_merge_candidate(candidate())
            .unwrap(),
        branch
            .clone()
            .with_pull_request(7)
            .unwrap()
            .with_merge_candidate(candidate())
            .unwrap()
            .with_publisher(publisher),
        branch
            .with_pull_requests(16)
            .unwrap()
            .with_publisher(publisher),
        config(b"refs/tags/v1").unwrap(),
    ];
    for (index, selection) in cases.into_iter().enumerate() {
        let root = std::env::temp_dir().join(format!(
            "fgit-invalid-queue-landing-service-{}-{index}",
            std::process::id()
        ));
        assert!(!root.exists());
        let mut selection = selection.with_landing_principal(lander);
        selection.run_parent = root.join("runs");
        let node = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([1; 16]),
            RepositoryId::from_bytes([2; 16]),
        );
        let ready = std::cell::Cell::new(false);
        let error =
            run_service_with_ready(node, selection, WorkflowWatchControl::default(), || {
                ready.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(
            matches!(error, WorkflowWatchError::Configuration(_)),
            "{index}"
        );
        assert!(!ready.get(), "{index}");
        assert!(!root.exists(), "{index}");
    }
}
