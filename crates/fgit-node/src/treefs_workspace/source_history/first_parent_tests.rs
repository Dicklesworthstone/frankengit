use super::*;
use fgit_forge::history::first_parent::FirstParentCursor;
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, GitHashAlgorithm};

#[test]
fn native_pages_are_read_only_and_revalidate_the_first_parent_cursor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_scratch, node, tip, other_tip) = super::super::super::tests::fixture(format, false);
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let query = FirstParentOptions {
            limit: 1,
            limits: HistoryLimits {
                max_commits: 1,
                ..HistoryLimits::default()
            },
            ..FirstParentOptions::default()
        };
        let request = node.request_context();
        let (head, first) = node
            .runtime()
            .block_on(node.read_first_parent_history_in(
                &request,
                &reference,
                &RefVisibility::new(),
                None,
                &query,
            ))
            .unwrap();
        assert_eq!(first.tip, tip);
        assert_eq!(first.commits[0].id, tip);
        assert_eq!(first.visited_commits, 1);
        assert!(!first.root_reached);
        let cursor = first.continuation(head, &reference).unwrap();
        let mut next = FirstParentOptions {
            cursor: Some(cursor.clone()),
            ..query.clone()
        };
        assert!(matches!(
            node.runtime().block_on(node.read_first_parent_history_in(
                &request, &reference, &RefVisibility::new(), None, &next,
            )),
            Err(NodeHistoryRefusal::History(error)) if *error == HistoryError::Budget("commits")
        ));
        next.limits.max_commits = 2;
        let (same_head, last) = node
            .runtime()
            .block_on(node.read_first_parent_history_in(
                &request,
                &reference,
                &RefVisibility::new(),
                None,
                &next,
            ))
            .unwrap();
        assert_eq!(same_head, head);
        assert_eq!(last.commits[0].id, first.commits[0].parents[0]);
        assert_ne!(last.commits[0].id, other_tip);
        assert_eq!(last.visited_commits, 2);
        assert!(last.root_reached);
        assert_eq!(last.next_after, None);
        assert_eq!(last.continuation(head, &reference), None);

        // Neither a substituted visible ref nor another admitted branch tip
        // can turn an offset token into an arbitrary object-read capability.
        let other_ref = RefName::try_new(b"refs/heads/topic").unwrap();
        assert!(matches!(
            node.runtime().block_on(node.read_first_parent_history_in(
                &request, &other_ref, &RefVisibility::new(), None, &next,
            )),
            Err(NodeHistoryRefusal::History(error)) if *error == HistoryError::InvalidOptions
        ));
        next.cursor.as_mut().unwrap().tip = other_tip;
        assert!(matches!(
            node.runtime().block_on(node.read_first_parent_history_in(
                &request, &reference, &RefVisibility::new(), None, &next,
            )),
            Err(NodeHistoryRefusal::History(error)) if *error == HistoryError::InvalidOptions
        ));
        next.cursor = Some(cursor);
        let wrong_head = RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithmId::try_new(1).unwrap(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[123; 32]).unwrap(),
        );
        assert!(matches!(
            node.runtime().block_on(node.read_first_parent_history_in(
                &request,
                &reference,
                &RefVisibility::new(),
                Some(wrong_head),
                &next,
            )),
            Err(NodeHistoryRefusal::SnapshotMoved)
        ));
        next.cursor.as_mut().unwrap().source_head = wrong_head;
        assert!(matches!(
            node.runtime().block_on(node.read_first_parent_history_in(
                &request,
                &reference,
                &RefVisibility::new(),
                None,
                &next,
            )),
            Err(NodeHistoryRefusal::SnapshotMoved)
        ));
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis()
                .id(),
            head
        );
        node.shutdown().unwrap();
    }
}

#[test]
fn hidden_missing_cancelled_and_malformed_queries_refuse_without_an_empty_result() {
    let (_scratch, node, _, _) = super::super::super::tests::fixture(GitHashAlgorithm::Sha1, false);
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = FirstParentOptions {
        limit: 1,
        ..FirstParentOptions::default()
    };
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(reference.as_bytes(), &fgit_wire::WireLimits::default())
        .unwrap();
    let request = node.request_context();
    for (reference, visibility) in [
        (reference.clone(), hidden),
        (
            RefName::try_new(b"refs/heads/missing").unwrap(),
            RefVisibility::new(),
        ),
    ] {
        assert!(matches!(
            node.runtime().block_on(node.read_first_parent_history_in(
                &request,
                &reference,
                &visibility,
                None,
                &query,
            )),
            Err(NodeHistoryRefusal::Unavailable)
        ));
    }
    let (head, page) = node
        .runtime()
        .block_on(node.read_first_parent_history_in(
            &request,
            &reference,
            &RefVisibility::new(),
            None,
            &query,
        ))
        .unwrap();
    let mut bad = query.clone();
    bad.cursor = Some(FirstParentCursor {
        source_head: head,
        reference: reference.clone(),
        tip: page.tip,
        after: 0,
    });
    assert!(matches!(
        node.runtime().block_on(node.read_first_parent_history_in(
            &request, &reference, &RefVisibility::new(), None, &bad,
        )),
        Err(NodeHistoryRefusal::History(error)) if *error == HistoryError::InvalidOptions
    ));
    request.cancel();
    assert!(
        node.runtime()
            .block_on(node.read_first_parent_history_in(
                &request,
                &reference,
                &RefVisibility::new(),
                None,
                &query,
            ))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.read_first_parent_history_in(
                &node.request_context(),
                &reference,
                &RefVisibility::new(),
                None,
                &query,
            ))
            .is_ok()
    );
    node.shutdown().unwrap();
}

#[test]
fn a_real_authority_advance_invalidates_the_original_cursor_even_when_the_ref_is_unchanged() {
    use fgit_admission::AdmissionLimits;
    use fgit_authority::IdempotencyKey;
    use fgit_forge::event::issue::{IssueAction, IssueCommand};
    use fgit_forge::{ExpectedVersion, IssueNumber};
    use fgit_types::{DecisionOutcome, PrincipalId};

    let (_scratch, node, _, _) = super::super::super::tests::fixture(GitHashAlgorithm::Sha1, false);
    let reference = RefName::try_new(b"refs/heads/main").unwrap();
    let query = FirstParentOptions {
        limit: 1,
        ..FirstParentOptions::default()
    };
    let request = node.request_context();
    let (head, first) = node
        .runtime()
        .block_on(node.read_first_parent_history_in(
            &request,
            &reference,
            &RefVisibility::new(),
            None,
            &query,
        ))
        .unwrap();
    let continuation = FirstParentOptions {
        cursor: first.continuation(head, &reference),
        ..query
    };
    let command = IssueCommand {
        number: IssueNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: IssueAction::Open {
            title: "move authority".into(),
            body: String::new(),
            labels: vec![],
        },
    };
    let session = crate::LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([7; 16]),
        IdempotencyKey::new(b"first-parent-head-change".to_vec()).unwrap(),
    );
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_issue_durable_in(
            &node.request_context(),
            &session,
            &command,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    assert!(matches!(
        node.runtime().block_on(node.read_first_parent_history_in(
            &node.request_context(),
            &reference,
            &RefVisibility::new(),
            None,
            &continuation,
        )),
        Err(NodeHistoryRefusal::SnapshotMoved)
    ));
    let (new_head, reopened) = node
        .runtime()
        .block_on(node.read_first_parent_history_in(
            &node.request_context(),
            &reference,
            &RefVisibility::new(),
            None,
            &query,
        ))
        .unwrap();
    assert_ne!(new_head, head);
    assert_eq!(reopened.tip, first.tip);
    node.shutdown().unwrap();
}

#[test]
fn recent_native_history_above_4096_commits_succeeds_without_raising_the_dag_limit() {
    use fgit_admission::{
        AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
        SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
        validate_source_import,
    };
    use fgit_authority::IdempotencyKey;
    use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch(std::env::temp_dir().join(format!(
            "fg-first-parent-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let (mut node, _) = OneNode::init(
            crate::NodeConfig::new(
                scratch.0.clone(),
                TenantId::from_bytes([0xa1; 16]),
                RepositoryId::from_bytes([0xa2; 16]),
            )
            .with_object_format(format)
            .with_worker_threads(2),
        )
        .unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let tree = node
            .put_git_object(ObjectType::Tree, Vec::new())
            .unwrap()
            .identity();
        let mut ids = BTreeSet::from([tree]);
        let mut parents = Vec::new();
        let mut tip = tree;
        for index in 0..4097 {
            let mut body = format!("tree {tree}\n");
            if let Some(parent) = parents.last() {
                body.push_str(&format!("parent {parent}\n"));
            }
            body.push_str(&format!(
                "author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\ncommit {index}"
            ));
            tip = node
                .put_git_object(ObjectType::Commit, body.into_bytes())
                .unwrap()
                .identity();
            ids.insert(tip);
            parents.push(tip);
        }
        let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
        let reference = RefName::try_new(b"refs/heads/main").unwrap();
        let updates = [SourceRefUpdate {
            old: zero,
            new: tip,
            ref_name: reference.as_bytes().to_vec(),
        }];
        let receipt = SourceImportReceipt {
            object_format: format,
            object_count: u32::try_from(ids.len()).unwrap(),
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        };
        let closure = ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                ids.clone(),
            ))
            .unwrap(),
            objects: ids,
        };
        let imported = validate_source_import(&updates, &receipt, closure).unwrap();
        let context = AdmissionContext {
            head_key: node.head_key.clone(),
            tenant_id: node.tenant_id,
            repository_id: node.repository_id,
            principal_id: PrincipalId::from_bytes([0xa3; 16]),
            idempotency_key: IdempotencyKey::new(b"long-first-parent".to_vec()).unwrap(),
            object_format: format,
        };
        let result = node
            .runtime()
            .block_on(node.admit_validated_source_import_durable_in(
                &node.request_context(),
                &context,
                &imported,
                AdmissionLimits::default(),
            ))
            .unwrap();
        assert!(
            result.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let old = node.runtime().block_on(node.read_commit_history_in(
            &node.request_context(),
            &reference,
            &RefVisibility::new(),
            None,
            LogOptions {
                limit: 1,
                ..LogOptions::default()
            },
        ));
        assert!(
            matches!(old, Err(NodeHistoryRefusal::History(error)) if *error == HistoryError::Budget("commits"))
        );
        let query = FirstParentOptions {
            limit: 2,
            limits: HistoryLimits {
                max_commits: 2,
                ..HistoryLimits::default()
            },
            ..FirstParentOptions::default()
        };
        let (head, page) = node
            .runtime()
            .block_on(node.read_first_parent_history_in(
                &node.request_context(),
                &reference,
                &RefVisibility::new(),
                None,
                &query,
            ))
            .unwrap();
        assert_eq!(
            page.commits
                .iter()
                .map(|commit| commit.id)
                .collect::<Vec<_>>(),
            [tip, parents[4095]]
        );
        assert_eq!(page.visited_commits, 2);
        assert_eq!(page.next_after, Some(2));
        assert!(!page.root_reached);
        let continuation = FirstParentOptions {
            cursor: page.continuation(head, &reference),
            limit: 2,
            limits: HistoryLimits {
                max_commits: 4,
                ..HistoryLimits::default()
            },
        };
        let (_, next) = node
            .runtime()
            .block_on(node.read_first_parent_history_in(
                &node.request_context(),
                &reference,
                &RefVisibility::new(),
                None,
                &continuation,
            ))
            .unwrap();
        assert_eq!(next.commits[0].id, parents[4094]);
        assert_eq!(next.visited_commits, 4);
        node.shutdown().unwrap();
    }
}
