//! Real native tag admission, verified peeling, execution and event custody.
use super::super::trigger::TrustedRefWorkflowPoll;
use super::*;
use crate::LoopbackReceiveSession;
use crate::workflow_watch::{PullRequestMergeWatchConfig, WorkflowWatchConfig};
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
use fgit_forge::tags::{TagCommand, TagMetadata};
use std::time::Duration;

struct Fixture {
    temp: Temp,
    config: NodeConfig,
    node: Option<OneNode>,
    commit: GitOid,
    tree: GitOid,
    blob: GitOid,
}

fn reference(name: &[u8]) -> RefName {
    RefName::try_new(name).unwrap()
}

fn actor() -> PrincipalId {
    PrincipalId::from_bytes([0xd3; 16])
}

fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(), IdempotencyKey::new(key.to_vec()).unwrap())
}

impl Fixture {
    fn new(format: GitHashAlgorithm, event: &str, tail: &str) -> Self {
        let temp = Temp::new();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(temp.0.join("runs"))
            .unwrap();
        let source = temp.0.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(
            source.join("config"),
            match format {
                GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
                GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
            },
        )
        .unwrap();
        let workflow = format!(
            "name: native-tags\non: {event}\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf x >> '{}'; {tail}\n",
            temp.0.join("effects").display()
        );
        let blob = loose(
            &source,
            format,
            GitObjectKind::Blob,
            "blob",
            workflow.as_bytes(),
        );
        let directory = loose(
            &source,
            format,
            GitObjectKind::Tree,
            "tree",
            &[b"100644 build.yml\0".as_slice(), blob.as_bytes()].concat(),
        );
        let tree = loose(
            &source,
            format,
            GitObjectKind::Tree,
            "tree",
            &[b"40000 ci\0".as_slice(), directory.as_bytes()].concat(),
        );
        let commit = loose(
            &source,
            format,
            GitObjectKind::Commit,
            "commit",
            format!(
                "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nrelease source\n"
            )
            .as_bytes(),
        );
        fs::write(source.join("refs/heads/main"), format!("{commit}\n")).unwrap();
        let config = NodeConfig::new(
            temp.0.join("node"),
            TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        serve(&mut node);
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.command_request_context(None),
                &source,
                actor(),
                b"tag-workflow-fixture",
            ))
            .unwrap();
        assert!(
            imported.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        Self {
            temp,
            config,
            node: Some(node),
            commit,
            tree,
            blob,
        }
    }

    fn node(&self) -> &OneNode {
        self.node.as_ref().unwrap()
    }

    fn parent(&self) -> PathBuf {
        self.temp.0.join("runs")
    }

    fn effects(&self) -> String {
        fs::read_to_string(self.temp.0.join("effects")).unwrap_or_default()
    }

    fn head(&self) -> RepositoryAuthorityHeadId {
        let node = self.node();
        node.runtime()
            .block_on(node.materialize_admission_in(&node.command_request_context(None)))
            .unwrap()
            .basis()
            .id()
    }

    fn apply(&self, command: &TagCommand, key: &[u8]) {
        let node = self.node();
        let result = node
            .runtime()
            .block_on(node.admit_tag_durable_in(
                &node.command_request_context(None),
                &session(key),
                command,
                Default::default(),
            ))
            .unwrap();
        assert_eq!(result.commands.len(), 1);
        assert!(
            matches!(
                result.commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ),
            "{result:?}"
        );
    }

    fn lightweight(&self, name: &[u8], target: GitOid) -> GitOid {
        self.apply(
            &TagCommand::Lightweight {
                name: reference(name),
                target,
            },
            name,
        );
        target
    }

    fn annotated(&self, name: &[u8], target: GitOid, kind: GitObjectKind, version: u8) -> GitOid {
        let command = TagCommand::Annotated {
            name: reference(name),
            target,
            target_kind: kind,
            metadata: TagMetadata {
                tagger: "Release Author <release@example.invalid>".into(),
                timestamp: u64::from(version),
                message: format!("release annotation {version}\n").into_bytes(),
            },
        };
        let oid = command
            .prepare(self.commit.algorithm())
            .unwrap()
            .object
            .unwrap()
            .id;
        self.apply(&command, format!("create-{oid}").as_bytes());
        oid
    }

    fn delete(&self, name: &[u8], expected: GitOid) {
        self.apply(
            &TagCommand::Delete {
                name: reference(name),
                expected,
            },
            format!("delete-{expected}").as_bytes(),
        );
    }

    fn run(
        &self,
        name: &[u8],
        nonce: u8,
        expected: (Option<RepositoryAuthorityHeadId>, Option<GitOid>),
    ) -> Result<TrustedWorkflowRun, TrustedWorkflowFailure> {
        let node = self.node();
        node.runtime().block_on(node.run_trusted_workflow_in(
            &node.command_request_context(None),
            &reference(name),
            b"ci/build.yml",
            [nonce; 16],
            &self.parent(),
            &[b"ci".to_vec()],
            expected,
            limits(),
        ))
    }

    fn poll(
        &self,
        name: &[u8],
        limits: WorkflowLimits,
    ) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
        let node = self.node();
        node.runtime().block_on(node.poll_trusted_ref_workflows_in(
            &node.command_request_context(None),
            &reference(name),
            b"ci",
            &self.parent(),
            &[b"ci".to_vec()],
            limits,
            None,
        ))
    }

    fn reopen(&mut self) {
        self.node.take().unwrap().shutdown().unwrap();
        let mut node = OneNode::open_existing(self.config.clone()).unwrap();
        serve(&mut node);
        self.node = Some(node);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(node) = self.node.take() {
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn lightweight_annotated_and_nested_tags_execute_the_verified_commit_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(
            format,
            "\n  push:\n    tags:\n      - 'v*'",
            "printf release",
        );
        let lightweight = fixture.lightweight(b"refs/tags/v-light", fixture.commit);
        let annotated = fixture.annotated(
            b"refs/tags/v-annotated",
            fixture.commit,
            GitObjectKind::Commit,
            1,
        );
        let nested = fixture.annotated(b"refs/tags/v-nested", annotated, GitObjectKind::Tag, 2);
        assert_ne!(annotated, fixture.commit);
        assert_ne!(nested, annotated);
        let before = generation(fixture.node());
        for (index, (name, raw_tip)) in [
            (b"refs/tags/v-light".as_slice(), lightweight),
            (b"refs/tags/v-annotated".as_slice(), annotated),
            (b"refs/tags/v-nested".as_slice(), nested),
        ]
        .into_iter()
        .enumerate()
        {
            let run = fixture
                .run(
                    name,
                    u8::try_from(index + 1).unwrap(),
                    (None, Some(fixture.commit)),
                )
                .unwrap();
            assert!(run.succeeded(), "{}", run.to_json());
            assert_eq!(run.source_reference, name);
            assert_eq!(run.source_commit, fixture.commit);
            assert_eq!(run.source_tag_tip, Some(raw_tip));
            assert_eq!(run.source_tree, fixture.tree);
            assert_eq!(run.workflow_blob, fixture.blob);
            assert_eq!(
                run.execution.jobs[0].steps[0].observation.stdout,
                b"release"
            );
            assert!(run.artifact_contract.is_none());
            assert!(run.artifacts.is_empty());
            let poll = fixture.poll(name, limits()).unwrap();
            assert_eq!(poll.state(), "dispatched");
            assert!(poll.execution_settled());
            assert!(poll.dispatch().unwrap().succeeded());
            assert_eq!(
                poll.dispatch().unwrap().runs()[0].source_commit,
                fixture.commit
            );
            assert_eq!(
                poll.dispatch().unwrap().runs()[0].source_tag_tip,
                Some(raw_tip)
            );
            assert!(
                poll.dispatch()
                    .unwrap()
                    .to_json()
                    .contains(&format!("\"source_tag_tip\":\"{raw_tip}\""))
            );
            let event = fs::read_to_string(
                poll.dispatch()
                    .unwrap()
                    .run_directory
                    .parent()
                    .unwrap()
                    .join("event.json"),
            )
            .unwrap();
            assert!(
                event.contains("\"profile\":\"latest-canonical-tag-update-v1\""),
                "{event}"
            );
            assert!(
                event.contains(&format!("\"tag_tip\":\"{raw_tip}\"")),
                "{event}"
            );
            assert!(
                event.contains(&format!("\"commit\":\"{}\"", fixture.commit)),
                "{event}"
            );
            assert!(event.contains("\"previous_tag_tip\":null"), "{event}");
            assert!(!event.contains("\"previous_commit\""), "{event}");
            assert_eq!(
                fixture.poll(name, limits()).unwrap().state(),
                "previously_settled"
            );
        }
        assert_eq!(fixture.effects(), "xxxxxx");
        fixture.reopen();
        for name in [
            b"refs/tags/v-light".as_slice(),
            b"refs/tags/v-annotated",
            b"refs/tags/v-nested",
        ] {
            let repeated = fixture.poll(name, limits()).unwrap();
            assert_eq!(repeated.state(), "previously_settled");
            assert!(repeated.execution_settled());
            assert!(repeated.dispatch().is_none());
        }
        assert_eq!(fixture.effects(), "xxxxxx");
        assert_eq!(generation(fixture.node()), before);
    }
}

#[test]
fn tags_to_blobs_and_trees_refuse_before_scripts_or_event_reservation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, "push", "true");
        for (name, target, kind, annotated) in [
            (
                b"refs/tags/blob".as_slice(),
                fixture.blob,
                GitObjectKind::Blob,
                false,
            ),
            (
                b"refs/tags/tree".as_slice(),
                fixture.tree,
                GitObjectKind::Tree,
                false,
            ),
            (
                b"refs/tags/annotated-blob".as_slice(),
                fixture.blob,
                GitObjectKind::Blob,
                true,
            ),
            (
                b"refs/tags/annotated-tree".as_slice(),
                fixture.tree,
                GitObjectKind::Tree,
                true,
            ),
        ] {
            if annotated {
                fixture.annotated(name, target, kind, 1);
            } else {
                fixture.lightweight(name, target);
            }
            for error in [
                fixture.run(name, 0x41, (None, None)).unwrap_err(),
                fixture.poll(name, limits()).unwrap_err(),
            ] {
                assert!(
                    matches!(
                        error,
                        TrustedWorkflowFailure::Source(NodeWorkspaceRefusal::CommitRequired)
                    ),
                    "{error:?}"
                );
            }
        }
        assert_eq!(fixture.effects(), "");
        for watch in fs::read_dir(fixture.parent()).unwrap() {
            let watch = watch.unwrap();
            assert!(watch.file_name().to_string_lossy().starts_with("watch-"));
            assert!(
                fs::read_dir(watch.path())
                    .unwrap()
                    .all(|entry| entry.unwrap().file_name() == "owner.lock")
            );
        }
    }
}

#[test]
fn stale_heads_and_raw_annotation_ids_cannot_reserve_a_peeled_commit_dispatch() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, "\n  push:\n    tags:\n      - 'v*'", "true");
        let name = b"refs/tags/v1";
        let first = fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 1);
        let stale = fixture.head();
        fixture.delete(name, first);
        let current_raw = fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 2);
        let current = fixture.head();
        assert_ne!(current, stale);
        assert_ne!(current_raw, first);
        let node = fixture.node();
        for (index, expected, should_reserve) in [
            (0, (stale, fixture.commit), false),
            (1, (current, current_raw), false),
            (2, (current, fixture.commit), true),
        ] {
            let parent = fixture.temp.0.join(format!("pinned-{index}"));
            let mut reservations = 0;
            let result =
                node.runtime()
                    .block_on(node.dispatch_trusted_workflows_with_trigger_branch_in(
                        &node.command_request_context(None),
                        &reference(name),
                        b"ci",
                        "push",
                        [0x51; 16],
                        &parent,
                        &[b"ci".to_vec()],
                        expected,
                        limits(),
                        None,
                        None,
                        None,
                        Some(|| {
                            reservations += 1;
                            fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
                            Ok(())
                        }),
                    ));
            assert_eq!(reservations, usize::from(should_reserve));
            assert_eq!(parent.exists(), should_reserve);
            if should_reserve {
                let dispatch = result.unwrap();
                assert!(dispatch.succeeded());
                assert_eq!(dispatch.runs().len(), 1);
                assert_eq!(dispatch.runs()[0].source_commit, fixture.commit);
            } else {
                assert!(
                    matches!(result, Err(TrustedWorkflowFailure::Source(NodeWorkspaceRefusal::SourceBrowse(error)))
                    if matches!(error.as_ref(), fgit_forge::source_browse::SourceBrowseError::SnapshotMoved | fgit_forge::source_browse::SourceBrowseError::CommitMoved))
                );
                assert_eq!(fixture.effects(), "");
            }
        }
        assert_eq!(fixture.effects(), "x");
    }
}

#[test]
fn tag_pushes_ignore_paths_while_branch_pushes_still_require_matching_changes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(
            format,
            "\n  push:\n    branches:\n      - main\n    tags:\n      - 'v*'\n    paths:\n      - 'not-present/**'",
            "true",
        );
        fixture.lightweight(b"refs/tags/v1", fixture.commit);
        fixture.lightweight(b"refs/tags/preview", fixture.commit);
        let release = fixture.poll(b"refs/tags/v1", limits()).unwrap();
        assert_eq!(release.dispatch().unwrap().runs().len(), 1);
        assert!(
            !release
                .dispatch()
                .unwrap()
                .to_json()
                .contains("\"changed_paths\"")
        );
        for name in [b"refs/heads/main".as_slice(), b"refs/tags/preview"] {
            let skipped = fixture.poll(name, limits()).unwrap();
            assert!(skipped.dispatch().unwrap().runs().is_empty());
            assert!(skipped.execution_settled());
        }
        assert_eq!(fixture.effects(), "x");
    }
}

#[test]
fn reannotation_of_the_same_commit_is_a_distinct_event_but_unrelated_heads_are_not() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, "push", "true");
        let name = b"refs/tags/v1";
        let first_raw = fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 1);
        let first = fixture.poll(name, limits()).unwrap();
        let first_directory = first.dispatch().unwrap().run_directory.clone();
        let node = fixture.node();
        let unrelated = node
            .runtime()
            .block_on(node.admit_branch_updates_durable_in(
                &node.command_request_context(None),
                &session(b"unrelated-tag-watch-branch"),
                &[RefCommand {
                    name: reference(b"refs/heads/unrelated"),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(fixture.commit),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            unrelated.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            fixture.poll(name, limits()).unwrap().state(),
            "previously_settled"
        );
        assert_eq!(fixture.effects(), "x");
        fixture.delete(name, first_raw);
        let second_raw = fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 2);
        assert_ne!(first_raw, second_raw);
        let second = fixture.poll(name, limits()).unwrap();
        assert_eq!(second.state(), "dispatched");
        assert_ne!(second.dispatch().unwrap().run_directory, first_directory);
        assert_eq!(
            second.dispatch().unwrap().runs()[0].source_commit,
            fixture.commit
        );
        assert!(
            second
                .to_json()
                .contains(&format!("\"tag_tip\":\"{second_raw}\""))
        );
        // The immediate canonical predecessor is deletion, even when no poll
        // observed it. The first annotation must not be invented as that tip.
        assert!(second.to_json().contains("\"previous_tag_tip\":null"));
        fixture.reopen();
        assert_eq!(
            fixture.poll(name, limits()).unwrap().state(),
            "previously_settled"
        );
        assert_eq!(fixture.effects(), "xx");
    }
}

#[test]
fn interrupted_tag_execution_fences_later_annotations_after_reopen() {
    let mut fixture = Fixture::new(GitHashAlgorithm::Sha256, "push", "sleep 30");
    let name = b"refs/tags/v1";
    let first = fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 1);
    let interrupted = fixture
        .poll(
            name,
            WorkflowLimits {
                step_timeout: Duration::from_millis(100),
                run_timeout: Duration::from_secs(3),
                ..limits()
            },
        )
        .unwrap();
    assert!(interrupted.requires_reconciliation());
    assert!(!interrupted.execution_settled());
    assert!(!interrupted.stopped_before_reservation());
    assert_eq!(fixture.effects(), "x");
    fixture.delete(name, first);
    fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 2);
    fixture.reopen();
    let blocked = fixture.poll(name, limits()).unwrap();
    assert_eq!(blocked.state(), "blocked_unresolved");
    assert!(blocked.requires_reconciliation());
    assert!(!blocked.execution_settled());
    assert!(blocked.dispatch().is_none());
    assert_eq!(fixture.effects(), "x");
}

#[test]
fn tag_settlement_recovery_verifies_original_raw_tip_without_reexecuting() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut fixture = Fixture::new(format, "push", "true");
        let name = b"refs/tags/v1";
        let raw_tip = fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 1);
        let original = fixture.poll(name, limits()).unwrap();
        assert!(original.execution_settled());
        let dispatch = original.dispatch().unwrap();
        let event = dispatch.run_directory.parent().unwrap().to_path_buf();
        let child = dispatch.runs()[0].run_directory.clone();
        assert_eq!(dispatch.runs()[0].source_tag_tip, Some(raw_tip));
        let acknowledgement = fs::read(event.join("settled")).unwrap();
        let handoff = fs::read(event.join("check-sources")).unwrap();
        let owner = fs::read(child.join(OWNER_FILE)).unwrap();
        let journal = fs::read(child.join(JOURNAL_FILE)).unwrap();
        let before = generation(fixture.node());
        // A crash after the closed-run handoff may lose its final acknowledgement.
        // Neither an event annotation nor an attempt may substitute the peeled
        // commit for the raw tag ref that selected this original execution.
        fs::remove_file(event.join("settled")).unwrap();
        for (path, field) in [
            (event.join("event.json"), "tag_tip"),
            (
                dispatch.run_directory.join("dispatch.json"),
                "source_tag_tip",
            ),
            (child.join("attempt.json"), "source_tag_tip"),
        ] {
            let retained = fs::read_to_string(&path).unwrap();
            let original_field = format!("\"{field}\":\"{raw_tip}\"");
            assert!(retained.contains(&original_field), "{retained}");
            let changed = retained.replace(
                &original_field,
                &format!("\"{field}\":\"{}\"", fixture.commit),
            );
            fs::write(&path, changed).unwrap();
            assert!(fixture.poll(name, limits()).is_err());
            assert!(!event.join("settled").exists());
            assert_eq!(fixture.effects(), "x");
            fs::write(&path, retained).unwrap();
        }
        fixture.reopen();
        let recovered = fixture.poll(name, limits()).unwrap();
        assert_eq!(recovered.state(), "previously_settled");
        assert!(recovered.execution_settled());
        assert!(recovered.dispatch().is_none());
        assert_eq!(fs::read(event.join("settled")).unwrap(), acknowledgement);
        assert_eq!(fs::read(event.join("check-sources")).unwrap(), handoff);
        assert_eq!(fs::read(child.join(OWNER_FILE)).unwrap(), owner);
        assert_eq!(fs::read(child.join(JOURNAL_FILE)).unwrap(), journal);
        assert_eq!(generation(fixture.node()), before);
        assert_eq!(fixture.effects(), "x");
    }
}

#[test]
fn tag_selection_cannot_enter_branch_check_pr_or_queue_authority() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha256, "push", "true");
    let name = b"refs/tags/v1";
    fixture.lightweight(name, fixture.commit);
    let selection = WorkflowWatchConfig::try_new(
        fixture.commit.algorithm(),
        reference(name),
        b"ci".to_vec(),
        fixture.parent(),
        vec![b"ci".to_vec()],
        Duration::from_millis(20),
    )
    .unwrap();
    selection.validate().unwrap();
    assert!(
        selection
            .clone()
            .with_publisher(actor())
            .validate()
            .is_err()
    );
    assert!(selection.clone().with_pull_request(1).is_err());
    assert!(selection.clone().with_pull_requests(4).is_err());
    assert!(selection.with_merge_queue(1).is_err());
    let merge = PullRequestMergeWatchConfig::try_new(
        reference(b"refs/heads/ci"),
        actor(),
        MergeMetadata {
            author: "Fixture <fixture@example.invalid>".into(),
            committer: "Fixture <fixture@example.invalid>".into(),
            timestamp: 1,
            message: b"candidate\n".to_vec(),
        },
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap();
    let node = fixture.node();
    let before = generation(node);
    assert!(
        node.runtime()
            .block_on(node.poll_trusted_pull_request_workflows_in(
                &node.command_request_context(None),
                &reference(name),
                1,
                b"ci",
                &fixture.parent(),
                &[b"ci".to_vec()],
                limits(),
                None,
            ))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.poll_trusted_queue_head_merge_workflows_in(
                &node.command_request_context(None),
                &reference(name),
                1,
                b"ci",
                &fixture.parent(),
                &[b"ci".to_vec()],
                limits(),
                None,
                &merge,
            ))
            .is_err()
    );
    let mut observed = 0;
    let publication = node
        .runtime()
        .block_on(node.publish_trusted_ref_workflow_checks_in(
            &node.command_request_context(None),
            &reference(name),
            b"ci",
            &fixture.parent(),
            actor(),
            |_| {
                observed += 1;
                Ok(())
            },
        ));
    assert!(publication.error.is_some());
    assert_eq!(publication.committed, 0);
    assert_eq!(publication.events_reported, 0);
    assert_eq!(observed, 0);
    assert_eq!(generation(node), before);
    assert_eq!(fs::read_dir(fixture.parent()).unwrap().count(), 0);
    assert_eq!(fixture.effects(), "");
}

#[test]
fn cancelled_tag_selection_stops_before_custody_without_hiding_invalid_names() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, "push", "true");
    let name = b"refs/tags/v1";
    fixture.annotated(name, fixture.commit, GitObjectKind::Commit, 1);
    let node = fixture.node();
    let request = node.command_request_context(None);
    request.cancel();
    let poll = node
        .runtime()
        .block_on(node.poll_trusted_ref_workflows_in(
            &request,
            &reference(name),
            b"ci",
            &fixture.parent(),
            &[b"ci".to_vec()],
            limits(),
            None,
        ))
        .unwrap();
    assert!(poll.stopped_before_reservation());
    assert!(!poll.execution_settled());
    assert!(poll.dispatch().is_none());
    assert!(
        node.runtime()
            .block_on(node.poll_trusted_ref_workflows_in(
                &request,
                &reference(b"refs/notes/release"),
                b"ci",
                &fixture.parent(),
                &[b"ci".to_vec()],
                limits(),
                None,
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(fixture.parent()).unwrap().count(), 0);
    assert_eq!(fixture.effects(), "");
    assert_eq!(fixture.poll(name, limits()).unwrap().state(), "dispatched");
    assert_eq!(fixture.effects(), "x");
}
