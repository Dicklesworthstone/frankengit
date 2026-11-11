#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Complete real local executions survive loss of the final watch marker.
//! The mutations below model crash prefixes or adversarial local corruption;
//! they never manufacture successful executions or canonical check receipts.
#[path = "trusted_merge_workflow/support.rs"]
mod support;
use support::*;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::workflow_watch::{
    PullRequestMergeWatchConfig, WorkflowWatchConfig, WorkflowWatchControl, run_service_with_ready,
};
use fgit_node::{LoopbackReceiveSession, TrustedWorkflowFailure};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use std::{collections::BTreeMap, fs, path::PathBuf, time::Duration};

#[path = "trusted_watch_settlement_recovery/cancellation.rs"]
mod cancellation;

#[derive(Clone, Copy, Debug)]
enum Mode {
    Ref,
    PullRequest,
    Queue,
}
impl Mode {
    fn reference(self) -> RefName {
        if matches!(self, Self::Queue) {
            target_ref()
        } else {
            source_ref()
        }
    }
    fn reporting_reference(self) -> RefName {
        if matches!(self, Self::Ref) {
            source_ref()
        } else {
            ci_ref()
        }
    }
}
fn ci_ref() -> RefName {
    RefName::try_new(b"refs/heads/ci/settlement").unwrap()
}
fn merge_config() -> PullRequestMergeWatchConfig {
    PullRequestMergeWatchConfig::try_new(
        ci_ref(),
        OWNER,
        MergeMetadata {
            author: "CI <ci@example.test>".into(),
            committer: "CI <ci@example.test>".into(),
            timestamp: 1700000000,
            message: b"Settlement recovery candidate\n".to_vec(),
        },
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap()
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(key.to_vec()).unwrap())
}

// The shared fixture supplies the real node and divergent native history;
// native incremental admission adds the workflow under the exact source lease.
struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let oid = git_object_id(format, kind, &body);
        self.0.insert(oid, (kind, body));
        oid
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, oid: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .get(oid)
            .ok_or(PackWriteError::MissingCanonicalObject(*oid))?;
        Ok(CanonicalPackObject::new(
            *oid,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
fn fixture(format: GitHashAlgorithm, mode: Mode) -> Fixture {
    fixture_with_exit(format, mode, 0)
}
fn fixture_with_exit(format: GitHashAlgorithm, mode: Mode, exit: u8) -> Fixture {
    fixture_with_command(format, mode, |root| {
        format!(
            "printf x >> '{}'; exit {exit}",
            root.join("executed").display()
        )
    })
}
fn fixture_with_command(
    format: GitHashAlgorithm,
    mode: Mode,
    command: impl FnOnce(&std::path::Path) -> String,
) -> Fixture {
    let mut f = Fixture::new(format, WORKFLOW);
    let mut objects = Objects(BTreeMap::new());
    let trigger = if matches!(mode, Mode::Ref) {
        "push"
    } else {
        "pull_request"
    };
    let command = command(&f.root);
    let definition = format!(
        "name: settlement\non: {trigger}\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {command}\n",
    );
    let workflow = objects.put(format, GitObjectKind::Blob, definition.into_bytes());
    let ci = objects.put(
        format,
        GitObjectKind::Tree,
        [b"100644 check.yml\0".as_slice(), workflow.as_bytes()].concat(),
    );
    let left = objects.put(format, GitObjectKind::Blob, b"base\n".to_vec());
    let right = objects.put(format, GitObjectKind::Blob, b"source\n".to_vec());
    let tree = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"40000 ci\0".as_slice(),
            ci.as_bytes(),
            b"100644 left\0",
            left.as_bytes(),
            b"100644 right\0",
            right.as_bytes(),
            b"100644 workflow.yml\0",
            f.workflow.as_bytes(),
        ]
        .concat(),
    );
    let source = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "workflow source"),
    );
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(
        &objects,
        &objects.0.keys().copied().collect::<Vec<_>>(),
        &mut || true,
    )
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(
        format!(
            "-{} original source\n{source} refs/heads/topic\n\n",
            f.source
        )
        .as_bytes(),
    );
    bundle.extend_from_slice(&pack);
    let imported = f
        .node()
        .runtime()
        .block_on(f.node().import_incremental_git_bundle_durable_in(
            &f.node().request_context(),
            &session(b"settlement-workflow-fixture"),
            &bundle,
            &[(source_ref(), Some(f.source))],
            Default::default(),
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    f.source = source;
    if !matches!(mode, Mode::Ref) {
        let command = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data: PullRequestData {
                source_ref: source_ref(),
                target_ref: target_ref(),
                source_tip: f.source,
                target_tip: f.target,
                title: "Recover completed candidate".into(),
                body: String::new(),
            },
        };
        let (_, outcome) = f
            .node()
            .runtime()
            .block_on(f.node().admit_pull_request_durable_in(
                &f.node().request_context(),
                &session(b"settlement-pr"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    }
    if matches!(mode, Mode::Queue) {
        let command = QueueCommand {
            number: QueueNumber::FIRST,
            target_ref: target_ref(),
            expected_version: ExpectedVersion::NewStream,
            action: QueueCommandAction::Enqueue {
                pull_request: PullRequestNumber::FIRST,
                expected_pull_request_version: AggregateVersion::FIRST,
                source_ref: source_ref(),
                head_tip: f.source,
                expected_target_tip: f.target,
                priority: 0,
            },
        };
        let (_, outcome) = f
            .node()
            .runtime()
            .block_on(f.node().admit_queue_durable_in(
                &f.node().request_context(),
                &session(b"settlement-queue"),
                &command,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
    }
    f
}

struct Retained {
    event: PathBuf,
    child: PathBuf,
    manifest: String,
    commit: GitOid,
}
fn poll(f: &Fixture, mode: Mode) -> Result<(String, Option<Retained>), TrustedWorkflowFailure> {
    poll_with_request(f, mode, &f.node().request_context())
}
fn poll_with_request(
    f: &Fixture,
    mode: Mode,
    request: &fgit_node::NodeRequestContext,
) -> Result<(String, Option<Retained>), TrustedWorkflowFailure> {
    let node = f.node();
    let reference = mode.reference();
    let parent = f.parent();
    let inputs = vec![b"ci".to_vec()];
    let merge = merge_config();
    let observed = node.runtime().block_on(async {
        match mode {
            Mode::Ref => {
                node.poll_trusted_ref_workflows_in(
                    request,
                    &reference,
                    b"ci",
                    &parent,
                    &inputs,
                    Default::default(),
                    None,
                )
                .await
            }
            Mode::PullRequest => {
                node.poll_trusted_pull_request_merge_workflows_in(
                    request,
                    &reference,
                    1,
                    b"ci",
                    &parent,
                    &inputs,
                    Default::default(),
                    None,
                    &merge,
                )
                .await
            }
            Mode::Queue => {
                node.poll_trusted_queue_head_merge_workflows_in(
                    request,
                    &reference,
                    1,
                    b"ci",
                    &parent,
                    &inputs,
                    Default::default(),
                    None,
                    &merge,
                )
                .await
            }
        }
    })?;
    let retained = observed.dispatch().map(|dispatch| {
        assert_eq!(dispatch.runs().len(), 1);
        let run = &dispatch.runs()[0];
        let pin = run.open_check_journal(None, &|| true).unwrap().pin();
        let manifest = node
            .prepare_trusted_workflow_check_set(
                &node.command_request_context(None),
                &run.run_directory,
                run.check_journal_scope().journal_id.digest(),
                (pin.byte_len(), pin.tail().digest()),
                OWNER,
                mode.reporting_reference(),
                (128, 16 * 1024 * 1024),
            )
            .unwrap()
            .to_json();
        Retained {
            event: dispatch.run_directory.parent().unwrap().to_path_buf(),
            child: run.run_directory.clone(),
            manifest,
            commit: run.executed_commit(),
        }
    });
    Ok((observed.to_json(), retained))
}
fn complete(f: &Fixture, mode: Mode) -> Retained {
    let (json, retained) = poll(f, mode).unwrap();
    assert!(json.contains("\"state\":\"dispatched\""), "{json}");
    assert!(json.contains("\"execution_settled\":true"), "{json}");
    assert!(json.contains("\"succeeded\":true"), "{json}");
    assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
    retained.unwrap()
}
fn publish(f: &Fixture, mode: Mode) -> (usize, usize, Vec<String>, Option<String>) {
    let node = f.node();
    let request = node.request_context();
    let reference = mode.reference();
    let parent = f.parent();
    let merge = merge_config();
    let mut lines = Vec::new();
    let observe = |line: &str| {
        lines.push(line.to_owned());
        Ok(())
    };
    let result = node.runtime().block_on(async {
        match mode {
            Mode::Ref => {
                node.publish_trusted_ref_workflow_checks_in(
                    &request, &reference, b"ci", &parent, OWNER, observe,
                )
                .await
            }
            Mode::PullRequest => {
                node.publish_trusted_pull_request_merge_workflow_checks_in(
                    &request, &reference, 1, b"ci", &parent, OWNER, &merge, observe,
                )
                .await
            }
            Mode::Queue => {
                node.publish_trusted_queue_head_merge_workflow_checks_in(
                    &request, &reference, 1, b"ci", &parent, OWNER, &merge, observe,
                )
                .await
            }
        }
    });
    (
        result.committed,
        result.previously_reported,
        lines,
        result.error,
    )
}
fn assert_refs(f: &Fixture, mode: Mode, commit: GitOid) {
    let current = f
        .node()
        .runtime()
        .block_on(f.node().materialize_admission())
        .unwrap();
    assert_eq!(current.snapshot().refs[&source_ref()], f.source);
    assert_eq!(current.snapshot().refs[&target_ref()], f.target);
    if !matches!(mode, Mode::Ref) {
        assert_eq!(current.snapshot().refs[&ci_ref()], commit);
    }
}

#[test]
fn completed_handoff_recovers_every_watch_mode_and_original_check_identity_without_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::Ref, Mode::PullRequest, Mode::Queue] {
            let mut f = fixture(format, mode);
            let retained = complete(&f, mode);
            let marker = fs::read(retained.event.join("settled")).unwrap();
            let owner = fs::read(retained.child.join("execution.owner")).unwrap();
            let journal = fs::read(retained.child.join("check-proposals.journal")).unwrap();
            let sources = fs::read(retained.event.join("check-sources")).unwrap();
            fs::remove_file(retained.event.join("settled")).unwrap();
            // Final human-readable reports are optional after durable handoff;
            // recovery must use the original owner, markers and journal pins.
            fs::remove_file(retained.child.join("report.json")).unwrap();
            fs::remove_file(retained.child.parent().unwrap().join("report.json")).unwrap();
            f.reopen();
            let before = generation(f.node());
            let (recovered, dispatch) = poll(&f, mode).unwrap();
            assert!(
                recovered.contains("\"state\":\"previously_settled\""),
                "{mode:?}: {recovered}"
            );
            assert!(recovered.contains("\"execution_settled\":true"));
            assert!(dispatch.is_none());
            assert_eq!(
                generation(f.node()),
                before,
                "recovery admitted a new command"
            );
            assert_eq!(fs::read(retained.event.join("settled")).unwrap(), marker);
            assert_eq!(
                fs::read(retained.child.join("execution.owner")).unwrap(),
                owner
            );
            assert_eq!(
                fs::read(retained.child.join("check-proposals.journal")).unwrap(),
                journal
            );
            assert_eq!(
                fs::read(retained.event.join("check-sources")).unwrap(),
                sources
            );
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
            assert_refs(&f, mode, retained.commit);
            let (committed, previous, lines, error) = publish(&f, mode);
            assert!(error.is_none(), "{error:?}");
            assert_eq!((committed, previous), (1, 0));
            assert_eq!(
                lines[0], retained.manifest,
                "recovery changed original check IDs or evidence"
            );
            assert!(lines[1].contains("\"command_committed\":true"));
            let after = generation(f.node());
            let (committed, previous, lines, error) = publish(&f, mode);
            assert!(error.is_none(), "{error:?}");
            assert_eq!((committed, previous), (0, 1));
            assert!(lines.is_empty());
            assert_eq!(generation(f.node()), after);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
            assert_refs(&f, mode, retained.commit);
        }
    }
}

#[test]
fn recovering_a_closed_failed_job_preserves_its_original_failure_check() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = fixture_with_exit(format, Mode::Queue, 17);
        let (original, retained) = poll(&f, Mode::Queue).unwrap();
        assert!(original.contains("\"state\":\"dispatched\""));
        assert!(
            original.contains("\"execution_settled\":true"),
            "{original}"
        );
        assert!(original.contains("\"succeeded\":false"), "{original}");
        let retained = retained.unwrap();
        assert!(retained.manifest.contains("\"conclusion\":\"failure\""));
        fs::remove_file(retained.event.join("settled")).unwrap();
        f.reopen();
        // The reporter must recover directly, without a poll that might admit
        // another CI candidate before the original failed check is published.
        let (committed, previous, lines, error) = publish(&f, Mode::Queue);
        assert!(error.is_none(), "{error:?}");
        assert_eq!((committed, previous), (1, 0));
        assert_eq!(lines[0], retained.manifest);
        assert!(lines[1].contains("\"conclusion\":\"failure\""));
        assert!(lines[1].contains("\"command_committed\":true"));
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        assert_refs(&f, Mode::Queue, retained.commit);
        assert!(
            poll(&f, Mode::Queue)
                .unwrap()
                .0
                .contains("\"state\":\"previously_settled\"")
        );
    }
}

#[test]
fn reporter_and_service_recover_before_readiness_without_any_new_poll() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [Mode::Ref, Mode::PullRequest, Mode::Queue] {
            let f = fixture(format, mode);
            let retained = complete(&f, mode);
            fs::remove_file(retained.event.join("settled")).unwrap();
            let mut watch = WorkflowWatchConfig::try_new(
                format,
                mode.reference(),
                b"ci".to_vec(),
                f.parent(),
                vec![b"ci".to_vec()],
                Duration::from_millis(20),
            )
            .unwrap()
            .with_publisher(OWNER);
            match mode {
                Mode::Ref => {}
                Mode::PullRequest => {
                    watch = watch
                        .with_pull_request(1)
                        .unwrap()
                        .with_merge_candidate(merge_config())
                        .unwrap()
                }
                Mode::Queue => {
                    watch = watch
                        .with_merge_queue(1)
                        .unwrap()
                        .with_merge_candidate(merge_config())
                        .unwrap()
                }
            }
            let control = WorkflowWatchControl::default();
            let receipt =
                run_service_with_ready(f.config.clone(), watch.clone(), control.clone(), || {
                    assert!(retained.event.join("settled").is_file());
                    assert!(retained.event.join("reported").is_file());
                    assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
                    control.request_stop();
                    Ok(())
                })
                .unwrap();
            assert_eq!(receipt.checks_committed, 1);
            assert_eq!(receipt.polls, 0);
            assert!(!receipt.publication_pending);
            assert!(!receipt.requires_reconciliation);
            assert_refs(&f, mode, retained.commit);
            let control = WorkflowWatchControl::default();
            let repeated = run_service_with_ready(f.config.clone(), watch, control.clone(), || {
                control.request_stop();
                Ok(())
            })
            .unwrap();
            assert_eq!(repeated.checks_committed, 0);
            assert_eq!(repeated.polls, 0);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Damage {
    MissingHandoff,
    TruncatedHandoff,
    CorruptHandoff,
    ForeignScope,
    ForeignCommit,
    ForgedEmptyRuns,
    PinMismatch,
    TruncatedJournal,
    AlteredJournal,
    MissingOwner,
    StartedOwner,
    ContainmentOwner,
    PartialSettled,
}

#[test]
fn cancelled_recovery_keeps_completion_handoff_for_a_later_live_owner() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let f = fixture(format, Mode::Queue);
        let retained = complete(&f, Mode::Queue);
        fs::remove_file(retained.event.join("settled")).unwrap();
        let sources = fs::read(retained.event.join("check-sources")).unwrap();
        let before = generation(f.node());
        let request = f.node().request_context();
        request.cancel();
        let stopped = f
            .node()
            .runtime()
            .block_on(f.node().poll_trusted_queue_head_merge_workflows_in(
                &request,
                &target_ref(),
                1,
                b"ci",
                &f.parent(),
                &[b"ci".to_vec()],
                Default::default(),
                None,
                &merge_config(),
            ))
            .unwrap();
        assert!(stopped.stopped_before_reservation());
        assert!(stopped.dispatch().is_none());
        let reported = f.node().runtime().block_on(
            f.node()
                .publish_trusted_queue_head_merge_workflow_checks_in(
                    &request,
                    &target_ref(),
                    1,
                    b"ci",
                    &f.parent(),
                    OWNER,
                    &merge_config(),
                    |_| panic!("cancelled recovery published a manifest or decision"),
                ),
        );
        assert!(reported.request_stopped);
        assert_eq!(reported.committed, 0);
        assert!(!retained.event.join("settled").exists());
        assert!(!retained.event.join("reported").exists());
        assert_eq!(
            fs::read(retained.event.join("check-sources")).unwrap(),
            sources
        );
        assert_eq!(generation(f.node()), before);
        let (committed, _, lines, error) = publish(&f, Mode::Queue);
        assert!(error.is_none(), "{error:?}");
        assert_eq!(committed, 1);
        assert_eq!(lines[0], retained.manifest);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        assert_refs(&f, Mode::Queue, retained.commit);
    }
}

#[test]
fn verified_empty_trigger_selection_settles_without_inventing_checks() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        // The real definition selects pull_request. A plain ref watch's push
        // trigger therefore has a persisted definition and zero selected work.
        let f = fixture(format, Mode::PullRequest);
        let before = generation(f.node());
        let original = f
            .node()
            .runtime()
            .block_on(f.node().poll_trusted_ref_workflows_in(
                &f.node().request_context(),
                &source_ref(),
                b"ci",
                &f.parent(),
                &[b"ci".to_vec()],
                Default::default(),
                None,
            ))
            .unwrap();
        assert_eq!(original.state(), "dispatched");
        assert!(original.execution_settled());
        let dispatch = original.dispatch().unwrap();
        assert!(dispatch.runs().is_empty());
        let event = dispatch.run_directory.parent().unwrap();
        fs::remove_file(event.join("settled")).unwrap();
        fs::remove_file(dispatch.run_directory.join("report.json")).unwrap();
        let (recovered, repeated) = poll(&f, Mode::Ref).unwrap();
        assert!(
            recovered.contains("\"state\":\"previously_settled\""),
            "{recovered}"
        );
        assert!(repeated.is_none());
        let (committed, previous, lines, error) = publish(&f, Mode::Ref);
        assert!(error.is_none(), "{error:?}");
        assert_eq!((committed, previous), (0, 0));
        assert!(lines.is_empty());
        assert!(event.join("settled").is_file());
        assert!(event.join("reported").is_file());
        assert!(!f.root.join("executed").exists());
        assert_eq!(generation(f.node()), before);
        assert_refs(&f, Mode::Ref, f.source);
    }
}
fn damage(retained: &Retained, damage: Damage) {
    let settled = retained.event.join("settled");
    if matches!(damage, Damage::PartialSettled) {
        fs::write(&settled, b"partial").unwrap();
        return;
    }
    fs::remove_file(&settled).unwrap();
    let handoff = retained.event.join("check-sources");
    let journal = retained.child.join("check-proposals.journal");
    let owner = retained.child.join("execution.owner");
    match damage {
        Damage::MissingHandoff => fs::remove_file(handoff).unwrap(),
        Damage::TruncatedHandoff => {
            let mut bytes = fs::read(&handoff).unwrap();
            bytes.pop();
            fs::write(handoff, bytes).unwrap();
        }
        Damage::CorruptHandoff
        | Damage::ForeignScope
        | Damage::ForeignCommit
        | Damage::ForgedEmptyRuns
        | Damage::PinMismatch => {
            let mut bytes = fs::read(&handoff).unwrap();
            let count = 73 + retained.commit.algorithm().digest_len();
            match damage {
                Damage::CorruptHandoff => bytes[40] ^= 1,
                Damage::ForeignScope => bytes[8] ^= 1,
                Damage::ForeignCommit => bytes[73] ^= 1,
                Damage::ForgedEmptyRuns => {
                    bytes.truncate(count + 4);
                    bytes[count..].fill(0);
                    bytes.extend([0; 32]);
                }
                Damage::PinMismatch => bytes[count + 4 + 56] ^= 1,
                _ => unreachable!(),
            }
            // Foreign bindings and pins carry a valid checksum, proving that
            // a checksum alone is not execution or original-scope evidence.
            if !matches!(damage, Damage::CorruptHandoff) {
                let end = bytes.len() - 32;
                let checksum = sha256_digest(&bytes[..end]);
                bytes[end..].copy_from_slice(&checksum);
            }
            fs::write(handoff, bytes).unwrap();
        }
        Damage::TruncatedJournal | Damage::AlteredJournal => {
            let mut bytes = fs::read(&journal).unwrap();
            if matches!(damage, Damage::TruncatedJournal) {
                bytes.pop();
            } else {
                let last = bytes.last_mut().unwrap();
                *last ^= 1;
            }
            fs::write(journal, bytes).unwrap();
        }
        Damage::MissingOwner => fs::remove_file(owner).unwrap(),
        Damage::StartedOwner => {
            let mut bytes = fs::read(&owner).unwrap();
            // Exact FGWA0001 header and durable Started frame, without a
            // Completed frame. Original closed jobs cannot authorize retry.
            assert_eq!(&bytes[..8], b"FGWA0001");
            bytes.truncate(168 + 77);
            fs::write(owner, bytes).unwrap();
        }
        Damage::ContainmentOwner => {
            let mut bytes = fs::read(&owner).unwrap();
            assert_eq!(&bytes[..8], b"FGWA0001");
            let end = bytes.len() - 32;
            // Keep the actual receipt bytes but mark local custody unresolved.
            // A valid frame checksum must not conceal its containment flag.
            bytes[168 + 77 + 4 + 41] = 1;
            let checksum = sha256_digest(
                &[
                    b"frankengit/trusted-attempt-frame/v1\0".as_slice(),
                    &bytes[168 + 45..168 + 77],
                    &bytes[168 + 77..end],
                ]
                .concat(),
            );
            bytes[end..].copy_from_slice(&checksum);
            fs::write(owner, bytes).unwrap();
        }
        Damage::PartialSettled => unreachable!(),
    }
}

#[test]
fn incomplete_or_altered_custody_never_recovers_publishes_or_reexecutes() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for defect in [
            Damage::MissingHandoff,
            Damage::TruncatedHandoff,
            Damage::CorruptHandoff,
            Damage::ForeignScope,
            Damage::ForeignCommit,
            Damage::ForgedEmptyRuns,
            Damage::PinMismatch,
            Damage::TruncatedJournal,
            Damage::AlteredJournal,
            Damage::MissingOwner,
            Damage::StartedOwner,
            Damage::ContainmentOwner,
            Damage::PartialSettled,
        ] {
            let mut f = fixture(format, Mode::Queue);
            let retained = complete(&f, Mode::Queue);
            damage(&retained, defect);
            let before_marker = fs::read(retained.event.join("settled")).ok();
            f.reopen();
            let before = generation(f.node());
            let attempted = poll(&f, Mode::Queue);
            if matches!(defect, Damage::MissingHandoff) {
                let (json, dispatch) = attempted.unwrap();
                assert!(json.contains("\"state\":\"blocked_unresolved\""), "{json}");
                assert!(dispatch.is_none());
            } else {
                assert!(attempted.is_err(), "{format:?} {defect:?} was adopted");
            }
            let (committed, previous, lines, error) = publish(&f, Mode::Queue);
            assert!(error.is_some(), "{format:?} {defect:?} was published");
            assert_eq!((committed, previous), (0, 0));
            assert!(lines.is_empty());
            assert_eq!(generation(f.node()), before);
            assert_eq!(fs::read(retained.event.join("settled")).ok(), before_marker);
            assert!(!retained.event.join("reported").exists());
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
            assert_refs(&f, Mode::Queue, retained.commit);
        }
    }
}
