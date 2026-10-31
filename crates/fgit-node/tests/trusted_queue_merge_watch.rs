#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real canonical queue selection, exact-candidate CI and retained execution custody.
#[path = "trusted_merge_workflow/support.rs"]
mod support;
use support::*;

use fgit_admission::merge::native::queue::QueueCandidateLandingCommand;
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id, sha256_digest};
use fgit_forge::event::protection::{
    ProtectedBranch, ProtectionCommand, RequiredWorkflowCheck, ReviewProtection,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::workflow_watch::PullRequestMergeWatchConfig;
use fgit_node::{LoopbackReceiveSession, TrustedWorkflowFailure};
use fgit_pack::full_bundle::{FullBundleInput, FullBundleLimits};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, RefName, RefusalCode};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn branch(bytes: &[u8]) -> RefName {
    RefName::try_new(bytes).unwrap()
}
fn ci_ref() -> RefName {
    branch(b"refs/heads/ci/queue-main")
}
fn second_ref() -> RefName {
    branch(b"refs/heads/topic-two")
}
fn pull_number(number: u64) -> PullRequestNumber {
    PullRequestNumber::try_new(number).unwrap()
}
fn version(number: u64) -> AggregateVersion {
    AggregateVersion::try_new(number).unwrap()
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(key.to_vec()).unwrap())
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "CI <ci@example.test>".into(),
        committer: "CI <ci@example.test>".into(),
        timestamp: 1700000000,
        message: b"Queue candidate\n".to_vec(),
    }
}
fn config() -> PullRequestMergeWatchConfig {
    PullRequestMergeWatchConfig::try_new(
        ci_ref(),
        OWNER,
        metadata(),
        MergeProfile::PathMergeV1,
        MergeCommitStyle::TwoParent,
    )
    .unwrap()
}
fn read_inputs() -> Vec<Vec<u8>> {
    vec![b"ci".to_vec(), b"left".to_vec(), b"right".to_vec()]
}
fn json_string<'a>(text: &'a str, field: &str) -> &'a str {
    text.split_once(&format!("\"{field}\":\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}
fn hex32(text: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    assert_eq!(text.len(), bytes.len() * 2);
    for (i, value) in bytes.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    bytes
}

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

// Extend the shared imported fixture with two distinct incoming commits and
// real executable definitions. Both must be combined with the target to pass.
fn install_ci(f: &mut Fixture, conflict: bool, malformed: bool) -> GitOid {
    let format = f.source.algorithm();
    let mut objects = Objects(BTreeMap::new());
    let definition = if malformed {
        "name: broken\non: pull_request\njobs: invalid\n".into()
    } else {
        format!(
            "name: queue-check\non:\n  pull_request:\n    branches:\n      - main\n    paths:\n      - right\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: test \"$(cat left)\" = target && test \"$(cat right)\" = source || exit 7; printf x >> '{}'\n",
            f.root.join("executed").display(),
        )
    };
    let workflow = objects.put(format, GitObjectKind::Blob, definition.into_bytes());
    let excluded = objects.put(format, GitObjectKind::Blob,
        b"name: target-only\non:\n  pull_request:\n    paths:\n      - left\njobs:\n  excluded:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: exit 61\n".to_vec());
    let ci = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"100644 check.yml\0".as_slice(),
            workflow.as_bytes(),
            b"100644 excluded.yml\0",
            excluded.as_bytes(),
        ]
        .concat(),
    );
    let left = objects.put(
        format,
        GitObjectKind::Blob,
        if conflict {
            b"conflict\n".to_vec()
        } else {
            b"base\n".to_vec()
        },
    );
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
    let first = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "first queued source"),
    );
    let second = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "second queued source"),
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
            "-{} original incoming\n{first} refs/heads/topic\n{second} refs/heads/topic-two\n\n",
            f.source
        )
        .as_bytes(),
    );
    bundle.extend_from_slice(&pack);
    let node = f.node();
    let imported = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session(b"queue-ci-definitions"),
            &bundle,
            &[(source_ref(), Some(f.source)), (second_ref(), None)],
            Default::default(),
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|row| matches!(row.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    f.source = first;
    second
}

fn open(f: &Fixture, number: u64, source: RefName, tip: GitOid) {
    let node = f.node();
    let command = PullRequestCommand {
        number: pull_number(number),
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: source,
            target_ref: target_ref(),
            source_tip: tip,
            target_tip: f.target,
            title: format!("Queue candidate {number}"),
            body: String::new(),
        },
    };
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(format!("queue-pr-{number}").as_bytes()),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}
fn change_queue(f: &Fixture, previous: u64, action: QueueCommandAction, key: &[u8]) {
    let node = f.node();
    let (_, outcome) = node
        .runtime()
        .block_on(node.admit_queue_durable_in(
            &node.request_context(),
            &session(key),
            &QueueCommand {
                number: QueueNumber::FIRST,
                target_ref: target_ref(),
                expected_version: if previous == 0 {
                    ExpectedVersion::NewStream
                } else {
                    ExpectedVersion::Exactly(version(previous))
                },
                action,
            },
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(outcome.outcome, DecisionOutcome::Committed { .. }));
}
fn queued_fixture(format: GitHashAlgorithm, conflict: bool, malformed: bool) -> (Fixture, GitOid) {
    let mut f = Fixture::new(format, WORKFLOW);
    let second = install_ci(&mut f, conflict, malformed);
    for (number, source, tip) in [(1, source_ref(), f.source), (2, second_ref(), second)] {
        open(&f, number, source.clone(), tip);
        change_queue(
            &f,
            number - 1,
            QueueCommandAction::Enqueue {
                pull_request: pull_number(number),
                expected_pull_request_version: AggregateVersion::FIRST,
                source_ref: source,
                head_tip: tip,
                expected_target_tip: f.target,
                priority: if number == 2 { 10 } else { 0 },
            },
            format!("enqueue-{number}").as_bytes(),
        );
    }
    (f, second)
}
fn poll(
    f: &Fixture,
    config: &PullRequestMergeWatchConfig,
) -> Result<String, TrustedWorkflowFailure> {
    let node = f.node();
    node.runtime()
        .block_on(node.poll_trusted_queue_head_merge_workflows_in(
            &node.request_context(),
            &target_ref(),
            1,
            b"ci",
            &f.parent(),
            &read_inputs(),
            Default::default(),
            None,
            config,
        ))
        .map(|poll| poll.to_json())
}
fn event_directories(f: &Fixture) -> Vec<PathBuf> {
    fs::read_dir(f.parent())
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("watch-"))
        })
        .flat_map(|entry| fs::read_dir(entry.path()).unwrap().map(Result::unwrap))
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("event-"))
        })
        .map(|entry| entry.path())
        .collect()
}
fn assert_pr_refs(f: &Fixture, second: GitOid) {
    let current = f
        .node()
        .runtime()
        .block_on(f.node().materialize_admission())
        .unwrap();
    assert_eq!(current.snapshot().refs[&source_ref()], f.source);
    assert_eq!(current.snapshot().refs[&second_ref()], second);
    assert_eq!(current.snapshot().refs[&target_ref()], f.target);
}

#[test]
fn canonical_queue_head_executes_actual_candidate_reports_checks_and_lands_atomically() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, false);
        let config = config();
        let before_queue = f
            .node()
            .runtime()
            .block_on(f.node().read_queue_in(
                &f.node().request_context(),
                &Default::default(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(
            before_queue.deterministic_order(),
            vec![pull_number(2), pull_number(1)]
        );
        let observed = poll(&f, &config).unwrap();
        assert!(observed.contains("\"state\":\"dispatched\""));
        assert!(observed.contains("\"succeeded\":true"));
        assert!(observed.contains("\"merge_queue\":{\"number\":\"1\",\"version\":\"2\""));
        assert!(observed.contains("\"pull_request\":\"2\""));
        assert!(observed.contains("\"matched_count\":1"), "{observed}");
        let candidate_json = observed.split_once("\"merge_candidate\":").unwrap().1;
        let candidate = GitOid::from_hex(format, json_string(candidate_json, "commit")).unwrap();
        assert_ne!(candidate, f.source);
        assert_ne!(candidate, second);
        assert_ne!(candidate, f.target);
        assert!(observed.contains(&format!("\"parents\":[\"{}\",\"{second}\"]", f.target)));
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        assert_pr_refs(&f, second);
        f.reopen();
        let head = generation(f.node());
        assert!(
            poll(&f, &config)
                .unwrap()
                .contains("\"state\":\"previously_settled\"")
        );
        assert_eq!(generation(f.node()), head);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");

        // Local execution cannot satisfy a canonical required check. Install
        // the exact graph and CI publisher, alongside the mandatory queue gate.
        let graph = hex32(json_string(&observed, "graph_sha256"));
        let node = f.node();
        let policy = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![OWNER],
                ref_policy: None,
                branches: vec![ProtectedBranch {
                    name: target_ref(),
                    reviewers: Vec::new(),
                    required_approvals: 0,
                    require_merge_queue: true,
                    required_checks: vec![RequiredWorkflowCheck {
                        source_ref: ci_ref(),
                        publisher: OWNER,
                        graph_root: graph,
                        job: "check".into(),
                    }],
                }],
            },
        };
        let (_, protection) = node
            .runtime()
            .block_on(node.admit_review_protection_durable_in(
                &node.request_context(),
                &session(b"queue-required-check"),
                &policy,
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            protection.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let epoch = PolicyEpoch::FIRST.next().unwrap();
        let refreshed = poll(&f, &config).unwrap();
        assert!(refreshed.contains("\"state\":\"dispatched\""));
        assert!(refreshed.contains("\"policy_epoch\":\"2\""));
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
        let fresh_event = event_directories(&f)
            .into_iter()
            .find(|path| {
                fs::read_to_string(path.join("event.json"))
                    .unwrap()
                    .contains("\"policy_epoch\":\"2\"")
            })
            .unwrap();
        let retained_landing = fs::read(fresh_event.join("landing.bundle")).unwrap();
        assert_eq!(
            sha256_digest(&retained_landing),
            hex32(json_string(&refreshed, "landing_bundle_sha256")),
        );
        assert_eq!(
            fs::metadata(&fresh_event).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(fresh_event.join("landing.bundle"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let prepared = node
            .runtime()
            .block_on(node.prepare_queue_head_bundle_in(
                &node.request_context(),
                QueueNumber::FIRST,
                version(2),
                &ReviewSubject {
                    pull_request: pull_number(2),
                    pull_request_version: AggregateVersion::FIRST,
                    source_ref: second_ref(),
                    target_ref: target_ref(),
                    source_tip: second,
                    target_tip: f.target,
                    policy_epoch: epoch,
                },
                &Default::default(),
                &metadata(),
                Default::default(),
            ))
            .unwrap();
        let MergePreparation::Clean(plan) = prepared.outcome else {
            panic!("clean exact queue head")
        };
        assert_eq!(plan.commit, candidate);
        let bundle = prepared.bundle.unwrap();
        let retained = FullBundleInput::parse_incremental(
            &retained_landing,
            FullBundleLimits::default(),
            &mut || true,
        )
        .unwrap();
        let independent =
            FullBundleInput::parse_incremental(&bundle, FullBundleLimits::default(), &mut || true)
                .unwrap();
        assert_eq!(retained.references(), independent.references());
        assert_eq!(retained.prerequisites(), independent.prerequisites());
        let retained_ci_bytes = fs::read(fresh_event.join("candidate.bundle")).unwrap();
        let retained_ci = FullBundleInput::parse_incremental(
            &retained_ci_bytes,
            FullBundleLimits::default(),
            &mut || true,
        )
        .unwrap();
        assert_eq!(retained.pack_bytes(), retained_ci.pack_bytes());
        let command = QueueCandidateLandingCommand {
            number: QueueNumber::FIRST,
            expected_version: version(2),
            expected_policy_epoch: epoch,
            pull_request: pull_number(2),
            expected_pull_request_version: AggregateVersion::FIRST,
            merge: fgit_forge::event::NativeMerge {
                source_ref: second_ref(),
                source_tip: second,
                target_ref: target_ref(),
                target_tip_before: f.target,
                base_tip: plan.base,
                merge_commit: candidate,
            },
        };
        let land = |key: &[u8]| {
            node.runtime()
                .block_on(node.land_queue_head_bundle_durable_in(
                    &node.request_context(),
                    &session(key),
                    &command,
                    &retained_landing,
                    Default::default(),
                ))
                .unwrap()
        };
        let denied = land(b"local-green-only");
        assert!(matches!(
            denied.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        assert_pr_refs(&f, second);
        let reported =
            node.runtime()
                .block_on(node.publish_trusted_queue_head_merge_workflow_checks_in(
                    &node.request_context(),
                    &target_ref(),
                    1,
                    b"ci",
                    &f.parent(),
                    OWNER,
                    &config,
                    |_| Ok(()),
                ));
        assert!(reported.error.is_none(), "{:?}", reported.error);
        assert_eq!(reported.committed, 2);
        assert_eq!(reported.refused, 0);
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
        assert_eq!(
            land(b"local-green-only"),
            denied,
            "old refusal cannot be upgraded by later evidence"
        );
        let ordinary = node
            .runtime()
            .block_on(node.apply_merge_bundle_durable_in(
                &node.request_context(),
                OWNER,
                b"checked-but-not-queued",
                pull_number(2),
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &command.merge,
                &retained_landing,
            ))
            .unwrap();
        assert!(matches!(
            ordinary.1.outcome,
            DecisionOutcome::Refused {
                code: RefusalCode::ProtectedRefTransitionDenied,
                ..
            }
        ));
        let before = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        let accepted = land(b"canonical-queue-check");
        assert!(matches!(
            accepted.1.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let after = node
            .runtime()
            .block_on(node.materialize_admission())
            .unwrap();
        assert_eq!(after.snapshot().refs[&target_ref()], candidate);
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        assert_eq!(after.snapshot().refs[&second_ref()], second);
        assert_eq!(
            after
                .basis()
                .body()
                .latest_repository_sequence
                .unwrap()
                .get(),
            before
                .basis()
                .body()
                .latest_repository_sequence
                .unwrap()
                .get()
                + 1
        );
        let remaining = node
            .runtime()
            .block_on(node.read_queue_in(
                &node.request_context(),
                &Default::default(),
                QueueNumber::FIRST,
                None,
            ))
            .unwrap()
            .queue
            .unwrap();
        assert_eq!(remaining.version, version(4));
        assert_eq!(remaining.deterministic_order(), vec![pull_number(1)]);
        assert!(
            poll(&f, &config)
                .unwrap()
                .contains("\"state\":\"queue_head_stale\"")
        );
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
    }
}

#[test]
fn reorder_selects_another_exact_candidate_and_restart_never_replays_either_event() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, false);
        let config = config();
        let first = poll(&f, &config).unwrap();
        let first_commit = json_string(
            first.split_once("\"merge_candidate\":").unwrap().1,
            "commit",
        )
        .to_owned();
        change_queue(
            &f,
            2,
            QueueCommandAction::Reorder {
                order: vec![pull_number(1), pull_number(2)],
            },
            b"reorder-head",
        );
        let second_poll = poll(&f, &config).unwrap();
        assert!(second_poll.contains("\"state\":\"dispatched\""));
        assert!(second_poll.contains("\"merge_queue\":{\"number\":\"1\",\"version\":\"3\""));
        assert!(second_poll.contains("\"pull_request\":\"1\""));
        let next_commit = json_string(
            second_poll.split_once("\"merge_candidate\":").unwrap().1,
            "commit",
        );
        assert_ne!(
            first_commit, next_commit,
            "ordered native parents bind the selected source"
        );
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
        assert_pr_refs(&f, second);
        assert_eq!(event_directories(&f).len(), 2);
        f.reopen();
        assert!(
            poll(&f, &config)
                .unwrap()
                .contains("\"state\":\"previously_settled\"")
        );
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
        let mut changed = metadata();
        changed.message = b"replacement configuration".to_vec();
        let changed = PullRequestMergeWatchConfig::try_new(
            ci_ref(),
            OWNER,
            changed,
            MergeProfile::PathMergeV1,
            MergeCommitStyle::TwoParent,
        )
        .unwrap();
        assert!(
            poll(&f, &changed).is_err(),
            "a changed config cannot escape original scope custody"
        );
        assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"xx");
        assert_pr_refs(&f, second);
    }
}

#[test]
fn unresolved_candidate_custody_blocks_reordered_head_and_conflicts_never_publish() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (mut f, second) = queued_fixture(format, false, true);
        let config = config();
        let directory = match poll(&f, &config) {
            Err(TrustedWorkflowFailure::Journal { directory, .. }) => directory,
            other => panic!("malformed real workflow retains admitted candidate: {other:?}"),
        };
        let original_event = fs::read(directory.join("event.json")).unwrap();
        let original_bundle = fs::read(directory.join("candidate.bundle")).unwrap();
        assert!(!directory.join("settled").exists());
        assert!(!f.root.join("executed").exists());
        change_queue(
            &f,
            2,
            QueueCommandAction::Reorder {
                order: vec![pull_number(1), pull_number(2)],
            },
            b"reorder-unresolved",
        );
        f.reopen();
        assert!(
            poll(&f, &config)
                .unwrap()
                .contains("\"state\":\"blocked_unresolved\"")
        );
        assert_eq!(
            fs::read(directory.join("event.json")).unwrap(),
            original_event
        );
        assert_eq!(
            fs::read(directory.join("candidate.bundle")).unwrap(),
            original_bundle
        );
        assert_eq!(event_directories(&f).len(), 1);
        assert!(!f.root.join("executed").exists());
        assert_pr_refs(&f, second);

        let (conflict, second) = queued_fixture(format, true, false);
        let before = generation(conflict.node());
        assert!(
            poll(&conflict, &config)
                .unwrap()
                .contains("\"state\":\"merge_conflicted\"")
        );
        assert_eq!(generation(conflict.node()), before);
        assert!(event_directories(&conflict).is_empty());
        assert!(!conflict.root.join("executed").exists());
        assert_pr_refs(&conflict, second);
        let current = conflict
            .node()
            .runtime()
            .block_on(conflict.node().materialize_admission())
            .unwrap();
        assert!(!current.snapshot().refs.contains_key(&ci_ref()));
    }
}
