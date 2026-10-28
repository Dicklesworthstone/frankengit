#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Real native PR selection, CI ref admission, host execution and recovery.
#[path = "trusted_merge_workflow/support.rs"]
mod support;
use support::*;

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::workflow_watch::PullRequestMergeWatchConfig;
use fgit_node::{LoopbackReceiveSession, TrustedWorkflowFailure};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, RefName};
use std::{collections::BTreeMap, fs, path::PathBuf};

struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.0.insert(id, (kind, body));
        id
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, body) = self
            .0
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            body.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}
fn ci_ref() -> RefName {
    RefName::try_new(b"refs/heads/ci/pr-1").unwrap()
}
fn session(key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(OWNER, IdempotencyKey::new(key.to_vec()).unwrap())
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "CI <ci@example.test>".into(),
        committer: "CI <ci@example.test>".into(),
        timestamp: 1700000000,
        message: b"CI candidate\n".to_vec(),
    }
}
fn config(style: MergeCommitStyle) -> PullRequestMergeWatchConfig {
    PullRequestMergeWatchConfig::try_new(
        ci_ref(),
        OWNER,
        metadata(),
        MergeProfile::PathMergeV1,
        style,
    )
    .unwrap()
}
fn read_inputs() -> Vec<Vec<u8>> {
    vec![b"ci".to_vec(), b"left".to_vec(), b"right".to_vec()]
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn workflow(filter: &str, command: &str) -> String {
    format!(
        "name: candidate\non:\n  pull_request:\n    branches:\n      - main\n    paths:\n      - {filter}\njobs:\n  check:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: {command}\n"
    )
}

// Add real workflow definitions above the original visible incoming history.
// Neither production nor this fixture invokes Git or a substitute VCS engine.
fn install_workflows(f: &mut Fixture, conflict: bool, malformed: bool) {
    let format = f.source.algorithm();
    let mut objects = Objects(BTreeMap::new());
    let command = format!(
        "test \"$(cat left)\" = target && test \"$(cat right)\" = source || exit 7; printf x >> '{}'",
        f.root.join("executed").display()
    );
    let main = if malformed {
        "name: broken\non: pull_request\njobs: invalid\n".into()
    } else {
        workflow("right", &command)
    };
    let selected = objects.put(format, GitObjectKind::Blob, main.into_bytes());
    let excluded = objects.put(
        format,
        GitObjectKind::Blob,
        workflow("left", "exit 61").into_bytes(),
    );
    let ci = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"100644 a.yml\0".as_slice(),
            selected.as_bytes(),
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
    let commit = objects.put(
        format,
        GitObjectKind::Commit,
        commit_bytes(tree, &[f.source], "native CI definitions"),
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
            "-{} original incoming\n{commit} refs/heads/topic\n\n",
            f.source
        )
        .as_bytes(),
    );
    bundle.extend_from_slice(&pack);
    let node = f.node();
    let result = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session(b"install-ci-definitions"),
            &bundle,
            &[(source_ref(), Some(f.source))],
            Default::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    f.source = commit;
}
fn pull(
    f: &Fixture,
    action: PullRequestAction,
    version: ExpectedVersion,
    source_tip: GitOid,
    key: &[u8],
) {
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: version,
        action,
        data: PullRequestData {
            source_ref: source_ref(),
            target_ref: target_ref(),
            source_tip,
            target_tip: f.target,
            title: "Exact candidate".into(),
            body: "Native fixture".into(),
        },
    };
    let node = f.node();
    let result = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(key),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(
        result.1.outcome,
        DecisionOutcome::Committed { .. }
    ));
}
fn poll(
    f: &Fixture,
    config: &PullRequestMergeWatchConfig,
) -> Result<String, TrustedWorkflowFailure> {
    let node = f.node();
    node.runtime()
        .block_on(node.poll_trusted_pull_request_merge_workflows_in(
            &node.request_context(),
            &source_ref(),
            1,
            b"ci",
            &f.parent(),
            &read_inputs(),
            Default::default(),
            None,
            config,
        ))
        .map(|p| p.to_json())
}
fn set_branch(f: &Fixture, name: RefName, old: Option<GitOid>, new: GitOid, key: &[u8]) {
    let format = new.algorithm();
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        format,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(&Objects(BTreeMap::new()), &[], &mut || true)
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = match format {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    bundle.extend_from_slice(format!("-{new} visible history\n{new} ").as_bytes());
    bundle.extend_from_slice(name.as_bytes());
    bundle.extend_from_slice(b"\n\n");
    bundle.extend_from_slice(&pack);
    let node = f.node();
    let result = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session(key),
            &bundle,
            &[(name, old)],
            Default::default(),
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
}
fn event_directories(f: &Fixture) -> Vec<PathBuf> {
    fs::read_dir(f.parent())
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry
                .file_name()
                .to_str()
                .filter(|name| name.starts_with("watch-"))
                .map(|_| entry.path())
        })
        .flat_map(|root| fs::read_dir(root).unwrap().map(Result::unwrap))
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("event-"))
        })
        .map(|entry| entry.path())
        .collect()
}
fn json_string<'a>(text: &'a str, name: &str) -> &'a str {
    text.split_once(&format!("\"{name}\":\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}

#[test]
fn exact_candidates_execute_and_recover_canonical_checks_in_both_formats_and_styles() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for style in [MergeCommitStyle::TwoParent, MergeCommitStyle::Squash] {
            let mut f = Fixture::new(format, WORKFLOW);
            install_workflows(&mut f, false, false);
            pull(
                &f,
                PullRequestAction::Open,
                ExpectedVersion::NewStream,
                f.source,
                b"open-pr",
            );
            let config = config(style);
            // Exercise replacing an existing CI tip, including squash rewrites.
            set_branch(&f, ci_ref(), None, f.source, b"seed-ci");
            let node = f.node();
            let prepared = node
                .runtime()
                .block_on(node.prepare_merge_bundle_with_options_in(
                    &node.request_context(),
                    &target_ref(),
                    &source_ref(),
                    &Default::default(),
                    &metadata(),
                    Default::default(),
                    MergeProfile::PathMergeV1,
                    style,
                ))
                .unwrap();
            let MergePreparation::Clean(expected) = prepared.outcome else {
                panic!("clean candidate");
            };
            let observation = node
                .runtime()
                .block_on(node.poll_trusted_pull_request_merge_workflows_in(
                    &node.request_context(),
                    &source_ref(),
                    1,
                    b"ci",
                    &f.parent(),
                    &read_inputs(),
                    Default::default(),
                    None,
                    &config,
                ))
                .unwrap();
            assert_eq!(observation.state(), "dispatched");
            assert!(observation.execution_settled());
            assert!(!observation.non_green());
            let dispatch = observation.dispatch().unwrap();
            assert!(dispatch.succeeded(), "{}", dispatch.to_json());
            assert_eq!(
                dispatch.runs().len(),
                1,
                "target-only path must not select excluded.yml"
            );
            assert_eq!(dispatch.runs()[0].executed_commit(), expected.commit);
            assert_eq!(dispatch.runs()[0].executed_tree(), expected.tree);
            let json = observation.to_json();
            assert!(json.contains(&format!("\"after\":\"{}\"", f.source)));
            assert!(json.contains(&format!(
                "\"trigger_ref_hex\":\"{}\"",
                hex(target_ref().as_bytes())
            )));
            assert!(json.contains(&format!(
                "\"source_ref_hex\":\"{}\"",
                hex(ci_ref().as_bytes())
            )));
            assert!(!json.contains("unpublished_candidate"));
            assert!(json.contains(&format!("\"expected_old\":\"{}\"", f.source)));
            let event = dispatch.run_directory.parent().unwrap();
            assert!(event.join("candidate.bundle").is_file());
            assert!(
                fs::read_to_string(event.join("candidate-publication.json"))
                    .unwrap()
                    .contains("\"committed\":true")
            );
            let current = node
                .runtime()
                .block_on(node.materialize_admission())
                .unwrap();
            assert_eq!(current.snapshot().refs[&ci_ref()], expected.commit);
            assert_eq!(current.snapshot().refs[&source_ref()], f.source);
            assert_eq!(current.snapshot().refs[&target_ref()], f.target);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
            drop(observation);
            f.reopen();
            assert!(
                poll(&f, &config)
                    .unwrap()
                    .contains("\"state\":\"previously_settled\"")
            );
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
            let node = f.node();
            let mut reports = Vec::new();
            let published = node.runtime().block_on(
                node.publish_trusted_pull_request_merge_workflow_checks_in(
                    &node.request_context(),
                    &source_ref(),
                    1,
                    b"ci",
                    &f.parent(),
                    OWNER,
                    &config,
                    |record| {
                        reports.push(record.to_owned());
                        Ok(())
                    },
                ),
            );
            assert!(published.error.is_none(), "{:?}", published.error);
            assert_eq!(published.committed, 1);
            assert_eq!(published.refused, 0);
            assert!(reports.iter().any(|record| {
                record.contains(&format!("\"source_commit\":\"{}\"", expected.commit))
                    && record.contains(&format!(
                        "\"source_ref_hex\":\"{}\"",
                        hex(ci_ref().as_bytes())
                    ))
            }));
            let source_checks = node
                .runtime()
                .block_on(node.read_pull_request_checks_in(
                    &node.request_context(),
                    &Default::default(),
                    PullRequestNumber::FIRST,
                    None,
                    100,
                    None,
                ))
                .unwrap()
                .unwrap();
            assert!(
                source_checks.checks.is_empty(),
                "candidate evidence must not be relabeled as source-head evidence"
            );
            let after = generation(node);
            let again = node.runtime().block_on(
                node.publish_trusted_pull_request_merge_workflow_checks_in(
                    &node.request_context(),
                    &source_ref(),
                    1,
                    b"ci",
                    &f.parent(),
                    OWNER,
                    &config,
                    |_| Ok(()),
                ),
            );
            assert!(again.error.is_none());
            assert_eq!(again.previously_reported, 1);
            assert_eq!(generation(node), after);
            assert_eq!(fs::read(f.root.join("executed")).unwrap(), b"x");
        }
    }
}

#[test]
fn stale_pr_conflicts_and_ref_aliases_never_reserve_or_execute() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        pull(
            &f,
            PullRequestAction::Open,
            ExpectedVersion::NewStream,
            f.source,
            b"open-pr",
        );
        install_workflows(&mut f, false, false);
        let config = config(MergeCommitStyle::TwoParent);
        let before = generation(f.node());
        let observation = poll(&f, &config).unwrap();
        assert!(observation.contains("\"state\":\"pull_request_stale\""));
        assert_eq!(generation(f.node()), before);
        assert!(event_directories(&f).is_empty());
        assert!(!f.root.join("executed").exists());
        // Explicit canonical metadata refresh, not a silent watcher substitution.
        pull(
            &f,
            PullRequestAction::Update,
            ExpectedVersion::Exactly(AggregateVersion::FIRST),
            f.source,
            b"refresh-pr",
        );
        assert!(
            poll(&f, &config)
                .unwrap()
                .contains("\"state\":\"dispatched\"")
        );

        let mut conflict = Fixture::new(format, WORKFLOW);
        install_workflows(&mut conflict, true, false);
        pull(
            &conflict,
            PullRequestAction::Open,
            ExpectedVersion::NewStream,
            conflict.source,
            b"open-pr",
        );
        let before = generation(conflict.node());
        assert!(
            poll(&conflict, &config)
                .unwrap()
                .contains("\"state\":\"merge_conflicted\"")
        );
        assert_eq!(generation(conflict.node()), before);
        assert!(event_directories(&conflict).is_empty());
        assert!(!conflict.root.join("executed").exists());
        let state = conflict
            .node()
            .runtime()
            .block_on(conflict.node().materialize_admission())
            .unwrap();
        assert!(!state.snapshot().refs.contains_key(&ci_ref()));
        for reference in [source_ref(), target_ref()] {
            // Use a fresh custody parent because immutable selection binding is
            // itself required to refuse configuration changes in an old scope.
            let parent = conflict
                .root
                .join(format!("alias-{}", hex(reference.as_bytes())));
            fs::create_dir(&parent).unwrap();
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            let alias = PullRequestMergeWatchConfig::try_new(
                reference,
                OWNER,
                metadata(),
                MergeProfile::PathMergeV1,
                MergeCommitStyle::TwoParent,
            )
            .unwrap();
            let node = conflict.node();
            assert!(
                node.runtime()
                    .block_on(node.poll_trusted_pull_request_merge_workflows_in(
                        &node.request_context(),
                        &source_ref(),
                        1,
                        b"ci",
                        &parent,
                        &read_inputs(),
                        Default::default(),
                        None,
                        &alias,
                    ))
                    .is_err()
            );
            assert_eq!(generation(node), before);
        }
    }
}

#[test]
fn interrupted_custody_keeps_original_candidate_key_and_lease_and_blocks_replay() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut f = Fixture::new(format, WORKFLOW);
        install_workflows(&mut f, false, true);
        pull(
            &f,
            PullRequestAction::Open,
            ExpectedVersion::NewStream,
            f.source,
            b"open-pr",
        );
        let config = config(MergeCommitStyle::TwoParent);
        let directory = match poll(&f, &config) {
            Err(TrustedWorkflowFailure::Journal { directory, .. }) => directory,
            result => {
                panic!("malformed workflow must retain admitted candidate custody: {result:?}")
            }
        };
        assert!(!directory.join("settled").exists());
        assert!(!f.root.join("executed").exists());
        let event = fs::read_to_string(directory.join("event.json")).unwrap();
        assert!(event.contains("\"expected_old\":null"));
        let candidate_section = event.split_once("\"merge_candidate\":").unwrap().1;
        let candidate = GitOid::from_hex(format, json_string(candidate_section, "commit")).unwrap();
        let key_hex = json_string(candidate_section, "publication_key");
        let key = (0..key_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&key_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let bundle = fs::read(directory.join("candidate.bundle")).unwrap();
        // An independent ordinary ref writer moves CI after the original commit.
        set_branch(
            &f,
            ci_ref(),
            Some(candidate),
            f.source,
            b"independent-ci-writer",
        );
        let node = f.node();
        let after_move = generation(node);
        let historical = node
            .runtime()
            .block_on(node.import_incremental_git_bundle_durable_in(
                &node.request_context(),
                &session(&key),
                &bundle,
                &[(ci_ref(), None)],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            historical.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(
            generation(node),
            after_move,
            "original key recovers a decision, never overwrites the new tip"
        );
        // A fresh competing request with that original absent lease is refused.
        let stale = node
            .runtime()
            .block_on(node.import_incremental_git_bundle_durable_in(
                &node.request_context(),
                &session(b"competing-original-absent-lease"),
                &bundle,
                &[(ci_ref(), None)],
                Default::default(),
            ))
            .unwrap();
        assert!(matches!(
            stale.commands[0].terminal.outcome,
            DecisionOutcome::Refused { .. }
        ));
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission())
                .unwrap()
                .snapshot()
                .refs[&ci_ref()],
            f.source
        );
        f.reopen();
        let before = generation(f.node());
        assert!(
            poll(&f, &config)
                .unwrap()
                .contains("\"state\":\"blocked_unresolved\"")
        );
        assert_eq!(generation(f.node()), before);
        assert_eq!(
            fs::read(directory.join("candidate.bundle")).unwrap(),
            bundle
        );
        assert!(!f.root.join("executed").exists());
        let mut changed = metadata();
        changed.timestamp += 1;
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
            "configuration changes must not escape unresolved custody"
        );
        let node = f.node();
        let published =
            node.runtime()
                .block_on(node.publish_trusted_pull_request_merge_workflow_checks_in(
                    &node.request_context(),
                    &source_ref(),
                    1,
                    b"ci",
                    &f.parent(),
                    OWNER,
                    &config,
                    |_| Ok(()),
                ));
        assert!(published.error.is_some());
        assert_eq!(published.committed, 0);
    }
}
