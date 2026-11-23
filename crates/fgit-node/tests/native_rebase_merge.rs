#![forbid(unsafe_code)]
//! Real native histories, candidate bundles and file-backed atomic PR publication.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::NativeMergeMethod;
use fgit_authority::{ExpectedOld, IdempotencyKey, ProposedNew, RefCommand, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{
    PathReviewRule, PathReviewScope, ProtectedBranch, ProtectionCommand, ReviewProtection,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::preparation::rebase::resolutions::RebaseCommitResolution;
use fgit_forge::preparation::rebase::{
    EmptyCommitPolicy, PreparedRebase, RebaseCommitter, RebasePreparation, RebaseStepKind,
    RebaseStop,
};
use fgit_forge::preparation::resolution::{ConflictResolution, ResolutionChoice};
use fgit_forge::{AggregateVersion, ExpectedVersion, ForgeEventPayload, PullRequestNumber};
use fgit_node::{
    LoopbackReceiveSession, MaterializedAdmission, NodeConfig, NodeWorkspaceRefusal, OneNode,
};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RefusalCode, RepositoryId, TenantId, TxId,
};
use fgit_wire::visibility::RefVisibility;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-native-rebase-merge-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "preserving failed native rebase fixture: {}",
                self.0.display()
            );
        } else if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!(
                "could not remove native rebase fixture {}: {error}",
                self.0.display()
            );
        }
    }
}
const fn actor(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}
fn session(who: u8, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(who), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn target_ref() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn source_ref() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
}
fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0xb1; 16]),
        RepositoryId::from_bytes([0xb2; 16]),
    )
    .with_object_format(format)
    .with_worker_threads(2)
}
fn loose(root: &Path, format: GitHashAlgorithm, kind: GitObjectKind, body: &[u8]) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [
        format!("{} {}\0", kind.label(), body.len()).as_bytes(),
        body,
    ]
    .concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut zlib = vec![0x78, 0x01, 0x01];
    zlib.extend(length.to_le_bytes());
    zlib.extend((!length).to_le_bytes());
    zlib.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    zlib.extend(((b << 16) | a).to_be_bytes());
    let name = id.to_string();
    let directory = root.join("objects").join(&name[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&name[2..]), zlib).unwrap();
    id
}
fn tree(entries: &[(&[u8], u32, GitOid)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, mode, id) in entries {
        body.extend(format!("{mode:o} ").as_bytes());
        body.extend(*name);
        body.push(0);
        body.extend(id.as_bytes());
    }
    body
}
fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents {
        body.push_str(&format!("parent {parent}\n"));
    }
    body.push_str("author Original <original@example.invalid> 5 -0330\ncommitter Original <original@example.invalid> 6 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}
struct Fixture {
    node: OneNode,
    base: GitOid,
    first: GitOid,
    target: GitOid,
    source: GitOid,
    next_target: GitOid,
    next_source: GitOid,
    expected_tree: Vec<u8>,
    borrowed: [(GitOid, Vec<u8>); 2],
    data: PullRequestData,
}
/// 0: disjoint edits, 1: conflicting add, 2: both source edits already present,
/// 3: a merge commit inside the requested original suffix, 4: two conflict steps.
fn fixture(root: &Path, format: GitHashAlgorithm, mode: u8) -> Fixture {
    let path = root.join("source");
    fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        path.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
            GitHashAlgorithm::Sha256 => {
                "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n"
            }
        },
    )
    .unwrap();
    let put = |kind, bytes: &[u8]| loose(&path, format, kind, bytes);
    let keep = put(GitObjectKind::Blob, b"keep\n");
    let target_only = put(GitObjectKind::Blob, b"target-only\n");
    let selected_body = b"first source change\n".to_vec();
    let later_body = b"second source change\n".to_vec();
    let selected = put(GitObjectKind::Blob, &selected_body);
    let later = put(GitObjectKind::Blob, &later_body);
    let base_tree = put(GitObjectKind::Tree, &tree(&[(b"keep", 0o100644, keep)]));
    let first_tree = put(
        GitObjectKind::Tree,
        &tree(&[(b"keep", 0o100644, keep), (b"selected", 0o100755, selected)]),
    );
    let source_tree = put(
        GitObjectKind::Tree,
        &tree(&[
            (b"keep", 0o100644, keep),
            (b"later", 0o100644, later),
            (b"selected", 0o100755, selected),
        ]),
    );
    let expected_tree = tree(&[
        (b"keep", 0o100644, keep),
        (b"later", 0o100644, later),
        (b"selected", 0o100755, selected),
        (b"target", 0o100644, target_only),
    ]);
    let target_tree = put(
        GitObjectKind::Tree,
        &match mode {
            1 => tree(&[
                (b"keep", 0o100644, keep),
                (b"selected", 0o100755, target_only),
            ]),
            2 => expected_tree.clone(),
            4 => tree(&[
                (b"keep", 0o100644, keep),
                (b"later", 0o100644, target_only),
                (b"selected", 0o100755, target_only),
            ]),
            _ => tree(&[
                (b"keep", 0o100644, keep),
                (b"target", 0o100644, target_only),
            ]),
        },
    );
    let base = put(GitObjectKind::Commit, &commit(base_tree, &[], "base\n"));
    let target = put(
        GitObjectKind::Commit,
        &commit(target_tree, &[base], "target\n"),
    );
    let first = put(
        GitObjectKind::Commit,
        &commit(first_tree, &[base], "first original message\n"),
    );
    let parents = if mode == 3 {
        vec![first, target]
    } else {
        vec![first]
    };
    let source = put(
        GitObjectKind::Commit,
        &commit(source_tree, &parents, "second original message\n"),
    );
    let next_target = put(
        GitObjectKind::Commit,
        &commit(target_tree, &[target], "advanced target\n"),
    );
    let next_source = put(
        GitObjectKind::Commit,
        &commit(source_tree, &[source], "advanced source\n"),
    );
    for (name, id) in [
        ("main", target),
        ("topic", source),
        ("future-target", next_target),
        ("future-source", next_source),
    ] {
        fs::write(path.join("refs/heads").join(name), format!("{id}\n")).unwrap();
    }
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &node.request_context(),
            &path,
            actor(1),
            b"rebase-merge-import",
        ))
        .unwrap();
    assert_eq!(imported.commands.len(), 4);
    for command in &imported.commands {
        committed(&command.terminal);
    }
    let data = PullRequestData {
        source_ref: source_ref(),
        target_ref: target_ref(),
        source_tip: source,
        target_tip: target,
        title: "Rebase PR".into(),
        body: "Replay both source commits without rewriting its branch.".into(),
    };
    let command = PullRequestCommand {
        number: PullRequestNumber::FIRST,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: data.clone(),
    };
    let (_, opened) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(1, b"open-rebase-pr"),
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(&opened);
    Fixture {
        node,
        base,
        first,
        target,
        source,
        next_target,
        next_source,
        expected_tree,
        borrowed: [(selected, selected_body), (later, later_body)],
        data,
    }
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    node.runtime()
        .block_on(node.materialize_admission_in(&node.request_context()))
        .unwrap()
}
fn committed(outcome: &TerminalOutcome) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}
fn refused(outcome: &TerminalOutcome, expected: RefusalCode) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Refused { code, .. } if code == expected),
        "{outcome:?}"
    );
}
fn unchanged_effects(before: &MaterializedAdmission, after: &MaterializedAdmission) {
    assert_eq!(before.snapshot().refs, after.snapshot().refs);
    assert_eq!(before.snapshot().head_target, after.snapshot().head_target);
    assert_eq!(
        before.basis().body().ref_root,
        after.basis().body().ref_root
    );
    assert_eq!(
        before.basis().body().forge_position_root,
        after.basis().body().forge_position_root
    );
    assert_eq!(
        before.basis().body().outbox_root,
        after.basis().body().outbox_root
    );
    assert_eq!(
        before.basis().body().retention_root,
        after.basis().body().retention_root
    );
}
fn subject(f: &Fixture, epoch: PolicyEpoch) -> ReviewSubject {
    ReviewSubject {
        pull_request: PullRequestNumber::FIRST,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: source_ref(),
        target_ref: target_ref(),
        source_tip: f.source,
        target_tip: f.target,
        policy_epoch: epoch,
    }
}
fn committer() -> RebaseCommitter {
    RebaseCommitter {
        identity: "Rebaser <rebaser@example.invalid>".into(),
        timestamp: 100,
    }
}
struct Candidate {
    merge: NativeMerge,
    plan: PreparedRebase,
    bundle: Vec<u8>,
}
fn prepare(f: &Fixture, epoch: PolicyEpoch) -> Candidate {
    let before = snapshot(&f.node);
    let subject = subject(f, epoch);
    let prepared = f
        .node
        .runtime()
        .block_on(f.node.prepare_pull_request_rebase_bundle_in(
            &f.node.request_context(),
            &subject,
            &RefVisibility::new(),
            f.base,
            &committer(),
            Default::default(),
            EmptyCommitPolicy::Stop,
        ))
        .unwrap();
    assert_eq!(prepared.source_head, before.basis().id());
    assert_eq!(prepared.subject, subject);
    assert_eq!(snapshot(&f.node).basis(), before.basis());
    let RebasePreparation::Clean(plan) = prepared.preparation.outcome else {
        panic!("disjoint edits must form a complete clean series");
    };
    assert_eq!(plan.steps.len(), 2);
    assert_eq!(
        [plan.steps[0].original, plan.steps[1].original],
        [f.first, f.source]
    );
    assert!(
        plan.steps
            .iter()
            .all(|s| s.kind == RebaseStepKind::Replayed)
    );
    let bundle = prepared.preparation.bundle.unwrap();
    let offset = bundle.windows(2).position(|p| p == b"\n\n").unwrap() + 2;
    let header = std::str::from_utf8(&bundle[..offset]).unwrap();
    assert!(header.contains(&format!("{} refs/heads/main\n", plan.commit)));
    assert!(
        header
            .lines()
            .any(|line| line.starts_with(&format!("-{} ", f.target)))
    );
    assert!(!header.contains("refs/heads/topic"));
    let merge = NativeMerge {
        source_ref: source_ref(),
        source_tip: f.source,
        base_tip: f.base,
        target_ref: target_ref(),
        target_tip_before: f.target,
        merge_commit: plan.commit,
    };
    let candidate = Candidate {
        merge,
        plan,
        bundle,
    };
    assert_unplaced(f, &candidate);
    candidate
}
fn assert_unplaced(f: &Fixture, candidate: &Candidate) {
    for step in &candidate.plan.steps {
        if step.rewritten != f.target {
            assert!(
                f.node.read_git_object(step.rewritten).is_err(),
                "refused commit must remain unplaced"
            );
        }
    }
    assert_eq!(
        fs::read_dir(f.node.storage_root().join("staging"))
            .unwrap()
            .count(),
        0
    );
}
fn apply(
    node: &OneNode,
    candidate: &Candidate,
    key: &[u8],
    version: AggregateVersion,
) -> Result<(TxId, TerminalOutcome), NodeWorkspaceRefusal> {
    node.runtime()
        .block_on(node.apply_merge_bundle_with_method_durable_in(
            &node.request_context(),
            actor(2),
            key,
            PullRequestNumber::FIRST,
            ExpectedVersion::Exactly(version),
            &candidate.merge,
            &candidate.bundle,
            NativeMergeMethod::Rebase,
        ))
}
fn review(f: &Fixture, candidate: &Candidate, epoch: PolicyEpoch) -> CandidateReviewCommand {
    CandidateReviewCommand {
        review: ReviewCommand {
            expected_version: ExpectedVersion::NewStream,
            subject: subject(f, epoch),
            decision: ReviewDecision::Approve,
            reason: "Reviewed every rewritten commit and the complete resulting tree.".into(),
        },
        candidate: CandidateBinding {
            merge_base: f.base,
            commit: candidate.merge.merge_commit,
        },
    }
}

#[test]
fn two_rewrites_publish_target_pr_and_outbox_together_and_recover_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format, 0);
        let candidate = prepare(&f, PolicyEpoch::FIRST);
        let inspected = f
            .node
            .runtime()
            .block_on(f.node.inspect_pull_request_rebase_bundle_in(
                &f.node.request_context(),
                &subject(&f, PolicyEpoch::FIRST),
                f.base,
                candidate.plan.commit,
                &candidate.bundle,
                &RefVisibility::new(),
                None,
                &Default::default(),
            ))
            .unwrap();
        assert_eq!(inspected.commits.len(), 2);
        assert_eq!(inspected.commits[0].parent, f.target);
        assert_eq!(inspected.commits[1].parent, inspected.commits[0].id);
        assert_eq!(inspected.commits[1].id, candidate.plan.commit);
        for (index, rewritten) in inspected.commits.iter().enumerate() {
            assert_eq!(
                git_object_id(format, GitObjectKind::Commit, &rewritten.body),
                rewritten.id
            );
            let text = std::str::from_utf8(&rewritten.body).unwrap();
            assert!(text.contains("author Original <original@example.invalid> 5 -0330\n"));
            assert!(text.contains("committer Rebaser <rebaser@example.invalid> 100 +0000\n"));
            assert!(text.ends_with(if index == 0 {
                "first original message\n"
            } else {
                "second original message\n"
            }));
        }
        assert_eq!(
            inspected.comparisons.len(),
            3,
            "review includes each step and the overall source comparison"
        );
        let before = snapshot(&f.node);
        let accepted = apply(&f.node, &candidate, b"land-rebase", AggregateVersion::FIRST).unwrap();
        committed(&accepted.1);
        let after = snapshot(&f.node);
        assert_eq!(
            after.basis().generation().get(),
            before.basis().generation().get() + 1
        );
        assert_eq!(after.snapshot().refs[&target_ref()], candidate.plan.commit);
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        assert_eq!(
            after.snapshot().outbox.len(),
            before.snapshot().outbox.len() + 1
        );
        assert_ne!(
            after.basis().body().ref_root,
            before.basis().body().ref_root
        );
        assert_ne!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        assert_ne!(
            after.basis().body().outbox_root,
            before.basis().body().outbox_root
        );
        assert_eq!(
            f.node
                .read_git_object(candidate.plan.tree)
                .unwrap()
                .payload(),
            f.expected_tree
        );
        for rewritten in &inspected.commits {
            assert_eq!(
                f.node.read_git_object(rewritten.id).unwrap().payload(),
                rewritten.body
            );
        }
        let request = f.node.request_context();
        let history = f
            .node
            .runtime()
            .block_on(f.node.snapshot_history_in(&request))
            .unwrap();
        let last = history.last().unwrap();
        assert_eq!(last.batch.committed_rcrs.len(), 1);
        assert_eq!(last.batch.committed_rcrs[0].tx_id, accepted.0);
        assert_eq!(last.forge_events.len(), 1);
        assert_eq!(
            last.forge_events[0].payload,
            ForgeEventPayload::MergeCommittedNative(candidate.merge.clone())
        );
        let page = f
            .node
            .runtime()
            .block_on(
                f.node
                    .read_pull_requests_in(&request, &RefVisibility::new(), 0, 10, None),
            )
            .unwrap();
        assert_eq!(page.pull_requests[0].event, last.forge_events[0]);
        assert_eq!(page.pull_requests[0].data, Some(f.data.clone()));
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let retry = reopened
            .runtime()
            .block_on(reopened.apply_merge_bundle_with_method_durable_in(
                &reopened.request_context(),
                actor(2),
                b"land-rebase",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &candidate.merge,
                &[],
                NativeMergeMethod::Rebase,
            ))
            .unwrap();
        assert_eq!(retry, accepted);
        assert_eq!(snapshot(&reopened).basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn source_target_and_pr_changes_refuse_stale_rebase_without_partial_publication() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for movement in 0..3 {
            let scratch = Scratch::new();
            let f = fixture(&scratch.0, format, 0);
            let candidate = prepare(&f, PolicyEpoch::FIRST);
            if movement == 2 {
                let mut data = f.data.clone();
                data.title = "Changed after candidate inspection".into();
                let command = PullRequestCommand {
                    number: PullRequestNumber::FIRST,
                    expected_version: ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    action: PullRequestAction::Update,
                    data,
                };
                let (_, terminal) = f
                    .node
                    .runtime()
                    .block_on(f.node.admit_pull_request_durable_in(
                        &f.node.request_context(),
                        &session(1, b"change-pr"),
                        &command,
                        Default::default(),
                    ))
                    .unwrap();
                committed(&terminal);
            } else {
                let (name, old, new) = if movement == 0 {
                    (target_ref(), f.target, f.next_target)
                } else {
                    (source_ref(), f.source, f.next_source)
                };
                let moved = f
                    .node
                    .runtime()
                    .block_on(f.node.admit_branch_updates_durable_in(
                        &f.node.request_context(),
                        &session(1, b"move-ref"),
                        &[RefCommand {
                            name,
                            expected_old: ExpectedOld::Exactly(old),
                            proposed_new: ProposedNew::Update(new),
                            force: false,
                        }],
                        Default::default(),
                    ))
                    .unwrap();
                committed(&moved.commands[0].terminal);
            }
            let before = snapshot(&f.node);
            let rejected = apply(
                &f.node,
                &candidate,
                b"stale-rebase",
                AggregateVersion::FIRST,
            )
            .unwrap();
            refused(
                &rejected.1,
                if movement == 2 {
                    RefusalCode::EvidenceStale
                } else {
                    RefusalCode::TargetRefMoved
                },
            );
            let after = snapshot(&f.node);
            unchanged_effects(&before, &after);
            assert_eq!(
                apply(
                    &f.node,
                    &candidate,
                    b"stale-rebase",
                    AggregateVersion::FIRST
                )
                .unwrap(),
                rejected
            );
            assert_eq!(snapshot(&f.node).basis(), after.basis());
            assert_unplaced(&f, &candidate);
            f.node.shutdown().unwrap();
        }
    }
}

struct Objects(BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
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
fn nonlinear_bundle(f: &Fixture, candidate: &Candidate) -> (GitOid, Vec<u8>) {
    let format = f.target.algorithm();
    let mut objects = Objects(
        candidate
            .plan
            .objects
            .iter()
            .map(|o| (o.id, (o.kind, o.body.clone())))
            .collect(),
    );
    for (id, body) in &f.borrowed {
        objects.0.insert(*id, (GitObjectKind::Blob, body.clone()));
    }
    let (_, body) = objects.0.remove(&candidate.plan.commit).unwrap();
    let marker = body
        .windows(b"\nauthor ".len())
        .position(|w| w == b"\nauthor ")
        .unwrap();
    let mut changed = body[..marker].to_vec();
    changed.extend(format!("\nparent {}", f.target).as_bytes());
    changed.extend(&body[marker..]);
    let id = git_object_id(format, GitObjectKind::Commit, &changed);
    objects.0.insert(id, (GitObjectKind::Commit, changed));
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
    bundle.extend(format!("-{} onto\n{id} refs/heads/main\n\n", f.target).as_bytes());
    bundle.extend(pack);
    (id, bundle)
}

#[test]
fn malformed_series_and_cancelled_requests_never_place_candidates_and_clean_retry_succeeds() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format, 0);
        let candidate = prepare(&f, PolicyEpoch::FIRST);
        let (malformed_id, malformed) = nonlinear_bundle(&f, &candidate);
        let mut coordinates = candidate.merge.clone();
        coordinates.merge_commit = malformed_id;
        let before = snapshot(&f.node);
        let rejected = f
            .node
            .runtime()
            .block_on(f.node.apply_merge_bundle_with_method_durable_in(
                &f.node.request_context(),
                actor(2),
                b"nonlinear",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &coordinates,
                &malformed,
                NativeMergeMethod::Rebase,
            ))
            .unwrap();
        refused(&rejected.1, RefusalCode::EvidenceInvalid);
        unchanged_effects(&before, &snapshot(&f.node));
        assert!(f.node.read_git_object(malformed_id).is_err());
        assert_unplaced(&f, &candidate);
        assert_eq!(
            f.node
                .runtime()
                .block_on(f.node.apply_merge_bundle_with_method_durable_in(
                    &f.node.request_context(),
                    actor(2),
                    b"nonlinear",
                    PullRequestNumber::FIRST,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    &coordinates,
                    &[],
                    NativeMergeMethod::Rebase,
                ))
                .unwrap(),
            rejected
        );
        let request = f.node.request_context();
        request.cancel();
        assert!(
            f.node
                .runtime()
                .block_on(f.node.apply_merge_bundle_with_method_durable_in(
                    &request,
                    actor(2),
                    b"cancelled-rebase",
                    PullRequestNumber::FIRST,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    &candidate.merge,
                    &candidate.bundle,
                    NativeMergeMethod::Rebase,
                ))
                .is_err()
        );
        unchanged_effects(&before, &snapshot(&f.node));
        assert_unplaced(&f, &candidate);
        committed(
            &apply(
                &f.node,
                &candidate,
                b"cancelled-rebase",
                AggregateVersion::FIRST,
            )
            .unwrap()
            .1,
        );
        f.node.shutdown().unwrap();
    }
}

#[test]
fn preparation_is_read_only_on_conflicts_non_linear_originals_empty_results_and_cancellation() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in 0..4 {
            let scratch = Scratch::new();
            let f = fixture(&scratch.0, format, mode);
            let before = snapshot(&f.node);
            let request = f.node.request_context();
            if mode == 0 {
                request.cancel();
            }
            let prepared = f
                .node
                .runtime()
                .block_on(f.node.prepare_pull_request_rebase_bundle_in(
                    &request,
                    &subject(&f, PolicyEpoch::FIRST),
                    &RefVisibility::new(),
                    f.base,
                    &committer(),
                    Default::default(),
                    if mode == 2 {
                        EmptyCommitPolicy::Drop
                    } else {
                        EmptyCommitPolicy::Stop
                    },
                ));
            if mode == 1 {
                let stopped = prepared.unwrap();
                assert!(matches!(
                    stopped.preparation.outcome,
                    RebasePreparation::Stopped { .. }
                ));
                assert!(stopped.preparation.bundle.is_none());
            } else {
                assert!(
                    prepared.is_err(),
                    "cancelled, empty landing and nonlinear original history refuse"
                );
            }
            assert_eq!(snapshot(&f.node).basis(), before.basis());
            assert_eq!(
                fs::read_dir(f.node.storage_root().join("staging"))
                    .unwrap()
                    .count(),
                0
            );
            if mode == 0 {
                let candidate = prepare(&f, PolicyEpoch::FIRST);
                committed(
                    &apply(
                        &f.node,
                        &candidate,
                        b"fresh-after-cancellation",
                        AggregateVersion::FIRST,
                    )
                    .unwrap()
                    .1,
                );
            }
            f.node.shutdown().unwrap();
        }
    }
}

#[test]
fn exact_head_pr_resolutions_reconstruct_the_whole_series_without_rewriting_source() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format, 4);
        let before = snapshot(&f.node);
        let subject = subject(&f, PolicyEpoch::FIRST);
        let first = RebaseCommitResolution {
            original: f.first,
            paths: vec![ConflictResolution {
                path: b"selected".to_vec(),
                choice: ResolutionChoice::Theirs,
            }],
        };
        let resolved_bytes = b"\0exact binary resolution\xff\r\n";
        let second = RebaseCommitResolution {
            original: f.source,
            paths: vec![ConflictResolution {
                path: b"later".to_vec(),
                choice: ResolutionChoice::File {
                    mode: 0o100755,
                    bytes: resolved_bytes.to_vec(),
                },
            }],
        };
        let resolve = |head, recipes: &[RebaseCommitResolution]| {
            f.node
                .runtime()
                .block_on(f.node.prepare_resolved_pull_request_rebase_bundle_in(
                    &f.node.request_context(),
                    &subject,
                    &RefVisibility::new(),
                    head,
                    f.base,
                    &committer(),
                    Default::default(),
                    EmptyCommitPolicy::Stop,
                    recipes,
                ))
        };
        let (stopped, receipts) =
            resolve(before.basis().id(), std::slice::from_ref(&first)).unwrap();
        assert_eq!(stopped.source_head, before.basis().id());
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].original, f.first);
        let RebasePreparation::Stopped {
            original,
            completed,
            reason: RebaseStop::Conflicted(conflicts),
            ..
        } = stopped.preparation.outcome
        else {
            panic!("the second original commit must stop after resolving the first");
        };
        assert_eq!(original, f.source);
        assert_eq!(completed.len(), 1);
        assert_eq!(conflicts[0].path, b"later");
        assert!(stopped.preparation.bundle.is_none());
        assert_eq!(stopped.preparation.pack_objects, 0);
        assert!(f.node.read_git_object(completed[0].rewritten).is_err());
        assert_eq!(snapshot(&f.node).basis(), before.basis());

        // Recipes cannot use provisional rewrites or resolve a clean path;
        // malformed recipes and empty requests cannot select automatic replay.
        let mut provisional = first.clone();
        provisional.original = completed[0].rewritten;
        let mut clean_path = first.clone();
        clean_path.paths[0].path = b"keep".to_vec();
        for invalid in [
            Vec::new(),
            vec![provisional],
            vec![clean_path],
            vec![first.clone(), first.clone()],
        ] {
            assert!(resolve(before.basis().id(), &invalid).is_err());
            assert_eq!(snapshot(&f.node).basis(), before.basis());
        }
        let recipes = [first, second];
        let (prepared, receipts) = resolve(before.basis().id(), &recipes).unwrap();
        assert_eq!(prepared.subject, subject);
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].original, f.first);
        assert_eq!(receipts[1].original, f.source);
        let selected = receipts[1].paths[0].result.as_ref().unwrap();
        assert_eq!(selected.mode, 0o100755);
        assert_eq!(
            selected.oid,
            git_object_id(format, GitObjectKind::Blob, resolved_bytes)
        );
        let RebasePreparation::Clean(plan) = prepared.preparation.outcome else {
            panic!("both original-bound recipes must produce a complete candidate");
        };
        assert_eq!(plan.steps.len(), 2);
        for object in plan
            .objects
            .iter()
            .filter(|object| object.kind == GitObjectKind::Commit)
        {
            let body = std::str::from_utf8(&object.body).unwrap();
            assert!(body.contains("author Original <original@example.invalid> 5 -0330\n"));
            assert!(body.contains("original message\n"));
        }
        let candidate = Candidate {
            merge: NativeMerge {
                source_ref: source_ref(),
                source_tip: f.source,
                base_tip: f.base,
                target_ref: target_ref(),
                target_tip_before: f.target,
                merge_commit: plan.commit,
            },
            plan,
            bundle: prepared.preparation.bundle.unwrap(),
        };
        let (retry, repeated_receipts) = resolve(before.basis().id(), &recipes).unwrap();
        assert_eq!(retry.preparation.bundle.as_ref(), Some(&candidate.bundle));
        assert_eq!(repeated_receipts, receipts);
        assert_unplaced(&f, &candidate);
        assert_eq!(snapshot(&f.node).basis(), before.basis());

        // Even an unrelated, valid publication invalidates the resolution pin;
        // unchanged PR coordinates cannot silently refresh the authority head.
        let unrelated = f
            .node
            .runtime()
            .block_on(f.node.admit_branch_updates_durable_in(
                &f.node.request_context(),
                &session(1, b"resolution-unrelated-ref"),
                &[RefCommand {
                    name: RefName::try_new(b"refs/heads/unrelated").unwrap(),
                    expected_old: ExpectedOld::Absent,
                    proposed_new: ProposedNew::Update(f.target),
                    force: false,
                }],
                Default::default(),
            ))
            .unwrap();
        committed(&unrelated.commands[0].terminal);
        let current = snapshot(&f.node);
        assert!(matches!(
            resolve(before.basis().id(), &recipes),
            Err(NodeWorkspaceRefusal::StaleWorkspaceBase)
        ));
        assert_eq!(snapshot(&f.node).basis(), current.basis());
        let (fresh, _) = resolve(current.basis().id(), &recipes).unwrap();
        assert_eq!(fresh.preparation.bundle.as_ref(), Some(&candidate.bundle));
        let inspected = f
            .node
            .runtime()
            .block_on(f.node.inspect_pull_request_rebase_bundle_in(
                &f.node.request_context(),
                &subject,
                f.base,
                candidate.plan.commit,
                &candidate.bundle,
                &RefVisibility::new(),
                None,
                &Default::default(),
            ))
            .unwrap();
        assert_eq!(inspected.commits.len(), 2);
        assert_eq!(inspected.commits[0].parent, f.target);
        assert_eq!(inspected.commits[1].parent, inspected.commits[0].id);
        committed(
            &apply(
                &f.node,
                &candidate,
                b"land-resolved-rebase",
                AggregateVersion::FIRST,
            )
            .unwrap()
            .1,
        );
        let after = snapshot(&f.node);
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        assert_eq!(after.snapshot().refs[&target_ref()], candidate.plan.commit);
        assert_eq!(
            after.snapshot().outbox.len(),
            current.snapshot().outbox.len() + 1
        );
        f.node.shutdown().unwrap();
    }
}

fn protect(node: &OneNode, queue_only: bool) -> PolicyEpoch {
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            ref_policy: None,
            administrators: vec![actor(1)],
            branches: vec![ProtectedBranch {
                name: target_ref(),
                path_reviews: Vec::new(),
                required_candidate_checks: Vec::new(),
                require_merge_queue: queue_only,
                required_approvals: u16::from(!queue_only),
                required_checks: Vec::new(),
                reviewers: if queue_only {
                    Vec::new()
                } else {
                    vec![actor(3)]
                },
            }],
        },
    };
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &node.request_context(),
            &session(1, b"protect-rebase"),
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(&terminal);
    PolicyEpoch::FIRST.next().unwrap()
}
fn vote(node: &OneNode, approval: &CandidateReviewCommand, bundle: Option<&[u8]>, key: &[u8]) {
    let (_, terminal) = node
        .runtime()
        .block_on(node.admit_rebase_candidate_review_durable_in(
            &node.request_context(),
            &session(3, key),
            approval,
            bundle,
            Default::default(),
        ))
        .unwrap();
    committed(&terminal);
}

#[test]
fn protected_rebase_requires_complete_candidate_review_and_current_vote_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format, 0);
        let epoch = protect(&f.node, false);
        let candidate = prepare(&f, epoch);
        let mut approval = review(&f, &candidate, epoch);
        let missing = apply(
            &f.node,
            &candidate,
            b"missing-series-review",
            AggregateVersion::FIRST,
        )
        .unwrap();
        refused(&missing.1, RefusalCode::EvidenceMissing);
        assert_unplaced(&f, &candidate);
        vote(
            &f.node,
            &approval,
            Some(&candidate.bundle),
            b"whole-series-review",
        );
        let mut withdrawn = approval.clone();
        withdrawn.review.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        withdrawn.review.decision = ReviewDecision::Withdraw;
        withdrawn.review.reason = "Withdraw the series approval.".into();
        vote(&f.node, &withdrawn, None, b"withdraw-rebase");
        let denied = apply(
            &f.node,
            &candidate,
            b"withdrawn-rebase",
            AggregateVersion::FIRST,
        )
        .unwrap();
        refused(&denied.1, RefusalCode::ProtectedRefTransitionDenied);
        assert_unplaced(&f, &candidate);
        approval.review.expected_version =
            ExpectedVersion::Exactly(AggregateVersion::try_new(2).unwrap());
        vote(
            &f.node,
            &approval,
            Some(&candidate.bundle),
            b"reapprove-rebase",
        );
        f.node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        assert_eq!(
            apply(
                &reopened,
                &candidate,
                b"missing-series-review",
                AggregateVersion::FIRST
            )
            .unwrap(),
            missing
        );
        let (_, accepted) = reopened
            .runtime()
            .block_on(reopened.apply_reviewed_merge_bundle_with_method_durable_in(
                &reopened.request_context(),
                actor(2),
                b"reviewed-rebase",
                PullRequestNumber::FIRST,
                ExpectedVersion::Exactly(AggregateVersion::FIRST),
                &candidate.merge,
                &candidate.bundle,
                epoch,
                &[actor(3)],
                NativeMergeMethod::Rebase,
            ))
            .unwrap();
        committed(&accepted);
        let after = snapshot(&reopened);
        assert_eq!(after.snapshot().refs[&target_ref()], candidate.plan.commit);
        assert_eq!(after.snapshot().refs[&source_ref()], f.source);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn queue_required_target_cannot_be_bypassed_by_rebase_and_merge() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format, 0);
        let epoch = protect(&f.node, true);
        let candidate = prepare(&f, epoch);
        let before = snapshot(&f.node);
        let denied = apply(
            &f.node,
            &candidate,
            b"queue-bypass",
            AggregateVersion::FIRST,
        )
        .unwrap();
        refused(&denied.1, RefusalCode::ProtectedRefTransitionDenied);
        unchanged_effects(&before, &snapshot(&f.node));
        assert_unplaced(&f, &candidate);
        f.node.shutdown().unwrap();
    }
}

fn add_transient_path(f: &Fixture, candidate: &mut Candidate) -> GitOid {
    let format = f.target.algorithm();
    let mut objects = Objects(
        candidate
            .plan
            .objects
            .iter()
            .map(|object| (object.id, (object.kind, object.body.clone())))
            .collect(),
    );
    for (id, bytes) in &f.borrowed {
        objects.0.insert(*id, (GitObjectKind::Blob, bytes.clone()));
    }
    let original_first = candidate.plan.steps[0].rewritten;
    let original_tree = candidate.plan.steps[0].tree;
    let (_, first_body) = objects.0.remove(&original_first).unwrap();
    let (_, mut first_tree) = objects.0.remove(&original_tree).unwrap();
    let (_, last_body) = objects.0.remove(&candidate.plan.commit).unwrap();
    let transient_body = b"temporary privileged content\n".to_vec();
    let transient = git_object_id(format, GitObjectKind::Blob, &transient_body);
    objects
        .0
        .insert(transient, (GitObjectKind::Blob, transient_body));
    first_tree.extend(b"100644 zz-private\0");
    first_tree.extend(transient.as_bytes());
    let changed_tree = git_object_id(format, GitObjectKind::Tree, &first_tree);
    objects
        .0
        .insert(changed_tree, (GitObjectKind::Tree, first_tree));
    let end_of_tree_line = first_body.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut changed_first = format!("tree {changed_tree}\n").into_bytes();
    changed_first.extend(&first_body[end_of_tree_line..]);
    let first = git_object_id(format, GitObjectKind::Commit, &changed_first);
    objects
        .0
        .insert(first, (GitObjectKind::Commit, changed_first));
    let changed_last = String::from_utf8(last_body)
        .unwrap()
        .replacen(
            &format!("parent {original_first}\n"),
            &format!("parent {first}\n"),
            1,
        )
        .into_bytes();
    let last = git_object_id(format, GitObjectKind::Commit, &changed_last);
    objects
        .0
        .insert(last, (GitObjectKind::Commit, changed_last));
    candidate.plan.steps[0].rewritten = first;
    candidate.plan.steps[0].tree = changed_tree;
    candidate.plan.steps[1].rewritten = last;
    candidate.plan.commit = last;
    candidate.merge.merge_commit = last;
    candidate.plan.objects = objects
        .0
        .iter()
        .map(
            |(id, (kind, body))| fgit_forge::preparation::PlannedMergeObject {
                id: *id,
                kind: *kind,
                body: body.clone(),
            },
        )
        .collect();
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
    bundle.extend(format!("-{} onto\n{last} refs/heads/main\n\n", f.target).as_bytes());
    bundle.extend(pack);
    candidate.bundle = bundle;
    transient
}

#[test]
fn transient_intermediate_path_requires_review_even_when_absent_from_final_tree() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let f = fixture(&scratch.0, format, 0);
        let protection = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: PolicyEpoch::FIRST,
            protection: ReviewProtection {
                administrators: vec![actor(1)],
                ref_policy: None,
                branches: vec![ProtectedBranch {
                    name: target_ref(),
                    reviewers: Vec::new(),
                    required_approvals: 0,
                    required_checks: Vec::new(),
                    required_candidate_checks: Vec::new(),
                    require_merge_queue: false,
                    path_reviews: vec![PathReviewRule {
                        path: b"zz-private".to_vec(),
                        scope: PathReviewScope::Exact,
                        reviewers: vec![actor(3)],
                        required_approvals: 1,
                    }],
                }],
            },
        };
        let (_, installed) = f
            .node
            .runtime()
            .block_on(f.node.admit_review_protection_durable_in(
                &f.node.request_context(),
                &session(1, b"protect-transient-path"),
                &protection,
                Default::default(),
            ))
            .unwrap();
        committed(&installed);
        let epoch = PolicyEpoch::FIRST.next().unwrap();
        let mut candidate = prepare(&f, epoch);
        let transient = add_transient_path(&f, &mut candidate);
        let inspected = f
            .node
            .runtime()
            .block_on(f.node.inspect_pull_request_rebase_bundle_in(
                &f.node.request_context(),
                &subject(&f, epoch),
                f.base,
                candidate.plan.commit,
                &candidate.bundle,
                &RefVisibility::new(),
                None,
                &Default::default(),
            ))
            .unwrap();
        assert!(
            inspected.comparisons[0]
                .entries
                .iter()
                .all(|entry| entry.path != b"zz-private")
        );
        assert!(inspected.comparisons[1..].iter().all(|comparison| {
            comparison
                .entries
                .iter()
                .any(|entry| entry.path == b"zz-private")
        }));
        assert_eq!(
            candidate.plan.tree,
            git_object_id(format, GitObjectKind::Tree, &f.expected_tree)
        );
        let before = snapshot(&f.node);
        let rejected = apply(
            &f.node,
            &candidate,
            b"transient-unreviewed",
            AggregateVersion::FIRST,
        )
        .unwrap();
        refused(&rejected.1, RefusalCode::EvidenceMissing);
        unchanged_effects(&before, &snapshot(&f.node));
        assert_unplaced(&f, &candidate);
        assert!(f.node.read_git_object(transient).is_err());
        vote(
            &f.node,
            &review(&f, &candidate, epoch),
            Some(&candidate.bundle),
            b"review-transient-series",
        );
        assert_eq!(
            apply(
                &f.node,
                &candidate,
                b"transient-unreviewed",
                AggregateVersion::FIRST
            )
            .unwrap(),
            rejected
        );
        committed(
            &apply(
                &f.node,
                &candidate,
                b"transient-reviewed",
                AggregateVersion::FIRST,
            )
            .unwrap()
            .1,
        );
        assert_eq!(
            f.node.read_git_object(transient).unwrap().payload(),
            b"temporary privileged content\n"
        );
        assert_eq!(
            f.node
                .read_git_object(candidate.plan.tree)
                .unwrap()
                .payload(),
            f.expected_tree
        );
        assert_eq!(snapshot(&f.node).snapshot().refs[&source_ref()], f.source);
        f.node.shutdown().unwrap();
    }
}
