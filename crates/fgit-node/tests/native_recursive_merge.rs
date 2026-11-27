#![forbid(unsafe_code)]
//! Criss-cross history through real snapshot selection, artifact inspection,
//! native admission, atomic PR publication and original-key recovery.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::NativeMergeMethod;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{CandidateBinding, ReviewSubject};
use fgit_forge::preparation::{
    MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile, PreparationError,
    PreparationLimits,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{
    LoopbackReceiveSession, MaterializedAdmission, NodeConfig, NodeWorkspaceRefusal, OneNode,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RepositoryAuthorityHeadId, RepositoryId, TenantId,
};
use fgit_wire::visibility::RefVisibility;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-native-recursive-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn config(root: &Path, format: GitHashAlgorithm) -> NodeConfig {
    NodeConfig::new(
        root.join("node"),
        TenantId::from_bytes([0xe1; 16]),
        RepositoryId::from_bytes([0xe2; 16]),
    )
    .with_object_format(format)
}

fn branch(name: &[u8]) -> RefName {
    RefName::try_new(name).unwrap()
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

fn tree(a: GitOid, b: GitOid) -> Vec<u8> {
    [
        b"100644 a\0".as_slice(),
        a.as_bytes(),
        b"100644 b\0",
        b.as_bytes(),
    ]
    .concat()
}

fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut body = format!("tree {tree}\n");
    for parent in parents {
        body.push_str(&format!("parent {parent}\n"));
    }
    body.push_str("author Fixture <test@example.invalid> 1 +0000\ncommitter Fixture <test@example.invalid> 1 +0000\n\n");
    body.push_str(message);
    body.into_bytes()
}

struct Fixture {
    node: OneNode,
    subject: ReviewSubject,
    bases: Vec<GitOid>,
    virtual_tree: GitOid,
    expected_tree: GitOid,
}

fn fixture(root: &Path, format: GitHashAlgorithm) -> Fixture {
    let (mut node, _) = OneNode::init(config(root, format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let path = root.join("source");
    fs::create_dir_all(path.join("refs/heads")).unwrap();
    fs::write(path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(
        path.join("config"),
        match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        },
    )
    .unwrap();
    let a = loose(&path, format, GitObjectKind::Blob, b"a\n");
    let b = loose(&path, format, GitObjectKind::Blob, b"b\n");
    let changed_a = loose(&path, format, GitObjectKind::Blob, b"A\n");
    let changed_b = loose(&path, format, GitObjectKind::Blob, b"B\n");
    let original_tree = loose(&path, format, GitObjectKind::Tree, &tree(a, b));
    let left_tree = loose(&path, format, GitObjectKind::Tree, &tree(changed_a, b));
    let right_tree = loose(&path, format, GitObjectKind::Tree, &tree(a, changed_b));
    let base = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(original_tree, &[], "root\n"),
    );
    let left = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(left_tree, &[base], "left\n"),
    );
    let right = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(right_tree, &[base], "right\n"),
    );
    // Both tips descend from both incomparable bases, but each reverts a
    // different change. Picking either original base loses the other revert.
    let target = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(right_tree, &[left, right], "revert a\n"),
    );
    let source = loose(
        &path,
        format,
        GitObjectKind::Commit,
        &commit(left_tree, &[right, left], "revert b\n"),
    );
    for (name, tip) in [("main", target), ("topic", source)] {
        fs::write(path.join("refs/heads").join(name), format!("{tip}\n")).unwrap();
    }
    let actor = PrincipalId::from_bytes([1; 16]);
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &path,
            actor,
            b"recursive-fixture-import",
        ))
        .unwrap();
    assert_eq!(imported.commands.len(), 2);
    for command in &imported.commands {
        committed(&command.terminal);
    }
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::FIRST,
        pull_request_version: AggregateVersion::FIRST,
        source_ref: branch(b"refs/heads/topic"),
        target_ref: branch(b"refs/heads/main"),
        source_tip: source,
        target_tip: target,
        policy_epoch: PolicyEpoch::FIRST,
    };
    let command = PullRequestCommand {
        number: subject.pull_request,
        expected_version: ExpectedVersion::NewStream,
        action: PullRequestAction::Open,
        data: PullRequestData {
            source_ref: subject.source_ref.clone(),
            target_ref: subject.target_ref.clone(),
            source_tip: source,
            target_tip: target,
            title: "Criss-cross reverts".into(),
            body: "Preserve each branch's independent revert.".into(),
        },
    };
    let session = LoopbackReceiveSession::authenticated(
        actor,
        IdempotencyKey::new(b"open-recursive-pr".to_vec()).unwrap(),
    );
    let (_, opened) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &request,
            &session,
            &command,
            Default::default(),
        ))
        .unwrap();
    committed(&opened);
    let mut bases = vec![left, right];
    bases.sort();
    Fixture {
        node,
        subject,
        bases,
        // Deliberately never stored in the source repository. This is a tree,
        // not a synthetic commit and never an admitted ancestry witness.
        virtual_tree: git_object_id(format, GitObjectKind::Tree, &tree(changed_a, changed_b)),
        expected_tree: original_tree,
    }
}

fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

fn committed(outcome: &TerminalOutcome) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}

struct PreparedCandidate {
    source_head: RepositoryAuthorityHeadId,
    subject: ReviewSubject,
    outcome: MergePreparation,
    bundle: Option<Vec<u8>>,
}

fn prepare(
    f: &Fixture,
    style: MergeCommitStyle,
    profile: MergeProfile,
    limits: PreparationLimits,
) -> Result<PreparedCandidate, NodeWorkspaceRefusal> {
    let request = f.node.request_context();
    f.node
        .runtime()
        .block_on(f.node.prepare_pull_request_bundle_with_options_in(
            &request,
            &f.subject,
            &RefVisibility::new(),
            &MergeMetadata {
                author: "Fixture <test@example.invalid>".into(),
                committer: "Fixture <test@example.invalid>".into(),
                timestamp: 1,
                message: b"combine both reverts\n".to_vec(),
            },
            limits,
            profile,
            style,
        ))
        .map(|prepared| PreparedCandidate {
            source_head: prepared.source_head,
            subject: prepared.subject,
            outcome: prepared.outcome,
            bundle: prepared.bundle,
        })
}

#[test]
fn recursive_criss_cross_preserves_both_reverts_and_publishes_with_real_ancestry_after_restart() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for (style, method) in [
            (MergeCommitStyle::TwoParent, NativeMergeMethod::MergeCommit),
            (MergeCommitStyle::Squash, NativeMergeMethod::Squash),
        ] {
            let scratch = Scratch::new();
            let f = fixture(&scratch.0, format);
            let before = snapshot(&f.node);
            assert!(matches!(
                prepare(&f, style, MergeProfile::PathMergeV1, Default::default()),
                Err(NodeWorkspaceRefusal::MergePreparation(
                    PreparationError::MultipleMergeBases(bases)
                )) if bases == f.bases
            ));
            assert!(
                matches!(
                    prepare(
                        &f,
                        style,
                        MergeProfile::RecursivePathMergeV1,
                        PreparationLimits { max_objects: 1, ..Default::default() },
                    ),
                    Err(NodeWorkspaceRefusal::MergePreparation(
                        PreparationError::Budget("objects")
                    ))
                ),
                "virtual construction must consume the caller's aggregate object budget"
            );
            let prepared = prepare(
                &f, style, MergeProfile::RecursivePathMergeV1, Default::default(),
            ).unwrap();
            let repeated = prepare(
                &f, style, MergeProfile::RecursivePathMergeV1, Default::default(),
            ).unwrap();
            assert_eq!(prepared.source_head, before.basis().id());
            assert_eq!(prepared.subject, f.subject);
            assert_eq!(prepared.outcome, repeated.outcome);
            assert_eq!(prepared.bundle, repeated.bundle);
            assert_eq!(
                snapshot(&f.node).basis(),
                before.basis(),
                "all construction remains read-only"
            );
            let MergePreparation::Clean(plan) = prepared.outcome else {
                panic!("the merged base makes both independent reverts unambiguous");
            };
            let evidence = plan.recursive_base.as_ref().expect("explicit recursive receipt");
            assert_eq!(evidence.bases, f.bases);
            assert_eq!(evidence.tree, f.virtual_tree);
            assert_eq!(plan.base, f.bases[0]);
            assert_eq!(plan.tree, f.expected_tree);
            assert!(f.node.read_git_object(plan.commit).is_err());
            assert!(f.node.read_git_object(f.virtual_tree).is_err());
            assert!(
                plan.objects.iter().all(|object| object.id != f.virtual_tree),
                "virtual-only objects must not leak into the candidate closure"
            );
            let parents = match style {
                MergeCommitStyle::TwoParent => vec![f.subject.target_tip, f.subject.source_tip],
                MergeCommitStyle::Squash => vec![f.subject.target_tip],
            };
            let expected_body = commit(f.expected_tree, &parents, "combine both reverts\n");
            assert_eq!(
                plan.commit,
                git_object_id(format, GitObjectKind::Commit, &expected_body)
            );
            let bundle = prepared.bundle.unwrap();
            let merge = NativeMerge {
                source_ref: f.subject.source_ref.clone(),
                source_tip: f.subject.source_tip,
                base_tip: plan.base,
                target_ref: f.subject.target_ref.clone(),
                target_tip_before: f.subject.target_tip,
                merge_commit: plan.commit,
            };
            let request = f.node.request_context();
            let inspected = f.node.runtime().block_on(f.node.inspect_pull_request_bundle_in(
                &request,
                &f.subject,
                CandidateBinding { merge_base: plan.base, commit: plan.commit },
                &bundle,
                &RefVisibility::new(),
                &Default::default(),
            )).unwrap();
            assert_eq!(inspected.parents, parents);
            assert_eq!(inspected.candidate_commit_body, expected_body);
            assert_eq!(snapshot(&f.node).basis(), before.basis());
            let actor = PrincipalId::from_bytes([2; 16]);
            let expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
            let accepted = f.node.runtime().block_on(
                f.node.apply_merge_bundle_with_method_durable_in(
                    &request,
                    actor,
                    b"land-recursive",
                    PullRequestNumber::FIRST,
                    expected_version,
                    &merge,
                    &bundle,
                    method,
                ),
            ).unwrap();
            committed(&accepted.1);
            let after = snapshot(&f.node);
            assert_eq!(
                after.basis().generation().get(),
                before.basis().generation().get() + 1
            );
            assert_eq!(after.snapshot().refs[&f.subject.target_ref], plan.commit);
            assert_eq!(after.snapshot().refs[&f.subject.source_ref], f.subject.source_tip);
            assert_eq!(after.snapshot().outbox.len(), before.snapshot().outbox.len() + 1);
            assert_ne!(
                after.basis().body().forge_position_root,
                before.basis().body().forge_position_root
            );
            assert_eq!(f.node.read_git_object(plan.commit).unwrap().payload(), expected_body);
            assert!(f.node.read_git_object(f.virtual_tree).is_err());
            f.node.shutdown().unwrap();
            let mut reopened = OneNode::open_existing(config(&scratch.0, format)).unwrap();
            reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
            let request = reopened.request_context();
            let retry = reopened.runtime().block_on(
                reopened.apply_merge_bundle_with_method_durable_in(
                    &request,
                    actor,
                    b"land-recursive",
                    PullRequestNumber::FIRST,
                    expected_version,
                    &merge,
                    &[],
                    method,
                ),
            ).unwrap();
            assert_eq!(retry, accepted);
            assert_eq!(snapshot(&reopened).basis(), after.basis());
            assert_eq!(reopened.read_git_object(plan.commit).unwrap().payload(), expected_body);
            reopened.shutdown().unwrap();
        }
    }
}
