//! Canonical queue/PR observations over the shared imported native fixture.
#[path = "../trusted_merge_workflow/support.rs"]
mod imported;
pub(super) use imported::{
    Fixture, OWNER, REPOSITORY, TENANT, WORKFLOW, commit_bytes, generation, source_ref, target_ref,
};

use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::protection::{ProtectedBranch, ProtectionCommand, ReviewProtection};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::merge_queue::{QueueCommand, QueueCommandAction};
use fgit_forge::preparation::{MergeMetadata, MergeProfile, PreparationLimits};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber, QueueNumber};
use fgit_node::{
    LoopbackReceiveSession, NodeWorkspaceRefusal, OneNode, PreparedQueuePrefixBundle,
    QueuePrefixEntry,
};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, PolicyEpoch, PrincipalId, RefName,
    RepositoryAuthorityHeadId,
};
use fgit_wire::visibility::RefVisibility;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn second_ref() -> RefName {
    RefName::try_new(b"refs/heads/second").unwrap()
}
pub(super) fn version(value: u64) -> AggregateVersion {
    AggregateVersion::try_new(value).unwrap()
}
pub(super) fn pr(value: u64) -> PullRequestNumber {
    PullRequestNumber::try_new(value).unwrap()
}
pub(super) fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        OWNER,
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
pub(super) fn metadata(index: u64) -> MergeMetadata {
    MergeMetadata {
        author: "Queue Author <author@example.invalid>".into(),
        committer: "Queue Committer <committer@example.invalid>".into(),
        timestamp: 1_700_000_000 + index,
        message: format!("Prepare exact queue prefix entry {index}\n").into_bytes(),
    }
}

#[derive(Default)]
pub(super) struct Objects(pub BTreeMap<GitOid, (GitObjectKind, Vec<u8>)>);
impl Objects {
    pub fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, bytes: Vec<u8>) -> GitOid {
        let oid = git_object_id(format, kind, &bytes);
        self.0.insert(oid, (kind, bytes));
        oid
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        let (kind, bytes) = self
            .0
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(CanonicalPackObject::new(
            *id,
            *kind,
            bytes.clone(),
            Vec::new(),
            0,
            0,
        ))
    }
}

pub(super) fn publish(
    node: &OneNode,
    reference: RefName,
    old: Option<GitOid>,
    tip: GitOid,
    prerequisite: GitOid,
    objects: &Objects,
    key: &str,
) {
    let limits = PackLimits::default();
    let plan = PackPlanner::new(
        tip.algorithm(),
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
        limits.clone(),
    )
    .plan_selected(
        objects,
        &objects.0.keys().copied().collect::<Vec<_>>(),
        &mut || true,
    )
    .unwrap();
    let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
    let mut bundle = format!(
        "# v3 git bundle\n@object-format={}\n-{prerequisite} selected parent\n{tip} ",
        tip.algorithm().as_str()
    )
    .into_bytes();
    bundle.extend_from_slice(reference.as_bytes());
    bundle.extend_from_slice(b"\n\n");
    bundle.extend_from_slice(&pack);
    let receipt = node
        .runtime()
        .block_on(node.import_incremental_git_bundle_durable_in(
            &node.request_context(),
            &session(key),
            &bundle,
            &[(reference, old)],
            Default::default(),
        ))
        .unwrap();
    assert_eq!(receipt.commands.len(), 1);
    assert!(matches!(
        receipt.commands[0].terminal.outcome,
        DecisionOutcome::Committed { .. }
    ));
}

fn second_source(f: &Fixture, conflict: bool) -> GitOid {
    let format = f.source.algorithm();
    let mut objects = Objects::default();
    let left = objects.put(format, GitObjectKind::Blob, b"base\n".to_vec());
    let right = objects.put(
        format,
        GitObjectKind::Blob,
        if conflict {
            b"conflicting second\n".to_vec()
        } else {
            b"base\n".to_vec()
        },
    );
    let extra = objects.put(format, GitObjectKind::Blob, b"second\n".to_vec());
    let tree = objects.put(
        format,
        GitObjectKind::Tree,
        [
            b"100644 extra\0".as_slice(),
            extra.as_bytes(),
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
        commit_bytes(tree, &[f.base], "second PR"),
    );
    publish(
        f.node(),
        second_ref(),
        None,
        commit,
        f.base,
        &objects,
        "prefix-second-source",
    );
    commit
}

pub(super) fn data(entry: &QueuePrefixEntry) -> PullRequestData {
    PullRequestData {
        source_ref: entry.subject.source_ref.clone(),
        target_ref: entry.subject.target_ref.clone(),
        source_tip: entry.subject.source_tip,
        target_tip: entry.subject.target_tip,
        title: format!("Prefix PR {}", entry.subject.pull_request),
        body: String::new(),
    }
}

pub(super) fn change_pull(
    node: &OneNode,
    entry: &QueuePrefixEntry,
    action: PullRequestAction,
    fresh: bool,
    key: &str,
) {
    let mut updated = data(entry);
    if !fresh {
        updated.title.push_str(" (updated metadata)");
    }
    let command = PullRequestCommand {
        number: entry.subject.pull_request,
        expected_version: if fresh {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(entry.subject.pull_request_version)
        },
        action,
        data: updated,
    };
    let (_, receipt) = node
        .runtime()
        .block_on(node.admit_pull_request_durable_in(
            &node.request_context(),
            &session(key),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(receipt.outcome, DecisionOutcome::Committed { .. }));
}

pub(super) fn change_queue(node: &OneNode, previous: u64, action: QueueCommandAction, key: &str) {
    let command = QueueCommand {
        number: QueueNumber::FIRST,
        target_ref: target_ref(),
        expected_version: if previous == 0 {
            ExpectedVersion::NewStream
        } else {
            ExpectedVersion::Exactly(version(previous))
        },
        action,
    };
    let (_, receipt) = node
        .runtime()
        .block_on(node.admit_queue_durable_in(
            &node.request_context(),
            &session(key),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(receipt.outcome, DecisionOutcome::Committed { .. }));
}

pub(super) fn fixture(
    format: GitHashAlgorithm,
    conflict: bool,
) -> (Fixture, Vec<QueuePrefixEntry>) {
    let f = Fixture::new(format, WORKFLOW);
    let second = second_source(&f, conflict);
    let mut entries = Vec::new();
    for (number, source, tip) in [(1, source_ref(), f.source), (2, second_ref(), second)] {
        let entry = QueuePrefixEntry {
            subject: ReviewSubject {
                pull_request: pr(number),
                pull_request_version: AggregateVersion::FIRST,
                source_ref: source.clone(),
                target_ref: target_ref(),
                source_tip: tip,
                target_tip: f.target,
                policy_epoch: PolicyEpoch::FIRST,
            },
            metadata: metadata(number),
        };
        change_pull(
            f.node(),
            &entry,
            PullRequestAction::Open,
            true,
            &format!("prefix-open-{number}"),
        );
        change_queue(
            f.node(),
            number - 1,
            QueueCommandAction::Enqueue {
                pull_request: pr(number),
                expected_pull_request_version: AggregateVersion::FIRST,
                source_ref: source,
                head_tip: tip,
                expected_target_tip: f.target,
                priority: 0,
            },
            &format!("prefix-enqueue-{number}"),
        );
        entries.push(entry);
    }
    (f, entries)
}

pub(super) fn prepare(
    f: &Fixture,
    expected_version: u64,
    entries: &[QueuePrefixEntry],
    visibility: &RefVisibility,
    profile: MergeProfile,
) -> Result<PreparedQueuePrefixBundle, NodeWorkspaceRefusal> {
    f.node()
        .runtime()
        .block_on(f.node().prepare_queue_prefix_bundle_in(
            &f.node().request_context(),
            QueueNumber::FIRST,
            version(expected_version),
            entries,
            visibility,
            PreparationLimits::default(),
            profile,
        ))
}

pub(super) fn advance(node: &OneNode, reference: RefName, old: GitOid, key: &str) {
    let object = node.read_git_object(old).unwrap();
    let tree = GitOid::from_hex(
        old.algorithm(),
        std::str::from_utf8(object.payload())
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .strip_prefix("tree ")
            .unwrap(),
    )
    .unwrap();
    let mut objects = Objects::default();
    let commit = objects.put(
        old.algorithm(),
        GitObjectKind::Commit,
        commit_bytes(tree, &[old], key),
    );
    publish(node, reference, Some(old), commit, old, &objects, key);
}

pub(super) fn change_policy(node: &OneNode) {
    let command = ProtectionCommand {
        expected_version: ExpectedVersion::NewStream,
        expected_epoch: PolicyEpoch::FIRST,
        protection: ReviewProtection {
            administrators: vec![OWNER],
            ref_policy: None,
            branches: vec![ProtectedBranch {
                name: target_ref(),
                reviewers: vec![PrincipalId::from_bytes([0x74; 16])],
                required_approvals: 1,
                required_checks: Vec::new(),
                require_merge_queue: true,
            }],
        },
    };
    let (_, receipt) = node
        .runtime()
        .block_on(node.admit_review_protection_durable_in(
            &node.request_context(),
            &session("prefix-change-policy"),
            &command,
            Default::default(),
        ))
        .unwrap();
    assert!(matches!(receipt.outcome, DecisionOutcome::Committed { .. }));
}

#[derive(Debug, Eq, PartialEq)]
pub(super) struct State {
    pub head: RepositoryAuthorityHeadId,
    generation: u64,
    refs: BTreeMap<RefName, GitOid>,
    objects: BTreeSet<GitOid>,
    outbox: usize,
}
pub(super) fn state(node: &OneNode) -> State {
    let current = node
        .runtime()
        .block_on(node.materialize_admission())
        .unwrap();
    State {
        head: current.basis().id(),
        generation: generation(node),
        refs: current.snapshot().refs.clone(),
        objects: current.selected_closure().closure().objects().clone(),
        outbox: current.snapshot().outbox.len(),
    }
}
