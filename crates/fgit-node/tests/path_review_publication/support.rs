//! Real native objects, production source import, private candidate bundles,
//! canonical policies/votes and the embedded authority store.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::objects::{
    validate_fast_forward_objects, validate_merge_objects, validate_squash_objects,
};
use fgit_admission::merge::native::{NativeMergeIntent, NativeMergeMethod};
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::event::NativeMerge;
use fgit_forge::event::protection::{
    PathReviewRule, ProtectedBranch, ProtectionCommand, ReviewProtection,
};
use fgit_forge::event::pull_request::{PullRequestAction, PullRequestCommand, PullRequestData};
use fgit_forge::event::review::{
    CandidateBinding, CandidateReviewCommand, ReviewCommand, ReviewDecision, ReviewSubject,
};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, PackLimits, PackPlanner, PackWriteError,
    PackWriteProfile, PackWriter,
};
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RefusalCode, RepositoryId, TenantId,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fgit-path-reviews-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
pub fn actor(n: u8) -> PrincipalId {
    PrincipalId::from_bytes([n; 16])
}
pub fn session(n: u8, key: &[u8]) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(actor(n), IdempotencyKey::new(key.to_vec()).unwrap())
}
fn branch(name: &[u8]) -> RefName {
    RefName::try_new(name).unwrap()
}

#[derive(Default)]
struct Objects(BTreeMap<GitOid, CanonicalPackObject>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: GitObjectKind, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.0.insert(
            id,
            CanonicalPackObject::new(id, kind, body, Vec::new(), 0, 0),
        );
        id
    }
    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&str, &str, GitOid)]) -> GitOid {
        let mut body = Vec::new();
        for (mode, name, id) in entries {
            body.extend(format!("{mode} {name}\0").as_bytes());
            body.extend(id.as_bytes());
        }
        self.put(format, GitObjectKind::Tree, body)
    }
    fn commit(&mut self, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str("author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n");
        body.push_str(label);
        self.put(tree.algorithm(), GitObjectKind::Commit, body.into_bytes())
    }
    fn write_loose(&self, root: &Path) {
        for object in self.0.values() {
            let label = match object.object_type() {
                GitObjectKind::Blob => "blob",
                GitObjectKind::Tree => "tree",
                GitObjectKind::Commit => "commit",
                GitObjectKind::Tag => "tag",
            };
            let raw = [
                format!("{label} {}\0", object.body().len()).as_bytes(),
                object.body(),
            ]
            .concat();
            let length = u16::try_from(raw.len()).unwrap();
            let mut encoded = vec![0x78, 0x01, 0x01];
            encoded.extend(length.to_le_bytes());
            encoded.extend((!length).to_le_bytes());
            encoded.extend(&raw);
            let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), byte| {
                let next = (a + u32::from(*byte)) % 65_521;
                (next, (b + next) % 65_521)
            });
            encoded.extend(((b << 16) | a).to_be_bytes());
            let name = object.id().to_string();
            let directory = root.join("objects").join(&name[..2]);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join(&name[2..]), encoded).unwrap();
        }
    }
    fn bundle(&self, merge: &NativeMerge, method: NativeMergeMethod) -> Vec<u8> {
        let limits = PackLimits::default();
        // The fixture constructs alternate trees for several scenarios. Only
        // actual native closure belongs in a review artifact; unrelated spare
        // trees must not be silently hidden from the production inspector.
        let closure = match method {
            NativeMergeMethod::MergeCommit => {
                validate_merge_objects(self, merge, Default::default(), &mut || true)
            }
            NativeMergeMethod::Squash => {
                validate_squash_objects(self, merge, Default::default(), &mut || true)
            }
            NativeMergeMethod::FastForwardOnly => {
                validate_fast_forward_objects(self, merge, Default::default(), &mut || true)
            }
        }
        .expect("fixture candidate must pass full native validation before inspection");
        let selected: Vec<_> = closure.objects.into_iter().collect();
        let plan = PackPlanner::new(
            merge.merge_commit.algorithm(),
            PackWriteProfile::COMPRESSED_NO_DELTA_V1,
            limits.clone(),
        )
        .plan_selected(self, &selected, &mut || true)
        .unwrap();
        let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
        let mut bytes = format!(
            "# v3 git bundle\n@object-format={}\n-{} target\n{} {}\n\n",
            merge.merge_commit.algorithm().as_str(),
            merge.target_tip_before,
            merge.merge_commit,
            merge.target_ref
        )
        .into_bytes();
        bytes.extend(pack);
        bytes
    }
}
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}

#[derive(Clone, Copy)]
pub enum Change {
    ProtectedLeaf,
    Unrelated,
    DirectoryReplacement,
    CandidateOnly,
}
pub struct Fixture {
    pub node: OneNode,
    pub merge: NativeMerge,
    pub method: NativeMergeMethod,
    pub bundle: Vec<u8>,
    pub epoch: PolicyEpoch,
}
impl Fixture {
    pub fn new(
        root: &Scratch,
        format: GitHashAlgorithm,
        method: NativeMergeMethod,
        change: Change,
    ) -> Self {
        let (mut node, _) = OneNode::init(root.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let mut objects = Objects::default();
        let old = objects.put(format, GitObjectKind::Blob, b"old\n".to_vec());
        let new = objects.put(format, GitObjectKind::Blob, b"new\n".to_vec());
        let old_secure = objects.tree(format, &[("100644", "key", old)]);
        let new_secure = objects.tree(format, &[("100644", "key", new)]);
        let old_docs = objects.tree(format, &[("100644", "readme", old)]);
        let new_docs = objects.tree(format, &[("100644", "readme", new)]);
        let before = objects.tree(
            format,
            &[("40000", "docs", old_docs), ("40000", "secure", old_secure)],
        );
        let source_tree = match change {
            Change::ProtectedLeaf => objects.tree(
                format,
                &[("40000", "docs", old_docs), ("40000", "secure", new_secure)],
            ),
            Change::Unrelated | Change::CandidateOnly => objects.tree(
                format,
                &[("40000", "docs", new_docs), ("40000", "secure", old_secure)],
            ),
            Change::DirectoryReplacement => objects.tree(
                format,
                &[("40000", "docs", old_docs), ("120000", "secure", new)],
            ),
        };
        let target = objects.commit(before, &[], "target\n");
        let source = objects.commit(source_tree, &[target], "source\n");
        let loose = root.0.join("source");
        fs::create_dir_all(loose.join("refs/heads")).unwrap();
        fs::write(loose.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(loose.join("config"), match format {
            GitHashAlgorithm::Sha1 => "[core]\nrepositoryformatversion = 0\nbare = true\n",
            GitHashAlgorithm::Sha256 => "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
        }).unwrap();
        objects.write_loose(&loose);
        fs::write(loose.join("refs/heads/main"), format!("{target}\n")).unwrap();
        fs::write(loose.join("refs/heads/topic"), format!("{source}\n")).unwrap();
        let imported = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.request_context(),
                &loose,
                actor(1),
                b"path-review-import",
            ))
            .unwrap();
        for command in imported.commands {
            committed(&command.terminal);
        }
        let candidate_tree = if matches!(change, Change::CandidateOnly) {
            objects.tree(
                format,
                &[("40000", "docs", new_docs), ("40000", "secure", new_secure)],
            )
        } else {
            source_tree
        };
        let candidate = match method {
            NativeMergeMethod::MergeCommit => {
                objects.commit(candidate_tree, &[target, source], "merge\n")
            }
            NativeMergeMethod::Squash => objects.commit(candidate_tree, &[target], "squash\n"),
            NativeMergeMethod::FastForwardOnly => {
                assert!(!matches!(change, Change::CandidateOnly));
                source
            }
        };
        let merge = NativeMerge {
            source_ref: branch(b"refs/heads/topic"),
            source_tip: source,
            base_tip: target,
            target_ref: branch(b"refs/heads/main"),
            target_tip_before: target,
            merge_commit: candidate,
        };
        let data = PullRequestData {
            source_ref: merge.source_ref.clone(),
            target_ref: merge.target_ref.clone(),
            source_tip: source,
            target_tip: target,
            title: "Path-specific reviews".into(),
            body: "Actual candidate paths".into(),
        };
        let command = PullRequestCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            action: PullRequestAction::Open,
            data,
        };
        let (_, terminal) = node
            .runtime()
            .block_on(node.admit_pull_request_durable_in(
                &node.request_context(),
                &session(1, b"open-pr"),
                &command,
                Default::default(),
            ))
            .unwrap();
        committed(&terminal);
        let bundle = objects.bundle(&merge, method);
        Self {
            node,
            merge,
            method,
            bundle,
            epoch: PolicyEpoch::FIRST,
        }
    }
    pub fn protect(
        &mut self,
        rules: Vec<PathReviewRule>,
        reviewers: Vec<PrincipalId>,
        queue: bool,
    ) {
        let command = ProtectionCommand {
            expected_version: ExpectedVersion::NewStream,
            expected_epoch: self.epoch,
            protection: ReviewProtection {
                administrators: vec![actor(1)],
                ref_policy: None,
                branches: vec![ProtectedBranch {
                    name: self.merge.target_ref.clone(),
                    required_approvals: reviewers.len() as u16,
                    reviewers,
                    required_checks: Vec::new(),
                    required_candidate_checks: Vec::new(),
                    require_merge_queue: queue,
                    path_reviews: rules,
                }],
            },
        };
        let (_, terminal) = self
            .node
            .runtime()
            .block_on(self.node.admit_review_protection_durable_in(
                &self.node.request_context(),
                &session(1, b"protect-paths"),
                &command,
                Default::default(),
            ))
            .unwrap();
        committed(&terminal);
        self.epoch = self.epoch.next().unwrap();
    }
    pub fn review(
        &self,
        who: u8,
        version: u64,
        decision: ReviewDecision,
        key: &[u8],
    ) -> TerminalOutcome {
        let command = CandidateReviewCommand {
            candidate: CandidateBinding {
                merge_base: self.merge.base_tip,
                commit: self.merge.merge_commit,
            },
            review: ReviewCommand {
                expected_version: if version == 0 {
                    ExpectedVersion::NewStream
                } else {
                    ExpectedVersion::Exactly(AggregateVersion::try_new(version).unwrap())
                },
                subject: ReviewSubject {
                    pull_request: PullRequestNumber::FIRST,
                    pull_request_version: AggregateVersion::FIRST,
                    source_ref: self.merge.source_ref.clone(),
                    target_ref: self.merge.target_ref.clone(),
                    source_tip: self.merge.source_tip,
                    target_tip: self.merge.target_tip_before,
                    policy_epoch: self.epoch,
                },
                decision,
                reason: "Inspected the complete exact candidate".into(),
            },
        };
        self.node
            .runtime()
            .block_on(self.node.admit_candidate_review_durable_in(
                &self.node.request_context(),
                &session(who, key),
                &command,
                if decision == ReviewDecision::Withdraw {
                    None
                } else {
                    Some(&self.bundle)
                },
                Default::default(),
            ))
            .unwrap()
            .1
    }
    pub fn publish(&self, key: &[u8], bytes: &[u8]) -> TerminalOutcome {
        if self.method == NativeMergeMethod::FastForwardOnly {
            let intent = NativeMergeIntent::fast_forward_only(
                PullRequestNumber::FIRST,
                AggregateVersion::FIRST,
                self.merge.source_ref.clone(),
                self.merge.source_tip,
                self.merge.target_ref.clone(),
                self.merge.target_tip_before,
            )
            .unwrap();
            self.node
                .runtime()
                .block_on(self.node.admit_native_merge_durable_in(
                    &self.node.request_context(),
                    &session(2, key),
                    &intent,
                    Default::default(),
                    Default::default(),
                ))
                .unwrap()
        } else {
            self.node
                .runtime()
                .block_on(self.node.apply_merge_bundle_with_method_durable_in(
                    &self.node.request_context(),
                    actor(2),
                    key,
                    PullRequestNumber::FIRST,
                    ExpectedVersion::Exactly(AggregateVersion::FIRST),
                    &self.merge,
                    bytes,
                    self.method,
                ))
                .unwrap()
                .1
        }
    }
    pub fn target(&self) -> GitOid {
        self.node
            .runtime()
            .block_on(self.node.materialize_admission())
            .unwrap()
            .snapshot()
            .refs[&self.merge.target_ref]
    }
    pub fn reopen(mut self, config: NodeConfig) -> Self {
        self.node.shutdown().unwrap();
        self.node = OneNode::open_existing(config).unwrap();
        let head = self
            .node
            .runtime()
            .block_on(self.node.authenticate_authority_head())
            .unwrap();
        self.node
            .bring_into_service(head.receipt().generation())
            .unwrap();
        self
    }
}
pub fn committed(outcome: &TerminalOutcome) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Committed { .. }),
        "{outcome:?}"
    );
}
pub fn refused(outcome: &TerminalOutcome, code: RefusalCode) {
    assert!(
        matches!(outcome.outcome, DecisionOutcome::Refused { code: actual, .. } if actual == code),
        "{outcome:?}"
    );
}
