//! Real file-backed node and imported native objects. No Git subprocess or
//! alternate authority implementation participates in these tests.
use super::*;
use crate::NodeConfig;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::preparation::{MergeMetadata, rebase::EmptyCommitPolicy};
use fgit_forge::review::{ComparisonMode, ReviewOptions};
use fgit_types::{DecisionOutcome, GitOid, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-replay-node-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_bytes([0xc1; 16]),
            RepositoryId::from_bytes([0xc2; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn main_ref() -> RefName {
    RefName::try_new(b"refs/heads/main").unwrap()
}
fn topic_ref() -> RefName {
    RefName::try_new(b"refs/heads/topic").unwrap()
}
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xc3; 16])
}
fn metadata() -> MergeMetadata {
    MergeMetadata {
        author: "Test <test@example.invalid>".into(),
        committer: "Test <test@example.invalid>".into(),
        timestamp: 2,
        message: b"exact replay\n".to_vec(),
    }
}
fn loose(
    path: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let bytes = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let n = u16::try_from(bytes.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(n.to_le_bytes());
    encoded.extend((!n).to_le_bytes());
    encoded.extend(&bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65521;
        (a, (b + a) % 65521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let directory = path.join("objects").join(&text[..2]);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join(&text[2..]), encoded).unwrap();
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
fn commit(tree: GitOid, parent: Option<GitOid>, label: &str) -> Vec<u8> {
    format!("tree {tree}\n{}author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n",
        parent.map_or_else(String::new, |id| format!("parent {id}\n"))).into_bytes()
}
struct Fixture {
    target: GitOid,
    source: GitOid,
    picked: GitOid,
    base: GitOid,
    target_tree: GitOid,
    borrowed: GitOid,
}
fn fixture(scratch: &Scratch, format: GitHashAlgorithm, conflict: bool) -> (OneNode, Fixture) {
    let path = scratch.0.join("source");
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
    let put = |kind, label, bytes: &[u8]| loose(&path, format, kind, label, bytes);
    let keep = put(GitObjectKind::Blob, "blob", b"keep\n");
    let target_only = put(GitObjectKind::Blob, "blob", b"target-only\n");
    let borrowed = put(GitObjectKind::Blob, "blob", b"selected source-only\n");
    let extra = put(
        GitObjectKind::Blob,
        "blob",
        b"later source must not appear\n",
    );
    let base_tree = put(
        GitObjectKind::Tree,
        "tree",
        &tree(&[(b"keep", 0o100644, keep)]),
    );
    let base = put(
        GitObjectKind::Commit,
        "commit",
        &commit(base_tree, None, "base"),
    );
    let target_name = if conflict {
        b"selected".as_slice()
    } else {
        b"target".as_slice()
    };
    let target_tree = put(
        GitObjectKind::Tree,
        "tree",
        &tree(&[
            (b"keep", 0o100644, keep),
            (target_name, 0o100755, target_only),
        ]),
    );
    let target = put(
        GitObjectKind::Commit,
        "commit",
        &commit(target_tree, Some(base), "target"),
    );
    let picked_tree = put(
        GitObjectKind::Tree,
        "tree",
        &tree(&[(b"keep", 0o100644, keep), (b"selected", 0o100755, borrowed)]),
    );
    let picked = put(
        GitObjectKind::Commit,
        "commit",
        &commit(picked_tree, Some(base), "selected"),
    );
    let source_tree = put(
        GitObjectKind::Tree,
        "tree",
        &tree(&[
            (b"keep", 0o100644, keep),
            (b"later", 0o100644, extra),
            (b"selected", 0o100755, borrowed),
        ]),
    );
    let source = put(
        GitObjectKind::Commit,
        "commit",
        &commit(source_tree, Some(picked), "later"),
    );
    fs::write(path.join("refs/heads/main"), format!("{target}\n")).unwrap();
    fs::write(path.join("refs/heads/topic"), format!("{source}\n")).unwrap();
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let request = node.request_context();
    let result = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &path,
            principal(),
            b"replay-import",
        ))
        .unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (
        node,
        Fixture {
            target,
            source,
            picked,
            base,
            target_tree,
            borrowed,
        },
    )
}

fn rebase_inputs(f: &Fixture) -> RebaseRequest {
    RebaseRequest {
        source_tip: f.source,
        upstream: f.base,
        onto: f.target,
        empty: EmptyCommitPolicy::Stop,
    }
}
fn committer() -> RebaseCommitter {
    RebaseCommitter {
        identity: "Rebaser <rebaser@example.invalid>".into(),
        timestamp: 100,
    }
}
fn bundle_pack(bundle: &[u8]) -> &[u8] {
    let offset = bundle.windows(2).position(|b| b == b"\n\n").unwrap() + 2;
    assert!(bundle[offset..].starts_with(b"PACK"));
    &bundle[offset..]
}
fn publish(
    node: &OneNode,
    old: GitOid,
    new: GitOid,
    pack: &[u8],
    key: &[u8],
) -> fgit_admission::AdmissionResult {
    use crate::quarantine_validator::ProductionReceiveQuarantineHandoff;
    use fgit_authority::IdempotencyKey;
    use fgit_wire::receive::{ReceiveContext, ReceiveLimits, ReceivePack, SignedPushProfile};
    use fgit_wire::{Capabilities, Packet, encode_packets};
    let request = node.request_context();
    let selected = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let limits = ReceiveLimits::default();
    let caps = format!(
        "report-status atomic object-format={}",
        old.algorithm().as_str()
    );
    let context = ReceiveContext::new(
        old.algorithm(),
        Capabilities::parse_v1(caps.as_bytes(), &limits.wire).unwrap(),
        limits.clone(),
        SignedPushProfile::Refuse,
    )
    .unwrap();
    let prefix = encode_packets(
        &[
            Packet::Data(format!("{old} {new} refs/heads/topic\0{caps}\n").into_bytes()),
            Packet::Flush,
        ],
        &limits.wire,
    )
    .unwrap();
    let validator = node
        .production_quarantine_validator(
            &selected,
            limits.pack.clone(),
            ParseLimits {
                tree_reference_bytes: old.algorithm().digest_len(),
                ..ParseLimits::default()
            },
        )
        .unwrap();
    let mut handoff = ProductionReceiveQuarantineHandoff::new(validator, selected.basis().clone());
    let mut receiver = ReceivePack::new(context).unwrap();
    receiver.push_bytes(&prefix).unwrap();
    receiver.push_bytes(pack).unwrap();
    receiver
        .finish_with_handoff(&mut handoff, &mut || true)
        .unwrap();
    let validated = handoff.into_validated_receive().unwrap();
    let session = crate::LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(key.to_vec()).unwrap(),
    );
    node.runtime()
        .block_on(node.admit_basis_bound_loopback_receive_durable_in(
            &request,
            &session,
            &validated,
            fgit_admission::AdmissionLimits::default(),
        ))
        .unwrap()
}

#[test]
fn complete_series_exports_source_dependencies_and_publishes_through_native_receive() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let artifact = node
            .runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                Some(before.basis().id()),
                &committer(),
                PreparationLimits::default(),
            ))
            .unwrap();
        let RebasePreparation::Clean(plan) = &artifact.outcome else {
            panic!("clean series expected");
        };
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].original, f.picked);
        assert_eq!(plan.steps[1].original, f.source);
        assert_eq!(artifact.source_head, before.basis().id());
        assert_eq!(artifact.borrowed_objects, 2);
        assert!(node.read_git_object(plan.commit).is_err());
        let bundle = artifact.bundle.as_ref().unwrap();
        let header = &bundle[..bundle.len() - bundle_pack(bundle).len()];
        assert!(
            header
                .windows(format!("-{} onto\n", f.target).len())
                .any(|p| p == format!("-{} onto\n", f.target).as_bytes())
        );
        assert!(
            !header
                .windows(format!("-{}", f.source).len())
                .any(|p| p == format!("-{}", f.source).as_bytes())
        );
        let pack = fgit_pack::read_verified_pack(
            bundle_pack(bundle),
            format,
            &PackLimits::default(),
            &mut || true,
            &fgit_pack::NativeChecksumVerifier,
        )
        .unwrap();
        assert_eq!(pack.entries().len(), artifact.pack_objects);
        let expected: BTreeSet<_> = plan
            .objects
            .iter()
            .map(|o| o.body.clone())
            .chain([
                b"selected source-only\n".to_vec(),
                b"later source must not appear\n".to_vec(),
            ])
            .collect();
        let observed: BTreeSet<_> = pack.entries().iter().map(|e| e.inflated.clone()).collect();
        assert_eq!(
            observed, expected,
            "onto-only recipient gets every source-only dependency, not the old source commits"
        );
        assert_eq!(
            node.runtime()
                .block_on(node.materialize_admission_in(&request))
                .unwrap()
                .basis(),
            before.basis()
        );
        let applied = publish(
            &node,
            f.source,
            plan.commit,
            bundle_pack(bundle),
            b"rebase-publish",
        );
        assert!(matches!(
            applied.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(after.snapshot().refs[&topic_ref()], plan.commit);
        assert_eq!(after.snapshot().refs[&main_ref()], f.target);
        assert_eq!(
            after.basis().body().forge_position_root,
            before.basis().body().forge_position_root
        );
        let candidate = plan.commit;
        let bytes = bundle_pack(bundle).to_vec();
        node.shutdown().unwrap();
        let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
        reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
        let retry = publish(&reopened, f.source, candidate, &bytes, b"rebase-publish");
        assert_eq!(retry.commands[0].terminal, applied.commands[0].terminal);
        let after_retry = reopened
            .runtime()
            .block_on(reopened.materialize_admission_in(&reopened.request_context()))
            .unwrap();
        assert_eq!(after_retry.basis(), after.basis());
        reopened.shutdown().unwrap();
    }
}

#[test]
fn conflicts_bad_coordinates_hidden_refs_and_bounds_leave_canonical_state_unchanged() {
    let scratch = Scratch::new();
    let (node, f) = fixture(&scratch, GitHashAlgorithm::Sha1, true);
    let request = node.request_context();
    let before = node
        .runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap();
    let artifact = node
        .runtime()
        .block_on(node.prepare_rebase_bundle_in(
            &request,
            &topic_ref(),
            &main_ref(),
            rebase_inputs(&f),
            &Default::default(),
            None,
            &committer(),
            PreparationLimits::default(),
        ))
        .unwrap();
    assert!(matches!(
        artifact.outcome,
        RebasePreparation::Stopped {
            reason: fgit_forge::preparation::rebase::RebaseStop::Conflicted(_),
            ..
        }
    ));
    assert!(artifact.bundle.is_none());
    assert_eq!(artifact.pack_objects, 0);
    let mut hidden = RefVisibility::new();
    hidden
        .push_rule(b"refs/heads/topic", &fgit_wire::WireLimits::default())
        .unwrap();
    assert!(matches!(
        node.runtime().block_on(node.prepare_rebase_bundle_in(
            &request,
            &topic_ref(),
            &main_ref(),
            rebase_inputs(&f),
            &hidden,
            None,
            &committer(),
            PreparationLimits::default()
        )),
        Err(RebasePreparationRefusal::RefUnavailable)
    ));
    for inputs in [
        RebaseRequest {
            source_tip: f.picked,
            ..rebase_inputs(&f)
        },
        RebaseRequest {
            onto: f.base,
            ..rebase_inputs(&f)
        },
    ] {
        assert!(matches!(
            node.runtime().block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                inputs,
                &Default::default(),
                None,
                &committer(),
                PreparationLimits::default()
            )),
            Err(RebasePreparationRefusal::TipMoved)
        ));
    }
    let unrelated = RebaseRequest {
        upstream: f.target,
        ..rebase_inputs(&f)
    };
    assert!(
        node.runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                unrelated,
                &Default::default(),
                None,
                &committer(),
                PreparationLimits::default()
            ))
            .is_err()
    );
    assert!(
        node.runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                rebase_inputs(&f),
                &Default::default(),
                None,
                &committer(),
                PreparationLimits {
                    max_commits: 1,
                    ..PreparationLimits::default()
                }
            ))
            .is_err()
    );
    assert_eq!(
        node.runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap()
            .basis(),
        before.basis()
    );
    node.shutdown().unwrap();
}

#[test]
fn identity_checked_original_metadata_preserves_bytes_but_not_stale_signatures() {
    let format = GitHashAlgorithm::Sha1;
    let tree = git_object_id(format, GitObjectKind::Tree, b"");
    let make = |extra: &[u8]| {
        let mut bytes=format!("tree {tree}\nauthor Original <o@x> -1 -0430\ncommitter Old <c@x> 1 +0000\nencoding ISO-8859-1\n").into_bytes();
        bytes.extend_from_slice(extra);
        bytes.extend_from_slice(b"\nraw\r\n\xff\n");
        bytes
    };
    let signed = make(b"gpgsig old signature\n continuation\ngpgsig-sha256 old\n bytes\n");
    let id = git_object_id(format, GitObjectKind::Commit, &signed);
    let parsed = original_metadata(id, &signed, &ParseLimits::default()).unwrap();
    assert_eq!(parsed.author, b"Original <o@x> -1 -0430");
    assert_eq!(parsed.encoding, Some(b"ISO-8859-1".to_vec()));
    assert_eq!(parsed.message, b"raw\r\n\xff\n");
    for extra in [
        b"author Other <e@x> 1 +0000\n".as_slice(),
        b"committer Other <e@x> 1 +0000\n",
        b"encoding UTF-8\n",
        b"unknown-extension important\n",
    ] {
        let body = make(extra);
        let id = git_object_id(format, GitObjectKind::Commit, &body);
        assert!(original_metadata(id, &body, &ParseLimits::default()).is_err());
    }
}

#[test]
fn empty_suffix_exports_a_valid_empty_pack_and_later_snapshot_pins_refuse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (node, f) = fixture(&scratch, format, false);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let inputs = RebaseRequest {
            upstream: f.source,
            ..rebase_inputs(&f)
        };
        let artifact = node
            .runtime()
            .block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                inputs,
                &Default::default(),
                None,
                &committer(),
                PreparationLimits::default(),
            ))
            .unwrap();
        let RebasePreparation::Clean(plan) = &artifact.outcome else {
            panic!();
        };
        assert_eq!(plan.commit, f.target);
        assert!(plan.steps.is_empty());
        assert_eq!(artifact.pack_objects, 0);
        let pack = bundle_pack(artifact.bundle.as_ref().unwrap());
        assert!(
            fgit_pack::read_verified_pack(
                pack,
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier
            )
            .unwrap()
            .entries()
            .is_empty()
        );
        let applied = publish(&node, f.source, f.target, pack, b"empty-suffix");
        assert!(matches!(
            applied.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        let inputs = RebaseRequest {
            source_tip: f.target,
            upstream: f.target,
            onto: f.target,
            empty: EmptyCommitPolicy::Stop,
        };
        assert!(matches!(
            node.runtime().block_on(node.prepare_rebase_bundle_in(
                &request,
                &topic_ref(),
                &main_ref(),
                inputs,
                &Default::default(),
                Some(before.basis().id()),
                &committer(),
                PreparationLimits::default()
            )),
            Err(RebasePreparationRefusal::SnapshotMoved)
        ));
        node.shutdown().unwrap();
    }
}
