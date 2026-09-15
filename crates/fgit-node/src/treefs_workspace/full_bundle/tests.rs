use super::*;
use crate::{MaterializedAdmission, NodeConfig};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RepositoryId, TenantId};
use fgit_types::{GitOid, RefName};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fg-bundles-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
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
fn principal() -> PrincipalId {
    PrincipalId::from_bytes([0xc3; 16])
}
fn reference(text: &str) -> RefName {
    RefName::try_new(text.as_bytes()).unwrap()
}
fn session(key: &str) -> LoopbackReceiveSession {
    LoopbackReceiveSession::authenticated(
        principal(),
        IdempotencyKey::new(key.as_bytes().to_vec()).unwrap(),
    )
}
fn create(name: &str, oid: GitOid) -> RefCommand {
    RefCommand {
        name: reference(name),
        expected_old: ExpectedOld::Absent,
        proposed_new: ProposedNew::Update(oid),
        force: false,
    }
}
fn loose(
    root: &Path,
    format: GitHashAlgorithm,
    kind: GitObjectKind,
    label: &str,
    body: &[u8],
) -> GitOid {
    let id = git_object_id(format, kind, body);
    let raw = [format!("{label} {}\0", body.len()).as_bytes(), body].concat();
    let length = u16::try_from(raw.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(length.to_le_bytes());
    encoded.extend((!length).to_le_bytes());
    encoded.extend(&raw);
    let (a, b) = raw.iter().fold((1_u32, 0_u32), |(a, b), v| {
        let a = (a + u32::from(*v)) % 65521;
        (a, (b + a) % 65521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    let text = id.to_string();
    let dir = root.join("objects").join(&text[..2]);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(&text[2..]), encoded).unwrap();
    id
}
fn fixture(scratch: &Scratch, format: GitHashAlgorithm) -> (OneNode, GitOid, GitOid, GitOid) {
    let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let root = scratch.0.join("source");
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"),match format {
        GitHashAlgorithm::Sha1=>"[core]\nrepositoryformatversion = 0\nbare = true\n",
        GitHashAlgorithm::Sha256=>"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n",
    }).unwrap();
    let blob = loose(
        &root,
        format,
        GitObjectKind::Blob,
        "blob",
        b"branch fixture\n",
    );
    let tree = loose(
        &root,
        format,
        GitObjectKind::Tree,
        "tree",
        &[b"100644 file\0".as_slice(), blob.as_bytes()].concat(),
    );
    let body = format!(
        "tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nbase\n"
    );
    let base = loose(
        &root,
        format,
        GitObjectKind::Commit,
        "commit",
        body.as_bytes(),
    );
    let child=loose(&root,format,GitObjectKind::Commit,"commit",format!("tree {tree}\nparent {base}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nchild\n").as_bytes());
    fs::write(root.join("refs/heads/main"), format!("{child}\n")).unwrap();
    let request = node.request_context();
    let imported = node
        .runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            &root,
            principal(),
            b"branch-fixture",
        ))
        .unwrap();
    assert!(
        imported
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Committed { .. }))
    );
    (node, base, child, blob)
}
fn apply(
    node: &OneNode,
    commands: &[RefCommand],
    key: &str,
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.admit_branch_updates_durable_in(
            &request,
            &session(key),
            commands,
            AdmissionLimits::default(),
        ))
}
fn accepted(result: Result<AdmissionResult, NodeWorkspaceRefusal>) -> AdmissionResult {
    let result = result.unwrap();
    assert!(result.session.atomic);
    assert_eq!(result.session.tx_ids.len(), 1);
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })),
        "{result:?}"
    );
    result
}
fn snapshot(node: &OneNode) -> MaterializedAdmission {
    let request = node.request_context();
    node.runtime()
        .block_on(node.materialize_admission_in(&request))
        .unwrap()
}

fn export(node: &OneNode, visibility: &RefVisibility) -> FullBundle {
    let request = node.request_context();
    node.runtime()
        .block_on(node.export_full_git_bundle_in(&request, visibility, None))
        .unwrap()
        .1
}
fn import(
    node: &OneNode,
    bytes: &[u8],
    key: &str,
) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
    let request = node.request_context();
    node.runtime()
        .block_on(node.import_full_git_bundle_durable_in(
            &request,
            &session(key),
            bytes,
            AdmissionLimits::default(),
        ))
}
fn empty_node(root: &Scratch, format: GitHashAlgorithm) -> OneNode {
    let (mut node, _) = OneNode::init(root.config(format)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}
#[test]
fn full_bundle_is_atomic_and_replays_after_reopen() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (source, base, child, _) = fixture(&root, format);
        accepted(apply(&source, &[create("refs/heads/topic", base)], "topic"));
        let before = snapshot(&source);
        let bytes = export(&source, &Default::default()).into_bytes();
        assert_eq!(snapshot(&source).basis(), before.basis());
        let target = Scratch::new();
        let mut destination = empty_node(&target, format);
        let empty = snapshot(&destination);
        let result = accepted(import(&destination, &bytes, "transfer"));
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0], result.commands[1]);
        let after = snapshot(&destination);
        assert_eq!(after.snapshot().refs, before.snapshot().refs);
        assert_eq!(
            after.selected_closure().closure(),
            before.selected_closure().closure()
        );
        assert_eq!(after.snapshot().head_target, empty.snapshot().head_target);
        assert_eq!(
            after.basis().body().forge_position_root,
            empty.basis().body().forge_position_root
        );
        assert_eq!(after.snapshot().outbox, empty.snapshot().outbox);
        assert_native_transfer(&source, &destination, child);
        destination.push_quota.limit.max_events = 0;
        assert_eq!(import(&destination, &bytes, "transfer").unwrap(), result);
        assert_eq!(snapshot(&destination).basis(), after.basis());
        destination.shutdown().unwrap();
        let reopened = OneNode::open_existing(target.config(format)).unwrap();
        assert_eq!(import(&reopened, &bytes, "transfer").unwrap(), result);
        reopened.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
#[test]
fn collision_refuses_every_ref_without_publishing_a_prefix() {
    let root = Scratch::new();
    let (source, base, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    accepted(apply(&source, &[create("refs/heads/topic", base)], "topic"));
    let bytes = export(&source, &Default::default()).into_bytes();
    let target = Scratch::new();
    let (destination, _, _, _) = fixture(&target, GitHashAlgorithm::Sha1);
    let before = snapshot(&destination);
    let result = import(&destination, &bytes, "collision").unwrap();
    assert!(
        result
            .commands
            .iter()
            .all(|c| matches!(c.terminal.outcome, DecisionOutcome::Refused { .. }))
    );
    assert_eq!(
        snapshot(&destination).snapshot().refs,
        before.snapshot().refs
    );
    assert_eq!(import(&destination, &bytes, "collision").unwrap(), result);
    destination.shutdown().unwrap();
    source.shutdown().unwrap();
}
#[test]
fn export_excludes_hidden_refs_and_their_exclusive_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base, child, _) = fixture(&root, format);
        accepted(apply(&node, &[create("refs/heads/public", base)], "public"));
        let mut visibility = RefVisibility::default();
        visibility
            .push_rule(b"refs/heads/main", &Default::default())
            .unwrap();
        let bytes = export(&node, &visibility).into_bytes();
        let parsed = FullBundleInput::parse(&bytes, Default::default(), &mut || true).unwrap();
        assert_eq!(parsed.references().len(), 1);
        assert_eq!(
            parsed.references()[0].name(),
            &reference("refs/heads/public")
        );
        assert!(parsed.head().is_none());
        let target = Scratch::new();
        let destination = empty_node(&target, format);
        accepted(import(&destination, &bytes, "filtered"));
        assert!(destination.read_git_object(base).is_ok());
        assert!(destination.read_git_object(child).is_err());
        let before = snapshot(&node);
        accepted(apply(&node, &[create("refs/heads/later", base)], "later"));
        let request = node.request_context();
        assert!(
            node.runtime()
                .block_on(node.export_full_git_bundle_in(
                    &request,
                    &visibility,
                    Some(before.basis().id())
                ))
                .is_err()
        );
        destination.shutdown().unwrap();
        node.shutdown().unwrap();
    }
}
#[test]
fn missing_graph_objects_cannot_be_borrowed_from_destination() {
    use fgit_pack::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
    struct Source(CanonicalPackObject);
    impl CanonicalObjectSource for Source {
        fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
            if *id == self.0.id() {
                Ok(self.0.clone())
            } else {
                Err(PackWriteError::MissingCanonicalObject(*id))
            }
        }
    }
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base, _, _) = fixture(&root, format);
        let request = node.request_context();
        let selected = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: node.selected_pack_limits.max_object_bytes,
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: None,
        };
        let object = source.load(&base).unwrap();
        let limits = fgit_pack::PackLimits::default();
        let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
            .plan_selected(&Source(object), &[base], &mut || true)
            .unwrap();
        let (pack, _) = PackWriter::new(limits).write(&plan, &mut || true).unwrap();
        let header = match format {
            GitHashAlgorithm::Sha1 => format!("# v2 git bundle\n{base} refs/heads/incomplete\n\n"),
            GitHashAlgorithm::Sha256 => {
                format!("# v3 git bundle\n@object-format=sha256\n{base} refs/heads/incomplete\n\n")
            }
        };
        assert!(import(&node, &[header.as_bytes(), &pack].concat(), "incomplete").is_err());
        assert_eq!(snapshot(&node).basis(), selected.basis());
        accepted(apply(
            &node,
            &[create("refs/heads/permitted", base)],
            "permitted",
        ));
        node.shutdown().unwrap();
    }
}
#[test]
fn corrupt_cancelled_and_foreign_format_intake_never_publishes() {
    let root = Scratch::new();
    let (source, _, _, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let bytes = export(&source, &Default::default()).into_bytes();
    let target = Scratch::new();
    let destination = empty_node(&target, GitHashAlgorithm::Sha256);
    let before = snapshot(&destination);
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(import(&destination, &bad, "bad").is_err());
    let request = destination.request_context();
    request.authority().cancel();
    assert!(
        destination
            .runtime()
            .block_on(destination.import_full_git_bundle_durable_in(
                &request,
                &session("cancel"),
                &bytes,
                Default::default()
            ))
            .is_err()
    );
    assert_eq!(snapshot(&destination).basis(), before.basis());
    let foreign_root = Scratch::new();
    let foreign = empty_node(&foreign_root, GitHashAlgorithm::Sha1);
    assert!(matches!(
        import(&foreign, &bytes, "foreign"),
        Err(NodeWorkspaceRefusal::ObjectFormatMismatch)
    ));
    foreign.shutdown().unwrap();
    destination.shutdown().unwrap();
    source.shutdown().unwrap();
}

mod fetch;

#[path = "incremental_tests.rs"]
mod incremental_tests;

// Native Git bytes cross repositories; incarnation-scoped storage envelopes do
// not. Compare the entire object after rebinding ONLY the namespace, and prove
// both original envelopes remain bound to their own independently created node.
fn assert_native_transfer(source: &OneNode, destination: &OneNode, id: GitOid) {
    let original = source.read_git_object(id).unwrap();
    let received = destination.read_git_object(id).unwrap();
    assert_eq!(original.identity(), id);
    assert_eq!(received.identity(), id);
    assert_eq!(original.envelope().namespace(), source.namespace);
    assert_eq!(received.envelope().namespace(), destination.namespace);
    assert_ne!(source.repository_incarnation_id, destination.repository_incarnation_id);
    assert_ne!(original.envelope().namespace(), received.envelope().namespace());
    let envelope = original.envelope();
    let local = fgit_object_fabric::ObjectEnvelope::new(
        destination.namespace.clone(),
        envelope.object_identity(),
        envelope.object_kind(),
        envelope.declared_length(),
        envelope.payload_commitment(),
        envelope.codec_namespace().to_vec(),
        envelope.logical_content_identity(),
        envelope.manifest_reference(),
        &destination.segment_limits,
    ).unwrap();
    let expected = fgit_object_fabric::fabric::VerifiedObject::new(
        local, original.payload().to_vec(),
    ).unwrap();
    assert_eq!(received, expected, "native identity, bytes and all non-placement fields must survive transfer");
}
