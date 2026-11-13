use std::fs;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::{PermittedObjectClosure, QuarantineValidator, permitted_object_closure_root};
use fgit_crypto::GitObjectKind;
use fgit_git_object::ParseLimits;
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, NativeChecksumVerifier, PackLimits, PackPlanner,
    PackWriteError, PackWriteProfile, PackWriter, QuarantinedPack, read_verified_pack,
};
use fgit_types::{GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId};
use fgit_wire::receive::{QuarantineReceipt, ReceiveCommand};

use super::*;
use crate::{AuthoritySelectedClosure, ClosureSelectionSource, NodeConfig, OneNode};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TENANT: TenantId = TenantId::from_bytes([0x41; 16]);
const REPOSITORY: RepositoryId = RepositoryId::from_bytes([0x42; 16]);

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = base.join(format!(
            "fg-receive-lfs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    node: OneNode,
    root: Temp,
    custody: PathBuf,
}
impl Fixture {
    fn new(format: GitHashAlgorithm, enabled: bool) -> Self {
        let root = Temp::new();
        let custody = root.0.join("lfs");
        fs::DirBuilder::new().mode(0o700).create(&custody).unwrap();
        let mut config =
            NodeConfig::new(root.0.join("node"), TENANT, REPOSITORY).with_object_format(format);
        if enabled {
            config = config.with_receive_lfs_root(custody.clone());
        }
        let node = OneNode::init(config).unwrap().0;
        Self {
            node,
            root,
            custody,
        }
    }

    fn store(&self) -> LfsStore {
        LfsStore::open(
            &self.custody,
            TENANT,
            REPOSITORY,
            self.node.repository_incarnation_id(),
        )
        .unwrap()
    }

    fn upload(&self, payload: &[u8]) -> LfsObject {
        let object = object(payload);
        self.store()
            .put(object, &mut Cursor::new(payload), &operation())
            .unwrap();
        object
    }

    fn validator(&self, selected: BTreeSet<GitOid>) -> ProductionQuarantineValidator<'_> {
        let closure = PermittedObjectClosure::new(selected);
        ProductionQuarantineValidator::new(
            &self.node,
            AuthoritySelectedClosure {
                root: permitted_object_closure_root(&closure).unwrap(),
                closure,
                source: ClosureSelectionSource::EmptyGenesis,
            },
            PackLimits::default(),
            ParseLimits::default(),
        )
    }

    fn head(&self) -> fgit_types::RepositoryAuthorityHeadId {
        self.node
            .runtime()
            .block_on(self.node.authenticate_authority_head())
            .unwrap()
            .id()
    }
}

fn object(payload: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(payload),
        size: payload.len() as u64,
    }
}

fn operation() -> ArtifactOperation<'static> {
    ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(15), &|| true).unwrap()
}

#[derive(Default)]
struct Objects(BTreeMap<GitOid, CanonicalPackObject>);
impl CanonicalObjectSource for Objects {
    fn load(&self, id: &GitOid) -> Result<CanonicalPackObject, PackWriteError> {
        self.0
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }
}
impl Objects {
    fn add(&mut self, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let crypto = match kind {
            ObjectType::Blob => GitObjectKind::Blob,
            ObjectType::Tree => GitObjectKind::Tree,
            ObjectType::Commit => GitObjectKind::Commit,
            ObjectType::Tag => GitObjectKind::Tag,
        };
        let id = fgit_crypto::git_object_id(format, crypto, &body);
        self.0.insert(
            id,
            CanonicalPackObject::new(id, kind, body, Vec::new(), 0, 0),
        );
        id
    }

    fn tree(&mut self, format: GitHashAlgorithm, entries: &[(&[u8], GitOid)]) -> GitOid {
        let mut body = Vec::new();
        for (name, id) in entries {
            body.extend_from_slice(b"100644 ");
            body.extend_from_slice(name);
            body.push(0);
            body.extend_from_slice(id.as_bytes());
        }
        self.add(format, ObjectType::Tree, body)
    }

    fn commit(&mut self, format: GitHashAlgorithm, tree: GitOid, parent: Option<GitOid>) -> GitOid {
        let mut body = format!("tree {tree}\n");
        if let Some(parent) = parent {
            body.push_str(&format!("parent {parent}\n"));
        }
        body.push_str(
            "author A <a@example.com> 1 +0000\ncommitter A <a@example.com> 1 +0000\n\nLFS policy\n",
        );
        self.add(format, ObjectType::Commit, body.into_bytes())
    }

    fn pack(&self, format: GitHashAlgorithm) -> (QuarantinedPack, QuarantineReceipt) {
        let limits = PackLimits::default();
        let ids: Vec<_> = self.0.keys().copied().collect();
        let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, limits.clone())
            .plan_selected(self, &ids, &mut || true)
            .unwrap();
        let (bytes, receipt) = PackWriter::new(limits.clone())
            .write(&plan, &mut || true)
            .unwrap();
        let pack = read_verified_pack(
            &bytes,
            format,
            &limits,
            &mut || true,
            &NativeChecksumVerifier,
        )
        .unwrap();
        (
            pack,
            QuarantineReceipt {
                object_format: format,
                object_count: receipt.object_count,
                pack_bytes: bytes.len(),
                delete_only: false,
            },
        )
    }

    fn place(&self, node: &OneNode) -> BTreeSet<GitOid> {
        for (id, value) in &self.0 {
            assert_eq!(
                node.put_git_object(value.object_type(), value.body().to_vec())
                    .unwrap()
                    .identity(),
                *id
            );
        }
        self.0.keys().copied().collect()
    }

    fn verified(
        &self,
        validator: &ProductionQuarantineValidator<'_>,
    ) -> BTreeMap<GitOid, VerifiedObject> {
        self.0
            .values()
            .map(|object| {
                validator
                    .verify_resolved_object(object.object_type(), object.body().to_vec())
                    .unwrap()
            })
            .collect()
    }
}

fn request(format: GitHashAlgorithm, root: GitOid) -> ReceiveRequest {
    ReceiveRequest {
        commands: vec![ReceiveCommand {
            old: zero(format),
            new: root,
            ref_name: b"refs/tags/lfs-policy".to_vec(),
        }],
        capabilities: Vec::new(),
        push_options: Vec::new(),
        certificate: None,
    }
}
fn zero(format: GitHashAlgorithm) -> GitOid {
    let width = match format {
        GitHashAlgorithm::Sha1 => 40,
        GitHashAlgorithm::Sha256 => 64,
    };
    GitOid::from_hex(format, &"0".repeat(width)).unwrap()
}
fn validate(
    validator: &ProductionQuarantineValidator<'_>,
    request: &ReceiveRequest,
    pack: &QuarantinedPack,
    receipt: &QuarantineReceipt,
) -> Result<(), RefusalCode> {
    validator
        .validate(request, Some(pack), receipt, &mut || true)
        .map(|_| ())
}

#[test]
fn missing_payload_refuses_before_staging_and_verified_payload_allows_identical_pack() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for spill in [false, true] {
            let fixture = Fixture::new(format, true);
            let pointer = object(b"retained large asset");
            let mut objects = Objects::default();
            let blob = objects.add(format, ObjectType::Blob, pointer.pointer().into_bytes());
            let tree = objects.tree(format, &[(b"model.bin", blob)]);
            let commit = objects.commit(format, tree, None);
            let (pack, receipt) = objects.pack(format);
            let validator = fixture
                .validator(BTreeSet::new())
                .with_resident_budgets(if spill { 0 } else { usize::MAX }, 1024 * 1024);
            let head = fixture.head();
            assert_eq!(
                validate(&validator, &request(format, commit), &pack, &receipt),
                Err(RefusalCode::ObjectClosureIncomplete)
            );
            for id in objects.0.keys() {
                assert!(fixture.node.read_git_object(*id).is_err());
            }
            assert_eq!(fixture.head(), head);
            fixture.upload(b"retained large asset");
            assert_eq!(
                validate(&validator, &request(format, commit), &pack, &receipt),
                Ok(())
            );
            assert_eq!(
                fixture.node.read_git_object(blob).unwrap().payload(),
                pointer.pointer().as_bytes()
            );
            assert_eq!(
                fixture.head(),
                head,
                "verified custody never publishes a ref"
            );
        }
    }
}

#[test]
fn default_policy_preserves_missing_payload_compatibility() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::new(format, false);
    let mut objects = Objects::default();
    let blob = objects.add(
        format,
        ObjectType::Blob,
        object(b"not uploaded").pointer().into_bytes(),
    );
    let (pack, receipt) = objects.pack(format);
    assert_eq!(
        validate(
            &fixture.validator(BTreeSet::new()),
            &request(format, blob),
            &pack,
            &receipt
        ),
        Ok(())
    );
}

#[test]
fn empty_pack_and_new_history_both_check_reused_native_pointers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for empty_pack in [true, false] {
            let fixture = Fixture::new(format, true);
            let mut history = Objects::default();
            let pointer = history.add(
                format,
                ObjectType::Blob,
                object(b"historical asset").pointer().into_bytes(),
            );
            let tree = history.tree(format, &[(b"old.bin", pointer)]);
            let old = history.commit(format, tree, None);
            let selected = history.place(&fixture.node);
            let mut incoming = Objects::default();
            let target = if empty_pack {
                old
            } else {
                let tree = incoming.tree(format, &[]);
                incoming.commit(format, tree, Some(old))
            };
            let (pack, receipt) = incoming.pack(format);
            let validator = fixture.validator(selected);
            assert_eq!(
                validate(&validator, &request(format, target), &pack, &receipt),
                Err(RefusalCode::ObjectClosureIncomplete)
            );
            fixture.upload(b"historical asset");
            assert_eq!(
                validate(&validator, &request(format, target), &pack, &receipt),
                Ok(())
            );
        }
    }
}

#[test]
fn unrelated_uploads_and_external_gitlinks_are_not_pointer_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, true);
        let mut objects = Objects::default();
        let unused = objects.add(
            format,
            ObjectType::Blob,
            object(b"unrelated").pointer().into_bytes(),
        );
        let fake_link = fgit_crypto::git_object_id(format, GitObjectKind::Commit, b"external");
        let mut tree_bytes = b"160000 submodule\0".to_vec();
        tree_bytes.extend_from_slice(fake_link.as_bytes());
        let tree = objects.add(format, ObjectType::Tree, tree_bytes);
        let (pack, receipt) = objects.pack(format);
        assert_eq!(
            validate(
                &fixture.validator(BTreeSet::new()),
                &request(format, tree),
                &pack,
                &receipt
            ),
            Ok(())
        );
        assert!(fixture.node.read_git_object(unused).is_err());
        assert!(fixture.node.read_git_object(fake_link).is_err());
    }
}

#[test]
fn deletion_only_needs_no_lfs_custody_and_cancellation_stays_a_refusal() {
    let fixture = Fixture::new(GitHashAlgorithm::Sha1, true);
    fs::remove_dir(&fixture.custody).unwrap();
    let mut deletion = request(GitHashAlgorithm::Sha1, zero(GitHashAlgorithm::Sha1));
    deletion.commands[0].old =
        fgit_crypto::git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, b"old");
    let receipt = QuarantineReceipt {
        object_format: GitHashAlgorithm::Sha1,
        object_count: 0,
        pack_bytes: 0,
        delete_only: true,
    };
    let validator = fixture.validator(BTreeSet::new());
    assert!(
        validator
            .validate(&deletion, None, &receipt, &mut || true)
            .is_ok()
    );
    assert!(matches!(
        validator.validate(&deletion, None, &receipt, &mut || false),
        Err(RefusalCode::CancellationInProgress)
    ));
}

#[test]
fn payloads_from_another_tenant_repository_or_incarnation_do_not_satisfy_policy() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, true);
        let payload = b"isolated payload";
        let pointer = object(payload);
        for (tenant, repository, incarnation) in [
            (
                TenantId::from_bytes([8; 16]),
                REPOSITORY,
                fixture.node.repository_incarnation_id(),
            ),
            (
                TENANT,
                RepositoryId::from_bytes([8; 16]),
                fixture.node.repository_incarnation_id(),
            ),
            (
                TENANT,
                REPOSITORY,
                RepositoryIncarnationId::from_bytes([8; 16]),
            ),
        ] {
            LfsStore::open(&fixture.custody, tenant, repository, incarnation)
                .unwrap()
                .put(pointer, &mut Cursor::new(payload), &operation())
                .unwrap();
        }
        let mut objects = Objects::default();
        let blob = objects.add(format, ObjectType::Blob, pointer.pointer().into_bytes());
        let (pack, receipt) = objects.pack(format);
        assert_eq!(
            validate(
                &fixture.validator(BTreeSet::new()),
                &request(format, blob),
                &pack,
                &receipt
            ),
            Err(RefusalCode::ObjectClosureIncomplete)
        );
        fixture.upload(payload);
        assert_eq!(
            validate(
                &fixture.validator(BTreeSet::new()),
                &request(format, blob),
                &pack,
                &receipt
            ),
            Ok(())
        );
    }
}

fn files(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .flat_map(|path| {
            if path.is_dir() {
                files(&path)
            } else {
                vec![path]
            }
        })
        .collect()
}

#[test]
fn corrupt_lfs_custody_refuses_instead_of_becoming_a_cache_miss() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::new(format, true);
    let pointer = fixture.upload(b"never trust a storage filename");
    let mut objects = Objects::default();
    let blob = objects.add(format, ObjectType::Blob, pointer.pointer().into_bytes());
    let (pack, receipt) = objects.pack(format);
    let path = files(&fixture.custody).pop().unwrap();
    let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::End(-1)).unwrap();
    file.write_all(b"!").unwrap();
    assert_eq!(
        validate(
            &fixture.validator(BTreeSet::new()),
            &request(format, blob),
            &pack,
            &receipt
        ),
        Err(RefusalCode::EvidenceInvalid)
    );
    assert!(fixture.node.read_git_object(blob).is_err());
}

#[test]
fn malformed_pointer_signatures_and_inconsistent_lengths_fail_before_custody() {
    let format = GitHashAlgorithm::Sha1;
    for malformed in [
        object(b"a").pointer().replace("/v1", "/v2"),
        object(b"a").pointer().replace("size 1", "size 01"),
        object(b"a").pointer().replace(
            "https://git-lfs.github.com/spec/v1",
            "https://hawser.github.com/spec/v1",
        ),
        object(b"a").pointer().replace(
            "https://git-lfs.github.com/spec/v1",
            "http://git-media.io/v/2",
        ),
        format!(" \t\n{}", object(b"a").pointer()),
        format!("\u{a0}{}", object(b"a").pointer()),
        object(b"a").pointer().replace('\n', "\r\n"),
        format!(
            "ext-0-transform sha256:{}\n{}",
            object(b"a").oid,
            object(b"a").pointer()
        ),
    ] {
        let fixture = Fixture::new(format, true);
        let mut objects = Objects::default();
        let blob = objects.add(format, ObjectType::Blob, malformed.into_bytes());
        let (pack, receipt) = objects.pack(format);
        assert_eq!(
            validate(
                &fixture.validator(BTreeSet::new()),
                &request(format, blob),
                &pack,
                &receipt
            ),
            Err(RefusalCode::ObjectHeaderInvalid)
        );
        // The same text embedded in an ordinary explanatory blob is not a
        // pointer. Recognition must not turn any mention of an LFS URL into
        // a publication restriction.
        let mut ordinary = Objects::default();
        let text = format!(
            "Example pointer:\n{}",
            String::from_utf8_lossy(objects.0[&blob].body())
        );
        let plain = ordinary.add(format, ObjectType::Blob, text.into_bytes());
        let (pack, receipt) = ordinary.pack(format);
        assert_eq!(
            validate(
                &fixture.validator(BTreeSet::new()),
                &request(format, plain),
                &pack,
                &receipt
            ),
            Ok(())
        );
    }
    let fixture = Fixture::new(format, true);
    let mut objects = Objects::default();
    let first = object(b"a");
    let second = LfsObject {
        oid: first.oid,
        size: 2,
    };
    let a = objects.add(format, ObjectType::Blob, first.pointer().into_bytes());
    let b = objects.add(format, ObjectType::Blob, second.pointer().into_bytes());
    let tree = objects.tree(format, &[(b"a", a), (b"b", b)]);
    let (pack, receipt) = objects.pack(format);
    assert_eq!(
        validate(
            &fixture.validator(BTreeSet::new()),
            &request(format, tree),
            &pack,
            &receipt
        ),
        Err(RefusalCode::ObjectHeaderInvalid)
    );
}

#[test]
fn all_additional_work_budgets_have_permitted_boundary_twins() {
    let format = GitHashAlgorithm::Sha1;
    let fixture = Fixture::new(format, true);
    let first = fixture.upload(b"a");
    let second = fixture.upload(b"bc");
    let mut objects = Objects::default();
    let a = objects.add(format, ObjectType::Blob, first.pointer().into_bytes());
    let b = objects.add(format, ObjectType::Blob, second.pointer().into_bytes());
    let tree = objects.tree(format, &[(b"a", a), (b"b", b)]);
    let validator = fixture.validator(BTreeSet::new());
    let verified = objects.verified(&validator);
    let native_bytes = objects
        .0
        .values()
        .map(|value| value.body().len() as u64)
        .sum();
    let exact = Limits {
        objects: 3,
        edges: 2,
        metadata_bytes: native_bytes,
        original_blob_bytes: 0,
        pointers: 2,
        payload_bytes: 3,
    };
    let mut spool = ObjectSpool::new(fixture.node.storage_root());
    for limits in [
        Limits {
            objects: 2,
            ..exact
        },
        Limits { edges: 1, ..exact },
        Limits {
            metadata_bytes: native_bytes - 1,
            ..exact
        },
        Limits {
            pointers: 1,
            ..exact
        },
        Limits {
            payload_bytes: 2,
            ..exact
        },
    ] {
        assert_eq!(
            validator.validate_lfs_payloads_bounded(
                &request(format, tree),
                &verified,
                &mut spool,
                limits,
                &mut || true
            ),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
    }
    assert_eq!(
        validator.validate_lfs_payloads_bounded(
            &request(format, tree),
            &verified,
            &mut spool,
            exact,
            &mut || true
        ),
        Ok(())
    );
    assert_eq!(
        validator.validate_lfs_payloads_bounded(
            &request(format, tree),
            &verified,
            &mut spool,
            exact,
            &mut || false
        ),
        Err(RefusalCode::CancellationInProgress)
    );
}

#[test]
fn duplicate_pointers_charge_payload_once_and_oversized_payloads_refuse() {
    let mut pointers = BTreeMap::new();
    let mut bytes = 0;
    let limits = Limits {
        pointers: 1,
        payload_bytes: 3,
        ..Limits::default()
    };
    let pointer = object(b"abc");
    for _ in 0..100 {
        assert_eq!(
            observe_pointer(
                pointer.pointer().as_bytes(),
                &mut pointers,
                &mut bytes,
                limits
            ),
            Ok(())
        );
    }
    assert_eq!(bytes, 3);
    assert_eq!(pointers.len(), 1);
    let oversized = LfsObject {
        size: MAX_OBJECT_BYTES + 1,
        ..pointer
    };
    assert_eq!(
        observe_pointer(
            oversized.pointer().as_bytes(),
            &mut BTreeMap::new(),
            &mut 0,
            Limits::default()
        ),
        Err(RefusalCode::ResourceBudgetExceeded)
    );
}

#[test]
fn existing_large_blobs_are_verified_to_eof_under_an_independent_byte_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Fixture::new(format, true);
        let mut objects = Objects::default();
        let blob = objects.add(format, ObjectType::Blob, vec![7; 65537]);
        let selected = objects.place(&fixture.node);
        let validator = fixture.validator(selected).for_reviewed_candidate();
        let mut spool = ObjectSpool::new(fixture.node.storage_root());
        let limits = Limits {
            original_blob_bytes: 65537,
            metadata_bytes: 0,
            ..Limits::default()
        };
        assert_eq!(
            validator.validate_lfs_payloads_bounded(
                &request(format, blob),
                &BTreeMap::new(),
                &mut spool,
                limits,
                &mut || true
            ),
            Ok(())
        );
        assert_eq!(
            validator.validate_lfs_payloads_bounded(
                &request(format, blob),
                &BTreeMap::new(),
                &mut spool,
                Limits {
                    original_blob_bytes: 65536,
                    ..limits
                },
                &mut || true
            ),
            Err(RefusalCode::ResourceBudgetExceeded)
        );
        let name = blob.to_string();
        let path = files(&fixture.root.0.join("node"))
            .into_iter()
            .find(|path| path.file_name().is_some_and(|file| file == name.as_str()))
            .unwrap();
        let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(&[8]).unwrap();
        assert_eq!(
            validator.validate_lfs_payloads_bounded(
                &request(format, blob),
                &BTreeMap::new(),
                &mut spool,
                limits,
                &mut || true
            ),
            Err(RefusalCode::EvidenceInvalid)
        );
    }
}
