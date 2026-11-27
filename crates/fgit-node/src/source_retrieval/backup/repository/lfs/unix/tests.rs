use super::super::super::archive::{Encoder as SourceEncoder, Identity};
use super::super::super::profile::Profile;
use super::*;
use fgit_authority::{HeadGeneration, StoreInstanceId};
use fgit_authority_fsqlite::{
    ExportBundle, ExportedHead, ExportedIssuance, IssuanceSequence, SCHEMA_VERSION, export_bundle,
    mint_token,
};
use fgit_crypto::{git_object_id, git_payload_commitment};
use fgit_object_fabric::artifact::storage::ArtifactScope;
use fgit_object_fabric::artifact::storage::lfs::TRUST_DOMAIN;
use fgit_types::{
    CANONICAL_CODEC_VERSION, GitHashAlgorithm, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::fs::OpenOptions;
use std::io::{Cursor, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-source-lfs-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self(root)
    }

    fn directory(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        path
    }

    fn file(&self, name: &str) -> (PathBuf, File) {
        let path = self.0.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        (path, file)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn object(payload: &[u8]) -> LfsObject {
    LfsObject {
        oid: LfsOid::of_payload(payload),
        size: payload.len() as u64,
    }
}

fn source(format: GitHashAlgorithm, records: &[(GitObjectKind, Vec<u8>)]) -> Vec<u8> {
    let token = mint_token(StoreInstanceId::from_raw(41), IssuanceSequence::FIRST)
        .to_opaque_bytes()
        .to_vec();
    let authority = export_bundle(&ExportBundle {
        schema_version: SCHEMA_VERSION,
        instance: 41,
        bodies: vec![],
        head: Some(ExportedHead {
            key: b"head".to_vec(),
            token: token.clone(),
            generation: HeadGeneration::FIRST.get(),
            body: b"exact selected source head".to_vec(),
        }),
        issuance: vec![ExportedIssuance {
            token,
            sequence: 1,
            head_key: b"head".to_vec(),
            generation: 1,
            body: b"exact selected source head".to_vec(),
        }],
    })
    .unwrap();
    let identity = Identity {
        tenant: TenantId::from_bytes([1; 16]),
        repository: RepositoryId::from_bytes([2; 16]),
        incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
        format,
    };
    let ordered: BTreeMap<_, _> = records
        .iter()
        .map(|(kind, payload)| (git_object_id(format, *kind, payload), (*kind, payload)))
        .collect();
    let mut encoder = SourceEncoder::new(identity, &authority, ordered.len()).unwrap();
    for (oid, (kind, payload)) in ordered {
        let commitment = git_payload_commitment(kind, payload, CANONICAL_CODEC_VERSION);
        encoder
            .object(
                oid,
                kind,
                payload,
                &commitment.digest().as_bytes().try_into().unwrap(),
            )
            .unwrap();
    }
    encoder.finish().unwrap()
}

fn pinned(bytes: Vec<u8>) -> PinnedArchive<Cursor<Vec<u8>>> {
    let digest = fgit_crypto::sha256_digest(&bytes);
    PinnedArchive::from_reader(
        Cursor::new(bytes),
        digest,
        TransferLimits::default(),
        Profile::default().start(),
    )
    .unwrap()
}

fn inventory(
    payloads: &[&[u8]],
    format: GitHashAlgorithm,
) -> (PinnedArchive<Cursor<Vec<u8>>>, Inventory) {
    let records: Vec<_> = payloads
        .iter()
        .map(|payload| (GitObjectKind::Blob, object(payload).pointer().into_bytes()))
        .collect();
    let mut archive = pinned(source(format, &records));
    let inventory = Inventory::collect(
        &mut archive,
        Profile::default().start(),
        TransferLimits::default(),
    )
    .unwrap();
    (archive, inventory)
}

fn companion(
    scratch: &Scratch,
    name: &str,
    source: SourceIdentity,
    payloads: &[&[u8]],
) -> (PathBuf, transfer::Seal) {
    let (path, mut file) = scratch.file(name);
    let ordered: BTreeMap<_, _> = payloads
        .iter()
        .map(|payload| (object(payload), *payload))
        .collect();
    let mut encoder = Encoder::new(
        &mut file,
        source,
        ordered.len(),
        ordered.keys().map(|object| object.size).sum(),
        transfer::TransferLimits::default(),
        &mut || true,
    )
    .unwrap();
    for (object, mut payload) in ordered {
        encoder.object(object, &mut payload, &mut || true).unwrap();
    }
    let seal = encoder.finish(&mut || true).unwrap();
    (path, seal)
}

fn stored_path(root: &Path, source: SourceIdentity, object: LfsObject) -> PathBuf {
    let hex = super::super::super::super::hex;
    let scope = ArtifactScope::new(
        source.tenant,
        source.repository,
        source.incarnation,
        TRUST_DOMAIN,
    )
    .unwrap();
    root.join(format!(
        "scope-{}",
        hex(scope.commitment().bytes().as_bytes())
    ))
    .join(hex(object
        .artifact_identity()
        .artifact_id()
        .bytes()
        .as_bytes()))
}

#[test]
fn exact_native_blob_inventory_streams_all_bytes_and_refuses_unsupported_pointers() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let pointer = object(b"retained payload");
        let records = [
            (GitObjectKind::Blob, pointer.pointer().into_bytes()),
            (GitObjectKind::Blob, vec![b'x'; 2 * CHUNK_BYTES + 1]),
            // Selection by raw substring or any native object kind is invalid.
            (GitObjectKind::Tag, pointer.pointer().into_bytes()),
        ];
        let mut archive = pinned(source(format, &records));
        let found = Inventory::collect(
            &mut archive,
            Profile::default().start(),
            TransferLimits::default(),
        )
        .unwrap();
        assert_eq!(found.objects, [pointer]);
        assert_eq!(found.payload_bytes, pointer.size);

        for invalid in [
            pointer.pointer().replace("spec/v1", "spec/v2").into_bytes(),
            format!("{}extra field\n", pointer.pointer()).into_bytes(),
            format!("{}{}", pointer.pointer(), "x".repeat(POINTER_BYTES)).into_bytes(),
        ] {
            let mut archive = pinned(source(format, &[(GitObjectKind::Blob, invalid)]));
            let error = Inventory::collect(
                &mut archive,
                Profile::default().start(),
                TransferLimits::default(),
            )
            .err()
            .expect("unsupported pointers cannot silently omit custody");
            assert!(error.contains("unsupported"), "{error}");
        }
    }
}

#[test]
fn pointer_inventory_deduplicates_and_bounds_counts_lengths_and_total_payload() {
    let pointer = object(b"some payload");
    let limits = transfer::TransferLimits {
        max_objects: 1,
        max_payload_bytes: pointer.size,
        ..Default::default()
    };
    let mut objects = BTreeMap::new();
    let mut total = 0;
    for _ in 0..2 {
        let text = pointer.pointer();
        observe_pointer(
            text.as_bytes(),
            text.len() as u64,
            &mut objects,
            &mut total,
            limits,
        )
        .unwrap();
    }
    assert_eq!(objects.len(), 1);
    assert_eq!(total, pointer.size);
    let conflicting = LfsObject {
        size: pointer.size + 1,
        ..pointer
    }
    .pointer();
    assert!(
        observe_pointer(
            conflicting.as_bytes(),
            conflicting.len() as u64,
            &mut objects,
            &mut total,
            limits
        )
        .unwrap_err()
        .contains("conflicting")
    );
    let other = object(b"other payload").pointer();
    assert!(
        observe_pointer(
            other.as_bytes(),
            other.len() as u64,
            &mut objects,
            &mut total,
            limits
        )
        .unwrap_err()
        .contains("object-count")
    );
    let too_large = LfsObject {
        size: MAX_OBJECT_BYTES + 1,
        ..pointer
    }
    .pointer();
    assert!(
        observe_pointer(
            too_large.as_bytes(),
            too_large.len() as u64,
            &mut BTreeMap::new(),
            &mut 0,
            limits
        )
        .unwrap_err()
        .contains("per-object")
    );
    let small = transfer::TransferLimits {
        max_payload_bytes: pointer.size - 1,
        ..limits
    };
    let text = pointer.pointer();
    assert!(
        observe_pointer(
            text.as_bytes(),
            text.len() as u64,
            &mut BTreeMap::new(),
            &mut 0,
            small
        )
        .unwrap_err()
        .contains("payload-byte")
    );

    let selected = TransferLimits {
        max_archive_bytes: 9000,
        max_blob_bytes: 1,
        max_objects: 100,
    };
    let lfs = super::limits(selected).unwrap();
    assert_eq!(lfs.max_archive_bytes, 9000);
    assert_eq!(lfs.max_payload_bytes, 9000);
    assert_eq!(lfs.max_objects, 100);
    assert_eq!(lfs.max_object_bytes, MAX_OBJECT_BYTES);
}

#[test]
fn changed_source_tail_cannot_return_a_prefix_only_inventory() {
    let scratch = Scratch::new();
    let bytes = source(
        GitHashAlgorithm::Sha256,
        &[
            (
                GitObjectKind::Blob,
                object(b"payload").pointer().into_bytes(),
            ),
            (GitObjectKind::Blob, vec![9; CHUNK_BYTES + 10]),
        ],
    );
    let (path, mut file) = scratch.file("source.fg");
    file.write_all(&bytes).unwrap();
    let mut archive = PinnedArchive::from_reader(
        file,
        fgit_crypto::sha256_digest(&bytes),
        TransferLimits::default(),
        Profile::default().start(),
    )
    .unwrap();
    let mut changed = bytes;
    *changed.last_mut().unwrap() ^= 1;
    fs::write(path, changed).unwrap();
    assert!(
        Inventory::collect(
            &mut archive,
            Profile::default().start(),
            TransferLimits::default(),
        )
        .is_err()
    );
}

#[test]
fn companion_requires_independent_pin_exact_snapshot_and_exact_pointer_set() {
    let scratch = Scratch::new();
    let payloads: [&[u8]; 2] = [b"first", b"second"];
    let (archive, inventory) = inventory(&payloads, GitHashAlgorithm::Sha256);
    let source = source_identity(archive.header()).unwrap();
    let open = |path: &Path, digest| {
        Companion::open(
            path,
            digest,
            archive.header(),
            &inventory,
            TransferLimits::default(),
            Profile::default().start(),
        )
    };
    let (path, seal) = companion(&scratch, "valid.lfs", source, &payloads);
    assert!(open(&path, seal.digest).is_ok());
    assert!(open(&path, [0; 32]).is_err());
    for (name, subset) in [
        ("missing.lfs", vec![payloads[0]]),
        (
            "extra.lfs",
            vec![payloads[0], payloads[1], b"unselected".as_slice()],
        ),
    ] {
        let (path, seal) = companion(&scratch, name, source, &subset);
        let error = open(&path, seal.digest)
            .err()
            .expect("exact coverage is required");
        assert!(error.contains("exactly match"), "{error}");
    }
    for field in 0..7 {
        let mut changed = source;
        match field {
            0 => changed.tenant = TenantId::from_bytes([9; 16]),
            1 => changed.repository = RepositoryId::from_bytes([9; 16]),
            2 => changed.incarnation = RepositoryIncarnationId::from_bytes([9; 16]),
            3 => changed.format = GitHashAlgorithm::Sha1,
            4 => changed.head_generation += 1,
            5 => changed.head_token[0] ^= 1,
            _ => changed.head_sha256[0] ^= 1,
        }
        let (path, seal) = companion(&scratch, &format!("wrong-{field}.lfs"), changed, &payloads);
        let error = open(&path, seal.digest)
            .err()
            .expect("snapshot must match exactly");
        assert!(error.contains("exact source snapshot"), "{field}: {error}");
    }
    let wrong_length = LfsObject {
        size: object(payloads[0]).size + 1,
        ..object(payloads[0])
    };
    let mut wrong_source = pinned(source_bytes_with_pointer(wrong_length));
    let wrong_inventory = Inventory::collect(
        &mut wrong_source,
        Profile::default().start(),
        TransferLimits::default(),
    )
    .unwrap();
    let (path, seal) = companion(&scratch, "wrong-length.lfs", source, &[payloads[0]]);
    assert!(
        Companion::open(
            &path,
            seal.digest,
            wrong_source.header(),
            &wrong_inventory,
            TransferLimits::default(),
            Profile::default().start(),
        )
        .err()
        .unwrap()
        .contains("exactly match")
    );
}

fn source_bytes_with_pointer(pointer: LfsObject) -> Vec<u8> {
    source(
        GitHashAlgorithm::Sha256,
        &[(GitObjectKind::Blob, pointer.pointer().into_bytes())],
    )
}

#[test]
fn source_custody_export_and_quarantine_install_survive_source_loss_in_both_git_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let large = vec![0x5a; 2 * CHUNK_BYTES + 7];
        let payloads: [&[u8]; 3] = [b"retained\0binary\xff", &large, b""];
        let (archive, inventory) = inventory(&payloads, format);
        let source = source_identity(archive.header()).unwrap();
        let custody = scratch.directory("source-custody");
        let store = open_store(&custody, source).unwrap();
        let deadline = Profile::default().start();
        let live = || true;
        let operation = artifact_operation(deadline, &live).unwrap();
        for payload in payloads {
            let mut input = payload;
            store.put(object(payload), &mut input, &operation).unwrap();
        }
        let (path, mut file) = scratch.file("source.lfs");
        let receipt = export(
            &custody,
            archive.header(),
            &inventory,
            &mut file,
            TransferLimits::default(),
            deadline,
        )
        .unwrap();
        assert!(receipt.fields().starts_with(",\"lfs_companion\":{"));
        assert!(receipt.fields().contains("\"objects\":3"));
        assert!(receipt.fields().contains("\"exact_snapshot\":true"));
        assert_eq!(
            receipt.digest(),
            fgit_crypto::sha256_digest(&fs::read(&path).unwrap())
        );
        fs::remove_dir_all(custody).unwrap();

        let mut companion = Companion::open(
            &path,
            receipt.digest(),
            archive.header(),
            &inventory,
            TransferLimits::default(),
            deadline,
        )
        .unwrap();
        let target = scratch.0.join("restored-custody");
        assert!(companion.verify_stored(&target, deadline).is_err());
        assert!(
            !target.exists(),
            "verification cannot create missing custody"
        );
        companion.install(&target, deadline).unwrap();
        companion.verify_stored(&target, deadline).unwrap();
        companion.install(&target, deadline).unwrap();
        companion.verify_stored(&target, deadline).unwrap();
        assert_eq!(companion.receipt(), receipt);
        let restored = open_store(&target, source).unwrap();
        for payload in payloads {
            assert_eq!(restored.read(object(payload), &operation).unwrap(), payload);
        }

        let corrupt = stored_path(&target, source, object(payloads[0]));
        fs::write(&corrupt, b"corrupted retained custody").unwrap();
        assert!(companion.verify_stored(&target, deadline).is_err());
        assert_eq!(fs::read(corrupt).unwrap(), b"corrupted retained custody");
    }
}

#[test]
fn companion_rechecks_retained_handle_before_writes_and_never_reopens_the_input_name() {
    let scratch = Scratch::new();
    let (archive, inventory) = inventory(&[b"payload"], GitHashAlgorithm::Sha256);
    let source = source_identity(archive.header()).unwrap();
    let (path, seal) = companion(&scratch, "input.lfs", source, &[b"payload"]);
    let original = fs::read(&path).unwrap();
    let deadline = Profile::default().start();
    let mut selected = Companion::open(
        &path,
        seal.digest,
        archive.header(),
        &inventory,
        TransferLimits::default(),
        deadline,
    )
    .unwrap();
    let mut changed = original.clone();
    *changed.last_mut().unwrap() ^= 1;
    fs::write(&path, changed).unwrap();
    let target = scratch.0.join("custody");
    assert!(selected.verify_archive(deadline).is_err());
    assert!(selected.install(&target, deadline).is_err());
    assert!(
        !target.exists(),
        "complete archive recheck must precede custody creation"
    );
    fs::write(&path, &original).unwrap();
    fs::rename(&path, scratch.0.join("retained-original.lfs")).unwrap();
    fs::write(&path, b"replacement pathname is not the selected input").unwrap();
    selected.verify_archive(deadline).unwrap();
    selected.install(&target, deadline).unwrap();
    selected.verify_stored(&target, deadline).unwrap();
}

#[test]
fn empty_pointer_inventory_has_an_exact_empty_companion_and_read_only_custody_check() {
    let scratch = Scratch::new();
    let (archive, inventory) = inventory(&[], GitHashAlgorithm::Sha1);
    let source = source_identity(archive.header()).unwrap();
    let custody = scratch.directory("empty-source");
    let (path, mut file) = scratch.file("empty.lfs");
    let deadline = Profile::default().start();
    let receipt = export(
        &custody,
        archive.header(),
        &inventory,
        &mut file,
        TransferLimits::default(),
        deadline,
    )
    .unwrap();
    assert_eq!(receipt.objects, 0);
    assert_eq!(receipt.payload_bytes, 0);
    assert_eq!(receipt.bytes, 125);
    let mut companion = Companion::open(
        &path,
        receipt.digest(),
        archive.header(),
        &inventory,
        TransferLimits::default(),
        deadline,
    )
    .unwrap();
    let target = scratch.0.join("empty-restored");
    companion.install(&target, deadline).unwrap();
    companion.verify_stored(&target, deadline).unwrap();
    assert!(open_store(&target, source).is_ok());
    fs::remove_dir(target.clone()).unwrap();
    assert!(companion.verify_stored(&target, deadline).is_err());
    assert!(!target.exists());
}

#[test]
fn missing_source_custody_wrong_limits_and_expired_deadlines_refuse() {
    let scratch = Scratch::new();
    let (archive, inventory) = inventory(&[b"missing"], GitHashAlgorithm::Sha256);
    let empty_custody = scratch.directory("empty");
    let (_, mut file) = scratch.file("cannot-complete.lfs");
    assert!(
        export(
            &empty_custody,
            archive.header(),
            &inventory,
            &mut file,
            TransferLimits::default(),
            Profile::default().start(),
        )
        .unwrap_err()
        .contains("missing or invalid")
    );
    let (path, seal) = companion(
        &scratch,
        "valid.lfs",
        source_identity(archive.header()).unwrap(),
        &[b"missing"],
    );
    let narrow = TransferLimits {
        max_archive_bytes: seal.bytes - 1,
        ..Default::default()
    };
    assert!(
        Companion::open(
            &path,
            seal.digest,
            archive.header(),
            &inventory,
            narrow,
            Profile::default().start(),
        )
        .is_err()
    );
    let expired = Profile {
        timeout: Duration::ZERO,
        ..Default::default()
    }
    .start();
    assert!(
        Companion::open(
            &path,
            seal.digest,
            archive.header(),
            &inventory,
            TransferLimits::default(),
            expired,
        )
        .is_err()
    );
    let mut selected = Companion::open(
        &path,
        seal.digest,
        archive.header(),
        &inventory,
        TransferLimits::default(),
        Profile::default().start(),
    )
    .unwrap();
    let target = scratch.0.join("expired-target");
    assert!(selected.install(&target, expired).is_err());
    assert!(!target.exists());
    assert!(selected.verify_stored(&target, expired).is_err());
    assert!(!target.exists());
}

#[test]
fn unsafe_companion_paths_and_custody_symlinks_refuse_before_installation() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new();
    let (archive, inventory) = inventory(&[b"payload"], GitHashAlgorithm::Sha1);
    let (path, seal) = companion(
        &scratch,
        "original.lfs",
        source_identity(archive.header()).unwrap(),
        &[b"payload"],
    );
    let alias = scratch.0.join("alias.lfs");
    symlink(&path, &alias).unwrap();
    assert!(
        Companion::open(
            &alias,
            seal.digest,
            archive.header(),
            &inventory,
            TransferLimits::default(),
            Profile::default().start(),
        )
        .is_err()
    );
    let mut selected = Companion::open(
        &path,
        seal.digest,
        archive.header(),
        &inventory,
        TransferLimits::default(),
        Profile::default().start(),
    )
    .unwrap();
    let actual = scratch.directory("actual");
    let linked = scratch.0.join("linked");
    symlink(&actual, &linked).unwrap();
    assert!(
        selected
            .install(&linked.join("custody"), Profile::default().start())
            .is_err()
    );
    assert!(!actual.join("custody").exists());
}
