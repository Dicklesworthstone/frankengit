#![forbid(unsafe_code)]
//! Real manifest/retention publication must fence both new and existing names.
//! These injected interruptions exercise the production fsync path; they do
//! not simulate power loss or infer authority from directory contents.

use fgit_crypto::{GitObjectKind, git_object_id, git_payload_commitment};
use fgit_object_fabric::fabric::{
    AuthenticatedRetentionRegistry, ImmutableObjectFabric, ManifestLimits, RetentionRootProposal,
    SegmentManifest, StorageOperation, StoreRefusal,
};
use fgit_object_fabric::local::{LocalCrashPoint, LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{
    CryptoDigest, MicrosegmentBuilder, MicrosegmentReader, ObjectEnvelope, ObjectKind,
    SegmentLimits, SegmentRecordInput,
};
use fgit_resource::OpaqueHandle;
use fgit_types::{
    CANONICAL_CODEC_VERSION, Digest, DigestAlgorithmId, DigestBytes, GitHashAlgorithm, GitOid,
    PublicationEpoch, RepositoryAuthorityHeadId,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
const NAMESPACE: &[u8] = b"durability";

struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "fg-immutable-durability-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create isolated storage root: {error}"),
            }
        }
    }

    fn fabric(&self, crash: Option<LocalCrashPoint>) -> LocalFilesystemFabric {
        let mut config = LocalFilesystemConfig::new(
            self.0.clone(),
            NAMESPACE.to_vec(),
            OpaqueHandle::new(b"disk").unwrap(),
            OpaqueHandle::new(b"key").unwrap(),
            1 << 20,
            SegmentLimits::default(),
        );
        if let Some(point) = crash {
            config = config.with_crash_injection(point);
        }
        LocalFilesystemFabric::open(config).unwrap()
    }

    // Physical observations only: these scans never select a recovery root.
    fn files(&self, directory: &str) -> BTreeMap<PathBuf, Vec<u8>> {
        fs::read_dir(self.0.join(directory))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }

    fn assert_clean(&self) {
        assert!(self.files("staging").is_empty());
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn manifest() -> SegmentManifest {
    let limits = SegmentLimits::default();
    let payload = b"immutable manifest payload";
    let identity = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, payload);
    let commitment = git_payload_commitment(GitObjectKind::Blob, payload, CANONICAL_CODEC_VERSION);
    let commitment: [u8; 32] = commitment.digest().as_bytes().try_into().unwrap();
    let envelope = ObjectEnvelope::new(
        NAMESPACE.to_vec(),
        identity,
        ObjectKind::Blob,
        payload.len() as u64,
        commitment,
        b"raw".to_vec(),
        commitment,
        None,
        &limits,
    )
    .unwrap();
    let digest = CryptoDigest;
    let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());
    builder
        .push(SegmentRecordInput {
            envelope,
            payload: payload.to_vec(),
        })
        .unwrap();
    let segment = builder.build().unwrap();
    let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits).unwrap();
    SegmentManifest::from_verified_segment(&reader, Vec::new(), &ManifestLimits::default()).unwrap()
}

struct Registry;

impl AuthenticatedRetentionRegistry for Registry {
    fn revalidate_root(&self, _proposal: &RetentionRootProposal) -> Result<(), StoreRefusal> {
        Ok(())
    }

    fn permits_placement_deletion(&self, _object: GitOid) -> Result<(), StoreRefusal> {
        Err(StoreRefusal::DeletionRetained)
    }
}

fn retention(root_byte: u8) -> RetentionRootProposal {
    let algorithm = DigestAlgorithmId::try_new(2).unwrap();
    let head = RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[3; 32]).unwrap(),
    );
    RetentionRootProposal::new(
        head,
        Digest::new(algorithm, DigestBytes::try_new(&[root_byte; 32]).unwrap()),
        Vec::new(),
    )
    .unwrap()
}

fn interrupted(operation: StorageOperation) -> StoreRefusal {
    StoreRefusal::StorageIo {
        operation,
        kind: std::io::ErrorKind::Interrupted,
    }
}

#[test]
fn manifest_creation_and_identical_replay_both_cross_the_directory_fence() {
    for already_present in [false, true] {
        let root = Root::new();
        let store = root.fabric(None);
        let manifest = manifest();
        let identity = manifest.identity().unwrap();
        if already_present {
            assert_eq!(store.write_manifest(&manifest).unwrap(), identity);
        }
        let crashing = root.fabric(Some(LocalCrashPoint::AfterPublishDirectorySync));
        assert_eq!(
            crashing.write_manifest(&manifest),
            Err(interrupted(StorageOperation::SyncDirectory)),
            "existing={already_present}: a directory-fence interruption must not return success",
        );
        root.assert_clean();
        let bytes = root.files("manifests");
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes.values().next().unwrap(), &manifest.encode().unwrap());

        let reopened = root.fabric(None);
        assert_eq!(reopened.read_manifest(identity).unwrap(), manifest);
        assert_eq!(reopened.write_manifest(&manifest).unwrap(), identity);
        assert_eq!(root.files("manifests"), bytes);
        root.assert_clean();
    }
}

#[test]
fn retry_after_an_unfenced_manifest_link_establishes_its_own_fence() {
    let root = Root::new();
    let manifest = manifest();
    let linking = root.fabric(Some(LocalCrashPoint::AfterImmutablePublish));
    assert_eq!(
        linking.write_manifest(&manifest),
        Err(interrupted(StorageOperation::PublishImmutableBody)),
    );
    let bytes = root.files("manifests");
    assert_eq!(bytes.len(), 1, "the failed writer already linked its name");
    root.assert_clean();

    let retry = root.fabric(Some(LocalCrashPoint::AfterPublishDirectorySync));
    assert_eq!(
        retry.write_manifest(&manifest),
        Err(interrupted(StorageOperation::SyncDirectory)),
    );
    assert_eq!(root.files("manifests"), bytes);
    root.assert_clean();
    let reopened = root.fabric(None);
    let identity = reopened.write_manifest(&manifest).unwrap();
    assert_eq!(reopened.read_manifest(identity).unwrap(), manifest);
    assert_eq!(root.files("manifests"), bytes);
    root.assert_clean();
}

#[test]
fn retention_creation_and_replay_propagate_directory_fence_interruption() {
    for already_present in [false, true] {
        let root = Root::new();
        let store = root.fabric(None);
        let proposal = retention(4);
        if already_present {
            store.publish_retention_root(&Registry, &proposal).unwrap();
        }
        let roots_before = root.files("retention/roots");
        let crashing = root.fabric(Some(LocalCrashPoint::AfterPublishDirectorySync));
        assert_eq!(
            crashing.publish_retention_root(&Registry, &proposal),
            Err(interrupted(StorageOperation::SyncDirectory)),
            "existing={already_present}: linked bytes are not a completed retention receipt",
        );
        assert_eq!(root.files("retention/roots"), roots_before);
        let bodies = root.files("retention/bodies");
        assert_eq!(bodies.len(), 1);
        root.assert_clean();

        let reopened = root.fabric(None);
        let published = reopened
            .publish_retention_root(&Registry, &proposal)
            .unwrap();
        assert!(published.contains(PublicationEpoch::Staged));
        assert!(published.contains(PublicationEpoch::Visible));
        assert!(published.contains(PublicationEpoch::Durable));
        assert_eq!(root.files("retention/bodies"), bodies);
        let roots = root.files("retention/roots");
        assert_eq!(roots.len(), 1);
        assert_eq!(
            reopened
                .publish_retention_root(&Registry, &proposal)
                .unwrap(),
            published,
        );
        assert_eq!(root.files("retention/roots"), roots);
        root.assert_clean();
    }
}

#[test]
fn conflicting_retention_replay_cannot_replace_the_existing_head_pointer() {
    let root = Root::new();
    let store = root.fabric(None);
    let original = retention(4);
    let published = store.publish_retention_root(&Registry, &original).unwrap();
    let roots = root.files("retention/roots");
    let bodies = root.files("retention/bodies");
    assert_eq!(
        store.publish_retention_root(&Registry, &retention(5)),
        Err(StoreRefusal::StoredObjectIdentityCollision),
    );
    assert_eq!(root.files("retention/roots"), roots);
    for (path, bytes) in bodies {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
    root.assert_clean();

    let reopened = root.fabric(None);
    assert_eq!(
        reopened
            .publish_retention_root(&Registry, &original)
            .unwrap(),
        published,
    );
    assert_eq!(root.files("retention/roots"), roots);
    root.assert_clean();
}
