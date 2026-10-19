#![forbid(unsafe_code)]
#![cfg(unix)]
use fgit_crypto::sha256_digest;
use fgit_object_fabric::artifact::storage::{
    ArtifactOperation, ArtifactScope, ArtifactStorageError, LocalArtifactStore,
};
use fgit_object_fabric::artifact::{
    ArtifactIdentity, ArtifactPayloadKind, MediaType, RetentionProfile,
};
use fgit_types::{
    Digest, DigestAlgorithmId, DigestBytes, RepositoryId, RepositoryIncarnationId, TenantId,
};
use std::os::unix::fs::DirBuilderExt;
use std::{
    fs,
    fs::File,
    io::{Seek, SeekFrom, Write},
    time::Duration,
};
fn digest(bytes: &[u8]) -> Digest {
    Digest::new(
        DigestAlgorithmId::try_new(2).unwrap(),
        DigestBytes::try_new(&sha256_digest(bytes)).unwrap(),
    )
}
#[test]
fn memory_reads_return_only_complete_verified_scoped_payloads_under_one_budget() {
    let root = std::env::temp_dir().join(format!("fg-artifact-read-{}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let scope = ArtifactScope::new(
        TenantId::from_bytes([1; 16]),
        RepositoryId::from_bytes([2; 16]),
        RepositoryIncarnationId::from_bytes([3; 16]),
        "test-read",
    )
    .unwrap();
    let store = LocalArtifactStore::open(&root, scope).unwrap();
    for (n, bytes) in [b"".as_slice(), b"binary\0\xffpayload"]
        .into_iter()
        .enumerate()
    {
        let identity = ArtifactIdentity::new(
            digest(bytes),
            bytes.len() as u64,
            MediaType::parse("application/octet-stream").unwrap(),
            ArtifactPayloadKind::CiArtifact,
            None,
            None,
            None,
            RetentionProfile::HotEphemeral { ttl_seconds: 86400 },
        );
        let path = root.join(format!("input-{n}"));
        fs::write(&path, bytes).unwrap();
        let op = ArtifactOperation::new(4096, Duration::from_secs(10), &|| true).unwrap();
        store
            .put(&identity, &mut File::open(&path).unwrap(), &op)
            .unwrap();
        let (observed, payload) = store.read_payload(identity.artifact_id(), &op).unwrap();
        assert_eq!(observed, identity);
        assert_eq!(payload, bytes);
        assert!(matches!(
            store.read_payload(
                identity.artifact_id(),
                &ArtifactOperation::new(4096, Duration::from_secs(10), &|| false).unwrap()
            ),
            Err(ArtifactStorageError::Cancelled)
        ));
        if bytes.len() > 1 {
            assert!(matches!(
                store.read_payload(
                    identity.artifact_id(),
                    &ArtifactOperation::new(1, Duration::from_secs(10), &|| true).unwrap()
                ),
                Err(ArtifactStorageError::PayloadLimit)
            ));
        }
        let hex = |value: &Digest| {
            value
                .bytes()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        let saved = root
            .join(format!("scope-{}", hex(&store.scope().commitment())))
            .join(hex(identity.artifact_id()));
        let mut file = fs::OpenOptions::new().write(true).open(saved).unwrap();
        file.seek(SeekFrom::End(-1)).unwrap();
        file.write_all(b"x").unwrap();
        file.sync_all().unwrap();
        assert!(store.read_payload(identity.artifact_id(), &op).is_err());
    }
    fs::remove_dir_all(root).unwrap();
}
