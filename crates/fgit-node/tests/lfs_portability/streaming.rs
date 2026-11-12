use super::*;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_object_fabric::artifact::storage::{ArtifactStorageError, MAX_BUFFERED_PAYLOAD_BYTES};
use std::io::{self, Read};

struct Generated(u64);
impl Read for Generated {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.0 as usize);
        output[..count].fill(0xb6);
        self.0 -= count as u64;
        Ok(count)
    }
}
fn generated_object(size: u64) -> LfsObject {
    let mut hash = Sha256Hasher::new();
    let chunk = [0xb6; 64 * 1024];
    let mut remaining = size;
    while remaining != 0 {
        let count = chunk.len().min(remaining as usize);
        hash.update(&chunk[..count]);
        remaining -= count as u64;
    }
    LfsObject {
        oid: LfsOid::parse(&hex(&hash.finish())).unwrap(),
        size,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn bounded_operation() -> ArtifactOperation<'static> {
    ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(180), &|| true).unwrap()
}
fn invoke_streaming(args: &[String]) -> String {
    let mut output = Vec::new();
    lfs_transfer::run_with_timeout(args, &mut output, Some(Duration::from_secs(180))).unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn generated_large_payload_roundtrips_through_pinned_native_companion_and_cold_custody() {
    let scratch = Scratch::new();
    let root = scratch.0.join("source");
    let source_custody = scratch.private("source-lfs");
    let target = scratch.0.join("target");
    let target_custody = scratch.private("target-lfs");
    let archives = scratch.private("archives");
    let archive = archives.join("large.fglfs");
    let object = generated_object(MAX_BUFFERED_PAYLOAD_BYTES + 31);
    let files = [("large.bin", object.pointer())];

    let node = init(&root, GitHashAlgorithm::Sha256, &files);
    let source_incarnation = node.repository_incarnation_id();
    assert_eq!(
        custody(&source_custody, source_incarnation)
            .put(object, &mut Generated(object.size), &bounded_operation())
            .unwrap(),
        ArtifactPut::Created,
    );
    node.shutdown().unwrap();

    let exported = invoke_streaming(&transfer_args(
        "export",
        &root,
        &source_custody,
        &archive,
        GitHashAlgorithm::Sha256,
    ));
    assert!(exported.contains("\"objects\":1"), "{exported}");
    assert!(
        exported.contains(&format!("\"payload_bytes\":{}", object.size)),
        "{exported}"
    );
    assert_eq!(
        fs::metadata(&archive).unwrap().len(),
        object.size + 125 + 40
    );

    // Independent streaming hash of the actual published archive, without
    // trusting its receipt or allocating the complete transport in memory.
    let mut archive_reader = fs::File::open(&archive).unwrap();
    let mut archive_hash = Sha256Hasher::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let count = archive_reader.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        archive_hash.update(&chunk[..count]);
    }
    let digest = hex(&archive_hash.finish());
    assert_eq!(field(&exported, "sha256"), digest);

    // Native Git format and repository incarnation may change while the raw
    // LFS identity stays fixed. Import still needs the actual target pins.
    let target_node = init(&target, GitHashAlgorithm::Sha1, &files);
    let target_incarnation = target_node.repository_incarnation_id();
    assert_ne!(source_incarnation, target_incarnation);
    target_node.shutdown().unwrap();
    let pins = invoke_streaming(&args("inventory", &target, GitHashAlgorithm::Sha1));
    let command = import_args(
        &target,
        &target_custody,
        &archive,
        GitHashAlgorithm::Sha1,
        &pins,
        &digest,
    );
    let imported = invoke_streaming(&command);
    assert!(imported.contains("\"objects_created\":1"), "{imported}");
    assert!(imported.contains("\"refs_published\":false"), "{imported}");
    assert!(
        imported.contains("\"retention_roots_published\":false"),
        "{imported}"
    );
    let store = custody(&target_custody, target_incarnation);
    let op = bounded_operation();
    assert!(matches!(
        store.read(object, &op),
        Err(ArtifactStorageError::PayloadLimit)
    ));
    let mut payload = store.open_verified(object, &op).unwrap();
    let mut hash = Sha256Hasher::new();
    let mut bytes = 0_u64;
    loop {
        let count = payload.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
        bytes += count as u64;
    }
    assert_eq!(bytes, object.size);
    assert_eq!(hex(&hash.finish()), object.oid.to_string());
    drop(payload);
    drop(store);

    let retried = invoke_streaming(&command);
    assert!(retried.contains("\"objects_created\":0"), "{retried}");
    assert!(
        retried.contains("\"objects_already_present\":1"),
        "{retried}"
    );
    let verified = invoke_streaming(&verify_args(
        &target,
        &target_custody,
        GitHashAlgorithm::Sha1,
    ));
    assert!(verified.contains("\"custody_verified\":true"), "{verified}");
    assert!(verified.contains(&format!("\"payload_bytes\":{}", object.size)));
    assert_eq!(
        invoke_streaming(&args("inventory", &target, GitHashAlgorithm::Sha1)),
        pins
    );
}
