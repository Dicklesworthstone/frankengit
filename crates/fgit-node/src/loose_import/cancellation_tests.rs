//! Real loose/packed source and embedded-authority tests. The explicit loader
//! test isolates graph cancellation; it does not substitute for durable storage.
use super::*;
use fgit_crypto::{git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::{LooseObject, ObjectType};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RefusalCode, RepositoryId, TenantId};
use crate::{NodeConfig, NodeSourceImportRefusal};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-import-control-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xe1; 16]),
            RepositoryId::from_bytes([0xe2; 16])).with_object_format(format).with_worker_threads(2)
    }
    fn node(&self, format: GitHashAlgorithm) -> OneNode { OneNode::init(self.config(format)).unwrap().0 }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn principal() -> PrincipalId { PrincipalId::from_bytes([0xe3; 16]) }
fn main_ref() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }

struct Source {
    root: PathBuf,
    tip: GitOid,
    objects: BTreeMap<GitOid, LooseObject>,
}
fn put(objects: &mut BTreeMap<GitOid, LooseObject>, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
    let id = git_object_id(format, kind, &body);
    objects.insert(id, LooseObject { object_type: kind, declared_size: body.len(), body }); id
}
fn digest(format: GitHashAlgorithm, bytes: &[u8]) -> Vec<u8> {
    match format { GitHashAlgorithm::Sha1 => sha1_digest(bytes).to_vec(),
        GitHashAlgorithm::Sha256 => sha256_digest(bytes).to_vec() }
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 { crc = (crc >> 1) ^ (0xedb8_8320_u32 & (0_u32.wrapping_sub(crc & 1))); }
    }
    !crc
}
fn stored(bytes: &[u8]) -> Vec<u8> {
    let mut result = vec![0x78, 0x01];
    let chunks = bytes.chunks(65_535); let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        result.push(u8::from(index + 1 == count));
        let n = u16::try_from(chunk.len()).unwrap();
        result.extend(n.to_le_bytes()); result.extend((!n).to_le_bytes()); result.extend(chunk);
    }
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521; (a, (b + a) % 65_521)
    });
    result.extend(((b << 16) | a).to_be_bytes()); result
}
fn source(scratch: &Scratch, format: GitHashAlgorithm, packed: bool) -> Source {
    let root = scratch.0.join("source"); fs::create_dir_all(root.join("objects")).unwrap();
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
    }).unwrap();
    let mut objects = BTreeMap::new();
    let content = (0..100_003).map(|n| n as u8).collect();
    let blob = put(&mut objects, format, ObjectType::Blob, content);
    let tree = put(&mut objects, format, ObjectType::Tree,
        [b"100755 file\0".as_slice(), blob.as_bytes()].concat());
    let tip = put(&mut objects, format, ObjectType::Commit, format!(
        "tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\ncontrolled import\n"
    ).into_bytes());
    fs::write(root.join("refs/heads/main"), format!("{tip}\n")).unwrap();
    if packed {
        let mut pack = b"PACK\0\0\0\x02".to_vec();
        pack.extend(u32::try_from(objects.len()).unwrap().to_be_bytes());
        let mut entries = Vec::new();
        for (id, object) in &objects {
            let offset = pack.len();
            let kind = match object.object_type { ObjectType::Commit => 1_u8, ObjectType::Tree => 2,
                ObjectType::Blob => 3, ObjectType::Tag => 4 };
            let mut size = object.body.len(); let mut byte = kind << 4 | (size as u8 & 15); size >>= 4;
            while size != 0 { pack.push(byte | 128); byte = size as u8 & 127; size >>= 7; }
            pack.push(byte); pack.extend(stored(&object.body));
            entries.push((*id, crc32(&pack[offset..]), u32::try_from(offset).unwrap()));
        }
        let checksum = digest(format, &pack); pack.extend(&checksum);
        let mut idx = b"\xfftOc\0\0\0\x02".to_vec();
        for byte in 0_u16..256 {
            idx.extend(u32::try_from(entries.iter().filter(|(id, _, _)| u16::from(id.as_bytes()[0]) <= byte).count()).unwrap().to_be_bytes());
        }
        for (id, _, _) in &entries { idx.extend(id.as_bytes()); }
        for (_, crc, _) in &entries { idx.extend(crc.to_be_bytes()); }
        for (_, _, offset) in &entries { idx.extend(offset.to_be_bytes()); }
        idx.extend(checksum); let checksum = digest(format, &idx); idx.extend(checksum);
        let directory = root.join("objects/pack"); fs::create_dir(&directory).unwrap();
        fs::write(directory.join("fixture.pack"), pack).unwrap();
        fs::write(directory.join("fixture.idx"), idx).unwrap();
    } else {
        for (id, object) in &objects {
            let hex = id.to_string(); let directory = root.join("objects").join(&hex[..2]);
            fs::create_dir_all(&directory).unwrap();
            let bytes = [format!("{} {}\0", object.object_type.label(), object.body.len()).as_bytes(), &object.body].concat();
            fs::write(directory.join(&hex[2..]), stored(&bytes)).unwrap();
        }
    }
    Source { root, tip, objects }
}
fn assert_absent(node: &OneNode, source: &Source) {
    for id in source.objects.keys() { assert!(node.read_git_object(*id).is_err(), "unexpected placement {id}"); }
}
fn is_cancelled(error: &LooseGitImportRefusal) -> bool {
    matches!(error, LooseGitImportRefusal::Interrupted { code: RefusalCode::CancellationInProgress, .. })
}

#[test]
fn the_original_durable_api_uses_its_cancelled_request_before_source_io_and_sealing() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for packed in [false, true] {
            let scratch = Scratch::new(); let source = source(&scratch, format, packed);
            let mut node = scratch.node(format); node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let request = node.request_context();
            let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            let cancelled = node.request_context(); cancelled.authority().cancel();
            for path in [&source.root, &scratch.0.join("does-not-exist")] {
                assert!(matches!(node.runtime().block_on(node.import_loose_git_directory_durable_in(
                    &cancelled, path, principal(), b"controlled-import")),
                    Err(NodeSourceImportRefusal::Staging(error)) if is_cancelled(&error)));
            }
            assert_absent(&node, &source);
            assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
            // A stopped, unsealed attempt must not poison this key. The live
            // twin publishes through the same original API, not a substitute.
            let fresh = node.request_context();
            let result = node.runtime().block_on(node.import_loose_git_directory_durable_in(
                &fresh, &source.root, principal(), b"controlled-import")).unwrap();
            assert_eq!(result.commands.len(), 1);
            assert!(matches!(result.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
            let after = node.runtime().block_on(node.materialize_admission_in(&fresh)).unwrap();
            assert_eq!(after.snapshot().refs[&main_ref()], source.tip);
            node.shutdown().unwrap();
            let mut reopened = OneNode::open_existing(scratch.config(format)).unwrap();
            reopened.bring_into_service(HeadGeneration::FIRST).unwrap();
            let request = reopened.request_context();
            let retry = reopened.runtime().block_on(reopened.import_loose_git_directory_durable_in(
                &request, &source.root, principal(), b"controlled-import")).unwrap();
            assert_eq!(retry.commands[0].terminal, result.commands[0].terminal);
            assert_eq!(reopened.runtime().block_on(reopened.materialize_admission_in(&request)).unwrap().basis(), after.basis());
            reopened.shutdown().unwrap();
        }
    }
}

#[test]
fn standalone_deadlines_cancel_before_reading_but_live_staging_remains_byte_identical() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let source = source(&scratch, format, false); let node = scratch.node(format);
        let stopped = node.stage_loose_git_import_with_deadline(&source.root, &mut || false).unwrap_err();
        assert!(is_cancelled(&stopped)); assert_absent(&node, &source);
        let staged = node.stage_loose_git_import_with_deadline(&source.root, &mut || true).unwrap();
        assert_eq!(staged, node.stage_loose_git_import(&source.root).unwrap());
        assert_eq!(staged.object_count(), source.objects.len());
        for (id, object) in &source.objects {
            assert_eq!(node.read_git_object(*id).unwrap().payload(), object.body.as_slice());
        }
        let request = node.request_context();
        assert!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().snapshot().refs.is_empty());
        node.shutdown().unwrap();
    }
}

#[test]
fn cancellation_during_staging_preserves_only_verified_noncanonical_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let source = source(&scratch, format, true); let node = scratch.node(format);
        let first = *source.objects.keys().next().unwrap();
        let stopped = node.stage_loose_git_import_with_deadline(&source.root,
            &mut || node.read_git_object(first).is_err()).unwrap_err();
        assert!(is_cancelled(&stopped));
        for (index, (id, object)) in source.objects.iter().enumerate() {
            if index == 0 { assert_eq!(node.read_git_object(*id).unwrap().payload(), object.body.as_slice()); }
            else { assert!(node.read_git_object(*id).is_err()); }
        }
        let request = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        assert!(before.snapshot().refs.is_empty());
        let staged = node.stage_loose_git_import(&source.root).unwrap();
        assert_eq!(staged.object_count(), source.objects.len());
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
        node.shutdown().unwrap();
    }
}

#[test]
fn cancelled_pack_decoding_never_installs_a_partial_verified_cache_or_stages_objects() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let source = source(&scratch, format, true); let node = scratch.node(format);
        let mut live = || true; let setup = ImportControl::new(&mut live);
        let mut baseline = PackedObjectSources::open(&source.root, format, node.max_object_bytes, &setup).unwrap();
        let probes = Cell::new(0);
        let mut counting = || { probes.set(probes.get() + 1); true };
        let control = ImportControl::new(&mut counting);
        let expected = baseline.read(source.tip, &control).unwrap().unwrap();
        assert_eq!(expected.body, source.objects[&source.tip].body);
        let total = probes.get(); assert!(total > 8);
        for stop_at in [1, 3, total / 2, total - 1] {
            let mut sources = PackedObjectSources::open(&source.root, format, node.max_object_bytes, &setup).unwrap();
            let probes = Cell::new(0);
            let mut deadline = || { probes.set(probes.get() + 1); probes.get() < stop_at };
            let control = ImportControl::new(&mut deadline);
            let read = sources.read(source.tip, &control);
            assert!(control.after(read, |error| error).is_err());
            assert!(!control.is_live());
            assert!(sources.sources.iter().all(|source| source.verified_objects.is_none()));
            assert_absent(&node, &source);
        }
        node.shutdown().unwrap();
    }
}

#[test]
fn the_graph_loader_and_shared_edge_reader_cannot_restart_a_cancelled_walk() {
    let format = GitHashAlgorithm::Sha256;
    let mut objects = BTreeMap::new();
    let blob = put(&mut objects, format, ObjectType::Blob, b"payload".to_vec());
    let tree = put(&mut objects, format, ObjectType::Tree,
        [b"100644 file\0".as_slice(), blob.as_bytes()].concat());
    let loaded = Cell::new(0); let stop = Cell::new(false);
    let mut deadline = || !stop.get(); let control = ImportControl::new(&mut deadline);
    let result = graph::validate_controlled([tree], format, &parse_limits(format, 1024),
        graph::Limits::default(), |id| {
            loaded.set(loaded.get() + 1); stop.set(true);
            objects.get(&id).cloned().ok_or(LooseGitImportRefusal::ObjectMissing(id))
        }, &control);
    assert!(matches!(result, Err(ref error) if is_cancelled(error)));
    assert_eq!(loaded.get(), 1);
    stop.set(false);
    let result = graph::validate_controlled([tree], format, &parse_limits(format, 1024),
        graph::Limits::default(), |_| { panic!("loader restarted after cancellation") }, &control);
    assert!(matches!(result, Err(ref error) if is_cancelled(error)));
    let mut live = || true; let control = ImportControl::new(&mut live);
    let valid = graph::validate_controlled([tree], format, &parse_limits(format, 1024),
        graph::Limits::default(), |id| objects.get(&id).cloned()
            .ok_or(LooseGitImportRefusal::ObjectMissing(id)), &control).unwrap();
    assert_eq!(valid.objects.len(), 2);
}
