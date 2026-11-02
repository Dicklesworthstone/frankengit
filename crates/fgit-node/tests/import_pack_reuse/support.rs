use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use fgit_admission::AdmissionResult;
use fgit_crypto::{git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::ObjectType;
use fgit_node::{GitDaemonSessionOutcome, NodeConfig, OneNode};
use fgit_pack::{
    ExternalBaseLookup, NativeChecksumVerifier, PackError, PackLimits, PackObject, ScalarResolver,
    build_pack_index_v2, read_verified_pack,
};
use fgit_types::numeric::HeadGeneration;
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RepositoryId, TenantId};
use fgit_wire::{Packet, WireLimits, encode_packets};

pub const CACHE_BYTES: usize = 2 * 1024 * 1024;
pub const FORMATS: [GitHashAlgorithm; 2] = [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256];
pub type Objects = BTreeMap<GitOid, (ObjectType, Vec<u8>)>;
static NEXT: AtomicU64 = AtomicU64::new(0);

pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-import-pack-reuse-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn config(root: &Path, format: GitHashAlgorithm, cache: usize) -> NodeConfig {
    NodeConfig::new(
        root.to_path_buf(),
        TenantId::from_bytes([0xa7; 16]),
        RepositoryId::from_bytes([0xb8; 16]),
    )
    .with_worker_threads(2)
    .with_object_format(format)
    .with_received_pack_cache_bytes(cache)
}

pub fn node(root: &Path, format: GitHashAlgorithm, cache: usize) -> OneNode {
    let (mut node, _) = OneNode::init(config(root, format, cache)).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    node
}

pub fn reopen(root: &Path, format: GitHashAlgorithm, cache: usize) -> OneNode {
    // A newly built config must not inherit the previous process's Arc cache.
    let mut node = OneNode::open_existing(config(root, format, cache)).unwrap();
    let head = node
        .runtime()
        .block_on(node.authenticate_authority_head())
        .unwrap();
    node.bring_into_service(head.receipt().generation())
        .unwrap();
    node
}

pub fn import(node: &OneNode, source: &Path, key: &[u8]) -> AdmissionResult {
    let request = node.request_context();
    node.runtime()
        .block_on(node.import_loose_git_directory_durable_in(
            &request,
            source,
            PrincipalId::from_bytes([0xc9; 16]),
            key,
        ))
        .unwrap()
}

pub fn assert_committed(result: &AdmissionResult) {
    assert!(!result.commands.is_empty());
    assert!(
        result
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. })),
        "{result:?}"
    );
}

pub fn slots(root: &Path) -> Vec<PathBuf> {
    let mut slots = Vec::new();
    let Ok(scopes) = fs::read_dir(root.join("received-pack-cache/v1")) else {
        return slots;
    };
    for scope in scopes {
        for entry in fs::read_dir(scope.unwrap().path()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let name = name.to_str().unwrap();
            if name.starts_with("slot-") && name.ends_with(".rpack") {
                assert!(entry.file_type().unwrap().is_file());
                slots.push(entry.path());
            }
        }
    }
    slots.sort();
    slots
}

pub fn file_count(root: &Path) -> usize {
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .map(|entry| {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                file_count(&entry.path())
            } else {
                1
            }
        })
        .sum()
}

#[derive(Clone, Copy)]
pub enum Layout {
    Ofs,
    ForwardRef,
    Split,
}

pub struct Fixture {
    pub root: PathBuf,
    pub tip: GitOid,
    pub objects: Objects,
    pub packs: Vec<Vec<u8>>,
    pub pack_paths: Vec<PathBuf>,
    pub unselected: Option<GitOid>,
}

pub fn fixture(root: &Path, format: GitHashAlgorithm, layout: Layout, unselected: bool) -> Fixture {
    fs::create_dir_all(root.join("objects/pack")).unwrap();
    fs::create_dir_all(root.join("refs/heads")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    if format == GitHashAlgorithm::Sha256 {
        fs::write(root.join("config"), b"[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n").unwrap();
    }
    let mut objects = Objects::new();
    let mut add = |kind, body: Vec<u8>| {
        let id = git_object_id(format, kind, &body);
        assert!(objects.insert(id, (kind, body)).is_none());
        id
    };
    let old_body = b"preserve native imported compression\n".repeat(400);
    let new_body = [old_body.as_slice(), b"the next committed version\n"].concat();
    let old_blob = add(ObjectType::Blob, old_body.clone());
    let new_blob = add(ObjectType::Blob, new_body.clone());
    let old_tree = add(
        ObjectType::Tree,
        [b"100644 file.txt\0".as_slice(), old_blob.as_bytes()].concat(),
    );
    let new_tree = add(
        ObjectType::Tree,
        [b"100644 file.txt\0".as_slice(), new_blob.as_bytes()].concat(),
    );
    let author = "author Import <import@example.invalid> 1 +0000\ncommitter Import <import@example.invalid> 1 +0000\n";
    let old_commit = add(
        ObjectType::Commit,
        format!("tree {old_tree}\n{author}\nbase\n").into_bytes(),
    );
    let tip = add(
        ObjectType::Commit,
        format!("tree {new_tree}\nparent {old_commit}\n{author}\nnext\n").into_bytes(),
    );
    fs::write(root.join("refs/heads/main"), format!("{tip}\n")).unwrap();
    let delta = copy_append_delta(&old_body, &new_body[old_body.len()..]);
    let mut groups = match layout {
        Layout::Ofs => vec![vec![
            Entry::Whole(old_blob),
            Entry::Ofs(new_blob, 0, delta),
            Entry::Whole(tip),
            Entry::Whole(new_tree),
            Entry::Whole(old_commit),
            Entry::Whole(old_tree),
        ]],
        Layout::ForwardRef => vec![vec![
            Entry::Ref(new_blob, old_blob, delta),
            Entry::Whole(tip),
            Entry::Whole(new_tree),
            Entry::Whole(old_commit),
            Entry::Whole(old_tree),
            Entry::Whole(old_blob),
        ]],
        Layout::Split => vec![
            vec![
                Entry::Whole(old_blob),
                Entry::Whole(old_tree),
                Entry::Whole(old_commit),
            ],
            vec![
                Entry::Whole(new_blob),
                Entry::Whole(new_tree),
                Entry::Whole(tip),
            ],
        ],
    };
    let mut pack_objects = objects.clone();
    let unselected = unselected.then(|| {
        let body = b"not reachable from any imported ref".to_vec();
        let id = git_object_id(format, ObjectType::Blob, &body);
        pack_objects.insert(id, (ObjectType::Blob, body));
        groups[0].push(Entry::Whole(id));
        id
    });
    let mut packs = Vec::new();
    let mut pack_paths = Vec::new();
    for (index, entries) in groups.iter().enumerate() {
        let (pack, locations) = encode_pack(format, &pack_objects, entries);
        let idx = build_pack_index_v2(
            &pack,
            format,
            &locations,
            &PackLimits::default(),
            &mut || true,
        )
        .unwrap();
        let path = root.join(format!("objects/pack/part-{index}.pack"));
        fs::write(&path, &pack).unwrap();
        fs::write(path.with_extension("idx"), idx).unwrap();
        packs.push(pack);
        pack_paths.push(path);
    }
    Fixture {
        root: root.to_path_buf(),
        tip,
        objects,
        packs,
        pack_paths,
        unselected,
    }
}

enum Entry {
    Whole(GitOid),
    Ofs(GitOid, usize, Vec<u8>),
    Ref(GitOid, GitOid, Vec<u8>),
}

fn encode_pack(
    format: GitHashAlgorithm,
    objects: &Objects,
    entries: &[Entry],
) -> (Vec<u8>, Vec<(GitOid, u64)>) {
    let mut pack = b"PACK\0\0\0\x02".to_vec();
    pack.extend((entries.len() as u32).to_be_bytes());
    let mut locations: Vec<(GitOid, u64)> = Vec::new();
    for entry in entries {
        let offset = pack.len() as u64;
        let id = match entry {
            Entry::Whole(id) => {
                let (kind, body) = &objects[id];
                let code = match kind {
                    ObjectType::Commit => 1,
                    ObjectType::Tree => 2,
                    ObjectType::Blob => 3,
                    ObjectType::Tag => 4,
                };
                header(&mut pack, code, body.len());
                pack.extend(stored(body));
                *id
            }
            Entry::Ofs(id, base, program) => {
                header(&mut pack, 6, program.len());
                let mut distance = offset - locations[*base].1;
                let mut encoded = vec![(distance & 127) as u8];
                while {
                    distance >>= 7;
                    distance != 0
                } {
                    distance -= 1;
                    encoded.push(0x80 | (distance & 127) as u8);
                }
                encoded.reverse();
                pack.extend(encoded);
                pack.extend(stored(program));
                *id
            }
            Entry::Ref(id, base, program) => {
                header(&mut pack, 7, program.len());
                pack.extend(base.as_bytes());
                pack.extend(stored(program));
                *id
            }
        };
        locations.push((id, offset));
    }
    append_hash(format, &mut pack);
    (pack, locations)
}

fn header(pack: &mut Vec<u8>, code: u8, mut size: usize) {
    let mut byte = (code << 4) | (size & 15) as u8;
    size >>= 4;
    while size != 0 {
        pack.push(byte | 128);
        byte = (size & 127) as u8;
        size >>= 7;
    }
    pack.push(byte);
}

fn stored(bytes: &[u8]) -> Vec<u8> {
    let size = u16::try_from(bytes.len()).unwrap();
    let mut encoded = vec![0x78, 0x01, 0x01];
    encoded.extend(size.to_le_bytes());
    encoded.extend((!size).to_le_bytes());
    encoded.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    encoded.extend(((b << 16) | a).to_be_bytes());
    encoded
}

fn variable_integer(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value != 0 { 128 } else { 0 });
        if value == 0 {
            return bytes;
        }
    }
}

fn copy_append_delta(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let size = u16::try_from(base.len()).unwrap();
    let mut program = variable_integer(base.len());
    program.extend(variable_integer(base.len() + suffix.len()));
    program.push(0xb0); // Copy from offset zero, with two size bytes.
    program.extend(size.to_le_bytes());
    for part in suffix.chunks(127) {
        program.push(part.len() as u8);
        program.extend(part);
    }
    program
}

pub fn append_hash(format: GitHashAlgorithm, bytes: &mut Vec<u8>) {
    match format {
        GitHashAlgorithm::Sha1 => bytes.extend(sha1_digest(bytes)),
        GitHashAlgorithm::Sha256 => bytes.extend(sha256_digest(bytes)),
    }
}

pub fn fetch(node: OneNode, tip: GitOid, format: GitHashAlgorithm) -> (OneNode, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let path = node.git_daemon_repository_path().as_bytes().to_vec();
    let server = thread::spawn(move || {
        let outcome = node.serve_git_daemon_once(&listener);
        (node, outcome)
    });
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let greeting = [
        b"git-upload-pack ".as_slice(),
        path.as_slice(),
        b"\0host=loopback\0",
    ]
    .concat();
    client
        .write_all(format!("{:04x}", greeting.len() + 4).as_bytes())
        .unwrap();
    client.write_all(&greeting).unwrap();
    let mut advertisement = Vec::new();
    loop {
        let mut header = [0; 4];
        client.read_exact(&mut header).unwrap();
        if &header == b"0000" {
            break;
        }
        let length = usize::from_str_radix(std::str::from_utf8(&header).unwrap(), 16).unwrap();
        assert!(length >= 4);
        let mut bytes = vec![0; length - 4];
        client.read_exact(&mut bytes).unwrap();
        advertisement.extend(bytes);
    }
    assert!(
        advertisement
            .windows(tip.to_string().len())
            .any(|part| part == tip.to_string().as_bytes())
    );
    let format_name = match format {
        GitHashAlgorithm::Sha1 => "sha1",
        GitHashAlgorithm::Sha256 => "sha256",
    };
    let request = encode_packets(
        &[
            Packet::Data(
                format!("want {tip} ofs-delta object-format={format_name}\n").into_bytes(),
            ),
            Packet::Flush,
            Packet::Data(b"done\n".to_vec()),
        ],
        &WireLimits::default(),
    )
    .unwrap();
    client.write_all(&request).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    let (node, outcome) = server.join().unwrap();
    assert!(matches!(outcome.unwrap(), GitDaemonSessionOutcome::Pack(_)));
    let pack = response
        .strip_prefix(b"0008NAK\n")
        .expect("one completed legacy negotiation precedes the raw pack")
        .to_vec();
    (node, pack)
}

struct NoExternal;
impl ExternalBaseLookup for NoExternal {
    fn lookup(&self, _: &GitOid) -> Option<&[u8]> {
        None
    }
}

fn offset(object: &PackObject) -> u64 {
    match object {
        PackObject::Base { offset, .. } | PackObject::TypedBase { offset, .. } => *offset,
        PackObject::Delta(delta) => delta.offset,
    }
}

pub fn decode(bytes: &[u8], format: GitHashAlgorithm) -> Objects {
    let limits = PackLimits::default();
    let pack = read_verified_pack(
        bytes,
        format,
        &limits,
        &mut || true,
        &NativeChecksumVerifier,
    )
    .unwrap();
    let mut entries = pack.into_scalar_objects(|_| None).unwrap();
    let mut resolved = BTreeMap::new();
    for _ in 0..entries.len() {
        let resolver = ScalarResolver::new(&entries, &NoExternal, &limits, &mut || true).unwrap();
        let mut learned = Vec::new();
        for entry in &entries {
            let at = offset(entry);
            if resolved.contains_key(&at) {
                continue;
            }
            match resolver.resolve_offset_typed(at, &mut || true) {
                Ok((kind, body)) => {
                    learned.push((at, git_object_id(format, kind, &body), kind, body))
                }
                Err(PackError::MissingDeltaBase) => {}
                Err(error) => panic!("actual served pack refuses: {error:?}"),
            }
        }
        assert!(
            !learned.is_empty(),
            "served pack cannot depend on an unprovided base"
        );
        for (at, id, kind, body) in learned {
            match entries
                .iter_mut()
                .find(|entry| offset(entry) == at)
                .unwrap()
            {
                PackObject::Base { id: slot, .. } | PackObject::TypedBase { id: slot, .. } => {
                    *slot = Some(id)
                }
                PackObject::Delta(delta) => delta.id = Some(id),
            }
            assert!(resolved.insert(at, (id, kind, body)).is_none());
        }
        if resolved.len() == entries.len() {
            break;
        }
    }
    assert_eq!(resolved.len(), entries.len());
    let mut objects = Objects::new();
    for (id, kind, body) in resolved.into_values() {
        assert!(objects.insert(id, (kind, body)).is_none());
    }
    objects
}
