//! Shared real-node fixture for the public inspection target and its private
//! pack-limit cases. Every original is imported through canonical admission.
use super::{NodeConfig, OneNode};
use fgit_admission::{
    AdmissionContext, AdmissionLimits, PermittedObjectClosure, SourceImportOrigin,
    SourceImportReceipt, SourceRefUpdate, ValidatedClosure, permitted_object_closure_root,
    validate_source_import,
};
use fgit_authority::IdempotencyKey;
use fgit_crypto::{git_object_id, sha1_digest, sha256_digest};
use fgit_git_object::ObjectType;
use fgit_types::{
    DecisionOutcome, GitHashAlgorithm, GitOid, HeadGeneration, PrincipalId, RepositoryId, TenantId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "fg-thin-frontier-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }
    pub fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.clone(),
            TenantId::from_bytes([0x91; 16]),
            RepositoryId::from_bytes([0x92; 16]),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

pub struct History {
    pub parent: GitOid,
    pub source: GitOid,
    pub reused_blob: Option<GitOid>,
    pub sibling: GitOid,
    pub old_dir: GitOid,
    pub old_deep: GitOid,
    pub leaf: GitOid,
    pub secret: GitOid,
    pub candidate: GitOid,
    pub new_root: GitOid,
    pub new_dir: GitOid,
    pub new_deep: GitOid,
    pub changed: GitOid,
    pub originals: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
    pub uploaded: BTreeMap<GitOid, (ObjectType, Vec<u8>)>,
}
fn tree(entries: &[(&str, u32, GitOid)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, mode, id) in entries {
        bytes.extend_from_slice(format!("{mode:o} {name}\0").as_bytes());
        bytes.extend_from_slice(id.as_bytes());
    }
    bytes
}
pub fn commit(tree: GitOid, parents: &[GitOid], message: &str) -> Vec<u8> {
    let mut bytes = format!("tree {tree}\n");
    for parent in parents {
        writeln!(bytes, "parent {parent}").unwrap();
    }
    writeln!(bytes, "author Thin <thin@example.invalid> 1 +0000\ncommitter Thin <thin@example.invalid> 1 +0000\n\n{message}").unwrap();
    bytes.into_bytes()
}
pub fn fixture(root: &Scratch, format: GitHashAlgorithm) -> (OneNode, History) {
    build_fixture(root, format, None)
}

pub fn fixture_with_reused_blob(
    root: &Scratch,
    format: GitHashAlgorithm,
    blob_bytes: usize,
) -> (OneNode, History) {
    build_fixture(root, format, Some(blob_bytes))
}

fn build_fixture(
    root: &Scratch,
    format: GitHashAlgorithm,
    reused_blob_bytes: Option<usize>,
) -> (OneNode, History) {
    let mut config = root.config(format);
    if reused_blob_bytes.is_some() {
        config = config.with_max_object_bytes(64 * 1024 * 1024);
    }
    let (mut node, _) = OneNode::init(config).unwrap();
    node.bring_into_service(HeadGeneration::FIRST).unwrap();
    let mut originals = BTreeMap::new();
    let mut put = |kind, bytes: Vec<u8>| {
        let id = node.put_git_object(kind, bytes.clone()).unwrap().identity();
        originals.insert(id, (kind, bytes));
        id
    };
    // The sizable original leaf lets a small cache allowance distinguish the
    // aggregate external-base custody from each much smaller decoded result.
    let mut leaf_body = vec![b'x'; 4096];
    *leaf_body.last_mut().unwrap() = b'\n';
    let leaf = put(ObjectType::Blob, leaf_body);
    let old_deep = put(ObjectType::Tree, tree(&[("file", 0o100644, leaf)]));
    let old_dir = put(ObjectType::Tree, tree(&[("deep", 0o040000, old_deep)]));
    let untouched = put(ObjectType::Blob, b"untouched sibling\n".to_vec());
    let sibling = put(ObjectType::Tree, tree(&[("keep", 0o100644, untouched)]));
    let reused_blob = reused_blob_bytes.map(|bytes| put(ObjectType::Blob, vec![b'k'; bytes]));
    let root_body = |directory| {
        let mut entries = vec![("a", 0o040000, sibling)];
        if let Some(blob) = reused_blob {
            // A direct edge in the changed root requires frontier metadata;
            // an unchanged subtree would skip this blob's header entirely.
            entries.push(("keep", 0o100644, blob));
        }
        entries.push(("z", 0o040000, directory));
        tree(&entries)
    };
    let root_tree = put(ObjectType::Tree, root_body(old_dir));
    let ancestor = put(ObjectType::Commit, commit(root_tree, &[], "old history"));
    let parent = put(
        ObjectType::Commit,
        commit(root_tree, &[ancestor], "selected parent"),
    );
    let mut secret_body = vec![b'y'; 4096];
    *secret_body.last_mut().unwrap() = b'\n';
    let secret = put(ObjectType::Blob, secret_body);
    let secret_tree = put(ObjectType::Tree, tree(&[("private", 0o100644, secret)]));
    let private = put(
        ObjectType::Commit,
        commit(secret_tree, &[], "unrelated ref"),
    );
    let zero = GitOid::from_hex(format, &"0".repeat(format.digest_len() * 2)).unwrap();
    let ids: BTreeSet<_> = originals.keys().copied().collect();
    let mut updates = vec![
        SourceRefUpdate {
            old: zero,
            new: parent,
            ref_name: b"refs/heads/main".to_vec(),
        },
        SourceRefUpdate {
            old: zero,
            new: private,
            ref_name: b"refs/heads/private".to_vec(),
        },
    ];
    if reused_blob.is_some() {
        updates.push(SourceRefUpdate {
            old: zero,
            new: ancestor,
            ref_name: b"refs/heads/topic".to_vec(),
        });
    }
    let imported = validate_source_import(
        &updates,
        &SourceImportReceipt {
            object_format: format,
            object_count: u32::try_from(ids.len()).unwrap(),
            delete_only: false,
            origin: SourceImportOrigin::LocalGitDirectory,
        },
        ValidatedClosure {
            object_closure_root: permitted_object_closure_root(&PermittedObjectClosure::new(
                ids.clone(),
            ))
            .unwrap(),
            objects: ids,
        },
    )
    .unwrap();
    let context = AdmissionContext {
        head_key: node.authority_head_key().clone(),
        tenant_id: node.tenant_id(),
        repository_id: node.repository_id(),
        principal_id: PrincipalId::from_bytes([0x93; 16]),
        idempotency_key: IdempotencyKey::new(b"thin-frontier-fixture".to_vec()).unwrap(),
        object_format: format,
    };
    let request = node.request_context();
    let admitted = node
        .runtime()
        .block_on(node.admit_validated_source_import_durable_in(
            &request,
            &context,
            &imported,
            AdmissionLimits::default(),
        ))
        .unwrap();
    assert!(
        admitted
            .commands
            .iter()
            .all(|command| matches!(command.terminal.outcome, DecisionOutcome::Committed { .. }))
    );

    let mut uploaded = BTreeMap::new();
    let mut upload = |kind, bytes: Vec<u8>| {
        let id = git_object_id(format, kind, &bytes);
        uploaded.insert(id, (kind, bytes));
        id
    };
    let changed = upload(ObjectType::Blob, b"changed\n".to_vec());
    let new_deep = upload(ObjectType::Tree, tree(&[("file", 0o100644, changed)]));
    let new_dir = upload(ObjectType::Tree, tree(&[("deep", 0o040000, new_deep)]));
    let new_root = upload(ObjectType::Tree, root_body(new_dir));
    let candidate = upload(
        ObjectType::Commit,
        commit(new_root, &[parent], "actual thin candidate"),
    );
    (
        node,
        History {
            parent,
            source: ancestor,
            reused_blob,
            sibling,
            old_dir,
            old_deep,
            leaf,
            secret,
            candidate,
            new_root,
            new_dir,
            new_deep,
            changed,
            originals,
            uploaded,
        },
    )
}

pub enum Entry {
    Direct(u8, Vec<u8>),
    Ref(GitOid, Vec<u8>),
}
fn varint(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        output.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn replace(base: &[u8], result: &[u8]) -> Vec<u8> {
    let mut program = Vec::new();
    varint(base.len(), &mut program);
    varint(result.len(), &mut program);
    for chunk in result.chunks(127) {
        program.push(u8::try_from(chunk.len()).unwrap());
        program.extend_from_slice(chunk);
    }
    program
}
impl History {
    /// Place the as-yet-unproved leaf first. Opening it before the two tree
    /// bases would force breadth-first traversal of the unrelated a/ sibling.
    pub fn thin_entries(&self, leaf_base: GitOid) -> Vec<Entry> {
        vec![
            Entry::Ref(
                leaf_base,
                replace(
                    &self.originals[&leaf_base].1,
                    &self.uploaded[&self.changed].1,
                ),
            ),
            Entry::Ref(
                self.old_deep,
                replace(
                    &self.originals[&self.old_deep].1,
                    &self.uploaded[&self.new_deep].1,
                ),
            ),
            Entry::Ref(
                self.old_dir,
                replace(
                    &self.originals[&self.old_dir].1,
                    &self.uploaded[&self.new_dir].1,
                ),
            ),
            Entry::Direct(2, self.uploaded[&self.new_root].1.clone()),
            Entry::Direct(1, self.uploaded[&self.candidate].1.clone()),
        ]
    }
    pub fn thick_entries(&self) -> Vec<Entry> {
        [
            self.changed,
            self.new_deep,
            self.new_dir,
            self.new_root,
            self.candidate,
        ]
        .iter()
        .map(|id| {
            let (kind, body) = &self.uploaded[id];
            let code = match kind {
                ObjectType::Commit => 1,
                ObjectType::Tree => 2,
                ObjectType::Blob => 3,
                ObjectType::Tag => 4,
            };
            Entry::Direct(code, body.clone())
        })
        .collect()
    }
    pub fn external_bytes(&self) -> usize {
        [self.leaf, self.old_dir, self.old_deep]
            .iter()
            .map(|id| self.originals[id].1.len())
            .sum()
    }
}
fn zlib(bytes: &[u8]) -> Vec<u8> {
    let size = u16::try_from(bytes.len()).unwrap();
    let mut result = vec![0x78, 0x01, 1];
    result.extend(size.to_le_bytes());
    result.extend((!size).to_le_bytes());
    result.extend(bytes);
    let (a, b) = bytes.iter().fold((1u32, 0u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521;
        (a, (b + a) % 65_521)
    });
    result.extend(((b << 16) | a).to_be_bytes());
    result
}
pub fn pack(format: GitHashAlgorithm, entries: &[Entry]) -> Vec<u8> {
    let mut bytes = b"PACK".to_vec();
    bytes.extend(2u32.to_be_bytes());
    bytes.extend(u32::try_from(entries.len()).unwrap().to_be_bytes());
    for entry in entries {
        let (kind, body, base) = match entry {
            Entry::Direct(kind, body) => (*kind, body, &[][..]),
            Entry::Ref(base, body) => (7, body, base.as_bytes()),
        };
        let mut size = body.len();
        let mut byte = (kind << 4) | (size & 15) as u8;
        size >>= 4;
        while size != 0 {
            bytes.push(byte | 128);
            byte = (size & 127) as u8;
            size >>= 7;
        }
        bytes.push(byte);
        bytes.extend(base);
        bytes.extend(zlib(body));
    }
    match format {
        GitHashAlgorithm::Sha1 => bytes.extend(sha1_digest(&bytes)),
        GitHashAlgorithm::Sha256 => bytes.extend(sha256_digest(&bytes)),
    }
    bytes
}
pub fn bundle(history: &History, entries: &[Entry]) -> Vec<u8> {
    let format = history.parent.algorithm();
    let mut bytes = format!(
        "# v3 git bundle\n@object-format={}\n-{} parent\n{} refs/heads/main\n\n",
        format.as_str(),
        history.parent,
        history.candidate
    )
    .into_bytes();
    bytes.extend(pack(format, entries));
    bytes
}
/// Find the real envelope by native file name under the imported namespace.
/// Fault injection preserves its bounded envelope header while corrupting the
/// payload. Coverage still authenticates availability/type; any needless full
/// traversal must fail the genuine commitment/native-payload verification.
pub fn corrupt_object(root: &Path, id: GitOid) {
    let mut pending = vec![root.join("objects")];
    let mut found = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name() == id.to_string().as_str() {
                found.push(entry.path());
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "the imported canonical original must have one payload"
    );
    let mut bytes = std::fs::read(&found[0]).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&found[0], bytes).unwrap();
}
