//! Native bytes, real loose/idx-pack sources and the embedded authority.
//! In-memory loader tests are labelled separately and grant no source authority.
use super::*;
use crate::{NodeConfig, OneNode};
use fgit_crypto::{git_object_id, sha1_digest, sha256_digest};
use fgit_types::{DecisionOutcome, HeadGeneration, PrincipalId, RefName, RepositoryId, TenantId};
use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("fg-import-graph-{}-{}",
            std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap(); Self(path)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(self.0.join("node"), TenantId::from_bytes([0xd1; 16]),
            RepositoryId::from_bytes([0xd2; 16])).with_object_format(format).with_worker_threads(2)
    }
    fn node(&self, format: GitHashAlgorithm) -> OneNode {
        OneNode::init(self.config(format)).unwrap().0
    }
}
impl Drop for Scratch { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }

#[derive(Default)]
struct Objects(BTreeMap<GitOid, LooseObject>);
impl Objects {
    fn put(&mut self, format: GitHashAlgorithm, kind: ObjectType, body: Vec<u8>) -> GitOid {
        let id = git_object_id(format, kind, &body);
        self.0.insert(id, LooseObject { object_type: kind, declared_size: body.len(), body }); id
    }
    fn tree(&mut self, format: GitHashAlgorithm, mode: &str, child: GitOid) -> GitOid {
        self.put(format, ObjectType::Tree, [format!("{mode} entry\0").as_bytes(), child.as_bytes()].concat())
    }
    fn commit(&mut self, format: GitHashAlgorithm, tree: GitOid, parents: &[GitOid], label: &str) -> GitOid {
        let mut body = format!("tree {tree}\n");
        for parent in parents { body.push_str(&format!("parent {parent}\n")); }
        body.push_str(&format!("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\n{label}\n"));
        self.put(format, ObjectType::Commit, body.into_bytes())
    }
    fn tag(&mut self, format: GitHashAlgorithm, child: GitOid, kind: &str) -> GitOid {
        self.put(format, ObjectType::Tag, format!(
            "object {child}\ntype {kind}\ntag release\ntagger Test <test@example.invalid> 1 +0000\n\ntag\n"
        ).into_bytes())
    }
    fn load(&self, id: GitOid) -> Result<LooseObject, LooseGitImportRefusal> {
        self.0.get(&id).cloned().ok_or(LooseGitImportRefusal::ObjectMissing(id))
    }
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    let n = u16::try_from(bytes.len()).unwrap();
    let mut out = vec![0x78, 0x01, 0x01];
    out.extend(n.to_le_bytes()); out.extend((!n).to_le_bytes()); out.extend(bytes);
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let next = (a + u32::from(*byte)) % 65_521; (next, (b + next) % 65_521)
    });
    out.extend(((b << 16) | a).to_be_bytes()); out
}
fn hash(format: GitHashAlgorithm, bytes: &[u8]) -> Vec<u8> {
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
fn write_loose(root: &Path, id: GitOid, object: &LooseObject) {
    let hex = id.to_string(); let path = root.join("objects").join(&hex[..2]);
    fs::create_dir_all(&path).unwrap();
    let framed = [format!("{} {}\0", object.object_type.label(), object.body.len()).as_bytes(), &object.body].concat();
    fs::write(path.join(&hex[2..]), zlib(&framed)).unwrap();
}
/// Independent bounded no-delta pack/idx-v2 fixture, including CRCs and both
/// hash-domain trailers. Production still uses its existing pack reader.
fn write_pack(root: &Path, format: GitHashAlgorithm, objects: &Objects) {
    let mut pack = b"PACK".to_vec();
    pack.extend(2_u32.to_be_bytes()); pack.extend(u32::try_from(objects.0.len()).unwrap().to_be_bytes());
    let mut entries = Vec::new();
    for (id, object) in &objects.0 {
        let offset = pack.len();
        let kind = match object.object_type { ObjectType::Commit => 1_u8, ObjectType::Tree => 2,
            ObjectType::Blob => 3, ObjectType::Tag => 4 };
        let mut size = object.body.len(); let mut byte = kind << 4 | (size as u8 & 15); size >>= 4;
        while size != 0 { pack.push(byte | 128); byte = size as u8 & 127; size >>= 7; }
        pack.push(byte); pack.extend(zlib(&object.body));
        entries.push((*id, crc32(&pack[offset..]), u32::try_from(offset).unwrap()));
    }
    let checksum = hash(format, &pack); pack.extend(&checksum);
    let mut index = b"\xfftOc".to_vec(); index.extend(2_u32.to_be_bytes());
    for value in 0_u16..256 {
        let count = entries.iter().filter(|(id, _, _)| u16::from(id.as_bytes()[0]) <= value).count();
        index.extend(u32::try_from(count).unwrap().to_be_bytes());
    }
    for (id, _, _) in &entries { index.extend(id.as_bytes()); }
    for (_, crc, _) in &entries { index.extend(crc.to_be_bytes()); }
    for (_, _, offset) in &entries { index.extend(offset.to_be_bytes()); }
    index.extend(checksum); let checksum = hash(format, &index); index.extend(checksum);
    let dir = root.join("objects/pack"); fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("fixture.pack"), pack).unwrap(); fs::write(dir.join("fixture.idx"), index).unwrap();
}
fn source(root: &Path, format: GitHashAlgorithm, objects: &Objects, refs: &[(&str, GitOid)], packed: bool) {
    fs::create_dir_all(root.join("objects")).unwrap();
    fs::write(root.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(root.join("config"), match format {
        GitHashAlgorithm::Sha1 => "[core]\nbare=true\nrepositoryformatversion=0\n",
        GitHashAlgorithm::Sha256 => "[core]\nbare=true\nrepositoryformatversion=1\n[extensions]\nobjectformat=sha256\n",
    }).unwrap();
    for (name, id) in refs {
        let path = root.join(name); fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("{id}\n")).unwrap();
    }
    if packed { write_pack(root, format, objects); }
    else { for (id, object) in &objects.0 { write_loose(root, *id, object); } }
}
fn limits(format: GitHashAlgorithm) -> ParseLimits {
    ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() }
}
fn assert_unstaged(node: &OneNode, objects: &Objects) {
    for id in objects.0.keys() { assert!(node.read_git_object(*id).is_err(), "unexpected partial staging of {id}"); }
}

#[test]
fn absent_submodule_objects_import_from_loose_and_packed_sources_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for packed in [false, true] {
            let scratch = Scratch::new(); let mut objects = Objects::default();
            let external = git_object_id(format, ObjectType::Commit, b"object in another repository");
            // The padded mode is import-compatible and must remain a gitlink.
            let tree = objects.tree(format, if packed { "0160000" } else { "160000" }, external);
            let commit = objects.commit(format, tree, &[], "submodule");
            let tag = objects.tag(format, commit, "commit");
            let nested = objects.tag(format, tag, "tag");
            let unused = objects.put(format, ObjectType::Blob, b"unreachable source bytes".to_vec());
            let root = scratch.0.join("source");
            source(&root, format, &objects, &[("refs/heads/main", commit), ("refs/tags/release", nested)], packed);
            let node = scratch.node(format); let request = node.request_context();
            let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
            let staged = node.stage_loose_git_import(&root).unwrap();
            assert_eq!(staged.closure().objects(), &BTreeSet::from([tree, commit, tag, nested]));
            assert_eq!(staged.object_count(), 4);
            assert_eq!(staged.refs().head_target(), Some(&RefName::try_new(b"refs/heads/main").unwrap()));
            assert!(node.read_git_object(external).is_err()); assert!(node.read_git_object(unused).is_err());
            assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
            assert_eq!(node.stage_loose_git_import(&root).unwrap(), staged);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn checksum_valid_wrong_kind_graphs_refuse_before_any_fabric_placement() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for packed in [false, true] {
            for case in 0..6 {
                let scratch = Scratch::new(); let mut objects = Objects::default();
                let blob = objects.put(format, ObjectType::Blob, b"valid bytes, wrong relationship".to_vec());
                let empty = objects.put(format, ObjectType::Tree, Vec::new());
                let root = match case {
                    0 => objects.commit(format, blob, &[], "blob as tree"),
                    1 => objects.commit(format, empty, &[blob], "blob as parent"),
                    2 => objects.tree(format, "40000", blob),
                    3 => objects.tree(format, "100644", empty),
                    4 => objects.tree(format, "120000", empty),
                    _ => objects.tag(format, blob, "commit"),
                };
                let path = scratch.0.join("source");
                source(&path, format, &objects, &[("refs/heads/main", root)], packed);
                let node = scratch.node(format); let request = node.request_context();
                let before = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
                assert!(matches!(node.stage_loose_git_import(&path),
                    Err(LooseGitImportRefusal::ObjectGraph { code: RefusalCode::EvidenceInvalid, .. })), "case {case}");
                assert_unstaged(&node, &objects);
                assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis(), before.basis());
                node.shutdown().unwrap();
            }
        }
    }
}

#[test]
fn ambiguous_edges_and_unknown_kinds_do_not_choose_a_convenient_parse() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for case in 0..5 {
            let scratch = Scratch::new(); let mut objects = Objects::default();
            let empty = objects.put(format, ObjectType::Tree, Vec::new());
            let root = match case {
                0 => objects.put(format, ObjectType::Commit, format!("tree {empty}\ntree {empty}\n\nmessage").into_bytes()),
                1 => objects.put(format, ObjectType::Commit, format!("tree {empty}\n continuation\n\nmessage").into_bytes()),
                2 => objects.put(format, ObjectType::Commit, format!("tree {empty}\nparent {empty}\n continuation\n\nmessage").into_bytes()),
                3 => objects.put(format, ObjectType::Tag, format!("object {empty}\ntype tree\ntype blob\n\nmessage").into_bytes()),
                _ => objects.tree(format, "140000", empty),
            };
            let path = scratch.0.join("source"); source(&path, format, &objects, &[("refs/heads/main", root)], false);
            let node = scratch.node(format);
            assert!(matches!(node.stage_loose_git_import(&path),
                Err(LooseGitImportRefusal::ObjectGraph { code: RefusalCode::ObjectHeaderInvalid, .. })), "case {case}");
            assert_unstaged(&node, &objects); node.shutdown().unwrap();
        }
    }
}

#[test]
fn later_missing_dependencies_cannot_leave_an_earlier_valid_root_staged() {
    let format = GitHashAlgorithm::Sha256; let scratch = Scratch::new();
    let mut objects = Objects::default();
    let missing = git_object_id(format, ObjectType::Blob, b"missing");
    let tree = objects.tree(format, "100644", missing);
    let commit = objects.commit(format, tree, &[], "incomplete graph");
    let other = objects.put(format, ObjectType::Blob, b"independent valid ref".to_vec());
    let path = scratch.0.join("source");
    source(&path, format, &objects, &[("refs/heads/main", commit), ("refs/notes/data", other)], true);
    let node = scratch.node(format);
    assert!(matches!(node.stage_loose_git_import(&path), Err(LooseGitImportRefusal::ObjectMissing(id)) if id == missing));
    assert_unstaged(&node, &objects);
    // Supplying precisely the missing body makes the same mixed-source import
    // valid. No stale negative cache or partially minted publication exists.
    let id = objects.put(format, ObjectType::Blob, b"missing".to_vec()); assert_eq!(id, missing);
    write_loose(&path, id, objects.0.get(&id).unwrap());
    assert_eq!(node.stage_loose_git_import(&path).unwrap().closure().objects(), &objects.0.keys().copied().collect());
    node.shutdown().unwrap();
}

#[test]
fn contradictory_requirements_are_checked_even_for_previously_selected_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut objects = Objects::default();
        let blob = objects.put(format, ObjectType::Blob, b"root first".to_vec());
        let tree = objects.tree(format, "100644", blob);
        let bad = objects.commit(format, tree, &[blob], "contradictory parent kind");
        for roots in [[blob, bad], [bad, blob]] {
            assert!(matches!(validate(roots, format, &limits(format), Limits::default(), |id| objects.load(id)),
                Err(LooseGitImportRefusal::ObjectGraph { code: RefusalCode::EvidenceInvalid, .. })));
        }
        let valid = objects.commit(format, tree, &[], "near-identical permitted graph");
        let proof = validate([blob, valid], format, &limits(format), Limits::default(), |id| objects.load(id)).unwrap();
        assert_eq!(proof.objects.keys().copied().collect::<BTreeSet<_>>(), BTreeSet::from([blob, tree, valid]));
    }
}

#[test]
fn frontier_edges_and_retained_body_bytes_have_independent_inclusive_bounds() {
    let format = GitHashAlgorithm::Sha1; let mut objects = Objects::default();
    let blob = objects.put(format, ObjectType::Blob, b"bounded".to_vec());
    let tree = objects.tree(format, "100644", blob);
    let reads = Cell::new(0);
    let maximum = Limits::default();
    assert!(matches!(validate([tree], format, &limits(format), Limits { objects: 1, ..maximum }, |id| {
        reads.set(reads.get() + 1); objects.load(id)
    }), Err(LooseGitImportRefusal::ObjectLimitExceeded { limit: 1 })));
    assert_eq!(reads.get(), 1, "frontier charged before the next read");
    let bytes = objects.0.values().map(|o| o.body.len() as u64).sum::<u64>();
    let exact = Limits { objects: 2, edges: 1, bytes };
    assert_eq!(validate([tree], format, &limits(format), exact, |id| objects.load(id)).unwrap().total_bytes, bytes);
    assert!(matches!(validate([tree], format, &limits(format), Limits { bytes: bytes - 1, ..exact }, |id| objects.load(id)),
        Err(LooseGitImportRefusal::TotalObjectBytesExceeded { .. })));
    assert!(matches!(validate([tree], format, &limits(format), Limits { edges: 0, ..exact }, |id| objects.load(id)),
        Err(LooseGitImportRefusal::ObjectGraph { code: RefusalCode::ResourceBudgetExceeded, .. })));
    let external = git_object_id(format, ObjectType::Commit, b"external");
    let link = objects.tree(format, "160000", external);
    assert!(matches!(validate([link], format, &limits(format), Limits { edges: 0, ..maximum }, |id| objects.load(id)),
        Err(LooseGitImportRefusal::ObjectGraph { code: RefusalCode::ResourceBudgetExceeded, .. })));
}

#[test]
fn the_common_edge_reader_preserves_cancellation_and_requires_all_tag_target_types() {
    let format = GitHashAlgorithm::Sha1; let mut objects = Objects::default();
    let blob = objects.put(format, ObjectType::Blob, Vec::new());
    for kind in ["blob", "tree", "commit", "tag"] {
        let tag = objects.tag(format, blob, kind); let object = &objects.0[&tag];
        let parsed = parse_object_body(object.object_type, &object.body, AcceptanceProfile::GitCompatibleImport, &limits(format)).unwrap();
        assert_eq!(references(format, &parsed, &object.body, &limits(format), &mut 1, &mut || false),
            Err(RefusalCode::CancellationInProgress));
        let mut remaining = 1;
        let edges = references(format, &parsed, &object.body, &limits(format), &mut remaining, &mut || true).unwrap();
        assert_eq!(edges.len(), 1); assert_eq!(edges[0].0, blob); assert_eq!(edges[0].1.label(), kind);
        assert_eq!(remaining, 0);
    }
}

#[test]
fn a_substituted_body_never_produces_an_import_proof() {
    let format = GitHashAlgorithm::Sha256; let mut objects = Objects::default();
    let expected = objects.put(format, ObjectType::Blob, b"expected".to_vec());
    let replacement = objects.put(format, ObjectType::Blob, b"replacement".to_vec());
    assert!(matches!(validate([expected], format, &limits(format), Limits::default(), |_| objects.load(replacement)),
        Err(LooseGitImportRefusal::ObjectIdentityMismatch { expected: wanted, observed }) if wanted == expected && observed == replacement));
    let proof = validate([expected], format, &limits(format), Limits::default(), |id| objects.load(id)).unwrap();
    assert_eq!(proof.objects[&expected].body, b"expected");
}

#[test]
fn valid_submodule_import_publishes_and_reopens_through_the_original_durable_api() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new(); let mut objects = Objects::default();
        let foreign = git_object_id(format, ObjectType::Commit, b"unavailable external repository");
        let tree = objects.tree(format, "160000", foreign);
        let tip = objects.commit(format, tree, &[], "submodule import");
        let root = scratch.0.join("source"); source(&root, format, &objects, &[("refs/heads/main", tip)], true);
        let mut node = scratch.node(format); node.bring_into_service(HeadGeneration::FIRST).unwrap();
        let request = node.request_context();
        let terminal = node.runtime().block_on(node.import_loose_git_directory_durable_in(
            &request, &root, PrincipalId::from_bytes([0xd3; 16]), b"typed-import",
        )).unwrap();
        assert_eq!(terminal.commands.len(), 1);
        assert!(matches!(terminal.commands[0].terminal.outcome, DecisionOutcome::Committed { .. }));
        let after = node.runtime().block_on(node.materialize_admission_in(&request)).unwrap();
        let head = after.basis().id();
        assert_eq!(after.snapshot().refs[&RefName::try_new(b"refs/heads/main").unwrap()], tip);
        assert!(!after.selected_closure().closure().objects().contains(&foreign));
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
        node.bring_into_service(HeadGeneration::FIRST).unwrap(); let request = node.request_context();
        let retry = node.runtime().block_on(node.import_loose_git_directory_durable_in(
            &request, &root, PrincipalId::from_bytes([0xd3; 16]), b"typed-import",
        )).unwrap();
        assert_eq!(retry.commands[0].terminal, terminal.commands[0].terminal);
        assert_eq!(node.runtime().block_on(node.materialize_admission_in(&request)).unwrap().basis().id(), head);
        node.shutdown().unwrap();
    }
}
