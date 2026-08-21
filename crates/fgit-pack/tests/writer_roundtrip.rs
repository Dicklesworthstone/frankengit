#![forbid(unsafe_code)]
//! FG-017b: pack-writer validation evidence.
//!
//! Two obligations, kept deliberately separate because they have different
//! strengths and different failure meanings.
//!
//! 1. **Round-trip closure equality**, in-process and hermetic. Every pack
//!    `PackWriter` emits is read back through the FG-016 reader, and the object
//!    set it surfaces must equal the closure the planner said it packed —
//!    identity, type, and exact body. This runs on every `cargo test`; it
//!    invokes nothing external and needs no oracle.
//!
//! 2. **Client acceptance** by real upstream Git. That cannot be asserted from
//!    inside this process without violating AGENTS.md §3.1, which permits
//!    upstream Git only as a pinned, sandboxed oracle outside production. So
//!    the ignored producer below writes packs and a manifest into an artifact
//!    directory, and `scripts/e2e/suites/pack/pack_writer_roundtrip.sh` is what
//!    hands them to `git index-pack --strict` through `oracle.sh`. The process
//!    boundary stays outside Rust, exactly as `differential_oracle.rs`
//!    establishes for the reader direction.
//!
//! ## Why the corpus builds real Git objects rather than fixtures
//!
//! `index-pack --strict` validates object *content*: tree entry ordering and
//! modes, commit header shape, and every identity recomputed from the bytes. A
//! corpus of plausible-looking blobs would be accepted by our own reader and
//! rejected by Git, which is the one disagreement this bead exists to detect.
//! Every object here is therefore assembled in real Git wire format and
//! identified with [`fgit_git_object::native_object_oid`], so the corpus is a
//! genuine history that Git could have produced.
//!
//! ## Non-claims
//!
//! * Round-trip equality is evidence about **our** writer and **our** reader
//!   agreeing. Two components sharing one wrong assumption would agree with
//!   each other and both be wrong; only the oracle lane can catch that, and it
//!   is a separate obligation for that reason.
//! * Nothing here measures performance. The benchmark is its own artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, NativeChecksumVerifier, ObjectFormat, ObjectId,
    PackLimits, PackPlan, PackPlanner, PackWriteError, PackWriteProfile, PackWriter,
    ScalarResolver, read_verified_pack,
};

/// Where the e2e lane asks the producer to leave packs and their manifests.
const ARTIFACT_ENV: &str = "FGIT_PACK_WRITER_ARTIFACT_DIR";

/// Manifest schema the shell suite reads back.
const MANIFEST_SCHEMA: &str = "frankengit.pack-writer-corpus.v1";

// ---------------------------------------------------------------------------
// Corpus construction: real Git objects, not fixtures
// ---------------------------------------------------------------------------

/// One object in a corpus, with the closure edges the planner walks.
#[derive(Clone, Debug)]
struct CorpusObject {
    id: ObjectId,
    object_type: ObjectType,
    body: Vec<u8>,
    references: Vec<ObjectId>,
}

/// A named corpus and the roots a pack is planned from.
#[derive(Clone, Debug)]
struct Corpus {
    name: &'static str,
    objects: Vec<CorpusObject>,
    roots: Vec<ObjectId>,
}

/// A [`CanonicalObjectSource`] over an in-memory corpus.
///
/// Recency and path-hash are derived from the object's position and identity
/// rather than from a clock, so a corpus produces the same plan on every run
/// and on every platform. A clock here would make the writer's determinism
/// claim untestable.
struct CorpusSource {
    objects: BTreeMap<ObjectId, (CorpusObject, u64)>,
}

impl CorpusSource {
    fn new(corpus: &Corpus) -> Self {
        let mut objects = BTreeMap::new();
        for (index, object) in corpus.objects.iter().enumerate() {
            let recency = u64::try_from(index).unwrap_or(u64::MAX);
            objects.insert(object.id, (object.clone(), recency));
        }
        Self { objects }
    }
}

impl CanonicalObjectSource for CorpusSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let (object, recency) = self
            .objects
            .get(id)
            .unwrap_or_else(|| panic!("corpus is missing an object it referenced: {id:?}"));
        // The path hash is a stable function of identity, never of iteration
        // order: §16.3 forbids map order from becoming output semantics.
        let path_hash = stable_path_hash(&object.body);
        Ok(CanonicalPackObject::new(
            object.id,
            object.object_type,
            object.body.clone(),
            object.references.clone(),
            *recency,
            path_hash,
        ))
    }
}

/// A deterministic, non-cryptographic spread over object bytes.
///
/// Explicitly **not** a digest: it feeds only the frozen profile's delta
/// grouping heuristic, and nothing downstream treats it as an identity. Named
/// so a reader does not mistake it for one.
fn stable_path_hash(body: &[u8]) -> u64 {
    let mut accumulator = 0xcbf2_9ce4_8422_2325_u64;
    for byte in body {
        accumulator ^= u64::from(*byte);
        accumulator = accumulator.wrapping_mul(0x0000_0100_0000_01b3);
    }
    accumulator
}

/// Builds a blob and returns it with its real Git identity.
fn blob(content: &[u8]) -> CorpusObject {
    let body = content.to_vec();
    let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &body));
    CorpusObject {
        id,
        object_type: ObjectType::Blob,
        body,
        references: Vec::new(),
    }
}

/// Builds a tree from `(mode, name, id)` entries in Git's required ordering.
///
/// Git sorts tree entries by name with directories compared as though they end
/// in `/`. `index-pack --strict` rejects a tree that is out of order, so the
/// ordering is applied here rather than trusted from the caller.
fn tree(entries: &[(&str, &str, ObjectId)]) -> CorpusObject {
    let mut sorted: Vec<(&str, &str, ObjectId)> = entries.to_vec();
    sorted.sort_by(|left, right| sort_key(left.0, left.1).cmp(&sort_key(right.0, right.1)));

    let mut body = Vec::new();
    let mut references = Vec::new();
    for (mode, name, id) in &sorted {
        body.extend_from_slice(mode.as_bytes());
        body.push(b' ');
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(&raw_oid_bytes(*id));
        references.push(*id);
    }
    let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Tree, &body));
    CorpusObject {
        id,
        object_type: ObjectType::Tree,
        body,
        references,
    }
}

/// Git's tree-entry sort key: a directory sorts as if its name ended in `/`.
fn sort_key(mode: &str, name: &str) -> Vec<u8> {
    let mut key = name.as_bytes().to_vec();
    if mode == "40000" {
        key.push(b'/');
    }
    key
}

/// Builds a commit with a fixed identity and timestamp.
///
/// The timestamp is a constant, not `now()`. A clock would make the pack bytes
/// differ between runs and destroy the determinism this corpus is meant to
/// exercise.
fn commit(tree_id: ObjectId, parents: &[ObjectId], message: &str) -> CorpusObject {
    let mut body = Vec::new();
    body.extend_from_slice(b"tree ");
    body.extend_from_slice(hex_oid(tree_id).as_bytes());
    body.push(b'\n');
    let mut references = vec![tree_id];
    for parent in parents {
        body.extend_from_slice(b"parent ");
        body.extend_from_slice(hex_oid(*parent).as_bytes());
        body.push(b'\n');
        references.push(*parent);
    }
    body.extend_from_slice(b"author FrankenGit Corpus <corpus@invalid.example> 1700000000 +0000\n");
    body.extend_from_slice(
        b"committer FrankenGit Corpus <corpus@invalid.example> 1700000000 +0000\n",
    );
    body.push(b'\n');
    body.extend_from_slice(message.as_bytes());
    body.push(b'\n');
    let id = ObjectId::from(native_object_oid::<Sha1>(ObjectType::Commit, &body));
    CorpusObject {
        id,
        object_type: ObjectType::Commit,
        body,
        references,
    }
}

fn raw_oid_bytes(id: ObjectId) -> Vec<u8> {
    match id {
        ObjectId::Sha1(oid) => oid.as_bytes().to_vec(),
        ObjectId::Sha256(oid) => oid.as_bytes().to_vec(),
    }
}

fn hex_oid(id: ObjectId) -> String {
    raw_oid_bytes(id)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// The corpora
// ---------------------------------------------------------------------------

/// A single blob: the smallest pack that is still a real pack.
fn corpus_single_blob() -> Corpus {
    let only = blob(b"fg017b single blob\n");
    let roots = vec![only.id];
    Corpus {
        name: "single_blob",
        objects: vec![only],
        roots,
    }
}

/// One commit over a small tree: the shape every clone starts from.
fn corpus_one_commit() -> Corpus {
    let readme = blob(b"# FrankenGit\n\nfg017b corpus.\n");
    let license = blob(b"source-available\n");
    let root = tree(&[
        ("100644", "README.md", readme.id),
        ("100644", "LICENSE", license.id),
    ]);
    let head = commit(root.id, &[], "initial corpus commit");
    let roots = vec![head.id];
    Corpus {
        name: "one_commit",
        objects: vec![readme, license, root, head],
        roots,
    }
}

/// A three-commit history with a subdirectory and a modified file.
///
/// This is the corpus that matters for delta selection: the two revisions of
/// the same file are similar enough that the frozen profile's delta window can
/// choose to represent one against the other.
fn corpus_history() -> Corpus {
    let v1 = blob(b"line one\nline two\nline three\nline four\n");
    let v2 = blob(b"line one\nline two CHANGED\nline three\nline four\nline five\n");
    let nested = blob(b"nested content\n");
    let sub = tree(&[("100644", "nested.txt", nested.id)]);

    let tree1 = tree(&[("100644", "file.txt", v1.id), ("40000", "sub", sub.id)]);
    let tree2 = tree(&[("100644", "file.txt", v2.id), ("40000", "sub", sub.id)]);

    let first = commit(tree1.id, &[], "first");
    let second = commit(tree2.id, &[first.id], "second");
    let third = commit(tree2.id, &[second.id], "third, tree unchanged");

    let roots = vec![third.id];
    Corpus {
        name: "history",
        objects: vec![v1, v2, nested, sub, tree1, tree2, first, second, third],
        roots,
    }
}

/// Many similar blobs, to push the planner past its delta window.
fn corpus_wide() -> Corpus {
    let mut objects = Vec::new();
    let mut entries = Vec::new();
    let mut names = Vec::new();
    for index in 0..48_u32 {
        let content = format!("shared prefix line\nrecord {index}\nshared suffix line\n");
        let object = blob(content.as_bytes());
        names.push(format!("file{index:03}.txt"));
        entries.push(object.id);
        objects.push(object);
    }
    let tree_entries: Vec<(&str, &str, ObjectId)> = names
        .iter()
        .zip(entries.iter())
        .map(|(name, id)| ("100644", name.as_str(), *id))
        .collect();
    let root = tree(&tree_entries);
    let head = commit(root.id, &[], "wide corpus");
    let roots = vec![head.id];
    objects.push(root);
    objects.push(head);
    Corpus {
        name: "wide",
        objects,
        roots,
    }
}

fn all_corpora() -> Vec<Corpus> {
    vec![
        corpus_single_blob(),
        corpus_one_commit(),
        corpus_history(),
        corpus_wide(),
    ]
}

// ---------------------------------------------------------------------------
// Planning and writing
// ---------------------------------------------------------------------------

fn limits() -> PackLimits {
    PackLimits::default()
}

fn plan_for(corpus: &Corpus) -> PackPlan {
    let planner = PackPlanner::new(ObjectFormat::Sha1, PackWriteProfile::STORED_V1, limits());
    let source = CorpusSource::new(corpus);
    let mut deadline = || true;
    planner
        .plan(&source, &corpus.roots, &mut deadline)
        .unwrap_or_else(|error| panic!("planning {} failed: {error:?}", corpus.name))
}

fn write_pack(corpus: &Corpus) -> (Vec<u8>, PackPlan) {
    let plan = plan_for(corpus);
    let writer = PackWriter::new(limits());
    let mut deadline = || true;
    let (bytes, receipt) = writer
        .write(&plan, &mut deadline)
        .unwrap_or_else(|error| panic!("writing {} failed: {error:?}", corpus.name));
    assert_eq!(
        receipt.object_count as usize,
        plan.entries().len(),
        "{}: receipt object count disagrees with the plan",
        corpus.name
    );
    assert_eq!(
        receipt.output_bytes,
        bytes.len(),
        "{}: receipt output_bytes disagrees with the emitted pack",
        corpus.name
    );
    (bytes, plan)
}

/// The closure the planner said it packed: identity to (type, body).
fn planned_closure(plan: &PackPlan) -> BTreeMap<ObjectId, (ObjectType, Vec<u8>)> {
    plan.entries()
        .iter()
        .map(|entry| {
            let object = entry.object();
            (object.id(), (object.object_type(), object.body().to_vec()))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Obligation 1: round-trip closure equality (hermetic, always runs)
// ---------------------------------------------------------------------------

/// Every written pack reads back as exactly the planned closure.
///
/// This is the bead's "re-read by FG-016 (object-set equality with the planned
/// closure)" line, and it is deliberately stronger than reading declared
/// identities back out. The reader surfaces *unresolved* entries, so every
/// delta is reconstructed through the scalar resolver and each object's native
/// identity is **recomputed from the reconstructed bytes**. Set equality alone
/// would pass on a pack whose bodies were corrupted; recomputing the identity
/// cannot.
///
/// The offset-to-identity map is taken from the plan, in emission order. That
/// correspondence is an assumption, and it is self-checking: if it were wrong,
/// the recomputed identity would not match the identity the plan claimed, and
/// the assertion below fails.
#[test]
fn every_written_pack_reads_back_as_exactly_the_planned_closure() {
    for corpus in all_corpora() {
        let (bytes, plan) = write_pack(&corpus);
        let planned = planned_closure(&plan);

        let mut deadline = || true;
        let quarantined = read_verified_pack(
            &bytes,
            ObjectFormat::Sha1,
            &limits(),
            &mut deadline,
            &NativeChecksumVerifier,
        )
        .unwrap_or_else(|error| {
            panic!(
                "{}: our own reader refused our own pack: {error:?}",
                corpus.name
            )
        });

        assert_eq!(
            quarantined.entries().len(),
            plan.entries().len(),
            "{}: the pack holds a different number of entries than the plan",
            corpus.name
        );

        // Emission order is the plan's declared order, so entry N of the pack
        // is plan entry N. Verified by the identity check below.
        let mut id_at_offset: BTreeMap<u64, ObjectId> = BTreeMap::new();
        let mut offsets_in_order = Vec::new();
        for (entry, planned_entry) in quarantined.entries().iter().zip(plan.entries()) {
            id_at_offset.insert(entry.offset, planned_entry.object().id());
            offsets_in_order.push(entry.offset);
        }

        let objects = quarantined
            .into_scalar_objects(|offset| id_at_offset.get(&offset).copied())
            .unwrap_or_else(|error| {
                panic!("{}: scalar conversion refused: {error:?}", corpus.name)
            });
        let resolver_limits = limits();
        let resolver = ScalarResolver::new(&objects, &(), &resolver_limits, &mut || true)
            .unwrap_or_else(|error| {
                panic!("{}: resolver construction refused: {error:?}", corpus.name)
            });

        let mut surfaced: BTreeMap<ObjectId, Vec<u8>> = BTreeMap::new();
        for (offset, planned_entry) in offsets_in_order.iter().zip(plan.entries()) {
            let reconstructed = resolver
                .resolve_offset(*offset, &mut || true)
                .unwrap_or_else(|error| {
                    panic!(
                        "{}: delta resolution refused at {offset}: {error:?}",
                        corpus.name
                    )
                });
            let object = planned_entry.object();
            let recomputed = ObjectId::from(fgit_crypto::git_object_id(
                ObjectFormat::Sha1,
                object.object_type(),
                &reconstructed,
            ));
            assert_eq!(
                recomputed,
                object.id(),
                "{}: an object reconstructed from the pack does not hash to the identity the \
                 plan packed it under",
                corpus.name
            );
            surfaced.insert(recomputed, reconstructed);
        }

        let surfaced_ids: BTreeSet<ObjectId> = surfaced.keys().copied().collect();
        let expected_ids: BTreeSet<ObjectId> = planned.keys().copied().collect();

        let missing: Vec<&ObjectId> = expected_ids.difference(&surfaced_ids).collect();
        assert!(
            missing.is_empty(),
            "{}: the reader did not surface {} planned object(s): {missing:?}",
            corpus.name,
            missing.len()
        );
        let extra: Vec<&ObjectId> = surfaced_ids.difference(&expected_ids).collect();
        assert!(
            extra.is_empty(),
            "{}: the reader surfaced {} object(s) the plan never packed: {extra:?}",
            corpus.name,
            extra.len()
        );

        for (id, (_, expected_body)) in &planned {
            let actual = surfaced
                .get(id)
                .unwrap_or_else(|| panic!("{}: {id:?} vanished after set equality", corpus.name));
            assert_eq!(
                actual, expected_body,
                "{}: {id:?} round-tripped with different bytes",
                corpus.name
            );
        }
    }
}

/// The writer is deterministic: the same corpus produces byte-identical packs.
///
/// fg017a owns this property and tests it; the reason it is repeated here is
/// that the whole evidence slice is built on replanning the same corpus, and a
/// non-deterministic writer would make every artifact below unreproducible
/// without saying so.
#[test]
fn replanning_the_same_corpus_produces_byte_identical_packs() {
    for corpus in all_corpora() {
        let (first, _) = write_pack(&corpus);
        let (second, _) = write_pack(&corpus);
        assert_eq!(
            first, second,
            "{}: two writes of one corpus differ, so no artifact from this corpus is reproducible",
            corpus.name
        );
    }
}

/// A corpus that exercises deltas actually produces some.
///
/// Without this, the round-trip evidence could be entirely over base entries
/// and would say nothing about delta emission — the coverage equivalent of a
/// vacuous property.
#[test]
fn the_corpus_actually_exercises_delta_emission() {
    let mut deltas_seen = 0_usize;
    for corpus in all_corpora() {
        let plan = plan_for(&corpus);
        let writer = PackWriter::new(limits());
        let mut deadline = || true;
        let (_, receipt) = writer
            .write(&plan, &mut deadline)
            .unwrap_or_else(|error| panic!("writing {} failed: {error:?}", corpus.name));
        deltas_seen += receipt.delta_count;
    }
    assert!(
        deltas_seen > 0,
        "no corpus produced a single delta, so the round-trip evidence covers base entries only"
    );
}

// ---------------------------------------------------------------------------
// Obligation 2: produce artifacts for the pinned-oracle lane
// ---------------------------------------------------------------------------

/// Writes every corpus pack plus a manifest for the e2e oracle lane.
///
/// Ignored because it is a producer for an external consumer, not an assertion.
/// It invokes no Git: `scripts/e2e/suites/pack/pack_writer_roundtrip.sh` takes
/// these artifacts to `git index-pack --strict` through the sandboxed oracle,
/// which keeps upstream Git outside every Rust target (AGENTS.md §3.1).
#[test]
#[ignore = "producer for scripts/e2e/suites/pack/pack_writer_roundtrip.sh"]
fn emit_packs_for_the_pinned_oracle_lane() {
    let directory = env::var_os(ARTIFACT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{ARTIFACT_ENV} must name a writable artifact directory"));
    fs::create_dir_all(&directory)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", directory.display()));

    let mut manifest = String::new();
    for corpus in all_corpora() {
        let (bytes, plan) = write_pack(&corpus);
        let planned = planned_closure(&plan);

        let pack_path = directory.join(format!("{}.pack", corpus.name));
        fs::write(&pack_path, &bytes)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", pack_path.display()));

        // One NDJSON record per corpus, so the shell side can iterate without
        // parsing Rust output.
        manifest.push_str("{\"schema\":\"");
        manifest.push_str(MANIFEST_SCHEMA);
        manifest.push_str("\",\"corpus\":\"");
        manifest.push_str(corpus.name);
        manifest.push_str("\",\"pack\":\"");
        manifest.push_str(&format!("{}.pack", corpus.name));
        manifest.push_str("\",\"objects\":");
        manifest.push_str(&planned.len().to_string());
        manifest.push_str(",\"pack_bytes\":");
        manifest.push_str(&bytes.len().to_string());
        manifest.push_str(",\"object_ids\":[");
        for (index, id) in planned.keys().enumerate() {
            if index > 0 {
                manifest.push(',');
            }
            manifest.push('"');
            manifest.push_str(&hex_oid(*id));
            manifest.push('"');
        }
        manifest.push_str("],\"roots\":[");
        for (index, id) in corpus.roots.iter().enumerate() {
            if index > 0 {
                manifest.push(',');
            }
            manifest.push('"');
            manifest.push_str(&hex_oid(*id));
            manifest.push('"');
        }
        // A commit root lets the oracle lane walk the object graph with
        // rev-list. index-pack proves a pack is INDEXABLE; traversing from a
        // commit proves the objects inside it are USABLE, which is the stronger
        // reading of the bead's "consumed by pinned Git clients".
        manifest.push_str("],\"root_is_commit\":");
        let root_is_commit = corpus.roots.iter().all(|root| {
            corpus
                .objects
                .iter()
                .any(|object| object.id == *root && object.object_type == ObjectType::Commit)
        });
        manifest.push_str(if root_is_commit { "true" } else { "false" });
        manifest.push_str("}\n");

        println!(
            "corpus={} objects={} pack_bytes={}",
            corpus.name,
            planned.len(),
            bytes.len()
        );
    }

    let manifest_path = directory.join("manifest.ndjson");
    fs::write(&manifest_path, manifest)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", manifest_path.display()));
}
