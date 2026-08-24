#![forbid(unsafe_code)]
//! `frankengit-uw4e`: the on-disk integrity chain of `LocalObjectStore::load_object`.
//!
//! Independent adversary over `fgit-object-fabric`, which this file does not
//! own. Nothing here modifies `crates/fgit-object-fabric/src/**`; every probe
//! drives the public `ImmutableObjectFabric` surface and the filesystem the
//! backend writes to.
//!
//! `load_object` is the read path that turns bytes on disk back into a
//! `VerifiedObject`. It is a chain of guards, and before this file none of them
//! was exercised by any test in the workspace — including the identity
//! commitment, whose failure has no loud symptom: the object it hands back is
//! internally consistent and decodes cleanly. It is simply the wrong object.
//!
//! # Guard ordering is the whole difficulty
//!
//! The guards run in sequence, so a corruption that breaks more than one lets
//! the *earlier* guard fire and the probe proves nothing about the site it
//! claims to test. Every probe below therefore corrupts the minimum and
//! **asserts that the earlier guards still pass** — a truncation probe checks
//! that its magic survived, a namespace probe checks that its envelope still
//! decodes, and the identity probe uses bytes that are valid in every respect
//! except which object they are.
//!
//! # Two of the sites named in the bead cannot be reached
//!
//! The bead asks for three `MalformedStoredObject` sites pinned separately.
//! Only two are reachable, and manufacturing a probe for the third would be
//! inventing coverage:
//!
//! ```text
//! let envelope_len = u32::from_be_bytes(
//!     bytes[4..8].try_into().map_err(|_| StoreRefusal::MalformedStoredObject)?,
//! );
//! ```
//!
//! The guard above it returns unless `bytes.len() >= 8`, so `bytes[4..8]` is
//! *exactly* four bytes, and `<&[u8] as TryInto<[u8; 4]>>` fails only on a
//! length mismatch. The arm is dead code.
//! [`the_envelope_length_conversion_guard_cannot_fire`] demonstrates that
//! executably rather than asserting it in prose.
//!
//! The two `LengthOverflow` arms on the same path are unreachable for the same
//! class of reason on a 64-bit target: `u32 -> usize` is infallible, and
//! `8 + (u32::MAX as usize)` cannot overflow a 64-bit `usize`. They are
//! defensible as 32-bit portability guards; they are not testable here, and
//! this file does not pretend otherwise.
//!
//! # `reference.rs` is not the same guard, so one corpus cannot drive both
//!
//! The bead asks whether the second backend's stored-object refusal is the
//! same guard. It is not, and the asymmetry is worth recording: `reference.rs`
//! raises it on the **write** path when an object already exists under the
//! requested identity with different content (`existing != &object`), while
//! `local.rs` raises it on the **read** path when what is on disk reconstructs
//! to a different identity than the caller asked for. These are now distinct
//! structural refusals: `StoredObjectIdentityCollision` on the write path and
//! `StoredObjectReconstructionMismatch` on the read path. This file pins the
//! read-path corruption guard; `reference.rs` owns the corresponding in-crate
//! write-collision probe.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use fgit_object_fabric::fabric::{
    ImmutableObjectFabric, ManifestLimits, PlacementAdmission, PlacementBackend, PlacementReceipt,
    PutIfAbsent, SegmentManifest, StoreRefusal, VerifiedObject,
};
use fgit_object_fabric::local::{LocalFilesystemConfig, LocalFilesystemFabric};
use fgit_object_fabric::{
    CryptoDigest, DigestAlgorithm, MicrosegmentBuilder, MicrosegmentReader, ObjectEnvelope,
    ObjectKind, SegmentLimits, SegmentRecordInput,
};
use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{LeakDisposition, ObligationLedger};
use fgit_resource::{OpaqueHandle, RegionId};
use fgit_types::GitOid;

const NAMESPACE: &[u8] = b"uw4e-primary";
const OTHER_NAMESPACE: &[u8] = b"uw4e-secondary";
const OBJECT_MAGIC: &[u8] = b"FGOB";

/// Unique-per-invocation temp roots without a clock or an RNG, neither of which
/// belongs in a corpus that must be replayable.
static ROOT_COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_root(label: &str) -> PathBuf {
    let seq = ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("fgit-uw4e-{}-{label}-{seq}", std::process::id()));
    let _ignored = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("temp root must be creatable");
    root
}

fn oid_for(payload: &[u8]) -> GitOid {
    fgit_crypto::git_object_id(
        fgit_crypto::GitObjectFormat::Sha1,
        fgit_crypto::GitObjectKind::Blob,
        payload,
    )
}

fn envelope_for(payload: &[u8], namespace: &[u8]) -> ObjectEnvelope {
    let digest = CryptoDigest;
    let commitment = digest
        .payload_commitment(ObjectKind::Blob, payload)
        .expect("fixture commitment must be available");
    ObjectEnvelope::new(
        namespace.to_vec(),
        oid_for(payload),
        ObjectKind::Blob,
        u64::try_from(payload.len()).expect("fixture length must fit u64"),
        commitment,
        b"raw".to_vec(),
        [7; 32],
        None,
        &SegmentLimits::default(),
    )
    .expect("a content-derived envelope must build")
}

fn verified(payload: &[u8], namespace: &[u8]) -> VerifiedObject {
    VerifiedObject::new(envelope_for(payload, namespace), payload.to_vec())
        .expect("a content-derived identity must verify")
}

fn fabric(root: PathBuf, namespace: &[u8], max_stored_object_bytes: u64) -> LocalFilesystemFabric {
    LocalFilesystemFabric::open(LocalFilesystemConfig::new(
        root,
        namespace.to_vec(),
        OpaqueHandle::new(&[1; 20]).expect("failure domain handle"),
        OpaqueHandle::new(&[2; 20]).expect("encryption handle"),
        max_stored_object_bytes,
        SegmentLimits::default(),
    ))
    .expect("a well-formed local profile must open")
}

fn ledger() -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::FailFast,
        ResourceVector::single(Grade::Bytes, 1 << 20).with(Grade::Objects, 64),
    )
}

fn admission(ledger: &ObligationLedger) -> PlacementAdmission<'_> {
    let grant = ledger
        .grant(ResourceVector::single(Grade::Bytes, 4096).with(Grade::Objects, 1))
        .expect("ledger must issue the placement grant");
    PlacementAdmission::new(ledger, grant)
}

fn close_quiescent(ledger: ObligationLedger) {
    let outcome = ledger.close();
    assert!(
        outcome.is_quiescent(),
        "the drill must settle every obligation it opened: {outcome:?}"
    );
}

/// Every regular file beneath `<root>/objects`, sorted for determinism.
///
/// Walking rather than reconstructing the layout on purpose: `object_path` is
/// private, and a probe that hard-codes a private path shape breaks the day the
/// layout changes while still claiming to test the guard.
fn object_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(&root.join("objects"), &mut found);
    found.sort();
    found
}

/// Store `payload` and return the identity plus the single file it produced.
fn store_one(
    store: &LocalFilesystemFabric,
    root: &Path,
    payload: &[u8],
    namespace: &[u8],
) -> (GitOid, PathBuf) {
    let ledger = ledger();
    let outcome = store
        .put_if_absent(verified(payload, namespace), admission(&ledger))
        .expect("an unfaulted write must succeed");
    assert!(matches!(outcome, PutIfAbsent::Created { .. }));
    close_quiescent(ledger);

    let files = object_files(root);
    assert_eq!(
        files.len(),
        1,
        "the fixture assumes exactly one stored object; found {files:?}"
    );
    (oid_for(payload), files[0].clone())
}

// ---------------------------------------------------------------------------
// The permitted twin (acceptance 5)
// ---------------------------------------------------------------------------

/// PERMITTED TWIN. Every probe below asserts an `Err`; without this one they
/// would all pass against a `load_object` that refused unconditionally.
#[test]
fn a_round_tripped_object_loads_and_returns_the_identity_it_was_stored_under() {
    let root = temp_root("roundtrip");
    let store = fabric(root.clone(), NAMESPACE, 1 << 20);
    let payload = b"uw4e round trip payload";
    let (identity, _path) = store_one(&store, &root, payload, NAMESPACE);

    let read = store
        .read_whole(identity)
        .expect("a clean object must load");
    assert_eq!(
        read.object.identity(),
        identity,
        "the loaded object must be the one that was asked for"
    );
    assert_eq!(read.object.payload(), payload);
}

// ---------------------------------------------------------------------------
// :247 — the identity commitment
// ---------------------------------------------------------------------------

/// THE ONE THAT MATTERS. A well-formed stored object that is not the one the
/// caller asked for.
///
/// The substitution is a whole valid file from another object, so magic,
/// envelope, namespace and payload commitment all pass — every earlier guard is
/// satisfied and only the identity check can fire. That is what makes this a
/// probe of `:247` rather than of whichever guard broke first.
#[test]
fn a_substituted_object_is_refused_by_the_identity_commitment() {
    let root_a = temp_root("identity-a");
    let store_a = fabric(root_a.clone(), NAMESPACE, 1 << 20);
    let (identity_a, path_a) = store_one(&store_a, &root_a, b"uw4e object ALPHA", NAMESPACE);

    let root_b = temp_root("identity-b");
    let store_b = fabric(root_b.clone(), NAMESPACE, 1 << 20);
    let (identity_b, path_b) = store_one(&store_b, &root_b, b"uw4e object BRAVO", NAMESPACE);

    assert_ne!(
        identity_a, identity_b,
        "the two fixtures must be different objects or this probe is vacuous"
    );

    // Substitute B's bytes at A's path: a bad rename, a restored backup, a
    // namespace collision — the file is perfectly valid, just not A.
    let bravo_bytes = fs::read(&path_b).expect("B must be readable");
    fs::write(&path_a, &bravo_bytes).expect("substitution must land");

    // Earlier guards are satisfied by construction, asserted rather than assumed.
    assert_eq!(
        bravo_bytes.get(..4),
        Some(OBJECT_MAGIC),
        "the substituted file must keep valid magic, or :226 fires instead"
    );

    let outcome = store_a.read_whole(identity_a);
    assert_eq!(
        outcome,
        Err(StoreRefusal::StoredObjectReconstructionMismatch {
            requested: identity_a,
            reconstructed: identity_b,
        }),
        "a well-formed object that is not the requested one must be refused by \
         the identity commitment, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// :226 — magic and minimum length
// ---------------------------------------------------------------------------

#[test]
fn a_file_shorter_than_the_header_is_malformed() {
    let root = temp_root("short");
    let store = fabric(root.clone(), NAMESPACE, 1 << 20);
    let (identity, path) = store_one(&store, &root, b"uw4e short header", NAMESPACE);

    fs::write(&path, [b'F', b'G', b'O', b'B', 0, 0, 0]).expect("truncation must land");

    let outcome = store.read_whole(identity);
    assert!(
        matches!(outcome, Err(StoreRefusal::MalformedStoredObject)),
        "seven bytes cannot carry the eight-byte header, got {outcome:?}"
    );
}

#[test]
fn a_file_with_the_wrong_magic_is_malformed() {
    let root = temp_root("magic");
    let store = fabric(root.clone(), NAMESPACE, 1 << 20);
    let (identity, path) = store_one(&store, &root, b"uw4e wrong magic", NAMESPACE);

    let mut bytes = fs::read(&path).expect("stored file must be readable");
    assert!(bytes.len() >= 8, "the fixture must clear the length guard");
    bytes[0] ^= 0xFF; // corrupt magic only; length stays valid

    fs::write(&path, &bytes).expect("corruption must land");

    let outcome = store.read_whole(identity);
    assert!(
        matches!(outcome, Err(StoreRefusal::MalformedStoredObject)),
        "a file whose magic does not match must be refused, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// :239 — payload_start past the end
// ---------------------------------------------------------------------------

/// A declared envelope length that runs past the buffer.
///
/// The magic is left intact and asserted intact, so `:226` cannot fire and this
/// probe reaches `:239` specifically. The length is raised rather than the file
/// truncated, because truncation short enough to matter would also trip the
/// eight-byte minimum.
#[test]
fn an_envelope_length_past_the_end_of_the_buffer_is_malformed() {
    let root = temp_root("truncated");
    let store = fabric(root.clone(), NAMESPACE, 1 << 20);
    let (identity, path) = store_one(&store, &root, b"uw4e truncated payload", NAMESPACE);

    let mut bytes = fs::read(&path).expect("stored file must be readable");
    let overlong = u32::try_from(bytes.len()).expect("fixture fits u32") + 1;
    bytes[4..8].copy_from_slice(&overlong.to_be_bytes());
    fs::write(&path, &bytes).expect("corruption must land");

    assert_eq!(
        bytes.get(..4),
        Some(OBJECT_MAGIC),
        "the magic must survive, or :226 fires and this probe tests the wrong guard"
    );

    let outcome = store.read_whole(identity);
    assert!(
        matches!(outcome, Err(StoreRefusal::MalformedStoredObject)),
        "an envelope length past the end must be refused, got {outcome:?}"
    );
}

/// The site the bead asks for that **cannot be reached**, demonstrated rather
/// than asserted in prose.
///
/// `bytes[4..8]` is produced only after the length guard, so it is always
/// exactly four bytes, and the conversion it feeds cannot fail. If the length
/// guard above it were ever relaxed, this test still passes — which is why the
/// module header, not this test, carries the reachability argument.
#[test]
fn the_envelope_length_conversion_guard_cannot_fire() {
    for len in 8_usize..64 {
        let bytes = vec![0_u8; len];
        let four: Result<[u8; 4], _> = bytes[4..8].try_into();
        assert!(
            four.is_ok(),
            "a four-byte slice always converts; the MalformedStoredObject arm on \
             that conversion is dead code and must not be given a fake probe"
        );
    }
}

// ---------------------------------------------------------------------------
// :243 — namespace
// ---------------------------------------------------------------------------

/// A stored object whose envelope names a different namespace than the store.
///
/// Both stores share a root so the second store's path for this identity is
/// reachable; the bytes written there are a *valid* object from the first
/// namespace, so magic and envelope decoding both succeed and only the
/// namespace check can fire.
#[test]
fn an_object_from_another_namespace_is_refused() {
    let root_primary = temp_root("ns-primary");
    let store_primary = fabric(root_primary.clone(), NAMESPACE, 1 << 20);
    let payload = b"uw4e namespace payload";
    let (identity, path_primary) = store_one(&store_primary, &root_primary, payload, NAMESPACE);

    let root_secondary = temp_root("ns-secondary");
    let store_secondary = fabric(root_secondary.clone(), OTHER_NAMESPACE, 1 << 20);
    let (identity_secondary, path_secondary) =
        store_one(&store_secondary, &root_secondary, payload, OTHER_NAMESPACE);
    assert_eq!(
        identity, identity_secondary,
        "identity is content-derived, so both namespaces must agree on it"
    );

    // Put the primary namespace's bytes where the secondary store looks.
    let primary_bytes = fs::read(&path_primary).expect("primary file readable");
    fs::write(&path_secondary, &primary_bytes).expect("substitution must land");
    assert_eq!(
        primary_bytes.get(..4),
        Some(OBJECT_MAGIC),
        "magic must survive so the namespace guard is the one that fires"
    );

    let outcome = store_secondary.read_whole(identity);
    assert!(
        matches!(outcome, Err(StoreRefusal::NamespaceMismatch)),
        "an envelope naming another namespace must be refused, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// StoredObjectTooLarge — two different sites (acceptance 4)
// ---------------------------------------------------------------------------

/// `:262` — a runtime size refusal on a file already on disk.
#[test]
fn a_stored_file_larger_than_the_ceiling_is_refused_at_read_time() {
    let root = temp_root("toolarge-runtime");
    let generous = fabric(root.clone(), NAMESPACE, 1 << 20);
    let (identity, path) = store_one(&generous, &root, b"uw4e oversized payload", NAMESPACE);

    let stored_len = fs::metadata(&path).expect("stored file must exist").len();
    assert!(stored_len > 1, "the fixture must exceed the tight ceiling");

    // Same bytes on disk, a store that will no longer accept them.
    let strict = fabric(root, NAMESPACE, stored_len - 1);
    let outcome = strict.read_whole(identity);

    assert!(
        matches!(
            outcome,
            Err(StoreRefusal::StoredObjectTooLarge { offered, maximum })
                if offered == stored_len && maximum == stored_len - 1
        ),
        "the refusal must carry the offered and maximum sizes, got {outcome:?}"
    );
}

/// `:121` — constructor validation, which is a different thing from `:262`.
///
/// Asserted separately because they share a variant: a probe that accepted
/// either would not distinguish a config error from a runtime size refusal.
#[test]
fn a_zero_object_ceiling_is_refused_at_construction() {
    let root = temp_root("toolarge-config");
    let outcome = LocalFilesystemFabric::open(LocalFilesystemConfig::new(
        root,
        NAMESPACE.to_vec(),
        OpaqueHandle::new(&[1; 20]).expect("failure domain handle"),
        OpaqueHandle::new(&[2; 20]).expect("encryption handle"),
        0,
        SegmentLimits::default(),
    ));

    assert!(
        matches!(
            outcome,
            Err(StoreRefusal::StoredObjectTooLarge {
                offered: 1,
                maximum: 0
            })
        ),
        "a zero ceiling admits no object at all and must be refused at open, \
         got a store instead"
    );
}

// ---------------------------------------------------------------------------
// The permitted twin at the exact inclusive boundary (380x)
// ---------------------------------------------------------------------------

/// THE CASE A REFUSAL-ONLY SUITE CANNOT REACH.
///
/// Both `StoredObjectTooLarge` probes above set the ceiling *under* the object,
/// so `offered > maximum` and `offered >= maximum` are alike true for them:
/// they hold whether the guard is correct or tightened by one. A ceiling made
/// over-strict -- one that rejects an object which exactly fits -- is invisible
/// to them. `fabric_bounds.rs` already treats that as worth pinning for the
/// three `SegmentLimits` guards, in its own words "the guard is `>`. Written
/// `>=` it would reject a segment that exactly fits". This is that drill for
/// `max_stored_object_bytes`, which that file does not reach.
///
/// Two sites are exercised at once because they bound the same quantity:
/// `:392` bounds the write (`8 + envelope + payload`) and `:348` bounds the
/// read (the file's length on disk), and the writer emits magic(4) +
/// envelope_len(4) + envelope + payload, so the two coincide.
///
/// The ceiling is MEASURED, never re-derived. A test that hard-codes the
/// encoded size stops testing the boundary the day the envelope grows a field,
/// while still passing.
/// `a_stored_file_larger_than_the_ceiling_is_refused_at_read_time` brackets
/// this from below -- it refuses at `stored_len - 1` carrying
/// `offered == stored_len` -- so that probe and this one pin the read guard's
/// edge from both sides.
#[test]
fn an_object_of_exactly_the_ceiling_is_admitted_on_the_write_and_read_paths() {
    const PAYLOAD: &[u8] = b"380x exact-fit payload";

    // Measure the stored form under a ceiling that cannot be the constraint.
    let measure_root = temp_root("exactfit-measure");
    let generous = fabric(measure_root.clone(), NAMESPACE, 1 << 20);
    let (_ignored, measured_path) = store_one(&generous, &measure_root, PAYLOAD, NAMESPACE);
    let exact = fs::metadata(&measured_path)
        .expect("the measuring write must have produced a file")
        .len();
    let payload_len = u64::try_from(PAYLOAD.len()).expect("a test payload length fits u64");
    assert!(
        exact > payload_len,
        "the stored form must carry framing beyond the payload, so that `exact` \
         is a real encoding measurement and not merely the payload length: {exact}"
    );

    // A fresh store whose ceiling is exactly that measurement. `store_one`
    // asserts `Created` internally, so reaching its return value IS the
    // write-path twin: with `:392` written `>=`, this object would be refused.
    let tight_root = temp_root("exactfit-tight");
    let tight = fabric(tight_root.clone(), NAMESPACE, exact);
    let (identity, _path) = store_one(&tight, &tight_root, PAYLOAD, NAMESPACE);

    // ... and the read path admits it at the same exact ceiling, which is the
    // `:348` twin. The payload is asserted rather than `is_ok()`: a guard that
    // returned an empty body would satisfy `is_ok()` and prove nothing.
    let read = tight
        .read_whole(identity)
        .expect("an object of exactly the ceiling must load");
    assert_eq!(
        read.object.payload(),
        PAYLOAD,
        "the exact-fit object must come back byte-for-byte"
    );
}

/// PINS THE QUANTITY THE WRITE GUARD ACTUALLY COMPARES (hyf0).
///
/// Without this, the write half of the twin above is potentially VACUOUS. That
/// drill sets the ceiling to a length measured off disk and requires the write
/// to be admitted -- but nothing showed that `:392` compares that same number.
/// `:392` bounds `8 + envelope + payload`, while the on-disk file is magic(4) +
/// envelope_len(4) + envelope + payload. Those coincide by reading the encoder,
/// which is not a measurement. Were the guard's quantity anything larger, the
/// ceiling would sit clear of its boundary and the write would be admitted for
/// the wrong reason -- passing even if `:392` were written `>=`.
///
/// Refusing one byte under, while carrying `offered` equal to the measured
/// length, is what fixes the guard's arithmetic to the measurement. The read
/// path already had this from
/// `a_stored_file_larger_than_the_ceiling_is_refused_at_read_time`; the write
/// path did not.
#[test]
fn a_write_one_byte_over_the_ceiling_is_refused_and_names_the_measured_length() {
    const PAYLOAD: &[u8] = b"hyf0 write-boundary payload";

    let measure_root = temp_root("writepin-measure");
    let generous = fabric(measure_root.clone(), NAMESPACE, 1 << 20);
    let (_ignored, measured_path) = store_one(&generous, &measure_root, PAYLOAD, NAMESPACE);
    let exact = fs::metadata(&measured_path)
        .expect("the measuring write must have produced a file")
        .len();

    // The same object against a ceiling one byte too small. The refusal must
    // name `exact` as what was offered: that equality is the whole drill.
    let under_root = temp_root("writepin-under");
    let under = fabric(under_root, NAMESPACE, exact - 1);
    let ledger = ledger();
    let outcome = under.put_if_absent(verified(PAYLOAD, NAMESPACE), admission(&ledger));

    assert!(
        matches!(
            outcome,
            Err(StoreRefusal::StoredObjectTooLarge { offered, maximum })
                if offered == exact && maximum == exact - 1
        ),
        "the write guard must refuse one byte under and must report the same \
         length the stored form occupies, which is what pins the twin above to \
         the quantity this guard compares; got {outcome:?}"
    );

    // A REFUSED WRITE MUST STILL SETTLE. The ledger is fail-fast, so dropping
    // it with the placement grant outstanding panics on the leak rather than
    // failing the assertion above -- which is how this drill first failed. That
    // makes quiescence part of what is under test: a size refusal that returned
    // the grant to nobody would strand the caller's budget, and every later
    // drill sharing this ledger shape would inherit the leak.
    close_quiescent(ledger);
}

// ---------------------------------------------------------------------------
// :466 -- the immutable-body ceiling (e6eb)
// ---------------------------------------------------------------------------

/// A real manifest, derived from a real verified microsegment.
///
/// `ManifestEntry`'s fields are private with getters only, so an integration
/// test cannot build one by struct literal the way the in-crate test module
/// does -- that is `error[E0451]`. The public route is to build a microsegment,
/// verify it, and let `from_verified_segment` derive the entries, which is also
/// the more honest fixture: the manifest describes a segment that actually
/// exists.
fn manifest_over_one_record() -> SegmentManifest {
    let digest = CryptoDigest;
    let limits = SegmentLimits::default();
    let payload = b"e6eb immutable-body record";

    let mut builder = MicrosegmentBuilder::new(&digest, limits.clone());
    builder
        .push(SegmentRecordInput {
            envelope: envelope_for(payload, NAMESPACE),
            payload: payload.to_vec(),
        })
        .expect("one small record must fit the default limits");
    let segment = builder.build().expect("one record must build");

    let reader = MicrosegmentReader::open(segment.as_bytes(), &digest, &limits)
        .expect("a freshly built segment must verify");

    SegmentManifest::from_verified_segment(
        &reader,
        vec![PlacementReceipt::new(
            PlacementBackend::LocalFilesystem,
            OpaqueHandle::new(b"e6eb-locator").expect("fixture locator must fit"),
            OpaqueHandle::new(b"e6eb-domain").expect("fixture failure domain must fit"),
            OpaqueHandle::new(b"e6eb-key").expect("fixture key dependency must fit"),
        )],
        &ManifestLimits {
            max_namespace_bytes: 256,
            max_entries: 65_536,
            max_placements: 65_536,
        },
    )
    .expect("a manifest derived from a verified segment must be canonical")
}

/// THE THIRD CEILING SITE, WHICH NOTHING REACHED.
///
/// `:466` is in `write_immutable_bytes`, entered only from `write_manifest` and
/// `publish_retention_root` -- never from `put_if_absent`. So while `:348` and
/// `:392` are now pinned, a `>` -> `>=` tightening at `:466` was MEASURED to
/// survive the entire binary: 12 passed, 0 failed, in a run verified to have
/// recompiled. This drill is what makes that mutation observable.
///
/// Deliberately a separate test rather than another assertion on the object
/// twin: both existing kills already die to that one function, and hanging a
/// third site off it would make one test the single point of failure for all
/// three.
#[test]
fn a_manifest_body_of_exactly_the_ceiling_is_admitted_and_one_byte_under_is_refused() {
    let manifest = manifest_over_one_record();
    let body_len = u64::try_from(
        manifest
            .encode()
            .expect("the fixture manifest must encode")
            .len(),
    )
    .expect("an encoded manifest length fits u64");

    // Exactly the ceiling: admitted. This is the half a `>=` would break.
    let tight_root = temp_root("manifest-tight");
    let tight = fabric(tight_root, NAMESPACE, body_len);
    tight
        .write_manifest(&manifest)
        .expect("a manifest body of exactly the ceiling must be admitted");

    // One byte under: refused, and naming the encoded length it measured, which
    // is what fixes the guard's quantity to the body rather than to something
    // incidentally larger.
    let under_root = temp_root("manifest-under");
    let under = fabric(under_root, NAMESPACE, body_len - 1);
    let outcome = under.write_manifest(&manifest);

    assert!(
        matches!(
            outcome,
            Err(StoreRefusal::StoredObjectTooLarge { offered, maximum })
                if offered == body_len && maximum == body_len - 1
        ),
        "the immutable-body guard must refuse one byte under and report the \
         encoded manifest length as offered; got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Discrimination: the guards must not be interchangeable
// ---------------------------------------------------------------------------

/// The probes above must reach *different* guards, not all funnel into one.
///
/// Three sites share `MalformedStoredObject`, and two share
/// `StoredObjectTooLarge`. If every corruption produced the same refusal, each
/// probe would still pass while proving nothing about its own site. This drill
/// asserts the refusals are actually distinct across corruption kinds.
#[test]
fn distinct_corruptions_produce_distinct_refusals() {
    let root = temp_root("discriminate");
    let store = fabric(root.clone(), NAMESPACE, 1 << 20);
    let (identity, path) = store_one(&store, &root, b"uw4e discrimination", NAMESPACE);
    let pristine = fs::read(&path).expect("stored file readable");

    // Namespace corruption -> NamespaceMismatch, not MalformedStoredObject.
    let root_other = temp_root("discriminate-other");
    let store_other = fabric(root_other.clone(), OTHER_NAMESPACE, 1 << 20);
    let (_, path_other) = store_one(
        &store_other,
        &root_other,
        b"uw4e discrimination",
        OTHER_NAMESPACE,
    );
    fs::write(&path_other, &pristine).expect("substitution must land");
    let namespace_outcome = store_other.read_whole(identity);

    // Magic corruption -> MalformedStoredObject. `pristine` is moved here; it
    // has already served the namespace substitution above.
    let mut broken_magic = pristine;
    broken_magic[0] ^= 0xFF;
    fs::write(&path, &broken_magic).expect("corruption must land");
    let magic_outcome = store.read_whole(identity);

    assert!(matches!(
        namespace_outcome,
        Err(StoreRefusal::NamespaceMismatch)
    ));
    assert!(matches!(
        magic_outcome,
        Err(StoreRefusal::MalformedStoredObject)
    ));
    assert_ne!(
        format!("{namespace_outcome:?}"),
        format!("{magic_outcome:?}"),
        "two different corruptions produced the same refusal, so neither probe \
         discriminates its own guard"
    );
}
