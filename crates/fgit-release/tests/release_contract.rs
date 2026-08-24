#![forbid(unsafe_code)]
//! FG-035a acceptance: attempt identities, asset contracts, and mirror
//! reconciliation.
//!
//! Every refusal drill here has a **permitted twin**. Without one, a suite that
//! only ever observes `Err` passes unchanged against an implementation that
//! refuses everything — the release equivalent of a green build that never
//! built anything.
//!
//! Two properties are asserted as *denominators* rather than samples, because
//! both are claims about completeness and a sample cannot establish those:
//!
//! - signature coverage compares the signed set against the declared set in
//!   **both** directions, so neither an unsigned asset nor a signature over an
//!   undeclared path can slip through;
//! - the parameter sweep asserts how many cases planned versus refused, so a
//!   sweep that silently stopped exercising one branch fails instead of
//!   passing quietly.

use std::collections::{BTreeMap, BTreeSet};

use fgit_crypto::{KeyEpoch, KeyPurpose, KeyScope, PackageRelease, RootSecret, SecretKey};
use fgit_release::{
    Asset, AttemptInputs, EntryState, HostFingerprint, ReleaseManifest, ReleaseRefusal,
    SignedReleaseManifest, SourceEntry, ToolchainIdentity, TreeSnapshot, attempt_identity, publish,
    reconcile_mirror,
};

const fn digest(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn clean_tree() -> TreeSnapshot {
    TreeSnapshot::new()
        .with(SourceEntry::new("src/lib.rs", digest(1), EntryState::Clean))
        .with(SourceEntry::new("Cargo.toml", digest(2), EntryState::Clean))
}

fn inputs(tree: TreeSnapshot) -> AttemptInputs {
    let mut env = BTreeMap::new();
    env.insert("CARGO_TERM_COLOR".to_owned(), "never".to_owned());
    AttemptInputs {
        tree,
        toolchain: ToolchainIdentity {
            rustc: "rustc 1.94.0-nightly (2026-07-05)".to_owned(),
            cargo: "cargo 1.94.0-nightly (2026-07-05)".to_owned(),
            pinned_channel: "nightly-2026-07-05".to_owned(),
        },
        host: HostFingerprint {
            target: "x86_64-unknown-linux-gnu".to_owned(),
            os: "linux".to_owned(),
            arch: "x86_64".to_owned(),
        },
        command: vec![
            "cargo".to_owned(),
            "build".to_owned(),
            "--release".to_owned(),
        ],
        env,
    }
}

fn manifest_with(signed: BTreeSet<String>) -> ReleaseManifest {
    let attempt = attempt_identity(&inputs(clean_tree())).expect("a clean tree must mint");
    ReleaseManifest::new(
        attempt,
        vec![
            Asset::new("fg-linux-amd64", digest(10)),
            Asset::new("fg-linux-amd64.sha256", digest(11)),
        ],
        signed,
    )
    .expect("two distinct assets must assemble")
}

fn both_signed() -> BTreeSet<String> {
    ["fg-linux-amd64", "fg-linux-amd64.sha256"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn release_key() -> SecretKey<PackageRelease> {
    SecretKey::derive(
        &RootSecret::from_bytes([0xa5; 32]),
        KeyEpoch::FIRST,
        KeyScope::OPERATOR,
    )
}

// ---------------------------------------------------------------------------
// Dirty-tree refusal, and its twin
// ---------------------------------------------------------------------------

#[test]
fn a_dirty_working_tree_refuses_the_release_attempt() {
    let tree = clean_tree().with(SourceEntry::new(
        "src/dirty.rs",
        digest(3),
        EntryState::Dirty,
    ));

    let outcome = attempt_identity(&inputs(tree));
    assert!(
        matches!(
            outcome,
            Err(ReleaseRefusal::DirtyWorkingTree { dirty, ref first })
                if dirty == 1 && first == "src/dirty.rs"
        ),
        "a dirty tree must be refused and must name the path, got {outcome:?}"
    );
}

/// PERMITTED TWIN. Without this, the drill above passes against an
/// implementation that refuses every tree.
#[test]
fn a_clean_tree_mints_an_identity() {
    let identity = attempt_identity(&inputs(clean_tree())).expect("a clean tree must mint");
    assert_eq!(identity.to_hex().len(), 64);
    assert_eq!(identity.tree_digest(), clean_tree().tree_digest());
}

#[test]
fn the_refusal_counts_every_dirty_path_not_just_the_first() {
    let tree = clean_tree()
        .with(SourceEntry::new("a.rs", digest(4), EntryState::Dirty))
        .with(SourceEntry::new("b.rs", digest(5), EntryState::Dirty));

    let outcome = attempt_identity(&inputs(tree));
    let Err(ReleaseRefusal::DirtyWorkingTree { dirty, first }) = outcome else {
        panic!("expected a dirty refusal, got {outcome:?}");
    };
    assert_eq!(dirty, 2, "a count of 1 would understate the problem");
    assert_eq!(first, "a.rs", "the named path must be canonical-first");
}

#[test]
fn an_empty_tree_has_no_identity() {
    let outcome = attempt_identity(&inputs(TreeSnapshot::new()));
    assert!(matches!(outcome, Err(ReleaseRefusal::EmptyTree)));
}

// ---------------------------------------------------------------------------
// Identity determinism
// ---------------------------------------------------------------------------

#[test]
fn the_identity_is_a_pure_function_of_its_declared_inputs() {
    // If anything here ever consulted a clock, the environment, or the
    // filesystem, this is what catches it.
    let first = attempt_identity(&inputs(clean_tree())).expect("must mint");
    for _ in 0..32 {
        let again = attempt_identity(&inputs(clean_tree())).expect("must mint");
        assert_eq!(first, again, "identity is not deterministic");
    }
}

#[test]
fn declaration_order_does_not_change_the_tree_digest() {
    // Canonical ordering, not insertion order — §5.3 forbids publication
    // semantics that depend on map iteration order.
    let forward = TreeSnapshot::new()
        .with(SourceEntry::new("a", digest(1), EntryState::Clean))
        .with(SourceEntry::new("b", digest(2), EntryState::Clean));
    let reverse = TreeSnapshot::new()
        .with(SourceEntry::new("b", digest(2), EntryState::Clean))
        .with(SourceEntry::new("a", digest(1), EntryState::Clean));

    assert_eq!(forward.tree_digest(), reverse.tree_digest());
}

/// PRESENCE CASE for the digest: it must actually distinguish trees.
///
/// Order-independence proves nothing on its own — a digest that ignored its
/// input entirely would satisfy it. This asserts the digest is sensitive to
/// content before the invariance above is credited.
#[test]
fn the_tree_digest_changes_when_content_changes() {
    let base = TreeSnapshot::new().with(SourceEntry::new("a", digest(1), EntryState::Clean));
    let altered = TreeSnapshot::new().with(SourceEntry::new("a", digest(9), EntryState::Clean));

    assert_ne!(
        base.tree_digest(),
        altered.tree_digest(),
        "a digest blind to content would make every invariance drill vacuous"
    );
}

#[test]
fn a_different_toolchain_yields_a_different_attempt() {
    let base = attempt_identity(&inputs(clean_tree())).expect("must mint");
    let mut other = inputs(clean_tree());
    other.toolchain.pinned_channel = "nightly-2026-08-19".to_owned();
    let shifted = attempt_identity(&other).expect("must mint");

    assert_ne!(
        base.digest(),
        shifted.digest(),
        "the pinned channel is part of what a release is a function of"
    );
    assert_eq!(
        base.tree_digest(),
        shifted.tree_digest(),
        "the tree did not change, so its digest must not"
    );
}

// ---------------------------------------------------------------------------
// Asset contract: coverage as a denominator, both directions
// ---------------------------------------------------------------------------

#[test]
fn a_signature_covering_every_declared_asset_validates() {
    manifest_with(both_signed())
        .validate()
        .expect("full coverage must validate");
}

#[test]
fn a_signed_manifest_requires_the_existing_release_key_and_refuses_tampering() {
    let key = release_key();
    let manifest = manifest_with(both_signed());
    let signed = manifest
        .clone()
        .sign(&key)
        .expect("the complete asset denominator is signable");

    assert_eq!(signed.signature().purpose(), KeyPurpose::PackageRelease);
    signed
        .verify(&key.verifying_key())
        .expect("the typed package/release key signs the canonical body");
    SignedReleaseManifest::from_canonical_bytes(&signed.canonical_bytes())
        .expect("the signed root uses a bounded canonical representation")
        .verify(&key.verifying_key())
        .expect("a parsed root must remain independently verifiable");
    let mut tampered_root = signed.canonical_bytes();
    *tampered_root
        .last_mut()
        .expect("a detached signature has a nonempty canonical encoding") ^= 0x01;
    let parsed_tampered_root = SignedReleaseManifest::from_canonical_bytes(&tampered_root)
        .expect("altering a signature byte preserves structural framing");
    assert!(matches!(
        parsed_tampered_root.verify(&key.verifying_key()),
        Err(ReleaseRefusal::ReleaseSignatureInvalid)
    ));

    let tampered_manifest = ReleaseManifest::new(
        manifest.attempt().clone(),
        vec![
            Asset::new("fg-linux-amd64", digest(99)),
            Asset::new("fg-linux-amd64.sha256", digest(11)),
        ],
        both_signed(),
    )
    .expect("the altered body remains structurally valid so signature verification is exercised");
    let tampered = SignedReleaseManifest::from_parts(tampered_manifest, signed.signature());
    assert!(matches!(
        tampered.verify(&key.verifying_key()),
        Err(ReleaseRefusal::ReleaseSignatureInvalid)
    ));
}

#[test]
fn a_signature_missing_one_asset_is_refused_with_both_counts() {
    let partial: BTreeSet<String> = std::iter::once("fg-linux-amd64")
        .map(str::to_owned)
        .collect();
    let outcome = manifest_with(partial).validate();

    assert!(
        matches!(
            outcome,
            Err(ReleaseRefusal::SignatureCoverageIncomplete { signed, declared, ref first_unsigned })
                if signed == 1 && declared == 2 && first_unsigned == "fg-linux-amd64.sha256"
        ),
        "the refusal must carry both counts and name the gap, got {outcome:?}"
    );
}

#[test]
fn a_signature_over_an_undeclared_path_is_refused() {
    // The more dangerous direction: something was signed that the asset
    // contract does not account for. A coverage check that only counted would
    // report 3 >= 2 and pass.
    let mut over = both_signed();
    over.insert("fg-linux-amd64.smuggled".to_owned());

    let outcome = manifest_with(over).validate();
    assert!(
        matches!(
            outcome,
            Err(ReleaseRefusal::SignatureCoversUndeclared { ref path })
                if path == "fg-linux-amd64.smuggled"
        ),
        "signing an undeclared path must be refused, got {outcome:?}"
    );
}

#[test]
fn a_duplicate_asset_is_refused_rather_than_deduplicated() {
    let attempt = attempt_identity(&inputs(clean_tree())).expect("must mint");
    let outcome = ReleaseManifest::new(
        attempt,
        vec![
            Asset::new("fg-linux-amd64", digest(10)),
            Asset::new("fg-linux-amd64", digest(99)),
        ],
        both_signed(),
    );
    assert!(
        matches!(outcome, Err(ReleaseRefusal::DuplicateAsset { ref path }) if path == "fg-linux-amd64"),
        "silently collapsing a duplicate would change what the complete set means"
    );
}

#[test]
fn an_empty_asset_set_is_not_a_release() {
    let attempt = attempt_identity(&inputs(clean_tree())).expect("must mint");
    assert!(matches!(
        ReleaseManifest::new(attempt, Vec::new(), BTreeSet::new()),
        Err(ReleaseRefusal::EmptyAssetSet)
    ));
}

// ---------------------------------------------------------------------------
// Mirror reconciliation
// ---------------------------------------------------------------------------

fn honest_mirror() -> BTreeMap<String, [u8; 32]> {
    let mut mirror = BTreeMap::new();
    mirror.insert("fg-linux-amd64".to_owned(), digest(10));
    mirror.insert("fg-linux-amd64.sha256".to_owned(), digest(11));
    mirror
}

/// PERMITTED TWIN for the three tampering drills below.
#[test]
fn an_untampered_mirror_reconciles() {
    reconcile_mirror(&manifest_with(both_signed()), &honest_mirror())
        .expect("an honest mirror must reconcile");
}

#[test]
fn a_mirror_serving_altered_bytes_is_detected() {
    let mut tampered = honest_mirror();
    tampered.insert("fg-linux-amd64".to_owned(), digest(0xEE));

    let outcome = reconcile_mirror(&manifest_with(both_signed()), &tampered);
    assert!(
        matches!(
            outcome,
            Err(ReleaseRefusal::MirrorDigestMismatch { ref path, .. }) if path == "fg-linux-amd64"
        ),
        "altered bytes must be detected and named, got {outcome:?}"
    );
}

#[test]
fn a_mirror_missing_a_declared_asset_is_detected() {
    let mut short = honest_mirror();
    short.remove("fg-linux-amd64.sha256");

    let outcome = reconcile_mirror(&manifest_with(both_signed()), &short);
    assert!(matches!(
        outcome,
        Err(ReleaseRefusal::MirrorMissingAsset { ref path }) if path == "fg-linux-amd64.sha256"
    ));
}

#[test]
fn a_mirror_serving_an_undeclared_asset_is_detected() {
    // Extra bytes are tampering too: a mirror that adds a file the manifest
    // never named is serving something nobody signed.
    let mut extra = honest_mirror();
    extra.insert("fg-linux-amd64.backdoor".to_owned(), digest(0xAB));

    let outcome = reconcile_mirror(&manifest_with(both_signed()), &extra);
    assert!(matches!(
        outcome,
        Err(ReleaseRefusal::MirrorUndeclaredAsset { ref path }) if path == "fg-linux-amd64.backdoor"
    ));
}

#[test]
fn reconciliation_validates_the_manifest_before_blaming_the_mirror() {
    // An incoherent manifest must not be reported as a mirror problem — that
    // would send an operator to the wrong system.
    let partial: BTreeSet<String> = std::iter::once("fg-linux-amd64")
        .map(str::to_owned)
        .collect();
    let outcome = reconcile_mirror(&manifest_with(partial), &honest_mirror());

    assert!(
        matches!(
            outcome,
            Err(ReleaseRefusal::SignatureCoverageIncomplete { .. })
        ),
        "a broken contract must be reported as a contract failure, got {outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// The publication boundary
// ---------------------------------------------------------------------------

#[test]
fn publication_refuses_and_names_the_missing_gate() {
    let outcome = publish(&manifest_with(both_signed()));
    assert!(
        matches!(
            outcome,
            Err(ReleaseRefusal::PublicationUnsupported { missing_gate })
                if missing_gate.contains("run_all.sh")
        ),
        "publication must refuse and name what is missing, got {outcome:?}"
    );
}

#[test]
fn publication_reports_a_broken_contract_before_the_unsupported_boundary() {
    // Ordering matters: a caller with a broken asset contract should learn that
    // now, not on the day publication becomes available.
    let partial: BTreeSet<String> = std::iter::once("fg-linux-amd64")
        .map(str::to_owned)
        .collect();
    assert!(matches!(
        publish(&manifest_with(partial)),
        Err(ReleaseRefusal::SignatureCoverageIncomplete { .. })
    ));
}

// ---------------------------------------------------------------------------
// Sweep with an asserted denominator
// ---------------------------------------------------------------------------

#[test]
fn the_dirty_refusal_holds_across_the_tree_shapes_swept() {
    let mut minted = 0_u32;
    let mut refused = 0_u32;

    for clean_count in 1..=4_usize {
        for dirty_count in 0..=3_usize {
            let mut tree = TreeSnapshot::new();
            for index in 0..clean_count {
                tree = tree.with(SourceEntry::new(
                    format!("clean/{index}"),
                    digest(u8::try_from(index).unwrap_or(0)),
                    EntryState::Clean,
                ));
            }
            for index in 0..dirty_count {
                tree = tree.with(SourceEntry::new(
                    format!("dirty/{index}"),
                    digest(u8::try_from(index).unwrap_or(0)),
                    EntryState::Dirty,
                ));
            }

            match attempt_identity(&inputs(tree)) {
                Ok(_) => {
                    assert_eq!(dirty_count, 0, "a tree with dirty entries must not mint");
                    minted += 1;
                }
                Err(ReleaseRefusal::DirtyWorkingTree { dirty, .. }) => {
                    assert_eq!(dirty, dirty_count, "the count must match what was declared");
                    refused += 1;
                }
                Err(other) => panic!("unexpected refusal {other:?}"),
            }
        }
    }

    // Denominators asserted, so a sweep that stopped covering either branch
    // fails instead of passing quietly.
    assert_eq!(
        minted + refused,
        16,
        "the sweep did not cover its own space"
    );
    assert_eq!(minted, 4, "one clean case per clean_count");
    assert_eq!(refused, 12, "three dirty cases per clean_count");
}
