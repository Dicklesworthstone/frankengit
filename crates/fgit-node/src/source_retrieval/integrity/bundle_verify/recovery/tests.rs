//! Source-format goldens, not filesystem or authority-publication evidence.
use super::*;
use fgit_crypto::{lowercase_hex, sha256_digest};
use fgit_pack::IdxV2;
fn bytes(hex: &str) -> Vec<u8> {
    hex.trim().as_bytes().chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}
fn fixture(format: GitHashAlgorithm) -> (Vec<u8>, &'static str) {
    match format {
        GitHashAlgorithm::Sha1 => (
            bytes(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/native_bundle_recovery/sha1.bundle.hex"))),
            "7e81389280215f9a9139920f12a94d807d55cb83accd723799bc70919b010ec7",
        ),
        GitHashAlgorithm::Sha256 => (
            bytes(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/native_bundle_recovery/sha256.bundle.hex"))),
            "ad9f3bf1c1c2dc4d5483a02bda8dbae512d5e369ba4fc481d4a45d8f5afc2579",
        ),
    }
}
fn head() -> RefName { RefName::try_new(b"refs/heads/main").unwrap() }
fn prepare(input: &[u8]) -> Result<GitBundleRecovery<'_>, BundleRecoveryError> {
    prepare_git_bundle_recovery(input, &BundleVerifyLimits::default(), None, &head(), &mut || true)
}
fn with_refs(input: &[u8], references: &[(&[u8], fgit_types::GitOid)]) -> Vec<u8> {
    let verified = super::super::verify_git_bundle(input, &BundleVerifyLimits::default(), &mut || true).unwrap();
    let mut output = match verified.format() {
        GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
        GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
    };
    for (name, id) in references {
        output.extend_from_slice(lowercase_hex(id.as_bytes()).as_bytes());
        output.push(b' '); output.extend_from_slice(name); output.push(b'\n');
    }
    output.push(b'\n');
    output.extend_from_slice(&input[input.len() - verified.pack_bytes()..]);
    output
}
#[test]
fn produces_git_compatible_index_and_preserves_the_original_pack_in_both_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (input, golden) = fixture(format);
        let plan = prepare(&input).unwrap();
        assert_eq!(lowercase_hex(&sha256_digest(plan.index())), golden);
        assert_eq!(plan.pack(), &input[plan.pack_offset()..]);
        assert_eq!(plan.verified().sha256(), &sha256_digest(&input));
        assert_eq!(plan.verified().graph().objects, 5);
        assert_eq!(plan.verified().delta_objects(), 1);
        assert!(plan.verified().resolution_passes() > 1);
        assert_eq!(plan.head(), b"ref: refs/heads/main\n");
        assert!(plan.config().windows(b"bare = true".len()).any(|p| p == b"bare = true"));
        assert_eq!(plan.config().windows(b"objectformat = sha256".len()).any(|p| p == b"objectformat = sha256"), format == GitHashAlgorithm::Sha256);
        let index = IdxV2::parse(plan.index(), format, &BundleVerifyLimits::default().pack, &mut || true).unwrap();
        assert_eq!(index.entries().len(), 5);
        assert_eq!(*index.pack_checksum(), plan.verified().pack_checksum());
    }
}
#[test]
fn raw_native_reference_bytes_never_become_host_paths() {
    let (input, _) = fixture(GitHashAlgorithm::Sha256);
    let old = prepare(&input).unwrap();
    let id = *old.verified().references().get(&head()).unwrap();
    let raw = b"refs/heads/raw-\xff";
    let input = with_refs(&input, &[(raw, id)]);
    let reference = RefName::try_new(raw).unwrap();
    let plan = prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), None, &reference, &mut || true).unwrap();
    assert_eq!(plan.head(), [b"ref: ".as_slice(), raw, b"\n"].concat());
    assert!(plan.packed_refs().windows(raw.len()).any(|window| window == raw));
}
#[test]
fn head_must_be_an_advertised_branch_and_namespace_overlaps_refuse() {
    let (input, _) = fixture(GitHashAlgorithm::Sha1);
    for raw in [b"refs/tags/v1".as_slice(), b"refs/heads/missing"] {
        assert!(prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), None, &RefName::try_new(raw).unwrap(), &mut || true).is_err());
    }
    let old = prepare(&input).unwrap();
    let id = *old.verified().references().get(&head()).unwrap();
    let overlapping = with_refs(&input, &[(b"refs/heads/main", id), (b"refs/heads/main/child", id)]);
    assert!(matches!(prepare(&overlapping), Err(BundleRecoveryError::OverlappingRefs)));
    let sibling = with_refs(&input, &[(b"refs/heads/main", id), (b"refs/heads/main-other", id)]);
    assert!(prepare(&sibling).is_ok());
}
#[test]
fn matching_identity_never_bypasses_the_full_native_graph_or_pack_checks() {
    let (mut input, _) = fixture(GitHashAlgorithm::Sha1);
    let good = BundleExpectations::new(Some(sha256_digest(&input)), None, &[], false).unwrap();
    assert!(prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), Some(&good), &head(), &mut || true).is_ok());
    let wrong = BundleExpectations::new(Some([0x44; 32]), None, &[], false).unwrap();
    assert!(prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), Some(&wrong), &head(), &mut || true).is_err());
    *input.last_mut().unwrap() ^= 1;
    let corrupt_pin = BundleExpectations::new(Some(sha256_digest(&input)), None, &[], false).unwrap();
    assert!(prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), Some(&corrupt_pin), &head(), &mut || true).is_err());
}
#[test]
fn native_recovery_keeps_all_input_graph_and_index_limits() {
    let (input, _) = fixture(GitHashAlgorithm::Sha256);
    let mut limits = BundleVerifyLimits::default();
    limits.graph.max_objects = 4;
    assert!(prepare_git_bundle_recovery(&input, &limits, None, &head(), &mut || true).is_err());
    limits.graph.max_objects = 5;
    limits.pack.max_index_entries = 4;
    assert!(prepare_git_bundle_recovery(&input, &limits, None, &head(), &mut || true).is_err());
    for end in 0..input.len() { assert!(prepare(&input[..end]).is_err()); }
}
#[test]
fn cancellation_remains_latched_during_verification_and_index_construction() {
    let (input, _) = fixture(GitHashAlgorithm::Sha1);
    let mut count = 0;
    prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), None, &head(), &mut || { count += 1; true }).unwrap();
    for stop in [1, count / 2, count.saturating_sub(100), count] {
        let mut calls = 0;
        assert!(prepare_git_bundle_recovery(&input, &BundleVerifyLimits::default(), None, &head(), &mut || { calls += 1; calls != stop }).is_err());
        assert_eq!(calls, stop);
    }
}
