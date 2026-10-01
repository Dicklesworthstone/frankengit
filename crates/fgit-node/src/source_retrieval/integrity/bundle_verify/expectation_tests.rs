//! Expectations are exercised against real native verification, never a mock.
use super::*;
include!("expectation_fixtures.rs");

fn bytes(encoded: &str) -> Vec<u8> {
    encoded.as_bytes().chunks_exact(2).map(|pair| {
        u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
    }).collect()
}
fn input(format: GitHashAlgorithm) -> Vec<u8> {
    bytes(match format {
        GitHashAlgorithm::Sha1 => SHA1_MIXED,
        GitHashAlgorithm::Sha256 => SHA256_MIXED,
    })
}
fn reference(name: &[u8]) -> RefName {
    RefName::try_new(name).unwrap()
}
fn pins(format: GitHashAlgorithm) -> Vec<(RefName, GitOid)> {
    let (tip, tag) = match format {
        GitHashAlgorithm::Sha1 => (
            "169c83412c53e9c442925c858c152e4e6e4ccab7",
            "d41d0e19dbf400550087de77204882a839a94538",
        ),
        GitHashAlgorithm::Sha256 => (
            "3873e80a26b3babd9c8c59f893eec320625602ff09c1882277226420078b4295",
            "0d32f470555ee181eda9a7dfe0412716853a764a082d7a652924bfb651251ea5",
        ),
    };
    let tip = GitOid::from_hex(format, tip).unwrap();
    vec![
        (reference(b"refs/heads/main"), tip),
        (reference(b"refs/tags/release"), GitOid::from_hex(format, tag).unwrap()),
        (reference(b"refs/heads/\xff"), tip),
    ]
}
fn verify<'a>(input: &[u8], expected: &'a BundleExpectations) -> Result<MatchedGitBundle<'a>, BundleVerifyError> {
    verify_git_bundle_against(input, &BundleVerifyLimits::default(), expected, &mut || true)
}

#[test]
fn both_hash_domains_bind_complete_native_graphs_and_exact_raw_ref_sets() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let input = input(format);
        let expected = BundleExpectations::new(Some(sha256_digest(&input)), Some(format), &pins(format), true).unwrap();
        let result = verify(&input, &expected).unwrap();
        let plain = verify_git_bundle(&input, &BundleVerifyLimits::default(), &mut || true).unwrap();
        assert_eq!(result.verified().sha256(), plain.sha256());
        assert_eq!(result.verified().graph(), plain.graph());
        assert_eq!(result.verified().references(), expected.references());
        assert_eq!(result.verified().delta_objects(), 2);
        assert_eq!(result.expectations(), &expected);
        assert!(result.expectations().exact_references());
    }
}
#[test]
fn a_complete_backup_is_not_a_match_for_another_artifact_or_tip() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let data = input(format);
        assert!(verify_git_bundle(&data, &BundleVerifyLimits::default(), &mut || true).is_ok());
        let wrong_hash = BundleExpectations::new(Some([0x42; 32]), None, &[], false).unwrap();
        assert!(matches!(verify(&data, &wrong_hash), Err(BundleVerifyError::Expectation(BundleExpectationError::ArtifactMismatch))));
        let mut refs = pins(format);
        refs[0].1 = git_object_id(format, ObjectKind::Commit, b"another backup");
        let wrong_tip = BundleExpectations::new(None, Some(format), &refs, false).unwrap();
        assert!(matches!(verify(&data, &wrong_tip), Err(BundleVerifyError::Expectation(BundleExpectationError::ChangedReference { .. }))));
    }
}
#[test]
fn hash_only_checks_do_not_guess_the_native_hash_domain() {
    let data = input(GitHashAlgorithm::Sha256);
    let expected = BundleExpectations::new(Some(sha256_digest(&data)), None, &[], false).unwrap();
    assert!(verify(&data, &expected).unwrap().expectations().format().is_none());
}
#[test]
fn subset_and_exact_sets_have_distinct_semantics_and_missing_pins_refuse() {
    let format = GitHashAlgorithm::Sha1;
    let data = input(format);
    let mut refs = pins(format);
    refs.truncate(1);
    let subset = BundleExpectations::new(None, Some(format), &refs, false).unwrap();
    assert_eq!(verify(&data, &subset).unwrap().verified().graph().references, 3);
    let exact = BundleExpectations::new(None, Some(format), &refs, true).unwrap();
    assert!(matches!(verify(&data, &exact), Err(BundleVerifyError::Expectation(BundleExpectationError::ReferenceSetMismatch { expected: 1, actual: 3 }))));
    refs[0].0 = reference(b"refs/heads/absent");
    let missing = BundleExpectations::new(None, Some(format), &refs, false).unwrap();
    assert!(matches!(verify(&data, &missing), Err(BundleVerifyError::Expectation(BundleExpectationError::MissingReference(_)))));
}
#[test]
fn ref_pins_tolerate_transport_changes_but_artifact_pins_bind_the_entire_file() {
    let format = GitHashAlgorithm::Sha1;
    let original = input(format);
    // Reorder header records only. Pack/object bytes and native refs are unchanged.
    let split = original.windows(2).position(|p| p == b"\n\n").unwrap();
    let mut lines: Vec<_> = original[..split].split(|b| *b == b'\n').collect();
    lines[1..].reverse();
    let mut changed = Vec::new();
    for line in lines { changed.extend_from_slice(line); changed.push(b'\n'); }
    changed.push(b'\n'); changed.extend_from_slice(&original[split + 2..]);
    assert_ne!(sha256_digest(&original), sha256_digest(&changed));
    let refs = BundleExpectations::new(None, Some(format), &pins(format), true).unwrap();
    assert!(verify(&changed, &refs).is_ok());
    let exact = BundleExpectations::new(Some(sha256_digest(&original)), Some(format), &pins(format), true).unwrap();
    assert!(matches!(verify(&changed, &exact), Err(BundleVerifyError::Expectation(BundleExpectationError::ArtifactMismatch))));
}
#[test]
fn wrong_expectations_refuse_before_invalid_pack_checks() {
    let format = GitHashAlgorithm::Sha1;
    let mut data = input(format);
    *data.last_mut().unwrap() ^= 1;
    let wrong_hash = BundleExpectations::new(Some([0x42; 32]), None, &[], false).unwrap();
    assert!(matches!(verify(&data, &wrong_hash), Err(BundleVerifyError::Expectation(BundleExpectationError::ArtifactMismatch))));
    let wrong_format = BundleExpectations::new(Some(sha256_digest(&data)), Some(GitHashAlgorithm::Sha256), &[], false).unwrap();
    assert!(matches!(verify(&data, &wrong_format), Err(BundleVerifyError::Expectation(BundleExpectationError::FormatMismatch { .. }))));
    // A genuine hash of corrupt bytes cannot substitute for a valid native pack.
    let matching = BundleExpectations::new(Some(sha256_digest(&data)), Some(format), &pins(format), true).unwrap();
    assert!(matches!(verify(&data, &matching), Err(BundleVerifyError::Pack(_))));
}
#[test]
fn matching_pins_do_not_bypass_object_count_or_graph_limits() {
    let format = GitHashAlgorithm::Sha256;
    let data = input(format);
    let expected = BundleExpectations::new(Some(sha256_digest(&data)), Some(format), &pins(format), true).unwrap();
    let mut limits = BundleVerifyLimits::default();
    limits.graph.max_objects = 1;
    assert!(matches!(verify_git_bundle_against(&data, &limits, &expected, &mut || true), Err(BundleVerifyError::Pack(_))));
    let mut limits = BundleVerifyLimits::default();
    limits.graph.max_edges = 0;
    assert!(matches!(verify_git_bundle_against(&data, &limits, &expected, &mut || true), Err(BundleVerifyError::Graph(_))));
}
#[test]
fn malformed_expectations_are_not_constructible() {
    let format = GitHashAlgorithm::Sha1;
    let refs = pins(format);
    assert_eq!(BundleExpectations::new(None, None, &[], false).unwrap_err(), BundleExpectationError::MissingAnchor);
    assert_eq!(BundleExpectations::new(None, Some(format), &[], false).unwrap_err(), BundleExpectationError::MissingAnchor);
    assert_eq!(BundleExpectations::new(Some([0; 32]), None, &[], true).unwrap_err(), BundleExpectationError::ExactWithoutReferences);
    assert_eq!(BundleExpectations::new(None, None, &refs, false).unwrap_err(), BundleExpectationError::MissingFormat);
    assert_eq!(BundleExpectations::new(None, Some(GitHashAlgorithm::Sha256), &refs, false).unwrap_err(), BundleExpectationError::ReferenceFormat);
    let mut duplicate = refs.clone(); duplicate.push(refs[0].clone());
    assert!(matches!(BundleExpectations::new(None, Some(format), &duplicate, false), Err(BundleExpectationError::DuplicateReference(_))));
    let zero = GitOid::from_hex(format, &"0".repeat(40)).unwrap();
    assert_eq!(BundleExpectations::new(None, Some(format), &[(refs[0].0.clone(), zero)], false).unwrap_err(), BundleExpectationError::ZeroReferenceTarget);
}
#[test]
fn expectations_cannot_spend_larger_count_or_header_limits_than_the_verifier() {
    let format = GitHashAlgorithm::Sha1;
    let refs = pins(format);
    let expected = BundleExpectations::new(None, Some(format), &refs, true).unwrap();
    let mut limits = BundleVerifyLimits::default();
    limits.envelope.max_references = refs.len();
    limits.graph.max_references = refs.len();
    limits.envelope.max_header_bytes = refs.iter().map(|(name, _)| name.as_bytes().len()).sum();
    assert!(expected.validate_limits(&limits).is_ok());
    limits.envelope.max_header_bytes -= 1;
    assert!(matches!(expected.validate_limits(&limits), Err(BundleExpectationError::Limit("reference bytes"))));
    limits.envelope.max_header_bytes += 1;
    limits.graph.max_references -= 1;
    // These limits refuse before even an invalid input envelope is parsed.
    assert!(matches!(verify_git_bundle_against(b"not a bundle", &limits, &expected, &mut || true), Err(BundleVerifyError::Expectation(BundleExpectationError::Limit("references")))));
    let too_many = vec![refs[0].clone(); MAX_EXPECTED_REFS + 1];
    assert!(matches!(BundleExpectations::new(None, Some(format), &too_many, false), Err(BundleExpectationError::Limit("references"))));
}
#[test]
fn every_anchored_checkpoint_can_refuse_without_returning_a_partial_match() {
    let format = GitHashAlgorithm::Sha1;
    // A tiny independent one-blob fixture keeps the every-checkpoint sweep
    // bounded while exercising the real decoder, hasher and graph checker.
    let data = bytes("23207632206769742062756e646c650a6365303133363235303330626138646261393036663735363936376639653963613339343436346120726566732f746167732f626c6f620a0a5041434b000000020000000136789ccb48cdc9c9e70200084b021fde0412401f4a9e5f05411f44eaf9c86d46096746");
    let ref_id = GitOid::from_hex(format, "ce013625030ba8dba906f756967f9e9ca394464a").unwrap();
    let refs = vec![(reference(b"refs/tags/blob"), ref_id)];
    let expected = BundleExpectations::new(Some(sha256_digest(&data)), Some(format), &refs, true).unwrap();
    let limits = BundleVerifyLimits::default();
    let mut polls = 0;
    verify_git_bundle_against(&data, &limits, &expected, &mut || { polls += 1; true }).unwrap();
    for stop in 1..=polls {
        let mut seen = 0;
        let result = verify_git_bundle_against(&data, &limits, &expected, &mut || { seen += 1; seen != stop });
        assert!(matches!(result, Err(BundleVerifyError::Stopped)), "checkpoint {stop}");
        assert_eq!(seen, stop, "stopped invocation must never re-poll permissively");
    }
    assert!(verify(&data, &expected).is_ok());
}
#[test]
fn non_utf8_names_remain_byte_exact_and_diagnostics_are_terminal_safe() {
    let format = GitHashAlgorithm::Sha1;
    let data = input(format);
    let refs = pins(format);
    let raw = BundleExpectations::new(None, Some(format), &refs[2..], false).unwrap();
    assert!(verify(&data, &raw).is_ok());
    let replacement = vec![(reference("refs/heads/\u{fffd}".as_bytes()), refs[2].1)];
    let wrong = BundleExpectations::new(None, Some(format), &replacement, false).unwrap();
    let error = verify(&data, &wrong).unwrap_err().to_string();
    assert!(error.contains("ref_hex=726566732f68656164732fefbfbd"));
    assert!(error.is_ascii());
}

#[test]
fn a_genuine_artifact_pin_cannot_hide_checksum_valid_missing_history() {
    for encoded in [SHA1_MISSING_BLOB, SHA256_MISSING_BLOB] {
        let data = bytes(encoded);
        let expected = BundleExpectations::new(Some(sha256_digest(&data)), None, &[], false).unwrap();
        assert!(matches!(verify(&data, &expected), Err(BundleVerifyError::Graph(GraphRefusal::MissingTarget { .. }))));
    }
}
