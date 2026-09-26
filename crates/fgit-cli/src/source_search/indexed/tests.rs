use super::*;
use fgit_crypto::{IdentityDomain, internal_object_id};
use fgit_types::{CodecVersion, HeadGeneration, SchemaFamily, SchemaId};

fn args() -> Vec<String> {
    vec![
        "not-opened".into(), "11".repeat(16), "22".repeat(16),
        "refs/heads/main".into(), "--trusted-local".into(), "--term".into(), "Needle".into(),
    ]
}
fn activation(number: u64) -> GenerationActivation {
    GenerationActivation {
        generation_id: GenerationId::from_internal_object_id(internal_object_id(
            IdentityDomain::Generation,
            SchemaId::new(SchemaFamily::from_static("graph-generation"), 1, 0),
            CodecVersion::new(1, 0), b"indexed-cli",
        )).unwrap(),
        authority_generation: HeadGeneration::try_new(number).unwrap(),
    }
}
fn head() -> RepositoryAuthorityHeadId {
    RepositoryAuthorityHeadId::from_internal_object_id(internal_object_id(
        IdentityDomain::RepositoryAuthorityHead,
        SchemaId::new(SchemaFamily::from_static("repository-authority-head"), 1, 0),
        CodecVersion::new(1, 0), b"indexed-cli",
    )).unwrap()
}
fn pinned() -> Vec<String> {
    let mut a = args();
    a.extend([
        "--expected-head".into(), head_token(head()),
        "--expected-commit".into(), "a".repeat(40),
        "--generation".into(), generation_token(activation(1).generation_id),
        "--generation-number".into(), "1".into(),
        "--after".into(), "2".into(),
    ]);
    a
}

#[test]
fn complete_terms_channels_formats_and_byte_prefixes_are_explicit() {
    let mut a = args();
    a.extend(["--term", "NEEDLE", "--term", "other", "--channel", "path",
        "--object-format", "sha256", "--path-hex", "646972ff"].map(str::to_owned));
    let options = options::parse(&a).unwrap();
    assert_eq!(options.format, GitHashAlgorithm::Sha256);
    assert_eq!(options.query.channel(), LexicalChannel::Path);
    assert_eq!(options.query.terms(), &[b"needle".to_vec(), b"other".to_vec()]);
    assert_eq!(options.query.prefixes(), &[b"dir\xff".to_vec()]);
    assert_eq!(options.request().query, &options.query);
}

#[test]
fn missing_trust_duplicates_unsupported_modes_and_limits_refuse_before_open() {
    let mut a = args();
    a.remove(4);
    assert!(options::parse(&a).unwrap_err().contains("--trusted-local"));
    for pair in [
        ["--literal", "needle"], ["--regex", ".*"], ["--channel", "symbol"],
        ["--term", "a-b"], ["--path", "../secret"], ["--path-hex", "zz"],
        ["--max-results", "4097"], ["--max-results", "0"], ["--max-work", "16777217"],
        ["--max-index-bytes", "33554433"], ["--object-format", "other"],
        ["--max-results", "01"],
    ] {
        let mut a = args(); a.extend(pair.map(str::to_owned));
        assert!(options::parse(&a).is_err(), "{pair:?}");
    }
    for pair in [["--channel", "content"], ["--max-results", "1"]] {
        let mut a = args();
        a.extend(pair.map(str::to_owned)); a.extend(pair.map(str::to_owned));
        assert!(options::parse(&a).unwrap_err().contains("duplicate"));
    }
    let mut a = args(); a.push("--trusted-local".into());
    assert!(options::parse(&a).unwrap_err().contains("duplicate"));
}

#[test]
fn continuation_requires_every_pin_and_keeps_original_generation() {
    let a = pinned();
    let options = options::parse(&a).unwrap();
    assert_eq!(options.expected_head, Some(head()));
    assert_eq!(options.generation, Some(activation(1)));
    assert_eq!(options.after, Some(2));
    for flag in ["--expected-head", "--expected-commit", "--generation", "--generation-number"] {
        let mut partial = a.clone();
        let at = partial.iter().position(|v| v == flag).unwrap();
        partial.drain(at..at + 2);
        assert!(options::parse(&partial).is_err(), "missing {flag}");
    }
    let mut a = a;
    a.extend(["--minimum-generation".into(), generation_token(activation(3).generation_id),
        "--minimum-number".into(), "3".into()]);
    assert_eq!(options::parse(&a).unwrap().minimum, Some(activation(3)));
}

#[test]
fn document_and_generation_numbers_do_not_round_above_javascript_integer_precision() {
    let mut a = pinned();
    *a.last_mut().unwrap() = "9007199254740993".into();
    assert_eq!(options::parse(&a).unwrap().after, Some(9_007_199_254_740_993));
    assert!(activation_json(&activation(9_007_199_254_740_993))
        .contains("\"number\":\"9007199254740993\""));
    *a.last_mut().unwrap() = u64::MAX.to_string();
    assert_eq!(options::parse(&a).unwrap().after, Some(u64::MAX));
    *a.last_mut().unwrap() = "18446744073709551616".into();
    assert!(options::parse(&a).is_err());
}

#[test]
fn malformed_partial_and_unqualified_identity_tokens_fail_closed() {
    for token in ["abc", "alg:0:aa", "alg:01:aa", "alg:65536:aa", "alg:1:", "alg:1:AA", "alg:1:gg"] {
        let mut a = args();
        a.extend(["--expected-head".into(), token.into()]);
        assert!(options::parse(&a).is_err(), "{token}");
    }
    for flag in ["--generation-number", "--minimum-number"] {
        let mut a = args(); a.extend([flag, "1"].map(str::to_owned));
        assert!(options::parse(&a).is_err());
    }
    let mut a = args();
    a.extend(["--expected-commit".into(), "0".repeat(40)]);
    assert!(options::parse(&a).is_err());
}

#[test]
fn argument_and_query_size_bounds_have_permitted_twins() {
    let mut a = args(); a[6] = "x".repeat(128);
    assert!(options::parse(&a).is_ok());
    a[6].push('x');
    assert!(options::parse(&a).is_err());
    let mut a = args();
    for _ in 1..32 { a.extend(["--term", "word"].map(str::to_owned)); }
    assert!(options::parse(&a).is_ok());
    a.extend(["--term", "word"].map(str::to_owned));
    assert!(options::parse(&a).is_err());
    let mut a = args(); a[0] = "x".repeat(8193);
    assert!(options::parse(&a).is_err());
}

#[test]
fn read_and_cleanup_errors_are_both_retained_and_emit_no_success_payload() {
    let mut output = Vec::new();
    let error = finish(&mut output, Err("read refused".into()), Some("cleanup refused".into()))
        .unwrap_err();
    assert!(error.contains("read refused"));
    assert!(error.contains("cleanup refused"));
    assert!(output.is_empty());
}

#[test]
fn actual_search_dispatch_reaches_new_pre_io_validation_without_changing_literal_mode() {
    let mut a = args(); a.remove(4);
    a.insert(0, "--indexed-current".into());
    assert!(super::super::run(&a).unwrap_err().contains("--trusted-local"));
    // --term is not an alias for literal bytes in the existing default mode.
    assert!(super::super::run(&args()).unwrap_err().contains("unknown source search option --term"));
}
