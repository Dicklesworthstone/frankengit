use super::*;
fn args(extra: &[&str]) -> Vec<String> {
    let mut values=vec!["node".into(),"01".repeat(16),"02".repeat(16),"transfer.bundle".into(),"--trusted-local".into(),"--principal".into(),"03".repeat(16),"--key-stdin".into()];
    values.extend(extra.iter().map(|v|(*v).to_owned()));values
}
#[test]
fn exact_maps_preserve_raw_names_and_resolve_format_independently_of_flag_order() {
    let oid="a1".repeat(32);
    let raw=b"refs/remotes/origin/\xff";
    let options=parse(&args(&["--map","refs/heads/main","refs/heads/local","absent","--map-hex",&hex(b"refs/heads/topic"),&hex(raw),&oid,"--object-format","sha256"])).unwrap();
    assert_eq!(options.format,GitHashAlgorithm::Sha256);
    assert_eq!(options.mappings.len(),2);
    assert_eq!(options.mappings[0].destination.as_bytes(),b"refs/heads/local");
    assert_eq!(options.mappings[0].expected_old,None);
    assert_eq!(options.mappings[1].destination.as_bytes(),raw);
    assert_eq!(options.mappings[1].expected_old.unwrap().to_string(),oid);
    let reversed=parse(&args(&["--object-format","sha256","--map-hex",&hex(b"refs/heads/topic"),&hex(raw),&oid,"--map","refs/heads/main","refs/heads/local","absent"])).unwrap();
    assert_eq!(options.mappings,reversed.mappings);
}
#[test]
fn malformed_ambiguous_or_implicit_updates_refuse_before_node_open() {
    let valid=["--map","refs/heads/main","refs/remotes/origin/main","absent"];
    assert!(parse(&args(&valid)).is_ok());
    assert!(parse(&args(&[])).is_err());
    for bad in [vec!["--map","refs/heads/main","refs/meta/hidden","absent"],vec!["--map","refs/heads/*","refs/heads/a","absent"],vec!["--map","refs/heads/a","refs/heads/b"],vec!["--map-hex","0g","aa","absent"],vec!["--map-hex","6","aa","absent"],vec!["--map","refs/heads/a","refs/heads/b","latest"]] {
        assert!(parse(&args(&bad)).is_err());
    }
    let zero="0".repeat(40);let mixed="1".repeat(64);
    for old in [&zero,&mixed] { assert!(parse(&args(&["--map","refs/heads/a","refs/heads/b",old])).is_err()); }
    let mut duplicate=args(&valid);duplicate.extend(valid.map(String::from));assert!(parse(&duplicate).is_err());
    for flag in ["--force","--prune","--key-stdin","--trusted-local"] {
        let mut options=args(&valid);options.push(flag.into());assert!(parse(&options).is_err());
    }
    let mut untrusted=args(&valid);untrusted.remove(4);assert!(parse(&untrusted).is_err());
    let mut no_principal=args(&valid);no_principal.drain(5..7);assert!(parse(&no_principal).is_err());
    let mut no_key=args(&valid);no_key.remove(7);assert!(parse(&no_key).is_err());
    let mut two_keys=args(&valid);two_keys.extend(["--idempotency-key".into(),"private".into()]);assert!(parse(&two_keys).is_err());
    let mut huge=args(&valid);huge[0]="x".repeat(65537);assert!(parse(&huge).is_err());
}
#[test]
fn fetch_receipts_preserve_terminal_outcomes_and_never_include_key_bytes() {
    use fgit_types::hash::{DigestAlgorithmId,DigestBytes};
    use fgit_types::{CANONICAL_CODEC_VERSION,DecisionSequence,RefusalCode,RefusalRecordId,RepositoryCommitId};
    struct Broken(bool);
    impl Write for Broken {
        fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{if self.0{Err(std::io::Error::other("write failed"))}else{Ok(bytes.len())}}
        fn flush(&mut self)->std::io::Result<()>{Err(std::io::Error::other("flush failed"))}
    }
    let mut inputs=args(&["--map","refs/heads/topic","refs/remotes/origin/topic","absent"]);
    inputs[7]="--idempotency-key".into();inputs.insert(8,"secret-private-exact-key".into());
    let options=parse(&inputs).unwrap();
    let algorithm=DigestAlgorithmId::try_new(2).unwrap();let digest=DigestBytes::try_new(&[0x42;32]).unwrap();
    let tx=TxId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest);
    for refused in [false,true] {
        let outcome=if refused {DecisionOutcome::Refused{code:RefusalCode::ExpectedOldRefMismatch,refusal_record_id:RefusalRecordId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest)}}
            else {DecisionOutcome::Committed{repository_commit_id:RepositoryCommitId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest)}};
        let terminal=TerminalOutcome{decision_sequence:DecisionSequence::try_new(3).unwrap(),outcome};
        let mut bytes=Vec::new();assert_eq!(finish(&mut bytes,&options,tx,&terminal,None).unwrap(),if refused{3}else{0});
        let text=String::from_utf8(bytes).unwrap();
        assert!(text.contains("\"type\":\"git_bundle_fetch\""));assert!(text.contains("\"reference_count\":1"));
        assert!(text.contains(&format!("\"command_committed\":{}",!refused)));assert!(!text.contains("secret-private-exact-key"));
        assert!(text.contains(&hex(b"refs/remotes/origin/topic")));assert!(text.contains("\"expected_old\":null"));
        let mut bytes=Vec::new();assert!(finish(&mut bytes,&options,tx,&terminal,Some("close failed")).unwrap_err().contains(&describe(tx,&terminal)));
        assert!(String::from_utf8(bytes).unwrap().contains("\"node_closed\":false"));
        for mode in [false,true] { let error=finish(&mut Broken(mode),&options,tx,&terminal,Some("close also failed")).unwrap_err();
            assert!(error.contains(&describe(tx,&terminal)));assert!(error.contains("close also failed")); }
    }
}
