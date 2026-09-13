use super::*;

fn prepare_args(width: usize) -> Vec<String> {
    ["prepare", "node", &"11".repeat(16), &"22".repeat(16), "refs/heads/main", "input.patch", "new.bundle",
        "--trusted-local", "--profile", "exact-v1", "--workspace-id", &"44".repeat(16),
        "--expected-base", &"a".repeat(width), "--author", "Author <a@example.invalid>",
        "--timestamp", "2", "--message", "patch\n"].into_iter().map(str::to_owned).collect()
}
fn apply_args(width: usize) -> Vec<String> {
    ["apply", "node", &"11".repeat(16), &"22".repeat(16), "refs/heads/main", "reviewed.bundle",
        "--trusted-local", "--principal", &"33".repeat(16), "--idempotency-key", "private-retry-key",
        "--expected-base", &"a".repeat(width), "--expected-commit", &"b".repeat(width)]
        .into_iter().map(str::to_owned).collect()
}
fn replace(args: &mut [String], flag: &str, value: &str) {
    let at = args.iter().position(|arg| arg == flag).unwrap(); args[at+1] = value.into();
}
#[test]
fn complete_explicit_commands_support_both_domains_and_byte_exact_keys() {
    for width in [40,64] {
        let prepared = options::parse(&prepare_args(width)).unwrap();
        assert_eq!(prepared.base.to_string(), "a".repeat(width));
        let Operation::Prepare { workspace_id, metadata, .. } = prepared.operation else { panic!("wrong operation"); };
        assert_eq!(workspace_id, [0x44;16]); assert_eq!(metadata.author, metadata.committer);
        let parsed = options::parse(&apply_args(width)).unwrap();
        let Operation::Apply { key: options::Key::Bytes(key), candidate, .. } = parsed.operation else { panic!("wrong operation"); };
        assert_eq!(key,b"private-retry-key"); assert_eq!(candidate.to_string(),"b".repeat(width));
    }
    assert_eq!(read_key(&mut &b"key\n"[..]).unwrap(),b"key\n");
    assert_eq!(read_key(&mut &vec![b'k';256][..]).unwrap().len(),256);
    assert!(read_key(&mut &vec![b'k';257][..]).is_err()); assert!(read_key(&mut &b""[..]).is_err());
}
#[test]
fn missing_duplicate_and_cross_operation_fields_refuse_before_io() {
    for args in [prepare_args(40), apply_args(40)] {
        let mut no_trust=args.clone(); no_trust.retain(|s|s!="--trusted-local"); assert!(options::parse(&no_trust).is_err());
        for (at, flag) in args.iter().enumerate().filter(|(_,s)|s.starts_with("--") && *s!="--trusted-local") {
            let mut missing=args.clone(); missing.drain(at..at+2); assert!(options::parse(&missing).is_err(),"{flag}");
            let mut duplicate=args.clone(); duplicate.extend([flag.clone(),args[at+1].clone()]); assert!(options::parse(&duplicate).is_err());
        }
        let mut force=args.clone(); force.extend(["--force".into(),"true".into()]); assert!(options::parse(&force).is_err());
    }
    let mut args=prepare_args(40); args.extend(["--principal".into(),"33".repeat(16)]); assert!(options::parse(&args).is_err());
    let mut args=apply_args(40); args.extend(["--profile".into(),"exact-v1".into()]); assert!(options::parse(&args).is_err());
    let mut args=apply_args(40); args.push("--key-stdin".into()); assert!(options::parse(&args).is_err());
    let at=args.iter().position(|s|s=="--idempotency-key").unwrap();args.drain(at..at+2);
    assert!(matches!(options::parse(&args).unwrap().operation,Operation::Apply {key:options::Key::Stdin,..}));
}
#[test]
fn malformed_identity_profile_metadata_and_resource_envelopes_refuse() {
    for (flag,bad) in [("--profile","fuzzy"),("--workspace-id","00"),("--timestamp","0"),
        ("--timestamp","01"),("--timestamp","-1"),("--timestamp","18446744073709551616"),
        ("--author","Agent <a@example.invalid>\nparent injected"),("--message","")] {
        let mut args=prepare_args(40);replace(&mut args,flag,bad);assert!(options::parse(&args).is_err(),"{flag}");
    }
    for (flag,bad) in [("--max-files","0"),("--max-files","1025"),("--max-hunks","4097"),
        ("--max-input-bytes","16777217"),("--max-output-bytes","33554433")] {
        let mut args=prepare_args(40);args.extend([flag.into(),bad.into()]);assert!(options::parse(&args).is_err());
    }
    for bad in ["0".repeat(40),"a".repeat(40),"b".repeat(64),"G".repeat(40)] {
        let mut args=apply_args(40);replace(&mut args,"--expected-commit",&bad);assert!(options::parse(&args).is_err());
    }
    let mut args=prepare_args(40);args[4]="refs/tags/main".into();assert!(options::parse(&args).is_err());
    let mut args=prepare_args(40);args[4]=hex(b"refs/heads/caf\xc3\xa9");args.push("--ref-hex".into());
    assert_eq!(options::parse(&args).unwrap().reference.as_bytes(),b"refs/heads/caf\xc3\xa9");
    args[4]="0g".into();assert!(options::parse(&args).is_err());
}
#[test]
fn terminal_decisions_survive_broken_output_and_cleanup_without_key_disclosure() {
    use fgit_types::{CANONICAL_CODEC_VERSION, DecisionSequence, RefusalCode, RefusalRecordId,
        RepositoryCommitId, hash::{DigestAlgorithmId,DigestBytes}};
    let algorithm=DigestAlgorithmId::try_new(2).unwrap();let digest=DigestBytes::try_new(&[0x42;32]).unwrap();
    let tx=TxId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest);
    let rcr=RepositoryCommitId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest);
    let committed=TerminalOutcome {decision_sequence:DecisionSequence::try_new(2).unwrap(),
        outcome:DecisionOutcome::Committed {repository_commit_id:rcr}};
    let options=options::parse(&apply_args(40)).unwrap();let mut bytes=Vec::new();
    assert_eq!(finish_applied(&mut bytes,&options,tx,&committed,None).unwrap(),0);
    let text=String::from_utf8(bytes).unwrap();assert!(text.contains("\"published_to_repository\":true"));
    assert!(!text.contains("private-retry-key"));assert!(text.contains(&rcr.to_string()));
    let mut bytes=Vec::new();assert!(finish_applied(&mut bytes,&options,tx,&committed,Some("close failed")).is_err());
    let text=String::from_utf8(bytes).unwrap();assert!(text.contains("\"node_closed\":false"));assert!(text.contains("\"outcome\":\"committed\""));
    struct Broken(bool);
    impl Write for Broken {
        fn write(&mut self, bytes:&[u8])->std::io::Result<usize> {
            if self.0 {Ok(bytes.len())} else {Err(std::io::ErrorKind::BrokenPipe.into())}
        }
        fn flush(&mut self)->std::io::Result<()> {Err(std::io::ErrorKind::BrokenPipe.into())}
    }
    for flush in [false,true] {let error=finish_applied(&mut Broken(flush),&options,tx,&committed,Some("close failed")).unwrap_err();
        assert!(error.contains("is committed as"));assert!(error.contains("close failed"));}
    let refused=TerminalOutcome {decision_sequence:DecisionSequence::try_new(3).unwrap(),
        outcome:DecisionOutcome::Refused {code:RefusalCode::ExpectedOldRefMismatch,
            refusal_record_id:RefusalRecordId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest)}};
    let mut bytes=Vec::new();assert_eq!(finish_applied(&mut bytes,&options,tx,&refused,None).unwrap(),3);
    let text=String::from_utf8(bytes).unwrap();assert!(text.contains("\"published_to_repository\":false"));
    assert!(text.contains("ExpectedOldRefMismatch"));
}
