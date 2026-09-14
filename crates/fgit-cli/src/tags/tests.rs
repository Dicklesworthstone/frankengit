use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_forge::tags::TagAnnotation;
use fgit_types::{DecisionSequence, GitHashAlgorithm, RepositoryCommitId, CANONICAL_CODEC_VERSION};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
fn args(action:&str)->Vec<String>{
    let mut a=vec![action.into(),"unopened".into(),"ab".repeat(16),"ac".repeat(16),"--trusted-local".into()];
    if !matches!(action,"list"|"show"){a.extend(["--principal".into(),"ad".repeat(16),"--key-stdin".into()]);}
    if action!="list"{a.extend(["--ref".into(),"refs/tags/v1".into()]);}a
}
fn create()->Options{let mut a=args("create");a.extend(["--target".into(),"11".repeat(20)]);options::parse(&a).unwrap()}
fn head()->RepositoryAuthorityHeadId{RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(2).unwrap(),CANONICAL_CODEC_VERSION,DigestBytes::try_new(&[6;32]).unwrap())}
#[test]
fn action_specific_flags_and_authentication_cannot_be_weakened(){
    let mut a=args("create");a.extend(["--target".into(),"11".repeat(20)]);assert!(options::parse(&a).is_ok());
    for flag in ["--force","--expected-tip","--tagger","--expected-head","--message-file"]{let mut b=a.clone();b.extend([flag.into(),"bad".into()]);assert!(options::parse(&b).is_err());}
    let mut b=a.clone();b.extend(["--idempotency-key".into(),"second".into()]);assert!(options::parse(&b).is_err());
    let mut b=a.clone();b.extend(["--ref-hex".into(),hex(b"refs/tags/other")]);assert!(options::parse(&b).is_err());
    let mut b=a.clone();*b.last_mut().unwrap()="0".repeat(40);assert!(options::parse(&b).is_err());
    let mut b=a.clone();b.retain(|v|v!="--trusted-local");assert!(options::parse(&b).is_err());
    for action in ["list","show"]{for flag in ["--principal","--key-stdin","--target","--force"]{let mut b=args(action);b.push(flag.into());assert!(options::parse(&b).is_err());}}
}
#[test]
fn annotation_options_preserve_raw_names_native_formats_and_explicit_metadata(){
    let mut a=args("annotate");let n=a.iter().position(|v|v=="--ref").unwrap();a[n]="--ref-hex".into();a[n+1]=hex(b"refs/tags/\xff");
    a.extend(["--object-format".into(),"sha256".into(),"--target".into(),"12".repeat(32),"--target-kind".into(),"blob".into(),"--tagger".into(),"Release <r@example.invalid>".into(),"--timestamp".into(),"0".into(),"--message-file".into(),"empty-message".into()]);
    let parsed=options::parse(&a).unwrap();let Operation::Mutate{command,message_file,..}=parsed.operation else{panic!()};
    assert_eq!(command.reference().as_bytes(),b"refs/tags/\xff");assert_eq!(message_file.unwrap(),Path::new("empty-message"));
    let TagCommand::Annotated{metadata,target,..}=command else{panic!()};assert_eq!(metadata.timestamp,0);assert!(metadata.message.is_empty());assert_eq!(target.algorithm(),GitHashAlgorithm::Sha256);
    for (flag,value) in [("--target","11".repeat(20)),("--target-kind","invalid".into()),("--timestamp","18446744073709551615".into()),("--tagger","injected\nName <r@x>".into())]{
        let mut b=a.clone();let n=b.iter().position(|v|v==flag).unwrap();b[n+1]=value;assert!(options::parse(&b).is_err());
    }
}
#[test]
fn inventory_cursors_remain_tag_scoped_and_snapshot_bound(){
    let mut a=args("list");a.extend(["--after-hex".into(),hex(b"refs/tags/\xff"),"--expected-head".into(),head_token(head())]);
    let parsed=options::parse(&a).unwrap();let Operation::List{after,head:Some(h),..}=parsed.operation else{panic!()};assert_eq!(h,head());assert_eq!(after.unwrap().as_bytes(),b"refs/tags/\xff");
    a.truncate(a.len()-2);assert!(options::parse(&a).is_err());
    let mut a=args("list");a.extend(["--after".into(),"refs/heads/main".into(),"--expected-head".into(),head_token(head())]);assert!(options::parse(&a).is_err());
    for limit in ["0","101","18446744073709551616"]{let mut a=args("list");a.extend(["--limit".into(),limit.into()]);assert!(options::parse(&a).is_err());}
}
#[test]
fn key_and_message_intake_preserve_exact_bytes_and_reject_oversize(){
    assert_eq!(read_key(&Key::Stdin,&mut &b"secret\n"[..]).unwrap(),b"secret\n");assert!(read_key(&Key::Stdin,&mut &b""[..]).is_err());assert!(read_key(&Key::Stdin,&mut &vec![1;257][..]).is_err());
    let dir=std::env::temp_dir().join(format!("fg-tag-cli-input-{}",std::process::id()));fs::create_dir(&dir).unwrap();let path=dir.join("message");
    fs::write(&path,b"").unwrap();assert_eq!(message_bytes(&path).unwrap(),b"");
    fs::write(&path,b"exact\xff\r\nno-final").unwrap();assert_eq!(message_bytes(&path).unwrap(),b"exact\xff\r\nno-final");
    fs::write(&path,vec![b'x';MAX_TAG_MESSAGE_BYTES]).unwrap();assert_eq!(message_bytes(&path).unwrap().len(),MAX_TAG_MESSAGE_BYTES);
    fs::write(&path,vec![b'x';MAX_TAG_MESSAGE_BYTES+1]).unwrap();assert!(message_bytes(&path).is_err());
    fs::write(&path,b"nul\0").unwrap();assert!(message_bytes(&path).is_err());assert!(message_bytes(&dir).is_err());
    #[cfg(unix)]{let link=dir.join("link");std::os::unix::fs::symlink(&path,&link).unwrap();assert!(message_bytes(&link).is_err());}
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn tag_receipts_are_byte_exact_and_never_claim_signature_verification(){
    let options=create();let id=git_object_id(GitHashAlgorithm::Sha1,GitObjectKind::Blob,b"body");let reference=RefName::try_new(b"refs/tags/\xff").unwrap();
    let read=TagRead{head:head(),reference:reference.clone(),tip:id,peeled:id,peeled_kind:GitObjectKind::Blob,
        annotations:vec![TagAnnotation{id,target:id,target_kind:GitObjectKind::Blob,body:b"\xff\r\nno-final".to_vec(),signature:TagSignatureState::OpaqueUnverifiable}]};
    let receipt=show_receipt(&options,&read);assert!(receipt.contains(&hex(b"\xff\r\nno-final")));assert!(receipt.contains("\"signature_verification\":\"not_performed\""));assert!(receipt.contains("opaque_unverifiable"));
    assert!(receipt.contains(&hex(reference.as_bytes())));assert!(receipt.contains("\"repository_changed\":false"));
    let page=list_receipt(&options,head(),&[(reference.clone(),id)],Some(&reference));assert!(page.contains("\"has_more\":true"));assert!(page.contains(&head_token(head())));
}
#[test]
fn known_terminal_result_survives_cleanup_or_receipt_io_failure(){
    let options=create();let digest=DigestBytes::try_new(&[1;32]).unwrap();let algorithm=DigestAlgorithmId::try_new(2).unwrap();
    let tx=TxId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest);
    let terminal=TerminalOutcome{decision_sequence:DecisionSequence::FIRST,outcome:DecisionOutcome::Committed{
        repository_commit_id:RepositoryCommitId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest)}};
    let mut out=Vec::new();assert_eq!(finish_mutation(&mut out,&options,tx,&terminal,None).unwrap(),0);
    let receipt=String::from_utf8(out).unwrap();assert!(receipt.contains("\"command_committed\":true"));assert!(!receipt.contains("secret"));
    let mut out=Vec::new();assert!(finish_mutation(&mut out,&options,tx,&terminal,Some("close failed")).unwrap_err().contains("is committed"));
    assert!(String::from_utf8(out).unwrap().contains("\"node_closed\":false"));
    struct Broken;impl Write for Broken{fn write(&mut self,b:&[u8])->std::io::Result<usize>{Ok(b.len())}fn flush(&mut self)->std::io::Result<()>{Err(std::io::Error::other("flush"))}}
    assert!(finish_mutation(&mut Broken,&options,tx,&terminal,None).unwrap_err().contains("is committed"));assert!(write_read(&mut Broken,"page").unwrap_err().contains("incomplete"));
}
