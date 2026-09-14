use super::*;
use fgit_forge::source_browse::{SourceBrowseAction as Action, SourceBrowseContent as Content,
    SourceDirectoryEntry, SourceEntryKind as Kind};
use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm, GitOid, RepositoryCommitId};
use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
fn args() -> Vec<String> { vec!["not-opened".into(),"01".repeat(16),"02".repeat(16),
    "--trusted-local".into(),"--ref".into(),"refs/heads/main".into()] }
fn head() -> RepositoryAuthorityHeadId { RepositoryAuthorityHeadId::from_digest(
    DigestAlgorithmId::try_new(2).unwrap(),CANONICAL_CODEC_VERSION,DigestBytes::try_new(&[9;32]).unwrap()) }
fn report(content: Content) -> SourceBrowseReport {
    let options=options::parse(&args(),false).unwrap();
    let id=GitOid::from_hex(GitHashAlgorithm::Sha1,&"12".repeat(20)).unwrap();
    SourceBrowseReport {repository_id:options.repository,source_head:head(),
        source_rcr:RepositoryCommitId::from_digest(DigestAlgorithmId::try_new(2).unwrap(),
            CANONICAL_CODEC_VERSION,DigestBytes::try_new(&[8;32]).unwrap()),source_commit:id,
        root_tree:id,object_id:id,path:Some(b"file\xff".to_vec()),content}
}
#[test]
fn byte_exact_paths_refs_and_snapshot_tokens_round_trip() {
    let mut raw=args();raw.truncate(4);raw.extend(["--ref-hex".into(),hex(b"refs/heads/\xff"),
        "--path-hex".into(),hex(b"dir/\xff"),"--expected-head".into(),head_token(head()),
        "--after-hex".into(),hex(b"\xfe"),"--limit".into(),"2".into()]);
    let options=options::parse(&raw,false).unwrap();
    assert_eq!(options.reference.as_bytes(),b"refs/heads/\xff");
    assert_eq!(options.query.path.as_deref(),Some(&b"dir/\xff"[..]));assert_eq!(options.query.expected_head,Some(head()));
    assert_eq!(options.query.action,Action::List{after:Some(vec![254]),limit:2});
    let mut mixed=raw.clone();mixed.extend(["--path".into(),"different".into()]);assert!(options::parse(&mixed,false).is_err());
    raw[6]="--path".into();raw[7]="../outside".into();assert!(options::parse(&raw,false).is_err());
}
#[test]
fn mode_specific_flags_bounds_duplicates_and_unpinned_continuations_refuse() {
    let directory=args();assert!(options::parse(&directory,false).unwrap().query.path.is_none());
    assert!(options::parse(&directory,true).is_err());
    let mut file=args();file.extend(["--path".into(),"file".into()]);assert!(options::parse(&file,true).is_ok());
    for (flag,value) in [("--principal","x"),("--force","true"),("--idempotency-key","key"),
        ("--key-stdin","true"),("--limit","1001"),("--offset","1"),("--after-hex","00"),
        ("--after-hex","66696c65"),("--limit","01"),("--limit","18446744073709551616")] {
        let mut bad=directory.clone();bad.extend([flag.into(),value.into()]);assert!(options::parse(&bad,false).is_err(),"{bad:?}");
    }
    for (flag,value) in [("--offset","1"),("--max-bytes","0"),("--max-bytes","1048577"),
        ("--max-bytes","-1"),("--after-hex","61"),("--limit","1"),("--path-hex","66696c65")] {
        let mut bad=file.clone();bad.extend([flag.into(),value.into()]);assert!(options::parse(&bad,true).is_err(),"{bad:?}");
    }
    let mut duplicate=directory.clone();duplicate.push("--trusted-local".into());assert!(options::parse(&duplicate,false).is_err());
    let mut duplicate=directory.clone();duplicate.extend(["--limit".into(),"2".into(),"--limit".into(),"3".into()]);assert!(options::parse(&duplicate,false).is_err());
    let mut no_trust=directory.clone();no_trust.remove(3);assert!(options::parse(&no_trust,false).is_err());
    file.extend(["--offset".into(),u64::MAX.to_string(),"--expected-head".into(),head_token(head())]);
    assert!(options::parse(&file,true).is_ok()); // Range validation needs the verified blob length.
}
#[test]
fn expected_commit_is_nonzero_and_hash_domain_exact() {
    for (format,width) in [("sha1",20),("sha256",32)] {
        let mut good=args();good.extend(["--object-format".into(),format.into(),"--expected-commit".into(),"ab".repeat(width)]);
        assert!(options::parse(&good,false).is_ok());
        *good.last_mut().unwrap()="00".repeat(width);assert!(options::parse(&good,false).is_err());
        *good.last_mut().unwrap()="ab".repeat(if width==20 {32}else{20});assert!(options::parse(&good,false).is_err());
    }
}
#[test]
fn receipts_keep_binary_names_ranges_and_text_without_lossy_conversion() {
    let options=options::parse(&args(),false).unwrap();
    let binary=report(Content::Blob{kind:Kind::Symlink,bytes:b"\0\xff".to_vec(),total_bytes:7,offset:1,next_offset:Some(3)});
    let page=receipt(&options,&binary);assert!(page.contains("\"bytes_hex\":\"00ff\""));
    assert!(page.contains("\"text_utf8\":null"));assert!(page.contains("\"next_offset\":3"));
    assert!(page.contains("\"kind\":\"symlink\""));assert!(page.contains(&head_token(head())));
    let text=report(Content::Blob{kind:Kind::File,bytes:b"\"\\\r\n".to_vec(),total_bytes:4,offset:0,next_offset:None});
    assert!(receipt(&options,&text).contains(&format!("\"text_utf8\":{}",quote("\"\\\r\n"))));
    let tree=report(Content::Directory{entries:vec![SourceDirectoryEntry{name:vec![255],oid:binary.object_id,kind:Kind::Gitlink}],next_after:Some(vec![255])});
    let page=receipt(&options,&tree);assert!(page.contains("\"name_hex\":\"ff\""));
    assert!(page.contains("\"next_after_hex\":\"ff\""));assert!(page.contains("\"has_more\":true"));
}
#[test]
fn cleanup_and_output_failures_cannot_be_reported_as_complete_reads() {
    let options=options::parse(&args(),false).unwrap();
    let report=report(Content::Directory{entries:vec![],next_after:None});let mut bytes=Vec::new();
    let failure=finish(&mut bytes,&options,Ok(report.clone()),Some("not closed".into())).unwrap_err();
    assert!(failure.contains("shutdown"));assert!(bytes.is_empty());
    let failure=finish(&mut bytes,&options,Err("read failed".into()),Some("close failed".into())).unwrap_err();
    assert!(failure.contains("read failed") && failure.contains("close failed"));assert!(bytes.is_empty());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self,bytes:&[u8])->std::io::Result<usize>{Ok(bytes.len())}
        fn flush(&mut self)->std::io::Result<()>{Err(std::io::Error::other("flush failed"))}
    }
    assert!(finish(&mut Broken,&options,Ok(report.clone()),None).unwrap_err().contains("incomplete"));
    assert_eq!(finish(&mut bytes,&options,Ok(report),None).unwrap(),0);
    assert!(bytes.ends_with(b"\n"));
}
