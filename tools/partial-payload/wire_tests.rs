#![forbid(unsafe_code)]
use std::cell::Cell;
use fgit_wire::{AdvertisedRef,AnyGitOid,Capabilities,GitObjectFormat,LegacyUploadPack,ObjectFilter,Packet,UploadPackRepository,UploadPackVersion,WireError,WireLimits,parse_filter};

#[test]
fn scaled_blob_limits_and_encoded_compounds_preserve_native_meaning() {
    for format in [GitObjectFormat::Sha1,GitObjectFormat::Sha256] {
        for (text,size) in [("0",0),("1k",1024),("2M",2*1024*1024),("3g",3*1024*1024*1024),("18446744073709551615",u64::MAX)] {
            assert_eq!(parse_filter(format!("blob:limit={text}").as_bytes(),format,&WireLimits::default()).unwrap(),ObjectFilter::BlobLimit(size));
        }
        let expected=ObjectFilter::Combine(vec![ObjectFilter::TreeDepth(2),ObjectFilter::BlobNone]);
        for text in [b"combine:tree:2+blob:none".as_slice(),b"combine:tree%3A2+blob%3Anone"] {
            assert_eq!(parse_filter(text,format,&WireLimits::default()).unwrap(),expected);
        }
        assert_eq!(parse_filter(b"combine:combine%3Atree%253A2%2Bblob%253Anone+blob:limit=1k",format,&WireLimits::default()).unwrap(),ObjectFilter::Combine(vec![expected,ObjectFilter::BlobLimit(1024)]));
    }
}

#[test]
fn malformed_encodings_overflow_and_global_compound_budget_are_refused() {
    let format=GitObjectFormat::Sha1;
    for text in ["blob:limit=-1","blob:limit=1kb","blob:limit=18446744073709551615k","blob:limit=18446744073709551616","blob:limit=k","tree:4294967296","combine:","combine:blob:none+","combine:+tree:1","combine:tree%3","combine:tree%GG1","combine:blob:none%00","combine:blob:none\n"] {
        assert!(parse_filter(text.as_bytes(),format,&WireLimits::default()).is_err(),"{text}");
    }
    let limits=WireLimits {max_filter_parts:2,..WireLimits::default()};
    assert!(parse_filter(b"combine:tree:1+blob:none",format,&limits).is_ok());
    assert!(matches!(parse_filter(b"combine:combine%3Atree%3A1%2Bblob%3Anone+tree:2",format,&limits),Err(WireError::TooManyFilterParts {limit:2})));
    assert!(matches!(parse_filter(&vec![b'x';100],format,&WireLimits {max_packet_bytes:32,..WireLimits::default()}),Err(WireError::PacketTooLarge {declared:100,limit:32})));
}

struct Repository { format:GitObjectFormat, refs:Vec<AdvertisedRef>, permitted:AnyGitOid, checks:Cell<usize> }
impl UploadPackRepository for Repository {
    fn object_format(&self)->GitObjectFormat {self.format}
    fn advertised_refs(&self)->&[AdvertisedRef] {&self.refs}
    fn contains_want(&self,oid:AnyGitOid)->bool {self.checks.set(self.checks.get()+1);oid==self.permitted}
    fn is_common(&self,_oid:AnyGitOid)->bool {false}
}
fn oid(format:GitObjectFormat,byte:u8)->AnyGitOid {
    AnyGitOid::from_hex(format,&format!("{byte:02x}").repeat(format.digest_len())).unwrap()
}
#[test]
fn unadvertised_legacy_wants_require_both_server_capability_and_repository_permission() {
    for format in [GitObjectFormat::Sha1,GitObjectFormat::Sha256] {
        for version in [UploadPackVersion::V0,UploadPackVersion::V1] {
            for allow in [false,true] {
                let repository=Repository {format,refs:vec![AdvertisedRef::new(oid(format,1),b"refs/heads/main",&WireLimits::default()).unwrap()],permitted:oid(format,2),checks:Cell::new(0)};
                for wanted in [oid(format,1),oid(format,2),oid(format,3)] {
                    repository.checks.set(0);
                    let caps=Capabilities::parse_v1(if allow {b"allow-reachable-sha1-in-want"} else {b""},&WireLimits::default()).unwrap();
                    let mut machine=LegacyUploadPack::new(version,caps,WireLimits::default()).unwrap();
                    let result=machine.push_packet(&Packet::Data(format!("want {wanted}\n").into_bytes()),&repository);
                    if wanted==oid(format,1) || (allow && wanted==repository.permitted) {assert!(result.is_ok());}
                    else {assert!(matches!(result,Err(WireError::WantNotAdvertised {oid}) if oid==wanted));}
                    assert_eq!(repository.checks.get(),usize::from(allow && wanted!=oid(format,1)));
                }
                let mut machine=LegacyUploadPack::new(version,Capabilities::default(),WireLimits::default()).unwrap();
                assert!(matches!(machine.push_packet(&Packet::Data(format!("want {} allow-reachable-sha1-in-want\n",repository.permitted).into_bytes()),&repository),Err(WireError::WantNotAdvertised {..})),"client text cannot authorize itself");
            }
        }
    }
}
