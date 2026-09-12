
#[cfg(test)]
mod tests {
    use super::*;
    struct Repo { format:GitObjectFormat, refs:Vec<AdvertisedRef> }
    impl UploadPackRepository for Repo {
        fn object_format(&self)->GitObjectFormat {self.format}
        fn advertised_refs(&self)->&[AdvertisedRef] {&self.refs}
        fn contains_want(&self,id:AnyGitOid)->bool {self.refs.iter().any(|r|r.oid==id)}
        fn is_common(&self,_:AnyGitOid)->bool {false}
        fn resolve_ref(&self,_:&[u8])->Option<AnyGitOid> {Some(oid(self.format,99))}
    }
    fn oid(format:GitObjectFormat,byte:u8)->AnyGitOid {AnyGitOid::from_hex(format,&format!("{byte:02x}").repeat(format.digest_len())).unwrap()}
    fn repo(format:GitObjectFormat)->Repo {Repo {format,refs:[("HEAD",1),("refs/heads/public",1),("refs/tags/release",2),("refs/remotes/upstream/HEAD",3)]
        .into_iter().map(|(name,id)|AdvertisedRef::new(oid(format,id),name.as_bytes(),&WireLimits::default()).unwrap()).collect()}}
    fn line(text:impl AsRef<str>)->Packet {Packet::Data(format!("{}\n",text.as_ref()).into_bytes())}
    #[test]
    fn advertised_short_and_full_names_resolve_without_hidden_or_arbitrary_resolver_access() {
        for format in [GitObjectFormat::Sha1,GitObjectFormat::Sha256] {
            let repository=repo(format);let limits=WireLimits::default();
            for (name,id) in [("HEAD",1),("public",1),("heads/public",1),("refs/heads/public",1),("release",2),("tags/release",2),("upstream",3)] {
                assert_eq!(resolve(&repository,name.as_bytes(),&limits).unwrap(),oid(format,id));
            }
            for name in [b"hidden".as_slice(),b"refs/heads/hidden"] {
                assert!(matches!(resolve(&repository,name,&limits),Err(WireError::UnknownDeepenNotRef {..})));
            }
        }
    }
    #[test]
    fn two_visible_names_are_ambiguous_even_when_their_object_ids_are_equal() {
        let mut repository=repo(GitObjectFormat::Sha1);
        repository.refs.push(AdvertisedRef::new(oid(repository.format,1),b"refs/tags/public",&WireLimits::default()).unwrap());
        assert!(matches!(resolve(&repository,b"public",&WireLimits::default()),Err(WireError::UnknownDeepenNotRef {..})));
        assert_eq!(resolve(&repository,b"refs/heads/public",&WireLimits::default()).unwrap(),oid(repository.format,1));
    }
    #[test]
    fn names_hash_domains_and_advertisement_counts_remain_bounded() {
        let mut repository=repo(GitObjectFormat::Sha1);let limits=WireLimits::default();
        assert!(matches!(resolve(&repository,b"public",&WireLimits {max_advertised_refs:1,..limits.clone()}),Err(WireError::TooManyAdvertisedRefs {..})));
        assert!(matches!(resolve(&repository,b"public",&WireLimits {max_ref_name_bytes:2,..limits.clone()}),Err(WireError::RefNameTooLarge {..})));
        assert!(matches!(resolve(&repository,b"../public",&limits),Err(WireError::InvalidRefName)));
        repository.refs[1].oid=oid(GitObjectFormat::Sha256,1);
        assert!(matches!(resolve(&repository,b"public",&limits),Err(WireError::ObjectFormatMismatch {..})));
    }
    #[test]
    fn both_wire_versions_bind_short_exclusions_to_the_advertised_native_identity() {
        for format in [GitObjectFormat::Sha1,GitObjectFormat::Sha256] {
            let repository=repo(format);let limits=WireLimits::default();
            let arguments=[line(format!("want {}",oid(format,1))),line("deepen-since 1700000000"),line("deepen-not release")];
            for version in [UploadPackVersion::V0,UploadPackVersion::V1] {
                let capabilities=Capabilities::parse_v1(b"shallow deepen-since deepen-not",&limits).unwrap();
                let mut machine=LegacyUploadPack::new(version,capabilities,limits.clone()).unwrap();
                for packet in &arguments {machine.push_packet(packet,&repository).unwrap();}
                machine.push_packet(&Packet::Flush,&repository).unwrap();
                let transition=machine.push_packet(&line("done"),&repository).unwrap();
                let [WireEvent::PackRequested(request)]=transition.events.as_slice() else {panic!("native pack request required")};
                assert_eq!(request.deepen_since,Some(1700000000));assert_eq!(request.deepen_not,vec![oid(format,2)]);
            }
            let capabilities=Capabilities::parse_v2_advertisement(&[line("version 2"),line("fetch=shallow"),Packet::Flush],&limits).unwrap();
            let mut machine=V2UploadPack::new(capabilities,limits.clone()).unwrap();
            for packet in [line("command=fetch"),Packet::Delimiter].iter().chain(arguments.iter()).chain([line("done")].iter()) {
                machine.push_packet(packet,&repository).unwrap();
            }
            let transition=machine.push_packet(&Packet::Flush,&repository).unwrap();
            let [WireEvent::PackRequested(request)]=transition.events.as_slice() else {panic!("native v2 pack request required")};
            assert_eq!(request.deepen_since,Some(1700000000));assert_eq!(request.deepen_not,vec![oid(format,2)]);
        }
    }
}
