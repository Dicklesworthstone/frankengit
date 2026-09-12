#![forbid(unsafe_code)]
use fgit_wire::closure::{
    ClosureError, ClosureLimits, ClosureObject, ObjectClosureRepository, compute_pack_closure,
};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, PackOptions,
    PackRequest, Packet, UploadPackRepository, UploadPackVersion, V2UploadPack, WireError,
    WireEvent, WireLimits,
};
struct Repository {
    format: GitObjectFormat,
    refs: Vec<AdvertisedRef>,
}
impl UploadPackRepository for Repository {
    fn object_format(&self) -> GitObjectFormat {
        self.format
    }
    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }
    fn contains_want(&self, id: AnyGitOid) -> bool {
        id == self.refs[0].oid
    }
    fn is_common(&self, _: AnyGitOid) -> bool {
        false
    }
}
fn repository(format: GitObjectFormat) -> Repository {
    let id = AnyGitOid::from_hex(format, &"1".repeat(format.digest_len() * 2)).unwrap();
    Repository {
        format,
        refs: vec![AdvertisedRef::new(id, b"refs/heads/main", &WireLimits::default()).unwrap()],
    }
}
fn line(text: impl AsRef<str>) -> Packet {
    Packet::Data(format!("{}\n", text.as_ref()).into_bytes())
}
fn v2(repository: &Repository, shallow: bool) -> V2UploadPack {
    let limits = WireLimits::default();
    let feature = if shallow { "fetch=shallow" } else { "fetch" };
    let caps = Capabilities::parse_v2_advertisement(
        &[line("version 2"), line(feature), Packet::Flush],
        &limits,
    )
    .unwrap();
    let mut machine = V2UploadPack::new(caps, limits).unwrap();
    for packet in [
        line("command=fetch"),
        Packet::Delimiter,
        line(format!("want {}", repository.refs[0].oid)),
    ] {
        machine.push_packet(&packet, repository).unwrap();
    }
    machine
}
#[test]
fn legacy_relative_capability_preserves_the_increment_in_the_pack_handoff() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        for version in [UploadPackVersion::V0, UploadPackVersion::V1] {
            let limits = WireLimits::default();
            let caps =
                Capabilities::parse_v1(b"shallow deepen-relative ofs-delta", &limits).unwrap();
            let mut machine = LegacyUploadPack::new(version, caps, limits).unwrap();
            for packet in [
                line(format!(
                    "want {} deepen-relative ofs-delta",
                    repository.refs[0].oid
                )),
                line("deepen 3"),
                Packet::Flush,
            ] {
                machine.push_packet(&packet, &repository).unwrap();
            }
            let transition = machine.push_packet(&line("done"), &repository).unwrap();
            let [WireEvent::PackRequested(request)] = transition.events.as_slice() else {
                panic!("missing pack handoff")
            };
            assert_eq!(request.deepen, Some(3));
            assert!(request.options.deepen_relative());
            assert!(request.options.ofs_delta());
        }
    }
}
#[test]
fn v2_relative_argument_is_order_independent_and_idempotent() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        for controls in [
            ["deepen-relative", "deepen 2", "deepen-relative"],
            ["deepen 2", "deepen-relative", "deepen-relative"],
        ] {
            let mut machine = v2(&repository, true);
            for text in controls {
                machine.push_packet(&line(text), &repository).unwrap();
            }
            machine.push_packet(&line("done"), &repository).unwrap();
            let transition = machine.push_packet(&Packet::Flush, &repository).unwrap();
            let [WireEvent::PackRequested(request)] = transition.events.as_slice() else {
                panic!("missing pack handoff")
            };
            assert_eq!(request.deepen, Some(2));
            assert!(request.options.deepen_relative());
            assert!(request.options.sideband_64k());
        }
    }
}
#[test]
fn relative_controls_require_the_feature_and_a_positive_depth() {
    let repository = repository(GitObjectFormat::Sha1);
    let mut unsupported = v2(&repository, false);
    assert!(matches!(
        unsupported.push_packet(&line("deepen-relative"), &repository),
        Err(WireError::UnknownCapability { .. })
    ));
    for controls in [
        vec!["deepen-relative"],
        vec!["deepen-relative", "deepen-since 1"],
        vec!["deepen-relative", "deepen 4294967295"],
    ] {
        let mut machine = v2(&repository, true);
        for control in controls {
            machine.push_packet(&line(control), &repository).unwrap();
        }
        assert_eq!(
            machine.push_packet(&Packet::Flush, &repository),
            Err(WireError::InvalidDepth)
        );
    }
    let limits = WireLimits::default();
    let caps = Capabilities::parse_v1(b"shallow", &limits).unwrap();
    let mut legacy = LegacyUploadPack::new(UploadPackVersion::V1, caps, limits).unwrap();
    assert!(matches!(
        legacy.push_packet(
            &line(format!("want {} deepen-relative", repository.refs[0].oid)),
            &repository
        ),
        Err(WireError::UnknownCapability { .. })
    ));
}
#[test]
fn clearing_relative_selection_preserves_other_negotiated_options() {
    let base = PackOptions::SIDE_BAND_64K;
    let relative = base.with_deepen_relative(true);
    assert!(relative.deepen_relative() && relative.sideband_64k());
    assert_eq!(relative.with_deepen_relative(false), base);
}
#[test]
fn a_legacy_graph_api_never_silently_reinterprets_relative_depth_as_absolute() {
    struct NoReads;
    impl ObjectClosureRepository for NoReads {
        fn object_format(&self) -> GitObjectFormat {
            GitObjectFormat::Sha1
        }
        fn object(&self, _: AnyGitOid) -> Result<ClosureObject, ClosureError> {
            panic!("unsupported provider must not read graph")
        }
    }
    let repository = repository(GitObjectFormat::Sha1);
    let request = PackRequest {
        version: UploadPackVersion::V2,
        wants: vec![repository.refs[0].oid],
        haves: vec![],
        shallows: vec![],
        deepen: Some(1),
        deepen_since: None,
        deepen_not: vec![],
        filter: None,
        options: PackOptions::NONE.with_deepen_relative(true),
    };
    assert_eq!(
        compute_pack_closure(&NoReads, &request, &ClosureLimits::default()),
        Err(ClosureError::UnsupportedRelativeDeepening)
    );
}
