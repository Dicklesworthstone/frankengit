//! Real native-node sockets and storage. No simulated pack builder or foreign Git.
use super::*;
use std::io;

fn read_packet(stream: &mut TcpStream, transcript: &mut Vec<u8>) -> io::Result<Packet> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    transcript.extend_from_slice(&header);
    let length = usize::from_str_radix(
        std::str::from_utf8(&header)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-ASCII pkt-line header"))?,
        16,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-hex pkt-line header"))?;
    match length {
        0 => Ok(Packet::Flush),
        1 => Ok(Packet::Delimiter),
        2 => Ok(Packet::ResponseEnd),
        3 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reserved pkt-line length",
        )),
        4..=fgit_wire::MAX_PKT_LINE_BYTES => {
            let mut bytes = vec![0; length - 4];
            stream.read_exact(&mut bytes)?;
            transcript.extend_from_slice(&bytes);
            Ok(Packet::Data(bytes))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized pkt-line",
        )),
    }
}

fn exchange_shallow(
    node: OneNode,
    version: u8,
    want: GitOid,
    shallow: Option<GitOid>,
    depth: Option<u32>,
    have: Option<GitOid>,
    filter: Option<&str>,
) -> (
    OneNode,
    Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>,
    Vec<u8>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let path = node.git_daemon_repository_path().as_bytes().to_vec();
    let format = node.object_format;
    let worker = std::thread::spawn(move || {
        let result = node.serve_git_daemon_once(&listener);
        (node, result)
    });
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let limits = WireLimits::default();
    let mut transcript = Vec::new();
    let client_result = (|| -> io::Result<()> {
        let suffix = if version == 0 {
            String::new()
        } else {
            format!("\0version={version}\0")
        };
        let greeting = Packet::Data(
            format!(
                "git-upload-pack {}\0host=loopback\0{suffix}",
                String::from_utf8_lossy(&path)
            )
            .into_bytes(),
        );
        stream.write_all(&encode_packets(&[greeting], &limits).unwrap())?;
        loop {
            if read_packet(&mut stream, &mut transcript)? == Packet::Flush {
                break;
            }
        }
        let mut packets = Vec::new();
        if version == 2 {
            packets.extend([
                Packet::Data(b"command=fetch\n".to_vec()),
                Packet::Data(format!("object-format={}\n", format.as_str()).into_bytes()),
                Packet::Delimiter,
            ]);
        }
        let caps = if version != 2 && filter.is_some() {
            " filter"
        } else {
            ""
        };
        packets.push(Packet::Data(format!("want {want}{caps}\n").into_bytes()));
        if let Some(shallow) = shallow {
            packets.push(Packet::Data(format!("shallow {shallow}\n").into_bytes()));
        }
        if let Some(depth) = depth {
            packets.push(Packet::Data(format!("deepen {depth}\n").into_bytes()));
        }
        if let Some(filter) = filter {
            packets.push(Packet::Data(format!("filter {filter}\n").into_bytes()));
        }
        if version != 2 {
            packets.push(Packet::Flush);
            stream.write_all(&encode_packets(&packets, &limits).unwrap())?;
            packets.clear();
            if depth.is_some() {
                // An ordinary legacy client waits here. Sending done up front
                // would hide the missing shallow-response deadlock entirely.
                loop {
                    match read_packet(&mut stream, &mut transcript)? {
                        Packet::Flush => break,
                        Packet::Data(line)
                            if line.starts_with(b"shallow ") || line.starts_with(b"unshallow ") => {
                        }
                        _ => {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "expected shallow records then flush before haves",
                            ));
                        }
                    }
                }
            }
        }
        if let Some(have) = have {
            packets.push(Packet::Data(format!("have {have}\n").into_bytes()));
        }
        packets.push(Packet::Data(b"done\n".to_vec()));
        if version == 2 {
            packets.push(Packet::Flush);
        }
        stream.write_all(&encode_packets(&packets, &limits).unwrap())?;
        stream.shutdown(Shutdown::Write)?;
        stream.read_to_end(&mut transcript)?;
        Ok(())
    })();
    drop(stream);
    let (node, result) = worker.join().unwrap();
    if result.is_ok() {
        client_result.expect("native shallow exchange completes without an early done packet");
    }
    (node, result, transcript)
}

fn shallow_records(bytes: &[u8]) -> BTreeSet<Vec<u8>> {
    let mut records = BTreeSet::new();
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset..].starts_with(b"PACK") {
            break;
        }
        assert!(offset + 4 <= bytes.len());
        let size =
            usize::from_str_radix(std::str::from_utf8(&bytes[offset..offset + 4]).unwrap(), 16)
                .unwrap();
        if size < 4 {
            offset += 4;
            continue;
        }
        assert!(offset + size <= bytes.len());
        let body = &bytes[offset + 4..offset + size];
        if body.starts_with(b"shallow ") || body.starts_with(b"unshallow ") {
            records.insert(body.to_vec());
        }
        offset += size;
    }
    records
}

fn stored_bodies(node: &OneNode, ids: &BTreeSet<GitOid>) -> BTreeSet<Vec<u8>> {
    ids.iter()
        .map(|id| node.read_git_object(*id).unwrap().payload().to_vec())
        .collect()
}

#[test]
fn native_shallow_clone_deepen_unshallow_and_partial_filters_match_exact_pack_bodies() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture {
            scratch,
            mut node,
            public,
            private,
            ancestor,
            visible,
            ..
        } = fixture(format);
        delete_private(&node, private);
        let blob = git_object_id(format, GitObjectKind::Blob, b"current public content");
        let tree = git_object_id(
            format,
            GitObjectKind::Tree,
            &tree_bytes(&[
                (b"100644", b"public", blob),
                (b"160000", b"submodule", private),
            ]),
        );
        let tip_ids = BTreeSet::from([public, tree, blob]);
        let ancestor_ids = visible
            .difference(&tip_ids)
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(ancestor_ids.len(), 3);
        let request = node.request_context();
        let before = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        let retained = before.selected_closure().closure().objects().clone();
        for version in [0, 1, 2] {
            for (depth, old, have, filter, expected_ids, expected_records) in [
                (
                    Some(1),
                    None,
                    None,
                    None,
                    tip_ids.clone(),
                    BTreeSet::from([format!("shallow {public}\n").into_bytes()]),
                ),
                (
                    Some(2),
                    Some(public),
                    Some(public),
                    None,
                    ancestor_ids.clone(),
                    BTreeSet::from([
                        format!("shallow {ancestor}\n").into_bytes(),
                        format!("unshallow {public}\n").into_bytes(),
                    ]),
                ),
                (
                    Some(2_147_483_647),
                    Some(public),
                    Some(public),
                    None,
                    ancestor_ids.clone(),
                    BTreeSet::from([format!("unshallow {public}\n").into_bytes()]),
                ),
                (
                    None,
                    Some(public),
                    Some(public),
                    None,
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                (
                    Some(1),
                    None,
                    None,
                    Some("blob:none"),
                    BTreeSet::from([public, tree]),
                    BTreeSet::from([format!("shallow {public}\n").into_bytes()]),
                ),
                (
                    Some(1),
                    None,
                    None,
                    Some("tree:0"),
                    BTreeSet::from([public]),
                    BTreeSet::from([format!("shallow {public}\n").into_bytes()]),
                ),
            ] {
                let expected = stored_bodies(&node, &expected_ids);
                let (returned, result, response) =
                    exchange_shallow(node, version, public, old, depth, have, filter);
                node = returned;
                assert!(
                    matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))),
                    "{format:?} v{version} depth={depth:?} filter={filter:?}: {result:?}"
                );
                assert_eq!(shallow_records(&response), expected_records);
                let pack_bytes = extract_pack(&response, version);
                let pack = fgit_pack::read_verified_pack(
                    &pack_bytes,
                    format,
                    &PackLimits::default(),
                    &mut || true,
                    &fgit_pack::NativeChecksumVerifier,
                )
                .unwrap();
                let actual: BTreeSet<_> = pack
                    .entries()
                    .iter()
                    .map(|entry| entry.inflated.clone())
                    .collect();
                assert_eq!(
                    actual, expected,
                    "history and object filters must both affect the real outgoing pack"
                );
            }
            let (returned, result, response) = exchange_shallow(
                node,
                version,
                blob,
                Some(public),
                None,
                Some(public),
                Some("blob:none"),
            );
            node = returned;
            assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
            assert!(shallow_records(&response).is_empty());
            let pack_bytes = extract_pack(&response, version);
            let pack = fgit_pack::read_verified_pack(
                &pack_bytes,
                format,
                &PackLimits::default(),
                &mut || true,
                &fgit_pack::NativeChecksumVerifier,
            )
            .unwrap();
            assert_eq!(
                pack.entries()
                    .iter()
                    .map(|entry| entry.inflated.clone())
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([b"current public content".to_vec()]),
                "an explicitly wanted blob is still hydrated below a shallow have"
            );
        }
        let request = node.request_context();
        let after = node
            .runtime()
            .block_on(node.materialize_admission_in(&request))
            .unwrap();
        assert_eq!(
            before.basis(),
            after.basis(),
            "serving never writes repository authority"
        );
        assert_eq!(
            after.selected_closure().closure().objects(),
            &retained,
            "shallow transfer cannot prune retained canonical history"
        );
        assert!(
            node.read_git_object(private).is_ok(),
            "retention and disclosure remain distinct"
        );
        node.shutdown().unwrap();
        drop(scratch);
    }
}

#[test]
fn disconnected_shallow_markers_are_not_echoed_or_promoted_to_disclosure_authority() {
    let Fixture {
        scratch,
        mut node,
        public,
        private,
        visible,
        ..
    } = fixture(GitHashAlgorithm::Sha256);
    delete_private(&node, private);
    let expected = stored_bodies(&node, &visible);
    for version in [0, 1, 2] {
        let (returned, result, response) = exchange_shallow(
            node,
            version,
            public,
            Some(private),
            None,
            Some(private),
            None,
        );
        node = returned;
        assert!(matches!(result, Ok(GitDaemonSessionOutcome::Pack(_))));
        assert!(shallow_records(&response).is_empty());
        let pack_bytes = extract_pack(&response, version);
        let pack = fgit_pack::read_verified_pack(
            &pack_bytes,
            GitHashAlgorithm::Sha256,
            &PackLimits::default(),
            &mut || true,
            &fgit_pack::NativeChecksumVerifier,
        )
        .unwrap();
        assert_eq!(
            pack.entries()
                .iter()
                .map(|entry| entry.inflated.clone())
                .collect::<BTreeSet<_>>(),
            expected
        );
        let (returned, result, response) =
            exchange_shallow(node, version, private, Some(private), Some(1), None, None);
        node = returned;
        assert!(result.is_err());
        assert!(!response.windows(4).any(|word| word == b"PACK"));
    }
    node.shutdown().unwrap();
    drop(scratch);
}
