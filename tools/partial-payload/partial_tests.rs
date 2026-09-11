use super::*;
use super::super::partial_clone as engine;
use fgit_wire::ObjectFilter;

fn request(wants: Vec<GitOid>, haves: Vec<GitOid>, filter: Option<ObjectFilter>) -> PackRequest {
    PackRequest { version: UploadPackVersion::V2, wants, haves, filter,
        shallows: Vec::new(), deepen: None, deepen_since: None, deepen_not: Vec::new(),
        options: fgit_wire::PackOptions::NONE }
}
fn graph(source: &MemorySource, roots: &[GitOid]) -> VisibleGraph {
    project_visible_graph(source, &source.admitted(), roots.iter().copied(), &PackLimits::default()).unwrap()
}
fn apply(graph: &VisibleGraph, ids: &[GitOid], request: &PackRequest) -> Vec<GitOid> {
    let mut result = ids.to_vec();
    engine::apply_selection(&graph.objects, &mut result, request, &PackLimits::default(), &mut || true).unwrap();
    result
}

#[test]
fn minimum_tree_depth_is_shared_across_paths_and_selected_commit_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut source = MemorySource::new(format);
        let blob = source.put(ObjectType::Blob, b"small".to_vec());
        let shared = source.tree(&[(b"100644", b"file", blob)]);
        let deep = source.tree(&[(b"40000", b"deep", shared)]);
        let root = source.tree(&[(b"40000", b"a-long", deep), (b"40000", b"z-short", shared)]);
        let commit = source.commit(root, &[]);
        let other = source.commit(shared, &[]);
        let graph = graph(&source, &[commit, other]);
        let all = graph.closure.objects().iter().copied().collect::<Vec<_>>();
        let only_first = all.iter().copied().filter(|id| *id != other).collect::<Vec<_>>();
        let filtered = apply(&graph, &only_first, &request(vec![commit], vec![], Some(ObjectFilter::TreeDepth(2))));
        assert_eq!(filtered.into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([commit, root, deep, shared]),
            "shared tree's shorter path wins; its depth-two blob is omitted");
        for wants in [vec![commit, other], vec![other, commit, other]] {
            let filtered = apply(&graph, &all, &request(wants, vec![], Some(ObjectFilter::TreeDepth(2))));
            assert_eq!(filtered, all, "another selected commit seeds the shared tree at zero");
        }
        let filtered = apply(&graph, &all, &request(vec![commit, other], vec![], Some(ObjectFilter::TreeDepth(0))));
        assert_eq!(filtered.into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([commit, other]));
    }
}

#[test]
fn explicit_lazy_roots_override_filters_without_treating_a_have_commit_as_a_blob_have() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha256);
    let blob = source.put(ObjectType::Blob, b"missing on partial client".to_vec());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let commit = source.commit(tree, &[]);
    let graph = graph(&source, &[commit]);
    for filter in [None, Some(ObjectFilter::BlobNone), Some(ObjectFilter::TreeDepth(0))] {
        assert_eq!(apply(&graph, &[], &request(vec![blob], vec![commit], filter)), vec![blob]);
    }
    assert_eq!(apply(&graph, &[], &request(vec![tree], vec![commit], None)).into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([tree, blob]));
    assert_eq!(apply(&graph, &[], &request(vec![tree], vec![commit], Some(ObjectFilter::TreeDepth(0)))), vec![tree]);
    assert!(apply(&graph, &[], &request(vec![blob], vec![blob], None)).is_empty());
    assert!(apply(&graph, &[], &request(vec![commit], vec![commit], None)).is_empty());
    let missing = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, b"not visible");
    let mut ids = vec![commit];
    assert!(matches!(engine::apply_selection(&graph.objects, &mut ids, &request(vec![missing], vec![], None), &PackLimits::default(), &mut || true),
        Err(NodePackMaterializationRefusal::RequestedWantOutsideClosure(id)) if id == missing));
    assert_eq!(ids, vec![commit]);
}

#[test]
fn blob_limit_is_exclusive_including_empty_blobs_and_combines_by_intersection() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let empty = source.put(ObjectType::Blob, Vec::new());
    let small = source.put(ObjectType::Blob, b"abc".to_vec());
    let large = source.put(ObjectType::Blob, b"abcd".to_vec());
    let tree = source.tree(&[(b"100644", b"a", empty), (b"100644", b"b", small), (b"100644", b"c", large)]);
    let commit = source.commit(tree, &[]);
    let graph = graph(&source, &[commit]);
    let all = graph.closure.objects().iter().copied().collect::<Vec<_>>();
    for (filter, expected) in [
        (ObjectFilter::BlobLimit(0), BTreeSet::from([commit, tree])),
        (ObjectFilter::BlobLimit(4), BTreeSet::from([commit, tree, empty, small])),
        (ObjectFilter::Combine(vec![ObjectFilter::BlobLimit(4), ObjectFilter::TreeDepth(1)]), BTreeSet::from([commit, tree])),
        (ObjectFilter::Combine(vec![ObjectFilter::BlobLimit(4), ObjectFilter::TreeDepth(2)]), BTreeSet::from([commit, tree, empty, small])),
    ] {
        assert_eq!(apply(&graph, &all, &request(vec![commit], vec![], Some(filter))).into_iter().collect::<BTreeSet<_>>(), expected);
    }
}

#[test]
fn every_partial_selection_stop_leaves_original_selection_untouched() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let blob = source.put(ObjectType::Blob, b"body".to_vec());
    let tree = source.tree(&[(b"100644", b"file", blob)]);
    let commit = source.commit(tree, &[]);
    let graph = graph(&source, &[commit]);
    let original = graph.closure.objects().iter().copied().collect::<Vec<_>>();
    let request = request(vec![commit], vec![], Some(ObjectFilter::TreeDepth(1)));
    let polls = Cell::new(0);
    let mut ids = original.clone();
    engine::apply_selection(&graph.objects, &mut ids, &request, &PackLimits::default(), &mut || { polls.set(polls.get()+1); true }).unwrap();
    assert_eq!(ids.len(), 2);
    for stop in 1..=polls.get() {
        let mut count = 0;
        let mut ids = original.clone();
        let result = engine::apply_selection(&graph.objects, &mut ids, &request, &PackLimits::default(), &mut || { count += 1; count < stop });
        assert!(matches!(result, Err(NodePackMaterializationRefusal::Pack(error)) if matches!(*error, PackWriteError::Pack(PackError::DeadlineExceeded))));
        assert_eq!(ids, original);
    }
    for limits in [PackLimits { max_entries: 2, ..PackLimits::default() }, PackLimits { max_delta_work: 1, ..PackLimits::default() }] {
        let mut ids = original.clone();
        assert!(matches!(engine::apply_selection(&graph.objects, &mut ids, &request, &limits, &mut || true), Err(NodePackMaterializationRefusal::DisclosureGraph(RefusalCode::ResourceBudgetExceeded))));
        assert_eq!(ids, original);
    }
}

#[test]
fn unsupported_controls_fail_instead_of_silently_returning_an_unfiltered_pack() {
    let mut source = MemorySource::new(GitHashAlgorithm::Sha1);
    let blob = source.put(ObjectType::Blob, b"body".to_vec());
    let graph = graph(&source, &[blob]);
    for filter in [ObjectFilter::SparsePath(b"secret".to_vec()), ObjectFilter::SparseObject(blob), ObjectFilter::Combine(vec![ObjectFilter::BlobNone, ObjectFilter::SparseObject(blob)])] {
        let mut ids = vec![blob];
        assert!(matches!(engine::apply_selection(&graph.objects, &mut ids, &request(vec![blob], vec![], Some(filter)), &PackLimits::default(), &mut || true), Err(NodePackMaterializationRefusal::UnsupportedFetch("sparse filters"))));
        assert_eq!(ids, vec![blob]);
    }
    let mut shallow = request(vec![blob], vec![], None);
    shallow.deepen = Some(1);
    let mut ids = vec![blob];
    assert!(matches!(engine::apply_selection(&graph.objects, &mut ids, &shallow, &PackLimits::default(), &mut || true), Err(NodePackMaterializationRefusal::UnsupportedFetch("shallow history"))));
    assert_eq!(ids, vec![blob]);
}

fn exchange_filtered(node: OneNode, version: u8, wants: &[GitOid], have: Option<GitOid>, filter: Option<&str>, include_tag: bool)
    -> (OneNode, Result<GitDaemonSessionOutcome, NodeGitDaemonServeRefusal>, Vec<u8>)
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let suffix = if version == 0 { String::new() } else { format!("\0version={version}\0") };
    let mut packets = vec![Packet::Data(format!("git-upload-pack {}\0host=loopback\0{suffix}", String::from_utf8_lossy(node.git_daemon_repository_path().as_bytes())).into_bytes())];
    if version == 2 {
        packets.extend([Packet::Data(b"command=fetch\n".to_vec()), Packet::Data(format!("object-format={}\n",node.object_format.as_str()).into_bytes()), Packet::Delimiter]);
    }
    for (index, want) in wants.iter().enumerate() {
        let mut caps = String::new();
        if version != 2 && index == 0 {
            if filter.is_some() { caps.push_str(" filter"); }
            if include_tag { caps.push_str(" include-tag"); }
        }
        packets.push(Packet::Data(format!("want {want}{caps}\n").into_bytes()));
    }
    if let Some(filter) = filter { packets.push(Packet::Data(format!("filter {filter}\n").into_bytes())); }
    if version == 2 && include_tag { packets.push(Packet::Data(b"include-tag\n".to_vec())); }
    if version != 2 { packets.push(Packet::Flush); }
    if let Some(have) = have { packets.push(Packet::Data(format!("have {have}\n").into_bytes())); }
    packets.push(Packet::Data(b"done\n".to_vec()));
    if version == 2 { packets.push(Packet::Flush); }
    let bytes = encode_packets(&packets,&WireLimits::default()).unwrap();
    let worker = std::thread::spawn(move || { let result = node.serve_git_daemon_once(&listener); (node,result) });
    let mut client = TcpStream::connect(address).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    client.set_write_timeout(Some(Duration::from_secs(30))).unwrap();
    client.write_all(&bytes).unwrap(); client.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new(); let read = client.read_to_end(&mut response); drop(client);
    let (node, result) = worker.join().unwrap();
    if result.is_ok() { read.unwrap(); }
    (node,result,response)
}
fn bodies(response: &[u8], version: u8, format: GitHashAlgorithm) -> BTreeSet<Vec<u8>> {
    let bytes = extract_pack(response, version);
    fgit_pack::read_verified_pack(&bytes,format,&PackLimits::default(),&mut || true,&fgit_pack::NativeChecksumVerifier).unwrap()
        .entries().iter().map(|entry| entry.inflated.clone()).collect()
}

#[test]
fn actual_partial_clones_and_lazy_fetches_preserve_native_bytes_current_visibility_and_retention() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let Fixture { scratch, mut node, config, public, private, private_blob, ancestor, visible } = fixture(format);
        delete_private(&node, private);
        let (tag, outer, _) = publish_tag_fixture(&node, ancestor);
        let public_blob = git_object_id(format, GitObjectKind::Blob, b"current public content");
        let metadata = visible.iter().map(|id| {
            let object = node.read_git_object(*id).unwrap();
            (*id, (object.envelope().object_kind(), object.payload().to_vec()))
        }).collect::<BTreeMap<_,_>>();
        let tag_bodies = [tag,outer].map(|id| node.read_git_object(id).unwrap().payload().to_vec());
        let request_context = node.request_context();
        let before = node.runtime().block_on(node.materialize_admission_in(&request_context)).unwrap();
        let historical_objects = before.selected_closure().closure().objects().clone();
        node.shutdown().unwrap(); node = OneNode::open_existing(config).unwrap();
        for version in [0,1,2] {
            for filter in [None, Some("blob:none"), Some("blob:limit=21"), Some("tree:0"), Some("tree:1"), Some("tree:2"), Some("combine:tree%3A1+blob%3Anone")] {
                let expected = metadata.values().filter(|(kind,body)| {
                    use fgit_object_fabric::ObjectKind;
                    match filter {
                        None | Some("tree:2") => true,
                        Some("tree:0") => *kind == ObjectKind::Commit,
                        Some("blob:limit=21") => *kind != ObjectKind::Blob || body.len() < 21,
                        _ => *kind != ObjectKind::Blob,
                    }
                }).map(|(_,body)| body.clone()).collect::<BTreeSet<_>>();
                let (returned,result,response) = exchange_filtered(node,version,&[public],None,filter,false); node = returned;
                assert!(matches!(result,Ok(GitDaemonSessionOutcome::Pack(_))),"{format:?} v{version} {filter:?}: {result:?}");
                assert_eq!(bodies(&response,version,format),expected,"native filtered body set {format:?} v{version} {filter:?}");
                let advertisement = if version == 2 { b"fetch=filter\n".as_slice() } else { b"allow-reachable-sha1-in-want filter".as_slice() };
                assert!(response.windows(advertisement.len()).any(|bytes| bytes == advertisement));
            }
            for filter in [None, Some("blob:none"), Some("tree:0")] {
                let (returned,result,response) = exchange_filtered(node,version,&[public_blob],Some(public),filter,false); node = returned;
                assert!(matches!(result,Ok(GitDaemonSessionOutcome::Pack(_))),"lazy {format:?} v{version}: {result:?}");
                assert_eq!(bodies(&response,version,format),BTreeSet::from([b"current public content".to_vec()]));
            }
            let (returned,result,response) = exchange_filtered(node,version,&[public],None,Some("blob:none"),true); node = returned;
            assert!(matches!(result,Ok(GitDaemonSessionOutcome::Pack(_))));
            let mut expected = metadata.values().filter(|(kind,_)| *kind != fgit_object_fabric::ObjectKind::Blob).map(|(_,body)| body.clone()).collect::<BTreeSet<_>>();
            expected.extend(tag_bodies.clone());
            assert_eq!(bodies(&response,version,format),expected);
            for forbidden in [private,private_blob] {
                let (returned,result,response) = exchange_filtered(node,version,&[forbidden],None,Some("blob:none"),false); node = returned;
                assert!(result.is_err()); assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
            }
            let (returned,result,response) = exchange_filtered(node,version,&[public],None,Some("sparse:path=anything"),false); node = returned;
            assert!(result.is_err()); assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
        }
        let context = node.request_context();
        let after = node.runtime().block_on(node.materialize_admission_in(&context)).unwrap();
        assert_eq!(before.basis(),after.basis(),"fetches never publish canonical state");
        assert_eq!(after.selected_closure().closure().objects(), &historical_objects,"omission is not retention removal");
        delete_named_ref(&node, public, b"refs/heads/public", b"partial-clone-revoke");
        assert!(node.read_git_object(public_blob).is_ok());
        for version in [0,1,2] {
            let (returned,result,response) = exchange_filtered(node,version,&[public_blob],None,None,false); node = returned;
            assert!(result.is_err(),"a previous partial-clone promise is not a permanent disclosure grant");
            assert!(!response.windows(4).any(|bytes| bytes == b"PACK"));
            let (returned,result,response) = exchange_filtered(node,version,&[ancestor],None,Some("blob:none"),false); node = returned;
            assert!(matches!(result,Ok(GitDaemonSessionOutcome::Pack(_)))) ;
            assert_eq!(bodies(&response,version,format).len(),2,"still-visible ancestor succeeds beside revoked lazy want");
        }
        node.shutdown().unwrap(); drop(scratch);
    }
}
