use super::*;

fn relative(want: GitOid, increment: u32, old: Vec<GitOid>, haves: Vec<GitOid>) -> PackRequest {
    let mut request = request(want, Some(increment), old, haves);
    request.options = request.options.with_deepen_relative(true);
    request
}

#[test]
fn repeated_relative_deepening_crosses_successive_old_boundaries_without_resending_the_tip() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let root = graph.commit(&[]); let first = graph.commit(&[root.0]);
        let second = graph.commit(&[first.0]); let tip = graph.commit(&[second.0]);
        for (old, next) in [(tip.0,second),(second.0,first),(first.0,root)] {
            let request = relative(tip.0,1,vec![old],vec![tip.0]);
            assert_eq!(ids(&graph,&request),BTreeSet::from([next.0,next.1,next.2]));
            assert_eq!(update(&graph,&request),ShallowUpdate { shallow:vec![next.0],unshallow:vec![old] });
            let absolute = request(tip.0,Some(1),vec![old],vec![tip.0]);
            assert!(!ids(&graph,&absolute).contains(&next.0));
        }
        let complete = relative(tip.0,1,vec![root.0],vec![tip.0]);
        assert!(ids(&graph,&complete).is_empty());
        assert_eq!(update(&graph,&complete),ShallowUpdate { shallow:vec![],unshallow:vec![root.0] });
    }
}

#[test]
fn nearest_reachable_marker_defines_the_offset_not_input_order_or_a_foreign_history() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let mut graph = Graph::new(format);
        let root=graph.commit(&[]);let first=graph.commit(&[root.0]);let second=graph.commit(&[first.0]);
        let tip=graph.commit(&[second.0]);let unrelated=graph.commit(&[]);
        let tag=graph.add(ObjectType::Tag,vec![(tip.0,ObjectType::Commit)]);
        let unknown=GitOid::from_hex(format,&"f".repeat(format.digest_len()*2)).unwrap();
        for old in [vec![root.0,second.0,unrelated.0,unknown],vec![unknown,unrelated.0,second.0,root.0]] {
            let request=relative(tag,1,old,vec![]);
            assert_eq!(update(&graph,&request).shallow,vec![first.0]);
            assert_eq!(update(&graph,&request).unshallow,vec![second.0]);
            assert!(ids(&graph,&request).contains(&first.0));
            assert!(!ids(&graph,&request).contains(&root.0));
            assert!(!ids(&graph,&request).contains(&unrelated.0));
        }
        let no_match=relative(tip.0,1,vec![unrelated.0,unknown],vec![]);
        assert_eq!(update(&graph,&no_match).shallow,vec![tip.0]);
        assert_eq!(ids(&graph,&no_match),BTreeSet::from([tip.0,tip.1,tip.2]));
    }
}

#[test]
fn merged_and_multiple_wanted_histories_use_shortest_generations() {
    let mut graph=Graph::new(GitHashAlgorithm::Sha256);
    let root=graph.commit(&[]);let shared=graph.commit(&[root.0]);let long=graph.commit(&[shared.0]);
    let merge=graph.commit(&[long.0,shared.0]);
    let mut query=relative(merge.0,1,vec![shared.0],vec![]);
    assert_eq!(update(&graph,&query).shallow,vec![root.0]);
    let original=ids(&graph,&query);
    graph.objects.get_mut(&merge.0).unwrap().edges.reverse();
    assert_eq!(ids(&graph,&query),original);
    for wants in [vec![merge.0,shared.0],vec![shared.0,merge.0,shared.0]] {
        query.wants=wants;
        assert_eq!(update(&graph,&query).shallow,vec![root.0,long.0]);
        assert!(ids(&graph,&query).contains(&root.0));
    }
}

#[test]
fn relative_depth_does_not_turn_unknown_markers_into_permission_or_overflow_into_unshallow() {
    let mut graph=Graph::new(GitHashAlgorithm::Sha1);
    let root=graph.commit(&[]);let tip=graph.commit(&[root.0]);
    let unknown=GitOid::from_hex(graph.format,&"e".repeat(40)).unwrap();
    let mut query=relative(tip.0,1,vec![unknown],vec![]);
    assert_eq!(update(&graph,&query).shallow,vec![tip.0]);
    query.wants.push(unknown);
    assert!(matches!(select(&graph.objects,&query,&PackLimits::default(),&mut || true),Err(NodePackMaterializationRefusal::RequestedWantOutsideClosure(id)) if id==unknown));
    let overflow=relative(tip.0,2_147_483_646,vec![root.0],vec![tip.0]);
    assert!(matches!(select(&graph.objects,&overflow,&PackLimits::default(),&mut || true),Err(NodePackMaterializationRefusal::DisclosureGraph(RefusalCode::ResourceBudgetExceeded))));
    let exact=relative(tip.0,2_147_483_645,vec![root.0],vec![tip.0]);
    assert!(update(&graph,&exact).shallow.is_empty());
    assert_eq!(update(&graph,&exact).unshallow,vec![root.0]);
    let mut orphan=relative(tip.0,1,vec![tip.0],vec![]);orphan.deepen=None;
    assert!(matches!(select(&graph.objects,&orphan,&PackLimits::default(),&mut || true),Err(NodePackMaterializationRefusal::UnsupportedFetch(_))));
}

#[test]
fn relative_offset_and_selection_share_one_exact_work_and_cancellation_budget() {
    let mut graph=Graph::new(GitHashAlgorithm::Sha256);
    let root=graph.commit(&[]);let parent=graph.commit(&[root.0]);let tip=graph.commit(&[parent.0]);
    let query=relative(tip.0,1,vec![parent.0],vec![tip.0]);
    let mut polls=0;
    let expected=select(&graph.objects,&query,&PackLimits::default(),&mut || { polls+=1;true }).unwrap();
    let exact=PackLimits { max_delta_work:polls,..PackLimits::default() };
    assert_eq!(select(&graph.objects,&query,&exact,&mut || true).unwrap(),expected);
    let short=PackLimits { max_delta_work:polls-1,..exact.clone() };
    assert!(matches!(select(&graph.objects,&query,&short,&mut || true),Err(NodePackMaterializationRefusal::DisclosureGraph(RefusalCode::ResourceBudgetExceeded))));
    for stop in 1..=polls {
        let mut seen=0;
        assert!(matches!(select(&graph.objects,&query,&exact,&mut || {seen+=1;seen<stop}),Err(NodePackMaterializationRefusal::Pack(error)) if matches!(*error,PackWriteError::Pack(PackError::DeadlineExceeded))));
    }
}
