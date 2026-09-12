//! Time/ref history cuts on the connection-owned verified graph.
//! Dates select traversal, not trust; ref exclusions never authorize reads.
use super::*;
use fgit_git_object::ParsedObject;

pub(super) fn requested(request: &PackRequest) -> bool {
    request.deepen_since.is_some() || !request.deepen_not.is_empty()
}

/// Observe a unique, uncontinued native committer date without changing import
/// acceptance. A time-filtered request refuses an unusable date when visited;
/// ordinary and ref-only fetches retain the existing byte-preserving behavior.
pub(crate) fn committer_time(parsed: &ParsedObject) -> Option<i64> {
    let ParsedObject::Commit(commit) = parsed else {
        return None;
    };
    let mut fields = commit
        .headers()
        .iter()
        .filter(|header| header.name == b"committer");
    let header = fields.next()?;
    if fields.next().is_some() || !header.continuations.is_empty() {
        return None;
    }
    let mut tail = header.value.rsplitn(3, |byte| *byte == b' ');
    let zone = tail.next()?;
    let timestamp = tail.next()?;
    let identity = tail.next()?;
    if zone.len() != 5
        || !matches!(zone[0], b'+' | b'-')
        || !zone[1..].iter().all(u8::is_ascii_digit)
        || !identity.ends_with(b">")
        || !identity.contains(&b'<')
    {
        return None;
    }
    std::str::from_utf8(timestamp).ok()?.parse().ok()
}

fn commit_root(
    objects: &BTreeMap<GitOid, FilterObject>,
    mut id: GitOid,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<Option<GitOid>, NodePackMaterializationRefusal> {
    let mut visited = BTreeSet::new();
    loop {
        if !work.insert(&mut visited, id)? {
            return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
        }
        let item = object(objects, id)?;
        match item.kind {
            ObjectType::Commit => return Ok(Some(id)),
            ObjectType::Tree | ObjectType::Blob => return Ok(None),
            ObjectType::Tag => {
                let [(target, _)] = item.edges.as_slice() else {
                    return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
                };
                id = *target;
            }
        }
    }
}

pub(super) fn history(
    objects: &BTreeMap<GitOid, FilterObject>,
    request: &PackRequest,
    old: BTreeSet<GitOid>,
    work: &mut Work<'_, impl FnMut() -> bool>,
) -> Result<History, NodePackMaterializationRefusal> {
    work.tick()?;
    work.count(request.deepen_not.len())?;
    if request.deepen.is_some() || request.options.deepen_relative() {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "depth and time/ref cutoffs cannot be combined",
        ));
    }
    if request.deepen_since.is_some_and(|value| value <= 0) {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "nonpositive shallow timestamp",
        ));
    }
    // Exclude complete commit ancestry before evaluating dates. Tag chains are
    // peeled through verified edges, and neither trees nor gitlinks are roots.
    let mut excluded = BTreeSet::new();
    let mut pending = BTreeSet::new();
    for &id in &request.deepen_not {
        work.tick()?;
        let root = commit_root(objects, id, work)?
            .ok_or_else(|| disclosure_refusal(RefusalCode::EvidenceInvalid))?;
        work.insert(&mut pending, root)?;
    }
    while let Some(id) = pending.pop_first() {
        if !work.insert(&mut excluded, id)? {
            continue;
        }
        let item = object(objects, id)?;
        if item.kind != ObjectType::Commit {
            return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
        }
        for &(parent, kind) in &item.edges {
            work.tick()?;
            if kind == ObjectType::Commit && !excluded.contains(&parent) {
                work.insert(&mut pending, parent)?;
            }
        }
    }
    let mut visited = BTreeSet::new();
    let mut included = BTreeSet::new();
    for &id in &request.wants {
        work.tick()?;
        if let Some(root) = commit_root(objects, id, work)? {
            work.insert(&mut pending, root)?;
        }
    }
    while let Some(id) = pending.pop_first() {
        if !work.insert(&mut visited, id)? || excluded.contains(&id) {
            continue;
        }
        let item = object(objects, id)?;
        if item.kind != ObjectType::Commit {
            return Err(disclosure_refusal(RefusalCode::EvidenceInvalid));
        }
        if let Some(since) = request.deepen_since {
            let timestamp = item
                .commit_time
                .ok_or_else(|| disclosure_refusal(RefusalCode::ObjectHeaderInvalid))?;
            // Git's max-age cutoff is inclusive. Stop on an old commit rather
            // than searching through it for an anomalously newer ancestor.
            if timestamp < since {
                continue;
            }
        }
        work.insert(&mut included, id)?;
        for &(parent, kind) in &item.edges {
            work.tick()?;
            if kind == ObjectType::Commit && !visited.contains(&parent) {
                work.insert(&mut pending, parent)?;
            }
        }
    }
    if included.is_empty() {
        return Err(NodePackMaterializationRefusal::UnsupportedFetch(
            "shallow cutoffs select no commits",
        ));
    }
    // A Git shallow marker cuts ALL parent edges, even when just one parent
    // is excluded. Determine membership first, then boundaries, so parent/want
    // order cannot invent or erase a cut in a shared or merged history.
    let mut boundaries = BTreeSet::new();
    for &id in &included {
        work.tick()?;
        for &(parent, kind) in &object(objects, id)?.edges {
            work.tick()?;
            if kind == ObjectType::Commit && !included.contains(&parent) {
                work.insert(&mut boundaries, id)?;
                break;
            }
        }
    }
    let mut update = ShallowUpdate {
        shallow: Vec::new(),
        unshallow: Vec::new(),
    };
    update
        .shallow
        .try_reserve_exact(boundaries.len())
        .map_err(|_| budget())?;
    update
        .unshallow
        .try_reserve_exact(old.len())
        .map_err(|_| budget())?;
    for &id in &boundaries {
        work.tick()?;
        if !old.contains(&id) {
            update.shallow.push(id);
        }
    }
    for &id in &old {
        work.tick()?;
        if included.contains(&id) && !boundaries.contains(&id) {
            update.unshallow.push(id);
        }
    }
    work.tick()?;
    Ok(History {
        old,
        boundaries,
        update,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::PackOptions;
    struct Graph {
        objects: BTreeMap<GitOid, FilterObject>,
        format: GitHashAlgorithm,
        next: usize,
    }
    impl Graph {
        fn new(format: GitHashAlgorithm) -> Self {
            Self {
                objects: BTreeMap::new(),
                format,
                next: 1,
            }
        }
        fn add(
            &mut self,
            kind: ObjectType,
            time: Option<i64>,
            edges: Vec<(GitOid, ObjectType)>,
        ) -> GitOid {
            let width = self.format.digest_len() * 2;
            let id = GitOid::from_hex(self.format, &format!("{:0width$x}", self.next)).unwrap();
            self.next += 1;
            self.objects.insert(
                id,
                FilterObject {
                    kind,
                    size: 10,
                    edges,
                    commit_time: time,
                },
            );
            id
        }
        fn commit(&mut self, time: i64, parents: &[GitOid]) -> [GitOid; 3] {
            let blob = self.add(ObjectType::Blob, None, vec![]);
            let tree = self.add(ObjectType::Tree, None, vec![(blob, ObjectType::Blob)]);
            let mut edges = vec![(tree, ObjectType::Tree)];
            edges.extend(parents.iter().map(|id| (*id, ObjectType::Commit)));
            [self.add(ObjectType::Commit, Some(time), edges), tree, blob]
        }
    }
    fn request(want: GitOid, since: Option<i64>, not: Vec<GitOid>) -> PackRequest {
        PackRequest {
            version: UploadPackVersion::V2,
            wants: vec![want],
            haves: vec![],
            shallows: vec![],
            deepen: None,
            deepen_since: since,
            deepen_not: not,
            filter: None,
            options: PackOptions::NONE,
        }
    }
    fn selected(graph: &Graph, request: &PackRequest) -> BTreeSet<GitOid> {
        select(&graph.objects, request, &PackLimits::default(), &mut || {
            true
        })
        .unwrap()
        .into_iter()
        .collect()
    }
    fn update(graph: &Graph, request: &PackRequest) -> ShallowUpdate {
        boundary_update(&graph.objects, request, &PackLimits::default(), &mut || {
            true
        })
        .unwrap()
    }
    #[test]
    fn time_is_inclusive_and_an_older_cutoff_restores_missing_ancestry() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let mut graph = Graph::new(format);
            let root = graph.commit(10, &[]);
            let mid = graph.commit(20, &[root[0]]);
            let tip = graph.commit(30, &[mid[0]]);
            let mut req = request(tip[0], Some(20), vec![]);
            assert_eq!(selected(&graph, &req), tip.into_iter().chain(mid).collect());
            assert_eq!(update(&graph, &req).shallow, vec![mid[0]]);
            req.haves = vec![tip[0]];
            req.shallows = vec![mid[0]];
            req.deepen_since = Some(10);
            assert_eq!(selected(&graph, &req), root.into_iter().collect());
            assert_eq!(
                update(&graph, &req),
                ShallowUpdate {
                    shallow: vec![],
                    unshallow: vec![mid[0]]
                }
            );
        }
    }
    #[test]
    fn ref_exclusions_union_and_combine_with_dates_without_object_subtraction() {
        let mut graph = Graph::new(GitHashAlgorithm::Sha256);
        let root = graph.commit(10, &[]);
        let mid = graph.commit(20, &[root[0]]);
        let tip = graph.commit(30, &[mid[0]]);
        let tag = graph.add(ObjectType::Tag, None, vec![(root[0], ObjectType::Commit)]);
        let outer = graph.add(ObjectType::Tag, None, vec![(tag, ObjectType::Tag)]);
        let req = request(tip[0], Some(20), vec![outer, root[0], outer]);
        assert_eq!(selected(&graph, &req), tip.into_iter().chain(mid).collect());
        assert_eq!(update(&graph, &req).shallow, vec![mid[0]]);
        let req = request(tip[0], None, vec![mid[0], outer]);
        assert_eq!(selected(&graph, &req), tip.into_iter().collect());
        assert_eq!(update(&graph, &req).shallow, vec![tip[0]]);
    }
    #[test]
    fn merge_cut_severs_all_parent_edges_but_an_independent_want_keeps_its_history() {
        let mut graph = Graph::new(GitHashAlgorithm::Sha1);
        let root = graph.commit(10, &[]);
        let left = graph.commit(30, &[root[0]]);
        let right = graph.commit(15, &[root[0]]);
        let merge = graph.commit(40, &[left[0], right[0]]);
        let mut req = request(merge[0], Some(20), vec![]);
        assert_eq!(selected(&graph, &req), merge.into_iter().collect());
        assert!(update(&graph, &req).shallow.contains(&merge[0]));
        req.wants.push(left[0]);
        let expected = merge.into_iter().chain(left).collect();
        assert_eq!(selected(&graph, &req), expected);
        req.wants.reverse();
        assert_eq!(selected(&graph, &req), expected);
    }
    #[test]
    fn clock_inversion_is_not_a_license_to_walk_through_an_old_commit() {
        let mut graph = Graph::new(GitHashAlgorithm::Sha1);
        let root = graph.commit(90, &[]);
        let old = graph.commit(10, &[root[0]]);
        let tip = graph.commit(100, &[old[0]]);
        let req = request(tip[0], Some(50), vec![]);
        assert_eq!(selected(&graph, &req), tip.into_iter().collect());
        assert_eq!(update(&graph, &req).shallow, vec![tip[0]]);
    }
    #[test]
    fn unusable_dates_refuse_time_requests_but_not_ref_only_fetches() {
        let mut graph = Graph::new(GitHashAlgorithm::Sha1);
        let root = graph.commit(10, &[]);
        let tip = graph.commit(20, &[root[0]]);
        graph.objects.get_mut(&tip[0]).unwrap().commit_time = None;
        assert!(matches!(
            select(
                &graph.objects,
                &request(tip[0], Some(10), vec![]),
                &PackLimits::default(),
                &mut || true
            ),
            Err(NodePackMaterializationRefusal::DisclosureGraph(
                RefusalCode::ObjectHeaderInvalid
            ))
        ));
        assert_eq!(
            selected(&graph, &request(tip[0], None, vec![root[0]])),
            tip.into_iter().collect()
        );
    }
    #[test]
    fn empty_history_invalid_roots_and_mixed_controls_never_fall_back_to_full_pack() {
        let mut graph = Graph::new(GitHashAlgorithm::Sha256);
        let root = graph.commit(10, &[]);
        for mut req in [
            request(root[0], Some(11), vec![]),
            request(root[0], None, vec![root[0]]),
            request(root[0], None, vec![root[2]]),
        ] {
            assert!(select(&graph.objects, &req, &PackLimits::default(), &mut || true).is_err());
            req.deepen = Some(2);
            assert!(select(&graph.objects, &req, &PackLimits::default(), &mut || true).is_err());
        }
    }
    #[test]
    fn every_cutoff_checkpoint_is_cancellable_and_all_walks_share_one_work_budget() {
        let mut graph = Graph::new(GitHashAlgorithm::Sha256);
        let root = graph.commit(10, &[]);
        let tip = graph.commit(20, &[root[0]]);
        let req = request(tip[0], Some(20), vec![root[0]]);
        let mut calls = 0;
        select(&graph.objects, &req, &PackLimits::default(), &mut || {
            calls += 1;
            true
        })
        .unwrap();
        for stop in 1..=calls {
            let mut seen = 0;
            assert!(
                select(&graph.objects, &req, &PackLimits::default(), &mut || {
                    seen += 1;
                    seen < stop
                })
                .is_err()
            );
        }
        let limits = PackLimits {
            max_delta_work: calls - 1,
            ..PackLimits::default()
        };
        assert!(select(&graph.objects, &req, &limits, &mut || true).is_err());
        assert!(
            select(
                &graph.objects,
                &req,
                &PackLimits {
                    max_delta_work: calls,
                    ..limits
                },
                &mut || true
            )
            .is_ok()
        );
    }
    #[test]
    fn committer_date_is_observed_without_normalizing_or_trusting_headers() {
        use fgit_git_object::{AcceptanceProfile, ParseLimits, parse_commit};
        for (suffix, expected) in [
            ("1700000000 +0000", Some(1700000000)),
            ("-1 -0400", Some(-1)),
            ("bad +0000", None),
            ("1700000000 bad", None),
        ] {
            let body = format!(
                "tree {}\ncommitter Name <email> {suffix}\n\nraw\r\n",
                "1".repeat(40)
            );
            let commit = parse_commit(
                body.as_bytes(),
                AcceptanceProfile::GitCompatibleImport,
                &ParseLimits::default(),
            )
            .unwrap();
            assert_eq!(
                committer_time(&ParsedObject::Commit(commit.clone())),
                expected
            );
            assert_eq!(commit.as_bytes(), body.as_bytes());
        }
        let body = format!(
            "tree {}\ncommitter A <a> 1 +0000\ncommitter B <b> 2 +0000\n\n",
            "1".repeat(40)
        );
        let commit = parse_commit(
            body.as_bytes(),
            AcceptanceProfile::GitCompatibleImport,
            &ParseLimits::default(),
        )
        .unwrap();
        assert_eq!(committer_time(&ParsedObject::Commit(commit)), None);
    }
}
