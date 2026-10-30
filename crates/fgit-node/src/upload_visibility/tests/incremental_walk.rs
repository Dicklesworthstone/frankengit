//! A walk seeded with an earlier walk's facts equals an unseeded walk, reads
//! only what the earlier walk never read, and refuses exactly where an
//! unseeded walk refuses (frankengit-8g42).
use super::*;

struct History {
    source: MemorySource,
    before: Vec<GitOid>,
    after: Vec<GitOid>,
    shared: GitOid,
}

/// Two ref views of one history: the later adds a commit, a tree and a blob,
/// names a former root blob through a tree, adds a blob root that the earlier
/// view reached only through a tree, and drops a root. Trees carry a gitlink
/// (charged but never walked) and one blob under two names.
fn history(format: GitHashAlgorithm) -> History {
    let mut source = MemorySource::new(format);
    let readme = source.put(ObjectType::Blob, b"readme\n".to_vec());
    let shared = source.put(ObjectType::Blob, b"shared\n".to_vec());
    let lib = source.put(ObjectType::Blob, b"lib\n".to_vec());
    let raw = source.put(ObjectType::Blob, b"a blob ref\n".to_vec());
    let elsewhere = git_object_id(
        format,
        crypto_object_kind(ObjectType::Commit),
        b"another repository's commit",
    );
    let sub = source.tree(&[
        (b"100644", b"copy.txt", shared),
        (b"100644", b"shared.txt", shared),
    ]);
    let tree1 = source.tree(&[
        (b"100644", b"README", readme),
        (b"160000", b"module", elsewhere),
        (b"40000", b"sub", sub),
    ]);
    let first = source.commit(tree1, &[]);
    let tree2 = source.tree(&[
        (b"100644", b"README", readme),
        (b"100644", b"lib.rs", lib),
        (b"160000", b"module", elsewhere),
        (b"40000", b"sub", sub),
    ]);
    let second = source.commit(tree2, &[first]);
    let tag = source.put(ObjectType::Tag, tag_bytes(second, "commit"));
    let fresh = source.put(ObjectType::Blob, b"new file\n".to_vec());
    let tree3 = source.tree(&[
        (b"100644", b"README", readme),
        (b"100644", b"lib.rs", lib),
        (b"160000", b"module", elsewhere),
        (b"100644", b"new.txt", fresh),
        (b"100644", b"raw", raw),
        (b"40000", b"sub", sub),
    ]);
    let third = source.commit(tree3, &[second]);
    History {
        source,
        before: vec![second, tag, raw],
        after: vec![third, tag, lib],
        shared,
    }
}

fn walk(
    source: &MemorySource,
    roots: &[GitOid],
    limits: &PackLimits,
    seed: Option<&VisibleGraph>,
) -> Result<VisibleGraph, NodePackMaterializationRefusal> {
    let memo = seed.map(|graph| ProjectionMemo {
        objects: &graph.objects,
        facts: &graph.facts,
    });
    walk_visible_graph(
        source,
        &source.admitted(),
        roots.iter().copied(),
        limits,
        memo.as_ref(),
    )
}

fn walk_with_edges(
    source: &MemorySource,
    roots: &[GitOid],
    edge_budget: usize,
    seed: Option<&VisibleGraph>,
) -> Result<VisibleGraph, NodePackMaterializationRefusal> {
    let memo = seed.map(|graph| ProjectionMemo {
        objects: &graph.objects,
        facts: &graph.facts,
    });
    walk_within_edge_budget(
        source,
        &source.admitted(),
        roots.iter().copied(),
        &PackLimits::default(),
        edge_budget,
        memo.as_ref(),
    )
}

fn take_reads(source: &MemorySource) -> (BTreeSet<GitOid>, BTreeSet<GitOid>) {
    (
        source.reads.borrow_mut().drain(..).collect(),
        source.header_reads.borrow_mut().drain(..).collect(),
    )
}

#[test]
fn a_seeded_walk_equals_an_unseeded_one_and_reads_only_what_was_never_read() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let History {
            source,
            before,
            after,
            shared,
        } = history(format);
        let limits = PackLimits::default();
        let earlier = walk(&source, &before, &limits, None).unwrap();
        take_reads(&source);
        let fresh = walk(&source, &after, &limits, None).unwrap();
        let (fresh_reads, fresh_headers) = take_reads(&source);
        let seeded = walk(&source, &after, &limits, Some(&earlier)).unwrap();
        let (seeded_reads, seeded_headers) = take_reads(&source);

        assert_eq!(seeded, fresh);
        let unread = fresh_reads
            .iter()
            .filter(|id| !earlier.facts.contains_key(id))
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(seeded_reads, unread);
        let unseen = fresh_headers
            .iter()
            .filter(|id| !earlier.objects.contains_key(id))
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(seeded_headers, unseen);
        assert!(
            seeded_reads.len() + seeded_headers.len() < fresh_reads.len() + fresh_headers.len(),
            "the later view shares most of its history with the earlier one"
        );
        // One blob under two names keeps the smaller hint either way.
        assert_eq!(
            fresh.path_hashes.get(&shared),
            Some(&basename_path_hash(b"copy.txt").min(basename_path_hash(b"shared.txt")))
        );
        // A seed with no overlap is an unseeded walk.
        take_reads(&source);
        let unrelated = walk(&source, &before, &limits, Some(&fresh)).unwrap();
        assert_eq!(unrelated, earlier);
    }
}

#[test]
fn a_seeded_walk_refuses_exactly_where_an_unseeded_walk_refuses() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let History {
            source,
            before,
            after,
            ..
        } = history(format);
        let earlier = walk(&source, &before, &PackLimits::default(), None).unwrap();
        let complete = walk(&source, &after, &PackLimits::default(), None).unwrap();
        let whole_bytes = complete
            .facts
            .keys()
            .map(|id| complete.objects[id].size)
            .sum::<usize>();
        let mut refusals = 0;
        let mut compare = |limits: PackLimits, what: String| {
            let fresh = walk(&source, &after, &limits, None);
            let seeded = walk(&source, &after, &limits, Some(&earlier));
            refusals += usize::from(fresh.is_err());
            assert_eq!(format!("{seeded:?}"), format!("{fresh:?}"), "{what}");
        };
        // The byte envelope also bounds the edge budget, so this sweep crosses
        // refusals inside an object's edge charges as well as between objects.
        for budget in 0..=whole_bytes + 1 {
            compare(
                PackLimits {
                    max_total_expanded_bytes: budget,
                    ..PackLimits::default()
                },
                format!("expanded bytes {budget}"),
            );
        }
        for entries in 0..=u32::try_from(complete.objects.len()).unwrap() + 1 {
            compare(
                PackLimits {
                    max_entries: entries,
                    ..PackLimits::default()
                },
                format!("entries {entries}"),
            );
        }
        let largest = complete
            .objects
            .values()
            .map(|object| object.size)
            .max()
            .unwrap();
        for object_bytes in 0..=largest + 1 {
            compare(
                PackLimits {
                    max_object_bytes: object_bytes,
                    ..PackLimits::default()
                },
                format!("object bytes {object_bytes}"),
            );
        }
        // The edge budget is the byte envelope capped at 4,000,000 edges, so a
        // byte sweep never makes it bind; sweep it on its own, through every
        // object's charges (a tree's gitlink included).
        let charged = complete
            .facts
            .values()
            .map(|facts| facts.charged)
            .sum::<usize>();
        for edge_budget in 0..=charged + 1 {
            let fresh = walk_with_edges(&source, &after, edge_budget, None);
            let seeded = walk_with_edges(&source, &after, edge_budget, Some(&earlier));
            refusals += usize::from(fresh.is_err());
            assert_eq!(
                format!("{seeded:?}"),
                format!("{fresh:?}"),
                "edge budget {edge_budget}"
            );
        }
        assert!(refusals > 0, "the sweeps must cross refusals");
    }
}
