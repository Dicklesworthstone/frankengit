use super::*;
use fgit_crypto::{GitObjectKind, git_object_id};
use std::cell::Cell;

fn blob(format: GitHashAlgorithm, bytes: &[u8]) -> GitOid {
    git_object_id(format, GitObjectKind::Blob, bytes)
}
fn collect(format: GitHashAlgorithm, channels: &[(ContextChannel, Vec<&[u8]>)], limit: usize) -> ContextRanking {
    let id = blob(format, b"native source\n");
    let mut accumulator = Accumulator::default();
    for (channel, paths) in channels {
        accumulator.add(*channel, paths.iter().map(|path| (*path, id)), format, &|| false).unwrap();
    }
    accumulator.finish(limit, &|| false).unwrap()
}

#[test]
fn corroborated_late_path_wins_with_exact_fixed_point_contributions() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let result = collect(format, &[
            (ContextChannel::Content, vec![b"00.txt", b"z/Thing.rs"]),
            (ContextChannel::Path, vec![b"z/Thing.rs"]),
            (ContextChannel::Symbol, vec![b"z/Thing.rs", b"z/Thing.rs"]),
        ], 1);
        assert_eq!(result.candidate_files(), 2);
        let selected = &result.selected()[0];
        assert_eq!(selected.path(), b"z/Thing.rs");
        assert_eq!(selected.score_q16(), 65_536 / 62 + 65_536 / 61 + 131_072 / 61);
        assert_eq!(selected.contributions().iter().map(|r| (r.channel(), r.document_rank(), r.score_q16())).collect::<Vec<_>>(),
            vec![(ContextChannel::Content, 2, 1057), (ContextChannel::Path, 1, 1074), (ContextChannel::Symbol, 1, 2148)]);
    }
}

#[test]
fn repeated_declarations_do_not_amplify_or_displace_distinct_document_ranks() {
    let channels = [(ContextChannel::Symbol, vec![b"a.rs".as_slice(), b"z.rs"])];
    let expected = collect(GitHashAlgorithm::Sha1, &channels, 32);
    let mut repeated = vec![b"a.rs".as_slice(); MAX_CHANNEL_HITS - 1];
    repeated.push(b"z.rs");
    assert_eq!(collect(GitHashAlgorithm::Sha1, &[(ContextChannel::Symbol, repeated)], 32), expected);
    assert_eq!(expected.selected()[1].contributions()[0].document_rank(), 2);
}

#[test]
fn channel_arrival_order_does_not_change_receipts_and_ties_use_raw_bytes() {
    let channels = vec![
        (ContextChannel::Content, vec![b"raw\xff.rs".as_slice()]),
        (ContextChannel::Path, vec![b"raw\xfe.rs".as_slice()]),
        (ContextChannel::Symbol, vec![]),
    ];
    let first = collect(GitHashAlgorithm::Sha256, &channels, 32);
    let mut reversed = channels; reversed.reverse();
    assert_eq!(collect(GitHashAlgorithm::Sha256, &reversed, 32), first);
    assert_eq!(first.selected()[0].path(), b"raw\xfe.rs");
    assert_eq!(first.selected()[0].score_q16(), first.selected()[1].score_q16());
    let prefix = collect(GitHashAlgorithm::Sha256, &reversed, 1);
    assert_eq!(prefix.candidate_files(), first.candidate_files());
    assert_eq!(prefix.selected(), &first.selected()[..1]);
}

#[test]
fn identity_conflicts_are_checked_even_for_repeated_or_unselected_paths() {
    let format = GitHashAlgorithm::Sha256;
    let one = blob(format, b"one"); let two = blob(format, b"two");
    let mut accumulator = Accumulator::default();
    assert!(matches!(accumulator.add(ContextChannel::Symbol,
        [(b"a.rs".as_slice(), one), (b"a.rs", two)], format, &|| false), Err(RetrievalError::MixedSource)));
    let mut accumulator = Accumulator::default();
    accumulator.add(ContextChannel::Content, [(b"z.rs".as_slice(), one)], format, &|| false).unwrap();
    assert!(matches!(accumulator.add(ContextChannel::Path, [(b"z.rs".as_slice(), two)], format, &|| false),
        Err(RetrievalError::MixedSource)));
    let mut accumulator = Accumulator::default();
    assert!(accumulator.add(ContextChannel::Path, [(b"a.rs".as_slice(), blob(GitHashAlgorithm::Sha1, b"one"))], format, &|| false).is_err());
}

#[test]
fn invalid_paths_reordered_inputs_and_duplicate_channels_never_become_rankings() {
    let format = GitHashAlgorithm::Sha1; let id = blob(format, b"source");
    for paths in [vec![b"z.rs".as_slice(), b"a.rs"], vec![b"../secret"], vec![b""]] {
        assert!(Accumulator::default().add(ContextChannel::Content,
            paths.into_iter().map(|path| (path, id)), format, &|| false).is_err());
    }
    let mut accumulator = Accumulator::default();
    accumulator.add(ContextChannel::Path, [(b"a.rs".as_slice(), id)], format, &|| false).unwrap();
    assert!(accumulator.add(ContextChannel::Path, [(b"a.rs".as_slice(), id)], format, &|| false).is_err());
}

#[test]
fn channel_cardinality_and_cancelled_sort_have_permitted_twins() {
    let format = GitHashAlgorithm::Sha1; let id = blob(format, b"source");
    let paths: Vec<_> = (0..=MAX_CHANNEL_HITS).map(|n| format!("file{n:04}.rs").into_bytes()).collect();
    let mut allowed = Accumulator::default();
    allowed.add(ContextChannel::Content, paths[..MAX_CHANNEL_HITS].iter().map(|p| (p.as_slice(), id)), format, &|| false).unwrap();
    assert_eq!(allowed.finish(32, &|| false).unwrap().candidate_files(), MAX_CHANNEL_HITS);
    assert!(matches!(Accumulator::default().add(ContextChannel::Content, paths.iter().map(|p| (p.as_slice(), id)), format, &|| false),
        Err(RetrievalError::Limit("fusion channel hits"))));
    let probes = Cell::new(0);
    assert!(Accumulator::default().add(ContextChannel::Content, paths.iter().map(|p| (p.as_slice(), id)), format,
        &|| { probes.set(probes.get() + 1); probes.get() > 3 }).is_err());
    let mut accumulator = Accumulator::default();
    accumulator.add(ContextChannel::Content, [(b"a.rs".as_slice(), id)], format, &|| false).unwrap();
    assert!(accumulator.finish(1, &|| true).is_err());
    assert!(Accumulator::default().finish(0, &|| false).is_err());
    assert!(Accumulator::default().finish(33, &|| false).is_err());
    assert_eq!(Accumulator::default().finish(1, &|| false).unwrap().candidate_files(), 0);
}

#[test]
fn path_storage_has_a_shared_preallocation_ceiling() {
    let format = GitHashAlgorithm::Sha1; let id = blob(format, b"source");
    let mut accumulator = Accumulator { path_bytes: MAX_PATH_BYTES - 4, ..Default::default() };
    accumulator.add(ContextChannel::Content, [(b"a.rs".as_slice(), id)], format, &|| false).unwrap();
    // A second channel can reuse existing metadata at the exact limit.
    accumulator.add(ContextChannel::Path, [(b"a.rs".as_slice(), id)], format, &|| false).unwrap();
    assert!(matches!(accumulator.add(ContextChannel::Symbol, [(b"b.rs".as_slice(), id)], format, &|| false),
        Err(RetrievalError::Limit("fusion path bytes"))));
}
