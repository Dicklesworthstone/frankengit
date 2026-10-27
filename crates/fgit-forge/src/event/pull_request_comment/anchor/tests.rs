use super::*;
use crate::event::pull_request_comment::PullRequestCommentCommand;
use crate::preparation::CommitInput;
use crate::{ExpectedVersion, ForgeEvent, ForgeEventPayload, PullRequestNumber};
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_crypto::{GitObjectKind, git_object_id};
use fgit_types::{GitHashAlgorithm, PrincipalId};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Default)]
struct Source {
    commits: BTreeMap<GitOid, CommitInput>,
    trees: BTreeMap<GitOid, Vec<MergeEntry>>,
    blobs: BTreeMap<GitOid, Vec<u8>>,
    polls: Cell<usize>,
    stop: Cell<Option<usize>>,
}
impl MergeObjectSource for Source {
    fn checkpoint(&self) -> Result<(), MergeSourceError> {
        let poll = self.polls.get();
        self.polls.set(poll + 1);
        if self.stop.get() == Some(poll) {
            Err(MergeSourceError::Cancelled)
        } else {
            Ok(())
        }
    }
    fn commit(&self, id: GitOid) -> Result<CommitInput, MergeSourceError> {
        self.checkpoint()?;
        self.commits
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn tree(&self, id: GitOid) -> Result<Vec<MergeEntry>, MergeSourceError> {
        self.checkpoint()?;
        self.trees
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
    fn blob(&self, id: GitOid) -> Result<Vec<u8>, MergeSourceError> {
        self.checkpoint()?;
        self.blobs
            .get(&id)
            .cloned()
            .ok_or(MergeSourceError::Unavailable(id))
    }
}
impl Source {
    fn commit_with(
        &mut self,
        format: GitHashAlgorithm,
        content: &[u8],
        mode: u32,
        parents: &[GitOid],
    ) -> (GitOid, GitOid) {
        let blob = git_object_id(format, GitObjectKind::Blob, content);
        self.blobs.insert(blob, content.to_vec());
        let mut body = format!("{mode:o} text\0").into_bytes();
        body.extend(blob.as_bytes());
        let tree = git_object_id(format, GitObjectKind::Tree, &body);
        self.trees.insert(
            tree,
            vec![MergeEntry {
                name: b"text".to_vec(),
                mode,
                oid: blob,
            }],
        );
        let mut body = format!("tree {tree}\n");
        for parent in parents {
            writeln!(body, "parent {parent}").unwrap();
        }
        body.push_str("author Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nsource anchor\n");
        let commit = git_object_id(format, GitObjectKind::Commit, body.as_bytes());
        self.commits.insert(
            commit,
            CommitInput {
                tree,
                parents: parents.to_vec(),
            },
        );
        (commit, blob)
    }
}
fn fixture(
    format: GitHashAlgorithm,
    old: &[u8],
    new: &[u8],
    mode: u32,
) -> (Source, SourceCommentAnchor) {
    let mut source = Source::default();
    let (base, _) = source.commit_with(format, old, mode, &[]);
    let (tip, blob) = source.commit_with(format, new, mode, &[base]);
    let anchor = SourceCommentAnchor {
        pull_request_version: AggregateVersion::FIRST,
        source_ref: RefName::try_new(b"refs/heads/topic").unwrap(),
        target_ref: RefName::try_new(b"refs/heads/main").unwrap(),
        source_tip: tip,
        target_tip: base,
        compared_base: base,
        comparison: SourceCommentComparison::MergeBase,
        path: b"text".to_vec(),
        side: SourceCommentSide::After,
        blob,
        mode,
        byte_start: 0,
        byte_end: new
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(new.len(), |n| n + 1) as u64,
        line_start: 0,
        line_count: 1,
    };
    (source, anchor)
}

#[test]
fn exact_lf_crlf_unicode_and_raw_bytes_are_preserved_on_both_sides_and_formats() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [0o100644, 0o100755, 0o120000] {
            let (source, mut anchor) = fixture(
                format,
                b"old\r\n\xff\nlast",
                "new\r\né\nlast".as_bytes(),
                mode,
            );
            anchor.verify_source(&source).unwrap();
            anchor.byte_start = 5;
            anchor.byte_end = 8;
            anchor.line_start = 1;
            anchor.verify_source(&source).unwrap();
            anchor.byte_start = 8;
            anchor.byte_end = 12;
            anchor.line_start = 2;
            anchor.verify_source(&source).unwrap();
            anchor.side = SourceCommentSide::Before;
            anchor.blob = source.trees[&source.commits[&anchor.compared_base].tree][0].oid;
            anchor.byte_start = 5;
            anchor.byte_end = 7;
            anchor.line_start = 1;
            anchor.verify_source(&source).unwrap();
            anchor.comparison = SourceCommentComparison::Direct;
            anchor.verify_source(&source).unwrap();
        }
    }
}

#[test]
fn forged_line_byte_identity_base_and_path_coordinates_fail_beside_valid_twin() {
    let (source, original) = fixture(
        GitHashAlgorithm::Sha256,
        b"old\nlast\n",
        b"new\nlast\n",
        0o100644,
    );
    for mutation in 0..13 {
        original.verify_source(&source).unwrap();
        let mut anchor = original.clone();
        match mutation {
            0 => anchor.byte_end -= 1,
            1 => {
                anchor.byte_start = 1;
                anchor.line_start = 1;
            }
            2 => anchor.line_count = 2,
            3 => {
                anchor.byte_start = 9;
                anchor.byte_end = 10;
                anchor.line_start = 2;
            }
            4 => anchor.blob = anchor.source_tip,
            5 => anchor.mode = 0o100755,
            6 => anchor.path = b"elsewhere".to_vec(),
            7 => anchor.side = SourceCommentSide::Before,
            8 => anchor.compared_base = anchor.source_tip,
            9 => anchor.target_tip = anchor.source_tip,
            10 => anchor.path = b"../text".to_vec(),
            11 => anchor.path = b"text/child".to_vec(),
            _ => anchor.mode = 0o160000,
        }
        assert_eq!(
            anchor.verify_source(&source),
            Err(SourceCommentError::Invalid),
            "mutation {mutation}"
        );
    }
}

#[test]
fn binary_comparison_sides_and_duplicate_or_malformed_tree_entries_never_anchor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for mode in [0o100644, 0o120000] {
            for (before, after) in [
                (b"old\0\n".as_slice(), b"new\n".as_slice()),
                (b"old\n".as_slice(), b"new\0\n".as_slice()),
            ] {
                let (source, anchor) = fixture(format, before, after, mode);
                assert_eq!(
                    anchor.verify_source(&source),
                    Err(SourceCommentError::Invalid)
                );
            }
        }
        for mutation in 0..4 {
            let (mut source, anchor) = fixture(format, b"old\n", b"new\n", 0o100644);
            anchor.verify_source(&source).unwrap();
            let values = source
                .trees
                .get_mut(&source.commits[&anchor.source_tip].tree)
                .unwrap();
            match mutation {
                0 => values.push(values[0].clone()),
                1 => values[0].name = b"bad/name".to_vec(),
                2 => values[0].name = b"..".to_vec(),
                _ => values[0].mode = 0o100777,
            }
            assert_eq!(
                anchor.verify_source(&source),
                Err(SourceCommentError::Invalid)
            );
        }
    }
}

#[test]
fn missing_inputs_single_checkpoint_cancellation_and_resource_limits_do_not_succeed() {
    let (mut source, anchor) = fixture(GitHashAlgorithm::Sha1, b"old\n", b"new\n", 0o100644);
    source.polls.set(0);
    anchor.verify_source(&source).unwrap();
    let polls = source.polls.get();
    for stop in 0..polls {
        source.polls.set(0);
        source.stop.set(Some(stop));
        assert_eq!(
            anchor.verify_source(&source),
            Err(SourceCommentError::Source(MergeSourceError::Cancelled)),
            "checkpoint {stop}"
        );
    }
    source.stop.set(None);
    anchor.verify_source(&source).unwrap();
    let bytes = source.blobs.remove(&anchor.blob).unwrap();
    assert_eq!(
        anchor.verify_source(&source),
        Err(SourceCommentError::Source(MergeSourceError::Unavailable(
            anchor.blob
        )))
    );
    source.blobs.insert(anchor.blob, bytes);
    anchor.verify_source(&source).unwrap();
    let huge = vec![b'x'; MAX_SOURCE_COMMENT_BLOB_BYTES as usize + 1];
    let (source, mut anchor) = fixture(GitHashAlgorithm::Sha1, b"old\n", &huge, 0o100644);
    anchor.byte_end = MAX_SOURCE_COMMENT_SPAN_BYTES;
    assert_eq!(
        anchor.verify_source(&source),
        Err(SourceCommentError::Budget)
    );
    let exact = vec![b'x'; MAX_SOURCE_COMMENT_SPAN_BYTES as usize];
    let (source, anchor) = fixture(GitHashAlgorithm::Sha1, b"old", &exact, 0o100644);
    anchor.verify_source(&source).unwrap();
    let too_wide = vec![b'x'; MAX_SOURCE_COMMENT_SPAN_BYTES as usize + 1];
    let (source, anchor) = fixture(GitHashAlgorithm::Sha1, b"old", &too_wide, 0o100644);
    assert_eq!(
        anchor.verify_source(&source),
        Err(SourceCommentError::Invalid)
    );
}

#[test]
fn anchored_kind_fifteen_roundtrips_without_reinterpreting_plain_kind_twelve() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (_, anchor) = fixture(format, b"old\n", b"new\n", 0o100644);
        let command = PullRequestCommentCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            body: "Exact source comment\n".into(),
            anchor: Some(anchor),
        };
        let event = command
            .proposed_event(PrincipalId::from_bytes([7; 16]))
            .unwrap();
        assert_eq!(event.payload.kind(), 15);
        let encoded = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for end in 0..encoded.len() {
            assert!(decode_body::<ForgeEvent>(&encoded[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut plain = event.clone();
        let ForgeEventPayload::PullRequestCommentedNative(comment) = &mut plain.payload else {
            panic!("comment");
        };
        comment.anchor = None;
        assert_eq!(plain.payload.kind(), 12);
        let bytes = encode_body(&plain).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&bytes, DecodeLimits::DEFAULT).unwrap(),
            plain
        );
        assert_ne!(bytes, encoded);
    }
}

#[test]
fn status_preserves_original_coordinates_and_never_heuristically_reattaches() {
    let (_, anchor) = fixture(GitHashAlgorithm::Sha1, b"old\n", b"new\n", 0o100644);
    let data = PullRequestData {
        source_ref: anchor.source_ref.clone(),
        target_ref: anchor.target_ref.clone(),
        source_tip: anchor.source_tip,
        target_tip: anchor.target_tip,
        title: "PR".into(),
        body: String::new(),
    };
    assert_eq!(
        anchor.status(AggregateVersion::FIRST, &data),
        SourceCommentStatus::Exact
    );
    assert_eq!(
        anchor.status(AggregateVersion::try_new(2).unwrap(), &data),
        SourceCommentStatus::Outdated
    );
    let mut moved = data;
    moved.source_ref = RefName::try_new(b"refs/heads/other").unwrap();
    assert_eq!(
        anchor.status(AggregateVersion::FIRST, &moved),
        SourceCommentStatus::Outdated
    );
}

#[test]
fn ambiguous_or_absent_merge_base_and_unchanged_paths_have_no_fabricated_anchor() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let (source, anchor) = fixture(format, b"same\n", b"same\n", 0o100644);
        assert_eq!(
            anchor.verify_source(&source),
            Err(SourceCommentError::Invalid)
        );
        let (mut source, mut anchor) = fixture(format, b"root\n", b"initial\n", 0o100644);
        let root = anchor.target_tip;
        let (a, _) = source.commit_with(format, b"a\n", 0o100644, &[root]);
        let (b, _) = source.commit_with(format, b"b\n", 0o100644, &[root]);
        let (target, _) = source.commit_with(format, b"target\n", 0o100644, &[a, b]);
        let (incoming, blob) = source.commit_with(format, b"source\n", 0o100644, &[b, a]);
        anchor.target_tip = target;
        anchor.source_tip = incoming;
        anchor.blob = blob;
        anchor.byte_end = 7;
        anchor.compared_base = a;
        assert_eq!(
            anchor.verify_source(&source),
            Err(SourceCommentError::Invalid)
        );
        // Direct is an explicit usable comparison of these same immutable tips;
        // it does not silently choose either ambiguous merge base.
        anchor.comparison = SourceCommentComparison::Direct;
        anchor.compared_base = target;
        anchor.verify_source(&source).unwrap();
        let (unrelated, _) = source.commit_with(format, b"unrelated\n", 0o100644, &[]);
        anchor.target_tip = unrelated;
        anchor.compared_base = unrelated;
        anchor.comparison = SourceCommentComparison::MergeBase;
        assert_eq!(
            anchor.verify_source(&source),
            Err(SourceCommentError::Invalid)
        );
    }
}
