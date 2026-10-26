use super::*;
use fgit_crypto::{GitObjectHasher, NativeObjectIdentity, Sha1, Sha256, git_object_id};
use fgit_treefs::integrity::GraphLimits;
use fgit_types::{GitHashAlgorithm, GitOid};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Cursor};

struct Repeated {
    remaining: usize,
    largest: usize,
    calls: usize,
}
impl Read for Repeated {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(out.len());
        self.calls += 1;
        let count = self.remaining.min(out.len()).min(4093);
        out[..count].fill(b'x');
        self.remaining -= count;
        Ok(count)
    }
}
fn repeated_id<A: fgit_crypto::GitHashAlgorithm>(length: usize) -> GitOid {
    let mut hash = GitObjectHasher::<A>::new(GitObjectKind::Blob, length as u64);
    let block = [b'x'; 4096];
    let mut remaining = length;
    while remaining != 0 {
        let count = remaining.min(block.len());
        hash.update(&block[..count]).unwrap();
        remaining -= count;
    }
    hash.finish().unwrap().erase()
}
fn audit(id: GitOid, payload: usize) -> ObjectGraphAudit {
    ObjectGraphAudit::new(
        &BTreeSet::from([id]),
        id.algorithm(),
        GraphLimits {
            max_payload_bytes: payload as u64,
            ..GraphLimits::default()
        },
        &mut || true,
    )
    .unwrap()
}
fn header(id: GitOid, kind: GitObjectKind, length: usize) -> RecordHeader {
    // Payload helper owns native graph verification; the archive reader owns
    // this independent commitment. These tests do not claim archive evidence.
    RecordHeader {
        oid: id,
        kind,
        length: length as u64,
        commitment: [0; 32],
    }
}

#[test]
fn selected_blobs_above_the_metadata_ceiling_stream_in_both_native_domains() {
    let length = MAX_OBJECT_BYTES + 17;
    for id in [repeated_id::<Sha1>(length), repeated_id::<Sha256>(length)] {
        let mut graph = audit(id, length);
        let mut reader = Repeated {
            remaining: length,
            largest: 0,
            calls: 0,
        };
        assert!(
            observe(
                &mut graph,
                header(id, GitObjectKind::Blob, length),
                &mut reader,
                length as u64,
                &mut || true
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(reader.remaining, 0);
        assert!(reader.largest <= 64 * 1024);
        assert!(
            reader.calls > 2,
            "short readers must be consumed to authenticated EOF"
        );
        let report = graph.finish(&BTreeMap::new(), &mut || true).unwrap();
        assert_eq!(report.payload_bytes, length as u64);
        assert_eq!(report.objects, 1);
        let mut refused = audit(id, length);
        reader.remaining = length;
        reader.calls = 0;
        assert!(
            observe(
                &mut refused,
                header(id, GitObjectKind::Blob, length),
                &mut reader,
                (length - 1) as u64,
                &mut || true
            )
            .is_err()
        );
        assert_eq!(reader.calls, 0, "blob ceiling precedes payload I/O");
        assert!(refused.finish(&BTreeMap::new(), &mut || true).is_err());
    }
}

#[test]
fn blob_allowance_never_widens_metadata_or_aggregate_bounds() {
    let small = b"blob";
    let id = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, small);
    let mut graph = audit(id, small.len() - 1);
    let mut reader = Cursor::new(small);
    assert!(
        observe(
            &mut graph,
            header(id, GitObjectKind::Blob, small.len()),
            &mut reader,
            1 << 40,
            &mut || true
        )
        .is_err()
    );
    assert_eq!(reader.position(), 0);
    let mut graph = audit(id, MAX_OBJECT_BYTES + 1);
    let mut reader = Cursor::new(small);
    assert!(
        observe(
            &mut graph,
            header(id, GitObjectKind::Commit, MAX_OBJECT_BYTES + 1),
            &mut reader,
            1 << 40,
            &mut || true
        )
        .unwrap_err()
        .contains("metadata object-byte")
    );
    assert_eq!(reader.position(), 0);
    let tree = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Tree, b"");
    let mut graph = audit(tree, 0);
    assert_eq!(
        observe(
            &mut graph,
            header(tree, GitObjectKind::Tree, 0),
            &mut Cursor::new(b""),
            1 << 40,
            &mut || true
        )
        .unwrap(),
        Some(Vec::new())
    );
    assert_eq!(
        graph
            .finish(&BTreeMap::new(), &mut || true)
            .unwrap()
            .objects,
        1
    );
}

#[test]
fn changed_short_and_late_failed_blob_readers_never_finish_the_graph() {
    let body = b"original";
    let id = git_object_id(GitHashAlgorithm::Sha1, GitObjectKind::Blob, body);
    for bad in [
        b"modified".as_slice(),
        b"orig".as_slice(),
        b"originalx".as_slice(),
    ] {
        let mut graph = audit(id, 100);
        assert!(
            observe(
                &mut graph,
                header(id, GitObjectKind::Blob, body.len()),
                &mut Cursor::new(bad),
                100,
                &mut || true
            )
            .is_err()
        );
        assert!(graph.finish(&BTreeMap::new(), &mut || true).is_err());
    }
    struct Late<'a>(&'a [u8]);
    impl Read for Late<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::other("strong commitment refused"));
            }
            self.0.read(out)
        }
    }
    let mut graph = audit(id, 100);
    assert!(
        observe(
            &mut graph,
            header(id, GitObjectKind::Blob, body.len()),
            &mut Late(body),
            100,
            &mut || true
        )
        .unwrap_err()
        .contains("strong commitment")
    );
    assert!(graph.finish(&BTreeMap::new(), &mut || true).is_err());
    let mut graph = audit(id, 100);
    let mut input = Cursor::new(body);
    assert!(
        observe(
            &mut graph,
            header(id, GitObjectKind::Blob, body.len()),
            &mut input,
            100,
            &mut || false
        )
        .is_err()
    );
    assert_eq!(input.position(), 0);
}

#[test]
fn buffered_metadata_also_requires_exact_authenticated_eof() {
    let id = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Tree, b"");
    let mut graph = audit(id, 0);
    assert!(
        observe(
            &mut graph,
            header(id, GitObjectKind::Tree, 0),
            &mut Cursor::new(b"x"),
            100,
            &mut || true
        )
        .is_err()
    );
    let body = b"text";
    let id = git_object_id(GitHashAlgorithm::Sha256, GitObjectKind::Blob, body);
    assert!(
        metadata(
            header(id, GitObjectKind::Blob, body.len()),
            &mut Cursor::new(body)
        )
        .unwrap_err()
        .contains("streaming custody")
    );
}
