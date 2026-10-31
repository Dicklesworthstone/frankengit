//! Native blob verification without an object-sized graph input allocation.
use std::fmt;

use fgit_crypto::{GitObjectHasher, NativeObjectIdentity, Sha1, Sha256};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::{GraphRefusal, ObjectGraphAudit, ObjectKind, checkpoint};

const CHUNK_BYTES: usize = 64 * 1024;

/// Preserve a storage reader's typed refusal without converting it into
/// apparently successful graph evidence. Either error poisons the audit.
#[derive(Debug)]
pub enum BlobGraphError<E> {
    Graph(GraphRefusal),
    Reader(E),
}
impl<E: fmt::Display> fmt::Display for BlobGraphError<E> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graph(error) => fmt::Display::fmt(error, out),
            Self::Reader(error) => write!(out, "graph_blob_reader: {error}"),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for BlobGraphError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Graph(error) => Some(error),
            Self::Reader(error) => Some(error),
        }
    }
}
impl<E> From<GraphRefusal> for BlobGraphError<E> {
    fn from(error: GraphRefusal) -> Self {
        Self::Graph(error)
    }
}

impl ObjectGraphAudit {
    /// Observe one selected blob through a bounded reader. This method owns
    /// native identity verification: a caller-supplied ID/length is never a
    /// verification token. The reader returns zero only at exact EOF, after
    /// completing any storage-side strong commitment checks. The audit checks
    /// declared length, native SHA-1/SHA-256 identity and EOF independently.
    ///
    /// `max_blob_bytes` is an explicit streaming-only allowance; metadata still
    /// uses `GraphLimits::max_object_bytes`. The normal selected order, object
    /// count and aggregate payload limit apply. No body bytes are retained by
    /// the audit. An error or cancellation poisons it, including a reader error
    /// after all declared bytes have been delivered.
    pub fn observe_blob_stream<E>(
        &mut self,
        id: GitOid,
        declared_length: usize,
        max_blob_bytes: usize,
        read_chunk: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BlobGraphError<E>> {
        if self.failed {
            return Err(GraphRefusal::Failed.into());
        }
        let result =
            self.observe_blob_stream_inner(id, declared_length, max_blob_bytes, read_chunk, live);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn observe_blob_stream_inner<E>(
        &mut self,
        id: GitOid,
        declared_length: usize,
        max_blob_bytes: usize,
        read_chunk: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
        live: &mut impl FnMut() -> bool,
    ) -> Result<(), BlobGraphError<E>> {
        checkpoint(live)?;
        if self.nodes.get(self.next).map(|node| node.id) != Some(id) {
            return Err(GraphRefusal::ObjectOrder.into());
        }
        if declared_length > max_blob_bytes {
            return Err(GraphRefusal::Limit("object bytes").into());
        }
        let payload_bytes = self
            .payload_bytes
            .checked_add(declared_length as u64)
            .filter(|total| *total <= self.limits.max_payload_bytes)
            .ok_or(GraphRefusal::Limit("payload bytes"))?;
        match self.format {
            GitHashAlgorithm::Sha1 => verify_blob::<Sha1, E>(id, declared_length, read_chunk, live),
            GitHashAlgorithm::Sha256 => {
                verify_blob::<Sha256, E>(id, declared_length, read_chunk, live)
            }
        }?;
        checkpoint(live)?;
        let node = &mut self.nodes[self.next];
        node.kind = Some(ObjectKind::Blob);
        node.start = self.edges.len();
        node.end = self.edges.len();
        self.next += 1;
        self.payload_bytes = payload_bytes;
        Ok(())
    }
}

fn verify_blob<A: fgit_crypto::GitHashAlgorithm, E>(
    id: GitOid,
    length: usize,
    read_chunk: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
    live: &mut impl FnMut() -> bool,
) -> Result<(), BlobGraphError<E>> {
    let mut hash = GitObjectHasher::<A>::new(ObjectKind::Blob, length as u64);
    let mut remaining = length;
    // Large inventories often contain many tiny blobs. Allocate only their
    // bounded body size while preserving a nonempty buffer for the EOF probe.
    let buffer_bytes = length.min(CHUNK_BYTES).max(1);
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(buffer_bytes)
        .map_err(|_| GraphRefusal::Allocation)?;
    buffer.resize(buffer_bytes, 0_u8);
    while remaining != 0 {
        checkpoint(live)?;
        let offered = remaining.min(buffer.len());
        let result = read_chunk(&mut buffer[..offered]);
        checkpoint(live)?;
        let count = result.map_err(BlobGraphError::Reader)?;
        if count == 0 || count > offered {
            return Err(GraphRefusal::IdentityMismatch(id).into());
        }
        hash.update(&buffer[..count])
            .map_err(|_| GraphRefusal::IdentityMismatch(id))?;
        remaining -= count;
    }
    // EOF is an explicit reader operation, even for empty blobs. A late
    // storage commitment failure must not be hidden by the declared length.
    checkpoint(live)?;
    let result = read_chunk(&mut buffer[..1]);
    checkpoint(live)?;
    if result.map_err(BlobGraphError::Reader)? != 0 {
        return Err(GraphRefusal::IdentityMismatch(id).into());
    }
    let actual = hash
        .finish()
        .map_err(|_| GraphRefusal::IdentityMismatch(id))?
        .erase();
    if actual != id {
        return Err(GraphRefusal::IdentityMismatch(id).into());
    }
    checkpoint(live)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::GraphLimits;
    use super::*;
    use fgit_crypto::git_object_id;
    use std::collections::{BTreeMap, BTreeSet};
    use std::convert::Infallible;
    use std::io::{Cursor, Read};

    fn audit(format: GitHashAlgorithm, id: GitOid, total: u64) -> ObjectGraphAudit {
        ObjectGraphAudit::new(
            &BTreeSet::from([id]),
            format,
            GraphLimits {
                max_object_bytes: 16,
                max_payload_bytes: total,
                ..GraphLimits::default()
            },
            &mut || true,
        )
        .unwrap()
    }

    #[test]
    fn streamed_blob_matches_slice_audit_in_both_domains_without_widening_metadata() {
        let body = vec![b'w'; 150_000];
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let id = git_object_id(format, ObjectKind::Blob, &body);
            let mut actual = audit(format, id, body.len() as u64);
            let mut input = Cursor::new(&body);
            let mut reads = 0;
            actual
                .observe_blob_stream(
                    id,
                    body.len(),
                    body.len(),
                    &mut |out| {
                        assert!(out.len() <= CHUNK_BYTES);
                        reads += 1;
                        input.read(out)
                    },
                    &mut || true,
                )
                .unwrap();
            assert!(reads >= 4);
            let result = actual.finish(&BTreeMap::new(), &mut || true).unwrap();
            let mut expected = ObjectGraphAudit::new(
                &BTreeSet::from([id]),
                format,
                GraphLimits {
                    max_object_bytes: body.len(),
                    ..GraphLimits::default()
                },
                &mut || true,
            )
            .unwrap();
            expected
                .observe(id, ObjectKind::Blob, &body, &mut || true)
                .unwrap();
            assert_eq!(
                result,
                expected.finish(&BTreeMap::new(), &mut || true).unwrap()
            );
            let mut unchanged = audit(format, id, body.len() as u64);
            assert_eq!(
                unchanged.observe(id, ObjectKind::Blob, &body, &mut || true),
                Err(GraphRefusal::Limit("object bytes"))
            );
        }
    }

    #[test]
    fn short_extra_changed_and_late_refused_bodies_poison_the_graph() {
        let body = b"correct bytes";
        let id = git_object_id(GitHashAlgorithm::Sha256, ObjectKind::Blob, body);
        for supplied in [
            body[..body.len() - 1].to_vec(),
            [body.as_slice(), b"x"].concat(),
            b"wrong!! bytes".to_vec(),
        ] {
            let mut graph = audit(GitHashAlgorithm::Sha256, id, 100);
            let mut reader = Cursor::new(supplied);
            assert!(matches!(
                graph.observe_blob_stream(
                    id,
                    body.len(),
                    100,
                    &mut |out| reader.read(out),
                    &mut || true
                ),
                Err(BlobGraphError::Graph(GraphRefusal::IdentityMismatch(_)))
            ));
            assert_eq!(
                graph.finish(&BTreeMap::new(), &mut || true),
                Err(GraphRefusal::Failed)
            );
        }
        let mut graph = audit(GitHashAlgorithm::Sha256, id, 100);
        let mut reader = Cursor::new(body);
        let result = graph.observe_blob_stream(
            id,
            body.len(),
            100,
            &mut |out| {
                if reader.position() == body.len() as u64 {
                    Err("strong-commitment")
                } else {
                    Ok(reader.read(out).unwrap())
                }
            },
            &mut || true,
        );
        assert!(matches!(
            result,
            Err(BlobGraphError::Reader("strong-commitment"))
        ));
        assert_eq!(
            graph.finish(&BTreeMap::new(), &mut || true),
            Err(GraphRefusal::Failed)
        );
    }

    #[test]
    fn limits_precede_reads_and_empty_blob_still_requires_eof() {
        let body = b"abcd";
        let id = git_object_id(GitHashAlgorithm::Sha1, ObjectKind::Blob, body);
        for (per_blob, aggregate) in [(3, 4), (4, 3)] {
            let mut graph = audit(GitHashAlgorithm::Sha1, id, aggregate);
            let mut reads = 0;
            assert!(
                graph
                    .observe_blob_stream(
                        id,
                        body.len(),
                        per_blob,
                        &mut |_| {
                            reads += 1;
                            Ok::<_, Infallible>(0)
                        },
                        &mut || true
                    )
                    .is_err()
            );
            assert_eq!(reads, 0);
        }
        let empty = git_object_id(GitHashAlgorithm::Sha1, ObjectKind::Blob, b"");
        let mut graph = audit(GitHashAlgorithm::Sha1, empty, 0);
        let mut reads = 0;
        graph
            .observe_blob_stream(
                empty,
                0,
                0,
                &mut |out| {
                    assert_eq!(out.len(), 1);
                    reads += 1;
                    Ok::<_, Infallible>(0)
                },
                &mut || true,
            )
            .unwrap();
        assert_eq!(reads, 1);
        assert_eq!(
            graph
                .finish(&BTreeMap::new(), &mut || true)
                .unwrap()
                .payload_bytes,
            0
        );
    }

    #[test]
    fn tiny_blobs_bound_read_buffers_and_preserve_exact_eof_checks() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            for body in [b"".as_slice(), b"12345678".as_slice()] {
                let id = git_object_id(format, ObjectKind::Blob, body);
                let mut graph = audit(format, id, body.len() as u64);
                let mut input = Cursor::new(body);
                let mut offered = Vec::new();
                graph
                    .observe_blob_stream(
                        id,
                        body.len(),
                        body.len(),
                        &mut |out| {
                            offered.push(out.len());
                            input.read(out)
                        },
                        &mut || true,
                    )
                    .unwrap();
                assert_eq!(offered.last(), Some(&1));
                assert_eq!(offered.iter().max(), Some(&body.len().max(1)));
                graph.finish(&BTreeMap::new(), &mut || true).unwrap();

                let mut graph = audit(format, id, body.len() as u64);
                let mut input = Cursor::new([body, b"x"].concat());
                assert!(matches!(
                    graph.observe_blob_stream(
                        id,
                        body.len(),
                        body.len(),
                        &mut |out| input.read(out),
                        &mut || true,
                    ),
                    Err(BlobGraphError::Graph(GraphRefusal::IdentityMismatch(_)))
                ));
                assert_eq!(
                    graph.finish(&BTreeMap::new(), &mut || true),
                    Err(GraphRefusal::Failed)
                );

                let mut graph = audit(format, id, body.len() as u64);
                let mut input = Cursor::new(body);
                assert!(matches!(
                    graph.observe_blob_stream(
                        id,
                        body.len(),
                        body.len(),
                        &mut |out| {
                            if input.position() == body.len() as u64 {
                                Err("late storage refusal")
                            } else {
                                Ok(input.read(out).unwrap())
                            }
                        },
                        &mut || true,
                    ),
                    Err(BlobGraphError::Reader("late storage refusal"))
                ));
                assert_eq!(
                    graph.finish(&BTreeMap::new(), &mut || true),
                    Err(GraphRefusal::Failed)
                );
            }
        }
    }

    #[test]
    fn cancellation_inside_blob_reads_cannot_finish_a_partial_audit() {
        use std::cell::Cell;
        let body = vec![b'v'; 100_000];
        let id = git_object_id(GitHashAlgorithm::Sha256, ObjectKind::Blob, &body);
        let mut graph = audit(GitHashAlgorithm::Sha256, id, body.len() as u64);
        let cancelled = Cell::new(false);
        let mut input = Cursor::new(&body);
        let result = graph.observe_blob_stream(
            id,
            body.len(),
            body.len(),
            &mut |out| {
                let count = input.read(out);
                cancelled.set(true);
                count
            },
            &mut || !cancelled.get(),
        );
        assert!(matches!(
            result,
            Err(BlobGraphError::Graph(GraphRefusal::Cancelled))
        ));
        assert_eq!(
            graph.finish(&BTreeMap::new(), &mut || true),
            Err(GraphRefusal::Failed)
        );
    }
}
