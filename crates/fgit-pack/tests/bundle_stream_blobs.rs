#![forbid(unsafe_code)]
//! Large native blobs use bounded readers without weakening either bundle
//! profile's original identity, graph, resource or completion obligations.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{self, Cursor};

use fgit_crypto::{GitObjectHasher, NativeObjectIdentity, Sha1, Sha256};
use fgit_git_object::ObjectType;
use fgit_pack::full_bundle::stream::{
    STREAM_FULL_BUNDLE_PROFILE, STREAM_INCREMENTAL_BUNDLE_PROFILE, StreamFullBundleError,
    StreamFullBundleLimits, StreamFullBundleReceipt, write_full_bundle_stream,
    write_incremental_bundle_stream,
};
use fgit_pack::full_bundle::{FullBundleError, FullBundleHeader};
use fgit_pack::{
    BundleReference, CanonicalBlobReader, CanonicalBlobStream, CanonicalObjectSource,
    CanonicalPackObject, Deadline, EntryKind, ObjectFormat, ObjectId, PackError, PackOrderKey,
    PackWriteError, StreamPackEvent, read_streamed_pack_chunks,
};
use fgit_types::RefName;

const CHUNK: usize = 16 * 1024;

enum NativeHash {
    Sha1(GitObjectHasher<Sha1>),
    Sha256(GitObjectHasher<Sha256>),
}
impl NativeHash {
    fn new(format: ObjectFormat, kind: ObjectType, length: usize) -> Self {
        match format {
            ObjectFormat::Sha1 => Self::Sha1(GitObjectHasher::new(kind, length as u64)),
            ObjectFormat::Sha256 => Self::Sha256(GitObjectHasher::new(kind, length as u64)),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hash) => hash.update(bytes).unwrap(),
            Self::Sha256(hash) => hash.update(bytes).unwrap(),
        }
    }
    fn finish(self) -> ObjectId {
        match self {
            Self::Sha1(hash) => hash.finish().unwrap().erase(),
            Self::Sha256(hash) => hash.finish().unwrap().erase(),
        }
    }
}

enum Payload {
    Bytes(Vec<u8>),
    Repeated { byte: u8, length: usize },
}
impl Payload {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Repeated { length, .. } => *length,
        }
    }
    fn fill(&self, position: usize, output: &mut [u8]) {
        match self {
            Self::Bytes(bytes) => output.copy_from_slice(&bytes[position..position + output.len()]),
            Self::Repeated { byte, .. } => output.fill(*byte),
        }
    }
    fn id(&self, format: ObjectFormat) -> ObjectId {
        let mut hash = NativeHash::new(format, ObjectType::Blob, self.len());
        let mut chunk = [0; CHUNK];
        let mut offset = 0;
        while offset < self.len() {
            let count = chunk.len().min(self.len() - offset);
            self.fill(offset, &mut chunk[..count]);
            hash.update(&chunk[..count]);
            offset += count;
        }
        hash.finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Fault {
    #[default]
    None,
    Corrupt,
    Short,
    Extra,
    Overflow,
    Read,
    Eof,
}

struct Source {
    metadata: BTreeMap<ObjectId, CanonicalPackObject>,
    blobs: BTreeMap<ObjectId, Payload>,
    streaming: bool,
    fragment: usize,
    key: Option<PackOrderKey>,
    declared: Option<usize>,
    fault: Fault,
    pulse_on_open: bool,
    pulse_on_read: Option<usize>,
    pulse: Cell<bool>,
    loads: RefCell<Vec<ObjectId>>,
    opened: RefCell<Vec<ObjectId>>,
    reads: Cell<usize>,
    maximum_read: Cell<usize>,
    active: Cell<usize>,
}
impl Source {
    fn new() -> Self {
        Self {
            metadata: BTreeMap::new(),
            blobs: BTreeMap::new(),
            streaming: true,
            fragment: usize::MAX,
            key: None,
            declared: None,
            fault: Fault::None,
            pulse_on_open: false,
            pulse_on_read: None,
            pulse: Cell::new(false),
            loads: RefCell::new(Vec::new()),
            opened: RefCell::new(Vec::new()),
            reads: Cell::new(0),
            maximum_read: Cell::new(0),
            active: Cell::new(0),
        }
    }
    fn blob(&mut self, format: ObjectFormat, payload: Payload) -> ObjectId {
        let id = payload.id(format);
        self.blobs.insert(id, payload);
        id
    }
    fn object(&mut self, format: ObjectFormat, kind: ObjectType, body: Vec<u8>) -> ObjectId {
        let id = fgit_crypto::git_object_id(format, kind, &body);
        self.metadata
            .insert(id, CanonicalPackObject::new(id, kind, body, vec![], 0, 0));
        id
    }
    fn ids(&self) -> Vec<ObjectId> {
        self.metadata
            .keys()
            .chain(self.blobs.keys())
            .copied()
            .collect()
    }
    fn reset_observations(&self) {
        assert_eq!(self.active.get(), 0);
        self.loads.borrow_mut().clear();
        self.opened.borrow_mut().clear();
        self.reads.set(0);
        self.maximum_read.set(0);
        self.pulse.set(false);
    }
}

struct Reader<'a> {
    source: &'a Source,
    payload: &'a Payload,
    position: usize,
}
impl Drop for Reader<'_> {
    fn drop(&mut self) {
        assert_eq!(self.source.active.replace(0), 1);
    }
}
impl CanonicalBlobReader for Reader<'_> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, PackWriteError> {
        let reads = self.source.reads.get() + 1;
        self.source.reads.set(reads);
        self.source
            .maximum_read
            .set(self.source.maximum_read.get().max(output.len()));
        if self.source.pulse_on_read == Some(reads) {
            self.source.pulse.set(true);
        }
        match self.source.fault {
            Fault::Overflow => return Ok(output.len() + 1),
            Fault::Read => return Err(PackWriteError::TemporaryReadRefused),
            Fault::Eof if self.position == self.payload.len() => {
                return Err(PackWriteError::TemporaryReadRefused);
            }
            _ => {}
        }
        let length = match self.source.fault {
            Fault::Short => self.payload.len().saturating_sub(1),
            Fault::Extra => self.payload.len() + 1,
            _ => self.payload.len(),
        };
        let count = output
            .len()
            .min(self.source.fragment)
            .min(length - self.position);
        let original = count.min(self.payload.len().saturating_sub(self.position));
        self.payload.fill(
            self.position.min(self.payload.len()),
            &mut output[..original],
        );
        output[original..count].fill(0x5a);
        if self.source.fault == Fault::Corrupt && self.position == 0 && count != 0 {
            output[0] ^= 1;
        }
        self.position += count;
        Ok(count)
    }
}
impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        assert_eq!(
            self.active.get(),
            0,
            "previous reader survived to the next source call"
        );
        self.loads.borrow_mut().push(*id);
        if let Some(object) = self.metadata.get(id) {
            return Ok(object.clone());
        }
        assert!(
            !self.streaming,
            "a streamed blob must never use buffered load"
        );
        let payload = self
            .blobs
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        assert!(
            payload.len() <= 1024 * 1024,
            "test fallback must not allocate a large blob"
        );
        let mut body = vec![0; payload.len()];
        payload.fill(0, &mut body);
        Ok(CanonicalPackObject::new(
            *id,
            ObjectType::Blob,
            body,
            vec![],
            0,
            0,
        ))
    }
    fn open_blob(&self, id: &ObjectId) -> Result<Option<CanonicalBlobStream<'_>>, PackWriteError> {
        assert_eq!(
            self.active.get(),
            0,
            "previous reader survived to the next source call"
        );
        self.opened.borrow_mut().push(*id);
        if self.pulse_on_open {
            self.pulse.set(true);
        }
        if !self.streaming {
            return Ok(None);
        }
        let Some(payload) = self.blobs.get(id) else {
            return Ok(None);
        };
        self.active.set(1);
        Ok(Some(CanonicalBlobStream::new(
            self.key.unwrap_or(PackOrderKey {
                id: *id,
                object_type: ObjectType::Blob,
                recency: 19,
                path_hash: 31,
            }),
            self.declared.unwrap_or_else(|| payload.len()),
            Reader {
                source: self,
                payload,
                position: 0,
            },
        )))
    }
}

struct Fixture {
    format: ObjectFormat,
    source: Source,
    refs: Vec<BundleReference>,
    base: Option<ObjectId>,
    external: BTreeMap<ObjectId, ObjectType>,
}
fn reference(id: ObjectId, name: &[u8]) -> BundleReference {
    BundleReference::new(id, RefName::try_new(name).unwrap())
}
fn commit(tree: ObjectId, parent: Option<ObjectId>) -> Vec<u8> {
    let parent = parent.map_or_else(String::new, |id| format!("parent {id}\n"));
    format!("tree {tree}\n{parent}author A <a@example.invalid> 1 +0000\ncommitter A <a@example.invalid> 1 +0000\n\nstreamed\n").into_bytes()
}
fn fixture(format: ObjectFormat, incremental: bool, payloads: Vec<Payload>) -> Fixture {
    let mut source = Source::new();
    let mut tree = Vec::new();
    for (index, payload) in payloads.into_iter().enumerate() {
        let id = source.blob(format, payload);
        tree.extend_from_slice(format!("100644 file{index:03}\0").as_bytes());
        tree.extend_from_slice(id.as_bytes());
    }
    let mut external = BTreeMap::new();
    let base = if incremental {
        let empty_tree = fgit_crypto::git_object_id(format, ObjectType::Tree, b"");
        let base =
            fgit_crypto::git_object_id(format, ObjectType::Commit, &commit(empty_tree, None));
        external.insert(empty_tree, ObjectType::Tree);
        external.insert(base, ObjectType::Commit);
        Some(base)
    } else {
        None
    };
    let tree = source.object(format, ObjectType::Tree, tree);
    let tip = source.object(format, ObjectType::Commit, commit(tree, base));
    Fixture {
        format,
        source,
        refs: vec![reference(tip, b"refs/heads/main")],
        base,
        external,
    }
}
fn raw_fixture(format: ObjectFormat, length: usize) -> Fixture {
    let mut source = Source::new();
    let id = source.blob(format, Payload::Repeated { byte: 0x73, length });
    Fixture {
        format,
        source,
        refs: vec![reference(id, b"refs/tags/raw")],
        base: None,
        external: BTreeMap::new(),
    }
}
fn export(
    fixture: &Fixture,
    limits: &StreamFullBundleLimits,
    live: &mut impl Deadline,
) -> Result<(Vec<u8>, StreamFullBundleReceipt), StreamFullBundleError> {
    let mut output = Vec::new();
    let ids = fixture.source.ids();
    let receipt = if let Some(base) = fixture.base {
        write_incremental_bundle_stream(
            fixture.format,
            &fixture.refs,
            &[base],
            &ids,
            &fixture.external,
            &fixture.source,
            limits,
            live,
            &mut output,
        )?
    } else {
        write_full_bundle_stream(
            fixture.format,
            &fixture.refs,
            None,
            &ids,
            &fixture.source,
            limits,
            live,
            &mut output,
        )?
    };
    Ok((output, receipt))
}

#[test]
fn both_profiles_keep_exact_bytes_and_work_across_short_reads_and_chunk_boundaries() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        for incremental in [false, true] {
            let mut fixture = fixture(
                format,
                incremental,
                [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 37]
                    .into_iter()
                    .map(|length| Payload::Bytes((0..length).map(|n| (n % 251) as u8).collect()))
                    .collect(),
            );
            let limits = StreamFullBundleLimits::default();
            fixture.source.streaming = false;
            let baseline = export(&fixture, &limits, &mut || true).unwrap();
            fixture.source.streaming = true;
            for fragment in [1, 7, CHUNK - 1, CHUNK, 2 * CHUNK] {
                fixture.source.fragment = fragment;
                fixture.source.reset_observations();
                let streamed = export(&fixture, &limits, &mut || true).unwrap();
                assert_eq!(
                    streamed, baseline,
                    "{format:?} incremental={incremental}, fragment={fragment}"
                );
                assert_eq!(fixture.source.active.get(), 0);
                assert!(fixture.source.maximum_read.get() <= CHUNK);
                assert!(
                    fixture
                        .source
                        .loads
                        .borrow()
                        .iter()
                        .all(|id| fixture.source.metadata.contains_key(id))
                );
                let mut sorted = fixture.source.ids();
                sorted.sort_unstable();
                assert_eq!(*fixture.source.opened.borrow(), sorted);
            }
        }
    }
}

#[test]
fn blobs_above_32_mib_round_trip_in_both_domains_and_bundle_profiles_without_buffered_load() {
    let length = 32 * 1024 * 1024 + 37;
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        for incremental in [false, true] {
            let fixture = fixture(
                format,
                incremental,
                vec![Payload::Repeated { byte: 0x73, length }],
            );
            let mut limits = StreamFullBundleLimits::default();
            limits.pack.max_object_bytes = 4096;
            assert!(matches!(export(&fixture, &limits, &mut || true),
                Err(StreamFullBundleError::Bundle(FullBundleError::Pack(PackError::ObjectSizeLimit { actual, limit })))
                if actual == length && limit == 32 * 1024 * 1024));
            assert_eq!(fixture.source.reads.get(), 0);
            fixture.source.reset_observations();
            limits.max_streamed_blob_bytes = length;
            let (bytes, receipt) = export(&fixture, &limits, &mut || true).unwrap();
            assert_eq!(
                receipt.profile_id(),
                if incremental {
                    STREAM_INCREMENTAL_BUNDLE_PROFILE
                } else {
                    STREAM_FULL_BUNDLE_PROFILE
                }
            );
            assert_eq!(receipt.bundle_sha256(), fgit_crypto::sha256_digest(&bytes));
            assert_eq!(
                receipt.total_object_bytes(),
                length
                    + fixture
                        .source
                        .metadata
                        .values()
                        .map(|object| object.body().len())
                        .sum::<usize>()
            );
            assert_eq!(fixture.source.active.get(), 0);
            assert!(fixture.source.maximum_read.get() <= CHUNK);
            assert_eq!(
                fixture.source.loads.borrow().len(),
                fixture.source.metadata.len()
            );

            let mut input = Cursor::new(&bytes);
            let header = if incremental {
                FullBundleHeader::read_incremental(&mut input, limits.envelope, &mut || true)
            } else {
                FullBundleHeader::read(&mut input, limits.envelope, &mut || true)
            }
            .unwrap();
            assert_eq!(header.format(), format);
            let mut pending: Option<(NativeHash, ObjectType, usize)> = None;
            let mut recovered = Vec::new();
            let verified = read_streamed_pack_chunks(
                &mut input,
                format,
                &limits.pack,
                limits.max_streamed_blob_bytes,
                &mut || true,
                |event| -> Result<(), io::Error> {
                    match event {
                        StreamPackEvent::Begin(start) => {
                            assert!(pending.is_none());
                            assert!(!matches!(
                                start.header.kind,
                                EntryKind::OfsDelta | EntryKind::RefDelta
                            ));
                            let kind =
                                fgit_pack::object_type_from_base_entry(start.header.kind).unwrap();
                            pending = Some((
                                NativeHash::new(format, kind, start.header.declared_size),
                                kind,
                                0,
                            ));
                        }
                        StreamPackEvent::Data(bytes) => {
                            assert!(bytes.len() <= CHUNK);
                            let (hash, kind, count) = pending.as_mut().unwrap();
                            if *kind == ObjectType::Blob {
                                assert!(bytes.iter().all(|byte| *byte == 0x73));
                            }
                            *count += bytes.len();
                            hash.update(bytes);
                        }
                        StreamPackEvent::End(_) => {
                            let (hash, kind, count) = pending.take().unwrap();
                            let id = hash.finish();
                            if kind == ObjectType::Blob {
                                assert_eq!(count, length);
                                assert!(fixture.source.blobs.contains_key(&id));
                            } else {
                                assert!(fixture.source.metadata.contains_key(&id));
                            }
                            recovered.push(id);
                        }
                    }
                    Ok(())
                },
            )
            .unwrap();
            let mut sorted = fixture.source.ids();
            sorted.sort_unstable();
            assert_eq!(recovered, sorted);
            assert_eq!(verified.trailer(), receipt.pack_checksum());
            assert_eq!(verified.pack_bytes() as usize, receipt.pack_bytes());
            assert_eq!(input.position() as usize, bytes.len());
        }
    }
}

#[test]
fn blob_metadata_aggregate_and_output_limits_are_independent_with_exact_permitted_twins() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        for incremental in [false, true] {
            let fixture = fixture(
                format,
                incremental,
                vec![Payload::Repeated {
                    byte: 0x73,
                    length: 2 * CHUNK + 37,
                }],
            );
            let baseline = StreamFullBundleLimits::default();
            let (_, receipt) = export(&fixture, &baseline, &mut || true).unwrap();
            let mut exact = baseline;
            exact.max_streamed_blob_bytes = 2 * CHUNK + 37;
            exact.pack.max_object_bytes = fixture
                .source
                .metadata
                .values()
                .map(|object| object.body().len())
                .max()
                .unwrap();
            exact.pack.max_total_expanded_bytes = receipt.total_object_bytes();
            exact.pack.max_input_bytes = receipt.pack_bytes();
            exact.envelope.max_bundle_bytes = receipt.bundle_bytes();
            exact.max_compression_work = receipt.compression_work();
            exact.max_graph_edges = if incremental { 3 } else { 2 };
            assert_eq!(export(&fixture, &exact, &mut || true).unwrap().1, receipt);
            let reductions: [fn(&mut StreamFullBundleLimits); 7] = [
                |limits| limits.max_streamed_blob_bytes -= 1,
                |limits| limits.pack.max_object_bytes -= 1,
                |limits| limits.pack.max_total_expanded_bytes -= 1,
                |limits| limits.pack.max_input_bytes -= 1,
                |limits| limits.envelope.max_bundle_bytes -= 1,
                |limits| limits.max_compression_work -= 1,
                |limits| limits.max_graph_edges -= 1,
            ];
            for reduce in reductions {
                let mut refused = exact.clone();
                reduce(&mut refused);
                assert!(
                    export(&fixture, &refused, &mut || true).is_err(),
                    "{refused:?}"
                );
                assert_eq!(fixture.source.active.get(), 0);
            }
        }

        let mut fixture = raw_fixture(format, 37);
        fixture.source.streaming = false;
        let mut limits = StreamFullBundleLimits::default();
        limits.pack.max_object_bytes = 36;
        limits.max_streamed_blob_bytes = 1024;
        assert!(matches!(
            export(&fixture, &limits, &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::ObjectSizeLimit {
                    actual: 37,
                    limit: 36
                }
            )))
        ));
        limits.pack.max_object_bytes = 37;
        limits.max_streamed_blob_bytes = 36;
        assert!(matches!(
            export(&fixture, &limits, &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::ObjectSizeLimit {
                    actual: 37,
                    limit: 36
                }
            )))
        ));
        limits.max_streamed_blob_bytes = 37;
        export(&fixture, &limits, &mut || true).unwrap();
    }
}

#[test]
fn forged_reader_metadata_refuses_before_payload_reads_and_drops_the_reader() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let mut fixture = raw_fixture(format, 37);
        let requested = *fixture.refs[0].target();
        let key = PackOrderKey {
            id: requested,
            object_type: ObjectType::Blob,
            recency: 19,
            path_hash: 31,
        };
        let other = fgit_crypto::git_object_id(format, ObjectType::Blob, b"other");
        let limits = StreamFullBundleLimits::default();
        fixture.source.key = Some(PackOrderKey { id: other, ..key });
        assert!(matches!(
            export(&fixture, &limits, &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Write(
                PackWriteError::SourceIdentityMismatch { .. }
            )))
        ));
        assert_eq!(fixture.source.reads.get(), 0);
        assert_eq!(fixture.source.active.get(), 0);
        fixture.source.key = Some(PackOrderKey {
            object_type: ObjectType::Commit,
            ..key
        });
        assert!(matches!(export(&fixture, &limits, &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Write(PackWriteError::SourceOrderMismatch(id)))) if id == requested));
        assert_eq!(fixture.source.reads.get(), 0);
        assert_eq!(fixture.source.active.get(), 0);
        fixture.source.key = None;
        fixture.source.declared = Some(limits.max_streamed_blob_bytes + 1);
        assert!(matches!(
            export(&fixture, &limits, &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::ObjectSizeLimit { .. }
            )))
        ));
        assert_eq!(fixture.source.reads.get(), 0);
        assert_eq!(fixture.source.active.get(), 0);
        fixture.source.declared = None;
        export(&fixture, &limits, &mut || true).unwrap();
    }
}

#[test]
fn short_growing_corrupt_overflowing_and_failed_reader_completion_never_issue_a_receipt() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let mut fixture = raw_fixture(format, CHUNK + 37);
        fixture.source.fragment = 7;
        let limits = StreamFullBundleLimits::default();
        for fault in [
            Fault::Short,
            Fault::Extra,
            Fault::Corrupt,
            Fault::Overflow,
            Fault::Read,
            Fault::Eof,
        ] {
            fixture.source.fault = fault;
            fixture.source.reset_observations();
            let error = export(&fixture, &limits, &mut || true).unwrap_err();
            let StreamFullBundleError::Bundle(FullBundleError::Write(error)) = error else {
                panic!("unexpected source refusal for {fault:?}: {error:?}");
            };
            match fault {
                Fault::Short | Fault::Extra => {
                    assert!(matches!(error, PackWriteError::SourceLengthMismatch { .. }))
                }
                Fault::Corrupt => assert_eq!(
                    error,
                    PackWriteError::Pack(PackError::NativeObjectIdMismatch)
                ),
                Fault::Overflow => {
                    assert!(matches!(error, PackWriteError::SourceReadOverflow { .. }))
                }
                Fault::Read | Fault::Eof => assert_eq!(error, PackWriteError::TemporaryReadRefused),
                Fault::None => unreachable!(),
            }
            assert_eq!(fixture.source.active.get(), 0);
            assert!(fixture.source.loads.borrow().is_empty());
            fixture.source.fault = Fault::None;
            export(&fixture, &limits, &mut || true).unwrap();
        }
        // An advertised length is neither a hash override nor permission to
        // silently truncate a source that really contains more bytes.
        for declared in [0, CHUNK + 36, CHUNK + 38] {
            fixture.source.declared = Some(declared);
            assert!(matches!(
                export(&fixture, &limits, &mut || true),
                Err(StreamFullBundleError::Bundle(FullBundleError::Write(
                    PackWriteError::SourceLengthMismatch { .. }
                )))
            ));
            assert_eq!(fixture.source.active.get(), 0);
        }
    }
}

#[test]
fn cancellation_after_open_each_read_and_exact_eof_drops_custody_and_permits_a_fresh_retry() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let mut fixture = raw_fixture(format, CHUNK + 37);
        fixture.source.fragment = 7;
        let limits = StreamFullBundleLimits::default();
        let baseline = export(&fixture, &limits, &mut || true).unwrap();
        let last_read = fixture.source.reads.get();
        fixture.source.reset_observations();
        fixture.source.pulse_on_open = true;
        assert!(matches!(
            export(&fixture, &limits, &mut || !fixture
                .source
                .pulse
                .replace(false)),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::DeadlineExceeded
            )))
        ));
        assert_eq!(fixture.source.reads.get(), 0);
        assert_eq!(fixture.source.active.get(), 0);
        fixture.source.pulse_on_open = false;
        for read in [1, 2, last_read] {
            fixture.source.reset_observations();
            fixture.source.pulse_on_read = Some(read);
            assert!(matches!(
                export(&fixture, &limits, &mut || !fixture
                    .source
                    .pulse
                    .replace(false)),
                Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                    PackError::DeadlineExceeded
                )))
            ));
            assert_eq!(fixture.source.reads.get(), read);
            assert_eq!(fixture.source.active.get(), 0);
            fixture.source.pulse_on_read = None;
            assert_eq!(export(&fixture, &limits, &mut || true).unwrap(), baseline);
        }
        fixture.source.reset_observations();
        fixture.source.pulse_on_read = Some(1);
        fixture.source.fault = Fault::Read;
        assert!(matches!(
            export(&fixture, &limits, &mut || !fixture
                .source
                .pulse
                .replace(false)),
            Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                PackError::DeadlineExceeded
            )))
        ));
        assert_eq!(fixture.source.active.get(), 0);
    }
}

#[test]
fn streamed_blob_kind_and_reachability_still_come_from_native_graph_bytes() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let mut fixture = raw_fixture(format, 37);
        let blob = *fixture.refs[0].target();
        fixture.refs = vec![reference(blob, b"refs/heads/main")];
        assert!(matches!(
            export(&fixture, &StreamFullBundleLimits::default(), &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
                "branch target kind"
            )))
        ));
        fixture.refs = vec![reference(blob, b"refs/tags/raw")];
        let extra = fixture
            .source
            .blob(format, Payload::Bytes(b"unreachable".to_vec()));
        assert!(
            matches!(export(&fixture, &StreamFullBundleLimits::default(), &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::UnreachableObject(id))) if id == extra)
        );
        fixture.source.blobs.remove(&extra);
        let mut body = b"40000 directory\0".to_vec();
        body.extend_from_slice(blob.as_bytes());
        let tree = fixture.source.object(format, ObjectType::Tree, body);
        fixture.refs = vec![reference(tree, b"refs/tags/tree")];
        assert!(matches!(
            export(&fixture, &StreamFullBundleLimits::default(), &mut || true),
            Err(StreamFullBundleError::Bundle(FullBundleError::Invalid(
                "graph edge target kind"
            )))
        ));
        assert_eq!(fixture.source.active.get(), 0);
    }
}
