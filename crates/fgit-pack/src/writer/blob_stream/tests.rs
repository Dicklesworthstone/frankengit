use super::*;
use std::cell::Cell;

use crate::{NativeChecksumVerifier, ScalarResolver, read_verified_pack};

#[derive(Default)]
struct Sink {
    created: usize,
    aborted: usize,
    writes: usize,
    published: Option<Vec<u8>>,
    fail_create: bool,
    fail_write: Option<usize>,
    fail_promote: bool,
}

impl PackArtifactSink for Sink {
    type Temporary = Vec<u8>;

    fn create_temporary(&mut self) -> Result<Self::Temporary, PackWriteError> {
        if self.fail_create {
            return Err(PackWriteError::TemporaryArtifactRefused);
        }
        self.created += 1;
        Ok(Vec::new())
    }

    fn write_temporary(
        &mut self,
        temporary: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        self.writes += 1;
        if self.fail_write == Some(self.writes) {
            return Err(PackWriteError::TemporaryWriteRefused);
        }
        temporary.extend_from_slice(bytes);
        Ok(())
    }

    fn promote_temporary(&mut self, temporary: &mut Vec<u8>) -> Result<(), PackWriteError> {
        if self.fail_promote {
            return Err(PackWriteError::PromotionRefused);
        }
        self.published = Some(std::mem::take(temporary));
        Ok(())
    }

    fn abort_temporary(&mut self, _: Vec<u8>) {
        self.aborted += 1;
    }
}

struct Source {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
    stream: bool,
    fragment: usize,
    declared: Option<usize>,
    key: Option<PackOrderKey>,
    corrupt: bool,
    fail_at: Option<usize>,
    overflow: bool,
    loads: Cell<usize>,
    reads: Cell<usize>,
}

impl Source {
    fn new(format: ObjectFormat, bodies: &[Vec<u8>]) -> Self {
        Self {
            objects: bodies
                .iter()
                .enumerate()
                .map(|(index, body)| {
                    let id = fgit_crypto::git_object_id(format, ObjectType::Blob, body);
                    (
                        id,
                        CanonicalPackObject::new(
                            id,
                            ObjectType::Blob,
                            body.clone(),
                            Vec::new(),
                            (bodies.len() - index) as u64,
                            0,
                        ),
                    )
                })
                .collect(),
            stream: true,
            fragment: usize::MAX,
            declared: None,
            key: None,
            corrupt: false,
            fail_at: None,
            overflow: false,
            loads: Cell::new(0),
            reads: Cell::new(0),
        }
    }

    fn keys(&self) -> Vec<PackOrderKey> {
        self.objects
            .values()
            .map(|object| PackOrderKey {
                id: object.id,
                object_type: object.object_type,
                recency: object.recency,
                path_hash: object.path_hash,
            })
            .collect()
    }
}

struct Reader<'a> {
    source: &'a Source,
    body: &'a [u8],
    position: usize,
}

impl CanonicalBlobReader for Reader<'_> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize, PackWriteError> {
        self.source.reads.set(self.source.reads.get() + 1);
        if self
            .source
            .fail_at
            .is_some_and(|stop| self.position >= stop)
        {
            return Err(PackWriteError::TemporaryReadRefused);
        }
        if self.source.overflow {
            return Ok(output.len() + 1);
        }
        let count = output
            .len()
            .min(self.source.fragment)
            .min(self.body.len() - self.position);
        output[..count].copy_from_slice(&self.body[self.position..self.position + count]);
        if self.source.corrupt && self.position == 0 && count != 0 {
            output[0] ^= 1;
        }
        self.position += count;
        Ok(count)
    }
}

impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        self.loads.set(self.loads.get() + 1);
        self.objects
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))
    }

    fn open_blob(&self, id: &ObjectId) -> Result<Option<CanonicalBlobStream<'_>>, PackWriteError> {
        if !self.stream {
            return Ok(None);
        }
        let object = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        let key = self.key.unwrap_or(PackOrderKey {
            id: *id,
            object_type: object.object_type,
            recency: object.recency,
            path_hash: object.path_hash,
        });
        Ok(Some(CanonicalBlobStream::new(
            key,
            self.declared.unwrap_or(object.body.len()),
            Reader {
                source: self,
                body: &object.body,
                position: 0,
            },
        )))
    }
}

fn profile() -> PackWriteProfile {
    PackWriteProfile {
        id: "test-pack-streaming-v1",
        stream_blob_threshold: Some(64),
        ..PackWriteProfile::COMPRESSED_V6
    }
}

fn limits() -> PackLimits {
    PackLimits {
        max_object_bytes: 4096,
        max_total_expanded_bytes: 8192,
        ..PackLimits::default()
    }
}

fn write(
    source: &Source,
    profile: PackWriteProfile,
    limits: PackLimits,
    sink: &mut Sink,
    deadline: &mut impl Deadline,
) -> Result<PackWriteReceipt, PackWriteError> {
    let format = source.objects.first_key_value().unwrap().0.algorithm();
    PackPlanner::new(format, profile, limits.clone()).stream_selected_thin(
        source,
        &source.keys(),
        &[],
        &PackWriter::new(limits),
        &mut DeterministicPackEncoder::for_profile(profile),
        sink,
        deadline,
    )
}

fn assert_aborted(sink: &Sink) {
    assert!(sink.published.is_none());
    assert_eq!(sink.created, sink.aborted);
}

#[test]
fn streamed_blobs_match_buffered_plans_across_short_reads_and_delta_barriers() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let bodies = [
            vec![b'a'; 64],
            [vec![b'a'; 63], vec![b'b']].concat(),
            vec![b'x'; 200],
            [vec![b'a'; 63], vec![b'c']].concat(),
            [vec![b'a'; 63], vec![b'd']].concat(),
        ];
        let mut source = Source::new(format, &bodies);
        let ids = source.objects.keys().copied().collect::<Vec<_>>();
        for profile in [
            profile(),
            PackWriteProfile {
                thin: true,
                ..profile()
            },
            PackWriteProfile {
                delta_window: 0,
                ..profile()
            },
        ] {
            let planner = PackPlanner::new(format, profile, limits());
            let plan = planner.plan_selected(&source, &ids, &mut || true).unwrap();
            let (expected, expected_receipt) = PackWriter::new(limits())
                .write(&plan, &mut || true)
                .unwrap();
            if profile.delta_window != 0 {
                assert!(plan.entries()[1].delta().is_some());
                assert!(plan.entries()[2].delta().is_none());
                assert!(
                    plan.entries()[3].delta().is_none(),
                    "the large blob clears older bases"
                );
                assert!(plan.entries()[4].delta().is_some());
            }
            for fragment in [1, 7, 63, 64, 257, usize::MAX] {
                source.fragment = fragment;
                let mut sink = Sink::default();
                let receipt = write(&source, profile, limits(), &mut sink, &mut || true).unwrap();
                assert_eq!(receipt, expected_receipt);
                assert_eq!(sink.published.as_ref().unwrap(), &expected);
                assert_eq!(sink.aborted, 0);
                let pack = read_verified_pack(
                    sink.published.as_ref().unwrap(),
                    format,
                    &limits(),
                    &mut || true,
                    &NativeChecksumVerifier,
                )
                .unwrap();
                let entries = pack
                    .entries()
                    .iter()
                    .zip(plan.entries())
                    .map(|(entry, planned)| (entry.offset, planned.object().id()))
                    .collect::<BTreeMap<_, _>>();
                let scalar = pack
                    .into_scalar_objects(|offset| entries.get(&offset).copied())
                    .unwrap();
                let bounds = limits();
                let resolver = ScalarResolver::new(&scalar, &(), &bounds, &mut || true).unwrap();
                for (offset, id) in entries {
                    let body = resolver.resolve_offset(offset, &mut || true).unwrap();
                    assert_eq!(body.as_slice(), source.objects[&id].body());
                    assert_eq!(
                        fgit_crypto::git_object_id(format, ObjectType::Blob, &body),
                        id
                    );
                }
            }
            source.stream = false;
            let mut sink = Sink::default();
            assert_eq!(
                write(&source, profile, limits(), &mut sink, &mut || true).unwrap(),
                expected_receipt
            );
            assert_eq!(sink.published.unwrap(), expected);
            source.stream = true;
        }
    }
}

#[test]
fn old_profiles_never_open_blob_streams_and_small_v6_output_stays_equal() {
    let source = Source::new(ObjectFormat::Sha1, &[vec![1; 40], vec![2; 40]]);
    for profile in [
        PackWriteProfile::COMPRESSED_V5,
        PackWriteProfile::COMPRESSED_NO_DELTA_V1,
    ] {
        let mut sink = Sink::default();
        write(&source, profile, limits(), &mut sink, &mut || true).unwrap();
        assert_eq!(source.reads.get(), 0);
        let bytes = sink.published.unwrap();
        let next = if profile.delta_window == 0 {
            PackWriteProfile::COMPRESSED_NO_DELTA_V2
        } else {
            PackWriteProfile::COMPRESSED_V6
        };
        let mut sink = Sink::default();
        write(&source, next, limits(), &mut sink, &mut || true).unwrap();
        assert_eq!(sink.published.unwrap(), bytes);
        source.reads.set(0);
    }
}

#[test]
fn malformed_streams_and_metadata_never_publish() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        for case in 0..9 {
            let mut source = Source::new(format, &[vec![42; 100]]);
            let mut key = source.keys()[0];
            match case {
                0 => source.declared = Some(99),
                1 => source.declared = Some(101),
                2 => source.corrupt = true,
                3 => source.fail_at = Some(0),
                4 => {
                    source.fragment = 17;
                    source.fail_at = Some(51);
                }
                5 => source.overflow = true,
                6 => {
                    key.id = fgit_crypto::git_object_id(format, ObjectType::Blob, b"wrong");
                    source.key = Some(key);
                }
                7 => {
                    key.object_type = ObjectType::Tree;
                    source.key = Some(key);
                }
                8 => {
                    key.recency += 1;
                    source.key = Some(key);
                }
                _ => unreachable!(),
            }
            let mut sink = Sink::default();
            let error = write(&source, profile(), limits(), &mut sink, &mut || true).unwrap_err();
            match case {
                0 | 1 => assert!(matches!(error, PackWriteError::SourceLengthMismatch { .. })),
                2 => assert_eq!(error, PackError::NativeObjectIdMismatch.into()),
                3 | 4 => assert_eq!(error, PackWriteError::TemporaryReadRefused),
                5 => assert!(matches!(error, PackWriteError::SourceReadOverflow { .. })),
                6 => assert!(matches!(
                    error,
                    PackWriteError::SourceIdentityMismatch { .. }
                )),
                7 | 8 => assert!(matches!(error, PackWriteError::SourceOrderMismatch(_))),
                _ => unreachable!(),
            }
            assert_aborted(&sink);
        }
        let source = Source::new(format, &[vec![42; 100]]);
        write(
            &source,
            profile(),
            limits(),
            &mut Sink::default(),
            &mut || true,
        )
        .unwrap();
    }
}

#[test]
fn object_aggregate_output_and_codec_limits_have_exact_success_twins() {
    let source = Source::new(ObjectFormat::Sha256, &[vec![42; 100]]);
    let mut exact = limits();
    exact.max_object_bytes = 100;
    exact.max_total_expanded_bytes = 100;
    let mut sink = Sink::default();
    let receipt = write(&source, profile(), exact.clone(), &mut sink, &mut || true).unwrap();
    exact.max_input_bytes = receipt.output_bytes;
    write(
        &source,
        profile(),
        exact.clone(),
        &mut Sink::default(),
        &mut || true,
    )
    .unwrap();
    for case in 0..3 {
        let mut tight = exact.clone();
        match case {
            0 => tight.max_object_bytes -= 1,
            1 => tight.max_total_expanded_bytes -= 1,
            2 => tight.max_input_bytes -= 1,
            _ => unreachable!(),
        }
        source.reads.set(0);
        let mut sink = Sink::default();
        let error = write(&source, profile(), tight, &mut sink, &mut || true).unwrap_err();
        match case {
            0 => assert!(matches!(
                error,
                PackWriteError::Pack(PackError::ObjectSizeLimit { .. })
            )),
            1 => assert!(matches!(
                error,
                PackWriteError::Pack(PackError::TotalExpandedLimit { .. })
            )),
            2 => assert!(matches!(error, PackWriteError::OutputLimit { .. })),
            _ => unreachable!(),
        }
        if case != 2 {
            assert_eq!(source.reads.get(), 0);
        }
        assert_aborted(&sink);
    }
    for compression_limits in [
        DeflateLimits {
            max_input_bytes: 99,
            ..DeflateLimits::GIT_OBJECT
        },
        DeflateLimits {
            max_work_units: 1,
            ..DeflateLimits::GIT_OBJECT
        },
        DeflateLimits {
            max_output_bytes: 6,
            ..DeflateLimits::GIT_OBJECT
        },
    ] {
        let mut sink = Sink::default();
        let result = PackPlanner::new(ObjectFormat::Sha256, profile(), limits())
            .stream_selected_thin(
                &source,
                &source.keys(),
                &[],
                &PackWriter::new(limits()),
                &mut DeterministicPackEncoder::new(compression_limits, profile().compression),
                &mut sink,
                &mut || true,
            );
        assert!(matches!(
            result,
            Err(PackWriteError::Deflate(
                DeflateRefusal::ResourceLimit { .. }
            ))
        ));
        assert_aborted(&sink);
    }
}

#[test]
fn cancellation_at_each_checkpoint_and_every_sink_failure_aborts() {
    let source = Source::new(ObjectFormat::Sha1, &[vec![42; 100]]);
    let profile = PackWriteProfile {
        compression: DeflateProfile::FAST_STORED,
        ..profile()
    };
    let mut polls = 0;
    let mut success = Sink::default();
    write(&source, profile, limits(), &mut success, &mut || {
        polls += 1;
        true
    })
    .unwrap();
    for stop in 1..=polls {
        let mut seen = 0;
        let mut sink = Sink::default();
        assert!(
            write(&source, profile, limits(), &mut sink, &mut || {
                seen += 1;
                seen < stop
            })
            .is_err(),
            "checkpoint {stop}"
        );
        assert_aborted(&sink);
    }
    for failing_write in 1..=success.writes {
        let mut sink = Sink {
            fail_write: Some(failing_write),
            ..Sink::default()
        };
        assert_eq!(
            write(&source, profile, limits(), &mut sink, &mut || true),
            Err(PackWriteError::TemporaryWriteRefused)
        );
        assert_aborted(&sink);
    }
    for (fail_create, fail_promote) in [(true, false), (false, true)] {
        let mut sink = Sink {
            fail_create,
            fail_promote,
            ..Sink::default()
        };
        assert!(write(&source, profile, limits(), &mut sink, &mut || true).is_err());
        assert_aborted(&sink);
    }
}

#[test]
fn streamed_large_blobs_are_not_compression_cache_entries() {
    let source = Source::new(ObjectFormat::Sha1, &[vec![42; 100]]);
    let cache = Arc::new(PackComputationCache::new(4096));
    let mut encoder = MemoizedPackEncoder::for_profile(profile(), Arc::clone(&cache));
    for _ in 0..2 {
        PackPlanner::new(ObjectFormat::Sha1, profile(), limits())
            .stream_selected_thin(
                &source,
                &source.keys(),
                &[],
                &PackWriter::new(limits()),
                &mut encoder,
                &mut Sink::default(),
                &mut || true,
            )
            .unwrap();
    }
    assert_eq!(cache.stats().entries, 0);
    assert_eq!(cache.stats().reserved_bytes, 0);
    assert_eq!(cache.stats().compression_hits, 0);
    assert!(encoder.work_units() > 0);
}

#[test]
fn large_thin_bases_are_omitted_without_reading_or_charging_their_bodies() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let source = Source::new(format, &[vec![1; 60], vec![2; 200]]);
        let target = source
            .objects
            .values()
            .find(|object| object.body.len() == 60)
            .unwrap();
        let base = source
            .objects
            .values()
            .find(|object| object.body.len() == 200)
            .unwrap();
        let key = PackOrderKey {
            id: target.id,
            object_type: ObjectType::Blob,
            recency: target.recency,
            path_hash: 0,
        };
        let profile = PackWriteProfile {
            thin: true,
            ..profile()
        };
        let limits = PackLimits {
            max_object_bytes: 64,
            max_total_expanded_bytes: 64,
            ..limits()
        };
        let planner = PackPlanner::new(format, profile, limits.clone());
        let offers = [ThinBase::new(target.id, base.id)];
        let mut sink = Sink::default();
        let receipt = planner
            .stream_selected_thin(
                &source,
                &[key],
                &offers,
                &PackWriter::new(limits.clone()),
                &mut DeterministicPackEncoder::for_profile(profile),
                &mut sink,
                &mut || true,
            )
            .unwrap();
        assert_eq!(receipt.delta_count, 0);
        assert_eq!(receipt.total_object_bytes, 60);
        assert_eq!(source.loads.get(), 0);
        assert_eq!(
            source.reads.get(),
            2,
            "only the target and its EOF probe are read"
        );
        let plan = planner
            .plan_selected_thin(&source, &[target.id], &offers, &mut || true)
            .unwrap();
        assert_eq!(
            PackWriter::new(limits)
                .write(&plan, &mut || true)
                .unwrap()
                .0,
            sink.published.unwrap()
        );
    }
}

#[test]
fn a_custom_encoder_cannot_skip_source_verification_or_invent_receipt_lengths() {
    struct Encoder {
        skip: bool,
    }
    impl PackEntryEncoder for Encoder {
        fn encode_entry(
            &mut self,
            input: &[u8],
            deadline: &mut dyn Deadline,
            emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
        ) -> Result<DeflateReceipt, PackWriteError> {
            DeterministicPackEncoder::for_profile(profile()).encode_entry(input, deadline, emit)
        }
        fn encode_blob_stream(
            &mut self,
            input: &mut dyn CanonicalBlobReader,
            length: usize,
            deadline: &mut dyn Deadline,
            emit: &mut dyn FnMut(&[u8]) -> Result<(), PackWriteError>,
        ) -> Result<DeflateReceipt, PackWriteError> {
            if self.skip {
                return Ok(DeflateReceipt {
                    profile: profile().compression,
                    input_bytes: length,
                    output_bytes: 0,
                    block_count: 1,
                });
            }
            let mut receipt = DeterministicPackEncoder::for_profile(profile())
                .encode_blob_stream(input, length, deadline, emit)?;
            receipt.output_bytes += 1;
            Ok(receipt)
        }
    }
    let source = Source::new(ObjectFormat::Sha1, &[vec![42; 100]]);
    for skip in [true, false] {
        let mut sink = Sink::default();
        let result = PackPlanner::new(ObjectFormat::Sha1, profile(), limits())
            .stream_selected_thin(
                &source,
                &source.keys(),
                &[],
                &PackWriter::new(limits()),
                &mut Encoder { skip },
                &mut sink,
                &mut || true,
            );
        if skip {
            assert!(matches!(
                result,
                Err(PackWriteError::SourceLengthMismatch { .. })
            ));
        } else {
            assert_eq!(result, Err(PackWriteError::CompressionReceiptMismatch));
        }
        assert_aborted(&sink);
    }
}

#[test]
fn a_blob_larger_than_32_mib_uses_only_bounded_source_and_output_chunks() {
    struct Generated {
        key: PackOrderKey,
        length: usize,
        maximum_read: Cell<usize>,
    }
    struct GeneratedReader<'a> {
        remaining: usize,
        maximum_read: &'a Cell<usize>,
    }
    impl CanonicalBlobReader for GeneratedReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> Result<usize, PackWriteError> {
            self.maximum_read
                .set(self.maximum_read.get().max(output.len()));
            let count = output.len().min(self.remaining);
            output[..count].fill(42);
            self.remaining -= count;
            Ok(count)
        }
    }
    impl CanonicalObjectSource for Generated {
        fn load(&self, _: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            panic!("large blob must never be materialized as a Vec");
        }
        fn open_blob(
            &self,
            _: &ObjectId,
        ) -> Result<Option<CanonicalBlobStream<'_>>, PackWriteError> {
            Ok(Some(CanonicalBlobStream::new(
                self.key,
                self.length,
                GeneratedReader {
                    remaining: self.length,
                    maximum_read: &self.maximum_read,
                },
            )))
        }
    }
    #[derive(Default)]
    struct CountingSink {
        published: Option<usize>,
        largest_write: usize,
        aborted: bool,
    }
    impl PackArtifactSink for CountingSink {
        type Temporary = usize;
        fn create_temporary(&mut self) -> Result<usize, PackWriteError> {
            Ok(0)
        }
        fn write_temporary(
            &mut self,
            bytes: &mut usize,
            chunk: &[u8],
        ) -> Result<(), PackWriteError> {
            self.largest_write = self.largest_write.max(chunk.len());
            *bytes += chunk.len();
            Ok(())
        }
        fn promote_temporary(&mut self, bytes: &mut usize) -> Result<(), PackWriteError> {
            self.published = Some(*bytes);
            Ok(())
        }
        fn abort_temporary(&mut self, _: usize) {
            self.aborted = true;
        }
    }
    let length = 33 * 1024 * 1024 + 17;
    // Independent framed SHA-256 oracle; no payload-sized allocation exists in
    // the source, expected-identity calculation, encoder, or output sink.
    let mut hash = Sha256Hasher::new();
    hash.update(format!("blob {length}\0").as_bytes());
    let chunk = [42; 4096];
    let mut left = length;
    while left != 0 {
        let count = left.min(chunk.len());
        hash.update(&chunk[..count]);
        left -= count;
    }
    let id = object_id_from_bytes(ObjectFormat::Sha256, &hash.finish()).unwrap();
    let source = Generated {
        key: PackOrderKey {
            id,
            object_type: ObjectType::Blob,
            recency: 0,
            path_hash: 0,
        },
        length,
        maximum_read: Cell::new(0),
    };
    let profile = PackWriteProfile {
        id: "test-large-streamed-blob-v1",
        compression: DeflateProfile::FAST_STORED,
        ..PackWriteProfile::COMPRESSED_V6
    };
    let limits = PackLimits {
        max_object_bytes: length,
        max_total_expanded_bytes: length,
        max_cached_bytes: 1,
        ..PackLimits::default()
    };
    let mut sink = CountingSink::default();
    let receipt = PackPlanner::new(ObjectFormat::Sha256, profile, limits.clone())
        .stream_selected_thin(
            &source,
            &[source.key],
            &[],
            &PackWriter::new(limits),
            &mut DeterministicPackEncoder::for_profile(profile),
            &mut sink,
            &mut || true,
        )
        .unwrap();
    assert_eq!(receipt.total_object_bytes, length);
    assert_eq!(receipt.object_count, 1);
    assert_eq!(sink.published, Some(receipt.output_bytes));
    assert_eq!(receipt.delta_count, 0);
    assert!(source.maximum_read.get() <= ENCODER_INPUT_CHUNK_BYTES);
    assert!(sink.largest_write <= 64 * 1024);
    assert!(!sink.aborted);
}
