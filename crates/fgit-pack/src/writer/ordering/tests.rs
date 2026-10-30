use super::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use crate::writer::{CanonicalBlobReader, ENCODER_INPUT_CHUNK_BYTES};
use crate::{
    DeterministicPackEncoder, NativeChecksumVerifier, ObjectFormat, PackArtifactSink, PackError,
    PackLimits, PackPlanner, PackWriteProfile, PackWriter, ScalarResolver, ThinBase,
    object_id_from_bytes, read_verified_pack,
};
use fgit_crypto::git_object_id;
use fgit_deflate::DeflateProfile;

fn object(format: ObjectFormat, body: Vec<u8>) -> CanonicalPackObject {
    CanonicalPackObject::new(
        git_object_id(format, ObjectType::Blob, &body),
        ObjectType::Blob,
        body,
        Vec::new(),
        0,
        0,
    )
}

fn key(object: &CanonicalPackObject) -> PackOrderKey {
    PackOrderKey {
        id: object.id,
        object_type: object.object_type,
        recency: object.recency,
        path_hash: object.path_hash,
    }
}

struct Source {
    objects: BTreeMap<ObjectId, CanonicalPackObject>,
    returned: Option<PackOrderKey>,
    stream: bool,
    corrupt: bool,
    loads: Cell<usize>,
    opens: Cell<usize>,
    reads: Cell<usize>,
}

impl Source {
    fn new(objects: Vec<CanonicalPackObject>) -> Self {
        Self {
            objects: objects
                .into_iter()
                .map(|object| (object.id, object))
                .collect(),
            returned: None,
            stream: true,
            corrupt: false,
            loads: Cell::new(0),
            opens: Cell::new(0),
            reads: Cell::new(0),
        }
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
        let count = output.len().min(71).min(self.body.len() - self.position);
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
        let mut object = self
            .objects
            .get(id)
            .cloned()
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        if let Some(returned) = self.returned {
            object.id = returned.id;
            object.object_type = returned.object_type;
        }
        if self.corrupt && !object.body.is_empty() {
            object.body[0] ^= 1;
        }
        Ok(object)
    }

    fn open_blob(&self, id: &ObjectId) -> Result<Option<CanonicalBlobStream<'_>>, PackWriteError> {
        self.opens.set(self.opens.get() + 1);
        if !self.stream {
            return Ok(None);
        }
        let object = self
            .objects
            .get(id)
            .ok_or(PackWriteError::MissingCanonicalObject(*id))?;
        Ok(Some(CanonicalBlobStream::new(
            self.returned.unwrap_or_else(|| key(object)),
            object.body.len(),
            Reader {
                source: self,
                body: &object.body,
                position: 0,
            },
        )))
    }
}

#[derive(Default)]
struct Sink {
    published: Option<Vec<u8>>,
    aborted: bool,
}

impl PackArtifactSink for Sink {
    type Temporary = Vec<u8>;
    fn create_temporary(&mut self) -> Result<Vec<u8>, PackWriteError> {
        Ok(Vec::new())
    }
    fn write_temporary(
        &mut self,
        temporary: &mut Vec<u8>,
        bytes: &[u8],
    ) -> Result<(), PackWriteError> {
        temporary.extend_from_slice(bytes);
        Ok(())
    }
    fn promote_temporary(&mut self, temporary: &mut Vec<u8>) -> Result<(), PackWriteError> {
        self.published = Some(std::mem::take(temporary));
        Ok(())
    }
    fn abort_temporary(&mut self, _: Vec<u8>) {
        self.aborted = true;
    }
}

#[test]
fn basename_hash_has_frozen_byte_exact_vectors() {
    // Independent SHA-256 vectors, including bytes which are not UTF-8. The
    // argument is already a basename: this function never strips a prefix.
    for (name, expected) in [
        (&b""[..], 0x3065_a16f_0b2a_c658),
        (&b"Cargo.lock"[..], 0x852b_af75_ffe5_fdb6),
        (&b"issues.jsonl"[..], 0x9279_13e9_095b_5f24),
        (&b"cargo.lock"[..], 0x47a3_b3d5_5cfa_14a8),
        (&b"\xff\x00\xfe"[..], 0xab9a_fe69_2e2c_08d6),
        (&b"dir/name"[..], 0xe453_96ba_8213_a824),
    ] {
        assert_eq!(basename_path_hash(name), expected);
        assert_eq!(basename_path_hash(&name.to_vec()), expected);
    }
}

#[test]
fn buffered_overlay_moves_existing_body_and_references_without_an_extra_load() {
    struct OwnedSource {
        object: RefCell<Option<CanonicalPackObject>>,
        loads: Cell<usize>,
    }
    impl CanonicalObjectSource for OwnedSource {
        fn load(&self, _: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            self.loads.set(self.loads.get() + 1);
            Ok(self
                .object
                .borrow_mut()
                .take()
                .expect("exactly one source load"))
        }
    }
    let mut original = object(ObjectFormat::Sha256, vec![7; 4096]);
    original.references = vec![git_object_id(
        ObjectFormat::Sha256,
        ObjectType::Blob,
        b"edge",
    )];
    let body = original.body.as_ptr();
    let references = original.references.as_ptr();
    let hint = PackOrderKey {
        recency: 19,
        path_hash: 41,
        ..key(&original)
    };
    let source = OwnedSource {
        object: RefCell::new(Some(original)),
        loads: Cell::new(0),
    };
    let ordered = PackOrderingSource::new(&source, |_| Some(hint));
    let loaded = ordered.load(&hint.id).unwrap();
    assert_eq!(loaded.body.as_ptr(), body);
    assert_eq!(loaded.references.as_ptr(), references);
    assert_eq!(key(&loaded), hint);
    assert_eq!(source.loads.get(), 1);
}

#[test]
fn streamed_overlay_does_not_read_or_buffer_before_the_writer() {
    let original = object(ObjectFormat::Sha1, vec![23; 4096]);
    let hint = PackOrderKey {
        recency: 3,
        path_hash: 97,
        ..key(&original)
    };
    let source = Source::new(vec![original.clone()]);
    let ordered = PackOrderingSource::new(&source, |_| Some(hint));
    let stream = ordered.open_blob(&hint.id).unwrap().unwrap();
    assert_eq!(stream.order_key(), hint);
    assert_eq!(stream.length(), original.body.len());
    assert_eq!(source.opens.get(), 1);
    assert_eq!(source.loads.get(), 0);
    assert_eq!(source.reads.get(), 0);
    let buffered = stream.into_buffered(&mut || true).unwrap();
    assert_eq!(buffered.body, original.body);
    assert_eq!(key(&buffered), hint);
    assert!(source.reads.get() > 1);
    assert_eq!(source.loads.get(), 0);
}

#[test]
fn absent_hints_preserve_metadata_and_optional_stream_fallback() {
    let mut original = object(ObjectFormat::Sha256, Vec::new());
    original.recency = 81;
    original.path_hash = 37;
    let mut source = Source::new(vec![original.clone()]);
    let ordered = PackOrderingSource::new(&source, |_| None);
    assert_eq!(ordered.load(&original.id).unwrap(), original);
    let stream = ordered.open_blob(&original.id).unwrap().unwrap();
    assert_eq!(stream.order_key(), key(&original));
    assert_eq!(stream.length(), 0);
    assert_eq!(stream.into_buffered(&mut || true).unwrap(), original);
    source.stream = false;
    let ordered = PackOrderingSource::new(&source, |_| None);
    assert!(ordered.open_blob(&original.id).unwrap().is_none());
    assert_eq!(
        source.loads.get(),
        1,
        "a missing stream never adds a body load"
    );
    let missing = git_object_id(ObjectFormat::Sha256, ObjectType::Blob, b"missing");
    assert!(
        matches!(ordered.load(&missing), Err(PackWriteError::MissingCanonicalObject(id)) if id == missing)
    );
}

#[test]
fn mismatched_lookup_and_source_identity_or_type_are_never_relabelled() {
    let original = object(ObjectFormat::Sha1, vec![1; 128]);
    let valid = key(&original);
    let foreign = PackOrderKey {
        id: git_object_id(ObjectFormat::Sha1, ObjectType::Blob, b"foreign"),
        ..valid
    };
    let wrong_kind = PackOrderKey {
        object_type: ObjectType::Tree,
        ..valid
    };
    for invalid in [foreign, wrong_kind] {
        let source = Source::new(vec![original.clone()]);
        let ordered = PackOrderingSource::new(&source, |_| Some(invalid));
        for error in [
            ordered.load(&valid.id).unwrap_err(),
            ordered.open_blob(&valid.id).unwrap_err(),
        ] {
            if invalid.id != valid.id {
                assert_eq!(
                    error,
                    PackWriteError::SourceIdentityMismatch {
                        requested: valid.id,
                        returned: invalid.id
                    }
                );
            } else {
                assert_eq!(error, PackWriteError::SourceOrderMismatch(valid.id));
            }
        }
        assert_eq!(source.reads.get(), 0);
        let mut source = Source::new(vec![original.clone()]);
        source.returned = Some(invalid);
        let ordered = PackOrderingSource::new(&source, |_| Some(valid));
        for error in [
            ordered.load(&valid.id).unwrap_err(),
            ordered.open_blob(&valid.id).unwrap_err(),
        ] {
            if invalid.id != valid.id {
                assert_eq!(
                    error,
                    PackWriteError::SourceIdentityMismatch {
                        requested: valid.id,
                        returned: invalid.id
                    }
                );
            } else {
                assert_eq!(error, PackWriteError::SourceOrderMismatch(valid.id));
            }
        }
        assert_eq!(source.reads.get(), 0);
    }
    let mut source = Source::new(vec![original]);
    source.returned = Some(foreign);
    let ordered = PackOrderingSource::new(&source, |_| None);
    assert!(matches!(
        ordered.load(&valid.id),
        Err(PackWriteError::SourceIdentityMismatch { .. })
    ));
    assert!(matches!(
        ordered.open_blob(&valid.id),
        Err(PackWriteError::SourceIdentityMismatch { .. })
    ));
}

#[test]
fn populated_hints_produce_identical_planned_and_streamed_packs_in_both_formats() {
    for format in [ObjectFormat::Sha1, ObjectFormat::Sha256] {
        let objects: Vec<_> = (0..5)
            .map(|index| {
                let mut body = vec![b'a'; if index == 2 { 2048 } else { 512 }];
                body[32 + index] = b'0' + index as u8;
                object(format, body)
            })
            .collect();
        let keys: Vec<_> = objects
            .iter()
            .enumerate()
            .map(|(index, object)| PackOrderKey {
                recency: 10 - index as u64,
                path_hash: basename_path_hash(if index % 2 == 0 { b"a.lock" } else { b"b.lock" }),
                ..key(object)
            })
            .collect();
        let source = Source::new(objects);
        let ordered =
            PackOrderingSource::new(&source, |id| keys.iter().find(|key| key.id == *id).copied());
        let ids: Vec<_> = keys.iter().rev().map(|key| key.id).collect();
        for profile in [
            PackWriteProfile::COMPRESSED_V5,
            PackWriteProfile {
                id: "test-hinted-stream-v1",
                stream_blob_threshold: Some(1024),
                ..PackWriteProfile::COMPRESSED_V6
            },
        ] {
            let limits = PackLimits::default();
            let planner = PackPlanner::new(format, profile, limits.clone());
            let plan = planner.plan_selected(&ordered, &ids, &mut || true).unwrap();
            assert_eq!(
                plan.entries()
                    .iter()
                    .map(|entry| entry.object().id())
                    .collect::<Vec<_>>(),
                keys.iter().map(|key| key.id).collect::<Vec<_>>()
            );
            let (expected, expected_receipt) = PackWriter::new(limits.clone())
                .write(&plan, &mut || true)
                .unwrap();
            let mut sink = Sink::default();
            let receipt = planner
                .stream_selected_thin(
                    &ordered,
                    &keys,
                    &[],
                    &PackWriter::new(limits.clone()),
                    &mut DeterministicPackEncoder::for_profile(profile),
                    &mut sink,
                    &mut || true,
                )
                .unwrap();
            assert_eq!(receipt, expected_receipt);
            assert_eq!(sink.published.as_ref().unwrap(), &expected);
            assert!(!sink.aborted);
            let pack = read_verified_pack(
                &expected,
                format,
                &limits,
                &mut || true,
                &NativeChecksumVerifier,
            )
            .unwrap();
            let entries: BTreeMap<_, _> = pack
                .entries()
                .iter()
                .zip(plan.entries())
                .map(|(entry, planned)| (entry.offset, planned.object().id()))
                .collect();
            let scalar = pack
                .into_scalar_objects(|offset| entries.get(&offset).copied())
                .unwrap();
            let resolver = ScalarResolver::new(&scalar, &(), &limits, &mut || true).unwrap();
            for (offset, id) in entries {
                let body = resolver.resolve_offset(offset, &mut || true).unwrap();
                assert_eq!(body.as_slice(), source.objects[&id].body());
                assert_eq!(git_object_id(format, ObjectType::Blob, &body), id);
            }
        }
        assert!(
            source.reads.get() > 0,
            "the streaming variant must actually consume source readers"
        );
    }
}

#[test]
fn missing_hints_on_client_held_thin_bases_still_match_planned_output() {
    let base = object(ObjectFormat::Sha1, vec![b'x'; 4096]);
    let mut body = base.body.clone();
    body[2000] = b'y';
    let target = object(ObjectFormat::Sha1, body);
    let hint = PackOrderKey {
        recency: 9,
        path_hash: basename_path_hash(b"large.json"),
        ..key(&target)
    };
    let thin = [ThinBase::new(target.id, base.id)];
    let source = Source::new(vec![base, target]);
    let ordered = PackOrderingSource::new(&source, |id| (*id == hint.id).then_some(hint));
    let limits = PackLimits::default();
    let profile = PackWriteProfile::COMPRESSED_V5_THIN;
    let planner = PackPlanner::new(ObjectFormat::Sha1, profile, limits.clone());
    let plan = planner
        .plan_selected_thin(&ordered, &[hint.id], &thin, &mut || true)
        .unwrap();
    assert!(plan.entries()[0].delta().is_some());
    let (expected, expected_receipt) = PackWriter::new(limits.clone())
        .write(&plan, &mut || true)
        .unwrap();
    let mut sink = Sink::default();
    let receipt = planner
        .stream_selected_thin(
            &ordered,
            &[hint],
            &thin,
            &PackWriter::new(limits),
            &mut DeterministicPackEncoder::for_profile(profile),
            &mut sink,
            &mut || true,
        )
        .unwrap();
    assert_eq!(receipt, expected_receipt);
    assert_eq!(sink.published.unwrap(), expected);
}

#[test]
fn an_empty_selection_never_loads_or_opens_an_object() {
    let source = Source::new(Vec::new());
    let ordered = PackOrderingSource::new(&source, |_| None);
    let limits = PackLimits::default();
    let profile = PackWriteProfile::COMPRESSED_V5;
    let planner = PackPlanner::new(ObjectFormat::Sha256, profile, limits.clone());
    let plan = planner.plan_selected(&ordered, &[], &mut || true).unwrap();
    let (expected, expected_receipt) = PackWriter::new(limits.clone())
        .write(&plan, &mut || true)
        .unwrap();
    let mut sink = Sink::default();
    let receipt = planner
        .stream_selected_thin(
            &ordered,
            &[],
            &[],
            &PackWriter::new(limits),
            &mut DeterministicPackEncoder::for_profile(profile),
            &mut sink,
            &mut || true,
        )
        .unwrap();
    assert_eq!(receipt, expected_receipt);
    assert_eq!(sink.published.unwrap(), expected);
    assert_eq!(
        (source.loads.get(), source.opens.get(), source.reads.get()),
        (0, 0, 0)
    );
}

#[test]
fn hints_do_not_hide_corruption_or_allow_promotion() {
    let original = object(ObjectFormat::Sha256, vec![17; 2048]);
    let hint = PackOrderKey {
        recency: 9,
        path_hash: 83,
        ..key(&original)
    };
    let mut source = Source::new(vec![original]);
    source.corrupt = true;
    let ordered = PackOrderingSource::new(&source, |_| Some(hint));
    for profile in [
        PackWriteProfile::COMPRESSED_V5,
        PackWriteProfile {
            id: "test-corrupt-hinted-stream-v1",
            stream_blob_threshold: Some(1024),
            ..PackWriteProfile::COMPRESSED_V6
        },
    ] {
        let limits = PackLimits::default();
        let planner = PackPlanner::new(ObjectFormat::Sha256, profile, limits.clone());
        assert!(matches!(
            planner.plan_selected(&ordered, &[hint.id], &mut || true),
            Err(PackWriteError::Pack(PackError::NativeObjectIdMismatch))
        ));
        let mut sink = Sink::default();
        assert!(matches!(
            planner.stream_selected_thin(
                &ordered,
                &[hint],
                &[],
                &PackWriter::new(limits),
                &mut DeterministicPackEncoder::for_profile(profile),
                &mut sink,
                &mut || true,
            ),
            Err(PackWriteError::Pack(PackError::NativeObjectIdMismatch))
        ));
        assert!(sink.published.is_none());
        assert!(sink.aborted);
    }
}

#[test]
fn a_hinted_blob_above_the_served_threshold_stays_bounded_and_never_loads() {
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
            let count = self.remaining.min(output.len());
            output[..count].fill(42);
            self.remaining -= count;
            Ok(count)
        }
    }
    impl CanonicalObjectSource for Generated {
        fn load(&self, _: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
            panic!("the ordering adapter must preserve large-blob streaming");
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
    let hint = PackOrderKey {
        recency: 7,
        path_hash: basename_path_hash(b"large.bin"),
        ..source.key
    };
    let ordered = PackOrderingSource::new(&source, |_| Some(hint));
    let profile = PackWriteProfile {
        id: "test-large-hinted-blob-v1",
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
            &ordered,
            &[hint],
            &[],
            &PackWriter::new(limits),
            &mut DeterministicPackEncoder::for_profile(profile),
            &mut sink,
            &mut || true,
        )
        .unwrap();
    assert_eq!(receipt.total_object_bytes, length);
    assert_eq!(receipt.object_count, 1);
    assert_eq!(receipt.delta_count, 0);
    assert_eq!(sink.published, Some(receipt.output_bytes));
    assert!(source.maximum_read.get() <= ENCODER_INPUT_CHUNK_BYTES);
    assert!(sink.largest_write <= 64 * 1024);
    assert!(!sink.aborted);
}
