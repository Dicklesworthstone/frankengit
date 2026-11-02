use super::*;
use crate::full_bundle::FullBundleInput;
use crate::full_bundle::stream::write_full_bundle_stream;
use crate::{CanonicalObjectSource, CanonicalPackObject, PackWriteError};
use fgit_crypto::{git_object_id, sha256_digest};
use fgit_types::RefName;
use std::io::Cursor;

const FORMATS: [ObjectFormat; 2] = [ObjectFormat::Sha1, ObjectFormat::Sha256];

struct Source(CanonicalPackObject);
impl CanonicalObjectSource for Source {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        if *id == self.0.id() {
            Ok(self.0.clone())
        } else {
            Err(PackWriteError::MissingCanonicalObject(*id))
        }
    }
}

struct Fixture {
    format: ObjectFormat,
    id: ObjectId,
    refs: Vec<BundleReference>,
    raw: Vec<u8>,
    binding: ExistingPackBinding,
}

fn fixture(format: ObjectFormat) -> Fixture {
    let body: Vec<u8> = (0..65_536)
        .map(|index| (index * 31 + index / 251) as u8)
        .collect();
    let id = git_object_id(format, ObjectType::Blob, &body);
    let refs = vec![BundleReference::new(
        id,
        RefName::try_new(b"refs/tags/blob").unwrap(),
    )];
    let source = Source(CanonicalPackObject::new(
        id,
        ObjectType::Blob,
        body,
        vec![],
        0,
        0,
    ));
    let limits = StreamFullBundleLimits::default();
    let mut encoded = Vec::new();
    let receipt = write_full_bundle_stream(
        format,
        &refs,
        None,
        &[id],
        &source,
        &limits,
        &mut || true,
        &mut encoded,
    )
    .unwrap();
    let parsed = FullBundleInput::parse(&encoded, limits.envelope, &mut || true).unwrap();
    let raw = parsed.pack_bytes().to_vec();
    let binding = ExistingPackBinding {
        checksum: receipt.pack_checksum(),
        sha256: sha256_digest(&raw),
        object_count: 1,
        bytes: raw.len(),
    };
    Fixture {
        format,
        id,
        refs,
        raw,
        binding,
    }
}

fn frame(
    fixture: &Fixture,
    raw: &[u8],
    binding: ExistingPackBinding,
    limits: &StreamFullBundleLimits,
    deadline: &mut impl Deadline,
    output: &mut (impl Write + ?Sized),
) -> Result<ExistingPackBundleReceipt, StreamFullBundleError> {
    write_existing_pack_bundle_stream(
        fixture.format,
        &fixture.refs,
        None,
        &[],
        &[fixture.id],
        &BTreeMap::new(),
        binding,
        limits,
        deadline,
        &mut Cursor::new(raw),
        output,
    )
}

#[test]
fn both_hash_domains_preserve_the_exact_existing_pack_and_bind_the_new_envelope() {
    for format in FORMATS {
        let f = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let mut output = Vec::new();
        let receipt = frame(&f, &f.raw, f.binding, &limits, &mut || true, &mut output).unwrap();
        let parsed = FullBundleInput::parse(&output, limits.envelope, &mut || true).unwrap();
        parsed
            .verify_pack_framing(&limits.pack, &mut || true)
            .unwrap();
        assert_eq!(parsed.pack_bytes(), f.raw);
        assert_eq!(parsed.references(), f.refs);
        assert_eq!(receipt.format(), format);
        assert_eq!(receipt.pack_checksum(), f.binding.checksum);
        assert_eq!(receipt.object_count(), 1);
        assert_eq!(receipt.pack_bytes(), f.raw.len());
        assert_eq!(receipt.header_bytes(), parsed.header_bytes());
        assert_eq!(receipt.bundle_bytes(), output.len());
        assert_eq!(receipt.bundle_sha256(), sha256_digest(&output));
        assert_eq!(receipt.prerequisite_count(), 0);
        assert_eq!(receipt.external_object_count(), 0);
    }
}

#[test]
fn incremental_framing_keeps_declared_prerequisites_separate_from_transferred_entries() {
    for format in FORMATS {
        let f = fixture(format);
        let prerequisite =
            git_object_id(format, ObjectType::Commit, b"caller-verified prerequisite");
        let external = BTreeMap::from([(prerequisite, ObjectType::Commit)]);
        let limits = StreamFullBundleLimits::default();
        let mut output = Vec::new();
        let receipt = write_existing_pack_bundle_stream(
            format,
            &f.refs,
            None,
            &[prerequisite],
            &[f.id],
            &external,
            f.binding,
            &limits,
            &mut || true,
            &mut Cursor::new(&f.raw),
            &mut output,
        )
        .unwrap();
        assert!(FullBundleInput::parse(&output, limits.envelope, &mut || true).is_err());
        let parsed =
            FullBundleInput::parse_incremental(&output, limits.envelope, &mut || true).unwrap();
        assert_eq!(parsed.prerequisites(), &[prerequisite]);
        assert_eq!(parsed.pack_bytes(), f.raw);
        assert_eq!(receipt.prerequisite_count(), 1);
        assert_eq!(receipt.external_object_count(), 1);
    }
}

#[test]
fn framing_receipt_deliberately_does_not_certify_the_selected_native_object_identity() {
    // The caller's separate verified custody must supply this proof. Reusing
    // encoder evidence here would silently turn this accepted framing into a
    // false native-object assertion.
    for format in FORMATS {
        let mut f = fixture(format);
        f.id = git_object_id(format, ObjectType::Blob, b"a different selected identity");
        f.refs[0] = BundleReference::new(f.id, RefName::try_new(b"refs/tags/blob").unwrap());
        let mut output = Vec::new();
        assert!(
            frame(
                &f,
                &f.raw,
                f.binding,
                &StreamFullBundleLimits::default(),
                &mut || true,
                &mut output
            )
            .is_ok()
        );
    }
}

#[test]
fn altered_count_length_native_hash_strong_hash_and_trailing_bytes_never_complete() {
    for format in FORMATS {
        let f = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let mut cases = Vec::new();
        let mut binding = f.binding;
        binding.object_count += 1;
        cases.push((f.raw.clone(), binding));
        let mut binding = f.binding;
        binding.bytes -= 1;
        cases.push((f.raw.clone(), binding));
        let mut binding = f.binding;
        binding.bytes += 1;
        cases.push((f.raw.clone(), binding));
        let mut binding = f.binding;
        binding.sha256[0] ^= 1;
        cases.push((f.raw.clone(), binding));
        let mut raw = f.raw.clone();
        raw[11] = 2;
        cases.push((raw, f.binding));
        let mut raw = f.raw.clone();
        raw[13] ^= 1;
        cases.push((raw, f.binding));
        let mut raw = f.raw.clone();
        *raw.last_mut().unwrap() ^= 1;
        cases.push((raw, f.binding));
        let mut raw = f.raw.clone();
        raw.push(0);
        cases.push((raw, f.binding));
        cases.push((f.raw[..f.raw.len() - 1].to_vec(), f.binding));
        for (raw, binding) in cases {
            let mut output = Vec::new();
            assert!(frame(&f, &raw, binding, &limits, &mut || true, &mut output).is_err());
        }
    }
}

#[test]
fn exact_output_bounds_succeed_and_smaller_bounds_refuse_before_output() {
    let f = fixture(ObjectFormat::Sha256);
    let mut baseline = Vec::new();
    let receipt = frame(
        &f,
        &f.raw,
        f.binding,
        &StreamFullBundleLimits::default(),
        &mut || true,
        &mut baseline,
    )
    .unwrap();
    let mut exact = StreamFullBundleLimits::default();
    exact.pack.max_entries = 1;
    exact.pack.max_index_entries = 1;
    exact.pack.max_input_bytes = receipt.pack_bytes();
    exact.envelope.max_bundle_bytes = receipt.bundle_bytes();
    exact.envelope.max_header_bytes = receipt.header_bytes();
    exact.envelope.max_references = 1;
    let mut output = Vec::new();
    assert!(frame(&f, &f.raw, f.binding, &exact, &mut || true, &mut output).is_ok());
    assert_eq!(output, baseline);
    for dimension in 0..6 {
        let mut limits = exact.clone();
        match dimension {
            0 => limits.pack.max_entries -= 1,
            1 => limits.pack.max_index_entries -= 1,
            2 => limits.pack.max_input_bytes -= 1,
            3 => limits.envelope.max_bundle_bytes -= 1,
            4 => limits.envelope.max_header_bytes -= 1,
            _ => limits.envelope.max_references -= 1,
        }
        let mut output = Vec::new();
        assert!(frame(&f, &f.raw, f.binding, &limits, &mut || true, &mut output).is_err());
        assert!(output.is_empty(), "dimension {dimension}");
    }
}

#[test]
fn every_cancellation_checkpoint_is_sticky_and_withholds_the_receipt() {
    let f = fixture(ObjectFormat::Sha1);
    let limits = StreamFullBundleLimits::default();
    let mut calls = 0;
    let mut output = Vec::new();
    frame(
        &f,
        &f.raw,
        f.binding,
        &limits,
        &mut || {
            calls += 1;
            true
        },
        &mut output,
    )
    .unwrap();
    for stop in 1..=calls {
        let mut observed = 0;
        let mut tentative = Vec::new();
        let result = frame(
            &f,
            &f.raw,
            f.binding,
            &limits,
            &mut || {
                observed += 1;
                observed != stop // A transient false must never resume work.
            },
            &mut tentative,
        );
        assert!(
            matches!(
                result,
                Err(StreamFullBundleError::Bundle(FullBundleError::Pack(
                    PackError::DeadlineExceeded
                )))
            ),
            "checkpoint {stop}"
        );
        assert_eq!(observed, stop);
    }
}

struct ShortReader<'a> {
    bytes: &'a [u8],
    calls: usize,
}
impl Read for ShortReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls % 3 == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = output.len().min(self.bytes.len()).min(7);
        output[..count].copy_from_slice(&self.bytes[..count]);
        self.bytes = &self.bytes[count..];
        Ok(count)
    }
}
struct ShortWriter {
    bytes: Vec<u8>,
    calls: usize,
    fail_at: usize,
}
impl Write for ShortWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.bytes.len() >= self.fail_at {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if self.calls % 3 == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let count = bytes.len().min(5).min(self.fail_at - self.bytes.len());
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("framing must not publish or flush")
    }
}

#[test]
fn interrupted_short_io_preserves_bytes_and_sink_failure_stays_tentative() {
    for format in FORMATS {
        let f = fixture(format);
        let limits = StreamFullBundleLimits::default();
        let mut baseline = Vec::new();
        let expected = frame(&f, &f.raw, f.binding, &limits, &mut || true, &mut baseline).unwrap();
        let mut input = ShortReader {
            bytes: &f.raw,
            calls: 0,
        };
        let mut output = ShortWriter {
            bytes: vec![],
            calls: 0,
            fail_at: usize::MAX,
        };
        let receipt = write_existing_pack_bundle_stream(
            format,
            &f.refs,
            None,
            &[],
            &[f.id],
            &BTreeMap::new(),
            f.binding,
            &limits,
            &mut || true,
            &mut input,
            &mut output,
        )
        .unwrap();
        assert_eq!(receipt, expected);
        assert_eq!(output.bytes, baseline);
        let mut output = ShortWriter {
            bytes: vec![],
            calls: 0,
            fail_at: 20,
        };
        assert!(matches!(
            frame(&f, &f.raw, f.binding, &limits, &mut || true, &mut output),
            Err(StreamFullBundleError::Io(_))
        ));
        assert_eq!(output.bytes, baseline[..20]);
    }
}
