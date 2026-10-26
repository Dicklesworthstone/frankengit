use super::*;
use fgit_crypto::Sha1;
use fgit_pack::{PackError, STREAM_DELTA_CHUNK_BYTES};
use fgit_treefs::integrity::GraphRefusal;
fn repeated_with_suffix<A: fgit_crypto::GitHashAlgorithm>(length: usize, suffix: &[u8]) -> GitOid {
    let mut hash = GitObjectHasher::<A>::new(ObjectKind::Blob, (length + suffix.len()) as u64);
    let bytes = [b'x'; 8192];
    let mut remaining = length;
    while remaining != 0 {
        let take = remaining.min(bytes.len());
        hash.update(&bytes[..take]).unwrap();
        remaining -= take;
    }
    hash.update(suffix).unwrap();
    hash.finish().unwrap().erase()
}
fn id(format: GitHashAlgorithm, length: usize, suffix: &[u8]) -> GitOid {
    match format {
        GitHashAlgorithm::Sha1 => repeated_with_suffix::<Sha1>(length, suffix),
        GitHashAlgorithm::Sha256 => repeated_with_suffix::<Sha256>(length, suffix),
    }
}
fn copy(program: &mut Vec<u8>, offset: usize, length: usize) {
    assert!(length > 0 && length <= 0xff_ffff && offset <= u32::MAX as usize);
    let mut opcode = 0x80;
    let mut operands = Vec::new();
    for i in 0..4 {
        let part = ((offset >> (8 * i)) & 255) as u8;
        if part != 0 {
            opcode |= 1 << i;
            operands.push(part);
        }
    }
    for i in 0..3 {
        let part = ((length >> (8 * i)) & 255) as u8;
        if part != 0 {
            opcode |= 1 << (4 + i);
            operands.push(part);
        }
    }
    program.push(opcode);
    program.extend(operands);
}
fn extend(base_length: usize, suffix: &[u8]) -> Vec<u8> {
    assert!(!suffix.is_empty() && suffix.len() <= 127);
    let mut program = Vec::new();
    delta_varint(base_length, &mut program);
    delta_varint(base_length + suffix.len(), &mut program);
    let mut offset = 0;
    while offset < base_length {
        let length = (base_length - offset).min(1024 * 1024);
        copy(&mut program, offset, length);
        offset += length;
    }
    program.push(suffix.len() as u8);
    program.extend(suffix);
    program
}
fn pair(format: GitHashAlgorithm, length: usize) -> (Vec<u8>, usize) {
    let program = extend(length, b"!");
    let input = bundle(
        format,
        &[
            repeated_entry(length),
            record(7, &program, id(format, length, b"").as_bytes()),
        ],
        id(format, length, b"!"),
    );
    (input, program.len())
}
fn streamed_limits(length: usize) -> BundleVerifyLimits {
    let mut limits = BundleVerifyLimits::default();
    limits.max_streamed_blob_bytes = length + 2;
    limits.pack.max_object_bytes = 4096;
    limits.graph.max_object_bytes = 4096;
    limits
}
#[test]
fn large_ref_and_ofs_delta_chains_match_the_buffered_oracle_in_both_domains() {
    let files = Files::new();
    let length = 3 * STREAM_DELTA_CHUNK_BYTES + 17;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for forward_ref in [false, true] {
            let first = extend(length, b"!");
            let second = extend(length + 1, b"?");
            let base = repeated_entry(length);
            let records = if forward_ref {
                vec![
                    record(7, &second, id(format, length, b"!").as_bytes()),
                    record(7, &first, id(format, length, b"").as_bytes()),
                    base,
                ]
            } else {
                let child = record(6, &first, &ofs(base.len() as u64));
                let grandchild = record(6, &second, &ofs(child.len() as u64));
                vec![base, child, grandchild]
            };
            let input = bundle(format, &records, id(format, length, b"!?"));
            let limits = streamed_limits(length);
            let mut ordinary = limits.clone();
            ordinary.pack.max_object_bytes = length + 2;
            ordinary.graph.max_object_bytes = length + 2;
            let expected = verify_git_bundle(&input, &ordinary, &mut || true).unwrap();
            let mut scratch = BoundedScratch::new(
                files.file(&format!("chain-{}-{forward_ref}", format.as_str(),)),
            );
            let actual = verify_git_bundle_reader(
                &mut Cursor::new(&input),
                &mut scratch,
                &limits,
                None,
                &mut || true,
            )
            .unwrap();
            assert_same(actual.verified(), &expected);
            assert_eq!(
                actual.verified().graph().payload_bytes,
                (3 * length + 3) as u64
            );
            assert_eq!(actual.verified().delta_objects(), 2);
            assert_eq!(
                scratch.write_bytes,
                3 * length + 3 + first.len() + second.len()
            );
        }
    }
}
#[test]
fn a_delta_result_larger_than_32_mib_streams_from_real_files() {
    let files = Files::new();
    let (input, program_length) = pair(GitHashAlgorithm::Sha256, LARGE);
    let mut source = files.file("large-delta.bundle");
    source.write_all(&input).unwrap();
    let limits = BundleVerifyLimits {
        max_streamed_blob_bytes: LARGE + 1,
        ..BundleVerifyLimits::default()
    };
    let mut scratch = BoundedScratch::new(files.file("large-delta-scratch"));
    let verified =
        verify_git_bundle_reader(&mut source, &mut scratch, &limits, None, &mut || true).unwrap();
    assert_eq!(verified.verified().graph().objects, 2);
    assert_eq!(
        verified.verified().graph().payload_bytes,
        (2 * LARGE + 1) as u64
    );
    assert_eq!(scratch.write_bytes, 2 * LARGE + 1 + program_length);
    assert!(limits.pack.max_object_bytes < LARGE);
    assert!(limits.graph.max_object_bytes < LARGE);
    assert!(verify_git_bundle(&input, &limits, &mut || true).is_err());
}
#[test]
fn streamed_result_program_total_payload_and_actual_read_work_limits_remain_independent() {
    let files = Files::new();
    let length = 3 * STREAM_DELTA_CHUNK_BYTES + 17;
    let (input, program_length) = pair(GitHashAlgorithm::Sha256, length);
    let mut limits = streamed_limits(length);
    limits.max_streamed_blob_bytes = length + 1;
    limits.pack.max_total_expanded_bytes = 2 * length + 1;
    limits.graph.max_payload_bytes = (2 * length + 1) as u64;
    limits.pack.max_delta_work = 4 + 3 * length + 1;
    let mut scratch = BoundedScratch::new(files.file("exact"));
    assert!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &limits,
            None,
            &mut || true,
        )
        .is_ok()
    );
    for dimension in 0..5 {
        let mut denied = limits.clone();
        match dimension {
            0 => denied.max_streamed_blob_bytes -= 1,
            1 => denied.pack.max_total_expanded_bytes -= 1,
            2 => denied.graph.max_payload_bytes -= 1,
            3 => denied.pack.max_delta_work -= 1,
            _ => denied.pack.max_object_bytes = program_length - 1,
        }
        let mut scratch = BoundedScratch::new(files.file(&format!("limit-{dimension}")));
        let error = verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &denied,
            None,
            &mut || true,
        )
        .unwrap_err();
        match dimension {
            0 => assert!(matches!(
                error,
                BundleVerifyError::Pack(PackError::DeltaResultSizeLimit { .. })
            )),
            1 => assert!(matches!(
                error,
                BundleVerifyError::Pack(PackError::TotalExpandedLimit { .. })
            )),
            2 => assert!(matches!(
                error,
                BundleVerifyError::Graph(GraphRefusal::Limit("payload bytes"))
            )),
            3 => assert!(matches!(
                error,
                BundleVerifyError::Pack(PackError::DeltaWorkLimit { .. })
            )),
            _ => assert!(matches!(
                error,
                BundleVerifyError::Pack(PackError::ObjectSizeLimit { .. })
            )),
        }
        if dimension < 3 {
            assert_eq!(
                scratch.write_bytes,
                length + program_length,
                "no result output before declared budgets pass"
            );
            assert_eq!(
                scratch.read_bytes, program_length,
                "no base scan before declared budgets pass"
            );
        }
    }
}
#[test]
fn a_scratch_mutation_after_full_base_verification_is_caught_before_copying() {
    let files = Files::new();
    let length = 3 * STREAM_DELTA_CHUNK_BYTES + 17;
    let (input, program_length) = pair(GitHashAlgorithm::Sha256, length);
    let limits = streamed_limits(length);
    let mut scratch = BoundedScratch::new(files.file("changed-random-block"));
    scratch.corrupt_at = Some(program_length + length + 1);
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &limits,
            None,
            &mut || true,
        ),
        Err(BundleVerifyError::ScratchChanged)
    ));
    assert_eq!(scratch.write_bytes, length + program_length);
    let mut twin = BoundedScratch::new(files.file("unchanged-random-block"));
    assert!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut twin,
            &limits,
            None,
            &mut || true,
        )
        .is_ok()
    );
}
#[test]
fn streamed_results_are_reverified_from_scratch_before_graph_receipts() {
    let files = Files::new();
    let format = GitHashAlgorithm::Sha256;
    let length = 3 * STREAM_DELTA_CHUNK_BYTES + 17;
    let (input, program_length) = pair(format, length);
    let limits = streamed_limits(length);
    let mut scratch = BoundedScratch::new(files.file("changed-result"));
    let prior_graph = if id(format, length, b"") < id(format, length, b"!") {
        length
    } else {
        0
    };
    scratch.corrupt_at = Some(program_length + 2 * length + prior_graph + 1);
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &limits,
            None,
            &mut || true,
        ),
        Err(BundleVerifyError::ScratchChanged)
    ));
    assert_eq!(scratch.write_bytes, 2 * length + 1 + program_length);
}
#[test]
fn a_shared_streamed_base_is_counted_once_but_each_read_remains_work() {
    let files = Files::new();
    let format = GitHashAlgorithm::Sha256;
    let length = 3 * STREAM_DELTA_CHUNK_BYTES + 17;
    let base = id(format, length, b"");
    let first = extend(length, b"!");
    let second = extend(length, b"?");
    let input = bundle(
        format,
        &[
            repeated_entry(length),
            record(7, &first, base.as_bytes()),
            record(7, &second, base.as_bytes()),
        ],
        id(format, length, b"?"),
    );
    let mut limits = streamed_limits(length);
    limits.pack.max_total_expanded_bytes = 3 * length + 2;
    limits.graph.max_payload_bytes = (3 * length + 2) as u64;
    limits.pack.max_delta_work = 6 + 2 * (3 * length + 1);
    let mut scratch = BoundedScratch::new(files.file("shared-base"));
    let actual = verify_git_bundle_reader(
        &mut Cursor::new(&input),
        &mut scratch,
        &limits,
        None,
        &mut || true,
    )
    .unwrap();
    assert_eq!(
        actual.verified().graph().payload_bytes,
        (3 * length + 2) as u64
    );
    limits.pack.max_total_expanded_bytes -= 1;
    let mut scratch = BoundedScratch::new(files.file("shared-base-short-budget"));
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut scratch,
            &limits,
            None,
            &mut || true,
        ),
        Err(BundleVerifyError::Pack(
            PackError::TotalExpandedLimit { .. }
        ))
    ));
}
struct CancellingScratch {
    inner: BoundedScratch,
    stopped: Rc<Cell<bool>>,
    read_at: Option<usize>,
    write_at: Option<usize>,
}
impl Read for CancellingScratch {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(out)?;
        if self.read_at.is_some_and(|at| self.inner.read_bytes >= at) {
            self.stopped.set(true);
        }
        Ok(count)
    }
}
impl Write for CancellingScratch {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        if self.write_at.is_some_and(|at| self.inner.write_bytes >= at) {
            self.stopped.set(true);
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl Seek for CancellingScratch {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
#[test]
fn cancellation_during_index_random_read_and_result_write_stops_without_a_receipt() {
    let files = Files::new();
    let length = 3 * STREAM_DELTA_CHUNK_BYTES + 17;
    let (input, program_length) = pair(GitHashAlgorithm::Sha256, length);
    let limits = streamed_limits(length);
    for stage in 0..3 {
        let stopped = Rc::new(Cell::new(false));
        let mut scratch = CancellingScratch {
            inner: BoundedScratch::new(files.file(&format!("cancel-{stage}"))),
            stopped: Rc::clone(&stopped),
            read_at: match stage {
                0 => Some(program_length + 1),
                1 => Some(program_length + length + 1),
                _ => None,
            },
            write_at: (stage == 2).then_some(length + program_length + 1),
        };
        assert!(matches!(
            verify_git_bundle_reader(
                &mut Cursor::new(&input),
                &mut scratch,
                &limits,
                None,
                &mut || !stopped.get(),
            ),
            Err(BundleVerifyError::Stopped)
        ));
        assert!(stopped.get());
        if stage < 2 {
            assert_eq!(scratch.inner.write_bytes, length + program_length);
        } else {
            assert!(
                scratch.inner.write_bytes <= length + program_length + STREAM_DELTA_CHUNK_BYTES
            );
        }
    }
}
#[test]
fn a_large_blob_allowance_cannot_expand_metadata_delta_results() {
    let format = GitHashAlgorithm::Sha256;
    let blob = git_object_id(format, ObjectKind::Blob, b"");
    let tag = format!(
        "object {}\ntype blob\ntag sample\ntagger A <a@example.test> 1 +0000\n\nmessage\n",
        lowercase_hex(blob.as_bytes())
    )
    .into_bytes();
    let mut program = Vec::new();
    delta_varint(tag.len(), &mut program);
    delta_varint(tag.len() * 2, &mut program);
    copy(&mut program, 0, tag.len());
    copy(&mut program, 0, tag.len());
    let result = [tag.as_slice(), tag.as_slice()].concat();
    let input = bundle(
        format,
        &[
            record(3, b"", &[]),
            record(4, &tag, &[]),
            record(
                7,
                &program,
                git_object_id(format, ObjectKind::Tag, &tag).as_bytes(),
            ),
        ],
        git_object_id(format, ObjectKind::Tag, &result),
    );
    let mut limits = BundleVerifyLimits::default();
    limits.pack.max_object_bytes = result.len();
    limits.graph.max_object_bytes = result.len();
    assert!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true,
        )
        .is_ok()
    );
    limits.graph.max_object_bytes = tag.len();
    assert!(matches!(
        verify_git_bundle_reader(
            &mut Cursor::new(&input),
            &mut Cursor::new(Vec::new()),
            &limits,
            None,
            &mut || true,
        ),
        Err(BundleVerifyError::Pack(
            PackError::DeltaResultSizeLimit { .. }
        ))
    ));
}
