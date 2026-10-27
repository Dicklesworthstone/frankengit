#![forbid(unsafe_code)]
//! Streamed delta execution is compared with the buffered scalar oracle. Large
//! inputs use a generated source and checking sink, without object-sized Vecs.

use fgit_pack::{
    Deadline, DeltaStreamIo, PackError, PackLimits, ResolutionBudget, STREAM_DELTA_CHUNK_BYTES,
    StreamDeltaError, apply_delta_streamed_to_charged_base_with_budget,
    apply_delta_to_charged_base_with_budget, delta_declared_sizes,
};
use std::cell::Cell;

fn size(mut value: usize, output: &mut Vec<u8>) {
    loop {
        let next = value & 127;
        value >>= 7;
        output.push(next as u8 | if value == 0 { 0 } else { 128 });
        if value == 0 {
            break;
        }
    }
}
fn program(base: usize, result: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    size(base, &mut bytes);
    size(result, &mut bytes);
    bytes
}
fn copy(offset: usize, length: usize, output: &mut Vec<u8>) {
    assert!(u32::try_from(offset).is_ok() && length <= 0xff_ffff);
    output.push(0xff);
    output.extend((offset as u32).to_le_bytes());
    output.extend(&(length as u32).to_le_bytes()[..3]);
}
fn limits() -> PackLimits {
    PackLimits {
        max_object_bytes: 64 * 1024 * 1024,
        max_total_expanded_bytes: 128 * 1024 * 1024,
        max_delta_work: 256 * 1024 * 1024,
        ..PackLimits::default()
    }
}

struct MemoryIo<'a> {
    base: &'a [u8],
    output: Vec<u8>,
    begun: usize,
    reads: usize,
    maximum: usize,
    short: usize,
    invalid: Option<usize>,
    fail: Option<&'static str>,
    cancel: Option<(&'a Cell<bool>, &'static str)>,
}
impl<'a> MemoryIo<'a> {
    const fn new(base: &'a [u8]) -> Self {
        Self {
            base,
            output: Vec::new(),
            begun: 0,
            reads: 0,
            maximum: 0,
            short: usize::MAX,
            invalid: None,
            fail: None,
            cancel: None,
        }
    }
    fn boundary(&self, name: &'static str) -> Result<(), &'static str> {
        if let Some((live, phase)) = self.cancel
            && phase == name
        {
            live.set(false);
        }
        if self.fail == Some(name) {
            return Err(name);
        }
        Ok(())
    }
}
impl DeltaStreamIo for MemoryIo<'_> {
    type Error = &'static str;
    fn begin_result(&mut self, _: usize, _: &mut impl Deadline) -> Result<(), Self::Error> {
        self.begun += 1;
        self.boundary("begin")
    }
    fn read_base(
        &mut self,
        offset: usize,
        output: &mut [u8],
        _: &mut ResolutionBudget,
        _: &mut impl Deadline,
    ) -> Result<usize, Self::Error> {
        self.boundary("read")?;
        self.reads += 1;
        self.maximum = self.maximum.max(output.len());
        if let Some(count) = self.invalid {
            return Ok(count);
        }
        let count = output.len().min(self.short);
        output[..count].copy_from_slice(&self.base[offset..offset + count]);
        Ok(count)
    }
    fn write_result(&mut self, bytes: &[u8], _: &mut impl Deadline) -> Result<(), Self::Error> {
        self.boundary("write")?;
        self.maximum = self.maximum.max(bytes.len());
        self.output.extend(bytes);
        Ok(())
    }
}
fn streamed(
    base: &[u8],
    delta: &[u8],
    bounds: &PackLimits,
) -> Result<Vec<u8>, StreamDeltaError<&'static str>> {
    let mut io = MemoryIo::new(base);
    let mut budget = ResolutionBudget::new();
    budget.charge_expanded(base.len(), bounds).unwrap();
    apply_delta_streamed_to_charged_base_with_budget(
        base.len(),
        delta,
        bounds,
        &mut budget,
        &mut io,
        &mut || true,
    )?;
    assert!(io.maximum <= STREAM_DELTA_CHUNK_BYTES);
    Ok(io.output)
}

#[test]
fn arbitrary_copy_order_and_inserts_match_scalar_oracle_with_short_reads() {
    let base: Vec<_> = (0..100_000).map(|i| (i * 71 + i / 19) as u8).collect();
    let bounds = limits();
    let mut seed = 1_u64;
    for case in 0..80 {
        let mut instructions = Vec::new();
        let mut length = 0;
        for step in 0..16 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            if step % 3 == 0 {
                let bytes = format!("insert-{case}-{step}");
                instructions.push(bytes.len() as u8);
                instructions.extend(bytes.as_bytes());
                length += bytes.len();
            } else {
                let n = 1 + seed as usize % 9000;
                let offset = (seed >> 25) as usize % (base.len() - n);
                copy(offset, n, &mut instructions);
                length += n;
            }
        }
        let mut delta = program(base.len(), length);
        delta.extend(instructions);
        let mut scalar_budget = ResolutionBudget::new();
        scalar_budget.charge_expanded(base.len(), &bounds).unwrap();
        let expected = apply_delta_to_charged_base_with_budget(
            &base,
            &delta,
            &bounds,
            &mut scalar_budget,
            &mut || true,
        )
        .unwrap();
        for short in [1, 71, usize::MAX] {
            let mut budget = ResolutionBudget::new();
            budget.charge_expanded(base.len(), &bounds).unwrap();
            let mut io = MemoryIo::new(&base);
            io.short = short;
            let actual = apply_delta_streamed_to_charged_base_with_budget(
                base.len(),
                &delta,
                &bounds,
                &mut budget,
                &mut io,
                &mut || true,
            )
            .unwrap();
            assert_eq!(actual, expected.len());
            assert_eq!(io.output, expected);
            assert!(io.maximum <= STREAM_DELTA_CHUNK_BYTES);
            // The successful logical work charge is base + emitted bytes.
            let tight = PackLimits {
                max_delta_work: base.len() + length,
                ..bounds.clone()
            };
            assert!(budget.charge_work(0, &tight).is_ok());
            assert!(matches!(
                budget.charge_work(1, &tight),
                Err(PackError::DeltaWorkLimit { .. })
            ));
        }
    }
}

#[test]
fn zero_copy_size_means_64k_and_empty_result_is_valid() {
    let base = vec![77; 65_536];
    let mut delta = program(base.len(), base.len());
    delta.push(0x80);
    assert_eq!(streamed(&base, &delta, &limits()).unwrap(), base);
    assert_eq!(streamed(&[], &[0, 0], &limits()).unwrap(), []);
    assert_eq!(
        streamed(&base, &program(base.len(), 0), &limits()).unwrap(),
        []
    );
}

#[test]
fn malformed_programs_have_the_scalar_oracles_refusals() {
    let base = b"abcd";
    let mut invalid_copy = program(4, 2);
    copy(3, 2, &mut invalid_copy);
    let cases = [
        vec![],
        vec![4],
        vec![3, 0],
        vec![4, 1, 0],
        vec![4, 2, 3, 1],
        vec![4, 1, 2, 65, 66],
        vec![4, 2, 1, 65],
        invalid_copy,
        vec![4, 1, 0xff, 0, 0],
        vec![4, 1, 0x80],
    ];
    for delta in cases {
        let bounds = limits();
        let mut budget = ResolutionBudget::new();
        budget.charge_expanded(base.len(), &bounds).unwrap();
        let expected = apply_delta_to_charged_base_with_budget(
            base,
            &delta,
            &bounds,
            &mut budget,
            &mut || true,
        )
        .unwrap_err();
        assert_eq!(
            streamed(base, &delta, &bounds),
            Err(StreamDeltaError::Pack(expected))
        );
    }
}

#[test]
fn overflowing_size_bits_cannot_wrap_into_an_admissible_length() {
    let mut bad = vec![0x80; (usize::BITS as usize - 1) / 7];
    let remaining = usize::BITS as usize - (bad.len() * 7);
    bad.push(1 << remaining);
    bad.push(0);
    assert!(matches!(
        delta_declared_sizes(&bad, &mut || true),
        Err(PackError::InvalidVarint { .. })
    ));
    assert!(matches!(
        streamed(&[], &bad, &limits()),
        Err(StreamDeltaError::Pack(PackError::InvalidVarint { .. }))
    ));
    let mut budget = ResolutionBudget::new();
    assert!(matches!(
        apply_delta_to_charged_base_with_budget(&[], &bad, &limits(), &mut budget, &mut || true),
        Err(PackError::InvalidVarint { .. })
    ));
    let valid = program(usize::MAX, 0);
    assert_eq!(
        delta_declared_sizes(&valid, &mut || true).unwrap(),
        (usize::MAX, 0)
    );
}

#[test]
fn header_and_aggregate_limits_refuse_before_io_and_do_not_relax_other_limits() {
    let base = b"abcd";
    let delta = [4, 4, 0x90, 4];
    let cases = [
        PackLimits {
            max_input_bytes: 3,
            ..limits()
        },
        PackLimits {
            max_object_bytes: 3,
            ..limits()
        },
        PackLimits {
            max_total_expanded_bytes: 7,
            ..limits()
        },
        PackLimits {
            max_delta_work: 3,
            ..limits()
        },
    ];
    for bounds in cases {
        let mut budget = ResolutionBudget::new();
        budget.charge_expanded(base.len(), &bounds).unwrap();
        let mut io = MemoryIo::new(base);
        assert!(
            apply_delta_streamed_to_charged_base_with_budget(
                base.len(),
                &delta,
                &bounds,
                &mut budget,
                &mut io,
                &mut || true
            )
            .is_err()
        );
        assert_eq!(io.begun, 0);
        assert_eq!(io.reads, 0);
        assert!(io.output.is_empty());
    }
    let exact = PackLimits {
        max_object_bytes: 4,
        max_total_expanded_bytes: 8,
        max_delta_work: 8,
        ..limits()
    };
    assert_eq!(streamed(base, &delta, &exact).unwrap(), base);
    let too_large = [4, 5, 5, 1, 2, 3, 4, 5];
    assert!(matches!(
        streamed(base, &too_large, &exact),
        Err(StreamDeltaError::Pack(PackError::DeltaResultSizeLimit {
            declared: 5,
            limit: 4
        }))
    ));
}

#[test]
fn cancellation_is_observed_before_and_after_every_io_phase() {
    let base = b"abcd";
    let delta = [4, 4, 0x90, 4];
    let bounds = limits();
    for phase in ["before", "begin", "read", "write"] {
        let live = Cell::new(phase != "before");
        let mut io = MemoryIo::new(base);
        io.cancel = Some((&live, phase));
        let mut budget = ResolutionBudget::new();
        budget.charge_expanded(base.len(), &bounds).unwrap();
        let result = apply_delta_streamed_to_charged_base_with_budget(
            base.len(),
            &delta,
            &bounds,
            &mut budget,
            &mut io,
            &mut || live.get(),
        );
        assert_eq!(
            result,
            Err(StreamDeltaError::Pack(PackError::DeadlineExceeded))
        );
        if phase == "before" {
            assert_eq!(io.begun, 0);
        }
    }
    assert_eq!(streamed(base, &delta, &bounds).unwrap(), base);
}

#[test]
fn interrupted_custody_preserves_error_and_reserved_aggregate_budget() {
    let base = b"abcd";
    let delta = [4, 4, 0x90, 4];
    let bounds = PackLimits {
        max_total_expanded_bytes: 8,
        ..limits()
    };
    for phase in ["begin", "read", "write"] {
        let mut io = MemoryIo::new(base);
        io.fail = Some(phase);
        let mut budget = ResolutionBudget::new();
        budget.charge_expanded(base.len(), &bounds).unwrap();
        assert_eq!(
            apply_delta_streamed_to_charged_base_with_budget(
                base.len(),
                &delta,
                &bounds,
                &mut budget,
                &mut io,
                &mut || true
            ),
            Err(StreamDeltaError::Io(phase))
        );
        let mut retry = MemoryIo::new(base);
        assert!(matches!(
            apply_delta_streamed_to_charged_base_with_budget(
                base.len(),
                &delta,
                &bounds,
                &mut budget,
                &mut retry,
                &mut || true
            ),
            Err(StreamDeltaError::Pack(PackError::TotalExpandedLimit { .. }))
        ));
        assert_eq!(retry.begun, 0);
    }
}

#[test]
fn invalid_base_read_counts_refuse_without_writing_unreturned_bytes() {
    for count in [0, 5] {
        let mut io = MemoryIo::new(b"abcd");
        io.invalid = Some(count);
        let mut budget = ResolutionBudget::new();
        budget.charge_expanded(4, &limits()).unwrap();
        assert_eq!(
            apply_delta_streamed_to_charged_base_with_budget(
                4,
                &[4, 4, 0x90, 4],
                &limits(),
                &mut budget,
                &mut io,
                &mut || true
            ),
            Err(StreamDeltaError::InvalidBaseRead {
                requested: 4,
                received: count
            })
        );
        assert!(io.output.is_empty());
    }
}

struct GeneratedIo {
    written: usize,
    maximum: usize,
    declared: usize,
}
const fn pattern(at: usize) -> u8 {
    (at.wrapping_mul(71) ^ (at / 97)) as u8
}
impl DeltaStreamIo for GeneratedIo {
    type Error = &'static str;
    fn begin_result(&mut self, length: usize, _: &mut impl Deadline) -> Result<(), Self::Error> {
        self.declared = length;
        Ok(())
    }
    fn read_base(
        &mut self,
        offset: usize,
        output: &mut [u8],
        _: &mut ResolutionBudget,
        _: &mut impl Deadline,
    ) -> Result<usize, Self::Error> {
        self.maximum = self.maximum.max(output.len());
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = pattern(offset + index);
        }
        Ok(output.len())
    }
    fn write_result(&mut self, bytes: &[u8], _: &mut impl Deadline) -> Result<(), Self::Error> {
        self.maximum = self.maximum.max(bytes.len());
        for byte in bytes {
            assert_eq!(*byte, pattern(self.written));
            self.written += 1;
        }
        Ok(())
    }
}

#[test]
fn large_blob_reconstruction_uses_only_bounded_source_and_sink_chunks() {
    let length = 33 * 1024 * 1024 + 17;
    let mut delta = program(length, length);
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(1 << 20);
        copy(offset, count, &mut delta);
        offset += count;
    }
    assert!(delta.len() < 1024);
    let mut io = GeneratedIo {
        written: 0,
        maximum: 0,
        declared: 0,
    };
    let mut budget = ResolutionBudget::new();
    let bounds = limits();
    budget.charge_expanded(length, &bounds).unwrap();
    assert_eq!(
        apply_delta_streamed_to_charged_base_with_budget(
            length,
            &delta,
            &bounds,
            &mut budget,
            &mut io,
            &mut || true
        )
        .unwrap(),
        length
    );
    assert_eq!(io.written, length);
    assert_eq!(io.declared, length);
    assert_eq!(io.maximum, STREAM_DELTA_CHUNK_BYTES);
}
