use super::*;
use std::cell::Cell;
use std::io::Cursor;

fn cancelled<T>(result: Result<T, ReadFailure>) -> bool {
    matches!(result, Err(ReadFailure::Interrupted(LooseGitImportRefusal::Interrupted {
        code: RefusalCode::CancellationInProgress, ..
    })))
}

#[test]
fn cancellation_is_sticky_and_prevents_even_the_first_read() {
    let probes = Cell::new(0);
    let mut deadline = || { probes.set(probes.get() + 1); probes.get() != 1 };
    let control = ImportControl::new(&mut deadline);
    struct MustNotRead;
    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { panic!("read after cancellation"); }
    }
    assert!(cancelled(read_bytes(MustNotRead, 100, &control)));
    assert!(cancelled(read_bytes(MustNotRead, 100, &control)));
    assert_eq!(probes.get(), 1, "a stopped operation cannot revive its probe");
}

#[test]
fn chunked_reads_keep_exact_first_excess_byte_semantics() {
    let data: Vec<u8> = (0..3 * IO_CHUNK_BYTES + 19).map(|n| n as u8).collect();
    for limit in [0, 1, IO_CHUNK_BYTES - 1, IO_CHUNK_BYTES,
        2 * IO_CHUNK_BYTES + 3, data.len(), data.len() + 1] {
        let mut reader = Cursor::new(&data);
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        let bytes = read_bytes(&mut reader, limit as u64, &control).unwrap();
        let expected = (limit + 1).min(data.len());
        assert_eq!(bytes, data[..expected]);
        assert_eq!(reader.position(), expected as u64);
    }
}

#[test]
fn a_stop_after_a_read_discards_partial_bytes_and_prevents_the_next_read() {
    let probes = Cell::new(0);
    let mut deadline = || { probes.set(probes.get() + 1); probes.get() < 4 };
    let control = ImportControl::new(&mut deadline);
    let data = vec![b'x'; 4 * IO_CHUNK_BYTES];
    let mut reader = Cursor::new(&data);
    assert!(cancelled(read_bytes(&mut reader, data.len() as u64, &control)));
    assert_eq!(reader.position(), (2 * IO_CHUNK_BYTES) as u64);
    assert_eq!(probes.get(), 4);
    assert!(cancelled(read_bytes(&mut reader, data.len() as u64, &control)));
    assert_eq!(reader.position(), (2 * IO_CHUNK_BYTES) as u64);
}

#[test]
fn eof_and_interrupted_os_calls_cannot_suppress_the_caller_stop() {
    for eof in [false, true] {
        let stop = Cell::new(false);
        let reads = Cell::new(0);
        struct StopReader<'a> { stop: &'a Cell<bool>, reads: &'a Cell<usize>, eof: bool }
        impl Read for StopReader<'_> {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.reads.set(self.reads.get() + 1); self.stop.set(true);
                if self.eof { Ok(0) } else { Err(io::Error::from(io::ErrorKind::Interrupted)) }
            }
        }
        let mut deadline = || !stop.get();
        let control = ImportControl::new(&mut deadline);
        assert!(cancelled(read_bytes(StopReader { stop: &stop, reads: &reads, eof }, 50, &control)));
        assert_eq!(reads.get(), 1);
    }
    struct RetryReader { attempts: usize }
    impl Read for RetryReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.attempts += 1;
            match self.attempts {
                1 => Err(io::Error::from(io::ErrorKind::Interrupted)),
                2 => { buffer[0] = 0xff; Ok(1) }
                _ => Ok(0),
            }
        }
    }
    let mut live = || true;
    assert_eq!(read_bytes(RetryReader { attempts: 0 }, 10, &ImportControl::new(&mut live)).unwrap(), [0xff]);
}

fn zlib_stored(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0x78, 0x01];
    let chunks = bytes.chunks(65_535);
    let count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        output.push(u8::from(index + 1 == count));
        let size = u16::try_from(chunk.len()).unwrap();
        output.extend(size.to_le_bytes()); output.extend((!size).to_le_bytes());
        output.extend(chunk);
    }
    let (a, b) = bytes.iter().fold((1_u32, 0_u32), |(a, b), byte| {
        let a = (a + u32::from(*byte)) % 65_521; (a, (b + a) % 65_521)
    });
    output.extend(((b << 16) | a).to_be_bytes());
    output
}

#[test]
fn the_native_streaming_decoder_uses_the_correct_cancellation_polarity() {
    let body: Vec<u8> = (0..2 * IO_CHUNK_BYTES + 37).map(|n| n as u8).collect();
    let framed = [format!("blob {}\0", body.len()).as_bytes(), &body].concat();
    let compressed = zlib_stored(&framed);
    let probes = Cell::new(0);
    let mut live = || { probes.set(probes.get() + 1); true };
    let parsed = decode_loose(&compressed, InflateLimits::GIT_OBJECT,
        ParseLimits::default(), &ImportControl::new(&mut live)).unwrap();
    assert_eq!(parsed.body, body);
    let complete = probes.get();
    assert!(complete > 8, "the real decoder must consult its control");
    for stop_at in [1, 3, complete / 2, complete - 1] {
        let probes = Cell::new(0);
        let mut deadline = || { probes.set(probes.get() + 1); probes.get() < stop_at };
        let control = ImportControl::new(&mut deadline);
        assert!(matches!(decode_loose(&compressed, InflateLimits::GIT_OBJECT,
            ParseLimits::default(), &control), Err(LooseGitImportRefusal::Interrupted {
                code: RefusalCode::CancellationInProgress, ..
            })));
        assert_eq!(probes.get(), stop_at);
    }
    let mut damaged = compressed; *damaged.last_mut().unwrap() ^= 1;
    let mut live = || true;
    assert!(matches!(decode_loose(&damaged, InflateLimits::GIT_OBJECT,
        ParseLimits::default(), &ImportControl::new(&mut live)), Err(LooseGitImportRefusal::LooseObject(_))));
}

#[test]
fn reading_and_decoding_share_the_same_finite_probe_instead_of_resetting_it() {
    let framed = b"blob 5\0hello";
    let bytes = zlib_stored(framed);
    let probes = Cell::new(0);
    let mut deadline = || { probes.set(probes.get() + 1); probes.get() < 5 };
    let control = ImportControl::new(&mut deadline);
    let read = read_bytes(Cursor::new(&bytes), 4096, &control).unwrap();
    assert_eq!(probes.get(), 4);
    assert!(matches!(decode_loose(&read, InflateLimits::GIT_OBJECT,
        ParseLimits::default(), &control), Err(LooseGitImportRefusal::Interrupted { .. })));
    assert_eq!(probes.get(), 5);
}

#[test]
fn cpu_sampling_does_not_charge_a_runtime_poll_for_every_decode_byte() {
    let probes = Cell::new(0);
    let allowed = Cell::new(true);
    let mut deadline = || { probes.set(probes.get() + 1); allowed.get() };
    let control = ImportControl::new(&mut deadline);
    let mut cpu = control.cpu_probe();
    for _ in 0..CPU_PROBE_INTERVAL { assert!(Deadline::checkpoint(&mut cpu)); }
    assert_eq!(probes.get(), 1);
    assert!(Deadline::checkpoint(&mut cpu)); assert_eq!(probes.get(), 2);
    // A phase/I/O checkpoint is never postponed by the CPU countdown.
    allowed.set(false);
    assert!(control.checkpoint().is_err()); assert_eq!(probes.get(), 3);
    assert!(!Deadline::checkpoint(&mut cpu)); assert_eq!(probes.get(), 3);
    assert!(CancellationProbe::is_cancelled(&mut cpu));
}
