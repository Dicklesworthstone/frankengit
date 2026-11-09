use super::*;
use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_object_fabric::artifact::storage::MAX_BUFFERED_PAYLOAD_BYTES;
use std::cell::Cell;

struct Generated(u64);
impl Read for Generated {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.0 as usize);
        output[..count].fill(0x6d);
        self.0 -= count as u64;
        Ok(count)
    }
}

fn generated_object(size: u64) -> LfsObject {
    let mut hash = Sha256Hasher::new();
    let chunk = [0x6d; DOWNLOAD_CHUNK_BYTES];
    let mut remaining = size;
    while remaining != 0 {
        let count = chunk.len().min(remaining as usize);
        hash.update(&chunk[..count]);
        remaining -= count as u64;
    }
    LfsObject {
        oid: LfsOid::parse(&hex(&hash.finish())).unwrap(),
        size,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    )
}
fn header(method: &str, object: LfsObject, token: char) -> String {
    format!(
        "{method} {} HTTP/1.1\r\nHost: localhost:9418\r\nAuthorization: Bearer {}\r\nContent-Type: {BINARY_MEDIA}\r\nContent-Length: {}\r\n\r\n",
        path(object),
        token.to_string().repeat(64),
        if method == "PUT" { object.size } else { 0 },
    )
}

/// Retains only the small HTTP head and a streaming digest of the body.
struct Received {
    head: Vec<u8>,
    body_started: bool,
    bytes: u64,
    hash: Sha256Hasher,
    flushed: bool,
}
impl Received {
    fn new() -> Self {
        Self {
            head: Vec::new(),
            body_started: false,
            bytes: 0,
            hash: Sha256Hasher::new(),
            flushed: false,
        }
    }
    fn check(self, object: LfsObject) {
        let head = std::str::from_utf8(&self.head).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        assert!(head.contains(&format!("Content-Length: {}\r\n", object.size)));
        assert!(head.contains("Content-Type: application/octet-stream\r\n"));
        assert_eq!(self.bytes, object.size);
        assert_eq!(hex(&self.hash.finish()), object.oid.to_string());
        assert!(self.flushed);
    }
}
impl Write for Received {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.len() <= DOWNLOAD_CHUNK_BYTES);
        let mut payload = bytes;
        if !self.body_started {
            let mut consumed = 0;
            while consumed < bytes.len() && !self.body_started {
                self.head.push(bytes[consumed]);
                assert!(self.head.len() < 4096);
                consumed += 1;
                self.body_started = self.head.ends_with(b"\r\n\r\n");
            }
            payload = &bytes[consumed..];
        }
        self.bytes += payload.len() as u64;
        self.hash.update(payload);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushed = true;
        Ok(())
    }
}

#[test]
fn upload_batch_reopen_and_download_stream_beyond_the_buffered_ceiling() {
    let mut fixture = Fixture::new();
    let object = generated_object(MAX_BUFFERED_PAYLOAD_BYTES + 19);
    let head = header("PUT", object, 'a');
    let envelope = head::parse(head.as_bytes(), fixture.profile.http)
        .unwrap()
        .unwrap();
    let mut uploaded = Vec::new();
    assert_eq!(
        serve(
            &fixture.profile,
            &envelope,
            b"",
            &mut Generated(object.size),
            &mut uploaded,
            &deadline(),
            Some("127.0.0.1:9418".parse().unwrap()),
        ),
        Ok(()),
        "{}",
        String::from_utf8_lossy(&uploaded),
    );
    fixture.profile.lfs = Some(Service::open(&fixture.root, TENANT, REPO, INCARNATION).unwrap());
    let batch = fixture.batch("download", 'b', &[object]);
    assert_eq!(batch.result, Ok(()));
    assert!(String::from_utf8_lossy(batch.body()).contains("\"download\":"));
    assert!(!String::from_utf8_lossy(batch.body()).contains("\"error\":"));

    let head = header("GET", object, 'b');
    let envelope = head::parse(head.as_bytes(), fixture.profile.http)
        .unwrap()
        .unwrap();
    let mut received = Received::new();
    assert_eq!(
        serve(
            &fixture.profile,
            &envelope,
            b"",
            &mut io::empty(),
            &mut received,
            &deadline(),
            None,
        ),
        Ok(()),
    );
    received.check(object);
    assert_eq!(
        fixture.request("GET", &path(object), 'c', b"").result,
        Err(Status::Forbidden)
    );
}

#[test]
fn a_partial_download_failure_never_appends_an_error_response() {
    struct Broken {
        remaining: usize,
        output: Vec<u8>,
        failed: bool,
        writes_after_failure: usize,
    }
    impl Write for Broken {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.failed {
                self.writes_after_failure += 1;
                self.output.extend_from_slice(bytes);
                return Ok(bytes.len());
            }
            if self.remaining == 0 {
                self.failed = true;
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let count = bytes.len().min(self.remaining);
            self.output.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let bytes = vec![0x6d; DOWNLOAD_CHUNK_BYTES * 2];
    let object = object(&bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', &bytes).result,
        Ok(())
    );
    let head = header("GET", object, 'a');
    let envelope = head::parse(head.as_bytes(), fixture.profile.http)
        .unwrap()
        .unwrap();
    let mut broken = Broken {
        remaining: 4096,
        output: Vec::new(),
        failed: false,
        writes_after_failure: 0,
    };
    assert!(
        serve(
            &fixture.profile,
            &envelope,
            b"",
            &mut io::empty(),
            &mut broken,
            &deadline(),
            None,
        )
        .is_err()
    );
    let response = String::from_utf8_lossy(&broken.output);
    assert_eq!(response.matches("HTTP/1.1").count(), 1);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains("\"message\""));
    assert!(broken.failed);
    assert_eq!(broken.writes_after_failure, 0);
    let retry = fixture.request("GET", &path(object), 'a', b"");
    assert_eq!(retry.result, Ok(()));
    assert_eq!(retry.body(), bytes);
}

#[test]
fn cancellation_at_headers_or_flush_ends_the_original_verified_operation() {
    struct Stop<'a> {
        running: &'a Cell<bool>,
        during_flush: bool,
        received: Received,
    }
    impl Write for Stop<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = self.received.write(bytes)?;
            if self.received.body_started && !self.during_flush {
                self.running.set(false);
            }
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.received.flush()?;
            self.running.set(false);
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let bytes = b"bounded verified payload";
    let object = object(bytes);
    assert_eq!(
        fixture.request("PUT", &path(object), 'a', bytes).result,
        Ok(())
    );
    let store = &fixture.profile.lfs.as_ref().unwrap().store;
    for (during_flush, range) in [
        (false, None),
        (true, None),
        (false, Some((3, 12))),
        (true, Some((3, 12))),
    ] {
        let running = Cell::new(true);
        let live = || running.get();
        let op = ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(60), &live).unwrap();
        let mut payload = store.open_verified(object, &op).unwrap();
        let mut stop = Stop {
            running: &running,
            during_flush,
            received: Received::new(),
        };
        assert_eq!(
            send_download(
                &mut stop,
                HttpVersion::Http11,
                &mut payload,
                range,
                &super::super::range::etag(object),
                &live
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut,
        );
        assert_eq!(
            stop.received.bytes,
            if during_flush {
                range.map_or(object.size, |(start, end)| end - start + 1)
            } else {
                0
            }
        );
        assert_eq!(stop.received.flushed, during_flush);
    }
}

#[test]
fn ranged_download_skips_and_streams_in_bounded_chunks_and_cancellation_prevents_headers() {
    let fixture = Fixture::new();
    let object = generated_object(DOWNLOAD_CHUNK_BYTES as u64 * 4 + 19);
    let store = &fixture.profile.lfs.as_ref().unwrap().store;
    let live = || true;
    let op = ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(60), &live).unwrap();
    store.put(object, &mut Generated(object.size), &op).unwrap();
    let start = DOWNLOAD_CHUNK_BYTES as u64 + 17;
    let end = DOWNLOAD_CHUNK_BYTES as u64 * 3 + 7;
    let mut payload = store.open_verified(object, &op).unwrap();
    let mut received = Received::new();
    send_download(
        &mut received,
        HttpVersion::Http11,
        &mut payload,
        Some((start, end)),
        &super::super::range::etag(object),
        &live,
    )
    .unwrap();
    let header = std::str::from_utf8(&received.head).unwrap();
    assert!(header.starts_with("HTTP/1.1 206 Partial Content\r\n"));
    assert!(header.contains(&format!(
        "Content-Range: bytes {start}-{end}/{}\r\n",
        object.size
    )));
    assert!(header.contains(&format!("Content-Length: {}\r\n", end - start + 1)));
    assert_eq!(received.bytes, end - start + 1);
    assert_eq!(
        hex(&received.hash.finish()),
        generated_object(end - start + 1).oid.to_string()
    );
    assert!(received.flushed);

    let calls = Cell::new(0_usize);
    let stop_at = Cell::new(usize::MAX);
    let live = || {
        calls.set(calls.get() + 1);
        calls.get() < stop_at.get()
    };
    let op = ArtifactOperation::new(MAX_OBJECT_BYTES, Duration::from_secs(60), &live).unwrap();
    let mut payload = store.open_verified(object, &op).unwrap();
    // Cancellation arrives while skipping the original verified prefix, not
    // at opening or after already emitting a success response.
    stop_at.set(calls.get() + 5);
    let mut output = Vec::new();
    assert_eq!(
        send_download(
            &mut output,
            HttpVersion::Http11,
            &mut payload,
            Some((start, end)),
            &super::super::range::etag(object),
            &live
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );
    assert!(output.is_empty());
}

#[test]
fn lfs_response_writer_cannot_renew_an_expired_request_at_first_write() {
    use super::super::super::ResponseWriter;
    use crate::DeadlineTcpStream;
    use std::net::{TcpListener, TcpStream};

    // Exercise the actual socket wrapper used by serve_connection. Its legacy
    // phase-reset twin remains available to Git RPCs, while LFS keeps the
    // original deadline through 100 Continue and final response delivery.
    for preserve_request_deadline in [true, false] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (mut socket, _) = listener.accept().unwrap();
        let mut expired = deadline();
        expired.started -= GitDaemonSessionTimeout::DEFAULT.duration() + Duration::from_secs(1);
        let started = expired.started;
        let mut writer = ResponseWriter {
            inner: DeadlineTcpStream::new(&mut socket, expired),
            timeout: GitDaemonSessionTimeout::DEFAULT,
            started: false,
            preserve_request_deadline,
            agent: None,
            agent_bytes: 0,
        };
        let interim = b"HTTP/1.1 100 Continue\r\n\r\n";
        let result = writer.write_all(interim);
        if preserve_request_deadline {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(writer.inner.deadline.started, started);
            assert_eq!(writer.flush().unwrap_err().kind(), io::ErrorKind::TimedOut);
        } else {
            result.unwrap();
            writer.flush().unwrap();
            let mut received = vec![0; interim.len()];
            client.read_exact(&mut received).unwrap();
            assert_eq!(received, interim);
            assert!(writer.inner.deadline.started > started);
        }
    }
}
