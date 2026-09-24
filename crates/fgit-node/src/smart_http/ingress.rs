//! Pull-driven HTTP ingress shared by upload-pack and receive-pack.
//!
//! Framing and Git grammar remain in the wire RPC machine. This adapter owns
//! only bounded reads and exact consumption checks; it never retains a second
//! copy of the request body or calls a quarantine/publication handoff.

use std::io::{self, Read};

use fgit_wire::receive::ReceiveCancellation;
use fgit_wire::smart_http::rpc::{RpcError, RpcProgress};

use super::NodeSmartHttpRefusal;

const READ_BYTES: usize = 16 * 1024;

pub(super) enum BodyInput<'a> {
    /// An already-delimited request: every supplied byte must be consumed.
    Slice(&'a [u8]),
    /// A live transport: stop at HTTP completion, not transport EOF.
    Reader(&'a mut dyn Read),
}

impl BodyInput<'_> {
    /// Returns decoded payload bytes only after the complete HTTP envelope.
    /// The caller still owns RPC finalization and quarantine verification.
    pub(super) fn consume<C: ReceiveCancellation>(
        self,
        cancellation: &mut C,
        mut push: impl FnMut(&[u8], &mut C) -> Result<RpcProgress, RpcError>,
    ) -> Result<u64, NodeSmartHttpRefusal> {
        checkpoint(cancellation)?;
        match self {
            Self::Slice(bytes) => {
                let progress = push(bytes, cancellation)?;
                exact_consumption(bytes.len(), progress)?;
                if !progress.body_complete {
                    return Err(RpcError::IncompleteRequest.into());
                }
                Ok(progress.decoded_body_bytes)
            }
            Self::Reader(reader) => {
                // Content-Length: 0 is already complete. Do not wait for a
                // socket EOF the peer cannot send before receiving its reply.
                let initial = push(&[], cancellation)?;
                if initial.body_complete {
                    return Ok(initial.decoded_body_bytes);
                }
                let mut buffer = [0_u8; READ_BYTES];
                loop {
                    checkpoint(cancellation)?;
                    let count = match reader.read(&mut buffer) {
                        Ok(0) => return Err(RpcError::IncompleteRequest.into()),
                        Ok(count) => count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(source) => {
                            return Err(NodeSmartHttpRefusal::Io {
                                operation: "read smart HTTP body",
                                source,
                            });
                        }
                    };
                    checkpoint(cancellation)?;
                    let progress = push(&buffer[..count], cancellation)?;
                    exact_consumption(count, progress)?;
                    if progress.body_complete {
                        return Ok(progress.decoded_body_bytes);
                    }
                }
            }
        }
    }
}

fn checkpoint(cancellation: &mut impl ReceiveCancellation) -> Result<(), NodeSmartHttpRefusal> {
    if cancellation.checkpoint() {
        Ok(())
    } else {
        Err(RpcError::Cancelled.into())
    }
}

const fn exact_consumption(
    offered: usize,
    progress: RpcProgress,
) -> Result<(), NodeSmartHttpRefusal> {
    if progress.consumed != offered {
        return Err(NodeSmartHttpRefusal::TrailingRequestBytes {
            count: offered.saturating_sub(progress.consumed),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits};

    fn push(
        decoder: &mut BodyDecoder,
        input: &[u8],
        _live: &mut impl ReceiveCancellation,
    ) -> Result<RpcProgress, RpcError> {
        let mut consumed = 0;
        while consumed < input.len() && !decoder.is_complete() {
            consumed += decoder.push(&input[consumed..])?.consumed;
        }
        Ok(RpcProgress {
            consumed,
            body_complete: decoder.is_complete(),
            decoded_body_bytes: decoder.decoded_bytes(),
        })
    }

    struct Fragments<'a> {
        bytes: &'a [u8],
        width: usize,
        interrupt: bool,
    }
    impl Read for Fragments<'_> {
        fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
            assert!(target.len() <= READ_BYTES);
            if self.interrupt {
                self.interrupt = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            let count = self.bytes.len().min(self.width).min(target.len());
            target[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            self.interrupt = true;
            Ok(count)
        }
    }

    #[test]
    fn fixed_and_chunked_bodies_survive_every_small_fragment_width_and_interrupts() {
        for (framing, bytes) in [
            (BodyFraming::ContentLength(5), b"hello".as_slice()),
            (
                BodyFraming::Chunked,
                b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n".as_slice(),
            ),
        ] {
            for width in 1..=bytes.len() {
                let mut reader = Fragments {
                    bytes,
                    width,
                    interrupt: true,
                };
                let mut decoder = BodyDecoder::new(framing, HttpLimits::default()).unwrap();
                let decoded = BodyInput::Reader(&mut reader)
                    .consume(&mut || true, |bytes, live| push(&mut decoder, bytes, live))
                    .unwrap();
                assert_eq!(decoded, 5);
                assert!(reader.bytes.is_empty());
                decoder.finish().unwrap();
            }
        }
    }

    #[test]
    fn truncation_and_read_ahead_suffix_never_complete_ingress() {
        for (bytes, trailing) in [(b"hell".as_slice(), false), (b"helloNEXT".as_slice(), true)] {
            let mut reader = io::Cursor::new(bytes);
            let mut decoder =
                BodyDecoder::new(BodyFraming::ContentLength(5), HttpLimits::default()).unwrap();
            let result = BodyInput::Reader(&mut reader)
                .consume(&mut || true, |bytes, live| push(&mut decoder, bytes, live));
            if trailing {
                assert!(matches!(
                    result,
                    Err(NodeSmartHttpRefusal::TrailingRequestBytes { count: 4 })
                ));
            } else {
                assert!(matches!(result, Err(NodeSmartHttpRefusal::Rpc(error))
                    if matches!(*error, RpcError::IncompleteRequest)));
            }
        }
    }

    struct NoRead;
    impl Read for NoRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("an empty or cancelled request must not touch the transport");
        }
    }

    #[test]
    fn completion_does_not_require_socket_eof_and_cancellation_precedes_reads() {
        let mut decoder =
            BodyDecoder::new(BodyFraming::ContentLength(0), HttpLimits::default()).unwrap();
        assert_eq!(
            BodyInput::Reader(&mut NoRead)
                .consume(&mut || true, |bytes, live| push(&mut decoder, bytes, live))
                .unwrap(),
            0
        );
        let result = BodyInput::Reader(&mut NoRead)
            .consume(&mut || false, |_, _| panic!("cancelled before parser work"));
        assert!(matches!(result, Err(NodeSmartHttpRefusal::Rpc(error))
            if matches!(*error, RpcError::Cancelled)));
        // The same guarantee after a non-empty complete body: another read
        // would block on a real Git client's still-open request connection.
        let mut reader = io::Cursor::new(b"hello").chain(NoRead);
        let mut decoder =
            BodyDecoder::new(BodyFraming::ContentLength(5), HttpLimits::default()).unwrap();
        assert_eq!(
            BodyInput::Reader(&mut reader)
                .consume(&mut || true, |bytes, live| push(&mut decoder, bytes, live))
                .unwrap(),
            5
        );
    }

    #[test]
    fn large_ingress_never_requests_a_body_sized_read() {
        let length = 1024 * 1024;
        let mut reader = io::repeat(b'x').take(length);
        let mut decoder =
            BodyDecoder::new(BodyFraming::ContentLength(length), HttpLimits::default()).unwrap();
        let mut pushes = 0;
        let decoded = BodyInput::Reader(&mut reader)
            .consume(&mut || true, |bytes, live| {
                assert!(bytes.len() <= READ_BYTES);
                pushes += usize::from(!bytes.is_empty());
                push(&mut decoder, bytes, live)
            })
            .unwrap();
        assert_eq!(decoded, length);
        assert_eq!(pushes, 64);
    }
}
