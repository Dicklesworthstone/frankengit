//! Pull-driven HTTP body framing for immutable artifact intake. A complete
//! decoded body yields EOF without waiting for the peer to close its socket.

use std::io::{self, Read};

use fgit_wire::smart_http::{BodyDecoder, BodyFraming, HttpLimits};

const CHUNK: usize = 16 * 1024;

pub(super) struct Framed<'a, R> {
    decoder: BodyDecoder,
    prefix: &'a [u8],
    reader: &'a mut R,
    raw: [u8; CHUNK],
    at: usize,
    end: usize,
    live: &'a dyn Fn() -> bool,
}

impl<'a, R: Read> Framed<'a, R> {
    pub(super) fn new(
        framing: BodyFraming,
        limits: HttpLimits,
        maximum: u64,
        prefix: &'a [u8],
        reader: &'a mut R,
        live: &'a dyn Fn() -> bool,
    ) -> Result<Self, super::Failure> {
        let limits = HttpLimits {
            max_body_bytes: limits.max_body_bytes.min(maximum),
            max_body_wire_bytes: limits
                .max_body_wire_bytes
                .min(maximum.saturating_add(4 * 1024 * 1024)),
            ..limits
        };
        Ok(Self {
            decoder: BodyDecoder::new(framing, limits).map_err(super::Failure::http)?,
            prefix,
            reader,
            raw: [0; CHUNK],
            at: 0,
            end: 0,
            live,
        })
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid_lfs_body_framing")
}

impl<R: Read> Read for Framed<'_, R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if !(self.live)() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "lfs_request_expired",
                ));
            }
            if self.decoder.is_complete() {
                if !self.prefix.is_empty() || self.at != self.end {
                    return Err(invalid());
                }
                self.decoder.finish().map_err(|_| invalid())?;
                return Ok(0);
            }
            if self.at == self.end {
                self.at = 0;
                if self.prefix.is_empty() {
                    self.end = match self.reader.read(&mut self.raw) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => result?,
                    };
                    if self.end == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "incomplete_lfs_body",
                        ));
                    }
                } else {
                    self.end = self.prefix.len().min(CHUNK);
                    self.raw[..self.end].copy_from_slice(&self.prefix[..self.end]);
                    self.prefix = &self.prefix[self.end..];
                }
            }
            let limit = self.end.min(self.at.saturating_add(output.len()));
            let step = self
                .decoder
                .push(&self.raw[self.at..limit])
                .map_err(|_| invalid())?;
            if step.consumed == 0 {
                return Err(invalid());
            }
            self.at += step.consumed;
            if step.complete && (self.at != self.end || !self.prefix.is_empty()) {
                return Err(invalid());
            }
            if !step.data.is_empty() {
                output[..step.data.len()].copy_from_slice(step.data);
                return Ok(step.data.len());
            }
        }
    }
}

pub(super) fn json(
    framing: BodyFraming,
    limits: HttpLimits,
    prefix: &[u8],
    reader: &mut impl Read,
    live: &dyn Fn() -> bool,
) -> Result<Vec<u8>, super::Failure> {
    let mut framed = Framed::new(
        framing,
        limits,
        super::protocol::MAX_JSON_BYTES as u64,
        prefix,
        reader,
        live,
    )?;
    let mut bytes = Vec::new();
    let mut chunk = [0; CHUNK];
    loop {
        let count = framed.read(&mut chunk).map_err(super::Failure::io)?;
        if count == 0 {
            return Ok(bytes);
        }
        bytes
            .try_reserve(count)
            .map_err(|_| super::Failure::unavailable())?;
        bytes.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fragments<'a> {
        source: &'a [u8],
        width: usize,
    }
    impl Read for Fragments<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let count = out.len().min(self.width).min(self.source.len());
            out[..count].copy_from_slice(&self.source[..count]);
            self.source = &self.source[count..];
            Ok(count)
        }
    }

    #[test]
    fn every_read_ahead_and_fragment_boundary_preserves_the_payload() {
        for (framing, wire) in [
            (BodyFraming::ContentLength(5), b"hello".as_slice()),
            (
                BodyFraming::Chunked,
                b"2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n".as_slice(),
            ),
        ] {
            for prefix in 0..=wire.len() {
                for width in 1..=wire.len() {
                    let mut reader = Fragments {
                        source: &wire[prefix..],
                        width,
                    };
                    let mut framed = Framed::new(
                        framing,
                        HttpLimits::default(),
                        5,
                        &wire[..prefix],
                        &mut reader,
                        &|| true,
                    )
                    .unwrap();
                    let mut bytes = Vec::new();
                    let mut one = [0; 1];
                    while framed.read(&mut one).unwrap() != 0 {
                        bytes.push(one[0]);
                    }
                    assert_eq!(bytes, b"hello");
                }
            }
        }
    }

    #[test]
    fn truncation_extra_bytes_limits_and_cancellation_never_produce_complete_input() {
        for (framing, bytes) in [
            (BodyFraming::ContentLength(5), b"hell".as_slice()),
            (BodyFraming::ContentLength(5), b"helloNEXT".as_slice()),
            (BodyFraming::ContentLength(0), b"NEXT".as_slice()),
            (BodyFraming::Chunked, b"5\r\nhello\r\n0\r\n".as_slice()),
            (
                BodyFraming::Chunked,
                b"5\r\nhello\r\n0\r\n\r\nNEXT".as_slice(),
            ),
            (BodyFraming::Chunked, b"6\r\nhello!\r\n0\r\n\r\n".as_slice()),
        ] {
            let mut empty = io::empty();
            let mut framed = Framed::new(
                framing,
                HttpLimits::default(),
                5,
                bytes,
                &mut empty,
                &|| true,
            )
            .unwrap();
            assert!(framed.read_to_end(&mut Vec::new()).is_err());
        }
        let mut empty = io::empty();
        let mut framed = Framed::new(
            BodyFraming::ContentLength(5),
            HttpLimits::default(),
            5,
            b"hello",
            &mut empty,
            &|| false,
        )
        .unwrap();
        assert!(framed.read_to_end(&mut Vec::new()).is_err());
    }
}
