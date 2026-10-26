//! Record-scoped verification shared by backup encoding and decoding.
use std::io::{self, Read};

use fgit_crypto::{
    DigestHasher, GitObjectHasher, GitObjectKind, IdentityDomain, NativeObjectIdentity, Sha1,
    Sha256, Sha256Hasher,
};
use fgit_types::{GitHashAlgorithm, GitOid};

use super::{CHUNK_BYTES, Input};

/// Untrusted record declarations. The payload stream and whole-file pin must
/// both finish before these declarations can participate in publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordHeader {
    pub oid: GitOid,
    pub kind: GitObjectKind,
    pub length: u64,
    pub commitment: [u8; 32],
}

enum NativeHash {
    Sha1(GitObjectHasher<Sha1>),
    Sha256(GitObjectHasher<Sha256>),
}

pub(super) struct ObjectVerifier {
    header: RecordHeader,
    native: Option<NativeHash>,
    strong: Option<Sha256Hasher>,
    consumed: u64,
}
impl ObjectVerifier {
    pub(super) fn new(header: RecordHeader) -> Result<Self, String> {
        let native = match header.oid.algorithm() {
            GitHashAlgorithm::Sha1 => {
                NativeHash::Sha1(GitObjectHasher::new(header.kind, header.length))
            }
            GitHashAlgorithm::Sha256 => {
                NativeHash::Sha256(GitObjectHasher::new(header.kind, header.length))
            }
        };
        let git_header = format!("{} {}\0", header.kind.label(), header.length);
        let framed = header
            .length
            .checked_add(git_header.len() as u64)
            .ok_or("repository backup framed object length overflow")?;
        let mut strong = Sha256Hasher::new();
        strong.update(&fgit_crypto::internal_id_preimage_header(
            IdentityDomain::GitPayloadCommitment,
            fgit_crypto::GIT_PAYLOAD_SCHEMA,
            framed,
        ));
        strong.update(git_header.as_bytes());
        Ok(Self {
            header,
            native: Some(native),
            strong: Some(strong),
            consumed: 0,
        })
    }
    pub(super) fn update(&mut self, bytes: &[u8]) -> Result<(), String> {
        let next = self
            .consumed
            .checked_add(bytes.len() as u64)
            .filter(|next| *next <= self.header.length)
            .ok_or("repository backup record length mismatch")?;
        match self
            .native
            .as_mut()
            .ok_or("repository backup record already verified")?
        {
            NativeHash::Sha1(hash) => hash.update(bytes),
            NativeHash::Sha256(hash) => hash.update(bytes),
        }
        .map_err(|error| format!("repository backup native hash failed: {error}"))?;
        self.strong
            .as_mut()
            .ok_or("repository backup record already verified")?
            .update(bytes);
        self.consumed = next;
        Ok(())
    }
    pub(super) fn finish(&mut self) -> Result<(), String> {
        if self.consumed != self.header.length {
            return Err("repository backup record payload not completely consumed".into());
        }
        let actual = match self
            .native
            .take()
            .ok_or("repository backup record already verified")?
        {
            NativeHash::Sha1(hash) => hash.finish().map(|oid| oid.erase()),
            NativeHash::Sha256(hash) => hash.finish().map(|oid| oid.erase()),
        }
        .map_err(|error| format!("repository backup native hash failed: {error}"))?;
        if actual != self.header.oid {
            return Err(format!(
                "repository backup native object identity mismatch: {}",
                self.header.oid
            ));
        }
        let strong = self
            .strong
            .take()
            .ok_or("repository backup record already verified")?;
        if strong.finish() != self.header.commitment {
            return Err(format!(
                "repository backup payload commitment mismatch: {}",
                self.header.oid
            ));
        }
        Ok(())
    }
}

pub(super) struct RecordReader<'a, R, L> {
    input: &'a mut Input<R>,
    live: &'a mut L,
    verifier: ObjectVerifier,
    verified: bool,
    failed: Option<String>,
}
impl<'a, R: Read, L: FnMut() -> Result<(), String>> RecordReader<'a, R, L> {
    pub(super) fn new(
        input: &'a mut Input<R>,
        header: RecordHeader,
        live: &'a mut L,
    ) -> Result<Self, String> {
        Ok(Self {
            input,
            live,
            verifier: ObjectVerifier::new(header)?,
            verified: false,
            failed: None,
        })
    }
    pub(super) fn finish(&mut self) -> Result<(), String> {
        if let Some(error) = &self.failed {
            return Err(error.clone());
        }
        let result = self.finish_inner();
        if let Err(error) = &result {
            self.failed = Some(error.clone());
        }
        result
    }
    fn finish_inner(&mut self) -> Result<(), String> {
        (self.live)()?;
        if !self.verified {
            self.verifier.finish()?;
            (self.live)()?;
            self.verified = true;
        }
        Ok(())
    }
    fn read_inner(&mut self, output: &mut [u8]) -> Result<usize, String> {
        (self.live)()?;
        if output.is_empty() {
            return Ok(0);
        }
        let remaining = self.verifier.header.length - self.verifier.consumed;
        if remaining == 0 {
            self.finish()?;
            return Ok(0);
        }
        let amount = output
            .len()
            .min(CHUNK_BYTES)
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        self.input.read_exact(&mut output[..amount], self.live)?;
        self.verifier.update(&output[..amount])?;
        (self.live)()?;
        Ok(amount)
    }
}
impl<R: Read, L: FnMut() -> Result<(), String>> Read for RecordReader<'_, R, L> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if let Some(error) = &self.failed {
            return Err(io::Error::other(error.clone()));
        }
        let result = self.read_inner(output);
        if let Err(error) = &result {
            self.failed = Some(error.clone());
        }
        result.map_err(io::Error::other)
    }
}
