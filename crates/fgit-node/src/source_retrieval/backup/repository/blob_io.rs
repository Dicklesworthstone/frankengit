//! Bounded adapter over the node's authenticated-at-EOF blob stream.
use std::io::{self, Read};

use crate::{NodeRequestContext, OneNode};
use fgit_object_fabric::{StoreRefusal, local::LocalBlobStream};
use fgit_types::GitOid;

use super::profile::Deadline;

pub(super) struct BlobReader<'a> {
    stream: LocalBlobStream,
    deadline: Deadline,
    request: &'a NodeRequestContext,
}
impl<'a> BlobReader<'a> {
    pub fn open(
        node: &OneNode,
        identity: GitOid,
        maximum: u64,
        deadline: Deadline,
        request: &'a NodeRequestContext,
    ) -> Result<Self, String> {
        deadline.in_request(request)?;
        let stream = node
            .open_git_blob_stream(identity, maximum)
            .map_err(|e| e.to_string())?;
        deadline.in_request(request)?;
        Ok(Self {
            stream,
            deadline,
            request,
        })
    }
    pub const fn length(&self) -> u64 {
        self.stream.declared_length()
    }
    pub const fn commitment(&self) -> [u8; 32] {
        self.stream.payload_commitment()
    }
}
impl Read for BlobReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        self.deadline
            .in_request(self.request)
            .map_err(io::Error::other)?;
        let result = self.stream.read_tentative(out);
        self.deadline
            .in_request(self.request)
            .map_err(io::Error::other)?;
        result.map_err(|error| match error {
            StoreRefusal::StorageIo { kind, .. } => io::Error::new(kind, error.to_string()),
            _ => io::Error::other(error.to_string()),
        })
    }
}
