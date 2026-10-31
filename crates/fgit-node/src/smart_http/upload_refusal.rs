//! Bounded Git diagnostics for resource refusals raised before an HTTP pack.
//!
//! Only known public resource causes cross this boundary. Storage errors,
//! object identifiers, authority internals and caller-controlled text do not.

use super::NodeSmartHttpRefusal;
use crate::NodeGitDaemonServeRefusal;
use crate::upload_refusal::{pack_line, transport_line};

pub(super) fn line(refusal: &NodeSmartHttpRefusal) -> Option<Vec<u8>> {
    match refusal {
        NodeSmartHttpRefusal::Pack(refusal) => pack_line(refusal),
        NodeSmartHttpRefusal::Serve(refusal) => match refusal.as_ref() {
            NodeGitDaemonServeRefusal::Pack(refusal) => pack_line(refusal),
            NodeGitDaemonServeRefusal::Transport(refusal) => transport_line(refusal),
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests;
