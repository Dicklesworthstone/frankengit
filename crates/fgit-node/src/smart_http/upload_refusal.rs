//! Bounded Git diagnostics for resource refusals raised before an HTTP pack.
//!
//! Only known public resource causes cross this boundary. Storage errors,
//! object identifiers, authority internals and caller-controlled text do not.

use super::NodeSmartHttpRefusal;
use crate::{GitDaemonTransportRefusal, NodeGitDaemonServeRefusal, NodePackMaterializationRefusal};
use fgit_pack::{PackError, writer::PackWriteError};

pub(super) fn line(refusal: &NodeSmartHttpRefusal) -> Option<Vec<u8>> {
    let message = match refusal {
        NodeSmartHttpRefusal::Pack(refusal) => pack_message(refusal)?,
        NodeSmartHttpRefusal::Serve(refusal) => match refusal.as_ref() {
            NodeGitDaemonServeRefusal::Pack(refusal) => pack_message(refusal)?,
            NodeGitDaemonServeRefusal::Transport(refusal)
                if matches!(refusal.as_ref(), GitDaemonTransportRefusal::SessionDeadlineExceeded { .. }) =>
            {
                "upload-pack work exceeded this server's finite session allowance; the operator can configure --session-timeout-secs, --session-secs-per-mib and --session-max-extension-secs".to_owned()
            }
            _ => return None,
        },
        _ => return None,
    };
    let mut bytes = b"ERR ".to_vec();
    for character in message.chars() {
        if bytes.len().saturating_add(character.len_utf8()) > 516 {
            break;
        }
        if matches!(character, '\0' | '\r' | '\n') {
            bytes.push(b' ');
        } else {
            let mut encoded = [0; 4];
            bytes.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
        }
    }
    bytes.push(b'\n');
    Some(bytes)
}

fn pack_message(refusal: &NodePackMaterializationRefusal) -> Option<String> {
    match refusal {
        NodePackMaterializationRefusal::Pack(error)
            if matches!(
                error.as_ref(),
                PackWriteError::Pack(
                    PackError::TotalExpandedLimit { .. } | PackError::ObjectSizeLimit { .. }
                ) | PackWriteError::OutputLimit { .. }
                    | PackWriteError::WindowCacheLimit { .. }
            ) =>
        {
            Some(refusal.to_string())
        }
        NodePackMaterializationRefusal::BudgetClassExhausted { .. } => Some(refusal.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
