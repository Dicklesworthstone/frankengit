//! Bounded Git diagnostics for public resource failures before pack output.
//!
//! Git, SSH and HTTP use the same allowlist. Storage errors, object identities,
//! authority internals and arbitrary pack-builder diagnostics stay local.

use crate::{GitDaemonTransportRefusal, NodePackMaterializationRefusal};
use fgit_pack::{PackError, PackWriteError};

pub(super) fn pack_line(refusal: &NodePackMaterializationRefusal) -> Option<Vec<u8>> {
    let message = match refusal {
        NodePackMaterializationRefusal::Pack(error)
            if matches!(
                error.as_ref(),
                PackWriteError::Pack(
                    PackError::TotalExpandedLimit { .. } | PackError::ObjectSizeLimit { .. }
                ) | PackWriteError::OutputLimit { .. }
                    | PackWriteError::WindowCacheLimit { .. }
            ) =>
        {
            refusal.to_string()
        }
        NodePackMaterializationRefusal::BudgetClassExhausted { .. } => refusal.to_string(),
        _ => return None,
    };
    Some(bounded_line(&message))
}

pub(super) fn transport_line(refusal: &GitDaemonTransportRefusal) -> Option<Vec<u8>> {
    match refusal {
        GitDaemonTransportRefusal::SessionDeadlineExceeded { .. } => Some(bounded_line(
            "upload-pack work exceeded this server's finite session allowance; the operator can configure --session-timeout-secs, --session-secs-per-mib and --session-max-extension-secs",
        )),
        _ => None,
    }
}

fn bounded_line(message: &str) -> Vec<u8> {
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
    bytes
}

#[cfg(test)]
mod tests;
