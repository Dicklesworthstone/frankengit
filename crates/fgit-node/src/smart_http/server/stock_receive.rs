//! Stock Git receive discovery with an attempt-scoped repository URL.
//!
//! Git retains the base selected by an initial discovery redirect for its RPCs.
//! The URL carries a public retry identifier, NOT authentication or authority.
//! Every normalized request still passes through the normal credential, scope,
//! quota, quarantine, seal and publication path. There is no session registry.
//!
//! A fresh discovery gets fresh OS entropy, even for a later identical push
//! (create/delete/recreate must not alias an old terminal decision). Reusing an
//! attempt URL retains its key across reconnects and server restarts. Starting
//! a new Git invocation normally discovers a NEW attempt; this is not automatic
//! recovery of the earlier invocation. Explicit Idempotency-Key clients retain
//! their existing route and recovery contract.

use std::io::Write;

use asupersync::util::{EntropySource, OsEntropy};
use fgit_wire::smart_http::{HttpLimits, HttpVersion, Operation, Service, head, parse_head};

use super::{Profile, Status, authenticated_session, retry_key};

const MARKER: &str = "/.fgit-receive/";
const DISCOVERY: &str = "/info/refs?service=git-receive-pack";
const RPC: &str = "/git-receive-pack";
const KEY_PREFIX: &str = "fg-http-v1-";
const NONCE_HEX_BYTES: usize = 64;

/// `None` means a complete authenticated discovery redirect was written.
/// Otherwise the owned bytes retain all headers and trailing ingress bytes,
/// with only a scoped Git target and its missing retry header normalized.
pub(super) fn adapt(
    bytes: Vec<u8>,
    profile: &Profile,
    version: &mut HttpVersion,
    writer: &mut impl Write,
) -> Result<Option<Vec<u8>>, Status> {
    adapt_with_nonce(bytes, profile, version, writer, || {
        let mut nonce = [0_u8; 32];
        OsEntropy.fill_bytes(&mut nonce);
        nonce
    })
}

fn adapt_with_nonce(
    bytes: Vec<u8>,
    profile: &Profile,
    version: &mut HttpVersion,
    writer: &mut impl Write,
    nonce: impl FnOnce() -> [u8; 32],
) -> Result<Option<Vec<u8>>, Status> {
    let envelope = head::parse(&bytes, profile.http)?.ok_or(Status::BadRequest)?;
    *version = envelope.version;
    let route = std::str::from_utf8(&profile.route).map_err(|_| Status::Unavailable)?;
    let Some(suffix) = envelope.target.strip_prefix(route) else {
        return Ok(Some(bytes));
    };
    if let Some(scoped) = suffix.strip_prefix(MARKER) {
        let (identifier, tail) = scoped.split_once('/').ok_or(Status::NotFound)?;
        if identifier.len() != NONCE_HEX_BYTES
            || !identifier
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Status::NotFound);
        }
        let tail = match tail {
            "info/refs?service=git-receive-pack" => DISCOVERY,
            "git-receive-pack" => RPC,
            _ => return Err(Status::NotFound),
        };
        let key = format!("{KEY_PREFIX}{identifier}");
        let normalized = rewrite(&bytes, route, tail, &key, profile.http)?;
        return Ok(Some(normalized));
    }
    if suffix != DISCOVERY {
        return Ok(Some(bytes));
    }
    // Parse endpoint policy too: discovery is GET, bodyless and without Expect.
    let request = parse_head(&bytes, profile.http)?.ok_or(Status::BadRequest)?;
    authenticated_session(&request, &bytes[..request.consumed], profile)?;
    if bytes.len() != request.consumed {
        return Err(Status::BadRequest);
    }
    if retry_key(&bytes[..request.consumed])?.is_some() {
        return Ok(Some(bytes));
    }
    let mut identifier = String::with_capacity(NONCE_HEX_BYTES);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in nonce() {
        identifier.push(char::from(HEX[usize::from(byte >> 4)]));
        identifier.push(char::from(HEX[usize::from(byte & 15)]));
    }
    // The redirect is same-origin, constructed from a configured canonical
    // route, not Host, Forwarded, or any caller-selected redirect destination.
    let target = format!("{route}{MARKER}{identifier}{DISCOVERY}");
    if target.len() > profile.http.max_target_bytes {
        return Err(Status::HeaderTooLarge);
    }
    let protocol = match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    write!(
        writer,
        "{protocol} 307 Temporary Redirect\r\nLocation: {target}\r\nIdempotency-Key: {KEY_PREFIX}{identifier}\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
    )?;
    writer.flush()?;
    Ok(None)
}

fn rewrite(
    bytes: &[u8],
    route: &str,
    suffix: &str,
    key: &str,
    limits: HttpLimits,
) -> Result<Vec<u8>, Status> {
    let envelope = head::parse(bytes, limits)?.ok_or(Status::BadRequest)?;
    let existing = retry_key(&bytes[..envelope.consumed])?;
    if existing.is_some_and(|existing| existing != key.as_bytes()) {
        // Never let a header silently replace the URL's retry identity.
        return Err(Status::BadRequest);
    }
    let header = if existing.is_none() {
        format!("Idempotency-Key: {key}\r\n")
    } else {
        String::new()
    };
    let target_start = envelope.method.len() + 1;
    let target_end = target_start + envelope.target.len();
    let target = format!("{route}{suffix}");
    let head_len = envelope
        .consumed
        .checked_sub(envelope.target.len())
        .and_then(|length| length.checked_add(target.len()))
        .and_then(|length| length.checked_add(header.len()))
        .filter(|length| *length <= limits.max_head_bytes)
        .ok_or(Status::HeaderTooLarge)?;
    let total = head_len
        .checked_add(bytes.len() - envelope.consumed)
        .ok_or(Status::TooLarge)?;
    let mut normalized = Vec::new();
    normalized
        .try_reserve_exact(total)
        .map_err(|_| Status::Unavailable)?;
    normalized.extend_from_slice(&bytes[..target_start]);
    normalized.extend_from_slice(target.as_bytes());
    normalized.extend_from_slice(&bytes[target_end..envelope.consumed - 2]);
    normalized.extend_from_slice(header.as_bytes());
    normalized.extend_from_slice(b"\r\n");
    // Body bytes are opaque. Never decode them as UTF-8, hash them for a key,
    // change chunk boundaries, or confuse them with synthetic headers.
    normalized.extend_from_slice(&bytes[envelope.consumed..]);
    let request = parse_head(&normalized, limits)?.ok_or(Status::BadRequest)?;
    if !matches!(
        request.operation,
        Operation::Discover(Service::ReceivePack) | Operation::Rpc(Service::ReceivePack)
    ) || request.repository_route != route
    {
        return Err(Status::NotFound);
    }
    Ok(normalized)
}

#[cfg(test)]
#[path = "stock_receive_tests.rs"]
mod tests;
