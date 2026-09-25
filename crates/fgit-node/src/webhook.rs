//! Webhook delivery engine, OutboxDestination implementation, and dead-letter queue.

#[cfg(test)]
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fgit_admission::merge::native::settlement::{DeliveryRequest, OutboxDestination};
use fgit_forge::webhook::{
    DeadLetterEntry, SsrfPolicy, ValidatedWebhookUrl, WebhookRefusal, WebhookRegistration,
};
use fgit_resource::settlement::{DeliveryVerdict, DownstreamIdempotency, ProbeVerdict};
use fgit_types::{AsciiSlug, RefusalCode};
use fsqlite_types::cx::Cx;

mod request_io;
mod transport;

mod payload;
mod persistence;

mod store;
pub use store::{DeadLetterQueue, WebhookStore};

impl crate::OneNode {
    /// Opens the persistent webhook store for this node.
    pub fn webhook_store(&self) -> Result<WebhookStore, String> {
        WebhookStore::open(self.storage_root().join("webhooks"))
    }
}

/// An outbound HTTP transport adapter for webhook delivery implementing `OutboxDestination`.
pub struct WebhookDeliveryDestination {
    pub destination_slug: AsciiSlug,
    pub registration: WebhookRegistration,
    pub ssrf_policy: SsrfPolicy,
    /// One attempt deadline, not a renewed per-read/write idle timeout.
    pub timeout: Duration,
    pub dead_letters: DeadLetterQueue,
    pub acknowledged: Arc<Mutex<Vec<(AsciiSlug, u32)>>>,
}

impl WebhookDeliveryDestination {
    pub fn new(
        destination_slug: AsciiSlug,
        registration: WebhookRegistration,
        ssrf_policy: SsrfPolicy,
        dead_letters: DeadLetterQueue,
    ) -> Self {
        Self {
            destination_slug,
            registration,
            ssrf_policy,
            timeout: Duration::from_secs(5),
            dead_letters,
            acknowledged: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Legacy entry point without canonical payload evidence.
    ///
    /// A key and retry ordinal cannot reconstruct a committed event. Callers
    /// must select a verified outbox request and use `deliver_request`; this
    /// compatibility entry point refuses instead of transmitting a fake root.
    pub fn deliver_simple(
        &self,
        _key: AsciiSlug,
        _attempt: u32,
    ) -> Result<(&'static str, Vec<u8>), String> {
        Err(
            "EvidenceMissing: webhook delivery requires an authority-selected DeliveryRequest"
                .into(),
        )
    }

    /// Deliver the exact payload selected and verified by the canonical outbox
    /// reader. This direct adapter call does not itself settle an obligation.
    pub fn deliver_request(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
    ) -> Result<(&'static str, Vec<u8>), String> {
        self.deliver_request_with_checkpoint(request, attempt, &|| Ok(()))
    }

    /// Perform one bounded manual send with caller-owned cancellation checks.
    /// A stop after a write was attempted returns `AmbiguousTimeout`, not a
    /// definitive refusal. This does not settle a canonical obligation.
    /// Blocking OS DNS and local diagnostic persistence are not preemptible.
    pub fn deliver_request_with_checkpoint<C: Fn() -> Result<(), RefusalCode> + ?Sized>(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &C,
    ) -> Result<(&'static str, Vec<u8>), String> {
        let (verdict, body) = self
            .dispatch_http_with_checkpoint(request, attempt, checkpoint)
            .map_err(|code| format!("{code:?}"))?;
        let verdict_str = match verdict {
            DeliveryVerdict::Accepted => "Accepted",
            DeliveryVerdict::DuplicateSuppressed => "DuplicateSuppressed",
            DeliveryVerdict::TransientFailure => "TransientFailure",
            DeliveryVerdict::PermanentRejection => "PermanentRejection",
            DeliveryVerdict::AmbiguousTimeout => "AmbiguousTimeout",
        };
        Ok((verdict_str, body))
    }

    #[cfg(test)]
    fn dispatch_http(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        self.dispatch_http_with_checkpoint(request, attempt, &|| Ok(()))
    }

    /// Transmit one HTTP POST under the same deadline and cancellation scope.
    fn dispatch_http_with_checkpoint<C: Fn() -> Result<(), RefusalCode> + ?Sized>(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
        checkpoint: &C,
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        if !self.registration.active || request.destination != self.destination_slug {
            return Err(RefusalCode::PublicationPolicyRefused);
        }
        if attempt == 0 || self.timeout.is_zero() {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let budget = request_io::Attempt::new(self.timeout, checkpoint)?;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        // 1. SSRF pre-check on registered URL
        let validated = match self.ssrf_policy.validate_url(self.registration.url.raw()) {
            Ok(v) => v,
            Err(WebhookRefusal::SsrfBlocked { reason, .. }) => {
                self.record_terminal_failure(request, attempt, reason, now_secs)?;
                return Ok((
                    DeliveryVerdict::PermanentRejection,
                    reason.as_bytes().to_vec(),
                ));
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.record_terminal_failure(request, attempt, &err_msg, now_secs)?;
                return Ok((DeliveryVerdict::PermanentRejection, err_msg.into_bytes()));
            }
        };

        // URL validation admits HTTPS, but this adapter only owns a plain
        // TCP stream. Refuse before DNS, signing or I/O; never silently
        // downgrade an operator's HTTPS destination to cleartext HTTP.
        if let Err(reason) = transport::require_plain_http(&validated) {
            self.record_terminal_failure(request, attempt, reason, now_secs)?;
            return Ok((
                DeliveryVerdict::PermanentRejection,
                reason.as_bytes().to_vec(),
            ));
        }

        // Serialize full, ordered canonical events. Retry metadata remains in
        // HTTP headers, so one delivery key always signs the same payload bytes.
        let payload = payload::encode(request)?;
        let payload_bytes = payload.as_bytes();

        // 2. Resolve a policy-approved address, then connect to that exact IP.
        budget.check()?;
        let resolved = self.resolve_safe_socket_addr(&validated);
        // The blocking resolver cannot be interrupted here. Its elapsed time
        // is nevertheless charged; an expired attempt never opens a socket.
        budget.check()?;
        let target_addr = match resolved {
            Ok(addr) => addr,
            Err(reason) => {
                self.record_terminal_failure(request, attempt, &reason, now_secs)?;
                return Ok((DeliveryVerdict::PermanentRejection, reason.into_bytes()));
            }
        };

        // 4. Compute HMAC signature using active secret
        let sig_tag = self.registration.secrets.sign_active(payload_bytes);
        let sig_hex = format!("sha256={}", hex_encode(sig_tag));

        // 5. Connect and send HTTP request
        let connected = TcpStream::connect_timeout(&target_addr, budget.check()?);
        budget.check()?;
        let mut stream = match connected {
            Ok(s) => s,
            Err(e) => {
                let err_msg = format!("TCP connection failed: {e}");
                return self.handle_network_failure(request, attempt, err_msg, now_secs);
            }
        };

        let http_header = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: FrankenGit-Webhook/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-FrankenGit-Delivery: {}\r\nX-FrankenGit-Signature-256: {}\r\nX-FrankenGit-Timestamp: {}\r\nX-FrankenGit-Attempt: {}\r\nConnection: close\r\n\r\n",
            validated.path_and_query(),
            validated.host(),
            validated.port(),
            payload_bytes.len(),
            request.key.as_str(),
            sig_hex,
            now_secs,
            attempt,
        );

        let exchanged = budget.exchange(&mut stream, http_header.as_bytes(), payload_bytes);
        // Close before any local persistence, including failure reporting.
        drop(stream);
        let response = match exchanged {
            Ok(response) => response,
            Err(request_io::Failure::Refused(code)) => return Err(code),
            Err(request_io::Failure::Unsent(error)) => {
                return self.handle_network_failure(
                    request,
                    attempt,
                    format!("HTTP setup failed before transmission: {error}"),
                    now_secs,
                );
            }
            Err(request_io::Failure::Ambiguous(reason)) => {
                return Ok((DeliveryVerdict::AmbiguousTimeout, reason.into_bytes()));
            }
        };

        // 7. Parse HTTP response status
        let status_code = match parse_http_status(&response) {
            Some(code) => code,
            None => {
                return Ok((
                    DeliveryVerdict::AmbiguousTimeout,
                    b"invalid, incomplete, or empty HTTP response".to_vec(),
                ));
            }
        };

        match status_code {
            200..=299 => {
                self.acknowledged
                    .lock()
                    .unwrap()
                    .push((request.key, attempt));
                // A retry ordinal is not evidence of receiver-side deduplication.
                Ok((DeliveryVerdict::Accepted, response))
            }
            301 | 302 | 307 | 308 => {
                // Check Location header for redirect SSRF validation
                if let Some(location) = extract_header(&response, "location") {
                    match self.ssrf_policy.validate_redirect(&validated, &location) {
                        Ok(_) => {
                            // Valid redirect target, retriable
                            Ok((DeliveryVerdict::TransientFailure, response))
                        }
                        Err(WebhookRefusal::SsrfBlocked { reason, .. }) => {
                            self.record_terminal_failure(request, attempt, reason, now_secs)?;
                            Ok((
                                DeliveryVerdict::PermanentRejection,
                                reason.as_bytes().to_vec(),
                            ))
                        }
                        Err(e) => {
                            let reason = e.to_string();
                            self.record_terminal_failure(request, attempt, &reason, now_secs)?;
                            Ok((DeliveryVerdict::PermanentRejection, reason.into_bytes()))
                        }
                    }
                } else {
                    Ok((
                        DeliveryVerdict::PermanentRejection,
                        b"missing location header on redirect".to_vec(),
                    ))
                }
            }
            400..=499 if status_code != 429 => {
                let reason = format!("receiver returned HTTP {status_code}");
                self.record_terminal_failure(request, attempt, &reason, now_secs)?;
                Ok((DeliveryVerdict::PermanentRejection, response))
            }
            _ => {
                // 429 or 5xx
                let reason = format!("receiver returned HTTP {status_code}");
                if attempt < self.registration.retry_schedule.max_attempts {
                    Ok((DeliveryVerdict::TransientFailure, response))
                } else {
                    self.record_terminal_failure(request, attempt, &reason, now_secs)?;
                    Ok((DeliveryVerdict::PermanentRejection, response))
                }
            }
        }
    }

    fn resolve_safe_socket_addr(&self, url: &ValidatedWebhookUrl) -> Result<SocketAddr, String> {
        if let Some(ip) = url.ip_literal() {
            if !self.ssrf_policy.is_safe_ip(ip) {
                return Err("SSRF policy blocked IP literal".into());
            }
            return Ok(SocketAddr::new(ip, url.port()));
        }

        let addrs = (url.host(), url.port())
            .to_socket_addrs()
            .map_err(|e| format!("DNS resolution error for {}: {e}", url.host()))?;

        for addr in addrs {
            if self.ssrf_policy.is_safe_ip(addr.ip()) {
                return Ok(addr);
            }
        }
        Err("all resolved IP addresses were rejected by SSRF policy".into())
    }

    fn handle_network_failure(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
        err_msg: String,
        now_secs: u64,
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        if attempt < self.registration.retry_schedule.max_attempts {
            Ok((DeliveryVerdict::TransientFailure, err_msg.into_bytes()))
        } else {
            self.record_terminal_failure(request, attempt, &err_msg, now_secs)?;
            Ok((DeliveryVerdict::PermanentRejection, err_msg.into_bytes()))
        }
    }

    fn record_terminal_failure(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
        reason: &str,
        now_secs: u64,
    ) -> Result<(), RefusalCode> {
        self.dead_letters
            .try_push(DeadLetterEntry {
                delivery_id: request.key,
                webhook_id: self.registration.id,
                target_url: self.registration.url.raw().to_string(),
                payload_root: request.payload_root,
                event_name: "forge_event".into(),
                attempts: attempt,
                terminal_reason: reason.to_string(),
                failed_at_unix_secs: now_secs,
            })
            .map_err(|_| RefusalCode::EvidenceMissing)
    }
}

impl OutboxDestination<Cx> for WebhookDeliveryDestination {
    fn destination(&self) -> AsciiSlug {
        self.destination_slug
    }

    fn idempotency(&self) -> DownstreamIdempotency {
        // Generic HTTP receivers provide no durable, queryable deduplication
        // contract. A volatile local ACK cache cannot establish Strong.
        DownstreamIdempotency::Weak
    }

    fn probe<'a>(
        &'a mut self,
        cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
    ) -> impl std::future::Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + Send + 'a
    {
        async move {
            request_checkpoint(cx)?;
            let acks = self.acknowledged.lock().unwrap();
            if acks.iter().any(|(k, _)| *k == request.key) {
                Ok((ProbeVerdict::Delivered, Vec::new()))
            } else {
                Ok((ProbeVerdict::Unknown, Vec::new()))
            }
        }
    }

    fn deliver<'a>(
        &'a mut self,
        cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
        attempt: u32,
    ) -> impl std::future::Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + Send + 'a
    {
        async move { self.dispatch_http_with_checkpoint(request, attempt, &|| request_checkpoint(cx)) }
    }
}

fn request_checkpoint(cx: &Cx) -> Result<(), RefusalCode> {
    match crate::checkpoint_pack_context(cx) {
        crate::PackContextCheckpoint::Live => Ok(()),
        crate::PackContextCheckpoint::Stopped {
            budget_exhaustion: Some(_),
        } => Err(RefusalCode::ResourceBudgetExceeded),
        crate::PackContextCheckpoint::Stopped {
            budget_exhaustion: None,
        } => Err(RefusalCode::CancellationInProgress),
    }
}

/// Select a complete final HTTP/1 response head, skipping at most eight
/// informational responses. Response bodies are arbitrary bytes, not UTF-8.
fn final_response_head(mut response: &[u8]) -> Option<(u16, &[u8])> {
    for _ in 0..=8 {
        let end = response.windows(4).position(|bytes| bytes == b"\r\n\r\n")?;
        let head = &response[..end + 2];
        let mut lines = head.split_inclusive(|byte| *byte == b'\n');
        let status = lines.next()?.strip_suffix(b"\r\n")?;
        if !matches!(status.get(..9)?, b"HTTP/1.0 " | b"HTTP/1.1 ")
            || status.get(12) != Some(&b' ')
            || !status.get(9..12)?.iter().all(u8::is_ascii_digit)
            || status
                .get(13..)?
                .iter()
                .any(|byte| byte.is_ascii_control() && *byte != b'\t')
        {
            return None;
        }
        let code = u16::from(status[9] - b'0') * 100
            + u16::from(status[10] - b'0') * 10
            + u16::from(status[11] - b'0');
        if !(100..=599).contains(&code) || code == 101 {
            return None;
        }
        for line in lines {
            let line = line.strip_suffix(b"\r\n")?;
            let colon = line.iter().position(|byte| *byte == b':')?;
            if colon == 0
                || !line[..colon]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
                || line[colon + 1..]
                    .iter()
                    .any(|byte| byte.is_ascii_control() && *byte != b'\t')
            {
                return None;
            }
        }
        if code >= 200 {
            return Some((code, head));
        }
        response = &response[end + 4..];
    }
    None
}

fn parse_http_status(response: &[u8]) -> Option<u16> {
    final_response_head(response).map(|(code, _)| code)
}

fn extract_header(response: &[u8], header_name: &str) -> Option<String> {
    let (_, head) = final_response_head(response)?;
    let mut found = None;
    for line in head.split_inclusive(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r\n")?;
        let colon = line.iter().position(|byte| *byte == b':')?;
        if line[..colon].eq_ignore_ascii_case(header_name.as_bytes()) {
            // Conflicting/duplicate routing metadata is not a redirect target.
            if found.is_some() {
                return None;
            }
            found = Some(
                std::str::from_utf8(&line[colon + 1..])
                    .ok()?
                    .trim()
                    .to_owned(),
            );
        }
    }
    found
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    let b = bytes.as_ref();
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        use core::fmt::Write;
        let _ = write!(s, "{:02x}", byte);
    }
    s
}

#[cfg(test)]
mod tests;
