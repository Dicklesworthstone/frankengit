//! Webhook delivery engine, OutboxDestination implementation, and dead-letter queue.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fgit_admission::merge::native::settlement::{DeliveryRequest, OutboxDestination};
use fgit_forge::webhook::{
    DeadLetterEntry, SsrfPolicy, ValidatedWebhookUrl, WebhookEventFilter, WebhookId,
    WebhookRefusal, WebhookRegistration, WebhookSecret,
};
use fgit_resource::settlement::{DeliveryVerdict, DownstreamIdempotency, ProbeVerdict};
use fgit_types::{AsciiSlug, RefusalCode};
use fsqlite_types::cx::Cx;

mod transport;

mod payload;
mod persistence;

use persistence::{
    parse_dead_letter_line, parse_registration_line, serialize_dead_letter, serialize_registration,
};

/// In-memory and file-backed Dead Letter Queue for terminally failed webhook deliveries.
#[derive(Clone, Debug, Default)]
pub struct DeadLetterQueue {
    entries: Arc<Mutex<Vec<DeadLetterEntry>>>,
    persist_path: Option<PathBuf>,
}

impl DeadLetterQueue {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            persist_path: None,
        }
    }

    pub fn with_persist_path(path: PathBuf) -> Self {
        let loaded = Self::load_from_path(&path);
        Self {
            entries: Arc::new(Mutex::new(loaded)),
            persist_path: Some(path),
        }
    }

    fn load_from_path(path: &Path) -> Vec<DeadLetterEntry> {
        if !path.exists() {
            return Vec::new();
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        let mut list = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(entry) = parse_dead_letter_line(trimmed) {
                list.push(entry);
            }
        }
        list
    }

    pub fn push(&self, entry: DeadLetterEntry) {
        let mut list = self.entries.lock().unwrap();
        // Keep unique by delivery_id
        list.retain(|existing| existing.delivery_id != entry.delivery_id);
        list.push(entry);
        if let Some(path) = &self.persist_path {
            Self::persist_all(path, &list);
        }
    }

    fn persist_all(path: &Path, entries: &[DeadLetterEntry]) {
        if let Ok(mut file) = std::fs::File::create(path) {
            for entry in entries {
                let _ = writeln!(file, "{}", serialize_dead_letter(entry));
            }
            let _ = file.flush();
        }
    }

    #[must_use]
    pub fn list(&self) -> Vec<DeadLetterEntry> {
        self.entries.lock().unwrap().clone()
    }

    #[must_use]
    pub fn get(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.delivery_id == delivery_id)
            .cloned()
    }

    pub fn remove(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        let mut list = self.entries.lock().unwrap();
        if let Some(pos) = list.iter().position(|e| e.delivery_id == delivery_id) {
            let removed = list.remove(pos);
            if let Some(path) = &self.persist_path {
                Self::persist_all(path, &list);
            }
            Some(removed)
        } else {
            None
        }
    }
}

/// Persistent storage for webhook registrations and dead letters under `storage_root/webhooks/`.
#[derive(Clone, Debug)]
pub struct WebhookStore {
    root_dir: PathBuf,
    dead_letters: DeadLetterQueue,
    registrations: Arc<Mutex<Vec<WebhookRegistration>>>,
}

impl WebhookStore {
    pub fn open(root_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&root_dir)
            .map_err(|e| format!("failed to create webhook directory: {e}"))?;
        let dl_path = root_dir.join("dead_letters.jsonl");
        let dead_letters = DeadLetterQueue::with_persist_path(dl_path);

        let reg_path = root_dir.join("registrations.json");
        let regs = Self::load_registrations(&reg_path)?;

        Ok(Self {
            root_dir,
            dead_letters,
            registrations: Arc::new(Mutex::new(regs)),
        })
    }

    fn load_registrations(path: &Path) -> Result<Vec<WebhookRegistration>, String> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read registrations: {e}"))?;
        let mut list = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(reg) = parse_registration_line(trimmed) {
                list.push(reg);
            }
        }
        Ok(list)
    }

    fn persist_registrations(&self) -> Result<(), String> {
        let path = self.root_dir.join("registrations.json");
        let list = self.registrations.lock().unwrap();
        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("failed to open registrations file for write: {e}"))?;
        for reg in list.iter() {
            let line = serialize_registration(reg);
            writeln!(file, "{line}").map_err(|e| format!("failed to write registration: {e}"))?;
        }
        file.flush()
            .map_err(|e| format!("failed to flush registrations: {e}"))?;
        Ok(())
    }

    pub fn register(&self, reg: WebhookRegistration) -> Result<(), String> {
        {
            let mut list = self.registrations.lock().unwrap();
            list.retain(|existing| existing.id != reg.id);
            list.push(reg);
        }
        self.persist_registrations()
    }

    #[must_use]
    pub fn list(&self) -> Vec<WebhookRegistration> {
        self.registrations.lock().unwrap().clone()
    }

    #[must_use]
    pub fn get(&self, id: WebhookId) -> Option<WebhookRegistration> {
        self.registrations
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    pub fn rotate_secret(
        &self,
        id: WebhookId,
        new_secret: WebhookSecret,
        window_duration_secs: u64,
        now_unix_secs: u64,
    ) -> Result<WebhookRegistration, String> {
        let updated = {
            let mut list = self.registrations.lock().unwrap();
            let reg = list
                .iter_mut()
                .find(|r| r.id == id)
                .ok_or_else(|| format!("webhook id {} not found", id.0))?;
            reg.secrets
                .rotate(new_secret, window_duration_secs, now_unix_secs);
            reg.clone()
        };
        self.persist_registrations()?;
        Ok(updated)
    }

    #[must_use]
    pub fn dead_letters(&self) -> DeadLetterQueue {
        self.dead_letters.clone()
    }

    #[must_use]
    pub fn list_dead_letters(&self) -> Vec<DeadLetterEntry> {
        self.dead_letters.list()
    }

    #[must_use]
    pub fn get_dead_letter(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.dead_letters.get(delivery_id)
    }

    pub fn replay_dead_letter(&self, delivery_id: AsciiSlug) -> Option<DeadLetterEntry> {
        self.dead_letters.remove(delivery_id)
    }
}

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
        let (verdict, body) = self
            .dispatch_http(request, attempt)
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

    /// Transmit one HTTP POST webhook delivery.
    fn dispatch_http(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        if !self.registration.active || request.destination != self.destination_slug {
            return Err(RefusalCode::PublicationPolicyRefused);
        }
        if attempt == 0 || self.timeout.is_zero() {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        // 1. SSRF pre-check on registered URL
        let validated = match self.ssrf_policy.validate_url(self.registration.url.raw()) {
            Ok(v) => v,
            Err(WebhookRefusal::SsrfBlocked { reason, .. }) => {
                self.record_terminal_failure(request, attempt, reason, now_secs);
                return Ok((
                    DeliveryVerdict::PermanentRejection,
                    reason.as_bytes().to_vec(),
                ));
            }
            Err(e) => {
                let err_msg = e.to_string();
                self.record_terminal_failure(request, attempt, &err_msg, now_secs);
                return Ok((DeliveryVerdict::PermanentRejection, err_msg.into_bytes()));
            }
        };

        // URL validation admits HTTPS, but this adapter only owns a plain
        // TCP stream. Refuse before DNS, signing or I/O; never silently
        // downgrade an operator's HTTPS destination to cleartext HTTP.
        if let Err(reason) = transport::require_plain_http(&validated) {
            self.record_terminal_failure(request, attempt, reason, now_secs);
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
        let target_addr = match self.resolve_safe_socket_addr(&validated) {
            Ok(addr) => addr,
            Err(reason) => {
                self.record_terminal_failure(request, attempt, &reason, now_secs);
                return Ok((DeliveryVerdict::PermanentRejection, reason.into_bytes()));
            }
        };

        // 4. Compute HMAC signature using active secret
        let sig_tag = self.registration.secrets.sign_active(payload_bytes);
        let sig_hex = format!("sha256={}", hex_encode(sig_tag));

        // 5. Connect and send HTTP request
        let mut stream = match TcpStream::connect_timeout(&target_addr, self.timeout) {
            Ok(s) => s,
            Err(e) => {
                let err_msg = format!("TCP connection failed: {e}");
                return self.handle_network_failure(request, attempt, err_msg, now_secs);
            }
        };

        if let Err(error) = stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
        {
            // No request bytes have been sent, so retry remains unambiguous.
            return self.handle_network_failure(
                request,
                attempt,
                format!("cannot install HTTP timeouts: {error}"),
                now_secs,
            );
        }

        let http_req = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: FrankenGit-Webhook/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-FrankenGit-Delivery: {}\r\nX-FrankenGit-Signature-256: {}\r\nX-FrankenGit-Timestamp: {}\r\nX-FrankenGit-Attempt: {}\r\nConnection: close\r\n\r\n{}",
            validated.path_and_query(),
            validated.host(),
            validated.port(),
            payload_bytes.len(),
            request.key.as_str(),
            sig_hex,
            now_secs,
            attempt,
            payload
        );

        if let Err(e) = stream
            .write_all(http_req.as_bytes())
            .and_then(|()| stream.flush())
        {
            // write_all can fail after sending a prefix or the complete body.
            // A lost response is not proof that the receiver rejected the effect.
            return Ok((
                DeliveryVerdict::AmbiguousTimeout,
                format!("HTTP write outcome unknown: {e}").into_bytes(),
            ));
        }

        // 6. Read HTTP response
        let mut response = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&buf[..n]);
                    if response.len() > 65536 {
                        return Ok((
                            DeliveryVerdict::AmbiguousTimeout,
                            b"HTTP response headers exceed the 64 KiB limit".to_vec(),
                        ));
                    }
                    // A complete final status is the acknowledgement. Do not
                    // wait for EOF (or a response body) on a keep-alive peer.
                    if parse_http_status(&response).is_some() {
                        break;
                    }
                }
                Err(e) => {
                    return Ok((
                        DeliveryVerdict::AmbiguousTimeout,
                        format!("HTTP response outcome unknown: {e}").into_bytes(),
                    ));
                }
            }
        }

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
                            self.record_terminal_failure(request, attempt, reason, now_secs);
                            Ok((
                                DeliveryVerdict::PermanentRejection,
                                reason.as_bytes().to_vec(),
                            ))
                        }
                        Err(e) => {
                            let reason = e.to_string();
                            self.record_terminal_failure(request, attempt, &reason, now_secs);
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
                self.record_terminal_failure(request, attempt, &reason, now_secs);
                Ok((DeliveryVerdict::PermanentRejection, response))
            }
            _ => {
                // 429 or 5xx
                let reason = format!("receiver returned HTTP {status_code}");
                if attempt < self.registration.retry_schedule.max_attempts {
                    Ok((DeliveryVerdict::TransientFailure, response))
                } else {
                    self.record_terminal_failure(request, attempt, &reason, now_secs);
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
            self.record_terminal_failure(request, attempt, &err_msg, now_secs);
            Ok((DeliveryVerdict::PermanentRejection, err_msg.into_bytes()))
        }
    }

    fn record_terminal_failure(
        &self,
        request: &DeliveryRequest<'_>,
        attempt: u32,
        reason: &str,
        now_secs: u64,
    ) {
        self.dead_letters.push(DeadLetterEntry {
            delivery_id: request.key,
            webhook_id: self.registration.id,
            target_url: self.registration.url.raw().to_string(),
            payload_root: request.payload_root,
            event_name: "forge_event".into(),
            attempts: attempt,
            terminal_reason: reason.to_string(),
            failed_at_unix_secs: now_secs,
        });
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
        _cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
    ) -> impl std::future::Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + Send + 'a
    {
        async move {
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
        _cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
        attempt: u32,
    ) -> impl std::future::Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + Send + 'a
    {
        async move { self.dispatch_http(request, attempt) }
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
