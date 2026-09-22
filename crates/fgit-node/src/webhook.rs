//! Webhook delivery engine, OutboxDestination implementation, and dead-letter queue.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fgit_admission::merge::native::settlement::{DeliveryRequest, OutboxDestination};
use fgit_forge::webhook::{
    DeadLetterEntry, SsrfPolicy, ValidatedWebhookUrl, WebhookEventFilter, WebhookId,
    WebhookRefusal, WebhookRegistration, WebhookRetrySchedule, WebhookSecret,
    WebhookSecretRotation,
};
use fgit_resource::settlement::{DeliveryVerdict, DownstreamIdempotency, ProbeVerdict};
use fgit_types::{AsciiSlug, Digest, RefusalCode};
use fsqlite_types::cx::Cx;

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

    /// Transmit one HTTP POST webhook delivery for CLI execution or direct driver.
    pub fn deliver_simple(
        &self,
        key: AsciiSlug,
        attempt: u32,
    ) -> Result<(&'static str, Vec<u8>), String> {
        let empty_events = fgit_forge::ForgeEventBatch { events: Vec::new() };
        let dummy_digest = Digest::new(
            fgit_types::DigestAlgorithmId::try_new(1).unwrap(),
            fgit_types::DigestBytes::try_new(&[0xaa; 32]).unwrap(),
        );
        let request = DeliveryRequest {
            key,
            destination: self.destination_slug,
            payload_root: dummy_digest,
            events: &empty_events,
        };
        let (verdict, body) = self
            .dispatch_http(&request, attempt)
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

        // 2. Resolve DNS safely and check every resolved IP against SSRF policy
        let target_addr = match self.resolve_safe_socket_addr(&validated) {
            Ok(addr) => addr,
            Err(reason) => {
                self.record_terminal_failure(request, attempt, &reason, now_secs);
                return Ok((DeliveryVerdict::PermanentRejection, reason.into_bytes()));
            }
        };

        // 3. Construct JSON payload
        let payload = format!(
            "{{\"delivery_id\":\"{}\",\"destination\":\"{}\",\"payload_root\":\"{}\",\"events_count\":{},\"attempt\":{},\"timestamp\":{}}}",
            request.key.as_str(),
            request.destination.as_str(),
            request.payload_root,
            request.events.events.len(),
            attempt,
            now_secs
        );
        let payload_bytes = payload.as_bytes();

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

        let _ = stream.set_read_timeout(Some(self.timeout));
        let _ = stream.set_write_timeout(Some(self.timeout));

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
            let err_msg = format!("HTTP write error: {e}");
            return self.handle_network_failure(request, attempt, err_msg, now_secs);
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
                        break;
                    }
                }
                Err(e) => {
                    let err_msg = format!("HTTP read error: {e}");
                    return self.handle_network_failure(request, attempt, err_msg, now_secs);
                }
            }
        }

        // 7. Parse HTTP response status
        let status_code = match parse_http_status(&response) {
            Some(code) => code,
            None => {
                let err_msg = "invalid or empty HTTP response".to_string();
                return self.handle_network_failure(request, attempt, err_msg, now_secs);
            }
        };

        match status_code {
            200..=299 => {
                self.acknowledged
                    .lock()
                    .unwrap()
                    .push((request.key, attempt));
                let verdict = if attempt == 1 {
                    DeliveryVerdict::Accepted
                } else {
                    DeliveryVerdict::DuplicateSuppressed
                };
                Ok((verdict, response))
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
        DownstreamIdempotency::Strong
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

fn parse_http_status(response: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(response).ok()?;
    let first_line = text.lines().next()?;
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse::<u16>().ok()
    } else {
        None
    }
}

fn extract_header(response: &[u8], header_name: &str) -> Option<String> {
    let text = std::str::from_utf8(response).ok()?;
    let needle = header_name.to_ascii_lowercase();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(&needle) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
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

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ())?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out
}

fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":", key);
    let idx = json.find(&needle)? + needle.len();
    let rest = json[idx..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let rest = &rest[1..];
    let mut s = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    match escaped {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        _ => s.push(escaped),
                    }
                }
            }
            '"' => return Some(s),
            _ => s.push(c),
        }
    }
    None
}

fn extract_json_u64(json: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{}\":", key);
    let idx = json.find(&needle)? + needle.len();
    let rest = json[idx..].trim_start();
    let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse::<u64>().ok()
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{}\":", key);
    let idx = json.find(&needle)? + needle.len();
    let rest = json[idx..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn serialize_registration(reg: &WebhookRegistration) -> String {
    let filter_str = match &reg.filter {
        WebhookEventFilter::Wildcard => "\"*\"".to_string(),
        WebhookEventFilter::Selected(list) => {
            let items: Vec<String> = list.iter().map(|s| format!("\"{}\"", s)).collect();
            format!("[{}]", items.join(","))
        }
    };
    let active_secret_hex = hex_encode(reg.secrets.active().as_bytes());
    let expiring_json = match reg.secrets.expiring() {
        Some((sec, ts)) => format!(
            "{{\"secret_hex\":\"{}\",\"expires_at\":{}}}",
            hex_encode(sec.as_bytes()),
            ts
        ),
        None => "null".to_string(),
    };
    format!(
        "{{\"id\":{},\"url\":\"{}\",\"active_secret_hex\":\"{}\",\"expiring\":{},\"filter\":{},\"active\":{},\"max_attempts\":{},\"initial_delay_ms\":{},\"max_delay_ms\":{}}}",
        reg.id.0,
        reg.url.raw(),
        active_secret_hex,
        expiring_json,
        filter_str,
        reg.active,
        reg.retry_schedule.max_attempts,
        reg.retry_schedule.initial_delay.as_millis(),
        reg.retry_schedule.max_delay.as_millis(),
    )
}

fn serialize_dead_letter(entry: &DeadLetterEntry) -> String {
    format!(
        "{{\"delivery_id\":\"{}\",\"webhook_id\":{},\"target_url\":\"{}\",\"payload_root\":\"{}\",\"event_name\":\"{}\",\"attempts\":{},\"terminal_reason\":\"{}\",\"failed_at_unix_secs\":{}}}",
        entry.delivery_id.as_str(),
        entry.webhook_id.0,
        entry.target_url,
        entry.payload_root,
        entry.event_name,
        entry.attempts,
        escape_json(&entry.terminal_reason),
        entry.failed_at_unix_secs,
    )
}

fn parse_registration_line(line: &str) -> Option<WebhookRegistration> {
    let id_val = extract_json_u64(line, "id")?;
    let url_raw = extract_json_str(line, "url")?;
    let secret_hex = extract_json_str(line, "active_secret_hex")?;
    let secret_bytes = hex_decode(&secret_hex).ok()?;
    let secret = WebhookSecret::new(secret_bytes).ok()?;
    let mut rotation = WebhookSecretRotation::new(secret);
    if let Some(expiring_hex) = extract_json_str(line, "secret_hex") {
        if let Some(expires_at) = extract_json_u64(line, "expires_at") {
            if let Ok(exp_bytes) = hex_decode(&expiring_hex) {
                if let Ok(exp_sec) = WebhookSecret::new(exp_bytes) {
                    rotation.rotate(exp_sec, 0, expires_at);
                }
            }
        }
    }
    let filter = if line.contains("\"filter\":\"*\"") || line.contains("\"filter\": \"*\"") {
        WebhookEventFilter::Wildcard
    } else {
        WebhookEventFilter::Wildcard
    };
    let active = extract_json_bool(line, "active").unwrap_or(true);
    let max_attempts = extract_json_u64(line, "max_attempts").unwrap_or(5) as u32;
    let initial_delay_ms = extract_json_u64(line, "initial_delay_ms").unwrap_or(1000);
    let max_delay_ms = extract_json_u64(line, "max_delay_ms").unwrap_or(60000);

    let retry_schedule = WebhookRetrySchedule {
        max_attempts,
        initial_delay: Duration::from_millis(initial_delay_ms),
        max_delay: Duration::from_millis(max_delay_ms),
    };

    let url = SsrfPolicy::PERMISSIVE_FOR_TESTS
        .validate_url(&url_raw)
        .ok()?;

    Some(WebhookRegistration {
        id: WebhookId(id_val),
        url,
        secrets: rotation,
        filter,
        active,
        retry_schedule,
    })
}

fn parse_dead_letter_line(line: &str) -> Option<DeadLetterEntry> {
    let delivery_id_str = extract_json_str(line, "delivery_id")?;
    let delivery_id = AsciiSlug::try_new("delivery_id", delivery_id_str.as_bytes()).ok()?;
    let webhook_id_val = extract_json_u64(line, "webhook_id")?;
    let target_url = extract_json_str(line, "target_url")?;
    let attempts = extract_json_u64(line, "attempts").unwrap_or(1) as u32;
    let terminal_reason = extract_json_str(line, "terminal_reason").unwrap_or_default();
    let failed_at_unix_secs = extract_json_u64(line, "failed_at_unix_secs").unwrap_or(0);

    let dummy_digest = Digest::new(
        fgit_types::DigestAlgorithmId::try_new(1).unwrap(),
        fgit_types::DigestBytes::try_new(&[0xaa; 32]).unwrap(),
    );

    Some(DeadLetterEntry {
        delivery_id,
        webhook_id: WebhookId(webhook_id_val),
        target_url,
        payload_root: dummy_digest,
        event_name: "forge-event".to_string(),
        attempts,
        terminal_reason,
        failed_at_unix_secs,
    })
}

#[cfg(test)]
mod tests;
