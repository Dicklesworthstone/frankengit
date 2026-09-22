//! Webhook delivery product types, signing, secret rotation, SSRF validation,
//! and retry schedule.

use core::fmt;
use fgit_crypto::{hmac_sha256, verify_mac};
use fgit_types::{AsciiSlug, Digest};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Unique identifier for a registered webhook.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WebhookId(pub u64);

impl fmt::Display for WebhookId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Typed refusal codes for webhook operations and delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookRefusal {
    /// URL failed SSRF validation (internal/private/loopback/link-local/metadata IP).
    SsrfBlocked { url: String, reason: &'static str },
    /// URL scheme is not supported (only http and https are admitted).
    UnsupportedScheme(String),
    /// URL failed syntax parsing.
    InvalidUrl(String),
    /// Secret has invalid length or format.
    InvalidSecret(&'static str),
    /// Signature verification failed.
    InvalidSignature,
    /// Rotation window expired or invalid timestamp.
    RotationExpired,
    /// Target not found in registrations.
    NotFound(WebhookId),
    /// Delivery attempts exhausted.
    DeliveryExhausted { attempts: u32 },
}

impl fmt::Display for WebhookRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SsrfBlocked { url, reason } => write!(f, "SSRF blocked for {url}: {reason}"),
            Self::UnsupportedScheme(scheme) => write!(f, "unsupported webhook scheme: {scheme}"),
            Self::InvalidUrl(err) => write!(f, "invalid webhook URL: {err}"),
            Self::InvalidSecret(err) => write!(f, "invalid webhook secret: {err}"),
            Self::InvalidSignature => write!(f, "invalid webhook signature"),
            Self::RotationExpired => write!(f, "webhook secret rotation window expired"),
            Self::NotFound(id) => write!(f, "webhook {id} not found"),
            Self::DeliveryExhausted { attempts } => {
                write!(f, "webhook delivery exhausted after {attempts} attempts")
            }
        }
    }
}

/// Validated webhook URL guaranteed to have undergone SSRF validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedWebhookUrl {
    raw: String,
    scheme: String,
    host: String,
    port: u16,
    path_and_query: String,
    ip_literal: Option<IpAddr>,
}

impl ValidatedWebhookUrl {
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[must_use]
    pub fn path_and_query(&self) -> &str {
        &self.path_and_query
    }

    #[must_use]
    pub fn ip_literal(&self) -> Option<IpAddr> {
        self.ip_literal
    }

    #[doc(hidden)]
    pub fn new_unchecked_for_testing(
        raw: impl Into<String>,
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        path_and_query: impl Into<String>,
        ip_literal: Option<IpAddr>,
    ) -> Self {
        Self {
            raw: raw.into(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path_and_query: path_and_query.into(),
            ip_literal,
        }
    }
}

/// SSRF policy enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SsrfPolicy {
    allow_loopback: bool,
}

impl SsrfPolicy {
    /// Strict policy for production: loopback, private, and internal addresses are forbidden.
    pub const STRICT: Self = Self {
        allow_loopback: false,
    };

    /// Permissive loopback policy for test environments and local development.
    pub const PERMISSIVE_FOR_TESTS: Self = Self {
        allow_loopback: true,
    };

    #[must_use]
    pub const fn allows_loopback(self) -> bool {
        self.allow_loopback
    }

    /// Classifies an IP address: returns true if the IP is publicly routable and
    /// safe for outbound webhook egress under this policy.
    #[must_use]
    pub fn is_safe_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.is_safe_ipv4(v4),
            IpAddr::V6(v6) => self.is_safe_ipv6(v6),
        }
    }

    fn is_safe_ipv4(&self, ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        // 0.0.0.0/8 (current network)
        if octets[0] == 0 {
            return false;
        }
        // 127.0.0.0/8 (loopback)
        if octets[0] == 127 {
            return self.allow_loopback;
        }
        // 10.0.0.0/8 (private)
        if octets[0] == 10 {
            return false;
        }
        // 172.16.0.0/12 (private: 172.16.0.0 - 172.31.255.255)
        if octets[0] == 172 && (16..=31).contains(&octets[1]) {
            return false;
        }
        // 192.168.0.0/16 (private)
        if octets[0] == 192 && octets[1] == 168 {
            return false;
        }
        // 169.254.0.0/16 (link-local and cloud metadata 169.254.169.254)
        if octets[0] == 169 && octets[1] == 254 {
            return false;
        }
        // 100.64.0.0/10 (carrier-grade NAT, RFC 6598)
        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return false;
        }
        // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NET-1, TEST-NET-2, TEST-NET-3)
        if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        {
            return false;
        }
        // 224.0.0.0/4 (multicast)
        if octets[0] >= 224 && octets[0] <= 239 {
            return false;
        }
        // 240.0.0.0/4 (reserved / broadcast)
        if octets[0] >= 240 {
            return false;
        }
        true
    }

    fn is_safe_ipv6(&self, ip: Ipv6Addr) -> bool {
        // ::1 loopback
        if ip.is_loopback() {
            return self.allow_loopback;
        }
        // :: unspecified
        if ip.is_unspecified() {
            return false;
        }
        // IPv4-mapped IPv6: ::ffff:a.b.c.d
        let segments = ip.segments();
        if segments[0] == 0
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0xffff
        {
            let v4 = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                (segments[6] & 0xff) as u8,
                (segments[7] >> 8) as u8,
                (segments[7] & 0xff) as u8,
            );
            return self.is_safe_ipv4(v4);
        }
        // NAT64 well-known prefix: 64:ff9b::/96 (RFC 6052)
        if segments[0] == 0x0064
            && segments[1] == 0xff9b
            && segments[2] == 0
            && segments[3] == 0
            && segments[4] == 0
            && segments[5] == 0
        {
            let v4 = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                (segments[6] & 0xff) as u8,
                (segments[7] >> 8) as u8,
                (segments[7] & 0xff) as u8,
            );
            return self.is_safe_ipv4(v4);
        }
        // 6to4 prefix: 2002::/16 (RFC 3056)
        if segments[0] == 0x2002 {
            let v4 = Ipv4Addr::new(
                (segments[1] >> 8) as u8,
                (segments[1] & 0xff) as u8,
                (segments[2] >> 8) as u8,
                (segments[2] & 0xff) as u8,
            );
            return self.is_safe_ipv4(v4);
        }
        // Discard prefix: 100::/64 (RFC 6666)
        if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
            return false;
        }
        // fc00::/7 (unique local address / ULA, RFC 4193)
        if (segments[0] & 0xfe00) == 0xfc00 {
            return false;
        }
        // fe80::/10 (link-local unicast)
        if (segments[0] & 0xffc0) == 0xfe80 {
            return false;
        }
        // ff00::/8 (multicast)
        if (segments[0] & 0xff00) == 0xff00 {
            return false;
        }
        // 2001:db8::/32 (documentation)
        if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            return false;
        }
        true
    }

    /// Parse and validate a URL against SSRF rules.
    pub fn validate_url(&self, raw: &str) -> Result<ValidatedWebhookUrl, WebhookRefusal> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(WebhookRefusal::InvalidUrl("empty URL".into()));
        }
        if trimmed.len() > 4096 {
            return Err(WebhookRefusal::InvalidUrl(
                "URL exceeds maximum length of 4096 bytes".into(),
            ));
        }

        // Scheme extraction
        let (scheme, rest) = if let Some(stripped) = trimmed.strip_prefix("https://") {
            ("https", stripped)
        } else if let Some(stripped) = trimmed.strip_prefix("http://") {
            ("http", stripped)
        } else {
            let s = trimmed.split("://").next().unwrap_or(trimmed);
            return Err(WebhookRefusal::UnsupportedScheme(s.to_string()));
        };

        // Reject embedded credentials (user:pass@host)
        if let Some(at_idx) = rest.find('@') {
            let slash_idx = rest.find('/').unwrap_or(rest.len());
            if at_idx < slash_idx {
                return Err(WebhookRefusal::InvalidUrl(
                    "embedded credentials (@) not permitted in webhook URLs".into(),
                ));
            }
        }

        // Split authority from path_and_query
        let (authority, path_and_query) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        if authority.is_empty() {
            return Err(WebhookRefusal::InvalidUrl("missing host in URL".into()));
        }

        // Parse host and optional port
        let (host_str, port) = if authority.starts_with('[') {
            // IPv6 literal: [::1]:port or [::1]
            let close_bracket = authority.find(']').ok_or_else(|| {
                WebhookRefusal::InvalidUrl("unclosed IPv6 literal bracket".into())
            })?;
            let ipv6_text = &authority[1..close_bracket];
            let remainder = &authority[close_bracket + 1..];
            let port = if let Some(port_str) = remainder.strip_prefix(':') {
                port_str
                    .parse::<u16>()
                    .map_err(|_| WebhookRefusal::InvalidUrl("invalid port number".into()))?
            } else if remainder.is_empty() {
                if scheme == "https" { 443 } else { 80 }
            } else {
                return Err(WebhookRefusal::InvalidUrl(
                    "unexpected characters after IPv6 literal".into(),
                ));
            };
            (ipv6_text, port)
        } else if let Some(colon_idx) = authority.rfind(':') {
            let host_part = &authority[..colon_idx];
            let port_part = &authority[colon_idx + 1..];
            let port = port_part
                .parse::<u16>()
                .map_err(|_| WebhookRefusal::InvalidUrl("invalid port number".into()))?;
            (host_part, port)
        } else {
            let default_port = if scheme == "https" { 443 } else { 80 };
            (authority, default_port)
        };

        if port == 0 {
            return Err(WebhookRefusal::InvalidUrl("port 0 is not permitted".into()));
        }

        // Check for IP literal obfuscation (e.g. integer IP like 2130706433 or octal like 0177.0.0.1)
        if host_str.chars().all(|c| c.is_ascii_digit()) {
            // Pure decimal integer IP address
            return Err(WebhookRefusal::SsrfBlocked {
                url: raw.to_string(),
                reason: "numeric decimal IP address representation is forbidden",
            });
        }
        if host_str.starts_with("0x") || host_str.starts_with("0X") {
            return Err(WebhookRefusal::SsrfBlocked {
                url: raw.to_string(),
                reason: "hexadecimal IP address representation is forbidden",
            });
        }
        // Check for octal dotted components (e.g. 0177.0.0.1)
        if host_str.split('.').any(|part| {
            part.len() > 1 && part.starts_with('0') && part.chars().all(|c| c.is_ascii_digit())
        }) {
            return Err(WebhookRefusal::SsrfBlocked {
                url: raw.to_string(),
                reason: "octal IP address notation is forbidden",
            });
        }

        // Check if host_str is an IP literal
        let ip_literal = if let Ok(ipv4) = host_str.parse::<Ipv4Addr>() {
            let ip = IpAddr::V4(ipv4);
            if !self.is_safe_ip(ip) {
                return Err(WebhookRefusal::SsrfBlocked {
                    url: raw.to_string(),
                    reason: "target IPv4 address is in a forbidden private or local range",
                });
            }
            Some(ip)
        } else if let Ok(ipv6) = host_str.parse::<Ipv6Addr>() {
            let ip = IpAddr::V6(ipv6);
            if !self.is_safe_ip(ip) {
                return Err(WebhookRefusal::SsrfBlocked {
                    url: raw.to_string(),
                    reason: "target IPv6 address is in a forbidden private or local range",
                });
            }
            Some(ip)
        } else {
            // Validate hostname syntax
            if host_str.eq_ignore_ascii_case("localhost") && !self.allow_loopback {
                return Err(WebhookRefusal::SsrfBlocked {
                    url: raw.to_string(),
                    reason: "localhost is forbidden under strict SSRF policy",
                });
            }
            for label in host_str.split('.') {
                if label.is_empty() || label.len() > 63 {
                    return Err(WebhookRefusal::InvalidUrl(
                        "invalid DNS label length".into(),
                    ));
                }
                if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(WebhookRefusal::InvalidUrl(
                        "invalid characters in hostname".into(),
                    ));
                }
                if label.starts_with('-') || label.ends_with('-') {
                    return Err(WebhookRefusal::InvalidUrl(
                        "hostname label cannot start or end with hyphen".into(),
                    ));
                }
            }
            None
        };

        Ok(ValidatedWebhookUrl {
            raw: trimmed.to_string(),
            scheme: scheme.to_string(),
            host: host_str.to_ascii_lowercase(),
            port,
            path_and_query: path_and_query.to_string(),
            ip_literal,
        })
    }

    /// Re-validates a redirect URL against this policy, preventing redirect-based SSRF bypass.
    pub fn validate_redirect(
        &self,
        current: &ValidatedWebhookUrl,
        location: &str,
    ) -> Result<ValidatedWebhookUrl, WebhookRefusal> {
        let target = location.trim();
        if target.starts_with("http://") || target.starts_with("https://") {
            self.validate_url(target)
        } else if target.starts_with('/') {
            // Relative redirect on the same host
            let new_raw = format!(
                "{}://{}{}{}",
                current.scheme,
                current.host,
                if (current.scheme == "https" && current.port == 443)
                    || (current.scheme == "http" && current.port == 80)
                {
                    "".to_string()
                } else {
                    format!(":{}", current.port)
                },
                target
            );
            self.validate_url(&new_raw)
        } else {
            Err(WebhookRefusal::InvalidUrl(format!(
                "unrecognized redirect target: {location}"
            )))
        }
    }
}

/// Webhook signing secret with support for rotation windows.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret {
    bytes: Vec<u8>,
}

impl WebhookSecret {
    pub const MIN_SECRET_BYTES: usize = 16;
    pub const MAX_SECRET_BYTES: usize = 256;

    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, WebhookRefusal> {
        let bytes = secret.into();
        if bytes.len() < Self::MIN_SECRET_BYTES {
            return Err(WebhookRefusal::InvalidSecret(
                "secret must be at least 16 bytes",
            ));
        }
        if bytes.len() > Self::MAX_SECRET_BYTES {
            return Err(WebhookRefusal::InvalidSecret(
                "secret must be at most 256 bytes",
            ));
        }
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Compute HMAC-SHA256 signature for a payload.
    #[must_use]
    pub fn sign(&self, payload: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.bytes, payload)
    }

    /// Constant-time verification of candidate signature.
    #[must_use]
    pub fn verify(&self, payload: &[u8], candidate_signature: &[u8; 32]) -> bool {
        let expected = self.sign(payload);
        verify_mac(&expected, candidate_signature)
    }

    /// Hex-encoded signature string with "sha256=" prefix (standard GitHub format).
    #[must_use]
    pub fn sign_hex(&self, payload: &[u8]) -> String {
        let tag = self.sign(payload);
        format!("sha256={}", hex::encode(tag))
    }
}

impl core::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WebhookSecret([REDACTED {} bytes])", self.bytes.len())
    }
}

/// Webhook secret manager with rotation window support.
///
/// During the rotation window, payloads can be verified against either the active
/// secret or the expiring secret. Once the window expires, the old secret is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookSecretRotation {
    active: WebhookSecret,
    expiring: Option<(WebhookSecret, u64)>, // (secret, expires_at_unix_secs)
}

impl WebhookSecretRotation {
    pub fn new(initial_secret: WebhookSecret) -> Self {
        Self {
            active: initial_secret,
            expiring: None,
        }
    }

    #[must_use]
    pub fn active(&self) -> &WebhookSecret {
        &self.active
    }

    #[must_use]
    pub fn expiring(&self) -> Option<(&WebhookSecret, u64)> {
        self.expiring.as_ref().map(|(s, t)| (s, *t))
    }

    /// Rotate to a new secret with a specified rotation window duration in seconds.
    pub fn rotate(
        &mut self,
        new_secret: WebhookSecret,
        window_duration_secs: u64,
        now_unix_secs: u64,
    ) {
        let old = std::mem::replace(&mut self.active, new_secret);
        self.expiring = Some((old, now_unix_secs.saturating_add(window_duration_secs)));
    }

    /// Signs payloads using the currently active secret.
    #[must_use]
    pub fn sign_active(&self, payload: &[u8]) -> [u8; 32] {
        self.active.sign(payload)
    }

    /// Verify signature against active secret, or against expiring secret if within window.
    #[must_use]
    pub fn verify(
        &self,
        payload: &[u8],
        candidate_signature: &[u8; 32],
        now_unix_secs: u64,
    ) -> bool {
        if self.active.verify(payload, candidate_signature) {
            return true;
        }
        if let Some((expiring_secret, expires_at)) = &self.expiring {
            if now_unix_secs <= *expires_at && expiring_secret.verify(payload, candidate_signature)
            {
                return true;
            }
        }
        false
    }

    /// Verify hex signature (e.g. "sha256=<hex>").
    pub fn verify_hex(&self, payload: &[u8], header_value: &str, now_unix_secs: u64) -> bool {
        let hex_str = if let Some(stripped) = header_value.strip_prefix("sha256=") {
            stripped
        } else {
            header_value
        };
        let candidate = match hex::decode(hex_str) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            _ => return false,
        };
        self.verify(payload, &candidate, now_unix_secs)
    }
}

/// Deterministic retry schedule with exponential backoff and bounded jitter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebhookRetrySchedule {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
}

impl Default for WebhookRetrySchedule {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        }
    }
}

impl WebhookRetrySchedule {
    pub const MIN_ATTEMPTS: u32 = 2;
    pub const MAX_ATTEMPTS: u32 = 16;

    pub fn new(
        max_attempts: u32,
        initial_delay: Duration,
        max_delay: Duration,
    ) -> Result<Self, WebhookRefusal> {
        if !(Self::MIN_ATTEMPTS..=Self::MAX_ATTEMPTS).contains(&max_attempts) {
            return Err(WebhookRefusal::InvalidSecret(
                "max_attempts must be in 2..=16",
            ));
        }
        Ok(Self {
            max_attempts,
            initial_delay,
            max_delay,
        })
    }

    /// Compute bounded delay for a given attempt ordinal (1-based), with deterministic jitter.
    #[must_use]
    pub fn delay_for_attempt(&self, attempt: u32, jitter_seed: u64) -> Duration {
        if attempt <= 1 {
            return Duration::ZERO;
        }
        let exp = (attempt - 1).min(10);
        let factor = 1u64.checked_shl(exp - 1).unwrap_or(u64::MAX);
        let base_millis = self.initial_delay.as_millis() as u64;
        let exp_millis = base_millis
            .saturating_mul(factor)
            .min(self.max_delay.as_millis() as u64);

        // Deterministic pseudorandom jitter in range [-20%, +20%]
        // Hash combination of seed and attempt:
        let hash_input = [jitter_seed.to_le_bytes(), (attempt as u64).to_le_bytes()].concat();
        let digest = fgit_crypto::sha256_digest(&hash_input);
        let rand_val = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        // Map 0..u32::MAX to -200..+200 (representing -20.0% to +20.0%)
        let jitter_permille = (rand_val % 401) as i64 - 200;
        let delta = (exp_millis as i64 * jitter_permille) / 1000;
        let final_millis = (exp_millis as i64 + delta).max(0) as u64;
        Duration::from_millis(final_millis)
    }
}

/// Filter determining which forge events trigger a given webhook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebhookEventFilter {
    /// Deliver all forge events.
    Wildcard,
    /// Deliver only specific event kinds.
    Selected(Vec<String>),
}

impl WebhookEventFilter {
    #[must_use]
    pub fn matches(&self, event_name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Selected(list) => list
                .iter()
                .any(|item| item.eq_ignore_ascii_case(event_name)),
        }
    }
}

/// Registration record for one webhook subscription.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookRegistration {
    pub id: WebhookId,
    pub url: ValidatedWebhookUrl,
    pub secrets: WebhookSecretRotation,
    pub filter: WebhookEventFilter,
    pub active: bool,
    pub retry_schedule: WebhookRetrySchedule,
}

/// A record in the dead-letter queue for deliveries that failed terminally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeadLetterEntry {
    pub delivery_id: AsciiSlug,
    pub webhook_id: WebhookId,
    pub target_url: String,
    pub payload_root: Digest,
    pub event_name: String,
    pub attempts: u32,
    pub terminal_reason: String,
    pub failed_at_unix_secs: u64,
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let b = bytes.as_ref();
        let mut s = String::with_capacity(b.len() * 2);
        for byte in b {
            use core::fmt::Write;
            let _ = write!(s, "{:02x}", byte);
        }
        s
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
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
}

#[cfg(test)]
mod tests;
