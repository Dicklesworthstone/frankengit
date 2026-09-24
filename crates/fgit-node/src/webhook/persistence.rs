//! Bounded, lossless JSONL records for operator webhook configuration and
//! diagnostic dead letters. These records do not authorize an outbox effect;
//! replay must still load and verify its authority-selected payload root.

use std::collections::BTreeMap;
use std::time::Duration;

use fgit_forge::webhook::{
    DeadLetterEntry, SsrfPolicy, WebhookEventFilter, WebhookId, WebhookRegistration,
    WebhookRetrySchedule, WebhookSecret, WebhookSecretRotation,
};
use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};

pub(super) const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_VALUES: usize = 4096;
const MAX_DEPTH: usize = 4;

// This is deliberately the closed JSON subset used by these records, not a
// general API JSON parser: numbers are unsigned integers, nesting is bounded,
// duplicate keys and unknown record fields refuse, and trailing bytes refuse.
#[derive(Debug, PartialEq, Eq)]
enum Value {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Value {
    fn string(&self) -> Option<&str> {
        match self { Self::String(value) => Some(value), _ => None }
    }

    fn number(&self) -> Option<u64> {
        match self { Self::Number(value) => Some(*value), _ => None }
    }

    fn boolean(&self) -> Option<bool> {
        match self { Self::Bool(value) => Some(*value), _ => None }
    }
}

struct Reader<'a> {
    rest: &'a str,
    remaining_values: usize,
}

impl Reader<'_> {
    fn space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t', '\r', '\n']);
    }

    fn take(&mut self, token: &str) -> Option<()> {
        self.space();
        self.rest = self.rest.strip_prefix(token)?;
        Some(())
    }

    fn character(&mut self) -> Option<char> {
        let ch = self.rest.chars().next()?;
        self.rest = &self.rest[ch.len_utf8()..];
        Some(ch)
    }

    fn hex_quad(&mut self) -> Option<u32> {
        let mut value = 0_u32;
        for _ in 0..4 {
            value = value * 16 + self.character()?.to_digit(16)?;
        }
        Some(value)
    }

    fn string(&mut self) -> Option<String> {
        self.take("\"")?;
        let mut value = String::new();
        loop {
            match self.character()? {
                '"' => return Some(value),
                '\\' => {
                    let ch = match self.character()? {
                        '"' => '"',
                        '\\' => '\\',
                        '/' => '/',
                        'b' => '\u{0008}',
                        'f' => '\u{000c}',
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'u' => {
                            let high = self.hex_quad()?;
                            let scalar = if (0xd800..=0xdbff).contains(&high) {
                                // No whitespace is allowed inside an escape pair.
                                self.rest = self.rest.strip_prefix("\\u")?;
                                let low = self.hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&low) { return None; }
                                0x10000 + ((high - 0xd800) << 10) + low - 0xdc00
                            } else {
                                high
                            };
                            char::from_u32(scalar)?
                        }
                        _ => return None,
                    };
                    value.push(ch);
                }
                ch if ch <= '\u{001f}' => return None,
                ch => value.push(ch),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_DEPTH || self.remaining_values == 0 { return None; }
        self.remaining_values -= 1;
        self.space();
        match self.rest.as_bytes().first().copied()? {
            b'"' => Some(Value::String(self.string()?)),
            b'n' => { self.take("null")?; Some(Value::Null) }
            b't' => { self.take("true")?; Some(Value::Bool(true)) }
            b'f' => { self.take("false")?; Some(Value::Bool(false)) }
            b'0'..=b'9' => {
                let length = self.rest.bytes().take_while(u8::is_ascii_digit).count();
                let text = self.rest.get(..length)?;
                if length > 1 && text.starts_with('0') { return None; }
                let value = text.parse().ok()?;
                self.rest = &self.rest[length..];
                Some(Value::Number(value))
            }
            b'[' => {
                self.take("[")?;
                let mut values = Vec::new();
                self.space();
                if self.rest.starts_with(']') {
                    self.take("]")?;
                    return Some(Value::Array(values));
                }
                loop {
                    values.push(self.value(depth + 1)?);
                    self.space();
                    if self.rest.starts_with(']') { self.take("]")?; break; }
                    self.take(",")?;
                }
                Some(Value::Array(values))
            }
            b'{' => {
                self.take("{")?;
                let mut values = BTreeMap::new();
                self.space();
                if self.rest.starts_with('}') {
                    self.take("}")?;
                    return Some(Value::Object(values));
                }
                loop {
                    let key = self.string()?;
                    self.take(":")?;
                    let value = self.value(depth + 1)?;
                    if values.insert(key, value).is_some() { return None; }
                    self.space();
                    if self.rest.starts_with('}') { self.take("}")?; break; }
                    self.take(",")?;
                }
                Some(Value::Object(values))
            }
            _ => None,
        }
    }
}

fn object(line: &str) -> Option<BTreeMap<String, Value>> {
    if line.len() > MAX_RECORD_BYTES { return None; }
    let mut reader = Reader { rest: line, remaining_values: MAX_VALUES };
    let Value::Object(value) = reader.value(0)? else { return None; };
    reader.space();
    reader.rest.is_empty().then_some(value)
}

fn quote(text: &str) -> String {
    use std::fmt::Write;
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch <= '\u{001f}' => { let _ = write!(out, "\\u{:04x}", u32::from(ch)); }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.is_ascii() || text.len() % 2 != 0 { return None; }
    text.as_bytes().chunks_exact(2).map(|pair| {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        u8::try_from(high * 16 + low).ok()
    }).collect()
}

fn digest(text: &str) -> Option<Digest> {
    let (algorithm, bytes) = text.strip_prefix("alg:")?.split_once(':')?;
    let value = Digest::new(
        DigestAlgorithmId::try_new(algorithm.parse().ok()?).ok()?,
        DigestBytes::try_new(&hex_decode(bytes)?).ok()?,
    );
    // Preserve the exact persisted identity, including its algorithm domain.
    (value.to_string() == text).then_some(value)
}

pub(super) fn serialize_registration(reg: &WebhookRegistration) -> String {
    let filter = match &reg.filter {
        WebhookEventFilter::Wildcard => quote("*"),
        WebhookEventFilter::Selected(names) => {
            format!("[{}]", names.iter().map(|name| quote(name)).collect::<Vec<_>>().join(","))
        }
    };
    let expiring = match reg.secrets.expiring() {
        Some((secret, expires_at)) => format!(
            "{{\"secret_hex\":\"{}\",\"expires_at\":{expires_at}}}",
            super::hex_encode(secret.as_bytes()),
        ),
        None => "null".to_owned(),
    };
    format!(
        "{{\"id\":{},\"url\":{},\"active_secret_hex\":\"{}\",\"expiring\":{},\"filter\":{},\"active\":{},\"max_attempts\":{},\"initial_delay_ms\":{},\"max_delay_ms\":{}}}",
        reg.id.0, quote(reg.url.raw()), super::hex_encode(reg.secrets.active().as_bytes()),
        expiring, filter, reg.active, reg.retry_schedule.max_attempts,
        reg.retry_schedule.initial_delay.as_millis(), reg.retry_schedule.max_delay.as_millis(),
    )
}

pub(super) fn parse_registration_line(line: &str) -> Option<WebhookRegistration> {
    let fields = object(line)?;
    if fields.len() != 9 { return None; }
    let active_secret = WebhookSecret::new(hex_decode(fields.get("active_secret_hex")?.string()?)?).ok()?;
    let secrets = match fields.get("expiring")? {
        Value::Null => WebhookSecretRotation::new(active_secret),
        Value::Object(expiring) if expiring.len() == 2 => {
            let old = WebhookSecret::new(hex_decode(expiring.get("secret_hex")?.string()?)?).ok()?;
            let expires_at = expiring.get("expires_at")?.number()?;
            let mut rotation = WebhookSecretRotation::new(old);
            // Restore, do not rotate the active key back to the old secret or
            // compute a new expiry from the wall clock during every reopen.
            rotation.rotate(active_secret, expires_at, 0);
            rotation
        }
        _ => return None,
    };
    let filter = match fields.get("filter")? {
        Value::String(name) if name == "*" => WebhookEventFilter::Wildcard,
        Value::Array(names) => WebhookEventFilter::Selected(
            names.iter().map(|name| Some(name.string()?.to_owned())).collect::<Option<Vec<_>>>()?,
        ),
        _ => return None,
    };
    let retry_schedule = WebhookRetrySchedule::new(
        u32::try_from(fields.get("max_attempts")?.number()?).ok()?,
        Duration::from_millis(fields.get("initial_delay_ms")?.number()?),
        Duration::from_millis(fields.get("max_delay_ms")?.number()?),
    ).ok()?;
    // Restoring a loopback configuration is not an egress grant: dispatch
    // independently revalidates it against its operator-selected SSRF policy.
    let url = SsrfPolicy::PERMISSIVE_FOR_TESTS.validate_url(fields.get("url")?.string()?).ok()?;
    Some(WebhookRegistration {
        id: WebhookId(fields.get("id")?.number()?), url, secrets, filter,
        active: fields.get("active")?.boolean()?, retry_schedule,
    })
}

pub(super) fn serialize_dead_letter(entry: &DeadLetterEntry) -> String {
    format!(
        "{{\"delivery_id\":{},\"webhook_id\":{},\"target_url\":{},\"payload_root\":{},\"event_name\":{},\"attempts\":{},\"terminal_reason\":{},\"failed_at_unix_secs\":{}}}",
        quote(entry.delivery_id.as_str()), entry.webhook_id.0, quote(&entry.target_url),
        quote(&entry.payload_root.to_string()), quote(&entry.event_name), entry.attempts,
        quote(&entry.terminal_reason), entry.failed_at_unix_secs,
    )
}

pub(super) fn parse_dead_letter_line(line: &str) -> Option<DeadLetterEntry> {
    let fields = object(line)?;
    if fields.len() != 8 { return None; }
    let attempts = u32::try_from(fields.get("attempts")?.number()?).ok()?;
    if attempts == 0 { return None; }
    Some(DeadLetterEntry {
        delivery_id: AsciiSlug::try_new("delivery_id", fields.get("delivery_id")?.string()?.as_bytes()).ok()?,
        webhook_id: WebhookId(fields.get("webhook_id")?.number()?),
        target_url: fields.get("target_url")?.string()?.to_owned(),
        payload_root: digest(fields.get("payload_root")?.string()?)?,
        event_name: fields.get("event_name")?.string()?.to_owned(),
        attempts,
        terminal_reason: fields.get("terminal_reason")?.string()?.to_owned(),
        failed_at_unix_secs: fields.get("failed_at_unix_secs")?.number()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> WebhookRegistration {
        WebhookRegistration {
            id: WebhookId(7),
            url: SsrfPolicy::STRICT.validate_url("https://example.com/hook?name=a%22b").unwrap(),
            secrets: WebhookSecretRotation::new(WebhookSecret::new(vec![1; 32]).unwrap()),
            filter: WebhookEventFilter::Selected(vec!["issue".into(), "pull_request".into()]),
            active: false,
            retry_schedule: WebhookRetrySchedule::default(),
        }
    }

    fn dead_letter() -> DeadLetterEntry {
        DeadLetterEntry {
            delivery_id: AsciiSlug::from_static("delivery-roundtrip"), webhook_id: WebhookId(7),
            target_url: "https://example.com/\"hook\"".into(),
            payload_root: Digest::new(DigestAlgorithmId::try_new(2).unwrap(), DigestBytes::try_new(&[0x73; 32]).unwrap()),
            event_name: "pull_request\nchanged".into(), attempts: 5,
            terminal_reason: "binary\0 \u{0001} \u{0008} \u{000c} \n\r\t \\\" snow: 雪 / 🦀".into(),
            failed_at_unix_secs: u64::MAX,
        }
    }

    #[test]
    fn selected_empty_and_wildcard_filters_roundtrip_without_widening() {
        for filter in [
            WebhookEventFilter::Wildcard, WebhookEventFilter::Selected(Vec::new()),
            WebhookEventFilter::Selected(vec!["issue".into(), "a\"b\\c\n雪".into()]),
        ] {
            let mut reg = registration(); reg.filter = filter;
            assert_eq!(parse_registration_line(&serialize_registration(&reg)), Some(reg));
        }
    }

    #[test]
    fn rotation_preserves_active_key_and_original_expiry_after_reopen() {
        let mut reg = registration();
        let old = reg.secrets.active().clone();
        let active = WebhookSecret::new(vec![2; 32]).unwrap();
        reg.secrets.rotate(active.clone(), 30, 100);
        let restored = parse_registration_line(&serialize_registration(&reg)).unwrap();
        assert_eq!(restored, reg);
        assert_eq!(restored.secrets.sign_active(b"event"), active.sign(b"event"));
        assert!(restored.secrets.verify(b"event", &old.sign(b"event"), 130));
        assert!(!restored.secrets.verify(b"event", &old.sign(b"event"), 131));
        assert!(restored.secrets.verify(b"event", &active.sign(b"event"), 131));
        assert_eq!(parse_registration_line(&serialize_registration(&restored)), Some(reg));
    }

    #[test]
    fn dead_letter_preserves_exact_payload_domain_event_and_text() {
        let entry = dead_letter();
        let encoded = serialize_dead_letter(&entry);
        assert!(!encoded.contains('\n'));
        assert_eq!(parse_dead_letter_line(&encoded), Some(entry));
    }

    #[test]
    fn digest_domains_and_all_shell_lengths_roundtrip() {
        for algorithm in [1, 2, u16::MAX] {
            for length in [16, 20, 32, 64] {
                let mut entry = dead_letter();
                entry.payload_root = Digest::new(DigestAlgorithmId::try_new(algorithm).unwrap(), DigestBytes::try_new(&vec![0x19; length]).unwrap());
                assert_eq!(parse_dead_letter_line(&serialize_dead_letter(&entry)), Some(entry));
            }
        }
    }

    #[test]
    fn corrupt_or_absent_root_never_gets_a_dummy_identity() {
        let entry = dead_letter(); let encoded = serialize_dead_letter(&entry);
        for invalid in ["", "alg:0:abcd", "alg:2:abcd", "alg:2:éé", "alg:65536:abcd"] {
            assert!(parse_dead_letter_line(&encoded.replace(&entry.payload_root.to_string(), invalid)).is_none());
        }
        assert!(parse_dead_letter_line(&encoded.replace("\"payload_root\"", "\"other\"")).is_none());
    }

    #[test]
    fn missing_malformed_or_duplicate_security_fields_refuse() {
        let line = serialize_registration(&registration());
        for candidate in [
            line.replace("\"active\":false", "\"active\":truejunk"),
            line.replace("\"active\":false,", ""),
            line.replace("\"active\":false", "\"active\":false,\"active\":true"),
            line.replace("\"filter\":[\"issue\",\"pull_request\"]", "\"filter\":null"),
            line.replace("\"filter\":[\"issue\",\"pull_request\"]", "\"filter\":[1]"),
            line.replace("\"max_attempts\":5", "\"max_attempts\":4294967301"),
            line.replace("\"max_attempts\":5", "\"max_attempts\":1"),
            line.replace("\"expiring\":null", "\"expiring\":{\"secret_hex\":\"abcd\",\"expires_at\":1}"),
            format!("{line} trailing"),
        ] { assert!(parse_registration_line(&candidate).is_none(), "accepted corrupt record"); }
    }

    #[test]
    fn json_accepts_reordering_whitespace_and_surrogate_pairs() {
        let value = object(r#" { "b": "\uD83E\uDD80", "a": "雪" } "#).unwrap();
        assert_eq!(value.get("b").unwrap().string(), Some("🦀"));
        assert_eq!(value.get("a").unwrap().string(), Some("雪"));
    }

    #[test]
    fn json_rejects_ambiguous_escape_numeric_and_container_forms() {
        for text in [
            r#"{"a":1,"\u0061":2}"#, r#"{"a":"\uD800"}"#, r#"{"a":"\uDC00"}"#,
            r#"{"a":"\x01"}"#, r#"{"a":01}"#, r#"{"a":1e2}"#, r#"{"a":-1}"#,
            r#"{"a":18446744073709551616}"#, r#"{"a":truefalse}"#, r#"{"a":[1,]}"#,
            r#"{"a":1,}"#, "{\"a\":\"raw\nnewline\"}",
        ] { assert!(object(text).is_none(), "accepted {text}"); }
    }

    #[test]
    fn json_refuses_depth_value_and_byte_budget_exhaustion() {
        assert!(object(&format!("{{\"a\":{}0{}}}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1))).is_none());
        assert!(object(&format!("{{\"a\":[{}]}}", vec!["0"; MAX_VALUES].join(","))).is_none());
        assert!(object(&format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_RECORD_BYTES))).is_none());
    }

    #[test]
    fn hexadecimal_unicode_is_refused_without_slicing_panics() {
        for text in ["a雪", "雪a", "éé", "0g", "abc"] { assert!(hex_decode(text).is_none()); }
        assert_eq!(hex_decode("00abFF"), Some(vec![0, 0xab, 0xff]));
    }
}
