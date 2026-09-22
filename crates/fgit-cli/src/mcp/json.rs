//! Bounded RFC 8259 JSON. Duplicate decoded keys refuse; numbers stay exact.
use std::collections::BTreeMap;

pub const MAX_INPUT: usize = 64 * 1024;
const MAX_DEPTH: usize = 16;
const MAX_NODES: usize = 2048;
const MAX_ITEMS: usize = 256;
const MAX_STRING: usize = 16 * 1024;
pub type Object = BTreeMap<String, Value>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Self>),
    Object(Object),
}
impl Value {
    pub fn object(&self) -> Option<&Object> {
        if let Self::Object(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub fn text(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub fn unsigned(&self) -> Option<u64> {
        if let Self::Number(value) = self {
            decimal(value).ok()
        } else {
            None
        }
    }
    pub fn encode(&self, maximum: usize) -> Result<String, &'static str> {
        let mut out = Output {
            text: String::new(),
            maximum,
        };
        out.value(self, 0)?;
        Ok(out.text)
    }
}
pub fn text(value: impl Into<String>) -> Value {
    Value::String(value.into())
}
pub fn number(value: u64) -> Value {
    Value::Number(value.to_string())
}
pub fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
pub fn decimal(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("expected_canonical_decimal");
    }
    value.parse().map_err(|_| "integer_overflow")
}
pub fn parse(bytes: &[u8]) -> Result<Value, &'static str> {
    if bytes.len() > MAX_INPUT {
        return Err("input_limit");
    }
    let source = std::str::from_utf8(bytes).map_err(|_| "invalid_utf8")?;
    let mut parser = Parser {
        source,
        at: 0,
        nodes: 0,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.at != bytes.len() {
        return Err("trailing_json");
    }
    Ok(value)
}
struct Parser<'a> {
    source: &'a str,
    at: usize,
    nodes: usize,
}
impl Parser<'_> {
    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.at).copied()
    }
    fn whitespace(&mut self) {
        while self
            .byte()
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }
    fn take(&mut self, expected: u8) -> bool {
        if self.byte() == Some(expected) {
            self.at += 1;
            true
        } else {
            false
        }
    }
    fn node(&mut self) -> Result<(), &'static str> {
        if self.nodes == MAX_NODES {
            return Err("node_limit");
        }
        self.nodes += 1;
        Ok(())
    }
    fn value(&mut self, depth: usize) -> Result<Value, &'static str> {
        if depth > MAX_DEPTH {
            return Err("depth_limit");
        }
        self.node()?;
        self.whitespace();
        match self.byte() {
            Some(b'"') => self.string().map(Value::String),
            Some(b'{') => {
                self.at += 1;
                let mut fields = BTreeMap::new();
                self.whitespace();
                if self.take(b'}') {
                    return Ok(Value::Object(fields));
                }
                loop {
                    if fields.len() == MAX_ITEMS {
                        return Err("object_limit");
                    }
                    self.node()?;
                    self.whitespace();
                    let key = self.string()?;
                    if key.len() > 256 {
                        return Err("key_limit");
                    }
                    if fields.contains_key(&key) {
                        return Err("duplicate_key");
                    }
                    self.whitespace();
                    if !self.take(b':') {
                        return Err("missing_colon");
                    }
                    let value = self.value(depth + 1)?;
                    fields.insert(key, value);
                    self.whitespace();
                    if self.take(b'}') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err("missing_comma");
                    }
                }
                Ok(Value::Object(fields))
            }
            Some(b'[') => {
                self.at += 1;
                let mut values = Vec::new();
                self.whitespace();
                if self.take(b']') {
                    return Ok(Value::Array(values));
                }
                loop {
                    if values.len() == MAX_ITEMS {
                        return Err("array_limit");
                    }
                    let value = self.value(depth + 1)?;
                    values.try_reserve(1).map_err(|_| "allocation_refused")?;
                    values.push(value);
                    self.whitespace();
                    if self.take(b']') {
                        break;
                    }
                    if !self.take(b',') {
                        return Err("missing_comma");
                    }
                }
                Ok(Value::Array(values))
            }
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.numeric().map(Value::Number),
            _ => Err("invalid_value"),
        }
    }
    fn literal(&mut self, token: &str, value: Value) -> Result<Value, &'static str> {
        if !self.source[self.at..].starts_with(token) {
            return Err("invalid_literal");
        }
        self.at += token.len();
        Ok(value)
    }
    fn numeric(&mut self) -> Result<String, &'static str> {
        let start = self.at;
        self.take(b'-');
        if !self.take(b'0') {
            if !self.byte().is_some_and(|b| (b'1'..=b'9').contains(&b)) {
                return Err("invalid_number");
            }
            self.digits();
        }
        if self.take(b'.') && !self.digits() {
            return Err("invalid_fraction");
        }
        if self.take(b'e') || self.take(b'E') {
            if !self.take(b'+') {
                self.take(b'-');
            }
            if !self.digits() {
                return Err("invalid_exponent");
            }
        }
        if self.at - start > 128 {
            return Err("number_limit");
        }
        Ok(self.source[start..self.at].to_owned())
    }
    fn digits(&mut self) -> bool {
        let start = self.at;
        while self.byte().is_some_and(|b| b.is_ascii_digit()) {
            self.at += 1;
        }
        start != self.at
    }
    fn hex4(&mut self) -> Result<u32, &'static str> {
        let mut value = 0;
        for _ in 0..4 {
            let byte = self.byte().ok_or("truncated_unicode")?;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err("invalid_unicode_escape"),
            };
            value = value * 16 + u32::from(digit);
            self.at += 1;
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<String, &'static str> {
        if !self.take(b'"') {
            return Err("expected_string");
        }
        let mut out = String::new();
        loop {
            let byte = self.byte().ok_or("unterminated_string")?;
            let ch = match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                0..=31 => return Err("unescaped_control"),
                b'\\' => {
                    self.at += 1;
                    let escaped = self.byte().ok_or("truncated_escape")?;
                    self.at += 1;
                    match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut scalar = self.hex4()?;
                            if (0xd800..=0xdbff).contains(&scalar) {
                                if !self.take(b'\\') || !self.take(b'u') {
                                    return Err("missing_low_surrogate");
                                }
                                let low = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err("invalid_low_surrogate");
                                }
                                scalar = 0x10000 + ((scalar - 0xd800) << 10) + low - 0xdc00;
                            }
                            char::from_u32(scalar).ok_or("invalid_unicode_scalar")?
                        }
                        _ => return Err("invalid_escape"),
                    }
                }
                _ => {
                    let ch = self.source[self.at..]
                        .chars()
                        .next()
                        .ok_or("invalid_utf8")?;
                    self.at += ch.len_utf8();
                    ch
                }
            };
            if out.len() + ch.len_utf8() > MAX_STRING {
                return Err("string_limit");
            }
            out.try_reserve(ch.len_utf8())
                .map_err(|_| "allocation_refused")?;
            out.push(ch);
        }
    }
}
struct Output {
    text: String,
    maximum: usize,
}
impl Output {
    fn append(&mut self, value: &str) -> Result<(), &'static str> {
        if self
            .text
            .len()
            .checked_add(value.len())
            .is_none_or(|n| n > self.maximum)
        {
            return Err("response_limit");
        }
        self.text
            .try_reserve(value.len())
            .map_err(|_| "allocation_refused")?;
        self.text.push_str(value);
        Ok(())
    }
    fn string(&mut self, value: &str) -> Result<(), &'static str> {
        self.append("\"")?;
        for ch in value.chars() {
            match ch {
                '"' => self.append("\\\"")?,
                '\\' => self.append("\\\\")?,
                ch if ch.is_control()
                    || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}'
                    | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}') =>
                {
                    self.append(&format!("\\u{:04x}", u32::from(ch)))?
                }
                ch => {
                    let mut buffer = [0; 4];
                    self.append(ch.encode_utf8(&mut buffer))?;
                }
            }
        }
        self.append("\"")
    }
    fn value(&mut self, value: &Value, depth: usize) -> Result<(), &'static str> {
        if depth > 32 {
            return Err("response_depth");
        }
        match value {
            Value::Null => self.append("null"),
            Value::Bool(value) => self.append(if *value { "true" } else { "false" }),
            Value::Number(value) => {
                // No unchecked raw JSON fragment can enter an outgoing message.
                let mut parser = Parser {
                    source: value,
                    at: 0,
                    nodes: 0,
                };
                parser.numeric()?;
                if parser.at != value.len() {
                    return Err("invalid_output_number");
                }
                self.append(value)
            }
            Value::String(value) => self.string(value),
            Value::Array(values) => {
                self.append("[")?;
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        self.append(",")?;
                    }
                    self.value(value, depth + 1)?;
                }
                self.append("]")
            }
            Value::Object(values) => {
                self.append("{")?;
                for (index, (key, value)) in values.iter().enumerate() {
                    if index != 0 {
                        self.append(",")?;
                    }
                    self.string(key)?;
                    self.append(":")?;
                    self.value(value, depth + 1)?;
                }
                self.append("}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_escapes_and_exact_numbers_roundtrip() {
        for input in [
            r#"{"x":"é\uD83E\uDD80\n\u0000","n":18446744073709551615}"#,
            r#"[null,true,false,-0,1.2e+90,"\\u1234"]"#,
        ] {
            let value = parse(input.as_bytes()).unwrap();
            assert_eq!(
                parse(value.encode(MAX_INPUT).unwrap().as_bytes()).unwrap(),
                value
            );
        }
        assert_eq!(parse(br#""\uD83E\uDD80""#).unwrap().text(), Some("🦀"));
    }
    #[test]
    fn hostile_json_is_rejected_instead_of_reinterpreted() {
        for input in [
            r#"{"x":1,"\u0078":2}"#,
            "[1,]",
            "{\"x\":1,}",
            "01",
            "-01",
            "1.",
            "1e",
            "1e+",
            "+1",
            "NaN",
            "null true",
            r#""\ud800""#,
            r#""\udc00""#,
            r#""\ud800\u0041""#,
            r#""\q""#,
            "\"a\nb\"",
            "\u{feff}null",
        ] {
            assert!(parse(input.as_bytes()).is_err(), "{input}");
        }
        assert!(parse(&[b'"', 255, b'"']).is_err());
    }
    #[test]
    fn every_truncated_compound_message_refuses() {
        let input = br#"{"args":["hello\nworld",{"unicode":"\ud83e\udd80"}]}"#;
        for end in 0..input.len() {
            assert!(parse(&input[..end]).is_err(), "{end}");
        }
        assert!(parse(input).is_ok());
    }
    #[test]
    fn preallocation_and_encoded_output_limits_have_exact_twins() {
        let string = format!("\"{}\"", "x".repeat(MAX_STRING));
        assert!(parse(string.as_bytes()).is_ok());
        assert!(parse(format!("\"{}\"", "x".repeat(MAX_STRING + 1)).as_bytes()).is_err());
        assert!(
            parse(
                format!(
                    "{}0{}",
                    "[".repeat(MAX_DEPTH + 1),
                    "]".repeat(MAX_DEPTH + 1)
                )
                .as_bytes()
            )
            .is_err()
        );
        assert!(parse(format!("[{}]", vec!["0"; MAX_ITEMS + 1].join(",")).as_bytes()).is_err());
        assert!(parse(&vec![b' '; MAX_INPUT + 1]).is_err());
        let value = text("\n\"é");
        let encoded = value.encode(100).unwrap();
        assert_eq!(value.encode(encoded.len()).unwrap(), encoded);
        assert!(value.encode(encoded.len() - 1).is_err());
        assert!(Value::Number("1,null".into()).encode(100).is_err());
    }
}
