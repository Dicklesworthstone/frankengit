//! Shared escaping for the lab's delimiter-based canonical renderings.
//!
//! The renderings are human-readable records, not a general serialization
//! format, but their field and sequence delimiters still have to be reserved.
//! Escaping a caller-controlled component before inserting it keeps a value
//! from manufacturing another field or event boundary.

/// Escape one caller-controlled component of a delimiter-based canonical line.
///
/// `%` is escaped too, making the mapping injective. All structural separators
/// used by the counterexample, event, and schedule grammars are reserved, as
/// are control characters so a single-line rendering remains one line.
#[must_use]
pub fn escape_delimited_field(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '%' | '|' | ',' | '=' | ':' | '@') || character.is_control() {
            let mut encoded = [0_u8; 4];
            append_percent_encoded(&mut escaped, character.encode_utf8(&mut encoded));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn append_percent_encoded(output: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        output.push('%');
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use super::escape_delimited_field;

    #[test]
    fn delimiter_and_control_bytes_cannot_form_canonical_structure() {
        assert_eq!(
            escape_delimited_field("property|detail=value,step:actor@worker%\n"),
            "property%7Cdetail%3Dvalue%2Cstep%3Aactor%40worker%25%0A"
        );
        assert_eq!(escape_delimited_field("snowman ☃"), "snowman ☃");
    }

    #[test]
    fn literal_escape_sequences_remain_distinct_from_their_escaped_input() {
        assert_ne!(
            escape_delimited_field("detail|next"),
            escape_delimited_field("detail%7Cnext")
        );
    }
}
