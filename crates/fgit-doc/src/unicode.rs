//! The bidirectional formatting characters this crate refuses to pass through.
//!
//! A right-to-left override inside link text, a code span, or a code block is
//! the "trojan source" trick: what a reviewer sees and what a machine reads
//! diverge, with nothing visibly wrong. The characters are legitimate in prose,
//! so this crate does not reject a document for containing them. It makes them
//! *visible* instead: a destination carrying one is refused, a rendered surface
//! marks each one inertly, and the parse reports that the document contains
//! them at all.

/// Whether a character can silently reorder the text around it.
///
/// The list is the Unicode bidirectional formatting set, fixed by code point,
/// so this crate needs no Unicode tables and the answer cannot drift with a
/// table version.
#[must_use]
pub const fn is_bidi_control(value: char) -> bool {
    matches!(
        value,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'
            | '\u{202b}'
            | '\u{202c}'
            | '\u{202d}'
            | '\u{202e}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}

/// The `U+XXXX` spelling of a code point, for inert display.
#[must_use]
pub fn code_point_label(value: char) -> String {
    let mut out = String::with_capacity(8);
    out.push_str("U+");
    let code = u32::from(value);
    let mut started = false;
    for shift in (0..6).rev() {
        let nibble = (code >> (shift * 4)) & 0xf;
        if nibble != 0 || started || shift < 4 {
            started = true;
            out.push(crate::render::hex_digit(nibble).to_ascii_uppercase());
        }
    }
    out
}
