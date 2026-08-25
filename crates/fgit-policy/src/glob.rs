//! Ref patterns: the one wildcard vocabulary a policy may match names with.
//!
//! A pattern is a `/`-separated sequence of segments. Within a segment, `*`
//! matches any run of bytes that are not `/`, including an empty run. As a
//! whole final segment, `**` matches one or more remaining segments.
//!
//! ```text
//! refs/heads/*          matches refs/heads/main, not refs/heads/feature/x
//! refs/heads/release-*  matches refs/heads/release-1.2
//! refs/heads/**         matches refs/heads/main and refs/heads/feature/x
//! ```
//!
//! ## Why `**` is only accepted at the end
//!
//! A `**` in the middle needs a matcher that backtracks across segment
//! boundaries, and a backtracking matcher over attacker-influenced patterns is
//! where wildcard implementations acquire their pathological cases. Refusing
//! it ([`RefPatternRefusal::DoubleStarNotTrailing`]) keeps matching linear in
//! the length of the name, and keeps every accepted pattern's meaning readable
//! from left to right.
//!
//! ## Normalization
//!
//! A run of consecutive `*` inside a segment means exactly what one `*` means,
//! so a run is collapsed to one at compile time. Two spellings of the same
//! matcher therefore produce the same canonical bytes and so the same snapshot
//! identity.

use core::fmt;

use crate::error::RefPatternRefusal;

/// Largest accepted pattern, in bytes.
pub const MAX_PATTERN_LEN: usize = 512;

/// Largest accepted number of `/`-separated segments.
pub const MAX_PATTERN_SEGMENTS: usize = 32;

/// The literal spelling of the multi-segment wildcard.
const DOUBLE_STAR: &[u8] = b"**";

/// A compiled ref pattern.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefPattern {
    source: Box<str>,
    segments: Vec<Box<[u8]>>,
    trailing_double_star: bool,
}

impl RefPattern {
    /// Compiles a pattern, refusing anything it cannot match linearly.
    pub fn compile(source: &str) -> Result<Self, RefPatternRefusal> {
        if source.is_empty() {
            return Err(RefPatternRefusal::Empty);
        }
        if source.len() > MAX_PATTERN_LEN {
            return Err(RefPatternRefusal::TooLong {
                observed: source.len(),
                limit: MAX_PATTERN_LEN,
            });
        }
        for (offset, byte) in source.bytes().enumerate() {
            if !byte_is_permitted(byte) {
                return Err(RefPatternRefusal::ByteNotPermitted { offset, byte });
            }
        }

        let raw: Vec<&[u8]> = source.as_bytes().split(|byte| *byte == b'/').collect();
        if raw.len() > MAX_PATTERN_SEGMENTS {
            return Err(RefPatternRefusal::TooManySegments {
                observed: raw.len(),
                limit: MAX_PATTERN_SEGMENTS,
            });
        }

        let last = raw.len() - 1;
        let mut segments: Vec<Box<[u8]>> = Vec::with_capacity(raw.len());
        let mut trailing_double_star = false;
        for (index, segment) in raw.iter().enumerate() {
            if segment.is_empty() {
                return Err(RefPatternRefusal::SegmentEmpty { index });
            }
            if *segment == DOUBLE_STAR {
                if index != last {
                    return Err(RefPatternRefusal::DoubleStarNotTrailing { index });
                }
                trailing_double_star = true;
                continue;
            }
            segments.push(collapse_stars(segment));
        }

        // `**` alone is a pattern with no fixed prefix; it matches every name
        // with at least one segment. That is legal and is written out below as
        // the canonical form `**`.
        let canonical = canonical_source(&segments, trailing_double_star);
        Ok(Self {
            source: canonical.into_boxed_str(),
            segments,
            trailing_double_star,
        })
    }

    /// The canonical spelling of this pattern.
    ///
    /// Equal to the source it was compiled from except that runs of `*` inside
    /// a segment are collapsed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Whether the pattern ends in the multi-segment wildcard.
    #[must_use]
    pub const fn is_recursive(&self) -> bool {
        self.trailing_double_star
    }

    /// Whether `name` matches.
    #[must_use]
    pub fn matches(&self, name: &[u8]) -> bool {
        let components: Vec<&[u8]> = name.split(|byte| *byte == b'/').collect();
        if self.trailing_double_star {
            if components.len() <= self.segments.len() {
                return false;
            }
        } else if components.len() != self.segments.len() {
            return false;
        }
        self.segments
            .iter()
            .zip(components.iter())
            .all(|(pattern, component)| segment_matches(pattern, component))
    }
}

impl fmt::Display for RefPattern {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.source)
    }
}

/// Bytes a pattern may contain.
///
/// The excluded graphic bytes are the ones Git itself refuses inside a ref
/// name, so a pattern cannot be written that no legal name could ever match.
const fn byte_is_permitted(byte: u8) -> bool {
    byte.is_ascii_graphic() && !matches!(byte, b'~' | b'^' | b':' | b'?' | b'[' | b'\\')
}

fn collapse_stars(segment: &[u8]) -> Box<[u8]> {
    let mut out = Vec::with_capacity(segment.len());
    for byte in segment {
        if *byte == b'*' && out.last() == Some(&b'*') {
            continue;
        }
        out.push(*byte);
    }
    out.into_boxed_slice()
}

fn canonical_source(segments: &[Box<[u8]>], trailing_double_star: bool) -> String {
    let mut parts: Vec<String> = segments
        .iter()
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect();
    if trailing_double_star {
        parts.push("**".to_owned());
    }
    parts.join("/")
}

/// Matches one segment, where `*` stands for any run of bytes.
///
/// The two saved positions make this linear in the common case and `O(n*m)` in
/// the worst case, with no recursion and no exponential blow-up: on a mismatch
/// the matcher resumes one byte past the last `*` it consumed rather than
/// re-exploring every earlier choice.
fn segment_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pattern_at, mut text_at) = (0_usize, 0_usize);
    let mut star: Option<usize> = None;
    let mut resume = 0_usize;

    while text_at < text.len() {
        if pattern_at < pattern.len() && pattern[pattern_at] == text[text_at] {
            pattern_at += 1;
            text_at += 1;
        } else if pattern_at < pattern.len() && pattern[pattern_at] == b'*' {
            star = Some(pattern_at);
            pattern_at += 1;
            resume = text_at;
        } else if let Some(position) = star {
            pattern_at = position + 1;
            resume += 1;
            text_at = resume;
        } else {
            return false;
        }
    }

    pattern[pattern_at..].iter().all(|byte| *byte == b'*')
}

#[cfg(test)]
mod tests {
    use super::{MAX_PATTERN_SEGMENTS, RefPattern};
    use crate::error::RefPatternRefusal;

    fn pattern(source: &str) -> RefPattern {
        RefPattern::compile(source).unwrap_or_else(|refusal| panic!("{source}: {refusal}"))
    }

    #[test]
    fn a_literal_pattern_matches_only_itself() {
        let compiled = pattern("refs/heads/main");
        assert!(compiled.matches(b"refs/heads/main"));
        assert!(!compiled.matches(b"refs/heads/mainx"));
        assert!(!compiled.matches(b"refs/heads/main/x"));
        assert!(!compiled.matches(b"refs/heads"));
    }

    #[test]
    fn a_single_star_stays_inside_one_segment() {
        let compiled = pattern("refs/heads/*");
        assert!(compiled.matches(b"refs/heads/main"));
        assert!(compiled.matches(b"refs/heads/x"));
        // The permitted twin of the line below is the first assertion: the
        // same pattern DOES match a one-segment name, so this is a segment
        // boundary and not an inability to match.
        assert!(!compiled.matches(b"refs/heads/feature/x"));
    }

    #[test]
    fn a_star_may_carry_a_prefix_and_a_suffix() {
        let compiled = pattern("refs/heads/release-*.x");
        assert!(compiled.matches(b"refs/heads/release-1.x"));
        assert!(compiled.matches(b"refs/heads/release-.x"));
        assert!(!compiled.matches(b"refs/heads/release-1.y"));
        assert!(!compiled.matches(b"refs/heads/rel-1.x"));
    }

    #[test]
    fn a_trailing_double_star_crosses_segments_but_needs_one() {
        let compiled = pattern("refs/heads/**");
        assert!(compiled.matches(b"refs/heads/main"));
        assert!(compiled.matches(b"refs/heads/feature/deep/nesting"));
        assert!(!compiled.matches(b"refs/heads"));
        assert!(!compiled.matches(b"refs/tags/v1"));
    }

    #[test]
    fn a_double_star_before_the_end_is_refused_and_at_the_end_is_not() {
        assert_eq!(
            RefPattern::compile("refs/**/main"),
            Err(RefPatternRefusal::DoubleStarNotTrailing { index: 1 })
        );
        // The permitted twin: the same wildcard in the final position.
        assert!(RefPattern::compile("refs/heads/**").is_ok());
    }

    #[test]
    fn repeated_stars_collapse_to_one_canonical_spelling() {
        let collapsed = pattern("refs/heads/***");
        assert_eq!(collapsed.as_str(), "refs/heads/*");
        assert_eq!(collapsed, pattern("refs/heads/*"));
    }

    #[test]
    fn empty_segments_and_empty_patterns_are_refused() {
        assert_eq!(RefPattern::compile(""), Err(RefPatternRefusal::Empty));
        assert_eq!(
            RefPattern::compile("refs//main"),
            Err(RefPatternRefusal::SegmentEmpty { index: 1 })
        );
        assert_eq!(
            RefPattern::compile("/refs"),
            Err(RefPatternRefusal::SegmentEmpty { index: 0 })
        );
        assert_eq!(
            RefPattern::compile("refs/"),
            Err(RefPatternRefusal::SegmentEmpty { index: 1 })
        );
    }

    #[test]
    fn bytes_git_refuses_in_a_ref_name_are_refused_in_a_pattern() {
        for (source, offset, byte) in [
            ("refs/heads/ma:in", 13, b':'),
            ("refs/heads/ma?in", 13, b'?'),
            ("refs/heads/ma^in", 13, b'^'),
            ("refs/heads/ma~in", 13, b'~'),
            ("refs/heads/ma[in", 13, b'['),
        ] {
            assert_eq!(
                RefPattern::compile(source),
                Err(RefPatternRefusal::ByteNotPermitted { offset, byte }),
                "{source} must be refused"
            );
        }
        // The permitted twin: the same shape without the refused byte.
        assert!(RefPattern::compile("refs/heads/main").is_ok());
    }

    #[test]
    fn a_pattern_deeper_than_the_segment_bound_is_refused() {
        let deep = core::iter::repeat_n("a", MAX_PATTERN_SEGMENTS + 1)
            .collect::<Vec<&str>>()
            .join("/");
        assert_eq!(
            RefPattern::compile(&deep),
            Err(RefPatternRefusal::TooManySegments {
                observed: MAX_PATTERN_SEGMENTS + 1,
                limit: MAX_PATTERN_SEGMENTS,
            })
        );
        // The permitted twin: exactly at the bound.
        let at_bound = core::iter::repeat_n("a", MAX_PATTERN_SEGMENTS)
            .collect::<Vec<&str>>()
            .join("/");
        assert!(RefPattern::compile(&at_bound).is_ok());
    }

    #[test]
    fn a_star_heavy_pattern_terminates_without_backtracking_blow_up() {
        // Twelve stars against a long non-matching text is the classic
        // exponential case for a naive recursive matcher. This one is linear
        // in the text per star, so it returns rather than hanging.
        let compiled = pattern("refs/heads/*a*a*a*a*a*a*a*a*a*a*a*a");
        let text = format!("refs/heads/{}", "a".repeat(64));
        assert!(compiled.matches(text.as_bytes()));
        let mismatch = format!("refs/heads/{}b", "a".repeat(64));
        assert!(!compiled.matches(mismatch.as_bytes()));
    }
}
