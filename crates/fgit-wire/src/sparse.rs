//! Bounded, byte-oriented sparse-checkout patterns for `sparse:oid` fetches.
//!
//! This is a pure predicate over repository paths, never a host-path reader.
//! The caller authenticates the pattern blob and walks every tree, including
//! excluded directories: a later rule can select a child in such a directory.
//! Each directory's result is inherited only when no rule matches its child.
//! Checkpoints charge compilation and every wildcard transition to the caller's
//! existing request ledger. No recursive wildcard backtracking is used.

use std::fmt;

/// Closed bounds on an individual pattern document and path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SparseLimits {
    /// Maximum bytes in the original blob, including comments and whitespace.
    pub max_blob_bytes: usize,
    /// Maximum nonempty, noncomment rules.
    pub max_patterns: usize,
    /// Maximum bytes in any original line.
    pub max_pattern_bytes: usize,
    /// Maximum bytes in a complete repository-relative path.
    pub max_path_bytes: usize,
}

impl Default for SparseLimits {
    fn default() -> Self {
        Self {
            max_blob_bytes: 1024 * 1024,
            max_patterns: 4096,
            max_pattern_bytes: 4096,
            max_path_bytes: 4096,
        }
    }
}

/// A refusal never substitutes a less selective or unfiltered predicate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SparseError<E> {
    /// The original caller checkpoint stopped compilation or matching.
    Checkpoint(E),
    /// A named bounded resource could not accommodate the request.
    Limit(&'static str),
    /// A pattern outside the implemented, locale-independent grammar.
    Unsupported {
        /// One-based line number in the pattern blob.
        line: usize,
        /// The refused grammar feature.
        feature: &'static str,
    },
    /// A path is empty, absolute, contains NUL, or has invalid components.
    InvalidPath,
}

impl<E: fmt::Display> fmt::Display for SparseError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Checkpoint(error) => error.fmt(formatter),
            Self::Limit(field) => write!(formatter, "sparse filter exceeded {field}"),
            Self::Unsupported { line, feature } => {
                write!(
                    formatter,
                    "sparse pattern line {line}: unsupported {feature}"
                )
            }
            Self::InvalidPath => formatter.write_str("invalid sparse repository path"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SparseError<E> {}

#[derive(Clone, Copy, Debug)]
enum Atom {
    Byte(u8),
    Any,
    Star,
    AnyPath,
    Directories,
    Class(u32),
}

#[derive(Debug)]
struct Rule {
    include: bool,
    directory_only: bool,
    basename_only: bool,
    atoms: Vec<Atom>,
}

/// An immutable compiled document. Names and matching remain raw bytes.
#[derive(Debug)]
pub struct SparsePatterns {
    rules: Vec<Rule>,
    classes: Vec<[u64; 4]>,
    max_path_bytes: usize,
    root_included: bool,
}

impl SparsePatterns {
    /// State of the unnamed root directory. Basename rules such as `*/` can
    /// match it; anchored pathname rules cannot. Each tree walk starts here.
    pub const fn root_included(&self) -> bool {
        self.root_included
    }

    /// Number of compiled rules, for a caller's aggregate document budget.
    pub fn pattern_count(&self) -> usize {
        self.rules.len()
    }

    /// Compile ordered sparse-checkout rules without reading any object or path.
    /// POSIX named/equivalence/collation classes and malformed bracket/escape
    /// syntax refuse explicitly; byte classes and byte ranges are supported.
    pub fn compile<E>(
        body: &[u8],
        limits: SparseLimits,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<Self, SparseError<E>> {
        checkpoint().map_err(SparseError::Checkpoint)?;
        if body.len() > limits.max_blob_bytes {
            return Err(SparseError::Limit("pattern blob bytes"));
        }
        let mut result = Self {
            rules: Vec::new(),
            classes: Vec::new(),
            max_path_bytes: limits.max_path_bytes,
            root_included: false,
        };
        // Git's text pattern documents accept an initial UTF-8 BOM and CRLF.
        let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
        for (index, raw) in body.split(|byte| *byte == b'\n').enumerate() {
            checkpoint().map_err(SparseError::Checkpoint)?;
            if raw.len() > limits.max_pattern_bytes {
                return Err(SparseError::Limit("pattern line bytes"));
            }
            for byte in raw {
                checkpoint().map_err(SparseError::Checkpoint)?;
                if *byte == 0 {
                    return Err(unsupported(index + 1, "NUL in pattern"));
                }
            }
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            let mut end = raw.len();
            while end > 0 && raw[end - 1] == b' ' {
                checkpoint().map_err(SparseError::Checkpoint)?;
                let mut position = end - 1;
                while position > 0 && raw[position - 1] == b'\\' {
                    checkpoint().map_err(SparseError::Checkpoint)?;
                    position -= 1;
                }
                if (end - 1 - position) % 2 == 1 {
                    break;
                }
                end -= 1;
            }
            let mut pattern = &raw[..end];
            if pattern.is_empty() || pattern[0] == b'#' {
                continue;
            }
            let include = pattern[0] != b'!';
            if !include {
                pattern = &pattern[1..];
            }
            let directory_only = pattern.ends_with(b"/");
            if directory_only {
                pattern = &pattern[..pattern.len() - 1];
            }
            let anchored = pattern.starts_with(b"/");
            if anchored {
                pattern = &pattern[1..];
            }
            if result.rules.len() >= limits.max_patterns {
                return Err(SparseError::Limit("pattern count"));
            }
            let basename_only = !anchored && !pattern.contains(&b'/');
            let atoms = compile_atoms(pattern, index + 1, &mut result.classes, checkpoint)?;
            result
                .rules
                .try_reserve(1)
                .map_err(|_| SparseError::Limit("pattern allocation"))?;
            result.rules.push(Rule {
                include,
                directory_only,
                basename_only,
                atoms,
            });
        }
        for rule in result.rules.iter().rev() {
            checkpoint().map_err(SparseError::Checkpoint)?;
            if rule.basename_only && matches_atoms(&rule.atoms, &result.classes, b"", checkpoint)? {
                result.root_included = rule.include;
                break;
            }
        }
        checkpoint().map_err(SparseError::Checkpoint)?;
        Ok(result)
    }

    /// Match one entry at its complete repository-relative path.
    ///
    /// Start a root tree with [`Self::root_included`]; pass each directory's result
    /// to its immediate children. Do not prune an excluded directory. Rules
    /// match in reverse order, and an unmatched entry inherits its parent.
    pub fn matches_entry<E>(
        &self,
        path: &[u8],
        is_directory: bool,
        inherited: bool,
        checkpoint: &mut impl FnMut() -> Result<(), E>,
    ) -> Result<bool, SparseError<E>> {
        checkpoint().map_err(SparseError::Checkpoint)?;
        if path.len() > self.max_path_bytes {
            return Err(SparseError::Limit("repository path bytes"));
        }
        if path.is_empty() {
            return Err(SparseError::InvalidPath);
        }
        let mut basename = 0;
        for component in path.split(|byte| *byte == b'/') {
            checkpoint().map_err(SparseError::Checkpoint)?;
            if component.is_empty() || component == b"." || component == b".." {
                return Err(SparseError::InvalidPath);
            }
            for byte in component {
                checkpoint().map_err(SparseError::Checkpoint)?;
                if *byte == 0 {
                    return Err(SparseError::InvalidPath);
                }
            }
        }
        if let Some(index) = path.iter().rposition(|byte| *byte == b'/') {
            basename = index + 1;
        }
        for rule in self.rules.iter().rev() {
            checkpoint().map_err(SparseError::Checkpoint)?;
            if rule.directory_only && !is_directory {
                continue;
            }
            let text = if rule.basename_only {
                &path[basename..]
            } else {
                path
            };
            if matches_atoms(&rule.atoms, &self.classes, text, checkpoint)? {
                return Ok(rule.include);
            }
        }
        checkpoint().map_err(SparseError::Checkpoint)?;
        Ok(inherited)
    }
}

fn unsupported<E>(line: usize, feature: &'static str) -> SparseError<E> {
    SparseError::Unsupported { line, feature }
}

fn compile_atoms<E>(
    pattern: &[u8],
    line: usize,
    classes: &mut Vec<[u64; 4]>,
    checkpoint: &mut impl FnMut() -> Result<(), E>,
) -> Result<Vec<Atom>, SparseError<E>> {
    let mut result = Vec::new();
    result
        .try_reserve(pattern.len())
        .map_err(|_| SparseError::Limit("pattern allocation"))?;
    let mut position = 0;
    while position < pattern.len() {
        checkpoint().map_err(SparseError::Checkpoint)?;
        let byte = pattern[position];
        let atom = match byte {
            b'\\' => {
                position += 1;
                let Some(&escaped) = pattern.get(position) else {
                    return Err(unsupported(line, "trailing escape"));
                };
                if escaped == b'/' {
                    return Err(unsupported(line, "escaped path separator"));
                }
                Atom::Byte(escaped)
            }
            b'?' => Atom::Any,
            b'*' => {
                let start = position;
                while pattern.get(position + 1) == Some(&b'*') {
                    checkpoint().map_err(SparseError::Checkpoint)?;
                    position += 1;
                }
                let component_start = start == 0 || pattern[start - 1] == b'/';
                let two = position == start + 1;
                if two && component_start && pattern.get(position + 1) == Some(&b'/') {
                    position += 1;
                    Atom::Directories
                } else if two && component_start && position + 1 == pattern.len() {
                    Atom::AnyPath
                } else {
                    Atom::Star
                }
            }
            b'[' => {
                let (class, end) = compile_class(pattern, position, line, checkpoint)?;
                position = end;
                let index = u32::try_from(classes.len())
                    .map_err(|_| SparseError::Limit("pattern class count"))?;
                classes
                    .try_reserve(1)
                    .map_err(|_| SparseError::Limit("pattern class allocation"))?;
                classes.push(class);
                Atom::Class(index)
            }
            byte => Atom::Byte(byte),
        };
        result.push(atom);
        position += 1;
    }
    Ok(result)
}

fn compile_class<E>(
    pattern: &[u8],
    start: usize,
    line: usize,
    checkpoint: &mut impl FnMut() -> Result<(), E>,
) -> Result<([u64; 4], usize), SparseError<E>> {
    let mut position = start + 1;
    let negative = matches!(pattern.get(position), Some(b'!' | b'^'));
    position += usize::from(negative);
    let mut bits = [0_u64; 4];
    let mut first = true;
    loop {
        checkpoint().map_err(SparseError::Checkpoint)?;
        let Some(&byte) = pattern.get(position) else {
            return Err(unsupported(line, "unclosed byte class"));
        };
        if byte == b']' && !first {
            if negative {
                for word in &mut bits {
                    *word = !*word;
                }
            }
            // Wildcards never match a path separator, even in a negative class.
            bits[usize::from(b'/') / 64] &= !(1_u64 << (b'/' % 64));
            return Ok((bits, position));
        }
        first = false;
        let low = class_byte(pattern, &mut position, line)?;
        let high = if pattern.get(position + 1) == Some(&b'-')
            && pattern.get(position + 2).is_some_and(|byte| *byte != b']')
        {
            position += 2;
            class_byte(pattern, &mut position, line)?
        } else {
            low
        };
        if low > high {
            return Err(unsupported(line, "reversed byte range"));
        }
        for byte in low..=high {
            checkpoint().map_err(SparseError::Checkpoint)?;
            bits[usize::from(byte) / 64] |= 1_u64 << (byte % 64);
        }
        position += 1;
    }
}

fn class_byte<E>(pattern: &[u8], position: &mut usize, line: usize) -> Result<u8, SparseError<E>> {
    let Some(&byte) = pattern.get(*position) else {
        return Err(unsupported(line, "unclosed byte class"));
    };
    if byte == b'[' && matches!(pattern.get(*position + 1), Some(b':' | b'.' | b'=')) {
        return Err(unsupported(
            line,
            "POSIX named, collating or equivalence class",
        ));
    }
    if byte == b'\\' {
        *position += 1;
        pattern
            .get(*position)
            .copied()
            .ok_or_else(|| unsupported(line, "trailing class escape"))
    } else {
        Ok(byte)
    }
}

fn matches_atoms<E>(
    atoms: &[Atom],
    classes: &[[u64; 4]],
    text: &[u8],
    checkpoint: &mut impl FnMut() -> Result<(), E>,
) -> Result<bool, SparseError<E>> {
    let length = text
        .len()
        .checked_add(1)
        .ok_or(SparseError::Limit("path allocation"))?;
    let mut previous = Vec::new();
    let mut next = Vec::new();
    for row in [&mut previous, &mut next] {
        row.try_reserve_exact(length)
            .map_err(|_| SparseError::Limit("path allocation"))?;
        row.resize(length, false);
    }
    previous[0] = true;
    for atom in atoms {
        checkpoint().map_err(SparseError::Checkpoint)?;
        let mut directory_start = false;
        for position in 0..length {
            checkpoint().map_err(SparseError::Checkpoint)?;
            let before = position.checked_sub(1);
            next[position] = match atom {
                Atom::Byte(byte) => {
                    before.is_some_and(|index| previous[index] && text[index] == *byte)
                }
                Atom::Any => before.is_some_and(|index| previous[index] && text[index] != b'/'),
                Atom::Class(index) => before.is_some_and(|offset| {
                    let byte = text[offset];
                    previous[offset]
                        && classes[*index as usize][usize::from(byte) / 64] & (1_u64 << (byte % 64))
                            != 0
                }),
                Atom::Star => {
                    previous[position]
                        || before.is_some_and(|index| next[index] && text[index] != b'/')
                }
                Atom::AnyPath => previous[position] || before.is_some_and(|index| next[index]),
                Atom::Directories => {
                    let matched = previous[position]
                        || before.is_some_and(|index| directory_start && text[index] == b'/');
                    directory_start |= previous[position];
                    matched
                }
            };
        }
        std::mem::swap(&mut previous, &mut next);
    }
    checkpoint().map_err(SparseError::Checkpoint)?;
    Ok(previous[text.len()])
}
