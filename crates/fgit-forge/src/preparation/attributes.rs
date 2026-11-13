//! Explicit, bounded attribute semantics for native content merges.
//!
//! The pattern/precedence model follows the declared subset of
//! <https://git-scm.com/docs/gitattributes> and
//! <https://git-scm.com/docs/gitignore>. Only identical in-tree declarations in
//! all three inputs are considered. No worktree, index fallback, ambient Git
//! configuration, normalization, filter, or external driver participates.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use super::{MergeObjectSource, Planner, PreparationError, tree_entries};
use fgit_types::GitOid;

const FILE_BYTES: usize = 64 * 1024;
const TOTAL_BYTES: usize = 1024 * 1024;
const FILES: usize = 128;
const FILE_RULES: usize = 1024;
const TOTAL_RULES: usize = 8192;
const PATTERN_BYTES: usize = 1024;
const ASSIGNMENTS: usize = 64;
const MATCH_STEPS: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Driver {
    Text,
    Binary,
    Unsupported,
}

#[derive(Clone)]
pub(super) enum Context {
    Legacy(bool),
    Builtin {
        layers: Option<Rc<Layer>>,
        blocked: bool,
        state: Rc<RefCell<State>>,
    },
}

pub(super) struct Layer {
    parent: Option<Rc<Self>>,
    directory_bytes: usize,
    oid: GitOid,
}

#[derive(Default)]
pub(super) struct State {
    files: BTreeMap<GitOid, Rc<Rules>>,
    bytes: usize,
    rules: usize,
    steps: usize,
}

impl Context {
    pub(super) const fn legacy(present: bool) -> Self {
        Self::Legacy(present)
    }

    pub(super) fn builtin() -> Self {
        Self::Builtin {
            layers: None,
            blocked: false,
            state: Rc::new(RefCell::new(State::default())),
        }
    }

    /// Collect identities without reading blobs. One-sided/trivial content
    /// still reuses its original object, even under unsupported attributes.
    pub(super) fn descend(&self, trees: [&tree_entries::Tree; 3], path: &[u8]) -> Self {
        let entries = trees.map(|tree| tree.get(b".gitattributes".as_slice()));
        let present = entries.iter().any(Option::is_some);
        match self {
            Self::Legacy(inherited) => Self::Legacy(*inherited || present),
            Self::Builtin {
                layers,
                blocked,
                state,
            } => {
                let stable = entries[0].filter(|entry| {
                    matches!(entry.mode, 0o100644 | 0o100755)
                        && entries[1] == Some(*entry)
                        && entries[2] == Some(*entry)
                });
                Self::Builtin {
                    layers: stable.map_or_else(
                        || layers.clone(),
                        |entry| {
                            Some(Rc::new(Layer {
                                parent: layers.clone(),
                                directory_bytes: path.len(),
                                oid: entry.oid,
                            }))
                        },
                    ),
                    blocked: *blocked || (present && stable.is_none()),
                    state: Rc::clone(state),
                }
            }
        }
    }

    pub(super) fn driver<S: MergeObjectSource>(
        &self,
        planner: &Planner<'_, S>,
        path: &[u8],
    ) -> Result<Driver, PreparationError> {
        let (layers, shared) = match self {
            Self::Legacy(false) => return Ok(Driver::Text),
            Self::Legacy(true) | Self::Builtin { blocked: true, .. } => {
                return Ok(Driver::Unsupported);
            }
            Self::Builtin { layers, state, .. } => (layers, state),
        };
        let mut state = shared.borrow_mut();
        let mut selected = None;
        let mut binary = None;
        let mut layer = layers.as_deref();
        // Higher-precedence directories/rules/assignments decide each attribute
        // first. A later !merge blocks earlier values; a later -binary or
        // !binary suppresses expansion of an earlier built-in binary macro.
        while let Some(current) = layer {
            planner.source.checkpoint()?;
            let rules = state.load(planner, current.oid)?;
            let Rules::Parsed(rules) = &*rules else {
                return Ok(Driver::Unsupported);
            };
            let relative = if current.directory_bytes == 0 {
                path
            } else {
                path.get(current.directory_bytes + 1..)
                    .ok_or(PreparationError::InvalidTree)?
            };
            if selected.is_none() {
                for rule in rules.iter().rev() {
                    if rule.pattern.matches(relative, &mut state, planner.source)? {
                        for assignment in rule.assignments.iter().rev() {
                            match assignment {
                                Assignment::Merge(driver) if selected.is_none() => {
                                    selected = Some(*driver);
                                }
                                Assignment::Binary(value) if binary.is_none() => {
                                    binary = Some(*value);
                                    if *value && selected.is_none() {
                                        selected = Some(Driver::Binary);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    if selected.is_some() {
                        break;
                    }
                }
            }
            layer = current.parent.as_deref();
        }
        Ok(selected.unwrap_or(Driver::Text))
    }
}

impl State {
    fn load<S: MergeObjectSource>(
        &mut self,
        planner: &Planner<'_, S>,
        oid: GitOid,
    ) -> Result<Rc<Rules>, PreparationError> {
        if let Some(rules) = self.files.get(&oid) {
            return Ok(Rc::clone(rules));
        }
        if self.files.len() == FILES {
            return Err(PreparationError::Budget("attribute files"));
        }
        // MergeObjectSource bounds and verifies reads before allocation; this
        // profile then imposes its smaller parsing/cache envelope.
        let bytes = planner.blob(oid)?;
        if bytes.len() > FILE_BYTES {
            return Err(PreparationError::Budget("attribute file bytes"));
        }
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|size| *size <= TOTAL_BYTES)
            .ok_or(PreparationError::Budget("attribute bytes"))?;
        let rules = Rc::new(parse(&bytes, self, planner.source)?);
        self.files.insert(oid, Rc::clone(&rules));
        Ok(rules)
    }

    fn charge<S: MergeObjectSource>(
        &mut self,
        steps: usize,
        source: &S,
    ) -> Result<(), PreparationError> {
        source.checkpoint()?;
        self.steps = self
            .steps
            .checked_add(steps)
            .filter(|steps| *steps <= MATCH_STEPS)
            .ok_or(PreparationError::Budget("attribute matching work"))?;
        Ok(())
    }
}

enum Rules {
    Parsed(Vec<Rule>),
    Unsupported,
}

struct Rule {
    pattern: Pattern,
    assignments: Vec<Assignment>,
}

#[derive(Clone, Copy)]
enum Assignment {
    Merge(Driver),
    Binary(bool),
}

fn parse<S: MergeObjectSource>(
    bytes: &[u8],
    state: &mut State,
    source: &S,
) -> Result<Rules, PreparationError> {
    // Git ignores one UTF-8 signature at the beginning of the file. Treating
    // it as part of the first pattern could miss a binary/custom-driver rule.
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    if bytes
        .iter()
        .any(|byte| byte.is_ascii_control() && !b"\t\r\n".contains(byte))
    {
        return Ok(Rules::Unsupported);
    }
    let mut rules = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        source.checkpoint()?;
        let mut words = line
            .split(|byte| b" \t\r".contains(byte))
            .filter(|word| !word.is_empty());
        let Some(pattern) = words.next() else {
            continue;
        };
        if pattern.starts_with(b"#") {
            continue;
        }
        if rules.len() == FILE_RULES || state.rules == TOTAL_RULES {
            return Err(PreparationError::Budget("attribute rules"));
        }
        state.rules += 1;
        if pattern.len() > PATTERN_BYTES {
            return Err(PreparationError::Budget("attribute pattern bytes"));
        }
        let Some(pattern) = Pattern::parse(pattern) else {
            return Ok(Rules::Unsupported);
        };
        let mut assignments = Vec::new();
        for (index, word) in words.enumerate() {
            if index == ASSIGNMENTS {
                return Err(PreparationError::Budget("attribute assignments"));
            }
            let Some(assignment) = assignment(word) else {
                return Ok(Rules::Unsupported);
            };
            if let Some(assignment) = assignment {
                assignments.push(assignment);
            }
        }
        rules.push(Rule {
            pattern,
            assignments,
        });
    }
    source.checkpoint()?;
    Ok(Rules::Parsed(rules))
}

/// None is unsupported syntax, Some(None) is ordinary metadata. Ignoring a
/// conversion attribute here never normalizes or converts the native blobs.
fn assignment(word: &[u8]) -> Option<Option<Assignment>> {
    let (prefix, word) = match word.first()? {
        b'-' | b'!' => (Some(word[0]), &word[1..]),
        _ => (None, word),
    };
    let split = word.iter().position(|byte| *byte == b'=');
    let (name, value) = split.map_or((word, None), |at| (&word[..at], Some(&word[at + 1..])));
    if name.is_empty()
        || name.starts_with(b"-")
        || !name
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(byte))
        || (prefix.is_some() && value.is_some())
    {
        return None;
    }
    if name == b"merge" {
        let driver = match (prefix, value) {
            (Some(b'-'), None) | (None, Some(b"binary")) => Driver::Binary,
            (Some(b'!'), None) | (None, None | Some(b"text")) => Driver::Text,
            _ => Driver::Unsupported,
        };
        Some(Some(Assignment::Merge(driver)))
    } else if name == b"binary" {
        Some(Some(Assignment::Binary(
            prefix.is_none() && value.is_none(),
        )))
    } else {
        Some(None)
    }
}

struct Pattern {
    segments: Vec<Vec<u8>>,
    basename: bool,
    directory_only: bool,
}

impl Pattern {
    fn parse(bytes: &[u8]) -> Option<Self> {
        // These grammars cannot be guessed or silently treated as literals.
        // Custom macro declarations begin with '[' and are refused here too.
        if bytes.is_empty()
            || bytes.starts_with(b"!")
            || bytes.iter().any(|byte| b"\\\"[".contains(byte))
        {
            return None;
        }
        let basename = !bytes.contains(&b'/');
        let directory_only = bytes.ends_with(b"/");
        let bytes = bytes.strip_prefix(b"/").unwrap_or(bytes);
        let bytes = bytes.strip_suffix(b"/").unwrap_or(bytes);
        let mut segments = Vec::new();
        for part in bytes.split(|byte| *byte == b'/') {
            if part.is_empty() || matches!(part, b"." | b"..") {
                return None;
            }
            // Never downgrade a potentially recursive long all-star run to a
            // single-component match and accidentally admit default text.
            if part.len() >= 3 && part.iter().all(|byte| *byte == b'*') {
                return None;
            }
            if part == b"**" {
                segments.push(part.to_vec());
            } else {
                let mut normalized = Vec::new();
                for byte in part {
                    if *byte != b'*' || normalized.last() != Some(&b'*') {
                        normalized.push(*byte);
                    }
                }
                segments.push(normalized);
            }
        }
        Some(Self {
            segments,
            basename,
            directory_only,
        })
    }

    fn matches<S: MergeObjectSource>(
        &self,
        path: &[u8],
        state: &mut State,
        source: &S,
    ) -> Result<bool, PreparationError> {
        state.charge(1, source)?;
        // Only regular-file content reaches this matcher. A directory pattern
        // never recursively applies attributes to its descendants.
        if self.directory_only {
            return Ok(false);
        }
        if self.basename {
            let name = path.rsplit(|byte| *byte == b'/').next().unwrap_or(path);
            return segment(&self.segments[0], name, state, source);
        }
        let parts: Vec<_> = path.split(|byte| *byte == b'/').collect();
        let mut previous = vec![false; parts.len() + 1];
        previous[0] = true;
        for (index, pattern) in self.segments.iter().enumerate() {
            state.charge(parts.len() + 1, source)?;
            let mut current = vec![false; parts.len() + 1];
            if pattern == b"**" {
                let final_segment = index + 1 == self.segments.len();
                current[0] = !final_segment && previous[0];
                for at in 1..=parts.len() {
                    // A trailing '/**' needs a descendant; an interior '**/'
                    // admits zero directory components as well as many.
                    current[at] = current[at - 1]
                        || if final_segment {
                            previous[at - 1]
                        } else {
                            previous[at]
                        };
                }
            } else {
                for at in 1..=parts.len() {
                    current[at] =
                        previous[at - 1] && segment(pattern, parts[at - 1], state, source)?;
                }
            }
            previous = current;
        }
        Ok(previous[parts.len()])
    }
}

/// Two bounded rows, one pass per pattern byte. Wildcards never recursively
/// retry earlier choices, and every visited cell is charged before the work.
fn segment<S: MergeObjectSource>(
    pattern: &[u8],
    text: &[u8],
    state: &mut State,
    source: &S,
) -> Result<bool, PreparationError> {
    let mut previous = vec![false; text.len() + 1];
    previous[0] = true;
    for byte in pattern {
        state.charge(text.len() + 1, source)?;
        let mut current = vec![false; text.len() + 1];
        current[0] = *byte == b'*' && previous[0];
        for at in 1..=text.len() {
            current[at] = match byte {
                b'*' => previous[at] || current[at - 1],
                b'?' => previous[at - 1],
                _ => previous[at - 1] && *byte == text[at - 1],
            };
        }
        previous = current;
    }
    Ok(previous[text.len()])
}

#[cfg(test)]
mod tests;
