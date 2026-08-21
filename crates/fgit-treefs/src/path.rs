//! Canonical repository path bytes and the refusals that keep them inside a
//! workspace root.
//!
//! Path handling is the security core of TreeFS (`docs/GIT_TREE_FS.md` §3.3,
//! §5, §15). Everything else in this crate is capability-relative to a
//! [`TreePath`], so a path that normalises wrongly is not a cosmetic bug: it is
//! a workspace escape. The parser is therefore total and refuses by name rather
//! than repairing input.
//!
//! Two rules deserve stating outright because they are the ones that are
//! usually got wrong:
//!
//! * **Prefix containment is component-wise, never a byte prefix.** `a/bc` is
//!   not inside `a/b`. [`TreePath::starts_with`] compares components, which is
//!   what makes capability prefixes sound.
//! * **`..` is refused, never resolved.** Resolving it here would mean the
//!   answer depends on evaluation order relative to symlinks and whiteouts, and
//!   a workspace escape would follow from a correct-looking local decision.

use core::fmt::{self, Display, Formatter};

/// Longest accepted total path length in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// Longest accepted single component length in bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Deepest accepted component count.
pub const MAX_COMPONENTS: usize = 64;

/// Why a byte sequence is not an acceptable repository path.
///
/// Every variant names the offending construct. A caller can map these onto a
/// user-facing message without re-deriving what went wrong.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathRefusal {
    /// The path was empty, which never denotes an entry.
    Empty,
    /// The path began with a separator, i.e. it was rooted at the host.
    Absolute,
    /// A `..` component appeared. It is refused, never resolved.
    ParentEscape {
        /// Zero-based component index.
        component: usize,
    },
    /// A `.` component appeared.
    CurrentDirectory {
        /// Zero-based component index.
        component: usize,
    },
    /// Two adjacent separators, or a trailing separator, produced an empty
    /// component.
    EmptyComponent {
        /// Zero-based component index.
        component: usize,
    },
    /// A NUL byte appeared. Git tree entries are NUL-terminated, so a NUL in a
    /// name is unrepresentable rather than merely unusual.
    NulByte {
        /// Byte offset within the whole path.
        offset: usize,
    },
    /// A byte below 0x20 appeared in a component.
    ControlByte {
        /// Byte offset within the whole path.
        offset: usize,
        /// The offending byte.
        byte: u8,
    },
    /// A component matched a Git metadata directory under the active policy.
    GitMetadata {
        /// Zero-based component index.
        component: usize,
    },
    /// A component is reserved by a target host profile.
    HostReserved {
        /// Zero-based component index.
        component: usize,
    },
    /// A component ends with a byte a target host silently strips.
    HostTrailingByte {
        /// Zero-based component index.
        component: usize,
        /// The offending trailing byte.
        byte: u8,
    },
    /// The whole path exceeded [`MAX_PATH_BYTES`].
    PathTooLong {
        /// Observed length in bytes.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// One component exceeded [`MAX_COMPONENT_BYTES`].
    ComponentTooLong {
        /// Zero-based component index.
        component: usize,
        /// Observed length in bytes.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
    /// The path had more components than [`MAX_COMPONENTS`].
    TooManyComponents {
        /// Observed component count.
        observed: usize,
        /// Configured maximum.
        maximum: usize,
    },
}

impl Display for PathRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "path is empty"),
            Self::Absolute => write!(formatter, "path is absolute"),
            Self::ParentEscape { component } => {
                write!(formatter, "parent-escape component at index {component}")
            }
            Self::CurrentDirectory { component } => {
                write!(
                    formatter,
                    "current-directory component at index {component}"
                )
            }
            Self::EmptyComponent { component } => {
                write!(formatter, "empty component at index {component}")
            }
            Self::NulByte { offset } => write!(formatter, "NUL byte at offset {offset}"),
            Self::ControlByte { offset, byte } => {
                write!(formatter, "control byte {byte:#04x} at offset {offset}")
            }
            Self::GitMetadata { component } => {
                write!(formatter, "git metadata component at index {component}")
            }
            Self::HostReserved { component } => {
                write!(formatter, "host-reserved component at index {component}")
            }
            Self::HostTrailingByte { component, byte } => write!(
                formatter,
                "component {component} ends with host-stripped byte {byte:#04x}"
            ),
            Self::PathTooLong { observed, maximum } => {
                write!(formatter, "path is {observed} bytes, maximum {maximum}")
            }
            Self::ComponentTooLong {
                component,
                observed,
                maximum,
            } => write!(
                formatter,
                "component {component} is {observed} bytes, maximum {maximum}"
            ),
            Self::TooManyComponents { observed, maximum } => {
                write!(formatter, "{observed} components, maximum {maximum}")
            }
        }
    }
}

impl core::error::Error for PathRefusal {}

/// Which host-representability rules to enforce while parsing.
///
/// The repository profile accepts everything Git itself can store. A host
/// profile additionally refuses names a target filesystem would alias or
/// mangle, because silently aliasing two distinct Git paths is the failure
/// `docs/GIT_TREE_FS.md` §3.3 forbids outright.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HostProfile {
    /// Git semantics only.
    #[default]
    Repository,
    /// Additionally refuse names Windows reserves or rewrites.
    WindowsCompatible,
}

/// Path parsing policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathPolicy {
    /// Host representability rules.
    pub host_profile: HostProfile,
    /// Refuse `.git` and its case variants as a component.
    pub refuse_git_metadata: bool,
    /// Longest accepted total length in bytes.
    pub max_path_bytes: usize,
    /// Longest accepted component length in bytes.
    pub max_component_bytes: usize,
    /// Deepest accepted component count.
    pub max_components: usize,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            host_profile: HostProfile::Repository,
            refuse_git_metadata: true,
            max_path_bytes: MAX_PATH_BYTES,
            max_component_bytes: MAX_COMPONENT_BYTES,
            max_components: MAX_COMPONENTS,
        }
    }
}

/// Names Windows reserves regardless of extension.
const WINDOWS_RESERVED_STEMS: &[&[u8]] = &[
    b"con", b"prn", b"aux", b"nul", b"com1", b"com2", b"com3", b"com4", b"com5", b"com6", b"com7",
    b"com8", b"com9", b"lpt1", b"lpt2", b"lpt3", b"lpt4", b"lpt5", b"lpt6", b"lpt7", b"lpt8",
    b"lpt9",
];

/// Bytes Windows refuses inside a name.
const WINDOWS_FORBIDDEN_BYTES: &[u8] = b"<>:\"\\|?*";

/// A canonical repository path: non-empty, separator-joined components, with
/// no leading or trailing separator and no `.` or `..` component.
///
/// The byte sequence is preserved exactly as Git stores it. This type performs
/// no Unicode normalisation, because normalising would change the object
/// identity of the tree that contains it; normalisation concerns surface as
/// collision *keys* instead ([`TreePath::case_fold_key`]).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TreePath {
    bytes: Vec<u8>,
}

impl TreePath {
    /// Parses canonical repository path bytes under `policy`.
    pub fn parse(bytes: &[u8], policy: &PathPolicy) -> Result<Self, PathRefusal> {
        if bytes.is_empty() {
            return Err(PathRefusal::Empty);
        }
        if bytes.len() > policy.max_path_bytes {
            return Err(PathRefusal::PathTooLong {
                observed: bytes.len(),
                maximum: policy.max_path_bytes,
            });
        }
        if bytes[0] == b'/' {
            return Err(PathRefusal::Absolute);
        }

        let mut offset = 0_usize;
        let mut index = 0_usize;
        for component in bytes.split(|byte| *byte == b'/') {
            if index >= policy.max_components {
                return Err(PathRefusal::TooManyComponents {
                    observed: index + 1,
                    maximum: policy.max_components,
                });
            }
            validate_component(component, index, offset, policy)?;
            offset += component.len() + 1;
            index += 1;
        }
        if index > policy.max_components {
            return Err(PathRefusal::TooManyComponents {
                observed: index,
                maximum: policy.max_components,
            });
        }

        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Parses under the default policy.
    pub fn parse_default(bytes: &[u8]) -> Result<Self, PathRefusal> {
        Self::parse(bytes, &PathPolicy::default())
    }

    /// The canonical bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The components, in order.
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &[u8]> {
        self.bytes.split(|byte| *byte == b'/')
    }

    /// How many components the path has.
    #[must_use]
    pub fn component_count(&self) -> usize {
        self.components().count()
    }

    /// The final component.
    #[must_use]
    pub fn file_name(&self) -> &[u8] {
        self.components().next_back().unwrap_or(&self.bytes)
    }

    /// The containing directory, or `None` at the top level.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let position = self.bytes.iter().rposition(|byte| *byte == b'/')?;
        Some(Self {
            bytes: self.bytes[..position].to_vec(),
        })
    }

    /// Every proper ancestor, shallowest first.
    #[must_use]
    pub fn ancestors(&self) -> Vec<Self> {
        let mut out = Vec::new();
        let mut prefix: Vec<u8> = Vec::new();
        let mut components = self.components().peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !prefix.is_empty() {
                prefix.push(b'/');
            }
            prefix.extend_from_slice(component);
            out.push(Self {
                bytes: prefix.clone(),
            });
        }
        out
    }

    /// Appends one component under `policy`.
    pub fn join(&self, component: &[u8], policy: &PathPolicy) -> Result<Self, PathRefusal> {
        let mut bytes = self.bytes.clone();
        bytes.push(b'/');
        bytes.extend_from_slice(component);
        Self::parse(&bytes, policy)
    }

    /// Whether `self` is `prefix` or lies beneath it.
    ///
    /// Containment is component-wise. `a/bc` is **not** beneath `a/b`, which a
    /// byte-prefix test would get wrong and which capability scoping depends
    /// on.
    #[must_use]
    pub fn starts_with(&self, prefix: &Self) -> bool {
        let mut mine = self.components();
        let mut theirs = prefix.components();
        loop {
            match theirs.next() {
                None => return true,
                Some(expected) => match mine.next() {
                    Some(actual) if actual == expected => {}
                    _ => return false,
                },
            }
        }
    }

    /// An ASCII case-folded collision key.
    ///
    /// Two distinct Git paths that share a key would alias on a
    /// case-insensitive host. The key is advisory: it is used to *detect and
    /// refuse* an alias, never to rewrite a path.
    #[must_use]
    pub fn case_fold_key(&self) -> Vec<u8> {
        self.bytes.to_ascii_lowercase()
    }

    /// Whether this path would alias `other` on a case-insensitive host while
    /// being a genuinely different repository path.
    #[must_use]
    pub fn case_aliases(&self, other: &Self) -> bool {
        self != other && self.case_fold_key() == other.case_fold_key()
    }
}

impl Display for TreePath {
    /// Renders as lossy UTF-8. Repository paths are byte strings, so this is a
    /// display convenience and never a round-trip encoding.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", String::from_utf8_lossy(&self.bytes))
    }
}

fn validate_component(
    component: &[u8],
    index: usize,
    offset: usize,
    policy: &PathPolicy,
) -> Result<(), PathRefusal> {
    if component.is_empty() {
        return Err(PathRefusal::EmptyComponent { component: index });
    }
    if component.len() > policy.max_component_bytes {
        return Err(PathRefusal::ComponentTooLong {
            component: index,
            observed: component.len(),
            maximum: policy.max_component_bytes,
        });
    }
    if component == b"." {
        return Err(PathRefusal::CurrentDirectory { component: index });
    }
    if component == b".." {
        return Err(PathRefusal::ParentEscape { component: index });
    }
    for (position, byte) in component.iter().enumerate() {
        if *byte == 0 {
            return Err(PathRefusal::NulByte {
                offset: offset + position,
            });
        }
        if *byte < 0x20 {
            return Err(PathRefusal::ControlByte {
                offset: offset + position,
                byte: *byte,
            });
        }
    }
    if policy.refuse_git_metadata && is_git_metadata(component) {
        return Err(PathRefusal::GitMetadata { component: index });
    }
    if policy.host_profile == HostProfile::WindowsCompatible {
        validate_windows_component(component, index)?;
    }
    Ok(())
}

/// Whether a component names Git's metadata directory.
///
/// The comparison is ASCII case-insensitive and also covers the `git~1` short
/// name, because a case-insensitive or 8.3-aware host resolves those to the
/// same directory. Accepting one of them would let repository content write
/// into repository metadata.
fn is_git_metadata(component: &[u8]) -> bool {
    let folded = component.to_ascii_lowercase();
    if folded == b".git" || folded == b"git~1" {
        return true;
    }
    // `.git.` and `.git ` resolve to `.git` on hosts that strip trailing dots
    // and spaces.
    let trimmed: &[u8] = {
        let mut end = folded.len();
        while end > 0 && (folded[end - 1] == b'.' || folded[end - 1] == b' ') {
            end -= 1;
        }
        &folded[..end]
    };
    trimmed == b".git"
}

fn validate_windows_component(component: &[u8], index: usize) -> Result<(), PathRefusal> {
    for byte in component {
        if WINDOWS_FORBIDDEN_BYTES.contains(byte) {
            return Err(PathRefusal::HostReserved { component: index });
        }
    }
    let last = component[component.len() - 1];
    if last == b'.' || last == b' ' {
        return Err(PathRefusal::HostTrailingByte {
            component: index,
            byte: last,
        });
    }
    let stem_end = component
        .iter()
        .position(|byte| *byte == b'.')
        .unwrap_or(component.len());
    let stem = component[..stem_end].to_ascii_lowercase();
    if WINDOWS_RESERVED_STEMS.contains(&stem.as_slice()) {
        return Err(PathRefusal::HostReserved { component: index });
    }
    Ok(())
}
