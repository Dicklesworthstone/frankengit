//! Reference materialization: an export plan rendered as an on-disk object
//! layout, for use as a **conformance oracle only**.
//!
//! `docs/GIT_TREE_FS.md` §10.2 and AGENTS.md §3.1 and §6.
//!
//! # What this is for, and what it is emphatically not
//!
//! FG-026d compares `FrankenGit`'s exported objects against a pinned upstream
//! Git. To do that it needs to know *where each object would live* and *what
//! bytes would sit there*. This module answers exactly that, as data.
//!
//! It does **not** run Git. It does not spawn a process, touch a filesystem, or
//! know what a working directory is. AGENTS.md §3.1 forbids invoking `git`,
//! `libgit2`, or any helper hiding one, and §6 confines upstream Git to pinned,
//! sandboxed, explicitly non-production differential lanes. A materializer that
//! shelled out "just for the oracle" would be that forbidden path wearing a
//! test-shaped label, so this one returns a description and lets the caller —
//! in a conformance lane, under a pin manifest — decide what to do with it.
//!
//! # The compression boundary is explicit
//!
//! A real loose object is zlib-framed. That framing belongs to `fgit-deflate`
//! (FG-092), not here, so [`LooseObject::framed_bytes`] carries the
//! **uncompressed** canonical stream — `<type> <size>\0<body>` — and
//! [`LooseObject::compression`] states plainly that compression has not been
//! applied. Quietly emitting uncompressed bytes under a name that implies a
//! finished loose object would be the kind of near-miss that passes a shallow
//! test and fails a real Git.

use crate::export::ExportPlan;
use core::fmt::{self, Display, Formatter};
use fgit_crypto::{GitHashAlgorithm, GitObjectKind, NativeObjectIdentity};
use fgit_git_object::{ObjectError, ParseLimits, emit_loose_framed};

/// Whether a rendered object's bytes have been compressed.
///
/// A named state rather than an implicit assumption: a consumer that needs a
/// byte-exact loose object must know it still has to deflate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Compression {
    /// The canonical `<type> <size>\0<body>` stream, not yet deflated.
    ///
    /// This is what this module produces. Applying zlib is `fgit-deflate`'s
    /// job and is a separate, owned step.
    #[default]
    NoneCanonicalStream,
}

impl Display for Compression {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoneCanonicalStream => formatter.write_str("none (canonical stream)"),
        }
    }
}

/// Why a plan could not be rendered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterializeRefusal {
    /// An object could not be framed.
    Object(String),
    /// An object's identity is too short to split into a loose-object path.
    ///
    /// Git splits the hex identity after two characters; an identity shorter
    /// than that has no valid placement and is refused rather than padded.
    IdentityTooShort {
        /// Hex length observed.
        observed: usize,
    },
}

impl Display for MaterializeRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Object(inner) => write!(formatter, "object framing failed: {inner}"),
            Self::IdentityTooShort { observed } => write!(
                formatter,
                "identity is {observed} hex characters, too short for a loose-object path"
            ),
        }
    }
}

impl core::error::Error for MaterializeRefusal {}

impl From<ObjectError> for MaterializeRefusal {
    fn from(value: ObjectError) -> Self {
        Self::Object(value.to_string())
    }
}

/// One object rendered at the place Git would keep it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LooseObject {
    relative_path: String,
    kind: GitObjectKind,
    oid_hex: String,
    framed_bytes: Vec<u8>,
    compression: Compression,
}

impl LooseObject {
    /// The repository-relative path, e.g. `objects/ab/cdef…`.
    ///
    /// Always forward-slashed and relative. A host adapter decides how to place
    /// it; this module never assembles an absolute path, because an absolute
    /// path here would be a filesystem decision made in the wrong layer.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// The object kind.
    #[must_use]
    pub const fn kind(&self) -> GitObjectKind {
        self.kind
    }

    /// The lowercase hexadecimal identity.
    #[must_use]
    pub fn oid_hex(&self) -> &str {
        &self.oid_hex
    }

    /// The canonical `<type> <size>\0<body>` stream.
    ///
    /// Uncompressed; see [`Self::compression`].
    #[must_use]
    pub fn framed_bytes(&self) -> &[u8] {
        &self.framed_bytes
    }

    /// What has and has not been applied to [`Self::framed_bytes`].
    #[must_use]
    pub const fn compression(&self) -> Compression {
        self.compression
    }
}

/// A whole plan rendered as an object layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceLayout {
    objects: Vec<LooseObject>,
    root_tree_hex: String,
}

impl ReferenceLayout {
    /// The rendered objects, in identity order.
    #[must_use]
    pub fn objects(&self) -> &[LooseObject] {
        &self.objects
    }

    /// The root tree identity, in hex.
    #[must_use]
    pub fn root_tree_hex(&self) -> &str {
        &self.root_tree_hex
    }

    /// How many objects the layout holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether the layout is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Every relative path, in order, for set comparison against an oracle.
    #[must_use]
    pub fn paths(&self) -> Vec<&str> {
        self.objects
            .iter()
            .map(|object| object.relative_path.as_str())
            .collect()
    }
}

/// Renders an export plan as a reference object layout.
///
/// Deterministic: objects come from the plan in identity order and each path is
/// derived from the identity alone, so two runs over the same plan produce the
/// same layout byte for byte.
pub fn materialize<A: GitHashAlgorithm>(
    plan: &ExportPlan<A>,
    limits: &ParseLimits,
) -> Result<ReferenceLayout, MaterializeRefusal> {
    let mut objects = Vec::with_capacity(plan.object_count());
    for object in plan.objects() {
        let hex = hex_of(object.oid().digest_bytes());
        if hex.len() < 3 {
            return Err(MaterializeRefusal::IdentityTooShort {
                observed: hex.len(),
            });
        }
        let framed = emit_loose_framed(object.kind(), object.body(), limits)?;
        objects.push(LooseObject {
            relative_path: format!("objects/{}/{}", &hex[..2], &hex[2..]),
            kind: object.kind(),
            oid_hex: hex,
            framed_bytes: framed,
            compression: Compression::NoneCanonicalStream,
        });
    }
    Ok(ReferenceLayout {
        root_tree_hex: hex_of(plan.root_tree().digest_bytes()),
        objects,
    })
}

fn hex_of(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
