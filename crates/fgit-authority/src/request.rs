//! The canonical semantic request and its digest.
//!
//! `NORMATIVE_PROTOCOL_CONTRACTS.md` §3.3 fixes exactly which fields the
//! canonical request digest binds and exactly which it excludes. The binding
//! set is every client-visible semantic field: expected-old refs, proposed new
//! native object ids, force and atomic flags, push options, requested forge
//! transitions, policy-visible metadata, path and effect scope, and the schema
//! version. The exclusion set is everything about *how* the request arrived:
//! pack encoding, quarantine placement, the derived object-closure manifest,
//! retry count, receiving node, connection, wall-clock time, server nonce, and
//! the authority-head basis.
//!
//! That split is the whole point. A retry that re-uploads an equivalent pack
//! from a different node at a different time must produce the identical digest,
//! and therefore the identical transaction identity; a request that changes one
//! semantic field must not.
//!
//! [`SemanticRequest`] is the typed realisation of the binding set. It cannot
//! hold a field from the exclusion set, because none exists on it — the
//! exclusion is structural rather than a rule someone has to remember.
//!
//! # Canonicalization, not normalization
//!
//! Ref commands are logically an unordered set keyed by ref name, so they are
//! stored in ref-name order and the caller's order cannot reach the digest.
//! Two commands naming the *same* ref are **refused**, never merged or
//! deduplicated: contradictory duplicates are refused rather than silently
//! normalized into an invented policy. Push options are the opposite case —
//! their order is client-visible semantics, not framing — so their order is
//! preserved exactly.

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::label::{AsciiSlug, DomainTag, SchemaFamily, SchemaId};
use fgit_types::native::{GitHashAlgorithm, GitOid};
use fgit_types::refs::RefName;

/// Largest number of ref commands one request may carry.
pub const MAX_REF_COMMANDS: usize = 4096;
/// Largest number of push options one request may carry.
pub const MAX_PUSH_OPTIONS: usize = 256;
/// Largest push option, in bytes.
pub const MAX_PUSH_OPTION_BYTES: usize = 1024;
/// Largest number of scoped entries one request may carry.
pub const MAX_SCOPED_ENTRIES: usize = 1024;
/// Largest scoped-entry value, in bytes.
pub const MAX_SCOPED_VALUE_BYTES: usize = 4096;

/// Why a semantic request is not admissible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestRefusal {
    /// Two commands name the same ref.
    ///
    /// Merging them would invent a policy the client did not state.
    RefCommandDuplicated {
        /// The ref named twice.
        name: Box<RefName>,
    },
    /// Two scoped entries share a namespace and key.
    ScopedEntryDuplicated {
        /// The namespace named twice.
        namespace: Box<AsciiSlug>,
        /// The key named twice.
        key: Box<AsciiSlug>,
    },
    /// An object id does not belong to the repository's declared object format.
    ///
    /// Equal digest bytes under different algorithms are not equal identities,
    /// so a mixed-format request has no single meaning.
    ObjectFormatMismatch {
        /// Format the repository declared.
        declared: GitHashAlgorithm,
        /// Format the offending object id carries.
        observed: GitHashAlgorithm,
    },
    /// A bounded collection or value exceeded its declared limit.
    BoundExceeded {
        /// Which bound.
        field: &'static str,
        /// What was supplied.
        observed: usize,
        /// The limit.
        limit: usize,
    },
    /// The canonical encoder refused the request.
    Codec(CodecRefusal),
}

impl core::fmt::Display for RequestRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RefCommandDuplicated { name } => write!(
                f,
                "two commands name the ref {:?}; contradictory duplicates are refused",
                name.as_str()
            ),
            Self::ScopedEntryDuplicated { namespace, key } => write!(
                f,
                "two scoped entries share {}/{}",
                namespace.as_str(),
                key.as_str()
            ),
            Self::ObjectFormatMismatch { declared, observed } => write!(
                f,
                "object id in {} where the repository declares {}",
                observed.as_str(),
                declared.as_str()
            ),
            Self::BoundExceeded {
                field,
                observed,
                limit,
            } => write!(f, "{field}: {observed} exceeds the bound of {limit}"),
            Self::Codec(refusal) => write!(f, "canonical encoding refused: {refusal}"),
        }
    }
}

impl std::error::Error for RequestRefusal {}

impl From<CodecRefusal> for RequestRefusal {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

/// What the client asserts the ref currently holds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ExpectedOld {
    /// The client asserts the ref does not exist.
    Absent,
    /// The client asserts the ref holds exactly this object.
    Exactly(GitOid),
    /// The client supplied no expectation.
    ///
    /// This is a distinct semantic field value, not a missing one: a request
    /// that omits the expectation means something different from one that
    /// asserts absence, and the digest must tell them apart.
    Unspecified,
}

/// What the client wants the ref to hold.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProposedNew {
    /// Delete the ref.
    Delete,
    /// Point the ref at this object.
    Update(GitOid),
}

/// One requested ref transition.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RefCommand {
    /// The ref this command targets.
    pub name: RefName,
    /// What the client asserts the ref currently holds.
    pub expected_old: ExpectedOld,
    /// What the client wants the ref to hold.
    pub proposed_new: ProposedNew,
    /// Whether the client asked to bypass fast-forward checking for this ref.
    pub force: bool,
}

impl RefCommand {
    fn write(out: &mut Encoder, value: &Self) -> Result<(), CodecRefusal> {
        out.write_ref_name(&value.name)?;
        match value.expected_old {
            ExpectedOld::Absent => out.write_raw_byte(0),
            ExpectedOld::Exactly(oid) => {
                out.write_raw_byte(1);
                out.write_git_oid(&oid);
            }
            ExpectedOld::Unspecified => out.write_raw_byte(2),
        }
        match value.proposed_new {
            ProposedNew::Delete => out.write_raw_byte(0),
            ProposedNew::Update(oid) => {
                out.write_raw_byte(1);
                out.write_git_oid(&oid);
            }
        }
        out.write_bool(value.force);
        Ok(())
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let name = input.read_ref_name()?;
        let offset = input.offset();
        let expected_old = match input.read_raw_byte("ExpectedOld")? {
            0 => ExpectedOld::Absent,
            1 => ExpectedOld::Exactly(input.read_git_oid()?),
            2 => ExpectedOld::Unspecified,
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "ExpectedOld",
                    observed: u32::from(observed),
                    offset,
                });
            }
        };
        let offset = input.offset();
        let proposed_new = match input.read_raw_byte("ProposedNew")? {
            0 => ProposedNew::Delete,
            1 => ProposedNew::Update(input.read_git_oid()?),
            observed => {
                return Err(CodecRefusal::VariantUnknown {
                    field: "ProposedNew",
                    observed: u32::from(observed),
                    offset,
                });
            }
        };
        let force = input.read_bool("RefCommand.force")?;
        Ok(Self {
            name,
            expected_old,
            proposed_new,
            force,
        })
    }

    const fn object_ids(&self) -> [Option<GitOid>; 2] {
        let old = match self.expected_old {
            ExpectedOld::Exactly(oid) => Some(oid),
            ExpectedOld::Absent | ExpectedOld::Unspecified => None,
        };
        let new = match self.proposed_new {
            ProposedNew::Update(oid) => Some(oid),
            ProposedNew::Delete => None,
        };
        [old, new]
    }
}

/// One client-supplied push option, preserved byte-exactly.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PushOption(Vec<u8>);

impl PushOption {
    /// Accept a push option within its declared bound.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, RequestRefusal> {
        let bytes = bytes.into();
        if bytes.len() > MAX_PUSH_OPTION_BYTES {
            return Err(RequestRefusal::BoundExceeded {
                field: "push_option",
                observed: bytes.len(),
                limit: MAX_PUSH_OPTION_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// The exact option bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One namespaced semantic entry.
///
/// Requested forge transitions, policy-visible metadata, and path or effect
/// scope all live here. Their vocabularies belong to the forge and policy
/// subsystems, not to transaction identity, so this crate binds them exactly
/// and canonically without claiming to interpret them.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScopedEntry {
    /// Which subsystem owns the meaning of this entry.
    pub namespace: AsciiSlug,
    /// The entry key within that namespace.
    pub key: AsciiSlug,
    /// The exact entry value.
    pub value: Vec<u8>,
}

impl ScopedEntry {
    /// Accept an entry within its declared bound.
    pub fn new(
        namespace: AsciiSlug,
        key: AsciiSlug,
        value: impl Into<Vec<u8>>,
    ) -> Result<Self, RequestRefusal> {
        let value = value.into();
        if value.len() > MAX_SCOPED_VALUE_BYTES {
            return Err(RequestRefusal::BoundExceeded {
                field: "scoped_entry_value",
                observed: value.len(),
                limit: MAX_SCOPED_VALUE_BYTES,
            });
        }
        Ok(Self {
            namespace,
            key,
            value,
        })
    }

    fn write(out: &mut Encoder, value: &Self) -> Result<(), CodecRefusal> {
        out.write_bytes("ScopedEntry.namespace", value.namespace.as_bytes())?;
        out.write_bytes("ScopedEntry.key", value.key.as_bytes())?;
        out.write_bytes("ScopedEntry.value", &value.value)
    }

    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let namespace =
            AsciiSlug::try_new("ScopedEntry.namespace", input.read_bytes("namespace")?)?;
        let key = AsciiSlug::try_new("ScopedEntry.key", input.read_bytes("key")?)?;
        let value = input.read_bytes("value")?.to_vec();
        Ok(Self {
            namespace,
            key,
            value,
        })
    }
}

/// The complete client-visible semantic content of one mutation request.
///
/// Construct with [`SemanticRequest::build`], which canonicalizes and refuses;
/// the fields are private so a caller cannot assemble one that skipped the
/// checks.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SemanticRequest {
    request_schema: SchemaId,
    object_format: GitHashAlgorithm,
    atomic: bool,
    ref_commands: Vec<RefCommand>,
    push_options: Vec<PushOption>,
    scoped_entries: Vec<ScopedEntry>,
}

impl SemanticRequest {
    /// Canonicalize and admit one request.
    ///
    /// Ref commands and scoped entries are sorted into canonical order, so the
    /// caller's ordering cannot reach the digest; a repeated ref name or a
    /// repeated namespace-and-key pair is refused rather than merged.
    pub fn build(
        request_schema: SchemaId,
        object_format: GitHashAlgorithm,
        atomic: bool,
        ref_commands: Vec<RefCommand>,
        push_options: Vec<PushOption>,
        scoped_entries: Vec<ScopedEntry>,
    ) -> Result<Self, RequestRefusal> {
        check_bound("ref_commands", ref_commands.len(), MAX_REF_COMMANDS)?;
        check_bound("push_options", push_options.len(), MAX_PUSH_OPTIONS)?;
        check_bound("scoped_entries", scoped_entries.len(), MAX_SCOPED_ENTRIES)?;

        for command in &ref_commands {
            for oid in command.object_ids().into_iter().flatten() {
                if oid.algorithm() != object_format {
                    return Err(RequestRefusal::ObjectFormatMismatch {
                        declared: object_format,
                        observed: oid.algorithm(),
                    });
                }
            }
        }

        let mut ref_commands = ref_commands;
        ref_commands.sort_by(|left, right| left.name.cmp(&right.name));
        for window in ref_commands.windows(2) {
            if window[0].name == window[1].name {
                return Err(RequestRefusal::RefCommandDuplicated {
                    name: Box::new(window[0].name.clone()),
                });
            }
        }

        let mut scoped_entries = scoped_entries;
        scoped_entries.sort_by(|left, right| {
            (left.namespace.as_bytes(), left.key.as_bytes())
                .cmp(&(right.namespace.as_bytes(), right.key.as_bytes()))
        });
        for window in scoped_entries.windows(2) {
            if window[0].namespace == window[1].namespace && window[0].key == window[1].key {
                return Err(RequestRefusal::ScopedEntryDuplicated {
                    namespace: Box::new(window[0].namespace),
                    key: Box::new(window[0].key),
                });
            }
        }

        Ok(Self {
            request_schema,
            object_format,
            atomic,
            ref_commands,
            push_options,
            scoped_entries,
        })
    }

    /// The schema the request was canonicalized under.
    #[must_use]
    pub const fn request_schema(&self) -> SchemaId {
        self.request_schema
    }

    /// The repository's declared object format.
    #[must_use]
    pub const fn object_format(&self) -> GitHashAlgorithm {
        self.object_format
    }

    /// Whether the client asked for all-or-nothing application.
    #[must_use]
    pub const fn atomic(&self) -> bool {
        self.atomic
    }

    /// The ref commands, in canonical ref-name order.
    #[must_use]
    pub fn ref_commands(&self) -> &[RefCommand] {
        &self.ref_commands
    }

    /// The push options, in the order the client sent them.
    #[must_use]
    pub fn push_options(&self) -> &[PushOption] {
        &self.push_options
    }

    /// The scoped entries, in canonical namespace-and-key order.
    #[must_use]
    pub fn scoped_entries(&self) -> &[ScopedEntry] {
        &self.scoped_entries
    }
}

const fn check_bound(
    field: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), RequestRefusal> {
    if observed > limit {
        return Err(RequestRefusal::BoundExceeded {
            field,
            observed,
            limit,
        });
    }
    Ok(())
}

impl CanonicalBody for SemanticRequest {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/ref-txn/v2");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("canonical-request");
    const SCHEMA_MAJOR: u16 = 2;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_schema_id(self.request_schema)?;
        out.write_git_hash_algorithm(self.object_format);
        out.write_bool(self.atomic);
        out.write_sequence("ref_commands", &self.ref_commands, RefCommand::write)?;
        out.write_sequence("push_options", &self.push_options, |encoder, option| {
            encoder.write_bytes("push_option", option.as_bytes())
        })?;
        out.write_sequence("scoped_entries", &self.scoped_entries, ScopedEntry::write)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let request_schema = input.read_schema_id()?;
        let object_format = input.read_git_hash_algorithm()?;
        let atomic = input.read_bool("atomic")?;
        let ref_commands = input.read_sequence("ref_commands", RefCommand::read)?;
        let push_options = input.read_sequence("push_options", |decoder| {
            Ok(PushOption(decoder.read_bytes("push_option")?.to_vec()))
        })?;
        let scoped_entries = input.read_sequence("scoped_entries", ScopedEntry::read)?;
        Ok(Self {
            request_schema,
            object_format,
            atomic,
            ref_commands,
            push_options,
            scoped_entries,
        })
    }
}

/// `clippy::result_large_err` refuses an `Err` variant past this many bytes,
/// and it is right to: a fat error is copied through every `?` on the happy
/// path's error edge. `fgit-types` stores digests and labels as inline bounded
/// arrays, so anything carrying an identity or a domain tag crosses it and has
/// to be boxed. These assertions fail the build rather than the lint, so the
/// types cannot grow back quietly.
pub const MAX_ERROR_BYTES: usize = 128;

const _: () = assert!(size_of::<RequestRefusal>() <= MAX_ERROR_BYTES);
