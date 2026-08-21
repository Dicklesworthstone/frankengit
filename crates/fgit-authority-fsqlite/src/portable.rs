//! Canonical export and import of an embedded store's authority content.
//!
//! Export is how an embedded store is backed up, moved between machines, and
//! compared against another backend. Import is the entry point that turns bytes
//! from somewhere else into published authority state, which makes it the most
//! security-sensitive surface in this crate: everything that arrives here is
//! untrusted, including bytes that were once ours.
//!
//! So import is not a deserializer. It is a **validator that happens to
//! deserialize**, and it refuses a bundle whose internal claims do not agree:
//!
//! * a schema generation this build does not implement;
//! * a repeated body key, head key, token, or issuance sequence;
//! * bodies or issuance records out of canonical order;
//! * a head whose token is absent from the bundle's own issuance ledger;
//! * a head whose generation or bytes disagree with that ledger record.
//!
//! That last pair is the one that matters. Without it, a bundle could carry a
//! head bearing a token nobody issued — which is precisely the forged-receipt
//! attack the authenticated head read exists to stop, arriving through the back
//! door instead of the front.
//!
//! # Canonical order is part of the format
//!
//! Bodies are ordered by key and issuance records by sequence, so two stores
//! holding the same content export byte-identical bundles. That is what makes a
//! bundle comparable rather than merely decodable, and it is why import refuses
//! a mis-ordered bundle instead of sorting it: silently repairing the order
//! would make two different byte strings mean the same thing.

use fgit_authority::HeadGeneration;
use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::label::{DomainTag, SchemaFamily};

use crate::schema::SCHEMA_VERSION;
use crate::token::IssuanceSequence;

/// The largest number of immutable bodies one bundle may carry.
pub const MAX_EXPORT_BODIES: usize = 1 << 20;
/// The largest number of issuance records one bundle may carry.
pub const MAX_EXPORT_ISSUANCE: usize = 1 << 20;

/// One immutable body, as it travels.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExportedBody {
    /// The opaque slot key.
    pub key: Vec<u8>,
    /// The exact stored bytes.
    pub body: Vec<u8>,
}

/// One issuance-ledger row, as it travels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedIssuance {
    /// The token's transport form.
    pub token: Vec<u8>,
    /// Its ledger position.
    pub sequence: u64,
    /// The head slot it was minted for.
    pub head_key: Vec<u8>,
    /// The generation published under it.
    pub generation: u64,
    /// The exact bytes published under it.
    pub body: Vec<u8>,
}

/// The published head, as it travels.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedHead {
    /// The head slot key.
    pub key: Vec<u8>,
    /// The token the slot carries.
    pub token: Vec<u8>,
    /// The generation the slot carries.
    pub generation: u64,
    /// The exact head bytes.
    pub body: Vec<u8>,
}

/// One embedded store's complete authority content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportBundle {
    /// The schema generation the exporting store implemented.
    pub schema_version: i64,
    /// The exporting store's instance identity.
    pub instance: u64,
    /// Immutable bodies, in ascending key order.
    pub bodies: Vec<ExportedBody>,
    /// The published head, if the store has one.
    pub head: Option<ExportedHead>,
    /// The append-only issuance ledger, in ascending sequence order.
    pub issuance: Vec<ExportedIssuance>,
}

/// Why a bundle is not admissible.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleRefusal {
    /// The bundle was written by a schema generation this build does not implement.
    SchemaGenerationUnsupported {
        /// What the bundle claims.
        observed: i64,
        /// What this build implements.
        expected: i64,
    },
    /// Two entries share an identifier that must be unique.
    Duplicated {
        /// Which collection.
        collection: &'static str,
    },
    /// A collection is not in its canonical order.
    ///
    /// Refused rather than sorted: repairing the order silently would let two
    /// different byte strings mean the same bundle.
    OutOfOrder {
        /// Which collection.
        collection: &'static str,
    },
    /// A bounded collection exceeded its limit.
    BoundExceeded {
        /// Which collection.
        collection: &'static str,
        /// How many entries were supplied.
        observed: usize,
        /// The limit.
        limit: usize,
    },
    /// An issuance sequence is the reserved zero.
    SequenceReserved,
    /// The head bears a token the bundle's own ledger never issued.
    ///
    /// This is the forged-head case, and it is why import validates rather
    /// than merely decodes.
    HeadTokenUnissued,
    /// The head disagrees with the ledger record for its own token.
    HeadContradictsIssuance {
        /// Which field disagrees.
        field: &'static str,
    },
    /// A generation is the reserved zero.
    GenerationReserved,
    /// The canonical encoding refused.
    Codec(CodecRefusal),
}

impl core::fmt::Display for BundleRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SchemaGenerationUnsupported { observed, expected } => write!(
                f,
                "bundle claims schema generation {observed}; this build implements {expected}"
            ),
            Self::Duplicated { collection } => {
                write!(f, "{collection} carries a repeated identifier")
            }
            Self::OutOfOrder { collection } => write!(
                f,
                "{collection} is not in canonical order; a bundle is refused rather than \
                 silently reordered"
            ),
            Self::BoundExceeded {
                collection,
                observed,
                limit,
            } => write!(
                f,
                "{collection}: {observed} entries exceeds the bound of {limit}"
            ),
            Self::SequenceReserved => f.write_str("issuance sequence zero is reserved"),
            Self::HeadTokenUnissued => f.write_str(
                "the head bears a token this bundle's issuance ledger never issued; a head \
                 whose token nobody minted is a forged head",
            ),
            Self::HeadContradictsIssuance { field } => write!(
                f,
                "the head's {field} disagrees with the ledger record for its own token"
            ),
            Self::GenerationReserved => f.write_str("head generation zero is reserved"),
            Self::Codec(refusal) => write!(f, "canonical encoding refused: {refusal}"),
        }
    }
}

impl std::error::Error for BundleRefusal {}

impl From<CodecRefusal> for BundleRefusal {
    fn from(refusal: CodecRefusal) -> Self {
        Self::Codec(refusal)
    }
}

impl ExportBundle {
    /// Check every internal claim the bundle makes about itself.
    ///
    /// Called by [`import_bundle`] before anything is believed, and exposed so
    /// an exporter can assert it produced an admissible bundle rather than
    /// discovering otherwise at the far end.
    pub fn validate(&self) -> Result<(), BundleRefusal> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(BundleRefusal::SchemaGenerationUnsupported {
                observed: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        check_bound("bodies", self.bodies.len(), MAX_EXPORT_BODIES)?;
        check_bound("issuance", self.issuance.len(), MAX_EXPORT_ISSUANCE)?;

        for pair in self.bodies.windows(2) {
            if pair[0].key == pair[1].key {
                return Err(BundleRefusal::Duplicated {
                    collection: "bodies",
                });
            }
            if pair[0].key > pair[1].key {
                return Err(BundleRefusal::OutOfOrder {
                    collection: "bodies",
                });
            }
        }

        for record in &self.issuance {
            if record.sequence == 0 {
                return Err(BundleRefusal::SequenceReserved);
            }
            if record.generation == 0 {
                return Err(BundleRefusal::GenerationReserved);
            }
        }
        for pair in self.issuance.windows(2) {
            if pair[0].sequence == pair[1].sequence || pair[0].token == pair[1].token {
                return Err(BundleRefusal::Duplicated {
                    collection: "issuance",
                });
            }
            if pair[0].sequence > pair[1].sequence {
                return Err(BundleRefusal::OutOfOrder {
                    collection: "issuance",
                });
            }
        }

        if let Some(head) = &self.head {
            if head.generation == 0 {
                return Err(BundleRefusal::GenerationReserved);
            }
            let issued = self
                .issuance
                .iter()
                .find(|record| record.token == head.token)
                .ok_or(BundleRefusal::HeadTokenUnissued)?;
            if issued.head_key != head.key {
                return Err(BundleRefusal::HeadContradictsIssuance { field: "head key" });
            }
            if issued.generation != head.generation {
                return Err(BundleRefusal::HeadContradictsIssuance {
                    field: "generation",
                });
            }
            if issued.body != head.body {
                return Err(BundleRefusal::HeadContradictsIssuance { field: "body" });
            }
        }
        Ok(())
    }

    /// The sequence a store restored from this bundle would mint next.
    ///
    /// Derived from the bundle's ledger rather than carried as a field, for the
    /// same reason the live store derives it from `MAX(issued_seq)`: a stored
    /// counter can disagree with the rows, and then one of them is wrong.
    pub fn next_issuance(&self) -> Result<IssuanceSequence, crate::token::TokenMintError> {
        let maximum = self.issuance.iter().map(|record| record.sequence).max();
        crate::token::next_issuance_after(maximum)
    }
}

const fn check_bound(
    collection: &'static str,
    observed: usize,
    limit: usize,
) -> Result<(), BundleRefusal> {
    if observed > limit {
        return Err(BundleRefusal::BoundExceeded {
            collection,
            observed,
            limit,
        });
    }
    Ok(())
}

impl CanonicalBody for ExportBundle {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/backup-export-bundle/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("authority-export");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.schema_version);
        out.write_scalar(self.instance);
        out.write_sequence("bodies", &self.bodies, |encoder, body| {
            encoder.write_bytes("body_key", &body.key)?;
            encoder.write_bytes("body_bytes", &body.body)
        })?;
        out.write_option(self.head.as_ref(), |encoder, head| {
            encoder.write_bytes("head_key", &head.key)?;
            encoder.write_bytes("head_token", &head.token)?;
            encoder.write_scalar(head.generation);
            encoder.write_bytes("head_body", &head.body)
        })?;
        out.write_sequence("issuance", &self.issuance, |encoder, record| {
            encoder.write_bytes("token", &record.token)?;
            encoder.write_scalar(record.sequence);
            encoder.write_bytes("issued_head_key", &record.head_key)?;
            encoder.write_scalar(record.generation);
            encoder.write_bytes("issued_body", &record.body)
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let schema_version = input.read_scalar::<i64>("schema_version")?;
        let instance = input.read_scalar::<u64>("instance")?;
        let bodies = input.read_sequence("bodies", |decoder| {
            Ok(ExportedBody {
                key: decoder.read_bytes("body_key")?.to_vec(),
                body: decoder.read_bytes("body_bytes")?.to_vec(),
            })
        })?;
        let head = input.read_option("head", |decoder| {
            Ok(ExportedHead {
                key: decoder.read_bytes("head_key")?.to_vec(),
                token: decoder.read_bytes("head_token")?.to_vec(),
                generation: decoder.read_scalar::<u64>("head_generation")?,
                body: decoder.read_bytes("head_body")?.to_vec(),
            })
        })?;
        let issuance = input.read_sequence("issuance", |decoder| {
            Ok(ExportedIssuance {
                token: decoder.read_bytes("token")?.to_vec(),
                sequence: decoder.read_scalar::<u64>("sequence")?,
                head_key: decoder.read_bytes("issued_head_key")?.to_vec(),
                generation: decoder.read_scalar::<u64>("issued_generation")?,
                body: decoder.read_bytes("issued_body")?.to_vec(),
            })
        })?;
        Ok(Self {
            schema_version,
            instance,
            bodies,
            head,
            issuance,
        })
    }
}

/// Encode a bundle, refusing to export one that is not internally consistent.
///
/// Validating on the way *out* as well as in means a corrupt store is caught
/// where it can still be investigated, rather than at a restore six months
/// later.
pub fn export_bundle(bundle: &ExportBundle) -> Result<Vec<u8>, BundleRefusal> {
    bundle.validate()?;
    Ok(fgit_codec::wire::encode_body(bundle)?)
}

/// Decode and fully validate a bundle from untrusted bytes.
pub fn import_bundle(bytes: &[u8]) -> Result<ExportBundle, BundleRefusal> {
    let bundle: ExportBundle =
        fgit_codec::wire::decode_body(bytes, fgit_codec::DecodeLimits::DEFAULT)?;
    bundle.validate()?;
    Ok(bundle)
}

/// The head generation a validated bundle publishes, if it has a head.
#[must_use]
pub fn bundle_head_generation(bundle: &ExportBundle) -> Option<HeadGeneration> {
    bundle
        .head
        .as_ref()
        .and_then(|head| HeadGeneration::try_new(head.generation).ok())
}
