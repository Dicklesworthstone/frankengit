//! Source-bound omissions are part of the manifest, never an unverified skip list.
//! Only local source/profile failures can become omissions. Integrity, authority,
//! cancellation and shared resource exhaustion still refuse the whole build.
use super::{
    Decoder, Encoder, Error, Format, GitOid, MAX_PAYLOAD, TreePath, engine, read_oid, table,
};

pub const OMISSION_INDEX_PROFILE: &str = "rust-declaration-omissions-v1";
pub const OMISSION_DIRECTORY_PROFILE: &str = "rust-symbol-omission-directory-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    FileBytes,
    InvalidUtf8,
    UnsupportedIdentifier,
    UnterminatedComment,
    UnterminatedLiteral,
    UnbalancedDelimiter,
    DepthLimit,
    NameLimit,
    TableBytes,
}
impl OmissionReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileBytes => "file_bytes",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::UnsupportedIdentifier => "unsupported_identifier",
            Self::UnterminatedComment => "unterminated_comment",
            Self::UnterminatedLiteral => "unterminated_literal",
            Self::UnbalancedDelimiter => "unbalanced_delimiter",
            Self::DepthLimit => "depth_limit",
            Self::NameLimit => "name_limit",
            Self::TableBytes => "table_bytes",
        }
    }
    const fn tag(self) -> u8 {
        match self {
            Self::FileBytes => 1,
            Self::InvalidUtf8 => 2,
            Self::UnsupportedIdentifier => 3,
            Self::UnterminatedComment => 4,
            Self::UnterminatedLiteral => 5,
            Self::UnbalancedDelimiter => 6,
            Self::DepthLimit => 7,
            Self::NameLimit => 8,
            Self::TableBytes => 9,
        }
    }
    fn read(tag: u8) -> Result<Self, Error> {
        Ok(match tag {
            1 => Self::FileBytes,
            2 => Self::InvalidUtf8,
            3 => Self::UnsupportedIdentifier,
            4 => Self::UnterminatedComment,
            5 => Self::UnterminatedLiteral,
            6 => Self::UnbalancedDelimiter,
            7 => Self::DepthLimit,
            8 => Self::NameLimit,
            9 => Self::TableBytes,
            _ => return Err(Error::Invalid("omission reason")),
        })
    }
}

/// One authorized current Rust path whose native blob could not be indexed by
/// this bounded parser profile. This never establishes absence of declarations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Omission {
    pub path: Vec<u8>,
    pub blob: GitOid,
    pub source_bytes: usize,
    pub reason: OmissionReason,
    pub byte_offset: Option<usize>,
    pub limit: Option<usize>,
}
impl Omission {
    pub fn validate(&self, format: Format) -> Result<(), Error> {
        if !self.path.ends_with(b".rs")
            || TreePath::parse_default(&self.path).is_err()
            || self.blob.is_zero()
            || self.blob.algorithm() != format
            || self.source_bytes == 0
            || self.source_bytes > 64 * 1024 * 1024
        {
            return Err(Error::Invalid("omission source"));
        }
        let valid = match self.reason {
            OmissionReason::FileBytes => {
                self.byte_offset.is_none()
                    && self.limit.is_some_and(|limit| {
                        (1..=engine::MAX_FILE_BYTES).contains(&limit) && self.source_bytes > limit
                    })
            }
            OmissionReason::TableBytes => {
                self.byte_offset.is_none()
                    && self.limit == Some(MAX_PAYLOAD)
                    && self.source_bytes <= engine::MAX_FILE_BYTES
            }
            _ => {
                self.limit.is_none()
                    && self
                        .byte_offset
                        .is_some_and(|offset| offset <= self.source_bytes)
                    && self.source_bytes <= engine::MAX_FILE_BYTES
            }
        };
        if !valid {
            return Err(Error::Invalid("omission diagnostics"));
        }
        Ok(())
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), Error> {
        out.write_bytes("omitted path", &self.path)?;
        out.write_raw(self.blob.as_bytes());
        out.write_scalar(self.source_bytes as u64);
        out.write_scalar(self.reason.tag());
        write_optional(out, self.byte_offset);
        write_optional(out, self.limit);
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>, format: Format) -> Result<Self, Error> {
        let path = input.read_bytes("omitted path")?.to_vec();
        let blob = read_oid(input, format)?;
        let source_bytes = usize::try_from(input.read_scalar::<u64>("omitted source bytes")?)
            .map_err(|_| Error::Limit("omission integer width"))?;
        let reason = OmissionReason::read(input.read_scalar("omission reason")?)?;
        let byte_offset = read_optional(input)?;
        let limit = read_optional(input)?;
        let entry = Self {
            path,
            blob,
            source_bytes,
            reason,
            byte_offset,
            limit,
        };
        entry.validate(format)?;
        Ok(entry)
    }

    /// A scanner error is classified explicitly. Shared work/declaration limits
    /// and cancellation must not become permission to publish a partial corpus.
    pub(super) fn from_table_error(
        path: &[u8],
        blob: GitOid,
        source_bytes: usize,
        error: &table::Error,
    ) -> Option<Self> {
        let (reason, byte_offset, limit) = match error {
            table::Error::Syntax(error) => {
                let reason = match error.kind {
                    engine::ErrorKind::InvalidUtf8 => OmissionReason::InvalidUtf8,
                    engine::ErrorKind::UnsupportedIdentifier => {
                        OmissionReason::UnsupportedIdentifier
                    }
                    engine::ErrorKind::UnterminatedComment => OmissionReason::UnterminatedComment,
                    engine::ErrorKind::UnterminatedLiteral => OmissionReason::UnterminatedLiteral,
                    engine::ErrorKind::UnbalancedDelimiter => OmissionReason::UnbalancedDelimiter,
                    engine::ErrorKind::DepthLimit => OmissionReason::DepthLimit,
                    engine::ErrorKind::NameLimit => OmissionReason::NameLimit,
                    engine::ErrorKind::Cancelled
                    | engine::ErrorKind::WorkLimit
                    | engine::ErrorKind::FileLimit
                    | engine::ErrorKind::DeclarationLimit => return None,
                };
                (reason, Some(error.byte_offset), None)
            }
            table::Error::Limit("table bytes") => {
                (OmissionReason::TableBytes, None, Some(MAX_PAYLOAD))
            }
            _ => return None,
        };
        Some(Self {
            path: path.to_vec(),
            blob,
            source_bytes,
            reason,
            byte_offset,
            limit,
        })
    }
}
fn write_optional(out: &mut Encoder, value: Option<usize>) {
    out.write_scalar(u8::from(value.is_some()));
    if let Some(value) = value {
        out.write_scalar(value as u64);
    }
}
fn read_optional(input: &mut Decoder<'_>) -> Result<Option<usize>, Error> {
    match input.read_scalar::<u8>("omission optional tag")? {
        0 => Ok(None),
        1 => usize::try_from(input.read_scalar::<u64>("omission optional value")?)
            .map(Some)
            .map_err(|_| Error::Limit("omission integer width")),
        _ => Err(Error::Invalid("omission optional tag")),
    }
}
