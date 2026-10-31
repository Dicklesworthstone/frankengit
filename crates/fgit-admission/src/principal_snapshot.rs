//! Exact-version principal evidence for an admitted transaction.
//!
//! Authentication provenance is a receipt over the sealed identity, not part
//! of that identity. Historical snapshots retain their original bytes and do
//! not acquire authentication facts when a newer reader opens them.

use fgit_chronicle::PublicationBasis;
use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder, body_id,
    decode_body, encode_body, read_frame_header,
};
use fgit_types::{DomainTag, PrincipalSnapshotId, RefusalCode, RepositoryId, SchemaFamily};

use super::PrincipalSnapshot;
use crate::AdmissionContext;

/// The bounded authentication fact established by the host before admission.
///
/// This records a transport verifier's result, never a claim in request data.
/// It does not classify the principal, assert membership, or establish the
/// expiry/revocation contract of an identity session. An operator-supplied
/// principal earns no credential-strength claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionAuthentication {
    OperatorAssertion,
    HttpToken,
    SshDeployKey,
}

impl AdmissionAuthentication {
    /// Stable schema-1.1 provenance tag; zero and unknown tags are refused.
    #[must_use]
    pub const fn code_point(self) -> u64 {
        match self {
            Self::OperatorAssertion => 1,
            Self::HttpToken => 2,
            Self::SshDeployKey => 3,
        }
    }

    pub fn from_code_point(observed: u64) -> Result<Self, CodecRefusal> {
        match observed {
            1 => Ok(Self::OperatorAssertion),
            2 => Ok(Self::HttpToken),
            3 => Ok(Self::SshDeployKey),
            _ => Err(match u32::try_from(observed) {
                Ok(observed) => CodecRefusal::VariantUnknown {
                    field: "principal_snapshot.authentication",
                    observed,
                    offset: 0,
                },
                Err(_) => CodecRefusal::ValueUnrepresentable {
                    field: "principal_snapshot.authentication",
                    observed,
                    limit: u64::from(u32::MAX),
                },
            }),
        }
    }

    /// Conservative mapping from a verified method to policy strength.
    /// Neither current transport proves MFA or hardware-backed authentication.
    #[must_use]
    pub const fn authentication_strength(self) -> fgit_policy::AuthenticationStrength {
        match self {
            Self::OperatorAssertion => fgit_policy::AuthenticationStrength::None,
            Self::HttpToken | Self::SshDeployKey => {
                fgit_policy::AuthenticationStrength::SingleFactor
            }
        }
    }
}

/// Schema 1.1 binds a verified authentication method to the same principal and
/// configuration coordinates as schema 1.0. It contains no credential secret.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipalSnapshot {
    identity: PrincipalSnapshot,
    authentication: AdmissionAuthentication,
}

impl CanonicalBody for AuthenticatedPrincipalSnapshot {
    const DOMAIN: DomainTag = PrincipalSnapshot::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PrincipalSnapshot::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 1;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.identity.write_payload(out)?;
        out.write_scalar(self.authentication.code_point());
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self {
            identity: PrincipalSnapshot::read_payload(input)?,
            authentication: AdmissionAuthentication::from_code_point(
                input.read_scalar("principal_snapshot.authentication")?,
            )?,
        })
    }
}

/// A principal snapshot with the exact factual profile its bytes declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalSnapshotRecord {
    Legacy(PrincipalSnapshot),
    Authenticated(AuthenticatedPrincipalSnapshot),
}

impl From<PrincipalSnapshot> for PrincipalSnapshotRecord {
    fn from(snapshot: PrincipalSnapshot) -> Self {
        Self::Legacy(snapshot)
    }
}

impl PrincipalSnapshotRecord {
    pub(super) const fn from_context(
        context: &AdmissionContext,
        basis: &PublicationBasis,
        authentication: Option<AdmissionAuthentication>,
    ) -> Self {
        let identity = PrincipalSnapshot::from_context(context, basis);
        match authentication {
            Some(authentication) => Self::Authenticated(AuthenticatedPrincipalSnapshot {
                identity,
                authentication,
            }),
            None => Self::Legacy(identity),
        }
    }

    const fn identity(&self) -> &PrincipalSnapshot {
        match self {
            Self::Legacy(snapshot) => snapshot,
            Self::Authenticated(snapshot) => &snapshot.identity,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.identity().repository_id()
    }

    /// None is a historical identity-only record, not a known weak credential.
    #[must_use]
    pub const fn authentication(&self) -> Option<AdmissionAuthentication> {
        match self {
            Self::Legacy(_) => None,
            Self::Authenticated(snapshot) => Some(snapshot.authentication),
        }
    }

    pub fn id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        self.snapshot_id()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecRefusal> {
        match self {
            Self::Legacy(snapshot) => encode_body(snapshot),
            Self::Authenticated(snapshot) => encode_body(snapshot),
        }
    }

    /// Decode only a declared supported schema and retain its exact bytes.
    pub fn decode(bytes: &[u8], limits: DecodeLimits) -> Result<Self, CodecRefusal> {
        let (header, _) = read_frame_header(bytes, limits)?;
        if header.domain != PrincipalSnapshot::DOMAIN {
            return Err(CodecRefusal::domain_unexpected(
                PrincipalSnapshot::DOMAIN,
                header.domain,
            ));
        }
        let value = match header.schema.minor() {
            0 => Self::Legacy(decode_body::<PrincipalSnapshot>(bytes, limits)?),
            1 => Self::Authenticated(decode_body::<AuthenticatedPrincipalSnapshot>(
                bytes, limits,
            )?),
            minor => {
                return Err(CodecRefusal::schema_minor_unsupported(
                    PrincipalSnapshot::DOMAIN,
                    minor,
                    1,
                ));
            }
        };
        if value.encode()? != bytes {
            return Err(CodecRefusal::VariantUnknown {
                field: "principal_snapshot.noncanonical",
                observed: 0,
                offset: 0,
            });
        }
        Ok(value)
    }

    pub(super) fn verify_context(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
    ) -> Result<(), RefusalCode> {
        if context.repository_id != basis.body().repository_id
            || *self.identity() != PrincipalSnapshot::from_context(context, basis)
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }
}

mod sealed {
    pub trait PrincipalSnapshotIdentity {}
    impl PrincipalSnapshotIdentity for super::PrincipalSnapshot {}
    impl PrincipalSnapshotIdentity for super::AuthenticatedPrincipalSnapshot {}
    impl PrincipalSnapshotIdentity for super::PrincipalSnapshotRecord {}
}

/// Canonical identity shared by legacy bodies and exact-version records.
/// The sealed implementations prevent callers substituting an unproved root.
pub trait PrincipalSnapshotIdentity: sealed::PrincipalSnapshotIdentity {
    fn snapshot_id(&self) -> Result<PrincipalSnapshotId, RefusalCode>;
}

fn body_snapshot_id<Body: CanonicalBody>(body: &Body) -> Result<PrincipalSnapshotId, RefusalCode> {
    let id =
        body_id(&CryptoBodyIdentity, body).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
    PrincipalSnapshotId::from_internal_object_id(id)
        .map_err(|_| RefusalCode::CanonicalFramingInvalid)
}

impl PrincipalSnapshotIdentity for PrincipalSnapshot {
    fn snapshot_id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        body_snapshot_id(self)
    }
}

impl PrincipalSnapshotIdentity for AuthenticatedPrincipalSnapshot {
    fn snapshot_id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        body_snapshot_id(self)
    }
}

impl PrincipalSnapshotIdentity for PrincipalSnapshotRecord {
    fn snapshot_id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        match self {
            Self::Legacy(snapshot) => snapshot.snapshot_id(),
            Self::Authenticated(snapshot) => snapshot.snapshot_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::tests::fixture;

    #[test]
    fn legacy_bytes_and_identity_are_preserved_without_authentication_inference() {
        let (context, basis, _, _) = fixture();
        let legacy = PrincipalSnapshot::from_context(&context, &basis);
        let bytes = encode_body(&legacy).unwrap();
        let record = PrincipalSnapshotRecord::decode(&bytes, DecodeLimits::DEFAULT).unwrap();
        assert_eq!(record, PrincipalSnapshotRecord::Legacy(legacy.clone()));
        assert_eq!(record.encode().unwrap(), bytes);
        assert_eq!(record.id().unwrap(), body_snapshot_id(&legacy).unwrap());
        assert_eq!(record.authentication(), None);
        assert_eq!(
            read_frame_header(&bytes, DecodeLimits::DEFAULT)
                .unwrap()
                .0
                .schema
                .minor(),
            0
        );
    }

    #[test]
    fn authentication_receipts_are_canonical_distinct_and_conservative() {
        let (context, basis, _, _) = fixture();
        let legacy = PrincipalSnapshotRecord::from_context(&context, &basis, None);
        let mut ids = vec![legacy.id().unwrap()];
        for authentication in [
            AdmissionAuthentication::OperatorAssertion,
            AdmissionAuthentication::HttpToken,
            AdmissionAuthentication::SshDeployKey,
        ] {
            let record =
                PrincipalSnapshotRecord::from_context(&context, &basis, Some(authentication));
            let bytes = record.encode().unwrap();
            assert_eq!(
                PrincipalSnapshotRecord::decode(&bytes, DecodeLimits::DEFAULT).unwrap(),
                record
            );
            assert_eq!(record.authentication(), Some(authentication));
            assert_eq!(
                read_frame_header(&bytes, DecodeLimits::DEFAULT)
                    .unwrap()
                    .0
                    .schema
                    .minor(),
                1
            );
            assert!(!ids.contains(&record.id().unwrap()));
            ids.push(record.id().unwrap());
            record.verify_context(&context, &basis).unwrap();
        }
        assert_eq!(
            AdmissionAuthentication::OperatorAssertion.authentication_strength(),
            fgit_policy::AuthenticationStrength::None
        );
        assert_eq!(
            AdmissionAuthentication::HttpToken.authentication_strength(),
            fgit_policy::AuthenticationStrength::SingleFactor
        );
        assert_eq!(
            AdmissionAuthentication::SshDeployKey.authentication_strength(),
            fgit_policy::AuthenticationStrength::SingleFactor
        );
    }

    #[test]
    fn unknown_authentication_and_snapshot_versions_refuse() {
        for tag in [0, 4, u64::MAX] {
            assert!(AdmissionAuthentication::from_code_point(tag).is_err());
        }
        struct UnknownVersion(PrincipalSnapshot);
        impl CanonicalBody for UnknownVersion {
            const DOMAIN: DomainTag = PrincipalSnapshot::DOMAIN;
            const SCHEMA_FAMILY: SchemaFamily = PrincipalSnapshot::SCHEMA_FAMILY;
            const SCHEMA_MAJOR: u16 = 1;
            const SCHEMA_MINOR: u16 = 2;
            fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
                self.0.write_payload(out)
            }
            fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
                PrincipalSnapshot::read_payload(input).map(Self)
            }
        }
        struct UnknownAuthentication(PrincipalSnapshot);
        impl CanonicalBody for UnknownAuthentication {
            const DOMAIN: DomainTag = PrincipalSnapshot::DOMAIN;
            const SCHEMA_FAMILY: SchemaFamily = PrincipalSnapshot::SCHEMA_FAMILY;
            const SCHEMA_MAJOR: u16 = 1;
            const SCHEMA_MINOR: u16 = 1;
            fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
                self.0.write_payload(out)?;
                out.write_scalar(4_u64);
                Ok(())
            }
            fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
                PrincipalSnapshot::read_payload(input).map(Self)
            }
        }
        let (context, basis, _, _) = fixture();
        let legacy = PrincipalSnapshot::from_context(&context, &basis);
        assert!(
            PrincipalSnapshotRecord::decode(
                &encode_body(&UnknownVersion(legacy.clone())).unwrap(),
                DecodeLimits::DEFAULT
            )
            .is_err()
        );
        assert!(
            PrincipalSnapshotRecord::decode(
                &encode_body(&UnknownAuthentication(legacy)).unwrap(),
                DecodeLimits::DEFAULT
            )
            .is_err()
        );
        let record = PrincipalSnapshotRecord::from_context(
            &context,
            &basis,
            Some(AdmissionAuthentication::HttpToken),
        );
        let bytes = record.encode().unwrap();
        for end in 0..bytes.len() {
            assert!(PrincipalSnapshotRecord::decode(&bytes[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(PrincipalSnapshotRecord::decode(&trailing, DecodeLimits::DEFAULT).is_err());
    }
}
