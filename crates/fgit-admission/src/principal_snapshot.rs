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
use fgit_forge::event::agent_credential::{AgentCredentialId, SponsorKind};
use fgit_types::{
    Digest, DomainTag, PrincipalId, PrincipalSnapshotId, RefusalCode, RepositoryId, SchemaFamily,
};

use super::PrincipalSnapshot;
use crate::AdmissionContext;

/// The bounded authentication fact established by the host before admission.
///
/// This records a transport verifier's result, never a claim in request data.
/// Historical methods do not classify the principal, assert membership, or
/// establish an identity-session expiry/revocation contract. The agent variant
/// retains only its explicitly verified grant and run witness. An
/// operator-supplied principal earns no credential-strength claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionAuthentication {
    OperatorAssertion,
    HttpToken,
    SshDeployKey,
    /// A host-verified canonical grant and the real request-scoped IntentRun.
    /// This records provenance; it does not itself authorize any effect.
    AgentCredential(AgentAuthentication),
}

impl AdmissionAuthentication {
    /// Stable provenance tag. Agent credentials require their complete newer
    /// witness and can never be decoded from this tag alone.
    #[must_use]
    pub const fn code_point(self) -> u64 {
        match self {
            Self::OperatorAssertion => 1,
            Self::HttpToken => 2,
            Self::SshDeployKey => 3,
            Self::AgentCredential(_) => 4,
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
            Self::HttpToken | Self::SshDeployKey | Self::AgentCredential(_) => {
                fgit_policy::AuthenticationStrength::SingleFactor
            }
        }
    }

    #[must_use]
    pub const fn agent_provenance(&self) -> Option<&AgentAuthentication> {
        match self {
            Self::AgentCredential(agent) => Some(agent),
            _ => None,
        }
    }
}

/// Immutable provenance supplied only after the host verifies a canonical
/// sponsored credential and creates a real, attenuated request-scoped run.
/// The source grant must still be checked against each publication basis.
/// Neither construction nor decoding authenticates a credential or grants a
/// process, code-write, review, merge, or administration capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentAuthentication {
    agent: PrincipalId,
    sponsor: PrincipalId,
    sponsor_kind: SponsorKind,
    credential_id: AgentCredentialId,
    grant_root: Digest,
    run_commitment: [u8; 32],
    authenticated_at: u64,
    expires_at: u64,
}

impl AgentAuthentication {
    pub fn try_new(
        agent: PrincipalId,
        sponsor: PrincipalId,
        sponsor_kind: SponsorKind,
        credential_id: AgentCredentialId,
        grant_root: Digest,
        run_commitment: [u8; 32],
        authenticated_at: u64,
        expires_at: u64,
    ) -> Result<Self, RefusalCode> {
        let value = Self {
            agent,
            sponsor,
            sponsor_kind,
            credential_id,
            grant_root,
            run_commitment,
            authenticated_at,
            expires_at,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), RefusalCode> {
        if self.agent.as_bytes() == &[0; 16]
            || self.sponsor.as_bytes() == &[0; 16]
            || self.agent == self.sponsor
            || self.run_commitment == [0; 32]
            || self
                .grant_root
                .bytes()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.authenticated_at == 0
            || self.authenticated_at >= self.expires_at
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        Ok(())
    }

    #[must_use]
    pub const fn agent(&self) -> PrincipalId {
        self.agent
    }
    #[must_use]
    pub const fn sponsor(&self) -> PrincipalId {
        self.sponsor
    }
    #[must_use]
    pub const fn sponsor_kind(&self) -> SponsorKind {
        self.sponsor_kind
    }
    #[must_use]
    pub const fn credential_id(&self) -> AgentCredentialId {
        self.credential_id
    }
    #[must_use]
    pub const fn grant_root(&self) -> Digest {
        self.grant_root
    }
    #[must_use]
    pub const fn run_commitment(&self) -> &[u8; 32] {
        &self.run_commitment
    }
    #[must_use]
    pub const fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(crate) fn write_fields(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()
            .map_err(|_| invalid_agent("agent_authentication.fields"))?;
        out.write_opaque_id(self.agent.as_bytes());
        out.write_opaque_id(self.sponsor.as_bytes());
        out.write_scalar(self.sponsor_kind.code_point());
        out.write_bytes(
            "agent_authentication.credential",
            self.credential_id.as_bytes(),
        )?;
        out.write_digest(&self.grant_root)?;
        out.write_bytes("agent_authentication.run", &self.run_commitment)?;
        out.write_scalar(self.authenticated_at);
        out.write_scalar(self.expires_at);
        Ok(())
    }

    pub(crate) fn read_fields(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let agent = PrincipalId::from_bytes(input.read_opaque_id("agent_authentication.agent")?);
        let sponsor =
            PrincipalId::from_bytes(input.read_opaque_id("agent_authentication.sponsor")?);
        let sponsor_kind =
            SponsorKind::from_code_point(input.read_scalar("agent_authentication.sponsor_kind")?)
                .ok_or_else(|| invalid_agent("agent_authentication.sponsor_kind"))?;
        let credential = input
            .read_bytes("agent_authentication.credential")?
            .try_into()
            .map_err(|_| invalid_agent("agent_authentication.credential"))?;
        let credential_id = AgentCredentialId::try_new(credential)
            .ok_or_else(|| invalid_agent("agent_authentication.credential"))?;
        let grant_root = input.read_digest()?;
        let run_commitment = input
            .read_bytes("agent_authentication.run")?
            .try_into()
            .map_err(|_| invalid_agent("agent_authentication.run"))?;
        let authenticated_at = input.read_scalar("agent_authentication.authenticated_at")?;
        let expires_at = input.read_scalar("agent_authentication.expires_at")?;
        Self::try_new(
            agent,
            sponsor,
            sponsor_kind,
            credential_id,
            grant_root,
            run_commitment,
            authenticated_at,
            expires_at,
        )
        .map_err(|_| invalid_agent("agent_authentication.fields"))
    }
}

const fn invalid_agent(field: &'static str) -> CodecRefusal {
    CodecRefusal::VariantUnknown {
        field,
        observed: 0,
        offset: 0,
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
        if matches!(
            self.authentication,
            AdmissionAuthentication::AgentCredential(_)
        ) {
            return Err(invalid_agent("principal_snapshot.authentication_version"));
        }
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

/// Schema 1.2 retains the entire canonical grant/run witness. A bare schema
/// 1.1 authentication tag cannot represent this evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentPrincipalSnapshot {
    identity: PrincipalSnapshot,
    agent: AgentAuthentication,
}

impl CanonicalBody for AgentPrincipalSnapshot {
    const DOMAIN: DomainTag = PrincipalSnapshot::DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = PrincipalSnapshot::SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 2;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        if self.identity.principal_id != self.agent.agent() {
            return Err(invalid_agent("principal_snapshot.agent"));
        }
        self.identity.write_payload(out)?;
        self.agent.write_fields(out)
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let identity = PrincipalSnapshot::read_payload(input)?;
        let agent = AgentAuthentication::read_fields(input)?;
        if identity.principal_id != agent.agent() {
            return Err(invalid_agent("principal_snapshot.agent"));
        }
        Ok(Self { identity, agent })
    }
}

/// A principal snapshot with the exact factual profile its bytes declared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalSnapshotRecord {
    Legacy(PrincipalSnapshot),
    Authenticated(AuthenticatedPrincipalSnapshot),
    Agent(AgentPrincipalSnapshot),
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
            Some(AdmissionAuthentication::AgentCredential(agent)) => {
                Self::Agent(AgentPrincipalSnapshot { identity, agent })
            }
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
            Self::Agent(snapshot) => &snapshot.identity,
        }
    }

    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.identity().repository_id()
    }

    #[must_use]
    pub const fn principal_id(&self) -> PrincipalId {
        self.identity().principal_id
    }

    #[must_use]
    pub const fn agent_provenance(&self) -> Option<&AgentAuthentication> {
        match self {
            Self::Agent(snapshot) => Some(&snapshot.agent),
            _ => None,
        }
    }

    /// None is a historical identity-only record, not a known weak credential.
    #[must_use]
    pub const fn authentication(&self) -> Option<AdmissionAuthentication> {
        match self {
            Self::Legacy(_) => None,
            Self::Authenticated(snapshot) => Some(snapshot.authentication),
            Self::Agent(snapshot) => Some(AdmissionAuthentication::AgentCredential(snapshot.agent)),
        }
    }

    pub fn id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        self.snapshot_id()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecRefusal> {
        match self {
            Self::Legacy(snapshot) => encode_body(snapshot),
            Self::Authenticated(snapshot) => encode_body(snapshot),
            Self::Agent(snapshot) => encode_body(snapshot),
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
            2 => Self::Agent(decode_body::<AgentPrincipalSnapshot>(bytes, limits)?),
            minor => {
                return Err(CodecRefusal::schema_minor_unsupported(
                    PrincipalSnapshot::DOMAIN,
                    minor,
                    2,
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

    /// Verify this original immutable receipt against its original admission
    /// coordinates. This never re-authenticates a current transport or grant.
    pub fn verify_context(
        &self,
        context: &AdmissionContext,
        basis: &PublicationBasis,
    ) -> Result<(), RefusalCode> {
        if context.repository_id != basis.body().repository_id
            || *self.identity() != PrincipalSnapshot::from_context(context, basis)
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        if let Some(agent) = self.agent_provenance() {
            agent.validate()?;
            if agent.agent() != context.principal_id {
                return Err(RefusalCode::EvidenceInvalid);
            }
        }
        Ok(())
    }
}

mod sealed {
    pub trait PrincipalSnapshotIdentity {}
    impl PrincipalSnapshotIdentity for super::PrincipalSnapshot {}
    impl PrincipalSnapshotIdentity for super::AuthenticatedPrincipalSnapshot {}
    impl PrincipalSnapshotIdentity for super::AgentPrincipalSnapshot {}
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

impl PrincipalSnapshotIdentity for AgentPrincipalSnapshot {
    fn snapshot_id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        body_snapshot_id(self)
    }
}

impl PrincipalSnapshotIdentity for PrincipalSnapshotRecord {
    fn snapshot_id(&self) -> Result<PrincipalSnapshotId, RefusalCode> {
        match self {
            Self::Legacy(snapshot) => snapshot.snapshot_id(),
            Self::Authenticated(snapshot) => snapshot.snapshot_id(),
            Self::Agent(snapshot) => snapshot.snapshot_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::tests::fixture;

    fn agent(context: &AdmissionContext) -> AgentAuthentication {
        AgentAuthentication::try_new(
            context.principal_id,
            PrincipalId::from_bytes([0x44; 16]),
            SponsorKind::Human,
            AgentCredentialId::try_new([0x55; 32]).unwrap(),
            fgit_codec::harness::digest_of(7),
            [0x66; 32],
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn historical_principal_frames_match_frozen_schema_zero_and_one_bytes() {
        // Independent fixtures fix both historical frame versions, including
        // the reserved corpus digest algorithm. New witness fields cannot
        // silently enter historical bytes or infer an agent/sponsor kind.
        const LEGACY: &str = "4647433100010000000000206672616e6b656e6769742f7072696e636970616c2d736e617073686f742f7631000000127072696e636970616c2d736e617073686f740001000000000056111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333fff1000000200606060606060606060606060606060606060606060606060606060606060606";
        const TOKEN: &str = "4647433100010000000000206672616e6b656e6769742f7072696e636970616c2d736e617073686f742f7631000000127072696e636970616c2d736e617073686f74000100010000005e111111111111111111111111111111112222222222222222222222222222222233333333333333333333333333333333fff10000002006060606060606060606060606060606060606060606060606060606060606060000000000000002";
        let (context, basis, _, _) = fixture();
        for (golden, authentication) in [
            (LEGACY, None),
            (TOKEN, Some(AdmissionAuthentication::HttpToken)),
        ] {
            let bytes: Vec<u8> = (0..golden.len())
                .step_by(2)
                .map(|offset| u8::from_str_radix(&golden[offset..offset + 2], 16).unwrap())
                .collect();
            let expected = PrincipalSnapshotRecord::from_context(&context, &basis, authentication);
            let decoded = PrincipalSnapshotRecord::decode(&bytes, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(expected.encode().unwrap(), bytes);
            assert_eq!(decoded.authentication(), authentication);
            assert_eq!(decoded.agent_provenance(), None);
            assert_eq!(decoded.principal_id(), context.principal_id);
        }
    }

    #[test]
    fn agent_snapshot_preserves_complete_witness_and_changes_identity_for_each_fact() {
        let (context, basis, _, _) = fixture();
        let original = agent(&context);
        let original_record = PrincipalSnapshotRecord::from_context(
            &context,
            &basis,
            Some(AdmissionAuthentication::AgentCredential(original)),
        );
        let mut variants = vec![original];
        let mut changed = original;
        changed.sponsor = PrincipalId::from_bytes([0x45; 16]);
        variants.push(changed);
        changed = original;
        changed.sponsor_kind = SponsorKind::Service;
        variants.push(changed);
        changed = original;
        changed.credential_id = AgentCredentialId::try_new([0x56; 32]).unwrap();
        variants.push(changed);
        changed = original;
        changed.grant_root = fgit_codec::harness::digest_of(8);
        variants.push(changed);
        changed = original;
        changed.run_commitment = [0x67; 32];
        variants.push(changed);
        changed = original;
        changed.authenticated_at = 101;
        variants.push(changed);
        changed = original;
        changed.expires_at = 201;
        variants.push(changed);
        let mut roots = Vec::new();
        for witness in variants {
            let authentication = AdmissionAuthentication::AgentCredential(witness);
            let record =
                PrincipalSnapshotRecord::from_context(&context, &basis, Some(authentication));
            record.verify_context(&context, &basis).unwrap();
            let bytes = record.encode().unwrap();
            assert_eq!(
                read_frame_header(&bytes, DecodeLimits::DEFAULT)
                    .unwrap()
                    .0
                    .schema
                    .minor(),
                2
            );
            let decoded = PrincipalSnapshotRecord::decode(&bytes, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, record);
            assert_eq!(decoded.encode().unwrap(), bytes);
            assert_eq!(decoded.principal_id(), context.principal_id);
            assert_eq!(decoded.agent_provenance(), Some(&witness));
            assert_eq!(decoded.authentication(), Some(authentication));
            assert_eq!(
                authentication.authentication_strength(),
                fgit_policy::AuthenticationStrength::SingleFactor
            );
            assert!(!roots.contains(&record.id().unwrap()));
            roots.push(record.id().unwrap());
        }
        let token = PrincipalSnapshotRecord::from_context(
            &context,
            &basis,
            Some(AdmissionAuthentication::HttpToken),
        );
        assert_ne!(original_record.id().unwrap(), token.id().unwrap());
        let old_schema = AuthenticatedPrincipalSnapshot {
            identity: PrincipalSnapshot::from_context(&context, &basis),
            authentication: AdmissionAuthentication::AgentCredential(original),
        };
        assert!(
            encode_body(&old_schema).is_err(),
            "schema 1.1 cannot encode a rich credential"
        );
        assert!(AdmissionAuthentication::from_code_point(4).is_err());
    }

    #[test]
    fn agent_snapshot_refuses_mismatched_identity_corrupt_witness_and_downgrade() {
        let (context, basis, request, fold) = fixture();
        let original = agent(&context);
        let mut other_agent = original;
        other_agent.agent = PrincipalId::from_bytes([0x77; 16]);
        assert_eq!(
            crate::evidence::DecisionEvidenceBodies::derive_with_authentication(
                &context,
                &basis,
                &request,
                &fold,
                AdmissionAuthentication::AgentCredential(other_agent),
            )
            .unwrap_err(),
            RefusalCode::EvidenceInvalid
        );

        let record = PrincipalSnapshotRecord::from_context(
            &context,
            &basis,
            Some(AdmissionAuthentication::AgentCredential(original)),
        );
        let frame = record.encode().unwrap();
        let (_, decoder) = read_frame_header(&frame, DecodeLimits::DEFAULT).unwrap();
        let payload = decoder.offset() + 4;
        let identity_len = fgit_codec::canonical_body_bytes(record.identity())
            .unwrap()
            .len();
        let witness = payload + identity_len;
        // This fixed schema's offsets are deliberately independent of the
        // decoder. Every malformed witness must fail before receipt replay.
        for (offset, length) in [
            (witness, 16),       // absent agent
            (witness + 16, 16),  // absent sponsor
            (witness + 32, 4),   // unknown sponsor kind
            (witness + 40, 32),  // zero credential commitment
            (witness + 78, 32),  // zero grant root
            (witness + 114, 32), // zero run commitment
            (witness + 146, 8),  // zero authentication time
            (witness + 154, 8),  // expired before authentication
        ] {
            let mut corrupt = frame.clone();
            corrupt[offset..offset + length].fill(0);
            assert!(PrincipalSnapshotRecord::decode(&corrupt, DecodeLimits::DEFAULT).is_err());
        }
        let mut mismatched = frame.clone();
        mismatched[witness..witness + 16].fill(0x77);
        assert!(PrincipalSnapshotRecord::decode(&mismatched, DecodeLimits::DEFAULT).is_err());
        let mut self_sponsor = frame.clone();
        self_sponsor[witness + 16..witness + 32].fill(0x33);
        assert!(PrincipalSnapshotRecord::decode(&self_sponsor, DecodeLimits::DEFAULT).is_err());
        // Changing only a frame's version cannot erase provenance.
        for minor in [0_u16, 1, 3] {
            let mut relabelled = frame.clone();
            relabelled[payload - 6..payload - 4].copy_from_slice(&minor.to_be_bytes());
            assert!(PrincipalSnapshotRecord::decode(&relabelled, DecodeLimits::DEFAULT).is_err());
        }
        for end in 0..frame.len() {
            assert!(PrincipalSnapshotRecord::decode(&frame[..end], DecodeLimits::DEFAULT).is_err());
        }
        let mut trailing = frame;
        trailing.push(0);
        assert!(PrincipalSnapshotRecord::decode(&trailing, DecodeLimits::DEFAULT).is_err());
    }

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
            const SCHEMA_MINOR: u16 = 3;
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
