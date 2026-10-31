//! Bounded cryptographic observations for checkpoint selection. An authentic
//! newer checkpoint remains evidence even if it cannot be used by this attempt.
//! Only explicit eligibility conversion produces a native recovery approval.

use super::*;

/// The independent trust inputs shared by every supplied candidate. There is
/// intentionally no approval pathname: the selector supplies each candidate.
#[derive(Debug, Default)]
pub(in super::super) struct SelectionTrustFlags {
    fields: ApprovalFlags,
}

impl SelectionTrustFlags {
    pub(in super::super) fn accepts(flag: &str) -> bool {
        flag != "--approval" && ApprovalFlags::accepts(flag)
    }

    pub(in super::super) fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        if !Self::accepts(flag) {
            return Err("unknown backup selection trust option".into());
        }
        self.fields.set(flag, value)
    }

    pub(in super::super) fn finish(self) -> Result<SelectionTrustOptions, String> {
        let missing = || {
            "backup selection requires --trust-key, --tenant-id, --repository-id, --incarnation-id, --object-format and --minimum-head-generation".to_owned()
        };
        let fields = self.fields;
        Ok(SelectionTrustOptions {
            trust_key: fields.trust_key.ok_or_else(missing)?,
            policy: Policy {
                identity: Identity {
                    tenant: fields.tenant.ok_or_else(missing)?,
                    repository: fields.repository.ok_or_else(missing)?,
                    incarnation: fields.incarnation.ok_or_else(missing)?,
                    format: fields.format.ok_or_else(missing)?,
                },
                minimum_generation: fields.minimum_generation.ok_or_else(missing)?,
            },
            #[cfg(test)]
            clock: None,
        })
    }
}

#[derive(Debug)]
pub(in super::super) struct SelectionTrustOptions {
    trust_key: PathBuf,
    policy: Policy,
    #[cfg(test)]
    clock: Option<Arc<AtomicI64>>,
}

impl SelectionTrustOptions {
    pub(in super::super) fn trust_key_path(&self) -> &Path {
        &self.trust_key
    }

    /// Load the independently supplied key exactly once. All observations and
    /// the eventual approval retain this same policy and original deadline.
    pub(in super::super) fn load(&self, deadline: Deadline) -> Result<LoadedApprovalTrust, String> {
        let pem = read_control(&self.trust_key, MAX_KEY_BYTES, deadline)?;
        let (key, der) = public_key(&pem)?;
        deadline.check()?;
        Ok(LoadedApprovalTrust {
            key,
            der,
            trusted_key_id: format!("sha256:{}", hex(&sha256(&der))),
            policy: self.policy,
            deadline,
            #[cfg(test)]
            clock: self.clock.clone(),
        })
    }

    #[cfg(test)]
    pub(in super::super) fn set_test_clock(&mut self, clock: Arc<AtomicI64>) {
        self.clock = Some(clock);
    }
}

/// This owns the external trust snapshot, not candidate-selected trust. It has
/// no archive path, no payload I/O capability, and no authority publication API.
#[derive(Debug)]
pub(in super::super) struct LoadedApprovalTrust {
    key: VerifyingKey,
    der: [u8; 44],
    trusted_key_id: String,
    policy: Policy,
    deadline: Deadline,
    #[cfg(test)]
    clock: Option<Arc<AtomicI64>>,
}

impl LoadedApprovalTrust {
    #[cfg(unix)]
    pub(super) fn policy(&self) -> Policy {
        self.policy
    }

    #[cfg(unix)]
    pub(super) fn trusted_key_id(&self) -> &str {
        &self.trusted_key_id
    }

    pub(super) fn check_deadline(&self) -> Result<(), String> {
        self.deadline.check()
    }

    /// A typed observation can carry newly learned recovery obligations even
    /// after its deadline expires. Establish trust without an eligibility or
    /// clock check so the witness poisons ownership before attempting to retain
    /// that knowledge. The independent floor constrains selection separately.
    #[cfg(unix)]
    pub(super) fn matches_observation(
        &self,
        observation: &AuthenticatedApprovalObservation,
    ) -> bool {
        self.policy.identity == observation.policy.identity
            && self.der == observation.der
            && self.trusted_key_id == observation.trusted_key_id
    }

    pub(in super::super) fn inspect_path(
        &self,
        path: &Path,
    ) -> Result<AuthenticatedApprovalObservation, String> {
        let encoded = read_control(path, MAX_ENVELOPE_BYTES, self.deadline)?;
        self.inspect_bytes(&encoded)
    }

    /// The fixed signed-size ceiling bounds all observations, while the
    /// caller's narrower transfer budget, floor and live clock gate only use.
    pub(in super::super) fn inspect_bytes(
        &self,
        encoded: &[u8],
    ) -> Result<AuthenticatedApprovalObservation, String> {
        self.deadline.check()?;
        if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_BYTES {
            return Err("backup approval JSON byte limit".into());
        }
        // Capture bounded original bytes before authentication can establish a
        // recovery obligation. A later allocation refusal must not hide known
        // higher or conflicting evidence from a live witness guard.
        let mut envelope = Vec::new();
        envelope
            .try_reserve_exact(encoded.len())
            .map_err(|_| "backup approval observation allocation refused")?;
        envelope.extend_from_slice(encoded);
        let (statement, _) = authenticated_statement(
            &envelope,
            &self.key,
            &self.trusted_key_id,
            self.policy.identity,
            MAX_SIGNED_ARCHIVE_BYTES,
            self.deadline,
        )?;
        Ok(self.completed_observation(envelope, statement))
    }

    /// Cryptographic, canonical and namespace inspection has completed. This
    /// handoff is deliberately infallible: the witness must receive the typed
    /// observation before any subsequent deadline or eligibility refusal.
    fn completed_observation(
        &self,
        envelope: Vec<u8>,
        statement: Statement,
    ) -> AuthenticatedApprovalObservation {
        AuthenticatedApprovalObservation {
            envelope,
            // Statement::parse already compared these exact canonical bytes
            // with the signed payload. No new UTF-8 validation can fail here.
            canonical: statement.canonical(),
            statement,
            der: self.der,
            trusted_key_id: self.trusted_key_id.clone(),
            policy: self.policy,
            deadline: self.deadline,
            #[cfg(test)]
            clock: self.clock.clone(),
        }
    }
}

/// Signature, original canonical statement and independent identity verified;
/// neither current eligibility nor native archive contents have been verified.
#[derive(Debug)]
pub(in super::super) struct AuthenticatedApprovalObservation {
    envelope: Vec<u8>,
    canonical: String,
    statement: Statement,
    der: [u8; 44],
    trusted_key_id: String,
    policy: Policy,
    deadline: Deadline,
    #[cfg(test)]
    clock: Option<Arc<AtomicI64>>,
}

impl AuthenticatedApprovalObservation {
    pub(in super::super) fn generation(&self) -> u64 {
        self.statement.generation
    }

    pub(in super::super) fn artifact_seal(&self) -> Seal {
        Seal {
            digest: self.statement.digest,
            bytes: self.statement.archive_bytes,
        }
    }

    pub(in super::super) fn same_statement(&self, other: &Self) -> bool {
        self.statement_json() == other.statement_json()
    }

    pub(in super::super) fn approval_digest(&self) -> [u8; 32] {
        sha256(self.envelope_bytes())
    }

    pub(in super::super) fn statement_digest(&self) -> [u8; 32] {
        sha256(self.statement_json().as_bytes())
    }

    pub(in super::super) fn trusted_key_id(&self) -> &str {
        &self.trusted_key_id
    }

    pub(in super::super) fn envelope_bytes(&self) -> &[u8] {
        &self.envelope
    }

    pub(in super::super) fn statement_json(&self) -> &str {
        &self.canonical
    }

    /// Transfer this exact observation into the existing native recovery
    /// boundary. No envelope/key is reopened, and no new deadline is started.
    pub(in super::super) fn into_verified(
        self,
        expected: [u8; 32],
        maximum_archive_bytes: u64,
    ) -> Result<VerifiedApproval, String> {
        let verified = VerifiedApproval {
            binding: binding(&self.envelope, &self.der, self.policy),
            statement: self.statement,
            trusted_key_id: self.trusted_key_id,
            policy: self.policy,
            deadline: self.deadline,
            #[cfg(test)]
            clock: self.clock,
        };
        verified.check_selected(expected, maximum_archive_bytes)?;
        Ok(verified)
    }
}

#[cfg(test)]
mod tests;
