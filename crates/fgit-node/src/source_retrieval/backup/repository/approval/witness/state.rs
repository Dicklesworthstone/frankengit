//! The existing JavaScript witness wire, with independently supplied trust.
//! Original signed envelopes remain evidence; this file never supplies a key.

use super::super::{
    AuthenticatedApprovalObservation, Identity, MAX_ENVELOPE_BYTES, Policy, Value, base64, decimal,
    exact_object, object_format, parse_json, string_field, unhex,
};
use super::LoadedApprovalTrust;
use fgit_types::{RepositoryId, RepositoryIncarnationId, TenantId};

pub(super) const MAX_STATE_BYTES: usize = 64 * 1024;
const TYPE: &str = "repository_backup_witness_v1";

pub(super) struct State {
    pub(super) floor: u64,
    pub(super) observations: Vec<AuthenticatedApprovalObservation>,
}

impl State {
    pub(super) fn empty(trust: &LoadedApprovalTrust) -> Self {
        Self {
            floor: trust.policy().minimum_generation,
            observations: Vec::new(),
        }
    }

    pub(super) fn decode(bytes: &[u8], trust: &LoadedApprovalTrust) -> Result<Self, String> {
        let parsed = parse_json(bytes, MAX_STATE_BYTES)?;
        let fields = exact_object(
            &parsed,
            &["type", "policy", "trusted_key_id", "observations"],
        )?;
        if string_field(fields, "type")? != TYPE
            || string_field(fields, "trusted_key_id")? != trust.trusted_key_id()
        {
            return Err("backup witness type or independently trusted key does not match".into());
        }
        let policy = exact_object(
            fields
                .get("policy")
                .ok_or("backup witness lacks its policy")?,
            &[
                "tenant_id",
                "repository_id",
                "incarnation_id",
                "object_format",
                "minimum_head_generation",
            ],
        )?;
        let identity = Identity {
            tenant: TenantId::from_bytes(unhex(string_field(policy, "tenant_id")?)?),
            repository: RepositoryId::from_bytes(unhex(string_field(policy, "repository_id")?)?),
            incarnation: RepositoryIncarnationId::from_bytes(unhex(string_field(
                policy,
                "incarnation_id",
            )?)?),
            format: object_format(string_field(policy, "object_format")?)?,
        };
        if identity != trust.policy().identity {
            return Err("backup witness identity does not match independent policy".into());
        }
        let floor = decimal(string_field(policy, "minimum_head_generation")?, u64::MAX)?;
        if trust.policy().minimum_generation < floor {
            return Err(
                "backup witness refuses a weaker independently retained generation floor".into(),
            );
        }
        let Some(Value::Array(encoded)) = fields.get("observations") else {
            return Err("backup witness observations must be an array".into());
        };
        if encoded.len() > 2 {
            return Err("backup witness permits at most two original signed observations".into());
        }
        let mut observations = Vec::with_capacity(encoded.len());
        for value in encoded {
            let Value::String(encoded) = value else {
                return Err("backup witness observation must be original base64 bytes".into());
            };
            let envelope = base64(encoded, MAX_ENVELOPE_BYTES)?;
            // Inspection intentionally ignores current expiry and a newly
            // stronger floor. Both continue to constrain later eligibility.
            observations.push(trust.inspect_bytes(&envelope)?);
        }
        if observations.len() == 2
            && (observations[0].generation() != observations[1].generation()
                || observations[0].same_statement(&observations[1]))
        {
            return Err(
                "backup witness conflict evidence is not two distinct statements at one generation"
                    .into(),
            );
        }
        let state = Self {
            floor,
            observations,
        };
        if state.encode(trust)? != bytes {
            return Err("backup witness state is not its exact canonical JSON".into());
        }
        Ok(state)
    }

    pub(super) fn encode(&self, trust: &LoadedApprovalTrust) -> Result<Vec<u8>, String> {
        if self.observations.len() > 2 || self.floor == 0 {
            return Err("backup witness state is outside its bounded profile".into());
        }
        let observations = self
            .observations
            .iter()
            .map(|observation| format!("\"{}\"", encode_base64(observation.envelope_bytes())))
            .collect::<Vec<_>>()
            .join(",");
        let bytes = format!(
            "{{\"type\":\"{TYPE}\",\"policy\":{},\"trusted_key_id\":\"{}\",\"observations\":[{}]}}\n",
            policy_json(Policy { minimum_generation: self.floor, ..trust.policy() }),
            trust.trusted_key_id(), observations,
        ).into_bytes();
        if bytes.len() > MAX_STATE_BYTES {
            return Err("backup witness state exceeds 65536 bytes".into());
        }
        Ok(bytes)
    }
}

pub(super) fn policy_json(policy: Policy) -> String {
    format!(
        concat!(
            "{{\"tenant_id\":\"{}\",\"repository_id\":\"{}\",\"incarnation_id\":\"{}\",",
            "\"object_format\":\"{}\",\"minimum_head_generation\":\"{}\"}}"
        ),
        policy.identity.tenant,
        policy.identity.repository,
        policy.identity.incarnation,
        policy.identity.format.as_str(),
        policy.minimum_generation,
    )
}

pub(super) fn encode_base64(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for part in bytes.chunks(3) {
        let bits = u32::from(part[0]) << 16
            | u32::from(part.get(1).copied().unwrap_or(0)) << 8
            | u32::from(part.get(2).copied().unwrap_or(0));
        text.push(char::from(DIGITS[(bits >> 18) as usize]));
        text.push(char::from(DIGITS[((bits >> 12) & 63) as usize]));
        text.push(if part.len() > 1 {
            char::from(DIGITS[((bits >> 6) & 63) as usize])
        } else {
            '='
        });
        text.push(if part.len() > 2 {
            char::from(DIGITS[(bits & 63) as usize])
        } else {
            '='
        });
    }
    text
}
