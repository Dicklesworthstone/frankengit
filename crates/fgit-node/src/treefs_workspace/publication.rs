//! Explicit local-operator publication of a reviewed workspace candidate.
//!
//! A bundle is untrusted transport, never authority. The caller independently
//! names the branch, expected old commit and reviewed new commit. This adapter
//! binds the envelope to those expectations, then uses the production receive
//! quarantine and basis-bound admission path. It does not run the tool again.

use super::{NodeWorkspaceRefusal, workspace_request_live};
use crate::quarantine_validator::ProductionReceiveQuarantineHandoff;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode};
use fgit_admission::{AdmissionLimits, AdmissionResult};
use fgit_authority::IdempotencyKey;
use fgit_git_object::{AcceptanceProfile, ObjectType, ParseLimits, ParsedObject, parse_object_body};
use fgit_object_fabric::ObjectKind;
use fgit_types::{GitHashAlgorithm, GitOid, PrincipalId, RefName};
use fgit_wire::receive::{ReceiveContext, ReceiveLimits, ReceivePack, SignedPushProfile};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, encode_packets};

const MAX_BUNDLE_BYTES: usize = 128 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CANDIDATE_BYTES: usize = 2 * 1024 * 1024;

fn invalid(reason: &'static str) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::InvalidWorkspaceCandidate(reason)
}

fn receive_error(error: impl Into<NodeReceiveTransportRefusal>) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::WorkspacePublication(Box::new(error.into()))
}

/// Only the header is inspected here. The pack remains completely untrusted
/// until ReceivePack and ProductionQuarantineValidator have validated it.
struct CandidateEnvelope<'a> {
    format: GitHashAlgorithm,
    base: GitOid,
    candidate: GitOid,
    reference: RefName,
    pack: &'a [u8],
}

impl<'a> CandidateEnvelope<'a> {
    fn parse(input: &'a [u8]) -> Result<Self, NodeWorkspaceRefusal> {
        if input.len() > MAX_BUNDLE_BYTES {
            return Err(invalid("bundle exceeds the 128 MiB input limit"));
        }
        let mut offset = 0;
        let format = match header_line(input, &mut offset)? {
            b"# v2 git bundle" => GitHashAlgorithm::Sha1,
            b"# v3 git bundle" => match header_line(input, &mut offset)? {
                b"@object-format=sha1" => GitHashAlgorithm::Sha1,
                b"@object-format=sha256" => GitHashAlgorithm::Sha256,
                _ => return Err(invalid("v3 requires exactly one supported object-format capability")),
            },
            _ => return Err(invalid("expected a Git bundle v2 or v3 signature")),
        };
        let prerequisite = header_line(input, &mut offset)?;
        let prerequisite = prerequisite.strip_prefix(b"-")
            .ok_or_else(|| invalid("exactly one prerequisite commit is required"))?;
        let (base, _comment) = split_oid(prerequisite, format)?;
        // Git explicitly gives prerequisite comments no semantic meaning.
        let advertisement = header_line(input, &mut offset)?;
        let (candidate, name) = split_oid(advertisement, format)?;
        let reference = RefName::try_new(name)
            .map_err(|_| invalid("invalid candidate reference"))?;
        if !reference.as_bytes().starts_with(b"refs/heads/") {
            return Err(invalid("workspace publication requires a branch reference"));
        }
        if !header_line(input, &mut offset)?.is_empty() {
            return Err(invalid("only one prerequisite and one branch are supported"));
        }
        if base == candidate {
            return Err(invalid("candidate and prerequisite must be different commits"));
        }
        let pack = &input[offset..];
        if pack.is_empty() {
            return Err(invalid("bundle has no pack"));
        }
        Ok(Self { format, base, candidate, reference, pack })
    }

    fn bind(
        &self,
        format: GitHashAlgorithm,
        reference: &RefName,
        base: GitOid,
        candidate: GitOid,
    ) -> Result<(), NodeWorkspaceRefusal> {
        if self.format != format || base.algorithm() != format || candidate.algorithm() != format {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
        if &self.reference != reference {
            return Err(invalid("bundle branch differs from the explicitly requested branch"));
        }
        if self.base != base {
            return Err(invalid("bundle prerequisite differs from the expected base commit"));
        }
        if self.candidate != candidate {
            return Err(invalid("bundle tip differs from the reviewed candidate commit"));
        }
        Ok(())
    }
}

fn header_line<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], NodeWorkspaceRefusal> {
    // Limit the SEARCH, not just the length retained after finding a newline.
    let end = input.len().min(MAX_HEADER_BYTES);
    let remaining = input.get(*offset..end)
        .ok_or_else(|| invalid("bundle header exceeds its byte limit"))?;
    let length = remaining.iter().position(|byte| *byte == b'\n')
        .ok_or_else(|| invalid("unterminated or oversized bundle header"))?;
    let line = &remaining[..length];
    *offset += length + 1;
    Ok(line)
}

fn split_oid(line: &[u8], format: GitHashAlgorithm) -> Result<(GitOid, &[u8]), NodeWorkspaceRefusal> {
    let width = format.digest_len() * 2;
    if line.get(width) != Some(&b' ') {
        return Err(invalid("malformed bundle object record"));
    }
    let text = std::str::from_utf8(&line[..width])
        .map_err(|_| invalid("bundle object ID is not hexadecimal"))?;
    let oid = GitOid::from_hex(format, text)
        .map_err(|_| invalid("bundle object ID is not canonical native hexadecimal"))?;
    if oid.is_zero() {
        return Err(invalid("zero is not a candidate or prerequisite object ID"));
    }
    Ok((oid, &line[width + 1..]))
}

impl OneNode {
    /// Publish one independently reviewed, single-parent workspace candidate.
    ///
    /// This is a local-operator boundary, not a remote authentication service.
    /// The owner authorizes `principal_id`; it is never read from bundle bytes.
    /// All three expectations and the idempotency key are explicit. Unknown
    /// bundle capabilities, partial-clone bundles and multi-ref bundles refuse.
    ///
    /// The prerequisite is an EXACT expected-old condition, not a preliminary
    /// check against a mutable ref. It survives into the seal and is evaluated
    /// by canonical admission. Consequently an identical retry can resolve its
    /// original terminal decision after the ref has moved. Another candidate
    /// with the same key is not allowed to alias that decision.
    ///
    /// New objects may be staged before refusal. Only the existing authority
    /// CAS publishes them; no local file, object presence or SQL projection
    /// decides success. Return values preserve canonical refusals and uncertain
    /// infrastructure failures. A non-success is never guessed to be non-commit.
    pub async fn apply_workspace_bundle_durable_in(
        &self,
        request: &NodeRequestContext,
        principal_id: PrincipalId,
        idempotency_key: &[u8],
        reference: &RefName,
        expected_base: GitOid,
        expected_candidate: GitOid,
        input: &[u8],
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let key = IdempotencyKey::new(idempotency_key.to_vec())
            .map_err(|_| invalid("invalid bounded idempotency key"))?;
        // Local input is still re-offerable: reject unavailable publication
        // before parsing/staging, rather than acting as a staging-only server.
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&principal_id).map_err(receive_error)?;
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let envelope = CandidateEnvelope::parse(input)?;
        envelope.bind(self.object_format, reference, expected_base, expected_candidate)?;
        let materialized = self.materialize_admission_in(request).await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if materialized.snapshot().hidden_refs.hides(reference.as_bytes()) {
            return Err(NodeWorkspaceRefusal::RefUnavailable);
        }
        // Only authenticated, selected history may supply prerequisite objects.
        // Merely finding matching bytes in the object fabric is insufficient.
        if !materialized.selected_closure().closure().objects().contains(&expected_base) {
            return Err(invalid("prerequisite is outside the authority-selected history"));
        }
        let base = self.read_git_object(expected_base)
            .map_err(|error| NodeWorkspaceRefusal::WorkspaceCandidateRead(Box::new(error)))?;
        if base.envelope().object_kind() != ObjectKind::Commit {
            return Err(invalid("prerequisite must identify a commit"));
        }
        drop(base);

        let mut limits = ReceiveLimits::default();
        limits.pack.max_input_bytes = MAX_BUNDLE_BYTES;
        limits.pack.max_total_expanded_bytes = MAX_BUNDLE_BYTES;
        limits.pack.max_object_bytes = limits.pack.max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let parse_limits = ParseLimits {
            max_object_bytes: limits.pack.max_object_bytes,
            tree_reference_bytes: self.object_format.digest_len(),
            ..ParseLimits::default()
        };
        let capabilities = format!("report-status atomic object-format={}", self.object_format.as_str());
        let advertised = Capabilities::parse_v1(capabilities.as_bytes(), &limits.wire)
            .map_err(|_| invalid("could not construct receive capabilities"))?;
        let wire_format = match self.object_format {
            GitHashAlgorithm::Sha1 => GitObjectFormat::Sha1,
            GitHashAlgorithm::Sha256 => GitObjectFormat::Sha256,
        };
        let mut command = format!("{expected_base} {expected_candidate} ").into_bytes();
        command.extend_from_slice(reference.as_bytes());
        command.push(0);
        command.extend_from_slice(capabilities.as_bytes());
        let prefix = encode_packets(&[Packet::Data(command), Packet::Flush], &limits.wire)
            .map_err(|_| invalid("could not encode the bounded ref command"))?;
        let validator = self.production_quarantine_validator(
            &materialized, limits.pack.clone(), parse_limits.clone(),
        ).map_err(|code| receive_error(fgit_wire::receive::ReceiveError::AuthoritativeRefusal(code)))?;
        let context = ReceiveContext::new(wire_format, advertised, limits, SignedPushProfile::Refuse)
            .map_err(receive_error)?;
        let mut receive = ReceivePack::new(context).map_err(receive_error)?;
        receive.push_bytes(&prefix).map_err(receive_error)?;
        // No second concatenated copy of the full input pack is constructed.
        receive.push_bytes(envelope.pack).map_err(receive_error)?;
        let mut handoff = ProductionReceiveQuarantineHandoff::new(validator, materialized.basis().clone());
        let mut live = || workspace_request_live(request);
        receive.finish_with_handoff(&mut handoff, &mut live).map_err(receive_error)?;
        let validated = handoff.into_validated_receive().map_err(receive_error)?;
        drop(receive);

        // Quarantine verified and staged the requested closure. Enforce the
        // extra workspace contract BEFORE sealing/publication: this is a real
        // commit with exactly the reviewed base as its one parent, not a tag,
        // blob, root commit, unrelated history or caller-invented force move.
        let candidate = self.read_git_object(expected_candidate)
            .map_err(|error| NodeWorkspaceRefusal::WorkspaceCandidateRead(Box::new(error)))?;
        if candidate.envelope().object_kind() != ObjectKind::Commit {
            return Err(invalid("candidate must identify a commit"));
        }
        check_candidate_commit(candidate.payload(), expected_base, parse_limits)?;
        drop(candidate);
        if !workspace_request_live(request) {
            return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None });
        }
        let session = LoopbackReceiveSession::authenticated(principal_id, key);
        // No post-publication cancellation check may replace a known terminal
        // outcome with a misleading request-cancelled/non-commit response.
        self.admit_basis_bound_loopback_receive_durable_in(
            request, &session, &validated, AdmissionLimits::default(),
        ).await.map_err(receive_error)
    }
}

fn check_candidate_commit(
    body: &[u8],
    expected_base: GitOid,
    mut limits: ParseLimits,
) -> Result<(), NodeWorkspaceRefusal> {
    limits.max_object_bytes = limits.max_object_bytes.min(MAX_CANDIDATE_BYTES);
    let ParsedObject::Commit(commit) = parse_object_body(
        ObjectType::Commit, body, AcceptanceProfile::StrictCreate, &limits,
    ).map_err(|_| invalid("candidate is not a bounded strict Git commit"))? else {
        return Err(invalid("candidate must identify a commit"));
    };
    let mut parents = commit.parent_references();
    let parent = parents.next().ok_or_else(|| invalid("candidate must have exactly one parent"))?;
    let parent = std::str::from_utf8(parent).ok()
        .and_then(|text| GitOid::from_hex(expected_base.algorithm(), text).ok());
    if parent != Some(expected_base) || parents.next().is_some() {
        return Err(invalid("candidate must have exactly the expected base as its sole parent"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(format: GitHashAlgorithm, digit: char) -> GitOid {
        GitOid::from_hex(format, &digit.to_string().repeat(format.digest_len() * 2)).unwrap()
    }

    fn bundle(format: GitHashAlgorithm) -> Vec<u8> {
        format!("# v3 git bundle\n@object-format={}\n-{} arbitrary prerequisite comment\n{} refs/heads/main\n\nPACK",
            format.as_str(), oid(format, '1'), oid(format, '2')).into_bytes()
    }

    #[test]
    fn envelope_binds_all_explicit_expectations_in_both_native_formats() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let bytes = bundle(format);
            let envelope = CandidateEnvelope::parse(&bytes).unwrap();
            let reference = RefName::try_new(b"refs/heads/main").unwrap();
            assert_eq!(envelope.pack, b"PACK", "only the envelope was checked, not pack validity");
            assert!(envelope.bind(format, &reference, oid(format, '1'), oid(format, '2')).is_ok());
            assert!(envelope.bind(format, &reference, oid(format, '3'), oid(format, '2')).is_err());
            assert!(envelope.bind(format, &reference, oid(format, '1'), oid(format, '3')).is_err());
            assert!(envelope.bind(format, &RefName::try_new(b"refs/heads/other").unwrap(),
                oid(format, '1'), oid(format, '2')).is_err());
        }
    }

    #[test]
    fn capabilities_extra_refs_missing_delimiter_and_zero_ids_fail_closed() {
        let valid = String::from_utf8(bundle(GitHashAlgorithm::Sha1)).unwrap();
        for bad in [
            valid.replace("@object-format=sha1", "@filter=blob:none"),
            valid.replace("@object-format=sha1", "@object-format=sha1\n@object-format=sha1"),
            valid.replace("\n\nPACK", &format!("\n{} refs/heads/extra\n\nPACK", "3".repeat(40))),
            valid.replace("\n\nPACK", "\nPACK"),
            valid.replace(&"1".repeat(40), &"0".repeat(40)),
            valid.replace("refs/heads/main", "refs/tags/main"),
        ] {
            assert!(CandidateEnvelope::parse(bad.as_bytes()).is_err());
        }
        assert!(CandidateEnvelope::parse(valid.as_bytes()).is_ok());
        let v2 = valid.replace("# v3 git bundle\n@object-format=sha1", "# v2 git bundle");
        assert!(CandidateEnvelope::parse(v2.as_bytes()).is_ok());
    }

    #[test]
    fn every_header_truncation_and_oversized_line_refuses() {
        let bytes = bundle(GitHashAlgorithm::Sha256);
        for end in 0..=bytes.len() - 4 {
            assert!(CandidateEnvelope::parse(&bytes[..end]).is_err(), "truncation {end}");
        }
        let oversized = [b"# v3 git bundle\n@object-format=sha256\n-".as_slice(),
            &vec![b'a'; MAX_HEADER_BYTES], b"\n\nPACK"].concat();
        assert!(CandidateEnvelope::parse(&oversized).is_err());
    }

    #[test]
    fn single_parent_contract_rejects_roots_merges_and_unrelated_history() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let base = oid(format, '1');
            let tree = oid(format, '2');
            let limits = ParseLimits { tree_reference_bytes: format.digest_len(), ..ParseLimits::default() };
            let commit = |parents: &str| format!("tree {tree}\n{parents}author Test <t@example.invalid> 1 +0000\ncommitter Test <t@example.invalid> 1 +0000\n\nchange\n");
            let permitted = commit(&format!("parent {base}\n"));
            assert!(check_candidate_commit(permitted.as_bytes(), base, limits.clone()).is_ok());
            // Preserve the existing StrictCreate epoch-zero divergence while
            // the parent-shape assertions use an otherwise permitted commit.
            let epoch_zero = permitted.replace(" 1 +0000\n", " 0 +0000\n");
            assert!(matches!(check_candidate_commit(epoch_zero.as_bytes(), base, limits.clone()),
                Err(NodeWorkspaceRefusal::InvalidWorkspaceCandidate("candidate is not a bounded strict Git commit"))));
            for parents in [String::new(), format!("parent {}\n", oid(format, '3')),
                format!("parent {base}\nparent {}\n", oid(format, '3'))] {
                assert!(check_candidate_commit(commit(&parents).as_bytes(), base, limits.clone()).is_err());
            }
        }
    }
}
