#![forbid(unsafe_code)]
//! Canonical verified-read wire bodies and a relay-to-client verification path.

use fgit_authority::{TerminalOutcome, outcome_index_proof, outcome_index_root};
use fgit_codec::{
    CryptoBodyIdentity, DecodeLimits, RepositoryAuthorityHeadBody, RepositoryConfigurationBody,
    body_id, canonical_body_bytes, decode_body, encode_body, split_frame,
};
use fgit_codec_verify::parse_frame;
use fgit_crypto::{
    IdentityDomain, MerkleProof, RefStateNonMembershipProof, object_closure_membership_proof,
    object_closure_merkle_root, object_closure_non_membership_proof, ref_state_membership_proof,
    ref_state_merkle_root, ref_state_non_membership_proof,
};
use fgit_types::CANONICAL_CODEC_VERSION;
use fgit_types::hash::{Digest, DigestBytes};
use fgit_types::identity::{RepositoryCommitId, RepositoryId, TxId};
use fgit_types::layout::RootLayoutVersion;
use fgit_types::native::{GitHashAlgorithm, GitOid, GitOidSha1};
use fgit_types::numeric::{DecisionSequence, HeadGeneration, PolicyEpoch, RegistryEpoch};
use fgit_types::refs::RefName;
use fgit_types::vocabulary::DecisionOutcome;
use fgit_verified_read::{
    MerkleProofBody, ObjectClosureNonMembershipProofBody, ObjectDisclosurePolicy,
    PinnedAuthorityHead, RefDisclosurePolicy, RefStateNonMembershipProofBody, VerifiedMembership,
    VerifiedReadAnswer, VerifiedReadEnvelope, VerifiedReadRefusal, authorize_object_absence,
    authorize_ref_absence, decode_merkle_proof, decode_object_closure_non_membership_proof,
    decode_ref_state_non_membership_proof, decode_verified_read_envelope, encode_merkle_proof,
    encode_object_closure_non_membership_proof, encode_ref_state_non_membership_proof,
    encode_verified_read_envelope, verify_envelope,
};

struct AllowAll;

impl RefDisclosurePolicy for AllowAll {
    fn permits_ref_disclosure(&self, _name: &RefName) -> bool {
        true
    }
}

struct AllowAllObject;

impl ObjectDisclosurePolicy for AllowAllObject {
    fn permits_object_disclosure(&self, _oid: &GitOid) -> bool {
        true
    }
}

fn name(value: &[u8]) -> RefName {
    RefName::try_new(value).expect("fixture ref name is valid")
}

const fn oid(byte: u8) -> GitOid {
    GitOid::Sha1(GitOidSha1::from_bytes([byte; GitOidSha1::LEN]))
}

fn tx(byte: u8) -> TxId {
    TxId::from_digest(
        IdentityDomain::RefTransaction.algorithm().id(),
        CANONICAL_CODEC_VERSION,
        DigestBytes::try_new(&[byte; 32]).expect("fixture digest is bounded"),
    )
}

fn committed(sequence: u64, byte: u8) -> TerminalOutcome {
    TerminalOutcome {
        decision_sequence: DecisionSequence::try_new(sequence)
            .expect("fixture sequence is positive"),
        outcome: DecisionOutcome::Committed {
            repository_commit_id: RepositoryCommitId::from_digest(
                IdentityDomain::RepositoryCommitRecord.algorithm().id(),
                CANONICAL_CODEC_VERSION,
                DigestBytes::try_new(&[byte; 32]).expect("fixture digest is bounded"),
            ),
        },
    }
}

fn v1_configuration() -> (RepositoryConfigurationBody, Digest) {
    let configuration = RepositoryConfigurationBody {
        root_layout: RootLayoutVersion::RefStateMerkleV1,
        object_format: GitHashAlgorithm::Sha1,
        hidden_ref_rules: Vec::new(),
    };
    let identity = body_id(&CryptoBodyIdentity, &configuration)
        .expect("the canonical configuration has an identity");
    (
        configuration,
        Digest::new(identity.algorithm(), *identity.digest()),
    )
}

fn ref_fixture() -> (PinnedAuthorityHead, VerifiedReadEnvelope) {
    let main = name(b"refs/heads/main");
    let entries = vec![
        (main.clone(), oid(0x11)),
        (name(b"refs/tags/v1"), oid(0x22)),
    ];
    let (bound_oid, proof) =
        ref_state_membership_proof(&entries, &main).expect("the named ref is present");
    let (configuration, configuration_root) = v1_configuration();
    let mut head = fgit_codec::harness::genesis_head();
    head.ref_root = ref_state_merkle_root(&entries).expect("the ref map is canonical");
    head.configuration_root = configuration_root;
    let pinned = PinnedAuthorityHead::new(head.clone());
    let envelope = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::RefMembership {
            name: main,
            oid: bound_oid,
            proof: Box::new(proof),
        },
    );
    (pinned, envelope)
}

fn golden_digest(byte: u8) -> Digest {
    Digest::new(
        IdentityDomain::MerkleNode.algorithm().id(),
        DigestBytes::try_new(&[byte; 32]).expect("golden digest is bounded"),
    )
}

fn golden_head() -> RepositoryAuthorityHeadBody {
    RepositoryAuthorityHeadBody {
        repository_id: RepositoryId::from_bytes([0x42; 16]),
        generation: HeadGeneration::FIRST,
        predecessor_head_id: None,
        decision_tail_id: None,
        latest_decision_sequence: None,
        latest_committed_rcr_id: None,
        latest_repository_sequence: None,
        ref_root: golden_digest(0x10),
        forge_position_root: golden_digest(0x11),
        outcome_index_root: golden_digest(0x12),
        retention_root: golden_digest(0x13),
        outbox_root: golden_digest(0x14),
        configuration_root: golden_digest(0x15),
        policy_epoch: PolicyEpoch::FIRST,
        format_registry_epoch: RegistryEpoch::FIRST,
        last_checkpoint_id: None,
    }
}

fn golden_bytes(text: &str) -> Vec<u8> {
    let text = text.trim();
    assert_eq!(text.len() % 2, 0, "golden hex has full bytes");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("golden file is lowercase hex"))
        .collect()
}

#[test]
fn committed_goldens_bind_the_envelope_and_both_proof_body_encodings() {
    let merkle = MerkleProofBody::new(MerkleProof::new(
        0,
        2,
        vec![DigestBytes::try_new(&[0xAA; 32]).expect("golden sibling is bounded")],
    ));
    let merkle_wire = golden_bytes(include_str!("goldens/merkle-proof-v1.hex"));
    assert_eq!(
        encode_body(&merkle).expect("Merkle golden encodes"),
        merkle_wire
    );
    assert_eq!(
        encode_body(
            &decode_body::<MerkleProofBody>(&merkle_wire, DecodeLimits::DEFAULT)
                .expect("Merkle golden decodes"),
        )
        .expect("Merkle golden re-encodes"),
        merkle_wire
    );

    let absence = RefStateNonMembershipProofBody::new(RefStateNonMembershipProof::Between {
        predecessor: Box::new(fgit_crypto::RefStateNeighbour::new(
            name(b"refs/heads/aaa"),
            oid(0x11),
            MerkleProof::new(0, 1, Vec::new()),
        )),
        successor: Box::new(fgit_crypto::RefStateNeighbour::new(
            name(b"refs/heads/zzz"),
            oid(0x22),
            MerkleProof::new(0, 1, Vec::new()),
        )),
    });
    let absence_wire = golden_bytes(include_str!("goldens/ref-non-membership-proof-v1.hex"));
    assert_eq!(
        encode_body(&absence).expect("absence golden encodes"),
        absence_wire
    );
    assert_eq!(
        encode_body(
            &decode_body::<RefStateNonMembershipProofBody>(&absence_wire, DecodeLimits::DEFAULT)
                .expect("absence golden decodes"),
        )
        .expect("absence golden re-encodes"),
        absence_wire
    );

    let envelope = VerifiedReadEnvelope::new(
        golden_head(),
        None,
        VerifiedReadAnswer::RefMembership {
            name: name(b"refs/heads/main"),
            oid: oid(0x31),
            proof: Box::new(MerkleProof::new(0, 1, Vec::new())),
        },
    );
    let envelope_wire = golden_bytes(include_str!("goldens/verified-read-envelope-v1.hex"));
    assert_eq!(
        encode_verified_read_envelope(&envelope).expect("envelope golden encodes"),
        envelope_wire
    );
    assert_eq!(
        encode_verified_read_envelope(
            &decode_verified_read_envelope(&envelope_wire, DecodeLimits::DEFAULT)
                .expect("envelope golden decodes"),
        )
        .expect("envelope golden re-encodes"),
        envelope_wire
    );
}

#[test]
fn both_native_proof_shapes_round_trip_through_their_canonical_bodies() {
    let main = name(b"refs/heads/main");
    let entries = vec![
        (main.clone(), oid(0x11)),
        (name(b"refs/tags/v1"), oid(0x22)),
    ];
    let (_, membership) =
        ref_state_membership_proof(&entries, &main).expect("the named ref is present");
    let absence = ref_state_non_membership_proof(&entries, &name(b"refs/heads/middle"))
        .expect("the query is absent");

    let membership_wire = encode_merkle_proof(&membership).expect("membership proof encodes");
    assert_eq!(
        encode_body(
            &decode_body::<MerkleProofBody>(&membership_wire, DecodeLimits::DEFAULT)
                .expect("membership proof decodes"),
        )
        .expect("decoded membership proof re-encodes"),
        membership_wire,
        "a Merkle proof has one canonical frame"
    );
    assert_eq!(
        decode_merkle_proof(&membership_wire, DecodeLimits::DEFAULT)
            .expect("membership proof decodes"),
        membership,
        "the native Merkle verifier receives exactly the decoded proof"
    );

    let absence_wire =
        encode_ref_state_non_membership_proof(&absence).expect("absence proof encodes");
    assert_eq!(
        encode_body(
            &decode_body::<RefStateNonMembershipProofBody>(&absence_wire, DecodeLimits::DEFAULT)
                .expect("absence proof decodes"),
        )
        .expect("decoded absence proof re-encodes"),
        absence_wire,
        "an ordered non-membership proof has one canonical frame"
    );
    assert_eq!(
        decode_ref_state_non_membership_proof(&absence_wire, DecodeLimits::DEFAULT)
            .expect("absence proof decodes"),
        absence,
        "the native absence verifier receives exactly the decoded proof"
    );
}

#[test]
fn relayed_envelope_is_parsed_independently_then_client_decoded_and_verified() {
    let (pinned, envelope) = ref_fixture();

    // Server side: only bytes leave this scope.
    let relay_bytes = encode_verified_read_envelope(&envelope).expect("server envelope encodes");

    // The std-only codec verifier independently consumes the relay frame.  It
    // shares neither fgit-codec nor fgit-verified-read implementation code.
    let parsed = parse_frame(&relay_bytes).expect("relay bytes have a valid canonical frame");
    assert_eq!(parsed.domain, "frankengit/verified-read-envelope/v1");
    assert_eq!(parsed.family, "verified-read-envelope");
    assert_eq!(parsed.schema_major, 1);
    assert_eq!(parsed.schema_minor, 0);

    // Client side: the decoded form, not any server-side object, is passed to
    // the proof verifier against the client-selected authenticated head.
    let decoded = decode_verified_read_envelope(&relay_bytes, DecodeLimits::DEFAULT)
        .expect("client decodes canonical relay bytes");
    assert_eq!(
        verify_envelope(&pinned, &decoded),
        Ok(VerifiedMembership::Ref),
        "a proxy can relay bytes without becoming a proof authority"
    );
    assert_eq!(
        encode_verified_read_envelope(&decoded).expect("client re-encodes decoded form"),
        relay_bytes,
        "strict decoding preserves byte identity"
    );
}

#[test]
fn outcome_and_authorized_absence_envelopes_round_trip_and_verify() {
    let outcome = committed(1, 0x55);
    let outcome_tx = tx(0xA1);
    let outcome_entries = vec![(outcome_tx, outcome)];
    let mut outcome_head = fgit_codec::harness::genesis_head();
    outcome_head.outcome_index_root =
        outcome_index_root(&outcome_entries).expect("outcome root is canonical");
    let outcome_envelope = VerifiedReadEnvelope::new(
        outcome_head.clone(),
        None,
        VerifiedReadAnswer::OutcomeMembership {
            tx_id: outcome_tx,
            outcome: Box::new(outcome),
            proof: Box::new(
                outcome_index_proof(&outcome_entries, outcome_tx, &outcome)
                    .expect("outcome proof exists"),
            ),
        },
    );
    let outcome_wire = encode_verified_read_envelope(&outcome_envelope).expect("outcome encodes");
    let outcome_decoded = decode_verified_read_envelope(&outcome_wire, DecodeLimits::DEFAULT)
        .expect("outcome decodes");
    assert_eq!(
        verify_envelope(&PinnedAuthorityHead::new(outcome_head), &outcome_decoded),
        Ok(VerifiedMembership::Outcome)
    );

    let query = name(b"refs/heads/middle");
    let entries = vec![
        (name(b"refs/heads/aaa"), oid(0x31)),
        (name(b"refs/heads/zzz"), oid(0x32)),
    ];
    let absence = authorize_ref_absence(&AllowAll, query.clone(), |_| false)
        .expect("the query was authorized before its absence was observed");
    let (configuration, configuration_root) = v1_configuration();
    let mut absence_head = fgit_codec::harness::genesis_head();
    absence_head.ref_root = ref_state_merkle_root(&entries).expect("ref root is canonical");
    absence_head.configuration_root = configuration_root;
    let absence_envelope = VerifiedReadEnvelope::new(
        absence_head.clone(),
        Some(configuration),
        VerifiedReadAnswer::AuthorizedRefAbsence {
            absence,
            proof: Box::new(
                ref_state_non_membership_proof(&entries, &query)
                    .expect("the query has ordered neighbour evidence"),
            ),
        },
    );
    let absence_wire = encode_verified_read_envelope(&absence_envelope).expect("absence encodes");
    let absence_decoded = decode_verified_read_envelope(&absence_wire, DecodeLimits::DEFAULT)
        .expect("absence decodes");
    assert_eq!(
        verify_envelope(&PinnedAuthorityHead::new(absence_head), &absence_decoded),
        Ok(VerifiedMembership::RefAbsence),
        "the decoded ordered witness verifies under the pinned V1 ref root"
    );
}

#[test]
fn hostile_wire_bytes_refuse_while_the_permitted_twin_decodes_and_verifies() {
    let (pinned, envelope) = ref_fixture();
    let permitted = encode_verified_read_envelope(&envelope).expect("fixture encodes");
    assert_eq!(
        verify_envelope(
            &pinned,
            &decode_verified_read_envelope(&permitted, DecodeLimits::DEFAULT)
                .expect("permitted twin decodes"),
        ),
        Ok(VerifiedMembership::Ref)
    );

    let truncated = &permitted[..permitted.len() - 1];
    assert!(matches!(
        decode_verified_read_envelope(truncated, DecodeLimits::DEFAULT),
        Err(VerifiedReadRefusal::WireDecode(_)),
    ));

    let (_, payload) = split_frame(&permitted, DecodeLimits::DEFAULT)
        .expect("the permitted fixture has one payload at the end of its frame");
    let payload_start = permitted.len() - payload.len();
    let mut unknown_version = permitted.clone();
    unknown_version[payload_start..payload_start + 2].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        decode_verified_read_envelope(&unknown_version, DecodeLimits::DEFAULT),
        Err(VerifiedReadRefusal::UnsupportedEnvelopeVersion { observed: 2 }),
        "a future envelope grammar must fail closed rather than being treated as V1"
    );

    let mut proof_tampered = permitted;
    let last = proof_tampered.len() - 1;
    proof_tampered[last] ^= 0x01;
    let decoded = decode_verified_read_envelope(&proof_tampered, DecodeLimits::DEFAULT)
        .expect("a syntactically valid but altered proof still decodes");
    assert_eq!(
        verify_envelope(&pinned, &decoded),
        Err(VerifiedReadRefusal::ProofRejected),
        "tampering must be rejected by the pinned-head proof verification step"
    );
}

#[test]
fn envelope_body_payload_is_the_identity_bearing_payload_not_the_transport_frame() {
    let (_, envelope) = ref_fixture();
    let frame = encode_verified_read_envelope(&envelope).expect("envelope encodes");
    let payload = canonical_body_bytes(&envelope).expect("payload encodes");
    assert!(frame.len() > payload.len());
    let (_, framed_payload) = split_frame(&frame, DecodeLimits::DEFAULT).expect("frame splits");
    assert_eq!(framed_payload, payload.as_slice());
}

#[test]
fn object_proofs_and_envelopes_round_trip_and_verify() {
    let objects = vec![oid(0x11), oid(0x22), oid(0x33)];
    let obj_root = object_closure_merkle_root(&objects).expect("object root");
    let (bound_oid, membership) = (
        oid(0x22),
        object_closure_membership_proof(&objects, &oid(0x22)).expect("proof"),
    );
    let absence = object_closure_non_membership_proof(&objects, &oid(0x15)).expect("absence proof");

    let absence_wire = encode_object_closure_non_membership_proof(&absence).expect("encodes");
    assert_eq!(
        encode_body(
            &decode_body::<ObjectClosureNonMembershipProofBody>(
                &absence_wire,
                DecodeLimits::DEFAULT
            )
            .expect("decodes"),
        )
        .expect("re-encodes"),
        absence_wire,
        "an object closure non-membership proof has one canonical frame"
    );
    assert_eq!(
        decode_object_closure_non_membership_proof(&absence_wire, DecodeLimits::DEFAULT)
            .expect("decodes"),
        absence,
        "the native object absence verifier receives exactly the decoded proof"
    );

    // Object membership envelope
    let (configuration, configuration_root) = v1_configuration();
    let mut head = fgit_codec::harness::genesis_head();
    head.configuration_root = configuration_root;
    let pinned = PinnedAuthorityHead::new_with_object_closure(head.clone(), obj_root);

    let member_envelope = VerifiedReadEnvelope::new(
        head.clone(),
        Some(configuration.clone()),
        VerifiedReadAnswer::ObjectMembership {
            oid: bound_oid,
            proof: Box::new(membership),
        },
    );
    let member_wire = encode_verified_read_envelope(&member_envelope).expect("member encodes");
    let member_decoded =
        decode_verified_read_envelope(&member_wire, DecodeLimits::DEFAULT).expect("member decodes");
    assert_eq!(
        verify_envelope(&pinned, &member_decoded),
        Ok(VerifiedMembership::Object),
    );

    // Object absence envelope
    let auth_absence = authorize_object_absence(&AllowAllObject, oid(0x15), |_| false)
        .expect("authorized absence");
    let absence_envelope = VerifiedReadEnvelope::new(
        head,
        Some(configuration),
        VerifiedReadAnswer::AuthorizedObjectAbsence {
            absence: auth_absence,
            proof: Box::new(absence),
        },
    );
    let absence_envelope_wire =
        encode_verified_read_envelope(&absence_envelope).expect("absence encodes");
    let absence_envelope_decoded =
        decode_verified_read_envelope(&absence_envelope_wire, DecodeLimits::DEFAULT)
            .expect("absence decodes");
    assert_eq!(
        verify_envelope(&pinned, &absence_envelope_decoded),
        Ok(VerifiedMembership::ObjectAbsence),
    );
}

/// A decoded leaf position outside the tree the proof itself declares is
/// refused, and the position one below it still decodes.
///
/// `MerkleProof::new` documents that its index, leaf count and siblings are
/// untrusted claims, so the wire is exactly where hostile values arrive. This
/// pins the decoder's own bound rather than the fold's: the refusal must come
/// back before a `MerkleProof` exists, so that a value that could never verify
/// is never carried around as if it might.
///
/// Both directions are asserted on purpose. A decoder that refused every proof
/// would satisfy every refusal below, so the in-range twins — including the
/// largest index the tree admits, which is the value one step from being
/// rejected — are what make the refusals mean anything.
#[test]
fn a_hostile_decoded_leaf_index_is_refused_before_a_proof_is_built() {
    // A real tree and a real proof, so the permitted twin genuinely verifies
    // rather than merely decoding.
    let objects = vec![oid(0x11), oid(0x22), oid(0x33)];
    let root = object_closure_merkle_root(&objects).expect("object closure root");
    let last = *objects.last().expect("the fixture closure is not empty");
    let honest = object_closure_membership_proof(&objects, &last).expect("honest proof");

    // The honest proof sits at the top of its own range, which is what makes
    // the off-by-one splice below land exactly on the boundary.
    assert_eq!(
        honest.index(),
        honest.leaf_count() - 1,
        "the fixture must prove the last leaf, or the boundary case below is not the boundary"
    );
    let leaf_count = u64::try_from(honest.leaf_count()).expect("fixture leaf count is small");

    let permitted = encode_merkle_proof(&honest).expect("the honest proof encodes");
    assert_eq!(
        decode_merkle_proof(&permitted, DecodeLimits::DEFAULT).expect("the honest proof decodes"),
        honest,
        "the permitted twin at the top of the range must survive its own wire form"
    );
    assert!(
        fgit_crypto::verify_object_closure_membership(&root, &last, &honest),
        "the permitted twin must be a proof that actually verifies, not just one that parses"
    );

    // The payload begins with the index scalar, then the leaf count: both are
    // eight big-endian bytes with no tag, so the splices below are exact.
    let (_, payload) = split_frame(&permitted, DecodeLimits::DEFAULT)
        .expect("the encoded proof has one payload at the end of its frame");
    let index_at = permitted.len() - payload.len();
    let leaf_count_at = index_at + 8;

    let spliced = |offset: usize, value: u64| {
        let mut bytes = permitted.clone();
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        bytes
    };
    let refusal_for = |bytes: Vec<u8>| match decode_merkle_proof(&bytes, DecodeLimits::DEFAULT) {
        Err(VerifiedReadRefusal::WireDecode(refusal)) => *refusal,
        other => panic!("a malformed leaf position must be a typed decode refusal: {other:?}"),
    };

    // The hostile maximum. On a 64-bit target this narrows to `usize` without
    // complaint, so nothing below the decoder would have caught it here.
    assert_eq!(
        refusal_for(spliced(index_at, u64::MAX)),
        fgit_codec::CodecRefusal::ValueUnrepresentable {
            field: "merkle_proof.index",
            observed: u64::MAX,
            limit: leaf_count - 1,
        },
        "the largest representable index must be refused against the tree the proof declares"
    );

    // The exact boundary: one past the last leaf. This is the case an
    // implementation that wrote `>` for `>=` would let through, and the value
    // adjacent to the twin that must still be accepted.
    assert_eq!(
        refusal_for(spliced(index_at, leaf_count)),
        fgit_codec::CodecRefusal::ValueUnrepresentable {
            field: "merkle_proof.index",
            observed: leaf_count,
            limit: leaf_count - 1,
        },
        "an index equal to the leaf count names a leaf one past the end of the tree"
    );

    // An empty tree admits no leaf at all, so even index zero is refused. No
    // separate rule produces this: `index < leaf_count` is unsatisfiable at
    // zero leaves.
    assert_eq!(
        refusal_for(spliced(leaf_count_at, 0)),
        fgit_codec::CodecRefusal::ValueUnrepresentable {
            field: "merkle_proof.index",
            observed: u64::try_from(honest.index()).expect("fixture index is small"),
            limit: 0,
        },
        "a proof claiming a tree with no leaves has no position to describe"
    );

    // The permitted twins at the boundary. Without these the three refusals
    // above are equally satisfied by a decoder that rejects everything.
    let widened = spliced(leaf_count_at, leaf_count + 1);
    let decoded = decode_merkle_proof(&widened, DecodeLimits::DEFAULT)
        .expect("an index strictly inside a larger declared tree still decodes");
    assert_eq!(decoded.index(), honest.index());
    assert_eq!(decoded.leaf_count(), honest.leaf_count() + 1);

    let at_top = spliced(index_at, leaf_count - 1);
    assert_eq!(
        decode_merkle_proof(&at_top, DecodeLimits::DEFAULT)
            .expect("the largest admissible index decodes")
            .index(),
        honest.index(),
        "the bound is exclusive on the leaf count, so the last leaf remains provable"
    );
}
