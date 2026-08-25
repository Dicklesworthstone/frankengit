//! The content-addressed policy snapshot.
//!
//! A compiled policy becomes canonical bytes under its own domain separation
//! tag, and the digest of those bytes is the snapshot's identity. A decision
//! trace names that identity, so "which policy decided this" is answerable
//! from the trace alone, and two nodes that name the same identity are holding
//! the same rules byte for byte.
//!
//! ## Its own identity domain
//!
//! `frankengit/policy-snapshot/v1` is deliberately not
//! `frankengit/policy-checkpoint/v1`. A checkpoint body and a compiled policy
//! are different bodies; sharing a domain would make their identities
//! computable in the same space, so a reader could not tell which body an
//! identity named. The tag must therefore carry a row in `fgit-crypto`'s
//! identity-domain registry: an unregistered tag has no identity, and
//! [`PolicySnapshot::seal`] refuses rather than minting a value nothing else
//! could verify.
//!
//! ## What the bytes commit to
//!
//! The policy's name, its declarations, its rules, and its default. Not the
//! source text: two source texts that state the same policy in a different
//! order compile to the same value and so to the same identity, which is the
//! determinism property FG-043a's acceptance asks for.

use fgit_codec::{
    CanonicalBody, CodecRefusal, CryptoBodyIdentity, DecodeLimits, Decoder, Encoder, body_id,
    canonical_body_bytes, decode_body, encode_body,
};
use fgit_types::identity::InternalObjectId;
use fgit_types::{DomainTag, SchemaFamily};

use crate::basis::{
    AggregateName, AuthenticationStrength, EvidenceKind, IssuerLabel, LabelName, PrincipalKind,
    RefUpdateKind,
};
use crate::glob::RefPattern;
use crate::program::{
    Compare, CompiledPolicy, CompiledRule, DenyReason, EvidenceRequirement, MAX_PREDICATE_DEPTH,
    PolicyName, Predicate, RuleId, RuleOutcome, Selector, TextLiteral,
};

/// The domain separation tag a policy snapshot is identified under.
pub const POLICY_SNAPSHOT_DOMAIN: DomainTag =
    DomainTag::from_static("frankengit/policy-snapshot/v1");

/// The schema family a policy snapshot body declares.
pub const POLICY_SNAPSHOT_SCHEMA_FAMILY: SchemaFamily =
    SchemaFamily::from_static("policy-snapshot");

/// The identity of one compiled policy snapshot.
///
/// Domain-pinned: adopting an identity computed in another domain is a typed
/// refusal, so a digest minted for some other body class cannot be presented
/// as the policy a decision was made under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicySnapshotId(InternalObjectId);

impl PolicySnapshotId {
    /// Adopts an internal identity, refusing one from another domain.
    pub fn from_internal_object_id(id: InternalObjectId) -> Result<Self, CodecRefusal> {
        if id.domain() == POLICY_SNAPSHOT_DOMAIN {
            Ok(Self(id))
        } else {
            Err(CodecRefusal::domain_unexpected(
                POLICY_SNAPSHOT_DOMAIN,
                id.domain(),
            ))
        }
    }

    /// The underlying internal identity.
    #[must_use]
    pub const fn as_internal_object_id(&self) -> &InternalObjectId {
        &self.0
    }
}

impl core::fmt::Display for PolicySnapshotId {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, formatter)
    }
}

/// The canonical body of a compiled policy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicySnapshotBody {
    policy: CompiledPolicy,
}

impl PolicySnapshotBody {
    /// Wraps a compiled policy as a canonical body.
    #[must_use]
    pub const fn new(policy: CompiledPolicy) -> Self {
        Self { policy }
    }

    /// The policy the body carries.
    #[must_use]
    pub const fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    /// Unwraps to the compiled policy.
    #[must_use]
    pub fn into_policy(self) -> CompiledPolicy {
        self.policy
    }
}

impl CanonicalBody for PolicySnapshotBody {
    const DOMAIN: DomainTag = POLICY_SNAPSHOT_DOMAIN;
    const SCHEMA_FAMILY: SchemaFamily = POLICY_SNAPSHOT_SCHEMA_FAMILY;
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_text("policy.name", self.policy.name().as_str())?;
        out.write_canonical_set(
            "policy.aggregates",
            self.policy.aggregates(),
            |out, name| out.write_text("aggregate", name.as_str()),
        )?;
        out.write_canonical_set("policy.evidence", self.policy.evidence(), write_requirement)?;
        // A sequence, not a set: the order rules are consulted in IS the trace
        // order, and `CompiledPolicy::new` has already put them in canonical
        // order by identifier. Encoding as a set would sort by encoded bytes
        // instead, which is a different order for identifiers of different
        // lengths.
        out.write_sequence("policy.rules", self.policy.rules(), write_rule)?;
        write_outcome(out, self.policy.default_outcome())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let name = read_label::<PolicyName>(input, "policy.name", PolicyName::try_new)?;
        let aggregates = input.read_canonical_set("policy.aggregates", |input| {
            read_label::<AggregateName>(input, "aggregate", AggregateName::try_new)
        })?;
        let evidence = input.read_canonical_set("policy.evidence", read_requirement)?;
        let rules = input.read_sequence("policy.rules", read_rule)?;
        let default_outcome = read_outcome(input)?;
        Ok(Self {
            policy: CompiledPolicy::new(name, aggregates, evidence, rules, default_outcome),
        })
    }
}

/// A compiled policy together with the identity of its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicySnapshot {
    body: PolicySnapshotBody,
    id: PolicySnapshotId,
}

impl PolicySnapshot {
    /// Computes the body's identity and pairs the two.
    ///
    /// Fallible because the identity is computed through `fgit-crypto`'s
    /// registry: a domain the registry has no row for has no identity, and
    /// this refuses rather than producing a digest nothing could verify.
    pub fn seal(body: PolicySnapshotBody) -> Result<Self, CodecRefusal> {
        let id = PolicySnapshotId::from_internal_object_id(body_id(&CryptoBodyIdentity, &body)?)?;
        Ok(Self { body, id })
    }

    /// Decodes a framed snapshot and re-derives its identity from the bytes.
    pub fn decode(frame: &[u8], limits: DecodeLimits) -> Result<Self, CodecRefusal> {
        Self::seal(decode_body::<PolicySnapshotBody>(frame, limits)?)
    }

    /// The snapshot's identity.
    #[must_use]
    pub const fn id(&self) -> PolicySnapshotId {
        self.id
    }

    /// The body.
    #[must_use]
    pub const fn body(&self) -> &PolicySnapshotBody {
        &self.body
    }

    /// The compiled policy.
    #[must_use]
    pub const fn policy(&self) -> &CompiledPolicy {
        self.body.policy()
    }

    /// The canonical body bytes the identity is computed over.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CodecRefusal> {
        canonical_body_bytes(&self.body)
    }

    /// The framed bytes, for storage or transfer.
    pub fn encode(&self) -> Result<Vec<u8>, CodecRefusal> {
        encode_body(&self.body)
    }
}

fn read_label<T>(
    input: &mut Decoder<'_>,
    field: &'static str,
    build: fn(&[u8]) -> Result<T, fgit_types::TypeRefusal>,
) -> Result<T, CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    build(bytes).map_err(CodecRefusal::from)
}

fn write_requirement(
    out: &mut Encoder,
    requirement: &EvidenceRequirement,
) -> Result<(), CodecRefusal> {
    out.write_text("evidence.kind", requirement.kind().as_str())?;
    out.write_text("evidence.issuer", requirement.issuer().as_str())?;
    out.write_option(requirement.max_age_seconds().as_ref(), |out, seconds| {
        out.write_scalar(*seconds);
        Ok(())
    })
}

fn read_requirement(input: &mut Decoder<'_>) -> Result<EvidenceRequirement, CodecRefusal> {
    let kind = read_label::<EvidenceKind>(input, "evidence.kind", EvidenceKind::try_new)?;
    let issuer = read_label::<IssuerLabel>(input, "evidence.issuer", IssuerLabel::try_new)?;
    let max_age_seconds = input.read_option("evidence.max_age", |input| {
        input.read_scalar::<u64>("evidence.max_age")
    })?;
    Ok(EvidenceRequirement::new(kind, issuer, max_age_seconds))
}

fn write_outcome(out: &mut Encoder, outcome: &RuleOutcome) -> Result<(), CodecRefusal> {
    match outcome {
        RuleOutcome::Allow => {
            out.write_raw_byte(1);
            Ok(())
        }
        RuleOutcome::Deny(reason) => {
            out.write_raw_byte(2);
            out.write_text("outcome.reason", reason.as_str())
        }
    }
}

fn read_outcome(input: &mut Decoder<'_>) -> Result<RuleOutcome, CodecRefusal> {
    let offset = input.offset();
    let tag = input.read_raw_byte("outcome.tag")?;
    match tag {
        1 => Ok(RuleOutcome::Allow),
        2 => {
            let reason = input.read_text("outcome.reason")?;
            Ok(RuleOutcome::Deny(DenyReason::new_truncating(reason)))
        }
        observed => Err(CodecRefusal::VariantUnknown {
            field: "outcome.tag",
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn write_rule(out: &mut Encoder, rule: &CompiledRule) -> Result<(), CodecRefusal> {
    out.write_text("rule.id", rule.id().as_str())?;
    write_predicate(out, rule.predicate(), 1)?;
    write_outcome(out, rule.outcome())
}

fn read_rule(input: &mut Decoder<'_>) -> Result<CompiledRule, CodecRefusal> {
    let id = read_label::<RuleId>(input, "rule.id", RuleId::try_new)?;
    let predicate = read_predicate(input, 1)?;
    let outcome = read_outcome(input)?;
    Ok(CompiledRule::new(id, predicate, outcome))
}

/// Predicate variant tags. Stable: a value here is a wire commitment.
mod tag {
    pub const ALWAYS: u8 = 1;
    pub const NEVER: u8 = 2;
    pub const ALL: u8 = 3;
    pub const ANY: u8 = 4;
    pub const NOT: u8 = 5;
    pub const TEXT_EQUALS: u8 = 6;
    pub const TEXT_IN: u8 = 7;
    pub const TEXT_MATCHES: u8 = 8;
    pub const UPDATE_KIND_EQUALS: u8 = 9;
    pub const UPDATE_KIND_IN: u8 = 10;
    pub const PRINCIPAL_KIND_EQUALS: u8 = 11;
    pub const PRINCIPAL_KIND_IN: u8 = 12;
    pub const AUTHENTICATION_COMPARE: u8 = 13;
    pub const LABEL_CONTAINS: u8 = 14;
    pub const FORCE_REQUESTED: u8 = 15;
    pub const AGGREGATE_COMPARE: u8 = 16;
    pub const EVIDENCE_ACCEPTED: u8 = 17;
}

fn depth_bound(depth: u32, offset: u64) -> Result<(), CodecRefusal> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(CodecRefusal::DepthBoundExceeded {
            limit: MAX_PREDICATE_DEPTH,
            offset,
        });
    }
    Ok(())
}

fn write_predicate(
    out: &mut Encoder,
    predicate: &Predicate,
    depth: u32,
) -> Result<(), CodecRefusal> {
    depth_bound(depth, u64::try_from(out.len()).unwrap_or(u64::MAX))?;
    match predicate {
        Predicate::Always => out.write_raw_byte(tag::ALWAYS),
        Predicate::Never => out.write_raw_byte(tag::NEVER),
        Predicate::ForceRequested => out.write_raw_byte(tag::FORCE_REQUESTED),
        Predicate::All(operands) => {
            out.write_raw_byte(tag::ALL);
            out.write_sequence("predicate.all", operands, |out, operand| {
                write_predicate(out, operand, depth + 1)
            })?;
        }
        Predicate::Any(operands) => {
            out.write_raw_byte(tag::ANY);
            out.write_sequence("predicate.any", operands, |out, operand| {
                write_predicate(out, operand, depth + 1)
            })?;
        }
        Predicate::Not(inner) => {
            out.write_raw_byte(tag::NOT);
            write_predicate(out, inner, depth + 1)?;
        }
        Predicate::TextEquals { selector, value } => {
            out.write_raw_byte(tag::TEXT_EQUALS);
            out.write_raw_byte(selector.code_point());
            out.write_text("predicate.text", value.as_str())?;
        }
        Predicate::TextIn { selector, values } => {
            out.write_raw_byte(tag::TEXT_IN);
            out.write_raw_byte(selector.code_point());
            out.write_canonical_set("predicate.text_set", values, |out, value| {
                out.write_text("predicate.text", value.as_str())
            })?;
        }
        Predicate::TextMatches { selector, pattern } => {
            out.write_raw_byte(tag::TEXT_MATCHES);
            out.write_raw_byte(selector.code_point());
            out.write_text("predicate.pattern", pattern.as_str())?;
        }
        Predicate::UpdateKindEquals(kind) => {
            out.write_raw_byte(tag::UPDATE_KIND_EQUALS);
            out.write_raw_byte(kind.code_point());
        }
        Predicate::UpdateKindIn(kinds) => {
            out.write_raw_byte(tag::UPDATE_KIND_IN);
            out.write_canonical_set("predicate.update_set", kinds, |out, kind| {
                out.write_raw_byte(kind.code_point());
                Ok(())
            })?;
        }
        Predicate::PrincipalKindEquals(kind) => {
            out.write_raw_byte(tag::PRINCIPAL_KIND_EQUALS);
            out.write_raw_byte(kind.code_point());
        }
        Predicate::PrincipalKindIn(kinds) => {
            out.write_raw_byte(tag::PRINCIPAL_KIND_IN);
            out.write_canonical_set("predicate.principal_set", kinds, |out, kind| {
                out.write_raw_byte(kind.code_point());
                Ok(())
            })?;
        }
        Predicate::AuthenticationCompare { operator, value } => {
            out.write_raw_byte(tag::AUTHENTICATION_COMPARE);
            out.write_raw_byte(operator.code_point());
            out.write_raw_byte(value.code_point());
        }
        Predicate::LabelContains { selector, label } => {
            out.write_raw_byte(tag::LABEL_CONTAINS);
            out.write_raw_byte(selector.code_point());
            out.write_text("predicate.label", label.as_str())?;
        }
        Predicate::AggregateCompare {
            name,
            operator,
            value,
        } => {
            out.write_raw_byte(tag::AGGREGATE_COMPARE);
            out.write_text("predicate.aggregate", name.as_str())?;
            out.write_raw_byte(operator.code_point());
            out.write_scalar(*value);
        }
        Predicate::EvidenceAccepted(kind) => {
            out.write_raw_byte(tag::EVIDENCE_ACCEPTED);
            out.write_text("predicate.evidence", kind.as_str())?;
        }
    }
    Ok(())
}

fn read_predicate(input: &mut Decoder<'_>, depth: u32) -> Result<Predicate, CodecRefusal> {
    let offset = input.offset();
    depth_bound(depth, offset)?;
    let tag = input.read_raw_byte("predicate.tag")?;
    match tag {
        tag::ALWAYS => Ok(Predicate::Always),
        tag::NEVER => Ok(Predicate::Never),
        tag::FORCE_REQUESTED => Ok(Predicate::ForceRequested),
        tag::ALL => Ok(Predicate::All(
            input.read_sequence("predicate.all", |input| read_predicate(input, depth + 1))?,
        )),
        tag::ANY => Ok(Predicate::Any(
            input.read_sequence("predicate.any", |input| read_predicate(input, depth + 1))?,
        )),
        tag::NOT => Ok(Predicate::Not(Box::new(read_predicate(input, depth + 1)?))),
        tag::TEXT_EQUALS => Ok(Predicate::TextEquals {
            selector: read_selector(input)?,
            value: TextLiteral::new(input.read_text("predicate.text")?),
        }),
        tag::TEXT_IN => {
            let selector = read_selector(input)?;
            let values = input.read_canonical_set("predicate.text_set", |input| {
                Ok(TextLiteral::new(input.read_text("predicate.text")?))
            })?;
            Ok(Predicate::TextIn { selector, values })
        }
        tag::TEXT_MATCHES => {
            let selector = read_selector(input)?;
            let written = input.read_text("predicate.pattern")?;
            let pattern =
                RefPattern::compile(written).map_err(|_| CodecRefusal::VariantUnknown {
                    field: "predicate.pattern",
                    observed: 0,
                    offset,
                })?;
            Ok(Predicate::TextMatches { selector, pattern })
        }
        tag::UPDATE_KIND_EQUALS => Ok(Predicate::UpdateKindEquals(read_update_kind(input)?)),
        tag::UPDATE_KIND_IN => Ok(Predicate::UpdateKindIn(
            input.read_canonical_set("predicate.update_set", read_update_kind)?,
        )),
        tag::PRINCIPAL_KIND_EQUALS => {
            Ok(Predicate::PrincipalKindEquals(read_principal_kind(input)?))
        }
        tag::PRINCIPAL_KIND_IN => Ok(Predicate::PrincipalKindIn(
            input.read_canonical_set("predicate.principal_set", read_principal_kind)?,
        )),
        tag::AUTHENTICATION_COMPARE => {
            let at = input.offset();
            let operator = Compare::from_code_point(input.read_raw_byte("predicate.operator")?)
                .ok_or(CodecRefusal::VariantUnknown {
                    field: "predicate.operator",
                    observed: 0,
                    offset: at,
                })?;
            let at = input.offset();
            let value =
                AuthenticationStrength::from_code_point(input.read_raw_byte("predicate.strength")?)
                    .ok_or(CodecRefusal::VariantUnknown {
                        field: "predicate.strength",
                        observed: 0,
                        offset: at,
                    })?;
            Ok(Predicate::AuthenticationCompare { operator, value })
        }
        tag::LABEL_CONTAINS => Ok(Predicate::LabelContains {
            selector: read_selector(input)?,
            label: read_label::<LabelName>(input, "predicate.label", LabelName::try_new)?,
        }),
        tag::AGGREGATE_COMPARE => {
            let name =
                read_label::<AggregateName>(input, "predicate.aggregate", AggregateName::try_new)?;
            let at = input.offset();
            let operator = Compare::from_code_point(input.read_raw_byte("predicate.operator")?)
                .ok_or(CodecRefusal::VariantUnknown {
                    field: "predicate.operator",
                    observed: 0,
                    offset: at,
                })?;
            let value = input.read_scalar::<u64>("predicate.value")?;
            Ok(Predicate::AggregateCompare {
                name,
                operator,
                value,
            })
        }
        tag::EVIDENCE_ACCEPTED => Ok(Predicate::EvidenceAccepted(read_label::<EvidenceKind>(
            input,
            "predicate.evidence",
            EvidenceKind::try_new,
        )?)),
        observed => Err(CodecRefusal::VariantUnknown {
            field: "predicate.tag",
            observed: u32::from(observed),
            offset,
        }),
    }
}

fn read_selector(input: &mut Decoder<'_>) -> Result<Selector, CodecRefusal> {
    let offset = input.offset();
    let code_point = input.read_raw_byte("predicate.selector")?;
    Selector::from_code_point(code_point).ok_or(CodecRefusal::VariantUnknown {
        field: "predicate.selector",
        observed: u32::from(code_point),
        offset,
    })
}

fn read_update_kind(input: &mut Decoder<'_>) -> Result<RefUpdateKind, CodecRefusal> {
    let offset = input.offset();
    let code_point = input.read_raw_byte("predicate.update_kind")?;
    RefUpdateKind::from_code_point(code_point).ok_or(CodecRefusal::VariantUnknown {
        field: "predicate.update_kind",
        observed: u32::from(code_point),
        offset,
    })
}

fn read_principal_kind(input: &mut Decoder<'_>) -> Result<PrincipalKind, CodecRefusal> {
    let offset = input.offset();
    let code_point = input.read_raw_byte("predicate.principal_kind")?;
    PrincipalKind::from_code_point(code_point).ok_or(CodecRefusal::VariantUnknown {
        field: "predicate.principal_kind",
        observed: u32::from(code_point),
        offset,
    })
}
