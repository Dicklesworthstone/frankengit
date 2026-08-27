#![forbid(unsafe_code)]
//! FG-060: Provenance graph and attestation chain querying (§30.7).
//!
//! # Provenance chain discipline
//!
//! ```text
//! source authority head / RCR
//!  -> BuildInputCapsule
//!  -> workflow / job / check receipt
//!  -> artifact / SBOM / signature
//!  -> package or release manifest
//!  -> deployment / consumption attestation
//! ```
//!
//! The provenance graph is queryable end-to-end, but every edge names its exact
//! evidence class. A verifier holding a release manifest or package version can traverse
//! the authenticated graph back to the exact source commit RCR that produced it,
//! verifying each cryptographic link.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use fgit_crypto::{DigestHasher, Sha256Hasher};
use fgit_types::{Digest, DigestAlgorithmId, DigestBytes, SchemaFamily, SchemaId};

fn digest_from_hasher(hasher: Sha256Hasher) -> Digest {
    let raw = DigestHasher::finish(hasher);
    let bytes = DigestBytes::try_new(&raw).expect("32 bytes is valid digest length");
    Digest::new(
        DigestAlgorithmId::try_new(2).expect("SHA-256 is code point 2"),
        bytes,
    )
}

use crate::artifact::ArtifactPayloadKind;

/// Schema ID for provenance chain receipts.
pub const PROVENANCE_RECEIPT_SCHEMA: SchemaId = SchemaId::new(
    SchemaFamily::from_static("frankengit.provenance-receipt"),
    1,
    0,
);

/// Evidence classification bound to each provenance relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EvidenceClass {
    /// E1: Deterministic derivation (pure function from inputs to outputs).
    E1DeterministicDerivation = 1,
    /// E2: Measured runtime usage / accounting receipt.
    E2MeasuredUsage = 2,
    /// E3: Pinned differential oracle comparison.
    E3DifferentialOracle = 3,
    /// E4: Cryptographic signed attestation / certificate.
    E4SignedAttestation = 4,
}

impl EvidenceClass {
    /// Wire code for this evidence class.
    #[must_use]
    pub const fn wire_code(self) -> u8 {
        self as u8
    }

    /// Descriptive label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::E1DeterministicDerivation => "E1_deterministic_derivation",
            Self::E2MeasuredUsage => "E2_measured_usage",
            Self::E3DifferentialOracle => "E3_differential_oracle",
            Self::E4SignedAttestation => "E4_signed_attestation",
        }
    }
}

impl fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A node in the provenance graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProvenanceNode {
    /// Source repository commit RCR / authority head.
    SourceCommit(Digest),
    /// Build input capsule from runner (§34).
    BuildCapsule(Digest),
    /// Check outcome / job execution receipt.
    CheckReceipt(Digest),
    /// Artifact payload or SBOM or signature.
    Artifact {
        artifact_id: Digest,
        kind: ArtifactPayloadKind,
    },
    /// Release manifest or package version.
    ReleaseManifest(Digest),
    /// External deployment or consumer attestation.
    Attestation(Digest),
}

impl ProvenanceNode {
    /// The unique digest representing this node's identity.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        match self {
            Self::SourceCommit(d)
            | Self::BuildCapsule(d)
            | Self::CheckReceipt(d)
            | Self::Artifact { artifact_id: d, .. }
            | Self::ReleaseManifest(d)
            | Self::Attestation(d) => d,
        }
    }

    /// Short descriptive label.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::SourceCommit(_) => "source_commit",
            Self::BuildCapsule(_) => "build_capsule",
            Self::CheckReceipt(_) => "check_receipt",
            Self::Artifact { .. } => "artifact",
            Self::ReleaseManifest(_) => "release_manifest",
            Self::Attestation(_) => "attestation",
        }
    }
}

impl fmt::Display for ProvenanceNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}({:?})", self.kind_label(), self.digest())
    }
}

/// A directed edge in the provenance graph from upstream input to downstream output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProvenanceEdge {
    pub from: ProvenanceNode,
    pub to: ProvenanceNode,
    pub evidence_class: EvidenceClass,
    pub description: String,
}

/// Directed Acyclic Graph (DAG) storing verified provenance relationships.
#[derive(Debug, Default, Clone)]
pub struct ProvenanceGraph {
    /// Outgoing edges: from -> [edges where from is source]
    outgoing: BTreeMap<Digest, Vec<ProvenanceEdge>>,
    /// Incoming edges: to -> [edges where to is destination]
    incoming: BTreeMap<Digest, Vec<ProvenanceEdge>>,
    /// Registered nodes: digest -> node
    nodes: BTreeMap<Digest, ProvenanceNode>,
}

impl ProvenanceGraph {
    /// Creates a new empty provenance graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a node into the graph.
    pub fn insert_node(&mut self, node: ProvenanceNode) {
        self.nodes.insert(*node.digest(), node);
    }

    /// Adds a verified provenance edge between two nodes.
    pub fn add_edge(
        &mut self,
        from: ProvenanceNode,
        to: ProvenanceNode,
        evidence_class: EvidenceClass,
        description: impl Into<String>,
    ) -> Result<(), ProvenanceError> {
        let from_digest = *from.digest();
        let to_digest = *to.digest();

        if from_digest == to_digest {
            return Err(ProvenanceError::SelfLoopForbidden(from_digest));
        }

        self.nodes.insert(from_digest, from.clone());
        self.nodes.insert(to_digest, to.clone());

        let edge = ProvenanceEdge {
            from,
            to,
            evidence_class,
            description: description.into(),
        };

        self.outgoing
            .entry(from_digest)
            .or_default()
            .push(edge.clone());
        self.incoming.entry(to_digest).or_default().push(edge);

        Ok(())
    }

    /// Queries the upstream ancestry chain leading up to a target node.
    pub fn query_upstream_chain(
        &self,
        target_digest: &Digest,
    ) -> Result<Vec<ProvenanceEdge>, ProvenanceError> {
        if !self.nodes.contains_key(target_digest) {
            return Err(ProvenanceError::NodeNotFound(*target_digest));
        }

        let mut visited = BTreeSet::new();
        let mut edges = Vec::new();
        let mut queue = vec![*target_digest];

        while let Some(current) = queue.pop() {
            if visited.insert(current)
                && let Some(incoming_edges) = self.incoming.get(&current)
            {
                for edge in incoming_edges {
                    edges.push(edge.clone());
                    queue.push(*edge.from.digest());
                }
            }
        }

        Ok(edges)
    }

    /// Verifies that a target node (e.g. `ReleaseManifest`) has an unbroken,
    /// authenticated provenance trail back to an expected source commit RCR.
    pub fn verify_provenance_closure(
        &self,
        target: &Digest,
        expected_source_rcr: &Digest,
    ) -> Result<ProvenanceVerificationReceipt, ProvenanceError> {
        let chain = self.query_upstream_chain(target)?;

        let mut has_source_rcr = false;
        let mut checked_nodes = BTreeSet::new();
        checked_nodes.insert(*target);

        for edge in &chain {
            checked_nodes.insert(*edge.from.digest());
            checked_nodes.insert(*edge.to.digest());
            if let ProvenanceNode::SourceCommit(rcr) = &edge.from
                && rcr == expected_source_rcr
            {
                has_source_rcr = true;
            }
        }

        if !has_source_rcr {
            return Err(ProvenanceError::BrokenProvenanceChain {
                target: *target,
                expected_source: *expected_source_rcr,
            });
        }

        let receipt_digest = Self::compute_receipt_digest(target, expected_source_rcr, &chain);

        Ok(ProvenanceVerificationReceipt {
            target_digest: *target,
            source_rcr: *expected_source_rcr,
            edge_count: chain.len() as u32,
            unique_nodes_count: checked_nodes.len() as u32,
            receipt_digest,
        })
    }

    fn compute_receipt_digest(
        target: &Digest,
        source: &Digest,
        edges: &[ProvenanceEdge],
    ) -> Digest {
        let mut hasher = Sha256Hasher::new();
        DigestHasher::update(&mut hasher, b"frankengit/provenance-receipt/v1\0");
        DigestHasher::update(&mut hasher, target.bytes().as_bytes());
        DigestHasher::update(&mut hasher, source.bytes().as_bytes());
        DigestHasher::update(&mut hasher, &(edges.len() as u32).to_be_bytes());
        for edge in edges {
            DigestHasher::update(&mut hasher, edge.from.digest().bytes().as_bytes());
            DigestHasher::update(&mut hasher, edge.to.digest().bytes().as_bytes());
            DigestHasher::update(&mut hasher, &[edge.evidence_class.wire_code()]);
        }
        digest_from_hasher(hasher)
    }
}

/// Verified audit receipt proving end-to-end provenance integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceVerificationReceipt {
    pub target_digest: Digest,
    pub source_rcr: Digest,
    pub edge_count: u32,
    pub unique_nodes_count: u32,
    pub receipt_digest: Digest,
}

/// Typed errors/refusals for provenance operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    SelfLoopForbidden(Digest),
    NodeNotFound(Digest),
    BrokenProvenanceChain {
        target: Digest,
        expected_source: Digest,
    },
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfLoopForbidden(d) => {
                write!(f, "self loops forbidden in provenance DAG: {d:?}")
            }
            Self::NodeNotFound(d) => write!(f, "node {d:?} not found in provenance graph"),
            Self::BrokenProvenanceChain {
                target,
                expected_source,
            } => write!(
                f,
                "broken provenance chain: target {target:?} does not trace back to expected source {expected_source:?}"
            ),
        }
    }
}

impl std::error::Error for ProvenanceError {}
