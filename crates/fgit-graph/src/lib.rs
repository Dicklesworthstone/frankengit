#![forbid(unsafe_code)]
//! Immutable, position-bound graph generations and deterministic exact graph algorithms.
//!
//! This crate owns the graph half of the generation contract shared with search:
//! a generation body is immutable, activation is an authority-head CAS against
//! its exact predecessor, and an unresolved CAS is never interpreted as a
//! negative result.  The algorithm surface is deliberately bounded and uses
//! sorted maps/sets for every observable choice, so no result or witness can
//! depend on hash-table or scheduler order.

mod algorithms;
mod architecture;
mod generation;
mod temporal;

pub use crate::algorithms::{
    AdvisoryRank, ArticulationBridgeReport, BetweennessCentrality, BipartiteMatching,
    ComplexityTerm, CriticalPath, DeterministicGraph, FlowCost, GraphAlgorithm, GraphBuilder,
    GraphBuilderError, GraphDecision, GraphDecisionWitness, GraphEdge, GraphLimits, GraphNodeId,
    GraphQuery, GraphRefusal, GraphResult, GraphSnapshot, GraphViewPolicy, HitsConfig, HitsScores,
    KShortestPaths, MinCostFlow, MinCostFlowRequest, MinimumCut, PageRankConfig,
    PersonalizedPageRank, RationalScore, Reachability, SetCover, SetCoverCandidate,
    SetCoverRequest, ShortestPath, SteinerTree, StronglyConnectedComponents, TopologicalOrder,
};
pub use crate::architecture::{
    ArchitecturalDriftReport, ArchitectureAdvisoryFence, ArchitectureAlgorithm,
    ArchitectureAnalysis, ArchitectureDecisionWitness, ArchitectureLimits, ArchitectureProposal,
    ArchitectureRefusal, CommunityBoundary, CommunityPartitionProposal, CoreDecompositionProposal,
    CoreMembership, FeedbackEdgeSetProposal, TransitiveReductionProposal,
};
pub use crate::generation::{
    BuilderProfileId, ExactGraphGeneration, GenerationActivation, GenerationAuthority,
    GenerationAuthorityError, GraphAuthorityClass, GraphAuthorityClassRefusal, GraphGenerationBody,
    GraphGenerationId, GraphSchemaId, GraphSourceStamp, GraphViewId,
};
pub use crate::temporal::{
    BranchAgentOverlay, CrossTimeJoinPolicy, CrossTimeJoinReceipt, CrossTimeJoinRequest,
    ModelEpoch, TemporalCrossTimeJoin, TemporalEdge, TemporalGraphCatalog, TemporalGraphGeneration,
    TemporalGraphLimits, TemporalGraphRefusal, TemporalGraphView, TemporalNode,
    TemporalOverlayRowKind, TemporalPosition, TemporalProjection, TemporalQueryMode,
    TemporalQueryResult, TemporalRowKind, TemporalValidity,
};
