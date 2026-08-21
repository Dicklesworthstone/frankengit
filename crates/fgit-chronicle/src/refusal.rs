//! The one refusal a chronicle construction or verification can produce.

use core::fmt;
use fgit_types::{DecisionSequence, HeadGeneration, RepositorySequence};

/// Why a decision batch and authority head do not form a publishable pair.
///
/// Every variant names the exact position that disagrees, because a caller
/// that cannot see which sequence broke has to re-derive the whole batch to
/// find out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChronicleRefusal {
    /// A batch with no decisions consumes no sequence and publishes nothing.
    EmptyBatch,
    /// The decision sequence skipped or repeated a position.
    ///
    /// Decision sequence is gap-free across *all* terminal decisions,
    /// refusals included.
    DecisionSequenceNotContiguous {
        /// Zero-based index of the offending decision within the batch.
        index: usize,
        /// The position the batch order requires.
        expected: DecisionSequence,
        /// The position the decision carries.
        observed: DecisionSequence,
    },
    /// The batch does not continue the predecessor head's decision sequence.
    DecisionSequenceNotContinuing {
        /// The first position the predecessor leaves open.
        expected: DecisionSequence,
        /// The position the batch starts at.
        observed: DecisionSequence,
    },
    /// The repository sequence skipped or repeated a position.
    ///
    /// Repository sequence advances across committed records only, so a
    /// refusal must not consume one.
    RepositorySequenceNotContiguous {
        /// Zero-based index of the offending record within the batch.
        index: usize,
        /// The position the commit order requires.
        expected: RepositorySequence,
        /// The position the record carries.
        observed: RepositorySequence,
    },
    /// The batch does not continue the predecessor head's repository sequence.
    RepositorySequenceNotContinuing {
        /// The first position the predecessor leaves open.
        expected: RepositorySequence,
        /// The position the first commit record carries.
        observed: RepositorySequence,
    },
    /// The number of committed records does not match the committed decisions.
    ///
    /// Every `Committed` decision owns exactly one record and every record is
    /// owned by exactly one decision, so a mismatch means the batch is
    /// internally inconsistent before it is even encoded.
    CommitRecordCountMismatch {
        /// Decisions whose outcome is `Committed`.
        committed_decisions: usize,
        /// Commit records carried by the batch.
        records: usize,
    },
    /// A committed decision names a record the batch does not carry in order.
    CommitRecordNotBound {
        /// Zero-based index of the committed decision.
        index: usize,
    },
    /// A commit record's parent is not the record that precedes it.
    CommitRecordParentBroken {
        /// Zero-based index of the offending record.
        index: usize,
    },
    /// The batch claims a predecessor head that is not the basis it was built
    /// against.
    PredecessorHeadMismatch,
    /// The batch claims a predecessor generation that is not the basis's.
    PredecessorGenerationMismatch {
        /// The basis head's generation.
        expected: HeadGeneration,
        /// The generation the batch claims.
        observed: HeadGeneration,
    },
    /// The successor head does not strictly advance the generation.
    GenerationNotAdvancing {
        /// The predecessor generation.
        predecessor: HeadGeneration,
        /// The generation the successor claims.
        successor: HeadGeneration,
    },
    /// The successor head does not name the batch it publishes.
    DecisionTailNotBound,
    /// The successor head does not name its predecessor.
    SuccessorPredecessorNotBound,
    /// The successor head's latest decision position is not the batch tail.
    DecisionTailSequenceMismatch {
        /// The batch's last decision position.
        expected: DecisionSequence,
        /// The position the head claims.
        observed: Option<DecisionSequence>,
    },
    /// A batch that committed nothing advanced committed state anyway.
    ///
    /// A refusal consumes decision sequence but never advances repository
    /// sequence or the source and forge roots.
    RefusalOnlyBatchAdvancedCommittedState {
        /// Which committed-state field moved.
        field: &'static str,
    },
    /// A counter reached its ceiling; the repository cannot advance further.
    SequenceExhausted {
        /// Which counter ran out.
        counter: &'static str,
    },
    /// The batch and the head disagree about a resulting root.
    ResultingRootMismatch {
        /// Which root disagrees.
        field: &'static str,
    },
    /// The head belongs to a different repository than the batch.
    RepositoryMismatch,
}

impl fmt::Display for ChronicleRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::EmptyBatch => f.write_str("a decision batch must carry at least one decision"),
            Self::DecisionSequenceNotContiguous {
                index,
                expected,
                observed,
            } => write!(
                f,
                "decision {index} is at sequence {} but batch order requires {}",
                observed.get(),
                expected.get()
            ),
            Self::DecisionSequenceNotContinuing { expected, observed } => write!(
                f,
                "batch starts at decision sequence {} but the basis head leaves {} open",
                observed.get(),
                expected.get()
            ),
            Self::RepositorySequenceNotContiguous {
                index,
                expected,
                observed,
            } => write!(
                f,
                "commit record {index} is at repository sequence {} but commit order requires {}",
                observed.get(),
                expected.get()
            ),
            Self::RepositorySequenceNotContinuing { expected, observed } => write!(
                f,
                "batch commits start at repository sequence {} but the basis head leaves {} open",
                observed.get(),
                expected.get()
            ),
            Self::CommitRecordCountMismatch {
                committed_decisions,
                records,
            } => write!(
                f,
                "{committed_decisions} committed decisions but {records} commit records"
            ),
            Self::CommitRecordNotBound { index } => {
                write!(f, "committed decision {index} does not name its record")
            }
            Self::CommitRecordParentBroken { index } => {
                write!(f, "commit record {index} does not name its predecessor")
            }
            Self::PredecessorHeadMismatch => {
                f.write_str("the batch was not prepared against this basis head")
            }
            Self::PredecessorGenerationMismatch { expected, observed } => write!(
                f,
                "batch claims predecessor generation {} but the basis is {}",
                observed.get(),
                expected.get()
            ),
            Self::GenerationNotAdvancing {
                predecessor,
                successor,
            } => write!(
                f,
                "successor generation {} does not strictly advance {}",
                successor.get(),
                predecessor.get()
            ),
            Self::DecisionTailNotBound => {
                f.write_str("the successor head does not name the batch it publishes")
            }
            Self::SuccessorPredecessorNotBound => {
                f.write_str("the successor head does not name its predecessor")
            }
            Self::DecisionTailSequenceMismatch { expected, observed } => write!(
                f,
                "successor head claims latest decision {:?} but the batch ends at {}",
                observed.map(DecisionSequence::get),
                expected.get()
            ),
            Self::RefusalOnlyBatchAdvancedCommittedState { field } => write!(
                f,
                "a batch that committed nothing advanced {field}; refusals consume decision sequence only"
            ),
            Self::SequenceExhausted { counter } => {
                write!(f, "{counter} is exhausted; the repository cannot advance")
            }
            Self::ResultingRootMismatch { field } => {
                write!(f, "batch and head disagree about {field}")
            }
            Self::RepositoryMismatch => {
                f.write_str("the head and the batch govern different repositories")
            }
        }
    }
}

impl std::error::Error for ChronicleRefusal {}
