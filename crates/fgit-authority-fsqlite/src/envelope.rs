//! The declared concurrency envelope, and the refusal that keeps it honest.
//!
//! §3.5 of the integration profile publishes an explicit support matrix and
//! then says the thing that matters: *"The reviewed upstream contract does not
//! yet support a blanket claim for ten or more concurrent implicit-autocommit
//! writers. `FrankenGit` therefore caps/admission-controls its writer topology to
//! a proven envelope or waits for the upstream four-scenario gate; it does not
//! extrapolate from smaller tests."*
//!
//! Extrapolation is the failure mode this module exists to prevent, and a
//! comment saying "do not extrapolate" would not have prevented it. A topology
//! outside the proven envelope is **refused at admission** — before any
//! connection is opened — so an unsupported writer count fails loudly at
//! configuration time rather than quietly at the ninety-ninth percentile.
//!
//! The bound is a claim about evidence, not about the engine's capability. It
//! moves when the upstream gate produces evidence, and the way to move it is to
//! change [`MAX_ADMITTED_AUTOCOMMIT_WRITERS`] here, in one place, with that
//! evidence in the commit.

/// The largest number of concurrent implicit-autocommit writers the reviewed
/// upstream contract supports.
///
/// §3.5 withholds the blanket claim at ten or more, so the admitted envelope
/// stops below it. This is a bound on what we have evidence for.
pub const MAX_ADMITTED_AUTOCOMMIT_WRITERS: u32 = 9;

/// A requested writer and connection topology.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WriterTopology {
    /// Connections the lane intends to hold open.
    pub connections: u32,
    /// Concurrent writers among them.
    pub writers: u32,
    /// Whether writers run in implicit autocommit rather than explicit
    /// transactions.
    ///
    /// The distinction matters: §3.5's withheld claim is specifically about
    /// implicit-autocommit writers.
    pub implicit_autocommit: bool,
    /// Whether more than one process writes the same database.
    pub multi_process: bool,
}

impl WriterTopology {
    /// One connection, one writer: the profile's first admitted scenario.
    pub const SINGLE_WRITER: Self = Self {
        connections: 1,
        writers: 1,
        implicit_autocommit: false,
        multi_process: false,
    };

    /// Several connections with readers plus a bounded writer count.
    #[must_use]
    pub const fn bounded_writers(connections: u32, writers: u32) -> Self {
        Self {
            connections,
            writers,
            implicit_autocommit: false,
            multi_process: false,
        }
    }
}

/// Why a topology is outside the admitted envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnvelopeRefusal {
    /// A lane with no connection cannot serve anything.
    NoConnection,
    /// More writers than connections cannot each hold one.
    ///
    /// A raw `Connection` is `!Send` and stays on its owning worker (§3.3), so
    /// writers cannot share one.
    WritersExceedConnections {
        /// Writers requested.
        writers: u32,
        /// Connections requested.
        connections: u32,
    },
    /// The implicit-autocommit writer count is beyond the reviewed evidence.
    AutocommitWritersUnproven {
        /// Writers requested.
        writers: u32,
        /// The largest count the upstream review supports.
        admitted: u32,
    },
    /// Multi-process writing is limited to the exact tested profile.
    ///
    /// §3.5 restricts multi-process writer and checkpoint claims to what was
    /// tested, and a multi-writer multi-process topology is not in that set.
    MultiProcessWritersUnproven {
        /// Writers requested.
        writers: u32,
    },
}

impl core::fmt::Display for EnvelopeRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::NoConnection => f.write_str("a lane needs at least one connection"),
            Self::WritersExceedConnections {
                writers,
                connections,
            } => write!(
                f,
                "{writers} writers cannot share {connections} connections; a raw connection \
                 is not Send and stays on its owning worker"
            ),
            Self::AutocommitWritersUnproven { writers, admitted } => write!(
                f,
                "{writers} concurrent implicit-autocommit writers exceeds the {admitted} the \
                 reviewed upstream contract supports; this is refused rather than extrapolated"
            ),
            Self::MultiProcessWritersUnproven { writers } => write!(
                f,
                "multi-process writing with {writers} writers is outside the exact tested \
                 profile; single-writer multi-process is the admitted shape"
            ),
        }
    }
}

impl std::error::Error for EnvelopeRefusal {}

/// A topology that passed admission.
///
/// Constructible only by [`ConcurrencyEnvelope::admit`], so a lane cannot be
/// opened against a topology nobody checked.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConcurrencyEnvelope {
    topology: WriterTopology,
}

impl ConcurrencyEnvelope {
    /// Admit a topology, or refuse it with the reason.
    pub const fn admit(topology: WriterTopology) -> Result<Self, EnvelopeRefusal> {
        if topology.connections == 0 {
            return Err(EnvelopeRefusal::NoConnection);
        }
        if topology.writers > topology.connections {
            return Err(EnvelopeRefusal::WritersExceedConnections {
                writers: topology.writers,
                connections: topology.connections,
            });
        }
        if topology.multi_process && topology.writers > 1 {
            return Err(EnvelopeRefusal::MultiProcessWritersUnproven {
                writers: topology.writers,
            });
        }
        if topology.implicit_autocommit && topology.writers > MAX_ADMITTED_AUTOCOMMIT_WRITERS {
            return Err(EnvelopeRefusal::AutocommitWritersUnproven {
                writers: topology.writers,
                admitted: MAX_ADMITTED_AUTOCOMMIT_WRITERS,
            });
        }
        Ok(Self { topology })
    }

    /// The admitted topology.
    #[must_use]
    pub const fn topology(self) -> WriterTopology {
        self.topology
    }

    /// How many dedicated workers the lane must own.
    ///
    /// One per connection: §3.3 pins a raw connection to its worker, so the
    /// worker count is not a tuning knob.
    #[must_use]
    pub const fn required_workers(self) -> u32 {
        self.topology.connections
    }
}
