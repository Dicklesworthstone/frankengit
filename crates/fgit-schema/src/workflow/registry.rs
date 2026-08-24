//! The construct registry: what the subset accepts, and why it refuses the rest.
//!
//! ADR-0008 D12 forbids blanket compatibility claims and requires a measured
//! per-construct registry instead. This is that registry. It is the **single**
//! place a construct's status is stated: the lowerer looks a construct up here
//! when it refuses, so a refusal and the published table cannot disagree, and
//! `tests/workflow.rs::every_construct_the_lowerer_names_exists_in_the_registry`
//! fails if the lowerer ever names a construct the registry does not carry.
//!
//! The table is also emitted as a generated artifact, so a consumer reads the
//! same facts a reviewer does rather than a prose summary of them.

/// How the subset treats one construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConstructStatus {
    /// Accepted and lowered as written.
    Accepted,
    /// Accepted after a documented normalization, so two equivalent spellings
    /// produce byte-identical graphs.
    Normalized,
    /// Outside the subset and refused by name.
    Unsupported,
    /// Refused because its meaning is not settled enough to implement.
    ///
    /// Distinct from [`Self::Unsupported`] on purpose: unsupported is work
    /// nobody has done, ambiguous is work nobody should do until the semantics
    /// are pinned. Collapsing them would hide the second behind the first.
    Ambiguous,
}

impl ConstructStatus {
    /// Stable lowercase name used in generated artifacts.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Normalized => "normalized",
            Self::Unsupported => "unsupported",
            Self::Ambiguous => "ambiguous",
        }
    }

    /// Whether a document containing this construct is refused.
    #[must_use]
    pub const fn refuses(self) -> bool {
        matches!(self, Self::Unsupported | Self::Ambiguous)
    }
}

/// One row of the compatibility registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Construct {
    /// Stable dotted key, used in refusals and in generated artifacts.
    pub key: &'static str,
    /// How the subset treats it.
    pub status: ConstructStatus,
    /// Why. For a refusal this is the text the author sees.
    pub reason: &'static str,
}

/// Every construct the subset has an opinion about, in key order.
///
/// Key order is enforced by
/// `tests/workflow.rs::the_construct_registry_is_sorted_complete_and_reasoned`
/// rather than by convention, so the emitted artifact is stable and a new row
/// cannot be appended somewhere that changes the output of unrelated rows.
pub static CONSTRUCTS: &[Construct] = &[
    Construct {
        key: "job.container",
        status: ConstructStatus::Unsupported,
        reason: "selects an execution image, which is an isolation decision AGENTS.md 9 puts outside workflow YAML",
    },
    Construct {
        key: "job.continue-on-error",
        status: ConstructStatus::Unsupported,
        reason: "turns a failed job into a passing one, which is gate self-weakening expressed as configuration",
    },
    Construct {
        key: "job.environment",
        status: ConstructStatus::Unsupported,
        reason: "names a deployment target with its own protection rules; the rules, not the name, are the authority",
    },
    Construct {
        key: "job.if",
        status: ConstructStatus::Ambiguous,
        reason: "expression truthiness has several context-dependent coercions; refusing beats guessing which one a reader meant",
    },
    Construct {
        key: "job.needs",
        status: ConstructStatus::Accepted,
        reason: "accepted as a scalar or a sequence of job identifiers; unknown names and cycles are refused",
    },
    Construct {
        key: "job.outputs",
        status: ConstructStatus::Unsupported,
        reason: "output values come from expressions, and expressions are not evaluated by this lowering",
    },
    Construct {
        key: "job.permissions",
        status: ConstructStatus::Unsupported,
        reason: "grants capability from YAML; AGENTS.md 9 says text may not widen capabilities",
    },
    Construct {
        key: "job.runs-on",
        status: ConstructStatus::Accepted,
        reason: "a single runner label, as a plain scalar",
    },
    Construct {
        key: "job.services",
        status: ConstructStatus::Unsupported,
        reason: "starts side-car containers, which is the same isolation decision as job.container",
    },
    Construct {
        key: "job.steps",
        status: ConstructStatus::Accepted,
        reason: "a sequence of steps, in source order, which is execution order",
    },
    Construct {
        key: "job.strategy",
        status: ConstructStatus::Unsupported,
        reason: "matrix expansion multiplies jobs, and the expansion order and identifier derivation need their own bead",
    },
    Construct {
        key: "job.timeout-minutes",
        status: ConstructStatus::Unsupported,
        reason: "a budget belongs to the effect broker's reservation, not to a YAML field the runner may ignore",
    },
    Construct {
        key: "step.if",
        status: ConstructStatus::Ambiguous,
        reason: "same expression semantics as job.if",
    },
    Construct {
        key: "step.name",
        status: ConstructStatus::Accepted,
        reason: "a display label; it carries no meaning for execution",
    },
    Construct {
        key: "step.run",
        status: ConstructStatus::Accepted,
        reason: "the command line, preserved verbatim; the lowering does not interpret shell syntax",
    },
    Construct {
        key: "step.uses",
        status: ConstructStatus::Unsupported,
        reason: "runs a third-party action, which is correctness logic living in YAML rather than in a repository-owned command (AGENTS.md 12)",
    },
    Construct {
        key: "step.with",
        status: ConstructStatus::Unsupported,
        reason: "only meaningful as arguments to step.uses, which is refused",
    },
    Construct {
        key: "workflow.concurrency",
        status: ConstructStatus::Unsupported,
        reason: "a concurrency group cancels in-flight runs, and cancellation semantics are request-drain-finalize rather than a YAML string",
    },
    Construct {
        key: "workflow.env",
        status: ConstructStatus::Unsupported,
        reason: "workflow-level environment leaks into every step invisibly; the subset requires a step to state what it needs",
    },
    Construct {
        key: "workflow.jobs",
        status: ConstructStatus::Accepted,
        reason: "a mapping of job identifier to job; identifiers must be unique",
    },
    Construct {
        key: "workflow.name",
        status: ConstructStatus::Accepted,
        reason: "a plain scalar display name",
    },
    Construct {
        key: "workflow.on",
        status: ConstructStatus::Accepted,
        reason: "accepted as a scalar or a sequence of trigger names, normalized to a sorted deduplicated list",
    },
    Construct {
        key: "workflow.secrets",
        status: ConstructStatus::Unsupported,
        reason: "a secret reference in YAML is a capability grant; AGENTS.md 9 keeps that out of untrusted text",
    },
    Construct {
        key: "yaml.alias",
        status: ConstructStatus::Unsupported,
        reason: "an alias lets one node be reached twice, so a bounded node count cannot bound the expanded document",
    },
    Construct {
        key: "yaml.anchor",
        status: ConstructStatus::Unsupported,
        reason: "an anchor only exists to be aliased, and aliases are refused",
    },
    Construct {
        key: "yaml.block-mapping",
        status: ConstructStatus::Accepted,
        reason: "the only mapping form in the subset; entries keep source order",
    },
    Construct {
        key: "yaml.block-scalar",
        status: ConstructStatus::Unsupported,
        reason: "the folding and chomping indicators have several spellings with subtly different results, so accepting them would mean accepting an ambiguity",
    },
    Construct {
        key: "yaml.block-sequence",
        status: ConstructStatus::Accepted,
        reason: "the only sequence form in the subset; items keep source order",
    },
    Construct {
        key: "yaml.comment",
        status: ConstructStatus::Accepted,
        reason: "discarded after scanning; it cannot carry meaning, so dropping it is not a silent drop of content",
    },
    Construct {
        key: "yaml.document-marker",
        status: ConstructStatus::Unsupported,
        reason: "a workflow is one document; --- and ... would make the file's meaning depend on which document a reader picked",
    },
    Construct {
        key: "yaml.double-quoted",
        status: ConstructStatus::Normalized,
        reason: "accepted with backslash escapes resolved, so a quoted and an equivalent plain scalar lower to the same bytes",
    },
    Construct {
        key: "yaml.flow-mapping",
        status: ConstructStatus::Unsupported,
        reason: "flow style admits nesting without indentation, which defeats the depth limit the scanner relies on",
    },
    Construct {
        key: "yaml.flow-sequence",
        status: ConstructStatus::Unsupported,
        reason: "same as flow mappings: depth without indentation",
    },
    Construct {
        key: "yaml.merge-key",
        status: ConstructStatus::Unsupported,
        reason: "<< depends on aliases, and it makes a key's value depend on a node declared elsewhere",
    },
    Construct {
        key: "yaml.plain-scalar",
        status: ConstructStatus::Accepted,
        reason: "trailing whitespace is stripped; no type inference is performed, so 'on' stays the string \"on\"",
    },
    Construct {
        key: "yaml.single-quoted",
        status: ConstructStatus::Normalized,
        reason: "accepted with '' resolved to a single quote, the only escape the form has",
    },
    Construct {
        key: "yaml.tab-indent",
        status: ConstructStatus::Unsupported,
        reason: "YAML forbids tabs in indentation, and accepting them would make depth depend on a renderer's tab width",
    },
    Construct {
        key: "yaml.tag",
        status: ConstructStatus::Unsupported,
        reason: "an explicit tag selects a type resolver, and the subset performs no type resolution at all",
    },
];

/// The registry row for a construct key.
///
/// Returns `None` only for a key the registry does not carry, which is a
/// programming error rather than an input error — the lowerer must only name
/// keys that exist, and a test enforces that.
#[must_use]
pub fn lookup(key: &str) -> Option<&'static Construct> {
    CONSTRUCTS.iter().find(|entry| entry.key == key)
}

/// The reason text for a refused construct.
///
/// Panics if the key is absent, because that is a bug in this crate rather
/// than something a workflow author can cause.
#[must_use]
pub fn reason_for(key: &'static str) -> &'static str {
    lookup(key).map_or("unregistered construct", |entry| entry.reason)
}

/// Counts by status, for the generated artifact and for reporting.
#[must_use]
pub fn tally() -> [(ConstructStatus, usize); 4] {
    let mut accepted = 0;
    let mut normalized = 0;
    let mut unsupported = 0;
    let mut ambiguous = 0;
    for entry in CONSTRUCTS {
        match entry.status {
            ConstructStatus::Accepted => accepted += 1,
            ConstructStatus::Normalized => normalized += 1,
            ConstructStatus::Unsupported => unsupported += 1,
            ConstructStatus::Ambiguous => ambiguous += 1,
        }
    }
    [
        (ConstructStatus::Accepted, accepted),
        (ConstructStatus::Normalized, normalized),
        (ConstructStatus::Unsupported, unsupported),
        (ConstructStatus::Ambiguous, ambiguous),
    ]
}
