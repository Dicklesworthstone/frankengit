//! Staged multi-output publication with all-or-nothing commit.
//!
//! Rendering many surfaces from one document is a transaction, not a loop.
//! Plan section 28.5 requires that multi-output rendering stage every sibling
//! and then publish atomically or roll them back, and the deep-dive synthesis
//! adds the preflight step: name aliases and collisions are caught *before*
//! anything is produced, not discovered halfway through.
//!
//! The obligation is typed and explicit:
//!
//! - **Reserved** — [`stage`] rendered every requested surface into memory. If
//!   any one of them refused, nothing is reserved and the refusal is returned;
//!   there is no partially staged reservation.
//! - **Committed** — [`OutputReservation::commit_with`] handed every body to
//!   the host writer and every write succeeded. The receipt names what was
//!   published.
//! - **Aborted** — either [`OutputReservation::abort`], or a host write failed
//!   and every already-written sibling was rolled back. Either way no output
//!   survives.
//!
//! This crate holds no ambient authority, so the actual write and the actual
//! undo are host effects passed in as closures. What this module owns is the
//! protocol: the ordering, the all-or-nothing boundary, and the receipt. A
//! rollback that itself fails is reported as a containment failure rather than
//! swallowed, because a half-undone publication is exactly the state an
//! operator must be told about.

use core::fmt;

use crate::ast::Document;
use crate::limits::{Limits, Refusal, RefusalKind, as_u64};
use crate::render::{RenderProfile, Rendered, render};

/// Longest accepted output name.
const MAX_OUTPUT_NAME_BYTES: usize = 200;

/// Most outputs one reservation may carry.
const MAX_OUTPUTS: usize = 64;

/// A host-meaningful name for one output of a multi-output render.
///
/// The charset is deliberately narrow: a name reaches a host that will very
/// likely turn it into a path, so anything that could traverse, alias, or hide
/// is refused here rather than trusted there.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputName(Box<str>);

impl OutputName {
    /// Accepts a name, refusing one that is empty, too long, or path-unsafe.
    pub fn new(name: &str) -> Result<Self, Refusal> {
        if name.is_empty() || name.len() > MAX_OUTPUT_NAME_BYTES {
            return Err(Refusal::exceeded(
                RefusalKind::OutputNameInvalid,
                as_u64(MAX_OUTPUT_NAME_BYTES),
                as_u64(name.len()),
            ));
        }
        let usable = name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            && !name.starts_with('.')
            && !name.contains("..");
        if !usable {
            return Err(Refusal::precondition(RefusalKind::OutputNameInvalid));
        }
        Ok(Self(Box::from(name)))
    }

    /// The accepted name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OutputName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One requested surface of a multi-output render.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRequest {
    /// Host-meaningful name for this output.
    pub name: OutputName,
    /// Which surface to render.
    pub profile: RenderProfile,
}

impl OutputRequest {
    /// Builds a request, validating the name.
    pub fn new(name: &str, profile: RenderProfile) -> Result<Self, Refusal> {
        Ok(Self {
            name: OutputName::new(name)?,
            profile,
        })
    }
}

/// One rendered surface, staged and not yet published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedOutput {
    name: OutputName,
    rendered: Rendered,
}

impl StagedOutput {
    /// The output's host-meaningful name.
    #[must_use]
    pub const fn name(&self) -> &OutputName {
        &self.name
    }

    /// The rendered body.
    #[must_use]
    pub const fn rendered(&self) -> &Rendered {
        &self.rendered
    }

    /// The rendered body as text.
    #[must_use]
    pub fn body(&self) -> &str {
        self.rendered.as_str()
    }
}

/// Every requested surface, rendered and awaiting a terminal decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputReservation {
    staged: Vec<StagedOutput>,
}

/// What a successful commit published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    published: Vec<OutputName>,
}

impl CommitReceipt {
    /// Names published, in commit order.
    #[must_use]
    pub fn published(&self) -> &[OutputName] {
        &self.published
    }
}

/// What an explicit abort discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbortReceipt {
    discarded: Vec<OutputName>,
}

impl AbortReceipt {
    /// Names discarded without ever being published.
    #[must_use]
    pub fn discarded(&self) -> &[OutputName] {
        &self.discarded
    }
}

/// What a failed commit rolled back, and whether the rollback itself held.
///
/// `contained` is the question an operator actually needs answered: if it is
/// false, some sibling may still exist on the host and the publication is in a
/// state this crate could not undo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackReceipt<E> {
    failed: OutputName,
    cause: E,
    rolled_back: Vec<OutputName>,
    rollback_failures: Vec<(OutputName, E)>,
}

impl<E> RollbackReceipt<E> {
    /// The output whose write failed and ended the commit.
    #[must_use]
    pub const fn failed(&self) -> &OutputName {
        &self.failed
    }

    /// The host error that ended the commit.
    #[must_use]
    pub const fn cause(&self) -> &E {
        &self.cause
    }

    /// Siblings successfully undone, in the order they were undone.
    #[must_use]
    pub fn rolled_back(&self) -> &[OutputName] {
        &self.rolled_back
    }

    /// Siblings the host could not undo, with the reason for each.
    #[must_use]
    pub fn rollback_failures(&self) -> &[(OutputName, E)] {
        &self.rollback_failures
    }

    /// Whether every already-written sibling was successfully undone.
    #[must_use]
    pub fn contained(&self) -> bool {
        self.rollback_failures.is_empty()
    }
}

/// Renders every requested surface, or none of them.
///
/// Preflight runs first: an empty request set, too many requests, or two
/// requests sharing a name are refused before any rendering happens. Then every
/// surface is rendered; the first refusal aborts the whole staging and no
/// reservation is produced.
pub fn stage(
    document: &Document,
    requests: &[OutputRequest],
    limits: Limits,
) -> Result<OutputReservation, Refusal> {
    if requests.is_empty() || requests.len() > MAX_OUTPUTS {
        return Err(Refusal::exceeded(
            RefusalKind::TooManyOutputs,
            as_u64(MAX_OUTPUTS),
            as_u64(requests.len()),
        ));
    }
    for (index, request) in requests.iter().enumerate() {
        if requests
            .iter()
            .take(index)
            .any(|earlier| earlier.name == request.name)
        {
            return Err(Refusal::precondition(RefusalKind::DuplicateOutputName));
        }
    }
    let mut staged = Vec::with_capacity(requests.len());
    for request in requests {
        let rendered = render(document, request.profile, limits)?;
        staged.push(StagedOutput {
            name: request.name.clone(),
            rendered,
        });
    }
    Ok(OutputReservation { staged })
}

impl OutputReservation {
    /// Everything staged, in request order.
    #[must_use]
    pub fn outputs(&self) -> &[StagedOutput] {
        &self.staged
    }

    /// How many outputs are staged.
    #[must_use]
    pub fn len(&self) -> usize {
        self.staged.len()
    }

    /// Whether the reservation carries no outputs.
    ///
    /// Always false: [`stage`] refuses an empty request set rather than
    /// producing an empty reservation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// Total staged body size in bytes.
    #[must_use]
    pub fn body_bytes(&self) -> usize {
        self.staged
            .iter()
            .map(|entry| entry.rendered.len())
            .fold(0_usize, usize::saturating_add)
    }

    /// Discards the reservation without publishing anything.
    #[must_use]
    pub fn abort(self) -> AbortReceipt {
        AbortReceipt {
            discarded: self.staged.into_iter().map(|entry| entry.name).collect(),
        }
    }

    /// Publishes every staged output through the host, or undoes them all.
    ///
    /// `write` publishes one body. `undo` removes one already-published output.
    /// On the first write failure every sibling written so far is undone in
    /// reverse order, and the receipt reports both what was undone and any undo
    /// that itself failed.
    pub fn commit_with<E, W, U>(
        self,
        mut write: W,
        mut undo: U,
    ) -> Result<CommitReceipt, Box<RollbackReceipt<E>>>
    where
        W: FnMut(&OutputName, &str) -> Result<(), E>,
        U: FnMut(&OutputName) -> Result<(), E>,
    {
        let mut published: Vec<OutputName> = Vec::with_capacity(self.staged.len());
        for entry in &self.staged {
            match write(&entry.name, entry.rendered.as_str()) {
                Ok(()) => published.push(entry.name.clone()),
                Err(cause) => {
                    let mut rolled_back = Vec::new();
                    let mut rollback_failures = Vec::new();
                    for name in published.iter().rev() {
                        match undo(name) {
                            Ok(()) => rolled_back.push(name.clone()),
                            Err(error) => rollback_failures.push((name.clone(), error)),
                        }
                    }
                    return Err(Box::new(RollbackReceipt {
                        failed: entry.name.clone(),
                        cause,
                        rolled_back,
                        rollback_failures,
                    }));
                }
            }
        }
        Ok(CommitReceipt { published })
    }
}

/// Renders the four standard surfaces of one document under one base name.
///
/// The extensions are fixed so a corpus staged by two different callers lands
/// on the same names.
pub fn standard_requests(base: &str) -> Result<Vec<OutputRequest>, Refusal> {
    let mut requests = Vec::with_capacity(4);
    for profile in RenderProfile::all() {
        let extension = match profile {
            RenderProfile::PlainText => "plain_text.txt",
            RenderProfile::HtmlSafe => "html_safe.html",
            RenderProfile::CompactMachine => "compact_machine.txt",
            RenderProfile::ApiJson => "api_json.json",
        };
        let name = format!("{base}.{extension}");
        if name.len() > MAX_OUTPUT_NAME_BYTES {
            return Err(Refusal::exceeded(
                RefusalKind::OutputNameInvalid,
                as_u64(MAX_OUTPUT_NAME_BYTES),
                as_u64(name.len()),
            ));
        }
        requests.push(OutputRequest::new(&name, profile)?);
    }
    Ok(requests)
}
