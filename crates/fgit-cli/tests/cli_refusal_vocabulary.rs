#![forbid(unsafe_code)]
//! The `fg` refusal vocabulary (`frankengit-qsql`).
//!
//! **This crate had no `tests/` directory.** Its only coverage was an inline
//! `cfg(test)` module of four tests. `CliRefusal` has sixteen variants:
//!
//! ```text
//! named by a test outside the crate      0 of 16
//! named by the inline module             3 of 16
//! named by nothing anywhere             13 of 16
//! ```
//!
//! And the three the inline module names are asserted with a bare
//! `matches!(.., Err(CliRefusal::Object(_)))`, so the inner refusal is
//! discarded in every case — variant granularity only.
//!
//! # Why this is one design decision, not sixteen chores
//!
//! §3.2 requires an effect that acquires responsibility to reap it **or report
//! containment failure**. Five variants exist solely to carry *two* failures at
//! once so that, in the enum's own words, "neither failure is discarded":
//! `ExportFileCleanup`, `ExportVisibleCleanup`, `DoctorCleanup`,
//! `ServeCleanup`, `ExportCleanup`.
//!
//! The 2×2 table is written out explicitly at two call sites, and every
//! quadrant means something different:
//!
//! ```text
//! (Ok , Ok )  success
//! (Err, Ok )  the operation's own refusal
//! (Ok , Err)  CliRefusal::Node(cleanup)   -- the work SUCCEEDED, shutdown did not
//! (Err, Err)  <Op>Cleanup { both }        -- neither discarded
//! ```
//!
//! # The sharpest claim, and it is assertable two independent ways
//!
//! `ExportVisibleCleanup` is the odd one out **by design**. Its doc: *"The
//! error intentionally does not claim the export failed: the named destination
//! is already visible and the retained staging path must be reported rather
//! than silently leaked."* That is §5.4 — staged, visible and durable are
//! distinct — and it has two separate consequences, both pinned below:
//!
//! 1. Its `Display` is the only one in the enum that never reports the
//!    operation as failed.
//! 2. `Error::source()` returns its **cleanup** error, while the other four
//!    cleanup variants return the **original** failure. It is the only one
//!    where there is no original failure to return.
//!
//! A refactor that "normalised" the five would break both.
//!
//! # Reachable versus constructed, stated rather than implied
//!
//! ```text
//! no node needed          Usage, Tenant, Repository, Object
//! after a cheap init      ExportDestination, ExportDestinationExists, Node
//! host/node fault         Listener, ExportMaterialization, Serve, ExportFile
//! TWO faults at once      the five cleanup variants
//! ```
//!
//! The last group cannot be driven end to end without fault injection this
//! crate does not have. Their claims that matter — `Display` and `source()` —
//! are pure functions over a constructed value, so they are covered **by
//! construction**, and every such test says so. **No test here implies it drove
//! a paired failure.**
//!
//! Nothing here modifies `crates/fgit-cli/src/**`.

use std::error::Error as _;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_cli::{CliOutcome, CliRefusal, run};
use fgit_node::NodeRefusal;

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(1);

/// A temp directory removed on drop, as the inline module does.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        Self(
            std::env::temp_dir().join(format!("frankengit-qsql-{}-{sequence}", std::process::id())),
        )
    }

    fn root(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// Initializes a real node in `scratch`, the way the inline module does.
fn init(scratch: &Scratch) {
    let outcome = run(&words(&["init", &scratch.root(), TENANT, REPOSITORY]))
        .expect("a fresh storage root initializes");
    assert!(matches!(outcome, CliOutcome::Initialized(_)));
}

#[track_caller]
fn refusal(arguments: &[&str], what: &str) -> CliRefusal {
    match run(&words(arguments)) {
        Ok(outcome) => panic!("{what} must be refused, got {outcome:?}"),
        Err(error) => error,
    }
}

/// A marker io error whose text contains no word this file asserts against.
fn marked_io(marker: &str) -> io::Error {
    io::Error::other(marker.to_owned())
}

// ---------------------------------------------------------------------------
// Through run(), with no node at all
// ---------------------------------------------------------------------------

/// A command outside the closed set, and every wrong arity, is `Usage`.
///
/// Exhaustive over the arities each command accepts, because the parser is a
/// slice-pattern match and a wrong-arity arm is how a command silently becomes
/// a different command.
#[test]
fn an_unknown_command_or_wrong_arity_is_a_usage_refusal() {
    let cases: [&[&str]; 6] = [
        &[],
        &["fetch", "/unused", TENANT, REPOSITORY],
        &["init"],
        &["init", "/unused", TENANT],
        &["init", "/unused", TENANT, REPOSITORY, "extra"],
        &["export", "/unused", TENANT, REPOSITORY],
    ];
    for arguments in cases {
        assert!(
            matches!(
                refusal(arguments, "an unusable command line"),
                CliRefusal::Usage
            ),
            "{arguments:?} must be a usage refusal"
        );
    }
}

/// A non-canonical tenant names the **tenant** field.
///
/// The inline module's probes stop at the variant. `TypeRefusal` carries a
/// `field` documented "stable across releases", and it is the only thing
/// separating a bad tenant from a bad repository — both are 32 hex characters
/// in the same shape, one argument apart.
#[test]
fn a_noncanonical_tenant_is_refused_and_names_the_tenant_field() {
    let error = refusal(
        &["init", "/unused", "not-hex", REPOSITORY],
        "a non-canonical tenant",
    );
    let CliRefusal::Tenant(inner) = error else {
        panic!("expected a tenant refusal, got {error:?}");
    };
    // `TypeRefusal`'s Display is "{field}: ...", and `field` is the identity
    // type name, documented stable across releases. Asserted exactly rather
    // than by a loose substring: it is the ONLY thing separating this from the
    // repository refusal below.
    let rendered = inner.to_string();
    assert!(
        rendered.starts_with("TenantId"),
        "the refusal must name the TenantId field, got {rendered:?}"
    );
}

/// A non-canonical repository names the **repository** field, with a valid
/// tenant in front of it so the earlier guard is satisfied.
#[test]
fn a_noncanonical_repository_is_refused_and_names_the_repository_field() {
    let error = refusal(
        &["init", "/unused", TENANT, "not-hex"],
        "a non-canonical repository",
    );
    let CliRefusal::Repository(inner) = error else {
        panic!("expected a repository refusal, got {error:?}");
    };
    let rendered = inner.to_string();
    assert!(
        rendered.starts_with("RepositoryId"),
        "the refusal must name the RepositoryId field, got {rendered:?}"
    );
}

/// **Ordering.** `node_config` validates the tenant before the repository, so a
/// command wrong in both places reports the tenant.
///
/// Paired with the two probes above: either alone would be satisfied by an
/// arbitrary order.
#[test]
fn the_tenant_is_validated_before_the_repository() {
    let error = refusal(
        &["init", "/unused", "not-hex", "also-not-hex"],
        "a command wrong in two places",
    );
    assert!(
        matches!(error, CliRefusal::Tenant(_)),
        "the first guard in the chain owns the refusal, got {error:?}"
    );
}

/// The doctor sample is parsed **before** any node is opened, which is why
/// `/unused` is a usable storage root here.
#[test]
fn a_noncanonical_doctor_sample_is_refused_before_the_node_opens() {
    let error = refusal(
        &["doctor", "/unused", TENANT, REPOSITORY, "not-an-object"],
        "a non-canonical sample object",
    );
    assert!(
        matches!(error, CliRefusal::Object(_)),
        "expected an object refusal, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Through run(), after a cheap init
// ---------------------------------------------------------------------------

/// A node operation against a root that was never initialized refuses as
/// `Node`, not as usage.
#[test]
fn doctor_on_an_uninitialized_root_is_a_node_refusal() {
    let scratch = Scratch::new();
    let error = refusal(
        &["doctor", &scratch.root(), TENANT, REPOSITORY],
        "doctor on an uninitialized root",
    );
    assert!(
        matches!(error, CliRefusal::Node(_)),
        "expected a node refusal, got {error:?}"
    );
}

/// **The permitted twin, and the guard it brackets.** A new export is written;
/// a second export to the same path refuses and names the path it would have
/// replaced.
///
/// §13 keeps a new export from ever replacing a pre-existing file, and the
/// refusal has to carry the path or an operator cannot act on it.
#[test]
fn an_export_is_written_once_and_a_second_refuses_to_replace_it() {
    let scratch = Scratch::new();
    init(&scratch);
    let destination = scratch.0.join("export.pack");
    let arguments = [
        "export",
        &scratch.root(),
        TENANT,
        REPOSITORY,
        &destination.to_string_lossy(),
    ];

    let outcome = run(&words(&arguments)).expect("the first export is written");
    assert!(matches!(outcome, CliOutcome::Exported { .. }));
    assert!(destination.is_file(), "the export must exist on disk");

    let error = refusal(&arguments, "a second export to the same path");
    let CliRefusal::ExportDestinationExists(path) = error else {
        panic!("expected a destination-exists refusal, got {error:?}");
    };
    assert_eq!(
        path.as_ref(),
        &destination,
        "the refusal must name the file it declined to replace"
    );
}

// ---------------------------------------------------------------------------
// source() selection — by CONSTRUCTION, not by execution
// ---------------------------------------------------------------------------

/// The four cleanup variants that wrap an original failure report **that**
/// failure as their source, not the cleanup.
///
/// Built directly: reaching these through `run` needs an operation failure and
/// a shutdown failure at the same moment, which this crate has no fault
/// injection for. What is claimed here is the `source()` selection, which is a
/// pure function of the value — not that the pairing was driven.
#[test]
fn the_cleanup_variants_wrapping_an_original_failure_report_that_failure() {
    let original = marked_io("ORIGINAL");
    let cleanup = marked_io("CLEANUP");

    let export_file = CliRefusal::ExportFileCleanup {
        operation: "publish",
        temporary: Box::new(PathBuf::from("/tmp/qsql/staged")),
        source: Box::new(original),
        cleanup: Box::new(cleanup),
    };
    assert!(
        export_file
            .source()
            .expect("ExportFileCleanup has a source")
            .to_string()
            .contains("ORIGINAL"),
        "ExportFileCleanup must expose the original failure"
    );

    let doctor = CliRefusal::DoctorCleanup {
        inspection: Box::new(NodeRefusal::AuthorityHeadAbsent),
        cleanup: Box::new(NodeRefusal::EmptyStorageRoot),
    };
    assert_eq!(
        doctor
            .source()
            .expect("DoctorCleanup has a source")
            .to_string(),
        NodeRefusal::AuthorityHeadAbsent.to_string(),
        "DoctorCleanup must expose the inspection failure, not the shutdown one"
    );

    let export = CliRefusal::ExportCleanup {
        export: Box::new(CliRefusal::ExportDestination),
        cleanup: Box::new(NodeRefusal::EmptyStorageRoot),
    };
    assert_eq!(
        export
            .source()
            .expect("ExportCleanup has a source")
            .to_string(),
        CliRefusal::ExportDestination.to_string(),
        "ExportCleanup must expose the export failure, not the shutdown one"
    );
}

/// **The odd one out, asserted as a difference.**
///
/// `ExportVisibleCleanup` reports its **cleanup** error, because there is no
/// original failure to report — the export is already visible. Every other
/// cleanup variant reports the original. Asserted as a contrast rather than in
/// isolation, so a refactor that normalised the five fails here.
#[test]
fn export_visible_cleanup_reports_the_cleanup_because_the_export_succeeded() {
    let visible = CliRefusal::ExportVisibleCleanup {
        destination: Box::new(PathBuf::from("/tmp/qsql/visible.pack")),
        temporary: Box::new(PathBuf::from("/tmp/qsql/staged.pack")),
        cleanup: Box::new(marked_io("CLEANUP")),
    };
    let reported = visible
        .source()
        .expect("ExportVisibleCleanup has a source")
        .to_string();
    assert!(
        reported.contains("CLEANUP"),
        "this variant reports the cleanup failure, got {reported:?}"
    );

    // The contrast: the same two errors in the sibling variant report the other
    // one. Same payloads, opposite selection.
    let sibling = CliRefusal::ExportFileCleanup {
        operation: "publish",
        temporary: Box::new(PathBuf::from("/tmp/qsql/staged.pack")),
        source: Box::new(marked_io("ORIGINAL")),
        cleanup: Box::new(marked_io("CLEANUP")),
    };
    let sibling_reported = sibling
        .source()
        .expect("ExportFileCleanup has a source")
        .to_string();
    assert!(
        sibling_reported.contains("ORIGINAL"),
        "the sibling reports the original failure, got {sibling_reported:?}"
    );
    assert_ne!(
        reported, sibling_reported,
        "the two must not collapse onto the same selection"
    );
}

/// The three refusals that carry no cause report none.
///
/// `ExportDestinationExists` is the interesting one: it carries a *path* and
/// still has no source, because nothing underneath it failed — the file simply
/// already existed.
#[test]
fn the_three_causeless_refusals_report_no_source() {
    assert!(CliRefusal::Usage.source().is_none());
    assert!(CliRefusal::ExportDestination.source().is_none());
    assert!(
        CliRefusal::ExportDestinationExists(Box::new(PathBuf::from("/tmp/qsql/present.pack")))
            .source()
            .is_none(),
        "a pre-existing destination is not an underlying failure"
    );
}

// ---------------------------------------------------------------------------
// Display semantics — by CONSTRUCTION
// ---------------------------------------------------------------------------

/// **§5.4.** The visible-cleanup message must not report the export as failed,
/// and must name both the visible destination and the leaked staging path.
///
/// This is the operator-facing half of the same decision `source()` encodes,
/// and it is the whole reason this variant exists separately from
/// `ExportFileCleanup`.
#[test]
fn export_visible_cleanup_never_claims_the_export_failed() {
    let rendered = CliRefusal::ExportVisibleCleanup {
        destination: Box::new(PathBuf::from("/tmp/qsql/visible.pack")),
        temporary: Box::new(PathBuf::from("/tmp/qsql/staged.pack")),
        cleanup: Box::new(marked_io("CLEANUP")),
    }
    .to_string();

    assert!(
        !rendered.contains("failed"),
        "the export IS visible; the message must not report it as failed, got {rendered:?}"
    );
    assert!(
        rendered.contains("visible"),
        "the message must say the destination is visible, got {rendered:?}"
    );
    assert!(
        rendered.contains("/tmp/qsql/visible.pack") && rendered.contains("/tmp/qsql/staged.pack"),
        "both the visible destination and the leaked staging path must appear, got {rendered:?}"
    );
}

/// Every other cleanup message names **both** failures, so neither is
/// discarded.
///
/// Asserted by the property the docs claim — each inner failure's own rendering
/// appears — rather than by exact string, which would be brittle and close to
/// tautological.
#[test]
fn the_other_cleanup_messages_name_both_failures() {
    let doctor = CliRefusal::DoctorCleanup {
        inspection: Box::new(NodeRefusal::AuthorityHeadAbsent),
        cleanup: Box::new(NodeRefusal::EmptyStorageRoot),
    }
    .to_string();
    assert!(
        doctor.contains(&NodeRefusal::AuthorityHeadAbsent.to_string())
            && doctor.contains(&NodeRefusal::EmptyStorageRoot.to_string()),
        "DoctorCleanup must render both failures, got {doctor:?}"
    );

    let export = CliRefusal::ExportCleanup {
        export: Box::new(CliRefusal::ExportDestination),
        cleanup: Box::new(NodeRefusal::EmptyStorageRoot),
    }
    .to_string();
    assert!(
        export.contains(&CliRefusal::ExportDestination.to_string())
            && export.contains(&NodeRefusal::EmptyStorageRoot.to_string()),
        "ExportCleanup must render both failures, got {export:?}"
    );

    let file = CliRefusal::ExportFileCleanup {
        operation: "publish",
        temporary: Box::new(PathBuf::from("/tmp/qsql/staged.pack")),
        source: Box::new(marked_io("ORIGINAL")),
        cleanup: Box::new(marked_io("CLEANUP")),
    }
    .to_string();
    assert!(
        file.contains("ORIGINAL") && file.contains("CLEANUP"),
        "ExportFileCleanup must render both failures, got {file:?}"
    );
}
