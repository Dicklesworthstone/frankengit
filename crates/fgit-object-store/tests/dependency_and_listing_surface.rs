//! FG-006 acceptance, the two lines that were true but unguarded.
//!
//! * *"adapter dependency surface is registry-approved (no SDK, no
//!   Tokio-transitive)"* — had no test at all.
//! * *"no bucket listing participates in truth or recovery"* — was a doc
//!   comment at `lib.rs:492` (*"The adapter has no listing or deletion
//!   operation"*) and nothing held the code to it.
//!
//! Both are true today. A property that is true and unenforced is one careless
//! commit from being false, and this crate is the one whose whole purpose is
//! refusing to trust a backend's marketing.
//!
//! # Every absence check here carries a presence case
//!
//! An assertion that something is *missing* passes just as happily when it
//! examined nothing — a mistyped path, an empty read, a regex that never
//! matched. That failure mode has bitten this workspace repeatedly tonight, so
//! each scanner below is first shown to find something that IS there.

use std::collections::BTreeSet;

/// This crate's manifest.
fn manifest() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("the crate's own manifest must be readable at {path}: {error}")
    })
}

/// The workspace lockfile, which is where a *transitive* dependency shows up.
fn lockfile() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock");
    std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!("the workspace lockfile must be readable at {path}: {error}")
    })
}

/// Dependency names declared by this crate, one per `name.workspace`/`name =` line.
fn declared_dependencies(manifest: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_dependencies = trimmed.starts_with("[dependencies")
                || trimmed.starts_with("[dev-dependencies")
                || trimmed.starts_with("[build-dependencies");
            continue;
        }
        if !in_dependencies || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((left, _)) = trimmed.split_once('=') {
            let name = left.trim().trim_end_matches(".workspace").trim();
            if !name.is_empty() {
                names.insert(name.to_owned());
            }
        }
    }
    names
}

/// Every package name the resolved workspace lockfile contains.
fn locked_packages(lock: &str) -> BTreeSet<String> {
    lock.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("name = \"")
                .and_then(|rest| rest.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

/// Cloud SDKs and HTTP stacks the adapter must not acquire.
///
/// DEP-010: the adapter owns a minimal HTTP/signing surface rather than
/// importing a provider SDK, because an SDK decides retry, redirect and
/// consistency behaviour on our behalf — and those decisions are exactly what
/// this crate exists to verify empirically per backend.
const FORBIDDEN_SDKS: [&str; 10] = [
    "aws-sdk-s3",
    "aws-config",
    "rusoto_core",
    "rusoto_s3",
    "s3",
    "minio",
    "google-cloud-storage",
    "azure_storage",
    "reqwest",
    "hyper",
];

/// Runtimes that would make Asupersync not the sole runtime (§3.2).
const FORBIDDEN_RUNTIMES: [&str; 4] = ["tokio", "async-std", "smol", "futures-executor"];

#[test]
fn the_manifest_parser_actually_parsed_this_manifest() {
    // Presence case for both manifest scanners below. A parser returning an
    // empty set satisfies every "is absent" assertion in this file.
    let declared = declared_dependencies(&manifest());
    assert!(
        declared.contains("fgit-authority"),
        "the parser did not find fgit-authority, which this crate certainly depends on, so it \
         parsed nothing and every absence assertion built on it is vacuous. Parsed: {declared:?}"
    );
    assert!(
        declared.contains("asupersync"),
        "the parser did not find asupersync. Parsed: {declared:?}"
    );
}

#[test]
fn no_cloud_sdk_or_alternate_runtime_is_declared() {
    let declared = declared_dependencies(&manifest());
    for forbidden in FORBIDDEN_SDKS.into_iter().chain(FORBIDDEN_RUNTIMES) {
        assert!(
            !declared.contains(forbidden),
            "{forbidden} is declared by this crate. FG-006 requires the adapter to own a minimal \
             HTTP/signing surface (DEP-010): an SDK decides retry, redirect and consistency \
             behaviour for us, and those are the behaviours this crate exists to verify rather \
             than inherit. Declared: {declared:?}"
        );
    }
}

#[test]
fn the_lockfile_parser_actually_parsed_the_lockfile() {
    // Presence case for the transitive check. This one matters more than the
    // manifest's: the lockfile path climbs two directories, and a wrong path
    // would read nothing while the absence assertion below passed.
    let locked = locked_packages(&lockfile());
    assert!(
        locked.len() > 50,
        "the lockfile parser found only {} packages, which is not a real workspace closure — the \
         path or the parse is wrong and the transitive check below proves nothing",
        locked.len()
    );
    assert!(
        locked.contains("fgit-object-store"),
        "the lockfile does not list this crate, so it is not the workspace lockfile"
    );
}

#[test]
fn no_alternate_runtime_enters_the_resolved_closure() {
    // The acceptance says "no Tokio-TRANSITIVE", and a manifest cannot answer
    // that: a forbidden runtime arrives through someone else's dependency, not
    // through ours. Only the resolved lockfile can.
    let locked = locked_packages(&lockfile());
    for forbidden in FORBIDDEN_RUNTIMES {
        assert!(
            !locked.contains(forbidden),
            "{forbidden} is present in the resolved workspace closure. §3.2 makes Asupersync the \
             sole runtime, and a second one is two runtime universes even when Cargo resolves \
             both. This is a transitive arrival: check what pulled it in rather than removing a \
             direct dependency that may not exist"
        );
    }
}

/// The adapter's own source.
fn adapter_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("the adapter source must be readable at {path}: {error}"))
}

#[test]
fn the_source_scanner_actually_read_the_adapter() {
    // Presence case for the listing guard. Asserting that "list" is absent from
    // a string that was never loaded is the purest form of the vacuous check.
    let source = adapter_source();
    assert!(
        source.len() > 1000,
        "the adapter source is {} bytes, which is not the real file",
        source.len()
    );
    assert!(
        source.contains("AuthorityStore") || source.contains("authority"),
        "the scanner did not find any authority vocabulary in the adapter source, so it is \
         reading the wrong file and the listing guard below is vacuous"
    );
}

#[test]
fn no_bucket_listing_operation_participates_in_truth_or_recovery() {
    // lib.rs documents "The adapter has no listing or deletion operation".
    // This is what holds the code to it.
    //
    // Listing is forbidden for the same reason GC roots come from the
    // authenticated registry rather than from a scan (§5.5): a bucket listing
    // is eventually consistent on most providers, so a recovery path that
    // enumerates keys can miss an object that exists and conclude it does not.
    // Truth is read by EXACT KEY or not at all.
    let source = adapter_source();

    let found = listing_calls_in(&source);
    assert!(
        found.is_empty(),
        "the adapter source contains {found:?}. FG-006 requires that no bucket listing \
         participates in truth or recovery: listings are eventually consistent on most providers, \
         so an enumeration can omit an object that exists. Read by exact key, or refuse"
    );
}

/// Operation-shaped listing spellings found in `source`.
///
/// Operation-shaped rather than the bare word "list", so the doc comment
/// saying *"no listing operation"* does not trip the guard that enforces it.
fn listing_calls_in(source: &str) -> Vec<&'static str> {
    const FORBIDDEN_CALLS: [&str; 7] = [
        "list_objects",
        "ListObjects",
        "list_bucket",
        "list_keys",
        "list_prefix",
        "?list-type",
        "&prefix=",
    ];
    FORBIDDEN_CALLS
        .into_iter()
        .filter(|call| source.contains(call))
        .collect()
}

#[test]
fn the_listing_guard_can_actually_fire() {
    // The presence case for the PREDICATE, which is a different thing from the
    // presence case for the reader.
    //
    // `the_source_scanner_actually_read_the_adapter` proves the file was
    // loaded. It does not prove the needles are spelled correctly: a typo like
    // "list_objectz" would match nothing, and the guard above would pass
    // forever while the adapter grew a listing call. So the predicate is run
    // against a synthetic source that definitely contains one.
    let planted = r"
        async fn recover(&self) {
            let keys = self.client.list_objects(&self.prefix).await;
            let _ = keys;
        }
    ";
    let found = listing_calls_in(planted);
    assert!(
        found.contains(&"list_objects"),
        "the listing guard did not fire on a source that plainly calls list_objects, so its \
         needles are wrong and it cannot detect the thing it exists to detect. Found: {found:?}"
    );

    // And the converse: it must stay silent on prose. The adapter's own doc
    // comment says "no listing or deletion operation", and a guard that trips
    // on its own documentation gets deleted by the next person to hit it.
    let prose = "/// The adapter has no listing or deletion operation.";
    assert!(
        listing_calls_in(prose).is_empty(),
        "the listing guard fires on the doc comment describing the property it enforces; it must \
         match operations, not prose"
    );
}
