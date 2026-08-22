#![forbid(unsafe_code)]

//! frankengit-22g1 acceptance: hidden-ref authorization must hold at
//! advertisement, want-validation, and pack-content disclosure, with
//! refusal-indistinguishability between "hidden" and "absent".
//!
//! Two inner repositories isolate who is responsible for what:
//!
//! - `ClosureRepository` honors the `UploadPackRepository` contract: its
//!   closure/common sets describe only visible history. Refusals of hidden
//!   or unknown objects through the wrapper must be indistinguishable.
//! - `PermissiveRepository` answers "yes" to every existence question,
//!   violating nothing the machines rely on except visibility. It proves the
//!   wrapper's own tip-level guards add real enforcement beyond the inner
//!   store's honesty.

use fgit_wire::visibility::{RefVisibility, VisibleUploadPackRepository, filter_advertised_refs};
use fgit_wire::{
    AdvertisedRef, AnyGitOid, Capabilities, GitObjectFormat, LegacyUploadPack, Packet,
    UploadPackRepository, UploadPackVersion, V1Advertisement, V2UploadPack, WireError, WireEvent,
    WireLimits,
};

const VISIBLE_TIP: &str = "1111111111111111111111111111111111111111";
const VISIBLE_TIP_TWO: &str = "5555555555555555555555555555555555555555";
const HIDDEN_TIP: &str = "2222222222222222222222222222222222222222";
const HIDDEN_INTERIOR: &str = "3333333333333333333333333333333333333333";
const UNKNOWN: &str = "4444444444444444444444444444444444444444";

fn oid(hex: &str) -> AnyGitOid {
    AnyGitOid::from_hex(GitObjectFormat::Sha1, hex).expect("fixture oid")
}

fn hex(target: AnyGitOid) -> String {
    // GitOid's Display is the lowercase digest, which is also the wire form.
    format!("{target}")
}

/// Substring search over byte slices (`[u8]::contains` only finds elements).
fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Strips every non-alphabetic character so two refusals can be compared for
/// identical shape independent of which object id they embed (the error
/// Displays render oids as Debug byte arrays).
fn error_shape(error: &WireError) -> String {
    format!("{error}")
        .chars()
        .filter(|character| character.is_ascii_alphabetic())
        .collect()
}

fn fixture_refs(limits: &WireLimits) -> Vec<AdvertisedRef> {
    vec![
        AdvertisedRef::new(oid(VISIBLE_TIP), b"refs/heads/main", limits).expect("visible ref"),
        AdvertisedRef::new(oid(VISIBLE_TIP_TWO), b"refs/heads/next", limits).expect("visible ref"),
        AdvertisedRef::new(oid(HIDDEN_TIP), b"refs/hidden/secret", limits).expect("hidden ref"),
    ]
}

fn standard_visibility() -> RefVisibility {
    let mut visibility = RefVisibility::new();
    visibility
        .push_rule(b"refs/hidden", &WireLimits::default())
        .expect("hide rule");
    visibility
}

/// Contract-honoring inner store: closure and commonality cover exactly the
/// visible history (visible tips plus one interior object of that history).
struct ClosureRepository {
    refs: Vec<AdvertisedRef>,
    closure: Vec<AnyGitOid>,
    common: AnyGitOid,
}

impl ClosureRepository {
    fn standard() -> Self {
        Self {
            refs: fixture_refs(&WireLimits::default()),
            closure: vec![oid(VISIBLE_TIP), oid(VISIBLE_TIP_TWO)],
            common: oid(VISIBLE_TIP_TWO),
        }
    }
}

impl UploadPackRepository for ClosureRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    fn contains_want(&self, target: AnyGitOid) -> bool {
        self.closure.contains(&target)
    }

    fn is_common(&self, target: AnyGitOid) -> bool {
        target == self.common
    }
}

/// Existence-permissive inner store: proves the wrapper enforces on its own.
#[derive(Default)]
struct PermissiveRepository {
    refs: Vec<AdvertisedRef>,
}

impl PermissiveRepository {
    fn standard() -> Self {
        Self {
            refs: fixture_refs(&WireLimits::default()),
        }
    }
}

impl UploadPackRepository for PermissiveRepository {
    fn object_format(&self) -> GitObjectFormat {
        GitObjectFormat::Sha1
    }

    fn advertised_refs(&self) -> &[AdvertisedRef] {
        &self.refs
    }

    // Both deliberately permissive: any refusal below is the wrapper's work.
    fn contains_want(&self, _target: AnyGitOid) -> bool {
        true
    }

    fn is_common(&self, _target: AnyGitOid) -> bool {
        true
    }
}

fn wrapped<R: UploadPackRepository>(repository: &R) -> VisibleUploadPackRepository<'_, R> {
    VisibleUploadPackRepository::new(repository, &standard_visibility())
}

#[test]
fn classification_is_exact_or_slash_bounded_with_last_match_wins() {
    let mut visibility = RefVisibility::new();
    let limits = WireLimits::default();
    visibility.push_rule(b"refs/hidden", &limits).expect("hide");
    assert!(visibility.hides(b"refs/hidden/secret"));
    assert!(visibility.hides(b"refs/hidden"));
    assert!(!visibility.hides(b"refs/hiddenx"), "boundary must not blur");
    assert!(!visibility.hides(b"refs/heads/main"));

    // A later negation re-exposes the subtree it names.
    visibility
        .push_rule(b"!refs/hidden/public", &limits)
        .expect("unhide rule");
    assert!(!visibility.hides(b"refs/hidden/public/latest"));
    assert!(visibility.hides(b"refs/hidden/secret"));

    // With no rules everything is visible.
    assert!(!RefVisibility::new().hides(b"refs/anything"));
    assert!(RefVisibility::new().is_empty());
}

#[test]
fn rule_ingestion_is_bounded_and_name_validated() {
    let mut visibility = RefVisibility::new();
    let mut limits = WireLimits::default();
    limits.max_ref_prefixes = 1;
    visibility
        .push_rule(b"refs/one", &limits)
        .expect("first rule");
    let second = visibility.push_rule(b"refs/two", &limits).unwrap_err();
    assert!(matches!(second, WireError::TooManyObjectIds { .. }));

    let invalid = RefVisibility::new()
        .push_rule(b"refs/has space", &WireLimits::default())
        .unwrap_err();
    assert!(matches!(invalid, WireError::InvalidRefName));

    let empty_negation = RefVisibility::new()
        .push_rule(b"!", &WireLimits::default())
        .unwrap_err();
    assert!(matches!(empty_negation, WireError::InvalidRefName));
}

#[test]
fn advertisement_carries_only_visible_refs_in_wire_order() {
    let repository = PermissiveRepository::standard();
    let visibility = standard_visibility();

    let filtered = filter_advertised_refs(&repository.refs, &visibility);
    let names: Vec<&[u8]> = filtered
        .iter()
        .map(|reference| reference.name.as_slice())
        .collect();
    assert_eq!(
        names,
        vec![&b"refs/heads/main"[..], &b"refs/heads/next"[..]]
    );

    let capabilities =
        Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).expect("capabilities");
    let limits = WireLimits::default();
    let encoded = V1Advertisement::new(
        filtered,
        capabilities.clone(),
        GitObjectFormat::Sha1,
        &limits,
    )
    .expect("visible advertisement")
    .encode(&limits)
    .expect("encode");

    // Control: the unfiltered wire form does carry the hidden tip; the
    // filtered form must never name it.
    let unfiltered_encoded = V1Advertisement::new(
        repository.refs.clone(),
        capabilities,
        GitObjectFormat::Sha1,
        &limits,
    )
    .expect("unfiltered advertisement")
    .encode(&limits)
    .expect("encode unfiltered");

    let hidden_hex = hex(oid(HIDDEN_TIP));
    assert!(
        !encoded
            .iter()
            .any(|packet| matches!(packet, Packet::Data(line) if bytes_contain(line, hidden_hex.as_bytes()))),
        "filtered advertisement must not name the hidden tip"
    );
    assert!(
        unfiltered_encoded
            .iter()
            .any(|packet| matches!(packet, Packet::Data(line) if bytes_contain(line, hidden_hex.as_bytes()))),
        "control: the unfiltered advertisement does carry the hidden tip"
    );
}

#[test]
fn all_hidden_advertisement_emits_no_ref_lines() {
    let mut visibility = RefVisibility::new();
    let limits = WireLimits::default();
    // `refs` matches every namespace member via the slash-boundary rule.
    visibility.push_rule(b"refs", &limits).expect("hide all");
    let filtered = filter_advertised_refs(&fixture_refs(&limits), &visibility);
    assert!(filtered.is_empty());
    let capabilities = Capabilities::parse_v1(b"multi_ack", &limits).expect("capabilities");
    let encoded = V1Advertisement::new(filtered, capabilities, GitObjectFormat::Sha1, &limits)
        .expect("empty advertisement")
        .encode(&limits)
        .expect("encode empty");
    assert!(
        !encoded.iter().any(|packet| {
            matches!(packet, Packet::Data(line) if bytes_contain(line, b"refs/"))
        })
    );
}

#[test]
fn v0_v1_hidden_want_is_refusal_indistinguishable_from_unknown() {
    let repository = PermissiveRepository::standard();
    let view = wrapped(&repository);
    let capabilities = Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).expect("caps");

    let mut hidden_machine = LegacyUploadPack::new(
        UploadPackVersion::V1,
        capabilities.clone(),
        WireLimits::default(),
    )
    .expect("machine");
    let hidden_error = hidden_machine
        .push_packet(
            &Packet::Data(format!("want {}\n", hex(oid(HIDDEN_TIP))).into_bytes()),
            &view,
        )
        .unwrap_err();

    let mut unknown_machine =
        LegacyUploadPack::new(UploadPackVersion::V1, capabilities, WireLimits::default())
            .expect("machine");
    let unknown_error = unknown_machine
        .push_packet(
            &Packet::Data(format!("want {}\n", hex(oid(UNKNOWN))).into_bytes()),
            &view,
        )
        .unwrap_err();

    assert!(matches!(hidden_error, WireError::WantNotAdvertised { .. }));
    assert!(matches!(unknown_error, WireError::WantNotAdvertised { .. }));
    assert_eq!(
        error_shape(&hidden_error),
        error_shape(&unknown_error),
        "refusals must share one shape; a distinguishable shape is an oracle"
    );
    assert!(!error_shape(&hidden_error).contains("hidden"));
}

#[test]
fn v2_hidden_want_is_refusal_indistinguishable_from_unknown() {
    let repository = ClosureRepository::standard();
    let view = wrapped(&repository);
    let capabilities = Capabilities::parse_v1(b"fetch", &WireLimits::default()).expect("fetch cap");

    let mut hidden_machine =
        V2UploadPack::new(capabilities.clone(), WireLimits::default()).expect("v2");
    hidden_machine
        .push_packet(&Packet::Data(b"command=fetch\n".to_vec()), &view)
        .expect("command line");
    hidden_machine
        .push_packet(&Packet::Delimiter, &view)
        .expect("delimiter");
    let hidden_error = hidden_machine
        .push_packet(
            &Packet::Data(format!("want {}\n", hex(oid(HIDDEN_TIP))).into_bytes()),
            &view,
        )
        .unwrap_err();

    let mut unknown_machine = V2UploadPack::new(capabilities, WireLimits::default()).expect("v2");
    unknown_machine
        .push_packet(&Packet::Data(b"command=fetch\n".to_vec()), &view)
        .expect("command line");
    unknown_machine
        .push_packet(&Packet::Delimiter, &view)
        .expect("delimiter");
    let unknown_error = unknown_machine
        .push_packet(
            &Packet::Data(format!("want {}\n", hex(oid(UNKNOWN))).into_bytes()),
            &view,
        )
        .unwrap_err();

    assert!(matches!(hidden_error, WireError::WantNotReachable { .. }));
    assert!(matches!(unknown_error, WireError::WantNotReachable { .. }));
    assert_eq!(
        error_shape(&hidden_error),
        error_shape(&unknown_error),
        "refusals must share one shape; a distinguishable shape is an oracle"
    );

    // The visible tip still validates on the same machine grammar.
    let mut visible_machine = V2UploadPack::new(
        Capabilities::parse_v1(b"fetch", &WireLimits::default()).expect("cap"),
        WireLimits::default(),
    )
    .expect("v2");
    visible_machine
        .push_packet(&Packet::Data(b"command=fetch\n".to_vec()), &view)
        .expect("command line");
    visible_machine
        .push_packet(&Packet::Delimiter, &view)
        .expect("delimiter");
    visible_machine
        .push_packet(
            &Packet::Data(format!("want {}\n", hex(oid(VISIBLE_TIP))).into_bytes()),
            &view,
        )
        .expect("visible want accepted");
}

#[test]
fn tip_level_guards_hold_even_over_a_permissive_inner_store() {
    let repository = PermissiveRepository::standard();
    // Inner claims everything exists and is common...
    assert!(repository.contains_want(oid(HIDDEN_TIP)));
    assert!(repository.is_common(oid(HIDDEN_TIP)));
    let view = wrapped(&repository);
    // ...and the view refuses the hidden-only tip on every seam regardless.
    assert!(!view.contains_want(oid(HIDDEN_TIP)));
    assert!(!view.is_common(oid(HIDDEN_TIP)));
    assert_eq!(view.resolve_ref(b"refs/hidden/secret"), None);
    assert_eq!(view.symref_target(b"refs/hidden/secret"), None);
    assert_eq!(view.peeled(oid(HIDDEN_TIP)), None);
}

#[test]
fn negotiation_never_confirms_hidden_history() {
    let repository = ClosureRepository::standard();
    let view = wrapped(&repository);

    assert!(!view.is_common(oid(HIDDEN_TIP)), "hidden tip: not common");
    assert!(
        !view.is_common(oid(HIDDEN_INTERIOR)),
        "hidden interior: outside the visible closure, so not common"
    );
    assert!(!view.contains_want(oid(HIDDEN_INTERIOR)));

    let capabilities = Capabilities::parse_v1(b"multi_ack", &WireLimits::default()).expect("caps");
    let mut machine =
        LegacyUploadPack::new(UploadPackVersion::V0, capabilities, WireLimits::default())
            .expect("machine");
    machine
        .push_packet(
            &Packet::Data(format!("want {}\n", hex(oid(VISIBLE_TIP))).into_bytes()),
            &view,
        )
        .expect("visible want");
    machine
        .push_packet(&Packet::Flush, &view)
        .expect("want flush");
    let transition = machine
        .push_packet(
            &Packet::Data(format!("have {}\n", hex(oid(HIDDEN_INTERIOR))).into_bytes()),
            &view,
        )
        .expect("have phase");

    let hidden_hex = hex(oid(HIDDEN_INTERIOR));
    assert!(
        !transition
            .output
            .iter()
            .any(|packet| matches!(packet, Packet::Data(line) if bytes_contain(line, hidden_hex.as_bytes()))),
        "no acknowledgement may name a hidden-only object"
    );
    assert!(
        !transition
            .events
            .iter()
            .any(|event| matches!(event, WireEvent::Common(event_oid) if *event_oid == oid(HIDDEN_INTERIOR))),
        "no common event may confirm a hidden-only object"
    );

    // Completing the have phase requires the client's terminating flush; the
    // resulting pack request roots exclusively at validated visible wants.
    let completed = machine
        .push_packet(&Packet::Data(b"done\n".to_vec()), &view)
        .expect("done line");
    let Some(WireEvent::PackRequested(request)) = completed.events.last() else {
        panic!("complete legacy request must ask for a pack");
    };
    assert_eq!(request.wants, vec![oid(VISIBLE_TIP)]);
    // Client-claimed haves are echoed as negotiation input, never as
    // acknowledgements; disclosure is governed by the output assertions
    // above, which no hidden-only object survived.
}

#[test]
fn dual_membership_tips_stay_disclosable() {
    let limits = WireLimits::default();
    let shared = oid(VISIBLE_TIP);
    let repository = PermissiveRepository {
        refs: vec![
            AdvertisedRef::new(shared, b"refs/heads/main", &limits).expect("visible"),
            AdvertisedRef::new(shared, b"refs/hidden/mirror", &limits).expect("hidden"),
        ],
    };
    let view = wrapped(&repository);
    assert!(
        view.contains_want(shared),
        "visible path wins for shared tips"
    );
    assert!(view.is_common(shared));
    assert_eq!(view.advertised_refs().len(), 1);
}

#[test]
fn attribute_lookups_answer_only_for_visible_names_and_tips() {
    let repository = ClosureRepository::standard();
    let view = wrapped(&repository);
    assert_eq!(view.resolve_ref(b"refs/heads/main"), Some(oid(VISIBLE_TIP)));
    assert_eq!(view.resolve_ref(b"refs/hidden/secret"), None);
    assert_eq!(view.symref_target(b"refs/hidden/secret"), None);
    assert_eq!(view.peeled(oid(HIDDEN_TIP)), None);
    // Inner answers for the hidden name; the view must not.
    assert_ne!(repository.resolve_ref(b"refs/hidden/secret"), None);
}
