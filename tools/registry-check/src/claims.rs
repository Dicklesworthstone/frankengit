//! Claims-registry validation and generated README status.
//!
//! The registry is deliberately evaluated rather than trusted. A `verified`
//! row remains verified only while its exact artifact commitments exist and
//! match. A stale artifact therefore becomes an explicit demotion in both the
//! checker diagnostic and generated status; no manually edited prose can round
//! it back up.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Component, Path};

use crate::{Report, sha256_hex};

const CLAIM_COLUMNS: usize = 14;
const CLAIM_CLASS_COLUMNS: usize = 6;
const CLOSED_CLAIM_CLASSES: [(&str, u8); 6] = [
    ("CLAIM-001", 6),
    ("CLAIM-002", 5),
    ("CLAIM-003", 4),
    ("CLAIM-004", 3),
    ("CLAIM-005", 2),
    ("CLAIM-006", 1),
];
const CLAIM_CLASS_HEADER: [&str; CLAIM_CLASS_COLUMNS] = [
    "id",
    "rank",
    "stronger_than",
    "required_evidence",
    "forbidden_upgrade",
    "status",
];
const CLAIM_HEADER: [&str; CLAIM_COLUMNS] = [
    "id",
    "claim_class",
    "scope",
    "owner_invariant",
    "required_artifacts",
    "evidence_class",
    "status",
    "source_revision",
    "toolchain",
    "target_profile",
    "assumptions",
    "non_claims",
    "revalidation",
    "fallback_wording",
];
const REGISTRY_MARKER: &str = "# franken-registry-v1";
const README_STATUS_BEGIN: &str = "<!-- franken-claims-status:begin -->";
const README_STATUS_END: &str = "<!-- franken-claims-status:end -->";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimRow {
    id: String,
    claim_class: String,
    scope: String,
    owner_invariant: String,
    required_artifacts: String,
    evidence_class: String,
    status: String,
    source_revision: String,
    toolchain: String,
    target_profile: String,
    assumptions: String,
    non_claims: String,
    revalidation: String,
    fallback_wording: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Evaluation {
    Verified,
    Recorded(String),
    Demoted(String),
}

/// Checks claim rank, evidence strength, and artifact commitments.
pub fn check(root: &Path, report: &mut Report) {
    let ranks = match load_claim_class_ranks(root) {
        Ok(ranks) => ranks,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let invariants = match load_invariant_ids(root) {
        Ok(invariants) => invariants,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    let rows = match load_claim_rows(root) {
        Ok(rows) => rows,
        Err(error) => {
            report.error(error);
            return;
        }
    };
    for row in &rows {
        match evaluate(root, row, &ranks, &invariants) {
            Evaluation::Verified | Evaluation::Recorded(_) => {}
            Evaluation::Demoted(reason) => report.error(format!(
                "claim `{}` demoted: {reason}; generated status must not present it as verified",
                row.id
            )),
        }
    }
}

/// Renders the README-owned, staleness-gated claim status section.
pub fn render_status(root: &Path) -> Result<String, String> {
    let ranks = load_claim_class_ranks(root)?;
    let invariants = load_invariant_ids(root)?;
    let rows = load_claim_rows(root)?;
    let mut output = String::new();
    writeln!(output, "{README_STATUS_BEGIN}").map_err(render_error)?;
    writeln!(
        output,
        "| Claim | Class | Effective status | Scope | Readiness wording |"
    )
    .map_err(render_error)?;
    writeln!(output, "| --- | --- | --- | --- | --- |").map_err(render_error)?;
    for row in &rows {
        let status = match evaluate(root, row, &ranks, &invariants) {
            Evaluation::Verified => "verified".to_owned(),
            Evaluation::Recorded(status) => status,
            Evaluation::Demoted(reason) => format!("demoted: {reason}"),
        };
        writeln!(
            output,
            "| {} | {} | {} | {} | {} |",
            row.id, row.claim_class, status, row.scope, row.fallback_wording
        )
        .map_err(render_error)?;
    }
    writeln!(output, "{README_STATUS_END}").map_err(render_error)?;
    Ok(output)
}

/// Refuses a README whose checked-in status block is not the generated result.
pub fn check_readme(root: &Path, report: &mut Report) {
    let expected = match render_status(root) {
        Ok(status) => status,
        Err(error) => {
            report.error(format!("cannot render claim status: {error}"));
            return;
        }
    };
    let path = root.join("README.md");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            report.error(format!("cannot read README claim status: {error}"));
            return;
        }
    };
    let Some(begin) = text.find(README_STATUS_BEGIN) else {
        report.error("README lacks the generated claim-status begin marker");
        return;
    };
    let Some(end_relative) = text[begin..].find(README_STATUS_END) else {
        report.error("README lacks the generated claim-status end marker");
        return;
    };
    let end = begin + end_relative + README_STATUS_END.len();
    let actual = &text[begin..end];
    if actual != expected.trim_end() {
        report.error(
            "README claim-status block is stale; regenerate it with `fgit-registry-check claims-status`",
        );
    }
}

fn render_error(error: std::fmt::Error) -> String {
    format!("cannot render claim status: {error}")
}

fn load_claim_class_ranks(root: &Path) -> Result<BTreeMap<String, u8>, String> {
    let path = root.join("registries/claim_classes.tsv");
    let text = fs::read_to_string(&path).map_err(|error| {
        format!(
            "cannot read claim-class registry {}: {error}",
            path.display()
        )
    })?;
    let rows = registry_rows(&path, &text, &CLAIM_CLASS_HEADER)?;
    let mut ranks = BTreeMap::new();
    let mut previous_id = None;
    for (line_number, line) in rows {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != CLAIM_CLASS_COLUMNS {
            return Err(format!(
                "claim-class registry line {} has {} columns; expected {CLAIM_CLASS_COLUMNS}",
                line_number,
                fields.len()
            ));
        }
        if fields.iter().any(|field| field.is_empty()) {
            return Err(format!(
                "claim-class registry line {line_number} has an empty required field"
            ));
        }
        if previous_id.is_some_and(|previous: &str| previous >= fields[0]) {
            return Err(format!(
                "claim-class registry IDs are not strictly sorted at line {line_number}"
            ));
        }
        previous_id = Some(fields[0]);
        let rank = fields[1].parse::<u8>().map_err(|error| {
            format!(
                "claim-class registry line {} has invalid rank `{}`: {error}",
                line_number, fields[1]
            )
        })?;
        if !(1..=6).contains(&rank) {
            return Err(format!(
                "claim-class registry line {} rank `{rank}` is outside the closed 1..=6 lattice",
                line_number
            ));
        }
        if ranks.insert(fields[0].to_owned(), rank).is_some() {
            return Err(format!("duplicate claim class `{}`", fields[0]));
        }
    }
    if ranks.len() != CLOSED_CLAIM_CLASSES.len()
        || CLOSED_CLAIM_CLASSES
            .iter()
            .any(|(id, rank)| ranks.get(*id) != Some(rank))
    {
        return Err(
            "claim-class registry must preserve the closed six-class strength lattice".to_owned(),
        );
    }
    Ok(ranks)
}

fn load_claim_rows(root: &Path) -> Result<Vec<ClaimRow>, String> {
    let path = root.join("registries/claims.tsv");
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read claims registry {}: {error}", path.display()))?;
    let registry_rows = registry_rows(&path, &text, &CLAIM_HEADER)?;
    let mut rows = Vec::new();
    let mut previous_id = None;
    for (line_number, line) in registry_rows {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != CLAIM_COLUMNS {
            return Err(format!(
                "claims registry line {} has {} columns; expected {CLAIM_COLUMNS}",
                line_number,
                fields.len()
            ));
        }
        if fields.iter().any(|field| field.is_empty()) {
            return Err(format!(
                "claims registry line {} has an empty required field",
                line_number
            ));
        }
        if fields.iter().any(|field| field.contains('|')) {
            return Err(format!(
                "claims registry line {} contains `|`, which would corrupt generated Markdown",
                line_number
            ));
        }
        if previous_id.is_some_and(|previous: &str| previous >= fields[0]) {
            return Err(format!(
                "claims registry IDs are not strictly sorted at line {line_number}"
            ));
        }
        previous_id = Some(fields[0]);
        if !is_known_status(fields[6]) {
            return Err(format!(
                "claims registry line {line_number} has unknown status `{}`",
                fields[6]
            ));
        }
        rows.push(ClaimRow {
            id: fields[0].to_owned(),
            claim_class: fields[1].to_owned(),
            scope: fields[2].to_owned(),
            owner_invariant: fields[3].to_owned(),
            required_artifacts: fields[4].to_owned(),
            evidence_class: fields[5].to_owned(),
            status: fields[6].to_owned(),
            source_revision: fields[7].to_owned(),
            toolchain: fields[8].to_owned(),
            target_profile: fields[9].to_owned(),
            assumptions: fields[10].to_owned(),
            non_claims: fields[11].to_owned(),
            revalidation: fields[12].to_owned(),
            fallback_wording: fields[13].to_owned(),
        });
    }
    Ok(rows)
}

fn load_invariant_ids(root: &Path) -> Result<BTreeSet<String>, String> {
    let path = root.join("registries/invariants.tsv");
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read invariant registry {}: {error}", path.display()))?;
    let mut ids = BTreeSet::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let id = line.split('\t').next().unwrap_or_default();
        if id.is_empty() || !ids.insert(id.to_owned()) {
            return Err(format!(
                "invariant registry line {} has a missing or duplicate ID",
                line_number + 1
            ));
        }
    }
    Ok(ids)
}

fn registry_rows<'a>(
    path: &Path,
    text: &'a str,
    expected_header: &[&str],
) -> Result<impl Iterator<Item = (usize, &'a str)>, String> {
    let mut meaningful = text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty());
    let Some((marker_line, marker)) = meaningful.next() else {
        return Err(format!("empty registry {}", path.display()));
    };
    if marker.trim() != REGISTRY_MARKER {
        return Err(format!(
            "registry marker mismatch at {}:{}: expected `{REGISTRY_MARKER}`",
            path.display(),
            marker_line + 1
        ));
    }
    let Some((header_line, header)) = meaningful.find(|(_, line)| !line.starts_with('#')) else {
        return Err(format!("registry {} has no header", path.display()));
    };
    let actual_header = header.split('\t').collect::<Vec<_>>();
    if actual_header != expected_header {
        return Err(format!(
            "registry header mismatch at {}:{}: expected {:?}, observed {:?}",
            path.display(),
            header_line + 1,
            expected_header,
            actual_header
        ));
    }
    Ok(text
        .lines()
        .enumerate()
        .skip(header_line + 1)
        .map(|(line, value)| (line + 1, value)))
}

fn is_known_status(value: &str) -> bool {
    matches!(
        value,
        "active" | "specified" | "implemented" | "verified" | "experimental" | "rejected"
    )
}

fn evaluate(
    root: &Path,
    row: &ClaimRow,
    ranks: &BTreeMap<String, u8>,
    invariants: &BTreeSet<String>,
) -> Evaluation {
    if !invariants.contains(&row.owner_invariant) {
        return Evaluation::Demoted(format!(
            "unknown owning invariant `{}`",
            row.owner_invariant
        ));
    }
    if [
        &row.source_revision,
        &row.toolchain,
        &row.target_profile,
        &row.assumptions,
        &row.non_claims,
        &row.revalidation,
    ]
    .iter()
    .any(|value| value.is_empty())
    {
        return Evaluation::Demoted("missing interpretation context".to_owned());
    }
    let Some(claim_rank) = ranks.get(&row.claim_class) else {
        return Evaluation::Demoted(format!("unknown claim class `{}`", row.claim_class));
    };
    let Some(evidence_rank) = ranks.get(&row.evidence_class) else {
        return Evaluation::Demoted(format!("unknown evidence class `{}`", row.evidence_class));
    };
    if evidence_rank < claim_rank {
        return Evaluation::Demoted(format!(
            "evidence class `{}` rank {evidence_rank} is weaker than claim class `{}` rank {claim_rank}",
            row.evidence_class, row.claim_class
        ));
    }
    if row.status != "verified" {
        return Evaluation::Recorded(row.status.clone());
    }
    match verify_artifacts(root, &row.required_artifacts) {
        Ok(()) => Evaluation::Verified,
        Err(error) => Evaluation::Demoted(error),
    }
}

fn verify_artifacts(root: &Path, value: &str) -> Result<(), String> {
    if value == "not_applicable" {
        return Err("verified claim has no required artifact commitment".to_owned());
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|error| format!("cannot resolve claims root {}: {error}", root.display()))?;
    let mut previous = None;
    let mut seen = BTreeSet::new();
    for raw in value.split(',') {
        let (path, digest) = raw.rsplit_once("@sha256:").ok_or_else(|| {
            format!("artifact `{raw}` must use relative-path@sha256:lowercase-hex")
        })?;
        if path.is_empty() || !is_relative_normal_path(path) {
            return Err(format!(
                "artifact path `{path}` is not a normal relative path"
            ));
        }
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(format!("artifact `{path}` has no lowercase SHA-256 digest"));
        }
        if previous.is_some_and(|prior: &str| prior >= raw) || !seen.insert(raw) {
            return Err("artifact commitments must be sorted and unique".to_owned());
        }
        previous = Some(raw);
        let artifact_path = root.join(path);
        let canonical_artifact = fs::canonicalize(&artifact_path)
            .map_err(|error| format!("artifact `{path}` is unavailable: {error}"))?;
        if !canonical_artifact.starts_with(&canonical_root) {
            return Err(format!(
                "artifact `{path}` resolves outside the claims root"
            ));
        }
        let bytes = fs::read(&canonical_artifact)
            .map_err(|error| format!("artifact `{path}` is unavailable: {error}"))?;
        let actual = sha256_hex(&bytes);
        if actual != digest {
            return Err(format!(
                "artifact `{path}` digest changed: expected {digest}, observed {actual}"
            ));
        }
    }
    Ok(())
}

fn is_relative_normal_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::{
        ClaimRow, Evaluation, evaluate, load_claim_class_ranks, render_status, verify_artifacts,
    };
    use crate::sha256_hex;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

    struct TemporaryRoot(PathBuf);

    impl Drop for TemporaryRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temporary_root() -> TemporaryRoot {
        let nonce = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("fgit-claims-{nanos}-{nonce}"));
        fs::create_dir_all(root.join("registries")).expect("create registries");
        TemporaryRoot(root)
    }

    fn row(artifacts: String) -> ClaimRow {
        ClaimRow {
            id: "CLM-001".to_owned(),
            claim_class: "CLAIM-004".to_owned(),
            scope: "parser".to_owned(),
            owner_invariant: "INV-001".to_owned(),
            required_artifacts: artifacts,
            evidence_class: "CLAIM-004".to_owned(),
            status: "verified".to_owned(),
            source_revision: "not_applicable".to_owned(),
            toolchain: "not_applicable".to_owned(),
            target_profile: "not_applicable".to_owned(),
            assumptions: "bounded".to_owned(),
            non_claims: "not_universal".to_owned(),
            revalidation: "on_change".to_owned(),
            fallback_wording: "demoted".to_owned(),
        }
    }

    fn ranks() -> BTreeMap<String, u8> {
        BTreeMap::from([("CLAIM-004".to_owned(), 3), ("CLAIM-006".to_owned(), 1)])
    }

    fn invariants() -> BTreeSet<String> {
        BTreeSet::from(["INV-001".to_owned()])
    }

    #[test]
    fn weaker_evidence_is_demoted_before_artifacts_are_credited() {
        let root = temporary_root();
        let mut row = row("not_applicable".to_owned());
        row.evidence_class = "CLAIM-006".to_owned();
        let result = evaluate(&root.0, &row, &ranks(), &invariants());
        assert!(matches!(result, Evaluation::Demoted(reason) if reason.contains("weaker")));
    }

    #[test]
    fn changed_artifact_demotes_a_previously_verified_claim() {
        let root = temporary_root();
        let artifact = root.0.join("receipt.txt");
        fs::write(&artifact, b"first evidence").expect("write artifact");
        let digest = sha256_hex(b"first evidence");
        let row = row(format!("receipt.txt@sha256:{digest}"));
        assert_eq!(
            evaluate(&root.0, &row, &ranks(), &invariants()),
            Evaluation::Verified
        );
        fs::write(&artifact, b"later evidence").expect("mutate artifact");
        assert!(matches!(
            evaluate(&root.0, &row, &ranks(), &invariants()),
            Evaluation::Demoted(reason) if reason.contains("digest changed")
        ));
    }

    #[test]
    fn artifact_parser_refuses_parent_paths_and_uppercase_digests() {
        let root = temporary_root();
        assert!(
            verify_artifacts(
                &root.0,
                "../receipt@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_err()
        );
        assert!(
            verify_artifacts(
                &root.0,
                "receipt@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )
            .is_err()
        );
        assert!(
            verify_artifacts(
                &root.0,
                "receipt//copy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_owning_invariant_demotes_before_artifacts_are_credited() {
        let root = temporary_root();
        let mut row = row("not_applicable".to_owned());
        row.owner_invariant = "INV-MISSING".to_owned();
        assert!(matches!(
            evaluate(&root.0, &row, &ranks(), &invariants()),
            Evaluation::Demoted(reason) if reason.contains("unknown owning invariant")
        ));
    }

    #[test]
    fn rendered_status_reflects_the_registry_not_a_handwritten_summary() {
        let root = temporary_root();
        fs::write(
            root.0.join("registries/claim_classes.tsv"),
            concat!(
                "# franken-registry-v1\n",
                "id\trank\tstronger_than\trequired_evidence\tforbidden_upgrade\tstatus\n",
                "CLAIM-001\t6\tCLAIM-002\tinvariant\tbenchmark_to_invariant\tactive\n",
                "CLAIM-002\t5\tCLAIM-003\tproof\tbenchmark_to_proof\tactive\n",
                "CLAIM-003\t4\tCLAIM-004\tmodel\tbenchmark_to_model\tactive\n",
                "CLAIM-004\t3\tCLAIM-005\tstatistical\tbenchmark_to_statistical\tactive\n",
                "CLAIM-005\t2\tCLAIM-006\tslo\tbenchmark_to_slo\tactive\n",
                "CLAIM-006\t1\tnone\tbenchmark\tbenchmark_to_universal\tactive\n"
            ),
        )
        .expect("write classes");
        fs::write(
            root.0.join("registries/invariants.tsv"),
            concat!(
                "# franken-registry-v1\n",
                "id\towner\tstatement\tverification\trelease_blocking\tstatus\n",
                "INV-001\tchecker\tclaim status is bounded\tunit\tyes\timplemented\n"
            ),
        )
        .expect("write invariants");
        fs::write(
            root.0.join("registries/claims.tsv"),
            concat!(
                "# franken-registry-v1\n",
                "id\tclaim_class\tscope\towner_invariant\trequired_artifacts\tevidence_class\tstatus\tsource_revision\ttoolchain\ttarget_profile\tassumptions\tnon_claims\trevalidation\tfallback_wording\n",
                "CLM-001\tCLAIM-004\tparser\tINV-001\tnot_applicable\tCLAIM-004\tspecified\tnot_applicable\tnot_applicable\tnot_applicable\tbounded\tnot_universal\ton_change\tdemoted\n"
            ),
        )
        .expect("write claims");
        assert_eq!(
            load_claim_class_ranks(&root.0)
                .expect("parse classes")
                .len(),
            6
        );
        let status = render_status(&root.0).expect("render status");
        assert!(status.contains("| CLM-001 | CLAIM-004 | specified | parser | demoted |"));
    }
}
