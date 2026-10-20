//! Persisted watch-to-check handoff. Only ordinary check admission grants authority.
use super::*;
use fgit_crypto::{Digest, DigestAlgorithm, DigestBytes};
use fgit_types::{DecisionOutcome, PrincipalId};
mod sources;
use sources::{Sources, read_private};

/// Counts refer to observed canonical decisions, including historical retries.
/// Previously reported events are suppression records, never passing checks.
#[derive(Debug, Default)]
pub struct TrustedRefCheckPublication {
    pub events_reported: usize,
    pub previously_reported: usize,
    pub committed: usize,
    pub refused: usize,
    pub error: Option<String>,
}
impl TrustedRefCheckPublication {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"type\":\"workflow_watch_publication\",\"schema_version\":1,\"events_reported\":{},\"previously_reported\":{},\"committed_decisions\":{},\"refused_decisions\":{},\"error\":{},\"execution_retried\":false,\"refs_changed\":false}}",
            self.events_reported,
            self.previously_reported,
            self.committed,
            self.refused,
            self.error.as_deref().map_or_else(|| "null".into(), quote)
        )
    }
}

impl OneNode {
    /// Explicitly report settled native-watch events as the operator's publisher.
    /// The caller must be authorized to use this identity; workflow text never
    /// supplies it. A creation-only scope record prevents publisher substitution.
    /// Call before polling to reconcile old work, then after polling to publish
    /// new work. A failed call must stop automatic later execution in that scope.
    /// All child sets of an event are verified before its first submission.
    /// This is not whole-event atomicity, hostile-code isolation or a new queue.
    pub async fn publish_trusted_ref_workflow_checks_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        directory: &[u8],
        parent: &Path,
        publisher: PrincipalId,
        observe: impl FnMut(&str) -> Result<(), String>,
    ) -> TrustedRefCheckPublication {
        self.publish_selected_workflow_checks_in(
            request, reference, directory, parent, publisher, None, observe,
        )
        .await
    }

    /// Report original settled PR-head runs without executing code or treating
    /// current PR metadata as permission to replace original journal identities.
    pub async fn publish_trusted_pull_request_workflow_checks_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        publisher: PrincipalId,
        observe: impl FnMut(&str) -> Result<(), String>,
    ) -> TrustedRefCheckPublication {
        self.publish_selected_workflow_checks_in(
            request,
            reference,
            directory,
            parent,
            publisher,
            Some(number),
            observe,
        )
        .await
    }

    async fn publish_selected_workflow_checks_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        directory: &[u8],
        parent: &Path,
        publisher: PrincipalId,
        pull_number: Option<u64>,
        mut observe: impl FnMut(&str) -> Result<(), String>,
    ) -> TrustedRefCheckPublication {
        let mut result = TrustedRefCheckPublication::default();
        let work: Result<(), TrustedWorkflowFailure> = async {
            if pull_number == Some(0) { return Err(invalid("pull-request number must be positive")); }
            if !request.checkpoint_is_live() { return Err(invalid("watch check publication cancelled")); }
            if !reference.as_bytes().starts_with(b"refs/heads/") || reference.as_bytes().len() > 4096
                || directory.is_empty() || directory.len() > 4096 || !parent.is_absolute()
                || fgit_treefs::TreePath::parse_default(directory).is_err() {
                return Err(invalid("invalid watch check publication scope"));
            }
            check_directory(parent)?;
            let scope = match pull_number {
                Some(number) => super::pull_request::scope(self, reference, directory, number),
                None => scope(self, reference, directory),
            };
            let root = parent.join(format!("watch-{}", hex(&scope)));
            let _owner = Owner::open(&root)?;
            let reporter = commitment(&[b"frankengit/watch-reporter/v1", &scope, publisher.as_bytes()]);
            bind_reporter(&root, &reporter)?;
            for entry in event_entries(&root)? {
                if !request.checkpoint_is_live() { return Err(invalid("watch check publication cancelled")); }
                let path = entry.path();
                let name = entry.file_name();
                let key = name.to_str().and_then(|s|s.strip_prefix("event-")).filter(|s|lower_hash(s))
                    .ok_or_else(|| invalid("unknown watch custody entry"))?;
                check_directory(&path)?;
                if !settled(&path, key)? { return Err(invalid("watch event unresolved; automatic check publication and later execution blocked")); }
                let sources = Sources::read(&path, &scope, key)?;
                let token = commitment(&[b"frankengit/watch-reported/v1", &reporter, &sources.identity]);
                if reported(&path, &token)? {
                    result.previously_reported += 1;
                    continue;
                }
                let mut sets = Vec::new();
                let (mut jobs_left, mut bytes_left) = (128usize, 16 * 1024 * 1024usize);
                // The dispatch shares one hard job/evidence envelope across all children.
                for source in &sources.runs {
                    let child = path.join(format!("dispatch-{}", &key[..32]))
                        .join(format!("workflow-{}", hex(&source.run)));
                    let set = self.prepare_trusted_workflow_check_set(request, &child,
                        digest(source.journal)?, (source.bytes, digest(source.tail)?),
                        publisher, reference.clone(), (jobs_left.max(1), bytes_left.max(1)))?;
                    if !set.targets_commit(sources.commit) { return Err(invalid("watch checks name another executed commit")); }
                    jobs_left = jobs_left.checked_sub(set.len()).ok_or_else(||invalid("watch check job limit exceeded"))?;
                    bytes_left = bytes_left.checked_sub(set.evidence_bytes()).ok_or_else(||invalid("watch check evidence limit exceeded"))?;
                    sets.push(set);
                }
                // Emit only verified manifests. A broken consumer admits no later work.
                for set in &sets {
                    observe(&set.to_json()).map_err(|e| failure(&path,e))?;
                }
                for set in &sets {
                    let published = self.publish_trusted_workflow_check_set_in(request, set,
                        |decision| observe(&decision.to_json())).await;
                    for decision in &published.decisions {
                        match decision.terminal.outcome {
                            DecisionOutcome::Committed { .. } => result.committed += 1,
                            DecisionOutcome::Refused { .. } => result.refused += 1,
                        }
                    }
                    if let Some(error) = published.error { return Err(failure(&path,error)); }
                    if published.decisions.len() != set.len() { return Err(invalid("incomplete watch check decisions")); }
                }
                // Local acknowledgement suppresses only future submissions, never grants
                // a check or conceals a canonical refusal. Retry before it uses original keys.
                write_new(&path.join("reported"), &token)
                    .and_then(|()|File::open(&path)?.sync_all()).map_err(io)?;
                result.events_reported += 1;
            }
            Ok(())
        }.await;
        if let Err(error) = work {
            result.error = Some(error.to_string());
        }
        result
    }
}

pub(super) fn scope(node: &OneNode, reference: &RefName, directory: &[u8]) -> [u8; 32] {
    commitment(&[
        b"frankengit/ref-workflow-watch/v1",
        node.tenant_id().as_bytes(),
        node.repository_id().as_bytes(),
        node.repository_incarnation_id().as_bytes(),
        reference.as_bytes(),
        directory,
    ])
}
pub(super) fn event_entries(root: &Path) -> Result<Vec<fs::DirEntry>, TrustedWorkflowFailure> {
    let mut entries = fs::read_dir(root)
        .map_err(io)?
        .take(MAX_EVENTS + 3)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io)?;
    if entries.len() > MAX_EVENTS + 2 {
        return Err(invalid("ref watcher retained-event limit exceeded"));
    }
    entries.retain(|entry| entry.file_name() != "owner.lock" && entry.file_name() != "publisher");
    if entries.len() > MAX_EVENTS {
        return Err(invalid("ref watcher retained-event limit exceeded"));
    }
    entries.sort_by_key(|entry| entry.file_name());
    Ok(entries)
}
pub(super) fn capture(
    path: &Path,
    scope: [u8; 32],
    event: [u8; 32],
    commit: GitOid,
    dispatch: &TrustedWorkflowDispatch,
    request: &NodeRequestContext,
) -> Result<(), TrustedWorkflowFailure> {
    Sources::capture(path, scope, event, commit, dispatch, request)
}
fn bind_reporter(root: &Path, expected: &[u8; 32]) -> Result<(), TrustedWorkflowFailure> {
    let path = root.join("publisher");
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if read_private(&path, 32)? != *expected {
                return Err(invalid(
                    "watch publisher differs from original reporting identity",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_new(&path, expected).map_err(io)?
        }
        Err(error) => return Err(io(error)),
    }
    File::open(&path)
        .and_then(|f| f.sync_all())
        .and_then(|()| File::open(root)?.sync_all())
        .map_err(io)
}
fn reported(path: &Path, expected: &[u8; 32]) -> Result<bool, TrustedWorkflowFailure> {
    let file = path.join("reported");
    match fs::symlink_metadata(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(io(e)),
        Ok(_) => (),
    }
    if read_private(&file, 32)? != *expected {
        return Err(invalid("watch publication acknowledgement mismatch"));
    }
    File::open(&file)
        .and_then(|f| f.sync_all())
        .and_then(|()| File::open(path)?.sync_all())
        .map_err(io)?;
    Ok(true)
}
fn digest(bytes: [u8; 32]) -> Result<Digest, TrustedWorkflowFailure> {
    Ok(Digest::new(
        DigestAlgorithm::Sha256.id(),
        DigestBytes::try_new(&bytes).map_err(|_| invalid("invalid watch digest"))?,
    ))
}
fn failure(path: &Path, detail: String) -> TrustedWorkflowFailure {
    TrustedWorkflowFailure::Journal {
        directory: path.to_owned(),
        detail,
    }
}
fn quote(text: &str) -> String {
    let mut s = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c if c < '\u{20}' => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}
