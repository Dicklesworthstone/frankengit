//! Decode only the original bounded watch event, independently derive its
//! scope/identity, and bind every publication field to the immutable config.
//! Retained strings never choose filesystem paths or refresh a lease.
use super::{
    GitOid, Intent, OneNode, OsStrExt, Path, Pending, Prepared, PullRequestMergeWatchConfig,
    RefName, RepositoryAuthorityHeadId, RepositoryDecisionBatchId, Selected,
    TrustedWorkflowFailure, checkpoint, commitment, fs, hex, invalid, io, merge_queue,
    pull_request, pull_request_merge, reporting, sha256_digest,
};
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::{AggregateVersion, PullRequestNumber, QueueNumber};
use fgit_schema::json::{self, Object, Value};
use fgit_types::{CANONICAL_CODEC_VERSION, DigestAlgorithmId, DigestBytes, PolicyEpoch};

pub(super) fn reconstruct(
    node: &OneNode,
    reference: &RefName,
    directory: &[u8],
    path: &Path,
    key: &str,
    config: &PullRequestMergeWatchConfig,
    intent: Intent,
    live: &dyn Fn() -> bool,
) -> Result<Pending, TrustedWorkflowFailure> {
    checkpoint(live)?;
    let bytes = reporting::read_private(&path.join("event.json"), 192 * 1024)?;
    if sha256_digest(&bytes) != intent.event_sha256 {
        return Err(invalid("prestart event changed during inspection"));
    }
    let event = String::from_utf8(bytes).map_err(|_| invalid("invalid prestart event UTF-8"))?;
    let document = parse(event.as_bytes(), 192 * 1024)?;
    let fields = object(&document)?;
    for (field, value) in [
        ("tenant_id", node.tenant_id().to_string()),
        ("repository_id", node.repository_id().to_string()),
        (
            "repository_incarnation",
            node.repository_incarnation_id().to_string(),
        ),
        ("event_id", key.to_owned()),
        ("dispatch_id", key[..32].to_owned()),
        ("workflow_directory_hex", hex(directory)),
        ("custody_directory_hex", hex(path.as_os_str().as_bytes())),
    ] {
        equal(fields, field, &value)?;
    }
    let queue_mode = match text(fields, "profile")? {
        "latest-canonical-pull-request-merge-v1" => false,
        "latest-canonical-queue-head-merge-v1" => true,
        _ => return Err(invalid("unsupported prestart event profile")),
    };
    let source = reference_field(fields, "ref_hex")?;
    let commit = native(node, text(fields, "commit")?)?;
    let candidate = object_field(fields, "merge_candidate")?;
    let pull = object_field(fields, "pull_request")?;
    let epoch = PolicyEpoch::try_new(decimal(text(candidate, "policy_epoch")?)?)
        .map_err(|_| invalid("invalid prestart policy epoch"))?;
    let number = decimal(text(pull, "number")?)?;
    let version = decimal(text(pull, "version")?)?;
    let pull = pull_request::PullSelection {
        number,
        version,
        target: reference_field(pull, "target_ref_hex")?,
        target_commit: native(node, text(pull, "observed_target_commit")?)?,
        recorded_source: native(node, text(pull, "recorded_source_commit")?)?,
        recorded_target: native(node, text(pull, "recorded_target_commit")?)?,
        policy_epoch: epoch,
    };
    if pull.recorded_source != commit || pull.recorded_target != pull.target_commit {
        return Err(invalid(
            "prestart PR did not select its exact recorded tips",
        ));
    }
    let subject = ReviewSubject {
        pull_request: PullRequestNumber::try_new(number)
            .ok_or_else(|| invalid("invalid prestart PR number"))?,
        pull_request_version: AggregateVersion::try_new(version)
            .ok_or_else(|| invalid("invalid prestart PR version"))?,
        source_ref: source.clone(),
        target_ref: pull.target.clone(),
        source_tip: commit,
        target_tip: pull.target_commit,
        policy_epoch: epoch,
    };
    if config.reference() == &source || config.reference() == &subject.target_ref {
        return Err(invalid("prestart CI branch overlaps a PR branch"));
    }
    let queue = if queue_mode {
        let queue = object_field(fields, "merge_queue")?;
        let number = QueueNumber::try_new(decimal(text(queue, "number")?)?)
            .ok_or_else(|| invalid("invalid prestart queue number"))?;
        let version = AggregateVersion::try_new(decimal(text(queue, "version")?)?)
            .ok_or_else(|| invalid("invalid prestart queue version"))?;
        if reference != &subject.target_ref
            || merge_queue::scope(node, reference, directory, number.get()) != intent.scope
        {
            return Err(invalid("prestart queue scope differs"));
        }
        merge_queue::validate_selection(reference, None, Some(number.get()), Some(config))?;
        Some(merge_queue::QueueSelection {
            number,
            version,
            source: source.clone(),
        })
    } else {
        if source != *reference
            || pull_request_merge::scope(node, reference, directory, number) != intent.scope
            || fields.contains_key("merge_queue")
        {
            return Err(invalid("prestart PR scope differs"));
        }
        None
    };
    let selected = Selected {
        head: head(text(fields, "observed_head")?)?,
        commit,
        previous_commit: None,
        batch: batch(text(fields, "decision_batch")?)?,
        event_head: head(text(fields, "event_head")?)?,
        pull: Some(pull),
        queue,
    };
    let original_pull = selected.pull.as_ref().expect("constructed original PR");
    let derived = match &selected.queue {
        Some(queue) => {
            // Require every repeated queue guard, including epoch and target,
            // to be exactly the original emitter's canonical representation.
            if parse(queue.to_json(&selected)?.as_bytes(), 16 * 1024)?
                != *fields.get("merge_queue").expect("validated queue object")
            {
                return Err(invalid("prestart queue guards differ"));
            }
            queue.event_id(&intent.scope, &selected)?
        }
        None => original_pull.event_id(&intent.scope, &selected),
    };
    if derived != intent.event
        || parse(original_pull.to_json(true).as_bytes(), 16 * 1024)?
            != *fields.get("pull_request").expect("validated PR object")
    {
        return Err(invalid("prestart original event derivation differs"));
    }
    for (field, value) in [
        ("ref_hex", hex(config.reference().as_bytes())),
        ("principal", config.principal().to_string()),
        ("bundle_sha256", hex(&intent.bundle_sha256)),
        ("method", config.style_name().to_owned()),
        ("profile", config.profile_name().to_owned()),
        ("author_hex", hex(config.metadata().author.as_bytes())),
        ("committer_hex", hex(config.metadata().committer.as_bytes())),
        ("timestamp", config.metadata().timestamp.to_string()),
        ("message_hex", hex(&config.metadata().message)),
    ] {
        equal(candidate, field, &value)?;
    }
    let publication_key = commitment(&[
        b"frankengit/watched-merge-ref-publication/v1",
        &intent.event,
        &config.identity(),
    ]);
    equal(candidate, "publication_key", &hex(&publication_key))?;
    let parents = match config.style() {
        fgit_forge::preparation::MergeCommitStyle::TwoParent => {
            vec![
                subject.target_tip.to_string(),
                subject.source_tip.to_string(),
            ]
        }
        fgit_forge::preparation::MergeCommitStyle::Squash => vec![subject.target_tip.to_string()],
    };
    let parents = Value::Array(parents.into_iter().map(Value::String).collect());
    if candidate.get("parents") != Some(&parents) {
        return Err(invalid("prestart candidate parents differ"));
    }
    match intent.landing {
        Some((digest, _)) if queue_mode => {
            equal(candidate, "landing_bundle", "landing.bundle")?;
            equal(candidate, "landing_bundle_sha256", &hex(&digest))?;
        }
        None if !queue_mode
            && !candidate.contains_key("landing_bundle")
            && !candidate.contains_key("landing_bundle_sha256") => {}
        _ => return Err(invalid("prestart landing artifact differs")),
    }
    let expected_old = match candidate.get("expected_old") {
        Some(Value::Null) => None,
        Some(Value::String(value)) => Some(native(node, value)?),
        _ => return Err(invalid("invalid prestart old CI lease")),
    };
    let prepared = Prepared {
        commit: native(node, text(candidate, "commit")?)?,
        bundle: Vec::new(),
        subject,
        source_head: selected.head,
        base: native(node, text(candidate, "base")?)?,
        tree: native(node, text(candidate, "tree")?)?,
        expected_old,
        publication_key,
        queue: selected.queue.clone(),
    };
    publication(node, path, config, &prepared, live)?;
    checkpoint(live)?;
    Ok(Pending {
        selected,
        prepared,
        event,
        event_id: intent.event,
        intent,
    })
}

fn publication(
    node: &OneNode,
    path: &Path,
    config: &PullRequestMergeWatchConfig,
    prepared: &Prepared,
    live: &dyn Fn() -> bool,
) -> Result<(), TrustedWorkflowFailure> {
    checkpoint(live)?;
    let path = path.join("candidate-publication.json");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io(error)),
        Ok(_) => {}
    }
    let bytes = reporting::read_private(&path, 4096)?;
    let expected = prepared.publication_receipt(prepared.publication_identity(node, config)?, true);
    if bytes != expected.as_bytes() {
        return Err(invalid(
            "prestart candidate publication refused or malformed",
        ));
    }
    checkpoint(live)
}

fn parse(bytes: &[u8], maximum: usize) -> Result<Value, TrustedWorkflowFailure> {
    json::parse_with(
        bytes,
        json::Limits {
            input: maximum,
            depth: 8,
            nodes: 256,
            items: 64,
            string: 128 * 1024,
        },
    )
    .map_err(|_| invalid("invalid bounded prestart JSON"))
}
fn object(value: &Value) -> Result<&Object, TrustedWorkflowFailure> {
    value
        .object()
        .ok_or_else(|| invalid("prestart object missing"))
}
fn object_field<'a>(fields: &'a Object, field: &str) -> Result<&'a Object, TrustedWorkflowFailure> {
    object(
        fields
            .get(field)
            .ok_or_else(|| invalid("prestart object missing"))?,
    )
}
fn text<'a>(fields: &'a Object, field: &str) -> Result<&'a str, TrustedWorkflowFailure> {
    fields
        .get(field)
        .and_then(Value::text)
        .ok_or_else(|| invalid("prestart text missing"))
}
fn equal(fields: &Object, field: &str, expected: &str) -> Result<(), TrustedWorkflowFailure> {
    if text(fields, field)? == expected {
        Ok(())
    } else {
        Err(invalid("prestart binding differs"))
    }
}
fn decimal(value: &str) -> Result<u64, TrustedWorkflowFailure> {
    let number = value
        .parse::<u64>()
        .map_err(|_| invalid("invalid prestart integer"))?;
    if number.to_string() != value {
        return Err(invalid("noncanonical prestart integer"));
    }
    Ok(number)
}
fn unhex(value: &str, maximum: usize) -> Result<Vec<u8>, TrustedWorkflowFailure> {
    if value.is_empty() || value.len() > maximum * 2 || !value.len().is_multiple_of(2) {
        return Err(invalid("invalid prestart hex width"));
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(invalid("noncanonical prestart hex")),
    };
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}
pub(super) fn hash(value: &str) -> Result<[u8; 32], TrustedWorkflowFailure> {
    unhex(value, 32)?
        .try_into()
        .map_err(|_| invalid("invalid prestart digest width"))
}
fn reference_field(fields: &Object, name: &str) -> Result<RefName, TrustedWorkflowFailure> {
    let bytes = unhex(text(fields, name)?, 4096)?;
    if !bytes.starts_with(b"refs/heads/") {
        return Err(invalid("prestart requires branch refs"));
    }
    RefName::try_new(&bytes).map_err(|_| invalid("invalid prestart branch"))
}
fn native(node: &OneNode, value: &str) -> Result<GitOid, TrustedWorkflowFailure> {
    let oid = GitOid::from_hex(node.object_format(), value)
        .map_err(|_| invalid("invalid prestart native identity"))?;
    if oid.is_zero() || oid.to_string() != value {
        return Err(invalid("invalid prestart native identity"));
    }
    Ok(oid)
}
fn identity(
    value: &str,
    domain: &str,
) -> Result<(DigestAlgorithmId, DigestBytes), TrustedWorkflowFailure> {
    let prefix = format!("{domain}/{CANONICAL_CODEC_VERSION}/alg:");
    let (algorithm, digest) = value
        .strip_prefix(&prefix)
        .and_then(|tail| tail.split_once('/'))
        .ok_or_else(|| invalid("invalid prestart typed identity"))?;
    let algorithm =
        u16::try_from(decimal(algorithm)?).map_err(|_| invalid("invalid prestart algorithm"))?;
    let algorithm =
        DigestAlgorithmId::try_new(algorithm).map_err(|_| invalid("invalid prestart algorithm"))?;
    let digest = DigestBytes::try_new(&unhex(digest, 64)?)
        .map_err(|_| invalid("invalid prestart digest"))?;
    Ok((algorithm, digest))
}
fn head(value: &str) -> Result<RepositoryAuthorityHeadId, TrustedWorkflowFailure> {
    let (algorithm, digest) = identity(value, RepositoryAuthorityHeadId::DOMAIN)?;
    Ok(RepositoryAuthorityHeadId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}
fn batch(value: &str) -> Result<RepositoryDecisionBatchId, TrustedWorkflowFailure> {
    let (algorithm, digest) = identity(value, RepositoryDecisionBatchId::DOMAIN)?;
    Ok(RepositoryDecisionBatchId::from_digest(
        algorithm,
        CANONICAL_CODEC_VERSION,
        digest,
    ))
}
