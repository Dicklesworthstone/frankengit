//! Bounded original watch/dispatch/attempt bindings. Retained path strings are
//! compared with owner-derived paths; they are never followed as file authority.
use super::{
    Budget, GitOid, OneNode, OsStrExt, Path, PrivateDirectory, RefName, Run, Sources,
    TrustedWorkflowFailure, checkpoint, hex, invalid, read_private,
};
use crate::treefs_workspace::trusted_workflow::durable::dispatch::child_id;
use fgit_crypto::sha256_digest;
use fgit_schema::json::{self, Object, Value};
use std::collections::BTreeSet;

pub(super) struct Definition {
    pub(super) run: [u8; 16],
    pub(super) path: Vec<u8>,
    pub(super) blob: GitOid,
    pub(super) graph: [u8; 32],
    pub(super) selected: bool,
}

pub(super) struct Dispatch {
    pub(super) directory: PrivateDirectory,
    pub(super) identity: [u8; 32],
    document: Value,
    pub(super) definitions: Vec<Definition>,
}

pub(super) fn dispatch(
    node: &OneNode,
    reference: &RefName,
    workflow_directory: &[u8],
    path: &Path,
    key: &str,
    sources: &Sources,
    budget: &mut Budget,
    live: &dyn Fn() -> bool,
) -> Result<Dispatch, TrustedWorkflowFailure> {
    let event = read_json(&path.join("event.json"), 192 * 1024, budget, live)?;
    let event = object(&event)?;
    scope(node, event)?;
    equal_text(event, "event_id", key)?;
    equal_text(event, "dispatch_id", &key[..32])?;
    equal_text(event, "workflow_directory_hex", &hex(workflow_directory))?;
    equal_text(
        event,
        "custody_directory_hex",
        &hex(path.as_os_str().as_bytes()),
    )?;
    let (trigger, candidate) = match text(event, "profile")? {
        "latest-canonical-ref-update-v1" => ("push", false),
        "latest-canonical-tag-update-v1" => {
            if !reference.as_bytes().starts_with(b"refs/tags/") {
                return Err(invalid("tag settlement names a non-tag reference"));
            }
            let tip = GitOid::from_hex(node.object_format(), text(event, "tag_tip")?)
                .map_err(|_| invalid("invalid original tag tip"))?;
            if tip.is_zero() {
                return Err(invalid("zero original tag tip"));
            }
            match event.get("previous_tag_tip") {
                Some(Value::Null) => {}
                Some(value) => {
                    let previous = value
                        .text()
                        .ok_or_else(|| invalid("invalid prior tag tip"))?;
                    let previous = GitOid::from_hex(node.object_format(), previous)
                        .map_err(|_| invalid("invalid prior tag tip"))?;
                    if previous.is_zero() {
                        return Err(invalid("zero prior tag tip"));
                    }
                }
                None => return Err(invalid("missing prior tag binding")),
            }
            ("push", false)
        }
        "latest-canonical-pull-request-head-v1" => ("pull_request", false),
        "latest-canonical-pull-request-merge-v1" | "latest-canonical-queue-head-merge-v1" => {
            ("pull_request", true)
        }
        _ => return Err(invalid("unsupported watch settlement profile")),
    };
    let subject = if candidate {
        object(
            event
                .get("merge_candidate")
                .ok_or_else(|| invalid("missing original candidate binding"))?,
        )?
    } else {
        event
    };
    equal_text(subject, "commit", &sources.commit.to_string())?;
    equal_text(subject, "ref_hex", &hex(reference.as_bytes()))?;
    let run_id = bytes::<16>(&key[..32])?;
    let directory = PrivateDirectory::open(&path.join(format!("dispatch-{}", hex(&run_id))))?;
    let (document, identity) = read_json_with_identity(
        &directory.path.join("dispatch.json"),
        1024 * 1024,
        budget,
        live,
    )?;
    let plan = object(&document)?;
    scope(node, plan)?;
    schema(plan)?;
    equal_text(plan, "type", "trusted_workflow_dispatch_plan")?;
    equal_text(plan, "event", trigger)?;
    equal_text(plan, "run_id", &hex(&run_id))?;
    equal_text(
        plan,
        "run_directory_hex",
        &hex(directory.path.as_os_str().as_bytes()),
    )?;
    equal_text(plan, "source_ref_hex", &hex(reference.as_bytes()))?;
    equal_text(plan, "source_commit", &sources.commit.to_string())?;
    equal_text(plan, "object_format", node.object_format().as_str())?;
    equal_text(plan, "workflow_directory_hex", &hex(workflow_directory))?;
    if text(event, "profile")? == "latest-canonical-tag-update-v1" {
        equal_text(plan, "source_tag_tip", text(event, "tag_tip")?)?;
        equal_text(plan, "source_head", text(event, "observed_head")?)?;
    } else if plan.contains_key("source_tag_tip") {
        return Err(invalid("non-tag watch dispatch contains a tag tip"));
    }
    if plan.contains_key("candidate")
        || plan.contains_key("merge")
        || plan
            .get("input_kind")
            .is_some_and(|kind| kind.text() != Some("canonical"))
    {
        return Err(invalid(
            "watch dispatch must select admitted canonical input",
        ));
    }
    let definitions = array(plan, "workflows")?;
    if definitions.len() > 32 {
        return Err(invalid("watch dispatch workflow bound exceeded"));
    }
    let mut selected = Vec::new();
    let mut previous: Option<Vec<u8>> = None;
    let mut seen = BTreeSet::new();
    for definition in definitions {
        checkpoint(live)?;
        let definition = object(definition)?;
        let path = path_bytes(text(definition, "path_hex")?)?;
        let tail = path
            .strip_prefix(workflow_directory)
            .and_then(|tail| tail.strip_prefix(b"/"))
            .ok_or_else(|| invalid("watch workflow is outside the original directory"))?;
        if tail.contains(&b'/')
            || !(tail.ends_with(b".yml") || tail.ends_with(b".yaml"))
            || previous.as_ref().is_some_and(|previous| previous >= &path)
        {
            return Err(invalid("watch workflow order or direct path differs"));
        }
        previous = Some(path.clone());
        let run = bytes::<16>(text(definition, "run_id")?)?;
        if run != child_id(run_id, trigger, &path) || !seen.insert(run) || run == [0; 16] {
            return Err(invalid("watch workflow child identity differs"));
        }
        let blob = GitOid::from_hex(node.object_format(), text(definition, "blob")?)
            .map_err(|_| invalid("watch workflow native identity invalid"))?;
        if blob.is_zero() {
            return Err(invalid("zero watch workflow identity"));
        }
        selected.push(Definition {
            run,
            path,
            blob,
            graph: bytes::<32>(text(definition, "graph_sha256")?)?,
            selected: boolean(definition, "selected")?,
        });
    }
    Ok(Dispatch {
        directory,
        identity,
        document,
        definitions: selected,
    })
}

pub(super) fn marker(
    node: &OneNode,
    reference: &RefName,
    child: &Path,
    dispatch: &Dispatch,
    definition: &Definition,
    run: &Run,
    commit: GitOid,
    budget: &mut Budget,
    live: &dyn Fn() -> bool,
) -> Result<Value, TrustedWorkflowFailure> {
    let marker = read_json(&child.join("attempt.json"), 512 * 1024, budget, live)?;
    let fields = object(&marker)?;
    scope(node, fields)?;
    schema(fields)?;
    equal_text(fields, "type", "trusted_workflow_attempt")?;
    equal_text(fields, "state", "started")?;
    equal_text(fields, "run_id", &hex(&run.run))?;
    equal_text(
        fields,
        "run_directory_hex",
        &hex(child.as_os_str().as_bytes()),
    )?;
    equal_text(fields, "source_ref_hex", &hex(reference.as_bytes()))?;
    equal_text(fields, "source_commit", &commit.to_string())?;
    equal_text(fields, "executed_commit", &commit.to_string())?;
    equal_text(fields, "object_format", node.object_format().as_str())?;
    equal_text(fields, "input_kind", "canonical")?;
    equal_text(fields, "workflow_blob", &definition.blob.to_string())?;
    equal_text(fields, "workflow_path_hex", &hex(&definition.path))?;
    if fields.get("candidate") != Some(&Value::Null) || fields.get("merge") != Some(&Value::Null) {
        return Err(invalid(
            "watch child is not an admitted canonical execution",
        ));
    }
    let plan = object(&dispatch.document)?;
    for field in [
        "source_head",
        "source_rcr",
        "source_tree",
        "source_tag_tip",
        "read_prefixes_hex",
        "artifact_contract",
    ] {
        if fields.get(field) != plan.get(field) {
            return Err(invalid("watch child differs from original dispatch inputs"));
        }
    }
    equal_text(fields, "executed_tree", text(fields, "source_tree")?)?;
    let execution = object(
        fields
            .get("execution_plan")
            .ok_or_else(|| invalid("missing original execution plan"))?,
    )?;
    if !array(execution, "jobs")?.is_empty() || boolean(execution, "succeeded")? {
        return Err(invalid(
            "original watch attempt marker is not an unexecuted plan",
        ));
    }
    Ok(marker)
}

fn read_json(
    path: &Path,
    maximum: usize,
    budget: &mut Budget,
    live: &dyn Fn() -> bool,
) -> Result<Value, TrustedWorkflowFailure> {
    read_json_with_identity(path, maximum, budget, live).map(|(value, _)| value)
}

fn read_json_with_identity(
    path: &Path,
    maximum: usize,
    budget: &mut Budget,
    live: &dyn Fn() -> bool,
) -> Result<(Value, [u8; 32]), TrustedWorkflowFailure> {
    checkpoint(live)?;
    let bytes = read_private(path, maximum.min(budget.metadata))?;
    budget.metadata = budget
        .metadata
        .checked_sub(bytes.len())
        .ok_or_else(|| invalid("watch settlement metadata limit exceeded"))?;
    let value = json::parse_with(
        &bytes,
        json::Limits {
            input: maximum,
            depth: 16,
            nodes: 16_384,
            items: 1024,
            string: 256 * 1024,
        },
    )
    .map_err(|_| invalid("invalid bounded watch custody JSON"))?;
    checkpoint(live)?;
    Ok((value, sha256_digest(&bytes)))
}

fn scope(node: &OneNode, fields: &Object) -> Result<(), TrustedWorkflowFailure> {
    equal_text(fields, "tenant_id", &node.tenant_id().to_string())?;
    equal_text(fields, "repository_id", &node.repository_id().to_string())?;
    equal_text(
        fields,
        "repository_incarnation",
        &node.repository_incarnation_id().to_string(),
    )
}

fn schema(fields: &Object) -> Result<(), TrustedWorkflowFailure> {
    if fields.get("schema_version").and_then(Value::unsigned) != Some(1) {
        return Err(invalid("unsupported watch custody schema"));
    }
    Ok(())
}

pub(super) fn object(value: &Value) -> Result<&Object, TrustedWorkflowFailure> {
    value
        .object()
        .ok_or_else(|| invalid("watch custody object missing"))
}
pub(super) fn text<'a>(fields: &'a Object, name: &str) -> Result<&'a str, TrustedWorkflowFailure> {
    fields
        .get(name)
        .and_then(Value::text)
        .ok_or_else(|| invalid("watch custody text missing"))
}
pub(super) fn equal_text(
    fields: &Object,
    name: &str,
    expected: &str,
) -> Result<(), TrustedWorkflowFailure> {
    if text(fields, name)? == expected {
        Ok(())
    } else {
        Err(invalid("watch custody binding differs"))
    }
}
fn array<'a>(fields: &'a Object, name: &str) -> Result<&'a [Value], TrustedWorkflowFailure> {
    match fields.get(name) {
        Some(Value::Array(values)) => Ok(values),
        _ => Err(invalid("watch custody array missing")),
    }
}
fn boolean(fields: &Object, name: &str) -> Result<bool, TrustedWorkflowFailure> {
    match fields.get(name) {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(invalid("watch custody boolean missing")),
    }
}
fn bytes<const N: usize>(text: &str) -> Result<[u8; N], TrustedWorkflowFailure> {
    if text.len() != 2 * N {
        return Err(invalid("watch custody identity length differs"));
    }
    let mut bytes = [0; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(bytes)
}
fn path_bytes(text: &str) -> Result<Vec<u8>, TrustedWorkflowFailure> {
    if text.is_empty() || text.len() > 8192 || !text.len().is_multiple_of(2) {
        return Err(invalid("watch custody path length invalid"));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        bytes.push((digit(pair[0])? << 4) | digit(pair[1])?);
    }
    fgit_treefs::TreePath::parse_default(&bytes)
        .map_err(|_| invalid("watch custody path invalid"))?;
    Ok(bytes)
}
fn digit(byte: u8) -> Result<u8, TrustedWorkflowFailure> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(invalid("watch custody hex is not canonical")),
    }
}
