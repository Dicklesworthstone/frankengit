//! Actual offline verification operation, separate from process signal/output ownership.
use std::fmt::Write as _;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

use fgit_crypto::lowercase_hex;
use fgit_node::source_retrieval::integrity::bundle_verify::{
    VerifiedGitBundle, prepare_git_bundle_recovery_reader, verify_git_bundle,
    verify_git_bundle_against, verify_git_bundle_reader,
};

use super::{Options, anchors, local_files, recovery};

pub(super) fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), String> {
    if live() {
        Ok(())
    } else {
        Err("bundle_verification_stopped".into())
    }
}
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.size() == right.size()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
            && left.mode() == right.mode()
            && left.uid() == right.uid()
            && left.nlink() == right.nlink()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
            && left.permissions().readonly() == right.permissions().readonly()
    }
}
pub(crate) fn read_input(
    path: &Path,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>, String> {
    checkpoint(live)?;
    let named = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file() || named.len() == 0 || named.len() > maximum as u64 {
        return Err(
            "bundle input must be a nonempty regular non-symlink file within the byte limit".into(),
        );
    }
    // Trusted-local path, not a descriptor-relative sandbox against namespace
    // races. Object verification always consumes this one immutable owned copy.
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || !same_file(&named, &before) {
        return Err("bundle input changed while opening".into());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        checkpoint(live)?;
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.to_string()),
        };
        checkpoint(live)?;
        if count == 0 {
            break;
        }
        let total = bytes
            .len()
            .checked_add(count)
            .filter(|total| *total <= maximum)
            .ok_or("bundle input grew beyond the byte limit")?;
        bytes
            .try_reserve(count)
            .map_err(|_| "bundle input allocation refused")?;
        bytes.extend_from_slice(&buffer[..count]);
        if total as u64 > before.len() {
            return Err("bundle input length changed".into());
        }
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    let named = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !named.is_file()
        || bytes.len() as u64 != before.len()
        || !same_file(&before, &after)
        || !same_file(&after, &named)
    {
        return Err("bundle input changed while reading".into());
    }
    checkpoint(live)?;
    Ok(bytes)
}
pub(super) fn report(result: &VerifiedGitBundle) -> Result<String, String> {
    let graph = result.graph();
    let mut out = format!(
        "{{\"type\":\"git_bundle_verification\",\"schema_version\":1,\"profile\":\"native-full-bundle-graph-v1\",\"object_format\":\"{}\",\"bundle_bytes\":{},\"artifact_sha256\":\"{}\",\"pack_bytes\":{},\"pack_checksum\":\"{}\",\"object_count\":{},\"reference_count\":{},\"payload_bytes\":{},\"local_edges\":{},\"external_gitlinks\":{},\"delta_objects\":{},\"resolution_passes\":{},\"advertised_head\":{},\"references\":[",
        result.format().as_str(),
        result.bytes(),
        lowercase_hex(result.sha256()),
        result.pack_bytes(),
        lowercase_hex(result.pack_checksum().as_bytes()),
        graph.objects,
        graph.references,
        graph.payload_bytes,
        graph.local_edges,
        graph.external_gitlinks,
        result.delta_objects(),
        result.resolution_passes(),
        result.advertised_head().map_or_else(
            || "null".into(),
            |id| format!("\"{}\"", lowercase_hex(id.as_bytes()))
        )
    );
    for (index, (name, id)) in result.references().iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write!(
            out,
            "{{\"ref_hex\":\"{}\",\"object_id\":\"{}\"}}",
            lowercase_hex(name.as_bytes()),
            lowercase_hex(id.as_bytes())
        )
        .map_err(|error| error.to_string())?;
    }
    out.push_str("],\"pack_checksum_verified\":true,\"objects_verified\":true,\"object_graph_verified\":true,\"graph_scope\":\"all-included-objects-and-advertised-direct-refs\",\"gitlink_targets_verified\":false,\"signatures_verified\":false,\"origin_authenticated\":false,\"current_branch_verified\":false,\"strict_fsck_equivalent\":false,\"repository_opened\":false,\"repository_changed\":false,\"forge_state_verified\":false}");
    Ok(out)
}
pub(super) fn execute(
    options: &Options,
    live: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    if let Some(directory) = options.scratch_directory.as_deref() {
        return execute_file_backed(options, directory, live);
    }
    let bytes = read_input(
        &options.path,
        options.limits.envelope.max_bundle_bytes,
        live,
    )?;
    if let Some(head) = &options.recovery_head {
        return recovery::execute(
            &bytes,
            &options.limits,
            options.expectations.as_ref(),
            head,
            live,
        );
    }
    match &options.expectations {
        Some(expected) => {
            let result = verify_git_bundle_against(&bytes, &options.limits, expected, live)
                .map_err(|error| error.to_string())?;
            checkpoint(live)?;
            anchors::report(&result)
        }
        None => {
            let result = verify_git_bundle(&bytes, &options.limits, live)
                .map_err(|error| error.to_string())?;
            checkpoint(live)?;
            report(&result)
        }
    }
}

fn execute_file_backed(
    options: &Options,
    directory: &Path,
    live: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    let mut input = local_files::StableInput::open(
        &options.path,
        options.limits.envelope.max_bundle_bytes as u64,
        live,
    )?;
    let mut scratch = local_files::OwnedScratch::create(directory, live)?;
    let operation = (|| {
        let (mut output, scratch_bytes, pack_sha256) = if let Some(head) = &options.recovery_head {
            let plan = prepare_git_bundle_recovery_reader(
                input.file_mut(),
                scratch.file_mut()?,
                &options.limits,
                options.expectations.as_ref(),
                head,
                live,
            )
            .map_err(|error| error.to_string())?;
            input.recheck(live)?;
            scratch.recheck()?;
            let output = recovery::format_layout(
                plan.verified(),
                options.expectations.as_ref(),
                recovery::Layout {
                    pack_offset: plan.pack_offset(),
                    head_ref: plan.head_ref(),
                    index: plan.index(),
                    packed_refs: plan.packed_refs(),
                    config: plan.config(),
                    head: plan.head(),
                },
                live,
            )?;
            (output, plan.scratch_bytes(), *plan.pack_sha256())
        } else {
            let verified = verify_git_bundle_reader(
                input.file_mut(),
                scratch.file_mut()?,
                &options.limits,
                options.expectations.as_ref(),
                live,
            )
            .map_err(|error| error.to_string())?;
            input.recheck(live)?;
            scratch.recheck()?;
            let output = match options.expectations.as_ref() {
                Some(expected) => anchors::report_matched(verified.verified(), expected)?,
                None => report(verified.verified())?,
            };
            (output, verified.scratch_bytes(), *verified.pack_sha256())
        };
        input.recheck(live)?;
        if output.pop() != Some('}') {
            return Err("invalid verification report".into());
        }
        write!(output,
            ",\"storage_profile\":\"file-backed-native-full-bundle-v1\",\"scratch_bytes\":{scratch_bytes},\"scratch_removed\":true,\"pack_sha256\":\"{}\"}}",
            lowercase_hex(&pack_sha256),
        ).map_err(|error| error.to_string())?;
        checkpoint(live)?;
        Ok(output)
    })();
    // A stopped verifier still relinquishes its exact private temporary file.
    // If the namespace changed, preserve it and describe the incomplete cleanup.
    let cleanup = scratch.cleanup();
    match (operation, cleanup) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

#[cfg(test)]
#[path = "engine/tests.rs"]
mod tests;
