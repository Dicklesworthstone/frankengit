//! Actual native verification and bare-source publication operation.
use super::{Options, filesystem, pack_source, verify};
use fgit_crypto::{lowercase_hex, sha256_digest};
use fgit_node::source_retrieval::integrity::bundle_verify::{
    VerifiedGitBundle, prepare_git_bundle_recovery, prepare_git_bundle_recovery_reader,
};
use fgit_types::RefName;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

pub(crate) fn execute(
    options: &Options,
    live: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    if let Some(directory) = options.verification.scratch_directory.as_deref() {
        return execute_file_backed(options, directory, live);
    }
    let verify = &options.verification;
    let bytes = verify::read_input(&verify.path, verify.limits.envelope.max_bundle_bytes, live)
        .map_err(|error| input_refusal(options, "input", error))?;
    let head = verify.recovery_head.as_ref().ok_or_else(|| {
        input_refusal(
            options,
            "verification",
            "missing native recovery head".into(),
        )
    })?;
    let plan = prepare_git_bundle_recovery(
        &bytes,
        &verify.limits,
        verify.expectations.as_ref(),
        head,
        live,
    )
    .map_err(|error| input_refusal(options, "verification", error.to_string()))?;
    publish(
        options,
        VerifiedLayout {
            verified: plan.verified(),
            head_ref: plan.head_ref(),
            pack: filesystem::Pack::Bytes(plan.pack()),
            index: plan.index(),
            packed_refs: plan.packed_refs(),
            config: plan.config(),
            head: plan.head(),
            file_profile: None,
        },
        live,
    )
}

fn input_refusal(options: &Options, phase: &str, error: String) -> String {
    // Verification precedes inspection of destination bodies. The file-backed
    // path only checks that scratch cannot write within the destination first.
    // A resume may already have a visible HEAD without reaching the writer.
    let uninspected_state = if options.resume {
        filesystem::State::PublicationUncertain
    } else {
        filesystem::State::Unchanged
    };
    format!(
        "native_bundle_recovery_refused: state={} no_destination_write_this_attempt=true {phase}={error}",
        uninspected_state.as_str()
    )
}

fn execute_file_backed(
    options: &Options,
    directory: &Path,
    live: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    let verify = &options.verification;
    let head = verify.recovery_head.as_ref().ok_or_else(|| {
        input_refusal(
            options,
            "verification",
            "missing native recovery head".into(),
        )
    })?;
    separate_scratch(&options.destination, directory, live)
        .map_err(|error| input_refusal(options, "scratch", error))?;
    let mut input = verify::local_files::StableInput::open(
        &verify.path,
        verify.limits.envelope.max_bundle_bytes as u64,
        live,
    )
    .map_err(|error| input_refusal(options, "input", error))?;
    let mut scratch = verify::local_files::OwnedScratch::create(directory, live)
        .map_err(|error| input_refusal(options, "scratch", error))?;
    let preparation = (|| {
        let plan = prepare_git_bundle_recovery_reader(
            input.file_mut(),
            scratch.file_mut()?,
            &verify.limits,
            verify.expectations.as_ref(),
            head,
            live,
        )
        .map_err(|error| error.to_string())?;
        input.recheck(live)?;
        scratch.recheck()?;
        Ok(plan)
    })();
    // Resolved payloads are no longer needed: the native plan owns its bounded
    // index and metadata, and publication replays the verified original pack.
    // Finish scratch ownership before inspecting any destination body or
    // performing any destination mutation.
    let cleanup = scratch.cleanup();
    let plan = match (preparation, cleanup) {
        (Ok(plan), Ok(())) => plan,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => {
            return Err(input_refusal(options, "verification", error));
        }
        (Err(error), Err(cleanup)) => {
            return Err(input_refusal(
                options,
                "verification",
                format!("{error}; {cleanup}"),
            ));
        }
    };
    input
        .recheck(live)
        .map_err(|error| input_refusal(options, "input", error))?;
    let mut source = pack_source::FilePack::new(
        &mut input,
        plan.pack_offset(),
        plan.pack_len(),
        *plan.pack_sha256(),
    )
    .map_err(|error| input_refusal(options, "input", error.to_string()))?;
    publish(
        options,
        VerifiedLayout {
            verified: plan.verified(),
            head_ref: plan.head_ref(),
            pack: filesystem::Pack::Stream(&mut source),
            index: plan.index(),
            packed_refs: plan.packed_refs(),
            config: plan.config(),
            head: plan.head(),
            file_profile: Some(FileProfile {
                scratch_bytes: plan.scratch_bytes(),
                pack_sha256: *plan.pack_sha256(),
            }),
        },
        live,
    )
}

/// Scratch is temporary verifier-owned output and must never become an entry
/// in the recovery destination. Canonicalization is read-only and also handles
/// aliases in destination parents accepted by the trusted filesystem profile.
fn separate_scratch(
    destination: &Path,
    directory: &Path,
    live: &mut impl FnMut() -> bool,
) -> Result<(), String> {
    if !live() {
        return Err("bundle verification stopped before scratch path separation".into());
    }
    let scratch = fs::canonicalize(directory)
        .map_err(|error| format!("cannot resolve scratch directory: {error}"))?;
    let destination = match fs::symlink_metadata(destination) {
        Ok(_) => fs::canonicalize(destination)
            .map_err(|error| format!("cannot resolve recovery destination: {error}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let leaf = destination
                .file_name()
                .ok_or("recovery destination must name a directory")?;
            let parent = destination
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            fs::canonicalize(parent)
                .map_err(|error| format!("cannot resolve recovery destination parent: {error}"))?
                .join(leaf)
        }
        Err(error) => return Err(format!("cannot inspect recovery destination path: {error}")),
    };
    if !live() {
        return Err("bundle verification stopped after scratch path separation".into());
    }
    if scratch.starts_with(&destination) {
        return Err("scratch directory must be outside the recovery destination".into());
    }
    // When scratch is the destination parent, its fresh private filename must
    // not alias a caller-selected destination before native verification.
    if destination.parent() == Some(scratch.as_path())
        && destination.file_name().is_some_and(|leaf| {
            let name = leaf.as_encoded_bytes();
            name.starts_with(b".fg-bundle-") && name.ends_with(b".scratch")
        })
    {
        return Err("recovery destination uses a reserved scratch filename".into());
    }
    Ok(())
}

struct FileProfile {
    scratch_bytes: u64,
    pack_sha256: [u8; 32],
}

struct VerifiedLayout<'a> {
    verified: &'a VerifiedGitBundle,
    head_ref: &'a RefName,
    pack: filesystem::Pack<'a>,
    index: &'a [u8],
    packed_refs: &'a [u8],
    config: &'a [u8],
    head: &'a [u8],
    file_profile: Option<FileProfile>,
}

fn publish(
    options: &Options,
    plan: VerifiedLayout<'_>,
    live: &mut impl FnMut() -> bool,
) -> Result<String, String> {
    let verified = plan.verified;
    let mut pack = plan.pack;
    let digest = lowercase_hex(verified.sha256());
    let head_hex = lowercase_hex(plan.head_ref.as_bytes());
    let pack_stem = format!(
        "pack-{}",
        lowercase_hex(verified.pack_checksum().as_bytes())
    );
    // The record is an exact local ownership/retry binding, never a signature,
    // trust anchor, source of object bytes, or alternate Git verification path.
    let record = format!(
        "frankengit-native-bare-recovery-v1\nartifact-sha256 {digest}\nobject-format {}\nhead-ref-hex {head_hex}\npack-checksum {}\n",
        verified.format().as_str(),
        lowercase_hex(verified.pack_checksum().as_bytes())
    );
    let mut layout = filesystem::Layout {
        record: record.as_bytes(),
        pack_stem: &pack_stem,
        // Reborrow the caller's stream for this publication. The recovery
        // record and pack filename are local metadata with the same lifetime.
        pack: match &mut pack {
            filesystem::Pack::Bytes(bytes) => filesystem::Pack::Bytes(bytes),
            filesystem::Pack::Stream(source) => filesystem::Pack::Stream(&mut **source),
        },
        index: plan.index,
        packed_refs: plan.packed_refs,
        config: plan.config,
        head: plan.head,
    };
    // Finish fallible report construction before any destination mutation.
    let mut output = format!(
        "{{\"type\":\"git_bundle_recovery\",\"schema_version\":1,\"profile\":\"native-bare-source-recovery-v1\",\"state\":\"durable\",\"object_format\":\"{}\",\"artifact_sha256\":\"{digest}\",\"bundle_bytes\":{},\"pack_checksum\":\"{}\",\"object_count\":{},\"reference_count\":{},\"head_ref_hex\":\"{head_hex}\",\"recovery_record_sha256\":\"{}\",\"resumed\":{},\"caller_expectations_matched\":{},\"object_graph_verified\":true,\"head_published\":true,\"files_synchronized\":true,\"publication_directories_synchronized\":true,\"authority_changed\":false,\"forge_state_restored\":false,\"signatures_verified\":false,\"origin_authenticated\":false,\"current_branch_verified\":false,\"gitlink_targets_verified\":false,\"references\":[",
        verified.format().as_str(),
        verified.bytes(),
        lowercase_hex(verified.pack_checksum().as_bytes()),
        verified.graph().objects,
        verified.graph().references,
        lowercase_hex(&sha256_digest(record.as_bytes())),
        options.resume,
        options.verification.expectations.is_some()
    );
    for (at, (name, id)) in verified.references().iter().enumerate() {
        if at > 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"ref_hex\":\"{}\",\"object_id\":\"{}\"}}",
            lowercase_hex(name.as_bytes()),
            lowercase_hex(id.as_bytes())
        )
        .map_err(|error| input_refusal(options, "report", error.to_string()))?;
    }
    output.push(']');
    if let Some(profile) = plan.file_profile {
        write!(output,
            ",\"storage_profile\":\"file-backed-native-bare-source-recovery-v1\",\"scratch_bytes\":{},\"scratch_removed\":true,\"pack_sha256\":\"{}\"",
            profile.scratch_bytes, lowercase_hex(&profile.pack_sha256),
        ).map_err(|error| input_refusal(options, "report", error.to_string()))?;
    }
    output.push_str(",\"already_published\":");
    output
        .try_reserve(6)
        .map_err(|_| input_refusal(options, "report", "allocation refused".into()))?;
    let completed =
        filesystem::materialize(&options.destination, &mut layout, options.resume, live)
            .map_err(|error| error.to_string())?;
    output.push_str(if completed.already_published {
        "true}"
    } else {
        "false}"
    });
    Ok(output)
}

#[cfg(all(test, unix))]
#[path = "engine/tests.rs"]
mod tests;
