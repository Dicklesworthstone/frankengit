//! Issue an interoperable source-backup approval only after complete native
//! verification. No canonical authority, capsule pointer or routing is changed.

#[cfg(unix)]
pub(super) mod filesystem;

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use super::super::emit;
#[cfg(unix)]
use super::super::{hex, quote, require_absent};
#[cfg(unix)]
use super::approval::issuer;
use super::approval::issuer::DeclarationFlags;
pub(super) use super::approval::issuer::Declarations;
#[cfg(unix)]
use super::input::PinnedArchive;
use super::profile::{Deadline, Profile, ProfileFlags};
#[cfg(unix)]
use super::restore::verify::{VerifiedSourceArchive, verify_pinned_in};
use fgit_authority::StoreInstanceId;

pub(super) const USAGE: &str =
    "usage: fg backup attest <backup-file> <new-approval-file> <new-scratch-root>
         --trusted-local --private-key <Ed25519-PKCS8-PEM>
         --expected-sha256 <64-lowercase-hex> --verification-instance <positive-integer>
         --tenant-id <hex> --repository-id <hex> --incarnation-id <hex>
         --object-format sha1|sha256 --head-generation <positive-u64>
         [--expires-at YYYY-MM-DDTHH:MM:SSZ]
         [--max-archive-bytes <1..1099511627776>] [--max-blob-bytes <1..1099511627776>]
         [--max-objects <1..1000000>] [--timeout-secs <1..86400>]

Verify the independently pinned archive's native objects, original commitments,
portable authority, exact selected inventory and complete graph before signing.
The explicit namespace, incarnation, format and exact generation must match the
native result. No private key is read before verification and scratch cleanup.
The same opened archive is rechecked through exact EOF immediately before signing.
One original deadline and all independent resource budgets cover every phase.

The detached DSSE approval uses the existing repository-backup-approval-v1 format
and is accepted by native signed verify/restore and existing operator consumers.
The key must be a canonical RFC8410 Ed25519 PKCS#8 PEM, owner-private, regular,
single-linked and stable while read. The output parent must be owner-private and
stable. This Unix filesystem profile rejects unsupported platforms explicitly.
Source, key and scratch parent paths must be trusted; this is not a hostile
same-user namespace sandbox. Existing outputs and scratch roots are never reused.

After verification closes and removes scratch, output is privately staged,
synchronized and read back before create-only publication. Failure after linking
reports visible or uncertain output; it never implies rollback or deletes it.
Preserve an output after an ambiguous result and verify it before retrying.

This is operator approval of SOURCE recovery bytes, not canonical authorization,
key-policy admission, newest-checkpoint evidence, a complete signed Capsule,
external-artifact recovery, routing or permission to replay external effects.
Keep the public key and generation floor independently for later signed restore.
Exit 0: native verification and durable approval publication; 2: refusal or an
incomplete operation, including output failure after publication.";

#[derive(Debug)]
pub(super) struct Options {
    pub input: PathBuf,
    pub output: PathBuf,
    pub scratch: PathBuf,
    pub private_key: PathBuf,
    pub expected: [u8; 32],
    pub instance: StoreInstanceId,
    pub declarations: Declarations,
    pub profile: Profile,
}

pub(super) fn parse(args: &[String]) -> Result<Options, String> {
    if !(21..=31).contains(&args.len())
        || args[0] != "attest"
        || args
            .iter()
            .any(|arg| arg.len() > 8192 || arg.contains('\0'))
        || args.iter().map(String::len).sum::<usize>() > 32768
        || args[1..4].iter().any(String::is_empty)
    {
        return Err(USAGE.into());
    }
    let (mut trusted, mut private_key, mut expected, mut instance) = (false, None, None, None);
    let mut declarations = DeclarationFlags::default();
    let mut profile = ProfileFlags::default();
    let mut cursor = 4;
    while let Some(flag) = args.get(cursor) {
        cursor += 1;
        if flag == "--trusted-local" && !trusted {
            trusted = true;
            continue;
        }
        let value = args
            .get(cursor)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        cursor += 1;
        match flag.as_str() {
            "--private-key" if private_key.is_none() => {
                if value.is_empty() {
                    return Err("private key requires a nonempty path".into());
                }
                private_key = Some(PathBuf::from(value));
            }
            "--expected-sha256" if expected.is_none() => {
                expected = Some(super::restore::digest(value)?);
            }
            "--verification-instance" if instance.is_none() => {
                if value.is_empty()
                    || value.starts_with('0')
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err("verification instance must be canonical positive decimal".into());
                }
                let number = value
                    .parse::<u64>()
                    .ok()
                    .filter(|number| *number > 0 && i64::try_from(*number).is_ok())
                    .ok_or("verification instance must fit a positive SQL integer")?;
                instance = Some(StoreInstanceId::from_raw(number));
            }
            "--max-archive-bytes" | "--max-blob-bytes" | "--max-objects" | "--timeout-secs" => {
                profile.set(flag, value)?
            }
            _ if DeclarationFlags::accepts(flag) => declarations.set(flag, value)?,
            _ => {
                return Err(format!(
                    "unknown or duplicate backup attestation option: {flag}"
                ));
            }
        }
    }
    if !trusted {
        return Err("attestation requires --trusted-local and explicit operator approval".into());
    }
    let output = PathBuf::from(&args[2]);
    let scratch = PathBuf::from(&args[3]);
    if output.file_name().is_none() || scratch.file_name().is_none() {
        return Err("attestation requires a named new approval file and scratch root".into());
    }
    Ok(Options {
        input: args[1].clone().into(),
        output,
        scratch,
        private_key: private_key.ok_or("attestation requires --private-key")?,
        expected: expected.ok_or("attestation requires independently trusted --expected-sha256")?,
        instance: instance.ok_or("attestation requires --verification-instance")?,
        declarations: declarations.finish()?,
        profile: profile.finish(),
    })
}

#[derive(Debug)]
pub(super) struct AttestationReceipt {
    json: String,
}
impl AttestationReceipt {
    pub(super) fn json(&self) -> &str {
        &self.json
    }
}

pub(super) fn execute_in(
    options: &Options,
    deadline: Deadline,
) -> Result<AttestationReceipt, String> {
    #[cfg(unix)]
    {
        execute_with_checkpoints(options, deadline, |_| Ok(()))
    }
    #[cfg(not(unix))]
    {
        let _ = (options, deadline);
        Err("backup attestation requires the Unix private-key and synchronized no-replace publication profile".into())
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    PreflightComplete,
    KeyRead,
    ContentRechecked,
    EnvelopeStaged,
    BeforePublication,
    Published,
}

#[cfg(unix)]
fn execute_with_checkpoints(
    options: &Options,
    deadline: Deadline,
    mut checkpoint: impl FnMut(Stage) -> Result<(), String>,
) -> Result<AttestationReceipt, String> {
    deadline.check()?;
    options.profile.transfer.validate()?;
    options.declarations.check_current(deadline)?;
    filesystem::destination_preflight(&options.output)?;
    require_absent(&options.scratch)?;
    let archive = PinnedArchive::open(
        &options.input,
        options.expected,
        options.profile.transfer,
        deadline,
    )?;
    let mut verified = verify_pinned_in(
        archive,
        &options.scratch,
        options.instance,
        options.profile,
        deadline,
    )?;
    options.declarations.match_archive(verified.header())?;
    options.declarations.check_current(deadline)?;
    checkpoint(Stage::PreflightComplete)?;
    let mut staged = filesystem::Stage::reserve(&options.output, deadline)?;
    let result = (|| {
        options.declarations.check_current(deadline)?;
        let key = filesystem::read_private_key(&options.private_key, staged.owner(), deadline)?;
        checkpoint(Stage::KeyRead)?;
        verified.recheck(deadline)?;
        checkpoint(Stage::ContentRechecked)?;
        let issued = issuer::issue(
            &options.declarations,
            verified.header(),
            verified.seal(),
            options.profile.transfer.max_archive_bytes,
            &key,
            deadline,
        )?;
        drop(key);
        staged.write_verified(issued.bytes(), deadline)?;
        checkpoint(Stage::EnvelopeStaged)?;
        checkpoint(Stage::BeforePublication)?;
        staged.publish(|| issued.check_current())?;
        checkpoint(Stage::Published)?;
        Ok(receipt(options, &verified, &issued))
    })();
    result.map_err(|error| staged.failure(error))
}

#[cfg(unix)]
fn receipt(
    options: &Options,
    verified: &VerifiedSourceArchive,
    issued: &issuer::IssuedApproval,
) -> AttestationReceipt {
    let graph = verified.graph();
    AttestationReceipt {
        json: format!(
            concat!(
                "{{\"type\":\"repository_backup_approval_created\",\"schema_version\":1,\"complete\":true,",
                "\"native_content_verified\":true,\"signed_identity_matched_native\":true,",
                "\"archive_bytes_authenticated\":true,\"object_graph_verified\":true,",
                "\"original_payload_commitments_verified\":true,\"authority_import_verified\":true,",
                "\"node_closed\":true,\"scratch_removed\":true,\"publication_state\":\"durable\",",
                "\"sha256\":{},\"archive_bytes\":{},\"objects\":{},\"references\":{},\"payload_bytes\":{},",
                "\"verification_instance\":{},\"approval_file\":{},\"trusted_key_id\":{},\"statement\":{},",
                "\"newest_checkpoint_verified\":false,\"complete_capsule_verified\":false,",
                "\"external_artifacts_verified\":false,\"destination_authority_published\":false,\"routing_published\":false}}"
            ),
            quote(&hex(&verified.seal().digest)),
            verified.seal().bytes,
            graph.objects,
            graph.references,
            graph.payload_bytes,
            options.instance.raw(),
            quote(&options.output.display().to_string()),
            quote(issued.trusted_key_id()),
            issued.statement_json()
        ),
    }
}

pub(super) fn run(
    args: &[String],
    output: &mut impl Write,
    timeout: Option<Duration>,
) -> Result<(), String> {
    if args == ["attest", "--help"] {
        return emit(output, USAGE);
    }
    let mut options = parse(args)?;
    options.profile = options.profile.with_timeout_cap(timeout)?;
    let receipt = execute_in(&options, options.profile.start())?;
    emit(output, receipt.json()).map_err(|error| format!("backup approval publication_state=durable; approval published; receipt output failed: {error}"))
}

#[cfg(all(test, unix))]
pub(super) mod tests;
