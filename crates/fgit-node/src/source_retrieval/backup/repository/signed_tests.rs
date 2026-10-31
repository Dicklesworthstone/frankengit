//! Explicit interoperability campaign: the existing JavaScript issuer creates
//! real signatures; all archive verification and restoration remain native.
//! No external executable is called by the production approval/restore path.
use super::*;
use std::process::Command;
use std::sync::{Arc, atomic::AtomicI64};

const ISSUED_MS: i64 = 1_577_836_800_000; // 2020-01-01T00:00:00Z
const EXPIRES_MS: i64 = 2_208_988_800_000; // 2040-01-01T00:00:00Z
const ISSUER_PROGRAM: &str = r"
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const [module, archive, approval, trustKey, encoded, seed, mode] = process.argv.slice(1);
const { signRepositoryBackupFile } = await import(pathToFileURL(module));
const key = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, Number(seed))]) });
const declarations = JSON.parse(encoded);
const signed = await signRepositoryBackupFile(archive,
  Buffer.from(key.export({ format: 'pem', type: 'pkcs8' })), declarations,
  { now: Date.parse(declarations.issued_at) });
let envelope = signed.envelope;
if (mode === 'mutated') {
  const changed = JSON.parse(envelope), payload = Buffer.from(changed.payload, 'base64');
  payload[0] ^= 1; changed.payload = payload.toString('base64');
  envelope = Buffer.from(JSON.stringify(changed) + '\n');
}
await writeFile(approval, envelope, { flag: 'wx', mode: 0o600 });
await writeFile(trustKey, createPublicKey(key).export({ format: 'pem', type: 'spki' }),
  { flag: 'wx', mode: 0o600 });
";

struct Signed {
    flags: Vec<String>,
    clock: Arc<AtomicI64>,
}
impl Signed {
    fn issue(
        scratch: &Scratch,
        input: &Path,
        pin: [u8; 32],
        label: &str,
        seed: u8,
        changed_tenant: bool,
        changed_generation: bool,
        mutated_payload: bool,
    ) -> Self {
        let profile = Profile::default();
        let archive = PinnedArchive::open(input, pin, profile.transfer, profile.start()).unwrap();
        let identity = archive.header().identity;
        let tenant = if changed_tenant {
            "aa".repeat(16)
        } else {
            identity.tenant.to_string()
        };
        let generation = archive.header().authority.head.as_ref().unwrap().generation
            + u64::from(changed_generation);
        let declarations = format!(
            "{{\"tenant_id\":{},\"repository_id\":{},\"incarnation_id\":{},\"object_format\":{},\"head_generation\":{},\"issued_at\":\"2020-01-01T00:00:00Z\",\"expires_at\":\"2040-01-01T00:00:00Z\"}}",
            quote(&tenant),
            quote(&identity.repository.to_string()),
            quote(&identity.incarnation.to_string()),
            quote(identity.format.as_str()),
            quote(&generation.to_string()),
        );
        let approval = scratch.0.join(format!("{label}.dsse.json"));
        let key = scratch.0.join(format!("{label}.public.pem"));
        let node = std::env::var_os("FG_BACKUP_APPROVAL_NODE")
            .expect("explicit campaign requires FG_BACKUP_APPROVAL_NODE pointing to Node.js");
        let module = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/lib/repository-backup-approval.mjs");
        let result = Command::new(node)
            .args(["--input-type=module", "--eval", ISSUER_PROGRAM])
            .arg(module)
            .arg(input)
            .arg(&approval)
            .arg(&key)
            .arg(declarations)
            .arg(seed.to_string())
            .arg(if mutated_payload { "mutated" } else { "normal" })
            .output()
            .expect("start explicit JavaScript test fixture issuer");
        assert!(
            result.status.success(),
            "issuer: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(result.stdout.is_empty(), "issuer emitted unexpected output");
        Self {
            flags: vec![
                "--approval".into(),
                approval.to_str().unwrap().into(),
                "--trust-key".into(),
                key.to_str().unwrap().into(),
                "--tenant-id".into(),
                tenant,
                "--repository-id".into(),
                identity.repository.to_string(),
                "--incarnation-id".into(),
                identity.incarnation.to_string(),
                "--object-format".into(),
                identity.format.as_str().into(),
                "--minimum-head-generation".into(),
                generation.to_string(),
            ],
            clock: Arc::new(AtomicI64::new(ISSUED_MS)),
        }
    }

    fn options(&self, input: &Path, output: PathBuf, pin: [u8; 32]) -> Options {
        let mut args = vec![
            "restore".into(),
            input.to_str().unwrap().into(),
            output.to_str().unwrap().into(),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            hex(&pin),
            "--destination-instance".into(),
            "991".into(),
        ];
        args.extend(self.flags.clone());
        let mut options = parse(&args).unwrap();
        options
            .approval
            .as_mut()
            .unwrap()
            .set_test_clock(Arc::clone(&self.clock));
        options
    }

    fn set(&mut self, flag: &str, value: impl Into<String>) {
        let at = self.flags.iter().position(|value| value == flag).unwrap();
        self.flags[at + 1] = value.into();
    }
}

#[test]
#[ignore = "explicit real JS issuer + native source-loss restoration; set FG_BACKUP_APPROVAL_NODE"]
fn signed_native_restore_and_verification_interoperate_with_js_issuer_in_both_domains() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = Scratch::new();
        let (input, pin, commit) = fixture(&scratch, format);
        let signed = Signed::issue(&scratch, &input, pin, "valid", 0x42, false, false, false);
        assert!(!scratch.0.join("source-node").exists());
        assert!(!scratch.0.join("source.git").exists());
        let verification = scratch.0.join("preflight");
        let mut args = vec![
            "verify".into(),
            input.to_str().unwrap().into(),
            verification.to_str().unwrap().into(),
            "--trusted-local".into(),
            "--expected-sha256".into(),
            hex(&pin),
            "--verification-instance".into(),
            "990".into(),
        ];
        args.extend(signed.flags.clone());
        let mut output = Vec::new();
        verify::run(&args, &mut output, None).unwrap();
        let receipt = String::from_utf8(output).unwrap();
        assert!(receipt.contains("\"signature_verified\":true"), "{receipt}");
        assert!(receipt.contains("\"scratch_removed\":true"));
        assert!(!verification.exists());
        let mut request = signed.options(&input, scratch.0.join("restored"), pin);
        let receipt = execute(&request).unwrap();
        assert!(receipt.contains("\"signature_verified\":true"));
        assert!(receipt.contains("\"reopened_and_verified\":true"));
        assert_eq!(
            &fs::read(request.output.join(".restore-intent")).unwrap()[..8],
            b"FGRES002"
        );
        with_node(node_config(&request.output, format), |node| {
            assert_eq!(
                node.read_git_object(commit)
                    .unwrap()
                    .envelope()
                    .object_identity(),
                commit
            );
            assert_eq!(
                node.read_git_object(git_object_id(format, GitObjectKind::Blob, PAYLOAD))
                    .unwrap()
                    .payload(),
                PAYLOAD
            );
            Ok(())
        })
        .unwrap();
        let before = snapshot(&request.output);
        request.resume = true;
        assert!(
            execute(&request)
                .unwrap()
                .contains("\"already_published\":true")
        );
        assert_eq!(snapshot(&request.output), before);
    }
}

#[test]
#[ignore = "explicit real JS issuer + native refusal campaign; set FG_BACKUP_APPROVAL_NODE"]
fn signed_refusals_precede_reservation_and_preserve_exact_retry_policy() {
    let scratch = Scratch::new();
    let (input, pin, _) = fixture(&scratch, GitHashAlgorithm::Sha256);
    let valid = Signed::issue(&scratch, &input, pin, "valid", 0x42, false, false, false);
    let other = Signed::issue(&scratch, &input, pin, "other", 0x43, false, false, false);
    let malformed = Signed::issue(&scratch, &input, pin, "mutated", 0x42, false, false, true);
    let foreign = Signed::issue(&scratch, &input, pin, "foreign", 0x42, true, false, false);
    let generation = Signed::issue(
        &scratch,
        &input,
        pin,
        "generation",
        0x42,
        false,
        true,
        false,
    );
    let mut wrong_key = valid.options(&input, scratch.0.join("wrong-key"), pin);
    let mut wrong_flags = valid.flags.clone();
    wrong_flags[3] = other.flags[3].clone();
    let wrong = Signed {
        flags: wrong_flags,
        clock: Arc::clone(&valid.clock),
    };
    wrong_key.approval = wrong
        .options(&input, wrong_key.output.clone(), pin)
        .approval;
    for request in [
        wrong_key,
        malformed.options(&input, scratch.0.join("bad-signature"), pin),
        foreign.options(&input, scratch.0.join("foreign-native-header"), pin),
        generation.options(&input, scratch.0.join("wrong-native-generation"), pin),
    ] {
        assert!(execute(&request).is_err());
        assert!(!request.output.exists());
    }
    let mut above = Signed {
        flags: valid.flags.clone(),
        clock: Arc::clone(&valid.clock),
    };
    above.set("--minimum-head-generation", "18446744073709551615");
    let request = above.options(&input, scratch.0.join("below-floor"), pin);
    assert!(execute(&request).is_err());
    assert!(!request.output.exists());

    let mut request = valid.options(&input, scratch.0.join("interrupted"), pin);
    stop(&request, Stage::DataPrepared);
    let marker = fs::read(request.output.join(".restore-intent")).unwrap();
    request.resume = true;
    let saved = request.approval.take();
    let error = execute(&request).unwrap_err();
    assert!(
        error.contains("prior attempt may already have published"),
        "{error}"
    );
    request.approval = saved;
    let mut changed = valid.flags.clone();
    changed[13] = "1".into(); // Weaker, independently accepted floor still changes the binding.
    let weaker = Signed {
        flags: changed,
        clock: Arc::clone(&valid.clock),
    };
    let mut retry = weaker.options(&input, request.output.clone(), pin);
    retry.resume = true;
    assert!(
        execute(&retry)
            .unwrap_err()
            .contains("intent does not match")
    );
    let mut different = other.options(&input, request.output.clone(), pin);
    different.resume = true;
    assert!(
        execute(&different)
            .unwrap_err()
            .contains("intent does not match")
    );
    assert_eq!(
        fs::read(request.output.join(".restore-intent")).unwrap(),
        marker
    );
    assert!(!request.output.join("authority.fsqlite").exists());
    assert!(
        request.output.join("objects").is_dir(),
        "failed retry must not normalize paths"
    );
    let approval_path = Path::new(&valid.flags[1]);
    let original = fs::read(approval_path).unwrap();
    let mut reformatted = original.clone();
    reformatted.push(b'\n');
    fs::write(approval_path, reformatted).unwrap();
    assert!(
        execute(&request)
            .unwrap_err()
            .contains("intent does not match")
    );
    assert!(request.output.join("objects").is_dir());
    fs::write(approval_path, original).unwrap();
    assert!(execute(&request).is_ok());
}

#[test]
#[ignore = "explicit real JS issuer + per-operation expiry clock; set FG_BACKUP_APPROVAL_NODE"]
fn approval_expiry_is_checked_at_publication_without_rewriting_visible_outcomes() {
    let scratch = Scratch::new();
    let (input, pin, _) = fixture(&scratch, GitHashAlgorithm::Sha1);
    let signed = Signed::issue(&scratch, &input, pin, "expiry", 0x42, false, false, false);
    let mut request = signed.options(&input, scratch.0.join("expires-before-link"), pin);
    let error = execute_with_checkpoints(&request, |stage| {
        if stage == Stage::DataPrepared {
            signed.clock.store(EXPIRES_MS, Ordering::SeqCst);
        }
        Ok(())
    })
    .unwrap_err();
    assert!(error.contains("expired"), "{error}");
    assert!(
        error.contains("destination authority not published"),
        "{error}"
    );
    assert!(!request.output.join("authority.fsqlite").exists());
    assert!(request.output.join(".restore-intent").exists());
    request.resume = true;
    assert!(
        execute(&request)
            .unwrap_err()
            .contains("prior attempt may already have published")
    );
    signed.clock.store(ISSUED_MS, Ordering::SeqCst);
    assert!(execute(&request).is_ok());

    let visible = signed.options(&input, scratch.0.join("expires-after-link"), pin);
    let receipt = execute_with_checkpoints(&visible, |stage| {
        if stage == Stage::Published {
            signed.clock.store(EXPIRES_MS, Ordering::SeqCst);
        }
        Ok(())
    })
    .unwrap();
    assert!(receipt.contains("\"signature_verified\":true"));
    assert!(visible.output.join("authority.fsqlite").exists());
    let before = snapshot(&visible.output);
    let mut retry = signed.options(&input, visible.output.clone(), pin);
    retry.resume = true;
    let error = execute(&retry).unwrap_err();
    assert!(
        error.contains("prior attempt may already have published"),
        "{error}"
    );
    assert_eq!(snapshot(&visible.output), before);
}
