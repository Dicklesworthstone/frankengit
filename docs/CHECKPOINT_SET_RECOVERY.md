# Recover from an explicit set of signed checkpoints

Related bead: `frankengit-root-doctrine-x2mv.4.21` remains partial.
This connects the existing pre-payload checkpoint selector to
[offsite/native recovery](OFFSITE_NATIVE_RECOVERY.md), including
[damaged-copy reconstruction](DAMAGED_REPLICA_RECOVERY.md). It implements the
plan's anti-rollback and verified-recovery requirements without another archive
parser, signature format, checkpoint authority or native restore engine.

## One operation selects before acquiring

Use the existing command with repeated candidate groups instead of `--approval`:

```sh
node scripts/recover_repository_backup.mjs verify \
  --cache-directory /private/recovery-cache \
  --trust-key /independent/operator-ed25519.pub \
  --witness /independent/checkpoint-witness \
  --fg /absolute/path/to/fg --trusted-local --verification-instance 11 \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --incarnation-id "$INCARNATION_ID" --object-format sha256 \
  --minimum-head-generation "$MINIMUM_GENERATION" \
  --candidate /independent/checkpoint-a.approval \
    --sources /private/checkpoint-a-urls.json \
  --candidate /independent/checkpoint-b.approval \
    --repair-catalog /independent/checkpoint-b.chunks \
    --repair-replica /damaged/checkpoint-b-copy-1 \
    --repair-replica /damaged/checkpoint-b-copy-2 \
  --max-archive-bytes 1073741824 --max-acquisition-bytes 6442450944
```

Each `--candidate APPROVAL` starts a group. Following `--sources`, `--ca-file`,
`--repair-catalog` and repeated `--repair-replica` options belong to that group
until the next candidate. Every other option is global and must not be repeated.
No acquisition flags are inherited across groups. HTTPS and repair options are
mutually exclusive within a group, but different candidates may use different
modes. A group with only its approval is cache-only. Singleton `--approval` and
its existing grammar remain supported; mixing singleton intake with groups refuses.

For `restore`, add the explicit native destination, destination instance and
separate approval record described in the offsite/native guide. Selection itself
does not authorize restoration. Native signed preflight always precedes restore.

All supplied approvals must authenticate against the independently selected key
and repository identity. The shared selector compares their full-width generation
numbers before opening any archive, chunk catalog, URL file or network endpoint.
Only the highest uniquely signed statement is eligible. Invalid signatures,
conflicting highest statements and unmet retained-witness constraints refuse.
Expired, future-dated or oversized higher signed observations remain remembered;
those approvals cannot simply be omitted on the next run to recover older state.
No native refusal or failed acquisition triggers a different checkpoint.

Losing acquisition files are not read or even physically resolved. Their missing
parents cannot block an otherwise eligible winner. All candidate syntax and lexical
output separation are validated first; physical separation is checked for every
approval and the common controls, then for the chosen acquisition inputs. Stable
owner-controlled parents and a trusted executable remain requirements, not hostile
filesystem confinement. Source URL contents remain private and out of reports.

## Exact intent and deterministic ties

For equal highest **identical signed statements**, caller order selects one
candidate plan. This does not create automatic failover between plans. A selected
HTTPS plan may already contain up to 16 mirrors; a repair plan may contain up to
64 damaged copies. A selected cache-only plan refuses a cache miss rather than
silently choosing another group. Explicitly reorder or revise acquisition plans
for another attempt, retaining the original checkpoint pin where required.

`--checkpoint APPROVAL_SHA256 TRUSTED_KEY_ID` restricts selection to the exact
original approval serialization among that highest identical-statement set. Thus
reordering equivalent approvals does not invalidate an explicit original-intent
resume. The pin can never select a lower checkpoint or bypass signatures, expiry,
size, repository identity or the retained witness. If no highest candidate has the
original approval bytes and trusted key ID, the operation refuses.

That same exact approval/key pin binds reconstruction, cache publication and the
native handoff. A different valid approval substituted after selection does not
become permission to change the native restore intent. An authenticated cache hit
still rechecks the original bytes and synchronizes the existing files. After lost
native output, `--resume` retains the same destination, instance, policy, approval
record and checkpoint pin; the URL/catalog inputs may be omitted for offline use.
All candidate approvals are still authenticated, even on a cache hit or resume.

## Ownership, bounds and reports

The existing witness lease covers selection, acquisition, native work and cleanup.
Ordinary cancellation drains owned work; killed-owner or failed-persistence leases
remain blocking, with no automatic stealing/reset. Existing native completion and
exit semantics remain unchanged: exit 0 is completion delivered, exit 1 is refusal
or uncertainty, and exit 4 preserves observed native completion when local delivery
or cleanup fails. A selected set is not an atomic batch of restore operations.

The library accepts 1..64 candidate records with a combined 256 KiB path-text
budget, in addition to existing per-file and per-plan bounds. The CLI accepts at
most 1024 argument strings and 384 KiB aggregate argument text. Every candidate is
snapshotted before the first await. One remaining-time budget spans selection and
all later phases; only the chosen archive uses the acquisition payload budget.
Approval/control reads retain their separate fixed bounds. Trusted callbacks and
filesystem operations are cooperative, not forcibly preempted.

Set-mode results add `checkpoint_selection`, also retained in `recovery` on
post-selection errors. It records the authenticated approval set, chosen index,
exact pin and original-pin enforcement. Its `candidate_set_sha256` is the shared
selector's commitment to **approval observations**, not a signature or commitment
to URL contents, acquisition-plan paths or native destination consent.
`payloads_read: false` describes the selection phase, not the whole recovery.
`newest_checkpoint_verified` and `candidate_set_completeness_verified` remain
false: an explicit supplied/retained set cannot prove there is no unseen newer
checkpoint. Existing singleton result shape is unchanged.

## Executable verification and scope

```sh
node --test --test-timeout=15000 --test-concurrency=1 \
  scripts/tests/repository-backup-recovery-candidates.test.mjs \
  scripts/tests/repository-backup-recovery-candidates-cli.test.mjs \
  scripts/tests/repository-backup-recovery.test.mjs \
  scripts/tests/repository-backup-recovery-cli.test.mjs \
  scripts/tests/repository-backup-recovery-repair.test.mjs \
  scripts/tests/repository-backup-recovery-repair-cli.test.mjs
```

Tests use real private files, Ed25519, TLS sockets and reaped command processes.
They cover both hash declarations, full-u64 ordering, unavailable newer evidence,
conflicts, invalid lower signatures, disjoint acquisition plans, equivalent-envelope
pins, offline lost-response resume, cancellation, output redirection and broken
stdout. The native executable remains an explicitly labelled schema fixture, not
Rust `fg`. These operator tests do not establish actual native archive/forge
restoration, authorization/CAS, complete capsule recovery, Rust compilation,
whole-workspace acceptance or hardware power-loss survival.
