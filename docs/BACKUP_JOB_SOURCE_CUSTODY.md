# Backup job source custody

Recovery replenishment jobs may retain several signed source paths so that a later
run can continue after one source disappears. Those paths are immutable intent,
but lexical path separation alone is not sufficient: a parent symlink can map an
apparently external source into the job directory, a replica destination, the
checkpoint witness, or the trust-key path.

The job now resolves every source that exists when sealing and again on each run.
Any resolved source overlapping a writable recovery custody domain is refused with
`backup_job_separate_path_required`. Missing optional sources remain admissible;
they are simply unavailable candidates and can become usable on a later explicit
restart. The immutable job format is unchanged.

This check is repeated at run time because a parent alias that was safe during seal
can be retargeted before restart. Artifact signatures still authenticate bytes;
physical separation additionally prevents recovery output from being recycled as
an original source through a path alias.

Focused regression coverage lives in
`scripts/tests/repository-backup-job.test.mjs` and exercises both seal-time alias
overlap and post-seal parent redirection. These trusted-local checks do not claim
protection against a malicious administrator or arbitrary same-user races outside
the operation's existing stable-parent assumptions.
