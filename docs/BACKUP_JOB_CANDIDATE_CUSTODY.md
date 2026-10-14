# Backup job candidate custody

Immutable replenishment jobs authenticate candidate archive/approval pairs before
sealing a recovery intent. Candidate controls are independent trust inputs and
must not physically reside inside the job directory, replica destinations,
checkpoint witness, or trust-key custody through a parent-directory alias.

Sealing now resolves every existing candidate input and approval before candidate
authentication or payload reads. Missing optional archive paths remain allowed so
restart can use another surviving replica, while a missing approval still fails in
the normal authentication path.

The selected archive/approval pair is resolved again after selection observers and
before its approval is reopened. This closes the race where an initially external
approval parent is redirected into a writable replica directory during selection.

The immutable job schema and content-addressed job identity are unchanged. These
are trusted-local stable-parent checks, not protection against a malicious
administrator or arbitrary same-user mutation between filesystem syscalls.
