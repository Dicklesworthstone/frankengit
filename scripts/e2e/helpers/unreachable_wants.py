"""Stock-client refusal/permission twins for frankengit-aitq.

Called by the stock transport capability campaign after its ordinary clone.
Objects admitted through a temporary branch remain stored after deletion, but
their presence must not be distinguishable from a never-stored object through
the upload-pack refusal. All Git invocations are test peers, never product code.
"""

from pathlib import Path


def exercise(git, work: Path, url: str, env: dict, root: Path, fmt: str,
             prefix: str, checks) -> None:
    payload = f"unreachable object for {prefix}\n".encode()
    blob = git.run("-C", work, "hash-object", "-w", "--stdin",
                   input_bytes=payload, check=True).stdout.decode().strip()
    tree = git.run("-C", work, "mktree", input_bytes=f"100644 blob {blob}\tprivate.txt\n".encode(),
                   check=True).stdout.decode().strip()
    commit = git.out("-C", work, "commit-tree", tree, "-m", "temporary private history")
    reference = "refs/heads/unreachable-want-fixture"
    pushed = git.run("-C", work, "push", "-q", url, f"{commit}:{reference}", env=env)
    checks.add(f"{prefix}-unreachable-setup-push", pushed.returncode == 0,
               pushed.stderr.decode(errors="replace"))
    if pushed.returncode != 0:
        raise RuntimeError("unreachable-want fixture was not admitted")
    deleted = git.run("-C", work, "push", "-q", url, f":{reference}", env=env)
    checks.add(f"{prefix}-unreachable-setup-delete", deleted.returncode == 0,
               deleted.stderr.decode(errors="replace"))
    if deleted.returncode != 0:
        raise RuntimeError("unreachable-want fixture was not deleted")
    reachable = git.out("-C", work, "rev-parse", "HEAD")
    unknown = "a" * len(commit)
    for version in ("0", "2"):
        for kind, oid in (("deleted-commit", commit), ("deleted-blob", blob), ("unknown", unknown)):
            label = f"{prefix}-unreachable-{kind}-v{version}"
            client = root / label
            git.run("init", "-q", f"--object-format={fmt}", client, check=True)
            refused = git.run("-C", client, "-c", f"protocol.version={version}",
                              "fetch", "--no-tags", url, oid, env=env)
            message = refused.stderr.decode(errors="replace")
            fatals = [line for line in message.splitlines() if line.startswith("fatal:")]
            expected = f"fatal: remote error: upload-pack: not our ref {oid}"
            # Checking only a nonzero exit would accept the original hang-up /
            # HTTP 400 defect. The FIRST fatal line must be the precise ERR.
            checks.add(f"{label}-refusal", refused.returncode != 0 and fatals[:1] == [expected],
                       f"exit={refused.returncode} {message}")
            present = git.run("-C", client, "cat-file", "-e", oid)
            checks.add(f"{label}-no-object", present.returncode != 0,
                       f"cat-file exit={present.returncode}")
            allowed = git.run("-C", client, "-c", f"protocol.version={version}",
                              "fetch", "--no-tags", url, reachable, env=env)
            actual = git.run("-C", client, "rev-parse", "FETCH_HEAD").stdout.decode().strip()
            still_absent = git.run("-C", client, "cat-file", "-e", oid).returncode != 0
            checks.add(f"{label}-reachable-twin",
                       allowed.returncode == 0 and actual == reachable and still_absent,
                       f"exit={allowed.returncode} tip={actual} rejected_absent={still_absent} "
                       f"{allowed.stderr.decode(errors='replace')}")
