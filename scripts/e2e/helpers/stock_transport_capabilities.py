#!/usr/bin/env python3
"""Stock-git transport capabilities through fg on git://, SSH and smart HTTP.

frankengit-root-doctrine-x2mv.4.33. For each object format, one source
repository is imported into a fresh node per transport, and stock git (the
host's, or the pinned oracle through --git-bin/--git-exec-path) exercises:

- partial clone with blob:none, blob:limit, tree:<depth> and combine, checked
  against the source's own `rev-list --filter-print-omitted` where the clone
  can observe the omission exactly;
- lazy fetch of omitted objects from the promisor remote (one object, then a
  checkout), compared with the source tree;
- the sparse-filter refusal (fg serves no sparse filters) for both the
  `<rev>:<path>` and the object-id spelling, which must reach the client as a
  typed refusal rather than a hang-up, beside its permitted blob:none twin;
- push and fetch of refs/notes/commits;
- clone and fetch of a superproject whose gitlink targets are absent by
  design, including a pushed gitlink update;
- `git push --atomic` success, all-or-nothing failure when one update is a
  refname conflict, and the non-atomic twin that publishes the other ref;
- absent-ref deletion alone and beside a create, in atomic and non-atomic
  sessions (frankengit-l6mb);
- unreachable commit/blob and never-existing OID fetches, with exact Git ERR
  diagnostics and a successful visible-object twin (frankengit-aitq);
- `git push -o` (push options, frankengit-321s), and the refusal of an option
  past the 1,024-byte sealable bound beside its twin at the bound;
- the typed pre-admission refusal of the over-bound option (frankengit-yrff):
  stock git must print its cause as "fatal: remote error: ...".

Every check lands in one JSON summary as {"checks": {id: {"ok", "detail"}}};
scripts/e2e/suites/transport/stock_transport_capabilities.sh asserts each id.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from unreachable_wants import exercise as unreachable_wants

TENANT, REPOSITORY, PRINCIPAL = "c1" * 16, "c2" * 16, "c3" * 16
TIMEOUT = 300
TRANSPORTS = ("http", "git", "ssh")
FILTERS = (
    ("blob-none", "blob:none", "exact"),
    ("blob-limit", "blob:limit=1k", "exact"),
    ("tree-0", "tree:0", "lazy"),
    ("tree-1", "tree:1", "lazy"),
    ("combine", "combine:blob:none+tree:2", "lazy"),
)
# Upstream's refusal of a filter it does not serve, as stock git prints it. It
# must be the client's FIRST fatal line: a hang-up, reset or truncated pack in
# its place is the defect. Over stateless HTTP protocol v0 the client adds
# "fatal: the remote end hung up unexpectedly" AFTER it; upstream's own
# git-http-backend produces the identical two lines (pinned oracle 2.54.0,
# uploadpackfilter.sparse:oid.allow=false), so that trailing line is the
# client's, not the server's.
SPARSE_REFUSAL = "fatal: remote error: filter 'sparse:oid' not supported"
# The typed pre-admission cause a stock client prints for an over-bound push
# option (frankengit-yrff).
OPTION_REFUSAL = ("fatal: remote error: a push option is empty, longer than this server accepts, "
                  "or contains NUL, CR or LF; no ref decision was attempted")


class Checks:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    def add(self, check_id: str, ok: bool, detail: str) -> bool:
        if check_id in self.rows:
            raise RuntimeError(f"duplicate check id {check_id}")
        self.rows[check_id] = {"ok": bool(ok), "detail": detail[-600:]}
        return bool(ok)


class Git:
    """Stock git with a hermetic environment; optional pinned binary and exec path."""

    def __init__(self, home: Path, git_bin: str | None, exec_path: str | None) -> None:
        home.mkdir(parents=True, exist_ok=True)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("GIT_") and not k.upper().endswith("_PROXY")}
        env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
                   GIT_AUTHOR_NAME="Capability", GIT_AUTHOR_EMAIL="capability@example.invalid",
                   GIT_COMMITTER_NAME="Capability", GIT_COMMITTER_EMAIL="capability@example.invalid",
                   GIT_AUTHOR_DATE="2001-01-01T00:00:00+0000",
                   GIT_COMMITTER_DATE="2001-01-01T00:00:00+0000")
        if git_bin:
            env["PATH"] = f"{git_bin}{os.pathsep}{env.get('PATH', '')}"
        if exec_path:
            env["GIT_EXEC_PATH"] = exec_path
        self.env = env

    def run(self, *args, env: dict | None = None, input_bytes: bytes | None = None,
            check: bool = False) -> subprocess.CompletedProcess:
        merged = dict(self.env, **(env or {}))
        result = subprocess.run(["git", *map(str, args)], env=merged, input=input_bytes,
                                capture_output=True, timeout=TIMEOUT)
        if check and result.returncode != 0:
            raise RuntimeError(f"git {' '.join(map(str, args))[:200]} failed: "
                               f"{result.stderr.decode(errors='replace')[-1500:]}")
        return result

    def out(self, *args, env: dict | None = None) -> str:
        return self.run(*args, env=env, check=True).stdout.decode().strip()


def text(result: subprocess.CompletedProcess) -> str:
    return (result.stdout + b"\n" + result.stderr).decode(errors="replace").strip()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_listening(port: int, process: subprocess.Popen) -> None:
    started = time.monotonic()
    while time.monotonic() - started < 60:
        if process.poll() is not None:
            raise RuntimeError("server exited before it listened")
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.2):
            return
        time.sleep(0.05)
    raise RuntimeError(f"nothing listened on {port}")


def build_source(git: Git, root: Path, fmt: str) -> dict:
    """Two commits on main (the second adds a gitlink), topic at the first, one note on main."""
    source = root / f"source-{fmt}"
    git.run("init", "-q", f"--object-format={fmt}", "-b", "main", source, check=True)
    (source / "d1" / "d2").mkdir(parents=True)
    (source / "small.txt").write_text("small\n")
    (source / "big.bin").write_bytes(hashlib.sha256(b"big").digest() * 128)  # 4 KiB, > 1k limit
    (source / "d1" / "mid.txt").write_text("mid\n")
    (source / "d1" / "d2" / "deep.txt").write_text("deep\n")
    git.run("-C", source, "add", ".", check=True)
    git.run("-C", source, "commit", "-qm", "base", check=True)
    git.run("-C", source, "branch", "topic", check=True)
    width = 40 if fmt == "sha1" else 64
    gitlink = ("1234567890abcdef" * 4)[:width]
    git.run("-C", source, "update-index", "--add", "--cacheinfo", f"160000,{gitlink},sub", check=True)
    (source / ".gitmodules").write_text('[submodule "sub"]\n\tpath = sub\n'
                                        "\turl = https://example.invalid/sub.git\n")
    git.run("-C", source, "add", ".gitmodules", check=True)
    git.run("-C", source, "commit", "-qm", "gitlink", check=True)
    git.run("-C", source, "notes", "add", "-m", "source note", "main", check=True)
    return {
        "path": source,
        "gitlink": gitlink,
        "main": git.out("-C", source, "rev-parse", "main"),
        "tree": git.out("-C", source, "rev-parse", "main^{tree}"),
        "big": git.out("-C", source, "rev-parse", "main:big.bin"),
        "note": git.out("-C", source, "notes", "show", "main"),
        "width": width,
    }


def omitted(git: Git, source: Path, filter_spec: str) -> set[str]:
    listed = git.out("-C", source, "rev-list", "--objects", f"--filter={filter_spec}",
                     "--filter-print-omitted", "refs/heads/main", "refs/heads/topic")
    return {line[1:].split()[0] for line in listed.splitlines() if line.startswith("~")}


def missing(git: Git, clone: Path) -> set[str]:
    listed = git.out("-C", clone, "rev-list", "--objects", "--missing=print", "--all")
    return {line[1:].split()[0] for line in listed.splitlines() if line.startswith("?")}


def ref_map(git: Git, url: str, env: dict) -> dict[str, str]:
    listed = git.out("ls-remote", url, env=env)
    return {name: oid for oid, name in (line.split("\t") for line in listed.splitlines() if line)}


def porcelain(result: subprocess.CompletedProcess) -> dict[str, str]:
    flags = {}
    for line in result.stdout.decode(errors="replace").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and ":" in parts[1]:
            flags[parts[1].split(":", 1)[1]] = parts[0] + " " + parts[2]
    return flags


def absent_ref_deletes(git: Git, work: Path, url: str, env: dict,
                      prefix: str, checks: Checks) -> None:
    """The stock client sends zero->zero only when given the full absent name.

    Short --delete names are rejected locally, so they cannot exercise the
    receiver. Compare the entire remote ref map to catch silently dropped
    companion updates as well as accidental removal of an unrelated ref.
    """
    head = git.out("-C", work, "rev-parse", "HEAD")
    for atomic in (False, True):
        label = "atomic" if atomic else "non-atomic"
        options = ["--atomic"] if atomic else []
        absent = f"refs/heads/absent-{label}"
        companion = f"refs/heads/absent-delete-create-{label}"
        before = ref_map(git, url, env)
        assert absent not in before and companion not in before
        alone = git.run("-C", work, "push", "--porcelain", *options,
                        "origin", "--delete", absent, env=env)
        after = ref_map(git, url, env)
        flags = porcelain(alone)
        checks.add(f"{prefix}-absent-delete-{label}",
                   alone.returncode == 0 and after == before
                   and flags.get(absent, "").startswith("-"),
                   f"unchanged={after == before} flags={flags} {text(alone)}")
        mixed = git.run("-C", work, "push", "--porcelain", *options, "origin",
                        f":{absent}", f"HEAD:{companion}", env=env)
        after = ref_map(git, url, env)
        expected = dict(before, **{companion: head})
        flags = porcelain(mixed)
        checks.add(f"{prefix}-absent-delete-create-{label}",
                   mixed.returncode == 0 and after == expected
                   and flags.get(absent, "").startswith("-")
                   and flags.get(companion, "").startswith("*"),
                   f"published_only_companion={after == expected} flags={flags} {text(mixed)}")


@contextlib.contextmanager
def served(fg: str, transport: str, node: Path, root: Path):
    """Yield (url, extra git env) for one continuous fg service with receive enabled."""
    label = f"{transport}-{node.name}"
    stop = root / f"{label}.stop"
    out = (root / f"{label}.out").open("wb")
    err = (root / f"{label}.err").open("wb")
    common = ["--continuous", "--stop-file", str(stop), "--max-in-flight", "1"]
    extra_env: dict[str, str] = {}
    if transport == "http":
        header = subprocess.run([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                                 "--trusted-local", "--print-credentials-header"],
                                capture_output=True, text=True, timeout=TIMEOUT, check=True).stdout.strip()
        token = secrets.token_hex(32)
        grants = root / f"{label}.grants"
        with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
            handle.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} read,receive\n")
        args = [fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                "--credentials-file", grants, "--allow-receive", *common]
        # Environment config reaches every git child, including lazy promisor fetches.
        extra_env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
                     "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {token}"}
    elif transport == "git":
        port = free_port()
        args = [fg, "serve", node, TENANT, REPOSITORY, f"127.0.0.1:{port}", "--receive-principal",
                PRINCIPAL, *common]
    else:
        port = free_port()
        key = root / f"{label}-key"
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key, "-C", "capability", "-q"],
                       check=True, timeout=TIMEOUT)
        public = base64.b64decode(Path(f"{key}.pub").read_text().split()[1])[-32:].hex()
        deploy = root / f"{label}.deploy"
        deploy.write_text(f"{public} {PRINCIPAL} read,write\n")
        host = root / f"{label}.host"
        host.write_text(secrets.token_hex(32))
        args = [fg, "serve-ssh", node, TENANT, REPOSITORY, f"127.0.0.1:{port}", "--host-key-file", host,
                "--deploy-keys-file", deploy, "--allow-receive", *common]
        extra_env = {"GIT_SSH_COMMAND": f"ssh -p {port} -i {key} -o StrictHostKeyChecking=no "
                                        "-o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR"}
    process = subprocess.Popen([str(a) for a in args], stdout=out, stderr=err)
    try:
        if transport == "http":
            url = None
            started = time.monotonic()
            while url is None and time.monotonic() - started < 60:
                if process.poll() is not None:
                    raise RuntimeError("serve-http exited before readiness")
                for line in (root / f"{label}.out").read_text().splitlines():
                    with contextlib.suppress(json.JSONDecodeError):
                        value = json.loads(line)
                        if value.get("type") == "smart_http_listening":
                            url = value["url"]
                time.sleep(0.05)
            if url is None:
                raise RuntimeError("serve-http never reported readiness")
        else:
            wait_listening(port, process)
            scheme = "git" if transport == "git" else "ssh"
            user = "" if transport == "git" else "git@"
            url = f"{scheme}://{user}127.0.0.1:{port}/{REPOSITORY}.git"
        yield url, extra_env
    finally:
        stop.touch()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=120)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        out.close()
        err.close()


def exercise(fg: str, git: Git, root: Path, fmt: str, transport: str, source: dict,
             checks: Checks, focus: str = "all") -> None:
    prefix = f"{fmt}-{transport}"
    node = root / f"node-{prefix}"
    subprocess.run([fg, "init", node, TENANT, REPOSITORY, fmt], check=True, capture_output=True, timeout=TIMEOUT)
    subprocess.run([fg, "import", node, TENANT, REPOSITORY, PRINCIPAL, f"import-{prefix}", source["path"] / ".git"],
                   check=True, capture_output=True, timeout=TIMEOUT)
    with served(fg, transport, node, root) as (url, env):
        if focus != "all":
            work = root / f"work-{prefix}"
            git.run("clone", "-q", url, work, env=env, check=True)
            if focus in ("absent-deletes", "ref-errors"):
                absent_ref_deletes(git, work, url, env, prefix, checks)
            if focus in ("unreachable-wants", "ref-errors"):
                unreachable_wants(git, work, url, env, root, fmt, prefix, checks)
            return
        # Partial clone, lazy fetch, and the sparse refusal twins (protocol v2, then v0 for blob:none).
        for name, spec, mode in FILTERS:
            clone = root / f"clone-{prefix}-{name}"
            cloned = git.run("-c", "protocol.version=2", "clone", "-q", "--no-checkout", f"--filter={spec}", url, clone,
                             env=env)
            if not checks.add(f"{prefix}-filter-{name}-clone", cloned.returncode == 0, text(cloned)):
                continue
            recorded = git.run("-C", clone, "config", "--get", "remote.origin.partialclonefilter").stdout.decode().strip()
            promisor = git.run("-C", clone, "config", "--get", "remote.origin.promisor").stdout.decode().strip()
            gone = missing(git, clone)
            if mode == "exact":
                expected = omitted(git, source["path"], spec)
                checks.add(f"{prefix}-filter-{name}-omits", promisor == "true" and gone == expected and expected,
                           f"promisor={promisor} filter={recorded} missing={sorted(gone)} expected={sorted(expected)}")
            else:
                checks.add(f"{prefix}-filter-{name}-omits", promisor == "true" and len(gone) > 0,
                           f"promisor={promisor} filter={recorded} missing={len(gone)}")
            if name == "blob-none":
                lazy = git.run("-C", clone, "cat-file", "-p", source["big"], env=env)
                checks.add(f"{prefix}-lazy-object", lazy.returncode == 0
                           and lazy.stdout == (source["path"] / "big.bin").read_bytes()
                           and source["big"] not in missing(git, clone), text(lazy)[-300:])
            checkout = git.run("-C", clone, "checkout", "-q", "main", env=env)
            tree = git.run("-C", clone, "rev-parse", "HEAD^{tree}").stdout.decode().strip()
            clean = git.run("-C", clone, "status", "--porcelain").stdout.decode().strip()
            checks.add(f"{prefix}-filter-{name}-lazy-checkout",
                       checkout.returncode == 0 and tree == source["tree"] and clean == "",
                       f"rc={checkout.returncode} tree={tree} status={clean!r} {text(checkout)[-300:]}")
        v0 = root / f"clone-{prefix}-blob-none-v0"
        cloned = git.run("-c", "protocol.version=0", "clone", "-q", "--no-checkout", "--filter=blob:none", url, v0, env=env)
        checks.add(f"{prefix}-filter-blob-none-v0", cloned.returncode == 0
                   and cloned.returncode == 0 and missing(git, v0) == omitted(git, source["path"], "blob:none"),
                   text(cloned))
        for name, spec in (("expression", "sparse:oid=main:.gitmodules"),
                           ("object-id", f"sparse:oid={git.out('-C', source['path'], 'rev-parse', 'main:.gitmodules')}")):
            for version in ("2", "0"):
                target = root / f"clone-{prefix}-sparse-{name}-v{version}"
                refused = git.run("-c", f"protocol.version={version}", "clone", "-q", "--no-checkout", f"--filter={spec}",
                                  url, target, env=env)
                said = text(refused)
                fatal = [line for line in said.splitlines() if line.startswith("fatal:")]
                checks.add(f"{prefix}-sparse-{name}-v{version}-refused",
                           refused.returncode != 0 and not target.exists() and fatal[:1] == [SPARSE_REFUSAL],
                           f"rc={refused.returncode} {said}")
        # Notes: fetch the imported note, push a second, read both from a fresh clone.
        work = root / f"work-{prefix}"
        cloned = git.run("clone", "-q", url, work, env=env)
        checks.add(f"{prefix}-clone", cloned.returncode == 0, text(cloned))
        fetched = git.run("-C", work, "fetch", "-q", "origin", "refs/notes/commits:refs/notes/commits", env=env)
        shown = git.run("-C", work, "notes", "show", "main").stdout.decode().strip()
        checks.add(f"{prefix}-notes-fetch", fetched.returncode == 0 and shown == source["note"],
                   f"{text(fetched)} note={shown!r}")
        git.run("-C", work, "notes", "add", "-m", f"pushed over {transport}", "main~1", check=True)
        pushed = git.run("-C", work, "push", "-q", "origin", "refs/notes/commits", env=env)
        local_notes = git.out("-C", work, "rev-parse", "refs/notes/commits")
        remote = ref_map(git, url, env)
        checks.add(f"{prefix}-notes-push", pushed.returncode == 0 and remote.get("refs/notes/commits") == local_notes,
                   f"{text(pushed)} remote={remote.get('refs/notes/commits')} local={local_notes}")
        reader = root / f"reader-{prefix}"
        git.run("clone", "-q", "--no-checkout", url, reader, env=env, check=True)
        git.run("-C", reader, "fetch", "-q", "origin", "refs/notes/commits:refs/notes/commits", env=env)
        both = (git.run("-C", reader, "notes", "show", "main").stdout.decode().strip(),
                git.run("-C", reader, "notes", "show", "main~1").stdout.decode().strip())
        checks.add(f"{prefix}-notes-roundtrip", both == (source["note"], f"pushed over {transport}"), repr(both))
        # Gitlinks: cloned as recorded, then moved by a push while the submodule stays absent.
        listed = git.run("-C", work, "ls-tree", "HEAD", "sub").stdout.decode().strip()
        checks.add(f"{prefix}-gitlink-clone",
                   listed == f"160000 commit {source['gitlink']}\tsub" and (work / ".gitmodules").is_file(), listed)
        moved = ("fedcba0987654321" * 4)[:source["width"]]
        git.run("-C", work, "update-index", "--cacheinfo", f"160000,{moved},sub", check=True)
        git.run("-C", work, "commit", "-qm", "move gitlink", check=True)
        pushed = git.run("-C", work, "push", "-q", "origin", "HEAD:refs/heads/main", env=env)
        git.run("-C", reader, "fetch", "-q", "origin", env=env)
        listed = git.run("-C", reader, "ls-tree", "origin/main", "sub").stdout.decode().strip()
        checks.add(f"{prefix}-gitlink-push", pushed.returncode == 0 and listed == f"160000 commit {moved}\tsub",
                   f"{text(pushed)} fetched={listed!r}")
        # Atomic push: success, all-or-nothing refusal, and the non-atomic twin.
        before = ref_map(git, url, env)
        ok = git.run("-C", work, "push", "--atomic", "--porcelain", "origin",
                     "HEAD:refs/heads/atomic-a", "HEAD:refs/heads/atomic-b", env=env)
        after = ref_map(git, url, env)
        head = git.out("-C", work, "rev-parse", "HEAD")
        checks.add(f"{prefix}-atomic-success", ok.returncode == 0
                   and after.get("refs/heads/atomic-a") == head and after.get("refs/heads/atomic-b") == head,
                   text(ok))
        before = after
        refused = git.run("-C", work, "push", "--atomic", "--porcelain", "origin",
                          "HEAD:refs/heads/atomic-c", "HEAD:refs/heads/topic/conflict", env=env)
        after = ref_map(git, url, env)
        flags = porcelain(refused)
        checks.add(f"{prefix}-atomic-all-or-nothing", refused.returncode != 0 and after == before
                   and set(flags) == {"refs/heads/atomic-c", "refs/heads/topic/conflict"}
                   and all(flag.startswith("!") for flag in flags.values()),
                   f"flags={flags} unchanged={after == before} {text(refused)[-300:]}")
        before = after
        partial = git.run("-C", work, "push", "--porcelain", "origin",
                          "HEAD:refs/heads/plain-a", "HEAD:refs/heads/topic/conflict2", env=env)
        after = ref_map(git, url, env)
        flags = porcelain(partial)
        expected = dict(before, **{"refs/heads/plain-a": head})
        checks.add(f"{prefix}-non-atomic-per-ref", partial.returncode != 0 and after == expected
                   and flags.get("refs/heads/plain-a", "").startswith("*")
                   and flags.get("refs/heads/topic/conflict2", "").startswith("!"),
                   f"flags={flags} published_only_plain={after == expected} {text(partial)[-300:]}")
        absent_ref_deletes(git, work, url, env, prefix, checks)
        unreachable_wants(git, work, url, env, root, fmt, prefix, checks)
        after = ref_map(git, url, env)
        # Push options (frankengit-321s): `git push -o` works only when the server
        # advertises push-options. The options are sealed with the request; one
        # past the sealable 1,024-byte bound is refused and publishes nothing,
        # beside its twin at the bound.
        before = after
        sent = git.run("-C", work, "push", "--porcelain", "-o", "ci.skip", "-o", "key=value", "origin",
                       "HEAD:refs/heads/push-options", env=env)
        after = ref_map(git, url, env)
        checks.add(f"{prefix}-push-options", sent.returncode == 0
                   and after == dict(before, **{"refs/heads/push-options": head}), text(sent))
        before = after
        too_long = git.run("-C", work, "push", "-o", "o" * 1025, "origin", "HEAD:refs/heads/push-option-long",
                           env=env)
        unchanged = ref_map(git, url, env) == before
        at_bound = git.run("-C", work, "push", "-o", "o" * 1024, "origin", "HEAD:refs/heads/push-option-bound",
                           env=env)
        after = ref_map(git, url, env)
        # The client reads the typed cause, not the generic pre-admission line
        # (frankengit-yrff), on every transport.
        named = OPTION_REFUSAL in text(too_long)
        checks.add(f"{prefix}-push-option-bound", too_long.returncode != 0 and unchanged and named
                   and at_bound.returncode == 0 and after == dict(before, **{"refs/heads/push-option-bound": head}),
                   f"refused_rc={too_long.returncode} unchanged={unchanged} named={named} "
                   f"{text(too_long)[-200:]} twin: {text(at_bound)[-200:]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--git-bin", help="directory holding the git to use (default: PATH)")
    parser.add_argument("--git-exec-path", help="GIT_EXEC_PATH for a relocated git install")
    parser.add_argument("--formats", default="sha1,sha256")
    parser.add_argument("--focus", choices=("all", "absent-deletes", "unreachable-wants", "ref-errors"),
                        default="all", help="run only the selected transport regression cases")
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-transport-capabilities-"))
    checks = Checks()
    summary: dict = {"type": "transport_capabilities_summary", "artifacts": str(root)}
    try:
        git = Git(root / "home", options.git_bin, options.git_exec_path)
        summary["git"] = git.out("--version")
        for fmt in options.formats.split(","):
            source = build_source(git, root, fmt)
            for transport in TRANSPORTS:
                try:
                    exercise(options.fg, git, root, fmt, transport, source, checks, options.focus)
                except Exception as error:  # recorded, never swallowed: the id fails the suite
                    checks.add(f"{fmt}-{transport}-campaign", False, f"{type(error).__name__}: {error}")
                else:
                    checks.add(f"{fmt}-{transport}-campaign", True, "completed")
    finally:
        summary["checks"] = checks.rows
        options.summary.write_text(json.dumps(summary, sort_keys=True) + "\n")
        print(json.dumps({"type": summary["type"], "artifacts": str(root),
                          "failed": sorted(k for k, v in checks.rows.items() if not v["ok"])}), flush=True)


if __name__ == "__main__":
    main()
