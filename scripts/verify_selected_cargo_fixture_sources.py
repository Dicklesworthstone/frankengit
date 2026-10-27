#!/usr/bin/env python3
"""Exercise selected Cargo inputs with the original checker fixtures intact.

Consumer: the .4.72 implementer and batch verifier. Feature: remote Cargo must
accept negative manifests as data and refuse the same bytes when selected.
Observed defect: RCH-E413 treated unselected checker fixtures as Cargo inputs.
Retire this focused entrypoint when the ordinary remote verification lane owns
these exact permitted/refused pairs. This is not cancellation/retry, full-bead,
independent batch, full-workspace, release, or deployed-helper acceptance.

Run on a Linux dispatcher. Supply an existing physical, owner-private canonical
work root, its already configured alias, a clean source checkout under that root,
and the explicit qualified RCH body/hash. The worker comes from normal RCH
inventory; --ssh-identity is used only for a read-only SBH check of that worker.
No routing/configuration installation, timeout/queue/priority changes, local
compiler fallback, fixture exclusions, recovery, or automatic replay occur.
Every invocation creates a new retained run directory; it never resumes a run.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile


FORBIDDEN = "tools/registry-check/tests/fixtures/crate_graph/forbidden_surfaces/crates/forbidden/Cargo.toml"
TABLE = "tools/registry-check/tests/fixtures/workspace_inheritance/table_header/crates/table/Cargo.toml"
ORIGINALS = {
    FORBIDDEN: b'''[package]
name = "fgit-forbidden"
version = "0.0.1"
edition = "2024"
build = "build.rs"

[lib]
proc-macro = true
''',
    TABLE: b'''[package]
name = "fgit-table-header"
version = "0.0.1"
edition = "2024"
publish = false

[dependencies.path-smuggle]
path = "/absolute/unpublished"

[dependencies.unpinned-git]
git = "https://example.invalid/unpinned.git"

[dependencies.pinned-git]
git = "https://example.invalid/pinned.git"
rev = "0123456789012345678901234567890123456789"
''',
}
CHECKER_TESTS = (
    "tests::planted_unsafe_ffi_assembly_build_proc_and_nested_lock_are_refused",
    "tests::dependency_table_headers_cannot_hide_path_or_unpinned_git_sources",
)
RUSTC = "90850177249efe0321573c569aec5d12b257f8d6"
TARGET = "x86_64-unknown-linux-gnu"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(body):
    return hashlib.sha256(body).hexdigest()


def process_start_ticks(pid):
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        require(raw.split("(", 1)[0].strip() == str(pid), "process stat PID differs")
        _, closing, tail = raw.rpartition(")")
        require(closing == ")", "process stat command field is incomplete")
        # tail starts at field 3 (state); starttime is Linux stat field 22.
        ticks = int(tail.split()[19])
        return ticks if ticks > 0 else None
    except (OSError, RuntimeError, ValueError, IndexError):
        return None


def physical_directory(value):
    path = Path(value)
    require(path.is_absolute() and path.resolve() == path, f"not a physical absolute path: {path}")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), f"not an owned directory: {path}")
    return path


def git(root, *args):
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        require(not os.environ.get(key), f"Git metadata override is not admitted: {key}")
    result = subprocess.run(["git", *args], cwd=root, capture_output=True,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"))
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
    require(result.returncode == 0, f"git {' '.join(args)} failed at {root}")
    return result.stdout


def inventory(root):
    entries = []
    for raw in git(root, "ls-files", "-z").split(b"\0"):
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = root / relative
        mode = path.lstat().st_mode
        kind = "symlink" if stat.S_ISLNK(mode) else "regular"
        require(kind == "symlink" or stat.S_ISREG(mode), f"non-file source: {path}")
        body = os.fsencode(os.readlink(path)) if kind == "symlink" else path.read_bytes()
        entries.append(dict(path=relative, kind=kind, executable=bool(mode & 0o111), bytes=len(body), sha256=sha(body)))
    return entries


def clean(root, revision, tree, expected):
    require(git(root, "rev-parse", "HEAD").decode().strip() == revision, f"HEAD changed: {root}")
    require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == tree, f"tree changed: {root}")
    require(not git(root, "status", "--porcelain=v1", "--untracked-files=all"), f"source is dirty: {root}")
    require(inventory(root) == expected, f"source bytes/modes changed: {root}")


def write_json(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


class Run:
    def __init__(self, args):
        require(sys.platform == "linux", "this command requires a Linux dispatcher and its normal durable RCH journals")
        self.args = args
        self.work = physical_directory(args.work_root)
        require(not self.work.stat().st_mode & 0o077, "work root must already be owner-private (0700)")
        self.source = physical_directory(args.source_root)
        require(self.source.is_relative_to(self.work) and self.source != self.work, "source checkout must be below the canonical work root")
        self.alias = Path(args.alias_root)
        require(self.alias.is_absolute() and self.alias.is_symlink() and self.alias.resolve() == self.work, "existing alias must resolve to the canonical work root")
        require(self.alias.lstat().st_uid == os.getuid(), "alias is not owned by this caller")
        self.rch = Path(args.rch)
        require(self.rch.is_absolute() and self.rch.resolve() == self.rch and stat.S_ISREG(self.rch.lstat().st_mode), "RCH must be the explicit regular executable, not an alias")
        require(sha(self.rch.read_bytes()) == args.rch_sha256, "qualified RCH body hash differs")
        require(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.source_revision), "supply the complete source revision")
        self.revision = git(self.source, "rev-parse", "HEAD").decode().strip()
        require(self.revision == args.source_revision, "source revision differs from the explicitly supplied revision")
        self.tree = git(self.source, "rev-parse", "HEAD^{tree}").decode().strip()
        self.source_inventory = inventory(self.source)
        clean(self.source, self.revision, self.tree, self.source_inventory)
        for relative, original in ORIGINALS.items():
            require((self.source / relative).read_bytes() == original, f"original fixture bytes changed: {relative}")
        self.toolchain = (self.source / "rust-toolchain.toml").read_bytes()
        require(b'channel = "nightly-2026-08-31"' in self.toolchain, "source must retain the dated 2026-08-31 toolchain")
        checker = (self.source / "tools/registry-check/src/main.rs").read_text()
        for name in CHECKER_TESTS:
            require(re.search(r"#\[test\]\s+fn " + re.escape(name.removeprefix("tests::")) + r"\(", checker), f"exact current checker test is missing: {name}")
        self.env = dict(os.environ)
        forbidden = (
            "RCH_CARGO_WRAPPER_BYPASS", "RCH_FORCE_REMOTE", "RCH_QUEUE_WHEN_BUSY",
            "RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS", "RCH_DAEMON_RESPONSE_TIMEOUT_SECS",
            "RCH_MAX_REMOTE_ATTEMPTS", "RCH_DISABLE_TARGET_REUSE", "RCH_STATE_HOME",
            "XDG_STATE_HOME", "XDG_CONFIG_HOME", "RCH_CONFIG", "RCH_CONFIG_PATH",
            "RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RCH_CARGO_JSON_STDOUT",
            "RCH_GIT_COMMIT", "VERGEN_GIT_SHA", "GIT_COMMIT", "GITHUB_SHA", "RCH_BUILD_SOURCE",
        )
        for key in forbidden:
            require(not self.env.get(key), f"environment override is not admitted: {key}")
        require(self.env.get("RCH_PRIORITY", "normal") == "normal", "only the normal priority is admitted")
        require(self.env.get("RCH_ENABLED", "1").lower() not in {"0", "false", "no"}, "RCH is disabled")
        require(not any(k.startswith("RCH_MOCK") and v for k, v in self.env.items()), "mock RCH environment is not admitted")
        self.env.update(RCH_REQUIRE_REMOTE="1", RCH_WORKER=args.worker,
                        RCH_CANONICAL_PROJECT_ROOT=str(self.work), RCH_ALIAS_PROJECT_ROOT=str(self.alias),
                        RCH_EXTERNAL_TIMEOUT_ENABLED="true", RCH_VISIBILITY="verbose", CARGO_NET_OFFLINE="true",
                        CARGO_HTTP_USER_AGENT="frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)")
        self.root = Path(tempfile.mkdtemp(prefix="selected-cargo-fixtures-", dir=self.work))
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(mode=0o700)
        self.env["TMPDIR"] = str(self.tmp)
        self.cli = [str(self.rch), "--no-self-healing", "--json"]
        self.journals = Path.home() / ".local/state/rch/job-leases"
        self.boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.identities = {str(p): (p.lstat().st_dev, p.lstat().st_ino, p.lstat().st_uid) for p in [self.work, self.source, self.alias, self.tmp]}
        self.configs = {p: sha(p.read_bytes()) for p in [Path.home() / ".config/rch/config.toml", Path.home() / ".config/rch/workers.toml"]}
        write_json(self.root / "source-manifest.json", self.source_inventory)
        write_json(self.root / "run.json", dict(source=str(self.source), source_revision=self.revision, source_tree=self.tree,
                   qualified_rch=str(self.rch), rch_sha256=args.rch_sha256, worker=args.worker,
                   fixtures={path: sha(body) for path, body in ORIGINALS.items()}, scope=__doc__))
        print(str(self.root), flush=True)

    def pinned(self):
        require(sha(self.rch.read_bytes()) == self.args.rch_sha256, "qualified RCH body changed")
        for path, expected in self.configs.items():
            require(sha(path.read_bytes()) == expected, f"normal RCH configuration changed: {path}")
        for raw, expected in self.identities.items():
            info = Path(raw).lstat()
            require((info.st_dev, info.st_ino, info.st_uid) == expected, f"owned path identity changed: {raw}")
        clean(self.source, self.revision, self.tree, self.source_inventory)

    def capture(self, label, argv, cwd, env=None):
        with (self.root / (label + ".stdout")).open("xb") as out, (self.root / (label + ".stderr")).open("xb") as err:
            child = subprocess.Popen(argv, cwd=cwd, env=env or self.env, stdout=out, stderr=err)
            birth = process_start_ticks(child.pid)
            write_json(self.root / (label + ".command.json"), dict(argv=argv, cwd=str(cwd), wrapper_pid=child.pid,
                       boot_id=self.boot, process_start_ticks=birth))
            code = child.wait()
        stderr = (self.root / (label + ".stderr")).read_bytes()
        if stderr:
            sys.stderr.buffer.write(stderr)
            sys.stderr.buffer.flush()
        return code, child.pid, birth

    def data(self, label):
        return json.loads((self.root / (label + ".stdout")).read_text())

    def checked(self, label, argv, cwd):
        code, _, _ = self.capture(label, argv, cwd)
        require(code == 0, f"{label} failed with {code}; raw output retained; no replay")
        return self.data(label)

    def worker_route(self):
        data = self.checked("worker-inventory", self.cli + ["workers", "list"], self.source)
        require(data["success"], "normal worker inventory unavailable")
        selected = [w for w in data["data"]["workers"] if w["id"] == self.args.worker]
        require(len(selected) == 1, "worker must be an existing unique configured row")
        row = selected[0]
        require(re.fullmatch(r"[A-Za-z0-9_.:-]+", row["host"]) and re.fullmatch(r"[A-Za-z0-9_.-]+", row["user"]), "unsupported SSH endpoint spelling")
        identity = Path(self.args.ssh_identity).expanduser().resolve(strict=True)
        self.ssh = ["ssh", "-T", "-i", str(identity), "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                    "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "IdentitiesOnly=yes",
                    "-o", "ForwardAgent=no", "-o", "IdentityAgent=none", row["user"] + "@" + row["host"]]

    def gates(self, label, cargo, cwd, kind):
        self.pinned()
        for suffix, argv in [("caller-sbh", [self.args.sbh, "check", "--need", "20G", str(self.work)]),
                             ("worker-sbh", self.ssh + [shlex.join([self.args.worker_sbh, "check", "--need", "20G", str(self.work)])]),
                             ("rustc", ["rustc", "-vV"])]:
            code, _, _ = self.capture(label + "-" + suffix, argv, cwd)
            require(code == 0, f"{label}-{suffix} failed; no dispatch")
        compiler = (self.root / (label + "-rustc.stdout")).read_text()
        require("commit-hash: " + RUSTC in compiler and "host: " + TARGET in compiler, "dated compiler fingerprint differs")
        key = "compilation.test_timeout_sec" if kind == "cargo_test" else "compilation.build_timeout_sec"
        for suffix, setting, expected in [("timeout", key, "10800"), ("guard", "compilation.external_timeout_enabled", "true")]:
            value = self.checked(label + "-" + suffix, self.cli + ["config", "get", setting], cwd)
            require(value["data"]["value"] == expected, f"normal {setting} differs; do not change it to proceed")
        diagnose = self.checked(label + "-diagnose", self.cli + ["diagnose", "--dry-run"] + cargo, cwd)["data"]
        require(diagnose["classification"]["kind"] == kind and diagnose["decision"]["would_intercept"], "command is not normally classified for offload")
        require(diagnose["daemon"]["reachable"] and diagnose["daemon"]["status"] == "healthy", "normal daemon is not healthy")
        placement = diagnose["placement"]
        require(placement["requested_worker"] == self.args.worker and placement["strict_remote_policy"] == "require_remote" and placement["queue_policy"] == "queue_when_busy", "normal strict remote placement differs")
        outcome = placement["requested_worker_outcome"]
        if diagnose["dry_run"]["would_offload"]:
            require(outcome["status"] == "honored" and placement["effective_worker"] == self.args.worker, "requested worker was not honored")
        else:
            require(outcome["status"] == "no_free_slots" and outcome["reason_code"] == "RCH-I003", "non-capacity placement refusal; stop")
            worker = next(w for w in diagnose["worker_selection"]["diagnostics"]["workers"] if w["worker_id"] == self.args.worker)
            require(worker["status"] == "healthy" and worker["circuit_state"] == "closed" and worker["pressure_state"] != "critical" and worker["runtime_available"] and not worker["active_project_excluded"] and worker["reason_codes"] == ["slots.insufficient"], "worker has another refusal; stop")
        admit = self.checked(label + "-admit", self.cli + ["admit"] + cargo, cwd)
        require(admit["success"] and admit["data"]["base_recommendation"] == "offload", "normal admission did not recommend offload")

    def custody(self, label, result, pid, birth, previous, refused):
        require(birth is not None, "execution process birth was unavailable; custody is unconfirmed")
        candidates = []
        for path in self.journals.glob("rchw-*.json"):
            if path.name in previous:
                continue
            lease = json.loads(path.read_text())
            if lease.get("wrapper_pid") == pid and lease.get("boot_id") == self.boot and lease.get("process_start_ticks") == birth:
                candidates.append((path, lease))
        require(len(candidates) == 1, "exact invocation journal is absent/ambiguous; custody is unconfirmed")
        path, lease = candidates[0]
        require(lease.get("process_birth") == {"boot_id": self.boot, "start": {"platform": "linux", "ticks": birth}}, "journal process birth differs from the observed child")
        identity = lease["identity"]
        require(path.name == identity["local_wrapper_id"] + ".json", "journal identity/path mismatch")
        require(lease["state"] == "finished" and lease["terminal_acknowledged"] and lease["strict_remote"] and not lease["self_healing_enabled"], "journal is not strictly remote and acknowledged terminal")
        admission = result.get("admission")
        if admission:
            require(admission["local_wrapper_id"] == identity["local_wrapper_id"] and int(admission["remote_build_id"]) == identity["remote_build_id"] and admission["journal_path"] == str(path), "envelope/journal identity differs")
            require(admission["strict_remote"] and admission["terminal_acknowledged"], "envelope custody is unconfirmed")
        require(lease.get("worker_id") == self.args.worker and identity.get("remote_build_id") is not None, "expected worker reservation is not identifiable")
        recovery = lease.get("recovery")
        if refused:
            require(lease["exit_code"] == 1, "pre-execution planner refusal has an unexpected terminal code")
            require(recovery is None or not recovery["execution_started"], "selected negative reached execution")
        else:
            require(admission is not None and lease["exit_code"] == 0, "successful remote result lacks matched admission/exit")
            require(recovery is not None and recovery["execution_started"], "remote execution is not established")
        if recovery is not None:
            require(all(recovery[k] for k in ["sources_released", "tree_retired", "pair_released", "retired"]), "custody is not fully retired; stop without recovery/replay")
        write_json(self.root / (label + ".lease.json"), lease)

    def execute(self, label, cwd, revision, cargo, kind, negative=None, expected_test=None):
        tree = git(cwd, "rev-parse", "HEAD^{tree}").decode().strip()
        source = inventory(cwd)
        clean(cwd, revision, tree, source)
        target = self.root / ("checker-target" if expected_test else label + "-target")
        target.mkdir(mode=0o700, exist_ok=bool(expected_test))
        physical_directory(target)
        self.env["CARGO_TARGET_DIR"] = str(target)
        self.gates(label, cargo, cwd, kind)
        clean(cwd, revision, tree, source)
        previous = {p.name for p in self.journals.glob("rchw-*.json")}
        argv = self.cli + ["exec", "--worker", self.args.worker, "--base", revision, "--clean-overlay", "--no-overlay", "--"] + cargo
        code, pid, birth = self.capture(label, argv, cwd)
        write_json(self.root / (label + ".result.json"), dict(exit_code=code, revision=revision, tree=tree,
                   wrapper_pid=pid, boot_id=self.boot, process_start_ticks=birth,
                   source_manifest=source, stdout_sha256=sha((self.root / (label + ".stdout")).read_bytes()),
                   stderr_sha256=sha((self.root / (label + ".stderr")).read_bytes())))
        clean(cwd, revision, tree, source)
        self.pinned()
        require(birth is not None, "execution process birth was unavailable; custody is unconfirmed")
        result = self.data(label)
        if negative:
            require(code != 0 and result["outcome"] == "refused" and result["location"] == "local", "negative did not produce a pre-execution refusal")
            reason = result.get("fallback_reason", "")
            require("dependency preflight failed:" in reason and "policy_violation selected_cargo_sources" in reason and all(part in reason for part in negative), "unexpected refusal: queue/transport/configuration failures do not count")
            reports = []
            for line in (self.root / (label + ".stderr")).read_text(errors="replace").splitlines():
                if line.startswith("[RCH] dependency preflight report: "):
                    reports.append(json.loads(line.split(": ", 1)[1]))
            require(len(reports) == 1 and reports[0]["verified"] is False and reports[0]["reason_code"] == "RCH-E413", "expected typed RCH-E413 policy report is absent")
            self.custody(label, result, pid, birth, previous, refused=True)
        else:
            require(code == 0 and result["outcome"] == "completed" and result["location"] == "remote" and result["worker_id"] == self.args.worker and result["remote_exit_code"] == 0, "actual remote command did not complete successfully")
            self.custody(label, result, pid, birth, previous, refused=False)
            if expected_test:
                raw = (self.root / (label + ".stdout")).read_text(errors="replace") + "\n" + (self.root / (label + ".stderr")).read_text(errors="replace")
                raw = re.sub(r"\x1b\[[0-9;]*m", "", raw)
                observed = re.findall(r"^test (\S+) \.\.\. (ok|FAILED|ignored)\s*$", raw, re.MULTILINE)
                require(observed == [(expected_test, "ok")], "exact checker test did not execute once, pass, and remain unignored")

    def fixture_workspace(self, name, active=None):
        root = self.root / name
        root.mkdir(mode=0o700)
        for relative, original in ORIGINALS.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original)
            # Targets exist so selection reaches the intended missing build.rs
            # or absolute dependency. The original manifest bytes never change.
            lib = path.parent / "src/lib.rs"
            lib.parent.mkdir()
            lib.write_text("#![forbid(unsafe_code)]\n")
        members = ["probe"] + ([str(Path(FORBIDDEN).parent)] if active == "member" else [])
        (root / "Cargo.toml").write_text('[workspace]\nresolver = "3"\nmembers = ' + json.dumps(members) + "\n")
        (root / "rust-toolchain.toml").write_bytes(self.toolchain)
        (root / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "fgit-selected-fixture-probe"\nversion = "0.0.0"\n')
        package = root / "probe"
        (package / "src").mkdir(parents=True)
        manifest = '[package]\nname = "fgit-selected-fixture-probe"\nversion = "0.0.0"\nedition = "2024"\n'
        if active == "dependency":
            manifest += '\n[dependencies]\nactive-negative = { package = "fgit-table-header", path = "../' + str(Path(TABLE).parent) + '" }\n'
        (package / "Cargo.toml").write_text(manifest)
        rust = '#![forbid(unsafe_code)]\nconst fn equal(a: &[u8], b: &[u8]) -> bool {\n    if a.len() != b.len() { return false; }\n    let mut i = 0;\n    while i < a.len() { if a[i] != b[i] { return false; } i += 1; }\n    true\n}\n'
        for relative, original in ORIGINALS.items():
            rust += 'const _: () = assert!(equal(include_bytes!("../../' + relative + '"), &[' + ",".join(str(byte) for byte in original) + ']));\n'
        (package / "src/lib.rs").write_text(rust)
        git(root, "init", "--quiet")
        paths = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "probe/Cargo.toml", "probe/src/lib.rs"]
        for relative in ORIGINALS:
            paths.extend([relative, str(Path(relative).parent / "src/lib.rs")])
        git(root, "add", "--", *paths)
        git(root, "-c", "user.name=FrankenGit fixture verification", "-c", "user.email=fixture-verification@example.invalid", "commit", "--quiet", "-m", "Commit selected Cargo fixture integration input")
        revision = git(root, "rev-parse", "HEAD").decode().strip()
        write_json(self.root / (name + ".source.json"), dict(revision=revision, tree=git(root, "rev-parse", "HEAD^{tree}").decode().strip(), files=inventory(root)))
        return root, revision

    def run(self):
        self.worker_route()
        check = ["cargo", "check", "--locked", "--offline", "--target", TARGET, "--workspace", "--all-targets", "--jobs", "1"]
        for label, active, negative in [
            ("fixture-data", None, None),
            ("selected-member", "member", [FORBIDDEN, 'package.build="build.rs"', "missing selected path", "build.rs"]),
            ("selected-path-dependency", "dependency", [TABLE, "dependencies.path-smuggle.path", 'unsupported or absolute path "/absolute/unpublished"']),
        ]:
            root, revision = self.fixture_workspace(label + "-source", active)
            self.execute(label, root, revision, check, "cargo_check", negative=negative)
        for index, name in enumerate(CHECKER_TESTS):
            cargo = ["cargo", "test", "--locked", "--offline", "--target", TARGET, "-p", "fgit-registry-check", "--bin", "fgit-registry-check", "--jobs", "1", name, "--", "--exact", "--test-threads=1"]
            self.execute("checker-" + str(index + 1), self.source, self.revision, cargo, "cargo_test", expected_test=name)
        write_json(self.root / "completed.json", dict(source_revision=self.revision, permitted_compiler_checks=1,
                   selected_policy_refusals=2, exact_checker_tests=list(CHECKER_TESTS),
                   non_claims=["original .4.72 remains open", "cancellation/retry unrun", "not full workspace or release acceptance", "not independent verification"]))
        print("Specified fixture integration cases completed; original .4.72 and cancellation/retry acceptance remain open.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--work-root", required=True, help="existing physical owner-private canonical root, also present on the normal worker")
    parser.add_argument("--alias-root", required=True, help="existing owned alias symlink to --work-root; no alias is created")
    parser.add_argument("--source-root", required=True, help="clean exact FrankenGit checkout below --work-root, never modified")
    parser.add_argument("--source-revision", required=True, help="complete revision expected at --source-root")
    parser.add_argument("--rch", required=True, help="absolute path to an already qualified RCH executable")
    parser.add_argument("--rch-sha256", required=True, help="expected lowercase SHA-256 of that executable")
    parser.add_argument("--worker", required=True, help="existing normal RCH worker ID; no worker/configuration is created")
    parser.add_argument("--ssh-identity", required=True, help="existing SSH key for the configured worker's read-only SBH check")
    parser.add_argument("--sbh", default=shutil.which("sbh") or "sbh", help="existing caller SBH executable (default: normal PATH)")
    parser.add_argument("--worker-sbh", default="sbh", help="existing normal worker SBH executable (default: sbh on its SSH PATH)")
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.rch_sha256), "--rch-sha256 must contain 64 lowercase hex digits")
    Run(args).run()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, StopIteration) as error:
        print(f"selected Cargo fixture verification stopped: {error}; retain raw outputs, do not replay or claim acceptance", file=sys.stderr)
        sys.exit(1)
