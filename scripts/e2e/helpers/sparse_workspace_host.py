#!/usr/bin/env python3
"""End-to-end host verification for frankengit-audit-treefs-host-zb0q.

Drives the real `fg` binary across SHA-1 and SHA-256 without invoking external
Git binaries or substituting mock storage. Emits per-phase structured JSON
results consumed by `scripts/e2e/suites/treefs/sparse_workspace_host.sh`.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import (
    AUTHOR,
    PRINCIPAL,
    REF,
    REPOSITORY,
    TENANT,
    commit,
    identity,
    inspect_bundle,
    require,
    tree,
    write_object,
)


class Runner:
    def __init__(self, fg: Path, root: Path):
        self.fg = fg
        self.root = root
        self.seq = 0
        self.records = []

    def invoke(self, label: str, args, success: bool = True, timeout: int = 60):
        self.seq += 1
        out_path = self.root / f"{self.seq:03d}-{label}.out"
        err_path = self.root / f"{self.seq:03d}-{label}.err"
        env = dict(os.environ, FG_HOST_E2E_SECRET="secret-value-998877")
        with out_path.open("wb") as out_f, err_path.open("wb") as err_f:
            done = subprocess.run(
                [str(self.fg), *map(str, args)],
                stdout=out_f,
                stderr=err_f,
                env=env,
                timeout=timeout,
                check=False,
            )
        stdout = out_path.read_bytes()
        stderr = err_path.read_bytes()
        self.records.append(
            {
                "step": self.seq,
                "label": label,
                "exit_code": done.returncode,
                "expected_success": success,
            }
        )
        if (done.returncode == 0) != success:
            raise AssertionError(
                f"{label} exited {done.returncode} (expected success={success}):\n"
                f"stdout={stdout.decode(errors='replace')}\n"
                f"stderr={stderr.decode(errors='replace')}"
            )
        return stdout, stderr


def write_repo_config(source: Path, fmt: str) -> None:
    (source / "refs/heads").mkdir(parents=True, exist_ok=True)
    (source / "HEAD").write_text(f"ref: {REF}\n")
    if fmt == "sha256":
        (source / "config").write_text(
            "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        )
    else:
        (source / "config").write_text(
            "[core]\nrepositoryformatversion = 0\nbare = true\n"
        )


def alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0]
        return state not in "ZX"
    except FileNotFoundError:
        return False


def wait_stopped(pids) -> bool:
    deadline = time.monotonic() + 1.0
    while any(alive(pid) for pid in pids) and time.monotonic() < deadline:
        time.sleep(0.01)
    return not any(alive(pid) for pid in pids)


def phase_ac1(runner: Runner, work: Path, parent_override: Path | None) -> dict:
    """AC1: Sparse materialization -> bounded tool -> semantic export -> apply -> reopen & verify."""
    summary = {}
    for fmt in ("sha1", "sha256"):
        sub = work / f"ac1-{fmt}"
        source, node = sub / "source", sub / "node"
        parent = (parent_override / f"ac1-{fmt}-private") if parent_override else (sub / "private")
        parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)
        write_repo_config(source, fmt)

        docs_keep = write_object(source, fmt, "blob", b"untouched docs\n")
        docs_tree = write_object(source, fmt, "tree", tree([(b"100644", b"keep.md", docs_keep)]))
        exec_sh = write_object(source, fmt, "blob", b"#!/bin/sh\necho hi\n")
        lib_rs = write_object(source, fmt, "blob", b"pub const V: u32 = 1;\n")
        src_tree = write_object(
            source,
            fmt,
            "tree",
            tree([(b"100755", b"exec.sh", exec_sh), (b"100644", b"lib.rs", lib_rs)]),
        )
        root_tree = write_object(
            source,
            fmt,
            "tree",
            tree([(b"40000", b"docs", docs_tree), (b"40000", b"src", src_tree)]),
        )
        base_commit = write_object(source, fmt, "commit", commit(root_tree, None, 0, b"initial\n"))
        (source / REF).write_text(base_commit + "\n")

        scope = [node, TENANT, REPOSITORY]
        runner.invoke(f"ac1-{fmt}-init", ["init", *scope, fmt])
        runner.invoke(f"ac1-{fmt}-import", ["import", *scope, PRINCIPAL, f"ac1-{fmt}", source])

        slot = "a1" * 16
        bundle_name = "ac1-candidate.bundle"
        script = (
            "from pathlib import Path; import os, stat; "
            "assert not Path('docs').exists(); "
            "assert os.environ.get('FG_HOST_E2E_SECRET') is None; "
            "assert Path('src/lib.rs').read_bytes() == b'pub const V: u32 = 1;\\n'; "
            "mode = Path('src/exec.sh').stat().st_mode; "
            "assert bool(mode & stat.S_IXUSR); "
            "Path('src/lib.rs').write_bytes(b'pub const V: u32 = 2;\\n'); "
            "Path('src/gen.sh').write_bytes(b'#!/bin/sh\\nexit 0\\n'); "
            "Path('src/gen.sh').chmod(0o755)"
        )
        out, _ = runner.invoke(
            f"ac1-{fmt}-run",
            [
                "workspace",
                "run",
                *scope,
                REF,
                parent,
                slot,
                bundle_name,
                "--trusted-local",
                "--read",
                "src",
                "--write",
                "src/lib.rs",
                "--write",
                "src/gen.sh",
                "--author",
                AUTHOR,
                "--timestamp",
                "10",
                "--message",
                "ac1 update\n",
                "--timeout-secs",
                "30",
                "--",
                sys.executable,
                "-c",
                script,
            ],
        )
        receipt = json.loads(out)
        new_lib = identity(fmt, "blob", b"pub const V: u32 = 2;\n")
        new_gen = identity(fmt, "blob", b"#!/bin/sh\nexit 0\n")
        expected_src_tree = identity(
            fmt,
            "tree",
            tree(
                [
                    (b"100755", b"exec.sh", exec_sh),
                    (b"100755", b"gen.sh", new_gen),
                    (b"100644", b"lib.rs", new_lib),
                ]
            ),
        )
        expected_root_tree = identity(
            fmt,
            "tree",
            tree([(b"40000", b"docs", docs_tree), (b"40000", b"src", expected_src_tree)]),
        )
        expected_commit = identity(
            fmt, "commit", commit(expected_root_tree, base_commit, 10, b"ac1 update\n")
        )
        require(receipt["candidate_commit"] == expected_commit, "AC1 candidate_commit mismatch")
        require(receipt["root_tree"] == expected_root_tree, "AC1 root_tree mismatch")
        require("host_telemetry" in receipt, "AC1 missing host_telemetry")
        telemetry = receipt["host_telemetry"]
        payload_len = len(b"#!/bin/sh\necho hi\n") + len(b"pub const V: u32 = 1;\n")
        require(
            telemetry["copied_bytes"] + telemetry["shared_host_bytes"] == payload_len,
            "AC1 telemetry byte conservation mismatch",
        )
        bundle_path = parent / bundle_name
        inspect_bundle(bundle_path.read_bytes(), fmt, base_commit, expected_commit)
        require(not (parent / f"workspace-{slot}").exists(), "AC1 workspace slot not reaped")

        # Apply the candidate bundle to canonical authority, reopen in a fresh process, and verify!
        apply_out, _ = runner.invoke(
            f"ac1-{fmt}-apply",
            [
                "workspace",
                "apply",
                *scope,
                REF,
                bundle_path,
                "--trusted-local",
                "--principal",
                PRINCIPAL,
                "--idempotency-key",
                f"ac1-apply-{fmt}",
                "--expected-base",
                base_commit,
                "--expected-commit",
                expected_commit,
            ],
        )
        apply_receipt = json.loads(apply_out)
        require(
            apply_receipt["outcome"] == "committed" and apply_receipt["published_to_repository"] is True,
            "AC1 workspace apply did not commit",
        )
        refs_out, _ = runner.invoke(f"ac1-{fmt}-reopen-refs", ["at", *scope, "latest", "refs"])
        require(expected_commit.encode() in refs_out, "AC1 reopened authority missing published commit")

        # Verify reopened repository materializes exact updated bytes AND preserved docs/keep.md!
        verify_slot = "a2" * 16
        verify_script = (
            "from pathlib import Path; import stat; "
            "assert Path('docs/keep.md').read_bytes() == b'untouched docs\\n'; "
            "assert Path('src/lib.rs').read_bytes() == b'pub const V: u32 = 2;\\n'; "
            "assert Path('src/gen.sh').read_bytes() == b'#!/bin/sh\\nexit 0\\n'; "
            "assert bool(Path('src/gen.sh').stat().st_mode & stat.S_IXUSR)"
        )
        runner.invoke(
            f"ac1-{fmt}-verify-reopened",
            [
                "workspace",
                "run",
                *scope,
                REF,
                parent,
                verify_slot,
                "ac1-verify.bundle",
                "--trusted-local",
                "--read",
                "docs",
                "--read",
                "src",
                "--author",
                AUTHOR,
                "--timestamp",
                "11",
                "--message",
                "verify\n",
                "--",
                sys.executable,
                "-c",
                verify_script,
            ],
        )
        summary[fmt] = {
            "base_commit": base_commit,
            "published_commit": expected_commit,
            "root_tree": expected_root_tree,
            "invocation_directory": receipt["invocation_directory"],
            "request_sha256": receipt["request_sha256"],
            "terminal_sha256": receipt["terminal_sha256"],
            "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        }
    return summary


def phase_ac2(runner: Runner, work: Path) -> dict:
    """AC2: Symlink (120000) & gitlink (160000) canonical refusals + symlink-replace, alias, permission & path boundaries."""
    summary = {}
    for fmt in ("sha1", "sha256"):
        sub = work / f"ac2-{fmt}"
        source, node, parent = sub / "source", sub / "node", sub / "private"
        parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)
        write_repo_config(source, fmt)

        safe_blob = write_object(source, fmt, "blob", b"safe\n")
        safe_tree = write_object(source, fmt, "tree", tree([(b"100644", b"ok.txt", safe_blob)]))
        sym_blob = write_object(source, fmt, "blob", b"../safe/ok.txt")
        sym_tree = write_object(source, fmt, "tree", tree([(b"120000", b"escape", sym_blob)]))
        # Gitlink 160000 points to a commit OID without needing the submodule object locally in Git trees,
        # or to an existing commit OID so loose import accepts the tree cleanly.
        dummy_sub_commit = write_object(source, fmt, "commit", commit(safe_tree, None, 0, b"sub\n"))
        gitlink_tree = write_object(
            source, fmt, "tree", tree([(b"160000", b"mod", dummy_sub_commit)])
        )
        root_tree = write_object(
            source,
            fmt,
            "tree",
            tree(
                [
                    (b"40000", b"gitlinkdir", gitlink_tree),
                    (b"40000", b"safe", safe_tree),
                    (b"40000", b"symlinkdir", sym_tree),
                ]
            ),
        )
        base_commit = write_object(source, fmt, "commit", commit(root_tree, None, 0, b"ac2\n"))
        (source / REF).write_text(base_commit + "\n")

        scope = [node, TENANT, REPOSITORY]
        runner.invoke(f"ac2-{fmt}-init", ["init", *scope, fmt])
        runner.invoke(f"ac2-{fmt}-import", ["import", *scope, PRINCIPAL, f"ac2-{fmt}", source])

        def run_case(label, slot_byte, reads, writes, script, bundle_name, expect_ok):
            slot = slot_byte * 16
            cmd = ["workspace", "run", *scope, REF, parent, slot, bundle_name, "--trusted-local"]
            for r in reads:
                cmd.extend(["--read", r])
            for w in writes:
                cmd.extend(["--write", w])
            cmd.extend(
                [
                    "--author",
                    AUTHOR,
                    "--timestamp",
                    "20",
                    "--message",
                    "ac2\n",
                    "--",
                    sys.executable,
                    "-c",
                    script,
                ]
            )
            return runner.invoke(f"ac2-{fmt}-{label}", cmd, success=expect_ok)

        # 1. Canonical symlink (120000) refused vs adjacent safe directory permitted
        _, sym_err = run_case("canonical-symlink-refused", "b1", ["symlinkdir"], [], "pass", "sym.bundle", False)
        require(b"UnsupportedEntry" in sym_err or b"Symlink" in sym_err, "expected symlink refusal")
        # 2. Canonical gitlink (160000) refused vs adjacent safe directory permitted
        _, gitlink_err = run_case("canonical-gitlink-refused", "b2", ["gitlinkdir"], [], "pass", "gitlink.bundle", False)
        require(b"Gitlink" in gitlink_err or b"Unsupported" in gitlink_err, "expected gitlink refusal")
        # Permitted twin on the exact same commit!
        run_case(
            "safe-permitted-twin",
            "b3",
            ["safe"],
            ["safe/ok.txt"],
            "from pathlib import Path; Path('safe/ok.txt').write_bytes(b'updated\\n')",
            "safe-ok.bundle",
            True,
        )

        # 3. Symlink replacement of declared output and parent directory refused via openat2 RESOLVE_NO_SYMLINKS (FilesystemLoop)
        _, replace_err = run_case(
            "symlink-output-refused",
            "b4",
            ["safe"],
            ["safe/ok.txt"],
            "import os; os.unlink('safe/ok.txt'); os.symlink('/etc/hosts', 'safe/ok.txt')",
            "sym-out.bundle",
            False,
        )
        require(
            b"FilesystemLoop" in replace_err or b"UnsupportedEntry" in replace_err,
            f"expected openat2 FilesystemLoop / UnsupportedEntry symlink output refusal, got {replace_err!r}",
        )
        _, parent_sym_err = run_case(
            "parent-symlink-replacement-refused",
            "bc",
            ["safe"],
            ["safe/ok.txt"],
            "import os, shutil; shutil.rmtree('safe'); os.symlink('/tmp', 'safe')",
            "parent-sym.bundle",
            False,
        )
        require(
            b"FilesystemLoop" in parent_sym_err or b"UnsupportedEntry" in parent_sym_err,
            f"expected openat2 FilesystemLoop parent-symlink refusal, got {parent_sym_err!r}",
        )

        # 4. Hardlink alias refusal (`nlink != 1`)
        _, alias_err = run_case(
            "hardlink-alias-refused",
            "b5",
            ["safe"],
            ["safe/ok.txt", "safe/alias.txt"],
            "import os; os.link('safe/ok.txt', 'safe/alias.txt')",
            "alias.bundle",
            False,
        )
        require(b"UnsupportedEntry" in alias_err or b"AliasedEntry" in alias_err, "expected hardlink refusal")

        # 5. Undeclared input modification refusal
        _, undeclared_err = run_case(
            "undeclared-change-refused",
            "b6",
            ["safe"],
            [],
            "from pathlib import Path; Path('safe/ok.txt').write_bytes(b'sneaky\\n')",
            "undeclared.bundle",
            False,
        )
        require(b"UndeclaredChange" in undeclared_err, "expected UndeclaredChange refusal")

        # 6. Path escape / outside read prefix refusal before tool execution
        _, outside_err = run_case(
            "write-outside-read-refused",
            "b7",
            ["safe"],
            ["other/escape.txt"],
            "raise SystemExit(99)",
            "outside.bundle",
            False,
        )
        require(b"declared read prefix" in outside_err, "expected write-outside-read refusal")

        # 7. Non-private parent (0755) refused, then 0700 permitted
        os.chmod(parent, 0o755)
        try:
            _, perm_err = run_case(
                "non-private-parent-refused",
                "b8",
                ["safe"],
                ["safe/ok.txt"],
                "pass",
                "perm.bundle",
                False,
            )
            require(b"PermissionDenied" in perm_err or b"private" in perm_err, "expected 0700 parent refusal")
        finally:
            os.chmod(parent, 0o700)
        run_case(
            "restored-private-parent-permitted",
            "b9",
            ["safe"],
            ["safe/ok.txt"],
            "from pathlib import Path; Path('safe/ok.txt').write_bytes(b'restored\\n')",
            "perm-ok.bundle",
            True,
        )

        present = sorted(p.name for p in parent.iterdir())
        require(present == ["perm-ok.bundle", "safe-ok.bundle"], f"unexpected leftover entries: {present}")
        summary[fmt] = {"refusals_verified": 8, "permitted_twins_verified": 2}
    return summary


def phase_ac3(runner: Runner, work: Path, ac1_summary: dict) -> dict:
    """AC3: Bounded timeout/signal containment, replay refusal, and offline recovery."""
    summary = {}
    for fmt in ("sha1", "sha256"):
        ac1 = ac1_summary[fmt]
        node = work / f"ac1-{fmt}" / "node"
        parent = work / f"ac3-{fmt}-private"
        parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)
        scope = [node, TENANT, REPOSITORY]

        # Offline recovery of AC1's completed invocation without running any tool!
        recovered_bundle = parent / "recovered-ac1.bundle"
        rec_out, _ = runner.invoke(
            f"ac3-{fmt}-recover-ok",
            [
                "workspace",
                "recover",
                ac1["invocation_directory"],
                "--trusted-local",
                "--request-id",
                ac1["request_sha256"],
                "--terminal-id",
                ac1["terminal_sha256"],
                "--output",
                recovered_bundle,
            ],
        )
        rec_json = json.loads(rec_out)
        rec_receipt = json.loads(rec_json["receipt_json"])
        require(rec_receipt["candidate_commit"] == ac1["published_commit"], "recovered candidate mismatch")
        require(
            hashlib.sha256(recovered_bundle.read_bytes()).hexdigest() == ac1["bundle_sha256"],
            "recovered bundle bytes differ from original",
        )

        # Timeout containment with live grandchild: retains workspace, stops descendants, refuses replay!
        slot = "c3" * 16
        pidfile = work / f"ac3-{fmt}.pids"
        grandfile = work / f"ac3-{fmt}.grand"
        counter = work / f"ac3-{fmt}.count"
        timeout_script = (
            "from pathlib import Path; import json, os, subprocess, time; "
            f"c = Path({str(counter)!r}); c.write_text((c.read_text() if c.exists() else '') + '1'); "
            "Path('src/lib.rs').write_bytes(b'unexported-partial\\n'); "
            f"child = subprocess.Popen(['/bin/sh', '-c', 'sleep 30 & echo $! > {str(grandfile)}; wait']); "
            f"Path({str(pidfile)!r}).write_text(json.dumps([os.getpid(), child.pid])); "
            "time.sleep(30)"
        )
        timeout_cmd = [
            "workspace",
            "run",
            *scope,
            REF,
            parent,
            slot,
            "timeout.bundle",
            "--trusted-local",
            "--read",
            "src",
            "--write",
            "src/lib.rs",
            "--author",
            AUTHOR,
            "--timestamp",
            "30",
            "--message",
            "timeout\n",
            "--timeout-secs",
            "1",
            "--",
            sys.executable,
            "-c",
            timeout_script,
        ]
        _, err = runner.invoke(f"ac3-{fmt}-timeout-containment", timeout_cmd, success=False)
        require(
            b"Containment" in err or b"TimedOut" in err or b"timed out" in err,
            f"expected timeout/containment refusal on timeout, got {err!r}",
        )
        pids = json.loads(pidfile.read_text())
        if grandfile.exists() and grandfile.read_text().strip():
            pids.append(int(grandfile.read_text().strip()))
        require(wait_stopped(pids), f"descendants still alive after containment: {pids}")
        require((parent / f"workspace-{slot}").is_dir(), "contained workspace must be retained")
        require(not (parent / "timeout.bundle").exists(), "timed-out run must not publish bundle")

        # Replay of the same workspace_id must refuse without executing the tool again!
        runner.invoke(f"ac3-{fmt}-replay-refused", timeout_cmd, success=False)
        require(counter.read_text() == "1", "replay refusal must not re-run tool")
        summary[fmt] = {
            "offline_recovered": True,
            "containment_retained_workspace": str(parent / f"workspace-{slot}"),
            "descendants_reaped": len(pids),
        }
    return summary


def phase_ac4(runner: Runner, work: Path, parent_override: Path | None) -> dict:
    """AC4: Destroy/rebuild determinism + parallel `run-batch` shared base without cross-run leakage + telemetry."""
    summary = {}
    shared_payload = (b"immutable-shared-treefs-block-0123456789abcdef\n" * 1400)[:65536]
    for fmt in ("sha1", "sha256"):
        sub = work / f"ac4-{fmt}"
        source, node = sub / "source", sub / "node"
        parent = (parent_override / f"ac4-{fmt}-private") if parent_override else (sub / "private")
        parent.mkdir(parents=True, mode=0o700)
        os.chmod(parent, 0o700)
        write_repo_config(source, fmt)

        corpus_oid = write_object(source, fmt, "blob", shared_payload)
        out_init_oid = write_object(source, fmt, "blob", b"seed\n")
        keep_oid = write_object(source, fmt, "blob", b"untouched\n")
        shared_tree = write_object(
            source,
            fmt,
            "tree",
            tree([(b"100644", b"corpus.bin", corpus_oid), (b"100644", b"out.txt", out_init_oid)]),
        )
        root_tree = write_object(
            source,
            fmt,
            "tree",
            tree([(b"100644", b"keep.txt", keep_oid), (b"40000", b"shared", shared_tree)]),
        )
        base_commit = write_object(source, fmt, "commit", commit(root_tree, None, 0, b"ac4-base\n"))
        (source / REF).write_text(base_commit + "\n")

        scope = [node, TENANT, REPOSITORY]
        runner.invoke(f"ac4-{fmt}-init", ["init", *scope, fmt])
        runner.invoke(f"ac4-{fmt}-import", ["import", *scope, PRINCIPAL, f"ac4-{fmt}", source])

        # 1. Destroy/rebuild determinism across independent workspace slots
        rebuild_script = (
            "from pathlib import Path; "
            f"assert len(Path('shared/corpus.bin').read_bytes()) == {len(shared_payload)}; "
            "Path('shared/out.txt').write_bytes(b'deterministic-rebuild\\n')"
        )
        bundles = []
        for idx, slot_hex in enumerate(("d1" * 16, "d2" * 16)):
            bname = f"rebuild-{idx}.bundle"
            out, _ = runner.invoke(
                f"ac4-{fmt}-rebuild-{idx}",
                [
                    "workspace",
                    "run",
                    *scope,
                    REF,
                    parent,
                    slot_hex,
                    bname,
                    "--trusted-local",
                    "--read",
                    "shared",
                    "--write",
                    "shared/out.txt",
                    "--author",
                    AUTHOR,
                    "--timestamp",
                    "40",
                    "--message",
                    "rebuild\n",
                    "--",
                    sys.executable,
                    "-c",
                    rebuild_script,
                ],
            )
            r = json.loads(out)
            bundles.append((r, (parent / bname).read_bytes()))
        require(
            bundles[0][0]["candidate_commit"] == bundles[1][0]["candidate_commit"]
            and bundles[0][0]["root_tree"] == bundles[1][0]["root_tree"]
            and bundles[0][1] == bundles[1][1],
            "AC4 destroy/rebuild produced non-identical receipts or bundle bytes",
        )

        # 2. Parallel 4-workspace `run-batch` in `prefer-reflink` vs `copy` modes
        expected_corpus_sha = hashlib.sha256(shared_payload).hexdigest()

        def make_spec(prefix_byte: int, mode_tag: str) -> Path:
            jobs = []
            for j in range(4):
                ws_id = f"{prefix_byte + j:02x}" * 16
                worker_code = (
                    "from pathlib import Path; import hashlib, time; "
                    f"assert hashlib.sha256(Path('shared/corpus.bin').read_bytes()).hexdigest() == {expected_corpus_sha!r}; "
                    "assert Path('shared/out.txt').read_bytes() == b'seed\\n'; "
                    "assert not Path('keep.txt').exists(); "
                    "time.sleep(0.03); "
                    "assert Path('shared/out.txt').read_bytes() == b'seed\\n'; "
                    f"Path('shared/out.txt').write_bytes(b'parallel-job-{j}\\n')"
                )
                jobs.append(
                    {
                        "workspace_id": ws_id,
                        "bundle": f"batch-{mode_tag}-{j}.bundle",
                        "writes": ["shared/out.txt"],
                        "author": AUTHOR,
                        "timestamp": 50 + j,
                        "message": f"batch {j}\n",
                        "program": sys.executable,
                        "args": ["-c", worker_code],
                    }
                )
            spec_file = sub / f"spec-{mode_tag}.json"
            spec_file.write_text(json.dumps({"jobs": jobs}, indent=2) + "\n")
            return spec_file

        prefer_spec = make_spec(0xE0, "prefer")
        prefer_out, _ = runner.invoke(
            f"ac4-{fmt}-batch-prefer",
            [
                "workspace",
                "run-batch",
                *scope,
                REF,
                parent,
                "--trusted-local",
                "--read",
                "shared",
                "--shared-inputs",
                "prefer-reflink",
                "--timeout-secs",
                "30",
                "--spec",
                prefer_spec,
            ],
        )
        prefer_batch = json.loads(prefer_out)

        copy_spec = make_spec(0xF0, "copy")
        copy_out, _ = runner.invoke(
            f"ac4-{fmt}-batch-copy",
            [
                "workspace",
                "run-batch",
                *scope,
                REF,
                parent,
                "--trusted-local",
                "--read",
                "shared",
                "--shared-inputs",
                "copy",
                "--timeout-secs",
                "30",
                "--spec",
                copy_spec,
            ],
        )
        copy_batch = json.loads(copy_out)

        total_payload = len(shared_payload) + len(b"seed\n")
        reflink_supported = prefer_batch["cache"]["reflink_supported"]
        require(prefer_batch["cache"]["resident_bytes"] == 0, "cache resident_bytes must settle to 0")
        if reflink_supported:
            require(
                prefer_batch["cache"]["seeded_bytes"] == total_payload
                and prefer_batch["cache"]["cloned_bytes"] == 4 * total_payload,
                "CoW batch cache must seed once and clone across all 4 workspaces",
            )
        else:
            require(
                prefer_batch["cache"]["seeded_bytes"] == 0
                and prefer_batch["cache"]["fallback_bytes"] == 4 * total_payload,
                "non-CoW batch cache must account exact fallback bytes",
            )

        for j in range(4):
            p_job = prefer_batch["jobs"][j]
            c_job = copy_batch["jobs"][j]
            expected_out = identity(fmt, "blob", f"parallel-job-{j}\n".encode())
            expected_stree = identity(
                fmt,
                "tree",
                tree([(b"100644", b"corpus.bin", corpus_oid), (b"100644", b"out.txt", expected_out)]),
            )
            expected_rtree = identity(
                fmt,
                "tree",
                tree([(b"100644", b"keep.txt", keep_oid), (b"40000", b"shared", expected_stree)]),
            )
            expected_commit = identity(
                fmt, "commit", commit(expected_rtree, base_commit, 50 + j, f"batch {j}\n".encode())
            )
            require(
                p_job["candidate_commit"] == expected_commit
                and c_job["candidate_commit"] == expected_commit,
                f"batch job {j} candidate mismatch",
            )
            p_bytes = (parent / f"batch-prefer-{j}.bundle").read_bytes()
            c_bytes = (parent / f"batch-copy-{j}.bundle").read_bytes()
            require(p_bytes == c_bytes, f"batch job {j} bundle bytes differ between sharing modes")
            inspect_bundle(p_bytes, fmt, base_commit, expected_commit)
            tel = p_job["host_telemetry"]
            require(
                tel["copied_bytes"] + tel["shared_host_bytes"] == total_payload,
                "per-job byte conservation mismatch",
            )
            require(
                tel["creation_ns"] > 0 and tel["execution_ns"] > 0 and tel["cleanup_ns"] > 0,
                "per-job latency telemetry must be positive",
            )

        # Verify `--shared-inputs require-reflink` behavior matches filesystem capability honestly!
        req_slot = "dd" * 16
        req_cmd = [
            "workspace",
            "run",
            *scope,
            REF,
            parent,
            req_slot,
            "require-reflink.bundle",
            "--trusted-local",
            "--read",
            "shared",
            "--write",
            "shared/out.txt",
            "--shared-inputs",
            "require-reflink",
            "--author",
            AUTHOR,
            "--timestamp",
            "60",
            "--message",
            "require\n",
            "--",
            sys.executable,
            "-c",
            rebuild_script,
        ]
        if reflink_supported:
            req_out, _ = runner.invoke(f"ac4-{fmt}-require-reflink-ok", req_cmd, success=True)
            req_tel = json.loads(req_out)["host_telemetry"]
            require(
                req_tel["shared_host_bytes"] == total_payload and req_tel["copied_bytes"] == 0,
                "require-reflink must clone 100% of immutable inputs",
            )
        else:
            _, req_err = runner.invoke(f"ac4-{fmt}-require-reflink-refused", req_cmd, success=False)
            require(
                b"SharedInputUnavailable" in req_err,
                "require-reflink on non-CoW filesystem must fail closed with SharedInputUnavailable",
            )

        leftover_workspaces = [p.name for p in parent.iterdir() if p.name.startswith("workspace-") or p.name.startswith(".fgit-staged-")]
        require(not leftover_workspaces, f"unreaped workspace directories: {leftover_workspaces}")
        summary[fmt] = {
            "reflink_supported": reflink_supported,
            "total_payload_bytes_per_workspace": total_payload,
            "prefer_cache": prefer_batch["cache"],
            "prefer_creation_ns": [j["host_telemetry"]["creation_ns"] for j in prefer_batch["jobs"]],
            "prefer_cleanup_ns": [j["host_telemetry"]["cleanup_ns"] for j in prefer_batch["jobs"]],
            "copy_creation_ns": [j["host_telemetry"]["creation_ns"] for j in copy_batch["jobs"]],
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--parent-root", type=Path, default=None)
    opts = parser.parse_args()

    fg = opts.fg.resolve(strict=True)
    work = opts.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    parent_override = opts.parent_root.resolve(strict=True) if opts.parent_root else None

    runner = Runner(fg, work)
    ac1 = phase_ac1(runner, work, parent_override)
    ac2 = phase_ac2(runner, work)
    ac3 = phase_ac3(runner, work, ac1)
    ac4 = phase_ac4(runner, work, parent_override)

    report = {
        "bead": "frankengit-audit-treefs-host-zb0q",
        "fg_sha256": hashlib.sha256(fg.read_bytes()).hexdigest(),
        "total_cli_invocations": runner.seq,
        "ac1": ac1,
        "ac2": ac2,
        "ac3": ac3,
        "ac4": ac4,
    }
    (work / "zb0q_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    with (work / "zb0q_steps.ndjson").open("w") as ndjson:
        for rec in runner.records:
            ndjson.write(json.dumps(rec, sort_keys=True) + "\n")
    print("OK")


if __name__ == "__main__":
    main()
