"""Real fg optional-step execution, safety stops and exact persisted evidence."""
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import sys
import time
import zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2]).resolve()
root.mkdir(parents=True, exist_ok=True)
tenant, repository, principal = "1" * 32, "2" * 32, "3" * 32
commands, cases = 0, []


def invoke(label, arguments, expected=0, seconds=120):
    global commands
    commands += 1
    result = subprocess.run(
        [fg, "--timeout-secs", str(seconds), *map(str, arguments)],
        capture_output=True,
        timeout=180,
    )
    (root / f"{commands:03d}-{label}.out").write_bytes(result.stdout)
    (root / f"{commands:03d}-{label}.err").write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (
        label, result.returncode, expected, result.stdout[-8000:], result.stderr[-8000:]
    )
    return result.stdout


def native_object(source, fmt, kind, body):
    raw = kind.encode() + b" " + str(len(body)).encode() + b"\0" + body
    oid = hashlib.new(fmt, raw).hexdigest()
    path = source / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(raw))
    return oid


def source_tree(source, fmt, files):
    entries = {}
    for path, value in files.items():
        name, separator, remainder = path.partition("/")
        if separator:
            entries.setdefault(name, {})[remainder] = value
        else:
            entries[name] = value
    body = bytearray()
    for name, value in sorted(entries.items(), key=lambda item: item[0] + ("/" if isinstance(item[1], dict) else "")):
        directory = isinstance(value, dict)
        oid = source_tree(source, fmt, value) if directory else native_object(source, fmt, "blob", value)
        body.extend((b"40000" if directory else b"100644") + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
    return native_object(source, fmt, "tree", body)


def workflow(script, optional=True, diagnostics=False):
    text = """name: optional step
on: workflow_dispatch
jobs:
  build:
    runs-on: fgit-trusted-local
    steps:
      - name: observed command
        continue-on-error: POLICY
        run: |
""".replace("POLICY", "true" if optional else "false")
    text += "".join("          " + line + "\n" for line in script.splitlines())
    text += """      - name: required continuation
        run: test -f state; printf REQUIRED
"""
    if diagnostics:
        text += """      - name: failure diagnostic
        if: failure()
        run: test -f state; printf DIAGNOSTIC
      - name: final diagnostic
        if: always()
        run: printf ALWAYS
"""
    return text + """  dependent:
    runs-on: fgit-trusted-local
    needs: build
    steps:
      - run: test ! -f state; printf DEPENDENT
"""


def alive(pid):
    try:
        stat = pathlib.Path(f"/proc/{pid}/stat").read_bytes()
    except FileNotFoundError:
        return False
    return stat[stat.rindex(b")") + 1:].split()[0] not in (b"Z", b"X")


def assert_stopped(pids):
    end = time.monotonic() + 1
    while any(alive(pid) for pid in pids) and time.monotonic() < end:
        time.sleep(0.01)
    assert not any(alive(pid) for pid in pids), pids


for fmt in ("sha1", "sha256"):
    source, node, parent = (root / f"{fmt}-{name}" for name in ("source", "node", "runs"))
    parent.mkdir(mode=0o700)
    effects = root / f"{fmt}-executions"
    ordinary = f"printf 'observed\\n' >> {shlex.quote(str(effects))}\nprintf state > state\nprintf OPTIONAL_FAILED\nexit 7"
    texts = {
        "optional": workflow(ordinary, diagnostics=True),
        "required": workflow(ordinary, optional=False, diagnostics=True),
        "output": workflow("exec head -c 1048576 /dev/zero"),
        "deadline": workflow("exec sleep 30"),
        "containment": workflow("sleep 30 & printf 'orphan=%s\\n' \"$!\"; exit 7"),
    }
    files = {f".github/workflows/{name}.yml": text.encode() for name, text in texts.items()}
    tree = source_tree(source, fmt, files)
    tip = native_object(source, fmt, "commit", f"tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\noptional steps\n".encode())
    (source / "refs/heads").mkdir(parents=True)
    (source / "refs/heads/main").write_text(tip + "\n")
    (source / "HEAD").write_text("ref: refs/heads/main\n")
    scope = [node, tenant, repository]
    invoke(fmt + "-init", ["init", *scope, fmt])
    assert json.loads(invoke(fmt + "-import", ["import", *scope, principal, fmt + "-fixture", source, "--json"]))["state"] == "committed"
    recoveries = []
    for number, name in enumerate(texts, 1):
        nonce = f"{number:032x}"
        arguments = ["workflow", "run", *scope, "refs/heads/main", "--trusted-local",
                     "--workflow", f".github/workflows/{name}.yml", "--run-parent", parent,
                     "--run-id", nonce, "--input", ".github", "--object-format", fmt]
        raw = invoke(fmt + "-" + name, arguments, 0 if name == "optional" else 1,
                     10 if name == "deadline" else 120)
        envelope = json.loads(raw)
        assert envelope["node_closed"] and envelope["node_cleanup_error"] is None
        report = envelope["run"]
        assert report["source_commit"] == tip
        execution = report["execution"]
        assert execution["schema_version"] == (1 if name == "required" else 3)
        jobs = execution["jobs"]
        assert [job["id"] for job in jobs] == ["build", "dependent"]
        build, dependent = jobs
        first = build["steps"][0]
        if name == "optional":
            assert report["succeeded"] and report["workspaces_closed"] and not report["request_interrupted"]
            assert build["outcome"] == dependent["outcome"] == "succeeded"
            assert [step["index"] for step in build["steps"]] == [0, 1, 3]
            assert first["continue_on_error"] is True and first["outcome_tolerated"] is True
            assert first["outcome"] == "failed" and first["exit_code"] == 7
            assert first["output_complete"] and not first["workspace_retained"]
            assert bytes.fromhex(first["stdout_hex"]) == b"OPTIONAL_FAILED"
            for step in build["steps"][1:] + dependent["steps"]:
                assert step["continue_on_error"] is False and step["outcome_tolerated"] is False
                assert step["outcome"] == "succeeded"
        elif name == "required":
            assert not report["succeeded"] and report["workspaces_closed"]
            assert build["outcome"] == "failed" and dependent["outcome"] == "skipped"
            assert [step["index"] for step in build["steps"]] == [0, 2, 3]
            assert first["outcome"] == "failed" and first["exit_code"] == 7
            assert "continue_on_error" not in first and "outcome_tolerated" not in first
        else:
            assert not report["succeeded"] and build["outcome"] != "succeeded"
            assert dependent["outcome"] in ("skipped", "cancelled") and not dependent["steps"]
            assert len(build["steps"]) == 1
            assert first["continue_on_error"] is True and first["outcome_tolerated"] is False
            assert first["outcome"] != "succeeded"
            if name == "output":
                assert first["outcome"] == "output_limit"
                assert not first["output_complete"]
                assert len(bytes.fromhex(first["stdout_hex"])) <= 256 * 1024
            elif name == "deadline":
                assert first["outcome"] in ("cancelled", "timed_out")
            else:
                assert first["outcome"] == "containment_failure" and first["workspace_retained"]
                assert not report["workspaces_closed"]
                pids = [int(value) for value in re.findall(rb"orphan=(\d+)", bytes.fromhex(first["stdout_hex"]))]
                assert len(pids) == 1
                assert_stopped(pids)

        directory = parent / ("workflow-" + nonce)
        saved = (directory / "report.json").read_bytes()
        assert json.loads(saved)["execution"] == execution
        journal = hashlib.sha256((directory / "attempt.json").read_bytes()).hexdigest()
        recovery = ["workflow", "recover", directory, tenant, repository, "--journal-id", journal]
        history_raw = invoke(fmt + "-" + name + "-recover", recovery)
        history = json.loads(history_raw)
        assert history["execution_retried"] is False
        facts = {fact["job"]: (entry, index, fact) for entry in history["entries"]
                 for index, fact in enumerate(entry["facts"]) if fact["status"] == "completed"}
        assert set(facts) == {"build", "dependent"}
        entry, index, fact = facts["build"]
        assert entry["workflow_graph_sha256"] == execution["workflow_graph"].split(":")[-1]
        assert entry["source_commit"] == tip
        evidence_path = parent / f"{name}-build-evidence"
        invoke(fmt + "-" + name + "-evidence", recovery + ["--batch", entry["batch_sha256"],
               "--evidence", fact["evidence_sha256"], "--output", evidence_path])
        evidence = evidence_path.read_bytes()
        assert hashlib.sha256(evidence).hexdigest() == fact["evidence_sha256"]
        # The observation frame ends in its length-prefixed exact native report.
        encoded = evidence[evidence.index(b'{"schema_version":'):]
        persisted = json.loads(encoded)
        assert persisted["jobs"] == [build]
        assert persisted["schema_version"] == execution["schema_version"]
        assert persisted["workflow_graph"] == execution["workflow_graph"]

        publish = ["workflow", "publish", *scope, "refs/heads/main", "--trusted-local",
                   "--run-directory", directory, "--journal-id", journal, "--batch", entry["batch_sha256"],
                   "--fact-index", index, "--principal-id", principal,
                   "--idempotency-key", fmt + "-" + name + "-check", "--object-format", fmt]
        published_raw = invoke(fmt + "-" + name + "-publish", publish)
        published = json.loads(published_raw)
        assert published["command_committed"] and published["node_closed"] and published["cleanup_error"] is None
        assert published["source_commit"] == tip and published["evidence_sha256"] == fact["evidence_sha256"]
        assert published["graph_root"] == entry["workflow_graph_sha256"]
        assert published["execution_retried"] is False and published["refs_changed"] is False
        assert published["authoritative_check"] is False
        if name == "optional":
            assert published["conclusion"] == "success"
        elif name in ("required", "output", "containment"):
            assert published["conclusion"] == "failure"
        else:
            assert published["conclusion"] in ("cancelled", "timed_out", "failure")
        before_effects = effects.read_bytes()
        assert invoke(fmt + "-" + name + "-publish-retry", publish) == published_raw
        invoke(fmt + "-" + name + "-occupied", arguments, 2)
        assert effects.read_bytes() == before_effects
        assert (directory / "report.json").read_bytes() == saved
        recoveries.append((name, recovery, history_raw))
        case = {"format": fmt, "case": name, "job_outcome": build["outcome"],
                "raw_step_outcome": first["outcome"], "outcome_tolerated": first.get("outcome_tolerated", False),
                "evidence_sha256": fact["evidence_sha256"], "canonical_conclusion": published["conclusion"],
                "exact_publication_retry": True, "occupied_attempt_not_reexecuted": True}
        cases.append(case)
        print(json.dumps(case), flush=True)
    expected_effects = b"observed\nobserved\n"
    assert effects.read_bytes() == expected_effects
    source.rename(root / (fmt + "-source-offline"))
    node.rename(root / (fmt + "-node-offline"))
    for name, arguments, history_raw in recoveries:
        assert invoke(fmt + "-" + name + "-offline-recover", arguments) == history_raw
    assert effects.read_bytes() == expected_effects

(root / "results.json").write_text(json.dumps({"commands": commands, "cases": cases}, indent=2) + "\n")
