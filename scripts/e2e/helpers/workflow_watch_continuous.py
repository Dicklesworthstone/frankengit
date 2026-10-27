#!/usr/bin/env python3
"""Real fg continuous workflow service, canonical checks, restart and drain.

Uses native loose-object fixtures and real trusted shell jobs. No watcher,
workflow executor, authority store, or check publisher is replaced by a peer.
This is functional trusted-host evidence, not hostile-runner containment or an
all-push delivery queue. Every wait and subprocess is bounded by this campaign.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from workspace_tool_smoke import (  # noqa: E402
    PRINCIPAL,
    REF,
    REPOSITORY,
    TENANT,
    commit,
    tree,
    write_object,
)

TARGET = "refs/heads/target"
ATTEMPT_SECONDS = 5


def read_rows(path):
    # A concurrently appended final line is incomplete until its newline.
    data = path.read_bytes()
    return [json.loads(line) for line in data.split(b"\n")[:-1] if line]


def live(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0]
        return state not in "ZX"
    except FileNotFoundError:
        return False


class Campaign:
    def __init__(self, binary, root):
        self.binary, self.root = binary, root
        self.sequence = 0
        self.results = []
        root.mkdir(parents=True, exist_ok=True)

    def invoke(self, label, arguments, code=0):
        self.sequence += 1
        stem = self.root / f"{self.sequence:03d}-{label}"
        output, diagnostic = Path(str(stem) + ".out"), Path(str(stem) + ".err")
        with output.open("wb") as stdout, diagnostic.open("wb") as stderr:
            result = subprocess.run(
                [str(self.binary), *map(str, arguments)],
                stdout=stdout,
                stderr=stderr,
                timeout=90,
                check=False,
            )
        error = diagnostic.read_bytes()
        if error:
            sys.stderr.buffer.write(error)
            sys.stderr.buffer.flush()
        assert result.returncode == code, (
            label, result.returncode, output.read_bytes(), error
        )
        return output.read_bytes()

    def record(self, fmt, name, **fields):
        row = {"format": fmt, "case": name, **fields}
        self.results.append(row)
        print(json.dumps(row), flush=True)
        (self.root / "results.json").write_text(json.dumps(self.results, indent=2) + "\n")


class Watcher:
    def __init__(self, fixture, label, *, publish=False, interval=100, attempt=ATTEMPT_SECONDS,
                 lifetime=None, extra=()):
        self.fixture = fixture
        self.stop_file = fixture.root / f"{label}.stop"
        self.output = fixture.root / f"{label}.out"
        self.diagnostic = fixture.root / f"{label}.err"
        args = fixture.arguments(publish=publish)
        args += ["--continuous", "--stop-file", self.stop_file,
                 "--attempt-timeout-secs", attempt, "--interval-ms", interval]
        args += list(extra)
        if lifetime is not None:
            args = ["--timeout-secs", lifetime, *args]
        with self.output.open("wb") as stdout, self.diagnostic.open("wb") as stderr:
            self.child = subprocess.Popen(
                [str(fixture.campaign.binary), *map(str, args)], stdout=stdout, stderr=stderr
            )

    def rows(self):
        return read_rows(self.output)

    def wait(self, condition, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            observed = self.rows()
            if condition(observed):
                return observed
            assert self.child.poll() is None, (
                "watch exited before the expected observation", self.child.returncode,
                self.output.read_bytes(), self.diagnostic.read_bytes()
            )
            time.sleep(0.02)
        raise AssertionError(("bounded native watch wait expired", self.output.read_bytes(),
                              self.diagnostic.read_bytes()))

    def ready(self, *, attempt=ATTEMPT_SECONDS, lifetime=None):
        observed = self.wait(lambda rows: any(row.get("type") == "workflow_watch_ready" for row in rows))
        ready = next(row for row in observed if row.get("type") == "workflow_watch_ready")
        assert observed[0] == ready, "readiness precedes any poll or canonical check publication"
        assert ready["schema_version"] == 1 and ready["continuous"] is True
        assert ready["attempt_timeout_secs"] == attempt
        assert ready["lifetime_timeout_secs"] == lifetime
        return ready

    def idle(self, after_index=0):
        return self.wait(lambda rows: any(
            row.get("type") == "workflow_watch_poll"
            and row["index"] > after_index
            and row["poll"]["state"] == "previously_settled"
            for row in rows
        ))

    def stop(self, code=0):
        self.stop_file.write_text("operator requested drain\n")
        return self.finish(code)

    def finish(self, code):
        result = self.child.wait(timeout=15)
        error = self.diagnostic.read_bytes()
        if error:
            sys.stderr.buffer.write(error)
            sys.stderr.buffer.flush()
        observed = self.rows()
        assert result == code, (result, code, self.output.read_bytes(), error)
        assert observed[-1]["type"] == "workflow_watch_result"
        summary = observed[-1]
        assert summary["node_closed"] and summary["cleanup_error"] is None
        assert summary["operation_error"] is None
        assert summary["continuous"] is True
        return observed

    def close(self):
        if self.child.poll() is None:
            # Exceptional test cleanup is not evidence of native service drain.
            self.child.send_signal(signal.SIGTERM)
            try:
                self.child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Fixture:
    def __init__(self, campaign, fmt, label, active=False):
        self.campaign, self.format = campaign, fmt
        self.root = campaign.root / f"{fmt}-{label}"
        self.root.mkdir()
        self.source = self.root / "source"
        self.node = self.root / "node"
        self.runs = self.root / "runs"
        self.runs.mkdir(mode=0o700)
        self.effects = self.root / "effects"
        self.pids = self.root / "pids"
        self.late = self.root / "late-effects"
        (self.source / "refs/heads").mkdir(parents=True)
        (self.source / "HEAD").write_text(f"ref: {REF}\n")
        (self.source / "config").write_text(
            "[core]\nbare=true\nrepositoryformatversion="
            + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n")
        )
        effect, pids, late = map(shlex.quote, map(str, (self.effects, self.pids, self.late)))
        action = f"printf 'executed\\n' >> {effect}; printf 'native check evidence\\n'"
        later = ""
        if active:
            action = (f"printf 'executed\\n' >> {effect}; printf '%s\\n' \"$$\" > {pids}; "
                      f"sleep 60 & echo $! >> {pids}; wait; printf 'late-step' >> {late}")
            later = (f"  b:\n    needs: a\n    if: always()\n    runs-on: fgit-trusted-local\n"
                     f"    steps:\n      - run: printf 'dependent' >> {late}\n"
                     f"  z:\n    runs-on: fgit-trusted-local\n    steps:\n"
                     f"      - run: printf 'independent' >> {late}\n")
        workflow = ("name: native-continuous\non: push\njobs:\n  a:\n"
                    f"    runs-on: fgit-trusted-local\n    steps:\n      - run: {action}\n{later}")
        blob = write_object(self.source, fmt, "blob", workflow.encode())
        ci = write_object(self.source, fmt, "tree", tree([(b"100644", b"build.yml", blob)]))
        root_tree = write_object(self.source, fmt, "tree", tree([(b"40000", b"ci", ci)]))
        self.base = write_object(self.source, fmt, "commit", commit(root_tree, None, 1, b"base\n"))
        self.tips = []
        parent = self.base
        for index in range(4):
            parent = write_object(self.source, fmt, "commit",
                                  commit(root_tree, parent, index + 2, f"revision {index}\n".encode()))
            self.tips.append(parent)
            if index:
                (self.source / f"refs/heads/future-{index}").write_text(parent + "\n")
        (self.source / TARGET).write_text(self.base + "\n")
        (self.source / REF).write_text(self.tips[0] + "\n")
        self.current = 0
        self.scope = [self.node, TENANT, REPOSITORY]
        campaign.invoke("init", ["init", *self.scope, fmt])
        campaign.invoke("import", ["import", *self.scope, PRINCIPAL, "continuous-source", self.source])
        header = campaign.invoke("incarnation", [
            "serve-http", *self.scope, "127.0.0.1:0", "--trusted-local", "--print-credentials-header"
        ]).decode().strip().split()
        assert header[:3] == ["frankengit-http-credentials-v1", TENANT, REPOSITORY]
        assert len(header) == 4 and len(header[3]) == 32
        self.incarnation = header[3]

    def arguments(self, publish=False):
        args = ["workflow", "watch", *self.scope, REF, "--trusted-local", "--workflow", "ci",
                "--input", "ci", "--run-parent", self.runs, "--object-format", self.format]
        if publish:
            args += ["--publish-checks", "--principal-id", PRINCIPAL,
                     "--expected-incarnation", self.incarnation]
        return args

    def effects_count(self):
        return len(self.effects.read_bytes().splitlines()) if self.effects.exists() else 0

    def advance(self):
        old = self.tips[self.current]
        self.current += 1
        self.campaign.invoke("advance-ref", [
            "branch", "update", *self.scope, "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", f"continuous-advance-{self.current}", "--ref", REF,
            "--expected-tip", old, "--target", self.tips[self.current],
            "--object-format", self.format,
        ])

    def open_pull(self):
        number = self.current + 1
        self.campaign.invoke("open-pull", [
            "pr", "open", *self.scope, number, "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", f"continuous-pr-{number}", "--expected-version", "0",
            "--source-ref", REF, "--target-ref", TARGET, "--expected-source", self.tips[self.current],
            "--expected-target", self.base, "--title", "Continuous native check",
            "--body", "Actual retained workflow evidence", "--object-format", self.format,
        ])

    def check(self):
        raw = self.campaign.invoke("native-checks", [
            "pr", "checks", *self.scope, self.current + 1, "--trusted-local",
            "--object-format", self.format,
        ])
        page = json.loads(raw)
        assert page["source_current"] is True and page["complete"] is True, page
        assert page["source_tip"] == self.tips[self.current], page
        assert len(page["checks"]) == 1, page
        check = page["checks"][0]
        assert check["conclusion"] == "success" and check["job"] == "a", check
        assert check["publisher"] == PRINCIPAL and len(check["evidence_sha256"]) == 64, check
        return check

    def authority(self):
        return self.campaign.invoke("authority", [
            "pr", "list", *self.scope, "--trusted-local", "--object-format", self.format,
        ])


def service_lifecycle(campaign, fmt):
    fixture = Fixture(campaign, fmt, "service")
    fixture.open_pull()
    ids = set()
    with Watcher(fixture, "service", publish=True) as watcher:
        watcher.ready()
        for revision in range(3):
            if revision:
                fixture.advance()
                fixture.open_pull()
            observed = watcher.wait(lambda rows: len([
                row for row in rows if row.get("type") == "workflow_check_set_decision"
            ]) == revision + 1)
            dispatched = [row for row in observed if row.get("type") == "workflow_watch_poll"
                          and row["poll"]["state"] == "dispatched"]
            assert len(dispatched) == revision + 1
            poll = dispatched[-1]
            assert poll["poll"]["dispatch"]["succeeded"] is True
            event = poll["poll"]["event"]
            assert event["event_id"] not in ids
            ids.add(event["event_id"])
            plans = [row for row in observed if row.get("type") == "workflow_check_set"]
            assert plans[-1]["checks"][0]["source_commit"] == fixture.tips[revision]
            decisions = [row for row in observed if row.get("type") == "workflow_check_set_decision"]
            assert all(row["command_committed"] and row["conclusion"] == "success" for row in decisions)
            assert fixture.effects_count() == revision + 1
            fixture.check()
            watcher.idle(after_index=poll["index"])
            if revision == 0:
                # Explicitly outlive the finite request budget. New polls must
                # use fresh bounded requests; idle service life is separate.
                began = time.monotonic()
                while time.monotonic() - began < ATTEMPT_SECONDS + 0.5:
                    assert watcher.child.poll() is None, (
                        "service inherited an expired attempt as its lifetime", watcher.rows(),
                        watcher.diagnostic.read_bytes()
                    )
                    time.sleep(0.02)
                assert fixture.effects_count() == 1
                campaign.record(fmt, "idle-service-outlives-attempt-budget", attempt_seconds=ATTEMPT_SECONDS)
        stopped = watcher.stop()
        summary = stopped[-1]
        assert summary["operator_stopped"] and not summary["requires_reconciliation"]
        assert summary["dispatched"] == 3 and summary["committed_check_decisions"] == 3
        assert summary["refused_check_decisions"] == 0 and not summary["non_green"]
    assert fixture.effects_count() == 3
    campaign.record(fmt, "successive-source-events-and-canonical-checks", executions=3, checks=3)
    original_authority = fixture.authority()
    with Watcher(fixture, "restart", publish=True) as watcher:
        watcher.ready()
        watcher.idle()
        resumed = watcher.stop()
        assert resumed[-1]["dispatched"] == 0 and resumed[-1]["committed_check_decisions"] == 0
        assert resumed[-1]["operator_stopped"] and not resumed[-1]["requires_reconciliation"]
    assert fixture.effects_count() == 3 and fixture.authority() == original_authority
    campaign.record(fmt, "restart-preserves-event-and-check-identities", executions=3, authority_unchanged=True)
    with Watcher(fixture, "global-lifetime", interval=60000, attempt=1, lifetime=2) as watcher:
        watcher.ready(attempt=1, lifetime=2)
        watcher.idle()
        bounded = watcher.finish(1)
        assert bounded[-1]["request_stopped"] and not bounded[-1]["operator_stopped"]
        assert not bounded[-1]["requires_reconciliation"] and bounded[-1]["dispatched"] == 0
    assert fixture.effects_count() == 3 and fixture.authority() == original_authority
    campaign.record(fmt, "explicit-lifetime-deadline-is-not-renewed")
    # Existing bounded polling retains its whole-command lifetime contract.
    bounded = campaign.invoke("bounded-legacy", ["--timeout-secs", 2, *fixture.arguments(),
                                               "--polls", 5, "--interval-ms", 60000], 1)
    summary = json.loads(bounded.splitlines()[-1])
    assert summary["request_stopped"] and summary["polls"] == 1
    assert not summary["continuous"] and not summary["operator_stopped"]
    assert fixture.effects_count() == 3
    campaign.record(fmt, "bounded-mode-retains-original-whole-command-deadline")


def interrupted_execution(campaign, fmt, *, operator_stop):
    label = "active-stop" if operator_stop else "attempt-expiry"
    fixture = Fixture(campaign, fmt, label, active=True)
    before = fixture.authority()
    pids = []
    try:
        attempt = 30 if operator_stop else 2
        with Watcher(fixture, label, attempt=attempt) as watcher:
            watcher.ready(attempt=attempt)
            watcher.wait(lambda _: fixture.pids.exists() and len(fixture.pids.read_text().splitlines()) == 2)
            pids = [int(value) for value in fixture.pids.read_text().splitlines()]
            assert len(set(pids)) == 2 and all(live(pid) for pid in pids)
            observed = watcher.stop(1) if operator_stop else watcher.finish(1)
            assert all(not live(pid) for pid in pids), "native service returned before process drain"
            summary = observed[-1]
            assert summary["operator_stopped"] == operator_stop
            assert summary["request_stopped"] and summary["requires_reconciliation"]
            assert summary["dispatched"] == 1 and summary["non_green"]
            assert summary["committed_check_decisions"] == 0
            poll = next(row["poll"] for row in observed if row.get("type") == "workflow_watch_poll")
            run = poll["dispatch"]["runs"][0]
            assert run["request_interrupted"] and not run["succeeded"]
            assert [job["id"] for job in run["execution"]["jobs"]] == ["a", "b", "z"]
            assert all(job["outcome"] == "cancelled" and job["steps"] == []
                       for job in run["execution"]["jobs"][1:])
        assert fixture.effects_count() == 1 and not fixture.late.exists()
        assert fixture.authority() == before
        campaign.record(fmt, label + "-drains-before-return-and-suppresses-later-work",
                        drained_processes=2, canonical_authority_unchanged=True)
        fixture.advance()
        after_update = fixture.authority()
        # Restart has a new request budget but the ORIGINAL event's unresolved
        # responsibility still blocks a new canonical source change.
        with Watcher(fixture, "unresolved-restart", attempt=30) as watcher:
            watcher.ready(attempt=30)
            resumed = watcher.finish(1)
            polls = [row["poll"] for row in resumed if row.get("type") == "workflow_watch_poll"]
            assert len(polls) == 1 and polls[0]["state"] == "blocked_unresolved"
            assert resumed[-1]["requires_reconciliation"] and resumed[-1]["dispatched"] == 0
            assert not resumed[-1]["operator_stopped"]
        assert fixture.effects_count() == 1 and not fixture.late.exists()
        assert fixture.authority() == after_update
        campaign.record(fmt, label + "-custody-blocks-new-source-after-restart", executions=1)
    finally:
        # Cleanup follows assertions and cannot count as proof of native drain.
        for pid in pids:
            if live(pid):
                os.kill(pid, signal.SIGKILL)


def invalid_controls(campaign, fmt):
    fixture = Fixture(campaign, fmt, "controls")
    before = fixture.authority()
    existing = fixture.root / "already-stopped"
    existing.write_text("preexisting operator stop\n")
    for name, extra in [
        ("missing-stop", ["--continuous"]),
        ("stop-without-continuous", ["--stop-file", fixture.root / "unused"]),
        ("polls-with-continuous", ["--continuous", "--stop-file", fixture.root / "unused", "--polls", 1]),
        ("preexisting-stop", ["--continuous", "--stop-file", existing]),
        ("zero-attempt", ["--continuous", "--stop-file", fixture.root / "unused", "--attempt-timeout-secs", 0]),
        ("unbounded-attempt", ["--continuous", "--stop-file", fixture.root / "unused", "--attempt-timeout-secs", 3601]),
    ]:
        campaign.invoke(name, [*fixture.arguments(), *extra], 2)
        assert fixture.effects_count() == 0
    assert fixture.authority() == before
    assert list(fixture.runs.iterdir()) == []
    campaign.record(fmt, "invalid-controls-refuse-before-event-custody-or-execution", cases=6)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    assert sys.platform.startswith("linux"), "native trusted workflow execution requires Linux"
    output = options.output.resolve() if options.output else Path(tempfile.mkdtemp(prefix="fg-continuous-watch-"))
    campaign = Campaign(binary, output)
    for fmt in ("sha1", "sha256"):
        invalid_controls(campaign, fmt)
        service_lifecycle(campaign, fmt)
        interrupted_execution(campaign, fmt, operator_stop=True)
        interrupted_execution(campaign, fmt, operator_stop=False)
    print(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": len(campaign.results), "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
