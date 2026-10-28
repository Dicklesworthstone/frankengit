"""Real PR candidate watch, canonical CI checks, and protected merge publication.

The independent fixture encoder writes native loose Git objects for both hash
formats. No Git executable, substitute service, or mocked admission participates.
This is functional native evidence, not an upstream-Git differential claim.
"""

import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import zlib


FG = str(Path(sys.argv[1]).resolve())
ROOT = Path(sys.argv[2]).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
TENANT, REPOSITORY, OWNER, PUBLISHER = [f"{value:02x}" * 16 for value in (81, 82, 83, 84)]
TARGET, SOURCE, CI_REF = "refs/heads/main", "refs/heads/topic", "refs/heads/ci/pr-7"
AUTHOR = "CI <ci@example.test>"
TIMESTAMP = 1_700_000_000
MESSAGE = "CI merge candidate\n"
SEQUENCE, RESULTS = 0, []


def invoke(label, arguments, expected=0):
    """Keep every native command's exact output and stderr in the retained run."""
    global SEQUENCE
    SEQUENCE += 1
    out, err = (ROOT / f"{SEQUENCE:03d}-{label}.{suffix}" for suffix in ("out", "err"))
    with out.open("wb") as stdout, err.open("wb") as stderr:
        done = subprocess.run(
            [FG, "--timeout-secs", "120", *map(str, arguments)],
            stdout=stdout,
            stderr=stderr,
            timeout=150,
        )
    diagnostics = err.read_bytes()
    if diagnostics:
        sys.stderr.buffer.write(diagnostics)
        sys.stderr.buffer.flush()
    assert done.returncode == expected, (
        label, done.returncode, expected, diagnostics[-5000:], out.read_bytes()[-8000:]
    )
    return out.read_bytes()


def rows(data):
    return [json.loads(line) for line in data.splitlines() if line]


def poll(data):
    selected = [row["poll"] for row in rows(data) if row["type"] == "workflow_watch_poll"]
    assert len(selected) == 1, selected
    return selected[0]


def record(fixture, case, **fields):
    row = dict(format=fixture.fmt, method=fixture.method, case=case, **fields)
    RESULTS.append(row)
    print(json.dumps(row), flush=True)


def identity(fmt, kind, body):
    return hashlib.new(fmt, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def tree(entries):
    ordered = sorted(entries, key=lambda entry: entry[0] + (b"/" if entry[1] == b"40000" else b""))
    return b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid) for name, mode, oid in ordered)


def commit(root, parents, message, timestamp=1):
    return (
        f"tree {root}\n"
        + "".join(f"parent {parent}\n" for parent in parents)
        + f"author {AUTHOR} {timestamp} +0000\ncommitter {AUTHOR} {timestamp} +0000\n\n"
        + message
    ).encode()


class Fixture:
    def __init__(self, fmt, method, label, conflict=False):
        self.fmt, self.method = fmt, method
        self.root = ROOT / f"{fmt}-{method}-{label}"
        self.root.mkdir()
        self.source, self.node, self.runs, self.effects, self.excluded = (
            self.root / name for name in ("source", "node", "runs", "effects", "excluded-effects")
        )
        self.runs.mkdir(mode=0o700)
        (self.source / "refs/heads").mkdir(parents=True)
        (self.source / "HEAD").write_text(f"ref: {TARGET}\n", encoding="ascii")
        (self.source / "config").write_text(
            "[core]\nbare=true\nrepositoryformatversion="
            + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"),
            encoding="ascii",
        )

        def put(kind, body):
            oid = identity(fmt, kind, body)
            path = self.source / "objects" / oid[:2] / oid[2:]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
            return oid

        # Neither canonical parent contains both required values. A source-head
        # run, or filtering against the CI ref, cannot satisfy this fixture.
        action = (
            'test "$(cat left)" = target && test "$(cat right)" = source || exit 7; '
            f"printf 'merged\\n' >> {shlex.quote(str(self.effects))}; "
            "cat left right"
        )
        build = (
            "name: exact-merge-watch\non:\n  pull_request:\n    branches:\n      - main\n"
            "    paths:\n      - right\njobs:\n  build:\n    runs-on: fgit-trusted-local\n"
            f"    steps:\n      - run: {action}\n"
        ).encode()
        excluded_action = f"printf excluded >> {shlex.quote(str(self.excluded))}; exit 99"
        exclusions = {
            b"push.yml": "on: push\n",
            b"wrong-branch.yml": "on:\n  pull_request:\n    branches:\n      - topic\n",
            b"target-only.yml": "on:\n  pull_request:\n    paths:\n      - left\n",
        }
        definitions = [(b"build.yml", b"100644", put("blob", build))]
        for name, trigger in exclusions.items():
            body = (
                "name: excluded\n" + trigger + "jobs:\n  wrong:\n"
                "    runs-on: fgit-trusted-local\n    steps:\n"
                f"      - run: {excluded_action}\n"
            ).encode()
            definitions.append((name, b"100644", put("blob", body)))
        ci = put("tree", tree(definitions))

        def source_tree(left, right):
            return put("tree", tree([
                (b"ci", b"40000", ci),
                (b"left", b"100644", put("blob", left)),
                (b"right", b"100644", put("blob", right)),
            ]))

        self.base = put("commit", commit(source_tree(b"base\n", b"base\n"), [], "base\n"))
        self.target = put("commit", commit(source_tree(b"target\n", b"base\n"), [self.base], "target\n"))
        self.incoming = put("commit", commit(
            source_tree(b"conflicting\n" if conflict else b"base\n", b"source\n"),
            [self.base], "source\n",
        ))
        for reference, oid in [(TARGET, self.target), (SOURCE, self.incoming)]:
            (self.source / reference).write_text(oid + "\n", encoding="ascii")
        self.merged_tree = identity(fmt, "tree", tree([
            (b"ci", b"40000", ci),
            (b"left", b"100644", identity(fmt, "blob", b"target\n")),
            (b"right", b"100644", identity(fmt, "blob", b"source\n")),
        ]))
        self.parents = [self.target] if method == "squash" else [self.target, self.incoming]
        self.candidate = identity(fmt, "commit", commit(self.merged_tree, self.parents, MESSAGE, TIMESTAMP))
        self.scope = [self.node, TENANT, REPOSITORY]
        invoke("init", ["init", *self.scope, fmt])
        invoke("import", ["import", *self.scope, OWNER, "merge-watch-fixture", self.source])
        self.open_pr(7, SOURCE, self.incoming)
        checks = self.checks(7)
        assert checks["found"] and not checks["checks"]
        self.incarnation = checks["repository_incarnation"]
        self.watch = [
            "workflow", "watch", *self.scope, SOURCE,
            "--trusted-local", "--pull-request", "7", "--workflow", "ci",
            "--input", "ci", "--input", "left", "--input", "right",
            "--run-parent", self.runs, "--object-format", fmt,
            "--expected-incarnation", self.incarnation,
            "--merge-candidate-ref", CI_REF, "--merge-principal", OWNER,
            "--merge-author", AUTHOR, "--merge-committer", AUTHOR,
            "--merge-timestamp", str(TIMESTAMP), "--merge-message", MESSAGE,
            "--merge-profile", "path", "--merge-method", method,
        ]

    def open_pr(self, number, source_ref, tip):
        return invoke("open-pr", [
            "pr", "open", *self.scope, str(number), "--trusted-local", "--principal", OWNER,
            "--idempotency-key", f"merge-watch-pr-{number}", "--expected-version", "0",
            "--source-ref", source_ref, "--target-ref", TARGET,
            "--expected-source", tip, "--expected-target", self.target,
            "--title", "Exact merge CI", "--body", "Native candidate execution evidence",
            "--object-format", self.fmt,
        ])

    def checks(self, number):
        return json.loads(invoke("canonical-checks", [
            "pr", "checks", *self.scope, str(number), "--trusted-local", "--object-format", self.fmt,
        ]))

    def refs(self):
        data = json.loads(invoke("refs", [
            "branch", "list", *self.scope, "--trusted-local", "--object-format", self.fmt,
        ]))
        assert data["node_closed"] and not data["has_more"]
        return data, {bytes.fromhex(row["reference_hex"]).decode(): row["tip"] for row in data["branches"]}

    def count(self):
        return self.effects.read_bytes().splitlines() if self.effects.exists() else []

    def require_original_refs(self):
        _, refs = self.refs()
        assert refs[TARGET] == self.target and refs[SOURCE] == self.incoming, refs
        assert not self.excluded.exists(), "an excluded workflow was executed"
        return refs

    def merge(self, key, accepted=False):
        data = json.loads(invoke("protected-merge", [
            "merge", "apply", *self.scope, TARGET, self.bundle,
            "--trusted-local", "--principal", OWNER, "--idempotency-key", key,
            "--source-ref", SOURCE, "--expected-source", self.incoming,
            "--expected-target", self.target, "--merge-base", self.base,
            "--expected-commit", self.candidate, "--pull-request", "7",
            "--expected-version", "1", "--method", self.method,
        ], 0 if accepted else 2))
        assert data["node_closed"] and data["published_to_repository"] is accepted
        assert data["candidate_commit"] == self.candidate
        assert data["outcome"] == ("committed" if accepted else "refused")
        if not accepted:
            assert data["refusal_code"] == "ProtectedRefTransitionDenied", data
        return data


def success(fmt, method):
    f = Fixture(fmt, method, "success")
    original, original_refs = f.refs()
    assert original_refs == {TARGET: f.target, SOURCE: f.incoming}
    for index, (reference, tip) in enumerate([(TARGET, f.target), (SOURCE, f.incoming)], 1):
        result = json.loads(invoke("parent-twin", [
            "workflow", "run", *f.scope, reference, "--trusted-local",
            "--workflow", "ci/build.yml", "--input", "ci", "--input", "left", "--input", "right",
            "--expected-commit", tip, "--run-id", f"{index:02x}" * 16,
            "--run-parent", f.runs, "--object-format", fmt,
        ], 1))
        assert result["node_closed"] and not result["run"]["succeeded"]
        assert not f.count()
    assert f.refs()[0] == original
    record(f, "both-parent-twins-fail-the-check-requiring-the-combined-tree")

    # A missing incarnation cannot create a candidate or run scripts, even
    # though ordinary execution without publication may omit that pin.
    invalid = list(f.watch)
    index = invalid.index("--expected-incarnation")
    del invalid[index:index + 2]
    invoke("missing-incarnation", invalid, 2)
    assert f.refs()[0] == original and not f.count()
    record(f, "candidate-publication-needs-explicit-incarnation-before-effects")

    observed = poll(invoke("watch-candidate", f.watch))
    assert observed["state"] == "dispatched" and observed["execution_settled"]
    event, dispatch = observed["event"], observed["dispatch"]
    assert event["commit"] == f.incoming
    assert event["pull_request"]["number"] == "7" and event["pull_request"]["version"] == "1"
    assert event["pull_request"]["recorded_source_commit"] == f.incoming
    assert event["pull_request"]["observed_target_commit"] == f.target
    assert event["merge_candidate"]["ref_hex"] == CI_REF.encode().hex()
    assert event["merge_candidate"]["commit"] == f.candidate
    assert event["merge_candidate"]["parents"] == f.parents
    assert dispatch["succeeded"] and dispatch["matched_count"] == dispatch["executed_count"] == 1
    assert dispatch["plan"]["event"] == "pull_request"
    assert dispatch["plan"]["changed_paths"]["after"] == f.incoming
    assert dispatch["plan"]["changed_paths"]["count"] == 1
    assert len(dispatch["runs"]) == 1
    run = dispatch["runs"][0]
    assert run["executed_commit"] == f.candidate and run["executed_tree"] == f.merged_tree
    assert run["input_kind"] == "canonical" and run["source_commit"] == f.candidate
    assert run["succeeded"] and run["workspaces_closed"]
    assert run["execution"]["jobs"][0]["steps"][0]["stdout_hex"] == b"target\nsource\n".hex()
    assert f.count() == [b"merged"]
    assert f.require_original_refs() == {**original_refs, CI_REF: f.candidate}
    assert not f.checks(7)["checks"]
    selected = [item for item in dispatch["plan"]["workflows"] if item["selected"]]
    assert len(selected) == 1 and selected[0]["path_hex"] == b"ci/build.yml".hex()
    graph = selected[0]["graph_sha256"]
    record(f, "watch-publishes-and-executes-exact-native-candidate", candidate=f.candidate,
           tree=f.merged_tree, parents=f.parents, graph=graph)

    settled, _ = f.refs()
    again = poll(invoke("restart-no-publication", f.watch))
    assert again["state"] == "previously_settled" and again["dispatch"] is None
    assert f.refs()[0] == settled and f.count() == [b"merged"]
    record(f, "fresh-process-restart-does-not-republish-candidate-or-rerun-scripts")

    # Obtain the reviewed bundle independently through native preparation and
    # demand the exact independently calculated identity used by the watcher.
    f.bundle = f.root / "reviewed.bundle"
    prepared = json.loads(invoke("same-reviewed-candidate", [
        "merge", "prepare", *f.scope, TARGET, f.bundle, "--trusted-local", "--profile", "path-v1",
        "--source-ref", SOURCE, "--author", AUTHOR, "--committer", AUTHOR,
        "--timestamp", str(TIMESTAMP), "--message", MESSAGE,
        "--method", method, "--object-format", fmt,
    ]))
    assert prepared["outcome"] == "prepared" and prepared["candidate_commit"] == f.candidate
    assert prepared["root_tree"] == f.merged_tree
    policy = json.loads(invoke("require-exact-candidate-check", [
        "protection", "set", *f.scope, "--trusted-local", "--principal", OWNER,
        "--admin", OWNER, "--idempotency-key", "require-merge-watch-build",
        "--expected-version", "0", "--expected-epoch", "1", "--object-format", fmt,
        "--require-check", f"{TARGET}:{CI_REF}:{PUBLISHER}:{graph}:build",
    ]))
    assert policy["committed"] and policy["committed_policy_epoch"] == 2
    denied = f.merge("before-canonical-check")
    f.require_original_refs()
    record(f, "local-success-alone-cannot-satisfy-canonical-protected-merge")

    automatic = f.watch + ["--publish-checks", "--principal-id", PUBLISHER]
    publication = rows(invoke("publish-original-candidate-check", automatic))
    decisions = [row for row in publication if row["type"] == "workflow_check_set_decision"]
    plans = [row for row in publication if row["type"] == "workflow_check_set"]
    assert len(decisions) == len(plans) == 1
    assert decisions[0]["command_committed"] and decisions[0]["conclusion"] == "success"
    assert decisions[0]["execution_retried"] is False and decisions[0]["refs_changed"] is False
    assert plans[0]["principal_id"] == PUBLISHER and plans[0]["selected_checks"] == 1
    check = plans[0]["checks"][0]
    assert check["source_ref_hex"] == CI_REF.encode().hex() and check["source_commit"] == f.candidate
    assert check["job"] == "build" and check["conclusion"] == "success"
    assert check["check_id"] == decisions[0]["check_id"]
    assert publication[-1]["node_closed"] and publication[-1]["committed_check_decisions"] == 1
    assert f.count() == [b"merged"]
    f.require_original_refs()
    assert not f.checks(7)["checks"], "candidate evidence was relabeled as source-head evidence"
    record(f, "restart-publishes-retained-check-for-ci-ref-and-candidate-without-reexecution",
           check=check["check_id"], publisher=PUBLISHER)

    # This second native fixture PR is only a canonical check-reader selection.
    # It does not replace or mutate the original PR's reviewed coordinates.
    f.open_pr(8, CI_REF, f.candidate)
    visible = f.checks(8)
    assert visible["source_ref_hex"] == CI_REF.encode().hex() and visible["source_tip"] == f.candidate
    assert visible["source_current"] and visible["complete"] and len(visible["checks"]) == 1
    canonical = visible["checks"][0]
    assert canonical["id"] == check["check_id"] and canonical["publisher"] == PUBLISHER
    assert canonical["graph_root"] == graph and canonical["job"] == "build"
    assert canonical["conclusion"] == "success"
    assert f.checks(8) == visible
    record(f, "fresh-process-canonical-reader-selects-only-the-tested-candidate")

    before_repeat, _ = f.refs()
    repeated = rows(invoke("repeat-reported-event", automatic))
    assert repeated[-1]["committed_check_decisions"] == 0
    assert poll(b"\n".join(json.dumps(row).encode() for row in repeated))["state"] == "previously_settled"
    assert f.refs()[0] == before_repeat and f.count() == [b"merged"]
    record(f, "completed-reporting-restart-has-no-additional-authority-or-script-effects")

    assert f.merge("before-canonical-check") == denied
    accepted = f.merge("after-canonical-check", accepted=True)
    _, refs = f.refs()
    assert refs == {TARGET: f.candidate, SOURCE: f.incoming, CI_REF: f.candidate}
    assert f.merge("after-canonical-check", accepted=True) == accepted
    closed = poll(invoke("merged-pr-no-execution", automatic))
    assert closed["state"] == "pull_request_unavailable" and f.count() == [b"merged"]
    record(f, "same-exact-candidate-merges-only-after-canonical-check-with-new-command-key",
           refused_tx=denied["tx_id"], committed_tx=accepted["tx_id"])


def conflict(fmt):
    f = Fixture(fmt, "merge-commit", "conflict", conflict=True)
    original, refs = f.refs()
    automatic = f.watch + ["--publish-checks", "--principal-id", PUBLISHER]
    for label in ("conflict", "conflict-restart"):
        output = invoke(label, automatic, 1)
        observed = poll(output)
        assert observed["state"] == "merge_conflicted" and observed["dispatch"] is None
        assert not any(row["type"] == "workflow_check_set_decision" for row in rows(output))
        assert not f.count() and not f.excluded.exists()
        current, current_refs = f.refs()
        assert current == original and current_refs == refs and CI_REF not in current_refs
        assert not f.checks(7)["checks"]
    record(f, "conflicting-parents-never-publish-ci-ref-or-checks-and-never-start-scripts")


if __name__ == "__main__":
    for object_format in ("sha1", "sha256"):
        for merge_method in ("merge-commit", "squash"):
            success(object_format, merge_method)
        conflict(object_format)

    (ROOT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n", encoding="utf-8")
