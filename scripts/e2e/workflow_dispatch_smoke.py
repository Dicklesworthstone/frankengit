#!/usr/bin/env python3
"""Native event dispatch -> immutable child custody -> canonical publication.

--fg executes the real binary in fresh processes; there is no simulated runner.
--self-test checks independent Git fixtures and damaged-report detection only.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = "d1" * 16, "d2" * 16, "d3" * 16
SOURCE, TARGET = "refs/heads/topic", "refs/heads/main"
DIRECTORY = b".github/workflows"
BATCH = "81" * 16
NAMES = [b"a.yml", b"b.yml", b"c.yaml", b"d.yml", b"\xff.yml"]
SELECTED = [NAMES[i] for i in (0, 1, 3, 4)]


def require(value, message):
    if not value:
        raise AssertionError(message)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def child_id(batch, event, path):
    name = event.encode("ascii")
    preimage = (b"frankengit/workflow-dispatch-child/v1\0" + bytes.fromhex(batch)
                + len(name).to_bytes(8, "big") + name + len(path).to_bytes(8, "big") + path)
    return hashlib.sha256(preimage).digest()[:16].hex()


def definition(event, script, runner="fgit-trusted-local"):
    return (f"name: dispatch-test\non: {event}\njobs:\n  test:\n    runs-on: {runner}\n"
            f"    steps:\n      - run: {script}\n").encode()


def fixture(root, algorithm, executions, mode="normal"):
    """Independent raw-byte tree and loose-object encoder, not production code."""
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n", encoding="ascii")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
        ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"), encoding="ascii")

    def store(kind, body):
        oid = identity(algorithm, kind, body)
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid

    log = shlex.quote(str(executions))
    definitions = {}
    for name, marker in zip(NAMES, "abcdx"):
        script = (f'test -f ../../dispatch.json; test "$(cat scratch.txt)" = original; '
                  f"printf changed > scratch.txt; printf {marker} >> {log}; printf {marker}")
        if name == b"b.yml":
            script += "; exit 7"
        definitions[name] = definition("workflow_dispatch" if name == b"c.yaml" else "push", script)
    if mode == "unmatched":
        definitions = {b"a.yml": definition("workflow_dispatch", f"printf forbidden >> {log}")}
    elif mode == "malformed":
        definitions[b"z.yml"] = b"name: bad\non: push\njobs: [\n"
    elif mode == "unsupported":
        definitions[b"z.yml"] = definition("push", "echo forbidden", "not-a-trusted-runner")
    elif mode == "too-many":
        definitions = {f"{i:02}.yml".encode(): definition("push", f"printf forbidden >> {log}") for i in range(33)}
    elif mode == "jobs-limit":
        definitions = {}
        for name in (b"a.yml", b"b.yml"):
            body = "name: job-budget\non: push\njobs:\n"
            for i in range(65):
                body += (f"  job{i:03}:\n    runs-on: fgit-trusted-local\n    steps:\n"
                         f"      - run: printf forbidden >> {log}\n")
            definitions[name] = body.encode()
    elif mode == "steps-limit":
        definitions = {}
        for i in range(5):
            body = ("name: step-budget\non: push\njobs:\n  test:\n"
                    "    runs-on: fgit-trusted-local\n    steps:\n")
            body += f"      - run: printf forbidden >> {log}\n" * 129
            definitions[f"{i}.yml".encode()] = body.encode()
    elif mode == "containment":
        definitions = {
            b"a.yml": definition("push", f"test -f ../../dispatch.json; printf a >> {log}; kill -TERM $$"),
            b"b.yml": definition("push", f"printf forbidden >> {log}"),
        }
    elif mode == "oversized":
        definitions[b"z.yml"] = b"#" + b"x" * (1024 * 1024)
    elif mode not in ("normal", "symlink"):
        raise ValueError(mode)
    blobs = {name: store("blob", body) for name, body in definitions.items()}
    graphs = {}
    for name, body in definitions.items():
        # Independently frame the simple fixture graphs; never call the native
        # compiler or use the returned graph hash as the expected identity.
        lines = body.decode().splitlines()
        if len(lines) != 7 or not lines[6].startswith("      - run: "):
            continue
        event = lines[1].removeprefix("on: ")
        runner = lines[4].removeprefix("    runs-on: ")
        script = lines[6].removeprefix("      - run: ")
        escaped = script.replace("\\", "\\\\").replace("\t", "\\t").replace("\n", "\\n")
        canonical = ("fgit-workflow/v1\nname\tdispatch-test\ntrigger\t" + event
                     + "\njob\ttest\t" + runner + "\nstep\ttest\t0\t\t" + escaped + "\n")
        graphs[name] = hashlib.sha256(canonical.encode()).hexdigest()
    # A nested invalid YAML file and a non-YAML file must not be discovered.
    nested_blob = store("blob", b"not a workflow at all")
    nested = store("tree", b"100644 hidden.yml\0" + bytes.fromhex(nested_blob))
    records = [(name, b"100644", oid) for name, oid in blobs.items()]
    records += [(b"nested", b"40000", nested), (b"notes.txt", b"100644", nested_blob)]
    if mode == "symlink":
        records.append((b"z.yml", b"120000", store("blob", b"a.yml")))
    records.sort(key=lambda row: row[0] + (b"/" if row[1] == b"40000" else b""))
    workflows = store("tree", b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid)
                                        for name, mode, oid in records))
    github = store("tree", b"40000 workflows\0" + bytes.fromhex(workflows))
    scratch = store("blob", b"original")
    tree = store("tree", b"40000 .github\0" + bytes.fromhex(github)
                 + b"100644 scratch.txt\0" + bytes.fromhex(scratch))

    def commit(parents, message):
        return (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents)
                + "author Dispatch Test <dispatch@example.invalid> 1700000000 +0000\n"
                  "committer Dispatch Test <dispatch@example.invalid> 1700000000 +0000\n\n"
                + message + "\n").encode()
    target = store("commit", commit([], "base"))
    source = store("commit", commit([target], "workflow inputs"))
    for name, tip in [(TARGET, target), (SOURCE, source)]:
        (root / name).write_text(tip + "\n", encoding="ascii")
    return dict(source=source, target=target, tree=tree, blobs=blobs, graphs=graphs)


def invoke(binary, args, code=0):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=180)
    require(result.returncode == code,
            f"exit {result.returncode}, wanted {code}: {args!r}\n{result.stderr!r}\n{result.stdout!r}")
    return result


def document(result):
    text = result.stdout.decode("utf-8", errors="strict")
    require(text.endswith("\n") and text.count("\n") == 1, "exactly one JSON line required")
    def pairs(entries):
        value = {}
        for key, item in entries:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    return json.loads(text, object_pairs_hook=pairs)


def check_result(value, f, algorithm, batch, event, names, source_head, succeeded):
    require(value["type"] == "workflow_dispatch_result" and value["schema_version"] == 1, "dispatch wrapper")
    require(value["node_closed"] is True and value["node_cleanup_error"] is None, "node close")
    report = value["dispatch"]
    require(report["type"] == "trusted_workflow_dispatch" and report["succeeded"] is succeeded, "batch outcome")
    require(report["stop_reason"] is None, "ordinary failure must not cancel independent workflows")
    require(type(report["matched_count"]) is int and report["matched_count"] == len(names), "match count")
    require(type(report["executed_count"]) is int and report["executed_count"] == len(names), "execution count")
    plan = report["plan"]
    require(plan["type"] == "trusted_workflow_dispatch_plan" and plan["schema_version"] == 1, "plan schema")
    require(plan["tenant_id"] == TENANT and plan["repository_id"] == REPOSITORY, "plan scope")
    require(plan["object_format"] == algorithm and plan["source_commit"] == f["source"]
            and plan["source_tree"] == f["tree"] and plan["source_head"] == source_head, "one pinned source")
    require(plan["source_ref_hex"] == SOURCE.encode().hex() and plan["workflow_directory_hex"] == DIRECTORY.hex(), "raw path scope")
    require(plan["read_prefixes_hex"] == [b".github".hex(), b"scratch.txt".hex()], "explicit source inputs")
    require(plan["run_id"] == batch and plan["event"] == event
            and plan["trigger_provenance"] == "explicit_local_operator", "explicit trigger binding")
    require(plan["run_timeout_ms"] == 600000 and plan["total_output_bytes"] == 16 * 1024 * 1024, "aggregate limits")
    for key in ["authoritative_check", "published", "execution_retried", "hostile_code_isolated"]:
        require(plan[key] is False, f"unearned {key}")
    definitions = plan["workflows"]
    require([bytes.fromhex(d["path_hex"]) for d in definitions] == [DIRECTORY + b"/" + name for name in sorted(f["blobs"])], "definition discovery order")
    for d in definitions:
        path = bytes.fromhex(d["path_hex"]); name = path.rsplit(b"/", 1)[1]
        require(d["blob"] == f["blobs"][name] and d["run_id"] == child_id(batch, event, path), "exact definition/child identity")
        require(d["selected"] is (name in names), "event selection")
        require(d["graph_sha256"] == f["graphs"][name], "compiled graph identity")
    require(len(report["runs"]) == len(names), "missing or duplicated child")
    remaining = 16 * 1024 * 1024
    for run, name in zip(report["runs"], names):
        path = DIRECTORY + b"/" + name
        require(run["source_head"] == source_head and run["source_commit"] == f["source"]
                and run["source_tree"] == f["tree"] and run["executed_commit"] == f["source"]
                and run["repository_incarnation"] == plan["repository_incarnation"], "mixed child source")
        require(run["workflow_path_hex"] == path.hex() and run["workflow_blob"] == f["blobs"][name]
                and run["run_id"] == child_id(batch, event, path), "child selected wrong definition")
        require(run["authoritative_check"] is False and run["published"] is False
                and run["workspaces_closed"] is True and run["request_interrupted"] is False, "child effect/cleanup boundary")
        require(run["execution"]["total_output_bytes"] == remaining, "output allowance reset between children")
        jobs = run["execution"]["jobs"]
        require(len(jobs) == 1 and jobs[0]["id"] == "test" and len(jobs[0]["steps"]) == 1, "real job execution")
        step = jobs[0]["steps"][0]
        marker = b"x" if name == b"\xff.yml" else name[:1]
        failed = name == b"b.yml"
        require(run["succeeded"] is (not failed) and jobs[0]["outcome"] == ("failed" if failed else "succeeded"), "exact child outcome")
        require(step["exit_code"] == (7 if failed else 0) and step["stdout_hex"] == marker.hex()
                and step["stderr_hex"] == "" and step["output_complete"] is True, "actual shell result")
        remaining -= len(marker)
    return report


def replace(args, flag, value):
    args = args.copy(); args[args.index(flag) + 1] = value; return args


def prepare(binary, root, algorithm, mode="normal"):
    node, source, runs, log = root / "node", root / "source", root / "runs", root / "executions"
    runs.mkdir(mode=0o700)
    f = fixture(source, algorithm, log, mode)
    invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
    invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "dispatch-fixture", source])
    listing = ["pr", "list", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm]
    pin = document(invoke(binary, listing))
    args = ["workflow", "dispatch", node, TENANT, REPOSITORY, SOURCE, "--trusted-local", "--event", "push",
            "--workflow", DIRECTORY.decode(), "--input", ".github", "--input", "scratch.txt",
            "--run-parent", runs, "--run-id", BATCH, "--expected-head", pin["snapshot_token"],
            "--expected-commit", f["source"], "--object-format", algorithm]
    return node, runs, log, f, listing, pin, args


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-workflow-dispatch-") as tmp:
        root = Path(tmp).resolve()
        node, runs, log, f, listing, pin, args = prepare(binary, root, algorithm)
        refs_args = ["at", node, TENANT, REPOSITORY, "latest", "refs"]
        refs_before = invoke(binary, refs_args).stdout
        untrusted = args.copy(); untrusted.remove("--trusted-local")
        negatives = [untrusted, args + ["--event", "push"], replace(args, "--event", "pull_request"),
                     replace(args, "--expected-commit", "ee" * (20 if algorithm == "sha1" else 32)),
                     replace(args, "--expected-head", "alg:2:" + "ff" * 32)]
        for flag in ["--expected-head", "--expected-commit"]:
            missing = args.copy(); at = missing.index(flag); del missing[at:at + 2]; negatives.append(missing)
        for bad in negatives:
            require(not invoke(binary, bad, 2).stdout, "invalid intake produced a dispatch result")
            require(not log.exists() and not any(runs.iterdir()), "preflight performed host execution")
        report = check_result(document(invoke(binary, args, 1)), f, algorithm, BATCH, "push", SELECTED, pin["source_head"], False)
        require(log.read_bytes() == b"abdx", "independent workflows did not execute once in byte order")
        batch = runs / f"dispatch-{BATCH}"
        require(json.loads((batch / "dispatch.json").read_bytes()) == report["plan"], "durable dispatch manifest")
        require(json.loads((batch / "report.json").read_bytes()) == report, "durable aggregate report")
        require(Path(os.fsdecode(bytes.fromhex(report["plan"]["run_directory_hex"]))) == batch, "batch path binding")
        require(document(invoke(binary, listing)) == pin, "execution published canonical state")
        retained = {p.relative_to(batch): p.read_bytes() for p in batch.rglob("*") if p.is_file()}
        require(not invoke(binary, args, 2).stdout and log.read_bytes() == b"abdx", "occupied dispatch replayed")
        require({p.relative_to(batch): p.read_bytes() for p in batch.rglob("*") if p.is_file()} == retained, "retry rewrote custody")
        manual_id = "82" * 16
        manual_args = replace(replace(args, "--event", "workflow_dispatch"), "--run-id", manual_id)
        check_result(document(invoke(binary, manual_args)), f, algorithm, manual_id, "workflow_dispatch", [b"c.yaml"], pin["source_head"], True)
        require(log.read_bytes() == b"abdxc", "manual trigger executed unselected jobs")
        require(document(invoke(binary, listing)) == pin, "manual execution published state")
        occupied_id = "83" * 16
        (runs / f"dispatch-{occupied_id}").mkdir(mode=0o700)
        require(not invoke(binary, replace(args, "--run-id", occupied_id), 2).stdout, "partial batch without marker was adopted")
        output_loss = False
        if Path("/dev/full").exists():
            loss_id = "84" * 16
            with open("/dev/full", "wb") as full:
                failed = subprocess.run([str(binary), *map(str, replace(manual_args, "--run-id", loss_id))],
                                        stdout=full, stderr=subprocess.PIPE, timeout=180)
            require(failed.returncode == 2 and b"do not replay" in failed.stderr, "receipt loss erased execution knowledge")
            saved = json.loads((runs / f"dispatch-{loss_id}" / "report.json").read_bytes())
            require(saved["succeeded"] is True and saved["executed_count"] == 1, "output loss lost saved result")
            require(not invoke(binary, replace(manual_args, "--run-id", loss_id), 2).stdout, "output-loss retry executed twice")
            require(log.read_bytes() == b"abdxcc", "receipt failure replayed a job")
            output_loss = True
        before_publication = log.read_bytes()
        require(invoke(binary, refs_args).stdout == refs_before, "dispatch changed code refs")
        for run in report["runs"][:2]:
            child = batch / f"workflow-{run['run_id']}"
            require(json.loads((child / "report.json").read_bytes()) == run, "saved child report")
            # Commitment captured from this trusted fixture, not an assertion that
            # hashing an arbitrary unknown directory establishes authenticity.
            marker = hashlib.sha256((child / "attempt.json").read_bytes()).hexdigest()
            recovery = ["workflow", "recover", child, TENANT, REPOSITORY, "--journal-id", marker]
            history = document(invoke(binary, recovery))
            completed = [(entry, index, fact) for entry in history["entries"]
                         for index, fact in enumerate(entry["facts"]) if fact["status"] == "completed"]
            require(len(completed) == 1, "child custody has wrong terminal count")
            entry, index, fact = completed[0]
            expected = "failure" if bytes.fromhex(run["workflow_path_hex"]).endswith(b"/b.yml") else "action_required"
            require(fact["conclusion"] == expected and entry["source_commit"] == f["source"], "child custody binding")
            publication = ["workflow", "publish", node, TENANT, REPOSITORY, SOURCE, "--trusted-local",
                           "--run-directory", child, "--journal-id", marker, "--batch", entry["batch_sha256"],
                           "--fact-index", index, "--principal-id", PRINCIPAL, "--idempotency-key", "dispatch-" + run["run_id"],
                           "--minimum-pin", history["snapshot"], "--object-format", algorithm,
                           "--expected-incarnation", run["repository_incarnation"]]
            published = document(invoke(binary, publication))
            require(published["type"] == "workflow_check_publication" and published["command_committed"] is True
                    and published["conclusion"] == expected and published["source_commit"] == f["source"]
                    and published["authoritative_check"] is False, "dispatch child did not publish its exact observation")
            pinned = document(invoke(binary, listing))
            require(document(invoke(binary, publication)) == published and document(invoke(binary, listing)) == pinned, "publication retry duplicated canonical state")
            require(document(invoke(binary, recovery)) == history, "publication consumed child custody")
        require(log.read_bytes() == before_publication, "recovery/publication reran a child")
        require(invoke(binary, refs_args).stdout == refs_before, "publication changed code refs")
        require({p.relative_to(batch): p.read_bytes() for p in batch.rglob("*") if p.is_file()} == retained, "publication rewrote batch evidence")
    for mode in ["malformed", "unsupported", "too-many", "oversized", "symlink", "jobs-limit", "steps-limit", "unmatched"]:
        with tempfile.TemporaryDirectory(prefix="fg-dispatch-preflight-") as tmp:
            _, runs, log, f, listing, pin, args = prepare(binary, Path(tmp).resolve(), algorithm, mode)
            if mode == "unmatched":
                check_result(document(invoke(binary, args)), f, algorithm, BATCH, "push", [], pin["source_head"], True)
            else:
                refused = invoke(binary, args, 2)
                require(not refused.stdout and not any(runs.iterdir()), f"{mode} created a partial batch")
                if mode in ("jobs-limit", "steps-limit"):
                    require(b"dispatch aggregate job or step limit exceeded" in refused.stderr, "wrong aggregate refusal")
            require(not log.exists(), f"{mode} ran a command")
            require(document(invoke(binary, listing)) == pin, f"{mode} changed repository authority")
    # A direct shell that terminates by signal is reaped, but the existing
    # trusted runner cannot prove descendant containment. Later workflows must
    # not start, and the original child workspace/evidence stays retained.
    with tempfile.TemporaryDirectory(prefix="fg-dispatch-containment-") as tmp:
        _, runs, log, f, listing, pin, args = prepare(binary, Path(tmp).resolve(), algorithm, "containment")
        value = document(invoke(binary, args, 1))
        require(value["node_closed"] is True, "containment report lost explicit node close")
        report = value["dispatch"]
        require(report["succeeded"] is False and report["stop_reason"] == "containment_unproved"
                and report["matched_count"] == 2 and report["executed_count"] == 1, "containment loss did not stop the batch")
        require(report["runs"][0]["workspaces_closed"] is False and log.read_bytes() == b"a", "later work ran after containment loss")
        batch = runs / f"dispatch-{BATCH}"
        later = child_id(BATCH, "push", DIRECTORY + b"/b.yml")
        require(not (batch / f"workflow-{later}").exists(), "later child was reserved after containment loss")
        require(json.loads((batch / "report.json").read_bytes()) == report, "containment report was not durable")
        require(document(invoke(binary, listing)) == pin, "containment failure changed repository authority")
        require(not invoke(binary, args, 2).stdout and log.read_bytes() == b"a", "containment batch was replayed")
    print(json.dumps(dict(type="workflow_dispatch_smoke", format=algorithm, passed=True, rust_executed=True,
                         native_dispatch=True, recovery_publication=True, output_failure_exercised=output_loss,
                         invalid_intake_requests=len(negatives), preflight_refusal_variants=7, containment_stop=True)))


def synthetic_report(f, algorithm):
    """Synthetic inputs belong ONLY to the checker self-test below."""
    plan = dict(type="trusted_workflow_dispatch_plan", schema_version=1, tenant_id=TENANT, repository_id=REPOSITORY,
                repository_incarnation="91" * 16, object_format=algorithm, source_commit=f["source"], source_tree=f["tree"],
                source_head="synthetic-head", source_ref_hex=SOURCE.encode().hex(), workflow_directory_hex=DIRECTORY.hex(),
                read_prefixes_hex=[b".github".hex(), b"scratch.txt".hex()], run_id=BATCH, event="push",
                trigger_provenance="explicit_local_operator", run_timeout_ms=600000, total_output_bytes=16 * 1024 * 1024,
                authoritative_check=False, published=False, execution_retried=False, hostile_code_isolated=False, workflows=[])
    runs, remaining = [], 16 * 1024 * 1024
    for name in sorted(f["blobs"]):
        path = DIRECTORY + b"/" + name
        plan["workflows"].append(dict(path_hex=path.hex(), blob=f["blobs"][name], graph_sha256=f["graphs"][name],
                                      run_id=child_id(BATCH, "push", path), selected=name in SELECTED))
        if name not in SELECTED:
            continue
        marker, failed = (b"x" if name == b"\xff.yml" else name[:1]), name == b"b.yml"
        step = dict(exit_code=7 if failed else 0, stdout_hex=marker.hex(), stderr_hex="", output_complete=True)
        runs.append(dict(source_head="synthetic-head", source_commit=f["source"], source_tree=f["tree"], executed_commit=f["source"],
                         repository_incarnation=plan["repository_incarnation"], workflow_path_hex=path.hex(), workflow_blob=f["blobs"][name],
                         run_id=child_id(BATCH, "push", path), authoritative_check=False, published=False, workspaces_closed=True,
                         request_interrupted=False, succeeded=not failed,
                         execution=dict(total_output_bytes=remaining, jobs=[dict(id="test", outcome="failed" if failed else "succeeded", steps=[step])])))
        remaining -= 1
    return dict(type="workflow_dispatch_result", schema_version=1, node_closed=True, node_cleanup_error=None,
                dispatch=dict(type="trusted_workflow_dispatch", succeeded=False, stop_reason=None, matched_count=4,
                              executed_count=4, plan=plan, runs=runs))


def self_test():
    rejected = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = fixture(root / "source", algorithm, root / "log")
            for path in (root / "source/objects").glob("*/*"):
                raw = zlib.decompress(path.read_bytes()); header, body = raw.split(b"\0", 1)
                kind, length = header.split(b" ", 1)
                require(int(length) == len(body) and identity(algorithm, kind.decode(), body) == path.parent.name + path.name, "loose fixture framing/identity")
            sample = synthetic_report(f, algorithm)
            check_result(sample, f, algorithm, BATCH, "push", SELECTED, "synthetic-head", False)
            mutations = [
                (("node_closed",), False), (("node_cleanup_error",), "lost"),
                (("dispatch", "succeeded"), True), (("dispatch", "stop_reason"), "cancelled"),
                (("dispatch", "matched_count"), True), (("dispatch", "executed_count"), 3),
                (("dispatch", "plan", "event"), "workflow_dispatch"),
                (("dispatch", "plan", "source_commit"), f["target"]),
                (("dispatch", "plan", "trigger_provenance"), "authenticated_push"),
                (("dispatch", "plan", "authoritative_check"), True),
                (("dispatch", "plan", "published"), True),
                (("dispatch", "plan", "execution_retried"), True),
                (("dispatch", "plan", "workflows", 0, "selected"), False),
                (("dispatch", "plan", "workflows", 0, "run_id"), "00" * 16),
                (("dispatch", "plan", "workflows", 0, "graph_sha256"), "00" * 32),
                (("dispatch", "runs", 1, "source_head"), "different-head"),
                (("dispatch", "runs", 1, "execution", "total_output_bytes"), 16 * 1024 * 1024),
                (("dispatch", "runs", 1, "execution", "jobs", 0, "steps", 0, "exit_code"), 0),
                (("dispatch", "runs", 1, "workspaces_closed"), False),
                (("dispatch", "runs"), []),
            ]
            for path, value in mutations:
                bad = copy.deepcopy(sample); target = bad
                for part in path[:-1]: target = target[part]
                target[path[-1]] = value
                try:
                    check_result(bad, f, algorithm, BATCH, "push", SELECTED, "synthetic-head", False)
                except (AssertionError, KeyError, TypeError, ValueError): rejected += 1
                else: raise AssertionError(f"checker accepted damaged {path}")
            require(not (root / "log").exists(), "fixture creation executed a job")
    print(json.dumps(dict(type="workflow_dispatch_checker_self_test", checker_passed=True, damaged_reports_rejected=rejected,
                         rust_executed=False, native_campaign_executed=False, synthetic_checker_inputs=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fg", type=Path)
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    binary = args.fg.resolve()
    require(binary.is_file() and os.access(binary, os.X_OK), "an actual built executable is mandatory; no skipped success")
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
    print(json.dumps(dict(type="binary_identity", sha256=digest.hexdigest())))
    for algorithm in ["sha1", "sha256"]: run_format(binary, algorithm)


if __name__ == "__main__":
    main()
