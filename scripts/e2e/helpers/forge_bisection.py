import hashlib, json, os, pathlib, subprocess, sys, zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
tenant, repository, principal = "1" * 32, "2" * 32, "3" * 32
counter = 0
cases = []

def run(label, args, expected=0):
    global counter
    counter += 1
    result = subprocess.run([fg, "--timeout-secs", "120", *map(str, args)], capture_output=True, timeout=180)
    (root / f"{counter:03d}-{label}.out").write_bytes(result.stdout)
    (root / f"{counter:03d}-{label}.err").write_bytes(result.stderr)
    assert result.returncode == expected, (label, result.returncode, expected, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
    return result.stdout

def receipt(raw):
    report = json.loads(raw)
    prefix, tail = raw.strip().rsplit(b',"receipt_sha256":"', 1)
    actual = hashlib.sha256(prefix + b"}").hexdigest()
    assert tail == actual.encode() + b'"}'
    assert report["receipt_sha256"] == actual
    assert report["authorization"] == "trusted_local_whole_repository"
    assert report["profile"] == "forge-state-bisect-local-v1"
    assert all(isinstance(probe["sequence"], str) for probe in report["probes"])
    assert len(report["probes"]) == report["steps_taken"]
    return report

def object_file(source, fmt, kind, body):
    framed = kind.encode() + b" " + str(len(body)).encode() + b"\0" + body
    oid = hashlib.new(fmt, framed).hexdigest()
    file = source / "objects" / oid[:2] / oid[2:]
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(zlib.compress(framed))
    return oid

for fmt in ("sha1", "sha256"):
    store = root / (fmt + "-node")
    scope = [store, tenant, repository]
    search = ["bisect", *scope, "--trusted-local"]
    missing = root / (fmt + "-must-not-exist")
    run(fmt + "-no-auth", ["bisect", missing, tenant, repository, "--issue", "1", "--state", "closed"], 2)
    assert not missing.exists()
    run(fmt + "-init", ["init", *scope, fmt])
    outcomes = []
    for version, action in enumerate(("open", "close", "reopen", "close")):
        args = ["issue", action, *scope, "1", "--trusted-local", "--principal", principal, "--idempotency-key", f"{fmt}-issue-{version}", "--expected-version", version, "--object-format", fmt]
        if action == "open":
            args += ["--title", "Temporary regression", "--body", "untrusted text is never an executable predicate"]
        outcome = json.loads(run(fmt + "-issue-" + action, args))
        assert outcome["command_committed"] and outcome["node_closed"]
        outcomes.append(outcome)
    selected = [*search, "--issue", "1", "--state", "closed"]
    raw = run(fmt + "-first-closed", selected)
    first = receipt(raw)
    assert first["complete"] and first["status"] == "matched"
    assert int(first["first_match"]) == outcomes[1]["decision_sequence"]
    assert first["steps_taken"] == 2
    assert run(fmt + "-deterministic-cold-replay", selected) == raw
    refused = receipt(run(fmt + "-probe-budget", [*selected, "--max-probes", "1"], 2))
    assert not refused["complete"] and refused["first_match"] is None
    assert refused["error"]["code"] == "probe_budget_exhausted"
    second = receipt(run(fmt + "-later-first", [*selected, "--start", outcomes[2]["decision_sequence"]]))
    assert int(second["first_match"]) == outcomes[3]["decision_sequence"]
    missing_issue = receipt(run(fmt + "-no-match", [*search, "--issue", "2", "--state", "closed"], 1))
    assert missing_issue["complete"] and missing_issue["status"] == "not_found"
    assert missing_issue["source_head"] == first["source_head"]
    pinned = receipt(run(fmt + "-pin", [*selected, "--expected-head", first["source_head"], "--expected-incarnation", first["repository_incarnation_id"]]))
    assert pinned["first_match"] == first["first_match"]
    run(fmt + "-wrong-incarnation", [*selected, "--expected-incarnation", "7" * 32], 2)
    # Independent native object fixture: no system Git or repository checkout.
    source = root / (fmt + "-source")
    blob = object_file(source, fmt, "blob", b"fixture\n")
    tree = object_file(source, fmt, "tree", b"100644 file\0" + bytes.fromhex(blob))
    tip = object_file(source, fmt, "commit", f"tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n".encode())
    source_tip = object_file(source, fmt, "commit", f"tree {tree}\nparent {tip}\nauthor Fixture <fixture@example.invalid> 2 +0000\ncommitter Fixture <fixture@example.invalid> 2 +0000\n\nsource change\n".encode())
    (source / "refs/heads").mkdir(parents=True)
    for branch, oid in (("main", tip), ("topic", source_tip)):
        (source / "refs/heads" / branch).write_text(oid + "\n")
    (source / "HEAD").write_text("ref: refs/heads/main\n")
    imported = json.loads(run(fmt + "-import", ["import", *scope, principal, fmt + "-import", source, "--json"]))
    assert imported["state"] == "committed"
    matched_ref = receipt(run(fmt + "-ref-equals", [*search, "--ref", "refs/heads/main", "--equals", tip]))
    assert int(matched_ref["first_match"]) == imported["decision_sequence"]
    absent = receipt(run(fmt + "-ref-absent", [*search, "--ref", "refs/heads/main", "--absent"]))
    assert int(absent["first_match"]) == outcomes[0]["decision_sequence"]
    assert not run(fmt + "-stale-head", [*selected, "--expected-head", first["source_head"]], 2)
    # Native metadata state is intentionally distinct from legacy digest PRs.
    pull_outcomes = []
    for version, action in enumerate(("open", "close", "reopen")):
        args = ["pr", action, *scope, "1", "--trusted-local", "--principal", principal, "--idempotency-key", f"{fmt}-pull-{version}", "--expected-version", version, "--source-ref", "refs/heads/topic", "--expected-source", source_tip, "--target-ref", "refs/heads/main", "--expected-target", tip, "--title", "Native lifecycle", "--body", "", "--object-format", fmt]
        pull_outcomes.append(json.loads(run(fmt + "-pull-" + action, args)))
    closed_pull = receipt(run(fmt + "-closed-pull", [*search, "--pull", "1", "--state", "closed"]))
    assert int(closed_pull["first_match"]) == pull_outcomes[1]["decision_sequence"]
    no_merge = receipt(run(fmt + "-not-merged", [*search, "--pull", "1", "--state", "merged"], 1))
    assert no_merge["complete"] and no_merge["status"] == "not_found"
    fast_forward = json.loads(run(fmt + "-fast-forward", ["pr", "fast-forward", *scope, "1", "--trusted-local", "--principal", principal, "--idempotency-key", fmt + "-ff", "--expected-version", "3", "--source-ref", "refs/heads/topic", "--expected-source", source_tip, "--target-ref", "refs/heads/main", "--expected-target", tip, "--object-format", fmt]))
    merged = receipt(run(fmt + "-first-merged", [*search, "--pull", "1", "--state", "merged"]))
    assert merged["complete"] and merged["status"] == "matched"
    assert int(merged["first_match"]) == int(fast_forward["decision_sequence"])
    moved = receipt(run(fmt + "-ref-after-merge", [*search, "--ref", "refs/heads/main", "--equals", source_tip]))
    assert moved["first_match"] == merged["first_match"]
    # A real canonical policy installation creates the threshold transition.
    policy = run(fmt + "-policy-install", ["protection", "set", *scope, "--trusted-local", "--principal", principal, "--idempotency-key", fmt + "-policy", "--expected-version", "0", "--expected-epoch", no_merge["current_policy_epoch"], "--admin", principal, "--clear", "--object-format", fmt])
    threshold = receipt(run(fmt + "-policy-threshold", [*search, "--policy-at-least", int(no_merge["current_policy_epoch"]) + 1]))
    assert threshold["strategy"] == "verified_non_decreasing_policy_epoch" and threshold["complete"]
    assert threshold["first_match"] == threshold["end"]
    assert threshold["steps_taken"] <= (threshold["published_positions"] - 1).bit_length() + 2
    # The mutable source path is no longer available to historical queries.
    source.rename(root / (fmt + "-source-offline"))
    final_raw = run(fmt + "-source-free-final", selected)
    final = receipt(final_raw)
    assert final["first_match"] == first["first_match"]
    assert run(fmt + "-source-free-repeat", selected) == final_raw
    assert int(final["end"]) == int(threshold["end"])
    cases.append({"format": fmt, "history_batches": final["history_batches"], "first_issue_closed": first["first_match"], "first_pull_closed": closed_pull["first_match"], "first_pull_merged": merged["first_match"], "policy_threshold": threshold["first_match"], "source_head": final["source_head"], "receipt_sha256": final["receipt_sha256"], "deterministic_cold_replay": True, "stale_and_budget_refusals": True})
    print(json.dumps(cases[-1]), flush=True)
(root / "results.json").write_text(json.dumps({"commands": counter, "cases": cases}, indent=2) + "\n")
