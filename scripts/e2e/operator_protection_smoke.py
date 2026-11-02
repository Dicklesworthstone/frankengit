#!/usr/bin/env python3
"""Shipped protection CLI -> actual native admission/outcomes and Rust policy reads.

Private trusted-local policies only; no Git objects, peer server, policy engine,
implicit build or production credential. Reuse existing operator/service owners.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
from urllib.parse import urlsplit

from operator_issue_smoke import OperatorCampaign
from scoped_events_smoke import HttpServer, PRINCIPAL, TENANT, REPOSITORY, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/fg_protection_admin.mjs"
SUCCESSOR, STRANGER = "44" * 16, "55" * 16
REVIEWERS = ["66" * 16, "77" * 16]
TOKENS = {"admin": "c" * 64, "successor": "d" * 64, "stranger": "f" * 64, "rotated": "e" * 64}
FULL = "outcomes-read,protection-read,protection-write"


def private_file(path, value):
    with path.open("x", encoding="utf-8") as out:
        out.write(value if isinstance(value, str) else json.dumps(value, sort_keys=True) + "\n")


def snapshot(path):
    return {str(p.relative_to(path)): file_sha256(p) if p.is_file() else "directory"
            for p in path.rglob("*")}


def accepted(server):
    records = [json.loads(line) for line in server.stdout_path.read_bytes().splitlines()]
    return next(row["accepted"] for row in records if row.get("type") == "smart_http_drained")


def policy(admin, reviewers):
    return {"administrators": [admin], "branches": [{"reference_hex": b"refs/heads/main".hex(),
             "required_reviewers": reviewers, "required_checks": []}] if reviewers else []}


def run_case(c, fmt):
    home = c.work / fmt
    home.mkdir(mode=0o700)
    root = home / "node"
    c.run("init", root, TENANT, REPOSITORY, fmt)
    credentials, incarnation = c.credentials(root, home)
    header = credentials.read_text().splitlines()[0]
    scope = home / "scope.json"
    private_file(scope, dict(tenant_id=TENANT, repository_id=REPOSITORY,
                            repository_incarnation=incarnation, object_format=fmt))
    token_files = {}
    for name, token in TOKENS.items():
        token_files[name] = home / (name + ".token")
        private_file(token_files[name], token + "\n")

    def grants(admin=FULL, successor=FULL):
        entries = [("admin", PRINCIPAL, admin), ("successor", SUCCESSOR, successor),
                   ("stranger", STRANGER, FULL), ("rotated", PRINCIPAL, "outcomes-read")]
        pending = home / "credentials.next"
        private_file(pending, header + "\n" + "\n".join(
            f"{hashlib.sha256(TOKENS[name].encode()).hexdigest()} {principal} {scopes}"
            for name, principal, scopes in entries) + "\n")
        pending.replace(credentials)

    def read():
        value = json.loads(c.run("protection", "show", root, TENANT, REPOSITORY,
                                 "--trusted-local", "--object-format", fmt))
        require(value["node_closed"] is True, "canonical policy read did not close")
        return value

    def refs():
        value = json.loads(c.run("refs", root, TENANT, REPOSITORY, "--trusted-local",
                                "--object-format", fmt, "--limit", "100"))
        require(value["node_closed"] is True and value["has_more"] is False, "incomplete canonical refs")
        return value["references"]

    def check(version, epoch, expected):
        value = read()
        require(value["version"] == version and value["policy_epoch"] == epoch and value["installed"] is True,
                "canonical policy predecessor/version mismatch")
        actual = value["policy"]
        require(actual["administrators"] == expected["administrators"], "canonical administrator set mismatch")
        require(len(actual["branches"]) == len(expected["branches"]), "canonical branch count mismatch")
        for row, wanted in zip(actual["branches"], expected["branches"]):
            require(row["ref_hex"] == wanted["reference_hex"] and row["required_reviewers"] == wanted["required_reviewers"],
                    "canonical branch/reviewer bytes mismatch")
            require(row["required_approvals"] == len(wanted["required_reviewers"])
                    # Legacy views omit false queues and empty candidate checks,
                    # as the client's historical policy normalization permits.
                    and row.get("require_merge_queue", False) is False and row["required_checks"] == []
                    and row.get("required_candidate_checks", []) == [], "unselected canonical policy requirement")
        require(actual.get("ref_policy") is None, "unselected DSL policy appeared")
        return value

    traffic = 0

    def call(action, *fields, who="admin", expected=0, error=False, network=True):
        nonlocal traffic
        args = [action]
        if action != "show-intent":
            args += ["--endpoint", endpoint, "--token-file", token_files[who]]
        if network:
            traffic += 1  # Expected one-hop contract; native drain counts are the independent oracle.
        return c.node_command(SCRIPT, list(map(str, [*args, *fields])), expected, error_reply=error)

    def prepare(name, replacement, who="admin", clear=False, expected=0, error=False):
        path, intent = home / (name + ".policy.json"), home / name
        private_file(path, replacement)
        result = call("prepare", "--scope-file", scope, "--principal",
                      {"admin": PRINCIPAL, "successor": SUCCESSOR, "stranger": STRANGER}[who],
                      "--policy-file", path, "--intent", intent, *(["--clear"] if clear else []),
                      who=who, expected=expected, error=error)
        return intent, result

    def send(intent, prepared, who="admin", expected=0, error=False, retry=False, network=True):
        return call("send", "--intent", intent, "--confirm-intent", prepared["intent_sha256"],
                    *(["--retry"] if retry else []), who=who, expected=expected, error=error, network=network)

    def server(label, enabled=True, port=None):
        instance = HttpServer(c, root, credentials, f"protection-{fmt}-{label}")
        instance.command.append("--allow-outcomes")
        if enabled:
            instance.command.append("--allow-protection")
        if port is not None:
            instance.command[5] = f"127.0.0.1:{port}"
        return instance

    grants()
    original_refs = refs()
    require(original_refs == [], "policy-only fixture unexpectedly has Git refs")
    p0, p1, p2 = policy(PRINCIPAL, REVIEWERS[:1]), policy(PRINCIPAL, REVIEWERS), policy(PRINCIPAL, REVIEWERS[1:])
    absent = read()
    with server("uninstalled") as initial:
        endpoint = initial.url
        view = call("inspect", "--scope-file", scope)
        require(view["installed"] is False and view["version"] == "0", "absent policy inspection changed")
        path, denied = prepare("remote-bootstrap", p0, expected=2, error=True)
        require(denied["code"] == "trusted_local_bootstrap_required" and not path.exists(), "remote client bootstrapped authority")
        require(read() == absent, "read/prepare published absent policy")
    require(accepted(initial) == traffic == 2, "bootstrap inspection made unexpected HTTP calls")
    c.run("protection", "set", root, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
          "--principal", PRINCIPAL, "--expected-version", "0", "--expected-epoch", "1",
          "--idempotency-key", "operator-local-bootstrap-" + fmt, "--admin", PRINCIPAL,
          "--require-reviewer", "refs/heads/main:" + REVIEWERS[0])
    check(1, 2, p0)
    c.facts[fmt + "_bootstrap_refusal_and_local_twin"] = True

    traffic = 0
    with server("active") as active:
        endpoint, port = active.url, urlsplit(active.url).port
        baseline = read()
        view = call("inspect", "--scope-file", scope)
        require(view["version"] == "1" and view["policy_epoch"] == "2" and view["policy"]["administrators"] == [PRINCIPAL],
                "HTTP inspection differs from Rust policy")
        a, pa = prepare("first-change", p1)
        b, pb = prepare("stale-change", p2)
        require(pa["mutation_sent_by_this_command"] is False and pb["expected_version"] == "1", "preparation sent or refreshed policy")
        shown = call("show-intent", "--intent", a, network=False)
        require(shown == pa and read() == baseline, "inspect/show/prepare changed canonical policy")
        before = snapshot(a)
        wrong = call("send", "--intent", a, "--confirm-intent", "0" * 64, expected=2, error=True, network=False)
        require(wrong["code"] == "explicit_intent_confirmation_required" and snapshot(a) == before, "local confirmation failure touched custody")
        c.facts[fmt + "_exact_inspect_and_readonly_prepare"] = True

        grants(admin="outcomes-read,protection-read")
        denied = send(a, pa, expected=3, error=True)
        require(denied["status"] == 403 and denied["outcome_unknown"] is True and (a / "attempt.json").is_file(),
                "missing write grant lost may-have-sent uncertainty")
        require(read() == baseline, "gateway-refused send changed observed canonical policy")
        pending = call("outcome", "--intent", a, expected=3)
        require(pending["summary"]["terminal"] is False and pending["absence_proves_non_commit"] is False, "absence became non-commit")
        guarded = send(a, pa, expected=3, error=True, network=False)
        require(guarded["code"] == "explicit_retry_required", "ambiguous send automatically retried")
        grants()
        committed = send(a, pa, retry=True)
        require(committed["summary"]["state"] == "committed" and committed["mutation_request_sent"] is True,
                "restored write grant did not commit exact saved command")
        check(2, 3, p1)
        c.facts[fmt + "_committed_change_and_canonical_policy"] = True
        lost = home / "lost-local-observation"
        lost.mkdir(mode=0o700)
        # Model a post-commit/pre-observation crash in NEW custody. The original
        # acknowledged directory and terminal bytes are retained unchanged.
        for name in ("intent.json", "attempt.json"):
            private_file(lost / name, (a / name).read_text())

        stale = send(b, pb, expected=2)
        require(stale["summary"]["state"] == "refused", "stale policy did not produce canonical refusal")
        check(2, 3, p1)
        recovered_stale = call("outcome", "--intent", b, expected=2)
        require(recovered_stale["summary"] == stale["summary"] and recovered_stale["request_reexecuted"] is False,
                "original stale decision changed on readback")
        current, pc = prepare("current-change", p2)
        send(current, pc)
        check(3, 4, p2)
        c.facts[fmt + "_stale_refusal_and_current_twin"] = True

        hostile, ph = prepare("stranger-takeover", policy(STRANGER, REVIEWERS[:1]), who="stranger")
        refused = send(hostile, ph, who="stranger", expected=2)
        require(refused["summary"]["state"] == "refused", "gateway grant appointed an administrator")
        check(3, 4, p2)
        rotated_policy = policy(SUCCESSOR, REVIEWERS[1:])
        rotation, pr = prepare("rotate-administrator", rotated_policy)
        send(rotation, pr)
        check(4, 5, rotated_policy)
        removed, prem = prepare("removed-admin", p0)
        require(send(removed, prem, expected=2)["summary"]["state"] == "refused", "removed administrator regained authority")
        check(4, 5, rotated_policy)
        clear_policy = policy(SUCCESSOR, [])
        uncleared, rejected = prepare("clear-without-opt-in", clear_policy, who="successor", expected=2, error=True)
        require(rejected["code"] == "explicit_clear_required_only_for_empty_protection" and not uncleared.exists(), "clear lacked explicit opt-in")
        cleared, pcl = prepare("clear-policy", clear_policy, who="successor", clear=True)
        send(cleared, pcl, who="successor")
        check(5, 6, clear_policy)
        c.facts[fmt + "_admin_rotation_and_current_authority"] = True

        settled = read()
        terminal_bytes = (a / "terminal.json").read_bytes()
        grants(admin="protection-read,protection-write")
        unavailable = call("outcome", "--intent", a, expected=4, error=True)
        require(unavailable["status"] == 403 and unavailable["outcome_unknown"] is False
                and unavailable["observation"]["summary"] == committed["summary"], "failed fresh lookup erased retained terminal")
        require((a / "terminal.json").read_bytes() == terminal_bytes and read() == settled, "failed lookup changed custody or policy")
        fresh, pf = prepare("not-sent", policy(SUCCESSOR, REVIEWERS), who="successor")
        grants(admin="protection-read,protection-write", successor="protection-read,protection-write")
        unknown = call("outcome", "--intent", fresh, who="successor", expected=3, error=True)
        require(unknown["outcome_unknown"] is True and unknown["observation"] is None, "unseen decision acquired fake terminal knowledge")
        grants()
        still_unknown = call("outcome", "--intent", fresh, who="successor", expected=3)
        require(still_unknown["summary"]["terminal"] is False and still_unknown["absence_proves_non_commit"] is False,
                "unobserved key became rollback proof")
        recovered = call("outcome", "--intent", a, who="rotated")
        require(recovered["summary"] == committed["summary"] and recovered["request_reexecuted"] is False,
                "rotated same-principal lookup changed terminal identity")
        token_denied = send(a, pa, who="rotated", expected=2, error=True, network=False)
        require(token_denied["code"] == "original_token_required_for_resend", "rotated lookup token enabled resend")
        require(read() == settled, "recovery/grant twins changed canonical policy")
        c.facts[fmt + "_independent_grant_and_recovery_twins"] = True
    require(accepted(active) == traffic == 24, "active CLI requests differ from the fixed native transport budget")

    traffic = 0
    with server("reopened", port=port) as reopened:
        require(reopened.url == endpoint, "restart changed the independently pinned endpoint")
        call("inspect", "--scope-file", scope, who="successor")
        cached = send(a, pa, network=False)
        require(cached["summary"] == committed["summary"] and cached["mutation_request_sent"] is False,
                "cached original send reexecuted after administrator removal/restart")
        cached_refusal = send(b, pb, expected=2, network=False)
        require(cached_refusal["summary"] == stale["summary"] and cached_refusal["mutation_request_sent"] is False,
                "cached stale refusal reexecuted")
        replayed = send(lost, pa, retry=True)
        require(replayed["summary"] == committed["summary"] and replayed["mutation_request_sent"] is True,
                "original-key POST did not recover after administrator removal/restart")
        recovered = call("outcome", "--intent", a, who="rotated")
        require(recovered["summary"] == committed["summary"] and read() == settled, "restart changed original terminal or policy")
    require(accepted(reopened) == traffic == 3, "local cache or explicit original-key recovery changed the transport count")
    c.facts[fmt + "_original_key_terminal_cache_after_restart"] = True

    for intent in [a, b, current, hostile, rotation, removed, cleared, fresh, lost]:
        for path in [intent, *intent.rglob("*")]:
            meta = path.stat()
            require(meta.st_uid == os.getuid() and meta.st_mode & 0o077 == 0, "public or foreign intent custody")
            require(not path.is_file() or all(token.encode() not in path.read_bytes() for token in TOKENS.values()), "raw credential retained in intent")
        require(not (intent / ".send-lock").exists(), "completed sender left an ownership lock")
    c.facts[fmt + "_retained_intents_private_and_token_free"] = True

    traffic = 0
    with server("disabled", enabled=False) as disabled:
        endpoint = disabled.url
        denied = call("inspect", "--scope-file", scope, who="successor", expected=2, error=True)
        require(denied["code"] == "http_request_refused" and denied["status"] == 403, "disabled protection route yielded a valid policy")
        require(read() == settled and refs() == original_refs, "read-only/disabled protection changed native state or refs")
    require(accepted(disabled) == traffic == 1, "disabled capability drain mismatch")
    c.facts[fmt + "_disabled_scope_refuses_without_change"] = True
    c.facts[fmt + "_owned_services_drained"] = True
    print(f"OPERATOR_PROTECTION {fmt}: five CLI actions, native policy/authority/grant twins, original recovery and drain", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()), "--work must be empty; prior custody is never reused")
    c = OperatorCampaign(args.fg.resolve(strict=True), args.node.resolve(strict=True), args.work.resolve())
    summary = {"complete": False, "facts": c.facts, "entrypoints": ["scripts/fg_protection_admin.mjs"],
        "binary_sha256": file_sha256(c.fg), "node_sha256": file_sha256(c.node), "artifacts": str(c.work),
        "non_claim": "Basic policy-only native fixture; no Git objects/oracle, writer enforcement, queue/candidate-check/DSL behavior, TLS, hostile isolation, hardware crash durability, current-source native or full operator qualification."}
    def stop(*_):
        raise InterruptedError("protection campaign interrupted; retain intent custody and drain native service")
    signal.signal(signal.SIGTERM, stop)
    try:
        identity = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity["type"] == "js_runtime_identity" and identity["corpus_started"] is False, "shared runtime identity missing")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
