#!/usr/bin/env python3
"""Synthetic GitHub inputs -> shipped branch/PR CLIs -> real Rust authority.

The existing sandboxed Git oracle checks fixture objects; separate Rust reads
check publication. GitHub observations are input, never native authorization.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import signal
from urllib.parse import urlsplit

from operator_issue_smoke import OperatorCampaign, ROOT, TOKEN
from operator_pull_smoke import check_fixture, PIN
from pull_request_smoke import fixture
from scoped_events_smoke import HttpServer, PRINCIPAL, TENANT, REPOSITORY, file_sha256, require

BRANCH_PRINCIPAL, BRANCH_TOKEN = "66" * 16, "d" * 64
PROFILE_FACTS = (
    "offline_plan_owned_source", "branch_requirements_independent_principal",
    "branch_refusal_and_exact_retry", "branch_budget_and_canonical_refs",
    "pr_refusal_and_exact_retry", "pr_resume_and_canonical_attribution",
    "collision_terminal_and_original_keys", "stopped_service_credential_free_completion",
)
SOURCE_FACTS = ["source_cli_discovery", "source_pin_refusals", "source_bounded_collection_resume", "source_offline_completion"]
PREPARATION_FACTS = ["preparation_cli_bounded_prefix", "preparation_cli_original_custody",
                     "preparation_cli_offline_completion", "preparation_cli_completed_recovery"]
FACTS = ["pinned_git_fixture", "synthetic_source_collection", "sha256_destination_refusal", "all_services_drained",
         "collection_encoded_capacity_preflight", "collection_exact_capacity_handoff",
         "source_worktree_alias_refusals", "source_external_alias_handoff", "requirements_worktree_alias_refusal",
         *SOURCE_FACTS, *PREPARATION_FACTS] + [
    f"{profile}_{fact}" for profile in ("single", "collection", "prepared") for fact in PROFILE_FACTS]


def private_json(path, value):
    with path.open("x", encoding="utf-8") as out:
        json.dump(value, out, ensure_ascii=False)
    return path


def request_hashes(path):
    files = {str(p.relative_to(path)): file_sha256(p) for p in path.rglob("*")
             if p.is_file() and (p.name == "intent.json" or p.name.startswith("request-"))}
    require(bool(files), "original sealed request population is empty")
    return files


@contextmanager
def native_service(campaign, root, credentials):
    for attempt in range(16):
        server = HttpServer(campaign, root, credentials, f"github-pr-{attempt}")
        server.command.extend(["--allow-source", "--allow-receive", "--allow-outcomes"])
        with server:
            if urlsplit(server.url).port <= 10080:
                continue
            yield server
            return
    raise AssertionError("native Fetch-compatible listener selection exhausted")


def run_case(c, oracle_run):
    home = c.work
    root, source = home / "repository", home / "git-source"
    objects = fixture(source, "sha1")
    (home / "reviewed.bundle").write_bytes(objects["bundle"])
    check_fixture(c, oracle_run, source, objects)
    c.facts["pinned_git_fixture"] = True
    c.run("init", root, TENANT, REPOSITORY, "sha1")
    c.run("import", root, TENANT, REPOSITORY, PRINCIPAL, "github-pr-native-fixture", source)

    def read(operation, number=None):
        args = ["pr", operation, root, TENANT, REPOSITORY]
        if number is not None:
            args.append(number)
        args += ["--trusted-local", "--object-format", "sha1"]
        if operation != "show":
            args += ["--limit", 100]
        page = json.loads(c.run(*args))
        require(page["node_closed"] is True, "independent canonical reader did not close")
        return page

    def refs():
        lines = c.run("at", root, TENANT, REPOSITORY, "latest", "refs").decode("ascii").splitlines()
        header = re.fullmatch(r"references at latest \(([0-9]+) total\):", lines[0])
        require(header is not None and int(header[1]) == len(lines) - 1, "canonical ref list is incomplete")
        values = {}
        for line in lines[1:]:
            row = re.fullmatch(r"  (refs/heads/[A-Za-z0-9_/-]+) -> ([0-9a-f]{40})", line)
            require(row is not None and row[1] not in values, "native ref row is malformed or repeated")
            values[row[1]] = row[2]
        require(list(values) == sorted(values), "canonical ref order changed")
        return values

    original_refs = refs()
    inputs = home / "source-inputs"
    inputs.mkdir(mode=0o700)
    helper = ROOT / "scripts/e2e/helpers/github_pull_migration_source.mjs"
    source = c.node_command(helper, ["setup", str(inputs), objects["source"], objects["target"]])
    discover = ROOT / "scripts/discover_github_pulls.mjs"
    collector = ROOT / "scripts/collect_github_pulls.mjs"
    preload, log = Path(source["preload"]), Path(source["log"])

    def source_command(script, args, expected=0, *, error_reply=False):
        return c.node_command(script, args, expected, error_reply=error_reply, preload=preload)

    before_source = read("list")
    # Explicit local path fixtures, not native authority or a hostile-parent
    # sandbox. Keep the original source population and permitted aliases.
    path_worktree = home / "path-worktree-fixture"
    path_worktree.mkdir(mode=0o700)
    (path_worktree / ".git").mkdir(mode=0o700)
    private = path_worktree / "private"
    private.mkdir(mode=0o700)
    hidden = home / "worktree-path-alias"
    hidden.symlink_to(private, target_is_directory=True)
    outside_alias = home / "source-input-alias"
    outside_alias.symlink_to(inputs, target_is_directory=True)
    source_log = log.read_bytes() if log.exists() else b""
    refused = source_command(discover, ["discover", "--repository", source["repository"],
        "--out", str(hidden / "inventory.json"), "--token-file", source["token"]], 2, error_reply=True)
    require(refused["code"] == "github_pull_inventory_worktree" and not (private / "inventory.json").exists()
            and (log.read_bytes() if log.exists() else b"") == source_log,
            "parent alias hid a worktree output or started source requests")
    inventory = source_command(discover, ["discover", "--repository", source["repository"], "--out", str(outside_alias / "inventory.json"),
        "--token-file", source["token"], "--batch-size", "1"])
    require(inventory["pulls"] == inventory["total_batches"] == 2 and not inventory["mutation_submitted"]
            and file_sha256(Path(source["inventory"])) == inventory["inventory_sha256"], "CLI discovery lost its pinned inventory")
    c.facts["source_external_alias_handoff"] = True
    original_inventory = Path(source["inventory"]).read_bytes()
    (private / "inventory.json").write_bytes(original_inventory)
    (private / "inventory.json").chmod(0o600)
    source_log = log.read_bytes()
    refused = source_command(discover, ["inspect", "--inventory", str(hidden / "inventory.json"),
        "--confirm", inventory["inventory_sha256"]], 2, error_reply=True)
    require(refused["code"] == "github_pull_inventory_worktree" and log.read_bytes() == source_log
            and (private / "inventory.json").read_bytes() == original_inventory
            and read("list") == before_source and refs() == original_refs,
            "aliased worktree inventory read changed files, source or native state")
    c.facts["source_worktree_alias_refusals"] = True
    inventory_args = ["--inventory", source["inventory"], "--confirm", inventory["inventory_sha256"]]
    inspected = source_command(discover, ["inspect", *inventory_args, "--batch", "1"])
    require(inspected["selection"]["numbers"] == [9] and not inspected["network_accessed"], "offline inventory selection differs")
    capture = inputs / "single-capture.json"
    refused_args = ["capture-batch", "--inventory", source["inventory"], "--confirm", "0" * 64,
                    "--batch", "1", "--out", str(capture), "--token-file", source["token"]]
    previous = log.read_bytes()
    refused = source_command(discover, refused_args, 2, error_reply=True)
    require(refused["code"] == "github_pull_inventory_pin_mismatch" and log.read_bytes() == previous
            and not capture.exists(), "wrong inventory pin started capture or published bytes")
    captured = source_command(discover, ["capture-batch", *inventory_args, "--batch", "1", "--out", str(capture),
                                        "--token-file", source["token"]])
    require(captured["pulls"] == 1 and file_sha256(capture) == captured["capture_sha256"], "CLI batch capture differs from its pin")
    c.facts["source_cli_discovery"] = True

    previous = log.read_bytes()
    prepared_source = source_command(collector, ["prepare", "--workdir", source["collection"],
        "--inventory", source["inventory"], "--inventory-confirm", inventory["inventory_sha256"]])
    require(not prepared_source["complete"] and not prepared_source["network_accessed"] and log.read_bytes() == previous,
            "collection preparation made a source request or falsely completed")
    Path(source["inventory"]).unlink()
    collection_args = ["--workdir", source["collection"], "--confirm", prepared_source["plan_sha256"]]
    refused = source_command(collector, ["run", "--workdir", source["collection"], "--confirm", "0" * 64], 2, error_reply=True)
    require(not refused["mutation_submitted"] and log.read_bytes() == previous
            and read("list") == before_source and refs() == original_refs, "wrong collection pin performed source/native work")
    c.facts["source_pin_refusals"] = True
    prefix = source_command(collector, ["run", *collection_args, "--token-file", source["token"], "--max-batches", "1"], 3)
    first = Path(source["collection"]) / "captures/batch-000001.json"
    original_first = first.read_bytes()
    require(not prefix["complete"] and prefix["checkpointed_batches"] == 1 and prefix["next_batch"] == 2
            and file_sha256(first) == captured["capture_sha256"], "bounded collection lost its original capture or exceeded one batch")
    previous = log.read_bytes()
    status = source_command(collector, ["status", *collection_args])
    require(status["checkpointed_batches"] == 1 and not status["complete"] and log.read_bytes() == previous,
            "partial collection status performed source work or lost its checkpoint")
    complete_source = source_command(collector, ["run", *collection_args, "--token-file", source["token"]])
    later = [json.loads(line)["address"] for line in log.read_bytes()[len(previous):].splitlines()]
    require(complete_source["complete"] and complete_source["new_batches"] == 1 and later
            and all("/pulls/9" not in address and "/issues/9" not in address for address in later)
            and first.read_bytes() == original_first, "collection resume recaptured or changed the checkpointed batch")
    c.facts["source_bounded_collection_resume"] = True
    custody = {str(p.relative_to(inputs)): file_sha256(p) for p in Path(source["collection"]).rglob("*") if p.is_file()}
    previous = log.read_bytes()
    Path(source["token"]).unlink()
    for operation in ("status", "run"):
        observed = source_command(collector, [operation, *collection_args,
            *(["--complete-confirm", complete_source["complete_sha256"]] if operation == "status" else [])])
        require(observed["complete"] and not observed["network_accessed"]
                and observed["complete_sha256"] == complete_source["complete_sha256"] and log.read_bytes() == previous,
                "completed collection needed a source credential or repeated source work")
    require(custody == {str(p.relative_to(inputs)): file_sha256(p) for p in Path(source["collection"]).rglob("*") if p.is_file()}
            and read("list") == before_source and refs() == original_refs, "source acquisition changed custody or native state")
    c.facts["source_offline_completion"] = True
    selected = c.node_command(helper, ["inspect", str(inputs)])
    require(selected["collection_confirm"] == prepared_source["plan_sha256"]
            and selected["complete_confirm"] == complete_source["complete_sha256"], "source helper changed independently retained pins")
    require(selected["source_class"] == "synthetic-github-input-only" and len(selected["pulls"]) == 2,
            "synthetic source population is incomplete or misclassified")
    c.facts["synthetic_source_collection"] = True
    auth = home / "auth"
    auth.mkdir(mode=0o700)
    credentials, incarnation = c.credentials(root, auth)
    header = credentials.read_text().splitlines()[0]
    token, branch_token = auth / "pr-token", auth / "branch-token"
    token.write_text(TOKEN, encoding="ascii")
    branch_token.write_text(BRANCH_TOKEN, encoding="ascii")

    def grants(branch="outcomes-read", pr="outcomes-read,pulls-read"):
        pending = auth / "credentials.next"
        rows = [(hashlib.sha256(BRANCH_TOKEN.encode()).hexdigest(), BRANCH_PRINCIPAL, branch),
                (hashlib.sha256(TOKEN.encode()).hexdigest(), PRINCIPAL, pr)]
        with pending.open("x", encoding="ascii") as out:
            out.write(header + "\n")
            for digest, principal, scopes in sorted(rows):
                out.write(f"{digest} {principal} {scopes}\n")
        pending.replace(credentials)

    grants()
    profiles = []
    with native_service(c, root, credentials) as server:
        for name, count, start in [("single", 1, 100), ("collection", 2, 200), ("prepared", 1, 300)]:
            directory = home / name
            directory.mkdir(mode=0o700)
            script = ROOT / ("scripts/migrate_github_pull_collection.mjs" if name == "collection" else "scripts/migrate_github_pulls.mjs")
            scope = {"tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": incarnation,
                     "principal_id": PRINCIPAL, "object_format": "sha1"}
            selection = {"endpoint": server.url, "scope": scope, "number_start": str(start),
                         "namespace": f"refs/heads/import/{name}/"}
            selection_file = private_json(directory / "selection.json", selection)
            workdir = directory / "migration"

            def preparation(job, selected_file, script=script, name=name):
                source_args = (["--capture", selected["single_capture"], "--capture-confirm", selected["single_capture_sha256"]]
                    if name != "collection" else ["--collection-dir", selected["collection_dir"],
                        "--collection-confirm", selected["collection_confirm"], "--complete-confirm", selected["complete_confirm"]])
                return ["prepare", *source_args, "--selection", str(selected_file), "--workdir", str(job), "--token-file", str(token)]

            if name == "single":
                wrong = private_json(directory / "sha256-selection.json", {**selection, "scope": {**scope, "object_format": "sha256"}})
                denied = c.node_command(script, preparation(directory / "sha256-refused", wrong), 2, error_reply=True)
                require(denied["code"] == "github_pull_destination_hash_domain" and not (directory / "sha256-refused").exists(),
                        "GitHub SHA-1 input was silently translated into a SHA-256 destination")
                c.facts["sha256_destination_refusal"] = True
            before = read("list")
            draft = None
            if name == "prepared":
                draft_args = preparation(workdir, selection_file)
                draft_args[0] = "prepare-begin"
                begun = c.node_command(script, draft_args)
                draft = dict(workdir=workdir, common=["--workdir", str(workdir), "--confirm", begun["preparation_sha256"]],
                             header=(workdir / "preparation.json").read_bytes())
                snapshot = {str(p.relative_to(workdir)): file_sha256(p) for p in workdir.rglob("*") if p.is_file()}
                refused = c.node_command(script, draft_args, 2, error_reply=True)
                require(refused["code"] == "github_pull_preparation_exists"
                        and snapshot == {str(p.relative_to(workdir)): file_sha256(p) for p in workdir.rglob("*") if p.is_file()},
                        "duplicate preparation replaced its selected identity")
                prepared = c.node_command(script, ["prepare-resume", *draft["common"], "--max-requests", "1"], 3)
                workdir = Path(prepared["import_workdir"])
                require(prepared["prepared_steps"] == prepared["new_steps"] == 1 and not prepared["preparation_complete"]
                        and not prepared["execution_complete"] and not prepared["mutation_submitted"]
                        and not (workdir / "manifest.json").exists(), "bounded preparation exceeded its one-slot prefix")
                c.facts["preparation_cli_bounded_prefix"] = True
                snapshot = {str(p.relative_to(draft["workdir"])): file_sha256(p) for p in draft["workdir"].rglob("*") if p.is_file()}
                for operation in ("prepare-status", "prepare-resume"):
                    refused = c.node_command(script, [operation, "--workdir", str(draft["workdir"]), "--confirm", "0" * 64], 2, error_reply=True)
                    require(refused["code"] == "github_pull_preparation_pin_mismatch" and not refused["mutation_submitted"],
                            "wrong preparation pin did not refuse before work")
                status = c.node_command(script, ["prepare-status", *draft["common"]])
                require(status["prepared_steps"] == 1 and status["local_read_only"] and not status["network_accessed"]
                        and snapshot == {str(p.relative_to(draft["workdir"])): file_sha256(p) for p in draft["workdir"].rglob("*") if p.is_file()}
                        and read("list") == before and refs() == original_refs, "preparation inspection/refusal changed custody or authority")
                c.facts["preparation_cli_original_custody"] = True
            else:
                prepared = c.node_command(script, preparation(workdir, selection_file))
                if name == "collection":
                    # Measure the already validated real intents, not a form-body
                    # estimate. The insufficient attempt must leave this new
                    # path reusable by an exact-boundary permitted preparation.
                    original_workdir, originals = workdir, request_hashes(workdir)
                    exact_bytes = sum(path.stat().st_size for path in workdir.glob("batches/*/requests/*/intent.json"))
                    require(exact_bytes == prepared["request_bytes"], "prepared byte count differs from retained intents")
                    workdir = directory / "capacity-job"
                    command = preparation(workdir, selection_file)
                    refused = c.node_command(script, [*command, "--max-request-bytes", str(exact_bytes - 1)], 2, error_reply=True)
                    require(refused["code"] == "github_pull_migration_plan_capacity"
                            and refused["migration_progress"]["directory_created"] is False
                            and not workdir.exists() and request_hashes(original_workdir) == originals
                            and read("list") == before and refs() == original_refs,
                            "encoded capacity refusal created custody or changed native state")
                    c.facts["collection_encoded_capacity_preflight"] = True
                    prepared = c.node_command(script, [*command, "--max-request-bytes", str(exact_bytes)])
                    require(prepared["preparation_complete"] and prepared["request_bytes"] == exact_bytes
                            and request_hashes(original_workdir) == originals,
                            "exact-capacity preparation did not preserve the reference job")
                    c.facts["collection_exact_capacity_handoff"] = True
            common = ["--workdir", str(workdir), "--confirm", prepared["plan_sha256"]]
            require(prepared["network_accessed"] is False and read("list") == before,
                    "offline planning contacted or changed native authority")
            profiles.append(dict(name=name, count=count, start=start, directory=directory, script=script,
                selection=selection, selection_file=selection_file, workdir=workdir, common=common,
                prepared=prepared, originals=request_hashes(workdir), preparation=draft))

        # Each plan must own all input bytes before the source path disappears.
        inputs.rename(home / "retained-source-inputs")
        for p in profiles:
            if p["preparation"] is None:
                continue
            draft = p["preparation"]
            before = read("list")
            token_hold = token.with_name("preparation-without-token")
            token.rename(token_hold)
            try:
                ready = c.node_command(p["script"], ["prepare-resume", *draft["common"]])
            finally:
                token_hold.rename(token)
            final = request_hashes(p["workdir"])
            require(ready["preparation_complete"] and ready["plan_sha256"] == p["prepared"]["plan_sha256"]
                    and ready["new_steps"] == ready["steps"] - 1 and not ready["network_accessed"]
                    and not ready["mutation_submitted"] and not ready["execution_complete"]
                    and all(final.get(name) == digest for name, digest in p["originals"].items())
                    and (draft["workdir"] / "preparation.json").read_bytes() == draft["header"]
                    and read("list") == before and refs() == original_refs,
                    "offline preparation completion lost its prefix, pin or native boundary")
            p["prepared"], p["originals"] = ready, final
            c.facts["preparation_cli_offline_completion"] = True
        for p in profiles:
            name, directory, script, common = p["name"], p["directory"], p["script"], p["common"]
            c.node_command(script, ["inspect", *common])
            c.facts[f"{name}_offline_plan_owned_source"] = True
            jobs, expected_refs = [], dict(refs())
            for index, entry in enumerate(selected["pulls"][:p["count"]], 1):
                requirements = directory / f"requirements-{index}.json"
                args = ["requirements", *common, *(["--batch", str(index)] if name == "collection" else []),
                        "--principal", BRANCH_PRINCIPAL, "--out", str(requirements)]
                if name == "single" and index == 1:
                    refused_args = [*args]
                    refused_args[-1] = str(hidden / "branches.json")
                    refused = c.node_command(script, refused_args, 2, error_reply=True)
                    require(refused["code"] == "github_pull_worktree" and not (private / "branches.json").exists()
                            and request_hashes(p["workdir"]) == p["originals"],
                            "aliased worktree branch output changed original custody")
                    c.facts["requirements_worktree_alias_refusal"] = True
                c.node_command(script, args)
                requirement = json.loads(requirements.read_text())
                source_pull = entry["pull"]
                wanted = {p["selection"]["namespace"] + f"pr-{source_pull['number']}/head": source_pull["head"]["sha"],
                          p["selection"]["namespace"] + f"pr-{source_pull['number']}/base": source_pull["base"]["sha"]}
                require(requirement["scope"]["principal_id"] == BRANCH_PRINCIPAL
                        and {row["ref"]: row["new_commit"] for row in requirement["refs"]} == wanted,
                        "derived branch requirements changed tips or copied source/PR authority")
                expected_refs.update(wanted)
                bootstrap = ROOT / "scripts/bootstrap_native_branches.mjs"
                job = directory / f"branches-{index}"
                created = c.node_command(bootstrap, ["prepare", "--workdir", str(job), "--selection", str(requirements),
                    "--token-file", str(branch_token)])
                branch_common = ["--workdir", str(job), "--confirm", created["plan_sha256"]]
                originals = request_hashes(job)
                if index == 1:
                    grants()
                    before = refs()
                    refused = c.node_command(bootstrap, ["run", *branch_common, "--token-file", str(branch_token)], 3)
                    require(refused["state"] == "unresolved" and refused["committed"] == 0 and refs() == before,
                            "branch grant denial published a reference or lost uncertainty")
                    key = refused["current"]["key"]
                    grants("read,receive,outcomes-read")
                    recover = c.node_command(bootstrap, ["run", *branch_common, "--token-file", str(branch_token)], 3)
                    require(recover["current"]["key"] == key and recover["mutation_submitted"] is False and refs() == before,
                            "restoring branch grants automatically resent an unresolved key")
                    partial = c.node_command(bootstrap, ["run", *branch_common, "--token-file", str(branch_token),
                        "--retry-key", key, "--max-operations", "1"], 3)
                    require(partial["committed"] == 1 and partial["operations"] == 1,
                            "explicit original-key branch retry did not preserve its one-operation prefix")
                done = c.node_command(bootstrap, ["run", *branch_common, "--token-file", str(branch_token)])
                require(done["complete"] is True and done["committed"] == created["branches"],
                        "native branch bootstrap did not confirm all original creates")
                require(request_hashes(job) == originals, "branch bootstrap replaced original request bodies")
                jobs.append(dict(script=bootstrap, common=branch_common, requirements=requirements, originals=originals, root=job))
            require(refs() == expected_refs and all(refs()[k] == v for k, v in original_refs.items()),
                    "native branch bootstrap missed exact tips or moved a pre-existing branch")
            c.facts[f"{name}_branch_requirements_independent_principal"] = True
            c.facts[f"{name}_branch_refusal_and_exact_retry"] = True
            c.facts[f"{name}_branch_budget_and_canonical_refs"] = True
            p["branch_jobs"] = jobs
            before = read("list")
            denied = c.node_command(script, ["run", *common, "--token-file", str(token)], 3)
            require(denied["state"] == "pending" and denied["committed_steps"] == 0 and read("list") == before,
                    "denied PR writer published or claimed a committed prefix")
            key = denied["current"]["key"]
            grants("read,receive,outcomes-read", "outcomes-read,pulls-read,pulls-write")
            recovered = c.node_command(script, ["run", *common, "--token-file", str(token)], 3)
            require(recovered["current"]["key"] == key and recovered["mutations_dispatched"] == 0
                    and read("list") == before, "restoring PR grants silently resent an original key")
            partial = c.node_command(script, ["run", *common, "--token-file", str(token), "--retry-key", key,
                "--max-operations", "1"], 3)
            require(partial["committed_steps"] == 1 and partial["new_operations"] == 1,
                    "PR retry exceeded its invocation operation allowance")
            c.facts[f"{name}_pr_refusal_and_exact_retry"] = True
            complete = c.node_command(script, ["run", *common, "--token-file", str(token)])
            require(complete["complete"] is True and complete["committed_steps"] == p["prepared"]["steps"],
                    "GitHub PR migration did not confirm every original native step")
            observed = {}
            for index, entry in enumerate(selected["pulls"][:p["count"]]):
                number = p["start"] + index
                row = read("show", number)["pull_request"]
                source_pull = entry["pull"]
                require(row["data"]["title"] == source_pull["title"] and row["data"]["body"] == source_pull["body"]
                        and row["state"] == source_pull["state"] and row["opened_by"] == row["last_metadata_actor"] == PRINCIPAL,
                        "canonical PR metadata lost source bytes/state or impersonated a source actor")
                discussion, reviews = read("comments", number), read("reviews", number)
                expected = [("pull-metadata", source_pull)] + [(kind, record) for kind, records in [
                    ("discussion-comment", entry["discussion"]), ("review", entry["reviews"]),
                    ("inline-review-comment", entry["inline"])] for record in records]
                require(len(discussion["comments"]) == len(expected) and reviews["reviews"] == [],
                        "canonical discussion lost observations or imported active approvals")
                for comment, (kind, original) in zip(discussion["comments"], expected):
                    envelope, payload = comment["body"].split("\n\n", 1)
                    provenance = json.loads(envelope.split("\n", 1)[1])
                    require(comment["actor"] == PRINCIPAL and provenance["kind"] == kind
                            and provenance["part"] == provenance["parts"] == 1 and json.loads(payload) == original
                            and hashlib.sha256(payload.encode()).hexdigest() == provenance["sha256"],
                            "native attributed observation differs from the pinned source record")
                observed[number] = (row, discussion["comments"])
            require(refs() == expected_refs, "PR metadata migration moved Git references")
            c.facts[f"{name}_pr_resume_and_canonical_attribution"] = True
            # New independent occupied-ref intent, not replacement of an uncertain key.
            first = jobs[0]
            collision_job = directory / "branch-collision"
            prepared = c.node_command(first["script"], ["prepare", "--workdir", str(collision_job),
                "--selection", str(first["requirements"]), "--token-file", str(branch_token)])
            collision_args = ["--workdir", str(collision_job), "--confirm", prepared["plan_sha256"]]
            collision = c.node_command(first["script"], ["run", *collision_args, "--token-file", str(branch_token)], 1)
            require(collision["state"] == "refused" and collision["committed"] == 0 and refs() == expected_refs,
                    "occupied branch create was overwritten, skipped or falsely completed")
            repeated = c.node_command(first["script"], ["run", *collision_args], 1)
            require(repeated["current"]["key"] == collision["current"]["key"] and repeated["operations"] == 0,
                    "occupied-branch recovery replaced its key or redispatched")
            retained = home / "retained-source-inputs"
            source_args = (["--capture", str(retained / Path(selected["single_capture"]).relative_to(inputs)),
                            "--capture-confirm", selected["single_capture_sha256"]] if name != "collection" else [
                            "--collection-dir", str(retained / Path(selected["collection_dir"]).relative_to(inputs)),
                            "--collection-confirm", selected["collection_confirm"], "--complete-confirm", selected["complete_confirm"]])
            collision_plan = directory / "pr-collision"
            prepared = c.node_command(script, ["prepare", *source_args, "--selection", str(p["selection_file"]),
                "--workdir", str(collision_plan), "--token-file", str(token)])
            collision_args = ["--workdir", str(collision_plan), "--confirm", prepared["plan_sha256"]]
            collision = c.node_command(script, ["run", *collision_args, "--token-file", str(token)], 1)
            require(collision["state"] == "refused" and collision["committed_steps"] == 0 and refs() == expected_refs,
                    "occupied PR number did not stop the migration before successor work")
            repeated = c.node_command(script, ["run", *collision_args], 1)
            require(repeated["current"]["key"] == collision["current"]["key"] and repeated["new_operations"] == 0,
                    "occupied-PR recovery replaced its key or redispatched")
            require(request_hashes(p["workdir"]) == p["originals"], "PR migration replaced an original sealed request")
            for number, (row, comments) in observed.items():
                require(read("show", number)["pull_request"] == row and read("comments", number)["comments"] == comments,
                        "branch collision changed existing PR content or discussion")
            c.facts[f"{name}_collision_terminal_and_original_keys"] = True
    token.rename(token.with_name("retained-pr-token"))
    branch_token.rename(branch_token.with_name("retained-branch-token"))
    for p in profiles:
        for operation in ("inspect", "status", "recover", "run"):
            settled = c.node_command(p["script"], [operation, *p["common"]])
            require(settled.get("network_accessed") is False, "completed PR custody needed a stopped endpoint or token")
        for job in p["branch_jobs"]:
            for operation in ("inspect", "status", "recover", "run"):
                settled = c.node_command(job["script"], [operation, *job["common"]])
                require(settled.get("network_accessed") is False, "completed branch custody needed a stopped endpoint or token")
        c.facts[f"{p['name']}_stopped_service_credential_free_completion"] = True
        if p["preparation"] is not None:
            for operation in ("prepare-status", "prepare-resume"):
                settled = c.node_command(p["script"], [operation, *p["preparation"]["common"]])
                require(settled["preparation_complete"] and not settled["network_accessed"]
                        and not settled["execution_complete"] and not settled["mutation_submitted"]
                        and request_hashes(p["workdir"]) == p["originals"],
                        "completed preparation recovery altered original native custody")
            c.facts["preparation_cli_completed_recovery"] = True
    c.facts["all_services_drained"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "oracle-run", "summary"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    fg, node = args.fg.resolve(strict=True), args.node.resolve(strict=True)
    c = OperatorCampaign(fg, node, args.work.resolve())
    summary = {"complete": False, "facts": c.facts, "selected_facts": FACTS,
        "binary_sha256": file_sha256(fg), "node_sha256": file_sha256(node), "artifacts": str(c.work),
        "oracle_pin": PIN, "oracle_run": str(args.oracle_run),
        "entrypoints": [{"path": "scripts/" + name, "binary_sha256": file_sha256(fg)} for name in (
            "bootstrap_native_branches.mjs", "migrate_github_pulls.mjs", "migrate_github_pull_collection.mjs",
            "discover_github_pulls.mjs", "collect_github_pulls.mjs")],
        "non_claim": "Synthetic GitHub source inputs and real native SHA-1 destination; not live GitHub, SHA-256 translation, every entrypoint, independent batch, D10 or full/release qualification."}

    def stop(_number, _frame):
        raise InterruptedError("GitHub PR campaign interrupted; draining native owners")

    signal.signal(signal.SIGTERM, stop)
    try:
        identity = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity["type"] == "js_runtime_identity" and identity["corpus_started"] is False,
                "runtime identity did not precede native dispatch")
        summary["node_version"] = identity["node"]
        run_case(c, args.oracle_run.resolve(strict=True))
        require(set(c.facts) == set(FACTS) and all(c.facts.values()), "selected native facts are missing")
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
