"""Actual detached-approval and remote-bundle CLIs over native Git source."""
from hashlib import sha256
import json
from pathlib import Path

from full_bundle_smoke import decode_export
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
REF = "refs/heads/main"


def run_remote_bundle_case(c, home, fmt, donor, base, objects, canonical, oracle):
    work = home / "native-bundle" / "remote"
    work.mkdir(mode=0o700)
    cli = ROOT / "scripts/remote_bundle.mjs"

    def private(name, value):
        path = work / name
        with path.open("x", encoding="utf-8") as out:
            path.chmod(0o600)
            out.write(value if isinstance(value, str) else json.dumps(value))
        return path

    def remote(args, expected=0, error=False, hook=None):
        args = list(map(str, [*args, "--timeout-ms", "10000"]))
        return c.node_command(cli if hook is None else Path("--import"),
            args if hook is None else [str(hook), str(cli), *args], expected, error_reply=error)

    def job(operation, request):
        return [operation, "--workdir", request["workdir"], "--confirm", request["intent_sha256"]]

    def authority(node):
        return c.run("at", node, TENANT, REPOSITORY, "latest")

    def credentials(node, label, token, scopes):
        directory = work / label
        directory.mkdir(mode=0o700)
        table, incarnation = c.credentials(node, directory)
        header = table.read_text().splitlines()[0]
        table.write_text(header + "\n" + sha256(token.encode()).hexdigest()
            + f" {PRINCIPAL} {scopes}\n")
        token_file = private(label + ".token", token)
        return table, token_file, incarnation

    destination = work / "destination"
    c.run("init", destination, TENANT, REPOSITORY, fmt)
    destination.chmod(0o700)
    source_table, source_token, source_incarnation = credentials(donor, "reader", "a" * 64, "read")
    target_table, target_token, target_incarnation = credentials(destination, "writer", "b" * 64, "receive,outcomes-read")
    wrong_token = private("wrong.token", "f" * 64)
    source_server = HttpServer(c, donor, source_table, "remote-bundle-source-" + fmt)
    source_server.command.append("--allow-source")
    target_server = HttpServer(c, destination, target_table, "remote-bundle-target-" + fmt)
    target_server.command.extend(["--allow-source", "--allow-receive", "--allow-outcomes"])
    source_before, destination_before = authority(donor), authority(destination)
    with source_server, target_server:
        selected = private("source.json", {"endpoint": source_server.url, "scope": {
            "tenant_id": TENANT, "repository_id": REPOSITORY,
            "repository_incarnation": source_incarnation, "object_format": fmt}})
        denied = work / "denied-download"
        refused = remote(["export", "--workdir", denied, "--selection", selected, "--token-file", wrong_token], 2, True)
        require(refused["code"] == "remote_bundle_export_http_refused" and not denied.exists(),
                "unauthenticated bundle export created complete local custody")
        downloaded = remote(["export", "--workdir", work / "download", "--selection", selected,
            "--token-file", source_token])
        bundle = Path(downloaded["bundle_file"])
        raw, digest = bundle.read_bytes(), file_sha256(bundle)
        require(downloaded["complete"] is True and downloaded["mutation_submitted"] is False
                and downloaded["native_bundle_validated"] is False and downloaded["artifact_sha256"] == digest
                and decode_export(raw, fmt) == ({b"HEAD": base, REF.encode(): base}, objects)
                and authority(donor) == source_before, "remote export changed canonical source or independent objects")
        inspect = ["inspect-download", "--workdir", downloaded["workdir"], "--confirm", downloaded["download_sha256"]]
        wrong = inspect.copy()
        wrong[-1] = "0" * 64
        remote(wrong, 2, True)
        checked = remote(inspect)
        require(checked["artifact_sha256"] == digest and bundle.read_bytes() == raw,
                "download inspection changed the selected native artifact")
        pinned_selection = {"endpoint": source_server.url, "scope": downloaded["source"]["scope"],
            "expected_head": downloaded["source"]["snapshot_token"]}
        wrong_head = json.loads(json.dumps(pinned_selection))
        token = wrong_head["expected_head"]
        wrong_head["expected_head"] = token[:-1] + ("0" if token[-1] != "0" else "1")
        wrong_selection = private("wrong-head.json", wrong_head)
        remote(["export", "--workdir", work / "wrong-head-download", "--selection", wrong_selection,
            "--token-file", source_token], 2, True)
        require(not (work / "wrong-head-download").exists(), "wrong native snapshot pin created complete custody")
        pinned = remote(["export", "--workdir", work / "pinned-download", "--selection",
            private("pinned-source.json", pinned_selection), "--token-file", source_token])
        require(Path(pinned["bundle_file"]).read_bytes() == raw and authority(donor) == source_before,
                "exact source-head export changed the independently selected native artifact")
        oracle("remote-export", "bundle", "verify", "../native-bundle/remote/download/repository.bundle")
        c.facts[f"{fmt}_remote_bundle_native_export"] = True

        created = c.node_command(Path("-e"), ["""const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const pair=crypto.generateKeyPairSync('ed25519'),other=crypto.generateKeyPairSync('ed25519');
for(const [name,key,type] of [['private.pem',pair.privateKey,'pkcs8'],['public.pem',pair.publicKey,'spki'],['wrong.pem',other.publicKey,'spki']])
  fs.writeFileSync(path.join(process.argv[1],name),key.export({type,format:'pem'}),{mode:0o600,flag:'wx'});
console.log(JSON.stringify({created:true}));""", "--", str(work)])
        require(created["created"] is True, "independent approval keys were not created")
        attester = ROOT / "scripts/attest_git_bundle.mjs"
        envelope, key, public = work / "approval.dsse.json", work / "private.pem", work / "public.pem"
        floor = "9007199254740993"
        signing = list(map(str, ["sign", bundle, envelope, "--key", key, "--repository", "fixture/native-source", "--sequence", floor]))
        key.chmod(0o644)
        refused = c.node_command(attester, signing, 1, error_reply=True)
        require(refused["code"] == "unsafe_attestation_private_key_permissions" and not envelope.exists(),
                "insecure signing key was accepted")
        key.chmod(0o600)
        signed = c.node_command(attester, signing)
        signed_bytes = envelope.read_bytes()
        signed_inode = envelope.stat().st_ino
        require(signed["statement"]["sequence"] == floor and signed["statement"]["artifact"]["sha256"] == digest
                and signed["object_closure_verified"] is False, "detached approval changed artifact identity or claimed Git validation")
        c.node_command(attester, signing, 1, error_reply=True)
        checking = list(map(str, ["check", bundle, envelope, "--trust-key", public,
            "--repository", "fixture/native-source", "--minimum-sequence", floor]))
        read_only = c.node_command(attester, checking)
        require(read_only["signature_verified"] is True and "copy" not in read_only
                and authority(donor) == source_before, "read-only approval check mutated source or published a copy")
        wrong = checking.copy()
        wrong[wrong.index("--trust-key") + 1] = str(work / "wrong.pem")
        c.node_command(attester, wrong, 1, error_reply=True)
        wrong = checking.copy()
        wrong[-1] = str(int(floor) + 1)
        refused = c.node_command(attester, wrong, 1, error_reply=True)
        require(refused["code"] == "attestation_below_sequence_floor", "stale external approval floor was ignored")
        authenticated = work / "authenticated.bundle"
        approved = c.node_command(attester, [*checking, "--copy-to", str(authenticated)])
        require(approved["signature_verified"] is True and approved["minimum_sequence"] == floor
                and approved["copy"]["state"] == "complete" and authenticated.read_bytes() == raw
                and envelope.read_bytes() == signed_bytes and envelope.stat().st_ino == signed_inode,
                "authenticated source copy lost exact approved bytes or replaced the original approval")
        copy_inode = authenticated.stat().st_ino
        c.node_command(attester, [*checking, "--copy-to", str(authenticated)], 1, error_reply=True)
        require(authenticated.read_bytes() == raw and authenticated.stat().st_ino == copy_inode,
                "occupied authenticated copy was overwritten")
        native = c.node_command(ROOT / "scripts/verify_git_bundle_native.mjs", list(map(str, [authenticated,
            "--fg", c.fg, "--expect-sha256", digest, "--expect-format", fmt, "--expect-ref", REF + "=" + base, "--exact-refs"])))
        require(native["object_graph_verified"] is True and native["artifact_sha256"] == digest,
                "authenticated copy did not enter actual native Git verification")
        c.facts[f"{fmt}_detached_attestation_native_source"] = True

        scope = {"tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": target_incarnation,
            "principal_id": PRINCIPAL, "object_format": fmt}
        selection = private("destination.json", {"endpoint": target_server.url, "scope": scope, "operation": "import"})
        prepare = ["prepare", "--workdir", work / "import-job", "--selection", selection,
            "--token-file", target_token, "--bundle-file", authenticated, "--bundle-confirm", digest]
        wrong = prepare.copy()
        wrong[wrong.index("--workdir") + 1] = work / "wrong-pin-job"
        wrong[-1] = "0" * 64
        remote(wrong, 2, True)
        require(not (work / "wrong-pin-job").exists() and authority(destination) == destination_before,
                "bad bundle pin created custody or canonical state")
        request = remote(prepare)
        intent = Path(request["workdir"]) / "intent.json"
        intent_bytes = intent.read_bytes()
        inspected = remote(job("inspect", request))
        require(request["state"] == "ready" and request["mutation_submitted"] is False
                and inspected["payload_verified"] is True and authority(destination) == destination_before,
                "remote preparation or inspection published source")
        remote([*job("run", request), "--token-file", wrong_token], 4, True)
        require(intent.read_bytes() == intent_bytes and remote(job("status", request))["attempts"] == 0,
                "changed credential dispatched the prepared request")

        # Test-only HTTP observation: actual request/response sockets and native
        # admission stay real. Truncate the first import reply after its headers;
        # record only method/path/key hash, never Authorization or payload bytes.
        hook = private("lose-import-reply.mjs", """import http from 'node:http';
import {appendFileSync,existsSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {syncBuiltinESMExports} from 'node:module';
const request=http.request,log=new URL('./http-requests.jsonl',import.meta.url),lost=new URL('./lost-reply.json',import.meta.url);
http.request=function(...args){
 const req=Reflect.apply(request,this,args),url=args[0],key=req.getHeader('Idempotency-Key');
 appendFileSync(log,JSON.stringify({method:req.method,path:url.pathname,key_sha256:key?createHash('sha256').update(key).digest('hex'):null})+'\\n',{mode:0o600});
 if(req.method==='POST'&&url.pathname.endsWith('/source/bundle/import')&&!existsSync(lost))
  req.prependOnceListener('response',res=>{writeFileSync(lost,JSON.stringify({status:res.statusCode}),{mode:0o600,flag:'wx'});res.destroy(new Error('planted reply truncation'));});
 return req;
};
syncBuiltinESMExports();
""")
        uncertain = remote([*job("run", request), "--token-file", target_token], 3, hook=hook)
        require(uncertain["complete"] is False and uncertain["mutation_submitted"] is True
                and uncertain["state"] == "unresolved" and uncertain["observation"]["publication"] is None,
                "lost reply was presented as a confirmed publication")
        canonical(destination)
        before = authority(destination)
        (Path(request["workdir"]) / "repository.bundle").rename(work / "retained-import.bundle")
        recovered = remote([*job("recover", request), "--token-file", target_token], hook=hook)
        require(recovered["complete"] is True and recovered["state"] == "committed"
                and recovered["mutation_submitted"] is False and recovered["key"] == request["key"]
                and recovered["payload_present"] is False and recovered["attempts"] == 2
                and intent.read_bytes() == intent_bytes and authority(destination) == before,
                "original-key recovery read lost payload, resubmitted or changed native authority")
        calls = [json.loads(line) for line in (work / "http-requests.jsonl").read_text().splitlines()]
        uploads = [row for row in calls if row["path"].endswith("/source/bundle/import")]
        lookups = [row for row in calls if row["path"].endswith("/api/v1/outcomes")]
        require(len(calls) == 3 and len(uploads) == 1 and len(lookups) == 2
                and all(row["method"] == "POST" and row["key_sha256"] == sha256(request["key"].encode()).hexdigest() for row in calls)
                and json.loads((work / "lost-reply.json").read_text())["status"] == 200,
                "native recovery repeated upload or lost the original request identity")
        c.facts[f"{fmt}_remote_bundle_native_import_recovery"] = True

        mapped = b"refs/remotes/operator/main"
        def fetch(name, old, reference=mapped):
            selected = private(name + ".json", {"endpoint": target_server.url, "scope": scope, "operation": "fetch",
                "mappings": [{"source_hex": REF.encode().hex(), "destination_hex": reference.hex(), "expected_old": old}]})
            return remote(["prepare", "--workdir", work / name, "--selection", selected,
                "--token-file", target_token, "--bundle-file", authenticated, "--bundle-confirm", digest])
        fetched = fetch("fetch-job", "absent")
        done = remote([*job("run", fetched), "--token-file", target_token])
        expected_refs = {REF.encode(): base, mapped: base}
        require(done["complete"] is True and done["mutation_submitted"] is True, "mapped absent-lease fetch did not commit")
        canonical(destination, expected_refs)
        unavailable = fetch("unavailable-fetch-job", "f" * len(base))
        blocked = remote([*job("run", unavailable), "--token-file", target_token], 3, hook=hook)
        require(blocked["state"] == "unresolved" and blocked["observation"]["publication"] is None
                and blocked["observation"]["outcome"]["terminal"] is False,
                "pre-admission ancestry refusal was promoted to a canonical decision")
        before = authority(destination)
        (Path(unavailable["workdir"]) / "repository.bundle").rename(work / "retained-unavailable.bundle")
        pending = remote([*job("recover", unavailable), "--token-file", target_token], 3, hook=hook)
        require(pending["state"] == "unresolved" and pending["mutation_submitted"] is False
                and pending["observation"]["outcome"]["absence_proves_non_commit"] is False
                and authority(destination) == before, "nonterminal recovery resubmitted or claimed noncommit")
        calls = [json.loads(line) for line in (work / "http-requests.jsonl").read_text().splitlines()]
        original_calls = [row for row in calls if row["key_sha256"] == sha256(unavailable["key"].encode()).hexdigest()]
        require(len(original_calls) == 3
                and sum(row["path"].endswith("/source/bundle/fetch") for row in original_calls) == 1
                and sum(row["path"].endswith("/api/v1/outcomes") for row in original_calls) == 2,
                "unresolved mapped fetch repeated its upload during recovery")
        exact = fetch("exact-fetch-job", base)
        require(remote([*job("run", exact), "--token-file", target_token])["complete"] is True,
                "the available current-lease twin was refused")
        canonical(destination, expected_refs)
        twin = b"refs/remotes/operator/lease-twin"
        stale = fetch("stale-fetch-job", base, twin)
        refused = remote([*job("run", stale), "--token-file", target_token], 1)
        require(refused["state"] == "refused" and refused["observation"]["outcome"]["terminal"] is True,
                "stale mapping lease was not a canonical refusal")
        canonical(destination, expected_refs)
        current = fetch("current-fetch-job", "absent", twin)
        require(remote([*job("run", current), "--token-file", target_token])["complete"] is True,
                "the current-lease twin was refused")
        expected_refs[twin] = base
        canonical(destination, expected_refs)
        before = authority(destination)

    target_token.rename(work / "retained-writer.token")
    (Path(stale["workdir"]) / "repository.bundle").rename(work / "retained-stale.bundle")
    journal_bytes = (work / "http-requests.jsonl").read_bytes()
    for operation in ("status", "recover", "run"):
        cached = remote(job(operation, request), hook=hook)
        require(cached["complete"] is True and cached["key"] == request["key"]
                and cached["network_accessed"] is False and authority(destination) == before,
                "cached remote import needed a stopped server, credential or lost payload")
    refused = remote(job("run", stale), 1, hook=hook)
    require(refused["state"] == "refused" and refused["mutation_submitted"] is False
            and refused["network_accessed"] is False and (work / "http-requests.jsonl").read_bytes() == journal_bytes,
            "terminal refusal was retried or cached recovery performed network work")
    c.facts[f"{fmt}_remote_bundle_native_fetch_leases"] = True
