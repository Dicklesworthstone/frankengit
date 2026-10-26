import contextlib, hashlib, http.client, json, os, pathlib, secrets, shutil, signal, struct, subprocess, sys, time, urllib.parse, zlib

fg, root = sys.argv[1], pathlib.Path(sys.argv[2])
root.chmod(0o700)
tenant, repository, incarnation, principal = '1' * 32, '2' * 32, '3' * 32, '4' * 32
commands = 0
cases = []
operator_calls = []
repo = pathlib.Path(__file__).resolve().parents[3]
node_bin = os.environ.get('NODE_BIN') or shutil.which('node')
assert node_bin, 'artifact operator coverage requires NODE_BIN or node on PATH'
node_version = subprocess.run([node_bin, '--version'], capture_output=True, timeout=10)
(root / 'node-version.out').write_bytes(node_version.stdout)
(root / 'node-version.err').write_bytes(node_version.stderr)
expected_node = 'v' + (repo / 'tests/node-version').read_text().strip()
if node_version.returncode != 0 or node_version.stdout.decode(errors='replace').strip() != expected_node:
    print(json.dumps({'type': 'artifact_operator_runtime_refusal', 'code': 'node_version_mismatch',
                      'expected': expected_node, 'native_commands_started': 0}), file=sys.stderr)
    sys.exit(3)
store = root / 'artifacts'
store.mkdir(mode=0o700)

def run(label, args, expected=0):
    global commands
    commands += 1
    result = subprocess.run([fg, '--timeout-secs', '120', *map(str, args)], capture_output=True, timeout=180)
    (root / f'{commands:03d}-{label}.out').write_bytes(result.stdout)
    (root / f'{commands:03d}-{label}.err').write_bytes(result.stderr)
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        sys.stderr.buffer.flush()
    assert result.returncode == expected, (label, result.returncode, expected, result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace'))
    return result.stdout

def scope(trust='trusted-ci', inc=incarnation):
    return [store, tenant, repository, inc, '--trusted-local', '--trust-domain', trust]

def identity(data, kind, media, retention, provenance=(None, None, None)):
    encoded = b'frankengit/artifact-identity/v1\0' + hashlib.sha256(data).digest()
    encoded += struct.pack('>QB', len(data), kind) + struct.pack('>I', len(media.encode())) + media.encode()
    encoded += b''.join(b'\0' if value is None else b'\1' + bytes.fromhex(value) for value in provenance)
    encoded += struct.pack('>I', len(retention)) + retention
    return hashlib.sha256(encoded).hexdigest()

def scope_id(trust='trusted-ci', inc=incarnation):
    encoded = b'frankengit/artifact-scope/v1\0' + bytes.fromhex(tenant + repository + inc)
    encoded += struct.pack('>H', len(trust.encode())) + trust.encode()
    return hashlib.sha256(encoded).hexdigest()

kinds = ['ci_artifact', 'build_log', 'release_asset', 'sbom', 'signature', 'provenance', 'git_lfs']
def put_args(source, data, kind='ci_artifact', retention_flags=(), retention=b'\1' + struct.pack('>Q', 86400), trust='trusted-ci', inc=incarnation, provenance=(None, None, None), maximum=64):
    artifact_id = identity(data, kinds.index(kind) + 1, 'application/octet-stream', retention, provenance)
    args = ['artifact', 'put', *scope(trust, inc), '--max-payload-mib', str(maximum), '--source', source,
            '--payload-sha256', hashlib.sha256(data).hexdigest(), '--payload-bytes', str(len(data)), '--kind', kind,
            '--media-type', 'application/octet-stream', '--expected-id', artifact_id, *retention_flags]
    for flag, value in zip(['--build-capsule', '--check-receipt', '--source-rcr'], provenance):
        if value is not None:
            args += [flag, value]
    return artifact_id, args

def validate(receipt, artifact_id, data, trust='trusted-ci', inc=incarnation):
    assert receipt['artifact_id'] == artifact_id
    assert receipt['scope_sha256'] == scope_id(trust, inc)
    assert receipt['payload_sha256'] == hashlib.sha256(data).hexdigest()
    assert receipt['payload_bytes'] == len(data) and receipt['payload_verified']
    assert receipt['tenant_id'] == tenant and receipt['repository_id'] == repository and receipt['repository_incarnation_id'] == inc
    assert receipt['trust_domain'] == trust and receipt['trusted_local']
    assert not receipt['provenance_authenticated'] and not receipt['canonical_repository_published']
    assert not receipt['refs_changed'] and not receipt['retention_enforced']

profiles = [([], b'\1' + struct.pack('>Q', 86400)),
            (['--retain-days', '4294967295'], b'\2' + struct.pack('>I', 4294967295)),
            (['--release-permanent'], b'\3'),
            (['--legal-hold-id', '18446744073709551615', '--legal-hold-reason', 'Original β\nrecord'],
             b'\4' + struct.pack('>QI', 18446744073709551615, len('Original β\nrecord'.encode())) + 'Original β\nrecord'.encode())]
source = root / 'binary-input'
data = bytes(range(256)) * 257
source.write_bytes(data)
ids = set()
for index, kind in enumerate(kinds):
    flags, retention = profiles[index % len(profiles)]
    provenance = ('a' * 64, 'b' * 64, 'c' * 64) if kind == 'provenance' else (None, None, None)
    artifact_id, args = put_args(source, data, kind, flags, retention, provenance=provenance)
    first = json.loads(run(kind + '-put', args)); validate(first, artifact_id, data)
    assert first['retention_canonical_hex'] == retention.hex() and first['disposition'] == 'created'
    assert artifact_id not in ids; ids.add(artifact_id)
    stored = store / ('scope-' + first['scope_sha256']) / artifact_id
    original = stored.read_bytes()
    second = json.loads(run(kind + '-retry', args)); validate(second, artifact_id, data)
    assert second['disposition'] == 'already_present' and stored.read_bytes() == original
    inspected = json.loads(run(kind + '-inspect', ['artifact', 'inspect', *scope(), '--id', artifact_id]))
    validate(inspected, artifact_id, data)
    output = root / (kind + '-export')
    exported = json.loads(run(kind + '-export', ['artifact', 'export', *scope(), '--id', artifact_id, '--output', output]))
    validate(exported, artifact_id, data); assert output.read_bytes() == data
    run(kind + '-no-overwrite', ['artifact', 'export', *scope(), '--id', artifact_id, '--output', output], 2)
    assert output.read_bytes() == data
cases.append({'all_payload_kinds': len(kinds), 'retention_profiles': len(profiles), 'independent_identity_oracle': True})

empty = root / 'empty'; empty.write_bytes(b'')
empty_id, empty_args = put_args(empty, b'')
validate(json.loads(run('empty-put', empty_args)), empty_id, b'')
empty.unlink()
validate(json.loads(run('empty-source-free-inspect', ['artifact', 'inspect', *scope(), '--id', empty_id])), empty_id, b'')

# Exact operation ceilings must also govern inspect/export, not just upload.
boundary = root / 'boundary'; exact = b'B' * (1024 * 1024); boundary.write_bytes(exact)
exact_id, exact_args = put_args(boundary, exact, maximum=1)
validate(json.loads(run('exact-byte-boundary', exact_args)), exact_id, exact)
over = exact + b'X'; boundary.write_bytes(over)
over_id, over_args = put_args(boundary, over, maximum=1)
run('over-byte-boundary', over_args, 2)
over_id, over_args = put_args(boundary, over, maximum=2)
validate(json.loads(run('larger-explicit-ceiling', over_args)), over_id, over)
run('inspect-byte-boundary', ['artifact', 'inspect', *scope(), '--id', over_id, '--max-payload-mib', '1'], 2)
run('export-byte-boundary', ['artifact', 'export', *scope(), '--id', over_id, '--max-payload-mib', '1', '--output', root / 'not-created'], 2)
assert not (root / 'not-created').exists()

# Wrong domains and copied metadata must not gain an independent namespace.
for field in [1, 2, 3]:
    other = scope(); other[field] = '9' * 32
    run('foreign-scope-' + str(field), ['artifact', 'inspect', *other, '--id', exact_id], 2)
run('foreign-trust', ['artifact', 'inspect', *scope('other'), '--id', exact_id], 2)
boundary.write_bytes(exact)
_, other_args = put_args(boundary, exact, maximum=1, trust='other')
other_receipt = json.loads(run('valid-other-trust', other_args)); validate(other_receipt, exact_id, exact, trust='other')
original_path = store / ('scope-' + scope_id()) / exact_id
copied_path = store / ('scope-' + scope_id('other')) / exact_id
copied_path.write_bytes(original_path.read_bytes())
run('copied-foreign-namespace', ['artifact', 'export', *scope('other'), '--id', exact_id, '--output', root / 'foreign-output'], 2)
assert not (root / 'foreign-output').exists()
original = original_path.read_bytes(); original_path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
run('corrupt-inspect', ['artifact', 'inspect', *scope(), '--id', exact_id], 2)
run('corrupt-export', ['artifact', 'export', *scope(), '--id', exact_id, '--output', root / 'corrupt-output'], 2)
run('corrupt-collision-not-overwritten', exact_args, 2)
assert not (root / 'corrupt-output').exists() and original_path.read_bytes() != original

# A pipe failure is not permission to lose or reproduce a successful artifact.
source.write_bytes(b'output failure keeps artifact')
lost_data = source.read_bytes(); lost_id, lost_args = put_args(source, lost_data)
read_fd, write_fd = os.pipe(); os.close(read_fd)
try:
    commands += 1
    lost = subprocess.run([fg, *map(str, lost_args)], stdout=write_fd, stderr=subprocess.PIPE, timeout=30)
finally:
    os.close(write_fd)
(root / 'output-failure.err').write_bytes(lost.stderr)
assert lost.returncode == 4, lost.stderr
retained = json.loads(lost.stderr)['retained_result']; validate(retained, lost_id, lost_data)
validate(json.loads(run('recover-after-lost-receipt', ['artifact', 'inspect', *scope(), '--id', lost_id])), lost_id, lost_data)

# Concurrency selects one immutable object; neither exact contender overwrites it.
source.write_bytes(b'concurrent retained body'); concurrent_data = source.read_bytes()
concurrent_id, concurrent_args = put_args(source, concurrent_data)
commands += 2
children = [subprocess.Popen([fg, *map(str, concurrent_args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
results = []
for child in children:
    stdout, stderr = child.communicate(timeout=30)
    assert child.returncode == 0, stderr
    result = json.loads(stdout); validate(result, concurrent_id, concurrent_data); results.append(result['disposition'])
assert sorted(results) == ['already_present', 'created']
cases.append({'boundary_and_scope_refusals': True, 'corruption_never_disclosed': True, 'output_loss_recovered': True, 'concurrent_exact_retry': True})

# Signal only this operation's own child after it has acquired its private stage.
large = root / 'cancellation-input'; large_data = b'C' * (64 * 1024 * 1024); large.write_bytes(large_data)
large_id, large_args = put_args(large, large_data)
commands += 1
child = subprocess.Popen([fg, *map(str, large_args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
end = time.monotonic() + 15
while child.poll() is None and time.monotonic() < end:
    stages = list(store.glob(f'scope-*/.fg-artifact-{child.pid}-*'))
    if any(path.stat().st_size > 65536 for path in stages):
        child.send_signal(signal.SIGTERM)
        break
    time.sleep(0.002)
stdout, stderr = child.communicate(timeout=30)
(root / 'cancel.out').write_bytes(stdout); (root / 'cancel.err').write_bytes(stderr)
assert child.returncode == 2 and b'Cancelled' in stderr, (child.returncode, stdout, stderr)
assert not (store / ('scope-' + scope_id()) / large_id).exists()
assert not list(store.glob('scope-*/.fg-artifact-*'))
cases.append({'sigterm_cancellation': True, 'unverified_stages_removed': True})
large.unlink(); del large_data

def native_object(source, fmt, kind, body):
    raw = kind.encode() + b' ' + str(len(body)).encode() + b'\0' + body
    oid = hashlib.new(fmt, raw).hexdigest(); path = source / 'objects' / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(zlib.compress(raw)); return oid

def native_tree(source, fmt, files):
    entries = {}
    for name, value in files.items():
        first, separator, rest = name.partition('/')
        if separator: entries.setdefault(first, {})[rest] = value
        else: entries[first] = value
    body = b''
    for name, value in sorted(entries.items(), key=lambda item: item[0] + ('/' if isinstance(item[1], dict) else '')):
        directory = isinstance(value, dict)
        oid = native_tree(source, fmt, value) if directory else native_object(source, fmt, 'blob', value)
        body += (b'40000' if directory else b'100644') + b' ' + name.encode() + b'\0' + bytes.fromhex(oid)
    return native_object(source, fmt, 'tree', body)

def private_replace(path, body):
    temporary = path.with_name(path.name + '.next')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def artifact_grants(path, inc, tokens, reader_scope='artifact-read'):
    body = f'frankengit-http-credentials-v1 {tenant} {repository} {inc}\n'
    for token, scopes in [(tokens['artifact'], reader_scope), (tokens['git'], 'read,lfs-read')]:
        if scopes is not None:
            body += f'{hashlib.sha256(token.encode()).hexdigest()} {principal} {scopes}\n'
    private_replace(path, body)


def listener_records(path):
    records = []
    for line in path.read_text().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


@contextlib.contextmanager
def artifact_server(node, inc, grants, label):
    global commands
    stop = root / (label + '.stop')
    stdout_path, stderr_path = root / (label + '.out'), root / (label + '.err')
    arguments = [fg, 'serve-http', str(node), tenant, repository, '127.0.0.1:0',
                 '--trusted-local', '--credentials-file', str(grants),
                 '--artifact-root', str(store), '--expected-incarnation', inc,
                 '--continuous', '--stop-file', str(stop), '--max-in-flight', '2',
                 '--session-timeout-secs', '30']
    commands += 1
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        try:
            until = time.monotonic() + 45
            ready = []
            while time.monotonic() < until:
                ready = [r for r in listener_records(stdout_path) if r.get('type') == 'smart_http_listening']
                if ready:
                    break
                assert child.poll() is None, (label, 'listener exited before readiness', stderr_path.read_text()[-8000:])
                time.sleep(0.02)
            assert len(ready) == 1, (label, 'missing or repeated readiness')
            selected = ready[0]
            assert selected['artifacts_enabled'] and selected['credential_mode'] == 'reloadable'
            assert selected['repository_incarnation'] == inc and selected['lifetime'] == 'continuous'
            assert not any(selected[name] for name in ['receive_enabled', 'issues_enabled', 'outcomes_enabled',
                                                       'pulls_enabled', 'source_enabled', 'protection_enabled', 'lfs_enabled'])
            url = urllib.parse.urlsplit(selected['url'])
            assert url.scheme == 'http' and url.hostname == '127.0.0.1' and url.port
            assert not url.username and not url.password and not url.query and not url.fragment
            assert url.path.endswith('/' + repository + '.git')
            yield selected['url']
            private_replace(stop, 'artifact read campaign complete; drain accepted requests\n')
            child.wait(timeout=45)
            assert child.returncode == 0, (label, 'listener drain failed', stderr_path.read_text()[-8000:])
            receipts = [r for r in listener_records(stdout_path) if r.get('type') == 'smart_http_drained']
            assert len(receipts) == 1, (label, 'missing native drain receipt')
            receipt = receipts[0]
            assert receipt['accepted'] == receipt['completed_transports'] + receipt['refused_transports']
            assert receipt['accepted'] > 0 and stop.is_file()
        finally:
            if child.poll() is None:
                # Failed assertions never become a successful drain. Stop only
                # this explicitly owned child, retaining its logs for diagnosis.
                if not stop.exists():
                    private_replace(stop, 'artifact read failure cleanup\n')
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)


def artifact_http(url, suffix, token, expected=200, *, method='GET', extra=None):
    endpoint = urllib.parse.urlsplit(url)
    assert endpoint.scheme == 'http' and endpoint.hostname == '127.0.0.1'
    headers = {'Connection': 'close', 'User-Agent': 'frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    headers.update(extra or {})
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=30)
    try:
        connection.request(method, endpoint.path + suffix, headers=headers)
        response = connection.getresponse()
        body = response.read(2 * 1024 * 1024 + 1)
        assert len(body) <= 2 * 1024 * 1024, 'artifact reply exceeded campaign bound'
        assert response.status == expected, (suffix, response.status, expected, body[:1000])
        fields = dict(response.getheaders())
        fields = {name.lower(): value for name, value in fields.items()}
        assert int(fields['content-length']) == len(body)
        if suffix.startswith('/api/v1/artifacts/'):
            assert fields['cache-control'] == 'no-store' and fields['vary'] == 'Authorization'
            assert fields['x-content-type-options'] == 'nosniff'
            if expected != 200:
                refusal = json.loads(body)
                assert refusal['type'] == 'artifact_error' and refusal['read_only']
                assert refusal['outcome_unknown'] is False and 'content_hex' not in refusal
        return fields, body
    finally:
        connection.close()


def verify_artifact_metadata(body, artifact_id, payload, inc, kind):
    value = json.loads(body)
    assert value['type'] == 'artifact_metadata' and value['schema_version'] == 1
    assert value['artifact_id'] == artifact_id and value['kind'] == kind
    assert value['payload_bytes'] == len(payload) and value['payload_sha256'] == hashlib.sha256(payload).hexdigest()
    assert value['tenant_id'] == tenant and value['repository_id'] == repository
    assert value['repository_incarnation_id'] == inc and value['trust_domain'] == 'trusted-workflow-local-owner'
    assert value['scope_sha256'] == scope_id('trusted-workflow-local-owner', inc)
    assert value['payload_verified'] and value['read_only']
    assert not value['provenance_authenticated'] and not value['canonical_repository_published'] and not value['retention_enforced']
    assert 'root' not in value and 'run_directory_hex' not in value
    return value


def operator_download(label, url, inc, token, receipt, output, payload, expected=0):
    # This is the real production operator over the owned native HTTP listener,
    # with the native producing job's unchanged create-only receipt.
    config_path, token_path = root / (label + '.input.json'), root / (label + '.token')
    destination = root / (label + '.payload')
    private_replace(config_path, json.dumps({
        'endpoint': url.rstrip('/'),
        'scope': {'tenant_id': tenant, 'repository_id': repository,
                  'repository_incarnation_id': inc, 'trust_domain': 'trusted-workflow-local-owner'},
        'job_id_hex': b'build'.hex(), 'path_hex': output['path_hex'],
    }))
    private_replace(token_path, token)
    result = subprocess.run([node_bin, str(repo / 'scripts/fg_workflow_watch.mjs'), 'artifact-download',
                             '--input', str(config_path), '--receipt', str(receipt),
                             '--token-file', str(token_path), '--output', str(destination),
                             '--timeout-ms', '10000'], capture_output=True, timeout=20)
    (root / (label + '.out')).write_bytes(result.stdout)
    (root / (label + '.err')).write_bytes(result.stderr)
    assert result.returncode == expected, (label, result.returncode, expected, result.stderr.decode(errors='replace'))
    assert token.encode() not in result.stdout + result.stderr
    operator_calls.append({'label': label, 'exit': result.returncode,
                           'stdout_sha256': hashlib.sha256(result.stdout).hexdigest(),
                           'stderr_sha256': hashlib.sha256(result.stderr).hexdigest()})
    if expected == 0:
        value = json.loads(result.stdout)
        assert value['type'] == 'workflow_artifact_download'
        assert value['artifact_id'] == output['artifact_id_sha256']
        assert value['payload_sha256'] == hashlib.sha256(payload).hexdigest()
        assert value['payload_bytes'] == len(payload) and value['payload_sha256_verified']
        assert not value['artifact_identity_independently_verified']
        assert not value['provenance_authenticated'] and not value['canonical_repository_published']
        assert not value['job_success_asserted'] and not value['execution_performed'] and not value['executable_mode_applied']
        assert destination.read_bytes() == payload and destination.stat().st_mode & 0o777 == 0o600
    else:
        value = json.loads(result.stderr)
        assert value['type'] == 'workflow_artifact_download_error'
        assert not destination.exists(), 'refused operator download exposed a destination'


def retrieve_workflow_artifacts(fmt, node, inc, report, directory, expected_payload):
    assert len(report['artifacts']) == 1
    captured = report['artifacts'][0]
    assert captured['job_id_hex'] == b'build'.hex() and len(captured['outputs']) == 1
    output = captured['outputs'][0]
    assert output['path_hex'] == b'dist/result'.hex() and output['payload_bytes'] == len(expected_payload)
    assert output['payload_sha256'] == hashlib.sha256(expected_payload).hexdigest()
    output_id, manifest_id = output['artifact_id_sha256'], captured['manifest_id_sha256']
    saved_bytes = (directory / 'job-000-artifacts.json').read_bytes()
    saved = json.loads(saved_bytes)
    assert saved['type'] == 'trusted_workflow_artifact_receipt' and saved['manifest_id_sha256'] == manifest_id
    prefix = ('{"type":"trusted_workflow_artifact_receipt","manifest_id_sha256":"' + manifest_id + '","manifest":').encode()
    assert saved_bytes.startswith(prefix) and saved_bytes.endswith(b'}')
    expected_manifest = saved_bytes[len(prefix):-1]
    assert json.loads(expected_manifest) == saved['manifest']
    tokens = {'artifact': secrets.token_hex(32), 'git': secrets.token_hex(32)}
    grants = root / (fmt + '-artifact-http-grants')
    artifact_grants(grants, inc, tokens)
    output_route = '/api/v1/artifacts/' + output_id
    manifest_route = '/api/v1/artifacts/' + manifest_id
    original_metadata = {}
    with artifact_server(node, inc, grants, fmt + '-artifact-http') as url:
        receipt_path = directory / 'job-000-artifacts.json'
        operator_download(fmt + '-operator-download', url, inc, tokens['artifact'], receipt_path, output, expected_payload)
        other_inc = ('f' if inc[0] != 'f' else 'e') + inc[1:]
        operator_download(fmt + '-operator-wrong-scope', url, other_inc, tokens['artifact'], receipt_path, output, expected_payload, 2)
        for artifact_id, route, payload, kind in [(output_id, output_route, expected_payload, 'ci_artifact'),
                                                (manifest_id, manifest_route, expected_manifest, 'provenance')]:
            fields, metadata = artifact_http(url, route, tokens['artifact'])
            assert fields['content-type'].startswith('application/json')
            original_metadata[artifact_id] = verify_artifact_metadata(metadata, artifact_id, payload, inc, kind)
            fields, content = artifact_http(url, route + '/content', tokens['artifact'])
            assert content == payload
            assert fields['content-type'] == 'application/octet-stream'
            assert fields['content-disposition'] == f'attachment; filename="artifact-{artifact_id}"'
            (root / (fmt + '-http-' + kind + '.metadata.json')).write_bytes(metadata)
            (root / (fmt + '-http-' + kind + '.payload')).write_bytes(content)
        for token, status in [(None, 401), (secrets.token_hex(32), 401), (tokens['git'], 403)]:
            _, body = artifact_http(url, output_route + '/content', token, status)
            assert expected_payload not in body
        artifact_http(url, '/info/refs?service=git-upload-pack', tokens['artifact'], 403)
        artifact_http(url, output_route + '?trust=trusted-ci', tokens['artifact'], 400)
        artifact_http(url, output_route, tokens['artifact'], 405, method='POST')
        artifact_http(url, output_route, tokens['artifact'], 400, extra={'Idempotency-Key': 'read-only'})
        artifact_grants(grants, inc, tokens, None)
        artifact_http(url, output_route + '/content', tokens['artifact'], 401)
        operator_download(fmt + '-operator-revoked', url, inc, tokens['artifact'], receipt_path, output, expected_payload, 2)
        artifact_grants(grants, inc, tokens, 'read')
        artifact_http(url, output_route + '/content', tokens['artifact'], 403)
        artifact_grants(grants, inc, tokens)
        assert artifact_http(url, output_route + '/content', tokens['artifact'])[1] == expected_payload
        stored = store / ('scope-' + scope_id('trusted-workflow-local-owner', inc)) / output_id
        original = stored.read_bytes()
        try:
            stored.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            for suffix in [output_route, output_route + '/content']:
                _, body = artifact_http(url, suffix, tokens['artifact'], 503)
                assert expected_payload not in body and json.loads(body)['code'] == 'artifact_storage_unavailable'
            operator_download(fmt + '-operator-corrupt', url, inc, tokens['artifact'], receipt_path, output, expected_payload, 2)
        finally:
            stored.write_bytes(original)
        assert artifact_http(url, output_route + '/content', tokens['artifact'])[1] == expected_payload
        operator_download(fmt + '-operator-restored', url, inc, tokens['artifact'], receipt_path, output, expected_payload)
        assert (directory / 'job-000-artifacts.json').read_bytes() == saved_bytes
    with artifact_server(node, inc, grants, fmt + '-artifact-http-reopened') as url:
        for artifact_id, route, payload in [(output_id, output_route, expected_payload),
                                            (manifest_id, manifest_route, expected_manifest)]:
            assert json.loads(artifact_http(url, route, tokens['artifact'])[1]) == original_metadata[artifact_id]
            assert artifact_http(url, route + '/content', tokens['artifact'])[1] == payload
    cases.append({'format': fmt, 'actual_workflow_output_and_manifest_downloaded': True,
                  'artifact_id': output_id, 'manifest_id': manifest_id,
                  'binary_bytes_match_producing_script': True, 'manifest_bytes_match_create_only_receipt': True,
                  'independent_scope_and_live_revocation': True, 'trailing_corruption_never_disclosed': True,
                  'verified_downloads_restored_after_corruption': True, 'http_reopen_preserves_exact_metadata_and_bytes': True})
    cases.append({'format': fmt, 'production_operator_downloaded_native_workflow_bytes': True,
                  'wrong_scope_revoked_and_corrupt_downloads_absent': True,
                  'saved_native_receipt_unchanged': True, 'operator_provenance_not_promoted': True})


for fmt in ['sha1', 'sha256']:
    src, node, parent = root / (fmt + '-source'), root / (fmt + '-node'), root / (fmt + '-runs')
    parent.mkdir(mode=0o700)
    expected_workflow_output = b'WORKFLOW-ARTIFACT\0\xff\n'
    workflow = b"name: archive evidence\non: workflow_dispatch\njobs:\n  build:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: mkdir -p dist; printf 'WORKFLOW-ARTIFACT\\000\\377\\n' > dist/result; printf VERIFIED-NATIVE-EVIDENCE\n"
    tree = native_tree(src, fmt, {'.github/workflows/archive.yml': workflow})
    tip = native_object(src, fmt, 'commit', f'tree {tree}\nauthor Fixture <f@example.invalid> 1 +0000\ncommitter Fixture <f@example.invalid> 1 +0000\n\nartifact source\n'.encode())
    (src / 'refs/heads').mkdir(parents=True); (src / 'refs/heads/main').write_text(tip + '\n'); (src / 'HEAD').write_text('ref: refs/heads/main\n')
    ns = [node, tenant, repository]
    run(fmt + '-init', ['init', *ns, fmt])
    imported = json.loads(run(fmt + '-import', ['import', *ns, principal, fmt + '-import', src, '--json']))
    assert imported['state'] == 'committed'; inc = imported['repository_incarnation_id']
    before = run(fmt + '-refs-before', ['refs', *ns, '--trusted-local', '--object-format', fmt])
    nonce = '5' * 32
    report = json.loads(run(fmt + '-workflow', ['workflow', 'run', *ns, 'refs/heads/main', '--trusted-local', '--workflow', '.github/workflows/archive.yml', '--run-parent', parent, '--run-id', nonce, '--input', '.github', '--object-format', fmt, '--artifact-root', store, '--artifact', '.github/workflows/archive.yml:build:dist/result']))['run']
    assert report['succeeded'] and report['workspaces_closed']
    directory = parent / ('workflow-' + nonce); marker = hashlib.sha256((directory / 'attempt.json').read_bytes()).hexdigest()
    history = json.loads(run(fmt + '-recover', ['workflow', 'recover', directory, tenant, repository, '--journal-id', marker]))
    batch, fact = next((entry, fact) for entry in history['entries'] for fact in entry['facts'] if fact['status'] == 'completed')
    evidence = root / (fmt + '-evidence')
    run(fmt + '-evidence-export', ['workflow', 'recover', directory, tenant, repository, '--journal-id', marker, '--batch', batch['batch_sha256'], '--evidence', fact['evidence_sha256'], '--output', evidence])
    payload = evidence.read_bytes(); assert hashlib.sha256(payload).hexdigest() == fact['evidence_sha256']
    rcr = report['source_rcr'].split('/')[-1]
    archive_id, archive_args = put_args(evidence, payload, 'provenance', ['--release-permanent'], b'\3', inc=inc, provenance=(None, None, rcr))
    archive = json.loads(run(fmt + '-archive-native-evidence', archive_args)); validate(archive, archive_id, payload, inc=inc)
    assert archive['source_rcr_sha256'] == rcr and archive['check_receipt_sha256'] is None
    retrieve_workflow_artifacts(fmt, node, inc, report, directory, expected_workflow_output)
    assert run(fmt + '-refs-after', ['refs', *ns, '--trusted-local', '--object-format', fmt]) == before
    for path in [src, node, parent, evidence]: path.rename(path.with_name(path.name + '-offline'))
    validate(json.loads(run(fmt + '-offline-artifact-inspect', ['artifact', 'inspect', *scope(inc=inc), '--id', archive_id])), archive_id, payload, inc=inc)
    restored = root / (fmt + '-restored-evidence')
    validate(json.loads(run(fmt + '-offline-artifact-export', ['artifact', 'export', *scope(inc=inc), '--id', archive_id, '--output', restored])), archive_id, payload, inc=inc)
    assert restored.read_bytes() == payload
    cases.append({'format': fmt, 'native_workflow_evidence_archived': True, 'artifact_id': archive_id, 'original_node_run_and_source_not_used_for_recovery': True, 'refs_unchanged': True})
(root / 'results.json').write_text(json.dumps({'native_commands': commands, 'operator_calls': operator_calls,
                                             'cases': cases, 'native_peers_are_fixtures': False}, indent=2) + '\n')
