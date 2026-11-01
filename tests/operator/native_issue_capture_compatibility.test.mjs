// Frozen by the actual production native-v1 importer before capture-v2 support.
// Extraction: Node 24.22.1; five TEST-ONLY deterministic nonces; no network calls.
// This is offline byte/retry-custody compatibility, not canonical publication evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import { mkdtemp, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { nativeCaptureBytes, parseNativeIssueCapture, nativeIssueImportSteps }
  from '../../scripts/lib/native-issue-source.mjs';
import { prepareNativeIssueImport, inspectPreparedNativeIssueImport }
  from '../../scripts/lib/native-issue-import.mjs';
import { recordDigest } from '../../scripts/lib/forge-operator-io.mjs';

const encode = value => Buffer.from(JSON.stringify(value) + '\n');
// V1 has no lock coordinate. Never regenerate these expected hashes with the
// candidate implementation, normalize this fixture to v2, or add locked:false.
const capture = {
  "schema": "frankengit-native-issue-capture-v1",
  "source": {
    "href": "https://fixture.invalid/source/ui/issues/",
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "snapshot_token": "alg:2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "source_head": "native-source-head/v1",
    "archive_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "issues": [
    {
      "number": 7,
      "id": "7",
      "snapshot": {
        "number": 7,
        "version": 6,
        "title": "Legacy issue é",
        "body": "Source body <script>\r\nno final newline",
        "labels": [
          "bug",
          "triage"
        ],
        "state": "closed",
        "opened_by": "33333333333333333333333333333333",
        "last_actor": "66666666666666666666666666666666",
        "comments": 2,
        "assignees": [
          "77777777777777777777777777777777",
          "88888888888888888888888888888888"
        ]
      },
      "comments": [
        {
          "version": 2,
          "actor": "33333333333333333333333333333333",
          "body": "First comment 雪\r\n"
        },
        {
          "version": 4,
          "actor": "66666666666666666666666666666666",
          "body": "Later comment with ~~~ and <script>"
        }
      ]
    },
    {
      "number": 19,
      "id": "19",
      "snapshot": {
        "number": 19,
        "version": 1,
        "title": "Still open",
        "body": "",
        "labels": [],
        "state": "open",
        "opened_by": "33333333333333333333333333333333",
        "last_actor": "33333333333333333333333333333333",
        "comments": 0,
        "assignees": []
      },
      "comments": []
    }
  ]
};
const golden = {
  "capture_sha256": "314c832e110403d16527e17e1df69eb05bae60c79016361e9c68fee4f5095827",
  "capture_bytes": 1259,
  "steps_sha256": "a49a56fede8baa3c5c6ebbf9c85b84d4e7e45d1b9e36966b12f87642895b8e31",
  "steps_bytes": 3865,
  "plan_sha256": "725b1b2b574dbe74f39af4162b54eeee96f7a582097c7849d41ef9247410a880",
  "hashes": {
    "capture.json": "314c832e110403d16527e17e1df69eb05bae60c79016361e9c68fee4f5095827",
    "manifest.json": "725b1b2b574dbe74f39af4162b54eeee96f7a582097c7849d41ef9247410a880",
    "step-000000.request.json": "e9e1722dba20576ae52723495e923942c7f1f1adb44ce01e544fad3b2a403f5c",
    "step-000001.request.json": "0b37109c59f62a0947da6c74c5fcb4b3f09e013bbb4acdb2095d732514bc824e",
    "step-000002.request.json": "fcc8d4afd3a52c3ffd4f0646866f88fbf9582da2df0fb2c8859d454157e1d50c",
    "step-000003.request.json": "f4dcf6cf7ccb495e2c5add7fb53fdac24d1c00234eb74764b13f74f2b4279cc3",
    "step-000004.request.json": "4783d53576245406e2c55cbed62b7e50691a7609ebf4f2f188d4390127e7106e"
  },
  "requests": [
    {
      "name": "step-000000.request.json",
      "number": 47,
      "expected_version": 0,
      "action": "open",
      "key": "fgui-01010101010101010101010101010101-5831e40aedcdbf9a635d7afa0cb93f327a2167f64a03c12ba75b3316bd771d3b",
      "body_sha256": "eadfd23122b43dc5a4f0b194bea989caa5f1ffac6214e2faf68638af5c62518b"
    },
    {
      "name": "step-000001.request.json",
      "number": 47,
      "expected_version": 1,
      "action": "comment",
      "key": "fgui-02020202020202020202020202020202-d37f95ed40a2f7cf977b7f1288fd216c3224b2020a2910e14d2ff3a95ba75c09",
      "body_sha256": "fff50068f20feea56d07acb43c013caba20efbaaecf6675803cf53124c2dce5b"
    },
    {
      "name": "step-000002.request.json",
      "number": 47,
      "expected_version": 2,
      "action": "comment",
      "key": "fgui-03030303030303030303030303030303-af9081b5fb5c790146483588a1161f6c4cc12f2e4e437dfac1116a30a77e8da1",
      "body_sha256": "59a65888f19892398b77bb1600828563ec1fe8571551aef1f5b3f57470304602"
    },
    {
      "name": "step-000003.request.json",
      "number": 47,
      "expected_version": 3,
      "action": "close",
      "key": "fgui-04040404040404040404040404040404-bbf5ec8b8654052dcc3dd58710aab5cc0dfc8e46b928f0b0d6efe6fd4d15ae7f",
      "body_sha256": "7e99a22f773f4242335898e42bc2e1abe53a9d4cb57fb879e98686d75bbd8966"
    },
    {
      "name": "step-000004.request.json",
      "number": 59,
      "expected_version": 0,
      "action": "open",
      "key": "fgui-05050505050505050505050505050505-4d5b56c7e9917f7c945c9bcf36197af91cd166ef9f524c3f3d5147331c1edba1",
      "body_sha256": "a71ef7b2a77cbb04e18e6d4c15c395c108cff5e0d670c77c1da5f2469709319f"
    }
  ],
  "manifest": {
    "schema": "frankengit-native-issue-import-v1",
    "href": "https://fixture.invalid/destination/ui/issues/",
    "tenant": "44444444444444444444444444444444",
    "repository": "55555555555555555555555555555555",
    "credential_fingerprint": "f592569589f163a80771f84fcc82e82c7de5bf047ea652e7b05852d6b96da097",
    "source_sha256": "314c832e110403d16527e17e1df69eb05bae60c79016361e9c68fee4f5095827",
    "steps_sha256": "a49a56fede8baa3c5c6ebbf9c85b84d4e7e45d1b9e36966b12f87642895b8e31",
    "offset": 40,
    "step_count": 5,
    "request_sha256": [
      "e9e1722dba20576ae52723495e923942c7f1f1adb44ce01e544fad3b2a403f5c",
      "0b37109c59f62a0947da6c74c5fcb4b3f09e013bbb4acdb2095d732514bc824e",
      "fcc8d4afd3a52c3ffd4f0646866f88fbf9582da2df0fb2c8859d454157e1d50c",
      "f4dcf6cf7ccb495e2c5add7fb53fdac24d1c00234eb74764b13f74f2b4279cc3",
      "4783d53576245406e2c55cbed62b7e50691a7609ebf4f2f188d4390127e7106e"
    ],
    "request_bytes": 10390
  }
};

async function hashesAt(root) {
  const hashes = {};
  for (const name of (await readdir(root)).sort()) hashes[name] = recordDigest(await readFile(join(root, name)));
  return hashes;
}
async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'fg-native-v1-capture-compat-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const captureFile = join(root, 'source.json'), tokenFile = join(root, 'token');
  // Public synthetic regression material, never a real credential.
  const credential = createHash('sha256')
    .update('FrankenGit native-v1 public regression token, never a real credential').digest('hex');
  await writeFile(captureFile, encode(capture), { mode: 0o600 });
  await writeFile(tokenFile, credential, { mode: 0o600 });
  return { captureFile, options: { workdir: join(root, 'plan'),
    href: 'https://fixture.invalid/destination/ui/issues/',
    tenant: '4'.repeat(32), repository: '5'.repeat(32), tokenFile } };
}

test('native capture-v1 preserves its frozen bytes and exact imported steps', () => {
  const expected = encode(capture), actual = nativeCaptureBytes(capture);
  assert.deepEqual(actual, expected);
  assert.equal(actual.length, golden.capture_bytes);
  assert.equal(recordDigest(actual), golden.capture_sha256);
  const parsed = parseNativeIssueCapture(expected);
  assert.deepEqual(parsed, capture);
  assert.ok(parsed.issues.every(row => !Object.hasOwn(row.snapshot, 'locked')));
  const steps = nativeIssueImportSteps(parsed, 40), bytes = encode(steps);
  assert.equal(bytes.length, golden.steps_bytes);
  assert.equal(recordDigest(bytes), golden.steps_sha256);
  assert.deepEqual(steps.map(({ number, expected_version, action }) => ({ number, expected_version, action })),
    golden.requests.map(({ number, expected_version, action }) => ({ number, expected_version, action })));
  assert.deepEqual(steps.map(step => step.source), [
    `native:${'d'.repeat(64)}:7:6`, `native:${'d'.repeat(64)}:7:2`,
    `native:${'d'.repeat(64)}:7:4`, `native:${'d'.repeat(64)}:7:6`,
    `native:${'d'.repeat(64)}:19:1`
  ]);
  assert.ok(steps.every(step => !Object.hasOwn(step.fields, 'assignees') && !Object.hasOwn(step.fields, 'actor')));
  for (const locked of [false, true]) {
    const changed = structuredClone(capture);
    changed.issues[0].snapshot.locked = locked;
    assert.throws(() => nativeCaptureBytes(changed), /native_issue_source_fields/,
      'a v1 capture must not acquire a new lock coordinate');
  }
});

test('prepared native-v1 plans retain frozen request bodies and original retry identities offline', async t => {
  const f = await fixture(t), descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const previousFetch = globalThis.fetch;
  let nonce = 0, networkCalls = 0, preparationFinished = false;
  Object.defineProperty(globalThis, 'crypto', { configurable: true,
    value: { subtle: webcrypto.subtle, getRandomValues(value) {
      assert.equal(preparationFinished, false, 'inspection must not allocate a replacement retry key');
      value.fill(++nonce); return value;
    } } });
  // A tripwire, not an authority peer: no network operation is permitted here.
  globalThis.fetch = () => { networkCalls++; throw new Error('native-v1 compatibility must remain offline'); };
  try {
    const plan = await prepareNativeIssueImport({ ...f.options, captureFile: f.captureFile, offset: 40 });
    preparationFinished = true;
    assert.equal(nonce, 5);
    assert.equal(plan.type, 'native_issue_import_prepared');
    assert.equal(plan.plan_sha256, golden.plan_sha256);
    assert.equal(plan.steps, 5);
    assert.equal(plan.mutation_submitted, false);
    assert.deepEqual(plan.mapping, [{ source: 7, target: 47 }, { source: 19, target: 59 }]);
    assert.deepEqual(await hashesAt(f.options.workdir), golden.hashes);
    assert.deepEqual(JSON.parse(await readFile(join(f.options.workdir, 'manifest.json'))), golden.manifest);
    for (const expected of golden.requests) {
      const record = JSON.parse(await readFile(join(f.options.workdir, expected.name)));
      const request = record.receipt.request;
      assert.deepEqual({ name: expected.name, number: request.number,
        expected_version: request.expected_version, action: request.action, key: request.key,
        body_sha256: recordDigest(Buffer.from(request.body)) }, expected);
    }
    // Prepared custody owns the original capture; losing the external source
    // must not recompile a new plan or replace any saved key on restart.
    await rm(f.captureFile);
    const options = { ...f.options, confirm: golden.plan_sha256 };
    const first = await inspectPreparedNativeIssueImport(options);
    const again = await inspectPreparedNativeIssueImport(options);
    assert.deepEqual(again, first);
    assert.equal(first.type, 'native_issue_import_verified');
    assert.equal(first.plan_sha256, golden.plan_sha256);
    assert.equal(first.source_sha256, golden.capture_sha256);
    assert.equal(first.offset, 40);
    assert.equal(first.steps, 5);
    assert.equal(first.request_bytes, golden.manifest.request_bytes);
    assert.deepEqual(first.source, capture.source);
    assert.deepEqual(first.issues, [{ number: 7, id: '7' }, { number: 19, id: '19' }]);
    assert.equal(first.network_accessed, false);
    assert.equal(first.mutation_submitted, false);
    assert.deepEqual(await hashesAt(f.options.workdir), golden.hashes);
    assert.equal(nonce, 5);
    assert.equal(networkCalls, 0);
  } finally {
    Object.defineProperty(globalThis, 'crypto', descriptor);
    globalThis.fetch = previousFetch;
  }
});
