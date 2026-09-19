// Native-shaped HTTP doubles, not execution of the Rust replay/admission engine.
// Object hashes are real; synthetic trees and bundles are explicitly not closure proofs.
import { createHash } from 'node:crypto';
import { fixture as sourceFixture, metadata, multipart, response, crypto, token, actor } from './source-edit-fixtures.mjs';
export { metadata, crypto, token, actor };
export const href = 'http://127.0.0.1:9418/repo.git/ui/replay/';
export const hex = value => Buffer.from(value).toString('hex');
export const hash = (kind, body, algorithm) => createHash(algorithm).update(`${kind} ${body.length}\0`).update(body).digest('hex');
export const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
export function upload(call) {
  if (typeof call.body === 'string') return { fields: new URLSearchParams(call.body), files: new Map() };
  const boundary = call.headers['content-type'].split('boundary=')[1], bytes = Buffer.from(call.body), marker = Buffer.from(`\r\n--${boundary}`);
  const files = new Map(); let fields, at = boundary.length + 4;
  while (at < bytes.length) {
    const end = bytes.indexOf('\r\n\r\n', at); if (end < 0) break;
    const headers = bytes.subarray(at, end).toString(), name = /name="([^"]+)"/.exec(headers)?.[1];
    const next = bytes.indexOf(marker, end + 4); if (next < 0) throw new Error('Missing multipart end');
    const payload = bytes.subarray(end + 4, next);
    if (name === 'command') fields = new URLSearchParams(payload.toString()); else files.set(name, new Uint8Array(payload));
    at = next + marker.length; if (bytes.subarray(at, at + 2).toString() === '--') break; at += 2;
  }
  return { fields, files };
}
export async function fixture(algorithm = 'sha1') {
  const source = await sourceFixture(algorithm), width = algorithm === 'sha1' ? 40 : 64;
  const topic = 'f'.repeat(width), selectedParent = 'd'.repeat(width), path = source.edits[0].path_hex;
  const original = { path_hex: path, kind: 'content', base: { mode: 0o100644, oid: 'e'.repeat(width) },
    ours: { mode: source.manifest[0].old_mode, oid: source.manifest[0].old_blob },
    theirs: { mode: source.manifest[0].new_mode, oid: source.manifest[0].new_blob } };
  const calls = [], config = { state: 'clean', resolvedState: 'resolved', prepare: null, resolve: null, inspect: null,
    select: null, apply: null, recover: null, loseApply: false, refuseApply: false, outcome: 'key_not_observed', root: false };
  let inspection = structuredClone(source.inspection), terminal = structuredClone(source.terminal);
  const input = () => ({ commit: topic, ...metadata });
  async function fetchImpl(url, options) {
    const pathName = new URL(url).pathname.split('/api/v1/')[1];
    const call = { path: pathName, method: options.method, headers: Object.fromEntries(new Headers(options.headers)),
      body: options.body instanceof Uint8Array ? options.body.slice() : options.body, signal: options.signal }; calls.push(call);
    if (pathName === 'source/tree') {
      const fields = new URLSearchParams(call.body), ref = fields.get('ref');
      const r = { ...source.selection, ref, ref_hex: hex(ref), source_commit: ref === 'refs/heads/topic' ? topic : source.base,
        type: 'source_tree', object_id: source.selection.root_tree, path_hex: null, after_hex: null, limit: 1, entries: [], next_after_hex: null };
      await config.select?.(r, call); return response(r);
    }
    if (/^source\/(cherry-pick|revert)\/(prepare|resolve)$/.test(pathName)) {
      const { fields, files } = upload(call), direction = pathName.split('/')[1], resolving = pathName.endsWith('/resolve');
      const state = resolving ? config.resolvedState : config.state;
      const selected = fields.get('commit'), parent = config.root ? null : selectedParent;
      const r = { ...source.prepared, type: 'replay_preparation', profile: 'path-v1', direction,
        source_head: source.selection.source_head, snapshot_token: source.selection.snapshot_token,
        target_ref: fields.get('target_ref'), target_ref_hex: hex(fields.get('target_ref')),
        source_ref: fields.get('source_ref'), source_ref_hex: hex(fields.get('source_ref')),
        expected_target: fields.get('expected_target'), expected_source: fields.get('expected_source'),
        selected_commit: selected, selected_parent: parent, selected_mainline: parent ? Number(fields.get('mainline') ?? 1) : null,
        author_identity_verified: false, state, conflicts: state === 'conflicted' ? [structuredClone(original)] : [],
        parents: [fields.get('expected_target')], generated_objects: 3, pack_objects: 4, borrowed_objects: 1 };
      delete r.paths; delete r.patch_sha256; delete r.ref; delete r.ref_hex; delete r.source_commit;
      if (resolving) {
        r.resolution_profile = 'exact-path-resolutions-v1';
        r.resolutions = fields.getAll('resolution').map(value => {
          const [path, choice, mode, label] = value.split(':');
          return { conflict: { ...structuredClone(original), path_hex: path }, choice,
            result: choice === 'file' ? { mode: Number.parseInt(mode, 8), oid: hash('blob', files.get(label), algorithm) }
              : choice === 'delete' ? null : structuredClone(original[choice]) };
        });
      }
      const body = Buffer.from(`tree ${r.root_tree}\nparent ${r.expected_target}\nauthor ${fields.get('author')} ${fields.get('timestamp')} +0000\ncommitter ${fields.get('committer')} ${fields.get('timestamp')} +0000\n\n${fields.get('message')}`);
      r.candidate_commit = hash('commit', body, algorithm);
      inspection = { ...structuredClone(source.inspection), ref: r.target_ref, ref_hex: r.target_ref_hex,
        expected_commit: r.expected_target, candidate_commit: r.candidate_commit, parents: [r.expected_target], candidate_commit_body_hex: hex(body) };
      terminal = { ...structuredClone(source.terminal), ref: r.target_ref, ref_hex: r.target_ref_hex, expected_commit: r.expected_target, candidate_commit: r.candidate_commit };
      if (resolving) {
        const result = r.resolutions[0].result;
        inspection.comparison.entries[0].after = result;
        inspection.comparison.entries[0].kind = result ? 'modified' : 'deleted';
        if (JSON.stringify(result) === JSON.stringify(original.ours)) { inspection.comparison.entries = []; inspection.comparison.entry_count = 0; }
      }
      if (state === 'conflicted' || state === 'no_change') { r.candidate_commit = null; r.root_tree = null; r.bundle = null; delete r.parents; }
      await (resolving ? config.resolve : config.prepare)?.(r, call);
      if (state === 'conflicted' || state === 'no_change') return response(r, state === 'conflicted' ? 409 : 200);
      const envelope = multipart(r, source.bundle, source.sha256);
      return new Response(envelope.value, { status: 200, headers: { 'Content-Type': envelope.type } });
    }
    if (pathName === 'source/inspect') { const r = structuredClone(inspection); await config.inspect?.(r, call); return response(r); }
    if (pathName === 'source/apply') {
      if (config.loseApply) throw new Error('Simulated lost reply');
      const r = structuredClone(terminal);
      if (config.refuseApply) { r.outcome = 'refused'; r.decision_record = 'refusal-record'; r.refusal_code = 'TargetRefMoved'; }
      await config.apply?.(r, call); return response(r, config.refuseApply ? 409 : 200);
    }
    if (pathName === 'outcomes') {
      source.config.outcome = config.outcome;
      const native = await source.fetchImpl(url, options), r = await native.json(); await config.recover?.(r, call); return response(r);
    }
    throw new Error(`Unexpected replay endpoint ${pathName}`);
  }
  return { ...source, calls, config, fetchImpl, input, topic, selectedParent, conflict: original, path };
}
