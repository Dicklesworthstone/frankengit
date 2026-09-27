import { ids, actor, show, data } from './pulls-fixtures.mjs';
import { showReply } from '../../crates/fgit-node/src/smart_http/server/browser/pulls-core.mjs';

export const checksHead = `alg:2:${'b'.repeat(64)}`;
export const checkLabel = n => `check/${n.toString(32).padStart(51, '0')}0`;
export const checkRow = (extra = {}) => ({ id: checkLabel(1), publisher: actor,
  run_id: '1'.repeat(64), attempt_id: '2'.repeat(64), graph_root: '3'.repeat(64), job: 'test',
  conclusion: 'action_required', evidence_sha256: '4'.repeat(64), evidence_bytes: '64', ...extra });
export const observation = (extra = {}) => showReply(show({ snapshot_token: checksHead, ...extra }), 1);
export const checks = (extra = {}) => ({ ...ids, type: 'pull_request_checks', number: '1', found: true,
  source_head: 'head-id', snapshot_token: checksHead, pull_request_version: '1',
  source_ref_hex: data().source_ref_hex, target_ref_hex: data().target_ref_hex,
  source_tip: data().source_tip, target_tip: data().target_tip, source_current: true,
  after: null, limit: 20, next_after: null, complete: true, scope: 'trusted_workflow_observations',
  merge_permission: null, checks: [checkRow()], ...extra });
export const unavailable = () => checks({ found: false, source_head: null, snapshot_token: null,
  pull_request_version: null, source_ref_hex: null, target_ref_hex: null, source_tip: null,
  target_tip: null, source_current: null, checks: [] });
