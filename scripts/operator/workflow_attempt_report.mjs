// Publication preparation calls this only after dispatchReport has validated
// scope, execution and artifact receipts. Result observations are not inputs.
import { fail } from './workflow_watch_io.mjs';

function sharedInputs(value) {
  const counters = ['resident_bytes', 'resident_entries', 'seeded_bytes', 'seeded_entries', 'probe_entries',
    'cloned_bytes', 'clone_operations', 'fallback_bytes', 'fallback_files', 'unsupported_files', 'capacity_files'];
  const fields = ['profile', 'cache_closed', 'reflink_supported', ...counters];
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(key => !Object.hasOwn(value, key)) ||
      value.profile !== 'verified-reflink-or-copy-v1' || value.cache_closed !== true ||
      typeof value.reflink_supported !== 'boolean' || value.resident_bytes !== 0 || value.resident_entries !== 0 ||
      counters.some(key => !Number.isSafeInteger(value[key]) || value[key] < 0)) {
    fail('Native shared-input cache completion is invalid or not quiescent.');
  }
}
export function markerMatches(marker, run) {
  if (!marker || typeof marker !== 'object' || Array.isArray(marker) ||
      marker.type !== 'trusted_workflow_attempt' || marker.state !== 'started') fail('Original workflow marker is unavailable.');
  // Native attempt_marker() omits cache statistics: they exist only after the
  // shared input cache drains. They cannot change the original journal scope.
  if (Object.hasOwn(marker, 'shared_inputs')) fail('Original workflow marker contains completion statistics.');
  if (Object.hasOwn(run, 'shared_inputs')) sharedInputs(run.shared_inputs);
  for (const [name, value] of Object.entries(run)) {
    // Files, deliveries and logs arrive after execution. The artifact_contract,
    // including opt-in log_capture, MUST still match the immutable start marker.
    if (['type', 'succeeded', 'workspaces_closed', 'request_interrupted', 'execution',
      'artifacts', 'artifact_inputs', 'artifact_logs', 'shared_inputs'].includes(name)) continue;
    if (JSON.stringify(marker[name]) !== JSON.stringify(value)) fail('Original workflow marker changed the selected executed input.');
  }
  if (!marker.execution_plan || typeof marker.execution_plan !== 'object' || Array.isArray(marker.execution_plan)) {
    fail('Original workflow marker is missing its compiled plan.');
  }
  for (const [name, value] of Object.entries(run.execution)) {
    const expected = name === 'jobs' ? [] : name === 'succeeded' ? false : value;
    if (JSON.stringify(marker.execution_plan[name]) !== JSON.stringify(expected)) fail('Original workflow marker changed its compiled plan.');
  }
}
