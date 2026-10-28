// Publication preparation calls this only after dispatchReport has validated
// scope, execution and artifact receipts. Result observations are not inputs.
import { fail } from './workflow_watch_io.mjs';

export function markerMatches(marker, run) {
  if (!marker || typeof marker !== 'object' || Array.isArray(marker) ||
      marker.type !== 'trusted_workflow_attempt' || marker.state !== 'started') fail('Original workflow marker is unavailable.');
  for (const [name, value] of Object.entries(run)) {
    // Files, deliveries and logs arrive after execution. The artifact_contract,
    // including opt-in log_capture, MUST still match the immutable start marker.
    if (['type', 'succeeded', 'workspaces_closed', 'request_interrupted', 'execution',
      'artifacts', 'artifact_inputs', 'artifact_logs'].includes(name)) continue;
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
