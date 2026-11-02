// Explicitly mapped native milestone batches. The archive coordinator owns the
// open -> issues -> close ordering; this sender owns one immutable batch only.
import { createIssueImportEngine } from './issue-import-engine.mjs';
import { parseNativeMilestoneCapture, nativeMilestoneImportSteps } from './native-milestone-source.mjs';

const engine = createIssueImportEngine({ kind: 'native', entity: 'milestone',
  parseCapture: parseNativeMilestoneCapture, issueImportSteps: nativeMilestoneImportSteps, CAPTURE_LIMIT: 1024 * 1024 });
export const prepareNativeMilestoneImport = engine.prepare;
export const inspectPreparedNativeMilestoneImport = engine.inspect;
export const runNativeMilestoneImport = engine.run;
