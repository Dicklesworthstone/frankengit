// Native archive projections use the SAME exact-key sender as GitHub captures.
// Schema separation prevents treating one source type as the other on restart.
import { createIssueImportEngine } from './issue-import-engine.mjs';
import { parseNativeIssueCapture, nativeIssueImportSteps, NATIVE_CAPTURE_LIMIT } from './native-issue-source.mjs';

const engine = createIssueImportEngine({ kind: 'native', parseCapture: parseNativeIssueCapture,
  issueImportSteps: nativeIssueImportSteps, CAPTURE_LIMIT: NATIVE_CAPTURE_LIMIT });
export const prepareNativeIssueImport = engine.prepare;
export const inspectPreparedNativeIssueImport = engine.inspect;
export const runNativeIssueImport = engine.run;
