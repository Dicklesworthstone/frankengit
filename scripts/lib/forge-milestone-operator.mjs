// Native milestones share the issue-service operator and exact outcome custody.
// Sponsored credentials require independent milestone scopes at the server;
// selecting this profile cannot add a grant or infer one from history.
import { createMetadataOperator } from './forge-issue-operator.mjs';

const milestone = createMetadataOperator('milestone');
export const milestoneOperatorOptions = milestone.options;
export const runMilestoneOperation = milestone.run;
