// Native milestones share the existing issue metadata grants and exact outcome
// operator. Selecting this profile cannot add a grant or infer one from history.
import { createMetadataOperator } from './forge-issue-operator.mjs';

const milestone = createMetadataOperator('milestone');
export const milestoneOperatorOptions = milestone.options;
export const runMilestoneOperation = milestone.run;
