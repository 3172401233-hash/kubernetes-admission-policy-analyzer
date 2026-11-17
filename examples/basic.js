import { analyzeAdmission, createExampleInput } from '../src/index.js';

const result = analyzeAdmission(createExampleInput());

console.log('decision:', result.decision);
for (const step of result.trace) {
  if (step.type === 'mutate') {
    console.log(`  [round ${step.round}] mutate by ${step.policy}: ${step.patch.length} ops`);
  } else if (step.type === 'deny') {
    console.log(`  [round ${step.round}] DENY by ${step.policy}`);
    for (const violation of step.violations) {
      console.log(`    - ${violation.code}: ${violation.message}`);
    }
  } else {
    console.log(`  [round ${step.round}] ${step.type} by ${step.policy ?? 'system'}`);
  }
}

console.log('final runAsUser:', result.finalPodSpec.containers[0].securityContext.runAsUser);
