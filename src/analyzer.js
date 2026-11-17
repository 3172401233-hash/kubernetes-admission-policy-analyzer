// Ordered, multi-round admission policy simulation.

import { applyJsonPatch, applyStrategicMergePatch, isJsonPatch } from './patch.js';
import { getPodSpec } from './workload.js';
import {
  normalizePolicy,
  policyApplies,
  evaluateRules,
  buildMutationOperations,
  POLICY_TYPE,
} from './policies.js';

const DEFAULT_OPTIONS = {
  operation: 'CREATE',
  maxRounds: 5,
  // When false policies run strictly in supplied order, regardless of type.
  // When true mutating policies are evaluated before validating ones in each
  // round (the real API server runs them in distinct admission phases).
  groupedPhases: false,
};

export function analyzeAdmission(input, options = {}) {
  const settings = { ...DEFAULT_OPTIONS, ...options };
  const original = structuredClone(input.workload);
  const working = structuredClone(input.workload);
  const namespace = input.namespace ?? { name: input.workload?.metadata?.namespace };
  const policies = (input.policies ?? []).map(normalizePolicy);

  const context = {
    operation: settings.operation,
    kind: working.kind,
    namespace: {
      name: working.metadata?.namespace ?? namespace?.name,
      labels: namespace?.labels ?? {},
    },
  };

  const trace = [];
  const rounds = [];
  let sequence = 0;

  function record(entry) {
    sequence += 1;
    const step = { sequence, ...entry };
    trace.push(step);
    return step;
  }

  // 1. User-supplied change patch (e.g. the patch inside the AdmissionReview).
  if (input.patch !== undefined && input.patch !== null) {
    const format = isJsonPatch(input.patch) ? 'jsonPatch' : 'strategicMerge';
    applyInitialPatch(working, input.patch, format);
    record({
      type: 'input-patch',
      format,
      patch: structuredClone(input.patch),
      note: 'user supplied change patch applied before policies',
    });
  }

  let decision = 'allow';
  let denial = null;
  let round = 0;

  function orderedPolicies() {
    if (!settings.groupedPhases) return policies;
    return [
      ...policies.filter((policy) => policy.type === POLICY_TYPE.MUTATING),
      ...policies.filter((policy) => policy.type === POLICY_TYPE.VALIDATING),
    ];
  }

  while (round < settings.maxRounds && !denial) {
    round += 1;
    const roundTrace = [];
    let roundChanged = false;

    for (const policy of orderedPolicies()) {
      if (!policyApplies(policy, context)) {
        const step = record({
          round,
          type: 'exempt',
          policy: policy.name,
          policyType: policy.type,
          reason: exemptionReason(policy, context),
        });
        roundTrace.push(step);
        continue;
      }

      if (policy.type === POLICY_TYPE.VALIDATING) {
        const { podSpec, basePath } = getPodSpec(working);
        const violations = evaluateRules(policy, context, podSpec, basePath);
        if (violations.length > 0) {
          const step = record({
            round,
            type: 'deny',
            policy: policy.name,
            policyType: policy.type,
            violations,
          });
          roundTrace.push(step);
          denial = step;
          break;
        }
        roundTrace.push(
          record({
            round,
            type: 'allow',
            policy: policy.name,
            policyType: policy.type,
          }),
        );
        continue;
      }

      const { podSpec, basePath } = getPodSpec(working);
      const operations = buildMutationOperations(policy, context, podSpec, basePath);
      if (operations.length === 0) {
        roundTrace.push(
          record({
            round,
            type: 'no-op',
            policy: policy.name,
            policyType: policy.type,
            patch: [],
          }),
        );
        continue;
      }

      applyJsonPatch(working, operations);
      roundChanged = true;
      roundTrace.push(
        record({
          round,
          type: 'mutate',
          policy: policy.name,
          policyType: policy.type,
          patch: structuredClone(operations),
        }),
      );
    }

    rounds.push({ round, steps: roundTrace, changed: roundChanged });
    if (denial) break;
    if (!roundChanged) break;
  }

  if (denial) {
    decision = 'deny';
  }

  const { podSpec: finalPodSpec } = getPodSpec(working);
  return {
    decision,
    operation: settings.operation,
    kind: working.kind,
    namespace: context.namespace,
    rounds,
    trace,
    denial: denial
      ? {
          policy: denial.policy,
          round: denial.round,
          reasons: denial.violations,
        }
      : null,
    // Final config write-back: mutated object plus the flattened pod spec.
    finalObject: working,
    finalPodSpec,
    originalObject: original,
    converged: !denial,
    maxRoundsReached: !denial && round === settings.maxRounds && lastRoundChanged(rounds),
  };
}

function applyInitialPatch(document, patch, format) {
  if (format === 'jsonPatch') {
    applyJsonPatch(document, patch);
    return;
  }
  if (document.kind === 'Pod') {
    document.spec = applyStrategicMergePatch(document.spec ?? {}, patch.spec ?? patch);
    return;
  }
  if (document.kind === 'CronJob') {
    const templateSpec = document.spec?.jobTemplate?.spec?.template?.spec;
    if (templateSpec && patch.spec?.template?.spec) {
      document.spec.jobTemplate.spec.template.spec = applyStrategicMergePatch(
        templateSpec,
        patch.spec.template.spec,
      );
    }
    return;
  }
  const templateSpec = document.spec?.template?.spec;
  if (templateSpec && patch.spec?.template?.spec) {
    document.spec.template.spec = applyStrategicMergePatch(
      templateSpec,
      patch.spec.template.spec,
    );
  }
}

function lastRoundChanged(rounds) {
  return rounds.length > 0 && rounds[rounds.length - 1].changed;
}

function exemptionReason(policy, context) {
  const name = context.namespace?.name;
  if (name && policy.exemptNamespaces.includes(name)) {
    return `namespace "${name}" is explicitly exempted`;
  }
  if (
    policy.exemptionNamespaceSelector &&
    (policy.exemptionNamespaceSelector.matchLabels ||
      policy.exemptionNamespaceSelector.matchExpressions)
  ) {
    return `namespace "${name ?? ''}" matches exemptionNamespaceSelector`;
  }
  if (!policy.modes.includes(context.operation)) {
    return `policy does not bind operation ${context.operation}`;
  }
  if (policy.resourceKinds.length > 0 && !policy.resourceKinds.includes(context.kind)) {
    return `policy does not bind kind ${context.kind}`;
  }
  if (policy.namespaces.length > 0 && !policy.namespaces.includes(name)) {
    return `namespace "${name ?? ''}" is not included in policy namespaces`;
  }
  return `namespace "${name ?? ''}" does not match namespaceSelector`;
}
