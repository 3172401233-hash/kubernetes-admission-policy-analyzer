// Policy matching, validation rules and mutation patch generation.

import {
  effectiveSecurityContext,
  runsAsRoot,
  listContainers,
} from './workload.js';

export const POLICY_TYPE = {
  VALIDATING: 'validating',
  MUTATING: 'mutating',
};

function normalizeType(type) {
  if (type === 'deny' || type === 'validating' || type === 'validatingadmissionpolicy') {
    return POLICY_TYPE.VALIDATING;
  }
  if (type === 'mutate' || type === 'mutating' || type === 'mutatingadmissionpolicy') {
    return POLICY_TYPE.MUTATING;
  }
  throw new Error(`Unknown policy type: ${String(type)}`);
}

export function normalizePolicy(policy) {
  if (!policy || typeof policy !== 'object' || !policy.name) {
    throw new Error('Every policy requires a unique "name"');
  }
  return {
    ...policy,
    type: normalizeType(policy.type),
    modes: policy.modes ?? ['CREATE', 'UPDATE'],
    resourceKinds: policy.resourceKinds ?? [],
    exemptNamespaces: policy.exemptNamespaces ?? [],
    namespaces: policy.namespaces ?? [],
    namespaceSelector: policy.namespaceSelector ?? null,
  };
}

function matchExpression(expression, labels) {
  const values = labels[expression.key] !== undefined ? [labels[expression.key]] : [];
  switch (expression.operator) {
    case 'In':
      return values.length === 1 && expression.values.includes(values[0]);
    case 'NotIn':
      return !(values.length === 1 && expression.values.includes(values[0]));
    case 'Exists':
      return labels[expression.key] !== undefined;
    case 'DoesNotExist':
      return labels[expression.key] === undefined;
    default:
      throw new Error(`Unsupported selector operator: ${expression.operator}`);
  }
}

export function matchesNamespaceSelector(selector, namespace) {
  if (!selector) return true;
  const labels = namespace?.labels ?? {};
  if (selector.matchLabels) {
    for (const [key, value] of Object.entries(selector.matchLabels)) {
      if (labels[key] !== value) return false;
    }
  }
  if (selector.matchExpressions) {
    for (const expression of selector.matchExpressions) {
      if (!matchExpression(expression, labels)) return false;
    }
  }
  return true;
}

// A policy is skipped (exempt) when the namespace is explicitly exempted by
// name, or selected by an exemption selector.
export function isExempt(policy, namespace) {
  const name = namespace?.name;
  if (name && policy.exemptNamespaces.includes(name)) return true;
  if (
    policy.exemptionNamespaceSelector &&
    matchesNamespaceSelector(policy.exemptionNamespaceSelector, namespace)
  ) {
    return true;
  }
  return false;
}

export function policyApplies(policy, context) {
  if (!policy.modes.includes(context.operation)) return false;
  if (policy.resourceKinds.length > 0 && !policy.resourceKinds.includes(context.kind)) {
    return false;
  }
  if (policy.namespaces.length > 0 && !policy.namespaces.includes(context.namespace?.name)) {
    return false;
  }
  if (isExempt(policy, context.namespace)) return false;
  if (!matchesNamespaceSelector(policy.namespaceSelector, context.namespace)) return false;
  return true;
}

function capPath(basePath, group, index, field) {
  return `${basePath}/${group}/${index}/securityContext/capabilities/${field}`;
}

function hasCapability(effectiveSecurity, capability) {
  const added = effectiveSecurity.capabilities?.add ?? [];
  const dropped = effectiveSecurity.capabilities?.drop ?? [];
  if (dropped.includes(capability) || dropped.includes('ALL')) return false;
  return added.includes(capability) || added.includes('ALL');
}

// Evaluate every enabled rule and return one violation per offending target.
export function evaluateRules(policy, context, podSpec, basePath) {
  const rules = policy.rules ?? {};
  const violations = [];

  if (rules.hostNetwork && podSpec.hostNetwork === true) {
    violations.push({
      code: 'HOST_NETWORK',
      message: 'pod uses hostNetwork',
      target: `${basePath}/hostNetwork`,
    });
  }

  if (rules.hostPath) {
    (podSpec.volumes ?? []).forEach((volume, index) => {
      if (volume.hostPath) {
        violations.push({
          code: 'HOST_PATH',
          message: `volume "${volume.name}" mounts a hostPath`,
          target: `${basePath}/volumes/${index}/hostPath`,
        });
      }
    });
  }

  for (const { group, index, container } of listContainers(podSpec)) {
    const targetBase = `${basePath}/${group}/${index}`;
    const security = effectiveSecurityContext(podSpec, container);

    if (rules.privileged && security.privileged === true) {
      violations.push({
        code: 'PRIVILEGED_CONTAINER',
        message: `container "${container.name}" runs privileged`,
        target: `${targetBase}/securityContext/privileged`,
      });
    }

    if (Array.isArray(rules.forbiddenCapabilities)) {
      for (const capability of rules.forbiddenCapabilities) {
        if (hasCapability(security, capability)) {
          violations.push({
            code: 'FORBIDDEN_CAPABILITY',
            message: `container "${container.name}" adds forbidden capability ${capability}`,
            target: capPath(basePath, group, index, 'add'),
          });
        }
      }
    }

    if (rules.runAsRoot && runsAsRoot(security)) {
      violations.push({
        code: 'RUN_AS_ROOT',
        message: `container "${container.name}" runs as root (effective UID 0)`,
        target: `${targetBase}/securityContext/runAsUser`,
      });
    }

    // Only flag an explicit opt-in; an unset value is reported separately via
    // the mutation hardening policy rather than treated as a hard violation.
    if (
      rules.allowPrivilegeEscalation &&
      (security.allowPrivilegeEscalation === true || security.privileged === true)
    ) {
      violations.push({
        code: 'ALLOW_PRIVILEGE_ESCALATION',
        message: `container "${container.name}" allows privilege escalation`,
        target: `${targetBase}/securityContext/allowPrivilegeEscalation`,
      });
    }
  }

  return violations;
}

function setScalar(operations, current, path, value) {
  if (current === value) return;
  operations.push({ op: current === undefined ? 'add' : 'replace', path, value });
}

// Build the RFC 6902 operations a mutating policy would issue. Each operation
// is only emitted when the current document actually differs, which makes
// repeated rounds naturally idempotent.
export function buildMutationOperations(policy, context, podSpec, basePath) {
  const mutation = policy.mutation ?? {};
  const operations = [];

  for (const field of ['hostNetwork', 'hostPID', 'hostIPC']) {
    if (field in mutation) {
      setScalar(operations, podSpec[field], `${basePath}/${field}`, mutation[field]);
    }
  }

  if (mutation.podSecurityContext) {
    for (const [key, value] of Object.entries(mutation.podSecurityContext)) {
      const current = podSpec.securityContext?.[key];
      setScalar(operations, current, `${basePath}/securityContext/${key}`, value);
    }
  }

  const containerMutation = mutation.containerSecurityContext ?? {};
  const scalarContainerFields = [
    'privileged',
    'allowPrivilegeEscalation',
    'runAsNonRoot',
    'runAsUser',
    'runAsGroup',
    'readOnlyRootFilesystem',
  ];

  for (const { group, index, container } of listContainers(podSpec)) {
    const containerBase = `${basePath}/${group}/${index}`;
    for (const field of scalarContainerFields) {
      if (field in containerMutation) {
        setScalar(
          operations,
          container.securityContext?.[field],
          `${containerBase}/securityContext/${field}`,
          containerMutation[field],
        );
      }
    }

    const wantedDrop = [
      ...(mutation.dropCapabilities ?? []),
      ...(containerMutation.capabilities?.drop ?? []),
    ];
    if (wantedDrop.length > 0) {
      appendCapabilities(operations, podSpec, container, group, index, basePath, 'drop', wantedDrop);
    }
    const wantedAdd = containerMutation.capabilities?.add ?? [];
    if (wantedAdd.length > 0) {
      appendCapabilities(operations, podSpec, container, group, index, basePath, 'add', wantedAdd);
    }
  }

  if (mutation.removeHostPathVolumes) {
    const hostPathIndexes = (podSpec.volumes ?? [])
      .map((volume, index) => (volume.hostPath ? index : -1))
      .filter((index) => index >= 0)
      // Descending order keeps earlier indexes valid while removing entries.
      .sort((left, right) => right - left);
    for (const index of hostPathIndexes) {
      operations.push({ op: 'remove', path: `${basePath}/volumes/${index}` });
    }
  }

  return operations;
}

function appendCapabilities(operations, podSpec, container, group, index, basePath, field, wanted) {
  const path = capPath(basePath, group, index, field);
  // Deduplicate against the container-local list only: a capability present in
  // "drop" must still be allowed to appear in "add" when a later policy asks.
  const existing = container.securityContext?.capabilities?.[field] ?? [];
  const uniqueWanted = [...new Set(wanted)].filter((capability) => !existing.includes(capability));
  if (uniqueWanted.length === 0) return;

  const containerLocal = container.securityContext?.capabilities?.[field];
  if (containerLocal === undefined) {
    operations.push({ op: 'add', path, value: uniqueWanted });
  } else {
    for (const capability of uniqueWanted) {
      operations.push({ op: 'add', path: `${path}/-`, value: capability });
    }
  }
}
