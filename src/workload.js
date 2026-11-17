// Locate the pod template inside Pod / workload resources and reason about
// the effective security context of every container.

const POD_TEMPLATE_WORKLOADS = new Set([
  'Deployment',
  'StatefulSet',
  'DaemonSet',
  'ReplicaSet',
  'Job',
  'CronJob',
  'ReplicationController',
]);

export function getPodSpec(document) {
  const kind = document.kind;
  if (kind === 'Pod') {
    return { podSpec: document.spec, basePath: '/spec' };
  }
  if (kind === 'CronJob') {
    return {
      podSpec: document.spec?.jobTemplate?.spec?.template?.spec,
      basePath: '/spec/jobTemplate/spec/template/spec',
    };
  }
  if (POD_TEMPLATE_WORKLOADS.has(kind)) {
    return {
      podSpec: document.spec?.template?.spec,
      basePath: '/spec/template/spec',
    };
  }
  // Fall back: treat an object that already looks like a pod spec.
  if (document.spec && (document.spec.containers || document.spec.volumes)) {
    return { podSpec: document.spec, basePath: '/spec' };
  }
  throw new Error(`Unsupported workload kind: ${String(kind)}`);
}

export function listContainers(podSpec) {
  const groups = [
    ['initContainers', podSpec.initContainers ?? []],
    ['containers', podSpec.containers ?? []],
    ['ephemeralContainers', podSpec.ephemeralContainers ?? []],
  ];
  const result = [];
  for (const [group, containers] of groups) {
    containers.forEach((container, index) => {
      result.push({ group, index, container });
    });
  }
  return result;
}

// Pod-level and container-level securityContext fields merge, with the
// container-level value winning. Arrays (capabilities) are concatenated and
// de-duplicated, matching the spirit of the Kubernetes effective model.
export function effectiveSecurityContext(podSpec, container) {
  const podSecurity = podSpec.securityContext ?? {};
  const containerSecurity = container.securityContext ?? {};

  const scalarKeys = new Set([
    'privileged',
    'allowPrivilegeEscalation',
    'runAsNonRoot',
    'runAsUser',
    'runAsGroup',
    'readOnlyRootFilesystem',
    'procMount',
  ]);
  const merged = {};
  for (const key of scalarKeys) {
    if (key in containerSecurity) merged[key] = containerSecurity[key];
    else if (key in podSecurity) merged[key] = podSecurity[key];
  }

  if (podSecurity.seLinuxOptions || containerSecurity.seLinuxOptions) {
    merged.seLinuxOptions = {
      ...podSecurity.seLinuxOptions,
      ...containerSecurity.seLinuxOptions,
    };
  }

  const podCaps = podSecurity.capabilities ?? {};
  const containerCaps = containerSecurity.capabilities ?? {};
  if (podCaps.add || podCaps.drop || containerCaps.add || containerCaps.drop) {
    merged.capabilities = {
      add: [...new Set([...(podCaps.add ?? []), ...(containerCaps.add ?? [])])],
      drop: [...new Set([...(podCaps.drop ?? []), ...(containerCaps.drop ?? [])])],
    };
  }
  return merged;
}

// A container is effectively root when runAsUser is 0, or unset together with
// a missing runAsNonRoot flag (the kubelet default user is root).
export function runsAsRoot(effectiveSecurity) {
  if (effectiveSecurity.runAsUser !== undefined) {
    return effectiveSecurity.runAsUser === 0;
  }
  return effectiveSecurity.runAsNonRoot !== true;
}

// allowPrivilegeEscalation defaults to true when not explicitly disabled,
// except that privileged containers always have it enabled.
export function allowsPrivilegeEscalation(effectiveSecurity) {
  if (effectiveSecurity.privileged === true) return true;
  if (effectiveSecurity.allowPrivilegeEscalation !== undefined) {
    return effectiveSecurity.allowPrivilegeEscalation;
  }
  return true;
}
