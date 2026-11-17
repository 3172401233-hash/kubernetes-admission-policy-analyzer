import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeAdmission,
  applyJsonPatch,
  applyStrategicMergePatch,
  createExampleInput,
  effectiveSecurityContext,
} from '../src/index.js';

function pod(overrides = {}) {
  return {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: { name: 'demo', namespace: 'default', ...overrides.metadata },
    spec: {
      containers: [
        {
          name: 'app',
          image: 'busybox:1.36',
          ...overrides.containerSpec,
          securityContext: {
            runAsUser: 0,
            capabilities: { add: ['NET_RAW'] },
            ...overrides.containerSecurity,
          },
        },
      ],
      ...overrides.podSpec,
    },
  };
}

const ns = (name = 'default', labels = {}) => ({ name, labels });

const denyRestricted = {
  name: 'restricted-deny',
  type: 'validating',
  rules: {
    privileged: true,
    hostNetwork: true,
    hostPath: true,
    runAsRoot: true,
    allowPrivilegeEscalation: true,
    forbiddenCapabilities: ['NET_RAW', 'SYS_ADMIN'],
  },
};

const mutateRestricted = {
  name: 'restricted-mutate',
  type: 'mutating',
  mutation: {
    hostNetwork: false,
    removeHostPathVolumes: true,
    dropCapabilities: ['NET_RAW', 'SYS_ADMIN'],
    containerSecurityContext: {
      privileged: false,
      allowPrivilegeEscalation: false,
      runAsNonRoot: true,
      runAsUser: 1000,
    },
  },
};

test('validating policy denies privileged, hostNetwork, root and added capabilities', () => {
  const result = analyzeAdmission({
    workload: pod({
      podSpec: { hostNetwork: true, volumes: [{ name: 'v', hostPath: { path: '/x' } }] },
      containerSecurity: {
        privileged: true,
        allowPrivilegeEscalation: true,
        capabilities: { add: ['SYS_ADMIN'] },
      },
    }),
    namespace: ns(),
    policies: [denyRestricted],
  });

  assert.equal(result.decision, 'deny');
  assert.equal(result.denial.policy, 'restricted-deny');
  const codes = result.denial.reasons.map((reason) => reason.code).sort();
  assert.deepEqual(codes, [
    'ALLOW_PRIVILEGE_ESCALATION',
    'FORBIDDEN_CAPABILITY',
    'HOST_NETWORK',
    'HOST_PATH',
    'PRIVILEGED_CONTAINER',
    'RUN_AS_ROOT',
  ]);
});

test('mutating policy then validating policy converges to allow and writes back config', () => {
  const result = analyzeAdmission({
    workload: pod({
      podSpec: { hostNetwork: true, volumes: [{ name: 'v', hostPath: { path: '/x' } }] },
      containerSecurity: { allowPrivilegeEscalation: true },
    }),
    namespace: ns(),
    policies: [mutateRestricted, denyRestricted],
  });

  assert.equal(result.decision, 'allow');
  const spec = result.finalPodSpec;
  assert.equal(spec.hostNetwork, false);
  assert.deepEqual(spec.volumes, []);
  const security = spec.containers[0].securityContext;
  assert.equal(security.runAsUser, 1000);
  assert.equal(security.allowPrivilegeEscalation, false);
  assert.deepEqual(security.capabilities.drop, ['NET_RAW', 'SYS_ADMIN']);

  const mutateSteps = result.trace.filter((step) => step.type === 'mutate');
  assert.ok(mutateSteps.length >= 1);
  assert.ok(mutateSteps.every((step) => Array.isArray(step.patch) && step.patch.length > 0));
  assert.equal(result.finalObject.kind, 'Pod');
});

test('namespace exemption by name and label skips all checks', () => {
  const byName = analyzeAdmission({
    workload: pod({ metadata: { namespace: 'kube-system' } }),
    namespace: ns('kube-system'),
    policies: [{ ...denyRestricted, exemptNamespaces: ['kube-system'] }],
  });
  assert.equal(byName.decision, 'allow');
  assert.equal(byName.trace[0].type, 'exempt');
  assert.match(byName.trace[0].reason, /explicitly exempted/);

  const byLabel = analyzeAdmission({
    workload: pod({ metadata: { namespace: 'special' } }),
    namespace: ns('special', { 'admission/skip': 'true' }),
    policies: [
      {
        ...denyRestricted,
        exemptionNamespaceSelector: { matchLabels: { 'admission/skip': 'true' } },
      },
    ],
  });
  assert.equal(byLabel.decision, 'allow');
  assert.match(byLabel.trace[0].reason, /exemptionNamespaceSelector/);

  const enforced = analyzeAdmission({
    workload: pod({ metadata: { namespace: 'team-b' } }),
    namespace: ns('team-b'),
    policies: [
      {
        ...denyRestricted,
        namespaceSelector: { matchLabels: { 'env': 'prod' } },
      },
    ],
  });
  assert.equal(enforced.decision, 'allow');
  assert.match(enforced.trace[0].reason, /namespaceSelector/);
});

test('repeated mutation rounds produce no duplicate patches (idempotent capabilities)', () => {
  const result = analyzeAdmission({
    workload: pod(),
    namespace: ns(),
    policies: [mutateRestricted, mutateRestricted, denyRestricted],
  });

  assert.equal(result.decision, 'allow');
  const capMutations = result.trace
    .filter((step) => step.type === 'mutate')
    .flatMap((step) => step.patch)
    .filter((operation) => operation.path.includes('capabilities'));
  for (const operation of capMutations) {
    const values = operation.op === 'add' && Array.isArray(operation.value)
      ? operation.value
      : [operation.value];
    const unique = new Set(values);
    assert.equal(unique.size, values.length, 'duplicate capability entries in patch');
  }
  const drop = result.finalPodSpec.containers[0].securityContext.capabilities.drop;
  assert.equal(drop.length, new Set(drop).size);
});

test('strategy ordering changes the outcome: deny-before-mutate vs mutate-before-deny', () => {
  const denied = analyzeAdmission({
    workload: pod(),
    namespace: ns(),
    policies: [denyRestricted, mutateRestricted],
  });
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.denial.round, 1);
  assert.equal(denied.trace[0].type, 'deny');

  const allowed = analyzeAdmission({
    workload: pod(),
    namespace: ns(),
    policies: [mutateRestricted, denyRestricted],
  });
  assert.equal(allowed.decision, 'allow');
});

test('conflicting mutating policies: last writer wins and every patch is retained', () => {
  const addNetRaw = {
    name: 'add-net-raw',
    type: 'mutating',
    mutation: {
      containerSecurityContext: { capabilities: { add: ['NET_RAW'] } },
    },
  };
  const dropNetRaw = {
    name: 'drop-net-raw',
    type: 'mutating',
    mutation: { dropCapabilities: ['NET_RAW'] },
  };

  const addFirst = analyzeAdmission({
    workload: pod({ containerSecurity: { capabilities: { add: [] } } }),
    namespace: ns(),
    policies: [addNetRaw, dropNetRaw],
  });
  assert.equal(addFirst.decision, 'allow');
  assert.deepEqual(
    addFirst.finalPodSpec.containers[0].securityContext.capabilities,
    { add: ['NET_RAW'], drop: ['NET_RAW'] },
  );

  const dropFirst = analyzeAdmission({
    workload: pod({ containerSecurity: { capabilities: { add: [] } } }),
    namespace: ns(),
    policies: [dropNetRaw, addNetRaw],
  });
  assert.deepEqual(
    dropFirst.finalPodSpec.containers[0].securityContext.capabilities,
    { add: ['NET_RAW'], drop: ['NET_RAW'] },
  );
  const names = dropFirst.trace.filter((step) => step.type === 'mutate').map((step) => step.policy);
  assert.deepEqual(names, ['drop-net-raw', 'add-net-raw']);
});

test('input change patch (JSON Patch and strategic merge) is applied before policies', () => {
  const jsonPatchResult = analyzeAdmission({
    workload: pod({ containerSecurity: { capabilities: { add: [] } } }),
    namespace: ns(),
    patch: [
      { op: 'add', path: '/spec/hostNetwork', value: true },
      { op: 'add', path: '/spec/containers/0/securityContext/privileged', value: true },
    ],
    policies: [denyRestricted],
  });
  assert.equal(jsonPatchResult.decision, 'deny');
  assert.ok(jsonPatchResult.denial.reasons.some((reason) => reason.code === 'PRIVILEGED_CONTAINER'));
  assert.equal(jsonPatchResult.trace[0].type, 'input-patch');
  assert.equal(jsonPatchResult.trace[0].format, 'jsonPatch');

  const mergeResult = analyzeAdmission({
    workload: pod(),
    namespace: ns(),
    patch: { spec: { hostNetwork: true } },
    policies: [
      {
        name: 'deny-hostnet',
        type: 'validating',
        rules: { hostNetwork: true },
      },
    ],
  });
  assert.equal(mergeResult.decision, 'deny');
  assert.equal(mergeResult.trace[0].format, 'strategicMerge');
});

test('Deployment templates and CronJob pods are supported with correct paths', () => {
  const deployment = {
    apiVersion: 'apps/v1',
    kind: 'Deployment',
    metadata: { name: 'web', namespace: 'default' },
    spec: {
      template: {
        spec: {
          containers: [
            {
              name: 'web',
              image: 'nginx:1.27',
              securityContext: { runAsUser: 0 },
            },
          ],
        },
      },
    },
  };
  const result = analyzeAdmission({
    workload: deployment,
    namespace: ns(),
    policies: [mutateRestricted, denyRestricted],
  });
  assert.equal(result.decision, 'allow');
  assert.equal(
    result.finalObject.spec.template.spec.containers[0].securityContext.runAsUser,
    1000,
  );
  assert.ok(
    result.trace.some(
      (step) => step.type === 'mutate' && step.patch.some((op) => op.path.startsWith('/spec/template/spec')),
    ),
  );

  const cronJob = {
    apiVersion: 'batch/v1',
    kind: 'CronJob',
    metadata: { name: 'job', namespace: 'default' },
    spec: {
      jobTemplate: {
        spec: { template: { spec: { containers: [{ name: 'c', image: 'busybox' }] } } },
      },
    },
  };
  const cronResult = analyzeAdmission({
    workload: cronJob,
    namespace: ns(),
    policies: [
      {
        name: 'deny-default-root',
        type: 'validating',
        rules: { runAsRoot: true },
      },
    ],
  });
  assert.equal(cronResult.decision, 'deny');
  assert.equal(cronResult.denial.reasons[0].code, 'RUN_AS_ROOT');
});

test('pod-level securityContext merges into container effective context', () => {
  const podSpec = {
    securityContext: { runAsUser: 1000, capabilities: { drop: ['ALL'] } },
    containers: [
      { name: 'app', securityContext: { capabilities: { add: ['CHOWN'] } } },
    ],
  };
  const effective = effectiveSecurityContext(podSpec, podSpec.containers[0]);
  assert.equal(effective.runAsUser, 1000);
  assert.deepEqual(effective.capabilities.add, ['CHOWN']);
  assert.deepEqual(effective.capabilities.drop, ['ALL']);
});

test('patch helpers behave on nested and array paths', () => {
  const doc = { spec: { containers: [{ name: 'a' }, { name: 'b' }] } };
  const patched = applyJsonPatch(doc, [
    { op: 'add', path: '/spec/containers/1/securityContext/privileged', value: false },
    { op: 'remove', path: '/spec/containers/0' },
  ]);
  assert.deepEqual(patched.spec.containers.map((c) => c.name), ['b']);
  assert.equal(patched.spec.containers[0].securityContext.privileged, false);

  const merged = applyStrategicMergePatch(
    { containers: [{ name: 'a', image: 'old' }], hostNetwork: true },
    { containers: [{ name: 'a', image: 'new' }], hostNetwork: false },
  );
  assert.equal(merged.containers[0].image, 'new');
  assert.equal(merged.hostNetwork, false);
});

test('example scenario: mutated capability addition still passes the final validating policy', () => {
  const result = analyzeAdmission(createExampleInput());
  assert.equal(result.decision, 'allow');
  const caps = result.finalPodSpec.containers[0].securityContext.capabilities;
  assert.deepEqual(caps.drop, ['NET_RAW']);
  assert.deepEqual(caps.add, ['NET_RAW', 'CHOWN']);
  assert.ok(result.trace.every((step) => step.sequence > 0));
});

test('UPDATE mode binding and operation-scoped policies are respected', () => {
  const updateOnly = { ...denyRestricted, modes: ['UPDATE'] };
  const createResult = analyzeAdmission(
    { workload: pod(), namespace: ns(), policies: [updateOnly] },
    { operation: 'CREATE' },
  );
  assert.equal(createResult.decision, 'allow');
  assert.match(createResult.trace[0].reason, /does not bind operation/);

  const updateResult = analyzeAdmission(
    { workload: pod(), namespace: ns(), policies: [updateOnly] },
    { operation: 'UPDATE' },
  );
  assert.equal(updateResult.decision, 'deny');
});
