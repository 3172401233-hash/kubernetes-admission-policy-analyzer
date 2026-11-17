export { analyzeAdmission } from './analyzer.js';
export {
  applyJsonPatch,
  applyStrategicMergePatch,
  isJsonPatch,
  applyPatch,
} from './patch.js';
export {
  getPodSpec,
  listContainers,
  effectiveSecurityContext,
  runsAsRoot,
  allowsPrivilegeEscalation,
} from './workload.js';
export {
  normalizePolicy,
  matchesNamespaceSelector,
  isExempt,
  policyApplies,
  evaluateRules,
  buildMutationOperations,
  POLICY_TYPE,
} from './policies.js';

export function createExampleInput() {
  return {
    workload: {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      metadata: { name: 'web', namespace: 'team-a' },
      spec: {
        template: {
          spec: {
            hostNetwork: true,
            volumes: [{ name: 'docker-sock', hostPath: { path: '/var/run/docker.sock' } }],
            containers: [
              {
                name: 'web',
                image: 'nginx:1.27',
                securityContext: { runAsUser: 0, capabilities: { add: ['NET_RAW'] } },
              },
            ],
          },
        },
      },
    },
    namespace: {
      name: 'team-a',
      labels: { 'env': 'prod', 'pod-security.kubernetes.io/enforce': 'restricted' },
    },
    policies: [
      {
        name: 'drop-dangerous-caps',
        type: 'mutating',
        mutation: {
          hostNetwork: false,
          removeHostPathVolumes: true,
          dropCapabilities: ['NET_RAW'],
          containerSecurityContext: {
            allowPrivilegeEscalation: false,
            runAsNonRoot: true,
            runAsUser: 1000,
            capabilities: { add: ['CHOWN'] },
          },
        },
      },
      {
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
      },
    ],
  };
}
