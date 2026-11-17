# kubernetes-admission-policy-analyzer

纯 Node.js（零依赖）的 Kubernetes 准入策略分析器。输入 Pod / Deployment 等工作负载、
一组有序策略、namespace 标签以及变更补丁，在本地模拟多轮 **mutate → validate** 的准入过程，
保留每一步发出的 JSON Patch 和拒绝原因，并把最终配置回写到工作负载对象。

## 能力范围

- 工作负载：`Pod`、`Deployment`、`StatefulSet`、`DaemonSet`、`ReplicaSet`、`Job`、`CronJob`
  （自动定位 pod template，init / 普通 / ephemeral 容器全部参与检查）
- 安全检查项：
  - `privileged` 特权容器
  - `hostNetwork` / `hostPID` / `hostIPC` 宿主命名空间
  - `hostPath` 卷挂载
  - 追加 capabilities（`securityContext.capabilities.add/drop`，含 pod 级与容器级合并、`ALL` 与 drop 抵消）
  - root 用户（`runAsUser: 0` 或未设置时的 kubelet 默认 root）
  - `allowPrivilegeEscalation` 显式开启
- 策略类型：`validating`（deny）与 `mutating`，按输入顺序执行；策略可绑定操作、资源类型、
  namespace 名称/标签，并支持按名称或标签选择器豁免
- 补丁：用户输入支持 RFC 6902 JSON Patch 与 strategic merge patch；mutation 策略输出 JSON Patch
- 多轮收敛：mutation 后自动再跑一轮，直到没有新补丁（默认上限 5 轮，防止非幂等策略死循环）

## 快速开始

```bash
node examples/basic.js
node --test
```

```js
import { analyzeAdmission } from './src/index.js';

const result = analyzeAdmission({
  workload: podObject,                 // Pod 或 Deployment 等
  namespace: { name: 'team-a', labels: { env: 'prod' } },
  patch: [{ op: 'add', path: '/spec/hostNetwork', value: true }], // 可选
  policies: [
    {
      name: 'harden',
      type: 'mutating',
      mutation: {
        hostNetwork: false,
        removeHostPathVolumes: true,
        dropCapabilities: ['NET_RAW'],
        containerSecurityContext: {
          privileged: false,
          allowPrivilegeEscalation: false,
          runAsNonRoot: true,
          runAsUser: 1000,
          capabilities: { add: ['CHOWN'], drop: ['NET_RAW'] },
        },
      },
    },
    {
      name: 'restricted',
      type: 'validating',
      exemptNamespaces: ['kube-system'],
      namespaceSelector: { matchLabels: { env: 'prod' } },
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
}, { operation: 'CREATE', maxRounds: 5 });

result.decision;            // 'allow' | 'deny'
result.trace;               // 全量有序步骤：input-patch / mutate / deny / allow / no-op / exempt
result.denial?.reasons;     // 拒绝原因数组（code、message、target JSON pointer）
result.finalObject;         // 最终配置回写后的完整工作负载
result.finalPodSpec;        // 便捷访问的 pod spec 子树
```

每个 trace 步骤都带有序号 `sequence`、所在轮次 `round`、策略名与策略类型；
mutate 步骤的 `patch` 是当次实际发出的 RFC 6902 操作深拷贝，可直接用于审计或回放。

## 策略字段

| 字段 | 说明 |
| --- | --- |
| `name` / `type` | 唯一名称；`validating`（也接受 `deny`）或 `mutating`（也接受 `mutate`） |
| `modes` | 绑定的操作，默认 `['CREATE', 'UPDATE']` |
| `resourceKinds` | 限定资源 kind，空数组表示全部 |
| `namespaces` | 仅作用于这些 namespace（白名单） |
| `exemptNamespaces` | 按 namespace 名称豁免 |
| `namespaceSelector` | `matchLabels` / `matchExpressions`（In、NotIn、Exists、DoesNotExist） |
| `exemptionNamespaceSelector` | 命中即豁免的标签选择器 |
| `rules` | validating 策略的检查开关，见上文六项 |
| `mutation` | mutating 策略的硬化动作，支持宿主命名空间标量、pod/容器 securityContext、capabilities、删除 hostPath 卷 |

## 顺序与冲突语义

- 默认严格按 `policies` 数组顺序执行，deny 策略一旦命中立即短路，后续策略不再运行。
- 同一轮里后执行的 mutating 策略覆盖先执行的结果（last-writer-wins），但两者的 patch 都保留在 trace 中。
- 被 `drop` 的 capability 仍允许被后续策略重新 `add`；forbidden 检查会先扣除 drop 集合。
- 重复执行同一 mutation 策略时，已存在的值不会再次出现在补丁中（集合语义，幂等）。
- 传入 `{ groupedPhases: true }` 可模拟真实集群“所有 mutating webhook 先于 validating webhook”的分阶段顺序。

## 明确不支持的真实 API Server 行为

本项目是**离线推理工具，不是一个准入 webhook**。以下真实行为被刻意简化或不实现：

1. 不发起、也不校验任何真实 HTTPS webhook 调用，不处理 `AdmissionReview` 的序列化、TLS、
   超时、失败策略（`failurePolicy`）与重注入（reinvocation）。
2. 不实现 `ValidatingAdmissionPolicy` 的 CEL 表达式、变量、参数资源（`paramRef`）与
   `matchConditions`；策略规则用声明式字段表达。
3. 不模拟 Pod Security Standards（PSS/Privacy）内置等级与命名空间 label 版本机制，
   只提供等价的六项原子检查。
4. 不实现完整的 strategic merge patch 语义：忽略 `patchMergeKey`/`patchStrategy` 指令，
   pod-spec 数组统一按 `name` 合并；不支持 `$retainKeys`、list-map 原子替换等高级语义。
5. 不模拟完整的 Linux capability 计算（如 bounding/ambient/inheritable 集合、文件权能、
   `CAP_AUDIT_WRITE` 默认集合）；仅按 `add`/`drop` 列表与 `ALL` 做集合推理。
6. 不处理 webhook 排序的真实规则（`reinvocationPolicy`、按名称排序、多 webhook 链式调用），
   顺序完全由输入数组决定；多轮“再注入”是本工具自己的固定重跑模型。
7. 不做 schema 校验、默认值填充（defaulting）、GVR 解析、RBAC 鉴权、quota 与其他准入插件
   （NodeRestriction、ServiceAccount、ResourceQuota 等）的联动。
8. 不支持 DELETE / CONNECT 等非对象操作的细节（`deleteOptions`、旧对象 `oldObject` 差异），
   `operation` 仅用于策略绑定过滤。
9. `hostPID`/`hostIPC` 仅支持 mutation 硬化与字段保留，没有对应的 deny 规则开关。
10. 不保证与任何特定 Kubernetes 版本的行为一致；升级 K8s 后请以真实集群审计结果为准。

## 目录结构

```
src/
  analyzer.js   # 多轮编排、trace、拒绝短路、最终回写
  policies.js   # namespace 匹配/豁免、deny 规则、mutation patch 生成
  workload.js   # pod template 定位、容器枚举、生效 securityContext 合并
  patch.js      # RFC 6902 JSON Patch 与简化 strategic merge
  index.js      # 公共导出与示例输入
test/           # node:test 测试（豁免、重复 patch、冲突、顺序、回写等）
examples/       # 可运行示例
```
