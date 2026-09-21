/**
 * Pure mappers from `@kubernetes/client-node` API objects to AICC
 * `infrastructure/*` models. Every mapper is total (undefined-safe)
 * and ends with `Schema.parse()` so a bad mapping fails loudly
 * instead of shipping malformed data to the dashboard.
 */
import { randomUUID } from 'node:crypto';
import type {
  V1Namespace,
  V1Pod,
  V1Container,
  V1ContainerStatus,
  V1Service,
  V1Ingress,
  V1Deployment,
  V1StatefulSet,
  V1DaemonSet,
} from '@kubernetes/client-node';
import {
  NamespaceSchema,
  type Namespace,
  PodSchema,
  type Pod,
  type PodPhase,
  type PodTerminationReason,
  type Container,
  ServiceSchema,
  type Service,
  type ServiceType,
  IngressSchema,
  type Ingress,
  type IngressClass,
  DeploymentSchema,
  type Deployment,
  DaemonSetSchema,
  type DaemonSet,
  StatefulSetSchema,
  type StatefulSet,
  type WorkloadHealth,
} from '@aicc/models';

const NOW = (): string => new Date().toISOString();

function toId(uid: string | undefined): string {
  return uid && /^[0-9a-f-]{36}$/i.test(uid) ? uid : randomUUID();
}

function isoOrNow(date: Date | string | undefined): string {
  if (!date) return NOW();
  return typeof date === 'string' ? date : date.toISOString();
}

/** Parses a Kubernetes CPU quantity (`"250m"`, `"1"`, `"0.5"`) into millicores. */
export function parseCpuMillicores(qty: string | undefined): number {
  if (!qty) return 0;
  if (qty.endsWith('m')) return Math.round(parseFloat(qty)) || 0;
  const cores = parseFloat(qty);
  return Number.isFinite(cores) ? Math.round(cores * 1000) : 0;
}

const MEMORY_SUFFIXES: Record<string, number> = {
  Ki: 1024,
  Mi: 1024 ** 2,
  Gi: 1024 ** 3,
  Ti: 1024 ** 4,
  Pi: 1024 ** 5,
  Ei: 1024 ** 6,
  k: 1000,
  M: 1000 ** 2,
  G: 1000 ** 3,
  T: 1000 ** 4,
  P: 1000 ** 5,
  E: 1000 ** 6,
};

/** Parses a Kubernetes memory quantity (`"512Mi"`, `"1Gi"`, `"1024"`) into bytes. */
export function parseMemoryBytes(qty: string | undefined): number {
  if (!qty) return 0;
  for (const [suffix, multiplier] of Object.entries(MEMORY_SUFFIXES)) {
    if (qty.endsWith(suffix)) {
      const n = parseFloat(qty.slice(0, -suffix.length));
      return Number.isFinite(n) ? Math.round(n * multiplier) : 0;
    }
  }
  const n = parseFloat(qty);
  return Number.isFinite(n) ? Math.round(n) : 0;
}

function aggregateResources(containers: V1Container[] | undefined): {
  cpuRequestsMillicores: number;
  cpuLimitsMillicores: number;
  memoryRequestsBytes: number;
  memoryLimitsBytes: number;
} {
  let cpuRequestsMillicores = 0;
  let cpuLimitsMillicores = 0;
  let memoryRequestsBytes = 0;
  let memoryLimitsBytes = 0;
  for (const c of containers ?? []) {
    cpuRequestsMillicores += parseCpuMillicores(c.resources?.requests?.cpu);
    cpuLimitsMillicores += parseCpuMillicores(c.resources?.limits?.cpu);
    memoryRequestsBytes += parseMemoryBytes(c.resources?.requests?.memory);
    memoryLimitsBytes += parseMemoryBytes(c.resources?.limits?.memory);
  }
  return { cpuRequestsMillicores, cpuLimitsMillicores, memoryRequestsBytes, memoryLimitsBytes };
}

function healthFromReplicas(ready: number, desired: number): WorkloadHealth {
  if (desired === 0) return 'unknown';
  if (ready === desired) return 'healthy';
  if (ready === 0) return 'unhealthy';
  return 'degraded';
}

const TERMINATION_REASON_MAP: Record<string, PodTerminationReason> = {
  CrashLoopBackOff: 'crash_loop_back_off',
  ImagePullBackOff: 'image_pull_back_off',
  ErrImagePull: 'err_image_pull',
  ErrImageNeverPull: 'err_image_never_pull',
  CreateContainerConfigError: 'create_container_config_error',
  InvalidImageName: 'invalid_image_name',
  OOMKilled: 'oom_killed',
  Evicted: 'evicted',
  NodeLost: 'node_lost',
  NodePressure: 'node_pressure',
  Completed: 'completed',
  Error: 'error',
  ContainerStatusUnknown: 'container_status_unknown',
};

function mapTerminationReason(reason: string | undefined): PodTerminationReason {
  if (!reason) return 'unknown';
  return TERMINATION_REASON_MAP[reason] ?? 'unknown';
}

function containerTerminationReason(status: V1ContainerStatus | undefined): PodTerminationReason {
  const reason =
    status?.state?.waiting?.reason ?? status?.state?.terminated?.reason ?? status?.lastState?.terminated?.reason;
  return mapTerminationReason(reason);
}

function mapContainers(pod: V1Pod): Container[] {
  const specContainers = pod.spec?.containers ?? [];
  const statuses = pod.status?.containerStatuses ?? [];
  const hostPathVolumes = new Set(
    (pod.spec?.volumes ?? []).filter((v) => v.hostPath).map((v) => v.name),
  );
  return specContainers.map((c) => {
    const status = statuses.find((s) => s.name === c.name);
    const state = status?.state?.running ? 'running' : status?.state?.terminated ? 'terminated' : 'waiting';
    return {
      name: c.name,
      image: c.image ?? 'unknown',
      state,
      ready: status?.ready ?? false,
      restartCount: status?.restartCount ?? 0,
      lastTerminationReason: containerTerminationReason(status),
      resources: {
        cpuRequestsMillicores: parseCpuMillicores(c.resources?.requests?.cpu),
        cpuLimitsMillicores: parseCpuMillicores(c.resources?.limits?.cpu),
        memoryRequestsBytes: parseMemoryBytes(c.resources?.requests?.memory),
        memoryLimitsBytes: parseMemoryBytes(c.resources?.limits?.memory),
      },
      privileged: c.securityContext?.privileged ?? false,
      runAsRoot: c.securityContext?.runAsNonRoot === false || c.securityContext?.runAsUser === 0,
      addedCapabilities: c.securityContext?.capabilities?.add ?? [],
      hostPaths: (c.volumeMounts ?? []).filter((vm) => hostPathVolumes.has(vm.name)).map((vm) => vm.mountPath),
    };
  });
}

const POD_PHASE_MAP: Record<string, PodPhase> = {
  Pending: 'pending',
  Running: 'running',
  Succeeded: 'succeeded',
  Failed: 'failed',
  Unknown: 'unknown',
};

const POD_CONDITION_TYPE_MAP: Record<string, string> = {
  PodScheduled: 'pod_scheduled',
  Ready: 'ready',
  Initialized: 'initialized',
  ContainersReady: 'containers_ready',
};

export function mapNamespace(
  tenantId: string,
  clusterId: string,
  clusterName: string,
  ns: V1Namespace,
): Namespace {
  return NamespaceSchema.parse({
    id: toId(ns.metadata?.uid),
    tenantId,
    clusterId,
    clusterName,
    name: ns.metadata?.name ?? 'unknown',
    uid: ns.metadata?.uid,
    phase: ns.status?.phase === 'Terminating' ? 'terminating' : 'active',
    labels: ns.metadata?.labels ?? {},
    annotations: ns.metadata?.annotations ?? {},
    createdAt: isoOrNow(ns.metadata?.creationTimestamp),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  });
}

export function mapPod(tenantId: string, clusterId: string, clusterName: string, pod: V1Pod): Pod {
  const containers = mapContainers(pod);
  const statuses = pod.status?.containerStatuses ?? [];
  const restarts = statuses.reduce((sum, s) => sum + (s.restartCount ?? 0), 0);
  const podTerminationReason =
    containers.map((c) => c.lastTerminationReason).find((r) => r !== 'unknown') ?? 'unknown';
  const owner = pod.metadata?.ownerReferences?.[0];
  return PodSchema.parse({
    id: toId(pod.metadata?.uid),
    tenantId,
    clusterId,
    clusterName,
    namespace: pod.metadata?.namespace ?? 'default',
    name: pod.metadata?.name ?? 'unknown',
    uid: pod.metadata?.uid,
    phase: POD_PHASE_MAP[pod.status?.phase ?? ''] ?? 'unknown',
    node: pod.spec?.nodeName,
    podIp: pod.status?.podIP,
    ownerKind: owner?.kind,
    ownerName: owner?.name,
    serviceAccount: pod.spec?.serviceAccountName,
    containers: containers.length > 0 ? containers : [
      { name: 'unknown', image: 'unknown', state: 'waiting', ready: false, restartCount: 0, lastTerminationReason: 'unknown' },
    ],
    conditions: (pod.status?.conditions ?? []).map((c) => ({
      type: POD_CONDITION_TYPE_MAP[c.type] ?? 'pod_scheduled',
      status: (c.status?.toLowerCase() as 'true' | 'false' | 'unknown') ?? 'unknown',
      message: c.message,
      lastTransitionTime: isoOrNow(c.lastTransitionTime),
    })),
    restarts,
    startedAt: pod.status?.startTime ? isoOrNow(pod.status.startTime) : undefined,
    lastTerminationReason: podTerminationReason,
    labels: pod.metadata?.labels ?? {},
    annotations: pod.metadata?.annotations ?? {},
    createdAt: isoOrNow(pod.metadata?.creationTimestamp),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  });
}

const SERVICE_TYPE_MAP: Record<string, ServiceType> = {
  ClusterIP: 'cluster_ip',
  NodePort: 'node_port',
  LoadBalancer: 'load_balancer',
  ExternalName: 'external_name',
};

export function mapService(tenantId: string, clusterId: string, clusterName: string, svc: V1Service): Service {
  const namespace = svc.metadata?.namespace ?? 'default';
  const name = svc.metadata?.name ?? 'unknown';
  return ServiceSchema.parse({
    id: toId(svc.metadata?.uid),
    tenantId,
    clusterId,
    clusterName,
    namespace,
    name,
    uid: svc.metadata?.uid,
    type: SERVICE_TYPE_MAP[svc.spec?.type ?? ''] ?? 'cluster_ip',
    clusterIp: svc.spec?.clusterIP,
    externalIp: svc.spec?.externalIPs ?? [],
    selector: svc.spec?.selector ?? {},
    ports: (svc.spec?.ports ?? []).map((p) => ({
      name: p.name,
      protocol: p.protocol ?? 'TCP',
      port: p.port,
      targetPort: p.targetPort,
      nodePort: p.nodePort,
    })),
    endpoints: [],
    fqdn: `${name}.${namespace}.svc.cluster.local`,
    sessionAffinity: svc.spec?.sessionAffinity === 'ClientIP' ? 'client_ip' : 'none',
    // ponytail: no ready-endpoint data without a separate Endpoints call; add when the topology view needs it.
    hasReadyEndpoints: false,
    ingressIds: [],
    labels: svc.metadata?.labels ?? {},
    createdAt: isoOrNow(svc.metadata?.creationTimestamp),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  });
}

const INGRESS_CLASS_VALUES: IngressClass[] = ['nginx', 'nginx_internal', 'traefik', 'istio', 'alb', 'gce', 'kong'];

export function mapIngress(tenantId: string, clusterId: string, clusterName: string, ing: V1Ingress): Ingress {
  const className = ing.spec?.ingressClassName;
  const rules = (ing.spec?.rules ?? []).flatMap((rule) =>
    (rule.http?.paths ?? []).map((path) => ({
      host: rule.host,
      path: path.path ?? '/',
      pathType: (path.pathType as 'Exact' | 'Prefix' | 'ImplementationSpecific') ?? 'Prefix',
      serviceName: path.backend.service?.name ?? 'unknown',
      servicePort: path.backend.service?.port?.number ?? path.backend.service?.port?.name ?? 0,
    })),
  );
  return IngressSchema.parse({
    id: toId(ing.metadata?.uid),
    tenantId,
    clusterId,
    clusterName,
    namespace: ing.metadata?.namespace ?? 'default',
    name: ing.metadata?.name ?? 'unknown',
    uid: ing.metadata?.uid,
    className: INGRESS_CLASS_VALUES.includes(className as IngressClass) ? (className as IngressClass) : 'unknown',
    rules,
    tls: (ing.spec?.tls ?? []).map((t) => ({ hosts: t.hosts ?? [], secretName: t.secretName })),
    defaultBackend: ing.spec?.defaultBackend?.service
      ? {
          serviceName: ing.spec.defaultBackend.service.name,
          servicePort: ing.spec.defaultBackend.service.port?.number ?? ing.spec.defaultBackend.service.port?.name ?? 0,
        }
      : undefined,
    labels: ing.metadata?.labels ?? {},
    createdAt: isoOrNow(ing.metadata?.creationTimestamp),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  });
}

function workloadBase(
  tenantId: string,
  clusterId: string,
  clusterName: string,
  meta: { namespace?: string; name?: string; uid?: string; labels?: Record<string, string>; creationTimestamp?: Date },
  containers: V1Container[] | undefined,
  replicas: { desired: number; ready: number; updated: number; available: number },
  conditions: { type: string; status: string; message?: string; lastTransitionTime?: Date }[],
) {
  return {
    id: toId(meta.uid),
    tenantId,
    clusterId,
    clusterName,
    namespace: meta.namespace ?? 'default',
    name: meta.name ?? 'unknown',
    uid: meta.uid,
    image: containers?.[0]?.image,
    replicas,
    health: healthFromReplicas(replicas.ready, replicas.desired),
    conditions: conditions.map((c) => ({
      type: c.type,
      status: (c.status?.toLowerCase() as 'true' | 'false' | 'unknown') ?? 'unknown',
      message: c.message,
      lastTransitionTime: isoOrNow(c.lastTransitionTime),
    })),
    labels: meta.labels ?? {},
    resources: aggregateResources(containers),
    createdAt: isoOrNow(meta.creationTimestamp),
    updatedAt: NOW(),
    lastSyncedAt: NOW(),
  };
}

export function mapDeployment(tenantId: string, clusterId: string, clusterName: string, dep: V1Deployment): Deployment {
  const desired = dep.spec?.replicas ?? 0;
  const ready = dep.status?.readyReplicas ?? 0;
  const base = workloadBase(
    tenantId,
    clusterId,
    clusterName,
    dep.metadata ?? {},
    dep.spec?.template?.spec?.containers,
    { desired, ready, updated: dep.status?.updatedReplicas ?? 0, available: dep.status?.availableReplicas ?? 0 },
    dep.status?.conditions ?? [],
  );
  return DeploymentSchema.parse({
    ...base,
    kind: 'deployment',
    strategy: dep.spec?.strategy?.type === 'Recreate' ? 'recreate' : 'rolling_update',
    rollingUpdate: {
      maxSurge: dep.spec?.strategy?.rollingUpdate?.maxSurge,
      maxUnavailable: dep.spec?.strategy?.rollingUpdate?.maxUnavailable,
    },
    terminatingReplicas: dep.status?.terminatingReplicas ?? 0,
    rollout: dep.spec?.paused
      ? 'paused'
      : desired === 0
        ? 'unknown'
        : ready >= desired
          ? 'complete'
          : 'progressing',
    changeCause: dep.metadata?.annotations?.['kubernetes.io/change-cause'],
    revisionHistoryLimit: dep.spec?.revisionHistoryLimit,
    paused: dep.spec?.paused ?? false,
  });
}

export function mapStatefulSet(
  tenantId: string,
  clusterId: string,
  clusterName: string,
  sts: V1StatefulSet,
): StatefulSet {
  const desired = sts.spec?.replicas ?? 0;
  const base = workloadBase(
    tenantId,
    clusterId,
    clusterName,
    sts.metadata ?? {},
    sts.spec?.template?.spec?.containers,
    {
      desired,
      ready: sts.status?.readyReplicas ?? 0,
      updated: sts.status?.updatedReplicas ?? 0,
      available: sts.status?.currentReplicas ?? 0,
    },
    sts.status?.conditions ?? [],
  );
  return StatefulSetSchema.parse({
    ...base,
    kind: 'statefulset',
    serviceName: sts.spec?.serviceName ?? `${base.name}-headless`,
    podManagementPolicy: sts.spec?.podManagementPolicy === 'Parallel' ? 'parallel' : 'ordered_ready',
    updateStrategy: sts.spec?.updateStrategy?.type === 'OnDelete' ? 'on_delete' : 'rolling_update',
    volumeClaimTemplates: (sts.spec?.volumeClaimTemplates ?? []).map((pvc) => ({
      name: pvc.metadata?.name ?? 'data',
      storageClassName: pvc.spec?.storageClassName,
      sizeBytes: parseMemoryBytes(pvc.spec?.resources?.requests?.storage),
      accessModes: (pvc.spec?.accessModes as ('ReadWriteOnce' | 'ReadOnlyMany' | 'ReadWriteMany')[] | undefined) ?? [
        'ReadWriteOnce',
      ],
    })),
    currentRevision: sts.status?.currentRevision,
    updateRevision: sts.status?.updateRevision,
  });
}

export function mapDaemonSet(tenantId: string, clusterId: string, clusterName: string, ds: V1DaemonSet): DaemonSet {
  const desired = ds.status?.desiredNumberScheduled ?? 0;
  const base = workloadBase(
    tenantId,
    clusterId,
    clusterName,
    ds.metadata ?? {},
    ds.spec?.template?.spec?.containers,
    {
      desired,
      ready: ds.status?.numberReady ?? 0,
      updated: ds.status?.updatedNumberScheduled ?? 0,
      available: ds.status?.numberAvailable ?? 0,
    },
    ds.status?.conditions ?? [],
  );
  return DaemonSetSchema.parse({
    ...base,
    kind: 'daemonset',
    updateStrategy: ds.spec?.updateStrategy?.type === 'OnDelete' ? 'on_delete' : 'rolling_update',
    desiredNumberScheduled: ds.status?.desiredNumberScheduled ?? 0,
    currentNumberScheduled: ds.status?.currentNumberScheduled ?? 0,
    numberReady: ds.status?.numberReady ?? 0,
    numberMisscheduled: ds.status?.numberMisscheduled ?? 0,
  });
}
