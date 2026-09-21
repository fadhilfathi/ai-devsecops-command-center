import { test, expect } from 'vitest';
import type {
  V1Pod,
  V1Deployment,
  V1Service,
  V1Ingress,
  V1Namespace,
  V1StatefulSet,
  V1DaemonSet,
} from '@kubernetes/client-node';
import {
  mapNamespace,
  mapPod,
  mapService,
  mapIngress,
  mapDeployment,
  mapStatefulSet,
  mapDaemonSet,
  parseCpuMillicores,
  parseMemoryBytes,
} from './k8s-mappers.js';

const TENANT = '11111111-1111-4111-8111-111111111111';
const CLUSTER = '22222222-2222-4222-8222-222222222222';
const CLUSTER_NAME = 'test-cluster';

test('parseCpuMillicores handles millicore and core forms', () => {
  expect(parseCpuMillicores('250m')).toBe(250);
  expect(parseCpuMillicores('1')).toBe(1000);
  expect(parseCpuMillicores('0.5')).toBe(500);
  expect(parseCpuMillicores(undefined)).toBe(0);
});

test('parseMemoryBytes handles binary and decimal suffixes', () => {
  expect(parseMemoryBytes('512Mi')).toBe(512 * 1024 * 1024);
  expect(parseMemoryBytes('1Gi')).toBe(1024 ** 3);
  expect(parseMemoryBytes('1000')).toBe(1000);
  expect(parseMemoryBytes(undefined)).toBe(0);
});

test('mapNamespace parses to a valid Namespace', () => {
  const ns: V1Namespace = {
    metadata: {
      uid: '33333333-3333-4333-8333-333333333333',
      name: 'default',
      creationTimestamp: new Date(),
    },
    status: { phase: 'Active' },
  };
  const mapped = mapNamespace(TENANT, CLUSTER, CLUSTER_NAME, ns);
  expect(mapped.name).toBe('default');
  expect(mapped.phase).toBe('active');
});

test('mapPod derives phase, restarts, and crash reason', () => {
  const pod: V1Pod = {
    metadata: {
      uid: '44444444-4444-4444-8444-444444444444',
      name: 'payments-api-abc',
      namespace: 'default',
      labels: { app: 'payments-api' },
    },
    spec: {
      containers: [
        {
          name: 'app',
          image: 'ghcr.io/example/payments-api:1.0',
          resources: { requests: { cpu: '250m', memory: '256Mi' } },
        },
      ],
      nodeName: 'node-1',
      serviceAccountName: 'default',
    },
    status: {
      phase: 'Running',
      podIP: '10.0.0.5',
      containerStatuses: [
        {
          name: 'app',
          image: 'ghcr.io/example/payments-api:1.0',
          imageID: '',
          ready: false,
          restartCount: 8,
          state: { waiting: { reason: 'CrashLoopBackOff' } },
        },
      ],
      conditions: [{ type: 'Ready', status: 'False' }],
    },
  };
  const mapped = mapPod(TENANT, CLUSTER, CLUSTER_NAME, pod);
  expect(mapped.phase).toBe('running');
  expect(mapped.restarts).toBe(8);
  expect(mapped.containers[0]?.lastTerminationReason).toBe('crash_loop_back_off');
  expect(mapped.node).toBe('node-1');
});

test('mapService maps type, ports, and namespace filtering fqdn', () => {
  const svc: V1Service = {
    metadata: {
      uid: '55555555-5555-4555-8555-555555555555',
      name: 'payments-api',
      namespace: 'prod',
    },
    spec: {
      type: 'ClusterIP',
      clusterIP: '10.96.0.10',
      selector: { app: 'payments-api' },
      ports: [{ port: 80, targetPort: 8080, protocol: 'TCP' }],
    },
  };
  const mapped = mapService(TENANT, CLUSTER, CLUSTER_NAME, svc);
  expect(mapped.type).toBe('cluster_ip');
  expect(mapped.ports[0]?.port).toBe(80);
  expect(mapped.fqdn).toBe('payments-api.prod.svc.cluster.local');
});

test('mapIngress flattens rules and hosts', () => {
  const ing: V1Ingress = {
    metadata: { uid: '66666666-6666-4666-8666-666666666666', name: 'public', namespace: 'default' },
    spec: {
      ingressClassName: 'nginx',
      rules: [
        {
          host: 'api.example.com',
          http: {
            paths: [
              {
                path: '/payments',
                pathType: 'Prefix',
                backend: { service: { name: 'payments-api', port: { number: 80 } } },
              },
            ],
          },
        },
      ],
      tls: [{ hosts: ['api.example.com'], secretName: 'api-tls' }],
    },
  };
  const mapped = mapIngress(TENANT, CLUSTER, CLUSTER_NAME, ing);
  expect(mapped.className).toBe('nginx');
  expect(mapped.rules[0]).toMatchObject({
    host: 'api.example.com',
    serviceName: 'payments-api',
    servicePort: 80,
  });
  expect(mapped.tls[0]?.hosts).toEqual(['api.example.com']);
});

test('mapDeployment computes replicas and rollout status', () => {
  const dep: V1Deployment = {
    metadata: {
      uid: '77777777-7777-4777-8777-777777777777',
      name: 'payments-api',
      namespace: 'default',
    },
    spec: {
      replicas: 3,
      selector: { matchLabels: { app: 'payments-api' } },
      template: {
        spec: { containers: [{ name: 'app', image: 'ghcr.io/example/payments-api:1.0' }] },
      },
    },
    status: { readyReplicas: 3, updatedReplicas: 3, availableReplicas: 3 },
  };
  const mapped = mapDeployment(TENANT, CLUSTER, CLUSTER_NAME, dep);
  expect(mapped.replicas).toEqual({ desired: 3, ready: 3, updated: 3, available: 3 });
  expect(mapped.health).toBe('healthy');
  expect(mapped.rollout).toBe('complete');
  expect(mapped.image).toBe('ghcr.io/example/payments-api:1.0');
});

test('mapStatefulSet and mapDaemonSet parse to valid workloads', () => {
  const sts: V1StatefulSet = {
    metadata: {
      uid: '88888888-8888-4888-8888-888888888888',
      name: 'postgres',
      namespace: 'default',
    },
    spec: {
      replicas: 1,
      serviceName: 'postgres-hl',
      selector: { matchLabels: { app: 'postgres' } },
      template: { spec: { containers: [{ name: 'db', image: 'postgres:16' }] } },
    },
    status: { replicas: 1, readyReplicas: 1, currentReplicas: 1 },
  };
  const mappedSts = mapStatefulSet(TENANT, CLUSTER, CLUSTER_NAME, sts);
  expect(mappedSts.serviceName).toBe('postgres-hl');
  expect(mappedSts.replicas.ready).toBe(1);

  const ds: V1DaemonSet = {
    metadata: {
      uid: '99999999-9999-4999-8999-999999999999',
      name: 'fluentbit',
      namespace: 'kube-system',
    },
    spec: {
      selector: { matchLabels: { app: 'fluentbit' } },
      template: { spec: { containers: [{ name: 'fb', image: 'fluent/fluent-bit:2.2' }] } },
    },
    status: {
      desiredNumberScheduled: 3,
      currentNumberScheduled: 3,
      numberReady: 3,
      numberMisscheduled: 0,
    },
  };
  const mappedDs = mapDaemonSet(TENANT, CLUSTER, CLUSTER_NAME, ds);
  expect(mappedDs.desiredNumberScheduled).toBe(3);
  expect(mappedDs.replicas.desired).toBe(3);
});
