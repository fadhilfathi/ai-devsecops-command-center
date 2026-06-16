import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { KpiGrid, KpiTile } from "@/components/ui/KpiTile";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { api } from "@/lib/api";
import { useFetch } from "@/hooks/useFetch";
import { fmtNumber, titleCase, fmtBytes } from "@/lib/format";
import type { Cluster, Node } from "@/types/infrastructure";

const nodeColumns: Column<Node & { key: string }>[] = [
  { key: "name", header: "Node", cell: (n) => <span className="font-medium">{n.name}</span> },
  { key: "roles", header: "Roles", cell: (n) => n.roles.join(", ") || "—" },
  { key: "kubeletVersion", header: "Kubelet", cell: (n) => n.kubeletVersion ?? "—" },
  { key: "architecture", header: "Arch", cell: (n) => n.architecture ?? "—" },
  {
    key: "conditions",
    header: "Conditions",
    cell: (n) => (
      <div className="flex flex-wrap gap-1">
        {n.conditions.length === 0 && <span className="text-aion-muted">—</span>}
        {n.conditions.map((c) => (
          <Badge key={c} variant={c === "ready" ? "ok" : "warn"}>{c}</Badge>
        ))}
        {n.unschedulable && <Badge variant="danger">unschedulable</Badge>}
      </div>
    ),
  },
];

/**
 * Cluster Explorer — drill into a single cluster's nodes,
 * namespaces, and resource summary.
 */
export function ClusterExplorer() {
  const { data: clusters } = useFetch(api.kubernetesClusters, { items: [], total: 0 });
  const firstId = clusters.items[0]?.id;
  const { data: namespaces } = useFetch(() => firstId ? api.kubernetesNamespaces(firstId) : { items: [], total: 0 }, { items: [], total: 0 });
  const { data: health } = useFetch(api.healthClusters, { items: [], total: 0 });
  const cluster = clusters.items[0];
  const clusterHealth = health.items.find((h) => h.subject.clusterId === cluster?.id);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Cluster Explorer"
        subtitle="Drill into a single cluster's nodes, namespaces, and resource summary."
        breadcrumbs={[{ label: "Infrastructure" }, { label: "Clusters" }]}
      />

      {cluster ? (
        <>
          <KpiGrid>
            <KpiTile label="Provider" value={titleCase(cluster.provider)} hint={cluster.region ?? "—"} />
            <KpiTile label="K8s version" value={cluster.k8sVersion ?? "—"} />
            <KpiTile label="Nodes" value={`${cluster.readyNodes}/${cluster.nodeCount}`} hint="ready / total" />
            <KpiTile label="CPU" value={`${cluster.totalCpuCores} cores`} />
            <KpiTile label="Memory" value={fmtBytes(cluster.totalMemoryBytes)} />
            <KpiTile label="Health" value={clusterHealth ? `${clusterHealth.score.score} (${clusterHealth.score.band})` : "—"} />
          </KpiGrid>

          <Card>
            <Card.Header title={`Nodes — ${cluster.name}`} subtitle="Ready nodes, conditions, and unschedulable state" />
            <Card.Body>
              <DataTable
                rows={cluster.nodes.map((n) => ({ ...n, key: n.name }))}
                columns={nodeColumns}
                rowKey={(n) => n.name}
              />
            </Card.Body>
          </Card>

          <Card>
            <Card.Header title="Namespaces" subtitle={`${namespaces.items.length} namespace(s) on this cluster`} />
            <Card.Body>
              <DataTable
                rows={namespaces.items.map((n) => ({ ...n, key: n.id }))}
                columns={[
                  { key: "name", header: "Name", cell: (n) => <span className="font-medium">{n.name}</span> },
                  { key: "workloadCount", header: "Workloads", cell: (n) => fmtNumber(n.workloadCount) },
                  { key: "podCount", header: "Pods", cell: (n) => fmtNumber(n.podCount) },
                  { key: "runningPods", header: "Running", cell: (n) => fmtNumber(n.runningPods) },
                  { key: "pendingPods", header: "Pending", cell: (n) => fmtNumber(n.pendingPods) },
                  { key: "failedPods", header: "Failed", cell: (n) => <span className={n.failedPods > 0 ? "text-severity-high" : ""}>{fmtNumber(n.failedPods)}</span> },
                  { key: "restartsLast1h", header: "Restarts 1h", cell: (n) => fmtNumber(n.restartsLast1h) },
                ]}
                rowKey={(n) => n.id}
              />
            </Card.Body>
          </Card>
        </>
      ) : (
        <Card><Card.Body><div className="text-sm text-aion-muted">No clusters onboarded yet.</div></Card.Body></Card>
      )}
    </div>
  );
}
