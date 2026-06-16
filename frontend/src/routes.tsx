import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { DashboardPage } from "./pages/Dashboard";
import { AssetsPage } from "./pages/Assets";
import { IncidentsPage } from "./pages/Incidents";
import { VulnerabilitiesPage } from "./pages/Vulnerabilities";
import { SBOMPage } from "./pages/SBOM";
import { CompliancePage } from "./pages/Compliance";
import { IntegrationsPage } from "./pages/Integrations";
import { SettingsPage } from "./pages/Settings";
import { NotFoundPage } from "./pages/NotFound";
import { InfrastructureOverview } from "./routes/InfrastructureOverview";
import { ClusterExplorer } from "./routes/ClusterExplorer";
import { NamespaceExplorer } from "./routes/NamespaceExplorer";
import { WorkloadExplorer } from "./routes/WorkloadExplorer";
import { RuntimeSecurity } from "./routes/RuntimeSecurity";
import { TopologyViewer } from "./routes/TopologyViewer";
import { CostIntelligence } from "./routes/CostIntelligence";
import { InfrastructureHealthPage } from "./routes/InfrastructureHealth";
import { InfrastructureIncidents } from "./routes/InfrastructureIncidents";

/**
 * Centralized route table for the AionUi SPA.
 *
 * Sprint-1 scope: every screen renders a fully-laid-out skeleton with
 * realistic mock data, but the data layer is wired through `lib/api.ts`
 * so swapping in real backend responses is a one-line change per hook.
 *
 * Sprint-4 additions: the Infrastructure Intelligence workstream
 * ships nine new dashboard modules under `/infrastructure/...`.
 */
export function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardPage />} />
        <Route path="assets" element={<AssetsPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="sbom" element={<SBOMPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="settings" element={<SettingsPage />} />

        {/* Sprint 4 — Infrastructure Intelligence */}
        <Route path="infrastructure" element={<InfrastructureOverview />} />
        <Route path="infrastructure/clusters" element={<ClusterExplorer />} />
        <Route path="infrastructure/namespaces" element={<NamespaceExplorer />} />
        <Route path="infrastructure/workloads" element={<WorkloadExplorer />} />
        <Route path="infrastructure/runtime-security" element={<RuntimeSecurity />} />
        <Route path="infrastructure/topology" element={<TopologyViewer />} />
        <Route path="infrastructure/cost" element={<CostIntelligence />} />
        <Route path="infrastructure/health" element={<InfrastructureHealthPage />} />
        <Route path="infrastructure/incidents" element={<InfrastructureIncidents />} />

        <Route path="404" element={<NotFoundPage />} />
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Route>
    </Routes>
  );
}
