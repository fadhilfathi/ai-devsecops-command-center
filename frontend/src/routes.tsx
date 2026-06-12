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

/**
 * Centralized route table for the AionUi SPA.
 *
 * Sprint-1 scope: every screen renders a fully-laid-out skeleton with
 * realistic mock data, but the data layer is wired through `lib/api.ts`
 * so swapping in real backend responses is a one-line change per hook.
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
        <Route path="404" element={<NotFoundPage />} />
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Route>
    </Routes>
  );
}
