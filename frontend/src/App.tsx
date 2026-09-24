import { lazy, Suspense } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { AppShell as Layout } from './components/layout/AppShell';
import { Login } from './routes/Login';
import { useAuth } from './lib/auth';

// All AionUi screens live in src/routes/ as the project's single
// page-path convention. S2.6 follow-up (R1 from the S2 retro) moved
// the Sprint 1 page stubs out of src/pages/ into src/routes/.
import { Dashboard } from './routes/Dashboard';
import { AssetsPage as Assets } from './routes/Assets';
import { IncidentsPage as Incidents } from './routes/Incidents';
import { Vulnerabilities } from './routes/Vulnerabilities';
import { SBOM } from './routes/SBOM';
import { CompliancePage as Compliance } from './routes/Compliance';
import { IntegrationsPage as Integrations } from './routes/Integrations';
import { SettingsPage as Settings } from './routes/Settings';
import { NotFoundPage as NotFound } from './routes/NotFound';
import { InfrastructureOverview } from './routes/InfrastructureOverview';
import { ClusterExplorer } from './routes/ClusterExplorer';
import { NamespaceExplorer } from './routes/NamespaceExplorer';
import { WorkloadExplorer } from './routes/WorkloadExplorer';
import { RuntimeSecurity } from './routes/RuntimeSecurity';
import { TopologyViewer } from './routes/TopologyViewer';
import { CostIntelligence } from './routes/CostIntelligence';
import { InfrastructureHealthPage as InfrastructureHealth } from './routes/InfrastructureHealth';
import { InfrastructureIncidents } from './routes/InfrastructureIncidents';

/**
 * DependencyGraph (and its `reactflow` + dagre-style layout bundle)
 * is heavy. Load it on demand so the initial SPA payload stays small.
 */
const Graph = lazy(() => import('./routes/Graph').then((m) => ({ default: m.Graph })));

function RouteFallback() {
  return (
    <div className="grid h-[60vh] place-items-center">
      <div className="aion-mono text-sm text-muted">loading…</div>
    </div>
  );
}

/**
 * App — root of the AionUi SPA.
 *
 * Routing model:
 *  - Component routes (Sprint 1 baseline).
 *  - The Dependency Graph route is the only lazy-loaded one; everything
 *    else is statically imported. Adding more lazy routes is a one-line
 *    change: hoist the import above and wrap in <Suspense>.
 *  - 404 catch-all.
 */
// Mocks stay the default (see lib/api.ts) so the app renders unauthenticated;
// only gate on login when talking to real services.
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false';

export default function App() {
  const { isAuthenticated } = useAuth();

  if (!USE_MOCKS && !isAuthenticated) {
    return <Login />;
  }

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="assets" element={<Assets />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="vulnerabilities" element={<Vulnerabilities />} />
        <Route path="vulnerabilities/timeline" element={<Vulnerabilities />} />
        <Route path="sbom" element={<SBOM />} />
        <Route path="sbom/:sbom_id" element={<SBOM />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="settings/*" element={<Settings />} />
        <Route path="infrastructure" element={<InfrastructureOverview />} />
        <Route path="infrastructure/clusters" element={<ClusterExplorer />} />
        <Route path="infrastructure/namespaces" element={<NamespaceExplorer />} />
        <Route path="infrastructure/workloads" element={<WorkloadExplorer />} />
        <Route path="infrastructure/runtime-security" element={<RuntimeSecurity />} />
        <Route path="infrastructure/topology" element={<TopologyViewer />} />
        <Route path="infrastructure/cost" element={<CostIntelligence />} />
        <Route path="infrastructure/health" element={<InfrastructureHealth />} />
        <Route path="infrastructure/incidents" element={<InfrastructureIncidents />} />
        <Route
          path="graph/:sbom_id?"
          element={
            <Suspense fallback={<RouteFallback />}>
              <Graph />
            </Suspense>
          }
        />
        <Route path="404" element={<NotFound />} />
        <Route path="*" element={<Navigate to="/404" replace />} />
      </Route>
    </Routes>
  );
}
