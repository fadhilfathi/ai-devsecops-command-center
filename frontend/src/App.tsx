import { Component, lazy, Suspense, type ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { AppShell as Layout } from './components/layout/AppShell';
import { Login } from './routes/Login';
import { NotFoundPage as NotFound } from './routes/NotFound';
import { useAuth } from './lib/auth';

// All AionUi screens live in src/routes/ as the project's single
// page-path convention. S2.6 follow-up (R1 from the S2 retro) moved
// the Sprint 1 page stubs out of src/pages/ into src/routes/.
//
// S9-3: every page route is lazy-loaded (one `<Suspense>` at the Routes
// level) so `recharts`/`reactflow`-heavy pages (Compliance, Vulnerabilities,
// TopologyViewer, Graph, CostIntelligence...) only ship to the browser when
// visited, instead of bloating the main chunk. Login and NotFound stay
// eager — they're on the unauthenticated/error path where an extra chunk
// round-trip isn't worth it.
const Dashboard = lazy(() => import('./routes/Dashboard').then((m) => ({ default: m.Dashboard })));
const Assets = lazy(() => import('./routes/Assets').then((m) => ({ default: m.AssetsPage })));
const Incidents = lazy(() =>
  import('./routes/Incidents').then((m) => ({ default: m.IncidentsPage })),
);
const Vulnerabilities = lazy(() =>
  import('./routes/Vulnerabilities').then((m) => ({ default: m.Vulnerabilities })),
);
const Remediation = lazy(() =>
  import('./routes/Remediation').then((m) => ({ default: m.Remediation })),
);
const SBOM = lazy(() => import('./routes/SBOM').then((m) => ({ default: m.SBOM })));
const Compliance = lazy(() =>
  import('./routes/Compliance').then((m) => ({ default: m.CompliancePage })),
);
const Integrations = lazy(() =>
  import('./routes/Integrations').then((m) => ({ default: m.IntegrationsPage })),
);
const Settings = lazy(() => import('./routes/Settings').then((m) => ({ default: m.SettingsPage })));
const InfrastructureOverview = lazy(() =>
  import('./routes/InfrastructureOverview').then((m) => ({ default: m.InfrastructureOverview })),
);
const ClusterExplorer = lazy(() =>
  import('./routes/ClusterExplorer').then((m) => ({ default: m.ClusterExplorer })),
);
const NamespaceExplorer = lazy(() =>
  import('./routes/NamespaceExplorer').then((m) => ({ default: m.NamespaceExplorer })),
);
const WorkloadExplorer = lazy(() =>
  import('./routes/WorkloadExplorer').then((m) => ({ default: m.WorkloadExplorer })),
);
const RuntimeSecurity = lazy(() =>
  import('./routes/RuntimeSecurity').then((m) => ({ default: m.RuntimeSecurity })),
);
const TopologyViewer = lazy(() =>
  import('./routes/TopologyViewer').then((m) => ({ default: m.TopologyViewer })),
);
const CostIntelligence = lazy(() =>
  import('./routes/CostIntelligence').then((m) => ({ default: m.CostIntelligence })),
);
const InfrastructureHealth = lazy(() =>
  import('./routes/InfrastructureHealth').then((m) => ({ default: m.InfrastructureHealthPage })),
);
const InfrastructureIncidents = lazy(() =>
  import('./routes/InfrastructureIncidents').then((m) => ({
    default: m.InfrastructureIncidents,
  })),
);
const Graph = lazy(() => import('./routes/Graph').then((m) => ({ default: m.Graph })));

function RouteFallback() {
  return (
    <div className="grid h-[60vh] place-items-center">
      <div className="aion-mono text-sm text-muted">loading…</div>
    </div>
  );
}

// ---- Route-level error boundary (S9-3) -----------------------------------
// Every page route is a dynamic import (see the `lazy(...)` calls above);
// after a redeploy, a stale tab's cached HTML/JS can request a chunk that
// no longer exists on the server. Detect that case (Vite/webpack's
// `ChunkLoadError` or the message browsers throw for a failed dynamic
// `import()`) and tell the user to reload instead of showing a generic
// crash message.

/** Pure so it's testable without jsdom/testing-library (neither is in this
 * project — see App.routes.test.ts). */
export function isChunkLoadError(error: Error): boolean {
  return (
    error.name === 'ChunkLoadError' ||
    error.message.includes('Failed to fetch dynamically imported module')
  );
}

/** Pure so it's testable without jsdom/testing-library. */
export function routeErrorMessage(error: Error): string {
  return isChunkLoadError(error)
    ? 'The app was updated — reload to get the latest version.'
    : 'Something went wrong loading this page.';
}

type RouteErrorBoundaryState = { error: Error | null };

class RouteErrorBoundary extends Component<{ children: ReactNode }, RouteErrorBoundaryState> {
  state: RouteErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): RouteErrorBoundaryState {
    return { error };
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="grid h-[60vh] place-items-center">
        <div className="text-center">
          <p className="mb-3 text-sm text-muted">{routeErrorMessage(error)}</p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="rounded-md border border-border bg-surface-2 px-3 py-1.5 text-sm text-text hover:bg-surface"
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}

/**
 * App — root of the AionUi SPA.
 *
 * Routing model:
 *  - Every page route is `React.lazy` (S9-3), wrapped in one `<Suspense>`
 *    around the whole `<Routes>` tree — the app shell (Layout), Login and
 *    NotFound stay eager.
 *  - 404 catch-all.
 */
// Mocks stay the default (see lib/api.ts) so the app renders unauthenticated;
// only gate on login when talking to real services.
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS !== 'false';

export default function App() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();

  if (!USE_MOCKS && !isAuthenticated) {
    return <Login />;
  }

  return (
    <RouteErrorBoundary key={location.pathname}>
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="assets" element={<Assets />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="vulnerabilities/timeline" element={<Vulnerabilities />} />
            <Route path="remediation" element={<Remediation />} />
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
            <Route path="graph/:sbom_id?" element={<Graph />} />
            <Route path="404" element={<NotFound />} />
            <Route path="*" element={<Navigate to="/404" replace />} />
          </Route>
        </Routes>
      </Suspense>
    </RouteErrorBoundary>
  );
}
