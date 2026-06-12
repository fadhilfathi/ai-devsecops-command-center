import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell as Layout } from "./components/layout/AppShell";

// All AionUi screens live in src/routes/ as the project's single
// page-path convention. S2.6 follow-up (R1 from the S2 retro) moved
// the Sprint 1 page stubs out of src/pages/ into src/routes/.
import { Dashboard } from "./routes/Dashboard";
import { Assets } from "./routes/Assets";
import { Incidents } from "./routes/Incidents";
import { Vulnerabilities } from "./routes/Vulnerabilities";
import { SBOM } from "./routes/SBOM";
import { Compliance } from "./routes/Compliance";
import { Integrations } from "./routes/Integrations";
import { Settings } from "./routes/Settings";
import { NotFound } from "./routes/NotFound";

/**
 * DependencyGraph (and its `reactflow` + dagre-style layout bundle)
 * is heavy. Load it on demand so the initial SPA payload stays small.
 */
const Graph = lazy(() =>
  import("./routes/Graph").then((m) => ({ default: m.Graph }))
);

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
export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="assets" element={<Assets />} />
        <Route path="incidents" element={<Incidents />} />
        <Route
          path="vulnerabilities"
          element={<Vulnerabilities />}
        />
        <Route
          path="vulnerabilities/timeline"
          element={<Vulnerabilities />}
        />
        <Route path="sbom" element={<SBOM />} />
        <Route path="sbom/:sbom_id" element={<SBOM />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="integrations" element={<Integrations />} />
        <Route path="settings/*" element={<Settings />} />
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
