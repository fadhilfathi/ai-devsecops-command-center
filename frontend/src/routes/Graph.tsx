import { useParams } from "react-router-dom";
import { PageHeader } from "@/components/ui/PageHeader";
import { DependencyGraph } from "@/components/security/DependencyGraph";
import { Card } from "@/components/ui/Card";

/**
 * Graph — `/graph/:sbom_id?`
 *
 * Sprint 2 / S2.6 visualization #4 host route. The actual
 * DependencyGraph (and its reactflow dependency) is lazy-loaded by
 * `App.tsx` so the heavy bundle does not land in the initial SPA
 * payload. This thin wrapper exists for two reasons:
 *
 *  1. The `reactflow` CSS import is scoped to this chunk.
 *  2. We get a stable `sbom_id` from the URL, with a default fallback.
 */
export function Graph() {
  const { sbom_id } = useParams<{ sbom_id: string }>();
  const sbomId = sbom_id ?? "default";

  return (
    <div>
      <PageHeader
        title="Dependency Graph"
        subtitle="Interactive view of components and their dependency relations. Red borders mark vulnerable components."
        breadcrumbs={[
          { label: "AionUi" },
          { label: "SBOM" },
          { label: sbomId },
        ]}
      />

      <Card>
        <Card.Body>
          <DependencyGraph sbomId={sbomId} />
        </Card.Body>
      </Card>
    </div>
  );
}
