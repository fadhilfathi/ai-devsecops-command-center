import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { Button } from "@/components/ui/Button";

export function NotFoundPage() {
  return (
    <div className="grid place-items-center py-24 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-md border border-aion-border bg-aion-surface2 text-aion-muted">
        <Compass className="h-6 w-6" />
      </div>
      <h1 className="mt-4 text-2xl font-semibold text-aion-text">404</h1>
      <p className="mt-1 text-sm text-aion-muted">
        That screen doesn't exist in the AionUi SPA.
      </p>
      <Link to="/" className="mt-4">
        <Button variant="primary" size="sm">
          Back to dashboard
        </Button>
      </Link>
    </div>
  );
}
