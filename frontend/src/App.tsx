import { AppRoutes } from "./routes";

/**
 * AionUi — AI-DevSecOps Command Center frontend.
 *
 * The application is intentionally minimal at the top level: routing,
 * error boundary, and global providers. All real UI lives inside the
 * layout components and the per-screen page modules.
 */
export default function App() {
  return <AppRoutes />;
}
