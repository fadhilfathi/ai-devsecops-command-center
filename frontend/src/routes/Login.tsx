import { useState, type FormEvent } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { Card } from '@/components/ui/Card';
import { login } from '@/lib/auth';

/**
 * Login — dev-login gate (S6-2). Only shown when `VITE_USE_MOCKS=false`
 * and the user has no token; posts to auth-service's `POST /v1/auth/dev-login`.
 */
export function Login() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(email);
    } catch {
      setError('Login failed. Check the email and that auth-service is reachable.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="grid h-full place-items-center bg-aion-bg">
      <Card className="w-80">
        <Card.Header title="AI-DevSecOps Command Center" subtitle="Sign in to continue" />
        <Card.Body>
          <form onSubmit={handleSubmit} className="flex flex-col gap-3">
            <label className="text-xs text-aion-muted" htmlFor="login-email">
              Email
            </label>
            <input
              id="login-email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@aicc.local"
              className="w-full rounded-md border border-aion-border bg-aion-surface2 px-2.5 py-1.5 text-sm text-aion-text placeholder:text-aion-muted focus:border-aion-accent/50 focus:outline-none focus:ring-1 focus:ring-aion-accent/30"
            />
            {error && <p className="text-xs text-aion-danger">{error}</p>}
            <Button type="submit" variant="primary" size="md" disabled={submitting}>
              <ShieldCheck className="h-4 w-4" />
              {submitting ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </Card.Body>
      </Card>
    </div>
  );
}
