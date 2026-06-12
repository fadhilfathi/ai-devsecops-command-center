/**
 * User repository — Sprint 1 in-memory implementation.
 *
 * Will be replaced by a Postgres-backed repository in Sprint 2.
 */
import type { User, UserRole, UUID } from '@aicc/shared';

export interface UserRepository {
  list(): Promise<User[]>;
  findById(id: UUID): Promise<User | undefined>;
  findByEmail(email: string): Promise<User | undefined>;
  create(input: { email: string; displayName: string; role: UserRole; tenantId: UUID }): Promise<User>;
  setActive(id: UUID, active: boolean): Promise<User | undefined>;
}

export function buildUserRepository(): UserRepository {
  const now = () => new Date().toISOString();
  const users = new Map<UUID, User>();

  // Seed a platform admin for local development.
  const seedId = '00000000-0000-4000-8000-000000000001';
  users.set(seedId, {
    id: seedId,
    tenantId: '00000000-0000-4000-8000-000000000000',
    email: 'admin@aicc.local',
    displayName: 'Platform Admin',
    role: 'platform_admin',
    active: true,
    createdAt: now(),
    updatedAt: now(),
  });

  function newId(): UUID {
    return globalThis.crypto?.randomUUID?.() ??
      'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
      });
  }

  return {
    async list() {
      return Array.from(users.values());
    },
    async findById(id) {
      return users.get(id);
    },
    async findByEmail(email) {
      for (const u of users.values()) if (u.email === email) return u;
      return undefined;
    },
    async create(input) {
      const id = newId();
      const ts = now();
      const user: User = { id, ...input, active: true, createdAt: ts, updatedAt: ts };
      users.set(id, user);
      return user;
    },
    async setActive(id, active) {
      const u = users.get(id);
      if (!u) return undefined;
      const updated: User = { ...u, active, updatedAt: now() };
      users.set(id, updated);
      return updated;
    },
  };
}
