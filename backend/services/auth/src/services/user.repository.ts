/**
 * User repository — in-memory default, Postgres when `DATABASE_URL` is set.
 *
 * No credential store exists yet: `POST /v1/auth/dev-login` is a
 * password-less email lookup, so `User` carries no password field and neither
 * implementation hashes or stores one. Both seed the same platform-admin row
 * (the migration seeds it for Postgres) because that row is the only login
 * path today.
 */
import type { User, UserRole, UUID } from '@aicc/shared';
import type { Queryable } from '@aicc/shared/db';

export interface CreateUserInput {
  email: string;
  displayName: string;
  role: UserRole;
  tenantId: UUID;
}

export interface UserRepository {
  list(): Promise<User[]>;
  findById(id: UUID): Promise<User | undefined>;
  findByEmail(email: string): Promise<User | undefined>;
  create(input: CreateUserInput): Promise<User>;
  setActive(id: UUID, active: boolean): Promise<User | undefined>;
}

function newId(): UUID {
  return (
    globalThis.crypto?.randomUUID?.() ??
    'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = (Math.random() * 16) | 0;
      return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    })
  );
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

interface UserRow {
  id: UUID;
  tenant_id: UUID;
  email: string;
  display_name: string;
  role: UserRole;
  active: boolean;
  created_at: string;
  updated_at: string;
}

function rowToUser(row: UserRow): User {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    active: row.active,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

export function buildPgUserRepository(db: Queryable): UserRepository {
  return {
    async list() {
      const { rows } = await db.query<UserRow>('SELECT * FROM users ORDER BY created_at ASC');
      return rows.map(rowToUser);
    },
    async findById(id) {
      const { rows } = await db.query<UserRow>('SELECT * FROM users WHERE id = $1', [id]);
      return rows[0] ? rowToUser(rows[0]) : undefined;
    },
    async findByEmail(email) {
      const { rows } = await db.query<UserRow>('SELECT * FROM users WHERE email = $1', [email]);
      return rows[0] ? rowToUser(rows[0]) : undefined;
    },
    async create(input) {
      const { rows } = await db.query<UserRow>(
        `INSERT INTO users (id, tenant_id, email, display_name, role, active)
         VALUES ($1, $2, $3, $4, $5, true)
         RETURNING *`,
        [newId(), input.tenantId, input.email, input.displayName, input.role],
      );
      return rowToUser(rows[0]!);
    },
    async setActive(id, active) {
      const { rows } = await db.query<UserRow>(
        'UPDATE users SET active = $2, updated_at = now() WHERE id = $1 RETURNING *',
        [id, active],
      );
      return rows[0] ? rowToUser(rows[0]) : undefined;
    },
  };
}
