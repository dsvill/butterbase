/**
 * RLS isolation integration tests — F-14.
 *
 * Runs against the local data-plane Postgres (port 5435).  The connection role
 * ("butterbase" locally, "neondb_owner" on Neon) is a superuser with BYPASSRLS,
 * which is exactly the production posture.  Tests deliberately exercise the
 * fail-open path (raw pool.query) to prove it bypasses RLS, and then the
 * safe path (executeWithRole) to prove isolation is restored.
 *
 * See docs/rls-isolation.md for the design rationale.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import pg from 'pg';
import { executeWithRole } from '../services/rls-context.js';
import { config } from '../config.js';

// ─── Test DB connection ───────────────────────────────────────────────────────

// Use the data-plane DB; the butterbase superuser has BYPASSRLS there,
// mirroring the production Neon connection role.
const pool = new pg.Pool({
  host: config.dataPlaneDb.host,
  port: config.dataPlaneDb.port,
  user: config.dataPlaneDb.user,
  password: config.dataPlaneDb.password,
  database: 'butterbase_data',
});

const SCHEMA = `test_rls_isolation_${Date.now()}`;

const USER_A = '00000000-0000-0000-0000-000000000001';
const USER_B = '00000000-0000-0000-0000-000000000002';

// ─── Fixture setup / teardown ─────────────────────────────────────────────────

beforeAll(async () => {
  // Create an isolated schema so parallel test runs don't collide.
  await pool.query(`CREATE SCHEMA "${SCHEMA}"`);
  await pool.query(`SET search_path = "${SCHEMA}"`);

  // Ensure the RLS roles exist on this cluster (created by 006_rls_roles.sql).
  // If they're missing the test will fail with a descriptive PG error.
  await pool.query(`
    DO $$ BEGIN
      IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'butterbase_user') THEN
        RAISE EXCEPTION 'Role butterbase_user not found — run db/data-plane/006_rls_roles.sql first';
      END IF;
    END $$
  `);

  // Grant role membership so SET LOCAL ROLE works from our connection.
  for (const role of ['butterbase_anon', 'butterbase_user', 'butterbase_service']) {
    await pool.query(
      `GRANT ${role} TO "${config.dataPlaneDb.user}"`,
    ).catch(() => { /* already granted */ });
  }

  // Create the helper function used by RLS policies.
  await pool.query(`
    CREATE OR REPLACE FUNCTION "${SCHEMA}".current_user_id() RETURNS TEXT AS $$
      SELECT current_setting('request.jwt.claim.sub', true)
    $$ LANGUAGE sql STABLE
  `);

  // Main test table: user-scoped RLS.
  await pool.query(`
    CREATE TABLE "${SCHEMA}".notes (
      id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL,
      body    TEXT NOT NULL
    )
  `);
  await pool.query(`ALTER TABLE "${SCHEMA}".notes ENABLE ROW LEVEL SECURITY`);
  // butterbase_user can only see their own rows.
  await pool.query(`
    CREATE POLICY user_owns_notes ON "${SCHEMA}".notes
      FOR ALL TO butterbase_user
      USING (user_id = current_setting('request.jwt.claim.sub', true)::uuid)
      WITH CHECK (user_id = current_setting('request.jwt.claim.sub', true)::uuid)
  `);
  // butterbase_service sees everything (full bypass via policy).
  await pool.query(`
    CREATE POLICY service_full_access ON "${SCHEMA}".notes
      FOR ALL TO butterbase_service
      USING (true)
      WITH CHECK (true)
  `);
  // butterbase_anon: no policy → default-deny (no SELECT rows returned).

  // Grant access to the non-privileged roles.
  await pool.query(`GRANT USAGE ON SCHEMA "${SCHEMA}" TO butterbase_anon, butterbase_user, butterbase_service`);
  await pool.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON "${SCHEMA}".notes TO butterbase_anon, butterbase_user, butterbase_service`);
  await pool.query(`GRANT EXECUTE ON FUNCTION "${SCHEMA}".current_user_id() TO butterbase_user, butterbase_service`);

  // Seed two rows owned by different users.
  await pool.query(
    `INSERT INTO "${SCHEMA}".notes (user_id, body) VALUES ($1, $2), ($3, $4)`,
    [USER_A, 'note-from-A', USER_B, 'note-from-B'],
  );
}, 15_000);

afterAll(async () => {
  await pool.query(`DROP SCHEMA IF EXISTS "${SCHEMA}" CASCADE`);
  await pool.end();
});

// ─── Fail-open path: raw pool.query bypasses RLS ─────────────────────────────

describe('without executeWithRole (raw pool.query — BYPASSRLS)', () => {
  it('returns ALL rows regardless of user context — RLS is not enforced', async () => {
    const { rows } = await pool.query(`SELECT * FROM "${SCHEMA}".notes ORDER BY body`);
    expect(rows).toHaveLength(2);
    expect(rows.map((r: { body: string }) => r.body)).toEqual(['note-from-A', 'note-from-B']);
  });

  it('confirms the connection role has BYPASSRLS', async () => {
    const { rows } = await pool.query<{ rolbypassrls: boolean }>(
      `SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user`,
    );
    expect(rows[0].rolbypassrls).toBe(true);
  });
});

// ─── Safe path: executeWithRole enforces isolation ────────────────────────────

describe('with executeWithRole — butterbase_user', () => {
  it('user A sees only their own row', async () => {
    const rows = await executeWithRole(pool, 'butterbase_user', USER_A, async (client) => {
      const r = await client.query(`SELECT body FROM "${SCHEMA}".notes ORDER BY body`);
      return r.rows as { body: string }[];
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].body).toBe('note-from-A');
  });

  it('user B sees only their own row', async () => {
    const rows = await executeWithRole(pool, 'butterbase_user', USER_B, async (client) => {
      const r = await client.query(`SELECT body FROM "${SCHEMA}".notes ORDER BY body`);
      return r.rows as { body: string }[];
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].body).toBe('note-from-B');
  });

  it('user A cannot read user B\'s row even by id', async () => {
    // Fetch B's row id first using the bypass connection.
    const { rows: allRows } = await pool.query<{ id: string; user_id: string }>(
      `SELECT id, user_id FROM "${SCHEMA}".notes WHERE user_id = $1`, [USER_B],
    );
    const bRowId = allRows[0].id;

    const rows = await executeWithRole(pool, 'butterbase_user', USER_A, async (client) => {
      const r = await client.query(
        `SELECT body FROM "${SCHEMA}".notes WHERE id = $1`, [bRowId],
      );
      return r.rows;
    });
    expect(rows).toHaveLength(0);
  });

  it('write blocked: user A cannot insert a row owned by user B', async () => {
    await expect(
      executeWithRole(pool, 'butterbase_user', USER_A, async (client) => {
        await client.query(
          `INSERT INTO "${SCHEMA}".notes (user_id, body) VALUES ($1, $2)`,
          [USER_B, 'forgery'],
        );
      }),
    ).rejects.toThrow();
  });
});

describe('with executeWithRole — butterbase_service', () => {
  it('service role sees all rows (policy-granted full access)', async () => {
    const rows = await executeWithRole(pool, 'butterbase_service', null, async (client) => {
      const r = await client.query(`SELECT body FROM "${SCHEMA}".notes ORDER BY body`);
      return r.rows as { body: string }[];
    });
    expect(rows).toHaveLength(2);
  });
});

describe('with executeWithRole — butterbase_anon', () => {
  it('anon role sees no rows (default-deny: no policy grants access)', async () => {
    const rows = await executeWithRole(pool, 'butterbase_anon', null, async (client) => {
      const r = await client.query(`SELECT body FROM "${SCHEMA}".notes`);
      return r.rows;
    });
    expect(rows).toHaveLength(0);
  });
});
