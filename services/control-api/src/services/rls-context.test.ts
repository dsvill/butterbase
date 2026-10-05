import { describe, it, expect, vi, beforeEach } from 'vitest';
import { executeWithRole } from './rls-context.js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─── Mock pg.Pool ─────────────────────────────────────────────────────────────

function makeMockClient() {
  return {
    query: vi.fn().mockResolvedValue({ rows: [], rowCount: 0 }),
    release: vi.fn(),
  };
}

function makeMockPool(client: ReturnType<typeof makeMockClient>) {
  return { connect: vi.fn().mockResolvedValue(client) } as any;
}

// ─── executeWithRole unit tests ───────────────────────────────────────────────

describe('executeWithRole', () => {
  let client: ReturnType<typeof makeMockClient>;
  let pool: ReturnType<typeof makeMockPool>;

  beforeEach(() => {
    client = makeMockClient();
    pool = makeMockPool(client);
  });

  function queriesIssued(): string[] {
    return client.query.mock.calls.map((c: unknown[]) => c[0] as string);
  }

  it('opens a transaction before switching role', async () => {
    await executeWithRole(pool, 'butterbase_user', 'uid-1', async () => 'x');
    const qs = queriesIssued();
    expect(qs.indexOf('BEGIN')).toBeLessThan(
      qs.findIndex((q: string) => q.startsWith('SET LOCAL ROLE')),
    );
  });

  it('issues SET LOCAL ROLE for the requested role', async () => {
    await executeWithRole(pool, 'butterbase_user', 'uid-1', async () => null);
    expect(queriesIssued()).toContain('SET LOCAL ROLE butterbase_user');
  });

  it('issues SET LOCAL app.role for the requested role', async () => {
    await executeWithRole(pool, 'butterbase_anon', null, async () => null);
    expect(queriesIssued()).toContain("SET LOCAL app.role = 'butterbase_anon'");
  });

  it('sets request.jwt.claim.sub for butterbase_user with a userId', async () => {
    await executeWithRole(pool, 'butterbase_user', 'user-abc-123', async () => null);
    expect(queriesIssued().some((q: string) => q.includes('request.jwt.claim.sub') && q.includes('user-abc-123'))).toBe(true);
  });

  it('does NOT set request.jwt.claim.sub for butterbase_anon', async () => {
    await executeWithRole(pool, 'butterbase_anon', null, async () => null);
    expect(queriesIssued().every((q: string) => !q.includes('request.jwt.claim.sub'))).toBe(true);
  });

  it('does NOT set request.jwt.claim.sub for butterbase_service', async () => {
    await executeWithRole(pool, 'butterbase_service', null, async () => null);
    expect(queriesIssued().every((q: string) => !q.includes('request.jwt.claim.sub'))).toBe(true);
  });

  it('commits on success', async () => {
    await executeWithRole(pool, 'butterbase_user', 'uid-1', async () => 'ok');
    const qs = queriesIssued();
    expect(qs).toContain('COMMIT');
    expect(qs).not.toContain('ROLLBACK');
  });

  it('rolls back and rethrows on error from the query function', async () => {
    await expect(
      executeWithRole(pool, 'butterbase_user', 'uid-1', async () => {
        throw new Error('query exploded');
      }),
    ).rejects.toThrow('query exploded');
    const qs = queriesIssued();
    expect(qs).toContain('ROLLBACK');
    expect(qs).not.toContain('COMMIT');
  });

  it('releases the client on success', async () => {
    await executeWithRole(pool, 'butterbase_user', 'uid-1', async () => null);
    expect(client.release).toHaveBeenCalledOnce();
  });

  it('releases the client even when the query function throws', async () => {
    await expect(
      executeWithRole(pool, 'butterbase_user', 'uid-1', async () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow();
    expect(client.release).toHaveBeenCalledOnce();
  });

  it('returns the value from the query function', async () => {
    const result = await executeWithRole(pool, 'butterbase_user', 'uid-1', async () => 42);
    expect(result).toBe(42);
  });

  it('SQL-escapes single quotes in userId (doubles them) to prevent injection', async () => {
    await executeWithRole(pool, 'butterbase_user', "user'; DROP TABLE users; --", async () => null);
    const subQuery = queriesIssued().find((q: string) => q.includes('request.jwt.claim.sub'))!;
    // The single quote is doubled — it's a string literal, not a statement terminator.
    expect(subQuery).toContain("user''; DROP TABLE users; --");
    // The value is enclosed in single quotes (valid SQL string literal).
    expect(subQuery).toMatch(/SET LOCAL request\.jwt\.claim\.sub = '.*'/);
  });
});

// ─── Duplication audit ────────────────────────────────────────────────────────
//
// auto-api.ts and rag.ts each define a private copy of executeWithRole instead
// of importing from rls-context.ts.  These tests document that known state and
// guard against silent divergence — if the copies drift from the canonical
// implementation, the string-comparison tests below will fail and draw attention.
//
// See docs/rls-isolation.md §"Duplicate implementations" for context and the
// consolidation plan.

describe('executeWithRole source-code duplication audit', () => {
  const routesDir = path.resolve(__dirname, '../routes');
  const canonicalSrc = fs.readFileSync(
    path.resolve(__dirname, 'rls-context.ts'),
    'utf-8',
  );

  // Extract the body of a private executeWithRole from a source file, if present.
  function extractLocalImpl(src: string): string | null {
    const marker = 'async function executeWithRole<T>';
    const start = src.indexOf(marker);
    if (start === -1) return null;
    // Find matching closing brace (naive but stable for this shape)
    let depth = 0;
    let i = src.indexOf('{', start);
    const bodyStart = i;
    for (; i < src.length; i++) {
      if (src[i] === '{') depth++;
      else if (src[i] === '}') { depth--; if (depth === 0) break; }
    }
    return src.slice(bodyStart, i + 1).replace(/\s+/g, ' ').trim();
  }

  const canonicalBody = extractLocalImpl(canonicalSrc)!;

  it('auto-api.ts has a private executeWithRole (known duplication)', () => {
    const src = fs.readFileSync(path.join(routesDir, 'auto-api.ts'), 'utf-8');
    const local = extractLocalImpl(src);
    expect(local, 'auto-api.ts no longer has a local copy — remove this test and the duplication note in the doc').not.toBeNull();
  });

  it('rag.ts has a private executeWithRole (known duplication)', () => {
    const src = fs.readFileSync(path.join(routesDir, 'rag.ts'), 'utf-8');
    const local = extractLocalImpl(src);
    expect(local, 'rag.ts no longer has a local copy — remove this test and the duplication note in the doc').not.toBeNull();
  });

  it('auto-api.ts private copy body is identical to the canonical rls-context.ts body', () => {
    const src = fs.readFileSync(path.join(routesDir, 'auto-api.ts'), 'utf-8');
    const local = extractLocalImpl(src)!;
    expect(local).toBe(canonicalBody);
  });

  it('rag.ts private copy is functionally equivalent to the canonical body (differs only in param name and whitespace)', () => {
    // rag.ts uses 'fn' instead of 'queryFn' and omits inline comments — cosmetically different,
    // functionally identical. Check the behaviorally-load-bearing patterns instead of exact text.
    const src = fs.readFileSync(path.join(routesDir, 'rag.ts'), 'utf-8');
    const local = extractLocalImpl(src)!;
    expect(local).toMatch(/client\.query\('BEGIN'\)/);
    expect(local).toMatch(/SET LOCAL ROLE \$\{role\}/);
    expect(local).toMatch(/SET LOCAL app\.role = '\$\{role\}'/);
    expect(local).toMatch(/request\.jwt\.claim\.sub/);
    expect(local).toMatch(/role === 'butterbase_user' && userId/);
    expect(local).toMatch(/client\.query\('COMMIT'\)/);
    expect(local).toMatch(/client\.query\('ROLLBACK'\)/);
    expect(local).toMatch(/client\.release\(\)/);
  });

  it('builtin-dispatcher.ts imports from rls-context (no local copy)', () => {
    const src = fs.readFileSync(
      path.resolve(__dirname, 'agent-tools/builtin-dispatcher.ts'),
      'utf-8',
    );
    expect(src).toMatch(/import.*executeWithRole.*from.*rls-context/);
    expect(extractLocalImpl(src)).toBeNull();
  });
});
