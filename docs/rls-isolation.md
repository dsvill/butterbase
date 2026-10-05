# RLS Isolation Design

Row-Level Security (RLS) on the data-plane database lets end-user apps ship
user-scoped data access without writing `WHERE user_id = $uid` on every query.
This document covers how it works, where the fail-open risk lives, and what the
tests cover.

## How it works

Every app database runs on a Postgres cluster where the connection role
(`neondb_owner` on Neon, `butterbase` locally) has `BYPASSRLS`. This is
required for administrative operations (migrations, backups, provisioning) but
means **any raw `pool.query()` call from application code ignores all RLS
policies completely**.

To enforce RLS, every app-data query must go through `executeWithRole`, which:

1. Opens a transaction (`BEGIN`)
2. Switches to a non-privileged role (`SET LOCAL ROLE <role>`) — this makes
   Postgres evaluate RLS policies for that role
3. Sets GUC variables the policies read:
   - `app.role` — which role class is active
   - `request.jwt.claim.sub` — the authenticated user's ID (for
     `butterbase_user` only); read by `current_user_id()` inside policy
     `USING` expressions
4. Runs the caller-supplied query function
5. Commits (or rolls back on error)

The three roles and their intended policy coverage:

| Role | Who uses it | Default policy |
|------|-------------|----------------|
| `butterbase_user` | Authenticated end-user | See only rows where `user_id = current_user_id()` |
| `butterbase_anon` | Unauthenticated access | Default-deny (no rows unless an explicit anon policy exists) |
| `butterbase_service` | Internal platform operations | Full access via a catch-all `USING (true)` service policy |

## The fail-open design

The system is **fail-open by design**: forgetting `executeWithRole` is not a
compile-time error. A route that calls `pool.query()` directly will execute as
the BYPASSRLS superuser and return every row in the table to whoever asked,
regardless of their user ID or role.

This is a deliberate trade-off: the alternative (making the connection role
unprivileged) breaks migrations, schema introspection, and provisioning. The
mitigation is:

- Every app-data route handler **must** call `executeWithRole` before touching
  user data.
- The integration tests in `src/__tests__/rls-isolation.test.ts` demonstrate
  the fail-open path explicitly (a raw `pool.query` returns all rows) and then
  prove isolation is restored with `executeWithRole`.

## Call sites

There are currently **19 call sites** of `executeWithRole` across three files:

| File | Calls | Source |
|------|-------|--------|
| `src/routes/auto-api.ts` | 5 | private local copy |
| `src/routes/rag.ts` | 9 | private local copy |
| `src/services/agent-tools/builtin-dispatcher.ts` | 5 | imports from `rls-context.ts` |

## Duplicate implementations

`executeWithRole` is defined three times:

1. **`src/services/rls-context.ts`** — the canonical implementation, exported.
2. **`src/routes/auto-api.ts`** — private copy; predates the extraction to
   `rls-context.ts`.
3. **`src/routes/rag.ts`** — private copy; same origin.

All three are currently byte-for-byte identical in behavior. The unit tests in
`src/services/rls-context.test.ts` include a source-comparison assertion that
will fail if any copy drifts from the canonical — making silent divergence
visible before it becomes a security issue.

**Consolidation plan:** import `executeWithRole` from `rls-context.ts` in both
`auto-api.ts` and `rag.ts` and delete the local copies. This is a mechanical
change with no behavioral impact. Tracked separately to keep this PR focused on
tests and documentation.

## Adding RLS to a new route

1. Accept `pool` from the route context (data-plane pool for the target app).
2. Resolve the role and `userId` from the request auth object.
3. Wrap every data query in `executeWithRole(pool, role, userId, ...)`.
4. Never call `pool.query()` or `client.query()` directly on the data pool
   outside of the `executeWithRole` callback.

## Running the tests

Unit tests (no DB required):

```bash
cd services/control-api
npm test -- --reporter=verbose src/services/rls-context.test.ts
```

Integration tests (requires local Docker stack — `npm run e2e:bootstrap`):

```bash
npm run test:integration -- --reporter=verbose src/__tests__/rls-isolation.test.ts
```
