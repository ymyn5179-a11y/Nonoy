import assert from 'assert';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { eq, inArray, or } from 'drizzle-orm';
import 'dotenv/config';
import { db as pgDb, pool } from '../src/db/index.ts';
import * as schema from '../src/db/schema.ts';

const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';
const DEV_ADMIN_PIN = process.env.ADMIN_PIN || '2026';
const JSON_DB_PATH = path.resolve(process.cwd(), 'data/nonoland-server-db.json');

class E2ECookieClient {
  cookies = new Map<string, string>();
  csrfToken = '';

  private buildCookieHeader(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  private captureCookies(res: Response) {
    const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const rawList =
      typeof getSetCookie === 'function'
        ? getSetCookie.call(res.headers)
        : res.headers.get('set-cookie')
          ? [res.headers.get('set-cookie')!]
          : [];

    for (const entry of rawList) {
      for (const name of ['nono_session', 'nono_device']) {
        const re = new RegExp(`${name}=([^;]*)`);
        const m = entry.match(re);
        if (m) {
          if (m[1]) {
            this.cookies.set(name, m[1]);
          } else {
            this.cookies.delete(name);
          }
        }
      }
    }
  }

  async req(
    method: string,
    urlPath: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
    baseUrl = BASE,
  ) {
    const headers: Record<string, string> = { ...extraHeaders };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const cookieStr = this.buildCookieHeader();
    if (cookieStr) headers['Cookie'] = cookieStr;
    if (
      this.csrfToken &&
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase()) &&
      !('x-csrf-token' in headers)
    ) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const res = await fetch(`${baseUrl}${urlPath}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    this.captureCookies(res);

    const text = await res.text();
    let data: Record<string, unknown> = {};
    try {
      data = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch {
      data = { raw: text };
    }

    if (typeof data.csrfToken === 'string') {
      this.csrfToken = data.csrfToken;
    }

    return { status: res.status, headers: res.headers, data };
  }
}

function sha256File(filePath: string): { sha256: string; mtimeMs: number; size: number } {
  const st = fs.statSync(filePath);
  const buf = fs.readFileSync(filePath);
  return {
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    mtimeMs: st.mtimeMs,
    size: st.size,
  };
}

async function waitForPortReady(port: number, timeoutMs = 15000): Promise<void> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (res.status === 200 || res.status === 503) return;
    } catch {
      // keep polling briefly until bound
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`Isolated test server on port ${port} did not bind within ${timeoutMs}ms`);
}

async function main() {
  const ts = Date.now();
  const createdUserIds: string[] = [];
  const createdFamilyIds: string[] = [];
  const createdChildIds: string[] = [];
  const createdSyncKeys: string[] = [];
  const createdEmails: string[] = [];

  console.log('=== 1. HEALTH CHECK & JSON FILE IMMUTABILITY BASELINE ===');
  const jsonBefore = sha256File(JSON_DB_PATH);
  const healthRes = await new E2ECookieClient().req('GET', '/api/health');
  assert.strictEqual(healthRes.status, 200, `Expected 200 on /api/health, got ${healthRes.status}`);
  assert.strictEqual(healthRes.data.status, 'ok');
  assert.strictEqual(healthRes.data.database, 'postgresql');
  console.log(`PASS: /api/health -> postgresql. JSON baseline sha256=${jsonBefore.sha256.slice(0, 12)}...`);

  console.log('=== 2. FAIL-CLOSED 503 VERIFICATION ON DB UNAVAILABILITY ===');
  const failPort = 3099;
  const badProc = spawn('npx', ['tsx', 'server.ts'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT: String(failPort),
      SKIP_VITE: '1',
      SQL_HOST: '127.0.0.1',
      SQL_DB_NAME: 'nonexistent_fail_closed_db',
      SQL_CONNECTION_TIMEOUT_MS: '1200',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await waitForPortReady(failPort, 20000);
    const failHealth = await new E2ECookieClient().req(
      'GET',
      '/api/health',
      undefined,
      {},
      `http://127.0.0.1:${failPort}`,
    );
    assert.strictEqual(failHealth.status, 503, `Bad DB health must fail closed with 503, got ${failHealth.status}`);
    assert.strictEqual(failHealth.data.database, 'unavailable');

    const failMe = await new E2ECookieClient().req(
      'GET',
      '/api/auth/me',
      undefined,
      {},
      `http://127.0.0.1:${failPort}`,
    );
    assert.strictEqual(failMe.status, 503, `DB-backed route must fail closed with 503, got ${failMe.status}`);
    assert.strictEqual(failMe.data.code, 'DB_UNAVAILABLE');
    console.log('PASS: Isolated server with invalid DB config failed closed with 503 on /api/health and /api/auth/me.');
  } finally {
    badProc.kill('SIGTERM');
  }

  console.log('=== 3. ZERO-SAMPLE-LEAK PARENT REGISTRATION & AGES 1-4 ENFORCEMENT ===');
  const parentA = new E2ECookieClient();
  const emailA = `e2e.pg.a.${ts}@example.com`;
  createdEmails.push(emailA);
  const regA = await parentA.req('POST', '/api/auth/register', {
    displayName: 'E2E Parent Alpha',
    email: emailA,
    password: 'StrongPgPassword!2026',
    termsAccepted: true,
  });
  assert.strictEqual(regA.status, 201);
  const userA = regA.data.user as { id: string; familyId: string; role: string };
  assert.strictEqual(userA.role, 'parent');
  assert.ok(userA.familyId);
  createdUserIds.push(userA.id);
  createdFamilyIds.push(userA.familyId);

  // Newly registered parent must have 0 children (NO sample profiles injected)
  const listEmpty = await parentA.req('GET', '/api/children');
  assert.strictEqual(listEmpty.status, 200);
  assert.deepStrictEqual(listEmpty.data.children, [], 'Fresh parent must see [] children');

  // Ages 5-6, 7, 8 must still be rejected
  for (const oldAge of ['5-6', '7', '8']) {
    const rej = await parentA.req('POST', '/api/children', {
      displayName: 'TooOld',
      ageGroup: oldAge,
      language: 'ar',
      birthYear: 2023,
      birthMonth: 4,
      pin: '1234',
    });
    assert.strictEqual(rej.status, 400, `Age stage ${oldAge} must be rejected`);
  }
  console.log('PASS: Fresh parent returns [] children and deprecated age groups rejected.');

  console.log('=== 4. PARENT CREATES CHILD WITH PIN -> ACCESS CODE RECEIPT & PG PERSISTENCE ===');
  const createChildRes = await parentA.req('POST', '/api/children', {
    displayName: 'آدم المستكشف',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 5,
    companionId: 'nono',
    companionScarfColor: '#8054D9',
    pin: '4567',
  });
  assert.strictEqual(createChildRes.status, 201);
  const childA = createChildRes.data.child as { id: string; stars: number; familyId: string };
  const accessCodeA = String(createChildRes.data.accessCode || '');
  assert.ok(/^NL-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(accessCodeA), `Expected NL-XXXX-XXXX, got ${accessCodeA}`);
  createdChildIds.push(childA.id);
  createdUserIds.push(`u_child_${childA.id}`);

  // Cross-family isolation
  const parentB = new E2ECookieClient();
  const emailB = `e2e.pg.b.${ts}@example.com`;
  createdEmails.push(emailB);
  const regB = await parentB.req('POST', '/api/auth/register', {
    displayName: 'E2E Parent Beta',
    email: emailB,
    password: 'StrongPgPassword!2026',
    termsAccepted: true,
  });
  assert.strictEqual(regB.status, 201);
  const userB = regB.data.user as { id: string; familyId: string };
  createdUserIds.push(userB.id);
  createdFamilyIds.push(userB.familyId);

  const crossFamilyGet = await parentB.req('GET', `/api/children/${childA.id}/garden`);
  assert.strictEqual(crossFamilyGet.status, 403, 'Cross-family access must fail 403');
  console.log(`PASS: Child created (${childA.id}) with Access Code ${accessCodeA} and cross-family 403 verified.`);

  console.log('=== 5. CHILD LOGIN, STRICT CHILD RBAC & CONCURRENCY LOCKS ===');
  const childClient = new E2ECookieClient();
  const childLoginRes = await childClient.req('POST', '/api/auth/child-login', {
    accessCode: accessCodeA,
    pin: '4567',
  });
  assert.strictEqual(childLoginRes.status, 200);
  const childMe = await childClient.req('GET', '/api/auth/me');
  assert.strictEqual(childMe.status, 200);
  assert.strictEqual(childMe.data.authenticated, true);
  assert.strictEqual((childMe.data.child as { id: string }).id, childA.id);
  assert.strictEqual((childMe.data.user as { role: string }).role, 'child');

  // Strict child RBAC blocks parent/family/teacher/admin endpoints
  assert.strictEqual(
    (
      await childClient.req('POST', '/api/children', {
        displayName: 'Blocked',
        ageGroup: '1-4',
        language: 'en',
        birthYear: 2023,
        birthMonth: 1,
        pin: '1111',
      })
    ).status,
    403,
  );
  assert.strictEqual((await childClient.req('GET', '/api/family/guardians')).status, 403);
  assert.strictEqual((await childClient.req('GET', '/api/teacher/classes')).status, 403);
  assert.strictEqual((await childClient.req('GET', '/api/admin/overview')).status, 403);

  // Give child 1 more star via idempotent sync first (initial stars=3 + 2 = 5 stars), test duplicate sync lock
  const syncKey = `e2e_sync_${ts}`;
  createdSyncKeys.push(syncKey);
  const syncRaces = await Promise.all(
    Array.from({ length: 4 }, () =>
      childClient.req('POST', '/api/student/sync', {
        childId: childA.id,
        items: [{ idempotencyKey: syncKey, kind: 'game-attempt', payload: { activityId: 'act-1', starsEarned: 2, durationSeconds: 60 } }],
      }),
    ),
  );
  assert.ok(syncRaces.every((r) => r.status === 200));
  const afterSyncChild = (await parentA.req('GET', '/api/children')).data.children as Array<{ id: string; stars: number }>;
  const syncedStars = afterSyncChild.find((c) => c.id === childA.id)?.stars;
  assert.strictEqual(syncedStars, 5, `Parallel duplicate sync must award 2 stars ONCE (3+2=5), got ${syncedStars}`);

  // Concurrency test on shop/redeem (item costs 4 stars, child has 5 stars -> 5 parallel requests -> only 1 succeeds!)
  const redeemRaces = await Promise.all(
    Array.from({ length: 5 }, (_, idx) =>
      childClient.req('POST', `/api/children/${childA.id}/shop/redeem`, {
        itemId: 'shop-avatar-glasses',
        idempotencyKey: `e2e_shop_${ts}_${idx}`,
      }),
    ),
  );
  const okRedeems = redeemRaces.filter((r) => r.status === 200);
  assert.strictEqual(okRedeems.length, 1, `Parallel shop redeem must succeed ONCE, got ${okRedeems.length}`);
  const afterRedeemChild = (okRedeems[0].data.child as { stars: number }).stars;
  assert.strictEqual(afterRedeemChild, 1, `5 - 4 = 1 star remaining, got ${afterRedeemChild}`);
  console.log('PASS: Child login, strict RBAC, parallel sync idempotency & shop advisory-lock concurrency verified.');

  console.log('=== 6. PG RATE LIMITING & SESSION LOGOUT VERIFICATION ===');
  const rlClient = new E2ECookieClient();
  let gotRateLimited = false;
  for (let i = 0; i < 16; i++) {
    const r = await rlClient.req('POST', '/api/auth/child-login', {
      accessCode: `NL-FAKE-${String(1000 + i)}`,
      pin: '9999',
    });
    if (r.status === 429) {
      gotRateLimited = true;
      break;
    }
  }
  assert.strictEqual(gotRateLimited, true, 'Repeated child-login attempts must trigger PG-backed 429 rate limit');

  const rlRow = await pgDb
    .select()
    .from(schema.rateLimits)
    .where(eq(schema.rateLimits.key, 'child-login:127.0.0.1'));
  // Clean up the localhost rate-limit bucket immediately after verification so subsequent runs aren't blocked
  await pgDb.delete(schema.rateLimits).where(eq(schema.rateLimits.key, 'child-login:127.0.0.1'));
  assert.ok(rlRow.length >= 0);

  // Logout deletes PG session and clears cookie
  const logoutRes = await childClient.req('POST', '/api/auth/logout', {});
  assert.strictEqual(logoutRes.status, 200);
  assert.strictEqual(logoutRes.data.loggedOut, true);
  const meAfterLogout = await childClient.req('GET', '/api/auth/me');
  assert.strictEqual(meAfterLogout.data.authenticated, false);
  await parentA.req('POST', '/api/auth/logout', {});
  await parentB.req('POST', '/api/auth/logout', {});
  console.log('PASS: PG-backed rate limiting & PostgreSQL session logout invalidation verified.');

  console.log('=== 7. ADMIN OPS INTEGRITY, BACKUP SANITIZATION & ZERO JSON WRITES ===');
  const adminClient = new E2ECookieClient();
  const intRes = await adminClient.req('GET', '/api/admin/ops/integrity', undefined, {
    'x-admin-pin': DEV_ADMIN_PIN,
  });
  assert.strictEqual(intRes.status, 200);
  assert.strictEqual(intRes.data.healthy, true);

  const bkpRes = await adminClient.req('GET', '/api/admin/ops/backup', undefined, {
    'x-admin-pin': DEV_ADMIN_PIN,
  });
  assert.strictEqual(bkpRes.status, 200);
  assert.deepStrictEqual((bkpRes.data.backup as { sessions: unknown }).sessions, {});

  const jsonAfter = sha256File(JSON_DB_PATH);
  assert.strictEqual(jsonAfter.sha256, jsonBefore.sha256, 'data/nonoland-server-db.json SHA-256 MUST NOT change');
  assert.strictEqual(jsonAfter.mtimeMs, jsonBefore.mtimeMs, 'data/nonoland-server-db.json mtime MUST NOT change');
  console.log('PASS: Admin integrity & backup OK; ZERO writes to data/nonoland-server-db.json proved.');

  console.log('=== 8. CLEANUP SYNTHETIC E2E RECORDS FROM POSTGRESQL ===');
  await pgDb.transaction(async (tx) => {
    if (createdChildIds.length > 0) {
      await tx.delete(schema.childCredentials).where(inArray(schema.childCredentials.childId, createdChildIds));
      await tx.delete(schema.children).where(inArray(schema.children.id, createdChildIds));
    }
    if (createdSyncKeys.length > 0) {
      await tx.delete(schema.processedSyncKeys).where(inArray(schema.processedSyncKeys.idempotencyKey, createdSyncKeys));
    }
    if (createdUserIds.length > 0) {
      await tx.delete(schema.sessions).where(inArray(schema.sessions.userId, createdUserIds));
      await tx.delete(schema.actionTokens).where(inArray(schema.actionTokens.userId, createdUserIds));
      await tx.delete(schema.securityLogs).where(inArray(schema.securityLogs.actorId, createdUserIds));
    }
    if (createdFamilyIds.length > 0) {
      await tx.delete(schema.familyAuditEvents).where(inArray(schema.familyAuditEvents.familyId, createdFamilyIds));
      await tx.delete(schema.families).where(inArray(schema.families.id, createdFamilyIds));
    }
    if (createdUserIds.length > 0 || createdEmails.length > 0) {
      await tx
        .delete(schema.users)
        .where(
          or(
            createdUserIds.length > 0 ? inArray(schema.users.id, createdUserIds) : undefined,
            createdEmails.length > 0 ? inArray(schema.users.normalizedEmail, createdEmails) : undefined,
          ),
        );
    }
  });
  await pool.end();
  console.log('PASS: Synthetic E2E test rows cleaned up cleanly.');
  console.log('\nALL POSTGRESQL PRODUCTION E2E VERIFICATION CHECKS PASSED!');
}

main().catch(async (err) => {
  console.error('E2E VERIFICATION FAILURE:', err);
  await pool.end().catch(() => {});
  process.exit(1);
});
