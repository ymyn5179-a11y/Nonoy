import assert from 'node:assert';
import crypto from 'node:crypto';
import { pool } from '../src/db/index.ts';

const BASE = 'http://127.0.0.1:3000';

class TestClient {
  private cookies = new Map<string, string>();
  public csrfToken: string | null = null;

  private storeCookies(res: Response) {
    const hdrs = res.headers as Headers & { getSetCookie?: () => string[] };
    const setCookies = typeof hdrs.getSetCookie === 'function' ? hdrs.getSetCookie() : [];
    const fallback = res.headers.get('set-cookie');
    const all = setCookies.length > 0 ? setCookies : fallback ? [fallback] : [];
    for (const raw of all) {
      const [nv] = raw.split(';');
      const idx = nv.indexOf('=');
      if (idx > 0) {
        const name = nv.slice(0, idx).trim();
        const val = nv.slice(idx + 1).trim();
        if (!val || /Max-Age=0/i.test(raw)) {
          this.cookies.delete(name);
        } else {
          this.cookies.set(name, val);
        }
      }
    }
  }

  async req<T = Record<string, unknown>>(
    method: string,
    urlPath: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<{ status: number; headers: Headers; data: T; rawText: string }> {
    const headers: Record<string, string> = { Origin: BASE, ...extraHeaders };
    const cookieStr = Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookieStr) headers['cookie'] = cookieStr;
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && this.csrfToken && !('x-csrf-token' in headers)) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const res = await fetch(`${BASE}${urlPath}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    this.storeCookies(res);
    const rawText = await res.text();
    let data = {} as T & { csrfToken?: string };
    try {
      data = rawText ? (JSON.parse(rawText) as T & { csrfToken?: string }) : ({} as T & { csrfToken?: string });
    } catch {
      data = {} as T & { csrfToken?: string };
    }
    if (data && typeof data === 'object' && typeof data.csrfToken === 'string') {
      this.csrfToken = data.csrfToken;
    }
    return { status: res.status, headers: res.headers, data, rawText };
  }
}

(async () => {
  const tag = crypto.randomBytes(4).toString('hex');
  const anon = new TestClient();
  const parentA = new TestClient();
  const parentB = new TestClient();
  const childA1Client = new TestClient();

  const emailA = `authorder_a_${tag}@example.test`;
  const emailB = `authorder_b_${tag}@example.test`;
  const password = `TestPass!${tag}#2026`;

  const createdUserIds: string[] = [];
  const createdFamilyIds: string[] = [];
  const createdChildIds: string[] = [];
  const createdAttemptIds: string[] = [];
  const createdCheckoutIds: string[] = [];

  try {
    // ------------------------------------------------------------------
    // Setup temporary test families & children
    // ------------------------------------------------------------------
    const regA = await parentA.req<{ user: { id: string; familyId?: string } }>('POST', '/api/auth/register', {
      displayName: 'Test Parent A',
      email: emailA,
      password,
      confirmPassword: password,
      termsAccepted: true,
    });
    assert.strictEqual(regA.status, 201, `Parent A register failed: ${regA.rawText}`);
    createdUserIds.push(regA.data.user.id);
    if (regA.data.user.familyId) createdFamilyIds.push(regA.data.user.familyId);

    const regB = await parentB.req<{ user: { id: string; familyId?: string } }>('POST', '/api/auth/register', {
      displayName: 'Test Parent B',
      email: emailB,
      password,
      confirmPassword: password,
      termsAccepted: true,
    });
    assert.strictEqual(regB.status, 201, `Parent B register failed: ${regB.rawText}`);
    createdUserIds.push(regB.data.user.id);
    if (regB.data.user.familyId) createdFamilyIds.push(regB.data.user.familyId);

    const pinA1 = '4242';
    const cA1 = await parentA.req<{ child: { id: string }; accessCode?: string }>('POST', '/api/children', {
      displayName: 'Child A1',
      birthYear: 2023,
      birthMonth: 3,
      language: 'ar',
      pin: pinA1,
    });
    assert.strictEqual(cA1.status, 201, `Child A1 create failed: ${cA1.rawText}`);
    const childA1Id = cA1.data.child.id;
    createdChildIds.push(childA1Id);
    const accessCodeA1 = cA1.data.accessCode;
    assert.ok(accessCodeA1, 'Child A1 accessCode must be generated');

    const cA2 = await parentA.req<{ child: { id: string } }>('POST', '/api/children', {
      displayName: 'Child A2',
      birthYear: 2023,
      birthMonth: 6,
      language: 'ar',
    });
    assert.strictEqual(cA2.status, 201);
    const childA2Id = cA2.data.child.id;
    createdChildIds.push(childA2Id);

    const loginChildA1 = await childA1Client.req('POST', '/api/auth/child-login', {
      accessCode: accessCodeA1,
      pin: pinA1,
    });
    assert.strictEqual(loginChildA1.status, 200);

    // ------------------------------------------------------------------
    // 1. POST /api/level1/assessment/start — Auth & child access BEFORE input validation
    // ------------------------------------------------------------------
    const l1UnauthEmpty = await anon.req('POST', '/api/level1/assessment/start', {});
    assert.strictEqual(l1UnauthEmpty.status, 401, `Expected 401 for unauth {}, got ${l1UnauthEmpty.status}`);

    const l1UnauthDemo = await anon.req('POST', '/api/level1/assessment/start', { childId: 'demo-1' });
    assert.strictEqual(l1UnauthDemo.status, 401, `Expected 401 for unauth demo childId, got ${l1UnauthDemo.status}`);

    // Parent B trying Parent A's childId WITHOUT lessonId must still get 403 (not 400!)
    const l1CrossFamilyNoLesson = await parentB.req('POST', '/api/level1/assessment/start', {
      childId: childA1Id,
    });
    assert.strictEqual(l1CrossFamilyNoLesson.status, 403, `Expected 403 cross-family before lessonId check, got ${l1CrossFamilyNoLesson.status}`);

    // Child A1 trying sibling A2's childId WITHOUT lessonId must get 403 (not 400!)
    const l1SiblingNoLesson = await childA1Client.req('POST', '/api/level1/assessment/start', {
      childId: childA2Id,
    });
    assert.strictEqual(l1SiblingNoLesson.status, 403, `Expected 403 sibling before lessonId check, got ${l1SiblingNoLesson.status}`);

    // Authorized Parent A starting valid assessment works (200)
    const l1Valid = await parentA.req<{ attemptId: string; questions: unknown[] }>('POST', '/api/level1/assessment/start', {
      childId: childA1Id,
      lessonId: 'AR01',
      questionCount: 4,
    });
    assert.strictEqual(l1Valid.status, 200, `Authorized level1 start failed: ${l1Valid.rawText}`);
    assert.ok(l1Valid.data.attemptId);
    createdAttemptIds.push(l1Valid.data.attemptId);
    console.log('PASS [1]: POST /api/level1/assessment/start auth & access verified before input validation.');

    // ------------------------------------------------------------------
    // 2. POST /api/payments/create-checkout — Parent auth & access BEFORE input validation
    // ------------------------------------------------------------------
    const chkUnauthEmpty = await anon.req('POST', '/api/payments/create-checkout', {});
    assert.strictEqual(chkUnauthEmpty.status, 401, `Expected 401 for unauth checkout {}, got ${chkUnauthEmpty.status}`);

    const chkUnauthConfirmed = await anon.req('POST', '/api/payments/create-checkout', {
      childId: childA1Id,
      parentConfirmed: true,
    });
    assert.strictEqual(chkUnauthConfirmed.status, 401, `Expected 401 for unauth checkout with body, got ${chkUnauthConfirmed.status}`);

    // Child session MUST be blocked (403) even with empty body or own childId
    const chkChildEmpty = await childA1Client.req('POST', '/api/payments/create-checkout', {});
    assert.strictEqual(chkChildEmpty.status, 403, `Expected 403 for child checkout {}, got ${chkChildEmpty.status}`);

    const chkChildOwn = await childA1Client.req('POST', '/api/payments/create-checkout', {
      childId: childA1Id,
      subject: 'arabic',
      parentConfirmed: true,
    });
    assert.strictEqual(chkChildOwn.status, 403, `Expected 403 for child checkout on own profile, got ${chkChildOwn.status}`);

    // Parent B targeting Parent A's childId WITHOUT parentConfirmed must get 403 (not 400!)
    const chkCrossFamilyNoConfirm = await parentB.req('POST', '/api/payments/create-checkout', {
      childId: childA1Id,
    });
    assert.strictEqual(chkCrossFamilyNoConfirm.status, 403, `Expected 403 cross-family checkout before parentConfirmed, got ${chkCrossFamilyNoConfirm.status}`);

    // Authorized Parent A creates checkout cleanly (200)
    const chkValid = await parentA.req<{ checkoutSessionId: string; amountEgp: number; gatewayMode: string }>(
      'POST',
      '/api/payments/create-checkout',
      {
        childId: childA1Id,
        subject: 'arabic',
        parentConfirmed: true,
      },
    );
    assert.strictEqual(chkValid.status, 200, `Authorized create-checkout failed: ${chkValid.rawText}`);
    const checkoutId = chkValid.data.checkoutSessionId;
    assert.ok(checkoutId);
    createdCheckoutIds.push(checkoutId);
    console.log('PASS [2]: POST /api/payments/create-checkout parent auth & ownership enforced before input validation.');

    // ------------------------------------------------------------------
    // 3. POST /api/payments/verify — Auth, ownership, replay protection & exam token use
    // ------------------------------------------------------------------
    const verUnauthEmpty = await anon.req('POST', '/api/payments/verify', {});
    assert.strictEqual(verUnauthEmpty.status, 401, `Expected 401 for unauth verify {}, got ${verUnauthEmpty.status}`);

    const verUnauthFakeId = await anon.req('POST', '/api/payments/verify', { checkoutSessionId: 'chk_nonexistent' });
    assert.strictEqual(verUnauthFakeId.status, 401, `Expected 401 for unauth verify fake id, got ${verUnauthFakeId.status}`);

    const verUnauthRealId = await anon.req('POST', '/api/payments/verify', { checkoutSessionId: checkoutId });
    assert.strictEqual(verUnauthRealId.status, 401, `Expected 401 for unauth verify real id, got ${verUnauthRealId.status}`);

    const verChild = await childA1Client.req('POST', '/api/payments/verify', { checkoutSessionId: checkoutId });
    assert.strictEqual(verChild.status, 403, `Expected 403 for child verify, got ${verChild.status}`);

    const verCrossParent = await parentB.req('POST', '/api/payments/verify', { checkoutSessionId: checkoutId });
    assert.strictEqual(verCrossParent.status, 403, `Expected 403 for cross-parent verify, got ${verCrossParent.status}`);

    const verAuthNotFound = await parentA.req('POST', '/api/payments/verify', { checkoutSessionId: 'chk_does_not_exist' });
    assert.strictEqual(verAuthNotFound.status, 404, `Expected 404 for authenticated missing checkout, got ${verAuthNotFound.status}`);

    const verValid = await parentA.req<{ verified: boolean; paymentVerificationToken: string }>(
      'POST',
      '/api/payments/verify',
      { checkoutSessionId: checkoutId },
    );
    assert.strictEqual(verValid.status, 200, `Authorized verify failed: ${verValid.rawText}`);
    assert.strictEqual(verValid.data.verified, true);
    assert.ok(verValid.data.paymentVerificationToken);

    // Replay protection on /api/payments/verify (calling again for same checkoutSessionId returns 409)
    const verReplay = await parentA.req('POST', '/api/payments/verify', { checkoutSessionId: checkoutId });
    assert.strictEqual(verReplay.status, 409, `Expected 409 replay protection on duplicate verify, got ${verReplay.status}`);

    // Official exam accepts the one-time token once, then blocks reuse (402)
    const examStart = await parentA.req<{ attemptId: string }>('POST', '/api/exams/start', {
      childId: childA1Id,
      ageGroup: '1-4',
      subject: 'arabic',
      mode: 'official',
      paymentVerificationToken: verValid.data.paymentVerificationToken,
    });
    assert.strictEqual(examStart.status, 200, `Official exam start failed: ${examStart.rawText}`);

    const examReplay = await parentA.req('POST', '/api/exams/start', {
      childId: childA1Id,
      ageGroup: '1-4',
      subject: 'arabic',
      mode: 'official',
      paymentVerificationToken: verValid.data.paymentVerificationToken,
    });
    assert.strictEqual(examReplay.status, 402, `Expected 402 reusing consumed payment token, got ${examReplay.status}`);
    console.log('PASS [3]: POST /api/payments/verify auth, parent ownership, replay protection & one-time token consumption verified.');

    // ------------------------------------------------------------------
    // 4. Unknown /api/* routes -> 404 JSON while preserving SPA & assets
    // ------------------------------------------------------------------
    const unknownGet = await anon.req<{ error: string }>('GET', '/api/nonexistent-endpoint-check');
    assert.strictEqual(unknownGet.status, 404, `Expected 404 on unknown GET /api/*, got ${unknownGet.status}`);
    assert.ok((unknownGet.headers.get('content-type') || '').includes('application/json'), 'Unknown /api/* must return JSON');
    assert.strictEqual(unknownGet.data.error, 'API endpoint not found');

    const unknownOverview = await anon.req<{ error: string }>('GET', '/api/family/overview');
    assert.strictEqual(unknownOverview.status, 404);
    assert.ok((unknownOverview.headers.get('content-type') || '').includes('application/json'));

    const unknownPost = await anon.req<{ error: string }>('POST', '/api/nonexistent-endpoint-check', {});
    assert.strictEqual(unknownPost.status, 404);
    assert.ok((unknownPost.headers.get('content-type') || '').includes('application/json'));

    const healthRes = await anon.req<{ status: string; schemaReady: boolean }>('GET', '/api/health');
    assert.strictEqual(healthRes.status, 200);
    assert.strictEqual(healthRes.data.schemaReady, true);

    const spaRoot = await fetch(`${BASE}/`);
    const spaRootHtml = await spaRoot.text();
    assert.strictEqual(spaRoot.status, 200);
    assert.ok(spaRootHtml.includes('<div id="root"></div>'), 'SPA root must continue returning index.html');

    const spaDeepRoute = await fetch(`${BASE}/academy`);
    const spaDeepHtml = await spaDeepRoute.text();
    assert.strictEqual(spaDeepRoute.status, 200);
    assert.ok(spaDeepHtml.includes('<div id="root"></div>'), 'SPA client route must continue returning index.html');

    const viteEntry = await fetch(`${BASE}/src/main.tsx`);
    assert.strictEqual(viteEntry.status, 200, 'Vite asset /src/main.tsx must remain accessible');
    console.log('PASS [4]: Unknown /api/* returns 404 JSON; SPA routes and static/Vite assets remain 200.');
  } finally {
    // Clean up ONLY temporary test records created by this test run
    const linkedUsersRes = await pool.query(
      `SELECT id FROM users WHERE id = ANY($1::text[]) OR family_id = ANY($2::text[]) OR linked_child_id = ANY($3::text[])`,
      [createdUserIds, createdFamilyIds, createdChildIds],
    );
    const allTestUserIds = Array.from(new Set([...createdUserIds, ...linkedUsersRes.rows.map((r: { id: string }) => r.id)]));

    await pool.query('BEGIN');
    try {
      await pool.query(`DELETE FROM exam_attempts WHERE child_id = ANY($1::text[])`, [createdChildIds]);
      await pool.query(`DELETE FROM level1_attempts WHERE id = ANY($1::text[]) OR child_id = ANY($2::text[])`, [createdAttemptIds, createdChildIds]);
      await pool.query(`DELETE FROM checkout_sessions WHERE id = ANY($1::text[]) OR child_id = ANY($2::text[])`, [createdCheckoutIds, createdChildIds]);
      await pool.query(`DELETE FROM child_credentials WHERE child_id = ANY($1::text[]) OR family_id = ANY($2::text[])`, [createdChildIds, createdFamilyIds]);
      await pool.query(`DELETE FROM children WHERE id = ANY($1::text[]) OR family_id = ANY($2::text[])`, [createdChildIds, createdFamilyIds]);
      await pool.query(`DELETE FROM action_tokens WHERE user_id = ANY($1::text[])`, [allTestUserIds]);
      await pool.query(`DELETE FROM sessions WHERE user_id = ANY($1::text[]) OR family_id = ANY($2::text[]) OR child_id = ANY($3::text[])`, [allTestUserIds, createdFamilyIds, createdChildIds]);
      await pool.query(`DELETE FROM privacy_consents WHERE family_id = ANY($1::text[]) OR granted_by_user_id = ANY($2::text[])`, [createdFamilyIds, allTestUserIds]);
      await pool.query(`DELETE FROM privacy_settings WHERE family_id = ANY($1::text[])`, [createdFamilyIds]);
      await pool.query(`DELETE FROM content_policies WHERE family_id = ANY($1::text[])`, [createdFamilyIds]);
      await pool.query(`DELETE FROM guardian_memberships WHERE family_id = ANY($1::text[]) OR user_id = ANY($2::text[])`, [createdFamilyIds, allTestUserIds]);
      await pool.query(`DELETE FROM family_audit_events WHERE family_id = ANY($1::text[]) OR actor_id = ANY($2::text[]) OR child_id = ANY($3::text[])`, [createdFamilyIds, allTestUserIds, createdChildIds]);
      await pool.query(`DELETE FROM security_logs WHERE family_id = ANY($1::text[]) OR actor_id = ANY($2::text[]) OR record_id = ANY($3::text[]) OR ip IN ('127.0.0.1', '::1', '::ffff:127.0.0.1')`, [createdFamilyIds, allTestUserIds, [...allTestUserIds, ...createdChildIds, ...createdFamilyIds]]);
      await pool.query(`DELETE FROM rate_limits WHERE key LIKE '%' || $1 || '%' OR key LIKE '%127.0.0.1%' OR key LIKE '%::1%'`, [tag]);
      await pool.query(`DELETE FROM users WHERE id = ANY($1::text[])`, [allTestUserIds]);
      await pool.query(`DELETE FROM families WHERE id = ANY($1::text[])`, [createdFamilyIds]);
      await pool.query('COMMIT');
    } catch (cleanupErr) {
      await pool.query('ROLLBACK');
      throw cleanupErr;
    }
    await pool.end();
  }
})();
