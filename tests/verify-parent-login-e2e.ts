import assert from 'node:assert';

const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';

class E2ECookieClient {
  private cookies = new Map<string, string>();
  public csrfToken: string | null = null;
  public lastSetCookies: string[] = [];

  private storeCookies(res: Response) {
    const hdrs = res.headers as Headers & { getSetCookie?: () => string[] };
    const setCookies = typeof hdrs.getSetCookie === 'function' ? hdrs.getSetCookie() : [];
    const fallback = res.headers.get('set-cookie');
    const all = setCookies.length > 0 ? setCookies : fallback ? [fallback] : [];
    this.lastSetCookies = all;
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

  public getCookie(name: string): string | undefined {
    return this.cookies.get(name);
  }

  public snapshotCookies(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  async req<T = Record<string, unknown>>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<{ status: number; data: T; headers: Headers; setCookies: string[] }> {
    const headers: Record<string, string> = { ...(extraHeaders || {}) };
    const cookieStr = this.snapshotCookies();
    if (cookieStr) headers['cookie'] = cookieStr;
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && this.csrfToken) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    this.storeCookies(res);
    const data = (await res.json().catch(() => ({}))) as T & { csrfToken?: string };
    if (data && typeof data === 'object' && typeof data.csrfToken === 'string') {
      this.csrfToken = data.csrfToken;
    }
    return { status: res.status, data, headers: res.headers, setCookies: [...this.lastSetCookies] };
  }
}

async function run() {
  const suffix = `${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
  const parentAEmail = `parent.login.a.${suffix}@nonoland.test`;
  const parentBEmail = `parent.login.b.${suffix}@nonoland.test`;
  const teacherEmail = `teacher.login.check.${suffix}@nonoland.test`;
  const password = `ParentPass!${suffix}`;

  console.log('=== SETUP: CREATE PARENT A + CHILD, PARENT B + CHILD, TEACHER ===');
  const regAClient = new E2ECookieClient();
  const regARes = await regAClient.req('POST', '/api/auth/register', {
    displayName: 'أم ليان',
    email: parentAEmail,
    password,
    termsAccepted: true,
  });
  assert.strictEqual(regARes.status, 201, `Parent A registration failed: ${JSON.stringify(regARes.data)}`);
  const parentAUser = regARes.data.user as { id: string; role: string; familyId: string };
  assert.strictEqual(parentAUser.role, 'parent');
  assert.ok(parentAUser.familyId, 'Parent A must have server-assigned familyId');

  const childARes = await regAClient.req('POST', '/api/children', {
    displayName: 'ليان',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 5,
  });
  assert.strictEqual(childARes.status, 201, 'Parent A should create Child A');
  const childA = childARes.data.child as { id: string; displayName: string; familyId: string };
  assert.strictEqual(childA.familyId, parentAUser.familyId);

  // Logout registration client cleanly
  const regLogout = await regAClient.req('POST', '/api/auth/logout', {});
  assert.strictEqual(regLogout.status, 200);

  // Register Parent B with Child B for isolation checks
  const parentBClient = new E2ECookieClient();
  const regBRes = await parentBClient.req('POST', '/api/auth/register', {
    displayName: 'أم يوسف',
    email: parentBEmail,
    password,
    termsAccepted: true,
  });
  assert.strictEqual(regBRes.status, 201);
  const parentBUser = regBRes.data.user as { id: string; role: string; familyId: string };
  assert.notStrictEqual(parentBUser.familyId, parentAUser.familyId);

  const childBRes = await parentBClient.req('POST', '/api/children', {
    displayName: 'يوسف',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2024,
    birthMonth: 2,
  });
  assert.strictEqual(childBRes.status, 201);
  const childB = childBRes.data.child as { id: string; displayName: string; familyId: string };

  // Register Teacher account (pending) to test cross-portal blocking
  const teacherRegClient = new E2ECookieClient();
  const tReg = await teacherRegClient.req('POST', '/api/auth/register-teacher', {
    displayName: 'أ. نور المعلمة',
    email: teacherEmail,
    password,
    confirmPassword: password,
    termsAccepted: true,
    subjects: ['arabic'],
  });
  assert.strictEqual(tReg.status, 201);

  console.log('=== COOKIE ATTRIBUTE TEST: PLAIN HTTP VS HTTPS CROSS-SITE IFRAME ===');
  const httpLoginCheck = await new E2ECookieClient().req('POST', '/api/auth/login', {
    email: parentAEmail,
    password,
    rememberMe: true,
    portal: 'parent',
  });
  assert.strictEqual(httpLoginCheck.status, 200);
  const httpCookie = httpLoginCheck.setCookies.find((c) => c.startsWith('nono_session='));
  assert.ok(httpCookie, 'Plain HTTP login must set nono_session cookie');
  assert.ok(/HttpOnly/i.test(httpCookie), 'Cookie must include HttpOnly');
  assert.ok(/SameSite=Lax/i.test(httpCookie), 'Plain HTTP cookie must use SameSite=Lax');
  assert.ok(!/;\s*Secure\b/i.test(httpCookie), 'Plain HTTP cookie must not require Secure');
  await httpLoginCheck;

  const httpsProxyClient = new E2ECookieClient();
  const httpsLoginCheck = await httpsProxyClient.req(
    'POST',
    '/api/auth/login',
    {
      email: parentAEmail,
      password,
      rememberMe: true,
      portal: 'parent',
    },
    {
      'x-forwarded-proto': 'https',
      origin: 'https://aistudio.google.com',
    },
  );
  assert.strictEqual(httpsLoginCheck.status, 200);
  const httpsCookie = httpsLoginCheck.setCookies.find((c) => c.startsWith('nono_session='));
  assert.ok(httpsCookie, 'HTTPS proxy login must set nono_session cookie');
  assert.ok(/SameSite=None/i.test(httpsCookie), 'HTTPS/iframe cookie must emit SameSite=None');
  assert.ok(/;\s*Secure\b/i.test(httpsCookie), 'HTTPS/iframe cookie must emit Secure');
  assert.ok(/Partitioned/i.test(httpsCookie), 'HTTPS/iframe cookie must emit Partitioned');

  const httpsLogoutCheck = await httpsProxyClient.req(
    'POST',
    '/api/auth/logout',
    {},
    {
      'x-forwarded-proto': 'https',
      origin: 'https://aistudio.google.com',
    },
  );
  assert.strictEqual(httpsLogoutCheck.status, 200);
  const httpsClearCookie = httpsLogoutCheck.setCookies.find((c) => c.startsWith('nono_session='));
  assert.ok(httpsClearCookie && /Max-Age=0/i.test(httpsClearCookie));
  assert.ok(/SameSite=None/i.test(httpsClearCookie) && /;\s*Secure\b/i.test(httpsClearCookie));
  console.log('PASS: Cookie attributes verified for both HTTP localhost and HTTPS AI Studio iframe.');

  console.log('=== TEST A: VALID PARENT LOGIN -> SESSION -> ROLE -> SMART PARENT DASHBOARD DATA ===');
  const browserA = new E2ECookieClient();
  const loginARes = await browserA.req('POST', '/api/auth/login', {
    email: parentAEmail,
    password,
    rememberMe: true,
    portal: 'parent',
  });
  assert.strictEqual(loginARes.status, 200, 'Valid parent login must succeed with 200');
  assert.ok(browserA.getCookie('nono_session'), 'Session cookie nono_session must be stored');
  assert.strictEqual((loginARes.data.user as { role: string }).role, 'parent');
  assert.strictEqual(loginARes.data.dashboardRoute, '/parent-dashboard');
  assert.ok(typeof loginARes.data.csrfToken === 'string' && loginARes.data.csrfToken.length > 10);

  // Simulate frontend session confirmation right after login (/api/auth/me + /api/children)
  const meA = await browserA.req<{
    authenticated: boolean;
    user: { id: string; role: string; familyId: string; dashboardRoute: string } | null;
    csrfToken: string | null;
  }>('GET', '/api/auth/me');
  assert.strictEqual(meA.status, 200);
  assert.strictEqual(meA.data.authenticated, true, '/api/auth/me must confirm authenticated=true');
  assert.strictEqual(meA.data.user?.role, 'parent', 'Authenticated user role must be parent');
  assert.strictEqual(meA.data.user?.familyId, parentAUser.familyId);
  assert.strictEqual(meA.data.user?.dashboardRoute, '/parent-dashboard');

  const childrenARes = await browserA.req<{ children: Array<{ id: string; displayName: string; familyId: string }> }>(
    'GET',
    '/api/children',
  );
  assert.strictEqual(childrenARes.status, 200);
  assert.strictEqual(childrenARes.data.children.length, 1);
  assert.strictEqual(childrenARes.data.children[0].id, childA.id);
  assert.strictEqual(childrenARes.data.children[0].displayName, 'ليان');

  // Verify Parent Dashboard overview endpoint works for parent's own child
  const overviewARes = await browserA.req('GET', `/api/parent/children/${childA.id}/overview`);
  assert.strictEqual(overviewARes.status, 200);
  console.log('PASS: Test A — Valid parent login established session, verified role=parent, routed to parent-dashboard & loaded own children.');

  console.log('=== TEST B: INVALID CREDENTIALS & UNAUTHORIZED LOGIN REJECTION ===');
  const badPwClient = new E2ECookieClient();
  const wrongPwRes = await badPwClient.req('POST', '/api/auth/login', {
    email: parentAEmail,
    password: 'WrongPassword!123',
    portal: 'parent',
  });
  assert.strictEqual(wrongPwRes.status, 401, 'Invalid password must return 401');
  assert.strictEqual(badPwClient.getCookie('nono_session'), undefined, 'Failed login must never set session cookie');
  const badMe = await badPwClient.req<{ authenticated: boolean; user: unknown }>('GET', '/api/auth/me');
  assert.strictEqual(badMe.data.authenticated, false);
  assert.strictEqual(badMe.data.user, null);

  const unknownRes = await badPwClient.req('POST', '/api/auth/login', {
    email: `nobody.${suffix}@nonoland.test`,
    password,
    portal: 'parent',
  });
  assert.strictEqual(unknownRes.status, 401);

  const wrongPortalRes = await new E2ECookieClient().req('POST', '/api/auth/login', {
    email: teacherEmail,
    password,
    portal: 'parent',
  });
  assert.strictEqual(wrongPortalRes.status, 403, 'Pending/teacher account must be rejected safely');
  console.log('PASS: Test B — Invalid credentials & unauthorized portal logins rejected with no session.');

  console.log('=== TEST C: SESSION PERSISTENCE ON REFRESH & LOGOUT INVALIDATION ===');
  const staleRawCookie = `nono_session=${browserA.getCookie('nono_session')}`;
  // Refresh #1 & #2 keep parent logged in
  const refresh1 = await browserA.req<{ authenticated: boolean; user: { id: string; role: string } | null }>(
    'GET',
    '/api/auth/me',
  );
  assert.strictEqual(refresh1.status, 200);
  assert.strictEqual(refresh1.data.authenticated, true);
  assert.strictEqual(refresh1.data.user?.id, parentAUser.id);
  const refreshChildren = await browserA.req<{ children: Array<{ id: string }> }>('GET', '/api/children');
  assert.strictEqual(refreshChildren.status, 200);
  assert.strictEqual(refreshChildren.data.children[0].id, childA.id);

  // Logout invalidates session server-side and clears cookie
  const logoutARes = await browserA.req('POST', '/api/auth/logout', {});
  assert.strictEqual(logoutARes.status, 200);
  assert.strictEqual(browserA.getCookie('nono_session'), undefined, 'Logout must clear session cookie');

  const afterLogoutMe = await browserA.req<{ authenticated: boolean }>('GET', '/api/auth/me');
  assert.strictEqual(afterLogoutMe.data.authenticated, false);
  const afterLogoutChildren = await browserA.req('GET', '/api/children');
  assert.strictEqual(afterLogoutChildren.status, 401, 'Protected /api/children must reject after logout');

  // Even replaying the old captured session cookie must fail after logout
  const replayMeRes = await fetch(`${BASE}/api/auth/me`, {
    headers: { cookie: staleRawCookie },
  });
  const replayMe = (await replayMeRes.json()) as { authenticated: boolean };
  assert.strictEqual(replayMe.authenticated, false, 'Old session token must be invalidated server-side');
  const replayChildrenRes = await fetch(`${BASE}/api/children`, {
    headers: { cookie: staleRawCookie },
  });
  assert.strictEqual(replayChildrenRes.status, 401, 'Old session token cannot access protected family data');
  console.log('PASS: Test C — Refresh persistence and post-logout session invalidation verified.');

  console.log('=== TEST D: STRICT FAMILY ISOLATION & CLIENT FAMILYID TAMPERING REJECTION ===');
  const browserB = new E2ECookieClient();
  const loginBRes = await browserB.req('POST', '/api/auth/login', {
    email: parentBEmail,
    password,
    portal: 'parent',
    familyId: parentAUser.familyId, // adversarial client familyId must be ignored
  });
  assert.strictEqual(loginBRes.status, 200);
  const loggedInB = loginBRes.data.user as { id: string; familyId: string };
  assert.strictEqual(loggedInB.familyId, parentBUser.familyId, 'Server must never trust client-provided familyId');
  assert.notStrictEqual(loggedInB.familyId, parentAUser.familyId);

  const childrenBRes = await browserB.req<{ children: Array<{ id: string; familyId: string }> }>('GET', '/api/children');
  assert.strictEqual(childrenBRes.status, 200);
  assert.strictEqual(childrenBRes.data.children.length, 1);
  assert.strictEqual(childrenBRes.data.children[0].id, childB.id);
  assert.ok(!childrenBRes.data.children.some((c) => c.id === childA.id), 'Parent B must never see Parent A child');

  // Cross-family IDOR checks on dashboard, child update, adaptive profile, weekly report & credentials
  assert.strictEqual((await browserB.req('GET', `/api/parent/children/${childA.id}/overview`)).status, 403);
  assert.strictEqual((await browserB.req('PATCH', `/api/children/${childA.id}`, { displayName: 'Tampered' })).status, 403);
  assert.strictEqual((await browserB.req('GET', `/api/family/children/${childA.id}/adaptive-profile`)).status, 403);
  assert.strictEqual((await browserB.req('GET', `/api/family/children/${childA.id}/weekly-report`)).status, 403);
  console.log('PASS: Test D — Strict family isolation & client familyId rejection verified.');

  console.log('ALL PARENT LOGIN E2E TESTS (A–D + COOKIE SECURITY) PASSED!');
}

run().catch((err) => {
  console.error('PARENT LOGIN E2E TEST FAILED:', err);
  process.exit(1);
});
