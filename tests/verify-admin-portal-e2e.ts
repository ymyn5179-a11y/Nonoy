import assert from 'node:assert';
import crypto from 'node:crypto';
import { spawn, ChildProcess } from 'node:child_process';

const PORT = 3199;
const BASE = `http://127.0.0.1:${PORT}`;

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

  public snapshotCookies(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  public getRawCookieHeader(): string {
    return this.snapshotCookies();
  }

  async req<T = Record<string, unknown>>(
    method: string,
    path: string,
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ): Promise<{ status: number; data: T; headers: Headers }> {
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
    return { status: res.status, data, headers: res.headers };
  }
}

async function waitForServerReady(): Promise<void> {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${BASE}/api/auth/admin-bootstrap/status`);
      if (r.ok) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('Isolated E2E test server did not become ready in time');
}

async function run() {
  const runtimeSetupSecret = crypto.randomBytes(24).toString('hex');
  const suffix = `${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

  const serverProc: ChildProcess = spawn('npx', ['tsx', 'server.ts'], {
    cwd: process.cwd(),
    detached: true,
    env: {
      ...process.env,
      PORT: String(PORT),
      NODE_ENV: 'development',
      SKIP_VITE: '1',
      SQL_HOST: '',
      SQL_DB_NAME: '',
      SQL_USER: '',
      SQL_PASSWORD: '',
      DATABASE_URL: '',
      REQUIRE_POSTGRES: '',
      NONOLAND_ADMIN_SETUP_SECRET: runtimeSetupSecret,
      ADMIN_PIN: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let serverLogs = '';
  serverProc.stdout?.on('data', (d) => {
    serverLogs += String(d);
  });
  serverProc.stderr?.on('data', (d) => {
    serverLogs += String(d);
  });

  try {
    await waitForServerReady();

    // Runtime-generated test credentials (never hardcoded defaults in app code)
    const superAdminEmail = `owner.admin.${suffix}@example.com`;
    const superAdminPw = `Sup3r!${crypto.randomBytes(6).toString('hex')}9Z`;
    const adminEmail = `ops.admin.${suffix}@example.com`;
    const adminPw = `Adm1n!${crypto.randomBytes(6).toString('hex')}8Q`;
    const parentEmail = `parent.${suffix}@example.com`;
    const parentPw = `Par3nt!${crypto.randomBytes(6).toString('hex')}7W`;
    const teacher1Email = `teacher.one.${suffix}@example.com`;
    const teacher2Email = `teacher.two.${suffix}@example.com`;
    const teacherPw = `T3ach!${crypto.randomBytes(6).toString('hex')}5X`;

    const anon = new E2ECookieClient();

    // =========================================================================
    // TEST A: First Super Admin Bootstrap & One-Time Lock
    // =========================================================================
    const stBefore = await anon.req<{ initialized: boolean; setupConfigured: boolean }>(
      'GET',
      '/api/auth/admin-bootstrap/status',
    );
    assert.strictEqual(stBefore.status, 200);
    assert.strictEqual(stBefore.data.initialized, false, 'Expected uninitialized before bootstrap');
    assert.strictEqual(stBefore.data.setupConfigured, true, 'Expected setupConfigured=true when env var set');
    assert.ok(
      !JSON.stringify(stBefore.data).includes(runtimeSetupSecret),
      'Setup secret must NEVER be leaked in status response',
    );

    // Wrong secret rejected 403
    const badBoot = await anon.req('POST', '/api/auth/admin-bootstrap', {
      setupSecret: 'wrong-secret',
      displayName: 'Wrong Owner',
      email: superAdminEmail,
      password: superAdminPw,
      confirmPassword: superAdminPw,
    });
    assert.strictEqual(badBoot.status, 403);

    // Valid one-time bootstrap succeeds
    const bootClient = new E2ECookieClient();
    const okBoot = await bootClient.req<{
      initialized: boolean;
      user: { id: string; role: string; email: string };
      dashboardRoute: string;
    }>('POST', '/api/auth/admin-bootstrap', {
      setupSecret: runtimeSetupSecret,
      displayName: 'Platform Owner',
      email: superAdminEmail,
      password: superAdminPw,
      confirmPassword: superAdminPw,
    });
    assert.strictEqual(okBoot.status, 201, `Bootstrap failed: ${JSON.stringify(okBoot.data)}`);
    assert.strictEqual(okBoot.data.initialized, true);
    assert.strictEqual(okBoot.data.user.role, 'super_admin');
    assert.strictEqual(okBoot.data.dashboardRoute, '/admin-dashboard');

    // Status now reports initialized=true & setupConfigured=false
    const stAfter = await anon.req<{ initialized: boolean; setupConfigured: boolean }>(
      'GET',
      '/api/auth/admin-bootstrap/status',
    );
    assert.strictEqual(stAfter.data.initialized, true);
    assert.strictEqual(stAfter.data.setupConfigured, false);

    // Second bootstrap attempt EVEN with valid secret MUST fail permanently (403)
    const secondBoot = await anon.req('POST', '/api/auth/admin-bootstrap', {
      setupSecret: runtimeSetupSecret,
      displayName: 'Second Owner',
      email: `second.${suffix}@example.com`,
      password: superAdminPw,
      confirmPassword: superAdminPw,
    });
    assert.strictEqual(secondBoot.status, 403);
    console.log('✓ TEST A passed: One-time Super Admin bootstrap & permanent lock');

    // =========================================================================
    // Prepare Parent & Child for Role Denial & Family Isolation Checks
    // =========================================================================
    const parentClient = new E2ECookieClient();
    const pReg = await parentClient.req('POST', '/api/auth/register', {
      displayName: 'Sara Parent',
      email: parentEmail,
      password: parentPw,
      termsAccepted: true,
    });
    assert.strictEqual(pReg.status, 201);

    // Public admin registration attempt on /api/auth/register must fail 403
    const escalReg = await anon.req('POST', '/api/auth/register', {
      displayName: 'Evil Public Admin',
      email: `evil.${suffix}@example.com`,
      password: parentPw,
      termsAccepted: true,
      role: 'super_admin',
    });
    assert.strictEqual(escalReg.status, 403);

    const escalRegAdmin = await anon.req('POST', '/api/auth/register', {
      displayName: 'Evil Public Admin 2',
      email: `evil2.${suffix}@example.com`,
      password: parentPw,
      termsAccepted: true,
      role: 'admin',
    });
    assert.strictEqual(escalRegAdmin.status, 403);

    // Create child & sign in as child
    const childPin = '4829';
    const childCreate = await parentClient.req<{ child: { id: string }; accessCode: string }>(
      'POST',
      '/api/children',
      {
        displayName: 'Lina',
        ageGroup: '1-4',
        language: 'ar',
        birthYear: new Date().getFullYear() - 3,
        birthMonth: 4,
        interests: ['animals'],
        pin: childPin,
      },
    );
    assert.strictEqual(childCreate.status, 201);

    const childClient = new E2ECookieClient();
    const childLoginRes = await childClient.req('POST', '/api/auth/child-login', {
      accessCode: childCreate.data.accessCode,
      pin: childPin,
    });
    assert.strictEqual(childLoginRes.status, 200);

    // =========================================================================
    // TEST B: Admin Authentication & Non-Admin Denial
    // =========================================================================
    // Super Admin login via portal='admin'
    const adminLoginClient = new E2ECookieClient();
    const admLogin = await adminLoginClient.req<{
      user: { role: string };
      dashboardRoute: string;
    }>('POST', '/api/auth/login', {
      email: superAdminEmail,
      password: superAdminPw,
      portal: 'admin',
    });
    assert.strictEqual(admLogin.status, 200);
    assert.strictEqual(admLogin.data.user.role, 'super_admin');
    assert.strictEqual(admLogin.data.dashboardRoute, '/admin-dashboard');

    // Admin cannot sign in through Parent portal tab
    const admWrongPortal = await anon.req('POST', '/api/auth/login', {
      email: superAdminEmail,
      password: superAdminPw,
      portal: 'parent',
    });
    assert.strictEqual(admWrongPortal.status, 403);

    // Parent denied Admin portal login & Admin APIs
    const pOnAdminPortal = await anon.req('POST', '/api/auth/login', {
      email: parentEmail,
      password: parentPw,
      portal: 'admin',
    });
    assert.strictEqual(pOnAdminPortal.status, 403);
    assert.strictEqual((await parentClient.req('GET', '/api/admin/overview-stats')).status, 403);
    assert.strictEqual((await parentClient.req('GET', '/api/admin/teachers')).status, 403);

    // Child denied Admin APIs
    assert.strictEqual((await childClient.req('GET', '/api/admin/overview-stats')).status, 403);
    assert.strictEqual((await childClient.req('GET', '/api/admin/parents')).status, 403);

    console.log('✓ TEST B passed: Admin authentication & non-admin 403 enforcement');

    // =========================================================================
    // TEST C: Teacher Registration -> Pending State -> Blocked Before Approval
    // =========================================================================
    const t1Reg = await anon.req<{
      pendingApproval: boolean;
      status: string;
      user: { id: string };
      messageAr: string;
    }>('POST', '/api/auth/register-teacher', {
      displayName: 'Mona Teacher',
      email: teacher1Email,
      password: teacherPw,
      confirmPassword: teacherPw,
      phone: '+201001234567',
      subjects: ['arabic', 'math'],
      termsAccepted: true,
    });
    assert.strictEqual(t1Reg.status, 201);
    assert.strictEqual(t1Reg.data.pendingApproval, true);
    assert.strictEqual(t1Reg.data.status, 'pending');
    assert.ok(t1Reg.data.messageAr.includes('بانتظار') || t1Reg.data.messageAr.includes('مراجعة'));

    const t2Reg = await anon.req<{ user: { id: string } }>('POST', '/api/auth/register-teacher', {
      displayName: 'Omar Teacher',
      email: teacher2Email,
      password: teacherPw,
      confirmPassword: teacherPw,
      subjects: ['english'],
      termsAccepted: true,
    });
    assert.strictEqual(t2Reg.status, 201);

    // Pending teacher blocked from login (even on teacher portal)
    const t1PendingLogin = await anon.req<{ status: string }>('POST', '/api/auth/login', {
      email: teacher1Email,
      password: teacherPw,
      portal: 'teacher',
    });
    assert.strictEqual(t1PendingLogin.status, 403);
    assert.strictEqual(t1PendingLogin.data.status, 'pending');

    // Pending teacher appears in Admin overview stats & teacher requests
    const ov1 = await adminLoginClient.req<{
      stats: { pendingTeachers: number; totalParents: number; totalChildren: number };
    }>('GET', '/api/admin/overview-stats');
    assert.strictEqual(ov1.status, 200);
    assert.ok(ov1.data.stats.pendingTeachers >= 2);
    assert.ok(ov1.data.stats.totalParents >= 1);
    assert.ok(ov1.data.stats.totalChildren >= 1);

    const tList1 = await adminLoginClient.req<{ teachers: Array<{ id: string; status: string }> }>(
      'GET',
      '/api/admin/teachers',
    );
    assert.strictEqual(tList1.status, 200);
    assert.ok(tList1.data.teachers.some((x) => x.id === t1Reg.data.user.id && x.status === 'pending'));

    console.log('✓ TEST C passed: Teacher pending workflow & login blocked');

    // =========================================================================
    // TEST D: Admin Approves Teacher -> Login & Teacher Dashboard Succeeds
    // =========================================================================
    const approveRes = await adminLoginClient.req<{
      approved: boolean;
      teacher: { status: string; teacherProfile?: { approvedBy?: string; approvedAt?: string } };
    }>('POST', `/api/admin/teachers/${t1Reg.data.user.id}/approve`);
    assert.strictEqual(approveRes.status, 200);
    assert.strictEqual(approveRes.data.approved, true);
    assert.strictEqual(approveRes.data.teacher.status, 'active');
    assert.ok(approveRes.data.teacher.teacherProfile?.approvedBy);
    assert.ok(approveRes.data.teacher.teacherProfile?.approvedAt);

    // Teacher 1 can now sign in via Teacher portal and NOT via Admin portal
    const t1WrongPortal = await anon.req('POST', '/api/auth/login', {
      email: teacher1Email,
      password: teacherPw,
      portal: 'admin',
    });
    assert.strictEqual(t1WrongPortal.status, 403);

    const teacherClient = new E2ECookieClient();
    const t1Login = await teacherClient.req<{ user: { role: string }; dashboardRoute: string }>(
      'POST',
      '/api/auth/login',
      {
        email: teacher1Email,
        password: teacherPw,
        portal: 'teacher',
      },
    );
    assert.strictEqual(t1Login.status, 200);
    assert.strictEqual(t1Login.data.user.role, 'teacher');
    assert.strictEqual(t1Login.data.dashboardRoute, '/teacher-dashboard');

    // Active teacher accesses teacher endpoint cleanly
    const tOverview = await teacherClient.req('GET', '/api/teacher/classes');
    assert.strictEqual(tOverview.status, 200);

    console.log('✓ TEST D passed: Teacher approval grants Teacher Portal & API access');

    // =========================================================================
    // TEST E: Teacher Rejection (Reason Preserved) + Suspension & Reactivation
    // =========================================================================
    const rejectReason = 'Missing early-childhood teaching credentials';
    const rejectRes = await adminLoginClient.req<{
      rejected: boolean;
      teacher: { status: string; teacherProfile?: { rejectionReason?: string } };
    }>('POST', `/api/admin/teachers/${t2Reg.data.user.id}/reject`, {
      reason: rejectReason,
    });
    assert.strictEqual(rejectRes.status, 200);
    assert.strictEqual(rejectRes.data.rejected, true);
    assert.strictEqual(rejectRes.data.teacher.status, 'rejected');
    assert.strictEqual(rejectRes.data.teacher.teacherProfile?.rejectionReason, rejectReason);

    // Rejected teacher record still exists & login returns 403 with rejection reason
    const t2RejectedLogin = await anon.req<{ status: string; rejectionReason?: string }>(
      'POST',
      '/api/auth/login',
      {
        email: teacher2Email,
        password: teacherPw,
        portal: 'teacher',
      },
    );
    assert.strictEqual(t2RejectedLogin.status, 403);
    assert.strictEqual(t2RejectedLogin.data.status, 'rejected');
    assert.strictEqual(t2RejectedLogin.data.rejectionReason, rejectReason);

    // Suspend active teacher -> active session immediately revoked & blocked from teacher API + login
    const suspRes = await adminLoginClient.req<{ suspended: boolean; teacher: { status: string } }>(
      'POST',
      `/api/admin/teachers/${t1Reg.data.user.id}/suspend`,
      { reason: 'Temporary policy review' },
    );
    assert.strictEqual(suspRes.status, 200);
    assert.strictEqual(suspRes.data.suspended, true);
    assert.strictEqual(suspRes.data.teacher.status, 'suspended');

    const t1SessionAfterSuspend = await teacherClient.req('GET', '/api/teacher/classes');
    assert.strictEqual(t1SessionAfterSuspend.status, 401);

    const t1SuspendedLogin = await anon.req<{ status: string }>('POST', '/api/auth/login', {
      email: teacher1Email,
      password: teacherPw,
      portal: 'teacher',
    });
    assert.strictEqual(t1SuspendedLogin.status, 403);
    assert.strictEqual(t1SuspendedLogin.data.status, 'suspended');

    // Reactivate teacher -> login works again
    const reactRes = await adminLoginClient.req<{ reactivated: boolean; teacher: { status: string } }>(
      'POST',
      `/api/admin/teachers/${t1Reg.data.user.id}/reactivate`,
    );
    assert.strictEqual(reactRes.status, 200);
    assert.strictEqual(reactRes.data.teacher.status, 'active');

    const t1ReLogin = await teacherClient.req('POST', '/api/auth/login', {
      email: teacher1Email,
      password: teacherPw,
      portal: 'teacher',
    });
    assert.strictEqual(t1ReLogin.status, 200);

    console.log('✓ TEST E passed: Rejection reason preserved & Suspend/Reactivate revoke/restore sessions');

    // =========================================================================
    // TEST F: Authorization Boundaries, Lower Admin vs Super Admin & Redacted Parents
    // =========================================================================
    // Teacher cannot approve another teacher or access Admin APIs
    assert.strictEqual(
      (await teacherClient.req('POST', `/api/admin/teachers/${t2Reg.data.user.id}/approve`)).status,
      403,
    );
    assert.strictEqual((await teacherClient.req('GET', '/api/admin/admins')).status, 403);

    // Parent cannot create admin or approve teacher
    assert.strictEqual(
      (await parentClient.req('POST', '/api/admin/admins', { displayName: 'Fake', email: 'f@e.com', password: adminPw })).status,
      403,
    );
    assert.strictEqual(
      (await parentClient.req('POST', `/api/admin/teachers/${t2Reg.data.user.id}/approve`)).status,
      403,
    );

    // Super Admin creates subordinate 'admin' user
    const createSubAdmin = await adminLoginClient.req<{ admin: { id: string; role: string } }>(
      'POST',
      '/api/admin/admins',
      {
        displayName: 'Operations Admin',
        email: adminEmail,
        password: adminPw,
        role: 'admin',
      },
    );
    assert.strictEqual(createSubAdmin.status, 201);
    assert.strictEqual(createSubAdmin.data.admin.role, 'admin');

    // Subordinate 'admin' can log in & approve/manage teachers & view parents,
    // BUT CANNOT create other admins (manage_admins is super_admin ONLY)
    const subAdminClient = new E2ECookieClient();
    const subLogin = await subAdminClient.req('POST', '/api/auth/login', {
      email: adminEmail,
      password: adminPw,
      portal: 'admin',
    });
    assert.strictEqual(subLogin.status, 200);
    assert.strictEqual((await subAdminClient.req('GET', '/api/admin/overview-stats')).status, 200);
    assert.strictEqual(
      (
        await subAdminClient.req('POST', '/api/admin/admins', {
          displayName: 'Unauthorized Sub',
          email: `unauth.${suffix}@example.com`,
          password: adminPw,
          role: 'admin',
        })
      ).status,
      403,
    );

    // Parents directory exposes safe fields only (NO passwordHash, NO child PIN, NO access code)
    const parentsRes = await subAdminClient.req<{ parents: Array<Record<string, unknown>> }>(
      'GET',
      '/api/admin/parents',
    );
    assert.strictEqual(parentsRes.status, 200);
    const parentsJson = JSON.stringify(parentsRes.data);
    assert.ok(!parentsJson.includes('passwordHash'));
    assert.ok(!parentsJson.includes(childCreate.data.accessCode));
    assert.ok(!parentsJson.includes(childPin));

    // Verify Audit Logs captured Bootstrap, Teacher Register, Approve, Reject, Suspend, Reactivate, Admin Login
    const auditRes = await adminLoginClient.req<{ logs: Array<{ actionType?: string; eventType: string }> }>(
      'GET',
      '/api/admin/audit-logs?limit=50',
    );
    assert.strictEqual(auditRes.status, 200);
    const actions = new Set(auditRes.data.logs.map((l) => l.actionType || l.eventType));
    assert.ok(actions.has('ADMIN_BOOTSTRAP'), 'Audit log missing ADMIN_BOOTSTRAP');
    assert.ok(actions.has('TEACHER_REGISTER'), 'Audit log missing TEACHER_REGISTER');
    assert.ok(actions.has('TEACHER_APPROVED'), 'Audit log missing TEACHER_APPROVED');
    assert.ok(actions.has('TEACHER_REJECTED'), 'Audit log missing TEACHER_REJECTED');
    assert.ok(actions.has('TEACHER_SUSPENDED'), 'Audit log missing TEACHER_SUSPENDED');
    assert.ok(actions.has('TEACHER_REACTIVATED'), 'Audit log missing TEACHER_REACTIVATED');
    assert.ok(actions.has('ADMIN_LOGIN_SUCCESS'), 'Audit log missing ADMIN_LOGIN_SUCCESS');

    console.log('✓ TEST F passed: Strict RBAC boundaries, data redaction, & immutable audit trail');

    // =========================================================================
    // TEST G: Admin Logout Invalidates Server Session & Rejects Stale Replay
    // =========================================================================
    const capturedAdminCookie = adminLoginClient.getRawCookieHeader();
    assert.ok(capturedAdminCookie.includes('nono_session='));

    const logoutRes = await adminLoginClient.req<{ loggedOut: boolean }>('POST', '/api/auth/logout');
    assert.strictEqual(logoutRes.status, 200);
    assert.strictEqual(logoutRes.data.loggedOut, true);

    const meAfterLogout = await adminLoginClient.req<{ authenticated: boolean }>('GET', '/api/auth/me');
    assert.strictEqual(meAfterLogout.data.authenticated, false);

    // Replaying previously captured cookie header MUST fail with 401
    const replayRes = await fetch(`${BASE}/api/admin/overview-stats`, {
      headers: { cookie: capturedAdminCookie },
    });
    assert.strictEqual(replayRes.status, 401, 'Replayed session cookie after logout must return 401');

    // Verify LOGOUT event recorded in audit log using subAdminClient
    const auditAfterLogout = await subAdminClient.req<{ logs: Array<{ actionType?: string; eventType: string }> }>(
      'GET',
      '/api/admin/audit-logs?limit=20',
    );
    assert.strictEqual(auditAfterLogout.status, 200);
    assert.ok(
      auditAfterLogout.data.logs.some((l) => l.eventType === 'LOGOUT' || l.actionType === 'ADMIN_LOGOUT'),
      'Audit log should record ADMIN_LOGOUT',
    );

    console.log('✓ TEST G passed: Admin logout invalidates server session & prevents cookie replay');
    console.log('\nALL ADMIN PORTAL & BOOTSTRAP E2E TESTS (A–G) PASSED CLEANLY ✓');
  } finally {
    if (serverProc.pid) {
      try {
        process.kill(-serverProc.pid, 'SIGTERM');
      } catch {
        serverProc.kill('SIGTERM');
      }
    }
  }
}

run().catch((err) => {
  console.error('❌ E2E Verification Failed:', err);
  process.exit(1);
});
