import assert from 'assert';
import {
  ALL_LEVEL1_LESSONS,
  LEVEL1_ARABIC_LESSONS,
  LEVEL1_COLOR_LESSONS,
  LEVEL1_ENGLISH_LESSONS,
  LEVEL1_NUMBER_LESSONS,
  LEVEL1_REVIEW_UNITS,
} from '../src/data/level1Curriculum';
import { LEVEL1_CURRICULUM_COUNTS, LEVEL1_QUESTION_BANK } from '../src/data/level1QuestionBank';
import { VALIDATED_EXAM_BANK } from '../src/data/deepCurriculum';

const BASE = 'http://127.0.0.1:3000';

class CookieClient {
  cookie = '';
  csrfToken = '';

  async req(
    method: string,
    urlPath: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ) {
    const headers: Record<string, string> = { ...extraHeaders };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.cookie) headers['Cookie'] = this.cookie;
    if (this.csrfToken && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !('x-csrf-token' in headers)) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const res = await fetch(`${BASE}${urlPath}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    const setCookie = res.headers.get('set-cookie');
    if (setCookie) {
      const m = setCookie.match(/nono_session=([^;]+)/);
      if (m) {
        this.cookie = m[1] ? `nono_session=${m[1]}` : '';
      }
    }

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

async function main() {
  console.log('--- 1. LEVEL 1 CURRICULUM & BANK INTEGRITY ---');
  assert.strictEqual(LEVEL1_ARABIC_LESSONS.length, 28, 'Arabic must have 28 lessons');
  assert.strictEqual(LEVEL1_ENGLISH_LESSONS.length, 26, 'English must have 26 lessons');
  assert.strictEqual(LEVEL1_NUMBER_LESSONS.length, 11, 'Numbers must have 11 lessons (0..10)');
  assert.strictEqual(LEVEL1_COLOR_LESSONS.length, 10, 'Colors must have 10 lessons');
  assert.strictEqual(ALL_LEVEL1_LESSONS.length, 75, 'Total Level 1 lessons must equal 75');
  assert.strictEqual(LEVEL1_REVIEW_UNITS.length, 12, 'Must have 12 Review Units');
  assert.strictEqual(LEVEL1_CURRICULUM_COUNTS.totalQuestions, 750, 'Level 1 bank must have 750 items');
  assert.strictEqual(LEVEL1_QUESTION_BANK.length, 750);
  const qIds = new Set(LEVEL1_QUESTION_BANK.map((q) => q.id));
  assert.strictEqual(qIds.size, 750, 'All 750 question IDs must be unique');
  console.log('PASS: 75 Level 1 lessons, 12 Review Units, 750 unique questions verified.');

  console.log('--- 2. REGISTRATION, VALIDATION & EMAIL VERIFICATION ---');
  const suffix = Date.now();
  const parentA = new CookieClient();
  const emailA = `Parent.Alpha.${suffix}@example.com`;
  const pwA = 'NonoAcademy!2026Strong';

  // Reject weak password & missing terms
  const badReg1 = await parentA.req('POST', '/api/auth/register', {
    displayName: 'A',
    email: 'not-an-email',
    password: 'password123',
    termsAccepted: false,
  });
  assert.strictEqual(badReg1.status, 400);

  // Reject password containing email/name
  const badReg2 = await parentA.req('POST', '/api/auth/register', {
    displayName: 'Sarah',
    email: `sarah.${suffix}@example.com`,
    password: `Sarah${suffix}!Strong`,
    termsAccepted: true,
  });
  assert.strictEqual(badReg2.status, 400);

  // Valid registration
  const regRes = await parentA.req('POST', '/api/auth/register', {
    displayName: 'أم عمر — Sarah',
    email: emailA,
    password: pwA,
    termsAccepted: true,
  });
  assert.strictEqual(regRes.status, 201);
  assert.ok(parentA.cookie.includes('nono_session='), 'HttpOnly session cookie must be set');
  assert.ok(parentA.csrfToken.length > 10, 'CSRF token must be issued');
  assert.ok(regRes.headers.get('x-content-type-options') === 'nosniff');
  assert.ok(regRes.headers.get('x-frame-options') === 'SAMEORIGIN');

  // Duplicate normalized email (lowercase) rejected with 409
  const dupReg = await new CookieClient().req('POST', '/api/auth/register', {
    displayName: 'Duplicate User',
    email: emailA.toLowerCase(),
    password: pwA,
    termsAccepted: true,
  });
  assert.strictEqual(dupReg.status, 409);

  // Email verification single-use
  const verifyToken = String(regRes.data.devVerificationToken || '');
  assert.ok(verifyToken.length > 0);
  const verOk = await parentA.req('POST', '/api/auth/verify-email', { token: verifyToken });
  assert.strictEqual(verOk.status, 200);
  const verReuse = await parentA.req('POST', '/api/auth/verify-email', { token: verifyToken });
  assert.strictEqual(verReuse.status, 400, 'Verification token cannot be reused');
  console.log('PASS: Registration, normalization, password policy, cookies & email verification verified.');

  console.log('--- 3. CSRF & CHILD OWNERSHIP (IDOR PROTECTION) ---');
  // CSRF missing on authenticated POST -> 403
  const noCsrf = await parentA.req(
    'POST',
    '/api/children',
    { displayName: 'Omar', ageGroup: '1-4', language: 'ar', birthYear: 2023, birthMonth: 3 },
    { 'x-csrf-token': 'invalid-csrf' },
  );
  assert.strictEqual(noCsrf.status, 403, 'CSRF mismatch must block mutation with 403');

  // Unauthenticated /api/children -> 401
  const unauthChild = await new CookieClient().req('GET', '/api/children');
  assert.strictEqual(unauthChild.status, 401);

  // Invalid child birthYear rejected -> 400
  const badChild = await parentA.req('POST', '/api/children', {
    displayName: '<b>Bad</b>',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 1990,
    birthMonth: 5,
  });
  assert.strictEqual(badChild.status, 400);

  // Deprecated age stages (5-6, 7, 8) rejected for new child profiles -> 400
  for (const deprecatedStage of ['5-6', '7', '8']) {
    const oldStageRes = await parentA.req('POST', '/api/children', {
      displayName: 'OldStageKid',
      ageGroup: deprecatedStage,
      language: 'en',
      birthYear: 2023,
      birthMonth: 2,
    });
    assert.strictEqual(oldStageRes.status, 400, `Stage ${deprecatedStage} must be rejected`);
  }

  // Valid child created by Parent A under Little Explorers (1-4 Years)
  const chRes = await parentA.req('POST', '/api/children', {
    displayName: 'ليلى الصغيرة',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 4,
  });
  assert.strictEqual(chRes.status, 201);
  const childA = chRes.data.child as { id: string; displayName: string };

  // Register Parent B & test IDOR access against childA
  const parentB = new CookieClient();
  const regB = await parentB.req('POST', '/api/auth/register', {
    displayName: 'Parent Beta',
    email: `beta.${suffix}@example.com`,
    password: 'BetaParent!2026Pass',
    termsAccepted: true,
  });
  assert.strictEqual(regB.status, 201);

  const idorPatch = await parentB.req('PATCH', `/api/children/${childA.id}`, { displayName: 'Hacked' });
  assert.strictEqual(idorPatch.status, 403, 'Parent B must get 403 on Parent A child PATCH');

  const idorL1 = await parentB.req('POST', '/api/level1/assessment/start', {
    childId: childA.id,
    lessonId: 'AR01',
  });
  assert.strictEqual(idorL1.status, 403, 'Parent B must get 403 starting Level 1 quiz for childA');

  const idorPay = await parentB.req('POST', '/api/payments/create-checkout', {
    childId: childA.id,
    subject: 'arabic',
    parentConfirmed: true,
  });
  assert.strictEqual(idorPay.status, 403, 'Parent B must get 403 creating payment for childA');
  console.log('PASS: CSRF protection and IDOR cross-parent isolation verified.');

  console.log('--- 4. LEVEL 1 BACKEND-GRADED ASSESSMENT (AR01 & NM01 ZERO) ---');
  const l1Start = await parentA.req('POST', '/api/level1/assessment/start', {
    childId: childA.id,
    lessonId: 'AR01',
    questionCount: 6,
  });
  assert.strictEqual(l1Start.status, 200);
  const l1Qs = l1Start.data.questions as Array<{ id: string; correctOptionId?: string }>;
  assert.strictEqual(l1Qs.length, 6);
  assert.ok(!l1Qs[0].correctOptionId, 'correctOptionId must NEVER leak before submission');

  const answerMap: Record<string, string> = {};
  for (const q of l1Qs) {
    const bankQ = LEVEL1_QUESTION_BANK.find((item) => item.id === q.id)!;
    answerMap[q.id] = bankQ.correctOptionId;
  }

  const l1Sub = await parentA.req('POST', '/api/level1/assessment/submit', {
    attemptId: l1Start.data.attemptId,
    answers: answerMap,
  });
  assert.strictEqual(l1Sub.status, 200);
  assert.strictEqual(l1Sub.data.percentage, 100);
  assert.strictEqual(l1Sub.data.demonstrated, true);
  assert.strictEqual(l1Sub.data.status, 'demonstrated');

  // Duplicate submission blocked
  const l1Dup = await parentA.req('POST', '/api/level1/assessment/submit', {
    attemptId: l1Start.data.attemptId,
    answers: {},
  });
  assert.strictEqual(l1Dup.data.duplicateBlocked, true);

  // Failing attempt (<80%) schedules needs-revision
  const l1FailStart = await parentA.req('POST', '/api/level1/assessment/start', {
    childId: childA.id,
    lessonId: 'NM01',
    questionCount: 5,
  });
  const l1FailSub = await parentA.req('POST', '/api/level1/assessment/submit', {
    attemptId: l1FailStart.data.attemptId,
    answers: {},
  });
  assert.strictEqual(l1FailSub.data.demonstrated, false);
  assert.strictEqual(l1FailSub.data.status, 'needs-revision');
  console.log('PASS: Level 1 backend grading, non-leak, duplicate guard & revision state verified.');

  console.log('--- 5. 40-QUESTION OFFICIAL EXAM, PAYMENT & 28/40 CERTIFICATION RULE ---');
  // Cannot start official exam without verified payment
  const unpaidOfficial = await parentA.req('POST', '/api/exams/start', {
    childId: childA.id,
    childName: childA.displayName,
    ageGroup: '1-4',
    subject: 'comprehensive',
    mode: 'official',
  });
  assert.strictEqual(unpaidOfficial.status, 402);

  // Create checkout (server enforces 50 EGP even if client tries sending price: 1)
  const chk1 = await parentA.req('POST', '/api/payments/create-checkout', {
    childId: childA.id,
    subject: 'comprehensive',
    parentConfirmed: true,
    amountEgp: 0, // ignored by server!
  });
  assert.strictEqual(chk1.status, 200);
  assert.strictEqual(chk1.data.amountEgp, 50);

  const verPay1 = await parentA.req('POST', '/api/payments/verify', {
    checkoutSessionId: chk1.data.checkoutSessionId,
  });
  assert.strictEqual(verPay1.status, 200);
  const payTok1 = String(verPay1.data.paymentVerificationToken);

  // Start Official Exam #1 -> Fail with 27/40 (68% < 70%)
  const ex1Start = await parentA.req('POST', '/api/exams/start', {
    childId: childA.id,
    childName: childA.displayName,
    ageGroup: '1-4',
    subject: 'comprehensive',
    mode: 'official',
    paymentVerificationToken: payTok1,
  });
  assert.strictEqual(ex1Start.status, 200);
  const ex1Qs = ex1Start.data.questions as Array<{ id: string }>;
  assert.strictEqual(ex1Qs.length, 40, 'Official exam must contain 40 questions');

  // Reusing same payment token blocked
  const reusePay = await parentA.req('POST', '/api/exams/start', {
    childId: childA.id,
    ageGroup: '1-4',
    mode: 'official',
    paymentVerificationToken: payTok1,
  });
  assert.strictEqual(reusePay.status, 402);

  const answers27: Record<string, string> = {};
  ex1Qs.slice(0, 27).forEach((q) => {
    const full = VALIDATED_EXAM_BANK.find((item) => item.id === q.id)!;
    answers27[q.id] = full.correctOptionId;
  });
  const ex1Sub = await parentA.req('POST', '/api/exams/submit', {
    attemptId: ex1Start.data.attemptId,
    answers: answers27,
  });
  assert.strictEqual((ex1Sub.data.summary as { score: number }).score, 27);
  assert.strictEqual((ex1Sub.data.summary as { passed: boolean }).passed, false);
  assert.ok(!ex1Sub.data.certificate, '27/40 MUST NOT issue a certificate');

  // Official Exam #2 -> Pass with 28/40 (70% >= 70%)
  const chk2 = await parentA.req('POST', '/api/payments/create-checkout', {
    childId: childA.id,
    subject: 'comprehensive',
    parentConfirmed: true,
  });
  const verPay2 = await parentA.req('POST', '/api/payments/verify', {
    checkoutSessionId: chk2.data.checkoutSessionId,
  });
  const ex2Start = await parentA.req('POST', '/api/exams/start', {
    childId: childA.id,
    childName: childA.displayName,
    ageGroup: '1-4',
    subject: 'comprehensive',
    mode: 'official',
    paymentVerificationToken: verPay2.data.paymentVerificationToken,
  });
  const ex2Qs = ex2Start.data.questions as Array<{ id: string }>;
  const answers28: Record<string, string> = {};
  ex2Qs.slice(0, 28).forEach((q) => {
    const full = VALIDATED_EXAM_BANK.find((item) => item.id === q.id)!;
    answers28[q.id] = full.correctOptionId;
  });
  const ex2Sub = await parentA.req('POST', '/api/exams/submit', {
    attemptId: ex2Start.data.attemptId,
    answers: answers28,
  });
  assert.strictEqual((ex2Sub.data.summary as { score: number }).score, 28);
  assert.strictEqual((ex2Sub.data.summary as { passed: boolean }).passed, true);
  const cert = ex2Sub.data.certificate as { uniqueCode: string };
  assert.ok(cert?.uniqueCode, '28/40 MUST issue a verifiable official certificate');

  // Public verification endpoint returns valid: true
  const certCheck = await new CookieClient().req('GET', `/api/certificates/verify/${cert.uniqueCode}`);
  assert.strictEqual(certCheck.status, 200);
  assert.strictEqual(certCheck.data.valid, true);
  console.log('PASS: 40-question exam, payment lock, 27/40 fail vs 28/40 pass & certificate verification passed.');

  console.log('--- 6. RBAC, LOCKOUT, PASSWORD RESET SESSION REVOCATION & PAYLOAD LIMITS ---');
  // Parent A cannot access Admin endpoints (RBAC 403!)
  const parentAdminTry = await parentA.req('GET', '/api/admin/overview', undefined, {
    'x-admin-pin': '2026', // Even with dev PIN, authenticated 'parent' role must be blocked 403!
  });
  assert.strictEqual(parentAdminTry.status, 403, 'Authenticated parent must get 403 on admin endpoints');

  // Promote Parent B to content_admin via dev admin pin -> can manage lessons, gets 403 on exam-config
  const roleSet = await new CookieClient().req(
    'POST',
    '/api/admin/users/role',
    { userId: (regB.data.user as { id: string }).id, role: 'content_admin' },
    { 'x-admin-pin': process.env.ADMIN_PIN || '2026' },
  );
  assert.strictEqual(roleSet.status, 200);

  const caOverview = await parentB.req('GET', '/api/admin/overview');
  assert.strictEqual(caOverview.status, 200);
  const caConfig = await parentB.req('PUT', '/api/admin/exam-config', { examPriceEgp: 99 });
  assert.strictEqual(caConfig.status, 403, 'content_admin cannot change exam pricing');

  // Oversized payload -> 413
  const bigStr = 'x'.repeat(600 * 1024);
  const bigRes = await parentA.req('POST', '/api/children', {
    displayName: bigStr,
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 1,
  });
  assert.strictEqual(bigRes.status, 413, 'Oversized payload (>512kb) must return 413');

  // 5 wrong logins trigger temporary 429 lockout
  const lockEmail = `lock.${suffix}@example.com`;
  await new CookieClient().req('POST', '/api/auth/register', {
    displayName: 'Lock Test',
    email: lockEmail,
    password: pwA,
    termsAccepted: true,
  });
  for (let i = 0; i < 4; i++) {
    const f = await new CookieClient().req('POST', '/api/auth/login', {
      email: lockEmail,
      password: 'WrongPassword!1234',
    });
    assert.strictEqual(f.status, 401);
  }
  const locked = await new CookieClient().req('POST', '/api/auth/login', {
    email: lockEmail,
    password: 'WrongPassword!1234',
  });
  assert.strictEqual(locked.status, 429, '5th wrong login must trigger temporary lockout');

  // Forgot password generic response + reset revokes all active sessions
  const forgotUnknown = await new CookieClient().req('POST', '/api/auth/forgot-password', {
    email: `nonexistent.${suffix}@example.com`,
  });
  assert.strictEqual(forgotUnknown.status, 200);

  const forgotA = await new CookieClient().req('POST', '/api/auth/forgot-password', {
    email: emailA,
  });
  assert.strictEqual(forgotA.status, 200);
  const resetTok = String(forgotA.data.devResetToken);
  const newPw = 'UpdatedNono!2026Secure';
  const resetOk = await new CookieClient().req('POST', '/api/auth/reset-password', {
    token: resetTok,
    newPassword: newPw,
  });
  assert.strictEqual(resetOk.status, 200);

  // Parent A's old session cookie must now be revoked
  const oldSessionMe = await parentA.req('GET', '/api/auth/me');
  assert.strictEqual(oldSessionMe.data.authenticated, false, 'Password reset must revoke active sessions');

  // SQLi/XSS string in child name rejected cleanly
  const xssRes = await parentB.req('POST', '/api/children', {
    displayName: "<script>alert('xss')</script>",
    ageGroup: '1-4',
    language: 'en',
    birthYear: 2023,
    birthMonth: 2,
  });
  assert.strictEqual(xssRes.status, 400, 'Angle-bracket XSS payload rejected in displayName');

  console.log('ALL VERIFICATION TESTS PASSED!');
}

main().catch((err) => {
  console.error('TEST FAILURE:', err);
  process.exit(1);
});
