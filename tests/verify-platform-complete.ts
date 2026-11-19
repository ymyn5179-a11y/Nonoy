import assert from 'assert';
import {
  evaluateSkillUpdate,
  getAdaptiveRecommendation,
  getAdventureMapProgress,
} from '../src/engine/adaptiveEngine';
import { createInitialSkillProgress, createSampleChildProfiles } from '../src/data/rewardsAndRoom';

const BASE = 'http://127.0.0.1:3000';
const DEV_ADMIN_PIN = '2026';

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
    let payload: BodyInit | undefined;
    if (body instanceof FormData) {
      payload = body;
    } else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }

    if (this.cookie) headers['Cookie'] = this.cookie;
    if (
      this.csrfToken &&
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) &&
      !('x-csrf-token' in headers)
    ) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const res = await fetch(`${BASE}${urlPath}`, {
      method,
      headers,
      body: payload,
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

    return { status: res.status, headers: res.headers, data, rawText: text };
  }
}

async function main() {
  const ts = Date.now();
  const adminHeaders = { 'x-admin-pin': DEV_ADMIN_PIN };
  const adminClient = new CookieClient();

  console.log('=== 1. ADAPTIVE ENGINE & ADVENTURE MAP UNIT CHECKS ===');
  const sampleChildren = createSampleChildProfiles();
  const freshChild = {
    ...sampleChildren[0],
    completedActivityIds: [],
    attempts: [],
    skillProgress: createInitialSkillProgress(),
  };

  // Multi-evidence mastery: 1 single correct try must NEVER mark skill mastered
  const after1Try = evaluateSkillUpdate(freshChild.skillProgress['early-recognition'], { accuracy: 100 });
  assert.notStrictEqual(
    after1Try.masteryLevel,
    'mastered',
    '1 single correct activity must NOT mark skill as mastered',
  );
  assert.strictEqual(after1Try.masteryLevel, 'growing');

  // Adventure map prerequisites: fresh child with 0 completions should have advanced worlds locked (upcoming)
  const freshMap = getAdventureMapProgress(freshChild);
  const arabicNode = freshMap.find((w) => w.world.id === 'arabic-letters');
  const scienceNode = freshMap.find((w) => w.world.id === 'science-galaxy');
  assert.ok(arabicNode && arabicNode.status === 'available', 'Arabic Letters should be open as starter world');
  assert.ok(scienceNode && scienceNode.status === 'upcoming', 'Science island must remain upcoming until prerequisites are earned');

  const rec = getAdaptiveRecommendation(freshChild);
  assert.ok(rec.reason.ar && rec.reason.en && rec.activity.id, 'Adaptive recommendation must provide bilingual reason');
  console.log('PASS: Adaptive multi-evidence mastery & earned prerequisite map locking verified.');

  console.log('=== 2. SETUP TEACHER, PARENT, CLASS & STUDENTS ===');
  const teacherClient = new CookieClient();
  const tEmail = `hw.teacher.${ts}@example.com`;
  const tPass = 'StrongTeacherPass!2026';
  const regT = await teacherClient.req('POST', '/api/auth/register-teacher', {
    displayName: 'Prof. Salma',
    email: tEmail,
    password: tPass,
    confirmPassword: tPass,
    subjects: ['arabic', 'math'],
    termsAccepted: true,
  });
  assert.strictEqual(regT.status, 201);
  const teacherId = (regT.data.user as { id: string }).id;

  const actT = await adminClient.req('PATCH', `/api/admin/teachers/${teacherId}`, { status: 'active' }, adminHeaders);
  assert.strictEqual(actT.status, 200);

  const loginT = await teacherClient.req('POST', '/api/auth/login', { email: tEmail, password: tPass });
  assert.strictEqual(loginT.status, 200);

  const parentClient = new CookieClient();
  const pEmail = `hw.parent.${ts}@example.com`;
  const pPass = 'StrongParentPass!2026';
  const regP = await parentClient.req('POST', '/api/auth/register', {
    displayName: 'Parent Hoda',
    email: pEmail,
    password: pPass,
    termsAccepted: true,
  });
  assert.strictEqual(regP.status, 201);

  const childRes1 = await parentClient.req('POST', '/api/children', {
    displayName: 'Zain',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 4,
  });
  assert.strictEqual(childRes1.status, 201);
  const childId = (childRes1.data.child as { id: string }).id;

  // Create student credential for Zain
  const stuEmail = `zain.${ts}@example.com`;
  const stuPass = 'BlueRocket!2026Secure';
  const stuCred = await parentClient.req('POST', `/api/parent/children/${childId}/student-account`, {
    email: stuEmail,
    password: stuPass,
  });
  assert.strictEqual(stuCred.status, 201);

  const studentClient = new CookieClient();
  const stuLogin = await studentClient.req('POST', '/api/auth/login', { email: stuEmail, password: stuPass });
  assert.strictEqual(stuLogin.status, 200);

  // Create an unassigned student (not in teacher's class) to verify authorization boundaries
  const otherParentClient = new CookieClient();
  const opEmail = `other.parent.${ts}@example.com`;
  await otherParentClient.req('POST', '/api/auth/register', {
    displayName: 'Other Parent',
    email: opEmail,
    password: pPass,
    termsAccepted: true,
  });
  const otherChildRes = await otherParentClient.req('POST', '/api/children', {
    displayName: 'Unassigned Kid',
    ageGroup: '1-4',
    language: 'en',
    birthYear: 2023,
    birthMonth: 6,
  });
  assert.strictEqual(otherChildRes.status, 201);
  const otherChildId = (otherChildRes.data.child as { id: string }).id;
  const oStuEmail = `other.stu.${ts}@example.com`;
  const oStuCred = await otherParentClient.req('POST', `/api/parent/children/${otherChildId}/student-account`, {
    email: oStuEmail,
    password: stuPass,
  });
  assert.strictEqual(oStuCred.status, 201);
  const otherStudentClient = new CookieClient();
  const oStuLogin = await otherStudentClient.req('POST', '/api/auth/login', { email: oStuEmail, password: stuPass });
  assert.strictEqual(oStuLogin.status, 200);

  // Admin creates class assigning Zain to Prof. Salma
  const clsRes = await adminClient.req('POST', '/api/admin/classes', {
    name: `Class A-${ts}`,
    subject: 'arabic',
    level: 2,
    teacherId,
    studentIds: [childId],
  }, adminHeaders);
  assert.strictEqual(clsRes.status, 201);
  const classId = (clsRes.data.classroom as { id: string }).id;
  console.log('PASS: Teacher, Parent, Class & Students ready.');

  console.log('=== 3. FEATURE FLAGS RBAC & SERVER ENFORCEMENT ===');
  const nonAdminFlag = await studentClient.req('PUT', '/api/admin/feature-flags', { teacherHomeworkEnabled: false });
  assert.strictEqual(nonAdminFlag.status, 403, 'Student must not modify feature flags');

  const disableHw = await adminClient.req('PUT', '/api/admin/feature-flags', { teacherHomeworkEnabled: false }, adminHeaders);
  assert.strictEqual(disableHw.status, 200);
  const blockedHwGet = await teacherClient.req('GET', '/api/teacher/homework');
  assert.strictEqual(blockedHwGet.status, 403, 'Homework endpoint must block when feature flag is off');
  await adminClient.req('PUT', '/api/admin/feature-flags', { teacherHomeworkEnabled: true }, adminHeaders);

  const disableL2 = await adminClient.req('PUT', '/api/admin/feature-flags', { level2Enabled: false }, adminHeaders);
  assert.strictEqual(disableL2.status, 200);
  const blockedL2Start = await studentClient.req('POST', '/api/level2/assessment/start', { childId, lessonId: 'L2-AR01' });
  assert.strictEqual(blockedL2Start.status, 403, 'Level 2 assessment must block when level2Enabled is false');
  await adminClient.req('PUT', '/api/admin/feature-flags', { level2Enabled: true }, adminHeaders);

  const disablePaid = await adminClient.req('PUT', '/api/admin/feature-flags', { paidAssessmentsEnabled: false }, adminHeaders);
  assert.strictEqual(disablePaid.status, 200);
  const blockedCheckout = await parentClient.req('POST', '/api/payments/create-checkout', { childId, subject: 'arabic', parentConfirmed: true });
  assert.strictEqual(blockedCheckout.status, 403, 'Checkout must block when paidAssessmentsEnabled is false');
  await adminClient.req('PUT', '/api/admin/feature-flags', { paidAssessmentsEnabled: true }, adminHeaders);
  console.log('PASS: Feature flags enforced server-side with RBAC protection.');

  console.log('=== 4. QUESTION QUALITY CHECKER, APPROVAL WORKFLOW & VERSION HISTORY ===');
  // Create flawed question (missing EN prompt + math lesson tagged as arabic)
  const flawedQ = await teacherClient.req('POST', '/api/teacher/questions', {
    subject: 'arabic',
    level: 2,
    lessonId: 'L2-MA01', // math lesson!
    questionType: 'multiple-choice',
    promptAr: 'ما ناتج الجمع؟',
    promptEn: '',
    options: [
      { id: 'a', textAr: '٢', textEn: '2' },
      { id: 'b', textAr: '٣', textEn: '3' },
    ],
    correctOptionId: 'a',
    marks: 2,
  });
  assert.strictEqual(flawedQ.status, 201);
  const flawedQFlags = ((flawedQ.data.question as { qualityFlags?: Array<{ code: string }> }).qualityFlags || []).map((f) => f.code);
  assert.ok(flawedQFlags.includes('MISSING_AR_OR_EN'), 'Quality checker must flag MISSING_AR_OR_EN');
  assert.ok(flawedQFlags.includes('SUBJECT_LESSON_MISMATCH'), 'Quality checker must flag SUBJECT_LESSON_MISMATCH');

  const auditRes = await adminClient.req('POST', '/api/admin/questions/quality-audit', {}, adminHeaders);
  assert.strictEqual(auditRes.status, 200);
  assert.ok((auditRes.data.flaggedCount as number) >= 1);

  // Create valid question for homework attachment
  const validQ = await teacherClient.req('POST', '/api/teacher/questions', {
    subject: 'arabic',
    level: 2,
    lessonId: 'L2-AR01',
    questionType: 'multiple-choice',
    promptAr: 'اختر الحرف بحركة الفتحة',
    promptEn: 'Pick the letter with Fatha',
    options: [
      { id: 'a', textAr: 'بَ', textEn: 'Ba' },
      { id: 'b', textAr: 'بُ', textEn: 'Bu' },
    ],
    correctOptionId: 'a',
    marks: 5,
  });
  assert.strictEqual(validQ.status, 201);
  const validQId = (validQ.data.question as { id: string }).id;

  // Enable requireTeacherContentApproval -> teacher homework publish goes to pending-review & is hidden from student
  await adminClient.req('PUT', '/api/admin/feature-flags', { requireTeacherContentApproval: true }, adminHeaders);

  console.log('=== 5. HOMEWORK ATTACHMENTS, DEADLINE ENFORCEMENT, EXTENSIONS, DUPLICATES & GRADING ===');
  // Test malicious executable rejection
  const badFd = new FormData();
  const exeBytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03]); // MZ header
  badFd.append('file', new Blob([exeBytes], { type: 'application/octet-stream' }), 'malware.exe');
  const badUpload = await teacherClient.req('POST', '/api/teacher/homework/attachments', badFd);
  assert.strictEqual(badUpload.status, 400, 'Executable file must be rejected');

  // Upload genuine valid PNG bytes
  const pngFd = new FormData();
  const validPngBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
  pngFd.append('file', new Blob([validPngBytes], { type: 'image/png' }), 'worksheet.png');
  const goodUpload = await teacherClient.req('POST', '/api/teacher/homework/attachments', pngFd);
  assert.strictEqual(goodUpload.status, 201);
  const attId = (goodUpload.data.attachment as { id: string }).id;

  // Unauthenticated access to attachment blocked
  const anonAtt = await new CookieClient().req('GET', `/api/homework/attachments/${attId}`);
  assert.strictEqual(anonAtt.status, 401);

  // Create homework with short deadline (1.5s from now) while requireTeacherContentApproval=true
  const hwCreate = await teacherClient.req('POST', '/api/teacher/homework', {
    title: { ar: 'واجب الحركات', en: 'Arabic Diacritics Homework' },
    instructions: { ar: 'أجب عن السؤال المرفق', en: 'Answer the attached question' },
    homeworkType: 'multiple-choice',
    subject: 'arabic',
    level: 2,
    lessonIds: ['L2-AR01'],
    questionIds: [validQId],
    attachmentIds: [attId],
    classIds: [classId],
    startDate: new Date(Date.now() - 5000).toISOString(),
    deadline: new Date(Date.now() + 1800).toISOString(),
    maxAttempts: 2,
    publish: true,
  });
  assert.strictEqual(hwCreate.status, 201);
  const hwId = (hwCreate.data.homework as { id: string }).id;
  assert.strictEqual((hwCreate.data.homework as { status: string }).status, 'pending-review');
  assert.strictEqual(hwCreate.data.requiresAdminApproval, true);

  // Unauthorized assignment to student outside teacher's classes must fail 403
  const unauthAssign = await teacherClient.req('POST', `/api/teacher/homework/${hwId}/assign`, {
    studentIds: [otherChildId],
  });
  assert.strictEqual(unauthAssign.status, 403);

  // Duplicate assignment to already-assigned Zain skips cleanly
  const dupAssign = await teacherClient.req('POST', `/api/teacher/homework/${hwId}/assign`, {
    studentIds: [childId],
  });
  assert.strictEqual(dupAssign.status, 201);
  assert.strictEqual(dupAssign.data.addedCount, 0);
  assert.strictEqual(dupAssign.data.skippedDuplicates, 1);

  // Student MUST NOT see pending-review homework
  const stuHwPending = await studentClient.req('GET', '/api/student/homework');
  assert.strictEqual(stuHwPending.status, 200);
  assert.strictEqual((stuHwPending.data.newAssignments as unknown[]).length, 0, 'Unapproved homework must NOT appear to students');

  // Admin approves & publishes homework (creates version snapshot!)
  const adminApproveHw = await adminClient.req('PATCH', `/api/admin/content/homework/${hwId}/review`, {
    status: 'published',
    feedback: 'Looks wonderful!',
  }, adminHeaders);
  assert.strictEqual(adminApproveHw.status, 200);
  assert.strictEqual((adminApproveHw.data.item as { version: number }).version, 2);

  // Verify suspended hides it from student immediately, then restore back to published
  await adminClient.req('PATCH', `/api/admin/content/homework/${hwId}/review`, { status: 'suspended' }, adminHeaders);
  const stuHwSuspended = await studentClient.req('GET', '/api/student/homework');
  assert.strictEqual((stuHwSuspended.data.newAssignments as unknown[]).length, 0, 'Suspended homework must be hidden from students');
  await adminClient.req('PATCH', `/api/admin/content/homework/${hwId}/review`, { status: 'published' }, adminHeaders);

  // Check version history endpoint
  const verRes = await teacherClient.req('GET', `/api/content/homework/${hwId}/versions`);
  assert.strictEqual(verRes.status, 200);
  assert.ok((verRes.data.versions as unknown[]).length >= 3, 'Version history must preserve immutable snapshots');

  // Assigned student can download attachment, unassigned student is blocked 403
  const otherAttGet = await otherStudentClient.req('GET', `/api/homework/attachments/${attId}`);
  assert.strictEqual(otherAttGet.status, 403, 'Unassigned student must not access homework attachment');
  const stuAttGet = await studentClient.req('GET', `/api/homework/attachments/${attId}`);
  assert.strictEqual(stuAttGet.status, 200);

  // Student opens homework, waits past deadline -> submission blocked 403
  await studentClient.req('POST', `/api/student/homework/${hwId}/open`, { studentId: childId });
  await new Promise((r) => setTimeout(r, 2000));
  const lateFail = await studentClient.req('POST', `/api/student/homework/${hwId}/submit`, {
    studentId: childId,
    answers: { [validQId]: 'a' },
  });
  assert.strictEqual(lateFail.status, 403, 'Late submission without teacher extension must be rejected');

  // Teacher tracks student -> sees subId -> grants deadline extension
  const trackRes = await teacherClient.req('GET', `/api/teacher/homework/${hwId}/tracking`);
  assert.strictEqual(trackRes.status, 200);
  const subId = (trackRes.data.tracking as Array<{ id: string }>)[0].id;
  const extRes = await teacherClient.req('PATCH', `/api/teacher/homework/submissions/${subId}/extend`, {
    extendedDeadline: new Date(Date.now() + 86400_000).toISOString(),
    reason: 'Family travel extension',
  });
  assert.strictEqual(extRes.status, 200);

  // Now student submits cleanly -> duplicate submission & post-submit save are BOTH blocked 409!
  const submitOk = await studentClient.req('POST', `/api/student/homework/${hwId}/submit`, {
    studentId: childId,
    answers: { [validQId]: 'a' },
  });
  assert.strictEqual(submitOk.status, 200);
  assert.strictEqual((submitOk.data.submission as { percentage: number }).percentage, 100);

  const dupSubmit = await studentClient.req('POST', `/api/student/homework/${hwId}/submit`, {
    studentId: childId,
    answers: { [validQId]: 'a' },
  });
  assert.strictEqual(dupSubmit.status, 409, 'Duplicate homework submission must be blocked');

  const postEdit = await studentClient.req('POST', `/api/student/homework/${hwId}/save`, {
    studentId: childId,
    answers: { [validQId]: 'b' },
  });
  assert.strictEqual(postEdit.status, 409, 'Post-submit edit must be blocked');

  // Teacher leaves feedback -> Parent sees homework + teacher feedback (NOT admin private notes)
  await teacherClient.req('PATCH', `/api/teacher/homework/submissions/${subId}/grade`, {
    percentage: 100,
    teacherFeedback: 'Excellent mastery of Fatha!',
  });

  const pOverview = await parentClient.req('GET', `/api/parent/children/${childId}/overview`);
  assert.strictEqual(pOverview.status, 200);
  const hwRow = (pOverview.data.assignedHomeworks as Array<Record<string, unknown>>)[0];
  assert.strictEqual(hwRow.teacherFeedback, 'Excellent mastery of Fatha!');
  assert.strictEqual(hwRow.adminFeedback, undefined, 'Admin private notes must never leak into Parent Overview');
  await adminClient.req('PUT', '/api/admin/feature-flags', { requireTeacherContentApproval: false }, adminHeaders);
  console.log('PASS: Homework lifecycle, attachment security, deadlines, extensions, anti-tamper & parent isolation verified.');

  console.log('=== 6. IDEMPOTENT OFFLINE SYNC DEDUPLICATION ===');
  const syncKey = `sync_${ts}_unique_1`;
  const [syncA, syncB] = await Promise.all([
    studentClient.req('POST', '/api/student/sync', {
      childId,
      items: [{ idempotencyKey: syncKey, kind: 'game-attempt', payload: { activityId: 'act-1', starsEarned: 2, durationSeconds: 120 } }],
    }),
    studentClient.req('POST', '/api/student/sync', {
      childId,
      items: [{ idempotencyKey: syncKey, kind: 'game-attempt', payload: { activityId: 'act-1', starsEarned: 2, durationSeconds: 120 } }],
    }),
  ]);
  assert.strictEqual(syncA.status, 200);
  assert.strictEqual(syncB.status, 200);
  // Across the two calls, totalStars must be identical (credited strictly once, never twice!)
  assert.strictEqual(syncA.data.totalStars, syncB.data.totalStars, 'Duplicate sync key must never double-credit stars');

  const syncReplay = await studentClient.req('POST', '/api/student/sync', {
    childId,
    items: [{ idempotencyKey: syncKey, kind: 'game-attempt', payload: { activityId: 'act-1', starsEarned: 2 } }],
  });
  assert.strictEqual((syncReplay.data.duplicateKeys as string[]).includes(syncKey), true);
  console.log('PASS: Idempotent offline sync prevented duplicate star rewards cleanly.');

  console.log('=== 7. OPS INTEGRITY, FILTERED AUDIT LOGS, SANITIZED BACKUP & RESTORE ===');
  const intRes = await adminClient.req('GET', '/api/admin/ops/integrity', undefined, adminHeaders);
  assert.strictEqual(intRes.status, 200);
  assert.strictEqual(intRes.data.healthy, true);
  assert.ok((intRes.data.operationalMetrics as { totalApiRequests: number }).totalApiRequests > 0);

  const logsRes = await adminClient.req('GET', '/api/admin/audit-logs?eventType=HOMEWORK_ACTION', undefined, adminHeaders);
  assert.strictEqual(logsRes.status, 200);
  assert.ok((logsRes.data.logs as unknown[]).length >= 1);

  const bkpRes = await adminClient.req('GET', '/api/admin/ops/backup', undefined, adminHeaders);
  assert.strictEqual(bkpRes.status, 200);
  const backupObj = bkpRes.data.backup as Record<string, unknown>;
  assert.deepStrictEqual(backupObj.sessions, {}, 'Exported backup must never expose active session tokens');

  const restRes = await adminClient.req('POST', '/api/admin/ops/restore', { backup: backupObj }, adminHeaders);
  assert.strictEqual(restRes.status, 200);
  assert.strictEqual(restRes.data.restored, true);
  console.log('PASS: Ops integrity, filtered audit logs, sanitized backup & restore verified.');

  console.log('\n✅ ALL COMPLETE PLATFORM ENHANCEMENT VERIFICATION CHECKS PASSED!');
}

main().catch((err) => {
  console.error('❌ Verification failed:', err);
  process.exit(1);
});
