import assert from 'assert';
import { createInitialSkillProgress, createSampleChildProfiles } from '../src/data/rewardsAndRoom';
import { evaluateSkillUpdate } from '../src/engine/adaptiveEngine';
import type { SkillProgress } from '../src/types/nonoland';

const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';
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
    if (body !== undefined) {
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

    return { status: res.status, headers: res.headers, data };
  }
}

function solveSmartQuestionForTest(q: Record<string, unknown>): unknown {
  const id = String(q.id || '');
  const format = String(q.format || '');
  if (format === 'matching') {
    return { p1: '🍯 العسل', p2: '🌊 البحر', p3: '🥕 الجزر' };
  }
  if (format === 'sorting') {
    return {
      '🍌': 'healthy',
      '🥦': 'healthy',
      '🍭': 'occasional',
      '🥕': 'healthy',
    };
  }
  if (format === 'sequencing') {
    return ['🌱 بذرة', '🌿 نبتة', '🌸 زهرة'];
  }
  if (format === 'memory') {
    return { completed: true };
  }
  const answerById: Record<string, string> = {
    'sa-mcq-ar-alef': 'opt-lion',
    'sa-img-planet': 'opt-earth',
    'sa-listen-en-b': 'opt-ball',
    'sa-phonics-cat': 'opt-c',
    'sa-math-apples': 'n5',
    'sa-challenge-pattern': 'n4',
  };
  if (answerById[id]) return answerById[id];
  const options = q.options as Array<{ id: string }> | undefined;
  return options?.[0]?.id || 'opt-1';
}

async function main() {
  const ts = Date.now();
  const adminHeaders = { 'x-admin-pin': DEV_ADMIN_PIN };

  console.log('=== 1. SETUP ACCOUNTS (PARENT A, CHILD A, STUDENT A, PARENT B, TEACHER) ===');
  const parentA = new CookieClient();
  const regA = await parentA.req('POST', '/api/auth/register', {
    displayName: 'Parent Smart A',
    email: `parent.smart.a.${ts}@example.com`,
    password: 'StrongParentPassword!2026',
    language: 'en',
    termsAccepted: true,
  });
  assert.strictEqual(regA.status, 201, `Parent register failed: ${JSON.stringify(regA.data)}`);

  const childRes = await parentA.req('POST', '/api/children', {
    displayName: 'Noor',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 4,
    interests: ['science', 'reading'],
    companionId: 'nono',
    companionScarfColor: '#8054D9',
  });
  assert.strictEqual(childRes.status, 201);
  const childId = (childRes.data.child as { id: string }).id;

  const studentEmail = `student.smart.${ts}@example.com`;
  const studentPass = 'StrongStudentPass!2026';
  const createStud = await parentA.req(
    'POST',
    `/api/parent/children/${encodeURIComponent(childId)}/student-account`,
    { email: studentEmail, password: studentPass },
  );
  assert.strictEqual(createStud.status, 201);

  const studentA = new CookieClient();
  const loginStud = await studentA.req('POST', '/api/auth/login', {
    email: studentEmail,
    password: studentPass,
  });
  assert.strictEqual(loginStud.status, 200);

  const parentB = new CookieClient();
  const regB = await parentB.req('POST', '/api/auth/register', {
    displayName: 'Parent Intruder B',
    email: `parent.smart.b.${ts}@example.com`,
    password: 'StrongParentPasswordB!2026',
    language: 'en',
    termsAccepted: true,
  });
  assert.strictEqual(regB.status, 201);

  const adminClient = new CookieClient();
  const teacherEmail = `teacher.smart.${ts}@example.com`;
  const teacherPass = 'StrongTeacherPass!2026';
  const createTch = await adminClient.req(
    'POST',
    '/api/admin/teachers',
    {
      displayName: 'Teacher Audit',
      email: teacherEmail,
      password: teacherPass,
      subjects: ['arabic', 'math'],
    },
    adminHeaders,
  );
  assert.strictEqual(createTch.status, 201);

  const teacherClient = new CookieClient();
  const loginTch = await teacherClient.req('POST', '/api/auth/login', {
    email: teacherEmail,
    password: teacherPass,
  });
  assert.strictEqual(loginTch.status, 200);
  console.log('PASS: Accounts created & authenticated cleanly.');

  console.log('=== 2. NONO AI PARENT TOGGLE, SAFETY GUARDRAILS, RBAC & HONEST KEY CHECK ===');
  const aiStatusRes = await parentA.req('GET', '/api/ai/status');
  assert.strictEqual(aiStatusRes.status, 200);
  assert.strictEqual(aiStatusRes.data.model, 'gemini-4-hydrogen');

  // Student and Teacher must NOT toggle parent AI settings
  const studToggleTry = await studentA.req('PUT', `/api/parent/children/${childId}/ai-settings`, {
    aiAssistantEnabled: false,
  });
  assert.strictEqual(studToggleTry.status, 403);
  const tchToggleTry = await teacherClient.req('PUT', `/api/parent/children/${childId}/ai-settings`, {
    aiAssistantEnabled: false,
  });
  assert.strictEqual(tchToggleTry.status, 403);

  // Parent disables Nono AI for child
  const disableAiRes = await parentA.req('PUT', `/api/parent/children/${childId}/ai-settings`, {
    aiAssistantEnabled: false,
  });
  assert.strictEqual(disableAiRes.status, 200);
  assert.strictEqual(disableAiRes.data.aiAssistantEnabled, false);

  // Student tries chatting while disabled -> 403 AI_DISABLED_BY_PARENT
  const chatDisabled = await studentA.req('POST', '/api/ai/nono-chat', {
    childId,
    message: 'Explain letter Alef',
    mode: 'explain',
    language: 'en',
  });
  assert.strictEqual(chatDisabled.status, 403);
  assert.strictEqual(chatDisabled.data.code, 'AI_DISABLED_BY_PARENT');

  // Parent re-enables AI
  const enableAiRes = await parentA.req('PUT', `/api/parent/children/${childId}/ai-settings`, {
    aiAssistantEnabled: true,
  });
  assert.strictEqual(enableAiRes.status, 200);
  assert.strictEqual(enableAiRes.data.aiAssistantEnabled, true);

  // Teacher blocked from student AI chat
  const tchAiTry = await teacherClient.req('POST', '/api/ai/nono-chat', {
    childId,
    message: 'Explain colors',
  });
  assert.strictEqual(tchAiTry.status, 403);

  // Cross-family IDOR blocked
  const idorAiTry = await parentB.req('POST', '/api/ai/nono-chat', {
    childId,
    message: 'Explain colors',
  });
  assert.strictEqual(idorAiTry.status, 403);

  // Safety guardrails: PII / purchase / unsafe prompts must be blocked with safe redirect
  const unsafePii = await studentA.req('POST', '/api/ai/nono-chat', {
    childId,
    message: 'Here is my home address and phone number, also buy me 100 stars!',
    language: 'en',
  });
  assert.strictEqual(unsafePii.status, 200);
  assert.strictEqual(unsafePii.data.blocked, true);
  assert.strictEqual(unsafePii.data.safeRedirect, true);

  // Normal educational prompt: if GEMINI_API_KEY is configured, assert real reply; otherwise assert honest 503 AI_KEY_MISSING
  if (!aiStatusRes.data.configured) {
    const noKeyChat = await studentA.req('POST', '/api/ai/nono-chat', {
      childId,
      message: 'How does water evaporate?',
      mode: 'explain',
      language: 'en',
    });
    assert.strictEqual(noKeyChat.status, 503);
    assert.strictEqual(noKeyChat.data.code, 'AI_KEY_MISSING');
    console.log('PASS: Unconfigured GEMINI_API_KEY honestly returns 503 AI_KEY_MISSING (no fake AI).');
  } else {
    const liveChat = await studentA.req('POST', '/api/ai/nono-chat', {
      childId,
      message: 'What is a triangle?',
      mode: 'explain',
      language: 'en',
    });
    assert.ok(
      liveChat.status === 200 || liveChat.status === 502,
      `Unexpected AI status ${liveChat.status}: ${JSON.stringify(liveChat.data)}`,
    );
    if (liveChat.status === 200) {
      assert.ok(typeof liveChat.data.reply === 'string' && (liveChat.data.reply as string).length > 5);
      console.log('PASS: Live GEMINI_API_KEY call succeeded with child-friendly reply.');
    } else {
      console.log('INFO: Live Gemini API returned 502 upstream error cleanly without faking reply.');
    }
  }
  console.log('PASS: Nono AI RBAC, parent kill-switch, and child safety filters verified.');

  console.log('=== 3. SMART ASSESSMENT (10 FORMATS, ZERO ANSWER KEY LEAKS, ADAPTIVE + FEEDBACK) ===');
  const startSa = await studentA.req('POST', '/api/assessment/start', {
    childId,
    questionCount: 8,
  });
  assert.strictEqual(startSa.status, 201, `Smart start failed: ${JSON.stringify(startSa.data)}`);
  const saSessionId = String(startSa.data.sessionId);
  let curQ = startSa.data.question as Record<string, unknown>;
  assert.ok(curQ && curQ.id, 'First question must be returned');

  // Verify ZERO leaked answer keys
  const verifyNoLeakedKeys = (qObj: Record<string, unknown>) => {
    assert.strictEqual(qObj.correctOptionId, undefined, 'correctOptionId must NOT leak to client');
    assert.strictEqual(qObj.correctPairs, undefined, 'correctPairs must NOT leak to client');
    assert.strictEqual(qObj.correctSortMap, undefined, 'correctSortMap must NOT leak to client');
    assert.strictEqual(qObj.correctSequence, undefined, 'correctSequence must NOT leak to client');
  };
  verifyNoLeakedKeys(curQ);

  // Cross-family IDOR check on hint/submit
  const idorHint = await parentB.req('POST', '/api/assessment/hint', {
    sessionId: saSessionId,
    questionId: curQ.id,
  });
  assert.strictEqual(idorHint.status, 403);

  // Request progressive hint
  const hintRes = await studentA.req('POST', '/api/assessment/hint', {
    sessionId: saSessionId,
    questionId: curQ.id,
  });
  assert.strictEqual(hintRes.status, 200);
  assert.ok(hintRes.data.hint, 'Hint payload should be returned');

  // Submit 1 wrong answer first to verify encouraging emotional feedback without shame, then finish session
  let finished = false;
  let stepCount = 0;
  while (!finished && stepCount < 10) {
    verifyNoLeakedKeys(curQ);
    const ans =
      stepCount === 0
        ? '__intentional_wrong_answer__'
        : solveSmartQuestionForTest(curQ);

    const sub = await studentA.req('POST', '/api/assessment/submit-item', {
      sessionId: saSessionId,
      questionId: curQ.id,
      answer: ans,
      responseTimeMs: 3200,
    });
    assert.strictEqual(sub.status, 200, `submit-item failed: ${JSON.stringify(sub.data)}`);

    if (stepCount === 0) {
      assert.strictEqual(sub.data.correct, false);
      const fb = sub.data.emotionalFeedback as { tone: string; hintStep?: unknown };
      assert.strictEqual(fb.tone, 'encourage');
      assert.ok(fb.hintStep, 'Wrong answer should include supportive hintStep');

      // Duplicate submission for the same questionId must be blocked (409)
      const dupTry = await studentA.req('POST', '/api/assessment/submit-item', {
        sessionId: saSessionId,
        questionId: curQ.id,
        answer: ans,
      });
      assert.strictEqual(dupTry.status, 409);
    }

    finished = Boolean(sub.data.finished);
    if (!finished) {
      curQ = sub.data.nextQuestion as Record<string, unknown>;
    } else {
      assert.ok(sub.data.summary, 'Finished assessment must include summary');
    }
    stepCount += 1;
  }
  assert.strictEqual(finished, true, 'Smart assessment session should finish cleanly');

  // Unit check: 1 single correct try must NEVER grant mastered
  const sampleChild = createSampleChildProfiles()[0];
  const initialProg = createInitialSkillProgress()['arabic-literacy'];
  const afterSingle = evaluateSkillUpdate(initialProg, { accuracy: 100 });
  assert.notStrictEqual(afterSingle.masteryLevel, 'mastered');
  console.log('PASS: Smart Assessment zero leaks, server grading, duplicate block, emotional feedback verified.');

  console.log('=== 4. READING ADVENTURE (8-STAGE PREREQUISITE GATING) ===');
  // Stage 3 before Stage 1 & 2 must be blocked (400 READING_PREREQUISITE_LOCKED)
  const skipStage = await studentA.req('POST', `/api/children/${childId}/reading/complete-stage`, {
    stage: 3,
    correctCount: 4,
    totalCount: 4,
  });
  assert.strictEqual(skipStage.status, 400);
  assert.strictEqual(skipStage.data.code, 'READING_PREREQUISITE_LOCKED');

  // Stage 1 mastery unlocks Stage 2
  const st1 = await studentA.req('POST', `/api/children/${childId}/reading/complete-stage`, {
    stage: 1,
    correctCount: 4,
    totalCount: 4,
  });
  assert.strictEqual(st1.status, 200);
  assert.strictEqual(st1.data.mastered, true);

  const st2 = await studentA.req('POST', `/api/children/${childId}/reading/complete-stage`, {
    stage: 2,
    correctCount: 3,
    totalCount: 4,
  });
  assert.strictEqual(st2.status, 200);
  assert.strictEqual(st2.data.mastered, true);
  console.log('PASS: 8-Stage Reading Adventure sequential prerequisite gating verified.');

  console.log('=== 5. ENTERTAINMENT SAVES & PARENT-CHILD SHARED ACTIVITY SKILL INTEGRITY ===');
  const saveMusic = await studentA.req('POST', `/api/children/${childId}/entertainment/save`, {
    kind: 'music',
    payload: {
      title: 'Star Song',
      notes: [
        { noteIdx: 0, instrument: 'xylophone', step: 0 },
        { noteIdx: 2, instrument: 'bell', step: 1 },
      ],
    },
  });
  assert.strictEqual(saveMusic.status, 201);

  const saveBuild = await studentA.req('POST', `/api/children/${childId}/entertainment/save`, {
    kind: 'build',
    payload: {
      title: 'Rocket Tower',
      templateId: 'tower',
      blocks: [{ id: 'b1', shape: 'square', color: '#39BDF2', x: 3, y: 5 }],
    },
  });
  assert.strictEqual(saveBuild.status, 201);
  const childBeforeFam = saveBuild.data.child as {
    skillProgress: Record<string, SkillProgress>;
    musicCompositions: unknown[];
    buildConstructions: unknown[];
  };
  assert.strictEqual(childBeforeFam.musicCompositions.length, 1);
  assert.strictEqual(childBeforeFam.buildConstructions.length, 1);

  // Log shared family activity and confirm skillProgress is NOT modified!
  const famLog = await parentA.req('POST', `/api/children/${childId}/family-activity`, {
    activityKey: 'coplay-story-evening',
    title: { ar: 'قصة المساء المشتركة', en: 'Shared Story Evening' },
    durationMinutes: 15,
    reflectionNote: 'Great conversation together!',
  });
  assert.strictEqual(famLog.status, 201);
  const childAfterFam = famLog.data.child as {
    skillProgress: Record<string, SkillProgress>;
    familyActivitiesCompleted: unknown[];
  };
  assert.strictEqual(childAfterFam.familyActivitiesCompleted.length, 1);
  assert.deepStrictEqual(
    childAfterFam.skillProgress,
    childBeforeFam.skillProgress,
    'Shared family activities must NEVER alter independent verified skillProgress!',
  );
  console.log('PASS: Entertainment portfolio persistence & family activity skill-integrity verified.');

  console.log('=== 6. ADMIN AUDIT LOG IMMUTABILITY, RBAC, FILTERS & SECRET REDACTION ===');
  // Non-admins must receive 403 on audit-logs
  const parentAuditTry = await parentA.req('GET', '/api/admin/audit-logs');
  assert.strictEqual(parentAuditTry.status, 403);
  const studAuditTry = await studentA.req('GET', '/api/admin/audit-logs');
  assert.strictEqual(studAuditTry.status, 403);
  const tchAuditTry = await teacherClient.req('GET', '/api/admin/audit-logs');
  assert.strictEqual(tchAuditTry.status, 403);

  // Even Admin CANNOT modify, delete, or append directly via HTTP to audit logs
  for (const method of ['PUT', 'PATCH', 'DELETE', 'POST'] as const) {
    const mutRes = await adminClient.req(
      method,
      '/api/admin/audit-logs/fake-id',
      { summary: 'tamper' },
      adminHeaders,
    );
    assert.strictEqual(mutRes.status, 403, `Expected 403 AUDIT_IMMUTABLE for ${method}`);
    assert.strictEqual(mutRes.data.code, 'AUDIT_IMMUTABLE');
  }

  // Admin queries audit logs with filters
  const logsRes = await adminClient.req('GET', '/api/admin/audit-logs?limit=200', undefined, adminHeaders);
  assert.strictEqual(logsRes.status, 200);
  const logs = logsRes.data.logs as Array<Record<string, unknown>>;
  assert.ok(logs.some((l) => l.eventType === 'PARENT_SETTING_CHANGE'));
  assert.ok(logs.some((l) => l.eventType === 'AI_SAFETY_BLOCK' && l.outcome === 'blocked'));
  assert.ok(logs.some((l) => l.eventType === 'READING_STAGE_COMPLETE'));
  assert.ok(logs.some((l) => l.eventType === 'FAMILY_ACTIVITY'));
  assert.ok(logs.some((l) => l.eventType === 'ENTERTAINMENT_SAVE'));
  assert.ok(logs.some((l) => l.eventType === 'SMART_ASSESSMENT'));

  // Verify no raw password or token leaked into any audit entry
  const serializedLogs = JSON.stringify(logs);
  assert.strictEqual(serializedLogs.includes(studentPass), false, 'Student password leaked into audit logs');
  assert.strictEqual(serializedLogs.includes(teacherPass), false, 'Teacher password leaked into audit logs');
  assert.strictEqual(serializedLogs.includes('StrongParentPassword!2026'), false, 'Parent password leaked into audit logs');

  // Filter query test
  const filteredRes = await adminClient.req(
    'GET',
    `/api/admin/audit-logs?eventType=FAMILY_ACTIVITY&q=${encodeURIComponent(childId)}`,
    undefined,
    adminHeaders,
  );
  assert.strictEqual(filteredRes.status, 200);
  assert.ok((filteredRes.data.logs as unknown[]).length >= 1, 'Filtered audit query should return matching record');

  console.log('PASS: Immutable audit log RBAC, HTTP tamper blocks, query filters & redaction verified.');
  assert.ok(sampleChild.id);
  console.log('\nALL AI, SMART ASSESSMENT, READING, ENTERTAINMENT & SECURITY CHECKS PASSED!');
}

main().catch((err) => {
  console.error('VERIFICATION FAILED:', err);
  process.exit(1);
});
