import assert from 'assert';

const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';

class FamilyTestClient {
  cookies = new Map<string, string>();
  csrfToken = '';

  private buildCookieHeader(): string {
    return Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }

  private captureCookies(res: Response) {
    const getSetCookie = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie;
    const rawList = typeof getSetCookie === 'function'
      ? getSetCookie.call(res.headers)
      : res.headers.get('set-cookie')
        ? [res.headers.get('set-cookie')!]
        : [];

    for (const entry of rawList) {
      for (const name of ['nono_session', 'nono_device']) {
        const re = new RegExp(`${name}=([^;]+)`);
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

    const res = await fetch(`${BASE}${urlPath}`, {
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

async function main() {
  const ts = Date.now();
  const parentPw = 'FamilyEco!2026Secure';

  console.log('=== 1. PARENT REGISTRATION & PRIVATE FAMILY ISOLATION ===');
  const parentA = new FamilyTestClient();
  const regA = await parentA.req('POST', '/api/auth/register', {
    displayName: 'Walid Family A',
    email: `fam.a.${ts}@example.com`,
    password: parentPw,
    termsAccepted: true,
  });
  assert.strictEqual(regA.status, 201, 'Parent A must register');

  const childARes = await parentA.req('POST', '/api/children', {
    displayName: 'كريم الصغير',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 6,
  });
  assert.strictEqual(childARes.status, 201);
  const childA = childARes.data.child as { id: string; displayName: string; familyId: string };
  assert.ok(childA.familyId, 'Child A must belong to a private familyId');

  const parentB = new FamilyTestClient();
  const regB = await parentB.req('POST', '/api/auth/register', {
    displayName: 'Mona Family B',
    email: `fam.b.${ts}@example.com`,
    password: parentPw,
    termsAccepted: true,
  });
  assert.strictEqual(regB.status, 201);
  const childBRes = await parentB.req('POST', '/api/children', {
    displayName: 'سلمى',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 8,
  });
  assert.strictEqual(childBRes.status, 201);
  const childB = childBRes.data.child as { id: string; familyId: string };
  assert.notStrictEqual(childA.familyId, childB.familyId, 'Families must have distinct familyIds');

  // Cross-family IDOR rejection
  assert.strictEqual(
    (await parentB.req('GET', `/api/family/children/${childA.id}/adaptive-profile`)).status,
    403,
  );
  assert.strictEqual(
    (await parentB.req('GET', `/api/family/children/${childA.id}/weekly-report`)).status,
    403,
  );
  assert.strictEqual(
    (await parentB.req('GET', `/api/children/${childA.id}/garden`)).status,
    403,
  );
  console.log('PASS: Private family spaces & cross-family isolation verified.');

  console.log('=== 2. PARENT GATE + CHILD ACCESS CODE & HASHED PIN ===');
  // Locked Parent Gate blocks child credentials management
  const lockedCredGet = await parentA.req('GET', `/api/family/children/${childA.id}/credentials`);
  assert.strictEqual(lockedCredGet.status, 403);
  assert.strictEqual(lockedCredGet.data.code, 'PARENT_GATE_REQUIRED');

  // Set Parent Gate PIN (requires account password)
  const setPinRes = await parentA.req('POST', '/api/parent/gate/pin', {
    currentPassword: parentPw,
    newPin: '4829',
  });
  assert.strictEqual(setPinRes.status, 200);
  assert.strictEqual(setPinRes.data.verified, true);

  // Lock & verify PIN fail/success
  await parentA.req('POST', '/api/parent/gate/lock', {});
  const badGate = await parentA.req('POST', '/api/parent/gate/verify', { pin: '0000' });
  assert.strictEqual(badGate.status, 401);
  const okGate = await parentA.req('POST', '/api/parent/gate/verify', { pin: '4829' });
  assert.strictEqual(okGate.status, 200);
  assert.strictEqual(okGate.data.verified, true);

  // Create Child Access Code + PIN
  const createCredRes = await parentA.req('POST', `/api/family/children/${childA.id}/credentials`, {
    pin: '2580',
  });
  assert.strictEqual(createCredRes.status, 201);
  const accessCode = String(createCredRes.data.accessCode || '');
  assert.ok(/^NL-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(accessCode), 'Access code must be non-guessable NL-XXXX-XXXX');
  console.log('PASS: Parent Gate & Child Access Code/PIN creation verified.');

  console.log('=== 3. CHILD LOGIN, PIN LOCKOUT & STRICT CHILD RBAC ===');
  const badChildLogin = await new FamilyTestClient().req('POST', '/api/auth/child-login', {
    accessCode,
    pin: '9999',
  });
  assert.strictEqual(badChildLogin.status, 401);

  const childClient = new FamilyTestClient();
  const childLoginRes = await childClient.req('POST', '/api/auth/child-login', {
    accessCode,
    pin: '2580',
  });
  assert.strictEqual(childLoginRes.status, 200);
  const childUser = childLoginRes.data.user as { role: string; linkedChildId: string };
  assert.strictEqual(childUser.role, 'child');
  assert.strictEqual(childUser.linkedChildId, childA.id);

  // Child blocked from parent, family governance, admin, teacher, and Family B child endpoints
  assert.strictEqual((await childClient.req('GET', '/api/family/guardians')).status, 403);
  assert.strictEqual((await childClient.req('GET', '/api/family/devices')).status, 403);
  assert.strictEqual((await childClient.req('GET', '/api/family/activity-logs')).status, 403);
  assert.strictEqual((await childClient.req('PUT', '/api/family/content-policy', { allowVideos: false })).status, 403);
  assert.strictEqual((await childClient.req('PUT', '/api/family/privacy', { aiFeaturesConsent: false })).status, 403);
  assert.strictEqual((await childClient.req('POST', '/api/parent/gate/verify', { pin: '4829' })).status, 403);
  assert.strictEqual((await childClient.req('GET', '/api/admin/overview')).status, 403);
  assert.strictEqual((await childClient.req('GET', '/api/teacher/classes')).status, 403);
  assert.strictEqual((await childClient.req('GET', `/api/children/${childB.id}/garden`)).status, 403);
  console.log('PASS: Child Login & strict RBAC isolation verified.');

  console.log('=== 4. TRUSTED FAMILY DEVICES & SESSION REVOCATION ===');
  const regDevRes = await parentA.req('POST', '/api/family/devices/register-current', {
    deviceName: 'Family Living Room iPad',
    trusted: true,
  });
  assert.strictEqual(regDevRes.status, 201);
  const deviceA = regDevRes.data.device as { id: string };
  assert.ok(parentA.cookies.has('nono_device'), 'Trusted device HttpOnly cookie must be issued');

  // Untrusted client sees zero profiles
  const untrustedProfiles = await new FamilyTestClient().req('GET', '/api/auth/trusted-device-profiles');
  assert.strictEqual(untrustedProfiles.data.trusted, false);
  assert.strictEqual((untrustedProfiles.data.profiles as unknown[]).length, 0);

  // Client carrying Parent A's nono_device cookie sees ONLY Family A children (never childB)
  const sharedDeviceClient = new FamilyTestClient();
  sharedDeviceClient.cookies.set('nono_device', parentA.cookies.get('nono_device')!);
  const devProfiles = await sharedDeviceClient.req('GET', '/api/auth/trusted-device-profiles');
  assert.strictEqual(devProfiles.status, 200);
  assert.strictEqual(devProfiles.data.trusted, true);
  const profileIds = (devProfiles.data.profiles as Array<{ id: string }>).map((p) => p.id);
  assert.ok(profileIds.includes(childA.id));
  assert.ok(!profileIds.includes(childB.id), 'Trusted device MUST NOT leak other families');

  // Quick login on trusted device fails for cross-family child & succeeds for childA
  const crossQuick = await sharedDeviceClient.req('POST', '/api/auth/child-quick-login', {
    childId: childB.id,
    pin: '2580',
  });
  assert.strictEqual(crossQuick.status, 401);

  const okQuick = await sharedDeviceClient.req('POST', '/api/auth/child-quick-login', {
    childId: childA.id,
    pin: '2580',
  });
  assert.strictEqual(okQuick.status, 200);

  // Revoke device -> sharedDeviceClient's child session must immediately terminate
  const revokeDev = await parentA.req('POST', `/api/family/devices/${deviceA.id}/revoke`, {});
  assert.strictEqual(revokeDev.status, 200);
  const afterRevokeMe = await sharedDeviceClient.req('GET', '/api/auth/me');
  assert.strictEqual(afterRevokeMe.data.authenticated, false, 'Device revocation must terminate linked sessions immediately');
  console.log('PASS: Trusted family device isolation & immediate session revocation verified.');

  console.log('=== 5. MULTIPLE GUARDIANS & CAREGIVER PERMISSIONS ===');
  const guardianEmail = `guardian.c.${ts}@example.com`;
  const inviteRes = await parentA.req('POST', '/api/family/guardians/invite', {
    email: guardianEmail,
    role: 'secondary_guardian',
  });
  assert.strictEqual(inviteRes.status, 201);
  const inviteToken = String(inviteRes.data.inviteToken || '');
  assert.ok(inviteToken.length > 12);

  // Wrong email Parent B cannot accept Parent A's guardian invitation
  const mismatchAccept = await parentB.req('POST', '/api/family/guardians/accept', { inviteToken });
  assert.strictEqual(mismatchAccept.status, 403);
  assert.strictEqual(mismatchAccept.data.code, 'INVITE_EMAIL_MISMATCH');

  // Guardian C registers & accepts
  const guardianC = new FamilyTestClient();
  const regC = await guardianC.req('POST', '/api/auth/register', {
    displayName: 'Grandma Nadia',
    email: guardianEmail,
    password: parentPw,
    termsAccepted: true,
  });
  assert.strictEqual(regC.status, 201);

  const acceptOk = await guardianC.req('POST', '/api/family/guardians/accept', { inviteToken });
  assert.strictEqual(acceptOk.status, 200);
  const membership = acceptOk.data.membership as { id: string };

  // Secondary guardian can view reports/adaptive profile, but cannot manage_credentials (not in default secondary perms)
  assert.strictEqual(
    (await guardianC.req('GET', `/api/family/children/${childA.id}/adaptive-profile`)).status,
    200,
  );
  await guardianC.req('POST', '/api/parent/gate/verify', { password: parentPw });
  assert.strictEqual(
    (await guardianC.req('GET', `/api/family/children/${childA.id}/credentials`)).status,
    403,
  );

  // Revoke Guardian C -> immediate termination
  const revokeG = await parentA.req('DELETE', `/api/family/guardians/${membership.id}`);
  assert.strictEqual(revokeG.status, 200);
  const revokedGuardianCheck = await guardianC.req('GET', `/api/family/children/${childA.id}/adaptive-profile`);
  assert.ok(revokedGuardianCheck.status === 401 || revokedGuardianCheck.status === 403);
  console.log('PASS: Multi-guardian invitation, email-match check, permissions & revocation verified.');

  console.log('=== 6. ADAPTIVE PROFILE, WEEKLY REPORT & TOGETHER TIME SEPARATION ===');
  const adaptiveRes = await parentA.req('GET', `/api/family/children/${childA.id}/adaptive-profile`);
  assert.strictEqual(adaptiveRes.status, 200);
  assert.strictEqual((adaptiveRes.data.skills as unknown[]).length, 10, 'Adaptive profile must track 10 domains');
  assert.ok(adaptiveRes.data.nextRecommendedActivity, 'Deterministic recommendation required');

  // Weekly report starts honestly with 0 fabricated minutes
  const week0Res = await parentA.req('GET', `/api/family/children/${childA.id}/weekly-report`);
  assert.strictEqual(week0Res.status, 200);
  const rep0 = week0Res.data.report as { metrics: { totalMinutes: number; lessonsCompleted: number; togetherActivitiesCount: number } };
  assert.strictEqual(rep0.metrics.totalMinutes, 0);
  assert.strictEqual(rep0.metrics.lessonsCompleted, 0);

  // Log a Together Time activity as Parent A -> must increment togetherActivitiesCount & minutes, NEVER skillProgress.attempts
  const preSkills = (await parentA.req('GET', `/api/family/children/${childA.id}/adaptive-profile`)).data.skills as Array<{ attempts: number }>;
  const preAttemptsSum = preSkills.reduce((s, sk) => s + sk.attempts, 0);

  const togetherRes = await parentA.req('POST', `/api/children/${childA.id}/family-activity`, {
    activityKey: 'tog-color-hunt',
    title: { ar: 'صيد الألوان معاً', en: 'Color Treasure Hunt' },
    durationMinutes: 6,
    reflectionNote: 'Loved finding blue and yellow toys!',
  });
  assert.strictEqual(togetherRes.status, 201);
  assert.strictEqual(togetherRes.data.gardenRewardAwarded, true);

  const postSkills = (await parentA.req('GET', `/api/family/children/${childA.id}/adaptive-profile`)).data.skills as Array<{ attempts: number }>;
  const postAttemptsSum = postSkills.reduce((s, sk) => s + sk.attempts, 0);
  assert.strictEqual(postAttemptsSum, preAttemptsSum, 'Together Time MUST NOT inflate independent child skillProgress attempts');

  const week1Res = await parentA.req('GET', `/api/family/children/${childA.id}/weekly-report`);
  const rep1 = week1Res.data.report as { metrics: { totalMinutes: number; togetherActivitiesCount: number } };
  assert.strictEqual(rep1.metrics.togetherActivitiesCount, 1);
  assert.strictEqual(rep1.metrics.totalMinutes, 6);
  console.log('PASS: Adaptive profile, honest UTC weekly report & Together Time separation verified.');

  console.log('=== 7. PERSONAL LEARNING GARDEN CONCURRENT IDEMPOTENCY ===');
  const waterRes = await childClient.req('POST', `/api/children/${childA.id}/garden/water`, {});
  assert.strictEqual(waterRes.status, 200);
  assert.strictEqual((waterRes.data.garden as { wateringCount: number }).wateringCount, 1);

  // Qualify 'reading-stage' without auto-claiming (practice attempt <75%), then race 5 concurrent claim requests
  const readPractice = await childClient.req('POST', `/api/children/${childA.id}/reading/complete-stage`, {
    stage: 1,
    correctCount: 1,
    totalCount: 4,
  });
  assert.strictEqual(readPractice.status, 200);

  const claimResults = await Promise.all(
    Array.from({ length: 5 }, () =>
      childClient.req('POST', `/api/children/${childA.id}/garden/claim-milestone`, {
        milestoneKey: 'reading-stage',
      }),
    ),
  );
  const awardedCount = claimResults.filter((r) => r.status === 200 && r.data.awarded === true).length;
  assert.strictEqual(awardedCount, 1, 'Concurrent milestone claim must award ONLY ONCE');
  console.log('PASS: Learning Garden watering & concurrent milestone idempotency verified.');

  console.log('=== 8. PRIVACY CONSENT WITHDRAWAL ENFORCEMENT & AUDIT LOG REDACTION ===');
  const withdrawRes = await parentA.req('PUT', '/api/family/privacy', {
    aiFeaturesConsent: false,
    voiceInteractionConsent: false,
  });
  assert.strictEqual(withdrawRes.status, 200);

  const blockedAiChat = await childClient.req('POST', '/api/ai/nono-chat', {
    childId: childA.id,
    message: 'Teach me Arabic letter Alif',
    language: 'en',
  });
  assert.strictEqual(blockedAiChat.status, 403);
  assert.strictEqual(blockedAiChat.data.code, 'AI_DISABLED_BY_PARENT');

  const blockedTts = await childClient.req('POST', '/api/ai/tts', {
    childId: childA.id,
    text: 'Hello explorer!',
    language: 'en',
  });
  assert.strictEqual(blockedTts.status, 403);
  assert.strictEqual(blockedTts.data.code, 'VOICE_DISABLED_BY_PARENT');

  const exportRes = await parentA.req('POST', '/api/family/privacy/export', {});
  assert.strictEqual(exportRes.status, 200);
  assert.ok(exportRes.data.exportPackage);

  const delReqRes = await parentA.req('POST', '/api/family/privacy/delete-request', { note: 'Test audit' });
  assert.strictEqual(delReqRes.status, 201);

  const auditRes = await parentA.req('GET', '/api/family/activity-logs');
  assert.strictEqual(auditRes.status, 200);
  const auditText = JSON.stringify(auditRes.data.events);
  assert.ok(!auditText.includes(accessCode), 'Plaintext Child Access Code MUST NOT appear in audit logs');
  assert.ok(!auditText.includes('2580'), 'Plaintext Child PIN MUST NOT appear in audit logs');
  assert.ok(!auditText.includes('4829'), 'Plaintext Parent Gate PIN MUST NOT appear in audit logs');
  console.log('PASS: Privacy consent enforcement, export/delete & audit secret redaction verified.');

  console.log('=== 9. SAFE CHILD REMOVAL WITH AUDIT TRAIL PRESERVATION ===');
  const delChildRes = await parentA.req('POST', `/api/family/children/${childA.id}/delete`, {
    reason: 'End-to-end verification cleanup',
  });
  assert.strictEqual(delChildRes.status, 200);
  assert.strictEqual(delChildRes.data.deleted, true);

  const childAfterDel = await childClient.req('GET', '/api/auth/me');
  assert.strictEqual(childAfterDel.data.authenticated, false, 'Deleted child active session must be revoked');

  const auditAfterDel = await parentA.req('GET', '/api/family/activity-logs?category=profile');
  assert.ok((auditAfterDel.data.events as unknown[]).length >= 1, 'Audit record preserved after child removal');
  console.log('PASS: Safe child removal & audit trail preservation verified.');

  console.log('\nALL FAMILY ECOSYSTEM SECURITY & FEATURE TESTS PASSED!');
}

main().catch((err) => {
  console.error('FAMILY ECOSYSTEM TEST FAILURE:', err);
  process.exit(1);
});
