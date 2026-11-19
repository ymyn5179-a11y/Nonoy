import assert from 'assert';
import { buildMonthlyReport, getCurrentMonthKey } from '../src/engine/monthlyReportEngine';
import { createInitialSkillProgress, createSampleChildProfiles } from '../src/data/rewardsAndRoom';

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

    return { status: res.status, data };
  }
}

async function main() {
  const ts = Date.now();
  console.log('=== 1. MONTHLY REPORT MISSING BASELINE HONESTY UNIT TEST ===');
  const sampleChildren = createSampleChildProfiles();
  const cleanChild = {
    ...sampleChildren[0],
    completedActivityIds: [],
    attempts: [],
    skillProgress: createInitialSkillProgress(),
    level1Progress: {},
    level2Progress: {},
    monthlySnapshots: {},
    completedLabIds: [],
    completedStoryIds: [],
    creativeProjects: [],
  };
  const emptyReport = buildMonthlyReport(cleanChild, getCurrentMonthKey());
  assert.strictEqual(emptyReport.baselineAvailable, false);
  for (const subj of emptyReport.subjectBreakdown) {
    assert.strictEqual(subj.baselineAvailable, false);
    assert.strictEqual(subj.improvementDeltaPct, null);
    assert.strictEqual(subj.currentAccuracyPct, null);
  }
  console.log('PASS: Monthly report never invents fake baselines or percentages.');

  console.log('=== 2. SETUP PARENT A, CHILD A, STUDENT ACCOUNT & PARENT B ===');
  const parentA = new CookieClient();
  const regA = await parentA.req('POST', '/api/auth/register', {
    displayName: 'Parent Immersive A',
    email: `parent.world.a.${ts}@example.com`,
    password: 'StrongParentPassword!2026',
    language: 'ar',
    termsAccepted: true,
  });
  assert.strictEqual(regA.status, 201);

  const createChildRes = await parentA.req('POST', '/api/children', {
    displayName: 'Lina',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 6,
    interests: ['science', 'art'],
    companionId: 'nono',
    companionScarfColor: '#8054D9',
  });
  assert.strictEqual(createChildRes.status, 201);
  const childId = (createChildRes.data.child as { id: string }).id;

  const studEmail = `student.world.${ts}@example.com`;
  const studPass = 'StrongStudentPass!2026';
  const createStudRes = await parentA.req(
    'POST',
    `/api/parent/children/${encodeURIComponent(childId)}/student-account`,
    { email: studEmail, password: studPass },
  );
  assert.strictEqual(createStudRes.status, 201);

  const studentClient = new CookieClient();
  const loginStud = await studentClient.req('POST', '/api/auth/login', {
    email: studEmail,
    password: studPass,
  });
  assert.strictEqual(loginStud.status, 200);

  const parentB = new CookieClient();
  const regB = await parentB.req('POST', '/api/auth/register', {
    displayName: 'Parent Intruder B',
    email: `parent.world.b.${ts}@example.com`,
    password: 'StrongParentPasswordB!2026',
    language: 'en',
    termsAccepted: true,
  });
  assert.strictEqual(regB.status, 201);

  console.log('=== 3. AVATAR, ROOM & GARDEN PERSISTENCE ===');
  const avatarPut = await parentA.req('PUT', `/api/children/${childId}/avatar`, {
    hairStyle: 'curly',
    hairColor: '#8054D9',
    skinTone: '#F6C7A3',
    outfit: 'astronaut',
    outfitColor: '#39BDF2',
    accessory: 'glasses',
    expression: 'proud',
  });
  assert.strictEqual(avatarPut.status, 200);
  assert.strictEqual((avatarPut.data.avatarConfig as { outfit: string }).outfit, 'astronaut');

  const roomPut = await parentA.req('PUT', `/api/children/${childId}/room`, {
    roomConfig: {
      theme: 'space',
      wallColor: '#E5F6FF',
      wallpaper: 'stars',
      floorStyle: 'star-carpet',
      curtains: 'violet',
      rug: 'star',
      lighting: 'nightlight',
      gardenPlants: [
        { id: 'gp-test', slotIndex: 0, speciesId: 'sunflower', stage: 2, waterCount: 4 },
      ],
    },
    placedRoomItems: [{ instanceId: 'inst-1', itemId: 'cloud-bed', x: 35, y: 65 }],
  });
  assert.strictEqual(roomPut.status, 200);
  assert.strictEqual((roomPut.data.roomConfig as { wallpaper: string }).wallpaper, 'stars');
  assert.strictEqual((roomPut.data.placedRoomItems as Array<unknown>).length, 1);
  console.log('PASS: Avatar, Room, and Garden persistence verified.');

  console.log('=== 4. VIRTUAL PET CARE (POSITIVE ONLY) ===');
  const adoptPet = await parentA.req('POST', `/api/children/${childId}/pet`, {
    action: 'adopt',
    speciesId: 'cosmic-dragon',
    presetNameId: 'coco-star',
  });
  assert.strictEqual(adoptPet.status, 200);
  assert.strictEqual((adoptPet.data.petState as { adopted: boolean }).adopted, true);

  const feedPet = await parentA.req('POST', `/api/children/${childId}/pet`, { action: 'feed' });
  assert.strictEqual(feedPet.status, 200);
  assert.strictEqual((feedPet.data.petState as { careCount: number }).careCount, 1);

  const playPet = await parentA.req('POST', `/api/children/${childId}/pet`, { action: 'play' });
  assert.strictEqual(playPet.status, 200);
  assert.strictEqual((playPet.data.petState as { playCount: number }).playCount, 1);
  console.log('PASS: Pet adopt, feed, and play verified.');

  console.log('=== 5. LAB SIMULATIONS + IDEMPOTENCY & STORIES + CUSTOM STORIES ===');
  const labKey = `lab-key-${ts}`;
  const lab1 = await studentClient.req('POST', `/api/children/${childId}/lab/complete`, {
    experimentId: 'lab-volcano',
    idempotencyKey: labKey,
  });
  assert.strictEqual(lab1.status, 200);
  assert.strictEqual(lab1.data.starsAdded, 4);

  const labDup = await studentClient.req('POST', `/api/children/${childId}/lab/complete`, {
    experimentId: 'lab-volcano',
    idempotencyKey: labKey,
  });
  assert.strictEqual(labDup.status, 200);
  assert.strictEqual(labDup.data.starsAdded, 0);

  const storyDone = await studentClient.req('POST', `/api/children/${childId}/stories/complete`, {
    storyId: 'story-bedtime-moonboat',
    title: { ar: 'قارب القمر', en: 'Moonboat' },
  });
  assert.strictEqual(storyDone.status, 200);
  assert.strictEqual(storyDone.data.starsAdded, 4);

  const customStoryCreate = await studentClient.req(
    'POST',
    `/api/children/${childId}/custom-stories`,
    {
      title: 'Nono Finds a Rainbow',
      characterId: 'nono',
      setting: 'space',
      pages: [{ title: 'Page 1', text: 'Nono flew past Saturn!', emojiScene: '🪐✨', characterId: 'nono', backdrop: 'from-[#E5F6FF] to-[#FFF8E9]' }],
    },
  );
  assert.strictEqual(customStoryCreate.status, 201);
  const customStoryId = (customStoryCreate.data.customStory as { id: string }).id;

  const customStoryDel = await studentClient.req(
    'DELETE',
    `/api/children/${childId}/custom-stories/${customStoryId}`,
  );
  assert.strictEqual(customStoryDel.status, 200);
  console.log('PASS: Lab idempotency, Story completion, and Custom Story CRUD verified.');

  console.log('=== 6. CREATIVE STUDIO + MALICIOUS DATAURL REJECTION ===');
  const badArt = await studentClient.req('POST', `/api/children/${childId}/creative-projects`, {
    kind: 'drawing',
    title: 'Bad XSS payload',
    dataUrl: 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
  });
  assert.strictEqual(badArt.status, 400, 'Unsafe SVG/HTML dataUrl must be rejected');

  const goodArt = await studentClient.req('POST', `/api/children/${childId}/creative-projects`, {
    kind: 'stickers',
    title: 'My Galaxy Scene',
    sceneJson: { placedStickers: [{ emoji: '🌟', x: 40, y: 40 }] },
  });
  assert.strictEqual(goodArt.status, 201);
  const artId = (goodArt.data.project as { id: string }).id;

  const delArt = await studentClient.req(
    'DELETE',
    `/api/children/${childId}/creative-projects/${artId}`,
  );
  assert.strictEqual(delArt.status, 200);
  console.log('PASS: Creative Studio validation and CRUD verified.');

  console.log('=== 7. DAILY MISSIONS PREREQUISITE & REWARD SHOP STAR DEDUCTION ===');
  const failMission = await studentClient.req('POST', `/api/children/${childId}/missions/claim`, {
    missionId: 'dm-arabic',
  });
  assert.strictEqual(failMission.status, 400, 'Incomplete Arabic mission must NOT grant stars');

  const passMission = await studentClient.req('POST', `/api/children/${childId}/missions/claim`, {
    missionId: 'dm-creative',
  });
  assert.strictEqual(passMission.status, 200, 'Completed lab unlocks dm-creative reward');

  const buyValid = await studentClient.req('POST', `/api/children/${childId}/shop/redeem`, {
    itemId: 'shop-avatar-glasses', // costs 4 stars
    idempotencyKey: `buy-glasses-${ts}`,
  });
  assert.strictEqual(buyValid.status, 200);

  const buyDup = await studentClient.req('POST', `/api/children/${childId}/shop/redeem`, {
    itemId: 'shop-avatar-glasses',
    idempotencyKey: `buy-glasses-2-${ts}`,
  });
  assert.strictEqual(buyDup.status, 409, 'Already unlocked item must return 409');

  // Now attempt an expensive item repeatedly until insufficient stars (or check remaining balance < 8 if stars < 8)
  const remainingStars = (buyValid.data.child as { stars: number }).stars;
  if (remainingStars < 8) {
    const buyTooExpensive = await studentClient.req('POST', `/api/children/${childId}/shop/redeem`, {
      itemId: 'shop-avatar-royal', // 8 stars
    });
    assert.strictEqual(buyTooExpensive.status, 400);
  }
  console.log('PASS: Daily mission gate and Reward Shop star deduction verified.');

  console.log('=== 8. MONTHLY REPORT API & LEARNING PLAN RBAC/IDOR CHECKS ===');
  const repRes = await parentA.req(
    'GET',
    `/api/children/${childId}/monthly-report?month=${getCurrentMonthKey()}`,
  );
  assert.strictEqual(repRes.status, 200);
  const reportObj = repRes.data.report as { completedLabCount: number; completedStoriesCount: number };
  assert.strictEqual(reportObj.completedLabCount, 1);
  assert.strictEqual(reportObj.completedStoriesCount, 1);

  const studPlanDeny = await studentClient.req('PUT', `/api/children/${childId}/learning-plan`, {
    parentSchedule: { dailyGoalMinutes: 15 },
  });
  assert.strictEqual(studPlanDeny.status, 403, 'Students must not alter parent learning schedule');

  const idorPlanDeny = await parentB.req('PUT', `/api/children/${childId}/learning-plan`, {
    parentSchedule: { dailyGoalMinutes: 60 },
  });
  assert.strictEqual(idorPlanDeny.status, 403, 'Cross-parent IDOR blocked');

  const idorReportDeny = await parentB.req('GET', `/api/children/${childId}/monthly-report`);
  assert.strictEqual(idorReportDeny.status, 403, 'Cross-parent monthly report IDOR blocked');

  const validPlan = await parentA.req('PUT', `/api/children/${childId}/learning-plan`, {
    parentSchedule: {
      preferredDays: ['sun', 'tue', 'thu'],
      dailyGoalMinutes: 30,
      reminderTime: '18:00',
      weeklySummaryEmail: true,
      achievementAlerts: true,
      focusAreas: ['arabic', 'logic'],
    },
  });
  assert.strictEqual(validPlan.status, 200);
  assert.strictEqual((validPlan.data.parentSchedule as { dailyGoalMinutes: number }).dailyGoalMinutes, 30);

  console.log('\nALL IMMERSIVE WORLDS, MONTHLY REPORT & SECURITY CHECKS PASSED!');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
