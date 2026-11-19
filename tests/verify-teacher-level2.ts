import assert from 'assert';
import fs from 'fs';
import path from 'path';
import ExcelJS from 'exceljs';
import {
  ALL_LEVEL1_LESSONS,
} from '../src/data/level1Curriculum';
import { LEVEL1_QUESTION_BANK } from '../src/data/level1QuestionBank';
import {
  ALL_LEVEL2_LESSONS,
  getLevel2LessonsBySubject,
} from '../src/data/level2Curriculum';
import {
  getQuestionsForLevel2Lesson,
  LEVEL2_QUESTION_BANK,
} from '../src/data/level2QuestionBank';

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
  const adminClient = new CookieClient();
  const adminHeaders = { 'x-admin-pin': DEV_ADMIN_PIN };

  console.log('=== 1. LEVEL 2 CURRICULUM (52 LESSONS) & LEVEL 1 REGRESSION CHECK ===');
  assert.strictEqual(ALL_LEVEL1_LESSONS.length, 75, 'Level 1 must keep 75 lessons');
  assert.strictEqual(LEVEL1_QUESTION_BANK.length, 750, 'Level 1 bank must keep 750 questions');

  assert.strictEqual(getLevel2LessonsBySubject('arabic').length, 12, 'L2 Arabic must have 12 lessons');
  assert.strictEqual(getLevel2LessonsBySubject('english').length, 10, 'L2 English must have 10 lessons');
  assert.strictEqual(getLevel2LessonsBySubject('math').length, 10, 'L2 Math must have 10 lessons');
  assert.strictEqual(getLevel2LessonsBySubject('colors-shapes').length, 6, 'L2 Colors & Shapes must have 6 lessons');
  assert.strictEqual(getLevel2LessonsBySubject('logic').length, 6, 'L2 Logic must have 6 lessons');
  assert.strictEqual(getLevel2LessonsBySubject('world-around-me').length, 8, 'L2 World Around Me must have 8 lessons');
  assert.strictEqual(ALL_LEVEL2_LESSONS.length, 52, 'Total Level 2 lessons must equal 52');

  const l2LessonIds = new Set(ALL_LEVEL2_LESSONS.map((l) => l.id));
  assert.strictEqual(l2LessonIds.size, 52, 'All 52 Level 2 lesson IDs must be unique');

  for (const lesson of ALL_LEVEL2_LESSONS) {
    const qs = getQuestionsForLevel2Lesson(lesson.id);
    const practiceCount = qs.filter((q) => q.kind === 'practice').length;
    const indepCount = qs.filter((q) => q.kind === 'independent').length;
    assert.ok(practiceCount >= 4 && indepCount >= 3, `${lesson.id} must have practice + fresh independent items`);
  }
  console.log(`PASS: All 52 Level 2 lessons & ${LEVEL2_QUESTION_BANK.length} Level 2 questions verified (Level 1 untouched).`);

  console.log('=== 2. PRIVILEGE ESCALATION, TEACHER REGISTRATION & APPROVAL FLOW ===');
  const escClient = new CookieClient();
  const escParentReg = await escClient.req('POST', '/api/auth/register', {
    displayName: 'Privilege Escalator',
    email: `esc.${ts}@example.com`,
    password: 'StrongPassword!2026',
    termsAccepted: true,
    role: 'super_admin',
  });
  assert.strictEqual(escParentReg.status, 403, 'Role injection on /api/auth/register must return 403');

  const escTeacherAttempt = await escClient.req('POST', '/api/auth/register', {
    displayName: 'Injected Teacher',
    email: `inj.${ts}@example.com`,
    password: 'StrongPassword!2026',
    termsAccepted: true,
    role: 'teacher',
  });
  assert.strictEqual(escTeacherAttempt.status, 403, 'Teacher role injection on /api/auth/register must return 403');

  const teacher1Client = new CookieClient();
  const t1Email = `teacher.one.${ts}@example.com`;
  const t1Pass = 'TeacherOne!2026Secure';

  // Reject weak password on teacher registration
  const weakT = await teacher1Client.req('POST', '/api/auth/register-teacher', {
    displayName: 'Ms. Nadia',
    email: t1Email,
    password: '123',
    termsAccepted: true,
  });
  assert.strictEqual(weakT.status, 400);

  // Register Teacher 1 -> must start as pending
  const regT1 = await teacher1Client.req('POST', '/api/auth/register-teacher', {
    displayName: 'Ms. Nadia Hassan',
    email: t1Email,
    password: t1Pass,
    confirmPassword: t1Pass,
    phone: '+201001234567',
    subjects: ['arabic', 'math'],
    termsAccepted: true,
  });
  assert.strictEqual(regT1.status, 201);
  assert.strictEqual(regT1.data.status, 'pending');

  // Pending teacher login must fail with 403
  const pendingLogin = await new CookieClient().req('POST', '/api/auth/login', {
    email: t1Email,
    password: t1Pass,
  });
  assert.strictEqual(pendingLogin.status, 403, 'Pending teacher must be blocked from login until approved');

  // Duplicate teacher email -> 409
  const dupT = await new CookieClient().req('POST', '/api/auth/register-teacher', {
    displayName: 'Duplicate Nadia',
    email: t1Email.toUpperCase(),
    password: t1Pass,
    termsAccepted: true,
  });
  assert.strictEqual(dupT.status, 409);

  // Admin approves Teacher 1
  const t1UserId = (regT1.data.user as { id: string }).id;
  const approveRes = await adminClient.req(
    'PATCH',
    `/api/admin/teachers/${t1UserId}`,
    { status: 'active' },
    adminHeaders,
  );
  assert.strictEqual(approveRes.status, 200);

  // Teacher 1 logs in -> role=teacher & dashboardRoute=/teacher-dashboard
  const t1Login = await teacher1Client.req('POST', '/api/auth/login', {
    email: t1Email,
    password: t1Pass,
  });
  assert.strictEqual(t1Login.status, 200);
  assert.strictEqual((t1Login.data.user as { role: string }).role, 'teacher');
  assert.strictEqual(t1Login.data.dashboardRoute, '/teacher-dashboard');

  // Mass-assignment escalation on /api/auth/profile must be blocked (403)
  const massAssign = await teacher1Client.req('PATCH', '/api/auth/profile', {
    displayName: 'Ms. Nadia',
    role: 'super_admin',
  });
  assert.strictEqual(massAssign.status, 403, 'Mass assignment on /api/auth/profile must return 403');

  // Admin creates Teacher 2 directly active for isolation tests
  const t2Email = `teacher.two.${ts}@example.com`;
  const t2Pass = 'TeacherTwo!2026Secure';
  const createT2 = await adminClient.req(
    'POST',
    '/api/admin/teachers',
    {
      displayName: 'Mr. Karim Adel',
      email: t2Email,
      password: t2Pass,
      subjects: ['english'],
      status: 'active',
    },
    adminHeaders,
  );
  assert.strictEqual(createT2.status, 201);
  const t2Id = (createT2.data.teacher as { id: string }).id;
  const teacher2Client = new CookieClient();
  const t2Login = await teacher2Client.req('POST', '/api/auth/login', {
    email: t2Email,
    password: t2Pass,
  });
  assert.strictEqual(t2Login.status, 200);
  console.log('PASS: Teacher registration pending workflow, admin approval, login redirect, & mass-assignment guards verified.');

  console.log('=== 3. PARENT, CHILDREN, STUDENT LOGIN & CLASSROOM SCOPING ===');
  const parentClient = new CookieClient();
  const pReg = await parentClient.req('POST', '/api/auth/register', {
    displayName: 'Parent Mona',
    email: `mona.parent.${ts}@example.com`,
    password: 'ParentMona!2026Secure',
    termsAccepted: true,
  });
  assert.strictEqual(pReg.status, 201);
  assert.strictEqual(pReg.data.dashboardRoute, '/parent-dashboard');

  // Parent creates Child 1 (for Teacher 1 class) & Child 2 (for Teacher 2 class)
  const c1Res = await parentClient.req('POST', '/api/children', {
    displayName: 'Ziad Explorer',
    ageGroup: '1-4',
    language: 'ar',
    birthYear: 2023,
    birthMonth: 5,
  });
  const c2Res = await parentClient.req('POST', '/api/children', {
    displayName: 'Hana Learner',
    ageGroup: '1-4',
    language: 'en',
    birthYear: 2023,
    birthMonth: 8,
  });
  assert.strictEqual(c1Res.status, 201);
  assert.strictEqual(c2Res.status, 201);
  const child1Id = (c1Res.data.child as { id: string }).id;
  const child2Id = (c2Res.data.child as { id: string }).id;

  // Parent creates direct Student Login for Child 1
  const stuEmail = `ziad.student.${ts}@example.com`;
  const stuPass = 'StudentZiad!2026Pass';
  const stuCreate = await parentClient.req('POST', `/api/parent/children/${child1Id}/student-account`, {
    email: stuEmail,
    password: stuPass,
  });
  assert.strictEqual(stuCreate.status, 201);

  const studentClient = new CookieClient();
  const stuLogin = await studentClient.req('POST', '/api/auth/login', {
    email: stuEmail,
    password: stuPass,
  });
  assert.strictEqual(stuLogin.status, 200);
  assert.strictEqual((stuLogin.data.user as { role: string }).role, 'student');
  assert.strictEqual(stuLogin.data.dashboardRoute, '/exams');

  // Cross-role access checks (parent & student cannot hit teacher endpoints)
  assert.strictEqual((await parentClient.req('GET', '/api/teacher/dashboard')).status, 403);
  assert.strictEqual((await studentClient.req('GET', '/api/teacher/dashboard')).status, 403);
  assert.strictEqual((await new CookieClient().req('GET', '/api/teacher/dashboard')).status, 401);

  // Admin assigns Class 1 -> Teacher 1 with Child 1, Class 2 -> Teacher 2 with Child 2
  const cls1Res = await adminClient.req(
    'POST',
    '/api/admin/classes',
    { name: 'Explorers Class A', subject: 'comprehensive', level: 2, teacherId: t1UserId, studentIds: [child1Id] },
    adminHeaders,
  );
  const cls2Res = await adminClient.req(
    'POST',
    '/api/admin/classes',
    { name: 'Explorers Class B', subject: 'english', level: 2, teacherId: t2Id, studentIds: [child2Id] },
    adminHeaders,
  );
  assert.strictEqual(cls1Res.status, 201);
  assert.strictEqual(cls2Res.status, 201);
  const class1Id = (cls1Res.data.classroom as { id: string }).id;

  // Duplicate student addition rejected with 409
  const dupStuCls = await adminClient.req(
    'POST',
    `/api/admin/classes/${class1Id}/students`,
    { studentId: child1Id },
    adminHeaders,
  );
  assert.strictEqual(dupStuCls.status, 409);

  // Teacher 1 sees Child 1 only, blocked (403) from viewing Child 2
  const t1Students = await teacher1Client.req('GET', '/api/teacher/students');
  assert.strictEqual(t1Students.status, 200);
  const t1StudentIds = (t1Students.data.students as Array<{ id: string }>).map((s) => s.id);
  assert.ok(t1StudentIds.includes(child1Id) && !t1StudentIds.includes(child2Id), 'Teacher 1 must only see assigned students');

  const idorStuProg = await teacher1Client.req('GET', `/api/teacher/students/${child2Id}/progress`);
  assert.strictEqual(idorStuProg.status, 403, 'Teacher 1 blocked from unassigned student progress');
  console.log('PASS: Student direct login, cross-role 403 guards & teacher-student class isolation verified.');

  console.log('=== 4. QUESTION BANK CRUD, VALIDATION & MULTI-FORMAT CREATION ===');
  // Reject invalid lesson/level mismatch & 0 marks
  const badQ1 = await teacher1Client.req('POST', '/api/teacher/questions', {
    subject: 'arabic',
    level: 1,
    lessonId: 'L2-AR01',
    questionType: 'multiple-choice',
    promptAr: 'سؤال',
    promptEn: 'Question',
    options: [
      { id: 'a', textAr: '١', textEn: '1' },
      { id: 'b', textAr: '٢', textEn: '2' },
    ],
    correctOptionId: 'a',
    marks: 2,
    difficulty: 'easy',
  });
  assert.strictEqual(badQ1.status, 400, 'Level mismatch with lessonId must be rejected');

  const badQ2 = await teacher1Client.req('POST', '/api/teacher/questions', {
    subject: 'math',
    level: 2,
    lessonId: 'L2-MA01',
    questionType: 'multiple-choice',
    promptAr: 'سؤال بدون درجة صالحة',
    options: [
      { id: 'a', textAr: '١', textEn: '1' },
      { id: 'b', textAr: '٢', textEn: '2' },
    ],
    correctOptionId: 'a',
    marks: 0,
    difficulty: 'easy',
  });
  assert.strictEqual(badQ2.status, 400, 'Zero marks must be rejected');

  // Create 5 varied questions for Teacher 1: MC, True/False, Matching, Ordering, Short-Answer
  const qPayloads = [
    {
      subject: 'arabic',
      level: 2,
      lessonId: 'L2-AR01',
      questionType: 'multiple-choice',
      promptAr: 'ما صوت حرف الباء بالفتحة؟',
      promptEn: 'What is the Fatha sound of Ba?',
      options: [
        { id: 'a', textAr: 'بَ', textEn: 'Ba' },
        { id: 'b', textAr: 'تَ', textEn: 'Ta' },
        { id: 'c', textAr: 'ثَ', textEn: 'Tha' },
      ],
      correctOptionId: 'a',
      marks: 2,
      difficulty: 'easy',
    },
    {
      subject: 'math',
      level: 2,
      lessonId: 'L2-MA04',
      questionType: 'true-false',
      promptAr: '٤ + ٣ = ٧',
      promptEn: '4 + 3 = 7',
      options: [
        { id: 'a', textAr: 'صح', textEn: 'True' },
        { id: 'b', textAr: 'خطأ', textEn: 'False' },
      ],
      correctOptionId: 'a',
      marks: 2,
      difficulty: 'easy',
    },
    {
      subject: 'logic',
      level: 2,
      lessonId: 'L2-LG02',
      questionType: 'matching',
      promptAr: 'طابق الكلمة بصفتها',
      promptEn: 'Match each item to its trait',
      options: [],
      matchingPairs: [
        { id: 'p1', left: 'Sun', right: 'Day' },
        { id: 'p2', left: 'Moon', right: 'Night' },
      ],
      marks: 2,
      difficulty: 'medium',
    },
    {
      subject: 'math',
      level: 2,
      lessonId: 'L2-MA01',
      questionType: 'ordering',
      promptAr: 'رتب الأرقام تصاعدياً',
      promptEn: 'Order numbers ascending',
      options: [],
      correctOrder: ['11', '15', '20'],
      marks: 2,
      difficulty: 'medium',
    },
    {
      subject: 'math',
      level: 2,
      lessonId: 'L2-MA04',
      questionType: 'short-answer',
      promptAr: 'كم ناتج ٦ + ٤؟',
      promptEn: 'What is 6 + 4?',
      options: [],
      acceptedAnswers: ['10', 'ten', '١٠'],
      marks: 2,
      difficulty: 'easy',
    },
  ];

  const createdQIds: string[] = [];
  for (const qp of qPayloads) {
    const r = await teacher1Client.req('POST', '/api/teacher/questions', qp);
    assert.strictEqual(r.status, 201, `Failed creating question ${qp.questionType}: ${JSON.stringify(r.data)}`);
    createdQIds.push((r.data.question as { id: string }).id);
  }

  // Teacher 2 cannot modify or delete Teacher 1's question -> 403
  const crossEdit = await teacher2Client.req('PATCH', `/api/teacher/questions/${createdQIds[0]}`, {
    promptEn: 'Hacked prompt',
  });
  assert.strictEqual(crossEdit.status, 403, 'Teacher 2 blocked from editing Teacher 1 question');

  // Duplicate + delete unused duplicate
  const dupQ = await teacher1Client.req('POST', `/api/teacher/questions/${createdQIds[0]}/duplicate`, {});
  assert.strictEqual(dupQ.status, 201);
  const dupQId = (dupQ.data.question as { id: string }).id;
  const delDup = await teacher1Client.req('DELETE', `/api/teacher/questions/${dupQId}`);
  assert.strictEqual(delDup.status, 200);
  assert.strictEqual(delDup.data.deleted, true);
  console.log('PASS: Multi-type Question Bank CRUD, validation, duplication, & cross-teacher 403 verified.');

  console.log('=== 5. BULK CSV & REAL .XLSX IMPORT + EXECUTABLE REJECTION ===');
  const csvTpl = await teacher1Client.req('GET', '/api/teacher/questions/import/template?format=csv');
  assert.strictEqual(csvTpl.status, 200);
  const xlsxTpl = await fetch(`${BASE}/api/teacher/questions/import/template?format=xlsx`, {
    headers: { Cookie: teacher1Client.cookie },
  });
  assert.strictEqual(xlsxTpl.status, 200);

  // Build CSV with 1 valid row + 1 invalid row
  const csvText = [
    'subject,level,lessonId,questionType,promptAr,promptEn,optionA_ar,optionA_en,optionB_ar,optionB_en,optionC_ar,optionC_en,optionD_ar,optionD_en,correctOption,acceptedAnswers,matchingPairs,correctOrder,marks,difficulty,explanationAr,explanationEn,audioText',
    'english,2,L2-EN01,multiple-choice,ما صوت sh؟,What sound is sh?,ش,sh,تش,ch,,,,,a,,,,2,easy,sh makes sh sound,sh sounds like sh,',
    'english,2,INVALID-LESSON,multiple-choice,سؤال خاطئ,Invalid row,أ,A,ب,B,,,,,a,,,,2,easy,,,',
  ].join('\r\n');

  const csvForm = new FormData();
  csvForm.append('file', new Blob([csvText], { type: 'text/csv' }), 'mixed-import.csv');
  const csvPreview = await teacher1Client.req('POST', '/api/teacher/questions/import/preview', csvForm);
  assert.strictEqual(csvPreview.status, 200);
  assert.strictEqual(csvPreview.data.validCount, 1);
  assert.strictEqual(csvPreview.data.invalidCount, 1);
  const csvCommit = await teacher1Client.req('POST', '/api/teacher/questions/import/commit', {
    importBatchId: csvPreview.data.importBatchId,
  });
  assert.strictEqual(csvCommit.status, 201);
  assert.strictEqual(csvCommit.data.importedCount, 1);

  // Real .xlsx workbook generated via ExcelJS
  const wb = new ExcelJS.Workbook();
  const ws = wb.addWorksheet('Questions');
  ws.addRow([
    'subject', 'level', 'lessonId', 'questionType', 'promptAr', 'promptEn',
    'optionA_ar', 'optionA_en', 'optionB_ar', 'optionB_en', 'optionC_ar', 'optionC_en', 'optionD_ar', 'optionD_en',
    'correctOption', 'acceptedAnswers', 'matchingPairs', 'correctOrder', 'marks', 'difficulty',
    'explanationAr', 'explanationEn', 'audioText',
  ]);
  ws.addRow([
    'math', '2', 'L2-MA05', 'short-answer', 'كم ٩ - ٤؟', 'What is 9 - 4?',
    '', '', '', '', '', '', '', '',
    '', '5|five|٥', '', '', '3', 'medium',
    '٩ ناقص ٤ يساوي ٥', '9 minus 4 equals 5', '',
  ]);
  const xlsxArrayBuf = await wb.xlsx.writeBuffer();
  const xlsxForm = new FormData();
  xlsxForm.append(
    'file',
    new Blob([xlsxArrayBuf], {
      type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    }),
    'real-questions.xlsx',
  );
  const xlsxPreview = await teacher1Client.req('POST', '/api/teacher/questions/import/preview', xlsxForm);
  assert.strictEqual(xlsxPreview.status, 200);
  assert.strictEqual(xlsxPreview.data.validCount, 1);
  const xlsxCommit = await teacher1Client.req('POST', '/api/teacher/questions/import/commit', {
    importBatchId: xlsxPreview.data.importBatchId,
  });
  assert.strictEqual(xlsxCommit.status, 201);
  assert.strictEqual(xlsxCommit.data.importedCount, 1);

  // Reject executable file disguised as .xlsx
  const exeHeader = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const evilForm = new FormData();
  evilForm.append(
    'file',
    new Blob([exeHeader], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }),
    'malware.xlsx',
  );
  const evilRes = await teacher1Client.req('POST', '/api/teacher/questions/import/preview', evilForm);
  assert.strictEqual(evilRes.status, 400, 'Executable MZ header disguised as .xlsx must be rejected');

  // Verify files stored in non-public server_uploads/ directory
  const uploadDir = path.join(process.cwd(), 'server_uploads');
  assert.ok(fs.existsSync(uploadDir) && fs.readdirSync(uploadDir).length >= 2, 'Uploads must be stored in server_uploads/');
  assert.ok(!fs.existsSync(path.join(process.cwd(), 'public', 'server_uploads')), 'Must not store imports in public/');
  console.log('PASS: CSV + ExcelJS .xlsx bulk import preview/commit, row validation, & executable rejection verified.');

  console.log('=== 6. EXAM BUILDER, SCHEDULE VALIDATION & ASSIGNMENT ===');
  const now = Date.now();
  const badExam = await teacher1Client.req('POST', '/api/teacher/exams', {
    titleAr: 'امتحان غير صالح',
    titleEn: 'Invalid Schedule Exam',
    subject: 'comprehensive',
    level: 2,
    ageGroup: '1-4',
    questionIds: createdQIds,
    passingPercentage: 70,
    durationMinutes: 15,
    startDate: new Date(now + 3600_000).toISOString(),
    endDate: new Date(now - 3600_000).toISOString(),
    allowedAttempts: 2,
  });
  assert.strictEqual(badExam.status, 400, 'Exam with startDate >= endDate must be rejected');

  const createExamRes = await teacher1Client.req('POST', '/api/teacher/exams', {
    titleAr: 'اختبار المستكشفون الشامل',
    titleEn: 'Explorers Mastery Exam',
    descriptionAr: 'تقييم شامل',
    descriptionEn: 'Comprehensive teacher evaluation',
    subject: 'comprehensive',
    level: 2,
    ageGroup: '1-4',
    questionIds: createdQIds,
    passingPercentage: 70,
    durationMinutes: 20,
    startDate: new Date(now - 60_000).toISOString(),
    endDate: new Date(now + 24 * 3600_000).toISOString(),
    allowedAttempts: 2,
    randomizeQuestions: false,
    randomizeAnswers: false,
    showResults: true,
    showCorrectAnswers: true,
    status: 'published',
  });
  assert.strictEqual(createExamRes.status, 201);
  const exam1 = createExamRes.data.exam as { id: string; totalMarks: number; totalQuestions: number };
  assert.strictEqual(exam1.totalQuestions, 5);
  assert.strictEqual(exam1.totalMarks, 10);

  // Also create a future scheduled exam so we verify scheduled window enforcement
  const futureExamRes = await teacher1Client.req('POST', '/api/teacher/exams', {
    titleAr: 'امتحان مستقبلي',
    titleEn: 'Future Scheduled Exam',
    subject: 'math',
    level: 2,
    ageGroup: '1-4',
    questionIds: [createdQIds[1]],
    passingPercentage: 70,
    durationMinutes: 10,
    startDate: new Date(now + 2 * 3600_000).toISOString(),
    endDate: new Date(now + 26 * 3600_000).toISOString(),
    allowedAttempts: 1,
    status: 'published',
  });
  assert.strictEqual(futureExamRes.status, 201);
  const futureExamId = (futureExamRes.data.exam as { id: string }).id;

  // Assign Exam 1 to Class 1 -> creates assignment for Child 1
  const assignRes = await teacher1Client.req('POST', `/api/teacher/exams/${exam1.id}/assign`, {
    classIds: [class1Id],
    publishNow: true,
  });
  assert.strictEqual(assignRes.status, 201);
  assert.strictEqual(assignRes.data.assignedCount, 1);

  const assignFuture = await teacher1Client.req('POST', `/api/teacher/exams/${futureExamId}/assign`, {
    studentIds: [child1Id],
    publishNow: true,
  });
  assert.strictEqual(assignFuture.status, 201);

  // Attempting to assign exam to unassigned Student 2 -> 403
  const forbiddenAssign = await teacher1Client.req('POST', `/api/teacher/exams/${exam1.id}/assign`, {
    studentIds: [child2Id],
  });
  assert.strictEqual(forbiddenAssign.status, 403);
  console.log('PASS: Exam creation, marks calculation, schedule guards, & class/student assignment verified.');

  console.log('=== 7. STUDENT EXAM EXECUTION, INCREMENTAL SAVE, GRADING & VISIBILITY ===');
  const stuList = await studentClient.req('GET', '/api/student/exams');
  assert.strictEqual(stuList.status, 200);
  const availCards = stuList.data.available as Array<{ assignmentId: string; examId: string }>;
  const upcomingCards = stuList.data.upcoming as Array<{ assignmentId: string; examId: string }>;
  assert.strictEqual(availCards.length, 1);
  assert.strictEqual(upcomingCards.length, 1);
  const assignment1Id = availCards[0].assignmentId;
  const futureAssignmentId = upcomingCards[0].assignmentId;

  // Starting upcoming future exam must be rejected (403)
  const startFuture = await studentClient.req('POST', `/api/student/exams/${futureAssignmentId}/start`, {});
  assert.strictEqual(startFuture.status, 403, 'Cannot start scheduled exam before startDate');

  // Start Exam 1
  const startRes = await studentClient.req('POST', `/api/student/exams/${assignment1Id}/start`, {});
  assert.strictEqual(startRes.status, 200);
  const attempt1Id = String(startRes.data.attemptId);
  const deliveredQs = startRes.data.questions as Array<{
    id: string;
    questionType: string;
    correctOptionId?: string;
    acceptedAnswers?: string[];
  }>;
  assert.strictEqual(deliveredQs.length, 5);
  assert.ok(!deliveredQs[0].correctOptionId && !deliveredQs[4].acceptedAnswers, 'Correct answers must never leak to student');

  // Save 1 answer incrementally, then call start again to verify resume preserves savedAnswers
  const saveStep = await studentClient.req('POST', `/api/student/exams/attempts/${attempt1Id}/answer`, {
    questionId: createdQIds[0],
    answer: 'a',
  });
  assert.strictEqual(saveStep.status, 200);

  const resumeRes = await studentClient.req('POST', `/api/student/exams/${assignment1Id}/start`, {});
  assert.strictEqual(resumeRes.status, 200);
  assert.strictEqual(resumeRes.data.resumed, true);
  assert.strictEqual((resumeRes.data.savedAnswers as Record<string, unknown>)[createdQIds[0]], 'a');

  // Submit all 5 correct answers across MC, TF, Matching, Ordering, Short-Answer
  const submitRes = await studentClient.req('POST', `/api/student/exams/attempts/${attempt1Id}/submit`, {
    answers: {
      [createdQIds[0]]: 'a',
      [createdQIds[1]]: 'a',
      [createdQIds[2]]: { p1: 'Day', p2: 'Night' },
      [createdQIds[3]]: ['11', '15', '20'],
      [createdQIds[4]]: '  Ten ',
    },
  });
  assert.strictEqual(submitRes.status, 200);
  assert.strictEqual(submitRes.data.score, 10);
  assert.strictEqual(submitRes.data.totalMarks, 10);
  assert.strictEqual(submitRes.data.percentage, 100);
  assert.strictEqual(submitRes.data.passed, true);

  // Duplicate submission blocked -> 409
  const dupSubmit = await studentClient.req('POST', `/api/student/exams/attempts/${attempt1Id}/submit`, {
    answers: {},
  });
  assert.strictEqual(dupSubmit.status, 409, 'Duplicate exam submission must be blocked with 409');

  // Teacher dashboard stats reflect real DB values (no fake defaults)
  const tDash = await teacher1Client.req('GET', '/api/teacher/dashboard');
  assert.strictEqual(tDash.status, 200);
  const stats = tDash.data.stats as Record<string, number>;
  assert.strictEqual(stats.classesCount, 1);
  assert.strictEqual(stats.assignedStudentsCount, 1);
  assert.strictEqual(stats.completedAttemptsCount, 1);
  assert.strictEqual(stats.averageScorePercentage, 100);

  // Teacher results & Parent overview see accurate score, without exposing private admin notes
  const tResults = await teacher1Client.req('GET', '/api/teacher/results');
  assert.strictEqual(tResults.status, 200);
  assert.strictEqual((tResults.data.results as unknown[]).length, 1);

  const pOverview = await parentClient.req('GET', `/api/parent/children/${child1Id}/overview`);
  assert.strictEqual(pOverview.status, 200);
  const pExams = pOverview.data.assignedExams as Array<Record<string, unknown>>;
  assert.ok(pExams.length >= 1);
  assert.strictEqual(pExams[0].percentage, 100);
  assert.strictEqual(pExams[0].adminReviewNote, undefined, 'Parent overview must never expose internal admin notes');

  // Verify hiding results (showResults=false) hides score from student/parent
  await teacher1Client.req('PATCH', `/api/teacher/exams/${exam1.id}`, { showResults: false });
  const hiddenResult = await studentClient.req('GET', `/api/student/exams/attempts/${attempt1Id}/result`);
  assert.strictEqual(hiddenResult.status, 200);
  assert.strictEqual(hiddenResult.data.showResults, false);
  assert.strictEqual(hiddenResult.data.score, undefined);
  console.log('PASS: Assigned exam start, resume, multi-type backend grading, duplicate-submit lock, & permission-gated results verified.');

  console.log('=== 8. LEVEL 2 ASSESSMENT, SPACED REVIEW & SESSION INVALIDATION ===');
  const l2Prog = await parentClient.req('POST', '/api/level2/progress', {
    childId: child1Id,
    lessonId: 'L2-AR01',
    completedSteps: [0, 1, 2],
    completedActivityIds: ['act1', 'act2'],
    correctCount: 2,
    timeSpentSeconds: 95,
  });
  assert.strictEqual(l2Prog.status, 200);

  const l2Start = await parentClient.req('POST', '/api/level2/assessment/start', {
    childId: child1Id,
    lessonId: 'L2-AR01',
    questionCount: 4,
  });
  assert.strictEqual(l2Start.status, 200);
  const l2Qs = l2Start.data.questions as Array<{ id: string; correctOptionId?: string }>;
  assert.strictEqual(l2Qs.length, 4);
  assert.ok(!l2Qs[0].correctOptionId, 'Level 2 assessment must strip correctOptionId');

  const l2Answers: Record<string, string> = {};
  for (const q of l2Qs) {
    l2Answers[q.id] = LEVEL2_QUESTION_BANK.find((item) => item.id === q.id)!.correctOptionId;
  }
  const l2Submit = await parentClient.req('POST', '/api/level2/assessment/submit', {
    attemptId: l2Start.data.attemptId,
    answers: l2Answers,
  });
  assert.strictEqual(l2Submit.status, 200);
  assert.strictEqual(l2Submit.data.demonstrated, true);
  assert.strictEqual(l2Submit.data.status, 'demonstrated');
  assert.ok(typeof l2Submit.data.revisionDueAt === 'string', 'Spaced review due date must be scheduled');

  // Password change revokes old session token cleanly
  const newTeacherPass = 'TeacherOne!2027Rotated';
  const oldCookieCopy = teacher1Client.cookie;
  const pwChangeRes = await teacher1Client.req('POST', '/api/auth/change-password', {
    currentPassword: t1Pass,
    newPassword: newTeacherPass,
    confirmPassword: newTeacherPass,
  });
  assert.strictEqual(pwChangeRes.status, 200);

  // Old session cookie before rotation must now fail 401
  const staleSessionRes = await fetch(`${BASE}/api/teacher/dashboard`, {
    headers: { Cookie: oldCookieCopy },
  });
  assert.strictEqual(staleSessionRes.status, 401, 'Old session cookie must be invalidated on password change');

  // Suspended teacher must immediately be blocked
  await adminClient.req('PATCH', `/api/admin/teachers/${t1UserId}`, { status: 'suspended' }, adminHeaders);
  const suspendedCheck = await teacher1Client.req('GET', '/api/teacher/dashboard');
  assert.strictEqual(suspendedCheck.status, 401);
  console.log('PASS: Level 2 backend grading + spaced review, password-change session rotation, & teacher suspension verified.');

  console.log('\nALL 9 TEACHER PORTAL, EXAM, LEVEL 2 & SECURITY VERIFICATION SUITES PASSED SUCCESSFULLY!');
}

main().catch((err) => {
  console.error('VERIFICATION FAILED:', err);
  process.exit(1);
});
