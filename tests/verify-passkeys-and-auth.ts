import assert from 'node:assert';
import crypto from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import http from 'node:http';
import express from 'express';
import { pool } from '../src/db/index.ts';
import { validatePassword } from '../src/utils/validation.ts';
import { clearWebAuthnDevMemoryForTests, registerPasskeyRoutes, resolveWebAuthnContext } from '../server/passkeyRoutes.ts';
import { getDefaultServerDb } from '../server/pgStore.ts';
import { hashPassword } from '../server/security.ts';
import type { AuthenticatedRequest } from '../server/dbTypes.ts';

const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:3000';
const WEBAUTHN_ORIGIN = 'http://localhost:3000';
const WEBAUTHN_RP_ID = 'localhost';

class CookieClient {
  private cookies = new Map<string, string>();
  public csrfToken: string | null = null;

  constructor(private readonly baseUrl: string = BASE) {}

  private captureCookies(res: Response) {
    const hdrs = res.headers as Headers & { getSetCookie?: () => string[] };
    const setCookies = typeof hdrs.getSetCookie === 'function' ? hdrs.getSetCookie() : [];
    const fallback = res.headers.get('set-cookie');
    const list = setCookies.length > 0 ? setCookies : fallback ? [fallback] : [];
    for (const raw of list) {
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

  public hasCookie(name: string): boolean {
    return this.cookies.has(name);
  }

  async req<T = Record<string, unknown>>(
    method: string,
    urlPath: string,
    body?: unknown,
    extraHeaders: Record<string, string> = {},
  ): Promise<{ status: number; headers: Headers; data: T; rawText: string }> {
    const headers: Record<string, string> = {
      Origin: WEBAUTHN_ORIGIN,
      ...extraHeaders,
    };
    const cookieStr = Array.from(this.cookies.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    if (cookieStr) headers['cookie'] = cookieStr;
    if (body !== undefined) headers['content-type'] = 'application/json';
    if (
      ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase()) &&
      this.csrfToken &&
      !('x-csrf-token' in headers)
    ) {
      headers['x-csrf-token'] = this.csrfToken;
    }

    const res = await fetch(`${this.baseUrl}${urlPath}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    this.captureCookies(res);
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

interface VirtualPasskey {
  credentialIdBytes: Buffer;
  credentialIdB64: string;
  privateKey: crypto.KeyObject;
  cosePublicKey: Buffer;
  multiDevice: boolean;
  backedUp: boolean;
}

function encodeCborLengthPrefixedBytes(majorType: number, payload: Buffer): Buffer {
  const len = payload.length;
  const high = majorType << 5;
  let header: Buffer;
  if (len < 24) {
    header = Buffer.from([high | len]);
  } else if (len < 256) {
    header = Buffer.from([high | 24, len]);
  } else {
    header = Buffer.alloc(3);
    header[0] = high | 25;
    header.writeUInt16BE(len, 1);
  }
  return Buffer.concat([header, payload]);
}

function encodeCoseEs256PublicKey(publicKey: crypto.KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' }) as { x?: string; y?: string };
  assert.ok(jwk.x && jwk.y, 'P-256 JWK coordinates required');
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  assert.strictEqual(x.length, 32);
  assert.strictEqual(y.length, 32);

  // COSE_Key CBOR map with 5 pairs: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
  return Buffer.concat([
    Buffer.from([0xa5]),
    Buffer.from([0x01, 0x02]), // kty: EC2 (2)
    Buffer.from([0x03, 0x26]), // alg: ES256 (-7)
    Buffer.from([0x20, 0x01]), // crv: P-256 (1)
    Buffer.from([0x21]),
    encodeCborLengthPrefixedBytes(2, x), // -2: x
    Buffer.from([0x22]),
    encodeCborLengthPrefixedBytes(2, y), // -3: y
  ]);
}

function createVirtualPasskey(opts: { multiDevice?: boolean; backedUp?: boolean } = {}): VirtualPasskey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const credentialIdBytes = crypto.randomBytes(32);
  return {
    credentialIdBytes,
    credentialIdB64: credentialIdBytes.toString('base64url'),
    privateKey,
    cosePublicKey: encodeCoseEs256PublicKey(publicKey),
    multiDevice: Boolean(opts.multiDevice),
    backedUp: Boolean(opts.backedUp),
  };
}

function buildRegistrationResponse(
  pk: VirtualPasskey,
  challenge: string,
  opts: { origin?: string; rpId?: string; counter?: number } = {},
) {
  const origin = opts.origin ?? WEBAUTHN_ORIGIN;
  const rpId = opts.rpId ?? WEBAUTHN_RP_ID;
  const counter = opts.counter ?? 0;

  const clientDataObj = {
    type: 'webauthn.create',
    challenge,
    origin,
    crossOrigin: false,
  };
  const clientDataJSON = Buffer.from(JSON.stringify(clientDataObj), 'utf8').toString('base64url');

  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  let flags = 0x01 | 0x04 | 0x40; // UP | UV | AT
  if (pk.multiDevice) flags |= 0x08; // BE
  if (pk.backedUp) flags |= 0x10; // BS

  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);
  const aaguid = Buffer.alloc(16, 0);
  const credLenBuf = Buffer.alloc(2);
  credLenBuf.writeUInt16BE(pk.credentialIdBytes.length, 0);

  const authData = Buffer.concat([
    rpIdHash,
    Buffer.from([flags]),
    counterBuf,
    aaguid,
    credLenBuf,
    pk.credentialIdBytes,
    pk.cosePublicKey,
  ]);

  // CBOR map { "fmt": "none", "attStmt": {}, "authData": <bytes> }
  const attestationObject = Buffer.concat([
    Buffer.from([0xa3]),
    encodeCborLengthPrefixedBytes(3, Buffer.from('fmt', 'utf8')),
    encodeCborLengthPrefixedBytes(3, Buffer.from('none', 'utf8')),
    encodeCborLengthPrefixedBytes(3, Buffer.from('attStmt', 'utf8')),
    Buffer.from([0xa0]),
    encodeCborLengthPrefixedBytes(3, Buffer.from('authData', 'utf8')),
    encodeCborLengthPrefixedBytes(2, authData),
  ]).toString('base64url');

  return {
    id: pk.credentialIdB64,
    rawId: pk.credentialIdB64,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
    response: {
      clientDataJSON,
      attestationObject,
      transports: ['internal'],
    },
  };
}

function buildAuthenticationResponse(
  pk: VirtualPasskey,
  challenge: string,
  opts: { origin?: string; rpId?: string; counter?: number; userHandle?: string; tamperSig?: boolean } = {},
) {
  const origin = opts.origin ?? WEBAUTHN_ORIGIN;
  const rpId = opts.rpId ?? WEBAUTHN_RP_ID;
  const counter = opts.counter ?? 0;

  const clientDataObj = {
    type: 'webauthn.get',
    challenge,
    origin,
    crossOrigin: false,
  };
  const clientDataBytes = Buffer.from(JSON.stringify(clientDataObj), 'utf8');
  const clientDataHash = crypto.createHash('sha256').update(clientDataBytes).digest();

  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  let flags = 0x01 | 0x04; // UP | UV
  if (pk.multiDevice) flags |= 0x08;
  if (pk.backedUp) flags |= 0x10;
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);

  const authData = Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf]);
  const signedPayload = Buffer.concat([authData, clientDataHash]);
  const signature = crypto.sign('sha256', signedPayload, pk.privateKey);
  if (opts.tamperSig) {
    signature[signature.length - 1] ^= 0xff;
  }

  return {
    id: pk.credentialIdB64,
    rawId: pk.credentialIdB64,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    clientExtensionResults: {},
    response: {
      clientDataJSON: clientDataBytes.toString('base64url'),
      authenticatorData: authData.toString('base64url'),
      signature: signature.toString('base64url'),
      ...(opts.userHandle ? { userHandle: Buffer.from(opts.userHandle, 'utf8').toString('base64url') } : {}),
    },
  };
}

async function waitForReady(url: string) {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`${url}/api/health`);
      if (r.status > 0) return;
    } catch {
      // retry
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Timed out waiting for server at ${url}`);
}

function stopProcess(proc: ChildProcess) {
  try {
    if (proc.pid) process.kill(-proc.pid, 'SIGTERM');
  } catch {
    try {
      proc.kill('SIGTERM');
    } catch {
      // ignore
    }
  }
}

async function testProductionOriginFailClosedUnit() {
  const savedEnv = { ...process.env };
  try {
    process.env.NODE_ENV = 'production';
    delete process.env.WEBAUTHN_ALLOWED_ORIGINS;
    delete process.env.APP_URL;
    delete process.env.WEBAUTHN_RP_ID;

    const fakeReq = (origin?: string, host = 'app.nonoland.example') =>
      ({ headers: { ...(origin ? { origin } : {}), host } } as unknown as express.Request);

    // 1. Missing HTTPS origin in prod -> 503 fail closed
    const missing = resolveWebAuthnContext(fakeReq('https://app.nonoland.example'));
    assert.strictEqual(missing.ok, false);
    if (!missing.ok) assert.strictEqual(missing.status, 503);

    // 2. HTTP and localhost origins ignored/rejected in prod -> 503
    process.env.WEBAUTHN_ALLOWED_ORIGINS = 'http://app.nonoland.example,https://localhost:3000';
    const insecure = resolveWebAuthnContext(fakeReq('http://app.nonoland.example'));
    assert.strictEqual(insecure.ok, false);
    if (!insecure.ok) assert.strictEqual(insecure.status, 503);

    // 3. Valid HTTPS origin configured, untrusted caller origin rejected -> 403
    process.env.WEBAUTHN_ALLOWED_ORIGINS = 'https://app.nonoland.example';
    const untrusted = resolveWebAuthnContext(fakeReq('https://evil.example'));
    assert.strictEqual(untrusted.ok, false);
    if (!untrusted.ok) assert.strictEqual(untrusted.status, 403);

    // 4. Valid HTTPS origin accepted cleanly
    const valid = resolveWebAuthnContext(fakeReq('https://app.nonoland.example'));
    assert.strictEqual(valid.ok, true);
    if (valid.ok) {
      assert.strictEqual(valid.rpId, 'app.nonoland.example');
      assert.strictEqual(valid.expectedOrigin, 'https://app.nonoland.example');
    }
    console.log('PASS [Unit 1]: Production WebAuthn origin/RP-ID resolution fails closed unless valid HTTPS origin is configured.');
  } finally {
    process.env = savedEnv;
  }
}

async function testPasswordPolicyUnit() {
  assert.strictEqual(validatePassword('Short1!', 'p@ex.com', 'Parent').ok, false, 'Under 12 chars rejected');
  assert.strictEqual(validatePassword('OnlyLettersHere', 'p@ex.com', 'Parent').ok, false, 'Letters-only rejected');
  assert.strictEqual(validatePassword('12345678901234', 'p@ex.com', 'Parent').ok, false, 'Digits-only rejected');
  assert.strictEqual(validatePassword('nonoland2026', 'p@ex.com', 'Parent').ok, false, 'Compromised password rejected');
  assert.strictEqual(validatePassword('secretAlice!99', 'alice@ex.com', 'User').ok, false, 'Email local part rejected');
  assert.strictEqual(validatePassword('Pass!Nadia2026', 'p@ex.com', 'Nadia').ok, false, 'Display name rejected');
  const good = validatePassword('GardenStar!2026', 'parent@ex.com', 'Layla');
  assert.strictEqual(good.ok, true, 'Strong password accepted');
  console.log('PASS [Unit 2]: Strong password policy enforces >=12 chars, letters + digit/symbol, and blocklists.');
}

async function testIsolatedAdminAndTeacherRestrictions() {
  const port = 3194;
  const baseUrl = `http://127.0.0.1:${port}`;
  const runtimeSetupSecret = crypto.randomBytes(24).toString('hex');

  const proc = spawn('npx', ['tsx', 'server.ts'], {
    cwd: process.cwd(),
    detached: true,
    env: {
      ...process.env,
      PORT: String(port),
      NODE_ENV: 'development',
      SKIP_VITE: '1',
      SQL_HOST: '',
      SQL_DB_NAME: '',
      SQL_USER: '',
      SQL_PASSWORD: '',
      DATABASE_URL: '',
      REQUIRE_POSTGRES: '',
      ADMIN_PIN: '',
      NONOLAND_ADMIN_SETUP_SECRET: runtimeSetupSecret,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    await waitForReady(baseUrl);
    const adminClient = new CookieClient(baseUrl);
    const adminEmail = `iso.adm.${crypto.randomBytes(4).toString('hex')}@nonoland.test`;
    const adminPw = `Sup3rAdm!n#${crypto.randomBytes(6).toString('hex')}`;

    const boot = await adminClient.req('POST', '/api/auth/admin-bootstrap', {
      setupSecret: runtimeSetupSecret,
      displayName: 'Isolated Admin',
      email: adminEmail,
      password: adminPw,
      confirmPassword: adminPw,
    });
    assert.strictEqual(boot.status, 201);

    // Super Admin blocked from Passkeys (strictly Parent only)
    for (const [method, endpoint, body] of [
      ['GET', '/api/auth/passkeys'],
      ['POST', '/api/auth/reauthenticate', { password: adminPw }],
      ['POST', '/api/auth/passkeys/register/options', { currentPassword: adminPw }],
    ] as const) {
      const r = await adminClient.req(method, endpoint, body);
      assert.strictEqual(r.status, 403, `Admin MUST be blocked from ${method} ${endpoint}, got ${r.status}`);
    }

    // Admin creates active teacher WITHOUT phone
    const teacherEmail = `iso.tch.${crypto.randomBytes(4).toString('hex')}@nonoland.test`;
    const teacherPw = `TchStr0ng!${crypto.randomBytes(6).toString('hex')}`;
    const tCreate = await adminClient.req<{ teacher: Record<string, unknown> }>('POST', '/api/admin/teachers', {
      displayName: 'Teacher Samira',
      email: teacherEmail,
      password: teacherPw,
      phone: '+201000000000', // legacy payload ignored
      subjects: ['arabic'],
      status: 'active',
    });
    assert.strictEqual(tCreate.status, 201, `Admin teacher creation failed: ${tCreate.rawText}`);
    assert.strictEqual('phone' in tCreate.data.teacher, false, 'Admin teacher response must not expose phone');

    // Active Teacher login -> blocked from Passkeys (403)
    const teacherClient = new CookieClient(baseUrl);
    const tLogin = await teacherClient.req('POST', '/api/auth/login', {
      email: teacherEmail,
      password: teacherPw,
      portal: 'teacher',
    });
    assert.strictEqual(tLogin.status, 200);
    for (const [method, endpoint, body] of [
      ['GET', '/api/auth/passkeys'],
      ['POST', '/api/auth/reauthenticate', { password: teacherPw }],
      ['POST', '/api/auth/passkeys/register/options', { currentPassword: teacherPw }],
    ] as const) {
      const r = await teacherClient.req(method, endpoint, body);
      assert.strictEqual(r.status, 403, `Active teacher MUST be blocked from ${method} ${endpoint}, got ${r.status}`);
    }

    console.log('PASS [Isolated]: Active Teacher & Super Admin sessions blocked (403) on all Passkey endpoints; phone omitted.');
  } finally {
    stopProcess(proc);
  }
}

async function testExpiredChallengeInMemory() {
  const savedEnv = { ...process.env };
  const origNow = Date.now;
  let clockOffsetMs = 0;
  Date.now = () => origNow() + clockOffsetMs;

  process.env.NODE_ENV = 'development';
  delete process.env.SQL_HOST;
  delete process.env.SQL_DB_NAME;
  delete process.env.SQL_USER;
  delete process.env.SQL_PASSWORD;
  delete process.env.DATABASE_URL;
  delete process.env.REQUIRE_POSTGRES;
  clearWebAuthnDevMemoryForTests();

  const db = getDefaultServerDb();
  const nowIso = new Date().toISOString();
  const parentId = 'usr_exp_test';
  const password = 'ExpTest!Pass2026#99';
  db.users[parentId] = {
    id: parentId,
    email: 'exp.parent@nonoland.test',
    normalizedEmail: 'exp.parent@nonoland.test',
    displayName: 'Expiry Test Parent',
    passwordHash: hashPassword(password),
    role: 'parent',
    emailVerified: true,
    status: 'active',
    familyId: 'fam_exp_test',
    policyVersion: '2026.1',
    termsAcceptedAt: nowIso,
    failedLoginAttempts: 0,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
  db.emailIndex['exp.parent@nonoland.test'] = parentId;

  const app = express();
  app.use(express.json());
  app.use((req: AuthenticatedRequest, _res, next) => {
    req.authSession = {
      user: db.users[parentId],
      session: {
        tokenHash: 'tok_exp_test',
        userId: parentId,
        csrfToken: 'csrf_exp_test',
        createdAt: Date.now(),
        lastActiveAt: Date.now(),
        expiresAt: Date.now() + 86_400_000,
        ip: '127.0.0.1',
        userAgent: 'test',
        sessionKind: 'parent',
        familyId: 'fam_exp_test',
      },
    };
    next();
  });

  registerPasskeyRoutes({
    app,
    getDb: () => db,
    saveDb: () => {},
    requireAuth: (req, res, next) => {
      if (!req.authSession) return res.status(401).json({ error: 'Authentication required' });
      next();
    },
    createSessionForUser: () => 'csrf_new_exp',
    toSafeUser: (u) => ({ id: u.id, role: u.role, email: u.email, displayName: u.displayName }),
  });

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  try {
    const client = new CookieClient(baseUrl);
    const reauth = await client.req('POST', '/api/auth/reauthenticate', { password });
    assert.strictEqual(reauth.status, 200);

    // Expired registration challenge (> 5 minutes)
    const regOpt = await client.req<{ options: { challenge: string } }>('POST', '/api/auth/passkeys/register/options', {});
    assert.strictEqual(regOpt.status, 200);
    const pk = createVirtualPasskey({ multiDevice: true, backedUp: true });
    clockOffsetMs = 5 * 60_000 + 2000;
    // Refresh password re-auth at the new clock so we specifically test the 5m challenge TTL (not reauth TTL)
    const reauthAfterClock = await client.req('POST', '/api/auth/reauthenticate', { password });
    assert.strictEqual(reauthAfterClock.status, 200);
    const regExp = await client.req('POST', '/api/auth/passkeys/register/verify', {
      response: buildRegistrationResponse(pk, regOpt.data.options.challenge),
      label: 'Expired Reg',
    });
    assert.strictEqual(regExp.status, 400, 'Expired registration challenge (>5m) must fail');

    // Register valid passkey at current clock, then expire an auth challenge (> 5 minutes)
    const reauth2 = await client.req('POST', '/api/auth/reauthenticate', { password });
    assert.strictEqual(reauth2.status, 200);
    const regOpt2 = await client.req<{ options: { challenge: string } }>('POST', '/api/auth/passkeys/register/options', {});
    assert.strictEqual(regOpt2.status, 200);
    const regOk = await client.req('POST', '/api/auth/passkeys/register/verify', {
      response: buildRegistrationResponse(pk, regOpt2.data.options.challenge),
      label: 'Valid Key',
    });
    assert.strictEqual(regOk.status, 201);

    const authOpt = await client.req<{ options: { challenge: string } }>('POST', '/api/auth/passkeys/login/options', {});
    assert.strictEqual(authOpt.status, 200);
    clockOffsetMs += 5 * 60_000 + 2000;
    const authExp = await client.req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk, authOpt.data.options.challenge),
    });
    assert.strictEqual(authExp.status, 401, 'Expired authentication challenge (>5m) must fail');
    console.log('PASS [Unit 3]: 5-minute challenge TTL expiry enforced on both registration and authentication.');
  } finally {
    Date.now = origNow;
    clearWebAuthnDevMemoryForTests();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    process.env = savedEnv;
  }
}

async function testLiveNeonPasskeysAndAuth() {
  const healthRes = await fetch(`${BASE}/api/health`);
  const healthJson = (await healthRes.json().catch(() => ({}))) as { database?: string };
  const isPostgresBackend = healthJson.database === 'postgresql';
  console.log(`[Passkey E2E] Target backend mode: ${healthJson.database || 'unknown'}`);

  const tag = crypto.randomBytes(5).toString('hex');
  const parentAEmail = `pk.parent.a.${tag}@nonoland.test`;
  const parentBEmail = `pk.parent.b.${tag}@nonoland.test`;
  const pendingTeacherEmail = `pk.teacher.${tag}@nonoland.test`;
  const passwordA = `ParentPass!${tag}99`;
  const passwordB = `OtherParent!${tag}88`;

  const createdUserIds: string[] = [];
  const createdFamilyIds: string[] = [];
  const createdChildIds: string[] = [];
  const createdChallengeStrings: string[] = [];

  try {
    // 1. Phone removal + Strong Password rejection/acceptance on live server
    const anon = new CookieClient();
    const weakReg = await anon.req('POST', '/api/auth/register', {
      displayName: 'Parent A',
      email: parentAEmail,
      password: 'OnlyLettersPassword',
      termsAccepted: true,
    });
    assert.strictEqual(weakReg.status, 400, 'Pure letters password must be rejected');

    const parentA = new CookieClient();
    const regA = await parentA.req<{ user: { id: string; familyId?: string } & Record<string, unknown> }>(
      'POST',
      '/api/auth/register',
      {
        displayName: 'Parent Amina',
        email: parentAEmail,
        password: passwordA,
        termsAccepted: true,
      },
    );
    assert.strictEqual(regA.status, 201, `Parent registration failed without phone: ${regA.rawText}`);
    assert.strictEqual('phone' in regA.data.user, false, 'Register response must not expose phone');
    createdUserIds.push(regA.data.user.id);
    if (regA.data.user.familyId) createdFamilyIds.push(regA.data.user.familyId);

    const meA = await parentA.req<{ authenticated: boolean; user: Record<string, unknown> }>('GET', '/api/auth/me');
    assert.strictEqual(meA.status, 200);
    assert.strictEqual('phone' in meA.data.user, false, '/api/auth/me must not expose phone');

    // PATCH /api/auth/profile ignores phone
    const profPatch = await parentA.req<{ user: Record<string, unknown> }>('PATCH', '/api/auth/profile', {
      displayName: 'Parent Amina Updated',
      phone: '+201112223334',
    });
    assert.strictEqual(profPatch.status, 200);
    assert.strictEqual('phone' in profPatch.data.user, false);

    // Teacher registration works without phone
    const teacherRegClient = new CookieClient();
    const regT = await teacherRegClient.req<{ user: { id: string } & Record<string, unknown> }>(
      'POST',
      '/api/auth/register-teacher',
      {
        displayName: 'Teacher Kareem',
        email: pendingTeacherEmail,
        password: passwordA,
        confirmPassword: passwordA,
        termsAccepted: true,
        subjects: ['math'],
      },
    );
    assert.strictEqual(regT.status, 201, `Teacher registration failed without phone: ${regT.rawText}`);
    assert.strictEqual('phone' in regT.data.user, false);
    createdUserIds.push(regT.data.user.id);

    // 2. Unauthenticated rejection on Passkey endpoints
    assert.strictEqual((await anon.req('GET', '/api/auth/passkeys')).status, 401);
    assert.strictEqual((await anon.req('POST', '/api/auth/reauthenticate', { password: passwordA })).status, 401);
    assert.strictEqual((await anon.req('POST', '/api/auth/passkeys/register/options', {})).status, 401);

    // 3. Recent password re-auth required before registering Passkey
    const noReauthOpt = await parentA.req<{ code?: string }>('POST', '/api/auth/passkeys/register/options', {});
    assert.strictEqual(noReauthOpt.status, 403);
    assert.strictEqual(noReauthOpt.data.code, 'PASSWORD_REAUTH_REQUIRED');

    const badReauth = await parentA.req('POST', '/api/auth/reauthenticate', { password: 'WrongPassword!999' });
    assert.strictEqual(badReauth.status, 403);

    const goodReauth = await parentA.req<{ reauthenticated: boolean; expiresInSeconds: number }>(
      'POST',
      '/api/auth/reauthenticate',
      { password: passwordA },
    );
    assert.strictEqual(goodReauth.status, 200);
    assert.strictEqual(goodReauth.data.reauthenticated, true);
    assert.ok(goodReauth.data.expiresInSeconds > 0);

    // 4. Register Passkey #1 (singleDevice, non-zero counter test later)
    const regOpt1 = await parentA.req<{
      options: { challenge: string; rp: { id: string } };
    }>('POST', '/api/auth/passkeys/register/options', {});
    assert.strictEqual(regOpt1.status, 200, `Register options failed: ${regOpt1.rawText}`);
    assert.strictEqual(regOpt1.data.options.rp.id, WEBAUTHN_RP_ID);
    const ch1 = regOpt1.data.options.challenge;
    createdChallengeStrings.push(ch1);

    const pk1 = createVirtualPasskey({ multiDevice: false, backedUp: false });

    // Origin mismatch on verify rejected
    const badOriginReg = await parentA.req(
      'POST',
      '/api/auth/passkeys/register/verify',
      {
        response: buildRegistrationResponse(pk1, ch1, { origin: 'https://evil.example' }),
        label: 'Bad Origin',
      },
      { Origin: 'https://evil.example' },
    );
    assert.strictEqual(badOriginReg.status, 403);

    // CSRF protection on Passkey endpoints (missing/wrong x-csrf-token -> 403)
    const badCsrfReauth = await parentA.req(
      'POST',
      '/api/auth/reauthenticate',
      { password: passwordA },
      { 'x-csrf-token': 'invalid-csrf-token' },
    );
    assert.strictEqual(badCsrfReauth.status, 403, 'CSRF mismatch on /reauthenticate must return 403');
    const badCsrfOpt = await parentA.req(
      'POST',
      '/api/auth/passkeys/register/options',
      {},
      { 'x-csrf-token': 'invalid-csrf-token' },
    );
    assert.strictEqual(badCsrfOpt.status, 403, 'CSRF mismatch on /register/options must return 403');
    const badCsrfVer = await parentA.req(
      'POST',
      '/api/auth/passkeys/register/verify',
      { response: buildRegistrationResponse(pk1, ch1) },
      { 'x-csrf-token': 'invalid-csrf-token' },
    );
    assert.strictEqual(badCsrfVer.status, 403, 'CSRF mismatch on /register/verify must return 403');

    // Invalid / unknown challenge on registration verify -> 400 (and ch1 remains usable!)
    const bogusChallenge = crypto.randomBytes(32).toString('base64url');
    const invalidChReg = await parentA.req('POST', '/api/auth/passkeys/register/verify', {
      response: buildRegistrationResponse(pk1, bogusChallenge, { counter: 0 }),
      label: 'Bogus Challenge',
    });
    assert.strictEqual(invalidChReg.status, 400, 'Unknown registration challenge must return 400');

    // RP ID mismatch in authenticatorData during registration -> 400
    const regOptBadRp = await parentA.req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/register/options',
      {},
    );
    assert.strictEqual(regOptBadRp.status, 200);
    createdChallengeStrings.push(regOptBadRp.data.options.challenge);
    const badRpReg = await parentA.req('POST', '/api/auth/passkeys/register/verify', {
      response: buildRegistrationResponse(pk1, regOptBadRp.data.options.challenge, { rpId: 'evil.example' }),
      label: 'Wrong RP ID',
    });
    assert.strictEqual(badRpReg.status, 400, 'Registration with mismatched rpIdHash must fail');

    // Valid registration verify -> 201
    const regVer1 = await parentA.req<{ passkey: { id: string; label: string } & Record<string, unknown> }>(
      'POST',
      '/api/auth/passkeys/register/verify',
      {
        response: buildRegistrationResponse(pk1, ch1, { counter: 0 }),
        label: 'MacBook Touch ID',
      },
    );
    assert.strictEqual(regVer1.status, 201, `Passkey #1 verify failed: ${regVer1.rawText}`);
    assert.strictEqual(regVer1.data.passkey.label, 'MacBook Touch ID');
    assert.strictEqual('publicKey' in regVer1.data.passkey, false, 'publicKey must never leak in API JSON');
    const pk1Id = regVer1.data.passkey.id;

    // Replay same registration challenge -> 400
    const replayReg = await parentA.req('POST', '/api/auth/passkeys/register/verify', {
      response: buildRegistrationResponse(pk1, ch1, { counter: 0 }),
      label: 'Replay Attempt',
    });
    assert.strictEqual(replayReg.status, 400, 'Replayed registration challenge must be rejected');

    // Duplicate credentialId -> 409
    const regOptDup = await parentA.req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/register/options',
      {},
    );
    assert.strictEqual(regOptDup.status, 200);
    createdChallengeStrings.push(regOptDup.data.options.challenge);
    const dupRes = await parentA.req('POST', '/api/auth/passkeys/register/verify', {
      response: buildRegistrationResponse(pk1, regOptDup.data.options.challenge, { counter: 0 }),
      label: 'Duplicate Credential',
    });
    assert.strictEqual(dupRes.status, 409, 'Duplicate credentialId must return 409');

    // Expired registration challenge -> rejected cleanly (400) when PostgreSQL is active
    if (isPostgresBackend) {
      const regOptExp = await parentA.req<{ options: { challenge: string } }>(
        'POST',
        '/api/auth/passkeys/register/options',
        {},
      );
      assert.strictEqual(regOptExp.status, 200);
      const expRegCh = regOptExp.data.options.challenge;
      createdChallengeStrings.push(expRegCh);
      await pool.query(`UPDATE webauthn_challenges SET expires_at = $1 WHERE challenge = $2`, [
        Date.now() - 5000,
        expRegCh,
      ]);
      const pkTemp = createVirtualPasskey();
      const expiredRegRes = await parentA.req('POST', '/api/auth/passkeys/register/verify', {
        response: buildRegistrationResponse(pkTemp, expRegCh),
        label: 'Expired Challenge',
      });
      assert.strictEqual(expiredRegRes.status, 400, 'Expired registration challenge must be rejected');
    }

    // Concurrent registration verify race on single challenge -> strictly 1 succeeds
    const regOptRace = await parentA.req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/register/options',
      {},
    );
    assert.strictEqual(regOptRace.status, 200);
    const raceCh = regOptRace.data.options.challenge;
    createdChallengeStrings.push(raceCh);
    const pk2 = createVirtualPasskey({ multiDevice: true, backedUp: true });
    const racePayload = {
      response: buildRegistrationResponse(pk2, raceCh, { counter: 0 }),
      label: 'iPhone Face ID',
    };
    const [rRaceA, rRaceB] = await Promise.all([
      parentA.req<{ passkey?: { id: string } }>('POST', '/api/auth/passkeys/register/verify', racePayload),
      parentA.req<{ passkey?: { id: string } }>('POST', '/api/auth/passkeys/register/verify', racePayload),
    ]);
    const raceStatuses = [rRaceA.status, rRaceB.status].sort();
    assert.deepStrictEqual(raceStatuses, [201, 400], `Expected [201, 400] for concurrent registration race, got ${raceStatuses}`);
    const pk2Id = (rRaceA.data.passkey?.id || rRaceB.data.passkey?.id)!;
    assert.ok(pk2Id);

    // List registered Passkeys -> 2 Passkeys
    const listRes = await parentA.req<{ passkeys: Array<Record<string, unknown>> }>('GET', '/api/auth/passkeys');
    assert.strictEqual(listRes.status, 200);
    assert.strictEqual(listRes.data.passkeys.length, 2);
    for (const item of listRes.data.passkeys) {
      assert.strictEqual('publicKey' in item, false, 'Passkey list must not leak publicKey');
    }
    console.log('PASS [Neon 1]: Parent registered 2 Passkeys cleanly with re-auth, duplicate/replay/expiry/race protections.');

    // 5. Passkey Authentication Flows
    // 5a. Email-scoped Passkey login with Passkey #1 (counter = 1)
    const loginClient1 = new CookieClient();
    const optScoped = await loginClient1.req<{
      options: { challenge: string; allowCredentials?: Array<{ id: string }> };
    }>('POST', '/api/auth/passkeys/login/options', { email: parentAEmail });
    assert.strictEqual(optScoped.status, 200);
    assert.ok((optScoped.data.options.allowCredentials?.length || 0) >= 2);
    createdChallengeStrings.push(optScoped.data.options.challenge);

    const loginVer1 = await loginClient1.req<{
      user: { id: string; role: string } & Record<string, unknown>;
      dashboardRoute: string;
      csrfToken: string;
    }>('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk1, optScoped.data.options.challenge, {
        counter: 1,
        userHandle: regA.data.user.id,
      }),
      rememberMe: true,
    });
    assert.strictEqual(loginVer1.status, 200, `Passkey #1 login failed: ${loginVer1.rawText}`);
    assert.strictEqual(loginVer1.data.user.role, 'parent');
    assert.strictEqual(loginVer1.data.dashboardRoute, '/parent-dashboard');
    assert.strictEqual('phone' in loginVer1.data.user, false);
    assert.ok(loginClient1.hasCookie('nono_session'));
    assert.ok(loginVer1.data.csrfToken);

    const meAfterPk = await loginClient1.req<{ authenticated: boolean; user: { id: string } }>('GET', '/api/auth/me');
    assert.strictEqual(meAfterPk.status, 200);
    assert.strictEqual(meAfterPk.data.authenticated, true);
    assert.strictEqual(meAfterPk.data.user.id, regA.data.user.id);

    // 5b. Counter replay detection: stored counter is 1 -> repeating counter=1 MUST fail (401), advancing counter=2 succeeds (200)
    const optCounterReplay = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      { email: parentAEmail },
    );
    createdChallengeStrings.push(optCounterReplay.data.options.challenge);
    const replayCounterRes = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk1, optCounterReplay.data.options.challenge, { counter: 1 }),
    });
    assert.strictEqual(replayCounterRes.status, 401, 'Stale authenticator counter MUST be rejected');

    const optCounterOk = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      { email: parentAEmail },
    );
    createdChallengeStrings.push(optCounterOk.data.options.challenge);
    const advanceCounterRes = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk1, optCounterOk.data.options.challenge, { counter: 2 }),
    });
    assert.strictEqual(advanceCounterRes.status, 200, 'Advancing authenticator counter must succeed');

    // 5c. Discoverable (empty body) login with Passkey #2 + synced 0 -> 0 repeated logins
    for (let i = 0; i < 2; i++) {
      const discoClient = new CookieClient();
      const optDisco = await discoClient.req<{ options: { challenge: string; allowCredentials?: unknown[] } }>(
        'POST',
        '/api/auth/passkeys/login/options',
        {},
      );
      assert.strictEqual(optDisco.status, 200);
      createdChallengeStrings.push(optDisco.data.options.challenge);
      const verDisco = await discoClient.req('POST', '/api/auth/passkeys/login/verify', {
        response: buildAuthenticationResponse(pk2, optDisco.data.options.challenge, { counter: 0 }),
      });
      assert.strictEqual(verDisco.status, 200, `Discoverable synced 0->0 login attempt ${i + 1} failed`);
    }

    // 5d. Tampered signature, challenge replay, concurrent auth race, expired auth challenge, untrusted origin, anti-enumeration
    const optBadSig = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      {},
    );
    createdChallengeStrings.push(optBadSig.data.options.challenge);
    const badSigRes = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk2, optBadSig.data.options.challenge, { tamperSig: true }),
    });
    assert.strictEqual(badSigRes.status, 401);

    const optAuthRace = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      {},
    );
    createdChallengeStrings.push(optAuthRace.data.options.challenge);
    const authRaceBody = {
      response: buildAuthenticationResponse(pk2, optAuthRace.data.options.challenge, { counter: 0 }),
    };
    const [aRace1, aRace2] = await Promise.all([
      new CookieClient().req('POST', '/api/auth/passkeys/login/verify', authRaceBody),
      new CookieClient().req('POST', '/api/auth/passkeys/login/verify', authRaceBody),
    ]);
    assert.deepStrictEqual([aRace1.status, aRace2.status].sort(), [200, 401], 'Concurrent auth replay must allow only 1 login');

    // Invalid / unknown challenge on login verify -> 401
    const unknownAuthChallenge = crypto.randomBytes(32).toString('base64url');
    const invalidAuthRes = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk2, unknownAuthChallenge, { counter: 0 }),
    });
    assert.strictEqual(invalidAuthRes.status, 401, 'Unknown login challenge must fail closed with 401');

    // Incorrect RP ID in authenticatorData on login verify -> 401
    const optBadRpAuth = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      {},
    );
    createdChallengeStrings.push(optBadRpAuth.data.options.challenge);
    const badRpAuthRes = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk2, optBadRpAuth.data.options.challenge, { rpId: 'evil.example' }),
    });
    assert.strictEqual(badRpAuthRes.status, 401, 'Login assertion with mismatched rpIdHash must return 401');

    if (isPostgresBackend) {
      const optAuthExp = await new CookieClient().req<{ options: { challenge: string } }>(
        'POST',
        '/api/auth/passkeys/login/options',
        {},
      );
      createdChallengeStrings.push(optAuthExp.data.options.challenge);
      await pool.query(`UPDATE webauthn_challenges SET expires_at = $1 WHERE challenge = $2`, [
        Date.now() - 5000,
        optAuthExp.data.options.challenge,
      ]);
      const expAuthRes = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
        response: buildAuthenticationResponse(pk2, optAuthExp.data.options.challenge, { counter: 0 }),
      });
      assert.strictEqual(expAuthRes.status, 401, 'Expired authentication challenge must fail closed');
    }

    // Origin mismatch on login verify
    const optOrig = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      {},
    );
    createdChallengeStrings.push(optOrig.data.options.challenge);
    const badOrigAuth = await new CookieClient().req(
      'POST',
      '/api/auth/passkeys/login/verify',
      {
        response: buildAuthenticationResponse(pk2, optOrig.data.options.challenge, { origin: 'https://phish.example' }),
      },
      { Origin: 'https://phish.example' },
    );
    assert.strictEqual(badOrigAuth.status, 403);

    // Anti-enumeration on unknown & teacher emails
    const enumUnknown = await new CookieClient().req<{ options: { challenge: string; allowCredentials?: unknown[] } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      { email: `unknown.${tag}@nonoland.test` },
    );
    const enumTeacher = await new CookieClient().req<{ options: { challenge: string; allowCredentials?: unknown[] } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      { email: pendingTeacherEmail },
    );
    assert.strictEqual(enumUnknown.status, 200);
    assert.strictEqual(enumTeacher.status, 200);
    assert.strictEqual(enumUnknown.data.options.allowCredentials, undefined);
    assert.strictEqual(enumTeacher.data.options.allowCredentials, undefined);
    createdChallengeStrings.push(enumUnknown.data.options.challenge, enumTeacher.data.options.challenge);

    console.log('PASS [Neon 2]: Email-scoped & discoverable Passkey logins, counter replay, signature tamper, race & anti-enumeration verified.');

    // 6. Role Restrictions (Child blocked), Cross-Parent IDOR, Revocation & Password Fallback
    const childCreate = await parentA.req<{ child: { id: string }; accessCode: string }>('POST', '/api/children', {
      displayName: 'Zaid',
      ageGroup: '1-4',
      language: 'ar',
      birthYear: 2023,
      birthMonth: 5,
      pin: '2580',
    });
    assert.strictEqual(childCreate.status, 201);
    createdChildIds.push(childCreate.data.child.id);

    const childClient = new CookieClient();
    const childLogin = await childClient.req('POST', '/api/auth/child-login', {
      accessCode: childCreate.data.accessCode,
      pin: '2580',
    });
    assert.strictEqual(childLogin.status, 200);
    assert.strictEqual((await childClient.req('GET', '/api/auth/passkeys')).status, 403);
    assert.strictEqual((await childClient.req('POST', '/api/auth/reauthenticate', { password: passwordA })).status, 403);
    assert.strictEqual((await childClient.req('POST', '/api/auth/passkeys/register/options', {})).status, 403);

    // Parent B cannot revoke Parent A's Passkey (even after Parent B reauthenticates)
    const parentB = new CookieClient();
    const regB = await parentB.req<{ user: { id: string; familyId?: string } }>('POST', '/api/auth/register', {
      displayName: 'Parent B',
      email: parentBEmail,
      password: passwordB,
      termsAccepted: true,
    });
    assert.strictEqual(regB.status, 201);
    createdUserIds.push(regB.data.user.id);
    if (regB.data.user.familyId) createdFamilyIds.push(regB.data.user.familyId);
    assert.strictEqual((await parentB.req('POST', '/api/auth/reauthenticate', { password: passwordB })).status, 200);
    const idorRevoke = await parentB.req('POST', `/api/auth/passkeys/${pk1Id}/revoke`, {});
    assert.strictEqual(idorRevoke.status, 403, 'Cross-parent Passkey revoke MUST fail with 403');

    // Cross-account login challenge mismatch: Parent B's email-scoped challenge cannot authenticate Parent A's credential
    const scopedBOpt = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      { email: parentBEmail },
    );
    assert.strictEqual(scopedBOpt.status, 200);
    createdChallengeStrings.push(scopedBOpt.data.options.challenge);
    const crossAccountLogin = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk2, scopedBOpt.data.options.challenge, { counter: 0 }),
    });
    assert.strictEqual(
      crossAccountLogin.status,
      401,
      'Parent A credential MUST NOT authenticate against Parent B email-scoped challenge',
    );

    // CSRF protection on Passkey revoke
    const badCsrfRevoke = await parentA.req(
      'POST',
      `/api/auth/passkeys/${pk1Id}/revoke`,
      {},
      { 'x-csrf-token': 'invalid-csrf-token' },
    );
    assert.strictEqual(badCsrfRevoke.status, 403, 'CSRF mismatch on revoke must return 403');

    // Fresh Parent A session without reauth cannot revoke Passkey
    const freshParentA = new CookieClient();
    assert.strictEqual(
      (
        await freshParentA.req('POST', '/api/auth/login', {
          email: parentAEmail,
          password: passwordA,
          portal: 'parent',
        })
      ).status,
      200,
    );
    const unconfirmedRevoke = await freshParentA.req<{ code?: string }>('POST', `/api/auth/passkeys/${pk1Id}/revoke`, {});
    assert.strictEqual(unconfirmedRevoke.status, 403);
    assert.strictEqual(unconfirmedRevoke.data.code, 'PASSWORD_REAUTH_REQUIRED');

    // Reauthenticate -> revoke Passkey #1 -> login with Passkey #1 rejected (401)
    assert.strictEqual((await freshParentA.req('POST', '/api/auth/reauthenticate', { password: passwordA })).status, 200);
    const rev1 = await freshParentA.req<{ revoked: boolean }>('POST', `/api/auth/passkeys/${pk1Id}/revoke`, {});
    assert.strictEqual(rev1.status, 200);
    assert.strictEqual(rev1.data.revoked, true);

    const optAfterRev = await new CookieClient().req<{ options: { challenge: string } }>(
      'POST',
      '/api/auth/passkeys/login/options',
      {},
    );
    createdChallengeStrings.push(optAfterRev.data.options.challenge);
    const loginRevoked = await new CookieClient().req('POST', '/api/auth/passkeys/login/verify', {
      response: buildAuthenticationResponse(pk1, optAfterRev.data.options.challenge, { counter: 3 }),
    });
    assert.strictEqual(loginRevoked.status, 401, 'Revoked Passkey MUST NOT be usable for login');

    // Revoke Passkey #2 as well -> Email + Password login still works cleanly!
    const rev2 = await freshParentA.req<{ revoked: boolean }>('POST', `/api/auth/passkeys/${pk2Id}/revoke`, {});
    assert.strictEqual(rev2.status, 200);
    const pwFallback = await new CookieClient().req('POST', '/api/auth/login', {
      email: parentAEmail,
      password: passwordA,
      portal: 'parent',
    });
    assert.strictEqual(pwFallback.status, 200, 'Parent can still log in with Email + Password after revoking all Passkeys');

    // 7. Rate limiting on Passkey reauthenticate (12 per 10m) & login/options (30 per 10m) using isolated synthetic IPs
    const rlIpReauth = `198.51.100.${10 + (crypto.randomBytes(1)[0] % 200)}`;
    for (let i = 0; i < 12; i++) {
      const r = await freshParentA.req(
        'POST',
        '/api/auth/reauthenticate',
        { password: 'WrongPassword!123' },
        { 'x-forwarded-for': rlIpReauth },
      );
      assert.strictEqual(r.status, 403);
    }
    const rlReauthBlocked = await freshParentA.req(
      'POST',
      '/api/auth/reauthenticate',
      { password: passwordA },
      { 'x-forwarded-for': rlIpReauth },
    );
    assert.strictEqual(rlReauthBlocked.status, 429, 'Reauthenticate rate limit must return 429 after 12 attempts');

    const rlIpLoginOpt = `198.51.101.${10 + (crypto.randomBytes(1)[0] % 200)}`;
    for (let i = 0; i < 30; i++) {
      const r = await new CookieClient().req(
        'POST',
        '/api/auth/passkeys/login/options',
        {},
        { 'x-forwarded-for': rlIpLoginOpt },
      );
      assert.strictEqual(r.status, 200);
    }
    const rlLoginOptBlocked = await new CookieClient().req(
      'POST',
      '/api/auth/passkeys/login/options',
      {},
      { 'x-forwarded-for': rlIpLoginOpt },
    );
    assert.strictEqual(rlLoginOptBlocked.status, 429, 'Passkey login/options rate limit must return 429 after 30 attempts');

    console.log('PASS [Live 3]: Child restriction, cross-parent IDOR & login mismatch, CSRF, rate limiting, reauth-gated revocation, and password fallback verified.');
  } finally {
    if (!isPostgresBackend) {
      return;
    }
    // Delete ONLY records created by this test run so Neon remains pristine
    const linkedUsersRes = await pool.query<{ id: string }>(
      `SELECT id FROM users WHERE id = ANY($1::text[]) OR family_id = ANY($2::text[]) OR linked_child_id = ANY($3::text[])`,
      [createdUserIds, createdFamilyIds, createdChildIds],
    );
    const allTestUserIds = Array.from(new Set([...createdUserIds, ...linkedUsersRes.rows.map((r) => r.id)]));

    await pool.query('BEGIN');
    try {
      await pool.query(
        `DELETE FROM webauthn_challenges WHERE challenge = ANY($1::text[]) OR user_id = ANY($2::text[])`,
        [createdChallengeStrings, allTestUserIds],
      );
      await pool.query(`DELETE FROM webauthn_credentials WHERE user_id = ANY($1::text[])`, [allTestUserIds]);
      await pool.query(
        `DELETE FROM child_credentials WHERE child_id = ANY($1::text[]) OR family_id = ANY($2::text[])`,
        [createdChildIds, createdFamilyIds],
      );
      await pool.query(`DELETE FROM children WHERE id = ANY($1::text[]) OR family_id = ANY($2::text[])`, [
        createdChildIds,
        createdFamilyIds,
      ]);
      await pool.query(`DELETE FROM action_tokens WHERE user_id = ANY($1::text[])`, [allTestUserIds]);
      await pool.query(
        `DELETE FROM sessions WHERE user_id = ANY($1::text[]) OR family_id = ANY($2::text[]) OR child_id = ANY($3::text[])`,
        [allTestUserIds, createdFamilyIds, createdChildIds],
      );
      await pool.query(
        `DELETE FROM privacy_consents WHERE family_id = ANY($1::text[]) OR granted_by_user_id = ANY($2::text[])`,
        [createdFamilyIds, allTestUserIds],
      );
      await pool.query(`DELETE FROM privacy_settings WHERE family_id = ANY($1::text[])`, [createdFamilyIds]);
      await pool.query(`DELETE FROM content_policies WHERE family_id = ANY($1::text[])`, [createdFamilyIds]);
      await pool.query(
        `DELETE FROM guardian_memberships WHERE family_id = ANY($1::text[]) OR user_id = ANY($2::text[])`,
        [createdFamilyIds, allTestUserIds],
      );
      await pool.query(
        `DELETE FROM family_audit_events WHERE family_id = ANY($1::text[]) OR actor_id = ANY($2::text[]) OR child_id = ANY($3::text[])`,
        [createdFamilyIds, allTestUserIds, createdChildIds],
      );
      await pool.query(
        `DELETE FROM security_logs WHERE family_id = ANY($1::text[]) OR actor_id = ANY($2::text[]) OR record_id = ANY($3::text[])`,
        [createdFamilyIds, allTestUserIds, [...allTestUserIds, ...createdChildIds, ...createdFamilyIds]],
      );
      await pool.query(
        `DELETE FROM security_logs WHERE event_type IN ('PASSKEY_LOGIN_FAIL', 'PASSKEY_LOGIN_SUCCESS', 'PASSKEY_REGISTERED', 'PASSKEY_REVOKED', 'PASSWORD_REAUTH_FAIL', 'PASSWORD_REAUTH_SUCCESS') AND ip IN ('127.0.0.1', '::1', '::ffff:127.0.0.1')`,
      );
      await pool.query(`DELETE FROM rate_limits WHERE key LIKE '%' || $1 || '%' OR key LIKE '%127.0.0.1%' OR key LIKE '%::1%'`, [
        tag,
      ]);
      await pool.query(`DELETE FROM users WHERE id = ANY($1::text[])`, [allTestUserIds]);
      await pool.query(`DELETE FROM families WHERE id = ANY($1::text[])`, [createdFamilyIds]);
      await pool.query('COMMIT');
    } catch (cleanupErr) {
      await pool.query('ROLLBACK');
      throw cleanupErr;
    }
    await pool.end();
  }
}

async function main() {
  await testProductionOriginFailClosedUnit();
  await testPasswordPolicyUnit();
  await testExpiredChallengeInMemory();
  await testIsolatedAdminAndTeacherRestrictions();
  await testLiveNeonPasskeysAndAuth();
  console.log('ALL PASSKEY & PASSWORD-ONLY AUTH VERIFICATION CHECKS PASSED!');
}

main().catch((err) => {
  console.error('PASSKEY & AUTH TEST FAILED:', err);
  process.exit(1);
});
