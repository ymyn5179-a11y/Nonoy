import 'dotenv/config';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool, type PoolConfig } from 'pg';
import * as schema from './schema.ts';

declare global {
  var _postgresPool: Pool | undefined;
}

export interface PgConnectionDiagnostics {
  configured: boolean;
  source: 'sql_vars' | 'database_url' | 'none';
  missingEnvVars: string[];
  sslEnabled: boolean;
  isNeonHost: boolean;
  isPooledEndpoint: boolean;
  hasDirectMigrationHost: boolean;
}

function isLocalOrSocketHost(host: string): boolean {
  const h = host.trim().toLowerCase();
  if (!h) return true;
  if (h.startsWith('/')) return true;
  return h === 'localhost' || h === '127.0.0.1' || h === '::1';
}

function resolveSslOption(host: string, urlSslMode?: string | null): PoolConfig['ssl'] {
  const rawSsl = (process.env.SQL_SSL || '').trim().toLowerCase();
  if (rawSsl === 'false' || rawSsl === 'disable' || rawSsl === '0') {
    return false;
  }
  if (rawSsl === 'no-verify') {
    return { rejectUnauthorized: false };
  }
  if (rawSsl === 'true' || rawSsl === 'require' || rawSsl === '1') {
    return { rejectUnauthorized: process.env.SQL_SSL_REJECT_UNAUTHORIZED !== 'false' };
  }
  const mode = (urlSslMode || '').trim().toLowerCase();
  if (mode === 'disable') {
    return false;
  }
  if (mode === 'no-verify' || mode === 'allow' || mode === 'prefer') {
    return { rejectUnauthorized: false };
  }
  if (
    mode === 'require' ||
    mode === 'verify-ca' ||
    mode === 'verify-full' ||
    host.toLowerCase().endsWith('.neon.tech') ||
    !isLocalOrSocketHost(host) ||
    process.env.NODE_ENV === 'production'
  ) {
    return { rejectUnauthorized: process.env.SQL_SSL_REJECT_UNAUTHORIZED !== 'false' };
  }
  return false;
}

function sanitizePgErrorMessage(msg: string): string {
  return String(msg || 'Unknown PostgreSQL error').replace(/postgres(?:ql)?:\/\/[^\s]+/gi, 'postgresql://[REDACTED]');
}

export function getPgConnectionDiagnostics(): PgConnectionDiagnostics {
  const sqlHost = (process.env.SQL_HOST || '').trim();
  const explicitSqlDb = (process.env.SQL_DB_NAME || '').trim();
  const sqlUser = (process.env.SQL_USER || '').trim();
  const sqlPassword = (process.env.SQL_PASSWORD || '').trim();
  const dbUrl = (process.env.DATABASE_URL || '').trim();

  if (sqlHost || explicitSqlDb || sqlUser || sqlPassword) {
    const sqlDb = explicitSqlDb || 'neondb';
    const missing: string[] = [];
    if (!sqlHost) missing.push('SQL_HOST');
    if (!sqlUser) missing.push('SQL_USER');
    if (!sqlPassword && !isLocalOrSocketHost(sqlHost)) missing.push('SQL_PASSWORD');
    const sslOpt = resolveSslOption(sqlHost);
    return {
      configured: Boolean(sqlHost && sqlDb && sqlUser && (sqlPassword || isLocalOrSocketHost(sqlHost))),
      source: 'sql_vars',
      missingEnvVars: missing,
      sslEnabled: Boolean(sslOpt),
      isNeonHost: sqlHost.toLowerCase().includes('.neon.tech'),
      isPooledEndpoint: sqlHost.toLowerCase().includes('-pooler.'),
      hasDirectMigrationHost: Boolean((process.env.SQL_DIRECT_HOST || process.env.DIRECT_DATABASE_URL || '').trim()),
    };
  }

  if (dbUrl) {
    try {
      const parsed = new URL(dbUrl);
      const host = parsed.hostname || '';
      const sslMode = parsed.searchParams.get('sslmode');
      const sslOpt = resolveSslOption(host, sslMode);
      return {
        configured: Boolean(host && parsed.pathname.replace(/^\//, '') && parsed.username),
        source: 'database_url',
        missingEnvVars: [],
        sslEnabled: Boolean(sslOpt),
        isNeonHost: host.toLowerCase().includes('.neon.tech'),
        isPooledEndpoint: host.toLowerCase().includes('-pooler.'),
        hasDirectMigrationHost: Boolean((process.env.SQL_DIRECT_HOST || process.env.DIRECT_DATABASE_URL || '').trim()),
      };
    } catch {
      return {
        configured: false,
        source: 'database_url',
        missingEnvVars: ['DATABASE_URL (invalid connection URI format)'],
        sslEnabled: false,
        isNeonHost: false,
        isPooledEndpoint: false,
        hasDirectMigrationHost: false,
      };
    }
  }

  return {
    configured: false,
    source: 'none',
    missingEnvVars: ['SQL_HOST', 'SQL_DB_NAME', 'SQL_USER', 'SQL_PASSWORD'],
    sslEnabled: false,
    isNeonHost: false,
    isPooledEndpoint: false,
    hasDirectMigrationHost: false,
  };
}

function buildPoolConfig(): PoolConfig {
  const max = Number(process.env.SQL_POOL_MAX) || 10;
  const connectionTimeoutMillis = Number(process.env.SQL_CONNECTION_TIMEOUT_MS) || 15000;
  const idleTimeoutMillis = Number(process.env.SQL_IDLE_TIMEOUT_MS) || 30000;

  const sqlHost = (process.env.SQL_HOST || '').trim();
  const sqlDb = (process.env.SQL_DB_NAME || '').trim() || 'neondb';
  const sqlUser = (process.env.SQL_USER || '').trim();
  const sqlPassword = process.env.SQL_PASSWORD ?? '';
  const sqlPort = Number(process.env.SQL_PORT) || 5432;

  if (sqlHost || sqlUser || (process.env.SQL_DB_NAME || '').trim()) {
    return {
      host: sqlHost,
      port: sqlPort,
      user: sqlUser,
      password: sqlPassword,
      database: sqlDb,
      ssl: resolveSslOption(sqlHost),
      max,
      connectionTimeoutMillis,
      idleTimeoutMillis,
    };
  }

  const dbUrl = (process.env.DATABASE_URL || '').trim();
  if (dbUrl) {
    try {
      const parsed = new URL(dbUrl);
      const host = parsed.hostname;
      const sslMode = parsed.searchParams.get('sslmode');
      return {
        host,
        port: Number(parsed.port) || sqlPort,
        user: decodeURIComponent(parsed.username || ''),
        password: decodeURIComponent(parsed.password || ''),
        database: decodeURIComponent(parsed.pathname.replace(/^\//, '')),
        ssl: resolveSslOption(host, sslMode),
        max,
        connectionTimeoutMillis,
        idleTimeoutMillis,
      };
    } catch {
      // Fall through to empty config; pgStore will reject safely with DB_UNAVAILABLE
    }
  }

  return {
    host: undefined,
    user: undefined,
    password: undefined,
    database: undefined,
    max,
    connectionTimeoutMillis,
    idleTimeoutMillis,
  };
}

export const createPool = () => {
  if (!global._postgresPool) {
    global._postgresPool = new Pool(buildPoolConfig());

    global._postgresPool.on('error', (err) => {
      const safeCode = (err as { code?: string })?.code || 'POOL_ERROR';
      console.error(`PostgreSQL idle pool error [${safeCode}]:`, sanitizePgErrorMessage(err.message));
    });
  }
  return global._postgresPool;
};

export function resetPoolForResolvedSecrets(): void {
  if (global._postgresPool) {
    const oldPool = global._postgresPool;
    global._postgresPool = new Pool(buildPoolConfig());
    global._postgresPool.on('error', (err) => {
      const safeCode = (err as { code?: string })?.code || 'POOL_ERROR';
      console.error(`PostgreSQL idle pool error [${safeCode}]:`, sanitizePgErrorMessage(err.message));
    });
    pool = global._postgresPool;
    db = drizzle(pool, { schema });
    void oldPool.end().catch(() => {});
  }
}

export let pool = createPool();
export let db = drizzle(pool, { schema });

