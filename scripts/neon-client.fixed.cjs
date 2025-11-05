const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL;

const sanitizeConnStr = (s) => {
  if (!s) return s;
  try {
    const str = String(s);
    const [base, qs] = str.split('?');
    if (!qs) return str;
    const params = qs.split('&').filter(p => !/^channel_binding=/i.test(p) && !/^sslmode=/i.test(p));
    return params.length ? base + '?' + params.join('&') : base;
  } catch (e) {
    return s;
  }
};

const getPool = () => {
  if (!DATABASE_URL) throw new Error('no_database_url');
  if (global.__pgPool) return global.__pgPool;
  const defaultTimeout = (process.env.VERCEL || process.env.NODE_ENV === 'production') ? 3000 : 5000;
  const buildOpts = (connStr) => {
    const o = { connectionString: connStr, connectionTimeoutMillis: defaultTimeout };
    if (process.env.DB_SSL !== 'false') o.ssl = { rejectUnauthorized: false };
    return o;
  };

  const connToUse = process.env.VERCEL ? sanitizeConnStr(DATABASE_URL) : DATABASE_URL;
  if (process.env.VERCEL && connToUse !== DATABASE_URL) console.warn('Using sanitized DATABASE_URL for serverless environment');
  const primaryPool = new Pool(buildOpts(connToUse));
  global.__pgPool = primaryPool;
  return global.__pgPool;
};

const poolClient = () => {
  const pool = getPool();
  let _client = null;
  return {
    connect: async () => { _client = await pool.connect(); },
    query: (...args) => (_client ? _client.query(...args) : pool.query(...args)),
    end: async () => { try { if (_client) { _client.release(); _client = null; } } catch (e) {} },
    on: (ev, fn) => { try { if (_client && _client.on) _client.on(ev, fn); } catch (e) {} }
  };
};

const testConnection = async () => {
  if (process.env.VERCEL) {
    try {
      const { neon } = require('@neondatabase/serverless');
      const sql = neon(process.env.DATABASE_URL);
      return await sql`SELECT 1`;
    } catch (e) {
      console.warn('Neon serverless client not available or failed:', e && e.message ? e.message : e);
    }
  }
  try {
    const pool = getPool();
    return await pool.query('SELECT 1');
  } catch (err) {
    console.warn('Primary DB connection failed:', err && err.message ? err.message : err);
    if (!DATABASE_URL) throw err;
    const s = String(DATABASE_URL);
    const [base, qs] = s.split('?');
    let newConn = base;
    if (qs) {
      const params = qs.split('&').filter(p => !/^channel_binding=/i.test(p) && !/^sslmode=/i.test(p));
      if (params.length) newConn = base + '?' + params.join('&');
    }
    console.warn('Attempting fallback DB connection without channel_binding/sslmode.');
    const defaultTimeout = (process.env.VERCEL || process.env.NODE_ENV === 'production') ? 3000 : 5000;
    const opts = { connectionString: newConn, connectionTimeoutMillis: defaultTimeout };
    if (process.env.DB_SSL !== 'false') opts.ssl = { rejectUnauthorized: false };
    const fallbackPool = new Pool(opts);
    global.__pgPool = fallbackPool;
    return await fallbackPool.query('SELECT 1');
  }
};

module.exports = { getPool, poolClient, testConnection };
