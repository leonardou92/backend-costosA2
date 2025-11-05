#!/usr/bin/env node
/* Simple API server exposing DB-backed endpoints for the frontend
   Endpoints:
   - GET /api/summary?year=YYYY&month=M  -> { ventas, costos, utilidad }
   - GET /api/series?type=day|month|year&year=YYYY&month=M -> [{ periodo, ventas, costos }]
*/
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const ExcelJS = require('exceljs');
// Swagger dependencies
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');
const path = require('path');
const fs = require('fs');
// (swaggerJsdoc / swaggerUi already declared above)
dotenv.config();
const DATABASE_URL = process.env.DATABASE_URL;
// Respect Render / cloud platform provided PORT first, then API_PORT, then fallback
// Normalize port coming from environment and trim any accidental whitespace/newlines
const APP_PORT = String(process.env.PORT || process.env.API_PORT || 3001).trim();
if (!DATABASE_URL) {
  const msg = 'DATABASE_URL not set in environment';
  // If this file is executed directly as a server, fail fast. If it's required
  // as a module (e.g., by a serverless wrapper during deployment), don't exit
  // the process so the build can continue — runtime should provide the env var.
  // For development convenience we will not exit here. Instead log a warning
  // so the local server can still start and serve lightweight endpoints
  // (e.g. /api/health) even when a DATABASE_URL is not provided. In production
  // the runtime should set DATABASE_URL; keep an eye on logs if DB-related
  // endpoints start failing.
  if (require.main === module) {
    console.warn('[dev] ' + msg + ' — starting server in degraded mode');
  } else {
    console.warn(msg);
  }
}

// Lightweight startup log (do NOT print secrets) to help debugging init issues
try {
  // Do not print credentials. Extract only host/port/dbname when possible to aid debugging
  const dbInfo = {};
  if (DATABASE_URL) {
    try {
      const u = new URL(DATABASE_URL);
      dbInfo.host = u.hostname;
      dbInfo.port = u.port || (u.protocol && (u.protocol.indexOf('postgres') !== -1) ? '5432' : '');
      dbInfo.database = u.pathname ? u.pathname.replace(/^\//, '') : '';
      dbInfo.protocol = u.protocol ? u.protocol.replace(':', '') : '';
    } catch (e) {
      // fallback: try to extract host=... from libpq style connection strings
      try {
        const m = String(DATABASE_URL).match(/host=([^\s]+)/);
        if (m && m[1]) dbInfo.host = m[1];
      } catch (ee) {}
    }
  }
  console.log('api-server loaded', { env_database_present: !!DATABASE_URL, node_env: process.env.NODE_ENV || 'not-set', db: dbInfo });
} catch (e) {}

const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));

// --- Swagger setup -------------------------------------------------------
try {
  const serverUrl = process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : `http://localhost:${APP_PORT}`;
  const swaggerSpec = {
    openapi: '3.0.0',
    info: {
      title: 'Costos API',
      version: '1.0.0',
      description: 'Documentación de la API de Costos A2'
    },
    servers: [{ url: serverUrl }],
    components: {
      securitySchemes: {
        basicAuth: { type: 'http', scheme: 'basic' }
      }
    },
    security: [{ basicAuth: [] }],
    paths: {
      '/api/health': { get: { summary: 'Health check', responses: { '200': { description: 'OK' } } } },
      '/api/summary': { get: { summary: 'Resumen ventas/costos', parameters: [ { name: 'year', in: 'query', schema: { type: 'integer' } }, { name: 'month', in: 'query', schema: { type: 'integer' } } ], responses: { '200': { description: 'Resumen calculado' }, '401': { description: 'No autorizado' } } } },
      '/api/series': { get: { summary: 'Series de ventas/costos', parameters: [ { name: 'type', in: 'query', schema: { type: 'string', enum: ['day','month','year'] } }, { name: 'year', in: 'query', schema: { type: 'integer' } }, { name: 'month', in: 'query', schema: { type: 'integer' } } ], responses: { '200': { description: 'Array de periodos' }, '401': { description: 'No autorizado' } } } },
      '/api/inventario': { get: { summary: 'Inventario por fecha', parameters: [ { name: 'year', in: 'query' }, { name: 'month', in: 'query' }, { name: 'day', in: 'query' } ], responses: { '200': { description: 'Lista de inventario' }, '400': { description: 'Bad request' }, '401': { description: 'No autorizado' } } } },
      '/api/inventario/days': { get: { summary: 'Días disponibles en inventario', parameters: [ { name: 'year', in: 'query' }, { name: 'month', in: 'query' } ], responses: { '200': { description: 'Lista de días' }, '401': { description: 'No autorizado' } } } },
      '/api/inventario/import': { post: { summary: 'Importar inventario (texto)', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { date: { type: 'string' }, content: { type: 'string' } } } } } }, responses: { '200': { description: 'Import finished' }, '400': { description: 'Bad request' }, '401': { description: 'No autorizado' } } } },
      '/api/inventario/clear': { post: { summary: 'Borrar inventario por fecha', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { date: { type: 'string' } } } } } }, responses: { '200': { description: 'Deleted count' }, '401': { description: 'No autorizado' } } } },
      '/api/ventas/import': { post: { summary: 'Importar ventas (texto)', requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { content: { type: 'string' } } } } } }, responses: { '202': { description: 'Accepted (jobId)' }, '400': { description: 'Bad request' }, '401': { description: 'No autorizado' } } } },
      '/api/report/costos-ventas': { get: { summary: 'Exportar costos de ventas (XLSX)', parameters: [ { name: 'year', in: 'query' }, { name: 'month', in: 'query' } ], responses: { '200': { description: 'XLSX file' }, '401': { description: 'No autorizado' } } } },
      '/api/report/costos-ventas/data': { get: { summary: 'Preview tabla costos-ventas', parameters: [ { name: 'page', in: 'query' }, { name: 'pageSize', in: 'query' } ], responses: { '200': { description: 'Paginated rows' }, '401': { description: 'No autorizado' } } } },
      '/api/import/status/{jobId}': { get: { summary: 'Estado de import (ventas/inventario)', parameters: [ { name: 'jobId', in: 'path', required: true } ], responses: { '200': { description: 'Job status' }, '401': { description: 'No autorizado' } } } },
      '/api/inventario/import/status/{jobId}': { get: { summary: 'Estado de import inventario', parameters: [ { name: 'jobId', in: 'path', required: true } ], responses: { '200': { description: 'Job status' }, '401': { description: 'No autorizado' } } } },
      '/api/dbtest': { get: { summary: 'DB connectivity test', responses: { '200': { description: 'db_reachable' }, '500': { description: 'db_connect_failed' } } } },
      '/api/ping': { get: { summary: 'Ping (no-auth)', responses: { '200': { description: 'pong' } } } }
    }
  };

  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  app.get('/api/docs.json', (req, res) => res.json(swaggerSpec));
} catch (e) {
  console.warn('Could not enable Swagger UI:', e && e.message ? e.message : e);
}

// -------------------------------------------------------------------------

// (swagger-jsdoc usage removed — using manual swaggerSpec above)

// Centralized Neon client (serverless-friendly). See scripts/neon-client.cjs
const { getPool, poolClient, testConnection } = require('./neon-client.cjs');
// in-memory job tracker for background imports
const importJobs = new Map();
// JWT-based auth (stateless) so serverless functions work across invocations
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
if (!process.env.JWT_SECRET) {
  console.warn('Warning: JWT_SECRET not set in environment; using fallback dev secret. Set JWT_SECRET in production.');
}

// Development credentials (can be overridden via env)
const DEV_USERNAME = process.env.DEV_USERNAME || 'leonardou92';
const DEV_PASSWORD = process.env.DEV_PASSWORD || '8121230219';

// helper to extract and verify JWT from Authorization header
const getSessionFromReq = (req) => {
  try {
    const auth = req.headers && (req.headers.authorization || req.headers.Authorization);
    if (!auth) return null;
    const parts = String(auth).split(' ');
    // Basic auth support: Authorization: Basic base64(user:pass)
    if (parts[0] && parts[0].toLowerCase() === 'basic') {
      try {
        const decoded = Buffer.from(parts[1] || '', 'base64').toString('utf8');
        const idx = decoded.indexOf(':');
        const user = idx === -1 ? decoded : decoded.slice(0, idx);
        const pass = idx === -1 ? '' : decoded.slice(idx + 1);
        if (user === DEV_USERNAME && pass === DEV_PASSWORD) return { username: user, createdAt: Date.now() };
        return null;
      } catch (e) {
        return null;
      }
    }
    // Bearer JWT fallback (if present)
    const token = parts.length === 2 && parts[0].toLowerCase() === 'bearer' ? parts[1] : parts[0];
    if (!token) return null;
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || !payload.username) return null;
    return { username: payload.username, createdAt: payload.iat ? payload.iat * 1000 : Date.now() };
  } catch (e) {
    return null;
  }
};

// normalize date for inventario importer: accept yyyy-mm-dd, dd/mm/yyyy or other parseable strings
const normalizeDateInv = (s) => {
  if (s === null || s === undefined) return '';
  let t = String(s).trim();
  if (t.length === 0) return '';
  // already yyyy-mm-dd or starts with date
  if (/^\d{4}-\d{2}-\d{2}/.test(t)) return t.split(' ')[0];
  // dd/mm/yyyy -> convert
  const m = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m) return `${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;
  // try Date.parse fallback
  const parsed = Date.parse(t);
  if (!Number.isNaN(parsed)) {
    const d = new Date(parsed);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
  }
  return '';
};

// normalize numeric-like strings to JS Number (accepts "1.234,56" or "1,234.56" or "1234.56" etc.)
const normalizeNumber = (v) => {
  if (v === null || v === undefined) return 0;
  let t = String(v).trim();
  if (t === '') return 0;
  // remove spaces
  t = t.replace(/\s+/g, '');
  // if contains comma as decimal sep and dots as thousand sep (e.g. 1.234,56)
  const commaCount = (t.match(/,/g) || []).length;
  const dotCount = (t.match(/\./g) || []).length;
  if (commaCount > 0 && dotCount > 0) {
    // assume dots are thousands and comma decimal -> remove dots, replace comma with dot
    t = t.replace(/\./g, '').replace(/,/g, '.');
  } else if (commaCount > 0 && dotCount === 0) {
    // likely comma decimal -> replace with dot
    t = t.replace(/,/g, '.');
  }
  // if multiple dots (e.g. 1.234.567.89) keep last as decimal
  const parts = t.split('.');
  if (parts.length > 2) {
    const last = parts.pop();
    t = parts.join('') + '.' + last;
  }
  // remove any non-digit, non-dot, non-minus
  t = t.replace(/[^0-9.\-]/g, '');
  if (t === '' || t === '-' || t === '.') return 0;
  const n = Number(t);
  return Number.isFinite(n) ? n : 0;
};

app.get('/api/summary', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const year = Number(req.query.year) || new Date().getFullYear();
  const month = Number(req.query.month) || (new Date().getMonth() + 1);
  const client = poolClient();
  try {
    await client.connect();
    // Use the provided select logic to compute totals using the matching inventario_costos row
    const q = `
      SELECT
        COALESCE(SUM(COALESCE(v.fdi_preciodeventadcto,0) * COALESCE(v.fdi_cantidad,0)), 0) AS ventas,
        COALESCE(SUM(
          CASE
            WHEN v.fdi_unddetallada <> TRUE
              THEN COALESCE(ici.costo_actual,0) * COALESCE(v.fdi_cantidad,0)
            ELSE (COALESCE(ici.costo_actual,0) / NULLIF(ici.capacidad_con,0)) * COALESCE(v.fdi_cantidad,0)
          END
        ), 0) AS costos
      FROM ventas v
      INNER JOIN inventario_costos ici
        ON ici.codigo = v.fdi_codigo AND ici.fecha_sistema = v.fdi_fechaoperacion
      WHERE EXTRACT(YEAR FROM v.fdi_fechaoperacion) = $1
        AND EXTRACT(MONTH FROM v.fdi_fechaoperacion) = $2
    `;
    const r = await client.query(q, [year, month]);
    const ventas = Number(r.rows[0] && r.rows[0].ventas) || 0;
    const costos = Number(r.rows[0] && r.rows[0].costos) || 0;

    await client.end();
    res.json({ ventas, costos, utilidad: Math.max(0, ventas - costos) });
  } catch (err) {
    console.error(err);
    try { await client.end(); } catch(e){}
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/series', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const type = req.query.type === 'year' ? 'year' : req.query.type === 'month' ? 'month' : 'day';
  const year = Number(req.query.year) || new Date().getFullYear();
  const month = Number(req.query.month) || (new Date().getMonth() + 1);
  const client = poolClient();
  try {
    await client.connect();
    let rows = [];
    if (type === 'day') {
      // sales per day
      const q = `SELECT date_trunc('day', fdi_fechaoperacion) as day,
        SUM(COALESCE(fdi_preciodeventadcto,0) * COALESCE(fdi_cantidad,0)) as ventas
        FROM ventas
        WHERE EXTRACT(YEAR FROM fdi_fechaoperacion) = $1 AND EXTRACT(MONTH FROM fdi_fechaoperacion) = $2
        GROUP BY day
        ORDER BY day`;
      const r = await client.query(q, [year, month]);
      // costos per day from inventario (use fecha_sistema). We'll sum costo_actual * existencia_deta by day
      const qc = `SELECT date_trunc('day', fecha_sistema) as day, SUM(COALESCE(costo_actual,0) * COALESCE(existencia_deta,0)) as costos
        FROM inventario_costos
        WHERE EXTRACT(YEAR FROM fecha_sistema) = $1 AND EXTRACT(MONTH FROM fecha_sistema) = $2
        GROUP BY day
        ORDER BY day`;
      const rc = await client.query(qc, [year, month]);
      const mapVentas = new Map(r.rows.map(row => [row.day.toISOString().slice(0,10), Number(row.ventas)||0]));
      const mapCostos = new Map(rc.rows.map(row => [row.day.toISOString().slice(0,10), Number(row.costos)||0]));

      // produce array for all days in month
      const daysInMonth = new Date(year, month, 0).getDate();
      for (let d = 1; d <= daysInMonth; d++) {
        const dt = new Date(year, month -1, d);
        const key = dt.toISOString().slice(0,10);
        rows.push({ periodo: `Día ${d}`, ventas: mapVentas.get(key) || 0, costos: mapCostos.get(key) || 0 });
      }
    } else if (type === 'month') {
      // months of the given year
      const qv = `SELECT EXTRACT(MONTH FROM fdi_fechaoperacion) as mes, SUM(COALESCE(fdi_preciodeventadcto,0) * COALESCE(fdi_cantidad,0)) as ventas
        FROM ventas WHERE EXTRACT(YEAR FROM fdi_fechaoperacion) = $1 GROUP BY mes ORDER BY mes`;
      const rcv = await client.query(qv, [year]);
      const qc = `SELECT EXTRACT(MONTH FROM fecha_sistema) as mes, SUM(COALESCE(costo_actual,0) * COALESCE(existencia_deta,0)) as costos
        FROM inventario_costos WHERE EXTRACT(YEAR FROM fecha_sistema) = $1 GROUP BY mes ORDER BY mes`;
      const rcc = await client.query(qc, [year]);
      const mapVentas = new Map(rcv.rows.map(r => [Number(r.mes), Number(r.ventas)||0]));
      const mapCostos = new Map(rcc.rows.map(r => [Number(r.mes), Number(r.costos)||0]));
      const monthNames = ['Ene','Feb','Mar','Abr','May','Jun','Jul','Ago','Sep','Oct','Nov','Dic'];
      for (let m = 1; m <= 12; m++) {
        rows.push({ periodo: monthNames[m-1], ventas: mapVentas.get(m) || 0, costos: mapCostos.get(m) || 0 });
      }
    } else {
      // year: last 5 years
      const start = year - 4;
      const qv = `SELECT EXTRACT(YEAR FROM fdi_fechaoperacion) as y, SUM(COALESCE(fdi_preciodeventadcto,0) * COALESCE(fdi_cantidad,0)) as ventas
        FROM ventas WHERE EXTRACT(YEAR FROM fdi_fechaoperacion) BETWEEN $1 AND $2 GROUP BY y ORDER BY y`;
      const rcv = await client.query(qv, [start, year]);
      const qc = `SELECT EXTRACT(YEAR FROM fecha_sistema) as y, SUM(COALESCE(costo_actual,0) * COALESCE(existencia_deta,0)) as costos
        FROM inventario_costos WHERE EXTRACT(YEAR FROM fecha_sistema) BETWEEN $1 AND $2 GROUP BY y ORDER BY y`;
      const rcc = await client.query(qc, [start, year]);
      const mapVentas = new Map(rcv.rows.map(r => [Number(r.y), Number(r.ventas)||0]));
      const mapCostos = new Map(rcc.rows.map(r => [Number(r.y), Number(r.costos)||0]));
      for (let y = start; y <= year; y++) rows.push({ periodo: `${y}`, ventas: mapVentas.get(y) || 0, costos: mapCostos.get(y) || 0 });
    }

    await client.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    try { await client.end(); } catch(e){}
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/inventario', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const year = Number(req.query.year);
  const month = Number(req.query.month);
  const day = Number(req.query.day);
  if (!year || !month || !day) return res.status(400).json({ error: 'year, month and day required' });
  const client = poolClient();
  try {
    await client.connect();
    const q = `SELECT codigo, descripcion, costo_anterior, costo_actual, costo_fob, principal, capacidad_con, existencia_deta, precio_sin_impu_1, precio_sin_impu_2, fecha_sistema
      FROM inventario_costos
      WHERE fecha_sistema::date = $1::date`;
    const dateStr = new Date(year, month - 1, day).toISOString().slice(0, 10);
    const r = await client.query(q, [dateStr]);
    await client.end();
    res.json(r.rows);
  } catch (err) {
    console.error(err);
    try { await client.end(); } catch(e){}
    res.status(500).json({ error: err.message });
  }
});

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Verificar estado del servidor
 *     description: Endpoint de health check que verifica si el servidor está funcionando
 *     responses:
 *       200:
 *         description: Servidor funcionando correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *                 healthy:
 *                   type: boolean
 *                   example: true
 *                 uptime:
 *                   type: number
 *                   example: 123.45
 *                 env_database:
 *                   type: boolean
 *                   example: true
 *                 now:
 *                   type: number
 *                   example: 1762374207697
 */
app.get('/api/health', (req, res) => {
  // Minimal, fast health check that avoids touching the DB.
  res.json({ ok: true, healthy: true, uptime: process.uptime(), env_database: !!DATABASE_URL, now: Date.now() });
});

app.get('/api/ping', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), env_database: !!DATABASE_URL });
});

// Convenience endpoint that mirrors the Vercel handler `api/ok.cjs`
app.get('/api/ok', (req, res) => {
  res.json({ ok: true, message: 'vercel api OK', env: { VERCEL_URL: process.env.VERCEL_URL || null } });
});

// DB connectivity test endpoint (no auth) — uses a short connection timeout so
// it fails fast if the DB is unreachable from Vercel. Returns a safe message
// on error without leaking credentials.
app.get('/api/dbtest', async (req, res) => {
  if (!DATABASE_URL) return res.status(500).json({ ok: false, error: 'no_database_url' });
  try {
    const pool = getPool();
    // run a simple query to verify connectivity
    await pool.query('SELECT 1');
    return res.json({ ok: true, message: 'db_reachable' });
  } catch (err) {
    console.error('dbtest connect error', err && err.message ? err.message : err);
    return res.status(500).json({ ok: false, error: 'db_connect_failed', message: String(err && err.message ? err.message : 'connect_error') });
  }
});

// return list of days in month that have inventario_costos entries
app.get('/api/inventario/days', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const year = Number(req.query.year);
  const month = Number(req.query.month);
  if (!year || !month) return res.status(400).json({ error: 'year and month required' });
  const client = poolClient();
  try {
    await client.connect();
    const q = `SELECT DISTINCT EXTRACT(DAY FROM fecha_sistema) as day FROM inventario_costos
      WHERE EXTRACT(YEAR FROM fecha_sistema) = $1 AND EXTRACT(MONTH FROM fecha_sistema) = $2 ORDER BY day`;
    const r = await client.query(q, [year, month]);
    await client.end();
    const days = r.rows.map(row => Number(row.day));
    res.json({ days });
  } catch (err) {
    console.error('error fetching inventario days', err);
    try { await client.end(); } catch (e) {}
    res.status(500).json({ error: err.message || String(err) });
  }
});

// Import endpoint: accepts JSON { date: 'YYYY-MM-DD', content: '...text...' }
app.post('/api/inventario/import', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const { date, content } = req.body || {};
  console.log('/api/inventario/import called - content length:', typeof content === 'string' ? content.length : 'n/a');
  if (typeof content === 'string') {
    console.log('content preview:', content.slice(0, 500).replace(/\n/g, '\\n').slice(0,300));
  }
  if (!date || !content) return res.status(400).json({ error: 'date and content required' });
  // simple parser: detect delimiter and optional header
  const detectDelimiter = (line) => {
    if (line.indexOf('|') !== -1) return '|';
    if (line.indexOf('\t') !== -1) return '\t';
    if (line.indexOf(',') !== -1) return ',';
    // fallback to 2+ spaces
    return /\s{2,}/;
  };

  const lines = String(content).split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  if (lines.length === 0) return res.status(400).json({ error: 'empty content' });

  const delim = detectDelimiter(lines[0]);
  const splitLine = (ln) => {
    if (typeof delim === 'string') return ln.split(delim).map(s => s.trim());
    return ln.split(delim).map(s => s.trim());
  };

  // known target columns in inventario_costos (extend to include costo_fob, principal, capacidad_con)
  const targetCols = ['codigo','descripcion','costo_anterior','costo_actual','costo_fob','principal','capacidad_con','existencia_deta','precio_sin_impu_1','precio_sin_impu_2','fecha_sistema'];

  // check header
  const firstParts = splitLine(lines[0]).map(p => p.trim());
  let hasHeader = false;
  const header = [];
  if (firstParts.length > 0) {
    const joined = firstParts.join(' ').toLowerCase();
    // if it contains at least one known keyword, treat as header
    const keywords = ['codigo','descripcion','costo','existencia','precio','precio_sin'];
    if (keywords.some(k => joined.includes(k))) {
      hasHeader = true;
      header.push(...firstParts.map(p => p.toLowerCase()));
    }
  }

  const dataLines = hasHeader ? lines.slice(1) : lines;
  const rows = [];
  for (const ln of dataLines) {
    const parts = splitLine(ln).map(p => p.trim());
    if (parts.length === 0) continue;
    const row = {};
    if (hasHeader) {
      // map fields by header names (best-effort). Clean header tokens to match known target columns
      for (let i = 0; i < parts.length; i++) {
        const rawHeader = header[i] || `col${i}`;
        const clean = String(rawHeader).replace(/\s+/g, '_').replace(/[^a-z0-9_]/gi, '').toLowerCase();
        // try to align to one of the known targetCols
        const mapped = targetCols.includes(clean) ? clean : (targetCols[i] || clean);
        row[mapped] = parts[i];
      }
    } else {
      // no header: map by position to targetCols
      for (let i = 0; i < Math.min(parts.length, targetCols.length); i++) {
        row[targetCols[i]] = parts[i];
      }
    }
    rows.push(row);
  }
  const insertStart = Date.now();
  const insertBase = `INSERT INTO inventario_costos (codigo, descripcion, costo_anterior, costo_actual, costo_fob, principal, capacidad_con, existencia_deta, precio_sin_impu_1, precio_sin_impu_2, fecha_sistema)`;
  const insertQ = insertBase + `\nVALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`;
  const updateQ = `UPDATE inventario_costos SET descripcion = $2, costo_anterior = $3, costo_actual = $4, costo_fob = $5, principal = $6, capacidad_con = $7, existencia_deta = $8, precio_sin_impu_1 = $9, precio_sin_impu_2 = $10, fecha_sistema = $11 WHERE codigo = $1`;

  // insert in chunks synchronously (no background job) to keep implementation simple and avoid job state here
  let inserted = 0;
  const chunkSize = 250;
  const chunkArray = (arr, size) => {
    const out = [];
    for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
    return out;
  };

  const rowChunks = chunkArray(rows, chunkSize);
  const client = poolClient();
  try {
    await client.connect();
    await client.query('BEGIN');
    for (const chunk of rowChunks) {
      const values = [];
      const placeholders = [];
      let idx = 1;
        for (const r of chunk) {
        // prefer the provided `date` parameter (endpoint input); fall back to per-row fecha_sistema
        let fechaVal = normalizeDateInv(date);
        if (!fechaVal) fechaVal = normalizeDateInv(r.fecha_sistema);
        if (!fechaVal) fechaVal = null;
        // debug: log first parsed date values for the first chunk to help troubleshooting
        if (inserted === 0 && placeholders.length === 0) {
          console.log('inventario.import sample fechaVal for first row:', { providedDate: date, sampleRowFecha: r.fecha_sistema, parsed: fechaVal });
        }
        const params = [
          r.codigo || null,
          r.descripcion || null,
          normalizeNumber(r.costo_anterior || 0),
          normalizeNumber(r.costo_actual || 0),
          normalizeNumber(r.costo_fob || 0),
          normalizeNumber(r.principal || 0),
          normalizeNumber(r.capacidad_con || 0),
          normalizeNumber(r.existencia_deta || 0),
          normalizeNumber(r.precio_sin_impu_1 || 0),
          normalizeNumber(r.precio_sin_impu_2 || 0),
          fechaVal
        ];
        values.push(...params);
        const ph = `(${new Array(params.length).fill(0).map(() => `$${idx++}`).join(',')})`;
        placeholders.push(ph);
      }
      const multiInsertQ = insertBase + '\nVALUES ' + placeholders.join(',');
      try {
        await client.query(multiInsertQ, values);
        inserted += chunk.length;
      } catch (ie) {
        // fallback to per-row insert/update
        if (ie && ie.code === '23505') {
          for (const r of chunk) {
            // per-row fallback path: prefer provided date param, fallback to row fecha_sistema
            let fechaVal = normalizeDateInv(date);
            if (!fechaVal) fechaVal = normalizeDateInv(r.fecha_sistema);
            if (!fechaVal) fechaVal = null;
            const params = [
              r.codigo || null,
              r.descripcion || null,
              normalizeNumber(r.costo_anterior || 0),
              normalizeNumber(r.costo_actual || 0),
              normalizeNumber(r.costo_fob || 0),
              normalizeNumber(r.principal || 0),
              normalizeNumber(r.capacidad_con || 0),
              normalizeNumber(r.existencia_deta || 0),
              normalizeNumber(r.precio_sin_impu_1 || 0),
              normalizeNumber(r.precio_sin_impu_2 || 0),
              fechaVal
            ];
            try {
              await client.query(insertQ, params);
              inserted += 1;
            } catch (ie2) {
              if (ie2 && ie2.code === '23505') {
                await client.query(updateQ, params);
                inserted += 1;
              } else {
                throw ie2;
              }
            }
          }
        } else {
          throw ie;
        }
      }
    }
    await client.query('COMMIT');
    await client.end();
    const insertEnd = Date.now();
    console.log('inventario import finished, inserted', inserted, 'of', rows.length, 'duration ms', insertEnd - insertStart);
    return res.status(200).json({ accepted: true, inserted, total: rows.length });
  } catch (err) {
    try { if (client) await client.query('ROLLBACK'); } catch (e) {}
    try { if (client) await client.end(); } catch (e) {}
    console.error('inventario import error', err && err.message ? err.message : err);
    return res.status(500).json({ error: err && err.message ? String(err.message) : 'internal' });
  }
});

// Clear (delete) all inventario_costos rows for a given date (dev/admin action)
app.post('/api/inventario/clear', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const { date } = req.body || {};
  if (!date) return res.status(400).json({ ok: false, error: 'date required' });
  const client = poolClient();
  try {
    await client.connect();
    const q = `DELETE FROM inventario_costos WHERE fecha_sistema::date = $1::date`;
    const r = await client.query(q, [date]);
    await client.end();
    return res.json({ ok: true, deleted: r.rowCount });
  } catch (err) {
    console.error('error clearing inventario for date', date, err && err.message ? err.message : err);
    try { await client.end(); } catch (e) {}
    return res.status(500).json({ ok: false, error: err && err.message ? String(err.message) : 'internal' });
  }
});

// Import ventas endpoint: accepts JSON { content: '...text...' }
app.post('/api/ventas/import', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const { content } = req.body || {};
  console.log('/api/ventas/import called - content length:', typeof content === 'string' ? content.length : 'n/a');
  if (typeof content === 'string') {
    console.log('ventas content preview:', content.slice(0, 500).replace(/\n/g, '\\n').slice(0,300));
  }
  if (!content) return res.status(400).json({ error: 'content required' });

  // parse as CSV or delimited file. Implement a CSV record extractor that respects
  // double-quotes and embedded newlines inside quoted fields, then split fields per record.
  const text = String(content);
  const parseCSVLine = (ln, sep = ',') => {
    const out = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < ln.length; i++) {
      const ch = ln[i];
      if (ch === '"') {
        // escaped quote
        if (inQuotes && i + 1 < ln.length && ln[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
        continue;
      }
      if (!inQuotes && ln.substr(i, sep.length) === sep) {
        out.push(cur.trim());
        cur = '';
        i += sep.length - 1;
        continue;
      }
      cur += ch;
    }
    out.push(cur.trim());
    return out;
  };

  // Split into records. Detect delimiter: prefer tab, pipe or comma for CSV-like content.
  // If none of those appear but the TXT looks column-aligned (multiple spaces), use a
  // space-based splitter (\s{2,}) which is common for fixed-width/space-aligned TXT files.
  const detectDelimiterFromContent = (txt) => {
    if (txt.indexOf('\t') !== -1) return '\t';
    if (txt.indexOf('|') !== -1) return '|';
    if (txt.indexOf(',') !== -1) return ',';
    // if many occurrences of two or more consecutive spaces, treat as space-aligned TXT
    const multiSpaceMatches = (txt.match(/\s{2,}/g) || []).length;
    if (multiSpaceMatches > 5) return /\s{2,}/; // heuristic
    // default to comma
    return ',';
  };
  const delim = detectDelimiterFromContent(text);

  // CSV-style parser that respects quoted fields and embedded newlines. Only used for
  // comma, tab or pipe delimiters. For space-aligned TXT (regex delimiter) we use a
  // simpler line-splitting + regex-based field split.
  const parseCSVRecords = (txt, sep = ',') => {
    if (sep instanceof RegExp) {
      // simple split by newline; assume fields are not quoted across lines for TXT
      return txt.split(/\r?\n/).map(l => l.replace(/\r$/,'').trim()).filter(l => l.length > 0);
    }
    const records = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < txt.length; i++) {
      const ch = txt[i];
      if (ch === '"') {
        // handle escaped quotes
        if (inQuotes && i + 1 < txt.length && txt[i + 1] === '"') {
          cur += '"';
          i++;
          continue;
        }
        inQuotes = !inQuotes;
        cur += ch;
        continue;
      }
      if (!inQuotes && ch === '\n') {
        // end of record
        if (cur.trim().length > 0) records.push(cur.replace(/\r$/,'').trim());
        cur = '';
        continue;
      }
      cur += ch;
    }
    if (cur.trim().length > 0) records.push(cur.replace(/\r$/,'').trim());
    return records;
  };

  const lines = parseCSVRecords(text, delim).filter(l => l && l.trim().length > 0);
  if (lines.length === 0) return res.status(400).json({ error: 'empty content' });

  const splitLine = (ln) => {
    let parts = [];
    if (delim instanceof RegExp) parts = ln.split(delim).map(s => s.trim());
    else parts = parseCSVLine(ln, delim);

    // normalize quoted fields: remove surrounding double-quotes and unescape doubled quotes
    parts = parts.map(p => {
      if (typeof p !== 'string') return p;
      let t = p.trim();
      if (t.length >= 2 && t[0] === '"' && t[t.length - 1] === '"') {
        t = t.slice(1, -1).replace(/""/g, '"');
      }
      return t;
    });
    return parts;
  };

  // expected ventas headers (common). Accept also the alternate field names the importer may provide
  // Common alternate names: tipo_operacion -> fdi_tipooperacion, tipo_uni -> fdi_unddetallada, bolivares -> fdi_preciodeventadcto, dolares -> fdi_montoimpuesto1dcto
  const expected = ['fdi_codigo','fdi_documento','fti_serie','tipo_operacion','fdi_fechaoperacion','fdi_cantidad','fdi_unddescarga','tipo_uni','bolivares','fti_factorreferencia','dolares'];

  // map possible header names (lowercased, underscored or not) to canonical column names used by the DB/staging
  const headerNameMap = {
    'tipo_operacion': 'fdi_tipooperacion',
    'tipooperacion': 'fdi_tipooperacion',
    'fdi_tipooperacion': 'fdi_tipooperacion',
    'tipo_uni': 'fdi_unddetallada',
    'tipouni': 'fdi_unddetallada',
    'fdi_unddetallada': 'fdi_unddetallada',
    'bolivares': 'fdi_preciodeventadcto',
    'bolivar': 'fdi_preciodeventadcto',
    'fdi_preciodeventadcto': 'fdi_preciodeventadcto',
    'dolares': 'fdi_montoimpuesto1dcto',
    'dolar': 'fdi_montoimpuesto1dcto',
    'fdi_montoimpuesto1dcto': 'fdi_montoimpuesto1dcto',
    'fti_factorreferencia': 'fti_factorreferencia',
    'fti_factor': 'fti_factorreferencia'
  };

  const firstParts = splitLine(lines[0]).map(p => p.trim());
  let hasHeader = false;
  const header = [];
  const headerCanonical = [];
  if (firstParts.length > 0) {
    const joined = firstParts.join(' ').toLowerCase();
    // heuristics: if the first line contains several expected keywords, treat as header
    if (expected.some(h => joined.includes(h) || joined.includes(h.replace(/_/g,'')) || joined.includes(h.replace(/_/g,'')))) {
      hasHeader = true;
      header.push(...firstParts.map(p => p.toLowerCase()));
      // build canonical mapping for header names
      for (const h of header) {
        const clean = h.replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '').toLowerCase();
        headerCanonical.push(headerNameMap[clean] || headerNameMap[h] || clean);
      }
    }
  }

  const dataLines = hasHeader ? lines.slice(1) : lines;
  const rows = [];
  for (const ln of dataLines) {
    const parts = splitLine(ln).map(p => p.trim());
    if (parts.length === 0) continue;
    // if no header, try to map by position according to expected
    const row = {};
    if (hasHeader) {
      for (let i = 0; i < parts.length; i++) {
        const raw = header[i] || `col${i}`;
        const canonical = headerCanonical[i] || raw;
        row[canonical] = parts[i];
      }
    } else {
      for (let i = 0; i < Math.min(parts.length, expected.length); i++) {
        const raw = expected[i];
        const canonical = headerNameMap[raw] || raw;
        row[canonical] = parts[i];
      }
    }
    // coerce numeric fields
    row.fdi_cantidad = Number((row.fdi_cantidad || 0) || 0);
    row.fdi_preciodeventadcto = Number((row.fdi_preciodeventadcto || 0) || 0);
    row.fdi_montoimpuesto1dcto = Number((row.fdi_montoimpuesto1dcto || 0) || 0);
    rows.push(row);
  }

  if (rows.length === 0) return res.status(400).json({ error: 'no rows parsed' });

  // background job insertion into ventas or table "58"
  const jobId = `${Date.now()}-v-${Math.floor(Math.random() * 100000)}`;
  importJobs.set(jobId, { status: 'queued', inserted: 0, total: rows.length, startedAt: null, finishedAt: null, error: null });

  // launch background import (kept the same) so UI can still use async flow.
  (async () => {
    const job = importJobs.get(jobId);
    let client = null;
    try {
      job.status = 'running';
      job.startedAt = Date.now();
      client = poolClient();
      await client.connect();
      // avoid unhandled 'error' events from pg Client crashing the process
      client.on('error', (cErr) => {
        console.error('pg client error event (ventas import)', cErr && cErr.message ? cErr.message : cErr);
      });
      await client.query('BEGIN');
      const insertStart = Date.now();
      // choose table: default 'ventas' (principal), or 'ventas58' if client requested target=58 or ventas58
      const requestedTarget = req.body && req.body.target ? String(req.body.target) : '';
      const allowedTargets = {
        'principal': 'ventas',
        'ventas': 'ventas',
        '58': 'ventas58',
        'ventas58': 'ventas58'
      };
      const chosenTable = allowedTargets[requestedTarget] || 'ventas';
  const insertBase = `INSERT INTO ${chosenTable} (fdi_codigo,fdi_documento,fti_serie,fdi_tipooperacion,fdi_fechaoperacion,fdi_cantidad,fdi_unddescarga,fdi_unddetallada,fdi_preciodeventadcto,fdi_montoimpuesto1dcto,fti_factorreferencia)`;
      const chunkSize = 250;
      const chunkArray = (arr, size) => {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
      };
      // safer flow: insert parsed rows into a staging table (all TEXT) with job_id
      const stagingCreate = `CREATE TABLE IF NOT EXISTS ventas_staging (
        job_id text,
        fdi_codigo text,
        fdi_documento text,
        fti_serie text,
        fdi_tipooperacion text,
        fdi_fechaoperacion text,
        fdi_cantidad text,
        fdi_unddescarga text,
        fdi_unddetallada text,
        fdi_preciodeventadcto text,
        fdi_montoimpuesto1dcto text,
        fti_factorreferencia text
      )`;
      await client.query(stagingCreate);

      // insert parsed rows into staging in chunks
      const rowChunks = chunkArray(rows, chunkSize);
      let staged = 0;
      // helper to sanitize numeric-looking strings: remove thousands separators, normalize comma decimals
      const sanitizeNumberString = (s) => {
        if (s === null || s === undefined) return '';
        let t = String(s).trim();
        if (t.length === 0) return '';
        // remove spaces
        t = t.replace(/\s+/g, '');
        // replace comma decimal with dot
        t = t.replace(/,/g, '.');
        // if there are multiple dots, keep only the last as decimal separator (collapse thousands dots)
        const parts = t.split('.');
        if (parts.length > 2) {
          const last = parts.pop();
          t = parts.join('') + '.' + last;
        }
        // remove any characters except digits, dot and minus
        t = t.replace(/[^0-9.\-]/g, '');
        return t;
      };

      const normalizeDate = (s) => {
        if (!s && s !== 0) return '';
        let t = String(s).trim();
        if (/^\d{4}-\d{2}-\d{2}$/.test(t)) return t;
        // try dd/mm/yyyy or mm/dd/yyyy detection -> attempt Date parse
        const parsed = Date.parse(t);
        if (!Number.isNaN(parsed)) {
          const d = new Date(parsed);
          const yyyy = d.getFullYear();
          const mm = String(d.getMonth() + 1).padStart(2, '0');
          const dd = String(d.getDate()).padStart(2, '0');
          return `${yyyy}-${mm}-${dd}`;
        }
        return '';
      };

      const normalizeBooleanLike = (s) => {
        // keep this helper limited to explicit boolean-like tokens only
        if (s === null || s === undefined) return '';
        const t = String(s).trim().toLowerCase();
        if (t === '') return '';
        if (/^(1|true|t|yes|y)$/i.test(t)) return 'true';
        if (/^(0|false|f|no|n)$/i.test(t)) return 'false';
        return '';
      };

      for (const chunk of rowChunks) {
        const values = [];
        const placeholders = [];
        let idx = 1;
        for (const r of chunk) {
          // normalize fields before inserting into staging so SQL casts succeed reliably
          const fdi_codigo = String(r.fdi_codigo || '').trim();
          const fdi_documento = String(r.fdi_documento || '').trim();
          const fti_serie = String(r.fti_serie || '').trim();
          const fdi_tipooperacion = String(r.fdi_tipooperacion || '').trim();
          const fdi_fechaoperacion = normalizeDate(r.fdi_fechaoperacion || '');
          const fdi_cantidad = sanitizeNumberString(r.fdi_cantidad == null ? '' : r.fdi_cantidad);
          const fdi_unddescarga = sanitizeNumberString(r.fdi_unddescarga == null ? '' : r.fdi_unddescarga);
          // preserve textual values like "UNIDAD" / "DETALLADO" as-is
          const fdi_unddetallada = String(r.fdi_unddetallada == null ? '' : r.fdi_unddetallada).trim();
          const fdi_preciodeventadcto = sanitizeNumberString(r.fdi_preciodeventadcto == null ? '' : r.fdi_preciodeventadcto);
          const fdi_montoimpuesto1dcto = sanitizeNumberString(r.fdi_montoimpuesto1dcto == null ? '' : r.fdi_montoimpuesto1dcto);
          const fti_factorreferencia = sanitizeNumberString(r.fti_factorreferencia == null ? '' : r.fti_factorreferencia);

          const params = [jobId, fdi_codigo, fdi_documento, fti_serie, fdi_tipooperacion, fdi_fechaoperacion, fdi_cantidad, fdi_unddescarga, fdi_unddetallada, fdi_preciodeventadcto, fdi_montoimpuesto1dcto, fti_factorreferencia];
          values.push(...params);
          const ph = `(${new Array(params.length).fill(0).map(() => `$${idx++}`).join(',')})`;
          placeholders.push(ph);
        }
        const insertStagingQ = `INSERT INTO ventas_staging (job_id,fdi_codigo,fdi_documento,fti_serie,fdi_tipooperacion,fdi_fechaoperacion,fdi_cantidad,fdi_unddescarga,fdi_unddetallada,fdi_preciodeventadcto,fdi_montoimpuesto1dcto,fti_factorreferencia) VALUES ` + placeholders.join(',');
        await client.query(insertStagingQ, values);
        staged += chunk.length;
        job.inserted = staged;
      }

      // now convert and insert into chosenTable using SQL conversion/mapping
      const finalInsert = `
        INSERT INTO ${chosenTable} (
          fdi_codigo,
          fdi_documento,
          fti_serie,
          fdi_tipooperacion,
          fdi_fechaoperacion,
          fdi_cantidad,
          fdi_unddescarga,
          fdi_unddetallada,
          fdi_unddetallada_text,
          fdi_preciodeventadcto,
          fdi_montoimpuesto1dcto,
          fti_factorreferencia,
          tipo_operacion,
          tipo_uni,
          bolivares,
          dolares
        )
        SELECT
          fdi_codigo,
          fdi_documento,
          fti_serie,
          CASE
            WHEN lower(fdi_tipooperacion) = 'factura' THEN 1
            WHEN lower(fdi_tipooperacion) = 'boleta' THEN 2
            WHEN lower(fdi_tipooperacion) = 'nota' THEN 3
            WHEN lower(fdi_tipooperacion) = 'remision' THEN 4
            WHEN fdi_tipooperacion ~ '^\\d+$' THEN (fdi_tipooperacion)::int
            ELSE NULL
          END,
          CASE WHEN fdi_fechaoperacion ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN fdi_fechaoperacion::date ELSE NULL END,
          CASE WHEN fdi_cantidad ~ '^[-+]?[0-9]+(\\.[0-9]+)?$' THEN fdi_cantidad::numeric ELSE NULL END,
          CASE WHEN fdi_unddescarga ~ '^[-+]?[0-9]+$' THEN fdi_unddescarga::int ELSE NULL END,
          -- map textual token to boolean for the existing boolean column, and also keep original text in a *_text column
          CASE
            WHEN lower(fdi_unddetallada) IN ('detallado','d','true','1','si','sí','s') THEN true
            WHEN lower(fdi_unddetallada) IN ('unidad','u','false','0','no','n') THEN false
            WHEN fdi_unddetallada ~ '^\\s*[01]\s*$' THEN (trim(fdi_unddetallada)::int = 1)
            ELSE NULL
          END AS fdi_unddetallada,
          fdi_unddetallada AS fdi_unddetallada_text,
          CASE WHEN fdi_preciodeventadcto ~ '^[-+]?[0-9]+(\\.[0-9]+)?$' THEN fdi_preciodeventadcto::numeric ELSE NULL END,
          CASE WHEN fdi_montoimpuesto1dcto ~ '^[-+]?[0-9]+(\\.[0-9]+)?$' THEN fdi_montoimpuesto1dcto::numeric ELSE NULL END,
          CASE WHEN fti_factorreferencia ~ '^[-+]?[0-9]+(\\.[0-9]+)?$' THEN fti_factorreferencia::numeric ELSE NULL END,
          -- also populate importer-friendly alternate columns from the staging raw values
          fdi_tipooperacion AS tipo_operacion,
          fdi_unddetallada AS tipo_uni,
          CASE WHEN fdi_preciodeventadcto ~ '^[-+]?[0-9]+(\\.[0-9]+)?$' THEN fdi_preciodeventadcto::numeric ELSE NULL END AS bolivares,
          CASE WHEN fdi_montoimpuesto1dcto ~ '^[-+]?[0-9]+(\\.[0-9]+)?$' THEN fdi_montoimpuesto1dcto::numeric ELSE NULL END AS dolares
        FROM ventas_staging WHERE job_id = $1
      `;
      // log a sample of staging rows to help debug formatting issues
      try {
        const sample = await client.query('SELECT * FROM ventas_staging WHERE job_id = $1 LIMIT 5', [jobId]);
        console.log('ventas_staging sample for job', jobId, JSON.stringify(sample.rows, null, 2));
      } catch (e) {
        console.error('error fetching staging sample', e && e.message ? e.message : e);
      }

      // Create a backup TEXT column to store the original token exactly as provided in the TXT
      const ensureBackupTextColumn = async (table) => {
        try {
          const addQ = `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS fdi_unddetallada_text text`;
          await client.query(addQ);
        } catch (e) {
          console.error('ensureBackupTextColumn error for', table, e && e.message ? e.message : e);
        }
      };

      // Ensure alternative columns exist to match importer-provided names
      const ensureAltColumns = async (table) => {
        try {
          const q1 = `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS tipo_operacion text`;
          const q2 = `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS tipo_uni text`;
          const q3 = `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS bolivares numeric`;
          const q4 = `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS dolares numeric`;
          await client.query(q1);
          await client.query(q2);
          await client.query(q3);
          await client.query(q4);
        } catch (e) {
          console.error('ensureAltColumns error for', table, e && e.message ? e.message : e);
        }
      };

      try {
  await ensureBackupTextColumn(chosenTable);
  if (chosenTable !== 'ventas') await ensureBackupTextColumn('ventas');
  await ensureAltColumns(chosenTable);
  if (chosenTable !== 'ventas') await ensureAltColumns('ventas');
      } catch (e) {
        console.error('error ensuring backup text column', e && e.message ? e.message : e);
      }

      // try running the final insert; if the chosen table does not exist, fall back to 'ventas'
      let rFinal = null;
      try {
        console.log('executing finalInsert SQL for job', jobId, finalInsert);
        rFinal = await client.query(finalInsert, [jobId]);
      } catch (finalErr) {
        console.error('finalInsert error for table', chosenTable, finalErr && finalErr.message ? finalErr.message : finalErr);
        // undefined_table (42P01) -> try fallback to main 'ventas' table if different
        if (finalErr && finalErr.code === '42P01' && chosenTable !== 'ventas') {
          try {
            console.log(`Falling back to insert into ventas for job ${jobId}`);
            const fallbackInsert = finalInsert.replace(new RegExp("INSERT INTO "+chosenTable, 'g'), 'INSERT INTO ventas')
            rFinal = await client.query(fallbackInsert, [jobId]);
          } catch (fbErr) {
            console.error('fallback finalInsert also failed', fbErr && fbErr.message ? fbErr.message : fbErr);
            throw fbErr;
          }
        } else {
          throw finalErr;
        }
      }

      console.log('finalInsert affected rows for job', jobId, rFinal && rFinal.rowCount);
      // backfill importer-friendly columns in case the INSERT didn't populate them (defensive)
      try {
        const backfillQ = `
          UPDATE ${chosenTable}
          SET
            tipo_operacion = COALESCE(tipo_operacion, (CASE WHEN fdi_tipooperacion IS NOT NULL THEN fdi_tipooperacion::text ELSE NULL END)),
            tipo_uni = COALESCE(tipo_uni, fdi_unddetallada_text, (CASE WHEN fdi_unddetallada IS NOT NULL THEN (CASE WHEN fdi_unddetallada THEN 'true' ELSE 'false' END) ELSE NULL END)),
            bolivares = COALESCE(bolivares, (CASE WHEN fdi_preciodeventadcto IS NOT NULL THEN fdi_preciodeventadcto::numeric ELSE NULL END)),
            dolares = COALESCE(dolares, (CASE WHEN fdi_montoimpuesto1dcto IS NOT NULL THEN fdi_montoimpuesto1dcto::numeric ELSE NULL END))
          WHERE (tipo_operacion IS NULL OR tipo_uni IS NULL OR bolivares IS NULL OR dolares IS NULL)
            AND (fdi_preciodeventadcto IS NOT NULL OR fdi_montoimpuesto1dcto IS NOT NULL OR fdi_tipooperacion IS NOT NULL OR fdi_unddetallada IS NOT NULL)
        `;
        console.log('running backfill for', chosenTable);
        await client.query(backfillQ);
      } catch (bfErr) {
        console.error('backfill update error for', chosenTable, bfErr && bfErr.message ? bfErr.message : bfErr);
      }

      // delete staging rows for this job
      try {
        await client.query('DELETE FROM ventas_staging WHERE job_id = $1', [jobId]);
      } catch (delErr) {
        console.error('error deleting staging rows for job', jobId, delErr && delErr.message ? delErr.message : delErr);
      }

      await client.query('COMMIT');
      job.status = 'done';
      job.finishedAt = Date.now();
      // prefer the actual number of rows inserted (rFinal.rowCount) when available
      try {
        job.inserted = (rFinal && typeof rFinal.rowCount === 'number') ? rFinal.rowCount : staged;
      } catch (e) {
        job.inserted = staged;
      }
      try { await client.end(); } catch (e) {}
      const insertEnd = Date.now();
      console.log('ventas import job', jobId, 'staged', staged, 'duration ms', insertEnd - insertStart);
    } catch (err) {
      console.error('ventas import error', err);
      try { job.status = 'error'; job.error = err && err.message ? String(err.message) : String(err); } catch (e) {}
      // attempt to rollback if in a transaction and close client
      try {
        if (client) await client.query('ROLLBACK');
      } catch (rbErr) {
        console.error('rollback error', rbErr && rbErr.message ? rbErr.message : rbErr);
      }
      try { if (client) await client.end(); } catch (endErr) { console.error('client end error', endErr && endErr.message ? endErr.message : endErr); }
    }
  })();

  // If client requested synchronous import (no jobId wanted), wait here until job finishes
  // Use req.body.sync === true to trigger synchronous behavior. Timeout after 2 minutes.
  if (req.body && req.body.sync === true) {
    const waitFor = async (id, timeoutMs = 120000) => {
      const start = Date.now();
      while (Date.now() - start < timeoutMs) {
        const j = importJobs.get(id);
        if (!j) return { error: 'job disappeared' };
        if (j.status === 'done' || j.status === 'error') return j;
        // sleep 500ms
        await new Promise(r => setTimeout(r, 500));
      }
      return { error: 'timeout waiting for import job' };
    };

    try {
      const result = await waitFor(jobId, 120000);
      if (result && result.status === 'done') {
        return res.status(200).json({ accepted: true, status: 'done', inserted: result.inserted, total: result.total });
      }
      // error or timeout
      return res.status(500).json({ accepted: false, error: result && result.error ? result.error : (result && result.error) || (result && result.status) || 'unknown' });
    } catch (e) {
      return res.status(500).json({ accepted: false, error: String(e && e.message ? e.message : e) });
    }
  }

  // default async response with jobId
  res.status(202).json({ accepted: true, jobId, rows: rows.length });
});

// Reporte: costos de ventas (CSV export)
app.get('/api/report/costos-ventas', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const year = Number(req.query.year) || new Date().getFullYear();
  const month = Number(req.query.month) || (new Date().getMonth() + 1);
  const client = poolClient();
  try {
    await client.connect();
    // Use lateral join to pick matching inventario_costos row for the venta date.
    // Note: avoid an extra LEFT JOIN by code-only which can duplicate rows; prefer the lateral row (ici).
    const requestedTarget = req.query && req.query.target ? String(req.query.target) : '';
    const allowedTargets = { 'principal': 'ventas', 'ventas': 'ventas', '58': 'ventas58', 'ventas58': 'ventas58' };
    const chosenTable = allowedTargets[requestedTarget] || 'ventas';

    const q = `SELECT
    CASE WHEN v.fdi_tipooperacion = 1 THEN 'FA' ELSE 'NC' END AS tipo_documento,
    v.fdi_documento AS documento,
    v.fti_serie AS serie,
    v.fdi_fechaoperacion AS fecha,
    v.fdi_codigo AS co_prod,
    ic.descripcion,
    v.fdi_cantidad AS cantidad,
    ic.capacidad_con AS capacidad,
    v.tipo_uni AS tipo_uni,
  -- Costo Actual
  (
    SELECT
      (CASE
        WHEN v.fdi_unddetallada <> TRUE
        THEN ici.costo_actual * v.fdi_cantidad
        ELSE (ici.costo_actual / ici.capacidad_con) * v.fdi_cantidad
      END)
    FROM
      inventario_costos ici
    WHERE
      ici.codigo = v.fdi_codigo
      AND ici.fecha_sistema = v.fdi_fechaoperacion
    GROUP BY
      ici.fecha_sistema, ici.costo_actual, ici.capacidad_con
  ) AS costo_actual,

  -- Costo Anterior
  (
    SELECT
      (CASE
        WHEN v.fdi_unddetallada <> TRUE
        THEN ici.costo_anterior * v.fdi_cantidad
        ELSE (ici.costo_anterior / ici.capacidad_con) * v.fdi_cantidad
      END)
    FROM
      inventario_costos ici
    WHERE
      ici.codigo = v.fdi_codigo
      AND ici.fecha_sistema = v.fdi_fechaoperacion
    GROUP BY
      ici.fecha_sistema, ici.costo_anterior, ici.capacidad_con
  ) AS costo_anterior,

  (
    SELECT
      (CASE
        WHEN v.fdi_unddetallada <> TRUE
        THEN ici.costo_fob * v.fdi_cantidad
        ELSE (ici.costo_fob / ici.capacidad_con) * v.fdi_cantidad
      END)
    FROM
      inventario_costos ici
    WHERE
      ici.codigo = v.fdi_codigo
      AND ici.fecha_sistema = v.fdi_fechaoperacion
    GROUP BY
      ici.fecha_sistema, ici.costo_fob, ici.capacidad_con
  ) AS costo_promedio,

  v.bolivares,
  v.fti_factorreferencia AS factor,
  v.dolares

FROM ${chosenTable} v
LEFT JOIN LATERAL (
  SELECT ic2.* FROM inventario_costos ic2
  WHERE ic2.codigo = v.fdi_codigo AND ic2.fecha_sistema = v.fdi_fechaoperacion
  LIMIT 1
) ic ON true
ORDER BY
  v.fdi_fechaoperacion ASC;`;

  const r = await client.query(q);

    // build XLSX using exceljs
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Costos de Ventas');

    const cols = [
      { header: 'tipo_documento', key: 'tipo_documento', width: 12 },
      { header: 'documento', key: 'documento', width: 20 },
      { header: 'serie', key: 'serie', width: 12 },
      { header: 'fecha', key: 'fecha', width: 15 },
      { header: 'co_prod', key: 'co_prod', width: 15 },
      { header: 'descripcion', key: 'descripcion', width: 40 },
      { header: 'cantidad', key: 'cantidad', width: 12 },
      { header: 'capacidad', key: 'capacidad', width: 12 },
      { header: 'tipo_uni', key: 'tipo_uni', width: 15 },
      { header: 'costo_actual', key: 'costo_actual', width: 15 },
      { header: 'costo_anterior', key: 'costo_anterior', width: 15 },
      { header: 'costo_promedio', key: 'costo_promedio', width: 15 },
      { header: 'bolivares', key: 'bolivares', width: 15 },
      { header: 'factor', key: 'factor', width: 12 },
      { header: 'dolares', key: 'dolares', width: 15 }
    ];

    sheet.columns = cols;
    // header style
    sheet.getRow(1).font = { bold: true };

    // add rows (convert fecha to Date objects so Excel can format properly)
    for (const row of r.rows) {
      const fechaVal = row.fecha ? (row.fecha instanceof Date ? row.fecha : new Date(row.fecha)) : null;
      sheet.addRow({
        tipo_documento: row.tipo_documento || '',
        documento: row.documento,
        serie: row.serie,
        fecha: fechaVal,
        co_prod: row.co_prod,
        descripcion: row.descripcion,
        cantidad: typeof row.cantidad === 'number' ? row.cantidad : Number(row.cantidad) || 0,
        capacidad: typeof row.capacidad === 'number' ? row.capacidad : Number(row.capacidad) || 0,
        tipo_uni: row.tipo_uni,
        costo_actual: row.costo_actual == null ? null : Number(row.costo_actual),
        costo_anterior: row.costo_anterior == null ? null : Number(row.costo_anterior),
        costo_promedio: row.costo_promedio == null ? null : Number(row.costo_promedio),
        bolivares: row.bolivares == null ? null : Number(row.bolivares),
        factor: row.factor == null ? null : Number(row.factor),
        dolares: row.dolares == null ? null : Number(row.dolares)
      });
    }

    // apply number/date formats and add totals row if there are data rows
  const numericKeys = ['cantidad','capacidad','costo_actual','costo_anterior','costo_promedio','bolivares','factor','dolares'];
    // helper to convert column index to letter (1 -> A)
    const colLetter = (n) => {
      let s = '';
      while (n > 0) {
        let m = (n - 1) % 26;
        s = String.fromCharCode(65 + m) + s;
        n = Math.floor((n - 1) / 26);
      }
      return s;
    };

    // set formats per column key
    sheet.columns.forEach((c, idx) => {
      if (!c || !c.key) return;
      if (c.key === 'fecha') {
        // date format
        c.numFmt = 'yyyy-mm-dd';
      }
      if (numericKeys.includes(c.key)) {
        c.numFmt = '#,##0.00';
        c.alignment = { horizontal: 'right' };
      }
    });

    // add totals row using formulas if there are data rows
    const dataStartRow = 2;
    const dataEndRow = sheet.rowCount;
    if (dataEndRow >= dataStartRow) {
      const totalRow = {};
      totalRow.documento = 'TOTAL';
      sheet.columns.forEach((c, idx) => {
        if (!c || !c.key) return;
        const colIndex = idx + 1;
        const letter = colLetter(colIndex);
        if (numericKeys.includes(c.key)) {
          totalRow[c.key] = { formula: `SUM(${letter}${dataStartRow}:${letter}${dataEndRow})` };
        }
      });
      sheet.addRow(totalRow);
    }

  const buf = await workbook.xlsx.writeBuffer();
    const name = `costos_ventas_${year}_${String(month).padStart(2,'0')}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
    res.send(Buffer.from(buf));
    await client.end();
  } catch (err) {
    console.error('error generating costos-ventas report', err && err.message ? err.message : err);
    try { await client.end(); } catch (e) {}
    res.status(500).json({ error: err && err.message ? String(err.message) : 'internal' });
  }
});

// JSON paginated preview for Costos de Ventas
app.get('/api/report/costos-ventas/data', async (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const year = Number(req.query.year) || new Date().getFullYear();
  const month = Number(req.query.month) || (new Date().getMonth() + 1);
  const page = Math.max(1, Number(req.query.page) || 1);
  const pageSize = Math.max(1, Math.min(1000, Number(req.query.pageSize) || 25));
  const offset = (page - 1) * pageSize;
  const client = poolClient();
  try {
    await client.connect();
    const requestedTarget = req.query && req.query.target ? String(req.query.target) : '';
    const allowedTargets = { 'principal': 'ventas', 'ventas': 'ventas', '58': 'ventas58', 'ventas58': 'ventas58' };
    const chosenTable = allowedTargets[requestedTarget] || 'ventas';

    // Use the exact SELECT the user requested for preview; no year/month filtering so result matches their SELECT exactly.
    const baseQ = `FROM ${chosenTable} v
      INNER JOIN inventario_costos ic ON ic.codigo = v.fdi_codigo`;

  const dataQ = `SELECT
    CASE WHEN v.fdi_tipooperacion = 1 THEN 'FA' ELSE 'NC' END AS tipo_documento,
    v.fdi_documento AS documento,
    v.fti_serie AS serie,
    v.fdi_fechaoperacion AS fecha,
    v.fdi_codigo AS co_prod,
    ic.descripcion,
    v.fdi_cantidad AS cantidad,
    ic.capacidad_con AS capacidad,
    v.tipo_uni AS tipo_uni,
    -- Costo Actual
    (
        SELECT
            (CASE
                WHEN v.fdi_unddetallada <> TRUE
                THEN ici.costo_actual * v.fdi_cantidad
                ELSE (ici.costo_actual / ici.capacidad_con) * v.fdi_cantidad
            END)
        FROM
            inventario_costos ici
        WHERE
            ici.codigo = v.fdi_codigo
            AND ici.fecha_sistema = v.fdi_fechaoperacion
        GROUP BY
            ici.fecha_sistema, ici.costo_actual, ici.capacidad_con
    ) AS costo_actual,

    -- Costo Anterior
    (
        SELECT
            (CASE
                WHEN v.fdi_unddetallada <> TRUE
                THEN ici.costo_anterior * v.fdi_cantidad
                ELSE (ici.costo_anterior / ici.capacidad_con) * v.fdi_cantidad
            END)
        FROM
            inventario_costos ici
        WHERE
            ici.codigo = v.fdi_codigo
            AND ici.fecha_sistema = v.fdi_fechaoperacion
        GROUP BY
            ici.fecha_sistema, ici.costo_anterior, ici.capacidad_con
    ) AS costo_anterior,

    (
        SELECT
            (CASE
                WHEN v.fdi_unddetallada <> TRUE
                THEN ici.costo_fob * v.fdi_cantidad
                ELSE (ici.costo_fob / ici.capacidad_con) * v.fdi_cantidad
            END)
        FROM
            inventario_costos ici
        WHERE
            ici.codigo = v.fdi_codigo
            AND ici.fecha_sistema = v.fdi_fechaoperacion
        GROUP BY
            ici.fecha_sistema, ici.costo_fob, ici.capacidad_con
    ) AS costo_promedio,

    v.bolivares,
    v.fti_factorreferencia AS factor,
    v.dolares
  FROM ${chosenTable} v
  LEFT JOIN LATERAL (
    SELECT ic2.* FROM inventario_costos ic2
    WHERE ic2.codigo = v.fdi_codigo AND ic2.fecha_sistema = v.fdi_fechaoperacion
    LIMIT 1
  ) ic ON true
  ORDER BY v.fdi_fechaoperacion ASC
  LIMIT $1 OFFSET $2`;

  const countQ = `SELECT COUNT(*) AS total FROM ${chosenTable} v`;

  const dataRes = await client.query(dataQ, [pageSize, offset]);
  const countRes = await client.query(countQ);
    const total = Number(countRes.rows[0] && countRes.rows[0].total) || 0;

    await client.end();
    res.json({ rows: dataRes.rows, total, page, pageSize });
  } catch (err) {
    console.error('error fetching costos-ventas data', err && err.message ? err.message : err);
    try { await client.end(); } catch (e) {}
    res.status(500).json({ error: err && err.message ? String(err.message) : 'internal' });
  }
});

// status endpoint for background import jobs
app.get('/api/inventario/import/status/:jobId', (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const jobId = req.params.jobId;
  if (!jobId) return res.status(400).json({ error: 'jobId required' });
  const job = importJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

// generic import status endpoint (ventas or inventario)
app.get('/api/import/status/:jobId', (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no autorizado' });
  const jobId = req.params.jobId;
  if (!jobId) return res.status(400).json({ error: 'jobId required' });
  const job = importJobs.get(jobId);
  if (!job) return res.status(404).json({ error: 'job not found' });
  res.json(job);
});

// Login endpoint: accept username/password and return a JWT for clients
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok: false, error: 'username and password required' });
  if (username === DEV_USERNAME && password === DEV_PASSWORD) {
    try {
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '8h' });
      return res.json({ ok: true, token, username });
    } catch (e) {
      console.error('error signing jwt', e && e.message ? e.message : e);
      return res.status(500).json({ ok: false, error: 'token_error' });
    }
  }
  return res.status(401).json({ ok: false, error: 'invalid credentials' });
});

// Validate token and return current user info
app.get('/api/me', (req, res) => {
  const sess = getSessionFromReq(req);
  if (!sess) return res.status(401).json({ ok: false, error: 'no token or invalid token' });
  return res.json({ ok: true, username: sess.username, createdAt: sess.createdAt });
});

// Logout: invalidate token
app.post('/api/logout', (req, res) => {
  // Stateless JWT: server cannot invalidate tokens without maintaining a blacklist.
  // For convenience, accept logout and tell client to discard token.
  return res.json({ ok: true, message: 'logout: discard the token on client side' });
});

// Serve static frontend if compiled `dist/` exists (useful for Docker deployment)
try {
  const distPath = path.join(__dirname, '..', 'dist');
  const indexFile = path.join(distPath, 'index.html');
  if (fs.existsSync(indexFile)) {
    app.use(express.static(distPath));
    // Any non-API route should serve index.html (SPA fallback)
    app.get('*', (req, res, next) => {
      if (req.path && req.path.startsWith('/api')) return next();
      res.sendFile(indexFile);
    });
    console.log('Serving static frontend from', distPath);
  }
} catch (e) {
  console.warn('Could not enable static file serving:', e && e.message ? e.message : e);
}

// If no frontend is present, provide a small root route to guide users.
app.get('/', (req, res) => {
  // prefer docs if available
  try {
    return res.redirect('/api/docs/');
  } catch (e) {
    return res.json({ ok: true, message: 'API is running', endpoints: ['/api/health','/api/docs'] });
  }
});

// Start the HTTP listener only when executed as a standalone script. When this
// module is required (for example by a serverless wrapper), export the `app`
// object so the wrapper can handle requests.
if (require.main === module) {
  const port = parseInt(APP_PORT, 10) || 3001;
  app.listen(port, () => {
    console.log(`API server listening on http://localhost:${port}`);
  });
} else {
  module.exports = app;
}

// Global error handler to return JSON on too-large payloads or other errors
app.use((err, req, res, next) => {
  if (!err) return next();
  // body-parser / express reports entity too large via status 413 or type 'entity.too.large'
  try {
    if (err.type === 'entity.too.large' || err.status === 413) {
      return res.status(413).json({ error: 'Payload too large' });
    }
  } catch (e) {
    // fall through
  }
  console.error('Unhandled error in API server:', err && err.stack ? err.stack : String(err));
  res.status(500).json({ error: err && err.message ? String(err.message) : 'Internal server error' });
});
