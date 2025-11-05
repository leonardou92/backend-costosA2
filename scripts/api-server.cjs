#!/usr/bin/env node
/* Simple API server exposing DB-backed endpoints for the frontend
   - GET /api/health
   - GET /api/ping
   - GET /api/dbtest
   The server is intended to run as a standalone backend (listen on PORT or API_PORT)
*/
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

dotenv.config();
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  const msg = 'DATABASE_URL not set in environment';
  if (require.main === module) {
    console.warn('[dev] ' + msg + ' — starting server in degraded mode');
  } else {
    console.warn(msg);
  }
}

try {
  const dbInfo = {};
  if (DATABASE_URL) {
    try {
      const u = new URL(DATABASE_URL);
      dbInfo.host = u.hostname;
      dbInfo.port = u.port || (u.protocol && (u.protocol.indexOf('postgres') !== -1) ? '5432' : '');
      dbInfo.database = u.pathname ? u.pathname.replace(/^\//, '') : '';
      dbInfo.protocol = u.protocol ? u.protocol.replace(':', '') : '';
    } catch (e) {
      try {
        const m = String(DATABASE_URL).match(/host=([^\s]+)/);
        if (m && m[1]) dbInfo.host = m[1];
      } catch (ee) {}
    }
  }
  console.log('api-server loaded', { env_database_present: !!DATABASE_URL, node_env: process.env.NODE_ENV || 'not-set', db: dbInfo });
} catch (e) {}

const app = express();
// Support configuring CORS origin via VITE_API_URL (used by frontend) or FRONTEND_ORIGIN
const FRONTEND_ORIGIN = process.env.VITE_API_URL || process.env.FRONTEND_ORIGIN || null;
const corsOptions = FRONTEND_ORIGIN ? { origin: FRONTEND_ORIGIN } : undefined;
app.use(cors(corsOptions));
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ limit: '20mb', extended: true }));

// Centralized Neon client (serverless-friendly). See scripts/neon-client.fixed.cjs
const { getPool, poolClient, testConnection } = require('./neon-client.fixed.cjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
if (!process.env.JWT_SECRET) {
  console.warn('Warning: JWT_SECRET not set in environment; using fallback dev secret. Set JWT_SECRET in production.');
}

const getSessionFromReq = (req) => {
  try {
    const auth = req.headers && (req.headers.authorization || req.headers.Authorization);
    if (!auth) return null;
    const parts = String(auth).split(' ');
    const token = parts.length === 2 && parts[0].toLowerCase() === 'bearer' ? parts[1] : parts[0];
    if (!token) return null;
    const payload = jwt.verify(token, JWT_SECRET);
    if (!payload || !payload.username) return null;
    return { username: payload.username, createdAt: payload.iat ? payload.iat * 1000 : Date.now() };
  } catch (e) {
    return null;
  }
};

// Middleware para requerir autenticación JWT
const requireAuth = (req, res, next) => {
  const session = getSessionFromReq(req);
  if (!session) {
    return res.status(401).json({ ok: false, error: 'unauthorized', message: 'Token JWT requerido en header Authorization' });
  }
  req.session = session;
  next();
};

app.get('/api/health', (req, res) => {
  res.json({ ok: true, healthy: true, uptime: process.uptime(), env_database: !!DATABASE_URL, now: Date.now() });
});

app.get('/api/ping', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), env_database: !!DATABASE_URL });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // Para demo: usuario fijo
  if (username === 'admin' && password === 'admin') {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ ok: true, token, message: 'Login exitoso' });
  }
  return res.status(401).json({ ok: false, error: 'invalid_credentials', message: 'Usuario o contraseña incorrectos' });
});

app.get('/api/inventario/reporte', requireAuth, async (req, res) => {
  if (!DATABASE_URL) return res.status(500).json({ ok: false, error: 'no_database_url' });
  try {
    const pool = getPool();
    const query = `
      SELECT * FROM inventario_costos 
      WHERE EXTRACT(YEAR FROM fecha_sistema) = 2025 
      AND EXTRACT(MONTH FROM fecha_sistema) = 10 
      ORDER BY fecha_sistema
    `;
    const result = await pool.query(query);
    return res.json({ 
      ok: true, 
      reporte: 'inventario_octubre_2025', 
      total_registros: result.rows.length, 
      data: result.rows,
      usuario: req.session.username 
    });
  } catch (err) {
    console.error('inventario reporte error', err && err.message ? err.message : err);
    return res.status(500).json({ ok: false, error: 'db_query_failed', message: String(err && err.message ? err.message : 'query_error') });
  }
});

// serve static front if present
try {
  const distPath = path.join(__dirname, '..', 'dist');
  const indexFile = path.join(distPath, 'index.html');
  if (fs.existsSync(indexFile)) {
    app.use(express.static(distPath));
    app.get('*', (req, res, next) => {
      if (req.path && req.path.startsWith('/api')) return next();
      res.sendFile(indexFile);
    });
    console.log('Serving static frontend from', distPath);
  }
} catch (e) {
  console.warn('Could not enable static file serving:', e && e.message ? e.message : e);
}

// Error handler
app.use((err, req, res, next) => {
  if (!err) return next();
  try {
    if (err.type === 'entity.too.large' || err.status === 413) {
      return res.status(413).json({ error: 'Payload too large' });
    }
  } catch (e) {}
  console.error('Unhandled error in API server:', err && err.stack ? err.stack : String(err));
  res.status(500).json({ error: err && err.message ? String(err.message) : 'Internal server error' });
});

// Start listener when executed directly. Prefer standard PORT, fall back to API_PORT.
if (require.main === module) {
  const port = process.env.PORT || process.env.API_PORT || 3001;
  app.listen(port, () => {
    console.log(`API server listening on http://localhost:${port}`);
  });
} else {
  module.exports = app;
}
