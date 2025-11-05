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
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

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

// Configuración de Swagger
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Backend Costos A2 API',
      version: '1.0.0',
      description: 'API para gestión de costos e inventarios',
    },
    servers: [
      {
        url: 'https://backend-costos-a2.vercel.app',
        description: 'Servidor de producción',
      },
      {
        url: 'http://localhost:3001',
        description: 'Servidor local',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
  },
  apis: [__filename], // archivos donde están las rutas
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);

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

// Ruta para documentación Swagger
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Ruta para obtener la especificación Swagger JSON
app.get('/api/docs.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// Centralized Neon client (serverless-friendly). See scripts/neon-client.fixed.cjs
const { getPool, poolClient, testConnection } = require('./neon-client.fixed.cjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
if (!process.env.JWT_SECRET) {
  console.warn('Warning: JWT_SECRET not set in environment; using fallback dev secret. Set JWT_SECRET in production.');
}

const getSessionFromReq = (req) => {
  try {
    const auth = req.headers.authorization || req.headers.Authorization;
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

/**
 * @swagger
 * /api/health:
 *   get:
 *     summary: Verificar estado del servidor
 *     description: Retorna información sobre el estado del servidor y conexión a BD
 *     responses:
 *       200:
 *         description: Estado del servidor
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 healthy:
 *                   type: boolean
 *                 uptime:
 *                   type: number
 *                 env_database:
 *                   type: boolean
 *                 now:
 *                   type: number
 */
app.get('/api/health', (req, res) => {
  res.json({ ok: true, healthy: true, uptime: process.uptime(), env_database: !!DATABASE_URL, now: Date.now() });
});

/**
 * @swagger
 * /api/ping:
 *   get:
 *     summary: Ping simple
 *     description: Respuesta básica para verificar que la API está funcionando
 *     responses:
 *       200:
 *         description: Respuesta de ping
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 uptime:
 *                   type: number
 *                 env_database:
 *                   type: boolean
 */
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), env_database: !!DATABASE_URL });
});

/**
 * @swagger
 * /api/dbtest:
 *   get:
 *     summary: Probar conexión a base de datos
 *     description: Verifica la conectividad con la base de datos PostgreSQL
 *     responses:
 *       200:
 *         description: Conexión exitosa
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       500:
 *         description: Error de conexión
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 error:
 *                   type: string
 *                 message:
 *                   type: string
 */
app.get('/api/dbtest', async (req, res) => {
  if (!DATABASE_URL) return res.status(500).json({ ok: false, error: 'no_database_url' });
  try {
    const pool = getPool();
    await pool.query('SELECT 1');
    return res.json({ ok: true, message: 'db_reachable' });
  } catch (err) {
    console.error('dbtest connect error', err && err.message ? err.message : err);
    return res.status(500).json({ ok: false, error: 'db_connect_failed', message: String(err && err.message ? err.message : 'connect_error') });
  }
});

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Autenticación de usuario
 *     description: Inicia sesión y obtiene un token JWT
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *                 example: admin
 *               password:
 *                 type: string
 *                 example: admin
 *     responses:
 *       200:
 *         description: Login exitoso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 token:
 *                   type: string
 *                 message:
 *                   type: string
 *       401:
 *         description: Credenciales inválidas
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 error:
 *                   type: string
 *                 message:
 *                   type: string
 */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  // Para demo: usuario fijo
  if (username === 'admin' && password === 'admin') {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
    return res.json({ ok: true, token, message: 'Login exitoso' });
  }
  return res.status(401).json({ ok: false, error: 'invalid_credentials', message: 'Usuario o contraseña incorrectos' });
});

/**
 * @swagger
 * /api/inventario/reporte:
 *   get:
 *     summary: Obtener reporte de inventario
 *     description: Retorna el reporte completo de inventario para octubre 2025
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Reporte de inventario
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 reporte:
 *                   type: string
 *                 total_registros:
 *                   type: integer
 *                 data:
 *                   type: array
 *                   items:
 *                     type: object
 *                 usuario:
 *                   type: string
 *       401:
 *         description: No autorizado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                 error:
 *                   type: string
 *                 message:
 *                   type: string
 */
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
