# Backend (costos-backend)

Este directorio contiene el servidor independiente (Express) que sirve las
APIs que consumen el frontend. Está pensado para desplegarse como un servicio
persistente en Render, Fly, Docker host, etc.

Instrucciones rápidas (desarrollo):

1) Copia `.env.example` a `.env` y añade `DATABASE_URL` y `JWT_SECRET`.

2) Instala dependencias e inicia (local):

```bash
cd backend
npm ci
npm run check-db   # opción: verifica conexión a la BD
npm run dev        # arranca con nodemon
```

3) Docker (build + run):

```bash
docker build -t costos-backend:latest ./backend
docker run --rm -p 3001:3001 -e DATABASE_URL="$DATABASE_URL" -e JWT_SECRET="$JWT_SECRET" costos-backend:latest
```

4) Conectar frontend (Vercel): en Project Settings -> Environment Variables, añade:

- `VITE_API_URL` = `https://your-backend.example.com`

Nota sobre puerto y CORS:

- El servidor backend usa por defecto el puerto 3001. Puedes sobreescribirlo con la variable de entorno `PORT` o `API_PORT`.
- Para restringir orígenes CORS en despliegue, define `VITE_API_URL` o `FRONTEND_ORIGIN` en el entorno del servidor; en su ausencia el backend permitirá orígenes desde cualquier host (útil para desarrollo).

Notas:
- No subas secretos al repositorio. Usa variables de entorno en el host.
- Si la conexión a Neon falla desde un entorno serverless por TLS, desplegar
  un backend persistente en una VM/container suele resolver ETIMEDOUT.
# Backend (costos-api)

This is the separated backend project for the Costos A2 app.

Quick start (local):

1. Copy `.env.example` to `.env` and fill values (DATABASE_URL, JWT_SECRET).

2. Install deps and run locally:

```bash
cd backend
npm ci
npm run check-db   # optional: verify DB connectivity
npm start          # starts API at http://localhost:3001
```

Docker:

```bash
docker build -t costos-api:latest .
docker run --rm -p 3001:3001 --env-file .env costos-api:latest
```

When deployed, point the frontend `VITE_API_URL` to the backend URL.
