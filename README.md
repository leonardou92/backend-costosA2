# Backend Costos A2

Este proyecto es el backend independiente (Express.js) para la aplicación de costos A2. Proporciona APIs REST para gestionar inventarios, costos y ventas, conectándose a una base de datos PostgreSQL en Neon.

## Características

- API REST con Express.js
- Conexión a base de datos PostgreSQL (Neon)
- Autenticación JWT
- Generación de reportes en Excel
- Despliegue en Docker

## Requisitos

- Node.js 18+
- PostgreSQL (Neon o similar)
- npm o yarn

## Instalación

1. Clona el repositorio y entra al directorio:
   ```bash
   git clone <url-del-repo>
   cd backend-costosA2
   ```

2. Instala las dependencias:
   ```bash
   npm install
   ```

3. Configura las variables de entorno creando un archivo `.env`:
   ```bash
   DATABASE_URL=postgresql://usuario:password@host:puerto/dbname
   JWT_SECRET=tu_clave_secreta_para_jwt
   ```

## Ejecución Local

### Desarrollo
```bash
npm run dev  # Con nodemon para recarga automática
```

### Producción
```bash
npm start  # Inicia el servidor en puerto 3001
```

### Verificar Conexión a BD
```bash
npm run check-db  # Inspecciona tablas y muestra datos de ejemplo
```

## Docker

### Construir Imagen
```bash
docker build -t backend-costos-a2:latest .
```

### Ejecutar Contenedor
```bash
docker run --rm -p 3001:3001 --env-file .env backend-costos-a2:latest
```

## API Endpoints

El servidor corre en `http://localhost:3001` por defecto.

- `GET /api/health` - Verifica el estado del servidor
- `GET /api/ping` - Respuesta simple de ping
- `GET /api/dbtest` - Prueba de conexión a la base de datos
- `POST /api/login` - Login con username/password, devuelve token JWT
- `GET /api/inventario/reporte` - **Requiere token JWT** - Reporte de inventario de octubre 2025

## Despliegue

### Variables de Entorno Requeridas
- `DATABASE_URL`: URL de conexión a PostgreSQL
- `JWT_SECRET`: Clave secreta para tokens JWT
- `PORT` (opcional): Puerto del servidor (default: 3001)

### Plataformas Recomendadas
- Render
- Fly.io
- Railway
- Docker en cualquier host

### Conectar con Frontend
En el frontend, configura `VITE_API_URL` apuntando a la URL del backend desplegado.

## Notas Importantes

- **Seguridad**: Nunca subas el archivo `.env` al repositorio. Está incluido en `.gitignore`.
- **CORS**: En desarrollo permite todos los orígenes. En producción, configura `FRONTEND_ORIGIN` para restringir.
- **Base de Datos**: Usa Neon para serverless PostgreSQL. Si hay problemas de TLS en entornos serverless, considera un backend persistente.
- **Reportes**: El proyecto incluye funcionalidad para generar reportes de inventario en Excel.

## Estructura del Proyecto

```
backend-costosA2/
├── api/                 # (vacío, posiblemente para rutas futuras)
├── scripts/
│   ├── api-server.cjs   # Servidor principal Express
│   ├── check-db.cjs     # Script para inspeccionar BD
│   └── neon-client.cjs  # Cliente de conexión a Neon
├── Dockerfile           # Configuración Docker
├── package.json         # Dependencias y scripts
├── README.md            # Este archivo
└── .gitignore           # Archivos ignorados por Git
```
