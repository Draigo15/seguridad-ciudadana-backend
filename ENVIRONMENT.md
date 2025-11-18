# Variables de Entorno (Backend)

Configura estas variables antes de ejecutar o desplegar el servidor.

## Obligatorias
- `FIREBASE_CONFIG_BASE64`: JSON de la credencial de servicio de Firebase, codificado en Base64.
  - Cómo obtenerlo:
    1. Descarga el archivo JSON de clave de servicio desde Firebase Console.
    2. Codifica el contenido en Base64.
    3. Asigna el resultado a `FIREBASE_CONFIG_BASE64`.

## Opcionales (SMTP)
- `SMTP_HOST`: host del servidor SMTP.
- `SMTP_PORT`: puerto SMTP (ej. `587`).
- `SMTP_SECURE`: `true` si usa TLS en puerto 465; `false` en 587.
- `SMTP_REQUIRE_TLS`: `true` fuerza STARTTLS en `587`.
- `SMTP_USER`: usuario SMTP.
- `SMTP_PASS`: contraseña SMTP.
- `SMTP_FROM`: remitente (por defecto `no-reply@seguridad-ciudadana.local`).
- `SMTP_CONNECTION_TIMEOUT_MS`: timeout de conexión (ms, por defecto `10000`).
- `SMTP_SOCKET_TIMEOUT_MS`: timeout de socket (ms, por defecto `10000`).

Si no configuras SMTP, el servidor funciona en modo DEV: el código OTP se imprime en consola y se devuelve como `devHint`.

## Alternativa (proveedor HTTP)
- `EMAIL_PROVIDER`: actualmente soporta `sendgrid`.
- `SENDGRID_API_KEY`: clave de API de SendGrid.
- `SMTP_FROM`: se usa también como remitente para SendGrid.

Si configuras `EMAIL_PROVIDER=sendgrid` y `SENDGRID_API_KEY`, el envío de emails se realizará vía HTTPS evitando bloqueos de puertos SMTP.

## Otros
- `PORT`: puerto del servidor (por defecto `3000`).
 
### Autenticación por sesión (sin JWT)
- `SESSION_TTL_MINUTES`: minutos de validez del token de sesión (por defecto `120`).

## Ejemplo (.env)
```env
FIREBASE_CONFIG_BASE64=eyJ0eXBlIjoi..."}
SMTP_HOST=smtp.tu-dominio.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_REQUIRE_TLS=true
SMTP_USER=usuario
SMTP_PASS=clave
SMTP_FROM=seguridad@tu-dominio.com
SMTP_CONNECTION_TIMEOUT_MS=15000
SMTP_SOCKET_TIMEOUT_MS=15000
PORT=3000

# Sesión
SESSION_TTL_MINUTES=120

# Alternativa por API
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=SG.xxxx
```