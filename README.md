# Backend SeguridadCiudadana

Servidor Node/Express para notificaciones, verificación OTP por email y gestión de tokens FCM.

## Stack
- `express` 5
- `firebase-admin` (Firestore y FCM)
- `nodemailer` (SMTP opcional para envío de OTP)
- `cors`, `body-parser`

## Requisitos
- Node.js 18+
- Cuenta y clave de servicio de Firebase (Firestore/FCM)
- (Opcional) Servidor SMTP para envío de correos

## Instalación
```bash
npm install
```

## Ejecución local
```bash
node index.js
# Por defecto inicia en PORT=3000
```
- Configura las variables de entorno (ver `ENVIRONMENT.md`).
- Endpoint raíz: `GET /` devuelve mensaje de estado.

## Endpoints principales
- `POST /api/guardar-token`: guarda token FCM del ciudadano.
- `POST /enviar-notificacion-estado`: envía notificación push con nuevo estado del reporte.
- `POST /api/auth/email-otp/send`: genera y envía OTP por email.
- `POST /api/auth/email-otp/verify`: verifica OTP por email.

Detalle de requests/responses en `API.md`.

## Despliegue
- Guía y recomendaciones en `DEPLOYMENT.md`.
- Asegura variables de entorno en la plataforma de despliegue.

## Seguridad
- Hash de OTP con SHA-256; expira a los 10 minutos.
- Límite de intentos de verificación (máx. 5) y limpieza del registro.
- SMTP no configurado: el OTP se muestra en consola (solo DEV).
- Prácticas y checklist en `SECURITY.md`.

## Notas
- El `android.package` de la app móvil se gestiona en el proyecto nativo; este backend solo provee API y notificaciones.