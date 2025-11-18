# Despliegue del Backend

Guía para ejecutar en local y desplegar en producción.

## Ejecución local
```bash
npm install
node index.js
# Servidor en http://localhost:3000
```
- Configura variables de entorno (ver `ENVIRONMENT.md`).
- Usa herramientas como `dotenv` o define variables en tu entorno.

## Despliegue (Render u otros)
- Crea un servicio web Node.
- Define `Node Version` acorde (>=18).
- Comando de inicio: `node index.js`.
- Variables de entorno:
  - `FIREBASE_CONFIG_BASE64` (obligatoria)
  - `SMTP_*` (si envías emails en producción)
  - Alternativa: `EMAIL_PROVIDER=sendgrid` y `SENDGRID_API_KEY` (recomendado si tu plataforma bloquea puertos SMTP)
  - `PORT` (Render asigna automáticamente)

## Logs y monitoreo
- Revisa logs para errores de Firestore/FCM/SMTP.
- Añade alertas si los endpoints OTP fallan o superan intentos.

## Consideraciones
- Asegura que la clave de servicio Firebase tenga permisos mínimos necesarios.
- Habilita CORS según dominios de la app móvil.
- No registrar códigos OTP en producción; usa transporter SMTP.

## Troubleshooting
- Error credenciales Firebase: verifica `FIREBASE_CONFIG_BASE64` y formato del JSON.
- Notificaciones FCM no llegan: confirma token guardado y permisos en cliente.
- Email OTP no se envía:
  - En SMTP: valida `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `SMTP_PORT`/`SMTP_SECURE`.
  - Si ves `ETIMEDOUT`/`CONN` al conectar a SMTP, usa proveedor HTTP (`EMAIL_PROVIDER=sendgrid`) para evitar bloqueos de egress.
  - Asegura `SMTP_FROM` con un remitente válido.