# API Backend SeguridadCiudadana

Documentación de endpoints disponibles y ejemplos de uso.

## Base URL
- Desarrollo: `http://localhost:3000`
- Producción: según plataforma de despliegue

## 1) GET `/`
- Propósito: verificación básica del estado del servidor.
- Respuesta 200:
```json
"🚀 Backend Seguridad Ciudadana funcionando en Render"
```

## 2) POST `/api/guardar-token`
- Propósito: guardar el token FCM del ciudadano para notificaciones push.
- Body (JSON):
```json
{ "token": "fcm_token", "email": "usuario@example.com" }
```
- Respuestas:
  - 200: `{ "success": true, "message": "Token guardado correctamente" }`
  - 400: `{ "error": "Token o email no proporcionado" }`
  - 500: `{ "error": "Error al guardar el token" }`

## 3) POST `/enviar-notificacion-estado`
- Propósito: enviar notificación push al ciudadano cuando cambia el estado de su reporte.
- Body (JSON):
```json
{ "email": "usuario@example.com", "newStatus": "En curso" }
```
- Respuestas:
  - 200: `{ "success": true, "message": "Notificación enviada" }`
  - 400: `{ "error": "Faltan email o estado nuevo" }`
  - 404: `{ "error": "Token FCM no encontrado para el email proporcionado" }`
  - 500: `{ "error": "Error interno al enviar notificación" }`

## 4) POST `/api/auth/email-otp/send`
- Propósito: generar y enviar un código OTP por email para 2FA.
- Body (JSON):
```json
{ "email": "usuario@example.com" }
```
- Respuestas:
  - 200: `{ "success": true }` (si SMTP configurado)
  - 200: `{ "success": true, "devHint": "123456" }` (si SMTP NO configurado, solo DEV)
  - 400: `{ "error": "Email requerido" }`
  - 500: `{ "error": "No se pudo enviar el email" }`

## 5) POST `/api/auth/email-otp/verify`
- Propósito: verificar el código OTP enviado por email y abrir sesión.
- Body (JSON):
```json
{ "email": "usuario@example.com", "code": "123456" }
```
- Respuestas:
  - 200: `{ "success": true, "token": "<session_token>", "expiresInMinutes": 120 }`
  - 400: `{ "error": "Email y código requeridos" }`
  - 404: `{ "error": "OTP no encontrado, solicita uno nuevo" }`
  - 410: `{ "error": "Código expirado, solicita uno nuevo" }`
  - 429: `{ "error": "Demasiados intentos, solicita un nuevo código" }`
  - 401: `{ "error": "Código inválido" }`
  - 500: `{ "error": "Error interno al verificar OTP" }`

## 6) GET `/api/auth/session/validate`
- Propósito: validar el token de sesión opaco del usuario.
- Headers: `Authorization: Bearer <token>`
- Respuestas:
  - 200: `{ "valid": true, "email": "usuario@example.com", "exp": 1712345678 }`
  - 401: `{ "error": "Token inválido o expirado" }`
  - 500: `{ "error": "Error al validar token" }`

## 7) POST `/api/auth/logout`
- Propósito: cerrar sesión (revocar el token opaco).
- Headers: `Authorization: Bearer <token>`
- Respuestas:
  - 200: `{ "success": true }`
  - 401: `{ "error": "Token inválido o expirado" }`
  - 500: `{ "error": "Error al revocar token" }`

## Notas
- El OTP expira a los 10 minutos y se almacena hashed en Firestore.
- El número de intentos está limitado a 5.
- En DEV sin SMTP, el código se imprime en consola y se devuelve como `devHint`.
 - Tras verificar OTP, se emite un token de sesión opaco con expiración configurable (`SESSION_TTL_MINUTES`).
 - Los tokens se almacenan en la colección `sessions` de Firestore y se invalidan al cerrar sesión o expirar.