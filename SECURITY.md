# Seguridad (Backend)

Prácticas recomendadas y consideraciones para este servicio.

## OTP y 2FA
- Los códigos OTP se almacenan hashed (SHA-256) y expiran en 10 minutos.
- Límite de intentos: 5. Tras superar el límite, se borra el registro.
- En producción, SMTP debe estar configurado; no exponer el OTP en respuestas.

## Credenciales y secretos
- Mantén `FIREBASE_CONFIG_BASE64` fuera del repositorio (solo en variables de entorno).
- Evita registrar datos sensibles en logs.
- Rotación periódica de claves y acceso mínimo en Firebase.

## CORS y exposición
- Restringe orígenes permitidos según tu app y dominios conocidos.
- Usa HTTPS en producción.

## Notificaciones FCM
- Verifica que los tokens se renuevan y se borran tokens inválidos.
- Considera manejo de errores y reintentos controlados.

## Endpoints y validaciones
- Valida inputs (`email`, `token`, `newStatus`).
- Limita tamaño de request y rate limit por IP si es público.

## Futuras mejoras
- Refuerzo de sesiones opacas: rotación periódica del token y límites de sesión activa.
- Auditoría de cambios y eventos críticos.
- Monitoreo y alertas (fallos de envío, picos de intentos OTP).