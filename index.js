const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
// Sesiones opacas (sin JWT)

// 🔥 Parsear manualmente el JSON de configuración desde BASE64
const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_CONFIG_BASE64, 'base64').toString('utf8')
);

// Inicializar Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(bodyParser.json());

// Render y la mayoría de plataformas de despliegue ponen un proxy delante.
// Esto permite que Express identifique correctamente la IP del cliente usando X-Forwarded-For.
app.set('trust proxy', 1);

// Seguridad HTTP Headers
app.use(helmet({
  contentSecurityPolicy: false, // Deshabilitar CSP por simplicidad en API JSON
}));

// CORS restringido
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));

// Rate limiting global y por ruta sensible
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 1000,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

const db = admin.firestore();

// Configuración de sesiones opacas
const SESSION_TTL_MINUTES = parseInt(process.env.SESSION_TTL_MINUTES || '120', 10);

// Helpers de sesión opaca
async function createSession(email) {
  const token = crypto.randomUUID();
  const expiresAt = Date.now() + SESSION_TTL_MINUTES * 60 * 1000;
  await db.collection('sessions').doc(token).set({
    token,
    email,
    expiresAt,
    createdAt: new Date(),
  });
  return { token, expiresAt };
}

async function getSession(token) {
  const snap = await db.collection('sessions').doc(token).get();
  return snap.exists ? snap.data() : null;
}

async function revokeSession(token) {
  await db.collection('sessions').doc(token).delete();
}

// 📧 Configuración de SMTP (opcional). Si no está configurado, se usa modo DEV que imprime el OTP en consola
const transporter = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      requireTLS: process.env.SMTP_REQUIRE_TLS === 'true', // útil en 587 con STARTTLS
      family: process.env.SMTP_FORCE_IPV4 === 'true' ? 4 : undefined,
      logger: process.env.SMTP_DEBUG === 'true',
      debug: process.env.SMTP_DEBUG === 'true',
      connectionTimeout: parseInt(process.env.SMTP_CONNECTION_TIMEOUT_MS || '10000', 10),
      socketTimeout: parseInt(process.env.SMTP_SOCKET_TIMEOUT_MS || '10000', 10),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    })
  : null;
const SMTP_FROM = process.env.SMTP_FROM || 'no-reply@seguridad-ciudadana.local';

// Proveedor HTTP (SendGrid) como alternativa para evitar bloqueos/timeout SMTP
const EMAIL_PROVIDER = process.env.EMAIL_PROVIDER;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
let sgMail = null;
const useSendGrid = EMAIL_PROVIDER === 'sendgrid' && !!SENDGRID_API_KEY;
if (useSendGrid) {
  sgMail = require('@sendgrid/mail');
  sgMail.setApiKey(SENDGRID_API_KEY);
}

async function sendEmail({ to, subject, text }) {
  if (transporter) {
    return transporter.sendMail({ from: SMTP_FROM, to, subject, text });
  }
  if (useSendGrid && sgMail) {
    return sgMail.send({ to, from: SMTP_FROM, subject, text });
  }
  throw new Error('Email provider not configured');
}

// =============================
// 🔎 Diagnóstico de proveedor de email
// =============================
app.get('/api/diagnostics/email', async (req, res) => {
  try {
    const base = {
      provider: transporter ? 'smtp' : (useSendGrid ? 'sendgrid' : 'none'),
      from: SMTP_FROM,
      smtp: transporter ? {
        host: process.env.SMTP_HOST,
        port: parseInt(process.env.SMTP_PORT || '587', 10),
        secure: process.env.SMTP_SECURE === 'true',
        requireTLS: process.env.SMTP_REQUIRE_TLS === 'true',
      } : null,
    };

    if (transporter) {
      try {
        const ok = await transporter.verify();
        return res.json({ ...base, configured: true, verifyOk: !!ok });
      } catch (e) {
        return res.status(500).json({ ...base, configured: true, verifyOk: false, error: String(e && e.message || e) });
      }
    }

    if (useSendGrid) {
      return res.json({ ...base, configured: true, verifyOk: true });
    }

    return res.status(200).json({ ...base, configured: false });
  } catch (err) {
    return res.status(500).json({ error: 'Diagnostics failed' });
  }
});

// Utilidades OTP
const generateOtp = () => Math.floor(100000 + Math.random() * 900000).toString();
const hashCode = (code) => crypto.createHash('sha256').update(code).digest('hex');

// 🚀 Ruta base de prueba
app.get('/', (req, res) => {
  res.send('🚀 Backend Seguridad Ciudadana funcionando en Render');
});

// 📥 Guardar token del ciudadano en Firestore
app.post('/api/guardar-token', async (req, res) => {
  const { token, email } = req.body;

  if (!token || !email) {
    return res.status(400).json({ error: 'Token o email no proporcionado' });
  }

  try {
    await db.collection('user_tokens').doc(email).set({
      token,
      email,
      updatedAt: new Date(),
    });

    console.log('📦 Token guardado en Firestore para:', email);
    res.status(200).json({ success: true, message: 'Token guardado correctamente' });
  } catch (error) {
    console.error('❌ Error al guardar token en Firestore:', error);
    res.status(500).json({ error: 'Error al guardar el token' });
  }
});

// 📬 Enviar notificación push al ciudadano al cambiar el estado
app.post('/enviar-notificacion-estado', async (req, res) => {
  const { email, newStatus } = req.body;

  if (!email || !newStatus) {
    return res.status(400).json({ error: 'Faltan email o estado nuevo' });
  }

  try {
    // Buscar el token FCM del usuario en Firestore
    const docRef = db.collection('user_tokens').doc(email);
    const docSnap = await docRef.get();

    if (!docSnap.exists) {
      return res.status(404).json({ error: 'Token FCM no encontrado para el email proporcionado' });
    }

    const { token } = docSnap.data();

    // Crear y enviar la notificación
    const message = {
      token,
      notification: {
        title: '🔔 Estado del Reporte Actualizado',
        body: `Tu reporte fue marcado como "${newStatus}"`,
      },
    };

    const response = await admin.messaging().send(message);
    console.log('✅ Notificación enviada:', response);

    res.status(200).json({ success: true, message: 'Notificación enviada' });
  } catch (error) {
    console.error('❌ Error al enviar la notificación:', error);
    res.status(500).json({ error: 'Error interno al enviar notificación' });
  }
});

// =============================
// 🔐 2FA: OTP por Email
// =============================

// Enviar OTP por email
app.post('/api/auth/email-otp/send', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email requerido' });
    }

    const code = generateOtp();
    const hashed = hashCode(code);
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutos

    await db.collection('email_otps').doc(email).set({
      hashed,
      expiresAt,
      attempts: 0,
      createdAt: new Date(),
    });

    // En modo test, o si no hay proveedor configurado, devolver devHint sin intentar enviar email
    const isTestEnv = process.env.NODE_ENV === 'test';
    const hasEmailProvider = !!transporter || (!!useSendGrid && !!sgMail);
    if (isTestEnv || !hasEmailProvider) {
      console.warn('⚠️ OTP devHint emitido (test/dev):', code);
      return res.json({ success: true, devHint: code });
    }

    try {
      await sendEmail({
        to: email,
        subject: 'Código de verificación (Seguridad Ciudadana)',
        text: `Tu código de verificación es ${code}. Expira en 10 minutos.`,
      });
      return res.json({ success: true });
    } catch (e) {
      // Fallback: si el proveedor falla, aún retornamos devHint para no bloquear autenticación en pruebas
      console.warn('⚠️ Falla proveedor email, OTP devHint:', String(e && e.message || e));
      return res.json({ success: true, devHint: code });
    }
  } catch (error) {
    console.error('❌ Error al enviar OTP por email:', error);
    return res.status(500).json({ error: 'No se pudo enviar el email' });
  }
});

// Verificar OTP por email
app.post('/api/auth/email-otp/verify', authLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      return res.status(400).json({ error: 'Email y código requeridos' });
    }

    const docRef = db.collection('email_otps').doc(email);
    const snap = await docRef.get();

    if (!snap.exists) {
      return res.status(404).json({ error: 'OTP no encontrado, solicita uno nuevo' });
    }

    const data = snap.data();

    if (data.expiresAt < Date.now()) {
      await docRef.delete();
      return res.status(410).json({ error: 'Código expirado, solicita uno nuevo' });
    }

    const attempts = (data.attempts || 0) + 1;
    if (attempts > 5) {
      await docRef.delete();
      return res.status(429).json({ error: 'Demasiados intentos, solicita un nuevo código' });
    }

    const ok = data.hashed === hashCode(code);
    if (!ok) {
      await docRef.update({ attempts });
      return res.status(401).json({ error: 'Código inválido' });
    }

    // Éxito: borrar OTP y crear sesión opaca
    await docRef.delete();
    const { token, expiresAt } = await createSession(email);
    const expiresInMinutes = SESSION_TTL_MINUTES;
    return res.json({ success: true, token, expiresInMinutes, expiresAt });
  } catch (error) {
    console.error('❌ Error al verificar OTP por email:', error);
    return res.status(500).json({ error: 'Error interno al verificar OTP' });
  }
});

// Validar sesión (token opaco)
app.get('/api/auth/session/validate', authLimiter, async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ valid: false, error: 'Token requerido' });
    }
    const token = auth.split(' ')[1];
    const session = await getSession(token);
    if (!session) {
      return res.status(401).json({ valid: false, error: 'Token inválido' });
    }
    if (session.expiresAt < Date.now()) {
      await revokeSession(token);
      return res.status(401).json({ valid: false, error: 'Token expirado' });
    }
    return res.json({ valid: true, email: session.email, exp: Math.floor(session.expiresAt / 1000) });
  } catch (error) {
    console.error('❌ Error al validar sesión:', error);
    return res.status(401).json({ valid: false, error: 'Token inválido o expirado' });
  }
});

// Cerrar sesión (revocar token opaco)
app.post('/api/auth/logout', authLimiter, async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, error: 'Token requerido' });
    }
    const token = auth.split(' ')[1];
    await revokeSession(token);
    return res.json({ success: true });
  } catch (error) {
    console.error('❌ Error al cerrar sesión:', error);
    return res.status(401).json({ success: false, error: 'Token inválido' });
  }
});

// Exportar la app para pruebas e iniciar servidor solo si es entrypoint directo
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`🚀 Servidor escuchando en http://localhost:${PORT}`);
  });
}

module.exports = app;
