const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

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
app.use(cors());

const db = admin.firestore();

// 📧 Configuración de SMTP (opcional). Si no está configurado, se usa modo DEV que imprime el OTP en consola
const transporter = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    })
  : null;
const SMTP_FROM = process.env.SMTP_FROM || 'no-reply@seguridad-ciudadana.local';

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
app.post('/api/auth/email-otp/send', async (req, res) => {
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

    if (transporter) {
      await transporter.sendMail({
        from: SMTP_FROM,
        to: email,
        subject: 'Código de verificación (Seguridad Ciudadana)',
        text: `Tu código de verificación es ${code}. Expira en 10 minutos.`,
      });
      return res.json({ success: true });
    } else {
      // Modo desarrollo: sin SMTP, mostramos el código en consola y lo devolvemos como pista
      console.warn('⚠️ SMTP no configurado. Código OTP (solo DEV):', code);
      return res.json({ success: true, devHint: code });
    }
  } catch (error) {
    console.error('❌ Error al enviar OTP por email:', error);
    return res.status(500).json({ error: 'No se pudo enviar el email' });
  }
});

// Verificar OTP por email
app.post('/api/auth/email-otp/verify', async (req, res) => {
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

    // Éxito: borramos OTP y confirmamos
    await docRef.delete();
    return res.json({ success: true });
  } catch (error) {
    console.error('❌ Error al verificar OTP por email:', error);
    return res.status(500).json({ error: 'Error interno al verificar OTP' });
  }
});

// 🟢 Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${PORT}`);
});
