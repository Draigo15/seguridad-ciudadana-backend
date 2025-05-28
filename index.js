const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const cors = require('cors');

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

// 🚀 Ruta base de prueba
app.get('/', (req, res) => {
  res.send('🚀 Backend Seguridad Ciudadana funcionando en Render');
});

// 📬 Enviar notificación cuando cambia el estado del reporte
app.post('/send-status-update', async (req, res) => {
  const { token, newStatus } = req.body;

  if (!token || !newStatus) {
    return res.status(400).json({ error: 'Faltan campos obligatorios' });
  }

  const message = {
    token,
    notification: {
      title: '🔔 Estado del Reporte',
      body: `Tu reporte fue marcado como "${newStatus}"`,
    },
  };

  try {
    const response = await admin.messaging().send(message);
    console.log('✅ Notificación enviada:', response);
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('❌ Error al enviar la notificación:', error);
    res.status(500).json({ error: 'Error al enviar la notificación' });
  }
});

// 📥 Guardar token del ciudadano en Firestore
app.post('/api/guardar-token', async (req, res) => {
  const { token, email } = req.body;

  if (!token || !email) {
    return res.status(400).json({ error: 'Token o email no proporcionado' });
  }

  try {
    const db = admin.firestore();
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

// 🟢 Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${PORT}`);
});
