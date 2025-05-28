const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const cors = require('cors');

// 🔥 PARSE MANUAL del JSON con secuencias de escape limpias (Firebase config en base64)
const serviceAccount = JSON.parse(Buffer.from(process.env.FIREBASE_CONFIG_BASE64, 'base64').toString('utf8'));

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(bodyParser.json());
app.use(cors());

// 🚀 Ruta base de prueba
app.get('/', (req, res) => {
  res.send('🚀 Backend Seguridad Ciudadana funcionando en Render');
});

// 📬 Enviar notificación push cuando cambia el estado del reporte
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

// 📥 Recibir y guardar el token del ciudadano
app.post('/api/guardar-token', async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: 'Token no proporcionado' });
  }

  console.log('📲 Token FCM recibido del ciudadano:', token);

  // Aquí podrías guardar el token en tu base de datos si lo necesitas

  res.status(200).json({ success: true, message: 'Token guardado (simulado)' });
});

// 🟢 Arrancar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${PORT}`);
});
