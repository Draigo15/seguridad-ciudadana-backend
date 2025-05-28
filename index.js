const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const cors = require('cors');

// Leer credenciales desde variable de entorno (ya escapadas correctamente)
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);

// Inicializar Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Ruta raíz de prueba
app.get('/', (req, res) => {
  res.send('🚀 Backend Seguridad Ciudadana funcionando en Render');
});

// Ruta para enviar notificaciones push
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
    res.status(200).json({ success: true, response });
  } catch (error) {
    console.error('❌ Error al enviar la notificación:', error);
    res.status(500).json({ error: 'Error al enviar la notificación' });
  }
});

// Puerto para Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor escuchando en http://localhost:${PORT}`);
});
