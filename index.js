const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');
const cors = require('cors');

const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post('/send-status-update', async (req, res) => {
  const { token, newStatus } = req.body;

  if (!token || !newStatus) {
    return res.status(400).json({ error: 'Token y estado requeridos.' });
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
    res.status(200).send('Notificación enviada');
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ error: 'No se pudo enviar la notificación' });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend en http://localhost:${PORT}`);
});
