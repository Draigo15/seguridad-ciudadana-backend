const request = require('supertest');

// Mocks e in-memory stores para Firestore Admin
const makeFirebaseAdminMock = () => {
  const stores = {
    sessions: new Map(),
    email_otps: new Map(),
    user_tokens: new Map(),
  };

  const collectionFor = (name) => {
    const map = stores[name];
    if (!map) throw new Error(`Unknown collection: ${name}`);
    return {
      doc: (id) => ({
        set: async (data) => { map.set(id, { ...(data || {}) }); },
        get: async () => ({ exists: map.has(id), data: () => map.get(id) }),
        update: async (data) => { Object.assign(map.get(id) || {}, data); },
        delete: async () => { map.delete(id); },
      }),
    };
  };

  return {
    initializeApp: jest.fn(),
    credential: { cert: jest.fn(() => ({})) },
    firestore: () => ({ collection: collectionFor }),
    messaging: () => ({ send: jest.fn().mockResolvedValue('ok') }),
    __stores: stores,
  };
};

// Helper para crear la app con mocks y entorno
const buildApp = (overrides = {}) => {
  jest.resetModules();
  process.env.FIREBASE_CONFIG_BASE64 = Buffer.from('{}', 'utf8').toString('base64');
  process.env.ALLOWED_ORIGINS = '';
  process.env.SESSION_TTL_MINUTES = String(overrides.SESSION_TTL_MINUTES ?? 120);

  const adminMock = makeFirebaseAdminMock();
  jest.doMock('firebase-admin', () => adminMock);

  const app = require('..');
  return { app, adminMock };
};

describe('RNF-9 Seguridad de Sesiones — invalidación de tokens', () => {
  test('Revoca token al hacer logout y no valida después', async () => {
    const { app } = buildApp({ SESSION_TTL_MINUTES: 120 });
    const email = 'usuario@example.com';

    // Solicitar OTP (modo DEV devuelve devHint)
    const sendRes = await request(app)
      .post('/api/auth/email-otp/send')
      .send({ email })
      .expect(200);
    expect(sendRes.body.success).toBe(true);
    const code = sendRes.body.devHint; // modo DEV
    expect(code).toBeTruthy();

    // Verificar OTP y obtener token opaco
    const verifyRes = await request(app)
      .post('/api/auth/email-otp/verify')
      .send({ email, code })
      .expect(200);
    expect(verifyRes.body.success).toBe(true);
    const token = verifyRes.body.token;
    expect(token).toBeTruthy();

    // Validar token: debe ser válido
    await request(app)
      .get('/api/auth/session/validate')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect(res => {
        expect(res.body.valid).toBe(true);
        expect(res.body.email).toBe(email);
      });

    // Logout: debe revocar el token
    await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect(res => {
        expect(res.body.success).toBe(true);
      });

    // Validar otra vez: ahora debe ser inválido
    await request(app)
      .get('/api/auth/session/validate')
      .set('Authorization', `Bearer ${token}`)
      .expect(401)
      .expect(res => {
        expect(res.body.valid).toBe(false);
      });
  });

  test('Token expira (TTL=0) y se revoca en la validación', async () => {
    const { app } = buildApp({ SESSION_TTL_MINUTES: 0 });
    const email = 'usuario@example.com';

    const sendRes = await request(app)
      .post('/api/auth/email-otp/send')
      .send({ email })
      .expect(200);
    const code = sendRes.body.devHint;

    const verifyRes = await request(app)
      .post('/api/auth/email-otp/verify')
      .send({ email, code })
      .expect(200);
    const token = verifyRes.body.token;

    // Debe expirar inmediatamente y devolver 401 + revocar
    await request(app)
      .get('/api/auth/session/validate')
      .set('Authorization', `Bearer ${token}`)
      .expect(401)
      .expect(res => {
        expect(res.body.valid).toBe(false);
      });
  });
});