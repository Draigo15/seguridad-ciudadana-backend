const request = require('supertest');

// Reutiliza el helper y mocks del RNF-9 para construir la app con TTL variable
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

describe('Autenticación — Refresh por re-autenticación post-401', () => {
  test('Token expirado devuelve 401; re-autenticación emite nuevo token válido', async () => {
    const email = 'usuario@example.com';

    // 1) Construir app con TTL=0 para que el primer token expire enseguida
    const { app } = buildApp({ SESSION_TTL_MINUTES: 0 });

    // Solicitar OTP (modo DEV devuelve devHint)
    const sendRes1 = await request(app)
      .post('/api/auth/email-otp/send')
      .send({ email })
      .expect(200);
    expect(sendRes1.body.success).toBe(true);
    const code1 = sendRes1.body.devHint;
    expect(code1).toBeTruthy();

    // Verificar OTP y obtener token opaco (expira inmediatamente)
    const verifyRes1 = await request(app)
      .post('/api/auth/email-otp/verify')
      .send({ email, code: code1 })
      .expect(200);
    const token1 = verifyRes1.body.token;
    expect(token1).toBeTruthy();

    // Validar token: debe devolver 401 por expiración
    await request(app)
      .get('/api/auth/session/validate')
      .set('Authorization', `Bearer ${token1}`)
      .expect(401)
      .expect(res => {
        expect(res.body.valid).toBe(false);
      });

    // 2) Reconstruir app con TTL=120 y re-autenticar para obtener un nuevo token válido
    const { app: app2 } = buildApp({ SESSION_TTL_MINUTES: 120 });

    const sendRes2 = await request(app2)
      .post('/api/auth/email-otp/send')
      .send({ email })
      .expect(200);
    expect(sendRes2.body.success).toBe(true);
    const code2 = sendRes2.body.devHint;
    expect(code2).toBeTruthy();

    const verifyRes2 = await request(app2)
      .post('/api/auth/email-otp/verify')
      .send({ email, code: code2 })
      .expect(200);
    const token2 = verifyRes2.body.token;
    expect(token2).toBeTruthy();

    // Validar nuevo token: debe ser 200 válido
    await request(app2)
      .get('/api/auth/session/validate')
      .set('Authorization', `Bearer ${token2}`)
      .expect(200)
      .expect(res => {
        expect(res.body.valid).toBe(true);
        expect(res.body.email).toBe(email);
      });
  });
});