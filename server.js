const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');

const { generateFromMeta } = require('./src/app/generateFromMeta');
const { slugifyWeb, parseFechaEmision, ymd, writeJsonAtomic } = require('./src/core/utils');
const { calcularTablaAmortizacion } = require('./src/calculators/amortizacion');
const { generarPagarePDF } = require('./src/documents/pagare');
const { generarContratoPDF } = require('./src/documents/contrato');

const app = express();
const PORT = process.env.PORT || 3000;

const AUTH_CONFIG = {
  username: 'isra',
  password: 'adein123',
  cookieName: 'lia_session',
  cookieValue: 'ok',
  sessionDuration: 8 * 60 * 60 * 1000,
  secret: 'lia-web-golden-secret-2026'
};

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(AUTH_CONFIG.secret));

// ESTÁTICOS PÚBLICOS (SIN AUTH) - DEBEN IR ANTES DE checkAuth
app.use('/css', express.static(path.join(__dirname, 'web', 'css')));
app.use('/js', express.static(path.join(__dirname, 'web', 'js')));
app.use('/assets', express.static(path.join(__dirname, 'web', 'assets')));

// RUTAS DE AUTH
app.get('/login', (req, res) => {
  const sessionCookie = req.signedCookies[AUTH_CONFIG.cookieName] || req.cookies[AUTH_CONFIG.cookieName];
  if (sessionCookie === AUTH_CONFIG.cookieValue) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'web', 'login.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === AUTH_CONFIG.username && password === AUTH_CONFIG.password) {
    res.cookie(AUTH_CONFIG.cookieName, AUTH_CONFIG.cookieValue, {
      maxAge: AUTH_CONFIG.sessionDuration,
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      signed: true,
      sameSite: 'strict'
    });
    return res.json({ success: true, redirect: '/' });
  }
  res.status(401).json({ success: false, error: 'Credenciales inválidas' });
});

app.get('/logout', (req, res) => {
  res.clearCookie(AUTH_CONFIG.cookieName);
  res.redirect('/login');
});

app.post('/logout', (req, res) => {
  res.clearCookie(AUTH_CONFIG.cookieName);
  res.json({ success: true });
});

// MIDDLEWARE DE AUTH (DESPUÉS de estáticos públicos)
const checkAuth = (req, res, next) => {
  if (req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/assets/') || req.path === '/login' || req.path === '/logout') {
    return next();
  }
  const sessionCookie = req.signedCookies[AUTH_CONFIG.cookieName] || req.cookies[AUTH_CONFIG.cookieName];
  if (sessionCookie === AUTH_CONFIG.cookieValue) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'No autenticado', redirect: '/login' });
  res.redirect('/login');
};

app.use(checkAuth);

// ESTÁTICOS PROTEGIDOS
app.use(express.static(path.join(__dirname, 'web')));

// APIs
app.post('/api/capturas', (req, res) => {
  try {
    const meta = req.body;
    const outDir = path.join(__dirname, 'data', 'capturas');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    
    let filename = `${slugifyWeb(meta.cliente?.nombre || 'captura')}-${ymd()}.json`;
    let filepath = path.join(outDir, filename);
    
    // FIX: Evitar "Source and destination must not be the same"
    if (fs.existsSync(filepath)) {
      filename = `${slugifyWeb(meta.cliente?.nombre || 'captura')}-${ymd()}-${Date.now()}.json`;
      filepath = path.join(outDir, filename);
    }
    
    writeJsonAtomic(filepath, meta);
    res.json({ ok: true, filename });
  } catch (err) {
    console.error('Error en /api/capturas:', err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/generar', async (req, res) => {
  try {
    const { meta, tipo } = req.body;
    if (!meta || Object.keys(meta).length === 0) return res.status(400).json({ error: 'Metadata vacía' });
    const result = await generateFromMeta(meta, tipo);
    res.json(result);
  } catch (err) {
    console.error('Error en /api/generar:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/descargar', (req, res) => {
  try {
    const { file } = req.query;
    if (!file) return res.status(400).json({ error: 'Falta parámetro file' });
    const safeFile = path.basename(file);
    const filepath = path.join(__dirname, 'output', safeFile);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'Archivo no encontrado' });
    res.download(filepath);
  } catch (err) {
    console.error('Error en /api/descargar:', err);
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 LIA-WEB-GOLDEN en http://localhost:${PORT}`);
  console.log(`🔐 Login: ${AUTH_CONFIG.username}`);
});
