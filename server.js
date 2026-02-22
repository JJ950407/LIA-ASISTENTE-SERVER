const path = require('path');
const fs = require('fs');
const express = require('express');
const cookieParser = require('cookie-parser');
const dotenv = require('dotenv');
const { parseDateDMYLoose } = require('./src/parsers/date');
const { generateFromMeta } = require('./src/app/generateFromMeta');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_CLIENTS_DIR = path.resolve(__dirname, 'data', 'clientes');
const ENABLE_AUTH = String(process.env.ENABLE_AUTH || '0') === '1';
const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;
const AUTH_REALM = process.env.AUTH_REALM || 'LIA Pagaré';
const SESSION_COOKIE = 'lia_session';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const LOGIN_USER = 'isra';
const LOGIN_PASS = 'adein123';

app.use(cookieParser());

function checkAuth(req, res, next) {
  const reqPath = req.path || '';
  const publicAssetExt = /\.(css|js|png|jpg|jpeg|svg|gif|woff|woff2|ttf|eot)$/i;
  if (
    reqPath === '/login' ||
    reqPath === '/logout' ||
    reqPath === '/web/login.html' ||
    reqPath.startsWith('/css/') ||
    reqPath.startsWith('/js/') ||
    reqPath.startsWith('/assets/') ||
    publicAssetExt.test(reqPath)
  ) {
    return next();
  }

  if (req.cookies && req.cookies[SESSION_COOKIE] === 'ok') {
    return next();
  }

  return res.redirect(302, '/login');
}

app.use(checkAuth);

app.use(express.static(path.join(__dirname, 'web')));

app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '1mb' }));

function unauthorized(res) {
  res.setHeader('WWW-Authenticate', `Basic realm="${AUTH_REALM}"`);
  return res.status(401).send('Autenticación requerida.');
}

function basicAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const [type, encoded] = header.split(' ');
  if (type !== 'Basic' || !encoded) {
    return unauthorized(res);
  }
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (!user || !pass) {
    return unauthorized(res);
  }
  if (user !== AUTH_USER || pass !== AUTH_PASS) {
    return unauthorized(res);
  }
  return next();
}

if (ENABLE_AUTH) {
  if (!AUTH_USER || !AUTH_PASS) {
    throw new Error('ENABLE_AUTH=1 requiere AUTH_USER y AUTH_PASS.');
  }
  app.use(basicAuth);
}

app.get('/login', (req, res) => {
  return res.sendFile(path.join(__dirname, 'web', 'login.html'));
});

app.post('/login', (req, res) => {
  const { usuario, password } = req.body || {};
  if (usuario === LOGIN_USER && password === LOGIN_PASS) {
    res.cookie(SESSION_COOKIE, 'ok', {
      maxAge: SESSION_TTL_MS,
      httpOnly: true
    });
    return res.redirect('/');
  }
  return res.redirect('/login?error=1');
});

app.get('/logout', (req, res) => {
  res.clearCookie(SESSION_COOKIE);
  return res.redirect('/login');
});

function slugifyWeb(text) {
  return String(text || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()
    .slice(0, 60);
}

function parseFechaEmision(raw) {
  if (!raw) return new Date();
  if (raw instanceof Date) return raw;
  if (typeof raw === 'number') return new Date(raw);
  const text = String(raw).trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(text)) {
    const parsed = new Date(text);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return parseDateDMYLoose(text);
}

function ymd(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function writeJsonAtomic(filePath, data) {
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, filePath);
}

app.post('/api/capturas', (req, res) => {
  try {
    const payload = req.body?.payload;
    if (!payload) {
      return res.status(400).json({ ok: false, error: 'Falta payload.' });
    }

    const fechaEmision = parseFechaEmision(payload.fechaEmision || payload.fechaEmisionLote);
    const dateISO = ymd(fechaEmision);
    const slug = slugifyWeb(payload.deudor || payload.deudorNombreCompleto || 'cliente');

    const basePathRel = path.join('data', 'clientes', slug, dateISO);
    const basePathAbs = path.resolve(__dirname, basePathRel);
    fs.mkdirSync(basePathAbs, { recursive: true });

    const now = new Date().toISOString();
    const meta = {
      ...payload,
      slug,
      dateISO,
      basePath: basePathRel,
      createdAt: payload.createdAt || now,
      updatedAt: now
    };

    const metaPath = path.join(basePathAbs, 'meta.json');
    writeJsonAtomic(metaPath, meta);

    const auditPath = path.join(basePathAbs, 'audit.json');
    if (!fs.existsSync(auditPath)) {
      writeJsonAtomic(auditPath, {
        docId: meta.docId || `LIA-WEB-${Date.now()}`,
        createdAt: now,
        updatedAt: now,
        basePath: basePathRel
      });
    }

    return res.json({
      ok: true,
      basePath: basePathRel,
      metaPath: path.join(basePathRel, 'meta.json'),
      slug,
      dateISO
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message || String(error) });
  }
});

app.post('/api/generar', async (req, res) => {
  try {
    const { basePath, docs } = req.body || {};
    if (!basePath) {
      return res.status(400).json({ ok: false, error: 'Falta basePath.' });
    }
    const docsType = docs || 'ambos';
    const basePathAbs = path.resolve(__dirname, basePath);
    if (!basePathAbs.startsWith(BASE_CLIENTS_DIR)) {
      return res.status(400).json({ ok: false, error: 'Ruta inválida.' });
    }

    const outputs = await generateFromMeta({ basePath: basePathAbs, docs: docsType });

    const responseOutputs = {};
    if (outputs.contratoPdfPath) {
      const rel = path.relative(__dirname, outputs.contratoPdfPath).replace(/\\/g, '/');
      responseOutputs.contratoPdfUrl = `/api/descargar?path=${encodeURIComponent(rel)}`;
    }
    if (outputs.pagaresPdfPath) {
      const rel = path.relative(__dirname, outputs.pagaresPdfPath).replace(/\\/g, '/');
      responseOutputs.pagaresPdfUrl = `/api/descargar?path=${encodeURIComponent(rel)}`;
    }

    return res.json({ ok: true, outputs: responseOutputs });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message || String(error) });
  }
});

app.get('/api/descargar', (req, res) => {
  const relPath = req.query.path;
  if (!relPath || typeof relPath !== 'string') {
    return res.status(400).send('Falta path.');
  }
  const absPath = path.resolve(__dirname, relPath);
  if (!absPath.startsWith(BASE_CLIENTS_DIR)) {
    return res.status(400).send('Ruta inválida.');
  }
  if (!fs.existsSync(absPath)) {
    return res.status(404).send('Archivo no encontrado.');
  }
  return res.download(absPath);
});

app.listen(PORT, () => {
  console.log(`LIA Pagaré web escuchando en http://localhost:${PORT}`);
});
