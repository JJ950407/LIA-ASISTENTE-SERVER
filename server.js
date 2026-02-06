const path = require('path');
const fs = require('fs');
const express = require('express');
const dotenv = require('dotenv');
const { parseDateDMYLoose } = require('./src/parsers/date');
const { generateFromMeta } = require('./src/app/generateFromMeta');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
// PARCHE: Timeout extendido para generación de documentos
const GENERATION_TIMEOUT_MS = 180000; // 3 minutos
const BASE_CLIENTS_DIR = path.resolve(__dirname, 'data', 'clientes');
const ENABLE_AUTH = String(process.env.ENABLE_AUTH || '0') === '1';
const AUTH_USER = process.env.AUTH_USER;
const AUTH_PASS = process.env.AUTH_PASS;
const AUTH_REALM = process.env.AUTH_REALM || 'LIA Pagaré';
const LOGIN_USER = 'Isra';
const LOGIN_PASS = 'adein123';
const SESSION_COOKIE = 'lia_session';
const SESSION_VALUE = 'ok';

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
// Aplicar timeout extendido a todas las requests
app.use((req, res, next) => {
  req.setTimeout(GENERATION_TIMEOUT_MS);
  res.setTimeout(GENERATION_TIMEOUT_MS);
  next();
});

if (process.env.DEBUG_HTTP === '1') {
  app.use((req, res, next) => {
    const rid = `${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 6)}`;
    req._rid = rid;
    const t0 = Date.now();
    const ct = req.headers['content-type'] || '';
    const accept = req.headers.accept || '';
    const ip = req.ip;
    console.log(`[HTTP][RID=${rid}] IN ${req.method} ${req.originalUrl} ct=${ct} accept=${accept} ip=${ip}`);

    res.on('finish', () => {
      const ms = Date.now() - t0;
      console.log(`[HTTP][RID=${rid}] FINISH status=${res.statusCode} headersSent=${res.headersSent} ms=${ms}`);
    });
    res.on('close', () => {
      const ms = Date.now() - t0;
      console.log(`[HTTP][RID=${rid}] CLOSE status=${res.statusCode} headersSent=${res.headersSent} ms=${ms}`);
    });
    res.on('error', (err) => {
      console.log(`[HTTP][RID=${rid}] RES_ERROR ${err?.message || String(err)}`);
    });
    req.on('aborted', () => {
      console.log(`[HTTP][RID=${rid}] ABORTED`);
    });
    next();
  });
}

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

function parseCookies(req) {
  const header = req.headers.cookie || '';
  return header.split(';').reduce((acc, part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join('='));
    return acc;
  }, {});
}

function isPublicPath(req) {
  const publicPrefixes = ['/assets', '/login', '/login.css', '/login.js'];
  if (req.path === '/logout') return true;
  return publicPrefixes.some((prefix) => req.path.startsWith(prefix));
}

function requireAuth(req, res, next) {
  if (isPublicPath(req)) return next();
  const cookies = parseCookies(req);
  if (cookies[SESSION_COOKIE] === SESSION_VALUE) return next();
  return res.redirect('/login');
}

app.use(requireAuth);

function setNoCache(res) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
}

app.get('/', (req, res) => {
  setNoCache(res);
  res.setHeader('Vary', 'Cookie');
  return res.sendFile(path.join(__dirname, 'web', 'index.html'));
});

app.get('/index.html', (req, res) => {
  setNoCache(res);
  res.setHeader('Vary', 'Cookie');
  return res.sendFile(path.join(__dirname, 'web', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'web'), {
  etag: false,
  lastModified: false,
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
}));

app.get('/login', (req, res) => {
  setNoCache(res);
  res.sendFile(path.join(__dirname, 'web', 'login.html'));
});

app.post('/login', (req, res) => {
  const { usuario, contrasena } = req.body || {};
  if (usuario === LOGIN_USER && contrasena === LOGIN_PASS) {
    res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${SESSION_VALUE}; HttpOnly; Path=/; SameSite=Lax`);
    return res.redirect(303, '/');
  }
  return res.redirect('/login?error=1');
});

app.get('/logout', (req, res) => {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
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
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${req._rid}] RESPONDING kind=json status=400`);
      }
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

    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${req._rid}] RESPONDING kind=json status=200`);
    }
    return res.json({
      ok: true,
      basePath: basePathRel,
      metaPath: path.join(basePathRel, 'meta.json'),
      slug,
      dateISO
    });
  } catch (error) {
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${req._rid}] RESPONDING kind=json status=500`);
    }
    return res.status(500).json({ ok: false, error: error.message || String(error) });
  }
});

app.post('/api/generar', async (req, res) => {
  const rid = req._rid;
  const timeoutId = setTimeout(() => {
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] TIMEOUT_WARNING still_pending`);
    }
  }, 25000);
  res.once('finish', () => clearTimeout(timeoutId));
  res.once('close', () => clearTimeout(timeoutId));
  try {
    const { basePath, docs } = req.body || {};
    if (!basePath) {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=json status=400`);
      }
      return res.status(400).json({ ok: false, error: 'Falta basePath.' });
    }
    const docsType = docs || 'ambos';
    const basePathAbs = path.resolve(__dirname, basePath);
    if (!basePathAbs.startsWith(BASE_CLIENTS_DIR)) {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=json status=400`);
      }
      return res.status(400).json({ ok: false, error: 'Ruta inválida.' });
    }

    const outputs = await generateFromMeta({ basePath: basePathAbs, docs: docsType });

    const responseOutputs = {};
    if (outputs.contratoPdfPath) {
      const rel = path.relative(BASE_CLIENTS_DIR, outputs.contratoPdfPath).replace(/\\/g, '/');
      responseOutputs.contratoPdfUrl = `/api/descargar?path=${encodeURIComponent(rel)}`;
    }
    if (outputs.pagaresPdfPath) {
      const rel = path.relative(BASE_CLIENTS_DIR, outputs.pagaresPdfPath).replace(/\\/g, '/');
      responseOutputs.pagaresPdfUrl = `/api/descargar?path=${encodeURIComponent(rel)}`;
    }

    if (res.headersSent) {
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
      }
      return;
    }
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] RESPONDING kind=json status=200`);
    }
    return res.json({ ok: true, outputs: responseOutputs });
  } catch (error) {
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] HANDLER_ERROR ${error?.stack || error?.message || String(error)}`);
    }
    if (!res.headersSent) {
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=json status=500`);
      }
      return res.status(500).json({ ok: false, error: 'INTERNAL', rid });
    }
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] ERROR_AFTER_HEADERS`);
    }
  }
});

app.get('/api/descargar', (req, res) => {
  const rid = req._rid;
  const timeoutId = setTimeout(() => {
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] TIMEOUT_WARNING still_pending`);
    }
  }, 25000);
  res.once('finish', () => clearTimeout(timeoutId));
  res.once('close', () => clearTimeout(timeoutId));
  try {
    const relPath = req.query.path;
    if (!relPath || typeof relPath !== 'string') {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=text status=400`);
      }
      return res.status(400).send('Falta path.');
    }
    if (relPath.includes('\0')) {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=text status=400`);
      }
      return res.status(400).send('Ruta inválida.');
    }
    if (path.isAbsolute(relPath)) {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=text status=400`);
      }
      return res.status(400).send('Ruta inválida.');
    }
    const candidate = path.resolve(BASE_CLIENTS_DIR, relPath);
    const rel = path.relative(BASE_CLIENTS_DIR, candidate);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=text status=400`);
      }
      return res.status(400).send('Ruta inválida.');
    }
    const exists = fs.existsSync(candidate);
    if (process.env.DEBUG_DOWNLOADS === '1') {
      console.log('[DEBUG_DOWNLOADS]', {
        BASE_CLIENTS_DIR,
        relPath,
        candidate,
        rel,
        exists
      });
    }
    if (!exists) {
      if (res.headersSent) {
        if (process.env.DEBUG_HTTP === '1') {
          console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
        }
        return;
      }
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=text status=404`);
      }
      return res.status(404).send('Archivo no encontrado.');
    }
    if (res.headersSent) {
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] DOUBLE_RESPONSE_PREVENTED`);
      }
      return;
    }
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] RESPONDING kind=file status=200`);
    }
    return res.download(candidate);
  } catch (error) {
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] HANDLER_ERROR ${error?.stack || error?.message || String(error)}`);
    }
    if (!res.headersSent) {
      if (process.env.DEBUG_HTTP === '1') {
        console.log(`[HTTP][RID=${rid}] RESPONDING kind=json status=500`);
      }
      return res.status(500).json({ ok: false, error: 'INTERNAL', rid });
    }
    if (process.env.DEBUG_HTTP === '1') {
      console.log(`[HTTP][RID=${rid}] ERROR_AFTER_HEADERS`);
    }
  }
});

app.listen(PORT, () => {
  console.log(`LIA Pagaré web escuchando en http://localhost:${PORT}`);
});
