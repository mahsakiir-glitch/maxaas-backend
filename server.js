// ============================================
// Maxaas.u Pro - Backend Server
// Production-ready Node.js/Express API
// ============================================

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Environment Configuration ──────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Halkan ayaan si toos ah u geliyey xogtaada si uusan qalad dambe u dhicin
const SUPABASE_URL = 'https://aoxclvpbdoxklwfrumhr.supabase.co';
const SUPABASE_KEY = 'sb_secret_R0GQpv5ZDMaoRrsGB4Yf4g_ooWmA0BD';

const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';

// Xiriirka Supabase
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Middleware ──────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many attempts. Try again later.' },
});
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 120,
  message: { error: 'Rate limit exceeded.' },
});
app.use('/api/v1/auth', authLimiter);
app.use('/api/v1', apiLimiter);

// Serve static frontend
app.use(express.static('public'));

// ── Auth Middleware ─────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    const decoded = jwt.verify(token, ADMIN_JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function generateStreamToken(videoId) {
  return jwt.sign({ videoId, type: 'stream' }, JWT_SECRET, { expiresIn: '2h' });
}

function verifyStreamToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// ── Helper: Convert Archive.org share links ────────────
function resolveArchiveUrl(url) {
  const detailMatch = url.match(/archive\.org\/details\/([^/?\s]+)/);
  if (detailMatch) {
    const fileId = detailMatch[1];
    return `https://archive.org/download/${fileId}/${fileId}.mp4`;
  }
  return url;
}

// ── Helper: Resolve video URL based on type ────────────
function resolveVideoUrl(video) {
  let url = video.url;
  switch (video.video_type) {
    case 'archive':
      url = resolveArchiveUrl(url);
      break;
    case 'ipfs':
      if (url.startsWith('ipfs://')) {
        const gateway = process.env.IPFS_GATEWAY || 'https://gateway.pinata.cloud';
        url = url.replace('ipfs://', `${gateway}/ipfs/`);
      }
      break;
    default:
      break;
  }
  return url;
}

// ── Helper: Proxy fetch with range request ─────────────
async function proxyStreamWithRange(req, res, url) {
  const fetch = (await import('node-fetch')).default;
  try {
    const headRes = await fetch(url, { method: 'HEAD' });
    const totalSize = parseInt(headRes.headers.get('content-length') || '0', 10);
    const contentType = headRes.headers.get('content-type') || 'video/mp4';

    const range = req.headers.range;
    if (range && totalSize > 0) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;
      const chunkSize = end - start + 1;

      const streamRes = await fetch(url, {
        headers: { Range: `bytes=${start}-${end}` },
      });

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${totalSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunkSize,
        'Content-Type': contentType,
      });
      streamRes.body.pipe(res);
    } else {
      const streamRes = await fetch(url);
      res.writeHead(200, {
        'Content-Length': totalSize,
        'Content-Type': contentType,
        'Accept-Ranges': 'bytes',
      });
      streamRes.body.pipe(res);
    }
  } catch (err) {
    res.status(502).json({ error: 'Stream fetch failed' });
  }
}

// ── PUBLIC API ROUTES ──────────────────────────────────

// Login
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', username).single();
    if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: admin.id, username: admin.username, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: admin.username });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

// Get Videos
app.get('/api/v1/videos', async (req, res) => {
  try {
    const { data, error } = await supabase.from('videos').select('*').eq('is_published', true).order('order_index');
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch videos' }); }
});

// Stream Video
app.get('/api/v1/stream/:videoId', async (req, res) => {
  try {
    const { token } = req.query;
    const decoded = verifyStreamToken(token);
    if (!decoded) return res.status(403).json({ error: 'Invalid token' });
    const { data: video } = await supabase.from('videos').select('*').eq('id', req.params.videoId).single();
    if (!video) return res.status(404).json({ error: 'Video not found' });
    const resolvedUrl = resolveVideoUrl(video);
    await proxyStreamWithRange(req, res, resolvedUrl);
  } catch (err) { res.status(500).json({ error: 'Stream failed' }); }
});

// ── SPA Fallback ───────────────────────────────────────
app.get('*', (req, res) => {
  res.send('Maxaas.u Pro API is running...');
});

// ── Start Server ───────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ============================================
  🚀 Maxaas.u Pro Backend Connected!
  📡 Port: ${PORT}
  🔗 Supabase: ${SUPABASE_URL}
  ============================================
  `);
});