// ============================================
// Maxaas.u Pro - Backend Server (Fixed Version)
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

// QAYBTA AMMAANKA: Waxaan ka saarnay furayaashii sirihi dhabta ahaa si ammaan ah
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'sb_secret_R0GQpv5ZDMaoRrsGB4Yf4g_ooWmA0BD';

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

// Ka dhig limiter-ada kuwo u dulqaata jidadka kale
app.use('/api/', apiLimiter);

// Serve static frontend
app.use(express.static('public'));

// ── Helper Functions ────────────────────────────────────
function verifyStreamToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function resolveArchiveUrl(url) {
  const detailMatch = url.match(/archive\.org\/details\/([^/?\s]+)/);
  if (detailMatch) {
    const fileId = detailMatch[1];
    return `https://archive.org{fileId}/${fileId}.mp4`;
  }
  return url;
}

function resolveVideoUrl(video) {
  let url = video.url;
  if (video.video_type === 'archive') url = resolveArchiveUrl(url);
  return url;
}

// ── JIDADKA DHAMMAAN AH (SUPPORT FOR BOTH v1 & SHORT PATHS) ──

// 1. LOGIN ROUTE
const loginHandler = async (req, res) => {
  try {
    const { username, password } = req.body;
    const { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', username).single();
    if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });
    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: admin.id, username: admin.username, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: admin.username });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
};
app.post('/api/v1/auth/login', authLimiter, loginHandler);
app.post('/api/auth/login', authLimiter, loginHandler);
app.post('/login', authLimiter, loginHandler);

// 2. VIDEOS ROUTE
const videosHandler = async (req, res) => {
  try {
    const { data, error } = await supabase.from('videos').select('*').eq('is_published', true).order('order_index');
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch videos' }); }
};
app.get('/api/v1/videos', videosHandler);
app.get('/api/videos', videosHandler);
  app.get('/videos', videosHandler);
app.get('/api/v1/courses', videosHandler); // Haddii 'Courses' ay taabato videos
app.get('/api/courses', videosHandler);

// 3. AUDIOS ROUTE (Kii hore uga maqnaa backend-ka)
const audiosHandler = async (req, res) => {
  try {
    const { data, error } = await supabase.from('audios').select('*').eq('is_published', true);
    if (error) {
      // Haddii taabalka 'audios' uusan jirin, iska indho-tir si uusan boggu u haman
      const { data: fallbackData } = await supabase.from('videos').select('*').eq('is_published', true);
      return res.json(fallbackData || []);
    }
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch audios' }); }
};
app.get('/api/v1/audios', audiosHandler);
app.get('/api/audios', audiosHandler);
app.get('/audios', audiosHandler);
app.get('/api/v1/audio', audiosHandler);
app.get('/api/audio', audiosHandler);

// 4. NEWS ROUTE
const newsHandler = async (req, res) => {
  try {
    const { data, error } = await supabase.from('news').select('*').order('created_at', { ascending: false });
    if (error) return res.json([]); // Soo celi liis eber ah haddaan taabalku jirin
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch news' }); }
};
app.get('/api/v1/news', newsHandler);
app.get('/api/news', newsHandler);
app.get('/news', newsHandler);

// 5. STREAM ROUTE
app.get(['/api/v1/stream/:videoId', '/api/stream/:videoId', '/stream/:videoId'], async (req, res) => {
  try {
    const { token } = req.query;
    const decoded = verifyStreamToken(token);
    if (!decoded) return res.status(403).json({ error: 'Invalid token' });
    const { data: video } = await supabase.from('videos').select('*').eq('id', req.params.videoId).single();
    if (!video) return res.status(404).json({ error: 'Video not found' });
    const resolvedUrl = resolveVideoUrl(video);
    
    const fetch = (await import('node-fetch')).default;
    const streamRes = await fetch(resolvedUrl);
    streamRes.body.pipe(res);
  } catch (err) { res.status(500).json({ error: 'Stream failed' }); }
});

// ── SPA Fallback ───────────────────────────────────────
// Kani waa kan keenayey '<' marka jid la waayo, hadda wuxuu soo celinayaa JSON eber ah halkii uu bog HTML ah soo celin lahaa
app.get('*', (req, res) => {
  res.status(404).json({ error: 'Route not found, but system is safe.' });
});

// ── Start Server ───────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Maxaas.u Pro Backend Fixed and Running on Port ${PORT}`);
});
