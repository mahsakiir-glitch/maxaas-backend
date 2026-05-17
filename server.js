// ============================================================
// MediaVault — Secure Media Platform Backend
// Express 5 + Supabase + JWT Auth + Proxy Streaming
// ============================================================

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

// ============ CONFIG ============
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PIN = process.env.ADMIN_PIN || '12345678';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const IS_PROD = process.env.NODE_ENV === 'production';

const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = createClient(
  process.env.SUPABASE_URL,
  SUPABASE_KEY
);

// STARTUP CHECK: Warn if service key is missing
if (!process.env.SUPABASE_SERVICE_KEY) {
  console.log('WARNING: SUPABASE_SERVICE_KEY not set! Using anon key. Admin operations may fail with RLS.');
} else {
  console.log('SUPABASE_SERVICE_KEY detected. Admin operations should work.');
}

// ============ APP ============
const app = express();

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  referrerPolicy: { policy: 'no-referrer' },
}));

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));

app.use(compression());
app.use(express.json({ limit: '1mb' }));

// ============ RATE LIMITERS ============
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded' },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  message: { error: 'Too many attempts' },
});
const streamLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 80,
  message: { error: 'Stream rate limit' },
});
const guestLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  message: { error: 'Guest token limit' },
});

app.use(globalLimiter);

app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'public, max-age=300');
  },
}));

// ============ AUTH MIDDLEWARE ============
function extractToken(req) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) return authHeader.slice(7);
  if (req.query && req.query.token) return req.query.token;
  return null;
}

function verifyToken(req, res, next) {
  const token = extractToken(req);
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded.role) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token expired or invalid' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Auth required' });
    if (req.user.role === 'super_admin') return next();
    if (req.user.permissions && req.user.permissions.all) return next();
    if (req.user.permissions && req.user.permissions[permission]) return next();
    return res.status(403).json({ error: 'Insufficient permissions' });
  };
}

function checkReferer(req, res, next) {
  if (IS_PROD && req.headers.referer) {
    const allowed = [process.env.FRONTEND_URL, 'https://b-rxig.onrender.com'];
    if (!allowed.some(u => req.headers.referer.startsWith(u))) {
      return res.status(403).send('Hotlinking denied');
    }
  }
  next();
}

// ============ AUTH ROUTES ============

app.post('/api/auth/guest', guestLimiter, (req, res) => {
  const token = jwt.sign(
    { id: 'guest', role: 'guest', permissions: { stream: true } },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
  res.json({ success: true, token });
});

app.post('/api/auth/signin', authLimiter, async (req, res) => {
  try {
    const { username, pin, password } = req.body;
    if (!username || !pin || !password) {
      return res.status(200).json({ success: false });
    }

    if (username === ADMIN_USERNAME && pin === ADMIN_PIN && password === ADMIN_PASSWORD) {
      const token = jwt.sign(
        { id: 'super_admin', username: ADMIN_USERNAME, role: 'super_admin', permissions: { all: true } },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      return res.json({
        success: true,
        token,
        user: { username: ADMIN_USERNAME, role: 'super_admin', permissions: { all: true } },
      });
    }

    const { data: admin } = await supabase
      .from('admins')
      .select('*')
      .eq('username', username)
      .eq('pin', pin)
      .single();

    if (admin) {
      const hash = crypto.createHash('sha256').update(password).digest('hex');
      if (admin.password_hash === hash) {
        const token = jwt.sign(
          { id: admin.id, username: admin.username, role: admin.role, permissions: admin.permissions || {} },
          JWT_SECRET,
          { expiresIn: '24h' }
        );
        return res.json({
          success: true,
          token,
          user: { username: admin.username, role: admin.role, permissions: admin.permissions },
        });
      }
    }

    return res.status(200).json({ success: false });
  } catch (e) {
    return res.status(200).json({ success: false });
  }
});

app.get('/api/auth/verify', verifyToken, (req, res) => {
  res.json({
    valid: true,
    user: { username: req.user.username || 'guest', role: req.user.role, permissions: req.user.permissions },
  });
});

app.post('/api/auth/signout', (req, res) => {
  res.json({ success: true });
});

// ============ PUBLIC CONTENT ============

app.get('/api/menu', async (req, res) => {
  try {
    const { data } = await supabase
      .from('menu_items')
      .select('*')
      .eq('is_active', true)
      .order('sort_order', { ascending: true });
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.get('/api/videos', async (req, res) => {
  try {
    const { category, sort, limit, offset } = req.query;
    let q = supabase
      .from('videos')
      .select('id, title, category, views, is_featured, created_at, description, sort_order')
      .order('created_at', { ascending: false });

    if (category && category !== 'all') q = q.eq('category', category);
    if (sort === 'top') q = q.order('views', { ascending: false });
    if (sort === 'latest') q = q.order('created_at', { ascending: false });
    if (limit) q = q.limit(parseInt(limit));
    if (offset && limit) q = q.range(parseInt(offset), parseInt(offset) + parseInt(limit) - 1);

    const { data } = await q;
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.get('/api/videos/featured', async (req, res) => {
  try {
    const { data } = await supabase
      .from('videos')
      .select('id, title, category, views, is_featured, created_at, description')
      .eq('is_featured', true)
      .order('created_at', { ascending: false })
      .limit(1);
    res.json(data && data.length > 0 ? data[0] : null);
  } catch (e) { res.json(null); }
});

app.get('/api/videos/:id', async (req, res) => {
  try {
    const { data } = await supabase
      .from('videos')
      .select('id, title, category, views, description, created_at')
      .eq('id', req.params.id)
      .single();
    if (!data) return res.status(404).json({ error: 'Not found' });
    supabase.from('videos').update({ views: (data.views || 0) + 1 }).eq('id', req.params.id).then(function() {});
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/audio', async (req, res) => {
  try {
    const { data } = await supabase
      .from('audio')
      .select('id, title, category, duration, created_at, description')
      .order('created_at', { ascending: false });
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.get('/api/news', async (req, res) => {
  try {
    const { data } = await supabase
      .from('news')
      .select('id, title, content, image_path, post_type, audio_path, created_at')
      .order('created_at', { ascending: false })
      .limit(200);
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.get('/api/lessons/:videoId', async (req, res) => {
  try {
    const { data } = await supabase
      .from('lesson_lists')
      .select('id, title, linked_video_id, sort_order')
      .eq('video_id', req.params.videoId)
      .order('sort_order', { ascending: true });
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.get('/api/categories', async (req, res) => {
  try {
    const { data } = await supabase.from('videos').select('category');
    const cats = [];
    (data || []).forEach(function(v) {
      if (v.category && cats.indexOf(v.category) === -1) cats.push(v.category);
    });
    res.json(cats);
  } catch (e) { res.json([]); }
});

app.get('/api/names', async (req, res) => {
  try {
    const { data } = await supabase.from('videos').select('id, title, category').order('title', { ascending: true });
    res.json(data || []);
  } catch (e) { res.json([]); }
});

// ============ PROXY STREAMING ============

async function proxyStream(storagePath, req, res) {
  const serviceKey = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;
  var targetUrl;

  if (storagePath.indexOf('http://') === 0 || storagePath.indexOf('https://') === 0) {
    try {
      var parsed = new URL(storagePath);
      var blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
      if (blocked.indexOf(parsed.hostname) !== -1 || parsed.hostname.indexOf('192.168.') === 0 || parsed.hostname.indexOf('10.') === 0) {
        return res.status(400).send('Invalid source');
      }
      targetUrl = storagePath;
    } catch (e) {
      return res.status(400).send('Invalid URL');
    }
  } else {
    targetUrl = process.env.SUPABASE_URL + '/storage/v1/object/media/' + storagePath;
  }

  var fetchHeaders = { 'Authorization': 'Bearer ' + serviceKey };
  if (req.headers.range) fetchHeaders['Range'] = req.headers.range;

  try {
    var upstream = await fetch(targetUrl, { headers: fetchHeaders });
    if (!upstream.ok) {
      return res.status(upstream.status === 404 ? 404 : 502).send('Stream unavailable');
    }

    res.status(upstream.status);
    var hNames = ['content-type', 'content-range', 'content-length', 'accept-ranges'];
    hNames.forEach(function(h) {
      var v = upstream.headers.get(h);
      if (v) res.setHeader(h, v);
    });

    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Disposition', 'inline');

    var reader = upstream.body.getReader();
    var aborted = false;
    req.on('close', function() {
      aborted = true;
      reader.cancel().catch(function() {});
    });

    var pump = async function() {
      try {
        while (!aborted) {
          var result = await reader.read();
          if (result.done) break;
          if (!res.destroyed && !aborted) {
            res.write(Buffer.from(result.value));
          }
        }
      } catch (e) { /* client disconnected */ }
      if (!res.destroyed) res.end();
    };
    pump();
  } catch (e) {
    if (!res.headersSent) res.status(502).send('Stream error');
    else res.end();
  }
}

app.get('/api/stream/video/:id', streamLimiter, checkReferer, verifyToken, async (req, res) => {
  try {
    var { data: video } = await supabase
      .from('videos')
      .select('storage_path, access_key')
      .eq('id', req.params.id)
      .single();
    if (!video) return res.status(404).send('Not found');
    if (video.access_key && req.query.key !== video.access_key) return res.status(403).send('Access denied');
    await proxyStream(video.storage_path, req, res);
  } catch (e) {
    if (!res.headersSent) res.status(500).send('Server error');
  }
});

app.get('/api/stream/audio/:id', streamLimiter, checkReferer, verifyToken, async (req, res) => {
  try {
    var { data: audio } = await supabase
      .from('audio')
      .select('storage_path')
      .eq('id', req.params.id)
      .single();
    if (!audio) return res.status(404).send('Not found');
    await proxyStream(audio.storage_path, req, res);
  } catch (e) {
    if (!res.headersSent) res.status(500).send('Server error');
  }
});

app.get('/api/stream/image/:id', verifyToken, async (req, res) => {
  try {
    var { data: item } = await supabase
      .from('news')
      .select('image_path')
      .eq('id', req.params.id)
      .single();
    if (!item || !item.image_path) return res.status(404).send('Not found');
    await proxyStream(item.image_path, req, res);
  } catch (e) {
    if (!res.headersSent) res.status(500).send('Server error');
  }
});

// ============ ADMIN ROUTES ============

app.get('/api/admin/stats', verifyToken, requireAdmin, async (req, res) => {
  try {
    var results = await Promise.all([
      supabase.from('videos').select('id', { count: 'exact', head: true }),
      supabase.from('audio').select('id', { count: 'exact', head: true }),
      supabase.from('news').select('id', { count: 'exact', head: true }),
      supabase.from('admins').select('id', { count: 'exact', head: true }),
    ]);
    res.json({
      videos: results[0].count || 0,
      audio: results[1].count || 0,
      news: results[2].count || 0,
      admins: results[3].count || 0,
    });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- VIDEO CRUD ----
app.post('/api/admin/videos', verifyToken, requirePermission('video'), async (req, res) => {
  try {
    var { title, storage_path, category, access_key, description, is_featured } = req.body;
    if (!title || !storage_path) return res.status(400).json({ error: 'Title and path required' });
    var { data, error } = await supabase
      .from('videos')
      .insert({
        title: title,
        storage_path: storage_path,
        category: category || 'general',
        access_key: access_key || null,
        description: description || null,
        is_featured: is_featured || false,
      })
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/videos/:id', verifyToken, requirePermission('video'), async (req, res) => {
  try {
    var { title, storage_path, category, access_key, description, is_featured } = req.body;
    var { data, error } = await supabase
      .from('videos')
      .update({ title: title, storage_path: storage_path, category: category, access_key: access_key, description: description, is_featured: is_featured })
      .eq('id', req.params.id)
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/videos/:id', verifyToken, requirePermission('video'), async (req, res) => {
  try {
    var { error } = await supabase.from('videos').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- AUDIO CRUD ----
app.post('/api/admin/audio', verifyToken, requirePermission('audio'), async (req, res) => {
  try {
    var { title, storage_path, category, description, duration } = req.body;
    if (!title || !storage_path) return res.status(400).json({ error: 'Title and path required' });
    var { data, error } = await supabase
      .from('audio')
      .insert({ title: title, storage_path: storage_path, category: category || 'general', description: description, duration: duration })
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/audio/:id', verifyToken, requirePermission('audio'), async (req, res) => {
  try {
    var { title, storage_path, category, description, duration } = req.body;
    var { data, error } = await supabase
      .from('audio')
      .update({ title: title, storage_path: storage_path, category: category, description: description, duration: duration })
      .eq('id', req.params.id)
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/audio/:id', verifyToken, requirePermission('audio'), async (req, res) => {
  try {
    var { error } = await supabase.from('audio').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- NEWS CRUD ----
app.post('/api/admin/news', verifyToken, requirePermission('news'), async (req, res) => {
  try {
    var { title, content, image_path, post_type, audio_path } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    var { data, error } = await supabase
      .from('news')
      .insert({ title: title, content: content, image_path: image_path, post_type: post_type || 'text', audio_path: audio_path })
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/news/:id', verifyToken, requirePermission('news'), async (req, res) => {
  try {
    var { title, content, image_path, post_type, audio_path } = req.body;
    var { data, error } = await supabase
      .from('news')
      .update({ title: title, content: content, image_path: image_path, post_type: post_type, audio_path: audio_path })
      .eq('id', req.params.id)
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/news/:id', verifyToken, requirePermission('news'), async (req, res) => {
  try {
    var { error } = await supabase.from('news').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- MENU MANAGEMENT ----
app.get('/api/admin/menu', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { data } = await supabase.from('menu_items').select('*').order('sort_order', { ascending: true });
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.post('/api/admin/menu', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { label, route, sort_order } = req.body;
    if (!label || !route) return res.status(400).json({ error: 'Label and route required' });
    var { data, error } = await supabase
      .from('menu_items').insert({ label: label, route: route, sort_order: sort_order || 0 }).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/menu/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { label, route, sort_order, is_active } = req.body;
    var { data, error } = await supabase
      .from('menu_items').update({ label: label, route: route, sort_order: sort_order, is_active: is_active }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/menu/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { error } = await supabase.from('menu_items').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- LESSON MANAGEMENT ----
app.post('/api/admin/lessons', verifyToken, requirePermission('video'), async (req, res) => {
  try {
    var { video_id, title, linked_video_id, sort_order } = req.body;
    if (!video_id || !title) return res.status(400).json({ error: 'Video ID and title required' });
    var { data, error } = await supabase
      .from('lesson_lists')
      .insert({ video_id: video_id, title: title, linked_video_id: linked_video_id || null, sort_order: sort_order || 0 })
      .select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/lessons/:id', verifyToken, requirePermission('video'), async (req, res) => {
  try {
    var { title, linked_video_id, sort_order } = req.body;
    var { data, error } = await supabase
      .from('lesson_lists').update({ title: title, linked_video_id: linked_video_id, sort_order: sort_order }).eq('id', req.params.id).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/lessons/:id', verifyToken, requirePermission('video'), async (req, res) => {
  try {
    var { error } = await supabase.from('lesson_lists').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- SUB-ADMIN MANAGEMENT ----
app.get('/api/admin/subadmins', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { data } = await supabase.from('admins').select('id, username, role, permissions, created_at').order('created_at', { ascending: false });
    res.json(data || []);
  } catch (e) { res.json([]); }
});

app.post('/api/admin/subadmins', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { username, password, pin, permissions } = req.body;
    if (!username || !password || !pin) return res.status(400).json({ error: 'All fields required' });
    var hash = crypto.createHash('sha256').update(password).digest('hex');
    var { data, error } = await supabase
      .from('admins')
      .insert({ username: username, password_hash: hash, pin: pin, role: 'sub_admin', permissions: permissions || {} })
      .select('id, username, role, permissions, created_at')
      .single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/admin/subadmins/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { username, password, pin, permissions } = req.body;
    var updates = { username: username, pin: pin, permissions: permissions || {} };
    if (password) updates.password_hash = crypto.createHash('sha256').update(password).digest('hex');
    var { data, error } = await supabase
      .from('admins').update(updates).eq('id', req.params.id).select('id, username, role, permissions, created_at').single();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.delete('/api/admin/subadmins/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { error } = await supabase.from('admins').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ---- SETTINGS ----
app.get('/api/admin/settings', verifyToken, requireAdmin, async (req, res) => {
  try {
    var { data } = await supabase.from('settings').select('*');
    var obj = {};
    (data || []).forEach(function(s) { obj[s.key] = s.value; });
    res.json(obj);
  } catch (e) { res.json({}); }
});

app.put('/api/admin/settings', verifyToken, requireAdmin, async (req, res) => {
  try {
    var updates = req.body;
    var keys = Object.keys(updates);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var value = updates[key];
      await supabase.from('settings').upsert({ key: key, value: value }, { onConflict: 'key' });
    }
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

// ============ SPA FALLBACK ============
app.use(function(req, res, next) {
  if (req.method === 'GET' && req.path.indexOf('/api/') !== 0) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    next();
  }
});

// ============ ERROR HANDLER ============
app.use(function(err, req, res, next) {
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ============ START ============
app.listen(PORT, function() {
  console.log('MediaVault running on port ' + PORT + ' [' + (IS_PROD ? 'production' : 'development') + ']');
  console.log('Security: media URLs are never exposed to the browser');
});