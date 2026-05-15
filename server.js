require('dotenv').config();
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

// ── Environment Variables ──
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('FATAL: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in Render Environment Variables');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ── Middleware ──
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts' } });
const apiLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 120, message: { error: 'Rate limit exceeded' } });
app.use('/api/v1/auth', authLimiter);
app.use('/api/v1', apiLimiter);

app.use(express.static('public'));

// ── Helper Functions ──
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    req.admin = jwt.verify(token, ADMIN_JWT_SECRET);
    next();
  } catch (err) { return res.status(403).json({ error: 'Invalid or expired token' }); }
}

function generateStreamToken(videoId) { return jwt.sign({ videoId, type: 'stream' }, JWT_SECRET, { expiresIn: '2h' }); }
function verifyStreamToken(token) { try { return jwt.verify(token, JWT_SECRET); } catch { return null; } }

function resolveArchiveUrl(url) {
  const m = url.match(/archive\.org\/details\/([^/?\s]+)/);
  return m ? `https://archive.org/download/${m[1]}/${m[1]}.mp4` : url;
}

function resolveVideoUrl(video) {
  let url = video.url;
  if (video.video_type === 'archive') url = resolveArchiveUrl(url);
  if (video.video_type === 'ipfs' && url.startsWith('ipfs://')) url = url.replace('ipfs://', `${process.env.IPFS_GATEWAY || 'https://gateway.pinata.cloud'}/ipfs/`);
  return url;
}

// ── Auto Admin Setup ──
async function setupDefaultAdmin() {
  try {
    const { data: admins } = await supabase.from('admin_users').select('id').limit(1);
    if (!admins || admins.length === 0) {
      const hash = await bcrypt.hash('Admin@2024', 12);
      await supabase.from('admin_users').insert({ username: 'admin', password_hash: hash, pin: '12345678' });
      console.log('Default admin created: admin / Admin@2024 / PIN: 12345678');
    }
  } catch (e) { console.error('Admin setup check error:', e.message); }
}
setupDefaultAdmin();

// ══════════════════════════════════════════════════
// PUBLIC API ROUTES
// ══════════════════════════════════════════════════

app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', username).single();
    if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: admin.id, username: admin.username, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: admin.username });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/v1/videos', async (req, res) => {
  try {
    let q = supabase.from('videos').select('id, title, description, video_type, thumbnail, category_id, order_index, is_featured, duration, views, created_at').eq('is_published', true).order('order_index', { ascending: true });
    if (req.query.category_id) q = q.eq('category_id', req.query.category_id);
    if (req.query.featured === 'true') q = q.eq('is_featured', true);
    const { data, error } = await q;
    if (error) throw error;
    res.json(data || []);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch videos' }); }
});

app.get('/api/v1/stream-token/:videoId', async (req, res) => {
  try {
    const { data: video } = await supabase.from('videos').select('id, is_published').eq('id', req.params.videoId).eq('is_published', true).single();
    if (!video) return res.status(404).json({ error: 'Video not found' });
    const token = generateStreamToken(video.id);
    res.json({ token, streamUrl: `/api/v1/stream/${video.id}?token=${token}` });
  } catch (e) { res.status(500).json({ error: 'Failed to generate token' }); }
});

app.get('/api/v1/stream/:videoId', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(401).json({ error: 'Stream token required' });
    const decoded = verifyStreamToken(token);
    if (!decoded || decoded.videoId !== req.params.videoId) return res.status(403).json({ error: 'Invalid token' });
    
    const { data: video } = await supabase.from('videos').select('*').eq('id', req.params.videoId).single();
    if (!video) return res.status(404).json({ error: 'Video not found' });
    
    const url = resolveVideoUrl(video);
    supabase.from('videos').update({ views: (video.views || 0) + 1 }).eq('id', video.id).then(() => {});
    
    const fetch = (await import('node-fetch')).default;
    const headRes = await fetch(url, { method: 'HEAD' });
    const totalSize = parseInt(headRes.headers.get('content-length') || '0', 10);
    const contentType = headRes.headers.get('content-type') || 'video/mp4';
    const range = req.headers.range;

    if (range && totalSize > 0) {
      const parts = range.replace(/bytes=/, '').split('-');
      const start = parseInt(parts[0], 10);
      const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;
      const streamRes = await fetch(url, { headers: { Range: `bytes=${start}-${end}` } });
      res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${totalSize}`, 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1, 'Content-Type': contentType });
      streamRes.body.pipe(res);
    } else {
      const streamRes = await fetch(url);
      res.writeHead(200, { 'Content-Length': totalSize, 'Content-Type': contentType, 'Accept-Ranges': 'bytes' });
      streamRes.body.pipe(res);
    }
  } catch (e) { res.status(500).json({ error: 'Stream failed' }); }
});

app.get('/api/v1/categories', async (req, res) => {
  try { const { data } = await supabase.from('categories').select('*').eq('is_active', true).order('order_index'); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/v1/posts', async (req, res) => {
  try { const { data } = await supabase.from('posts').select('*').eq('is_published', true).order('created_at', { ascending: false }); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/v1/audio', async (req, res) => {
  try { const { data } = await supabase.from('audio_tracks').select('id, title, artist, cover_url, duration, category').eq('is_published', true).order('created_at', { ascending: false }); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/v1/audio-token/:trackId', async (req, res) => {
  try {
    const { data } = await supabase.from('audio_tracks').select('id').eq('id', req.params.trackId).eq('is_published', true).single();
    if (!data) return res.status(404).json({ error: 'Not found' });
    const token = generateStreamToken(data.id);
    res.json({ token, streamUrl: `/api/v1/audio-stream/${data.id}?token=${token}` });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/v1/audio-stream/:trackId', async (req, res) => {
  try {
    const { token } = req.query; if (!token) return res.status(401).json({ error: 'Token required' });
    const decoded = verifyStreamToken(token); if (!decoded) return res.status(403).json({ error: 'Invalid' });
    const { data } = await supabase.from('audio_tracks').select('url').eq('id', req.params.trackId).single();
    if (!data) return res.status(404).json({ error: 'Not found' });
    const url = resolveArchiveUrl(data.url);
    const fetch = (await import('node-fetch')).default;
    const streamRes = await fetch(url);
    res.setHeader('Content-Type', streamRes.headers.get('content-type') || 'audio/mpeg');
    streamRes.body.pipe(res);
  } catch(e) { res.status(500).json({ error: 'Stream failed' }); }
});

app.get('/api/v1/settings', async (req, res) => {
  try { const { data } = await supabase.from('settings').select('*'); const s = {}; (data||[]).forEach(i => s[i.key] = i.value); res.json(s); } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/v1/contacts', async (req, res) => {
  try {
    const { alias_name, contact_method, message_type, message } = req.body;
    if (!alias_name || !message_type || !message) return res.status(400).json({ error: 'Missing fields' });
    if (!['suggestion','report','broken_video','new_request'].includes(message_type)) return res.status(400).json({ error: 'Invalid type' });
    const { data, error } = await supabase.from('contacts').insert({ alias_name, contact_method, message_type, message }).select().single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch(e) { res.status(500).json({ error: 'Failed to submit' }); }
});

// ══════════════════════════════════════════════════
// ADMIN API ROUTES (Protected)
// ══════════════════════════════════════════════════

app.get('/api/v1/admin/videos', authenticateToken, async (req, res) => { try { const { data } = await supabase.from('videos').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/v1/admin/videos', authenticateToken, async (req, res) => { try { const { title, description, url, video_type, thumbnail, category_id, is_featured, is_published, duration } = req.body; if (!title || !url) return res.status(400).json({ error: 'Title and URL required' }); const { data, error } = await supabase.from('videos').insert({ title, description, url, video_type: video_type || 'mp4', thumbnail, category_id: category_id || null, is_featured: is_featured || false, is_published: is_published !== false, duration: duration || '0:00' }).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.put('/api/v1/admin/videos/:id', authenticateToken, async (req, res) => { try { const { data, error } = await supabase.from('videos').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.delete('/api/v1/admin/videos/:id', authenticateToken, async (req, res) => { try { const { error } = await supabase.from('videos').delete().eq('id', req.params.id); if (error) throw error; res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.get('/api/v1/admin/categories', authenticateToken, async (req, res) => { try { const { data } = await supabase.from('categories').select('*').order('order_index'); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/v1/admin/categories', authenticateToken, async (req, res) => { try { const { name, description, icon, order_index } = req.body; if (!name) return res.status(400).json({ error: 'Name required' }); const { data, error } = await supabase.from('categories').insert({ name, description, icon: icon || 'fa-folder', order_index: order_index || 0 }).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.put('/api/v1/admin/categories/:id', authenticateToken, async (req, res) => { try { const { data, error } = await supabase.from('categories').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.delete('/api/v1/admin/categories/:id', authenticateToken, async (req, res) => { try { const { error } = await supabase.from('categories').delete().eq('id', req.params.id); if (error) throw error; res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.get('/api/v1/admin/posts', authenticateToken, async (req, res) => { try { const { data } = await supabase.from('posts').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/v1/admin/posts', authenticateToken, async (req, res) => { try { const { title, content, author, image_url, is_published } = req.body; if (!title || !content) return res.status(400).json({ error: 'Title and content required' }); const { data, error } = await supabase.from('posts').insert({ title, content, author: author || 'Maxaas.u Official', image_url, is_published: is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.put('/api/v1/admin/posts/:id', authenticateToken, async (req, res) => { try { const { data, error } = await supabase.from('posts').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.delete('/api/v1/admin/posts/:id', authenticateToken, async (req, res) => { try { const { error } = await supabase.from('posts').delete().eq('id', req.params.id); if (error) throw error; res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.get('/api/v1/admin/audio', authenticateToken, async (req, res) => { try { const { data } = await supabase.from('audio_tracks').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.post('/api/v1/admin/audio', authenticateToken, async (req, res) => { try { const { title, artist, url, cover_url, duration, category, is_published } = req.body; if (!title || !url) return res.status(400).json({ error: 'Title and URL required' }); const { data, error } = await supabase.from('audio_tracks').insert({ title, artist, url, cover_url, duration: duration || '0:00', category: category || 'General', is_published: is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.put('/api/v1/admin/audio/:id', authenticateToken, async (req, res) => { try { const { data, error } = await supabase.from('audio_tracks').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.delete('/api/v1/admin/audio/:id', authenticateToken, async (req, res) => { try { const { error } = await supabase.from('audio_tracks').delete().eq('id', req.params.id); if (error) throw error; res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.get('/api/v1/admin/contacts', authenticateToken, async (req, res) => { try { const { data } = await supabase.from('contacts').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.put('/api/v1/admin/contacts/:id', authenticateToken, async (req, res) => { try { const updates = {}; if (req.body.is_read !== undefined) updates.is_read = req.body.is_read; if (req.body.admin_response !== undefined) updates.admin_response = req.body.admin_response; const { data, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch(e) { res.status(500).json({ error: 'Failed' }); } });
app.delete('/api/v1/admin/contacts/:id', authenticateToken, async (req, res) => { try { const { error } = await supabase.from('contacts').delete().eq('id', req.params.id); if (error) throw error; res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.put('/api/v1/admin/settings', authenticateToken, async (req, res) => { try { for (const [key, value] of Object.entries(req.body)) { await supabase.from('settings').upsert({ key, value, updated_at: new Date().toISOString() }); } res.json({ success: true }); } catch(e) { res.status(500).json({ error: 'Failed' }); } });

app.put('/api/v1/admin/credentials', authenticateToken, async (req, res) => {
  try {
    const { pin, new_username, new_password, new_pin } = req.body;
    const { data: admin } = await supabase.from('admin_users').select('*').eq('id', req.admin.id).single();
    if (!admin || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });
    const updates = {};
    if (new_username) updates.username = new_username;
    if (new_password) updates.password_hash = await bcrypt.hash(new_password, 12);
    if (new_pin) updates.pin = new_pin;
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No changes' });
    const { error } = await supabase.from('admin_users').update(updates).eq('id', req.admin.id);
    if (error) throw error;
    let newToken;
    if (new_username) newToken = jwt.sign({ id: req.admin.id, username: new_username, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    res.json({ success: true, token: newToken });
  } catch(e) { res.status(500).json({ error: 'Failed' }); }
});

// ── SPA Fallback ──
app.get('*', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

app.listen(PORT, () => {
  console.log(`Maxaas.u Pro running on port ${PORT}`);
});