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
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error('ERROR: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set');
  process.exit(1);
}

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
    case 'm3u8':
      // Keep as is - HLS proxy will handle it
      break;
    default:
      break;
  }
  return url;
}

// ── Helper: Proxy fetch with range support ─────────────
async function proxyStream(res, url, reqHeaders = {}) {
  const fetch = (await import('node-fetch')).default;
  const headers = { ...reqHeaders };
  delete headers.host;
  delete headers.connection;

  try {
    const response = await fetch(url, { headers });
    const contentType = response.headers.get('content-type') || 'video/mp4';
    const contentLength = response.headers.get('content-length');

    res.setHeader('Content-Type', contentType);
    res.setHeader('Accept-Ranges', 'bytes');
    if (contentLength) res.setHeader('Content-Length', contentLength);
    res.setHeader('Cache-Control', 'public, max-age=3600');

    response.body.pipe(res);
    response.body.on('error', () => res.end());
  } catch (err) {
    console.error('Stream proxy error:', err.message);
    res.status(502).json({ error: 'Failed to fetch stream' });
  }
}

// ── Helper: Proxy fetch with range request ─────────────
async function proxyStreamWithRange(req, res, url) {
  const fetch = (await import('node-fetch')).default;

  try {
    // First, get content info with HEAD request
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
        'Cache-Control': 'public, max-age=3600',
      });

      streamRes.body.pipe(res);
      streamRes.body.on('error', () => res.end());
    } else {
      // No range - stream full content
      const streamRes = await fetch(url);
      res.writeHead(200, {
        'Content-Length': totalSize,
        'Content-Type': contentType,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'public, max-age=3600',
      });
      streamRes.body.pipe(res);
      streamRes.body.on('error', () => res.end());
    }
  } catch (err) {
    console.error('Range stream error:', err.message);
    res.status(502).json({ error: 'Stream fetch failed' });
  }
}

// ── Helper: Rewrite M3U8 for HLS proxy ────────────────
function rewriteM3U8(content, originalUrl, videoId, token) {
  const baseUrl = originalUrl.substring(0, originalUrl.lastIndexOf('/') + 1);
  const lines = content.split('\n');
  const rewritten = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      if (trimmed.startsWith('#EXT-X-KEY:') || trimmed.startsWith('#EXT-X-MAP:')) {
        // Rewrite URIs in encryption tags
        let modified = line;
        const uriMatch = modified.match(/URI="([^"]+)"/);
        if (uriMatch) {
          const resolvedUrl = new URL(uriMatch[1], baseUrl).href;
          const encoded = Buffer.from(resolvedUrl).toString('base64url');
          modified = modified.replace(uriMatch[1], `/api/v1/hls-seg/${encoded}?token=${token}`);
        }
        rewritten.push(modified);
      } else {
        rewritten.push(line);
      }
    } else {
      // Segment URL - resolve and proxy
      const resolvedUrl = new URL(trimmed, baseUrl).href;
      const encoded = Buffer.from(resolvedUrl).toString('base64url');
      rewritten.push(`/api/v1/hls-seg/${encoded}?token=${token}`);
    }
  }

  return rewritten.join('\n');
}

// ══════════════════════════════════════════════════════════
// PUBLIC API ROUTES
// ══════════════════════════════════════════════════════════

// ── Auth: Admin Login ──────────────────────────────────
app.post('/api/v1/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const { data: admin, error } = await supabase
      .from('admin_users')
      .select('*')
      .eq('username', username)
      .single();

    if (error || !admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, admin.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, role: 'admin' },
      ADMIN_JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ token, username: admin.username });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Auth: Verify PIN ───────────────────────────────────
app.post('/api/v1/auth/verify-pin', authenticateToken, async (req, res) => {
  try {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'PIN is required' });

    const { data: admin } = await supabase
      .from('admin_users')
      .select('pin')
      .eq('id', req.admin.id)
      .single();

    if (!admin || admin.pin !== pin) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    res.json({ verified: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Public: Get Videos ─────────────────────────────────
app.get('/api/v1/videos', async (req, res) => {
  try {
    const { category_id, featured } = req.query;
    let query = supabase
      .from('videos')
      .select('id, title, description, video_type, thumbnail, category_id, order_index, is_featured, duration, views, created_at')
      .eq('is_published', true)
      .order('order_index', { ascending: true });

    if (category_id) query = query.eq('category_id', category_id);
    if (featured === 'true') query = query.eq('is_featured', true);

    const { data, error } = await query;
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    console.error('Videos fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// ── Public: Get Stream Token ───────────────────────────
app.get('/api/v1/stream-token/:videoId', async (req, res) => {
  try {
    const { videoId } = req.params;
    const { data: video } = await supabase
      .from('videos')
      .select('id, is_published')
      .eq('id', videoId)
      .eq('is_published', true)
      .single();

    if (!video) return res.status(404).json({ error: 'Video not found' });

    const token = generateStreamToken(videoId);
    res.json({ token, streamUrl: `/api/v1/stream/${videoId}?token=${token}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate stream token' });
  }
});

// ── Public: Stream Video (URL Masking Core) ────────────
app.get('/api/v1/stream/:videoId', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(401).json({ error: 'Stream token required' });

    const decoded = verifyStreamToken(token);
    if (!decoded || decoded.videoId !== req.params.videoId) {
      return res.status(403).json({ error: 'Invalid stream token' });
    }

    const { data: video } = await supabase
      .from('videos')
      .select('*')
      .eq('id', req.params.videoId)
      .single();

    if (!video) return res.status(404).json({ error: 'Video not found' });

    const resolvedUrl = resolveVideoUrl(video);

    // Increment view count (fire and forget)
    supabase
      .from('videos')
      .update({ views: (video.views || 0) + 1 })
      .eq('id', video.id)
      .then(() => {});

    // Handle HLS M3U8 playlists
    if (video.video_type === 'm3u8') {
      const fetch = (await import('node-fetch')).default;
      const response = await fetch(resolvedUrl);
      const content = await response.text();
      const rewritten = rewriteM3U8(content, resolvedUrl, video.id, token);
      res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
      res.setHeader('Cache-Control', 'no-cache');
      return res.send(rewritten);
    }

    // Handle MP4 and other direct video formats with range support
    await proxyStreamWithRange(req, res, resolvedUrl);
  } catch (err) {
    console.error('Stream error:', err);
    res.status(500).json({ error: 'Stream failed' });
  }
});

// ── Public: HLS Segment Proxy ──────────────────────────
app.get('/api/v1/hls-seg/:encodedUrl', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(401).json({ error: 'Token required' });

    const decoded = verifyStreamToken(token);
    if (!decoded) return res.status(403).json({ error: 'Invalid token' });

    const realUrl = Buffer.from(req.params.encodedUrl, 'base64url').toString('utf8');

    // Security: Only allow known domains
    const allowedHosts = [
      'archive.org', 'gateway.pinata.cloud', 'ipfs.io',
      'cloudflare.com', 'cdn.jsdelivr.net',
      process.env.ALLOWED_STREAM_HOST,
    ].filter(Boolean);

    const urlObj = new URL(realUrl);
    const isAllowed = allowedHosts.some(h => urlObj.hostname.endsWith(h));
    if (!isAllowed && process.env.STRICT_STREAM_PROXY === 'true') {
      return res.status(403).json({ error: 'Domain not allowed' });
    }

    const fetch = (await import('node-fetch')).default;
    const response = await fetch(realUrl);
    const contentType = response.headers.get('content-type') || 'video/MP2T';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    response.body.pipe(res);
    response.body.on('error', () => res.end());
  } catch (err) {
    console.error('HLS seg error:', err);
    res.status(502).json({ error: 'Segment fetch failed' });
  }
});

// ── Public: Get Categories ─────────────────────────────
app.get('/api/v1/categories', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('categories')
      .select('*')
      .eq('is_active', true)
      .order('order_index', { ascending: true });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// ── Public: Get Posts (News) ───────────────────────────
app.get('/api/v1/posts', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('posts')
      .select('*')
      .eq('is_published', true)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

// ── Public: Get Audio Tracks ───────────────────────────
app.get('/api/v1/audio', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('audio_tracks')
      .select('id, title, artist, cover_url, duration, category')
      .eq('is_published', true)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audio' });
  }
});

// ── Public: Get Audio Stream Token ─────────────────────
app.get('/api/v1/audio-token/:trackId', async (req, res) => {
  try {
    const { data: track } = await supabase
      .from('audio_tracks')
      .select('id, is_published')
      .eq('id', req.params.trackId)
      .eq('is_published', true)
      .single();

    if (!track) return res.status(404).json({ error: 'Track not found' });

    const token = generateStreamToken(track.id);
    res.json({ token, streamUrl: `/api/v1/audio-stream/${track.id}?token=${token}` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

// ── Public: Stream Audio ───────────────────────────────
app.get('/api/v1/audio-stream/:trackId', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(401).json({ error: 'Token required' });

    const decoded = verifyStreamToken(token);
    if (!decoded || decoded.videoId !== req.params.trackId) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    const { data: track } = await supabase
      .from('audio_tracks')
      .select('url')
      .eq('id', req.params.trackId)
      .single();

    if (!track) return res.status(404).json({ error: 'Track not found' });

    const resolvedUrl = resolveArchiveUrl(track.url);
    await proxyStreamWithRange(req, res, resolvedUrl);
  } catch (err) {
    res.status(500).json({ error: 'Audio stream failed' });
  }
});

// ── Public: Get Settings ───────────────────────────────
app.get('/api/v1/settings', async (req, res) => {
  try {
    const { data, error } = await supabase.from('settings').select('*');
    if (error) throw error;
    const settings = {};
    (data || []).forEach(s => { settings[s.key] = s.value; });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// ── Public: Submit Contact ─────────────────────────────
app.post('/api/v1/contacts', async (req, res) => {
  try {
    const { alias_name, contact_method, message_type, message } = req.body;
    if (!alias_name || !message_type || !message) {
      return res.status(400).json({ error: 'Alias, type, and message are required' });
    }
    if (!['suggestion', 'report', 'broken_video', 'new_request'].includes(message_type)) {
      return res.status(400).json({ error: 'Invalid message type' });
    }
    if (message.length > 2000) {
      return res.status(400).json({ error: 'Message too long (max 2000 chars)' });
    }

    const { data, error } = await supabase
      .from('contacts')
      .insert({ alias_name, contact_method, message_type, message })
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch (err) {
    console.error('Contact submit error:', err);
    res.status(500).json({ error: 'Failed to submit message' });
  }
});

// ══════════════════════════════════════════════════════════
// ADMIN API ROUTES (All Protected)
// ══════════════════════════════════════════════════════════

// ── Admin: Get All Videos (including unpublished) ──────
app.get('/api/v1/admin/videos', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('videos')
      .select('*')
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// ── Admin: Add Video ───────────────────────────────────
app.post('/api/v1/admin/videos', authenticateToken, async (req, res) => {
  try {
    const { title, description, url, video_type, thumbnail, category_id, is_featured, is_published, duration } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'Title and URL are required' });

    const { data, error } = await supabase
      .from('videos')
      .insert({ title, description, url, video_type: video_type || 'mp4', thumbnail, category_id: category_id || null, is_featured: is_featured || false, is_published: is_published !== false, duration: duration || '0:00' })
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    console.error('Add video error:', err);
    res.status(500).json({ error: 'Failed to add video' });
  }
});

// ── Admin: Update Video ────────────────────────────────
app.put('/api/v1/admin/videos/:id', authenticateToken, async (req, res) => {
  try {
    const { title, description, url, video_type, thumbnail, category_id, is_featured, is_published, duration, order_index } = req.body;
    const updates = {};
    if (title !== undefined) updates.title = title;
    if (description !== undefined) updates.description = description;
    if (url !== undefined) updates.url = url;
    if (video_type !== undefined) updates.video_type = video_type;
    if (thumbnail !== undefined) updates.thumbnail = thumbnail;
    if (category_id !== undefined) updates.category_id = category_id;
    if (is_featured !== undefined) updates.is_featured = is_featured;
    if (is_published !== undefined) updates.is_published = is_published;
    if (duration !== undefined) updates.duration = duration;
    if (order_index !== undefined) updates.order_index = order_index;

    const { data, error } = await supabase
      .from('videos')
      .update(updates)
      .eq('id', req.params.id)
      .select()
      .single();

    if (error) throw error;
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update video' });
  }
});

// ── Admin: Delete Video ────────────────────────────────
app.delete('/api/v1/admin/videos/:id', authenticateToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('videos')
      .delete()
      .eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// ── Admin: Categories CRUD ─────────────────────────────
app.get('/api/v1/admin/categories', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('categories').select('*').order('order_index');
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch categories' }); }
});

app.post('/api/v1/admin/categories', authenticateToken, async (req, res) => {
  try {
    const { name, description, icon, order_index } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const { data, error } = await supabase
      .from('categories')
      .insert({ name, description, icon: icon || 'fa-folder', order_index: order_index || 0 })
      .select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to add category' }); }
});

app.put('/api/v1/admin/categories/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('categories').update(req.body).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to update category' }); }
});

app.delete('/api/v1/admin/categories/:id', authenticateToken, async (req, res) => {
  try {
    const { error } = await supabase.from('categories').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete category' }); }
});

// ── Admin: Posts (News) CRUD ───────────────────────────
app.get('/api/v1/admin/posts', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch posts' }); }
});

app.post('/api/v1/admin/posts', authenticateToken, async (req, res) => {
  try {
    const { title, content, author, image_url, is_published } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });
    const { data, error } = await supabase
      .from('posts')
      .insert({ title, content, author: author || 'Maxaas.u Official', image_url, is_published: is_published !== false })
      .select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to add post' }); }
});

app.put('/api/v1/admin/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('posts').update(req.body).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to update post' }); }
});

app.delete('/api/v1/admin/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { error } = await supabase.from('posts').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete post' }); }
});

// ── Admin: Audio CRUD ──────────────────────────────────
app.get('/api/v1/admin/audio', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('audio_tracks').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch audio' }); }
});

app.post('/api/v1/admin/audio', authenticateToken, async (req, res) => {
  try {
    const { title, artist, url, cover_url, duration, category, is_published } = req.body;
    if (!title || !url) return res.status(400).json({ error: 'Title and URL are required' });
    const { data, error } = await supabase
      .from('audio_tracks')
      .insert({ title, artist, url, cover_url, duration: duration || '0:00', category: category || 'General', is_published: is_published !== false })
      .select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to add audio' }); }
});

app.put('/api/v1/admin/audio/:id', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('audio_tracks').update(req.body).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to update audio' }); }
});

app.delete('/api/v1/admin/audio/:id', authenticateToken, async (req, res) => {
  try {
    const { error } = await supabase.from('audio_tracks').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete audio' }); }
});

// ── Admin: Contacts (Inbox) ────────────────────────────
app.get('/api/v1/admin/contacts', authenticateToken, async (req, res) => {
  try {
    const { data, error } = await supabase.from('contacts').select('*').order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch contacts' }); }
});

app.put('/api/v1/admin/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const updates = {};
    if (req.body.is_read !== undefined) updates.is_read = req.body.is_read;
    if (req.body.admin_response !== undefined) updates.admin_response = req.body.admin_response;
    const { data, error } = await supabase.from('contacts').update(updates).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch (err) { res.status(500).json({ error: 'Failed to update contact' }); }
});

app.delete('/api/v1/admin/contacts/:id', authenticateToken, async (req, res) => {
  try {
    const { error } = await supabase.from('contacts').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete contact' }); }
});

// ── Admin: Settings ────────────────────────────────────
app.put('/api/v1/admin/settings', authenticateToken, async (req, res) => {
  try {
    const updates = req.body;
    for (const [key, value] of Object.entries(updates)) {
      await supabase.from('settings').upsert({ key, value, updated_at: new Date().toISOString() });
    }
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update settings' }); }
});

// ── Admin: Change Credentials ──────────────────────────
app.put('/api/v1/admin/credentials', authenticateToken, async (req, res) => {
  try {
    const { pin, new_username, new_password } = req.body;

    // Verify PIN
    const { data: admin } = await supabase
      .from('admin_users')
      .select('*')
      .eq('id', req.admin.id)
      .single();

    if (!admin || admin.pin !== pin) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    const updates = {};
    if (new_username) updates.username = new_username;
    if (new_password) updates.password_hash = await bcrypt.hash(new_password, 12);
    if (req.body.new_pin) updates.pin = req.body.new_pin;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: 'No changes specified' });
    }

    const { error } = await supabase
      .from('admin_users')
      .update(updates)
      .eq('id', req.admin.id);

    if (error) throw error;

    // Generate new token if username changed
    let newToken;
    if (new_username) {
      newToken = jwt.sign(
        { id: req.admin.id, username: new_username, role: 'admin' },
        ADMIN_JWT_SECRET,
        { expiresIn: '24h' }
      );
    }

    res.json({ success: true, token: newToken });
  } catch (err) {
    console.error('Credentials error:', err);
    res.status(500).json({ error: 'Failed to update credentials' });
  }
});

// ── SPA Fallback ───────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

// ── Start Server ───────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Maxaas.u Pro server running on port ${PORT}`);
  console.log(`JWT_SECRET: ${JWT_SECRET.substring(0, 8)}...`);
  console.log(`Supabase: ${SUPABASE_URL}`);
});

module.exports = app;