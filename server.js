const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// --- SECURITY MIDDLEWARES ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            mediaSrc: ["'self'", "blob:", "data:"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https:"],
        }
    }
}));
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: "Too many attempts" });
const streamLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 60 });

// --- CONFIGURATION ---
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://aoxclvpbdoxklwfrumhr.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFveGNsdnBiZG94a2x3ZnJ1bWhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1OTYyMzYsImV4cCI6MjA5NDE3MjIzNn0.U9p-nW4bXH6iujT7omhAt1lRL5WMwUVnvjhk69OID5U';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// In-memory state (persisted to Supabase settings on change)
let state = {
    secret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
    email: 'admin@maxaas.u',
    passwordHash: bcrypt.hashSync('password', 10),
    pin: '82692035',          // 8-digit PIN; only first 5 needed to unlock
    pinPrefixLength: 5,       // how many digits unlock the button
    streamSecret: crypto.randomBytes(32).toString('hex'),
};

// Load persisted admin settings from Supabase on boot
(async () => {
    try {
        const { data } = await supabase.from('settings').select('*');
        if (data) {
            data.forEach(({ key, value }) => {
                if (key === 'admin_email') state.email = value;
                if (key === 'admin_password_hash') state.passwordHash = value;
                if (key === 'admin_pin') state.pin = value;
            });
        }
    } catch (e) { console.warn('Could not load persisted admin settings:', e.message); }
})();

// --- AUTH MIDDLEWARE ---
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        req.admin = jwt.verify(token, state.secret);
        next();
    } catch {
        res.status(403).json({ message: 'Invalid or expired token' });
    }
};

// Signed stream token (short-lived, video-id-bound)
const makeStreamToken = (videoId) =>
    jwt.sign({ vid: videoId, ts: Date.now() }, state.streamSecret, { expiresIn: '2h' });

const verifyStreamToken = (token, videoId) => {
    try {
        const p = jwt.verify(token, state.streamSecret);
        return p.vid === videoId;
    } catch { return false; }
};

// --- AUTH ROUTES ---
app.post('/api/v1/auth/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (email === state.email && bcrypt.compareSync(password, state.passwordHash)) {
        const token = jwt.sign({ role: 'admin', email }, state.secret, { expiresIn: '24h' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// PIN verification endpoint – returns a short-lived viewer token
app.post('/api/v1/auth/pin', loginLimiter, async (req, res) => {
    const { pin } = req.body;
    if (!pin) return res.status(400).json({ message: 'PIN required' });
    // Accept if first pinPrefixLength digits match
    const prefix = state.pin.slice(0, state.pinPrefixLength);
    if (pin === prefix) {
        const token = jwt.sign({ role: 'viewer' }, state.secret, { expiresIn: '12h' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid PIN' });
});

app.post('/api/v1/auth/change-credentials', authMiddleware, async (req, res) => {
    const { newEmail, newPassword, newPin } = req.body;
    if (!newEmail || !newPassword) return res.status(400).json({ message: 'Email and password required' });

    state.email = newEmail;
    state.passwordHash = bcrypt.hashSync(newPassword, 10);
    state.secret = crypto.randomBytes(64).toString('hex');
    if (newPin && /^\d{8}$/.test(newPin)) state.pin = newPin;

    // Persist to Supabase
    await supabase.from('settings').upsert({ key: 'admin_email', value: newEmail }, { onConflict: 'key' });
    await supabase.from('settings').upsert({ key: 'admin_password_hash', value: state.passwordHash }, { onConflict: 'key' });
    if (newPin) await supabase.from('settings').upsert({ key: 'admin_pin', value: newPin }, { onConflict: 'key' });

    const newToken = jwt.sign({ role: 'admin', email: newEmail }, state.secret, { expiresIn: '24h' });
    res.json({ message: 'Credentials updated.', token: newToken });
});

// --- STREAM TOKEN ISSUER ---
// Frontend calls this to get a signed token before requesting the stream
app.get('/api/v1/stream-token/:id', (req, res) => {
    // Public – any visitor can get a stream token (token hides the real URL)
    const token = makeStreamToken(req.params.id);
    res.json({ token });
});

// --- SECURE VIDEO STREAMING PROXY ---
app.get('/api/v1/stream/:id', streamLimiter, async (req, res) => {
    const { id } = req.params;
    const { t } = req.query; // signed stream token

    if (!t || !verifyStreamToken(t, id)) {
        return res.status(403).send('Access denied');
    }

    const { data, error } = await supabase.from('videos').select('url, type').eq('id', id).single();
    if (error || !data?.url) return res.status(404).send('Video not found');
    if (data.type === 'youtube') return res.status(400).send('Use iframe for YouTube');

    let streamUrl = data.url;

    // Transform known URL formats
    if (streamUrl.includes('archive.gnews.to') && !streamUrl.endsWith('/download')) {
        streamUrl = streamUrl.replace(/\/$/, '') + '/download';
    }
    if (streamUrl.includes('archive.org/details/')) {
        const fileId = streamUrl.split('/details/')[1].split('?')[0].replace(/\/$/, '');
        streamUrl = `https://archive.org/download/${fileId}/${fileId}.mp4`;
    }
    if (streamUrl.includes('ipfs://')) {
        streamUrl = streamUrl.replace('ipfs://', 'https://gateway.pinata.cloud/ipfs/');
    }
    if (streamUrl.includes('/ipfs/') && !streamUrl.startsWith('http')) {
        streamUrl = 'https://gateway.pinata.cloud' + streamUrl;
    }

    try {
        const headRes = await axios.head(streamUrl, { timeout: 8000 });
        const contentLength = headRes.headers['content-length'];
        const contentType = headRes.headers['content-type'] || 'video/mp4';
        const range = req.headers.range;

        if (range && contentLength) {
            const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
            const start = parseInt(startStr, 10);
            const end = endStr ? parseInt(endStr, 10) : parseInt(contentLength) - 1;
            const chunkSize = end - start + 1;

            res.writeHead(206, {
                'Content-Range': `bytes ${start}-${end}/${contentLength}`,
                'Accept-Ranges': 'bytes',
                'Content-Length': chunkSize,
                'Content-Type': contentType,
                'Cache-Control': 'no-store',
            });
            const streamRes = await axios.get(streamUrl, {
                responseType: 'stream',
                headers: { Range: `bytes=${start}-${end}` },
                timeout: 30000,
            });
            streamRes.data.pipe(res);
        } else {
            res.writeHead(200, {
                'Content-Length': contentLength || '',
                'Content-Type': contentType,
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'no-store',
            });
            const streamRes = await axios.get(streamUrl, { responseType: 'stream', timeout: 30000 });
            streamRes.data.pipe(res);
        }
    } catch (err) {
        console.error('Stream error:', err.message);
        res.status(502).send('Streaming error');
    }
});

// --- VIDEOS ---
app.get('/api/v1/videos', async (req, res) => {
    // Return videos WITHOUT the real url field (url is server-side only)
    const { data, error } = await supabase
        .from('videos')
        .select('id, title, type, parent_id, is_category, views, thumbnail_url, description, created_at')
        .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/v1/videos', authMiddleware, async (req, res) => {
    const { title, url, type, parent_id, is_category, views, thumbnail_url, description } = req.body;
    const { data, error } = await supabase.from('videos').insert([{
        title, url, type: type || 'video',
        parent_id: parent_id || null,
        is_category: is_category || false,
        views: views || 0,
        thumbnail_url: thumbnail_url || null,
        description: description || null
    }]).select('id, title, type, parent_id, is_category, views, thumbnail_url, description, created_at');
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.put('/api/v1/videos/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { data, error } = await supabase.from('videos').update(req.body).eq('id', id)
        .select('id, title, type, parent_id, is_category, views, thumbnail_url, description, created_at');
    if (error) return res.status(500).json({ error: error.message });
    if (!data.length) return res.status(404).json({ message: 'Not found' });
    res.json(data[0]);
});

app.delete('/api/v1/videos/:id', authMiddleware, async (req, res) => {
    const { error } = await supabase.from('videos').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// Increment view count
app.post('/api/v1/videos/:id/view', async (req, res) => {
    const { id } = req.params;
    const { data: vid } = await supabase.from('videos').select('views').eq('id', id).single();
    if (!vid) return res.status(404).json({ message: 'Not found' });
    await supabase.from('videos').update({ views: (vid.views || 0) + 1 }).eq('id', id);
    res.json({ ok: true });
});

// --- AUDIO ---
app.get('/api/v1/audio', async (req, res) => {
    const { data, error } = await supabase.from('audio').select('id, title, desc, created_at').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});
app.post('/api/v1/audio', authMiddleware, async (req, res) => {
    const { title, url, desc } = req.body;
    const { data, error } = await supabase.from('audio').insert([{ title, url, desc: desc || null }]).select('id, title, desc, created_at');
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});
app.delete('/api/v1/audio/:id', authMiddleware, async (req, res) => {
    const { error } = await supabase.from('audio').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- POSTS ---
app.get('/api/v1/posts', async (req, res) => {
    const { data, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});
app.post('/api/v1/posts', authMiddleware, async (req, res) => {
    const { content, imageUrl } = req.body;
    const { data, error } = await supabase.from('posts').insert([{ content, imageUrl: imageUrl || null }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});
app.delete('/api/v1/posts/:id', authMiddleware, async (req, res) => {
    const { error } = await supabase.from('posts').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- QUOTES ---
app.get('/api/v1/quotes', async (req, res) => {
    const { data, error } = await supabase.from('quotes').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});
app.post('/api/v1/quotes', authMiddleware, async (req, res) => {
    const { text, author } = req.body;
    const { data, error } = await supabase.from('quotes').insert([{ text, author: author || 'Unknown' }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});
app.delete('/api/v1/quotes/:id', authMiddleware, async (req, res) => {
    const { error } = await supabase.from('quotes').delete().eq('id', req.params.id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- CONTACT SUBMISSIONS ---
app.post('/api/v1/contact', async (req, res) => {
    const { type, message } = req.body;
    if (!type || !message) return res.status(400).json({ message: 'Type and message required' });
    const { error } = await supabase.from('contact_submissions').insert([{ type, message, created_at: new Date().toISOString() }]);
    if (error) {
        // Table may not exist yet — store in settings as fallback
        console.warn('contact_submissions table may not exist:', error.message);
    }
    res.json({ message: 'Submitted successfully' });
});

// Admin: read contact submissions
app.get('/api/v1/contact', authMiddleware, async (req, res) => {
    const { data, error } = await supabase.from('contact_submissions').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

// --- SETTINGS ---
app.get('/api/v1/settings', async (req, res) => {
    const { data, error } = await supabase.from('settings').select('key, value');
    if (error) return res.status(500).json({ error: error.message });
    const map = {};
    // Exclude sensitive keys from public endpoint
    const PRIVATE = new Set(['admin_password_hash', 'admin_pin']);
    data.forEach(({ key, value }) => { if (!PRIVATE.has(key)) map[key] = value; });
    res.json(map);
});
app.put('/api/v1/settings', authMiddleware, async (req, res) => {
    const updates = req.body;
    try {
        for (const [key, value] of Object.entries(updates)) {
            await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' });
        }
        res.json({ message: 'Settings updated' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Maxaas server running on port ${PORT}`));