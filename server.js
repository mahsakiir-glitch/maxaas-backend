const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(helmet());
app.use(cors({ origin: '*' })); 
app.use(express.json());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: "Isku day mar kale" });

const SUPABASE_URL = 'https://aoxclvpbdoxklwfrumhr.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFveGNsdnBiZG94a2x3ZnJ1bWhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1OTYyMzYsImV4cCI6MjA5NDE3MjIzNn0.U9p-nW4bXH6iujT7omhAt1lRL5WMwUVnvjhk69OID5U';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const JWT_SECRET = process.env.JWT_SECRET || 'Maxaas_Permanent_Secret_2026'; 
let currentCredentials = { email: 'admin@maxaas.u', passwordHash: '$2a$10$OqC6IeWmKJvZxP5eQ8Y4ouE5R3G1sH2dF7uI9jK0lM6nB8vC4wXyO', pin: '82692035' };

async function loadCredentials() {
    try {
        const { data } = await supabase.from('settings').select('*').in('key', ['admin_email', 'admin_password', 'admin_pin', 'pin_first5']);
        if (data) { const map = {}; data.forEach(i => map[i.key] = i.value); if (map.admin_email) currentCredentials.email = map.admin_email; if (map.admin_password) currentCredentials.passwordHash = map.admin_password; if (map.admin_pin) currentCredentials.pin = map.admin_pin; }
    } catch(e) {}
}
loadCredentials();

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try { jwt.verify(token, JWT_SECRET); next(); } catch (err) { res.status(403).json({ message: 'Invalid Token' }); }
};
const optionalAuth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token;
    if (token) { try { jwt.verify(token, JWT_SECRET); } catch(e) {} }
    next();
};

// --- AUTH ---
app.post('/api/v1/auth/precheck', async (req, res) => { const { pin5 } = req.body; const { data } = await supabase.from('settings').select('value').eq('key', 'pin_first5').single(); res.json({ valid: pin5 === (data?.value || currentCredentials.pin.substring(0, 5)) }); });
app.post('/api/v1/auth/login', loginLimiter, async (req, res) => { const { email, password, pin } = req.body; if (email === currentCredentials.email && bcrypt.compareSync(password, currentCredentials.passwordHash) && pin === currentCredentials.pin) { return res.json({ token: jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '24h' }) }); } res.status(401).json({ message: 'Xogtu ma aha sax ah' }); });
app.post('/api/v1/auth/change-credentials', authMiddleware, async (req, res) => { const { newEmail, newPassword, newPin } = req.body; if(newEmail) currentCredentials.email = newEmail; if(newPassword) currentCredentials.passwordHash = bcrypt.hashSync(newPassword, 10); if(newPin && newPin.length === 8) currentCredentials.pin = newPin; try { const u = [{key:'admin_email',value:currentCredentials.email},{key:'admin_password',value:currentCredentials.passwordHash},{key:'admin_pin',value:currentCredentials.pin},{key:'pin_first5',value:currentCredentials.pin.substring(0,5)}]; for(const i of u) await supabase.from('settings').upsert(i,{onConflict:'key'}); } catch(e){} res.json({ message: 'Waa la badalay!', token: jwt.sign({ role: 'admin', email: currentCredentials.email }, JWT_SECRET, { expiresIn: '24h' }) }); });

// --- VIDEO VIEWS ---
app.post('/api/v1/videos/:id/view', async (req, res) => { const { id } = req.params; const { data, error } = await supabase.from('videos').select('views').eq('id', id).single(); if (error) return res.status(404).json({ error: 'Not found' }); await supabase.from('videos').update({ views: (data.views || 0) + 1 }).eq('id', id); res.json({ views: (data.views || 0) + 1 }); });

// --- SECURE VIDEO STREAMING (Hidden Links & Speed Optimization) ---
app.get('/api/v1/stream/:id', optionalAuth, async (req, res) => {
    const { id } = req.params;
    const { data, error } = await supabase.from('videos').select('url, type').eq('id', id).single();
    if (error || !data || !data.url) return res.status(404).send('Not found');

    let streamUrl = data.url;
    if (streamUrl.includes('archive.gnews.to') && !streamUrl.endsWith('/download')) streamUrl = streamUrl.replace(/\/$/, '') + '/download';
    if (streamUrl.includes('archive.org/details/')) { const p = streamUrl.split('/details/'); streamUrl = `https://archive.org/download/${p[1]}/${p[1]}.mp4`; }
    if (streamUrl.startsWith('ipfs://')) streamUrl = streamUrl.replace('ipfs://', 'https://gateway.pinata.cloud/ipfs/');

    try {
        // Speed Optimization: Forward Range headers for fast seeking
        const headers = { 'User-Agent': 'Mozilla/5.0' };
        if (req.headers.range) headers.Range = req.headers.range;

        const headRes = await axios.head(streamUrl, { headers });
        const size = headRes.headers['content-length'];
        const range = req.headers.range;

        if (range && size) {
            const parts = range.replace(/bytes=/, "").split("-");
            const start = parseInt(parts[0], 10); const end = parts[1] ? parseInt(parts[1], 10) : size - 1;
            res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${size}`, 'Accept-Ranges': 'bytes', 'Content-Length': (end - start) + 1, 'Content-Type': 'video/mp4' });
            const streamRes = await axios.get(streamUrl, { responseType: 'stream', headers: { Range: range } });
            streamRes.data.pipe(res);
        } else {
            res.setHeader('Content-Length', size); res.setHeader('Content-Type', 'video/mp4'); res.setHeader('Accept-Ranges', 'bytes');
            const streamRes = await axios.get(streamUrl, { responseType: 'stream' });
            streamRes.data.pipe(res);
        }
    } catch (err) { res.status(500).send('Stream error'); }
});

// --- DATA ROUTES (EXACT SCHEMA MATCH) ---
app.get('/api/v1/videos', async (req, res) => { const { data, error } = await supabase.from('videos').select('*').order('created_at', { ascending: false }); if (error) return res.status(500).json({ error: error.message }); res.json(data); });
app.post('/api/v1/videos', authMiddleware, async (req, res) => { const { title, url, type, parent_id, is_category, views, thumbnail_url, description } = req.body; const insertData = { title, url: url || null, type: type || 'video', parent_id: parent_id || null, is_category: is_category || false, views: views || 0, thumbnail_url: thumbnail_url || null, description: description || null }; const { data, error } = await supabase.from('videos').insert([insertData]).select(); if (error) return res.status(500).json({ error: error.message }); res.status(201).json(data[0]); });
app.put('/api/v1/videos/:id', authMiddleware, async (req, res) => { const updateData = { ...req.body }; delete updateData.id; delete updateData.created_at; const { data, error } = await supabase.from('videos').update(updateData).eq('id', req.params.id).select(); if (error) return res.status(500).json({ error: error.message }); res.json(data[0]); });
app.delete('/api/v1/videos/:id', authMiddleware, async (req, res) => { const { error } = await supabase.from('videos').delete().eq('id', req.params.id); if (error) return res.status(500).json({ error: error.message }); res.status(204).send(); });

app.get('/api/v1/audio', async (req, res) => { const { data, error } = await supabase.from('audio').select('*'); if (error) return res.status(500).json({ error: error.message }); res.json(data); });
app.post('/api/v1/audio', authMiddleware, async (req, res) => { const { title, url, desc } = req.body; const { data, error } = await supabase.from('audio').insert([{ title, url, desc: desc || null }]).select(); if (error) return res.status(500).json({ error: error.message }); res.status(201).json(data[0]); });
app.delete('/api/v1/audio/:id', authMiddleware, async (req, res) => { const { error } = await supabase.from('audio').delete().eq('id', req.params.id); if (error) return res.status(500).json({ error: error.message }); res.status(204).send(); });

app.get('/api/v1/posts', async (req, res) => { const { data, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false }); if (error) return res.status(500).json({ error: error.message }); res.json(data); });
app.post('/api/v1/posts', authMiddleware, async (req, res) => { const { content, imageUrl, videoUrl, avatar } = req.body; const insertData = { content, imageUrl: imageUrl || null, videoUrl: videoUrl || null, avatar: avatar || null }; const { data, error } = await supabase.from('posts').insert([insertData]).select(); if (error) return res.status(500).json({ error: error.message }); res.status(201).json(data[0]); });
app.delete('/api/v1/posts/:id', authMiddleware, async (req, res) => { const { error } = await supabase.from('posts').delete().eq('id', req.params.id); if (error) return res.status(500).json({ error: error.message }); res.status(204).send(); });

app.get('/api/v1/contacts', authMiddleware, async (req, res) => { const { data, error } = await supabase.from('contacts').select('*').order('created_at', { ascending: false }); if (error) return res.status(500).json({ error: error.message }); res.json(data); });
app.post('/api/v1/contacts', async (req, res) => { const { type, content } = req.body; const insertData = { type, content }; const { data, error } = await supabase.from('contacts').insert([insertData]).select(); if (error) return res.status(500).json({ error: error.message }); res.status(201).json(data[0]); });
app.delete('/api/v1/contacts/:id', authMiddleware, async (req, res) => { const { error } = await supabase.from('contacts').delete().eq('id', req.params.id); if (error) return res.status(500).json({ error: error.message }); res.status(204).send(); });

app.get('/api/v1/settings', async (req, res) => { const { data, error } = await supabase.from('settings').select('*'); if (error) return res.status(500).json({ error: error.message }); const map = {}; data.forEach(i => map[i.key] = i.value); res.json(map); });
app.put('/api/v1/settings', authMiddleware, async (req, res) => { try { for (const [k, v] of Object.entries(req.body)) { await supabase.from('settings').upsert({ key: k, value: v }, { onConflict: 'key' }); } res.json({ message: 'Saved' }); } catch (e) { res.status(500).json({error: e.message}); }});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));