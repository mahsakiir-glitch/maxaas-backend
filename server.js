const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// --- SECURITY MIDDLEWARES ---
app.use(helmet());
app.use(cors({ origin: '*' })); 
app.use(express.json());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Too many login attempts, please try again after 15 minutes"
});

// --- CONFIGURATION ---
const SUPABASE_URL = 'https://aoxclvpbdoxklwfrumhr.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFveGNsdnBiZG94a2x3ZnJ1bWhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1OTYyMzYsImV4cCI6MjA5NDE3MjIzNn0.U9p-nW4bXH6iujT7omhAt1lRL5WMwUVnvjhk69OID5U';
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

let currentSecret = 'Maxaas_Gold_Trader_Initial_Secret_2026';
let currentCredentials = { 
    email: 'admin@maxaas.u', 
    passwordHash: bcrypt.hashSync('password', 10) 
};

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        jwt.verify(token, currentSecret);
        next();
    } catch (err) {
        res.status(403).json({ message: 'Invalid or Expired Token' });
    }
};

// --- AUTH ROUTES ---
app.post('/api/v1/auth/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    if (email === currentCredentials.email && bcrypt.compareSync(password, currentCredentials.passwordHash)) {
        const token = jwt.sign({ role: 'admin', email }, currentSecret, { expiresIn: '24h' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

app.post('/api/v1/auth/change-credentials', authMiddleware, async (req, res) => {
    const { newEmail, newPassword } = req.body;
    if (!newEmail || !newPassword) return res.status(400).json({ message: 'Email and password required' });
    currentCredentials.email = newEmail;
    currentCredentials.passwordHash = bcrypt.hashSync(newPassword, 10);
    currentSecret = require('crypto').randomBytes(64).toString('hex'); // Invalidate old tokens
    const newToken = jwt.sign({ role: 'admin', email: newEmail }, currentSecret, { expiresIn: '24h' });
    res.json({ message: 'Credentials updated.', token: newToken });
});

// --- SECURE VIDEO STREAMING PROXY ---
app.get('/api/v1/stream/:id', async (req, res) => {
    const { id } = req.params;
    const { data, error } = await supabase.from('videos').select('url, type').eq('id', id).single();
    
    if (error || !data || !data.url) return res.status(404).send('Video not found');
    if (data.type === 'youtube') return res.status(400).send('Use iframe for YouTube');

    let streamUrl = data.url;
    if (streamUrl.includes('archive.gnews.to') && !streamUrl.endsWith('/download')) {
        streamUrl = streamUrl.replace(/\/$/, '') + '/download';
    }
    if (streamUrl.includes('archive.org/details/')) {
        const parts = streamUrl.split('/details/');
        const fileId = parts[1].split('?')[0].replace(/\/$/, '');
        streamUrl = `https://archive.org/download/${fileId}/${fileId}.mp4`;
    }

    try {
        const response = await axios.head(streamUrl); 
        const size = response.headers['content-length'];
        const range = req.headers.range;
        
        if (range) {
            const parts = range.replace(/bytes=/, "").split("-");
            const start = parseInt(parts[0], 10);
            const end = parts[1] ? parseInt(parts[1], 10) : size - 1;
            res.writeHead(206, {
                'Content-Range': `bytes ${start}-${end}/${size}`,
                'Accept-Ranges': 'bytes',
                'Content-Length': (end - start) + 1,
                'Content-Type': 'video/mp4',
            });
            const streamResponse = await axios.get(streamUrl, { responseType: 'stream', headers: { Range: range } });
            streamResponse.data.pipe(res);
        } else {
            res.setHeader('Content-Length', size);
            res.setHeader('Content-Type', 'video/mp4');
            const streamResponse = await axios.get(streamUrl, { responseType: 'stream' });
            streamResponse.data.pipe(res);
        }
    } catch (err) {
        res.status(500).send('Streaming error');
    }
});

// --- DATA ROUTES ---
app.get('/api/v1/videos', async (req, res) => {
    const { data, error } = await supabase.from('videos').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});
app.post('/api/v1/videos', authMiddleware, async (req, res) => {
    const { title, url, type, parent_id, is_category, views, thumbnail_url, description } = req.body;
    const { data, error } = await supabase.from('videos').insert([{ title, url, type: type || 'video', parent_id: parent_id || null, is_category: is_category || false, views: views || 0, thumbnail_url: thumbnail_url || null, description: description || null }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});
app.put('/api/v1/videos/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { data, error } = await supabase.from('videos').update(req.body).eq('id', id).select();
    if (error) return res.status(500).json({ error: error.message });
    if (!data.length) return res.status(404).json({ message: 'Not found' });
    res.json(data[0]);
});
app.delete('/api/v1/videos/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('videos').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

app.get('/api/v1/audio', async (req, res) => {
    const { data, error } = await supabase.from('audio').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});
app.post('/api/v1/audio', authMiddleware, async (req, res) => {
    const { title, url, desc } = req.body;
    const { data, error } = await supabase.from('audio').insert([{ title, url, desc: desc || null }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});
app.delete('/api/v1/audio/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('audio').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

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
    const { id } = req.params;
    const { error } = await supabase.from('posts').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- QUOTES ROUTES ---
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
    const { id } = req.params;
    const { error } = await supabase.from('quotes').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- SETTINGS ROUTES (Menu Names & Avatar) ---
app.get('/api/v1/settings', async (req, res) => {
    const { data, error } = await supabase.from('settings').select('*');
    if (error) return res.status(500).json({ error: error.message });
    const settingsMap = {};
    data.forEach(item => settingsMap[item.key] = item.value);
    res.json(settingsMap);
});
app.put('/api/v1/settings', authMiddleware, async (req, res) => {
    const updates = req.body; // Expects { menu_videos: "Muqaal", news_avatar: "url" }
    try {
        for (const [key, value] of Object.entries(updates)) {
            await supabase.from('settings').upsert({ key, value }, { onConflict: 'key' });
        }
        res.json({ message: 'Settings updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));