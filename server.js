require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());

const supabase = createClient(
    process.env.SUPABASE_URL || 'https://supabase.co', 
    process.env.SUPABASE_KEY || 'mock-key'
);
const JWT_SECRET = process.env.JWT_SECRET || 'maxaas_u_pro_secret_key_2026';

// Middleware to protect admin endpoints
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Token missing" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        if (user.role !== 'admin') return res.status(403).json({ error: "Unauthorized" });
        req.user = user;
        next();
    });
};

function convertArchiveLink(url) {
    if (url.includes('archive.org/details/')) {
        return url.replace('details/', 'download/');
    }
    return url;
}

// --- PUBLIC APIS ---

// 1. Fetch Platform Data Dynamically
app.get('/api/v1/content', async (req, res) => {
    try {
        const { data: videos } = await supabase.from('videos').select('id, title, description, category, course_name, thumbnail_url');
        const { data: audio } = await supabase.from('audio_tracks').select('*');
        const { data: news } = await supabase.from('news_posts').select('*').order('created_at', { ascending: false });
        res.json({ videos, audio, news });
    } catch (err) {
        res.status(500).json({ error: "Failed to load data" });
    }
});

// 2. Video Streaming Proxy (Mask Real Link)
app.get('/api/v1/stream/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { token } = req.query;

        if (!token) return res.status(401).json({ error: "Token missing." });
        try { jwt.verify(token, JWT_SECRET); } catch { return res.status(403).json({ error: "Expired token." }); }

        const { data: video } = await supabase.from('videos').select('real_url').eq('id', id).single();
        if (!video) return res.status(404).json({ error: "Video not found." });

        let secureUrl = convertArchiveLink(video.real_url);

        const response = await axios({
            method: 'get',
            url: secureUrl,
            responseType: 'stream',
            headers: { 'User-Agent': 'Mozilla/5.0' }
        });
        res.set(response.headers);
        response.data.pipe(res);
    } catch (err) {
        res.status(500).json({ error: "Streaming connection loss." });
    }
});

app.get('/api/v1/video/token', (req, res) => {
    const token = jwt.sign({ access: 'stream_allowed' }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.post('/api/v1/contact', async (req, res) => {
    const { message_type, content } = req.body;
    await supabase.from('contact_messages').insert([{ message_type, content }]);
    res.json({ success: true });
});

// --- ADMIN APIS ---

app.post('/api/v1/admin/login', async (req, res) => {
    const { username, password, pin } = req.body;
    const { data: admin } = await supabase.from('admin_settings').select('*').single();
    if (!admin) return res.status(404).json({ error: "No admin config." });

    const validPassword = await bcrypt.compare(password, admin.password_hash);
    const validPin = (pin === admin.secure_pin);

    if (admin.username === username && validPassword && validPin) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
        return res.json({ success: true, token });
    }
    res.status(401).json({ error: "Wrong credentials." });
});

app.get('/api/v1/admin/messages', authenticateAdmin, async (req, res) => {
    const { data } = await supabase.from('contact_messages').select('*').order('created_at', { ascending: false });
    res.json({ messages: data });
});

app.post('/api/v1/admin/add-video', authenticateAdmin, async (req, res) => {
    const { title, description, real_url, category, course_name, thumbnail_url } = req.body;
    await supabase.from('videos').insert([{ title, description, real_url, category, course_name, thumbnail_url }]);
    res.json({ success: true });
});

app.listen(PORT, () => console.log(`Server environment configured on port ${PORT}`));
