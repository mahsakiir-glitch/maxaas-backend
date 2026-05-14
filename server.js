const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// --- CONFIGURATION ---
// Enabled CORS for all origins to support Web3/Unstoppable Domain requests
app.use(cors({ origin: '*' })); 
app.use(express.json());

const SUPABASE_URL = 'https://aoxclvpbdoxklwfrumhr.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImFveGNsdnBiZG94a2x3ZnJ1bWhyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzg1OTYyMzYsImV4cCI6MjA5NDE3MjIzNn0.U9p-nW4bXH6iujT7omhAt1lRL5WMwUVnvjhk69OID5U';
const SECRET_KEY = 'Maxaas_Gold_Trader_Secret_2026'; 

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// --- AUTH MIDDLEWARE ---
const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try {
        jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        res.status(403).json({ message: 'Invalid Token' });
    }
};

// --- AUTH ROUTES ---
app.post('/api/v1/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (email === 'admin@maxaas.u' && password === 'password') {
        const token = jwt.sign({ role: 'admin' }, SECRET_KEY, { expiresIn: '24h' });
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// --- VIDEO ROUTES ---
app.get('/api/v1/videos', async (req, res) => {
    const { data, error } = await supabase.from('videos').select('*').order('id', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/v1/videos', authMiddleware, async (req, res) => {
    const { title, url, desc, catId } = req.body;
    const { data, error } = await supabase
        .from('videos')
        .insert([{ title, url, desc, catId: catId || null, views: 0 }])
        .select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.put('/api/v1/videos/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { views, title, url, desc, catId } = req.body;
    const updateData = {};
    if (views !== undefined) updateData.views = views;
    if (title) updateData.title = title;
    if (url) updateData.url = url;
    if (desc) updateData.desc = desc;
    if (catId !== undefined) updateData.catId = catId;

    const { data, error } = await supabase.from('videos').update(updateData).eq('id', id).select();
    if (error) return res.status(500).json({ error: error.message });
    res.json(data[0]);
});

app.delete('/api/v1/videos/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('videos').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- AUDIO ROUTES ---
app.get('/api/v1/audio', async (req, res) => {
    const { data, error } = await supabase.from('audio').select('*').order('id', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/v1/audio', authMiddleware, async (req, res) => {
    const { title, url, dur, catId } = req.body;
    const { data, error } = await supabase
        .from('audio')
        .insert([{ title, url, dur: dur || '--:--', catId: catId || null }])
        .select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.delete('/api/v1/audio/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('audio').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- POSTS (NEWS) ROUTES ---
app.get('/api/v1/posts', async (req, res) => {
    const { data, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/v1/posts', authMiddleware, async (req, res) => {
    const { content, imageUrl, videoUrl, avatar } = req.body;
    const { data, error } = await supabase
        .from('posts')
        .insert([{ content, imageUrl: imageUrl || null, videoUrl: videoUrl || null, avatar: avatar || null }])
        .select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.delete('/api/v1/posts/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('posts').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- COURSES ROUTES ---
app.get('/api/v1/courses', async (req, res) => {
    const { data, error } = await supabase.from('courses').select('*').order('id', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/v1/courses', authMiddleware, async (req, res) => {
    const { name, desc, type } = req.body;
    const { data, error } = await supabase
        .from('courses')
        .insert([{ name, desc: desc || null, type: type || 'video' }])
        .select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.delete('/api/v1/courses/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('courses').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.status(204).send();
});

// --- SERVER START ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});