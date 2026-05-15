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

// JWT Secret - Ka beddel Render hadhow
const JWT_SECRET = process.env.JWT_SECRET || 'Maxaas_Permanent_Secret_2026'; 

// Default Credentials (Email: admin@maxaas.u | Pass: admin123 | PIN: 82692035)
let currentCredentials = { 
    email: 'admin@maxaas.u', 
    passwordHash: '$2a$10$OqC6IeWmKJvZxP5eQ8Y4ouE5R3G1sH2dF7uI9jK0lM6nB8vC4wXyO', 
    pin: '82692035' 
};

// Soo rido Credentials-ka haddii ay Database-ka ku jiraan
async function loadCredentials() {
    try {
        const { data } = await supabase.from('settings').select('*').in('key', ['admin_email', 'admin_password', 'admin_pin']);
        if (data) { 
            const map = {}; 
            data.forEach(i => map[i.key] = i.value); 
            if (map.admin_email) currentCredentials.email = map.admin_email; 
            if (map.admin_password) currentCredentials.passwordHash = map.admin_password; 
            if (map.admin_pin) currentCredentials.pin = map.admin_pin; 
        }
    } catch(e) {}
}
loadCredentials();

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    try { jwt.verify(token, JWT_SECRET); next(); } catch (err) { res.status(403).json({ message: 'Invalid Token' }); }
};

// --- AUTH ROUTES ---
app.post('/api/v1/auth/precheck', async (req, res) => { 
    const { pin5 } = req.body; 
    res.json({ valid: pin5 === currentCredentials.pin.substring(0, 5) }); 
});

app.post('/api/v1/auth/login', loginLimiter, async (req, res) => { 
    const { email, password, pin } = req.body; 
    if (email === currentCredentials.email && bcrypt.compareSync(password, currentCredentials.passwordHash) && pin === currentCredentials.pin) { 
        return res.json({ token: jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '24h' }) }); 
    } 
    res.status(401).json({ message: 'Xogtu ma aha sax' }); 
});

// --- VIDEO ROUTES ---
app.get('/api/v1/videos', async (req, res) => { 
    const { data, error } = await supabase.from('videos').select('*').order('created_at', { ascending: false }); 
    if (error) return res.status(500).json({ error: error.message }); 
    res.json(data); 
});

app.post('/api/v1/videos', authMiddleware, async (req, res) => {
    const { title, url, type, parent_id, is_category, description } = req.body;
    const { data, error } = await supabase.from('videos').insert([{
        title, url, type: type || 'video', parent_id: parent_id || null, 
        is_category: is_category === 'true' || is_category === true, 
        description, views: 0
    }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

// --- POSTS ROUTES ---
app.get('/api/v1/posts', async (req, res) => {
    const { data, error } = await supabase.from('posts').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

app.post('/api/v1/posts', authMiddleware, async (req, res) => {
    const { content, imageUrl } = req.body;
    const { data, error } = await supabase.from('posts').insert([{ content, imageUrl }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

// --- CONTACTS ---
app.post('/api/v1/contacts', async (req, res) => {
    const { type, content } = req.body;
    const { data, error } = await supabase.from('contacts').insert([{ type, content }]).select();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
});

app.get('/api/v1/contacts', authMiddleware, async (req, res) => {
    const { data, error } = await supabase.from('contacts').select('*').order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));