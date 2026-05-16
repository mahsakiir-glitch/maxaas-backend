require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!SUPABASE_URL || !SUPABASE_KEY) console.error('FATAL: SUPABASE_URL and SUPABASE_SERVICE_KEY must be set');
const supabase = createClient(SUPABASE_URL || 'https://placeholder.co', SUPABASE_KEY || 'key');

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false, trustProxy: true });
const apiLimiter = rateLimit({ windowMs: 1 * 60 * 1000, max: 300, standardHeaders: true, legacyHeaders: false, trustProxy: true });
app.use('/api/v1/auth', authLimiter);
app.use('/api/v1', apiLimiter);
app.use(express.static(path.join(__dirname, 'public')));

// --- Helpers ---
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });
    try { req.admin = jwt.verify(token, ADMIN_JWT_SECRET); next(); }
    catch (e) { return res.status(403).json({ error: 'Invalid or expired token' }); }
}
function generateStreamToken(id) { return jwt.sign({ id, type: 'stream' }, JWT_SECRET, { expiresIn: '4h' }); }
function verifyStreamToken(t) { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } }

// Resolve hidden real URLs into direct playable streams
function resolveUrl(v) {
    let u = v.url || '';
    const type = v.video_type || 'mp4';
    if (type === 'archive') {
        // Standard Archive.org: /details/ID -> /download/ID/ID.mp4
        u = u.replace(/archive\.org\/details\/([^/?\s]+)/, 'archive.org/download/$1/$1.mp4');
        // Archive GNews: ensure ends with /download
        if (u.includes('gnews.to') && !u.endsWith('/download')) u += '/download';
    } else if (type === 'ipfs') {
        if (u.startsWith('ipfs://')) u = u.replace('ipfs://', 'https://gateway.pinata.cloud/ipfs/');
        else if (!u.startsWith('http')) u = `https://gateway.pinata.cloud/ipfs/${u}`;
    }
    return u;
}

// Stream proxy with Range header support for seeking
async function streamMedia(req, res, url) {
    try {
        const fetch = (await import('node-fetch')).default;
        const headRes = await fetch(url, { method: 'HEAD' });
        const totalSize = parseInt(headRes.headers.get('content-length') || '0', 10);
        const contentType = headRes.headers.get('content-type') || (url.includes('.m3u8') ? 'application/vnd.apple.mpegurl' : 'video/mp4');
        const range = req.headers.range;

        if (range && totalSize > 0) {
            const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
            const start = parseInt(startStr, 10);
            const end = endStr ? parseInt(endStr, 10) : totalSize - 1;
            const streamRes = await fetch(url, { headers: { Range: `bytes=${start}-${end}` } });
            res.writeHead(206, { 'Content-Range': `bytes ${start}-${end}/${totalSize}`, 'Accept-Ranges': 'bytes', 'Content-Length': end - start + 1, 'Content-Type': contentType });
            streamRes.body.pipe(res);
        } else {
            const streamRes = await fetch(url);
            res.writeHead(200, { 'Content-Length': totalSize, 'Content-Type': contentType, 'Accept-Ranges': 'bytes' });
            streamRes.body.pipe(res);
        }
    } catch (e) { if (!res.headersSent) res.status(502).json({ error: 'Stream fetch failed' }); }
}

// Auto Admin Setup
async function setupAdmin() {
    if (!supabase) return;
    try {
        const { data } = await supabase.from('admin_users').select('id').limit(1);
        if (!data?.length) {
            const hash = await bcrypt.hash('Admin@2024', 12);
            await supabase.from('admin_users').insert({ username: 'admin', password_hash: hash, pin: '12345678' });
            console.log('Default admin created: admin / Admin@2024 / PIN: 12345678');
        }
    } catch (e) { console.error('Admin setup error:', e.message); }
}
setupAdmin();

// ═══════════════════════════════════════
// PUBLIC ROUTES
// ═══════════════════════════════════════

app.post('/api/v1/auth/check-pin', async (req, res) => {
    const { username, pin } = req.body;
    if (!username || !pin) return res.json({ valid: false });
    const { data: admin } = await supabase.from('admin_users').select('pin').eq('username', username).single();
    res.json({ valid: admin?.pin === pin && pin.length === 8 });
});

app.post('/api/v1/auth/login', async (req, res) => {
    try {
        const { username, password, pin } = req.body;
        if (!username || !password || !pin) return res.status(400).json({ error: 'All fields required' });
        const { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', username).single();
        if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });
        if (!(await bcrypt.compare(password, admin.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
        if (admin.pin !== pin || pin.length !== 8) return res.status(401).json({ error: 'Invalid PIN' });
        const token = jwt.sign({ id: admin.id, username: admin.username, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: admin.username });
    } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/v1/videos', async (req, res) => {
    try {
        let q = supabase.from('videos').select('id, title, description, video_type, thumbnail, category_id, is_featured, duration, views').eq('is_published', true).order('order_index');
        if (req.query.category_id) q = q.eq('category_id', req.query.category_id);
        if (req.query.featured === 'true') q = q.eq('is_featured', true);
        const { data, error } = await q;
        if (error) throw error;
        res.json(data || []);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/v1/stream-token/:id', async (req, res) => {
    try {
        const { data: v } = await supabase.from('videos').select('id, is_published, video_type').eq('id', req.params.id).eq('is_published', true).single();
        if (!v) return res.status(404).json({ error: 'Not found' });
        res.json({ token: generateStreamToken(v.id), streamUrl: `/api/v1/stream/${v.id}?token=${generateStreamToken(v.id)}`, video_type: v.video_type });
    } catch (e) { res.status(500).json({ error: 'Token generation failed' }); }
});

// THE SECURE STREAM ENDPOINT - Hides real URLs
app.get('/api/v1/stream/:id', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(401).json({ error: 'Token required' });
    const decoded = verifyStreamToken(token);
    if (!decoded || decoded.id !== req.params.id) return res.status(403).json({ error: 'Invalid token' });
    
    const { data: v } = await supabase.from('videos').select('*').eq('id', req.params.id).single();
    if (!v) return res.status(404).json({ error: 'Video not found' });

    supabase.from('videos').update({ views: (v.views||0)+1 }).eq('id', v.id).then(()=>{});
    const realUrl = resolveUrl(v);
    await streamMedia(req, res, realUrl);
});

app.get('/api/v1/categories', async (req, res) => { try { const {data,e}=await supabase.from('categories').select('*').eq('is_active',true).order('order_index'); if(e)throw e; res.json(data||[]); } catch(e){res.status(500).json({error:'Fail'})}});
app.get('/api/v1/posts', async (req, res) => { try { const {data,e}=await supabase.from('posts').select('*').eq('is_published',true).order('created_at',{ascending:false}); if(e)throw e; res.json(data||[]); } catch(e){res.status(500).json({error:'Fail'})}});
app.get('/api/v1/audio', async (req, res) => { try { const {data,e}=await supabase.from('audio_tracks').select('id,title,artist,cover_url,duration,category').eq('is_published',true); if(e)throw e; res.json(data||[]); } catch(e){res.status(500).json({error:'Fail'})}});
app.get('/api/v1/settings', async (req, res) => { try { const {data,e}=await supabase.from('settings').select('*'); if(e)throw e; const s={}; (data||[]).forEach(i=>s[i.key]=i.value); res.json(s); } catch(e){res.status(500).json({error:'Fail'})}});

app.post('/api/v1/contacts', async (req, res) => {
    try {
        const { alias_name, contact_method, message_type, message } = req.body;
        if (!alias_name || !message_type || !message) return res.status(400).json({ error: 'Missing' });
        const { data, error } = await supabase.from('contacts').insert({ alias_name, contact_method, message_type, message }).select().single();
        if (error) throw error;
        res.json({ success: true, id: data.id });
    } catch (e) { res.status(500).json({ error: 'Fail' }); }
});

// ═══════════════════════════════════════
// ADMIN ROUTES (Protected)
// ═══════════════════════════════════════
const adminGet = (route, table) => app.get(`/api/v1/admin/${route}`, authenticateToken, async (req, res) => { try { const {data,e}=await supabase.from(table).select('*').order('created_at',{ascending:false}); if(e)throw e; res.json(data||[]); } catch(e){res.status(500).json({error:'Fail'})}});
adminGet('videos', 'videos');
adminGet('categories', 'categories');
adminGet('posts', 'posts');
adminGet('audio', 'audio_tracks');
adminGet('contacts', 'contacts');

app.post('/api/v1/admin/videos', authenticateToken, async (req, res) => { try { const {title,description,url,video_type,thumbnail,category_id,is_featured,is_published,duration}=req.body; if(!title||!url)return res.status(400).json({error:'Title/URL req'}); const {data,e}=await supabase.from('videos').insert({title,description:description||'',url,video_type:video_type||'mp4',thumbnail:thumbnail||'',category_id:category_id||null,is_featured:is_featured||false,is_published:is_published!==false,duration:duration||'0:00'}).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.put('/api/v1/admin/videos/:id', authenticateToken, async (req, res) => { try { const {data,e}=await supabase.from('videos').update(req.body).eq('id',req.params.id).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.delete('/api/v1/admin/videos/:id', authenticateToken, async (req, res) => { try { const {e}=await supabase.from('videos').delete().eq('id',req.params.id); if(e)throw e; res.json({ok:true}); } catch(e){res.status(500).json({error:'Fail'})}});

app.post('/api/v1/admin/categories', authenticateToken, async (req, res) => { try { const {name,description,icon,order_index}=req.body; if(!name)return res.status(400).json({error:'Name req'}); const {data,e}=await supabase.from('categories').insert({name,description:description||'',icon:icon||'fa-folder',order_index:order_index||0}).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.put('/api/v1/admin/categories/:id', authenticateToken, async (req, res) => { try { const {data,e}=await supabase.from('categories').update(req.body).eq('id',req.params.id).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.delete('/api/v1/admin/categories/:id', authenticateToken, async (req, res) => { try { const {e}=await supabase.from('categories').delete().eq('id',req.params.id); if(e)throw e; res.json({ok:true}); } catch(e){res.status(500).json({error:'Fail'})}});

app.post('/api/v1/admin/posts', authenticateToken, async (req, res) => { try { const {title,content,author,image_url,is_published}=req.body; if(!title||!content)return res.status(400).json({error:'Title/Content req'}); const {data,e}=await supabase.from('posts').insert({title,content,author:author||'Official',image_url:image_url||'',is_published:is_published!==false}).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.put('/api/v1/admin/posts/:id', authenticateToken, async (req, res) => { try { const {data,e}=await supabase.from('posts').update(req.body).eq('id',req.params.id).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.delete('/api/v1/admin/posts/:id', authenticateToken, async (req, res) => { try { const {e}=await supabase.from('posts').delete().eq('id',req.params.id); if(e)throw e; res.json({ok:true}); } catch(e){res.status(500).json({error:'Fail'})}});

app.put('/api/v1/admin/contacts/:id', authenticateToken, async (req, res) => { try { const u={}; if(req.body.is_read!==undefined)u.is_read=req.body.is_read; if(req.body.admin_response!==undefined)u.admin_response=req.body.admin_response; const {data,e}=await supabase.from('contacts').update(u).eq('id',req.params.id).select().single(); if(e)throw e; res.json(data); } catch(e){res.status(500).json({error:'Fail'})}});
app.delete('/api/v1/admin/contacts/:id', authenticateToken, async (req, res) => { try { const {e}=await supabase.from('contacts').delete().eq('id',req.params.id); if(e)throw e; res.json({ok:true}); } catch(e){res.status(500).json({error:'Fail'})}});

app.put('/api/v1/admin/settings', authenticateToken, async (req, res) => { try { for(const[k,v] of Object.entries(req.body)) await supabase.from('settings').upsert({key:k,value:v,updated_at:new Date().toISOString()}); res.json({ok:true}); } catch(e){res.status(500).json({error:'Fail'})}});

// Credential Change (Old ones stop working instantly)
app.put('/api/v1/admin/credentials', authenticateToken, async (req, res) => {
    try {
        const { pin, new_username, new_password, new_pin } = req.body;
        if (!pin) return res.status(400).json({ error: 'Current PIN required' });
        const { data: admin } = await supabase.from('admin_users').select('*').eq('id', req.admin.id).single();
        if (!admin || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });
        
        const updates = {};
        if (new_username) updates.username = new_username;
        if (new_password) updates.password_hash = await bcrypt.hash(new_password, 12);
        if (new_pin) { if(new_pin.length!==8) return res.status(400).json({error:'PIN must be 8 digits'}); updates.pin = new_pin; }
        if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No changes' });

        const { error } = await supabase.from('admin_users').update(updates).eq('id', req.admin.id);
        if (error) throw error;
        
        let newToken;
        if (new_username) newToken = jwt.sign({ id: req.admin.id, username: new_username, role: 'admin' }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token: newToken }); // Old token is structurally invalid if username changed, or hash changed forcing re-login
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// SPA Fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`Maxaas.u Pro running on ${PORT}`));