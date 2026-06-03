const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('cloudinary').v2;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// PostgreSQL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Cloudinary (для хранения фото)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary,
  params: { folder: 'cloudnet', allowed_formats: ['jpg','jpeg','png','gif','webp'] }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// Create tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      about TEXT DEFAULT '',
      avatar_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      content TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reactions (
      id SERIAL PRIMARY KEY,
      post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type TEXT NOT NULL CHECK(type IN ('like','dislike')),
      UNIQUE(post_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS session (
      sid TEXT NOT NULL PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMPTZ NOT NULL
    );
  `);

  // Create admin
  const admin = await pool.query('SELECT id FROM users WHERE username = $1', ['siteowner']);
  if (admin.rows.length === 0) {
    const hash = bcrypt.hashSync('133213', 10);
    await pool.query(
      'INSERT INTO users (username, password_hash, about) VALUES ($1, $2, $3)',
      ['siteowner', hash, 'Site administrator']
    );
  }
}

initDB().catch(console.error);

// Banned words
const BANNED_WORDS = [
  'блять','блядь','бля','хуй','хуя','хуе','пизда','пизд','ебать','еба','ёбать','ёба',
  'пиздец','нахуй','нахуя','сука','суки','мудак','мудила','ебло','ёбло','залупа',
  'мразь','шлюха','шлюхи','курва','урод','уроды','гандон','долбоёб','долбоеб',
  'fuck','shit','bitch','asshole','cunt','dick','pussy','bastard','motherfucker','nigger','faggot'
];
function containsBannedWords(text) {
  const lower = text.toLowerCase();
  return BANNED_WORDS.some(w => lower.includes(w));
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'cloudnet-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
};

// ==================== AUTH ====================

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Only letters, numbers, underscores' });
  if (containsBannedWords(username)) return res.status(400).json({ error: 'Invalid username' });

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id',
      [username, hash]
    );
    req.session.userId = result.rows[0].id;
    req.session.username = username;
    res.json({ success: true, username });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ success: true, username: user.username });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const result = await pool.query(
    'SELECT id, username, about, avatar_url FROM users WHERE id = $1',
    [req.session.userId]
  );
  res.json({ user: result.rows[0] || null });
});

// ==================== POSTS ====================

app.get('/api/posts', async (req, res) => {
  const userId = req.session.userId || 0;
  const result = await pool.query(`
    SELECT p.id, p.content, p.image_url, p.created_at,
           u.username, u.id as user_id,
           COALESCE(l.likes, 0) as likes,
           COALESCE(l.dislikes, 0) as dislikes,
           r.type as my_reaction
    FROM posts p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN (
      SELECT post_id,
             SUM(CASE WHEN type='like' THEN 1 ELSE 0 END) as likes,
             SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END) as dislikes
      FROM reactions GROUP BY post_id
    ) l ON l.post_id = p.id
    LEFT JOIN reactions r ON r.post_id = p.id AND r.user_id = $1
    ORDER BY p.created_at DESC
    LIMIT 100
  `, [userId]);
  res.json(result.rows);
});

app.post('/api/posts', requireAuth, upload.single('image'), async (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Post content required' });
  if (content.trim().split(/\s+/).length > 50) return res.status(400).json({ error: 'Post cannot exceed 50 words' });
  if (containsBannedWords(content)) return res.status(400).json({ error: 'Post contains prohibited content' });

  const image_url = req.file ? req.file.path : '';
  const result = await pool.query(
    'INSERT INTO posts (user_id, content, image_url) VALUES ($1, $2, $3) RETURNING id',
    [req.session.userId, content.trim(), image_url]
  );

  const post = await pool.query(`
    SELECT p.id, p.content, p.image_url, p.created_at, u.username, u.id as user_id,
           0 as likes, 0 as dislikes, NULL as my_reaction
    FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = $1
  `, [result.rows[0].id]);

  res.json(post.rows[0]);
});

app.delete('/api/posts/:id', requireAuth, async (req, res) => {
  const result = await pool.query('SELECT * FROM posts WHERE id = $1', [req.params.id]);
  const post = result.rows[0];
  if (!post) return res.status(404).json({ error: 'Post not found' });

  const isAdmin = req.session.username === 'siteowner';
  const isOwner = post.user_id === req.session.userId;
  if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Not allowed' });

  await pool.query('DELETE FROM posts WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// ==================== REACTIONS ====================

app.post('/api/posts/:id/react', requireAuth, async (req, res) => {
  const { type } = req.body;
  if (!['like', 'dislike'].includes(type)) return res.status(400).json({ error: 'Invalid reaction' });

  const postId = parseInt(req.params.id);
  const userId = req.session.userId;

  const existing = await pool.query(
    'SELECT * FROM reactions WHERE post_id = $1 AND user_id = $2',
    [postId, userId]
  );

  let my_reaction = null;
  if (existing.rows.length > 0) {
    if (existing.rows[0].type === type) {
      await pool.query('DELETE FROM reactions WHERE post_id = $1 AND user_id = $2', [postId, userId]);
    } else {
      await pool.query('UPDATE reactions SET type = $1 WHERE post_id = $2 AND user_id = $3', [type, postId, userId]);
      my_reaction = type;
    }
  } else {
    await pool.query('INSERT INTO reactions (post_id, user_id, type) VALUES ($1, $2, $3)', [postId, userId, type]);
    my_reaction = type;
  }

  const counts = await pool.query(`
    SELECT
      SUM(CASE WHEN type='like' THEN 1 ELSE 0 END) as likes,
      SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END) as dislikes
    FROM reactions WHERE post_id = $1
  `, [postId]);

  res.json({
    likes: parseInt(counts.rows[0].likes) || 0,
    dislikes: parseInt(counts.rows[0].dislikes) || 0,
    my_reaction
  });
});

// ==================== PROFILE ====================

app.get('/api/profile/:username', async (req, res) => {
  const userRes = await pool.query(
    'SELECT id, username, about, avatar_url, created_at FROM users WHERE username = $1',
    [req.params.username]
  );
  if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  const user = userRes.rows[0];

  const posts = await pool.query(`
    SELECT p.id, p.content, p.image_url, p.created_at,
           COALESCE(l.likes, 0) as likes, COALESCE(l.dislikes, 0) as dislikes
    FROM posts p
    LEFT JOIN (
      SELECT post_id,
             SUM(CASE WHEN type='like' THEN 1 ELSE 0 END) as likes,
             SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END) as dislikes
      FROM reactions GROUP BY post_id
    ) l ON l.post_id = p.id
    WHERE p.user_id = $1
    ORDER BY p.created_at DESC
  `, [user.id]);

  res.json({ user, posts: posts.rows });
});

app.put('/api/profile', requireAuth, upload.single('avatar'), async (req, res) => {
  const { about } = req.body;
  if (about && containsBannedWords(about)) return res.status(400).json({ error: 'Bio contains prohibited content' });
  if (about && about.length > 200) return res.status(400).json({ error: 'Bio too long (max 200 chars)' });

  const updates = [];
  const params = [];
  let i = 1;

  if (about !== undefined) { updates.push(`about = $${i++}`); params.push(about); }
  if (req.file) { updates.push(`avatar_url = $${i++}`); params.push(req.file.path); }

  if (updates.length > 0) {
    params.push(req.session.userId);
    await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${i}`, params);
  }

  const result = await pool.query(
    'SELECT id, username, about, avatar_url FROM users WHERE id = $1',
    [req.session.userId]
  );
  res.json(result.rows[0]);
});

app.listen(PORT, () => console.log(`CloudNet running on port ${PORT}`));
