const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Support Render persistent disk
const DATA_DIR = process.env.DATA_DIR || '.';
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'cloudnet.db');

// Ensure uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Database setup
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    about TEXT DEFAULT '',
    avatar_url TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    image_url TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('like','dislike')),
    UNIQUE(post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Create admin account if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('siteowner');
if (!adminExists) {
  const hash = bcrypt.hashSync('133213', 10);
  db.prepare('INSERT INTO users (username, password_hash, about) VALUES (?, ?, ?)').run('siteowner', hash, 'Site administrator');
}

// Banned words list (Russian + English)
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

// Multer setup for image uploads
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    cb(null, allowed.test(file.mimetype));
  }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'cloudnet-secret-key-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  next();
};

// ==================== AUTH ROUTES ====================

app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Username can only contain letters, numbers, underscores' });
  if (containsBannedWords(username)) return res.status(400).json({ error: 'Invalid username' });
  
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
    req.session.userId = result.lastInsertRowid;
    req.session.username = username;
    res.json({ success: true, username });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'Username already taken' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
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

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id, username, about, avatar_url FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user });
});

// ==================== POST ROUTES ====================

app.get('/api/posts', (req, res) => {
  const userId = req.session.userId || 0;
  const posts = db.prepare(`
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
    LEFT JOIN reactions r ON r.post_id = p.id AND r.user_id = ?
    ORDER BY p.created_at DESC
    LIMIT 100
  `).all(userId);
  res.json(posts);
});

app.post('/api/posts', requireAuth, upload.single('image'), (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim()) return res.status(400).json({ error: 'Post content required' });
  
  const words = content.trim().split(/\s+/);
  if (words.length > 50) return res.status(400).json({ error: 'Post cannot exceed 50 words' });
  if (containsBannedWords(content)) return res.status(400).json({ error: 'Post contains prohibited content' });
  
  const image_url = req.file ? `/uploads/${req.file.filename}` : '';
  const result = db.prepare('INSERT INTO posts (user_id, content, image_url) VALUES (?, ?, ?)').run(req.session.userId, content.trim(), image_url);
  
  const post = db.prepare(`
    SELECT p.id, p.content, p.image_url, p.created_at, u.username, u.id as user_id,
           0 as likes, 0 as dislikes, NULL as my_reaction
    FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?
  `).get(result.lastInsertRowid);
  
  res.json(post);
});

app.delete('/api/posts/:id', requireAuth, (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  
  const isAdmin = req.session.username === 'siteowner';
  const isOwner = post.user_id === req.session.userId;
  
  if (!isAdmin && !isOwner) return res.status(403).json({ error: 'Not allowed' });
  
  if (post.image_url) {
    const filePath = path.join(DATA_DIR, post.image_url);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
  
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ==================== REACTION ROUTES ====================

app.post('/api/posts/:id/react', requireAuth, (req, res) => {
  const { type } = req.body;
  if (!['like', 'dislike'].includes(type)) return res.status(400).json({ error: 'Invalid reaction' });
  
  const postId = parseInt(req.params.id);
  const userId = req.session.userId;
  
  const existing = db.prepare('SELECT * FROM reactions WHERE post_id = ? AND user_id = ?').get(postId, userId);
  
  if (existing) {
    if (existing.type === type) {
      db.prepare('DELETE FROM reactions WHERE post_id = ? AND user_id = ?').run(postId, userId);
      var my_reaction = null;
    } else {
      db.prepare('UPDATE reactions SET type = ? WHERE post_id = ? AND user_id = ?').run(type, postId, userId);
      var my_reaction = type;
    }
  } else {
    db.prepare('INSERT INTO reactions (post_id, user_id, type) VALUES (?, ?, ?)').run(postId, userId, type);
    var my_reaction = type;
  }
  
  const counts = db.prepare(`
    SELECT SUM(CASE WHEN type='like' THEN 1 ELSE 0 END) as likes,
           SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END) as dislikes
    FROM reactions WHERE post_id = ?
  `).get(postId);
  
  res.json({ likes: counts.likes || 0, dislikes: counts.dislikes || 0, my_reaction });
});

// ==================== PROFILE ROUTES ====================

app.get('/api/profile/:username', (req, res) => {
  const user = db.prepare('SELECT id, username, about, avatar_url, created_at FROM users WHERE username = ?').get(req.params.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  
  const posts = db.prepare(`
    SELECT p.id, p.content, p.image_url, p.created_at,
           COALESCE(l.likes, 0) as likes, COALESCE(l.dislikes, 0) as dislikes
    FROM posts p
    LEFT JOIN (
      SELECT post_id,
             SUM(CASE WHEN type='like' THEN 1 ELSE 0 END) as likes,
             SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END) as dislikes
      FROM reactions GROUP BY post_id
    ) l ON l.post_id = p.id
    WHERE p.user_id = ?
    ORDER BY p.created_at DESC
  `).all(user.id);
  
  res.json({ user, posts });
});

app.put('/api/profile', requireAuth, upload.single('avatar'), (req, res) => {
  const { about } = req.body;
  if (about && containsBannedWords(about)) return res.status(400).json({ error: 'Bio contains prohibited content' });
  if (about && about.length > 200) return res.status(400).json({ error: 'Bio too long (max 200 chars)' });
  
  let updates = [];
  let params = [];
  
  if (about !== undefined) { updates.push('about = ?'); params.push(about); }
  if (req.file) { updates.push('avatar_url = ?'); params.push(`/uploads/${req.file.filename}`); }
  
  if (updates.length > 0) {
    params.push(req.session.userId);
    db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }
  
  const user = db.prepare('SELECT id, username, about, avatar_url FROM users WHERE id = ?').get(req.session.userId);
  res.json(user);
});

app.listen(PORT, () => console.log(`CloudNet running on port ${PORT}`));
