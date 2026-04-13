require('dotenv').config();
const express       = require('express');
const http          = require('http');
const path          = require('path');
const { Server }    = require('socket.io');
const cors          = require('cors');
const helmet        = require('helmet');
const morgan        = require('morgan');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const session       = require('express-session');
const passport      = require('passport');
const GoogleStrategy  = require('passport-google-oauth20').Strategy;
const GitHubStrategy  = require('passport-github2').Strategy;
const DiscordStrategy = require('passport-discord').Strategy;
const { google }    = require('googleapis');
const { v4: uuid }  = require('uuid');
const Database      = require('better-sqlite3');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*', methods: ['GET','POST'] } });

/* ── Env guards ── */
['JWT_SECRET','SESSION_SECRET'].forEach(k => {
  if (!process.env[k]) { console.error(`❌  ${k} missing in .env`); process.exit(1); }
});
const JWT_SECRET   = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5000';

/* ═══════════════════════════════════════════
   DATABASE
═══════════════════════════════════════════ */
const db = new Database(path.join(__dirname, 'skillswap.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    name                  TEXT    NOT NULL,
    email                 TEXT    UNIQUE,
    password_hash         TEXT    DEFAULT '',
    bio                   TEXT    DEFAULT '',
    role                  TEXT    DEFAULT '',
    availability          TEXT    DEFAULT '',
    avatar_seed           TEXT    DEFAULT '',
    avatar_url            TEXT    DEFAULT '',
    skills_teaching       TEXT    DEFAULT '[]',
    skills_learning       TEXT    DEFAULT '[]',
    public_key            TEXT    DEFAULT NULL,
    google_id             TEXT    UNIQUE,
    github_id             TEXT    UNIQUE,
    discord_id            TEXT    UNIQUE,
    google_access_token   TEXT    DEFAULT '',
    google_refresh_token  TEXT    DEFAULT '',
    discord_username      TEXT    DEFAULT '',
    created_at            TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user   INTEGER NOT NULL REFERENCES users(id),
    to_user     INTEGER NOT NULL REFERENCES users(id),
    ciphertext  TEXT    NOT NULL,
    iv          TEXT    NOT NULL,
    created_at  TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS meetings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    proposer_id   INTEGER NOT NULL REFERENCES users(id),
    peer_id       INTEGER NOT NULL REFERENCES users(id),
    title         TEXT    NOT NULL,
    description   TEXT    DEFAULT '',
    scheduled_at  TEXT    NOT NULL,
    duration_min  INTEGER DEFAULT 60,
    platform      TEXT    NOT NULL DEFAULT 'google_meet',
    meet_link     TEXT    DEFAULT '',
    discord_info  TEXT    DEFAULT '',
    status        TEXT    DEFAULT 'pending',
    notes         TEXT    DEFAULT '',
    created_at    TEXT    DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_msg_pair   ON messages(from_user, to_user);
  CREATE INDEX IF NOT EXISTS idx_mtg_peer   ON meetings(peer_id);
  CREATE INDEX IF NOT EXISTS idx_mtg_prop   ON meetings(proposer_id);
`);

/* Safe migration for existing databases */
(function migrate() {
  const cols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  const add  = (col, def) => { if (!cols.includes(col)) db.exec(`ALTER TABLE users ADD COLUMN ${col} ${def}`); };
  add('google_id',           'TEXT');
  add('github_id',           'TEXT');
  add('discord_id',          'TEXT');
  add('google_access_token', 'TEXT DEFAULT \'\'');
  add('google_refresh_token','TEXT DEFAULT \'\'');
  add('discord_username',    'TEXT DEFAULT \'\'');
  add('avatar_url',          'TEXT DEFAULT \'\'');
})();

/* ── Prepared statements ── */
const stmt = {
  insertUser:    db.prepare(`INSERT INTO users (name,email,password_hash,avatar_seed) VALUES (?,?,?,?)`),
  findByEmail:   db.prepare(`SELECT * FROM users WHERE email=?`),
  findById:      db.prepare(`SELECT * FROM users WHERE id=?`),
  allUsers:      db.prepare(`SELECT id,name,bio,role,availability,avatar_seed,avatar_url,skills_teaching,skills_learning,discord_username FROM users`),

  upsertGoogle: db.prepare(`
  INSERT INTO users (name,email,google_id,google_access_token,google_refresh_token,avatar_url,password_hash)
  VALUES (?,?,?,?,?,?,'')
  ON CONFLICT(email) DO UPDATE SET
    google_id            = excluded.google_id,
    google_access_token  = excluded.google_access_token,
    google_refresh_token = COALESCE(excluded.google_refresh_token, google_refresh_token),
    avatar_url           = excluded.avatar_url
`),
  upsertGithub: db.prepare(`
    INSERT INTO users (name,email,github_id,avatar_url,password_hash)
    VALUES (?,?,?,?,'')
    ON CONFLICT(github_id) DO UPDATE SET avatar_url=excluded.avatar_url
  `),
  upsertDiscord: db.prepare(`
    INSERT INTO users (name,discord_id,discord_username,avatar_url,password_hash)
    VALUES (?,?,?,?,'')
    ON CONFLICT(discord_id) DO UPDATE SET
      discord_username=excluded.discord_username,
      avatar_url=excluded.avatar_url
  `),
  findByGoogleId:  db.prepare(`SELECT * FROM users WHERE google_id=?`),
  findByGithubId:  db.prepare(`SELECT * FROM users WHERE github_id=?`),
  findByDiscordId: db.prepare(`SELECT * FROM users WHERE discord_id=?`),

  updatePublicKey: db.prepare(`UPDATE users SET public_key=? WHERE id=?`),
  insertMessage:   db.prepare(`INSERT INTO messages (from_user,to_user,ciphertext,iv) VALUES (?,?,?,?)`),
  getMessages:     db.prepare(`
    SELECT id,from_user,to_user,ciphertext,iv,created_at FROM messages
    WHERE (from_user=? AND to_user=?) OR (from_user=? AND to_user=?)
    ORDER BY created_at ASC
  `),
  insertMeeting: db.prepare(`
    INSERT INTO meetings (proposer_id,peer_id,title,description,scheduled_at,duration_min,platform,meet_link,discord_info,notes)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  `),
  getMeetingsByUser: db.prepare(`
    SELECT m.*,u.name AS proposer_name,p.name AS peer_name,
           u.avatar_url AS proposer_avatar, p.avatar_url AS peer_avatar
    FROM   meetings m
    JOIN   users u ON u.id=m.proposer_id
    JOIN   users p ON p.id=m.peer_id
    WHERE  m.proposer_id=? OR m.peer_id=?
    ORDER  BY m.scheduled_at ASC
  `),
  getMeetingById:    db.prepare(`SELECT * FROM meetings WHERE id=?`),
  updateMtgStatus:   db.prepare(`UPDATE meetings SET status=? WHERE id=?`),
};

/* ═══════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════ */
function makeJWT(user) {
  return jwt.sign({ id: user.id, name: user.name, email: user.email || '' }, JWT_SECRET, { expiresIn: '7d' });
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid or expired token' }); }
}

function safeUser(u) {
  if (!u) return null;
  const { password_hash, google_access_token, google_refresh_token, ...rest } = u;
  rest.skills_teaching = JSON.parse(u.skills_teaching || '[]');
  rest.skills_learning = JSON.parse(u.skills_learning || '[]');
  return rest;
}

/* ═══════════════════════════════════════════
   MIDDLEWARE
═══════════════════════════════════════════ */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(morgan('dev'));
app.use(express.json({ limit: '50kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 10 * 60 * 1000 },  // 10 min — OAuth handshake only
}));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((user, done)  => done(null, user.id));
passport.deserializeUser((id, done)  => done(null, stmt.findById.get(id) || false));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '../frontend')));
// Fonts live at project root /fonts, not inside /frontend
app.use('/fonts', express.static(path.join(__dirname, '../fonts')));

/* ═══════════════════════════════════════════
   OAUTH PASSPORT STRATEGIES
═══════════════════════════════════════════ */
if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  `${FRONTEND_URL}/auth/google/callback`,
    scope: ['profile','email','https://www.googleapis.com/auth/calendar.events'],
    accessType:   'offline',
    prompt:       'consent',
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value || null;
      const avatar = profile.photos?.[0]?.value || '';
      stmt.upsertGoogle.run(profile.displayName, email, profile.id, accessToken, refreshToken||'', avatar);
      done(null, stmt.findByGoogleId.get(profile.id));
    } catch(e) { done(e); }
  }));
}

if (process.env.GITHUB_CLIENT_ID) {
  passport.use(new GitHubStrategy({
    clientID:     process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL:  `${FRONTEND_URL}/auth/github/callback`,
    scope: ['user:email'],
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const email  = profile.emails?.[0]?.value || null;
      const avatar = profile.photos?.[0]?.value || '';
      stmt.upsertGithub.run(profile.displayName || profile.username, email, profile.id, avatar);
      done(null, stmt.findByGithubId.get(profile.id));
    } catch(e) { done(e); }
  }));
}

if (process.env.DISCORD_CLIENT_ID) {
  passport.use(new DiscordStrategy({
    clientID:     process.env.DISCORD_CLIENT_ID,
    clientSecret: process.env.DISCORD_CLIENT_SECRET,
    callbackURL:  `${FRONTEND_URL}/auth/discord/callback`,
    scope: ['identify','email'],
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const avatar = profile.avatar
        ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : '';
      const discordTag = `${profile.username}#${profile.discriminator || '0'}`;
      stmt.upsertDiscord.run(profile.global_name || profile.username, profile.id, discordTag, avatar);
      done(null, stmt.findByDiscordId.get(profile.id));
    } catch(e) { done(e); }
  }));
}

function oauthSuccess(req, res) {
  if (!req.user) return res.redirect('/login.html?error=oauth_failed');
  const token = makeJWT(req.user);
  const user  = encodeURIComponent(JSON.stringify({ id:req.user.id, name:req.user.name, email:req.user.email||'' }));
  res.redirect(`/oauth-callback.html?token=${token}&user=${user}`);
}

/**
 * Guard middleware — if the OAuth credentials for a provider are missing from .env,
 * the Passport strategy was never registered. Instead of crashing with a 500
 * ("Unknown authentication strategy"), redirect to login with a clear error message.
 */
function requireStrategy(name, envKey) {
  return (req, res, next) => {
    if (!process.env[envKey]) {
      console.warn(`⚠️  ${name} OAuth not configured — add ${envKey} to .env`);
      return res.redirect(`/login.html?error=${name}_not_configured`);
    }
    next();
  };
}

// Google
app.get('/auth/google',
  requireStrategy('google', 'GOOGLE_CLIENT_ID'),
  passport.authenticate('google', { accessType:'offline', prompt:'consent' })
);
app.get('/auth/google/callback',
  requireStrategy('google', 'GOOGLE_CLIENT_ID'),
  passport.authenticate('google', { session:false, failureRedirect:'/login.html?error=google_failed' }),
  oauthSuccess
);

// GitHub
app.get('/auth/github',
  requireStrategy('github', 'GITHUB_CLIENT_ID'),
  passport.authenticate('github')
);
app.get('/auth/github/callback',
  requireStrategy('github', 'GITHUB_CLIENT_ID'),
  passport.authenticate('github', { session:false, failureRedirect:'/login.html?error=github_failed' }),
  oauthSuccess
);

// Discord
app.get('/auth/discord',
  requireStrategy('discord', 'DISCORD_CLIENT_ID'),
  passport.authenticate('discord')
);
app.get('/auth/discord/callback',
  requireStrategy('discord', 'DISCORD_CLIENT_ID'),
  passport.authenticate('discord', { session:false, failureRedirect:'/login.html?error=discord_failed' }),
  oauthSuccess
);

/* ═══════════════════════════════════════════
   AUTH ROUTES
═══════════════════════════════════════════ */
app.post('/api/signup', async (req,res) => {
  const { name, email, password } = req.body;
  if (!name||!email||!password) return res.status(400).json({ error:'All fields required' });
  if (password.length < 6)      return res.status(400).json({ error:'Password must be 6+ characters' });
  try {
    const hash   = await bcrypt.hash(password, 12);
    const result = stmt.insertUser.run(name, email, hash, email.split('@')[0]);
    const user   = { id:result.lastInsertRowid, name, email };
    res.status(201).json({ token:makeJWT(user), user });
  } catch(err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ error:'Email already registered' });
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/api/login', async (req,res) => {
  const { email, password } = req.body;
  if (!email||!password) return res.status(400).json({ error:'Email and password required' });
  const user = stmt.findByEmail.get(email);
  if (!user||!user.password_hash) return res.status(401).json({ error:'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error:'Invalid credentials' });
  const payload = { id:user.id, name:user.name, email:user.email };
  res.json({ token:makeJWT(payload), user:payload });
});

/* ═══════════════════════════════════════════
   USER ROUTES
═══════════════════════════════════════════ */
app.get('/api/users', authenticate, (req,res) =>
  res.json(stmt.allUsers.all().filter(u=>u.id!==req.user.id).map(safeUser))
);
app.get('/api/users/:id', authenticate, (req,res) => {
  const u = stmt.findById.get(req.params.id);
  if (!u) return res.status(404).json({ error:'Not found' });
  res.json(safeUser(u));
});
app.post('/api/users/me/public-key', authenticate, (req,res) => {
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error:'publicKey required' });
  stmt.updatePublicKey.run(JSON.stringify(publicKey), req.user.id);
  res.json({ message:'Public key stored' });
});
app.get('/api/users/:id/public-key', authenticate, (req,res) => {
  const u = stmt.findById.get(req.params.id);
  if (!u||!u.public_key) return res.status(404).json({ error:'No public key' });
  res.json({ publicKey: JSON.parse(u.public_key) });
});

/* ═══════════════════════════════════════════
   MESSAGE ROUTES
═══════════════════════════════════════════ */
app.get('/api/messages/:toId', authenticate, (req,res) =>
  res.json(stmt.getMessages.all(req.user.id, req.params.toId, req.params.toId, req.user.id))
);
app.post('/api/messages', authenticate, (req,res) => {
  const { to_user, ciphertext, iv } = req.body;
  if (!to_user||!ciphertext||!iv) return res.status(400).json({ error:'to_user, ciphertext, iv required' });
  const result = stmt.insertMessage.run(req.user.id, to_user, ciphertext, iv);
  res.status(201).json({ id:result.lastInsertRowid });
});

/* ═══════════════════════════════════════════
   MEETING ROUTES
═══════════════════════════════════════════ */
app.get('/api/meetings', authenticate, (req,res) =>
  res.json(stmt.getMeetingsByUser.all(req.user.id, req.user.id))
);

app.post('/api/meetings', authenticate, async (req,res) => {
  const { peer_id, title, description='', scheduled_at, duration_min=60, platform='google_meet', notes='' } = req.body;
  if (!peer_id||!title||!scheduled_at||!platform)
    return res.status(400).json({ error:'peer_id, title, scheduled_at, platform required' });

  const me   = stmt.findById.get(req.user.id);
  const peer = stmt.findById.get(peer_id);
  if (!peer) return res.status(404).json({ error:'Peer not found' });

  let meetLink='', discordInfo='';

  if (platform === 'google_meet') {
    if (me.google_access_token) {
      try {
        const auth = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
        auth.setCredentials({ access_token: me.google_access_token, refresh_token: me.google_refresh_token });
        const calendar  = google.calendar({ version:'v3', auth });
        const startDt   = new Date(scheduled_at);
        const endDt     = new Date(startDt.getTime() + duration_min * 60000);
        const attendees = [{ email:me.email }];
        if (peer.email) attendees.push({ email:peer.email });

        const event = await calendar.events.insert({
          calendarId:'primary', conferenceDataVersion:1, sendUpdates:'all',
          requestBody: {
            summary:     `SkillSwap: ${title}`,
            description: description || `Skill swap: ${me.name} ↔ ${peer.name}`,
            start: { dateTime: startDt.toISOString() },
            end:   { dateTime: endDt.toISOString() },
            attendees,
            conferenceData: { createRequest: { requestId:uuid(), conferenceSolutionKey:{ type:'hangoutsMeet' } } },
          },
        });
        meetLink = event.data.hangoutLink || event.data.conferenceData?.entryPoints?.[0]?.uri || '';
      } catch(e) {
        console.error('Calendar API error:', e.message);
        meetLink = `https://meet.jit.si/SkillSwap-${uuid().slice(0,8)}`;
      }
    } else {
      meetLink = `https://meet.jit.si/SkillSwap-${uuid().slice(0,8)}`;
    }
  }

  if (platform === 'discord') {
    discordInfo = JSON.stringify({
      myTag:   me.discord_username   || '(not connected via Discord)',
      peerTag: peer.discord_username || '(not connected via Discord)',
    });
  }

  const result  = stmt.insertMeeting.run(req.user.id, peer_id, title, description, scheduled_at, duration_min, platform, meetLink, discordInfo, notes);
  const meeting = stmt.getMeetingById.get(result.lastInsertRowid);

  /* Notify peer in real time */
  const peerSocket = onlineUsers.get(String(peer_id));
  if (peerSocket) io.to(peerSocket).emit('meeting_invite', { meeting, proposerName:me.name });

  res.status(201).json(meeting);
});

app.patch('/api/meetings/:id/status', authenticate, (req,res) => {
  const { status } = req.body;
  if (!['confirmed','cancelled'].includes(status))
    return res.status(400).json({ error:'status must be confirmed or cancelled' });
  const meeting = stmt.getMeetingById.get(req.params.id);
  if (!meeting) return res.status(404).json({ error:'Meeting not found' });

  const isProposer = meeting.proposer_id === req.user.id;
  const isPeer     = meeting.peer_id     === req.user.id;
  if (!isProposer && !isPeer) return res.status(403).json({ error:'Not your meeting' });
  if (status==='confirmed' && !isPeer) return res.status(403).json({ error:'Only the invitee can confirm' });

  stmt.updateMtgStatus.run(status, meeting.id);

  const otherId = isProposer ? meeting.peer_id : meeting.proposer_id;
  const otherSocket = onlineUsers.get(String(otherId));
  if (otherSocket) io.to(otherSocket).emit('meeting_update', { meetingId:meeting.id, status });

  res.json({ ...meeting, status });
});

/* ═══════════════════════════════════════════
   SOCKET.IO
═══════════════════════════════════════════ */
const onlineUsers = new Map();

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  const uid = String(socket.user.id);
  onlineUsers.set(uid, socket.id);
  console.log(`🔌  ${socket.user.name} connected`);

  socket.on('send_message', ({ toUserId, ciphertext, iv, time }) => {
    try { stmt.insertMessage.run(socket.user.id, String(toUserId), ciphertext, iv); } catch {}
    const s = onlineUsers.get(String(toUserId));
    if (s) io.to(s).emit('receive_message', { fromUserId:socket.user.id, ciphertext, iv, time: time||new Date().toLocaleTimeString('en-US',{hour:'numeric',minute:'2-digit'}) });
  });

  socket.on('typing',      ({toUserId}) => { const s=onlineUsers.get(String(toUserId)); if(s) io.to(s).emit('user_typing',     {fromUserId:socket.user.id}); });
  socket.on('stop_typing', ({toUserId}) => { const s=onlineUsers.get(String(toUserId)); if(s) io.to(s).emit('user_stop_typing',{fromUserId:socket.user.id}); });

  socket.on('disconnect', () => { onlineUsers.delete(uid); console.log(`❌  ${socket.user.name} disconnected`); });
});

/* ═══════════════════════════════════════════
   START
═══════════════════════════════════════════ */
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`\n🚀  SkillSwap backend → http://localhost:${PORT}`);
  console.log(`🔒  OAuth: Google=${!!process.env.GOOGLE_CLIENT_ID} | GitHub=${!!process.env.GITHUB_CLIENT_ID} | Discord=${!!process.env.DISCORD_CLIENT_ID}\n`);
});