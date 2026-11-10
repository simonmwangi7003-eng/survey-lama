require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcrypt'), jwt = require('jsonwebtoken');
const cors = require('cors'), helmet = require('helmet'), rateLimit = require('express-rate-limit'), QR = require('qrcode');
const crypto = require('crypto'), path = require('path');
const { Schema, model } = mongoose;
const { MONGO_URI = 'mongodb://127.0.0.1:27017/surveyflow', JWT_SECRET, PORT = 3000, CORS_ORIGIN = '' } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 16) { console.error('Set JWT_SECRET (16+ chars) in .env'); process.exit(1); }

/* ---------- Models ---------- */
const User = model('User', new Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  bio: { type: String, maxlength: 300, default: '' },
  notifications: { type: Boolean, default: true },
  theme: { type: String, enum: ['light', 'dark'], default: 'light' }
}, { timestamps: true }));
const TYPES = ['single', 'multiple', 'checkbox', 'short', 'long', 'rating', 'linear', 'yesno', 'dropdown', 'date'];
const Survey = model('Survey', new Schema({
  owner: { type: Schema.Types.ObjectId, ref: 'User', index: true, required: true },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  description: { type: String, maxlength: 2000, default: '' },
  cover: { type: String, maxlength: 700000, default: '' },
  questions: [{ type: { type: String, enum: TYPES, required: true }, text: { type: String, required: true, maxlength: 500 },
    required: Boolean, options: [String], min: Number, max: Number }],
  status: { type: String, enum: ['draft', 'active', 'closed'], default: 'draft', index: true },
  publicId: { type: String, unique: true, index: true },
  startDate: Date, closeDate: Date, responseLimit: Number,
  anonymous: { type: Boolean, default: true }, views: { type: Number, default: 0 }
}, { timestamps: true }));
const Resp = model('Response', new Schema({
  survey: { type: Schema.Types.ObjectId, ref: 'Survey', index: true, required: true },
  participant: { name: String, email: String },
  answers: { type: Schema.Types.Mixed, default: {} },
  complete: { type: Boolean, default: true }, fp: String
}, { timestamps: true }));
Resp.schema.index({ survey: 1, fp: 1 });

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors(CORS_ORIGIN ? { origin: CORS_ORIGIN.split(',') } : {}));
app.use(express.json({ limit: '1mb' }));
const clean = o => Array.isArray(o) ? o.map(clean) : o && typeof o === 'object'
  ? Object.fromEntries(Object.entries(o).filter(([k]) => !k.startsWith('$') && !k.includes('.')).map(([k, v]) => [k, clean(v)])) : o;
app.use((q, s, n) => { q.body = clean(q.body || {}); n(); }); // NoSQL-injection guard
const authLimit = rateLimit({ windowMs: 15 * 60e3, limit: 30, message: { error: 'Too many attempts. Try again later.' } });
const pubLimit = rateLimit({ windowMs: 15 * 60e3, limit: 60, message: { error: 'Too many submissions. Try again later.' } });

const str = v => (typeof v === 'string' ? v : '');
const sign = u => jwt.sign({ id: u._id }, JWT_SECRET, { expiresIn: '7d' });
const safe = u => ({ id: u._id, name: u.name, email: u.email, bio: u.bio, notifications: u.notifications, theme: u.theme, createdAt: u.createdAt });
const auth = async (q, s, n) => {
  try { q.user = jwt.verify((q.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET).id; n(); }
  catch { s.status(401).json({ error: 'Please sign in again.' }); }
};
const own = async (q, s, n) => {
  if (!mongoose.isValidObjectId(q.params.id)) return s.status(404).json({ error: 'Survey not found.' });
  q.sv = await Survey.findOne({ _id: q.params.id, owner: q.user });
  q.sv ? n() : s.status(404).json({ error: 'Survey not found.' });
};

/* ---------- Auth & profile ---------- */
app.post('/api/auth/register', authLimit, async (q, s) => {
  const name = str(q.body.name).trim(), email = str(q.body.email).trim().toLowerCase(), pw = str(q.body.password);
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return s.status(400).json({ error: 'Enter your name and a valid email.' });
  if (pw.length < 8) return s.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (await User.findOne({ email })) return s.status(409).json({ error: 'An account with this email already exists.' });
  const u = await User.create({ name, email, password: await bcrypt.hash(pw, 12) });
  s.status(201).json({ token: sign(u), user: safe(u) });
});
app.post('/api/auth/login', authLimit, async (q, s) => {
  const u = await User.findOne({ email: str(q.body.email).trim().toLowerCase() });
  if (!u || !(await bcrypt.compare(str(q.body.password), u.password))) return s.status(401).json({ error: 'Incorrect email or password.' });
  s.json({ token: sign(u), user: safe(u) });
});
app.post('/api/auth/forgot', authLimit, (q, s) => s.json({ message: 'If that email has an account, reset instructions have been sent.' })); // wire an email provider here
app.get('/api/me', auth, async (q, s) => s.json(safe(await User.findById(q.user))));
app.put('/api/me', auth, async (q, s) => {
  const u = await User.findById(q.user), b = q.body;
  if (b.name !== undefined) u.name = str(b.name).trim() || u.name;
  if (b.bio !== undefined) u.bio = str(b.bio).slice(0, 300);
  if (typeof b.notifications === 'boolean') u.notifications = b.notifications;
  if (['light', 'dark'].includes(b.theme)) u.theme = b.theme;
  await u.save(); s.json(safe(u));
});
app.put('/api/me/password', auth, async (q, s) => {
  const u = await User.findById(q.user);
  if (!(await bcrypt.compare(str(q.body.current), u.password))) return s.status(400).json({ error: 'Current password is incorrect.' });
  if (str(q.body.next).length < 8) return s.status(400).json({ error: 'New password must be at least 8 characters.' });
  u.password = await bcrypt.hash(q.body.next, 12); await u.save(); s.json({ ok: true });
});

/* ---------- Surveys ---------- */
const F = ['title', 'description', 'cover', 'questions', 'startDate', 'closeDate', 'responseLimit', 'anonymous'];
const pick = b => {
  const o = Object.fromEntries(F.filter(k => k in b).map(k => [k, b[k]]));
  if (o.questions) o.questions = o.questions.map(x => ({ ...(/^[a-f0-9]{24}$/.test(x._id) ? { _id: x._id } : {}),
    type: x.type, text: str(x.text).trim(), required: !!x.required, options: (x.options || []).map(str).filter(Boolean), min: x.min, max: x.max }));
  for (const k of ['startDate', 'closeDate', 'responseLimit']) if (o[k] === '' || o[k] === null) o[k] = undefined;
  return o;
};
const pid = () => crypto.randomBytes(5).toString('hex');
const counts = async ids => {
  const a = await Resp.aggregate([{ $match: { survey: { $in: ids } } }, { $group: { _id: '$survey', n: { $sum: 1 } } }]);
  return Object.fromEntries(a.map(x => [String(x._id), x.n]));
};
app.get('/api/surveys', auth, async (q, s) => {
  const f = { owner: q.user };
  if (['draft', 'active', 'closed'].includes(q.query.status)) f.status = q.query.status;
  if (q.query.q) f.title = { $regex: String(q.query.q).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
  const list = await Survey.find(f).sort('-updatedAt').lean(), c = await counts(list.map(x => x._id));
  s.json(list.map(x => ({ ...x, cover: undefined, responses: c[String(x._id)] || 0 })));
});
app.post('/api/surveys', auth, async (q, s) => {
  const d = pick(q.body); if (!d.title) return s.status(400).json({ error: 'Add a survey title.' });
  s.status(201).json(await Survey.create({ ...d, owner: q.user, publicId: pid() }));
});
app.get('/api/surveys/:id', auth, own, (q, s) => s.json(q.sv));
app.put('/api/surveys/:id', auth, own, async (q, s) => {
  const d = pick(q.body); if (d.title === '') return s.status(400).json({ error: 'Add a survey title.' });
  q.sv.set(d); await q.sv.save(); s.json(q.sv);
});
app.delete('/api/surveys/:id', auth, own, async (q, s) => { await Resp.deleteMany({ survey: q.sv._id }); await q.sv.deleteOne(); s.json({ ok: true }); });
app.post('/api/surveys/:id/duplicate', auth, own, async (q, s) => {
  const o = q.sv.toObject(); delete o._id; delete o.createdAt; delete o.updatedAt;
  s.status(201).json(await Survey.create({ ...o, title: o.title + ' (copy)', status: 'draft', views: 0, publicId: pid(),
    questions: o.questions.map(({ _id, ...r }) => r) }));
});
app.post('/api/surveys/:id/status', auth, own, async (q, s) => {
  if (!['draft', 'active', 'closed'].includes(q.body.status)) return s.status(400).json({ error: 'Invalid status.' });
  if (q.body.status === 'active' && !q.sv.questions.length) return s.status(400).json({ error: 'Add at least one question before publishing.' });
  q.sv.status = q.body.status; await q.sv.save(); s.json(q.sv);
});
app.get('/api/surveys/:id/qr', auth, own, async (q, s) =>
  s.json({ dataUrl: await QR.toDataURL(`${q.protocol}://${q.get('host')}/#/s/${q.sv.publicId}`, { margin: 1, width: 240 }) }));

/* ---------- Analytics, responses, export ---------- */
app.get('/api/surveys/:id/analytics', auth, own, async (q, s) => {
  const sv = q.sv, rs = await Resp.find({ survey: sv._id }).lean(), day = {};
  rs.forEach(r => { const d = r.createdAt.toISOString().slice(0, 10); day[d] = (day[d] || 0) + 1; });
  const questions = sv.questions.map(qs => {
    const id = String(qs._id), vals = rs.map(r => r.answers?.[id]).filter(v => v !== undefined && v !== '' && !(Array.isArray(v) && !v.length));
    const o = { id, text: qs.text, type: qs.type, count: vals.length, counts: {} };
    if (['short', 'long', 'date'].includes(qs.type)) o.texts = vals.slice(-25);
    else { vals.flat().forEach(v => { o.counts[v] = (o.counts[v] || 0) + 1; });
      if (['rating', 'linear'].includes(qs.type)) o.avg = vals.length ? vals.reduce((a, b) => a + Number(b), 0) / vals.length : 0; }
    return o;
  });
  s.json({ total: rs.length, views: sv.views, completion: sv.views ? Math.min(100, Math.round(rs.length / sv.views * 100)) : 0, trend: day, questions });
});
app.get('/api/surveys/:id/responses', auth, own, async (q, s) => {
  let rs = await Resp.find({ survey: q.sv._id }).sort('-createdAt').limit(500).lean();
  const t = String(q.query.q || '').toLowerCase();
  if (t) rs = rs.filter(r => JSON.stringify([r.participant, r.answers]).toLowerCase().includes(t));
  s.json({ questions: q.sv.questions, responses: rs });
});
app.get('/api/surveys/:id/export', auth, own, async (q, s) => {
  const rs = await Resp.find({ survey: q.sv._id }).sort('createdAt').lean();
  const esc = v => { v = Array.isArray(v) ? v.join('; ') : v ?? ''; v = String(v); if (/^[=+\-@]/.test(v)) v = "'" + v; return `"${v.replace(/"/g, '""')}"`; };
  const rows = [['Submitted', 'Name', 'Email', ...q.sv.questions.map(x => x.text)].map(esc).join(',')];
  rs.forEach(r => rows.push([r.createdAt.toISOString(), r.participant?.name, r.participant?.email, ...q.sv.questions.map(x => r.answers?.[String(x._id)])].map(esc).join(',')));
  s.set({ 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="responses.csv"' }).send(rows.join('\n'));
});
app.get('/api/dashboard', auth, async (q, s) => {
  const sv = await Survey.find({ owner: q.user }).sort('-updatedAt').lean(), ids = sv.map(x => x._id), c = await counts(ids);
  const total = Object.values(c).reduce((a, b) => a + b, 0), views = sv.reduce((a, b) => a + b.views, 0);
  const since = new Date(Date.now() - 13 * 864e5); since.setHours(0, 0, 0, 0);
  const recent = await Resp.find({ survey: { $in: ids } }).sort('-createdAt').limit(8).lean();
  const trend = {}; (await Resp.find({ survey: { $in: ids }, createdAt: { $gte: since } }, 'createdAt').lean())
    .forEach(r => { const d = r.createdAt.toISOString().slice(0, 10); trend[d] = (trend[d] || 0) + 1; });
  const title = Object.fromEntries(sv.map(x => [String(x._id), x.title]));
  s.json({ total: sv.length, active: sv.filter(x => x.status === 'active').length, responses: total,
    completion: views ? Math.min(100, Math.round(total / views * 100)) : 0, trend,
    surveys: sv.slice(0, 5).map(x => ({ _id: x._id, title: x.title, status: x.status, responses: c[String(x._id)] || 0 })),
    recent: recent.map(r => ({ title: title[String(r.survey)], at: r.createdAt, who: r.participant?.name || 'Anonymous' })),
    activity: sv.slice(0, 6).map(x => ({ title: x.title, at: x.updatedAt, status: x.status })) });
});

/* ---------- Public participation ---------- */
const availability = (sv, n) => sv.status !== 'active' ? 'This survey is not accepting responses.'
  : sv.startDate && sv.startDate > new Date() ? 'This survey has not opened yet.'
  : sv.closeDate && sv.closeDate < new Date() ? 'This survey has closed.'
  : sv.responseLimit && n >= sv.responseLimit ? 'This survey has reached its response limit.' : null;
app.get('/api/public/:pid', pubLimit, async (q, s) => {
  const sv = await Survey.findOneAndUpdate({ publicId: str(q.params.pid) }, { $inc: { views: 1 } }).lean();
  if (!sv || sv.status === 'draft') return s.status(404).json({ error: 'Survey not found.' });
  const msg = availability(sv, await Resp.countDocuments({ survey: sv._id }));
  s.json({ title: sv.title, description: sv.description, cover: sv.cover, anonymous: sv.anonymous, unavailable: msg, questions: msg ? [] : sv.questions });
});
app.post('/api/public/:pid/submit', pubLimit, async (q, s) => {
  const sv = await Survey.findOne({ publicId: str(q.params.pid) });
  if (!sv) return s.status(404).json({ error: 'Survey not found.' });
  const msg = availability(sv, await Resp.countDocuments({ survey: sv._id })); if (msg) return s.status(403).json({ error: msg });
  const a = q.body.answers && typeof q.body.answers === 'object' ? q.body.answers : {}, out = {};
  for (const x of sv.questions) {
    const id = String(x._id); let v = a[id];
    const empty = v === undefined || v === '' || v === false || (Array.isArray(v) && !v.length);
    if (empty) { if (x.required) return s.status(400).json({ error: `Please answer: ${x.text}` }); continue; }
    if (Array.isArray(v)) v = v.map(str); else if (typeof v !== 'boolean') v = String(v).slice(0, 5000);
    if (['single', 'dropdown'].includes(x.type) && !x.options.includes(v)) return s.status(400).json({ error: `Invalid answer: ${x.text}` });
    if (x.type === 'multiple' && !v.every?.(o => x.options.includes(o))) return s.status(400).json({ error: `Invalid answer: ${x.text}` });
    out[id] = x.type === 'checkbox' ? 'Yes' : v;
  }
  const fp = crypto.createHash('sha256').update(q.ip + (q.headers['user-agent'] || '')).digest('hex');
  if (await Resp.exists({ survey: sv._id, fp })) return s.status(409).json({ error: 'A response from this device was already submitted.' });
  await Resp.create({ survey: sv._id, fp, answers: out, participant: sv.anonymous ? {} : { name: str(q.body.name).slice(0, 80), email: str(q.body.email).slice(0, 120) } });
  s.status(201).json({ ok: true });
});

/* ---------- Static + errors ---------- */
app.use(express.static(path.join(__dirname, 'public')));
app.get(/^(?!\/api).*/, (q, s) => s.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((e, q, s, n) => { console.error(e); s.status(e.status || 500).json({ error: e.status ? e.message : 'Something went wrong.' }); });

mongoose.connect(MONGO_URI).then(() => app.listen(PORT, () => console.log(`SurveyFlow running on http://localhost:${PORT}`)))
  .catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
