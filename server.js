const express = require('express'), multer = require('multer'), AdmZip = require('adm-zip'), cors = require('cors'),
  fs = require('fs'), path = require('path'), os = require('os'), crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;
const PASS = process.env.ADMIN_PASSWORD || 'hamzanjar8000.H';
// مجلد التخزين: اضبط DATA_DIR على مسار القرص الدائم (Persistent Disk) ليبقى كل شيء بعد إعادة التشغيل
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data')); fs.mkdirSync(DATA, { recursive: true });
// معرّف هذه النسخة من التخزين: إذا اختفت البيانات (قرص مؤقت) يتغير المعرّف فيعرف المتصفح أن عليه الاستعادة
const INSTANCE = (() => {
  const f = path.join(DATA, '.instance');
  try { const v = fs.readFileSync(f, 'utf8').trim(); if (v) return v; } catch {}
  const v = crypto.randomBytes(8).toString('hex'); try { fs.writeFileSync(f, v); } catch {} return v;
})();
const LOGS = [];
const log = (pid, m) => { LOGS.push({ t: new Date().toISOString(), p: pid || '-', m }); if (LOGS.length > 1000) LOGS.shift(); console.log(`[${pid || '-'}] ${m}`); };

// ---------- الدخول (رمز موقّع بدون جلسات في الذاكرة => لا يُطلب الدخول مجدداً بعد إعادة تشغيل السيرفر) ----------
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('hz:' + PASS).digest('hex');
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const mkTok = () => { const e = Date.now() + 30 * 864e5; return e + '.' + sign('auth.' + e); };
const okTok = t => {
  const [e, s] = String(t || '').split('.'); if (!e || !s || +e < Date.now()) return false;
  const a = Buffer.from(s), b = Buffer.from(sign('auth.' + e)); return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const cookieOf = (req, n) => { const c = (req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(n + '=')); return c ? c.slice(n.length + 1) : ''; };

app.set('trust proxy', 1);
app.use(cors({ origin: false }));

// ---------- وكيل عام لصفحة تسجيل البوت وواجهتها (بدون كلمة مرور المنصة) ----------
// الصفحة: /register  —  الواجهة: /api/flow/* (محددة بقائمة بيضاء). البوت يعمل داخلياً على BOT_PORT.
const http = require('http');
const BOT_PORT = Number(process.env.BOT_PORT) || 8080;
const PUBLIC_BOT = /^\/(register\/?(\?|$)|api\/flow\/(check-session|check-nickname|status|submit|health)\/?(\?|$)|api\/app\/crystal\/(open|info|spin)\/?(\?|$))/;
app.use((req, res, next) => {
  if (!PUBLIC_BOT.test(req.url)) return next();
  const pr = http.request({ host: '127.0.0.1', port: BOT_PORT, path: req.originalUrl, method: req.method, headers: { ...req.headers, host: '127.0.0.1:' + BOT_PORT } }, r => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
  pr.setTimeout(20000, () => pr.destroy(new Error('timeout')));
  pr.on('error', () => { if (!res.headersSent) res.status(502).type('text/html; charset=utf-8').send('<meta charset="utf-8"><body style="font-family:sans-serif;text-align:center;padding:40px;background:#050b1f;color:#fff"><h2>📡 البوت غير متاح الآن</h2><p>حاول بعد قليل.</p>'); else res.end(); });
  req.pipe(pr);
});
app.use(express.json({ limit: '20mb' }));

app.get('/api/ping', (req, res) => res.set('Cache-Control', 'no-store').json({ t: Date.now() })); // قياس زمن الاستجابة
app.get('/api/speedtest', (req, res) => {
  // عينة ثابتة صغيرة لقياس معدل النقل الفعلي بين المتصفح والخادم دون الاعتماد على Network Information API.
  const sample = Buffer.alloc(256 * 1024);
  res.set({ 'Content-Type': 'application/octet-stream', 'Content-Length': String(sample.length), 'Cache-Control': 'no-store, no-cache, must-revalidate', 'X-Content-Type-Options': 'nosniff' });
  res.end(sample);
});
app.post('/api/login', (req, res) => {
  const a = Buffer.from(String(req.body.password || '')), b = Buffer.from(PASS);
  if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
    res.cookie('hz_auth', mkTok(), { httpOnly: true, sameSite: 'lax', secure: req.secure, maxAge: 30 * 864e5 });
    log(null, 'تسجيل دخول ناجح'); return res.json({ ok: true });
  }
  log(null, 'محاولة دخول فاشلة'); res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
});
app.post('/api/logout', (req, res) => { res.clearCookie('hz_auth'); res.json({ ok: true }); });
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public/login.html')));
app.use((req, res, next) => {
  if (okTok(cookieOf(req, 'hz_auth'))) return next();
  if (req.path.startsWith('/api')) return res.status(401).json({ error: 'غير مصرح' });
  res.redirect('/login.html');
});
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

// ---------- helpers ----------
const okId = id => /^[a-zA-Z0-9_-]{1,40}$/.test(id);
const pdir = id => path.join(DATA, id);
const metaP = id => path.join(pdir(id), 'meta.json');
const defMeta = name => ({ name, keys: {}, vars: [], ai: { model: 'gpt-4o-mini', system: 'أنت مساعد برمجي خبير يساعد مدير المنصة. أجب بالعربية وباختصار شديد وبشكل مباشر.' } });
// كتابة آمنة: ملف مؤقت ثم إعادة تسمية + نسخة .bak (حتى لا يتلف الملف عند انقطاع مفاجئ فتختفي المنصات)
const writeMeta = (id, o) => {
  const p = metaP(id), t = p + '.tmp';
  fs.writeFileSync(t, JSON.stringify(o, null, 2));
  if (fs.existsSync(p)) { try { fs.copyFileSync(p, p + '.bak'); } catch {} }
  fs.renameSync(t, p);
};
const getMeta = id => {
  for (const f of [metaP(id), metaP(id) + '.bak']) {
    try {
      const m = JSON.parse(fs.readFileSync(f, 'utf8')), d = defMeta(m.name || id);
      return { ...d, ...m, keys: m.keys || {}, vars: Array.isArray(m.vars) ? m.vars : [], ai: { ...d.ai, ...(m.ai || {}) } };
    } catch {}
  }
  return defMeta(id);
};
const safe = (id, rel = '') => {
  const base = path.join(pdir(id), 'files');
  const p = path.resolve(base, '.' + path.sep + String(rel));
  if (p !== base && !p.startsWith(base + path.sep)) throw new Error('مسار غير مسموح');
  return p;
};
const wrap = fn => (req, res) => { try { Promise.resolve(fn(req, res)).catch(e => res.status(400).json({ error: e.message })); } catch (e) { res.status(400).json({ error: e.message }); } };
app.param('id', (req, res, next, id) => { if (!okId(id) || !fs.existsSync(pdir(id))) return res.status(404).json({ error: 'منصة غير موجودة' }); next(); });
const copyRec = (a, b) => fs.cpSync(a, b, { recursive: true });
const platIds = () => fs.readdirSync(DATA).filter(i => okId(i) && fs.existsSync(metaP(i)));

// مشي على ملفات المنصة (بدون node_modules و .git)
const SKIP = new Set(['node_modules', '.git']);
function walk(dir, cb, rel = '') {
  let list = []; try { list = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of list) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(dir, e.name), r = rel ? rel + '/' + e.name : e.name;
    if (e.isDirectory()) { cb(p, r, null, true); walk(p, cb, r); }
    else if (e.isFile()) { let s; try { s = fs.statSync(p); } catch { continue; } cb(p, r, s, false); }
  }
}
const SIGC = {};
const sigOf = id => {
  const c = SIGC[id]; if (c && Date.now() - c.t < 2000) return c.v;
  let n = 0, sz = 0, mt = 0;
  walk(safe(id), (p, r, s, d) => { if (!d) { n++; sz += s.size; mt = Math.max(mt, s.mtimeMs); } });
  try { mt = Math.max(mt, fs.statSync(metaP(id)).mtimeMs); } catch {}
  const v = { files: n, size: sz, sig: n + '-' + sz + '-' + Math.round(mt) }; SIGC[id] = { t: Date.now(), v }; return v;
};

const BOT_REPO = String(process.env.BOT_REPO || '').trim(), BOT_ID = 'bot';
const BOT_KEEP = String(process.env.BOT_KEEP || 'database.json,database.json.bak,session,pairing_state.json').split(',').map(x => x.trim()).filter(Boolean);
if (BOT_REPO && !fs.existsSync(metaP(BOT_ID))) {          // منصة البوت الوحيدة: تُنشأ تلقائياً من متغير BOT_REPO
  fs.mkdirSync(path.join(DATA, BOT_ID, 'files'), { recursive: true });
  writeMeta(BOT_ID, { ...defMeta('البوت'), autostart: true, keep: BOT_KEEP, github: { url: 'https://github.com/' + BOT_REPO.replace(/^https?:\/\/github\.com\//, ''), branch: String(process.env.BOT_BRANCH || '').trim(), subdir: '' } });
}
if (!platIds().length) { fs.mkdirSync(path.join(DATA, 'main/files'), { recursive: true }); writeMeta('main', defMeta('المنصة الرئيسية')); }

// ---------- إحصائيات النظام (المعالج / الذاكرة / حمل النظام) ----------
const rd = f => { try { return fs.readFileSync(f, 'utf8'); } catch { return null; } };
const kv = (txt, key) => { const m = txt && txt.match(new RegExp('^' + key + '\\s+(\\d+)', 'm')); return m ? +m[1] : null; };
let CPU0 = null, SYS = { t: 0 };
function cpuSample() {
  const s2 = rd('/sys/fs/cgroup/cpu.stat');
  if (s2 && kv(s2, 'usage_usec') != null) {
    let cores = os.cpus().length; const mx = (rd('/sys/fs/cgroup/cpu.max') || '').trim().split(/\s+/);
    if (mx[0] && mx[0] !== 'max' && +mx[0] > 0 && +mx[1] > 0) cores = mx[0] / mx[1];
    return { mode: 'cg', used: kv(s2, 'usage_usec'), cores, t: Date.now() };
  }
  const u1 = rd('/sys/fs/cgroup/cpuacct/cpuacct.usage');
  if (u1) {
    let cores = os.cpus().length; const q = +rd('/sys/fs/cgroup/cpu/cpu.cfs_quota_us'), p = +rd('/sys/fs/cgroup/cpu/cpu.cfs_period_us');
    if (q > 0 && p > 0) cores = q / p; return { mode: 'cg', used: +u1 / 1000, cores, t: Date.now() };
  }
  let idle = 0, tot = 0; for (const c of os.cpus()) { for (const k in c.times) tot += c.times[k]; idle += c.times.idle; }
  return { mode: 'os', idle, tot, t: Date.now() };
}
function cpuPct() {
  const n = cpuSample(), o = CPU0; CPU0 = n; if (!o || o.mode !== n.mode) return 0;
  if (n.mode === 'cg') { const dt = (n.t - o.t) * 1000; return dt > 0 ? Math.min(100, Math.max(0, (n.used - o.used) / (dt * n.cores) * 100)) : 0; }
  const dt = n.tot - o.tot; return dt > 0 ? Math.min(100, Math.max(0, (1 - (n.idle - o.idle) / dt) * 100)) : 0;
}
function memInfo() {
  const total = os.totalmem(); let used = null, limit = total;
  const cur = rd('/sys/fs/cgroup/memory.current'), max = rd('/sys/fs/cgroup/memory.max');
  if (cur) { limit = max && max.trim() !== 'max' ? Math.min(+max, total) : total; used = +cur - (kv(rd('/sys/fs/cgroup/memory.stat'), 'inactive_file') || 0); }
  else {
    const u = rd('/sys/fs/cgroup/memory/memory.usage_in_bytes'), l = rd('/sys/fs/cgroup/memory/memory.limit_in_bytes');
    if (u) { limit = l && +l < total ? +l : total; used = +u - (kv(rd('/sys/fs/cgroup/memory/memory.stat'), 'total_inactive_file') || 0); }
  }
  if (used == null) { const a = kv(rd('/proc/meminfo'), 'MemAvailable:'); used = a != null ? total - a * 1024 : total - os.freemem(); }
  return { used, limit, pct: Math.min(100, Math.max(0, used / limit * 100)) };
}
function treeMem(pid) { // ذاكرة عملية المنصة وكل ما تفرّع منها
  try {
    const kids = {};
    for (const d of fs.readdirSync('/proc')) {
      if (!/^\d+$/.test(d)) continue; const st = rd('/proc/' + d + '/stat'); if (!st) continue;
      const pp = st.slice(st.lastIndexOf(')') + 2).split(' ')[1]; (kids[pp] = kids[pp] || []).push(d);
    }
    let total = 0; const stack = [String(pid)];
    while (stack.length) { const p = stack.pop(), s = rd('/proc/' + p + '/status'), v = s && s.match(/VmRSS:\s+(\d+)/); if (v) total += +v[1] * 1024; (kids[p] || []).forEach(k => stack.push(k)); }
    return total;
  } catch { return null; }
}
const sysStats = id => {
  const now = Date.now();
  if (now - SYS.t > 700) { const m = memInfo(); SYS = { t: now, cpu: cpuPct(), mem: m.pct, used: m.used, limit: m.limit }; }
  const p = PROCS[id], pm = p && p.child ? treeMem(p.child.pid) : null;
  return { cpu: Math.round(SYS.cpu), mem: Math.round(SYS.mem), load: Math.round(Math.max(SYS.cpu, SYS.mem)),
    memUsedMB: Math.round(SYS.used / 1048576), memLimitMB: Math.round(SYS.limit / 1048576), procMB: pm == null ? null : Math.round(pm / 1048576) };
};

// ---------- process manager (تشغيل / إيقاف / كونسول / أوامر) ----------
const { spawn } = require('child_process');
const PROCS = {}, CON = {}, EXECS = {};
const ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]/g;
const con = id => CON[id] || (CON[id] = { seq: 0, lines: [], part: {} });
const cline = (id, k, m) => { const c = con(id); c.lines.push({ n: ++c.seq, k, m, t: Date.now() }); if (c.lines.length > 2000) c.lines.shift(); };
const csys = (id, m) => { cline(id, 'sys', m); log(id, m); };
const flushPart = id => { const c = con(id); for (const k of Object.keys(c.part)) if (c.part[k]) { cline(id, k, c.part[k]); c.part[k] = ''; } };
const cfeed = (id, k, d) => {
  const c = con(id), parts = ((c.part[k] || '') + String(d).replace(ANSI, '')).split(/\r?\n/);
  c.part[k] = parts.pop(); parts.forEach(m => cline(id, k, m));
  clearTimeout(c.tm); c.tm = setTimeout(() => flushPart(id), 500);
};
const killTree = (ch, sig) => { if (!ch) return; try { process.kill(-ch.pid, sig); } catch { try { ch.kill(sig); } catch {} } };
const childEnv = id => {
  const e = { ...process.env }; ['ADMIN_PASSWORD', 'SESSION_SECRET', 'PORT', 'AI_API_KEY', 'BACKUP_TOKEN', 'BOT_TOKEN', 'DATA_DIR'].forEach(k => delete e[k]);
  e.FLOW_PORT = String(BOT_PORT); e.PORT = String(BOT_PORT);
  if (!e.NODE_OPTIONS) e.NODE_OPTIONS = '--max-old-space-size=300';          // يمنع تضخم الذاكرة فيُقتل السيرفر كله
  for (const v of getMeta(id).vars) if (v.key) e[v.key] = String(v.value ?? '');
  return e;
};
// يشغّل أمر shell داخل مجلد ملفات المنصة ويمرّر المخرجات للكونسول
const runCmd = (id, holder, command, onExit) => {
  let done = false; const fin = (c, s) => { if (!done) { done = true; holder.child = null; onExit(c, s); } };
  let ch;
  try { ch = spawn('sh', ['-c', command], { cwd: safe(id), env: childEnv(id), detached: true, stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch (e) { cline(id, 'err', 'خطأ: ' + e.message); return setImmediate(() => fin(1, null)); }
  holder.child = ch;
  ch.stdout.setEncoding('utf8'); ch.stderr.setEncoding('utf8');
  ch.stdout.on('data', d => cfeed(id, 'out', d)); ch.stderr.on('data', d => cfeed(id, 'err', d));
  ch.stdin.on('error', () => {});
  ch.on('error', e => { cline(id, 'err', 'خطأ: ' + e.message); fin(1, null); });
  ch.on('exit', (c, s) => setTimeout(() => fin(c, s), 150));
};
const autoCmd = dir => {
  const pj = path.join(dir, 'package.json');
  if (fs.existsSync(pj)) { try { const j = JSON.parse(fs.readFileSync(pj, 'utf8')); if (j.scripts && j.scripts.start) return 'npm start'; if (j.main && fs.existsSync(path.join(dir, j.main))) return 'node ' + JSON.stringify(j.main); } catch {} }
  for (const f of ['index.js', 'bot.js', 'server.js', 'app.js', 'main.js']) if (fs.existsSync(path.join(dir, f))) return 'node ' + f;
  return null;
};
const RESTARTS = {}, WANT = {};
const finish = (id, p, msg) => {
  flushPart(id); if (PROCS[id] === p) delete PROCS[id]; csys(id, msg); p.waiters.forEach(f => f());
  // 🔁 إعادة تشغيل تلقائية إذا توقف البوت من تلقاء نفسه (لم يوقفه المستخدم)
  if (!p.stopping && WANT[id] && fs.existsSync(pdir(id))) {
    const r = RESTARTS[id] = RESTARTS[id] || { n: 0 };
    r.n = (Date.now() - p.startedAt > 120000) ? 1 : r.n + 1;
    if (r.n > 25) { csys(id, '✖ توقف البوت مراراً بسرعة — أُوقفت إعادة التشغيل التلقائية. راجع الأخطاء أعلاه.'); WANT[id] = false; return; }
    const delay = Math.min(60000, 3000 * Math.pow(1.6, r.n - 1));
    csys(id, `🔁 إعادة تشغيل تلقائية بعد ${Math.round(delay / 1000)} ثانية...`);
    setTimeout(() => { if (WANT[id] && !PROCS[id]) { try { startProc(id, true); } catch (e) { csys(id, '✖ ' + e.message); } } }, delay);
  }
};
const setAuto = (id, v) => { try { const m = getMeta(id); if (!!m.autostart !== v) { m.autostart = v; writeMeta(id, m); } } catch {} };
const statusOf = id => { const p = PROCS[id]; return p ? { state: p.phase, pid: (p.child && p.child.pid) || null, up: Math.round((Date.now() - p.startedAt) / 1000) } : { state: 'stopped' }; };
const startProc = (id, auto) => {
  if (PROCS[id]) throw new Error('المنصة تعمل بالفعل');
  WANT[id] = true; if (!auto) { RESTARTS[id] = { n: 0 }; setAuto(id, true); }
  const dir = safe(id); fs.mkdirSync(dir, { recursive: true });
  let cmd = String(getMeta(id).startCmd || '').trim(), install = false;
  if (!cmd) {
    cmd = autoCmd(dir);
    if (!cmd) throw new Error('لا يوجد ملف تشغيل (index.js / bot.js / package.json) في جذر الملفات. اكتب أمر التشغيل يدوياً.');
    const pj = path.join(dir, 'package.json');
    if (fs.existsSync(pj) && !fs.existsSync(path.join(dir, 'node_modules'))) { try { const j = JSON.parse(fs.readFileSync(pj, 'utf8')); install = Object.keys({ ...j.dependencies, ...j.devDependencies }).length > 0; } catch {} }
  }
  const p = PROCS[id] = { startedAt: Date.now(), phase: install ? 'installing' : 'running', stopping: false, child: null, waiters: [] };
  const exitMsg = (c, s) => p.stopping ? '⏹ تم إيقاف المنصة' : s ? `✖ أُنهيت العملية (${s})` : c === 0 ? '✔ انتهت العملية (code 0)' : `✖ توقفت العملية (code ${c})`;
  const launch = () => { p.phase = 'running'; p.startedAt = Date.now(); csys(id, '▶ تشغيل: ' + cmd); runCmd(id, p, cmd, (c, s) => finish(id, p, exitMsg(c, s))); };
  if (install) {
    csys(id, '📦 تثبيت الحزم (npm install)...');
    runCmd(id, p, 'npm install --no-audit --no-fund --legacy-peer-deps', c => { if (p.stopping) return finish(id, p, '⏹ تم إيقاف المنصة'); if (c !== 0) { p.stopping = true; return finish(id, p, `✖ فشل تثبيت الحزم (code ${c}) — صحّح package.json ثم اضغط تشغيل`); } launch(); });
  } else launch();
};
const stopProc = (id, keepWant) => new Promise(res => {
  if (!keepWant) { WANT[id] = false; setAuto(id, false); }
  const p = PROCS[id]; if (!p) return res(false);
  p.stopping = true; p.waiters.push(() => res(true));
  const ch = p.child;
  if (!ch) return finish(id, p, '⏹ تم إيقاف المنصة');
  csys(id, '⏹ جاري الإيقاف...'); killTree(ch, 'SIGTERM');
  setTimeout(() => { if (PROCS[id] === p && p.child === ch) killTree(ch, 'SIGKILL'); }, 5000);
  setTimeout(() => res(true), 8000);
});
const stopAll = async (id, keepWant) => { (EXECS[id] || new Set()).forEach(x => killTree(x.child, 'SIGTERM')); return stopProc(id, keepWant); };
const bye = async () => { Object.values(PROCS).forEach(p => killTree(p.child, 'SIGTERM')); try { await Promise.race([backupAll(), new Promise(r => setTimeout(r, 7000))]); } catch {} setTimeout(() => process.exit(0), 300); };
process.on('SIGTERM', bye); process.on('SIGINT', bye);

app.get('/api/platforms/:id/console', wrap((q, r) => {
  const c = con(q.params.id), since = +q.query.since || 0;
  r.json({ seq: c.seq, lines: c.lines.filter(l => l.n > since), status: statusOf(q.params.id), stats: sysStats(q.params.id) });
}));
app.post('/api/platforms/:id/console/clear', wrap((q, r) => { const c = con(q.params.id); c.lines = []; c.part = {}; r.json({ ok: 1 }); }));
app.post('/api/platforms/:id/control', wrap(async (q, r) => {
  const id = q.params.id, a = q.body.action;
  if (a === 'start') startProc(id);
  else if (a === 'stop') { if (!(await stopAll(id))) throw new Error('المنصة متوقفة أصلاً'); }
  else if (a === 'restart') { csys(id, '🔄 إعادة التشغيل...'); await stopAll(id, true); startProc(id); }
  else throw new Error('إجراء غير معروف');
  r.json(statusOf(id));
}));
app.post('/api/platforms/:id/exec', wrap((q, r) => {
  const id = q.params.id, cmd = String(q.body.cmd || '').trim();
  if (!cmd) throw new Error('اكتب أمراً أولاً');
  if (cmd.length > 4000) throw new Error('الأمر طويل جداً');
  if (q.body.mode === 'stdin') {
    const p = PROCS[id]; if (!p || p.phase !== 'running' || !p.child) throw new Error('المنصة غير شغالة');
    cline(id, 'cmd', '> ' + cmd); p.child.stdin.write(cmd + '\n'); return r.json({ ok: 1 });
  }
  const set = EXECS[id] || (EXECS[id] = new Set()); if (set.size >= 3) throw new Error('هناك أوامر كثيرة قيد التنفيذ');
  const ex = { child: null }; set.add(ex); cline(id, 'cmd', '$ ' + cmd); log(id, 'أمر: ' + cmd.slice(0, 200));
  const t = setTimeout(() => { cline(id, 'sys', '⏱ تجاوز المهلة (5 دقائق) — تم إيقاف الأمر'); killTree(ex.child, 'SIGKILL'); }, 300000);
  runCmd(id, ex, cmd, (c, s) => { clearTimeout(t); set.delete(ex); flushPart(id); cline(id, 'sys', c === 0 ? '✔ انتهى الأمر' : s ? `✖ أُنهي الأمر (${s})` : `✖ انتهى الأمر (code ${c})`); });
  r.json({ ok: 1 });
}));

// ---------- platforms ----------
app.get('/api/instance', (q, r) => r.json({ id: INSTANCE }));
app.get('/api/platforms', wrap((q, r) => r.json(platIds().map(id => ({ id, name: getMeta(id).name, ...sigOf(id) })))));
app.post('/api/platforms', wrap((q, r) => {
  const name = String(q.body.name || '').trim(); if (!name) throw new Error('الاسم مطلوب');
  const id = (name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'p') + '-' + crypto.randomBytes(2).toString('hex');
  fs.mkdirSync(path.join(pdir(id), 'files'), { recursive: true });
  writeMeta(id, defMeta(name)); log(id, 'تم إنشاء منصة: ' + name); r.json({ id, name });
}));
app.delete('/api/platforms/:id', wrap(async (q, r) => { if (q.params.id === 'main') throw new Error('لا يمكن حذف المنصة الرئيسية'); await stopAll(q.params.id); delete CON[q.params.id]; fs.rmSync(pdir(q.params.id), { recursive: true, force: true }); log(q.params.id, 'تم حذف المنصة'); r.json({ ok: 1 }); }));
app.get('/api/platforms/:id/meta', wrap((q, r) => r.json(getMeta(q.params.id))));
app.put('/api/platforms/:id/meta', wrap((q, r) => {
  const m = getMeta(q.params.id), b = q.body;
  ['name', 'keys', 'vars', 'ai', 'startCmd', 'github'].forEach(k => { if (b[k] !== undefined) m[k] = b[k]; });
  writeMeta(q.params.id, m); log(q.params.id, 'تم حفظ الإعدادات'); r.json({ ok: 1 });
}));
app.get('/api/platforms/:id/stats', wrap((q, r) => {
  const id = q.params.id, s = sigOf(id);
  r.json({ running: statusOf(id).state !== 'stopped', ram: Math.round(process.memoryUsage().rss / 1048576), uptime: Math.round(process.uptime()), files: s.files, vars: getMeta(id).vars.length, ...sysStats(id) });
}));
app.get('/api/platforms/:id/logs', wrap((q, r) => r.json(LOGS.filter(l => l.p === q.params.id || l.p === '-').slice(-200))));
app.get('/api/platforms/:id/env', wrap((q, r) => {
  r.type('text/plain').set('Content-Disposition', 'attachment; filename=".env"')
    .send(getMeta(q.params.id).vars.filter(v => v.key).map(v => `${v.key}=${v.value}`).join('\n') + '\n');
}));
app.get('/api/platforms/:id/backup', wrap((q, r) => { const m = getMeta(q.params.id); r.set('Content-Disposition', `attachment; filename="${q.params.id}-backup.json"`).json(m); }));
app.post('/api/platforms/:id/restore', wrap((q, r) => {
  const b = q.body; if (!b || typeof b !== 'object' || !Array.isArray(b.vars)) throw new Error('ملف نسخة احتياطية غير صالح');
  writeMeta(q.params.id, { ...defMeta(b.name || 'منصة'), ...b }); log(q.params.id, 'تمت استعادة نسخة احتياطية'); r.json({ ok: 1 });
}));

// ---------- نسخة كاملة (إعدادات + ملفات) — يحتفظ بها المتصفح تلقائياً ويعيدها إذا ضاعت بيانات السيرفر ----------
const SNAP_MAX = 120 * 1048576;
// يبني نسخة كاملة (إعدادات + ملفات بدون node_modules). الملفات الصغيرة أولاً (قاعدة البيانات والجلسة قبل الصور الكبيرة)
function buildSnapshot(id, max = SNAP_MAX) {
  const z = new AdmZip(); SIGC[id] = null;
  const s = sigOf(id); let total = 0, partial = 0; const items = [];
  z.addFile('meta.json', fs.readFileSync(metaP(id)));
  walk(safe(id), (p, rel, st, isDir) => { if (isDir) z.addFile('files/' + rel + '/', Buffer.alloc(0)); else items.push({ p, rel, size: st.size }); });
  items.sort((a, b) => a.size - b.size);
  for (const it of items) {
    if (total + it.size > max) { partial = 1; continue; }
    try { z.addFile('files/' + it.rel, fs.readFileSync(it.p)); total += it.size; } catch { partial = 1; }
  }
  return { buf: z.toBuffer(), sig: s.sig, files: s.files, partial };
}
function restoreSnapshotBuf(id, buf) {
  if (!okId(id)) throw new Error('معرّف غير صالح');
  if (PROCS[id]) throw new Error('أوقف المنصة أولاً');
  if (!Buffer.isBuffer(buf) || !buf.length) throw new Error('الملف فارغ');
  const z = new AdmZip(buf), ents = z.getEntries();
  for (const e of ents) { const n = e.entryName; if (n.includes('..') || n.startsWith('/') || n.includes('\\') || !(n === 'meta.json' || n.startsWith('files/'))) throw new Error('نسخة غير صالحة'); }
  if (!ents.some(e => e.entryName === 'meta.json')) throw new Error('نسخة غير صالحة (meta.json مفقود)');
  const dir = pdir(id); fs.mkdirSync(dir, { recursive: true });
  fs.rmSync(path.join(dir, 'files'), { recursive: true, force: true }); fs.mkdirSync(path.join(dir, 'files'), { recursive: true });
  z.extractAllTo(dir, true); SIGC[id] = null;
  try { JSON.parse(fs.readFileSync(metaP(id), 'utf8')); } catch { writeMeta(id, defMeta(id)); }
  return sigOf(id).files;
}
app.get('/api/platforms/:id/snapshot', wrap((q, r) => {
  const b = buildSnapshot(q.params.id);
  r.set({ 'Content-Type': 'application/zip', 'X-Sig': b.sig, 'X-Files': String(b.files), 'X-Partial': String(b.partial), 'Cache-Control': 'no-store' }).send(b.buf);
}));
app.post('/api/restore-snapshot/:rid', express.raw({ type: '*/*', limit: '300mb' }), wrap((q, r) => {
  const n = restoreSnapshotBuf(q.params.rid, q.body); log(q.params.rid, 'تمت استعادة نسخة كاملة'); r.json({ ok: 1, files: n });
}));

// ---------- نسخ احتياطي تلقائي إلى مستودع GitHub خاص (يحمي ملفاتك وبيانات البوت من مسح القرص المؤقت) ----------
// متغيرات البيئة: BACKUP_REPO=owner/repo  BACKUP_TOKEN=رمز GitHub (صلاحية Contents: Read and write)  BACKUP_BRANCH=main (اختياري)
const BK = { repo: String(process.env.BACKUP_REPO || '').trim(), token: String(process.env.BACKUP_TOKEN || '').trim(), branch: String(process.env.BACKUP_BRANCH || 'main').trim(), every: (Number(process.env.BACKUP_EVERY_MIN) || 3) * 60000, cap: 40 * 1048576 };
const bkOn = () => !!(BK.repo && BK.token);
const BKS = { last: 0, error: '', lastSig: {}, busy: false, restored: [], ready: false };
const ghr = (p, o = {}) => fetch('https://api.github.com/repos/' + BK.repo + p, { ...o, headers: { Authorization: 'Bearer ' + BK.token, 'User-Agent': 'hamza-platform', Accept: 'application/vnd.github+json', ...(o.headers || {}) }, signal: AbortSignal.timeout(90000) });
async function backupOne(id) {
  const sg = sigOf(id).sig; if (BKS.lastSig[id] === sg) return false;
  const mm = getMeta(id);
  if (sigOf(id).files === 0 && !mm.vars.length && !Object.keys(mm.keys || {}).length) return false;   // منصة فارغة: لا نكتب فوق نسخة سليمة
  const b = buildSnapshot(id, BK.cap), file = `/contents/backups/${encodeURIComponent(id)}.zip`;
  let sha; const g = await ghr(file + '?ref=' + encodeURIComponent(BK.branch)); if (g.ok) sha = (await g.json()).sha;
  const put = await ghr(file, { method: 'PUT', body: JSON.stringify({ message: `backup ${id} ${new Date().toISOString()}`, content: b.buf.toString('base64'), branch: BK.branch, ...(sha ? { sha } : {}) }) });
  if (!put.ok) { const j = await put.json().catch(() => ({})); throw new Error(`GitHub ${put.status}: ${j.message || ''}`.slice(0, 200)); }
  BKS.lastSig[id] = sg; return true;
}
async function backupAll() {
  if (!bkOn() || BKS.busy || !BKS.ready) return; BKS.busy = true;
  try { for (const id of platIds()) await backupOne(id); BKS.last = Date.now(); BKS.error = ''; } catch (e) { BKS.error = e.message; log(null, 'فشل النسخ الاحتياطي: ' + e.message); }
  BKS.busy = false;
}
async function restoreFromBackup() {
  if (!bkOn()) return true;
  try {
    const l = await ghr('/contents/backups?ref=' + encodeURIComponent(BK.branch));
    if (l.status === 404) { BKS.error = ''; return true; }                       // لا توجد نسخ بعد
    if (!l.ok) { const j = await l.json().catch(() => ({})); BKS.error = `استعادة: GitHub ${l.status} ${j.message || ''}`.slice(0, 200); return false; }
    for (const f of await l.json()) {
      const m = /^(.+)\.zip$/.exec(f.name || ''); if (!m || !okId(m[1])) continue; const id = m[1];
      if (fs.existsSync(metaP(id)) && (getMeta(id).keep || []).length) { const n = await pullKeep(id); if (n) { BKS.restored.push(id); log(id, `♻️ استُعيدت بيانات البوت من GitHub (${n} ملف)`); } continue; }
      if (fs.existsSync(metaP(id)) && sigOf(id).files > 0) continue;          // موجودة وفيها ملفات: لا نلمسها
      const n = await pullBackup(id); if (n != null) { BKS.restored.push(id); log(id, `♻️ استُعيدت المنصة من نسخة GitHub (${n} ملف)`); }
    }
    BKS.error = ''; return true;
  } catch (e) { BKS.error = 'استعادة: ' + e.message; log(null, BKS.error); return false; }
}
async function pullKeep(id) {            // يستعيد بيانات البوت فقط (قاعدة البيانات + الجلسة + المتغيرات) فوق الكود الجديد
  const m = getMeta(id), keep = m.keep || [];
  const r = await ghr(`/contents/backups/${encodeURIComponent(id)}.zip?ref=${encodeURIComponent(BK.branch)}`, { headers: { Accept: 'application/vnd.github.raw' } });
  if (r.status === 404) return 0; if (!r.ok) throw new Error(`تعذّر تنزيل نسخة ${id} (GitHub ${r.status})`);
  const z = new AdmZip(Buffer.from(await r.arrayBuffer())); let n = 0;
  for (const e of z.getEntries()) {
    const nm = e.entryName; if (e.isDirectory || nm.includes('..') || nm.startsWith('/') || !nm.startsWith('files/')) continue;
    const rel = nm.slice(6); if (!inKeep(keep, rel)) continue;
    const t = safe(id, rel); fs.mkdirSync(path.dirname(t), { recursive: true }); fs.writeFileSync(t, e.getData()); n++;
  }
  const me = z.getEntry('meta.json');
  if (me) { try { const bm = JSON.parse(me.getData().toString('utf8')), cur = getMeta(id);
    if (!cur.vars.length && Array.isArray(bm.vars)) cur.vars = bm.vars; cur.keys = { ...(bm.keys || {}), ...cur.keys }; cur.startCmd = cur.startCmd || bm.startCmd; writeMeta(id, cur); } catch {} }
  BKS.lastSig[id] = null; return n;
}
async function pullBackup(id) {
  const r = await ghr(`/contents/backups/${encodeURIComponent(id)}.zip?ref=${encodeURIComponent(BK.branch)}`, { headers: { Accept: 'application/vnd.github.raw' } });
  if (!r.ok) throw new Error(`تعذّر تنزيل نسخة ${id} (GitHub ${r.status})`);
  const n = restoreSnapshotBuf(id, Buffer.from(await r.arrayBuffer())); BKS.lastSig[id] = sigOf(id).sig; return n;
}
app.post('/api/platforms/:id/restore-github', wrap(async (q, r) => {
  if (!bkOn()) throw new Error('لم يتم ضبط BACKUP_REPO و BACKUP_TOKEN');
  const n = await pullBackup(q.params.id); log(q.params.id, `♻️ استعادة يدوية من GitHub (${n} ملف)`); r.json({ ok: 1, files: n });
}));
app.get('/api/backup-status', (q, r) => r.json({ enabled: bkOn(), ready: BKS.ready, repo: BK.repo, last: BKS.last, error: BKS.error, restored: BKS.restored, everyMin: BK.every / 60000 }));
app.post('/api/backup-now', wrap(async (q, r) => { if (!bkOn()) throw new Error('لم يتم ضبط BACKUP_REPO و BACKUP_TOKEN'); BKS.lastSig = {}; if (!BKS.ready) throw new Error('النسخ موقوف لأن الاستعادة عند الإقلاع فشلت: ' + BKS.error); await backupAll(); if (BKS.error) throw new Error(BKS.error); r.json({ ok: 1, last: BKS.last }); }));

// ---------- files ----------
const up = multer({ dest: os.tmpdir() });
app.get('/api/platforms/:id/files', wrap((q, r) => {
  const d = safe(q.params.id, q.query.path);
  r.json(fs.readdirSync(d, { withFileTypes: true }).map(e => { const s = fs.statSync(path.join(d, e.name)); return { name: e.name, dir: e.isDirectory(), size: s.size, mtime: s.mtimeMs }; })
    .sort((a, b) => b.dir - a.dir || a.name.localeCompare(b.name)));
}));
app.post('/api/platforms/:id/upload', up.array('files'), wrap((q, r) => {
  const d = safe(q.params.id, q.query.path); fs.mkdirSync(d, { recursive: true });
  for (const f of q.files) { const n = path.basename(Buffer.from(f.originalname, 'latin1').toString('utf8')); fs.copyFileSync(f.path, path.join(d, n)); fs.unlinkSync(f.path); log(q.params.id, 'رفع ملف: ' + n); }
  r.json({ ok: q.files.length });
}));
app.get('/api/platforms/:id/content', wrap((q, r) => { const p = safe(q.params.id, q.query.path); if (fs.statSync(p).size > 5e6) throw new Error('الملف كبير جداً للتعديل'); r.json({ content: fs.readFileSync(p, 'utf8') }); }));
app.put('/api/platforms/:id/content', wrap((q, r) => { const p = safe(q.params.id, q.body.path); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, q.body.content ?? ''); log(q.params.id, 'حفظ ملف: ' + q.body.path); r.json({ ok: 1 }); }));
app.post('/api/platforms/:id/mkdir', wrap((q, r) => { fs.mkdirSync(safe(q.params.id, q.body.path), { recursive: true }); log(q.params.id, 'مجلد جديد: ' + q.body.path); r.json({ ok: 1 }); }));
app.post('/api/platforms/:id/op', wrap((q, r) => {
  const { op, path: rel, to, paths } = q.body, id = q.params.id;
  if (op === 'delete') { for (const x of [rel, ...(paths || [])].filter(Boolean)) fs.rmSync(safe(id, x), { recursive: true, force: true }); }
  else if (op === 'rename' || op === 'move') { const t = safe(id, to); if (fs.existsSync(t)) throw new Error('الوجهة موجودة مسبقاً'); fs.mkdirSync(path.dirname(t), { recursive: true }); fs.renameSync(safe(id, rel), t); }
  else if (op === 'copy') { const t = safe(id, to); if (fs.existsSync(t)) throw new Error('الوجهة موجودة مسبقاً'); copyRec(safe(id, rel), t); }
  else if (op === 'extract') { const s = safe(id, rel); if (!/\.zip$/i.test(s)) throw new Error('يدعم فك ضغط ZIP فقط'); new AdmZip(s).extractAllTo(path.join(path.dirname(s), path.basename(s, path.extname(s))), true); }
  else if (op === 'zip') {
    const selected = Array.isArray(paths) && paths.length ? paths : (rel ? [rel] : []);
    if (!selected.length) throw new Error('حدد ملفاً أو مجلداً لضغطه');
    if (!to) throw new Error('حدد اسم ملف الضغط');
    const output = /\.zip$/i.test(String(to)) ? String(to) : String(to) + '.zip';
    const target = safe(id, output), z = new AdmZip();
    for (const x of selected) {
      const p = safe(id, x), st = fs.statSync(p);
      if (path.resolve(p) === path.resolve(target)) throw new Error('لا يمكن ضغط الملف داخل نفسه');
      if (st.isDirectory()) z.addLocalFolder(p, path.basename(p));
      else z.addLocalFile(p);
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    z.writeZip(target);
  } else throw new Error('عملية غير معروفة');
  SIGC[id] = null; log(id, `${op}: ${rel || (paths || []).join(', ')}${to ? ' → ' + to : ''}`); r.json({ ok: 1 });
}));
app.get('/api/platforms/:id/download', wrap((q, r) => {
  const id = q.params.id, list = q.query.paths ? JSON.parse(q.query.paths) : [q.query.path];
  if (list.length === 1) { const p = safe(id, list[0]); if (fs.statSync(p).isFile()) return r.download(p); }
  const z = new AdmZip(); for (const x of list) { const p = safe(id, x); fs.statSync(p).isDirectory() ? z.addLocalFolder(p, path.basename(p)) : z.addLocalFile(p); }
  r.set({ 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="download.zip"' }).send(z.toBuffer());
}));

// تنزيل جميع ملفات المنصة وإعداداتها في أرشيف واحد باسم المنصة.
app.get('/api/platforms/:id/download-all', wrap((q, r) => {
  const id = q.params.id, meta = getMeta(id);
  const safeName = String(meta.name || id).replace(/[\\\/:*?"<>|\r\n]+/g, '-').trim().slice(0, 80) || id;
  const snapshot = buildSnapshot(id, Number.MAX_SAFE_INTEGER), source = new AdmZip(snapshot.buf), out = new AdmZip();
  for (const entry of source.getEntries()) {
    const name = safeName + '/' + entry.entryName;
    if (entry.isDirectory) out.addFile(name.endsWith('/') ? name : name + '/', Buffer.alloc(0));
    else out.addFile(name, entry.getData());
  }
  const filename = safeName + '.zip';
  r.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="${id}.zip"; filename*=UTF-8''${encodeURIComponent(filename)}`, 'Cache-Control': 'no-store', 'X-Partial': String(snapshot.partial) }).send(out.toBuffer());
}));

// ---------- جلب ملفات البوت من GitHub (بدون git: تنزيل ZIP عبر واجهة GitHub) ----------
const parseGh = (url, branch, subdir) => {
  const m = String(url || '').trim().replace(/\.git$/i, '').replace(/\/$/, '').match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+)(?:\/tree\/([^/]+)(?:\/(.+))?)?$/i)
    || String(url || '').trim().match(/^([\w.-]+)\/([\w.-]+)$/);
  if (!m) throw new Error('رابط GitHub غير صالح. مثال: https://github.com/user/repo');
  return { owner: m[1], repo: m[2].replace(/\.git$/i, ''), branch: String(branch || m[3] || '').trim(), subdir: String(subdir || m[4] || '').replace(/^\/+|\/+$/g, '') };
};
const inKeep = (keep, rel) => (keep || []).some(k => rel === k || rel.startsWith(k + '/'));
async function pullGithub(id, b) {
  const m = getMeta(id);
  const g = parseGh(b.url, b.branch, b.subdir), token = String(b.token || m.keys.github_token || process.env.BOT_TOKEN || '').trim();
  const ref = g.branch ? '/' + encodeURIComponent(g.branch) : '';
  csys(id, `🐙 جلب ${g.owner}/${g.repo}${g.branch ? ' (' + g.branch + ')' : ''} من GitHub...`);
  const headers = { 'User-Agent': 'hamza-platform', Accept: 'application/vnd.github+json' }; if (token) headers.Authorization = 'Bearer ' + token;
  const resp = await fetch(`https://api.github.com/repos/${g.owner}/${g.repo}/zipball${ref}`, { headers, signal: AbortSignal.timeout(120000) });
  if (!resp.ok) {
    const msg = resp.status === 404 ? 'المستودع أو الفرع غير موجود، أو أنه خاص (أضف رمز GitHub)' : resp.status === 401 ? 'رمز GitHub غير صحيح' : resp.status === 403 ? 'GitHub رفض الطلب (حد الطلبات أو صلاحيات الرمز) — أضف رمز GitHub' : 'فشل الاتصال بـ GitHub (' + resp.status + ')';
    csys(id, '✖ ' + msg); throw new Error(msg);
  }
  const buf = Buffer.from(await resp.arrayBuffer()); if (buf.length > 200 * 1048576) throw new Error('المستودع كبير جداً (أكثر من 200MB)');
  const z = new AdmZip(buf), base = safe(id); fs.mkdirSync(base, { recursive: true }); let n = 0;
  for (const e of z.getEntries()) {
    const parts = e.entryName.split('/'); parts.shift(); let rel = parts.join('/'); if (!rel || rel.includes('..') || rel.startsWith('/')) continue;
    if (g.subdir) { if (rel !== g.subdir && !rel.startsWith(g.subdir + '/')) continue; rel = rel.slice(g.subdir.length).replace(/^\//, ''); if (!rel) continue; }
    if (rel.split('/').some(x => x === '.git')) continue;
    const t = safe(id, rel);
    if (e.isDirectory) { fs.mkdirSync(t, { recursive: true }); continue; }
    if (inKeep(m.keep, rel) && fs.existsSync(t)) continue;          // لا نكتب فوق بيانات البوت (قاعدة البيانات/الجلسة)
    fs.mkdirSync(path.dirname(t), { recursive: true }); fs.writeFileSync(t, e.getData()); n++;
  }
  if (!n) throw new Error('لم يتم العثور على ملفات' + (g.subdir ? ' في المجلد الفرعي المحدد' : ''));
  const m2 = getMeta(id); m2.github = { url: `https://github.com/${g.owner}/${g.repo}`, branch: g.branch, subdir: g.subdir, at: Date.now() };
  if (b.token) m2.keys.github_token = String(b.token).trim();
  writeMeta(id, m2); SIGC[id] = null; csys(id, `✔ تم جلب ${n} ملف من GitHub`);
  return { ok: 1, files: n, github: m2.github, hasPkg: fs.existsSync(path.join(base, 'package.json')) };
}
app.post('/api/platforms/:id/github', wrap(async (q, r) => r.json(await pullGithub(q.params.id, q.body))));

// ---------- الذكاء الاصطناعي ----------
// المفتاح يُحفظ في إعدادات المنصة (يبقى بعد الخروج). يمكن أيضاً ضبط AI_API_KEY كمتغير بيئة عام.
const aiKey = m => String(m.keys.ai_key || process.env.AI_API_KEY || '').trim();
async function callAI(m, system, msgs) {
  const key = aiKey(m); if (!key) throw new Error('أضف مفتاح الذكاء الاصطناعي من تبويب المساعد أولاً');
  const custom = String(m.keys.ai_base_url || '').trim().replace(/\/$/, '');
  const google = /^(AIza|AQ\.)/.test(key) && !custom, sig = AbortSignal.timeout(90000);
  if (!google) { // أي مزود متوافق مع OpenAI
    const resp = await fetch((custom || 'https://api.openai.com/v1') + '/chat/completions', { method: 'POST', signal: sig,
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + key },
      body: JSON.stringify({ model: m.ai.model, messages: [{ role: 'system', content: system }, ...msgs] }) });
    const j = await resp.json().catch(() => ({})); if (!resp.ok) throw new Error(j.error?.message || `فشل طلب الذكاء الاصطناعي (${resp.status})`);
    return j.choices?.[0]?.message?.content || '';
  }
  // مفاتيح Google (AIza... أو AQ....): نجرّب Gemini API ثم Vertex AI
  let model = String(m.ai.model || '').trim(); if (!model || /^(gpt|o\d|chatgpt)/i.test(model)) model = 'gemini-2.5-flash';
  const body = JSON.stringify({ systemInstruction: { parts: [{ text: system }] }, contents: msgs.map(x => ({ role: x.role === 'assistant' ? 'model' : 'user', parts: [{ text: String(x.content) }] })) });
  const M = encodeURIComponent(model), K = encodeURIComponent(key), errs = [];
  const tries = [[`https://generativelanguage.googleapis.com/v1beta/models/${M}:generateContent`, { 'x-goog-api-key': key }],
    [`https://aiplatform.googleapis.com/v1/publishers/google/models/${M}:generateContent?key=${K}`, {}]];
  for (const [url, h] of tries) {
    try {
      const resp = await fetch(url, { method: 'POST', signal: sig, headers: { 'Content-Type': 'application/json', ...h }, body });
      const j = await resp.json().catch(() => ({}));
      if (resp.ok) { const t = (j.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join(''); if (t) return t; errs.push('رد فارغ من النموذج'); continue; }
      errs.push(j.error?.message || `خطأ ${resp.status}`); if (![400, 401, 403, 404].includes(resp.status)) break;
    } catch (e) { errs.push(e.message); }
  }
  throw new Error([...new Set(errs)].join(' — ').slice(0, 400) || 'فشل طلب الذكاء الاصطناعي');
}
const tail = (id, n = 100) => { flushPart(id); return con(id).lines.slice(-n).map(l => l.m).join('\n').slice(-7000); };
const SYS_EXPLAIN = 'أنت مهندس برمجيات خبير. حلّل مخرجات الكونسول المرفقة. أجب بالعربية وباختصار شديد وبصيغة آمرة ومباشرة بهذا الترتيب:\n**الخطأ:** سطر واحد.\n**السبب:** سطر أو سطران.\n**الحل:** خطوات مرقمة قصيرة، وأي أمر أو كود يوضع داخل ``` ``` بدقة وكاملاً.\nإن لم يوجد خطأ في المخرجات فقل ذلك بجملة واحدة. لا تخمّن ولا تخترع معلومات غير موجودة في المخرجات.';
const cleanMsgs = a => (Array.isArray(a) ? a : []).filter(x => x && (x.role === 'user' || x.role === 'assistant') && typeof x.content === 'string').slice(-30).map(x => ({ role: x.role, content: x.content }));
app.post('/api/platforms/:id/ai', wrap(async (q, r) => {
  const id = q.params.id, m = getMeta(id); let sys = m.ai.system;
  if (q.body.console) { const t = tail(id, 80); if (t.trim()) sys += '\n\nآخر مخرجات كونسول المنصة (للاستعانة بها عند الحاجة):\n' + t; }
  const msgs = cleanMsgs(q.body.messages); if (!msgs.length) throw new Error('اكتب رسالة أولاً');
  const reply = await callAI(m, sys, msgs); log(id, 'طلب مساعد ذكاء اصطناعي'); r.json({ reply });
}));
app.post('/api/platforms/:id/ai/explain', wrap(async (q, r) => {
  const id = q.params.id, m = getMeta(id), out = String(q.body.text || '').trim() || tail(id, 120);
  if (!out.trim()) throw new Error('الكونسول فارغ — لا يوجد ما يُحلَّل');
  let extra = ''; try { const d = safe(id); extra += 'أمر التشغيل: ' + (m.startCmd || autoCmd(d) || 'غير محدد') + '\nالملفات في الجذر: ' + fs.readdirSync(d).slice(0, 40).join(', ');
    const pj = path.join(d, 'package.json'); if (fs.existsSync(pj)) extra += '\npackage.json: ' + fs.readFileSync(pj, 'utf8').slice(0, 1500); } catch {}
  const reply = await callAI(m, SYS_EXPLAIN, [{ role: 'user', content: `${extra}\n\nمخرجات الكونسول:\n${out}` }]);
  log(id, 'تحليل خطأ بالذكاء الاصطناعي'); r.json({ reply });
}));

app.listen(PORT, () => log(null, `المنصة تعمل على المنفذ ${PORT} — التخزين: ${DATA}`));
(async () => {
  if (BOT_REPO && !PROCS[BOT_ID]) {                               // كود البوت يُجلب من مستودعه عند كل إقلاع (لا يضيع أبداً)
    for (let i = 0; i < 5; i++) { try { await pullGithub(BOT_ID, getMeta(BOT_ID).github || { url: BOT_REPO }); break; } catch (e) { log(BOT_ID, 'فشل جلب البوت: ' + e.message); await new Promise(r => setTimeout(r, 10000)); } }
  }
  let ok = await restoreFromBackup();
  for (let i = 0; !ok && i < 10; i++) { await new Promise(r => setTimeout(r, 15000)); ok = await restoreFromBackup(); }
  BKS.ready = ok || !bkOn();
  for (const id of platIds()) { const m = getMeta(id); if (m.autostart && sigOf(id).files > 0) { try { csys(id, '🚀 تشغيل تلقائي بعد إقلاع المنصة'); startProc(id, true); } catch (e) { csys(id, '✖ ' + e.message); } } }
  const SELF = String(process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || '').replace(/\/$/, '');   // منع نوم Render: زيارة ذاتية كل 8 دقائق
  if (SELF) { const ping = () => fetch(SELF + '/api/ping', { signal: AbortSignal.timeout(20000) }).catch(() => {}); setInterval(ping, 8 * 60 * 1000).unref(); setTimeout(ping, 30000); }
  if (bkOn()) { setTimeout(backupAll, 20000); setInterval(backupAll, BK.every).unref(); log(null, '💾 النسخ الاحتياطي إلى GitHub مفعّل: ' + BK.repo + (BKS.ready ? '' : ' (متوقف: فشلت الاستعادة — راجع الخطأ)')); }
})();
