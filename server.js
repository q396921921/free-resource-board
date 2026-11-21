import express from 'express'
import pg from 'pg'
import crypto from 'node:crypto'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PORT = Number(process.env.PORT || 3000)
const TZ = process.env.APP_TZ || 'Asia/Shanghai'
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || ''
const SESSION_SECRET = process.env.SESSION_SECRET || ''
const API_TOKEN = process.env.API_TOKEN || ''
const DATABASE_URL = process.env.DATABASE_URL || ''
const SECURE_COOKIE = process.env.INSECURE_COOKIE !== '1'

if (!ADMIN_PASSWORD || !SESSION_SECRET || !DATABASE_URL) {
  console.error('缺少环境变量：ADMIN_PASSWORD / SESSION_SECRET / DATABASE_URL')
  process.exit(1)
}

const pool = new pg.Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false },
  max: 5,
})
const q = (text, params) => pool.query(text, params)

// ---------- 工具 ----------
const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

function safeUrl(u) {
  u = String(u || '').trim()
  return /^https?:\/\//i.test(u) ? u : ''
}

function tzParts(d = new Date()) {
  const f = new Intl.DateTimeFormat('en-CA', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit' })
  const [y, m, day] = f.format(d).split('-').map(Number)
  return { y, m, day }
}

function periodKey(recurrence, d = new Date()) {
  const { y, m, day } = tzParts(d)
  const pad = (n) => String(n).padStart(2, '0')
  if (recurrence === 'daily') return `${y}-${pad(m)}-${pad(day)}`
  if (recurrence === 'monthly') return `${y}-${pad(m)}`
  if (recurrence === 'once') return 'once'
  // weekly: ISO 周
  const t = new Date(Date.UTC(y, m - 1, day))
  const dayNum = t.getUTCDay() || 7
  t.setUTCDate(t.getUTCDate() + 4 - dayNum)
  const yStart = new Date(Date.UTC(t.getUTCFullYear(), 0, 1))
  const week = Math.ceil(((t - yStart) / 86400000 + 1) / 7)
  return `${t.getUTCFullYear()}-W${pad(week)}`
}

const RECUR_LABEL = { daily: '每日', weekly: '每周', monthly: '每月', once: '一次性' }
const RECUR_LIST = Object.keys(RECUR_LABEL)

// ---------- 会话（HMAC 签名 cookie，无依赖） ----------
const sign = (v) => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url')
function makeSession() {
  const exp = Date.now() + 7 * 24 * 3600 * 1000
  const v = String(exp)
  return `${v}.${sign(v)}`
}
function validSession(tok) {
  if (!tok) return false
  const [v, sig] = tok.split('.')
  if (!v || !sig) return false
  const good = sign(v)
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return false
  return Number(v) > Date.now()
}
function parseCookies(h = '') {
  return Object.fromEntries(
    h.split(';').map((p) => p.trim().split('=')).filter((p) => p[0]).map(([k, ...r]) => [k, decodeURIComponent(r.join('='))]),
  )
}
function safeEq(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest()
  const hb = crypto.createHash('sha256').update(String(b)).digest()
  return crypto.timingSafeEqual(ha, hb)
}

// 登录限速：同一 IP 15 分钟内最多 10 次失败
const fails = new Map()
function tooMany(ip) {
  const r = fails.get(ip)
  return r && r.n >= 10 && Date.now() - r.t < 15 * 60 * 1000
}
function noteFail(ip) {
  const r = fails.get(ip)
  if (!r || Date.now() - r.t > 15 * 60 * 1000) fails.set(ip, { n: 1, t: Date.now() })
  else r.n++
}

// ---------- 页面模板 ----------
const CSS = `
:root{color-scheme:light dark;--bg:#fafafa;--fg:#1a1a1a;--mut:#666;--card:#fff;--bd:#e3e3e3;--ac:#e8590c;--ok:#2b8a3e}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--fg:#eee;--mut:#9a9a9a;--card:#1c1c1c;--bd:#333;--ac:#ff8a4c;--ok:#69db7c}}
*{box-sizing:border-box}body{margin:0;font:15px/1.6 -apple-system,"PingFang SC",sans-serif;background:var(--bg);color:var(--fg)}
header{display:flex;gap:16px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--bd);background:var(--card);flex-wrap:wrap}
header b{font-size:16px}header a{color:var(--fg);text-decoration:none;color:var(--mut)}header a:hover,header a.on{color:var(--ac)}
header .sp{flex:1}main{max-width:900px;margin:0 auto;padding:20px}
h1{font-size:20px;margin:0 0 14px}h2{font-size:16px;margin:26px 0 10px;color:var(--mut);font-weight:600}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin-bottom:10px}
.row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}
.tag{display:inline-block;font-size:12px;padding:1px 8px;border-radius:99px;border:1px solid var(--bd);color:var(--mut);margin-right:6px}
.ok{color:var(--ok)}.mut{color:var(--mut)}.small{font-size:13px}
a{color:var(--ac)}
button,.btn{font:inherit;background:var(--ac);color:#fff;border:0;border-radius:8px;padding:6px 14px;cursor:pointer;text-decoration:none;display:inline-block}
button.ghost,.btn.ghost{background:transparent;color:var(--fg);border:1px solid var(--bd)}
button.danger{background:#c92a2a}
input,select,textarea{font:inherit;width:100%;padding:7px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--fg)}
textarea{min-height:110px}label{display:block;margin:10px 0 4px;color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:640px){.grid{grid-template-columns:1fr}}
ol.steps{padding-left:0;list-style:none;margin:8px 0}ol.steps li{display:flex;gap:10px;padding:8px 0;border-bottom:1px dashed var(--bd)}
ol.steps li:last-child{border:0}ol.steps input{width:auto;margin-top:5px}
pre.note{white-space:pre-wrap;word-break:break-word;font:inherit;margin:6px 0 0}
.msg{padding:8px 12px;border-radius:8px;background:#fff3bf;color:#5c4400;margin-bottom:12px}
`

function layout(title, body, active = '', flash = '') {
  const nav = [['/', '今日待办'], ['/notes', '备忘'], ['/admin', '后台管理']]
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(title)} · 免费资源台账</title><style>${CSS}</style></head><body>
<header><b>🐑 免费资源台账</b>${nav.map(([h, t]) => `<a href="${h}" class="${active === h ? 'on' : ''}">${t}</a>`).join('')}<span class="sp"></span>
<form method="post" action="/logout" style="margin:0"><button class="ghost small">退出</button></form></header>
<main>${flash ? `<div class="msg">${esc(flash)}</div>` : ''}${body}</main></body></html>`
}

const loginPage = (err = '') => `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>登录</title><style>${CSS}</style></head><body><main style="max-width:360px;margin-top:12vh">
<h1>🐑 免费资源台账</h1>${err ? `<div class="msg">${esc(err)}</div>` : ''}
<form method="post" action="/login" class="card"><label>密码</label><input type="password" name="password" autofocus required>
<p><button>登录</button></p></form></main></body></html>`

// ---------- 数据访问 ----------
async function todayList() {
  const { rows } = await q(`
    SELECT p.*, r.name AS resource_name, r.category,
           (SELECT count(*) FROM steps s WHERE s.procedure_id = p.id) AS step_count
    FROM procedures p LEFT JOIN resources r ON r.id = p.resource_id
    WHERE p.active ORDER BY p.sort, p.id`)
  const todo = []
  const done = []
  for (const p of rows) {
    const key = periodKey(p.recurrence)
    const c = await q('SELECT mode, done_at FROM completions WHERE procedure_id=$1 AND period_key=$2', [p.id, key])
    if (c.rows[0]) done.push({ ...p, completion: c.rows[0] })
    else todo.push(p)
  }
  return { todo, done }
}

async function complete(procedureId, mode, note = '') {
  const { rows } = await q('SELECT recurrence FROM procedures WHERE id=$1', [procedureId])
  if (!rows[0]) return false
  await q(
    `INSERT INTO completions (procedure_id, period_key, mode, note) VALUES ($1,$2,$3,$4)
     ON CONFLICT (procedure_id, period_key) DO NOTHING`,
    [procedureId, periodKey(rows[0].recurrence), mode, note.slice(0, 500)],
  )
  return true
}

async function seed() {
  const n = await q('SELECT count(*)::int AS n FROM resources')
  if (n.rows[0].n > 0) return
  const r = await q(
    `INSERT INTO resources (name, category, url, status, summary, notes) VALUES
     ('Altare', 'VPS/容器/存储', 'https://console.altare.gg/', '可用',
      '免费团队池：内存/CPU/磁盘/服务器槽；U3 对象存储 10GB、KV 1GB、Postgres 1 个、5 个 DNS zone。',
      '条款：一人一号；禁止脚本自动刷 AFK/每日奖励/推荐；免费额度可随时调整，无 SLA；账号被封则数据与升级全部作废，数据务必自留副本。') RETURNING id`)
  const rid = r.rows[0].id
  const addProc = async (title, recurrence, url, steps, sort) => {
    const p = await q(
      'INSERT INTO procedures (resource_id,title,recurrence,open_url,sort) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [rid, title, recurrence, url, sort],
    )
    for (let i = 0; i < steps.length; i++)
      await q('INSERT INTO steps (procedure_id, position, text) VALUES ($1,$2,$3)', [p.rows[0].id, i + 1, steps[i]])
  }
  await addProc('Altare 每日签到（领 Bolts）', 'daily', 'https://console.altare.gg/', [
    '打开 Altare 控制台并登录',
    '进入「钱包」，点击领取每日奖励（最多 20 Bolts/天，连续签到有加成）',
    '回到本页点「标记完成」',
  ], 10)
  await addProc('Altare 挂机 AFK（赚 Bolts）', 'daily', 'https://console.altare.gg/', [
    '保持控制台页面打开且人在场（0.04 Bolts/分钟，每天上限 30）',
    '不要用脚本/机器人刷，条款禁止',
    '挂到当天上限或今天不再使用时，回本页「标记完成」',
  ], 20)
  await addProc('Altare 兑换永久升级', 'once', 'https://console.altare.gg/', [
    '目标：8GB 内存 / 200%+ CPU / 4 服务器槽，约 1435 Bolts',
    '商店价格：1GB 内存 222.75、50% CPU 148.5、1 服务器槽 123.75 Bolts',
    '攒够后在控制台「钱包/商店」购买，购买后在备忘里记录新额度',
  ], 30)
  await q(
    `INSERT INTO notes (title, body, pinned) VALUES
     ('本站说明', '这里记录免费资源的领取/操作流程。后台管理里可增删改资源、流程和步骤。\n“自动完成”仅用于允许自动化的资源（通过 API 令牌标记）；Altare 的奖励只能人工领取。', true)`,
  )
}

// ---------- 应用 ----------
const app = express()
app.disable('x-powered-by')
app.set('trust proxy', true)
app.use(express.urlencoded({ extended: false, limit: '200kb' }))
app.use(express.json({ limit: '50kb' }))
app.use((req, res, next) => {
  res.set({
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'",
  })
  next()
})

app.get('/health', (_req, res) => res.type('text').send('ok'))

// 外部自动标记：Bearer API_TOKEN，只允许 complete
app.post('/api/procedures/:id/complete', async (req, res) => {
  const tok = (req.get('authorization') || '').replace(/^Bearer\s+/i, '')
  if (!API_TOKEN || !tok || !safeEq(tok, API_TOKEN)) return res.status(401).json({ error: 'unauthorized' })
  const ok = await complete(Number(req.params.id), 'auto', String(req.body?.note || ''))
  res.status(ok ? 200 : 404).json({ ok })
})

// 登录
app.get('/login', (_req, res) => res.send(loginPage()))
app.post('/login', (req, res) => {
  const ip = req.ip
  if (tooMany(ip)) return res.status(429).send(loginPage('失败次数过多，请 15 分钟后再试'))
  if (!safeEq(req.body.password || '', ADMIN_PASSWORD)) {
    noteFail(ip)
    return res.status(401).send(loginPage('密码错误'))
  }
  res.set('Set-Cookie', `sid=${makeSession()}; HttpOnly; Path=/; Max-Age=${7 * 24 * 3600}; SameSite=Lax${SECURE_COOKIE ? '; Secure' : ''}`)
  res.redirect('/')
})
app.post('/logout', (_req, res) => {
  res.set('Set-Cookie', `sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${SECURE_COOKIE ? '; Secure' : ''}`)
  res.redirect('/login')
})

// 之后全部需要登录；POST 校验 Origin 防 CSRF
app.use((req, res, next) => {
  if (!validSession(parseCookies(req.headers.cookie).sid)) return res.redirect('/login')
  if (req.method === 'POST') {
    const origin = req.get('origin')
    if (origin && new URL(origin).host !== req.get('host')) return res.status(403).send('bad origin')
  }
  next()
})

const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next)
const back = (res, to, msg) => res.redirect(`${to}${msg ? (to.includes('?') ? '&' : '?') + 'm=' + encodeURIComponent(msg) : ''}`)

// 今日待办
app.get('/', wrap(async (req, res) => {
  const { todo, done } = await todayList()
  const pinned = (await q('SELECT * FROM notes WHERE pinned ORDER BY updated_at DESC LIMIT 3')).rows
  const card = (p, isDone) => `<div class="card"><div class="row"><div>
    <a href="/p/${p.id}"><b>${esc(p.title)}</b></a><br>
    <span class="tag">${RECUR_LABEL[p.recurrence]}</span><span class="tag">${esc(p.resource_name || '未归类')}</span>
    <span class="mut small">${p.step_count} 步</span>
    ${isDone ? `<span class="ok small"> ✓ ${p.completion.mode === 'auto' ? '自动' : '手动'}完成 ${esc(new Date(p.completion.done_at).toLocaleString('zh-CN', { timeZone: TZ }))}</span>` : ''}
    </div><div>${isDone ? '' : `<a class="btn" href="/p/${p.id}">去操作</a>`}</div></div></div>`
  const body = `<h1>今日待办 <span class="mut small">${esc(new Date().toLocaleDateString('zh-CN', { timeZone: TZ, dateStyle: 'full' }))}</span></h1>
    ${todo.length ? todo.map((p) => card(p, false)).join('') : '<div class="card ok">🎉 今天的都做完了</div>'}
    ${done.length ? `<h2>已完成（${done.length}）</h2>${done.map((p) => card(p, true)).join('')}` : ''}
    ${pinned.length ? `<h2>置顶备忘</h2>${pinned.map((n) => `<div class="card"><b>${esc(n.title)}</b><pre class="note">${esc(n.body)}</pre></div>`).join('')}` : ''}`
  res.send(layout('今日待办', body, '/', req.query.m))
}))

// 操作页
app.get('/p/:id(\\d+)', wrap(async (req, res) => {
  const p = (await q(`SELECT p.*, r.name AS resource_name, r.url AS resource_url, r.notes AS resource_notes
    FROM procedures p LEFT JOIN resources r ON r.id=p.resource_id WHERE p.id=$1`, [req.params.id])).rows[0]
  if (!p) return res.status(404).send(layout('未找到', '<p>未找到</p>'))
  const steps = (await q('SELECT * FROM steps WHERE procedure_id=$1 ORDER BY position', [p.id])).rows
  const key = periodKey(p.recurrence)
  const c = (await q('SELECT * FROM completions WHERE procedure_id=$1 AND period_key=$2', [p.id, key])).rows[0]
  const hist = (await q('SELECT * FROM completions WHERE procedure_id=$1 ORDER BY done_at DESC LIMIT 10', [p.id])).rows
  const open = safeUrl(p.open_url) || safeUrl(p.resource_url)
  const body = `<p><a href="/">← 今日待办</a></p><h1>${esc(p.title)}</h1>
    <p><span class="tag">${RECUR_LABEL[p.recurrence]}</span><span class="tag">${esc(p.resource_name || '未归类')}</span>
    ${open ? `<a class="btn ghost" href="${esc(open)}" target="_blank" rel="noopener noreferrer">打开操作页面 ↗</a>` : ''}</p>
    <div class="card"><ol class="steps">${steps.map((s) => `<li><input type="checkbox" onchange="sv()"><span>${esc(s.text)}</span></li>`).join('') || '<li class="mut">还没有步骤，去后台添加</li>'}</ol></div>
    ${c ? `<div class="card ok">✓ 本周期已完成（${c.mode === 'auto' ? '自动' : '手动'}，${esc(new Date(c.done_at).toLocaleString('zh-CN', { timeZone: TZ }))}）</div>`
      : `<form method="post" action="/p/${p.id}/complete" class="card"><label>备注（可选）</label><input name="note" maxlength="200"><p><button>标记完成</button></p></form>`}
    ${p.resource_notes ? `<h2>资源备注</h2><div class="card"><pre class="note">${esc(p.resource_notes)}</pre></div>` : ''}
    ${hist.length ? `<h2>最近记录</h2><div class="card small">${hist.map((h) => `${esc(h.period_key)} · ${h.mode === 'auto' ? '自动' : '手动'} · ${esc(new Date(h.done_at).toLocaleString('zh-CN', { timeZone: TZ }))} ${esc(h.note)}`).join('<br>')}</div>` : ''}
    <script>function sv(){var k='st${p.id}_${key}',a=[...document.querySelectorAll('ol.steps input')].map(function(i){return i.checked?1:0});localStorage.setItem(k,a.join(''))}
    (function(){var v=localStorage.getItem('st${p.id}_${key}');if(!v)return;document.querySelectorAll('ol.steps input').forEach(function(i,n){i.checked=v[n]==='1'})})()</script>`
  res.send(layout(p.title, body, '/', req.query.m))
}))
app.post('/p/:id(\\d+)/complete', wrap(async (req, res) => {
  await complete(Number(req.params.id), 'manual', String(req.body.note || ''))
  back(res, '/', '已标记完成')
}))

// 备忘
app.get('/notes', wrap(async (req, res) => {
  const rows = (await q('SELECT * FROM notes ORDER BY pinned DESC, updated_at DESC')).rows
  const body = `<h1>备忘</h1>
  <form method="post" action="/notes" class="card"><label>标题</label><input name="title" required maxlength="100">
  <label>内容</label><textarea name="body"></textarea><label><input type="checkbox" name="pinned" value="1" style="width:auto"> 置顶</label><p><button>添加</button></p></form>
  ${rows.map((n) => `<div class="card"><div class="row"><b>${n.pinned ? '📌 ' : ''}${esc(n.title)}</b>
    <span><a class="btn ghost small" href="/notes/${n.id}/edit">编辑</a></span></div><pre class="note">${esc(n.body)}</pre>
    <div class="mut small">${esc(new Date(n.updated_at).toLocaleString('zh-CN', { timeZone: TZ }))}</div></div>`).join('')}`
  res.send(layout('备忘', body, '/notes', req.query.m))
}))
app.post('/notes', wrap(async (req, res) => {
  await q('INSERT INTO notes (title, body, pinned) VALUES ($1,$2,$3)', [req.body.title, req.body.body || '', req.body.pinned === '1'])
  back(res, '/notes', '已添加')
}))
app.get('/notes/:id(\\d+)/edit', wrap(async (req, res) => {
  const n = (await q('SELECT * FROM notes WHERE id=$1', [req.params.id])).rows[0]
  if (!n) return res.redirect('/notes')
  res.send(layout('编辑备忘', `<h1>编辑备忘</h1><form method="post" action="/notes/${n.id}" class="card">
    <label>标题</label><input name="title" required value="${esc(n.title)}"><label>内容</label><textarea name="body">${esc(n.body)}</textarea>
    <label><input type="checkbox" name="pinned" value="1" style="width:auto" ${n.pinned ? 'checked' : ''}> 置顶</label>
    <p><button>保存</button> <a class="btn ghost" href="/notes">取消</a></p></form>
    <form method="post" action="/notes/${n.id}/delete" onsubmit="return confirm('删除这条备忘？')"><button class="danger">删除</button></form>`, '/notes'))
}))
app.post('/notes/:id(\\d+)', wrap(async (req, res) => {
  await q('UPDATE notes SET title=$1, body=$2, pinned=$3, updated_at=now() WHERE id=$4', [req.body.title, req.body.body || '', req.body.pinned === '1', req.params.id])
  back(res, '/notes', '已保存')
}))
app.post('/notes/:id(\\d+)/delete', wrap(async (req, res) => {
  await q('DELETE FROM notes WHERE id=$1', [req.params.id])
  back(res, '/notes', '已删除')
}))

// 后台管理：资源 + 流程
app.get('/admin', wrap(async (req, res) => {
  const resources = (await q('SELECT * FROM resources ORDER BY id')).rows
  const procs = (await q(`SELECT p.*, r.name AS rn FROM procedures p LEFT JOIN resources r ON r.id=p.resource_id ORDER BY p.sort, p.id`)).rows
  const body = `<h1>后台管理</h1>
  <h2>流程 / 待办项（${procs.length}）</h2>
  ${procs.map((p) => `<div class="card"><div class="row"><div><b>${esc(p.title)}</b> ${p.active ? '' : '<span class="tag">已停用</span>'}<br>
    <span class="tag">${RECUR_LABEL[p.recurrence]}</span><span class="tag">${esc(p.rn || '未归类')}</span></div>
    <a class="btn ghost small" href="/admin/procedures/${p.id}">编辑</a></div></div>`).join('')}
  <p><a class="btn" href="/admin/procedures/new">+ 新建流程</a></p>
  <h2>资源（${resources.length}）</h2>
  ${resources.map((r) => `<div class="card"><div class="row"><div><b>${esc(r.name)}</b> <span class="tag">${esc(r.status)}</span><span class="tag">${esc(r.category)}</span><br>
    <span class="mut small">${esc(r.summary)}</span></div><a class="btn ghost small" href="/admin/resources/${r.id}">编辑</a></div></div>`).join('')}
  <p><a class="btn" href="/admin/resources/new">+ 新建资源</a></p>`
  res.send(layout('后台管理', body, '/admin', req.query.m))
}))

const STATUSES = ['可用', '候选', '待复核', '已失效']
const opt = (list, cur) => list.map((x) => `<option ${x === cur ? 'selected' : ''}>${esc(x)}</option>`).join('')

app.get('/admin/resources/:id(\\d+|new)', wrap(async (req, res) => {
  const isNew = req.params.id === 'new'
  const r = isNew ? { name: '', category: '其他', url: '', status: '候选', summary: '', notes: '' } : (await q('SELECT * FROM resources WHERE id=$1', [req.params.id])).rows[0]
  if (!r) return res.redirect('/admin')
  res.send(layout('资源', `<h1>${isNew ? '新建' : '编辑'}资源</h1><form method="post" action="/admin/resources/${isNew ? 'new' : r.id}" class="card">
    <div class="grid"><div><label>名称</label><input name="name" required value="${esc(r.name)}"></div>
    <div><label>分类</label><input name="category" value="${esc(r.category)}"></div>
    <div><label>状态</label><select name="status">${opt(STATUSES, r.status)}</select></div>
    <div><label>控制台/官网链接</label><input name="url" value="${esc(r.url)}"></div></div>
    <label>额度摘要</label><input name="summary" value="${esc(r.summary)}"><label>限制/备注</label><textarea name="notes">${esc(r.notes)}</textarea>
    <p><button>保存</button> <a class="btn ghost" href="/admin">取消</a></p></form>
    ${isNew ? '' : `<form method="post" action="/admin/resources/${r.id}/delete" onsubmit="return confirm('删除资源会同时删除其下所有流程和记录，确定？')"><button class="danger">删除资源</button></form>`}`, '/admin'))
}))
app.post('/admin/resources/:id(\\d+|new)', wrap(async (req, res) => {
  const b = req.body
  const vals = [b.name, b.category || '其他', safeUrl(b.url), STATUSES.includes(b.status) ? b.status : '候选', b.summary || '', b.notes || '']
  if (req.params.id === 'new') await q('INSERT INTO resources (name,category,url,status,summary,notes) VALUES ($1,$2,$3,$4,$5,$6)', vals)
  else await q('UPDATE resources SET name=$1,category=$2,url=$3,status=$4,summary=$5,notes=$6 WHERE id=$7', [...vals, req.params.id])
  back(res, '/admin', '资源已保存')
}))
app.post('/admin/resources/:id(\\d+)/delete', wrap(async (req, res) => {
  await q('DELETE FROM resources WHERE id=$1', [req.params.id])
  back(res, '/admin', '资源已删除')
}))

app.get('/admin/procedures/:id(\\d+|new)', wrap(async (req, res) => {
  const isNew = req.params.id === 'new'
  const p = isNew ? { title: '', recurrence: 'daily', open_url: '', active: true, sort: 100, resource_id: null } : (await q('SELECT * FROM procedures WHERE id=$1', [req.params.id])).rows[0]
  if (!p) return res.redirect('/admin')
  const steps = isNew ? [] : (await q('SELECT text FROM steps WHERE procedure_id=$1 ORDER BY position', [p.id])).rows
  const resources = (await q('SELECT id,name FROM resources ORDER BY id')).rows
  res.send(layout('流程', `<h1>${isNew ? '新建' : '编辑'}流程</h1><form method="post" action="/admin/procedures/${isNew ? 'new' : p.id}" class="card">
    <label>标题</label><input name="title" required value="${esc(p.title)}">
    <div class="grid"><div><label>所属资源</label><select name="resource_id"><option value="">（未归类）</option>${resources.map((r) => `<option value="${r.id}" ${r.id === p.resource_id ? 'selected' : ''}>${esc(r.name)}</option>`).join('')}</select></div>
    <div><label>周期</label><select name="recurrence">${RECUR_LIST.map((k) => `<option value="${k}" ${k === p.recurrence ? 'selected' : ''}>${RECUR_LABEL[k]}</option>`).join('')}</select></div>
    <div><label>操作链接（可选，默认用资源链接）</label><input name="open_url" value="${esc(p.open_url)}"></div>
    <div><label>排序（小的在前）</label><input name="sort" type="number" value="${esc(p.sort)}"></div></div>
    <label><input type="checkbox" name="active" value="1" style="width:auto" ${p.active ? 'checked' : ''}> 启用（出现在今日待办）</label>
    <label>步骤（每行一步）</label><textarea name="steps" style="min-height:180px">${esc(steps.map((s) => s.text).join('\n'))}</textarea>
    <p><button>保存</button> <a class="btn ghost" href="/admin">取消</a></p></form>
    ${isNew ? '' : `<p class="mut small">自动标记完成接口：<code>POST /api/procedures/${p.id}/complete</code>（Authorization: Bearer API_TOKEN）。仅用于条款允许自动化的资源。</p>
    <form method="post" action="/admin/procedures/${p.id}/delete" onsubmit="return confirm('删除该流程及其完成记录，确定？')"><button class="danger">删除流程</button></form>`}`, '/admin'))
}))
app.post('/admin/procedures/:id(\\d+|new)', wrap(async (req, res) => {
  const b = req.body
  const rid = b.resource_id ? Number(b.resource_id) : null
  const rec = RECUR_LIST.includes(b.recurrence) ? b.recurrence : 'daily'
  const vals = [rid, b.title, rec, safeUrl(b.open_url), b.active === '1', Number(b.sort) || 100]
  let id = req.params.id
  if (id === 'new') {
    id = (await q('INSERT INTO procedures (resource_id,title,recurrence,open_url,active,sort) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', vals)).rows[0].id
  } else {
    await q('UPDATE procedures SET resource_id=$1,title=$2,recurrence=$3,open_url=$4,active=$5,sort=$6 WHERE id=$7', [...vals, id])
    await q('DELETE FROM steps WHERE procedure_id=$1', [id])
  }
  const lines = String(b.steps || '').split('\n').map((s) => s.trim()).filter(Boolean)
  for (let i = 0; i < lines.length; i++) await q('INSERT INTO steps (procedure_id, position, text) VALUES ($1,$2,$3)', [id, i + 1, lines[i]])
  back(res, '/admin', '流程已保存')
}))
app.post('/admin/procedures/:id(\\d+)/delete', wrap(async (req, res) => {
  await q('DELETE FROM procedures WHERE id=$1', [req.params.id])
  back(res, '/admin', '流程已删除')
}))

app.use((err, _req, res, _next) => {
  console.error(err)
  res.status(500).send('服务器错误')
})

await q(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'))
await seed()
app.listen(PORT, '0.0.0.0', () => console.log(`listening on ${PORT}`))
