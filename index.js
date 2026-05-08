var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var ADMIN_EMAIL = "1065857324@qq.com";
var INVITE_CODE = "work2026";
var JWT_SECRET = "memory-system-jwt-secret-2026";
var FEISHU_HOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/5741cf98-9a86-4754-a5bd-8109a2cacca4";
var SITE_URL = "https://memorysystem.congwei970225.workers.dev";
async function signJWT(payload) {
  const header = btoa(unescape(encodeURIComponent(JSON.stringify({ alg: "HS256", typ: "JWT" }))));
  const body = btoa(unescape(encodeURIComponent(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 3600 * 1e3 }))));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(JWT_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}
__name(signJWT, "signJWT");
async function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split(".");
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(JWT_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBytes = Uint8Array.from(atob(sig), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(decodeURIComponent(escape(atob(body))));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}
__name(verifyJWT, "verifyJWT");
async function getUser(req) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "");
  if (!token) return null;
  return verifyJWT(token);
}
__name(getUser, "getUser");
async function initDB(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS worklogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    done TEXT DEFAULT '',
    plan TEXT DEFAULT '',
    problem TEXT DEFAULT '',
    thinking TEXT DEFAULT '',
    important TEXT DEFAULT '',
    author_id INTEGER NOT NULL,
    author_name TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(author_id) REFERENCES users(id)
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worklog_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    author_name TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(worklog_id) REFERENCES worklogs(id) ON DELETE CASCADE
  )`).run();
}
__name(initDB, "initDB");
async function hashPassword(password) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(password + JWT_SECRET));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(hashPassword, "hashPassword");
var CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization"
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" }
  });
}
__name(json, "json");
var index_default = {
  async fetch(req, env) {
    await initDB(env.DB);
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;
    if (method === "OPTIONS") return new Response(null, { headers: CORS });
    if (method === "GET" && (path === "/" || path === "/index.html")) {
      return new Response(getHTML(), {
        headers: { "Content-Type": "text/html;charset=utf-8" }
      });
    }
    if (path === "/api/register" && method === "POST") {
      const { name, email, password, inviteCode } = await req.json();
      if (inviteCode !== INVITE_CODE) return json({ error: "\u9080\u8BF7\u7801\u4E0D\u6B63\u786E" }, 400);
      if (!name || !email || !password) return json({ error: "\u8BF7\u586B\u5199\u6240\u6709\u5B57\u6BB5" }, 400);
      if (password.length < 6) return json({ error: "\u5BC6\u7801\u81F3\u5C116\u4F4D" }, 400);
      const hash = await hashPassword(password);
      try {
        const r = await env.DB.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").bind(name, email, hash).run();
        const token = await signJWT({ id: r.meta.last_row_id, name, email });
        return json({ token, user: { id: r.meta.last_row_id, name, email } });
      } catch {
        return json({ error: "\u8BE5\u90AE\u7BB1\u5DF2\u88AB\u6CE8\u518C" }, 400);
      }
    }
    if (path === "/api/login" && method === "POST") {
      const { email, password } = await req.json();
      const hash = await hashPassword(password);
      const user2 = await env.DB.prepare("SELECT * FROM users WHERE email=? AND password=?").bind(email, hash).first();
      if (!user2) return json({ error: "\u90AE\u7BB1\u6216\u5BC6\u7801\u9519\u8BEF" }, 401);
      const token = await signJWT({ id: user2.id, name: user2.name, email: user2.email });
      return json({ token, user: { id: user2.id, name: user2.name, email: user2.email } });
    }
    const user = await getUser(req);
    if (!user && path.startsWith("/api/")) return json({ error: "\u8BF7\u5148\u767B\u5F55" }, 401);
    const isAdmin = user?.email === ADMIN_EMAIL;
    if (path === "/api/worklogs" && method === "GET") {
      const rows = await env.DB.prepare("SELECT * FROM worklogs ORDER BY date DESC, created_at DESC").all();
      return json(rows.results);
    }
    if (path === "/api/worklogs" && method === "POST") {
      const { date, done, plan, problem, thinking, important } = await req.json();
      if (!date) return json({ error: "\u8BF7\u9009\u62E9\u65E5\u671F" }, 400);
      const r = await env.DB.prepare(
        "INSERT INTO worklogs(date,done,plan,problem,thinking,important,author_id,author_name) VALUES(?,?,?,?,?,?,?,?)"
      ).bind(date, done || "", plan || "", problem || "", thinking || "", important || "", user.id, user.name).run();
      return json({ id: r.meta.last_row_id });
    }
    const wlogMatch = path.match(/^\/api\/worklogs\/(\d+)$/);
    if (wlogMatch) {
      const wid = parseInt(wlogMatch[1]);
      const log = await env.DB.prepare("SELECT * FROM worklogs WHERE id=?").bind(wid).first();
      if (!log) return json({ error: "\u8BB0\u5F55\u4E0D\u5B58\u5728" }, 404);
      const canEdit = isAdmin || log.author_id === user.id;
      if (method === "PUT") {
        if (!canEdit) return json({ error: "\u65E0\u6743\u9650" }, 403);
        const { date, done, plan, problem, thinking, important } = await req.json();
        await env.DB.prepare(
          "UPDATE worklogs SET date=?,done=?,plan=?,problem=?,thinking=?,important=? WHERE id=?"
        ).bind(
          date || log.date,
          done ?? log.done,
          plan ?? log.plan,
          problem ?? log.problem,
          thinking ?? log.thinking,
          important ?? log.important,
          wid
        ).run();
        return json({ ok: true });
      }
      if (method === "DELETE") {
        if (!canEdit) return json({ error: "\u65E0\u6743\u9650" }, 403);
        await env.DB.prepare("DELETE FROM worklogs WHERE id=?").bind(wid).run();
        return json({ ok: true });
      }
    }
    const cmtMatch = path.match(/^\/api\/worklogs\/(\d+)\/comments$/);
    if (cmtMatch) {
      const wid = parseInt(cmtMatch[1]);
      if (method === "GET") {
        const rows = await env.DB.prepare("SELECT * FROM comments WHERE worklog_id=? ORDER BY created_at ASC").bind(wid).all();
        return json(rows.results);
      }
      if (method === "POST") {
        const { text } = await req.json();
        if (!text) return json({ error: "\u8BC4\u8BBA\u4E0D\u80FD\u4E3A\u7A7A" }, 400);
        const r = await env.DB.prepare(
          "INSERT INTO comments(worklog_id,text,author_id,author_name) VALUES(?,?,?,?)"
        ).bind(wid, text, user.id, user.name).run();
        const log = await env.DB.prepare("SELECT * FROM worklogs WHERE id=?").bind(wid).first();
        if (log && log.author_id !== user.id) {
          fetch(FEISHU_HOOK, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              msg_type: "interactive",
              card: {
                header: { title: { tag: "plain_text", content: "\u{1F4AC} \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF\u65B0\u56DE\u590D" }, template: "green" },
                elements: [{
                  tag: "div",
                  text: { tag: "lark_md", content: `**${user.name}** \u56DE\u590D\u4E86 **${log.author_name} ${log.date}** \u7684\u8BB0\u5F55\uFF0C\u5FEB\u53BB\u770B\u770B\u5427 \u{1F440}` }
                }, {
                  tag: "action",
                  actions: [{ tag: "button", text: { tag: "plain_text", content: "\u{1F449} \u67E5\u770B\u8BB0\u5F55" }, type: "primary", url: SITE_URL }]
                }]
              }
            })
          }).catch(() => {
          });
        }
        return json({ id: r.meta.last_row_id });
      }
    }
    const delCmtMatch = path.match(/^\/api\/comments\/(\d+)$/);
    if (delCmtMatch && method === "DELETE") {
      const cid = parseInt(delCmtMatch[1]);
      const cmt = await env.DB.prepare("SELECT * FROM comments WHERE id=?").bind(cid).first();
      if (!cmt) return json({ error: "\u4E0D\u5B58\u5728" }, 404);
      if (!isAdmin && cmt.author_id !== user.id) return json({ error: "\u65E0\u6743\u9650" }, 403);
      await env.DB.prepare("DELETE FROM comments WHERE id=?").bind(cid).run();
      return json({ ok: true });
    }
    if (path === "/api/comment-counts" && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT worklog_id, COUNT(*) as cnt FROM comments GROUP BY worklog_id"
      ).all();
      const map = {};
      rows.results.forEach((r) => map[r.worklog_id] = r.cnt);
      return json(map);
    }
    return json({ error: "Not found" }, 404);
  }
};
function getHTML() {
  return `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>\u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</title>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{--white:#fff;--border:#e0e4eb;--text:#1a2030;--muted:#8a94a6;--accent:#2f6be8;--accent-light:#edf2fd;--red:#e84040;--header-bg:#f4f6fa;--row-sel:#ddeeff;--row-h:36px;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:#f0f3f7;color:var(--text);font-family:'Noto Sans SC',sans-serif;font-size:13px;min-height:100vh;}
#loadingScreen{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);flex-direction:column;gap:14px;}
.loading-logo{font-size:1.2rem;font-weight:700;color:var(--accent);}
.loading-spinner{width:28px;height:28px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;}
@keyframes spin{to{transform:rotate(360deg);}}
#authScreen{display:none;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);}
.auth-card{background:var(--white);border-radius:14px;padding:36px 32px;width:100%;max-width:360px;box-shadow:0 4px 20px rgba(0,0,0,.09);}
.auth-logo{font-size:1.2rem;font-weight:700;color:var(--accent);text-align:center;margin-bottom:4px;}
.auth-sub{font-size:.78rem;color:var(--muted);text-align:center;margin-bottom:22px;}
.auth-tabs{display:flex;background:#f0f3f7;border-radius:7px;padding:3px;margin-bottom:18px;}
.auth-tab{flex:1;padding:7px;text-align:center;border-radius:5px;cursor:pointer;font-size:.82rem;color:var(--muted);transition:all .15s;}
.auth-tab.active{background:var(--white);color:var(--text);font-weight:500;box-shadow:0 1px 4px rgba(0,0,0,.07);}
.auth-form{display:none;flex-direction:column;gap:11px;}
.auth-form.active{display:flex;}
.field{display:flex;flex-direction:column;gap:4px;}
.field label{font-size:.72rem;color:var(--muted);font-weight:500;}
.field input{border:1px solid var(--border);border-radius:7px;padding:9px 11px;font-size:.86rem;font-family:'Noto Sans SC',sans-serif;outline:none;transition:border-color .15s;}
.field input:focus{border-color:var(--accent);}
.auth-error{color:var(--red);font-size:.76rem;text-align:center;min-height:15px;}
.btn-auth{background:var(--accent);border:none;border-radius:7px;padding:11px;color:white;font-size:.86rem;font-family:'Noto Sans SC',sans-serif;font-weight:500;cursor:pointer;}
.btn-auth:hover{opacity:.88;}
#appScreen{display:none;}
.topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 20px;height:48px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,.04);}
.topbar-title{font-size:.95rem;font-weight:700;color:var(--text);flex:1;}
.topbar-user{font-size:.78rem;color:var(--muted);}
.btn-logout{background:none;border:1px solid var(--border);border-radius:5px;padding:4px 11px;font-size:.75rem;color:var(--muted);cursor:pointer;font-family:'Noto Sans SC',sans-serif;}
.btn-notif{background:none;border:1px solid var(--border);border-radius:6px;padding:4px 11px;font-size:.78rem;color:var(--text);cursor:pointer;font-family:'Noto Sans SC',sans-serif;display:none;}
.notif-badge{background:var(--red);color:white;border-radius:10px;padding:1px 6px;font-size:.68rem;font-weight:700;margin-left:3px;}
.toolbar{padding:9px 20px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--white);border-bottom:1px solid var(--border);}
.filter-label{font-size:.75rem;color:var(--muted);white-space:nowrap;}
.filter-select{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;outline:none;width:180px;background:white;cursor:pointer;color:var(--text);}
.filter-select:focus{border-color:var(--accent);}
.filter-input{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;outline:none;width:130px;}
.filter-input:focus{border-color:var(--accent);}
.btn-add{background:var(--accent);border:none;border-radius:6px;padding:7px 16px;color:white;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;font-weight:500;cursor:pointer;margin-left:auto;}
.btn-add:hover{opacity:.88;}
.table-wrap{overflow-x:auto;padding:14px 20px 60px;}
table{width:100%;border-collapse:collapse;background:var(--white);border-radius:8px;overflow:hidden;box-shadow:0 1px 5px rgba(0,0,0,.06);min-width:1000px;}
thead tr{background:var(--header-bg);}
th{padding:9px 12px;text-align:left;font-size:.73rem;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;}
tbody tr{border-bottom:1px solid var(--border);height:var(--row-h);background:var(--white);}
tbody tr:last-child{border-bottom:none;}
.data-row{cursor:pointer;}
.data-row:hover{background:var(--accent-light)!important;}
.data-row.row-expanded{background:var(--accent-light)!important;}
.expand-row{background:#f7faff!important;}
.expand-panel{padding:16px 24px 18px!important;border-top:2px solid var(--accent);}
.expand-fields{display:flex;flex-wrap:wrap;gap:12px 24px;margin-bottom:14px;}
.ef-item{display:flex;flex-direction:column;gap:3px;min-width:160px;max-width:320px;}
.ef-label{font-size:.7rem;font-weight:600;color:var(--muted);letter-spacing:.04em;}
.ef-val{font-size:.84rem;color:var(--text);line-height:1.6;white-space:pre-wrap;}
.expand-divider{height:1px;background:var(--border);margin-bottom:14px;}
.td-date{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--accent);font-weight:600;white-space:nowrap;min-width:95px;}
.td-cell{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--text);min-width:140px;max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}
.td-sub{padding:0 12px;height:var(--row-h);font-size:.76rem;color:var(--muted);white-space:nowrap;}
.td-act{padding:0 10px;height:var(--row-h);white-space:nowrap;}
td.ed{cursor:cell;}
td.active-cell{padding:0!important;background:#fff!important;outline:2px solid var(--accent);outline-offset:-2px;}
.ghost-input{display:block;width:100%;height:var(--row-h);padding:0 12px;border:none;outline:none;background:transparent;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;color:var(--text);}
.new-row{background:#f0f7ff!important;}
.new-row td{border-top:1px solid #aac8f0;border-bottom:1px solid #aac8f0;height:var(--row-h);}
.nc{padding:0 4px;}
.nr-inp{display:block;width:100%;height:var(--row-h);border:none;border-bottom:1px solid transparent;padding:0 8px;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;outline:none;background:transparent;color:var(--text);}
.nr-inp:focus{border-bottom-color:var(--accent);}
.nr-inp::placeholder{color:#bcc4d0;}
.btn-sv{background:var(--accent);border:none;border-radius:3px;padding:3px 9px;color:white;font-size:.74rem;cursor:pointer;margin-right:3px;}
.btn-cx{background:none;border:1px solid var(--border);border-radius:3px;padding:2px 8px;color:var(--muted);font-size:.74rem;cursor:pointer;}
.btn-del{background:none;border:none;font-size:.74rem;color:var(--red);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.7;}
.btn-del:hover{opacity:1;}
.btn-comment{background:none;border:none;font-size:.74rem;color:var(--accent);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.8;margin-right:4px;}
.comment-list{display:flex;flex-direction:column;gap:10px;margin-bottom:8px;}
.no-comment{font-size:.78rem;color:var(--muted);padding:6px 0;}
.comment-item{display:flex;gap:9px;align-items:flex-start;}
.comment-avatar-sm{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6ea8fe,#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}
.comment-body{flex:1;}
.comment-meta{display:flex;align-items:center;gap:8px;margin-bottom:3px;}
.comment-name{font-size:.78rem;font-weight:600;color:var(--text);}
.comment-time{font-size:.7rem;color:var(--muted);}
.btn-del-comment{background:none;border:none;font-size:.7rem;color:var(--red);cursor:pointer;opacity:.6;font-family:'Noto Sans SC',sans-serif;}
.btn-reply-sm{background:none;border:none;font-size:.72rem;color:var(--accent);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.75;margin-left:4px;}
.comment-text{font-size:.82rem;color:var(--text);line-height:1.6;}
.comment-input-row{display:flex;align-items:center;gap:8px;padding-top:10px;border-top:1px solid var(--border);}
.comment-avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}
.comment-inp{flex:1;border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:.82rem;font-family:'Noto Sans SC',sans-serif;outline:none;}
.comment-inp:focus{border-color:var(--accent);}
.comment-send{background:var(--accent);border:none;border-radius:6px;padding:7px 14px;color:white;font-size:.78rem;cursor:pointer;font-family:'Noto Sans SC',sans-serif;}
.btn-cancel-comment{background:none;border:1px solid var(--border);border-radius:6px;padding:7px 12px;color:var(--muted);font-size:.78rem;cursor:pointer;font-family:'Noto Sans SC',sans-serif;}
.notif-panel{position:fixed;top:54px;right:20px;width:320px;background:white;border:1px solid var(--border);border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12);z-index:200;display:none;}
.notif-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);font-size:.85rem;font-weight:600;}
.notif-close{background:none;border:none;font-size:1.1rem;color:var(--muted);cursor:pointer;}
.notif-list{max-height:340px;overflow-y:auto;}
.notif-item{padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;}
.notif-item:last-child{border-bottom:none;}
.notif-item:hover{background:var(--accent-light);}
.notif-item.unread{background:#fff8f0;}
.notif-who{font-size:.8rem;font-weight:600;color:var(--text);margin-bottom:3px;}
.notif-who span{color:var(--accent);}
.notif-time{font-size:.7rem;color:#bbb;margin-top:3px;}
.notif-empty{padding:24px 16px;text-align:center;color:var(--muted);font-size:.82rem;}
.empty-msg{text-align:center;padding:50px;color:var(--muted);font-size:.86rem;}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(14px);background:#1a2030;color:white;padding:8px 20px;border-radius:18px;font-size:.8rem;opacity:0;transition:all .25s;z-index:999;white-space:nowrap;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>
<div id="loadingScreen"><div class="loading-logo">\u{1F9E0} \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</div><div class="loading-spinner"></div></div>
<div id="authScreen">
  <div class="auth-card">
    <div class="auth-logo">\u{1F9E0} \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</div>
    <div class="auth-sub">\u56E2\u961F\u6BCF\u65E5\u8BB0\u5FC6\u8BB0\u5F55\u7CFB\u7EDF</div>
    <div class="auth-tabs">
      <div class="auth-tab active" onclick="switchTab('login')">\u767B\u5F55</div>
      <div class="auth-tab" onclick="switchTab('register')">\u6CE8\u518C</div>
    </div>
    <div class="auth-form active" id="loginForm">
      <div class="field"><label>\u90AE\u7BB1</label><input type="email" id="loginEmail" placeholder="your@email.com" onkeydown="if(event.key==='Enter')doLogin()"/></div>
      <div class="field"><label>\u5BC6\u7801</label><input type="password" id="loginPass" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022" onkeydown="if(event.key==='Enter')doLogin()"/></div>
      <div class="auth-error" id="authError"></div>
      <button class="btn-auth" onclick="doLogin()">\u767B\u5F55</button>
    </div>
    <div class="auth-form" id="registerForm">
      <div class="field"><label>\u59D3\u540D</label><input type="text" id="regName" placeholder="\u4F60\u7684\u59D3\u540D"/></div>
      <div class="field"><label>\u90AE\u7BB1</label><input type="email" id="regEmail" placeholder="your@email.com"/></div>
      <div class="field"><label>\u5BC6\u7801\uFF08\u81F3\u5C116\u4F4D\uFF09</label><input type="password" id="regPass" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022"/></div>
      <div class="field"><label>\u9080\u8BF7\u7801</label><input type="text" id="regInvite" placeholder="\u8BF7\u8F93\u5165\u56E2\u961F\u9080\u8BF7\u7801"/></div>
      <div class="auth-error" id="regError"></div>
      <button class="btn-auth" id="regBtn" onclick="doRegister()">\u6CE8\u518C</button>
    </div>
  </div>
</div>
<div id="appScreen">
  <div class="topbar">
    <div class="topbar-title">\u{1F9E0} \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</div>
    <div class="topbar-user" id="topUser"></div>
    <button class="btn-notif" id="notifBtn" onclick="toggleNotif()">\u{1F514} <span class="notif-badge" id="notifCount">0</span></button>
    <button class="btn-logout" onclick="doLogout()">\u9000\u51FA</button>
  </div>
  <div class="toolbar">
    <span class="filter-label">\u7B5B\u9009\u6210\u5458\uFF1A</span>
    <select class="filter-select" id="filterUser" onchange="renderTable()"><option value="">\u5168\u90E8\u6210\u5458</option></select>
    <span class="filter-label">\u65E5\u671F\u4ECE\uFF1A</span>
    <input class="filter-input" type="date" id="filterDateFrom" onchange="renderTable()"/>
    <span class="filter-label">\u5230\uFF1A</span>
    <input class="filter-input" type="date" id="filterDateTo" onchange="renderTable()"/>
    <button class="btn-add" onclick="addNewRow()">\uFF0B \u65B0\u589E\u8BB0\u5F55</button>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>\u65E5\u671F</th><th>\u4ECA\u65E5\u5B8C\u6210</th><th>\u660E\u65E5\u8BA1\u5212</th><th>\u9047\u5230\u95EE\u9898</th><th>\u611F\u609F\u601D\u8003</th><th>\u91CD\u8981\u5907\u6CE8</th><th>\u63D0\u4EA4\u8005</th><th>\u64CD\u4F5C</th></tr></thead>
      <tbody id="tableBody"><tr><td colspan="8" class="empty-msg">\u52A0\u8F7D\u4E2D\u2026</td></tr></tbody>
    </table>
  </div>
</div>
<div class="notif-panel" id="notifPanel">
  <div class="notif-header"><span>\u65B0\u56DE\u590D\u901A\u77E5</span><button class="notif-close" onclick="toggleNotif()">\xD7</button></div>
  <div class="notif-list" id="notifList"></div>
</div>
<div class="toast" id="toast"></div>

<script>
const API = '';
let currentUser = null;
let allRecords  = [];
let newRowActive = false;
let commentCounts = {};
const ADMIN_EMAIL = '1065857324@qq.com';

// \u2500\u2500 Init \u2500\u2500
const saved = localStorage.getItem('memory_user');
if (saved) {
  currentUser = JSON.parse(saved);
  show('appScreen');
  hide('loadingScreen');
  document.getElementById('topUser').textContent = currentUser.name;
  loadRecords();
} else {
  hide('loadingScreen');
  show('authScreen');
}

function show(id){ document.getElementById(id).style.display = id==='authScreen'?'flex':'block'; }
function hide(id){ document.getElementById(id).style.display = 'none'; }

// \u2500\u2500 Auth \u2500\u2500
function switchTab(tab){
  document.querySelectorAll('.auth-tab').forEach((b,i)=>b.classList.toggle('active',(i===0)===(tab==='login')));
  document.getElementById('loginForm').classList.toggle('active',tab==='login');
  document.getElementById('registerForm').classList.toggle('active',tab==='register');
  document.getElementById('authError').textContent='';
}

async function doLogin(){
  const email=document.getElementById('loginEmail').value.trim();
  const pass=document.getElementById('loginPass').value;
  document.getElementById('authError').textContent='';
  if(!email||!pass){document.getElementById('authError').textContent='\u8BF7\u586B\u5199\u90AE\u7BB1\u548C\u5BC6\u7801';return;}
  const res=await fetch(API+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pass})});
  const data=await res.json();
  if(!res.ok){document.getElementById('authError').textContent=data.error;return;}
  localStorage.setItem('memory_token',data.token);
  localStorage.setItem('memory_user',JSON.stringify(data.user));
  currentUser=data.user;
  hide('authScreen'); show('appScreen');
  document.getElementById('topUser').textContent=currentUser.name;
  loadRecords();
}

async function doRegister(){
  const name=document.getElementById('regName').value.trim();
  const email=document.getElementById('regEmail').value.trim();
  const pass=document.getElementById('regPass').value;
  const invite=document.getElementById('regInvite').value.trim();
  const errEl=document.getElementById('regError');
  const btn=document.getElementById('regBtn');
  errEl.textContent='';
  if(!name||!email||!pass||!invite){errEl.textContent='\u8BF7\u586B\u5199\u6240\u6709\u5B57\u6BB5';return;}
  btn.textContent='\u6CE8\u518C\u4E2D\u2026';btn.disabled=true;
  const res=await fetch(API+'/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,email,password:pass,inviteCode:invite})});
  const data=await res.json();
  if(!res.ok){errEl.textContent=data.error;btn.textContent='\u6CE8\u518C';btn.disabled=false;return;}
  localStorage.setItem('memory_token',data.token);
  localStorage.setItem('memory_user',JSON.stringify(data.user));
  currentUser=data.user;
  hide('authScreen'); show('appScreen');
  document.getElementById('topUser').textContent=currentUser.name;
  loadRecords();
}

function doLogout(){
  localStorage.removeItem('memory_token');
  localStorage.removeItem('memory_user');
  currentUser=null; allRecords=[];
  hide('appScreen'); show('authScreen');
}

function authHeaders(){
  return {'Content-Type':'application/json','Authorization':'Bearer '+localStorage.getItem('memory_token')};
}

// \u2500\u2500 Records \u2500\u2500
async function loadRecords(){
  const res=await fetch(API+'/api/worklogs',{headers:authHeaders()});
  if(!res.ok){if(res.status===401)doLogout();return;}
  allRecords=await res.json();
  const cRes=await fetch(API+'/api/comment-counts',{headers:authHeaders()});
  commentCounts=cRes.ok?await cRes.json():{};
  updateMemberDropdown();
  renderTable();
  checkNotifications();
}

function updateMemberDropdown(){
  const sel=document.getElementById('filterUser');
  const cur=sel.value;
  const names=[...new Set(allRecords.map(r=>r.author_name).filter(Boolean))].sort();
  sel.innerHTML='<option value="">\u5168\u90E8\u6210\u5458</option>'+names.map(n=>\`<option value="\${n}" \${n===cur?'selected':''}>\${n}</option>\`).join('');
}

function renderTable(){
  const fu=document.getElementById('filterUser').value;
  const df=document.getElementById('filterDateFrom').value;
  const dt=document.getElementById('filterDateTo').value;
  let list=allRecords;
  if(fu) list=list.filter(r=>r.author_name===fu);
  if(df) list=list.filter(r=>r.date>=df);
  if(dt) list=list.filter(r=>r.date<=dt);

  const tbody=document.getElementById('tableBody');
  const isAdmin=currentUser?.email===ADMIN_EMAIL;
  const trunc=(s,n=28)=>s&&s.length>n?s.substring(0,n)+'\u2026':(s||'');
  let html='';

  if(newRowActive){
    const today=new Date().toISOString().split('T')[0];
    html+=\`<tr class="new-row"><td class="nc"><input class="nr-inp" type="date" id="nr_date" value="\${today}"/></td>
    <td class="nc"><input class="nr-inp" type="text" id="nr_done" placeholder="\u4ECA\u65E5\u5B8C\u6210\u2026"/></td>
    <td class="nc"><input class="nr-inp" type="text" id="nr_plan" placeholder="\u660E\u65E5\u8BA1\u5212\u2026"/></td>
    <td class="nc"><input class="nr-inp" type="text" id="nr_problem" placeholder="\u9047\u5230\u95EE\u9898\u2026"/></td>
    <td class="nc"><input class="nr-inp" type="text" id="nr_thinking" placeholder="\u611F\u609F\u601D\u8003\u2026"/></td>
    <td class="nc"><input class="nr-inp" type="text" id="nr_important" placeholder="\u91CD\u8981\u5907\u6CE8\u2026"/></td>
    <td class="td-sub">\${currentUser?.name||''}</td>
    <td class="td-act"><button class="btn-sv" onclick="saveNewRow()">\u2713</button><button class="btn-cx" onclick="cancelNewRow()">\u2715</button></td></tr>\`;
  }

  if(!list.length){
    html+=\`<tr><td colspan="8" class="empty-msg">\u6682\u65E0\u8BB0\u5F55</td></tr>\`;
  } else {
    html+=list.map(r=>{
      const own=r.author_id===currentUser?.id;
      const canEdit=own||isAdmin;
      const cnt=commentCounts[r.id]||0;
      return \`<tr class="data-row" data-rid="\${r.id}" onclick="toggleExpand(\${r.id})">
        <td class="td-date\${canEdit?' ed':''}" data-id="\${r.id}" data-field="date">\${r.date||''}</td>
        <td class="td-cell\${canEdit?' ed':''}" data-id="\${r.id}" data-field="done">\${trunc(r.done)}</td>
        <td class="td-cell\${canEdit?' ed':''}" data-id="\${r.id}" data-field="plan">\${trunc(r.plan)}</td>
        <td class="td-cell\${canEdit?' ed':''}" data-id="\${r.id}" data-field="problem">\${trunc(r.problem)}</td>
        <td class="td-cell\${canEdit?' ed':''}" data-id="\${r.id}" data-field="thinking">\${trunc(r.thinking)}</td>
        <td class="td-cell\${canEdit?' ed':''}" data-id="\${r.id}" data-field="important">\${trunc(r.important)}</td>
        <td class="td-sub">\${r.author_name||''}</td>
        <td class="td-act" onclick="event.stopPropagation()">
          <button class="btn-comment" onclick="toggleExpand(\${r.id})">\u{1F4AC} \${cnt}</button>
          \${canEdit?\`<button class="btn-del" onclick="delRecord(\${r.id})">\u5220\u9664</button>\`:''}
        </td></tr>
        <tr class="expand-row" id="er_\${r.id}" style="display:none">
          <td colspan="8" class="expand-panel">
            <div class="expand-fields">
              \${r.done?\`<div class="ef-item"><span class="ef-label">\u4ECA\u65E5\u5B8C\u6210</span><span class="ef-val">\${r.done}</span></div>\`:''}
              \${r.plan?\`<div class="ef-item"><span class="ef-label">\u660E\u65E5\u8BA1\u5212</span><span class="ef-val">\${r.plan}</span></div>\`:''}
              \${r.problem?\`<div class="ef-item"><span class="ef-label">\u9047\u5230\u95EE\u9898</span><span class="ef-val">\${r.problem}</span></div>\`:''}
              \${r.thinking?\`<div class="ef-item"><span class="ef-label">\u611F\u609F\u601D\u8003</span><span class="ef-val">\${r.thinking}</span></div>\`:''}
              \${r.important?\`<div class="ef-item"><span class="ef-label">\u91CD\u8981\u5907\u6CE8</span><span class="ef-val">\${r.important}</span></div>\`:''}
            </div>
            <div class="expand-divider"></div>
            <div class="comment-list" id="cl_\${r.id}"></div>
            <div class="comment-input-row" id="cbox_\${r.id}" style="display:none">
              <div class="comment-avatar">\${(currentUser?.name||'?')[0].toUpperCase()}</div>
              <input class="comment-inp" id="ci_\${r.id}" placeholder="\u5199\u4E0B\u4F60\u7684\u7591\u95EE\u6216\u56DE\u590D\u2026" onkeydown="if(event.key==='Enter')submitComment(\${r.id})"/>
              <button class="comment-send" onclick="submitComment(\${r.id})">\u53D1\u9001</button>
              <button class="btn-cancel-comment" onclick="toggleReplyBox(\${r.id})">\u53D6\u6D88</button>
            </div>
          </td>
        </tr>\`;
    }).join('');
  }

  tbody.innerHTML=html;
  document.querySelectorAll('td.ed').forEach(td=>{
    td.addEventListener('click',e=>{e.stopPropagation();document.querySelectorAll('.data-row').forEach(r=>r.classList.remove('row-expanded'));td.closest('tr').classList.add('row-expanded');startEdit(td);});
  });
  if(newRowActive) setTimeout(()=>document.getElementById('nr_done')?.focus(),30);
}

// \u2500\u2500 Inline edit \u2500\u2500
function startEdit(td){
  if(td.dataset.editing) return;
  td.dataset.editing='1';
  const id=parseInt(td.dataset.id), field=td.dataset.field;
  const rec=allRecords.find(r=>r.id===id);
  if(!rec) return;
  const origVal=rec[field]||'', origText=td.textContent;
  td.classList.add('active-cell');
  td.innerHTML=\`<input class="ghost-input" type="\${field==='date'?'date':'text'}" value="\${origVal}"/>\`;
  const inp=td.querySelector('input');
  inp.focus(); if(field!=='date'){inp.selectionStart=inp.selectionEnd=inp.value.length;}
  const allEd=()=>Array.from(document.querySelectorAll('td.ed'));
  const commit=async()=>{
    const newVal=inp.value.trim();
    delete td.dataset.editing; td.classList.remove('active-cell'); td.textContent=newVal;
    td.addEventListener('click',e=>{e.stopPropagation();startEdit(td);},{once:true});
    if(newVal===origVal) return;
    const body={...rec,[field]:newVal};
    const res=await fetch(API+\`/api/worklogs/\${id}\`,{method:'PUT',headers:authHeaders(),body:JSON.stringify(body)});
    if(res.ok){rec[field]=newVal;showToast('\u5DF2\u4FDD\u5B58 \u2713');}else{showToast('\u4FDD\u5B58\u5931\u8D25');td.textContent=origText;}
  };
  inp.addEventListener('blur',commit);
  inp.addEventListener('keydown',e=>{
    if(e.key==='Enter'){e.preventDefault();inp.blur();}
    if(e.key==='Escape'){inp.removeEventListener('blur',commit);delete td.dataset.editing;td.classList.remove('active-cell');td.textContent=origText;td.addEventListener('click',e=>{e.stopPropagation();startEdit(td);},{once:true});}
    if(e.key==='Tab'){e.preventDefault();const eds=allEd();const idx=eds.indexOf(td);inp.removeEventListener('blur',commit);commit().then(()=>{const next=eds[e.shiftKey?idx-1:idx+1];if(next)next.click();});}
  });
}

// \u2500\u2500 New row \u2500\u2500
function addNewRow(){if(newRowActive){document.getElementById('nr_done')?.focus();return;}newRowActive=true;renderTable();}
function cancelNewRow(){newRowActive=false;renderTable();}
async function saveNewRow(){
  const date=document.getElementById('nr_date')?.value||'';
  const done=document.getElementById('nr_done')?.value.trim()||'';
  const plan=document.getElementById('nr_plan')?.value.trim()||'';
  const problem=document.getElementById('nr_problem')?.value.trim()||'';
  const thinking=document.getElementById('nr_thinking')?.value.trim()||'';
  const important=document.getElementById('nr_important')?.value.trim()||'';
  if(!date){showToast('\u8BF7\u9009\u62E9\u65E5\u671F');return;}
  if(!done&&!plan){showToast('\u8BF7\u81F3\u5C11\u586B\u5199\u4ECA\u65E5\u5B8C\u6210\u6216\u660E\u65E5\u8BA1\u5212');return;}
  const res=await fetch(API+'/api/worklogs',{method:'POST',headers:authHeaders(),body:JSON.stringify({date,done,plan,problem,thinking,important})});
  if(res.ok){newRowActive=false;showToast('\u63D0\u4EA4\u6210\u529F \u2713');await loadRecords();}else{showToast('\u63D0\u4EA4\u5931\u8D25');}
}

// \u2500\u2500 Delete \u2500\u2500
async function delRecord(id){
  if(!confirm('\u786E\u5B9A\u5220\u9664\u8FD9\u6761\u8BB0\u5F55\uFF1F')) return;
  const res=await fetch(API+\`/api/worklogs/\${id}\`,{method:'DELETE',headers:authHeaders()});
  if(res.ok){showToast('\u5DF2\u5220\u9664');await loadRecords();}else showToast('\u5220\u9664\u5931\u8D25');
}

// \u2500\u2500 Expand \u2500\u2500
async function toggleExpand(id){
  const row=document.getElementById('er_'+id);
  if(!row) return;
  const isOpen=row.style.display!=='none';
  document.querySelectorAll('.expand-row').forEach(r=>r.style.display='none');
  document.querySelectorAll('.data-row').forEach(r=>r.classList.remove('row-expanded'));
  if(isOpen) return;
  row.style.display='table-row';
  document.querySelector(\`tr[data-rid="\${id}"]\`)?.classList.add('row-expanded');
  await loadComments(id);
}

// \u2500\u2500 Comments \u2500\u2500
async function loadComments(id){
  const res=await fetch(API+\`/api/worklogs/\${id}/comments\`,{headers:authHeaders()});
  if(!res.ok) return;
  const comments=await res.json();
  renderComments(id,comments);
}

function renderComments(id,comments){
  const el=document.getElementById('cl_'+id);
  if(!el) return;
  const replyBtn=\`<button class="btn-reply-sm" onclick="toggleReplyBox(\${id})">\u270F\uFE0F \u56DE\u590D</button>\`;
  if(!comments.length){el.innerHTML=\`<div class="no-comment">\u8FD8\u6CA1\u6709\u8BC4\u8BBA\uFF0C\u6765\u7B2C\u4E00\u4E2A\u63D0\u95EE\u5427 &nbsp;\${replyBtn}</div>\`;return;}
  el.innerHTML=comments.map((c,i)=>{
    const t=c.created_at?new Date(c.created_at*1000).toLocaleDateString('zh-CN',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'';
    const isMe=c.author_id===currentUser?.id;
    const isAdmin=currentUser?.email===ADMIN_EMAIL;
    const isLast=i===comments.length-1;
    return \`<div class="comment-item">
      <div class="comment-avatar-sm">\${(c.author_name||'?')[0].toUpperCase()}</div>
      <div class="comment-body">
        <div class="comment-meta">
          <span class="comment-name">\${c.author_name||''}</span>
          <span class="comment-time">\${t}</span>
          \${(isMe||isAdmin)?\`<button class="btn-del-comment" onclick="delComment(\${id},\${c.id})">\u5220\u9664</button>\`:''}
          \${isLast?replyBtn:''}
        </div>
        <div class="comment-text">\${c.text}</div>
      </div></div>\`;
  }).join('');
}

function toggleReplyBox(id){
  const box=document.getElementById('cbox_'+id);
  if(!box) return;
  const isOpen=box.style.display!=='none';
  box.style.display=isOpen?'none':'flex';
  if(!isOpen) setTimeout(()=>document.getElementById('ci_'+id)?.focus(),30);
}

async function submitComment(id){
  const inp=document.getElementById('ci_'+id);
  const text=inp?.value.trim();
  if(!text) return;
  inp.value='';
  const res=await fetch(API+\`/api/worklogs/\${id}/comments\`,{method:'POST',headers:authHeaders(),body:JSON.stringify({text})});
  if(res.ok){
    const box=document.getElementById('cbox_'+id);
    if(box) box.style.display='none';
    await loadComments(id);
    commentCounts[id]=(commentCounts[id]||0)+1;
    const cc=document.querySelector(\`tr[data-rid="\${id}"] .btn-comment\`);
    if(cc) cc.textContent=\`\u{1F4AC} \${commentCounts[id]}\`;
    await checkNotifications();
  }
}

async function delComment(wid,cid){
  if(!confirm('\u5220\u9664\u8FD9\u6761\u8BC4\u8BBA\uFF1F')) return;
  const res=await fetch(API+\`/api/comments/\${cid}\`,{method:'DELETE',headers:authHeaders()});
  if(res.ok) await loadComments(wid);
}

// \u2500\u2500 Notifications \u2500\u2500
async function checkNotifications(){
  if(!currentUser) return;
  const seenRaw=localStorage.getItem('notif_seen_'+currentUser.id)||'{}';
  const seen=JSON.parse(seenRaw);
  const notifs=[];
  for(const r of allRecords){
    if(r.author_id!==currentUser.id) continue;
    try{
      const res=await fetch(API+\`/api/worklogs/\${r.id}/comments\`,{headers:authHeaders()});
      if(!res.ok) continue;
      const comments=await res.json();
      for(const c of comments){
        if(c.author_id===currentUser.id) continue;
        const key=r.id+'_'+c.id;
        notifs.push({key,rid:r.id,comment:c,record:r,isNew:!seen[key]});
      }
    }catch(e){}
  }
  const newCount=notifs.filter(n=>n.isNew).length;
  const btn=document.getElementById('notifBtn');
  const badge=document.getElementById('notifCount');
  if(notifs.length>0){btn.style.display='inline-flex';badge.textContent=newCount;badge.style.display=newCount>0?'inline':'none';}
  const list=document.getElementById('notifList');
  if(!notifs.length){list.innerHTML='<div class="notif-empty">\u6682\u65E0\u65B0\u56DE\u590D</div>';return;}
  list.innerHTML=notifs.reverse().map(n=>{
    const t=n.comment.created_at?new Date(n.comment.created_at*1000).toLocaleDateString('zh-CN',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}):'';
    return \`<div class="notif-item \${n.isNew?'unread':''}" onclick="goToNotif(\${n.rid},'\${n.key}')">
      <div class="notif-who"><span>\${n.comment.author_name||''}</span> \u56DE\u590D\u4E86\u4F60\u7684\u8BB0\u5F55\u300C\${n.record.date||''}\u300D</div>
      <div class="notif-time">\${t}</div></div>\`;
  }).join('');
  window._notifs=notifs;
}

function toggleNotif(){
  const panel=document.getElementById('notifPanel');
  const isOpen=panel.style.display!=='none';
  panel.style.display=isOpen?'none':'block';
  if(!isOpen){
    const seen=JSON.parse(localStorage.getItem('notif_seen_'+currentUser?.id)||'{}');
    (window._notifs||[]).forEach(n=>seen[n.key]=true);
    localStorage.setItem('notif_seen_'+currentUser?.id,JSON.stringify(seen));
    document.getElementById('notifCount').style.display='none';
    document.querySelectorAll('.notif-item').forEach(el=>el.classList.remove('unread'));
  }
}

async function goToNotif(rid){
  document.getElementById('notifPanel').style.display='none';
  await toggleExpand(rid);
  document.querySelector(\`tr[data-rid="\${rid}"]\`)?.scrollIntoView({behavior:'smooth',block:'center'});
}

document.addEventListener('click',e=>{
  const panel=document.getElementById('notifPanel');
  const btn=document.getElementById('notifBtn');
  if(panel&&!panel.contains(e.target)&&btn&&!btn.contains(e.target)) panel.style.display='none';
});

function showToast(msg){
  const t=document.getElementById('toast');
  t.textContent=msg;t.classList.add('show');
  clearTimeout(window._tt);window._tt=setTimeout(()=>t.classList.remove('show'),2200);
}
<\/script>
</body>
</html>`;
}
__name(getHTML, "getHTML");
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
