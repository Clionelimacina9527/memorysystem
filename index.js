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
                  text: { tag: "lark_md", content: "**" + user.name + "** \u56DE\u590D\u4E86 **" + log.author_name + " " + log.date + "** \u7684\u8BB0\u5F55\uFF0C\u5FEB\u53BB\u770B\u770B\u5427 \u{1F440}" }
                }, {
                  tag: "action",
                  actions: [{ tag: "button", text: { tag: "plain_text", content: "\u{1F449} \u67E5\u770B\u8BB0\u5F55" }, type: "primary", url: SITE_URL }]
                }]
              }
            })
          }).catch(() => {});
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
    if (path === "/api/admin/users" && method === "GET") {
      if (!isAdmin) return json({ error: "\u65E0\u6743\u9650" }, 403);
      const rows = await env.DB.prepare("SELECT id, name, email, created_at FROM users").all();
      return json(rows.results);
    }
    if (path === "/api/admin/reset-password" && method === "POST") {
      if (!isAdmin) return json({ error: "\u65E0\u6743\u9650" }, 403);
      const { userId, newPassword } = await req.json();
      if (!userId || !newPassword) return json({ error: "\u53C2\u6570\u7F3A\u5931" }, 400);
      if (newPassword.length < 6) return json({ error: "\u5BC6\u7801\u81F3\u5C116\u4F4D" }, 400);
      const newHash = await hashPassword(newPassword);
      await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, userId).run();
      return json({ ok: true });
    }
    if (path === "/api/change-password" && method === "POST") {
      const { oldPassword, newPassword } = await req.json();
      if (!oldPassword || !newPassword) return json({ error: "\u8BF7\u586B\u5199\u5B8C\u6574" }, 400);
      if (newPassword.length < 6) return json({ error: "\u65B0\u5BC6\u7801\u81F3\u5C116\u4F4D" }, 400);
      const oldHash = await hashPassword(oldPassword);
      const dbUser = await env.DB.prepare("SELECT * FROM users WHERE id=? AND password=?").bind(user.id, oldHash).first();
      if (!dbUser) return json({ error: "\u65E7\u5BC6\u7801\u4E0D\u6B63\u786E" }, 400);
      const newHash = await hashPassword(newPassword);
      await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, user.id).run();
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
  return '<!DOCTYPE html>\n' +
'<html lang="zh">\n' +
'<head>\n' +
'<meta charset="UTF-8">\n' +
'<meta name="viewport" content="width=device-width, initial-scale=1.0">\n' +
'<title>\u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</title>\n' +
'<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;600&display=swap" rel="stylesheet">\n' +
'<style>\n' +
':root{--white:#fff;--border:#e0e4eb;--text:#1a2030;--muted:#8a94a6;--accent:#2f6be8;--accent-light:#edf2fd;--red:#e84040;--header-bg:#f4f6fa;--row-sel:#ddeeff;--row-h:36px;}\n' +
'*{margin:0;padding:0;box-sizing:border-box;}\n' +
'body{background:#f0f3f7;color:var(--text);font-family:\'Noto Sans SC\',sans-serif;font-size:13px;min-height:100vh;}\n' +
'#loadingScreen{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);flex-direction:column;gap:14px;}\n' +
'.loading-logo{font-size:1.2rem;font-weight:700;color:var(--accent);}\n' +
'.loading-spinner{width:28px;height:28px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;}\n' +
'@keyframes spin{to{transform:rotate(360deg);}}\n' +
'#authScreen{display:none;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);}\n' +
'.auth-card{background:var(--white);border-radius:14px;padding:36px 32px;width:100%;max-width:360px;box-shadow:0 4px 20px rgba(0,0,0,.09);}\n' +
'.auth-logo{font-size:1.2rem;font-weight:700;color:var(--accent);text-align:center;margin-bottom:4px;}\n' +
'.auth-sub{font-size:.78rem;color:var(--muted);text-align:center;margin-bottom:22px;}\n' +
'.auth-tabs{display:flex;background:#f0f3f7;border-radius:7px;padding:3px;margin-bottom:18px;}\n' +
'.auth-tab{flex:1;padding:7px;text-align:center;border-radius:5px;cursor:pointer;font-size:.82rem;color:var(--muted);transition:all .15s;}\n' +
'.auth-tab.active{background:var(--white);color:var(--text);font-weight:500;box-shadow:0 1px 4px rgba(0,0,0,.07);}\n' +
'.auth-form{display:none;flex-direction:column;gap:11px;}\n' +
'.auth-form.active{display:flex;}\n' +
'.field{display:flex;flex-direction:column;gap:4px;}\n' +
'.field label{font-size:.72rem;color:var(--muted);font-weight:500;}\n' +
'.field input{border:1px solid var(--border);border-radius:7px;padding:9px 11px;font-size:.86rem;font-family:\'Noto Sans SC\',sans-serif;outline:none;transition:border-color .15s;}\n' +
'.field input:focus{border-color:var(--accent);}\n' +
'.auth-error{color:var(--red);font-size:.76rem;text-align:center;min-height:15px;}\n' +
'.btn-auth{background:var(--accent);border:none;border-radius:7px;padding:11px;color:white;font-size:.86rem;font-family:\'Noto Sans SC\',sans-serif;font-weight:500;cursor:pointer;}\n' +
'.btn-auth:hover{opacity:.88;}\n' +
'#appScreen{display:none;}\n' +
'.topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 20px;height:48px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,.04);}\n' +
'.topbar-title{font-size:.95rem;font-weight:700;color:var(--text);flex:1;}\n' +
'.topbar-user{font-size:.78rem;color:var(--muted);}\n' +
'.btn-logout{background:none;border:1px solid var(--border);border-radius:5px;padding:4px 11px;font-size:.75rem;color:var(--muted);cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;}\n' +
'.btn-notif{background:none;border:1px solid var(--border);border-radius:6px;padding:4px 11px;font-size:.78rem;color:var(--text);cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;display:none;}\n' +
'.notif-badge{background:var(--red);color:white;border-radius:10px;padding:1px 6px;font-size:.68rem;font-weight:700;margin-left:3px;}\n' +
'.toolbar{padding:9px 20px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--white);border-bottom:1px solid var(--border);}\n' +
'.filter-label{font-size:.75rem;color:var(--muted);white-space:nowrap;}\n' +
'.filter-select{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:\'Noto Sans SC\',sans-serif;outline:none;width:180px;background:white;cursor:pointer;color:var(--text);}\n' +
'.filter-select:focus{border-color:var(--accent);}\n' +
'.filter-input{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:\'Noto Sans SC\',sans-serif;outline:none;width:130px;}\n' +
'.filter-input:focus{border-color:var(--accent);}\n' +
'.btn-add{background:var(--accent);border:none;border-radius:6px;padding:7px 16px;color:white;font-size:.8rem;font-family:\'Noto Sans SC\',sans-serif;font-weight:500;cursor:pointer;margin-left:auto;}\n' +
'.btn-add:hover{opacity:.88;}\n' +
'.table-wrap{overflow-x:auto;padding:14px 20px 60px;}\n' +
'table{width:100%;border-collapse:collapse;background:var(--white);border-radius:8px;overflow:hidden;box-shadow:0 1px 5px rgba(0,0,0,.06);min-width:1000px;}\n' +
'thead tr{background:var(--header-bg);}\n' +
'th{padding:9px 12px;text-align:left;font-size:.73rem;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;}\n' +
'tbody tr{border-bottom:1px solid var(--border);height:var(--row-h);background:var(--white);}\n' +
'tbody tr:last-child{border-bottom:none;}\n' +
'.data-row{cursor:pointer;}\n' +
'.data-row:hover{background:var(--accent-light)!important;}\n' +
'.data-row.row-expanded{background:var(--accent-light)!important;}\n' +
'.expand-row{background:#f7faff!important;}\n' +
'.expand-panel{padding:16px 24px 18px!important;border-top:2px solid var(--accent);}\n' +
'.expand-fields{display:flex;flex-wrap:wrap;gap:12px 24px;margin-bottom:14px;}\n' +
'.ef-item{display:flex;flex-direction:column;gap:3px;min-width:160px;max-width:320px;}\n' +
'.ef-label{font-size:.7rem;font-weight:600;color:var(--muted);letter-spacing:.04em;}\n' +
'.ef-val{font-size:.84rem;color:var(--text);line-height:1.6;white-space:pre-wrap;}\n' +
'.expand-divider{height:1px;background:var(--border);margin-bottom:14px;}\n' +
'.td-date{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--accent);font-weight:600;white-space:nowrap;min-width:95px;}\n' +
'.td-cell{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--text);min-width:140px;max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}\n' +
'.td-sub{padding:0 12px;height:var(--row-h);font-size:.76rem;color:var(--muted);white-space:nowrap;}\n' +
'.td-act{padding:0 10px;height:var(--row-h);white-space:nowrap;}\n' +
'td.ed{cursor:cell;}\n' +
'td.active-cell{padding:0!important;background:#fff!important;outline:2px solid var(--accent);outline-offset:-2px;}\n' +
'.ghost-input{display:block;width:100%;height:var(--row-h);padding:0 12px;border:none;outline:none;background:transparent;font-size:.8rem;font-family:\'Noto Sans SC\',sans-serif;color:var(--text);}\n' +
'.new-row{background:#f0f7ff!important;}\n' +
'.new-row td{border-top:1px solid #aac8f0;border-bottom:1px solid #aac8f0;height:var(--row-h);}\n' +
'.nc{padding:0 4px;}\n' +
'.nr-inp{display:block;width:100%;height:var(--row-h);border:none;border-bottom:1px solid transparent;padding:0 8px;font-size:.8rem;font-family:\'Noto Sans SC\',sans-serif;outline:none;background:transparent;color:var(--text);}\n' +
'.nr-inp:focus{border-bottom-color:var(--accent);}\n' +
'.nr-inp::placeholder{color:#bcc4d0;}\n' +
'.btn-sv{background:var(--accent);border:none;border-radius:3px;padding:3px 9px;color:white;font-size:.74rem;cursor:pointer;margin-right:3px;}\n' +
'.btn-cx{background:none;border:1px solid var(--border);border-radius:3px;padding:2px 8px;color:var(--muted);font-size:.74rem;cursor:pointer;}\n' +
'.btn-del{background:none;border:none;font-size:.74rem;color:var(--red);cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;opacity:.7;}\n' +
'.btn-del:hover{opacity:1;}\n' +
'.btn-comment{background:none;border:none;font-size:.74rem;color:var(--accent);cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;opacity:.8;margin-right:4px;}\n' +
'.comment-list{display:flex;flex-direction:column;gap:10px;margin-bottom:8px;}\n' +
'.no-comment{font-size:.78rem;color:var(--muted);padding:6px 0;}\n' +
'.comment-item{display:flex;gap:9px;align-items:flex-start;}\n' +
'.comment-avatar-sm{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6ea8fe,#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}\n' +
'.comment-body{flex:1;}\n' +
'.comment-meta{display:flex;align-items:center;gap:8px;margin-bottom:3px;}\n' +
'.comment-name{font-size:.78rem;font-weight:600;color:var(--text);}\n' +
'.comment-time{font-size:.7rem;color:var(--muted);}\n' +
'.btn-del-comment{background:none;border:none;font-size:.7rem;color:var(--red);cursor:pointer;opacity:.6;font-family:\'Noto Sans SC\',sans-serif;}\n' +
'.btn-reply-sm{background:none;border:none;font-size:.72rem;color:var(--accent);cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;opacity:.75;margin-left:4px;}\n' +
'.comment-text{font-size:.82rem;color:var(--text);line-height:1.6;}\n' +
'.comment-input-row{display:flex;align-items:center;gap:8px;padding-top:10px;border-top:1px solid var(--border);}\n' +
'.comment-avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}\n' +
'.comment-inp{flex:1;border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:.82rem;font-family:\'Noto Sans SC\',sans-serif;outline:none;}\n' +
'.comment-inp:focus{border-color:var(--accent);}\n' +
'.comment-send{background:var(--accent);border:none;border-radius:6px;padding:7px 14px;color:white;font-size:.78rem;cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;}\n' +
'.btn-cancel-comment{background:none;border:1px solid var(--border);border-radius:6px;padding:7px 12px;color:var(--muted);font-size:.78rem;cursor:pointer;font-family:\'Noto Sans SC\',sans-serif;}\n' +
'.notif-panel{position:fixed;top:54px;right:20px;width:320px;background:white;border:1px solid var(--border);border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12);z-index:200;display:none;}\n' +
'.notif-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);font-size:.85rem;font-weight:600;}\n' +
'.notif-close{background:none;border:none;font-size:1.1rem;color:var(--muted);cursor:pointer;}\n' +
'.notif-list{max-height:340px;overflow-y:auto;}\n' +
'.notif-item{padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;}\n' +
'.notif-item:last-child{border-bottom:none;}\n' +
'.notif-item:hover{background:var(--accent-light);}\n' +
'.notif-item.unread{background:#fff8f0;}\n' +
'.notif-who{font-size:.8rem;font-weight:600;color:var(--text);margin-bottom:3px;}\n' +
'.notif-who span{color:var(--accent);}\n' +
'.notif-time{font-size:.7rem;color:#bbb;margin-top:3px;}\n' +
'.notif-empty{padding:24px 16px;text-align:center;color:var(--muted);font-size:.82rem;}\n' +
'.empty-msg{text-align:center;padding:50px;color:var(--muted);font-size:.86rem;}\n' +
'.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:300;align-items:center;justify-content:center;}\n' +
'.modal-box{background:white;border-radius:14px;padding:28px;width:100%;max-width:360px;box-shadow:0 4px 24px rgba(0,0,0,.15);}\n' +
'.modal-title{font-size:.95rem;font-weight:700;color:#1a2030;margin-bottom:18px;}\n' +
'.modal-error{color:#e84040;font-size:.76rem;min-height:15px;margin-bottom:10px;text-align:center;}\n' +
'.modal-btns{display:flex;gap:8px;}\n' +
'.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(14px);background:#1a2030;color:white;padding:8px 20px;border-radius:18px;font-size:.8rem;opacity:0;transition:all .25s;z-index:999;white-space:nowrap;}\n' +
'.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}\n' +
'</style>\n' +
'</head>\n' +
'<body>\n' +
'<div id="loadingScreen"><div class="loading-logo">\uD83E\uDDE0 \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</div><div class="loading-spinner"></div></div>\n' +
'<div id="authScreen">\n' +
'  <div class="auth-card">\n' +
'    <div class="auth-logo">\uD83E\uDDE0 \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</div>\n' +
'    <div class="auth-sub">\u56E2\u961F\u6BCF\u65E5\u8BB0\u5FC6\u8BB0\u5F55\u7CFB\u7EDF</div>\n' +
'    <div class="auth-tabs">\n' +
'      <div class="auth-tab active" onclick="switchTab(\'login\')">\u767B\u5F55</div>\n' +
'      <div class="auth-tab" onclick="switchTab(\'register\')">\u6CE8\u518C</div>\n' +
'    </div>\n' +
'    <div class="auth-form active" id="loginForm">\n' +
'      <div class="field"><label>\u90AE\u7BB1</label><input type="email" id="loginEmail" placeholder="your@email.com" onkeydown="if(event.key===\'Enter\')doLogin()"/></div>\n' +
'      <div class="field"><label>\u5BC6\u7801</label><input type="password" id="loginPass" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022" onkeydown="if(event.key===\'Enter\')doLogin()"/></div>\n' +
'      <div class="auth-error" id="authError"></div>\n' +
'      <button class="btn-auth" onclick="doLogin()">\u767B\u5F55</button>\n' +
'    </div>\n' +
'    <div class="auth-form" id="registerForm">\n' +
'      <div class="field"><label>\u59D3\u540D</label><input type="text" id="regName" placeholder="\u4F60\u7684\u59D3\u540D"/></div>\n' +
'      <div class="field"><label>\u90AE\u7BB1</label><input type="email" id="regEmail" placeholder="your@email.com"/></div>\n' +
'      <div class="field"><label>\u5BC6\u7801\uFF08\u81F3\u5C116\u4F4D\uFF09</label><input type="password" id="regPass" placeholder="\u2022\u2022\u2022\u2022\u2022\u2022"/></div>\n' +
'      <div class="field"><label>\u9080\u8BF7\u7801</label><input type="text" id="regInvite" placeholder="\u8BF7\u8F93\u5165\u56E2\u961F\u9080\u8BF7\u7801"/></div>\n' +
'      <div class="auth-error" id="regError"></div>\n' +
'      <button class="btn-auth" id="regBtn" onclick="doRegister()">\u6CE8\u518C</button>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +
'<div id="appScreen">\n' +
'  <div class="topbar">\n' +
'    <div class="topbar-title">\uD83E\uDDE0 \u4E2A\u4EBA\u6570\u5B57\u8BB0\u5FC6\u7CFB\u7EDF</div>\n' +
'    <div class="topbar-user" id="topUser"></div>\n' +
'    <button class="btn-notif" id="notifBtn" onclick="toggleNotif()">\uD83D\uDD14 <span class="notif-badge" id="notifCount">0</span></button>\n' +
'    <button class="btn-logout" id="adminBtn" onclick="showAdminPanel()" style="display:none">\u7BA1\u7406</button>\n' +
'    <button class="btn-logout" onclick="showChangePwd()">\u6539\u5BC6\u7801</button>\n' +
'    <button class="btn-logout" onclick="doLogout()">\u9000\u51FA</button>\n' +
'  </div>\n' +
'  <div class="toolbar">\n' +
'    <span class="filter-label">\u7B5B\u9009\u6210\u5458\uFF1A</span>\n' +
'    <select class="filter-select" id="filterUser" onchange="renderTable()"><option value="">\u5168\u90E8\u6210\u5458</option></select>\n' +
'    <span class="filter-label">\u65E5\u671F\u4ECE\uFF1A</span>\n' +
'    <input class="filter-input" type="date" id="filterDateFrom" onchange="renderTable()"/>\n' +
'    <span class="filter-label">\u5230\uFF1A</span>\n' +
'    <input class="filter-input" type="date" id="filterDateTo" onchange="renderTable()"/>\n' +
'    <button class="btn-add" onclick="addNewRow()">\uFF0B \u65B0\u589E\u8BB0\u5F55</button>\n' +
'  </div>\n' +
'  <div class="table-wrap">\n' +
'    <table>\n' +
'      <thead><tr><th>\u65E5\u671F</th><th>\u4ECA\u65E5\u5B8C\u6210</th><th>\u660E\u65E5\u8BA1\u5212</th><th>\u9047\u5230\u95EE\u9898</th><th>\u611F\u609F\u601D\u8003</th><th>\u91CD\u8981\u5907\u6CE8</th><th>\u63D0\u4EA4\u8005</th><th>\u64CD\u4F5C</th></tr></thead>\n' +
'      <tbody id="tableBody"><tr><td colspan="8" class="empty-msg">\u52A0\u8F7D\u4E2D\u2026</td></tr></tbody>\n' +
'    </table>\n' +
'  </div>\n' +
'</div>\n' +
'<div class="notif-panel" id="notifPanel">\n' +
'  <div class="notif-header"><span>\u65B0\u56DE\u590D\u901A\u77E5</span><button class="notif-close" onclick="toggleNotif()">&times;</button></div>\n' +
'  <div class="notif-list" id="notifList"></div>\n' +
'</div>\n' +
'<!-- \u7BA1\u7406\u9762\u677F -->\n' +
'<div class="modal-overlay" id="adminModal">\n' +
'  <div class="modal-box" style="max-width:420px;max-height:80vh;overflow-y:auto;">\n' +
'    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;">\n' +
'      <div class="modal-title" style="margin-bottom:0">\u7528\u6237\u7BA1\u7406</div>\n' +
'      <button class="btn-logout" onclick="hideAdminPanel()">\u5173\u95ED</button>\n' +
'    </div>\n' +
'    <div id="adminUserList"></div>\n' +
'  </div>\n' +
'</div>\n' +
'<!-- \u91CD\u7F6E\u5BC6\u7801\u5F39\u7A97 -->\n' +
'<div class="modal-overlay" id="resetModal" style="z-index:400">\n' +
'  <div class="modal-box">\n' +
'    <div class="modal-title">\u91CD\u7F6E\u5BC6\u7801</div>\n' +
'    <div id="resetTargetName" style="font-size:.84rem;color:#8a94a6;margin-bottom:12px;"></div>\n' +
'    <div class="field" style="margin-bottom:14px;"><label>\u65B0\u5BC6\u7801</label><input type="password" id="reset_new" placeholder="\u81F3\u5C116\u4F4D"/></div>\n' +
'    <div class="modal-error" id="reset_error"></div>\n' +
'    <div class="modal-btns">\n' +
'      <button class="btn-auth" style="flex:1" onclick="doResetPwd()">\u786E\u8BA4\u91CD\u7F6E</button>\n' +
'      <button class="btn-logout" style="flex:1;padding:11px" onclick="hideResetModal()">\u53D6\u6D88</button>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +
'<!-- \u6539\u5BC6\u7801\u5F39\u7A97 -->\n' +
'<div class="modal-overlay" id="pwdModal">\n' +
'  <div class="modal-box">\n' +
'    <div class="modal-title">\u4FEE\u6539\u5BC6\u7801</div>\n' +
'    <div class="field" style="margin-bottom:10px;"><label>\u65E7\u5BC6\u7801</label><input type="password" id="pwd_old" placeholder="\u8F93\u5165\u65E7\u5BC6\u7801"/></div>\n' +
'    <div class="field" style="margin-bottom:10px;"><label>\u65B0\u5BC6\u7801</label><input type="password" id="pwd_new" placeholder="\u81F3\u5C116\u4F4D"/></div>\n' +
'    <div class="field" style="margin-bottom:14px;"><label>\u786E\u8BA4\u65B0\u5BC6\u7801</label><input type="password" id="pwd_confirm" placeholder="\u518D\u8F93\u4E00\u6B21"/></div>\n' +
'    <div class="modal-error" id="pwd_error"></div>\n' +
'    <div class="modal-btns">\n' +
'      <button class="btn-auth" style="flex:1" onclick="doChangePwd()">\u786E\u8BA4\u4FEE\u6539</button>\n' +
'      <button class="btn-logout" style="flex:1;padding:11px" onclick="hideChangePwd()">\u53D6\u6D88</button>\n' +
'    </div>\n' +
'  </div>\n' +
'</div>\n' +
'<div class="toast" id="toast"></div>\n' +
'<script>\n' +
'const API = "";\n' +
'let currentUser = null;\n' +
'let allRecords = [];\n' +
'let newRowActive = false;\n' +
'let commentCounts = {};\n' +
'let resetTargetId = null;\n' +
'const ADMIN_EMAIL = "1065857324@qq.com";\n' +
'\n' +
'function show(id){ document.getElementById(id).style.display = id==="authScreen"?"flex":"block"; }\n' +
'function hide(id){ document.getElementById(id).style.display = "none"; }\n' +
'function showModal(id){ document.getElementById(id).style.display = "flex"; }\n' +
'function hideModal(id){ document.getElementById(id).style.display = "none"; }\n' +
'\n' +
'const saved = localStorage.getItem("memory_user");\n' +
'if (saved) {\n' +
'  currentUser = JSON.parse(saved);\n' +
'  show("appScreen"); hide("loadingScreen");\n' +
'  document.getElementById("topUser").textContent = currentUser.name;\n' +
'  if(currentUser.email===ADMIN_EMAIL) document.getElementById("adminBtn").style.display="inline-block";\n' +
'  loadRecords();\n' +
'} else {\n' +
'  hide("loadingScreen"); show("authScreen");\n' +
'}\n' +
'\n' +
'function switchTab(tab){\n' +
'  document.querySelectorAll(".auth-tab").forEach((b,i)=>b.classList.toggle("active",(i===0)===(tab==="login")));\n' +
'  document.getElementById("loginForm").classList.toggle("active",tab==="login");\n' +
'  document.getElementById("registerForm").classList.toggle("active",tab==="register");\n' +
'  document.getElementById("authError").textContent="";\n' +
'}\n' +
'\n' +
'async function doLogin(){\n' +
'  const email=document.getElementById("loginEmail").value.trim();\n' +
'  const pass=document.getElementById("loginPass").value;\n' +
'  document.getElementById("authError").textContent="";\n' +
'  if(!email||!pass){document.getElementById("authError").textContent="\u8BF7\u586B\u5199\u90AE\u7BB1\u548C\u5BC6\u7801";return;}\n' +
'  const res=await fetch(API+"/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password:pass})});\n' +
'  const data=await res.json();\n' +
'  if(!res.ok){document.getElementById("authError").textContent=data.error;return;}\n' +
'  localStorage.setItem("memory_token",data.token);\n' +
'  localStorage.setItem("memory_user",JSON.stringify(data.user));\n' +
'  currentUser=data.user;\n' +
'  hide("authScreen"); show("appScreen");\n' +
'  document.getElementById("topUser").textContent=currentUser.name;\n' +
'  if(currentUser.email===ADMIN_EMAIL) document.getElementById("adminBtn").style.display="inline-block";\n' +
'  loadRecords();\n' +
'}\n' +
'\n' +
'async function doRegister(){\n' +
'  const name=document.getElementById("regName").value.trim();\n' +
'  const email=document.getElementById("regEmail").value.trim();\n' +
'  const pass=document.getElementById("regPass").value;\n' +
'  const invite=document.getElementById("regInvite").value.trim();\n' +
'  const errEl=document.getElementById("regError");\n' +
'  const btn=document.getElementById("regBtn");\n' +
'  errEl.textContent="";\n' +
'  if(!name||!email||!pass||!invite){errEl.textContent="\u8BF7\u586B\u5199\u6240\u6709\u5B57\u6BB5";return;}\n' +
'  btn.textContent="\u6CE8\u518C\u4E2D\u2026";btn.disabled=true;\n' +
'  const res=await fetch(API+"/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name,email,password:pass,inviteCode:invite})});\n' +
'  const data=await res.json();\n' +
'  if(!res.ok){errEl.textContent=data.error;btn.textContent="\u6CE8\u518C";btn.disabled=false;return;}\n' +
'  localStorage.setItem("memory_token",data.token);\n' +
'  localStorage.setItem("memory_user",JSON.stringify(data.user));\n' +
'  currentUser=data.user;\n' +
'  hide("authScreen"); show("appScreen");\n' +
'  document.getElementById("topUser").textContent=currentUser.name;\n' +
'  if(currentUser.email===ADMIN_EMAIL) document.getElementById("adminBtn").style.display="inline-block";\n' +
'  loadRecords();\n' +
'}\n' +
'\n' +
'function doLogout(){\n' +
'  localStorage.removeItem("memory_token");\n' +
'  localStorage.removeItem("memory_user");\n' +
'  currentUser=null; allRecords=[];\n' +
'  hide("appScreen"); show("authScreen");\n' +
'}\n' +
'\n' +
'function authHeaders(){\n' +
'  return {"Content-Type":"application/json","Authorization":"Bearer "+localStorage.getItem("memory_token")};\n' +
'}\n' +
'\n' +
'async function loadRecords(){\n' +
'  const res=await fetch(API+"/api/worklogs",{headers:authHeaders()});\n' +
'  if(!res.ok){if(res.status===401)doLogout();return;}\n' +
'  allRecords=await res.json();\n' +
'  const cRes=await fetch(API+"/api/comment-counts",{headers:authHeaders()});\n' +
'  commentCounts=cRes.ok?await cRes.json():{};\n' +
'  updateMemberDropdown();\n' +
'  renderTable();\n' +
'  checkNotifications();\n' +
'}\n' +
'\n' +
'function updateMemberDropdown(){\n' +
'  const sel=document.getElementById("filterUser");\n' +
'  const cur=sel.value;\n' +
'  const names=[...new Set(allRecords.map(r=>r.author_name).filter(Boolean))].sort();\n' +
'  sel.innerHTML="<option value=\'\'>\u5168\u90E8\u6210\u5458</option>"+names.map(n=>"<option value=\'"+n+"\' "+(n===cur?"selected":"")+">"+n+"</option>").join("");\n' +
'}\n' +
'\n' +
'function renderTable(){\n' +
'  const fu=document.getElementById("filterUser").value;\n' +
'  const df=document.getElementById("filterDateFrom").value;\n' +
'  const dt=document.getElementById("filterDateTo").value;\n' +
'  let list=allRecords;\n' +
'  if(fu) list=list.filter(r=>r.author_name===fu);\n' +
'  if(df) list=list.filter(r=>r.date>=df);\n' +
'  if(dt) list=list.filter(r=>r.date<=dt);\n' +
'  const tbody=document.getElementById("tableBody");\n' +
'  const isAdmin=currentUser&&currentUser.email===ADMIN_EMAIL;\n' +
'  const trunc=(s,n)=>{n=n||28;return s&&s.length>n?s.substring(0,n)+"\u2026":(s||"");};\n' +
'  let html="";\n' +
'  if(newRowActive){\n' +
'    const today=new Date().toISOString().split("T")[0];\n' +
'    html+="<tr class=\'new-row\'><td class=\'nc\'><input class=\'nr-inp\' type=\'date\' id=\'nr_date\' value=\'"+today+"\'/></td>";\n' +
'    html+="<td class=\'nc\'><input class=\'nr-inp\' type=\'text\' id=\'nr_done\' placeholder=\'\u4ECA\u65E5\u5B8C\u6210\u2026\'/></td>";\n' +
'    html+="<td class=\'nc\'><input class=\'nr-inp\' type=\'text\' id=\'nr_plan\' placeholder=\'\u660E\u65E5\u8BA1\u5212\u2026\'/></td>";\n' +
'    html+="<td class=\'nc\'><input class=\'nr-inp\' type=\'text\' id=\'nr_problem\' placeholder=\'\u9047\u5230\u95EE\u9898\u2026\'/></td>";\n' +
'    html+="<td class=\'nc\'><input class=\'nr-inp\' type=\'text\' id=\'nr_thinking\' placeholder=\'\u611F\u609F\u601D\u8003\u2026\'/></td>";\n' +
'    html+="<td class=\'nc\'><input class=\'nr-inp\' type=\'text\' id=\'nr_important\' placeholder=\'\u91CD\u8981\u5907\u6CE8\u2026\'/></td>";\n' +
'    html+="<td class=\'td-sub\'>"+(currentUser&&currentUser.name||"")+"</td>";\n' +
'    html+="<td class=\'td-act\'><button class=\'btn-sv\' onclick=\'saveNewRow()\'>\u2713</button><button class=\'btn-cx\' onclick=\'cancelNewRow()\'>\u2715</button></td></tr>";\n' +
'  }\n' +
'  if(!list.length){\n' +
'    html+="<tr><td colspan=\'8\' class=\'empty-msg\'>\u6682\u65E0\u8BB0\u5F55</td></tr>";\n' +
'  } else {\n' +
'    list.forEach(function(r){\n' +
'      const own=currentUser&&r.author_id===currentUser.id;\n' +
'      const canEdit=own||isAdmin;\n' +
'      const cnt=commentCounts[r.id]||0;\n' +
'      const ed=canEdit?" ed":"";\n' +
'      html+="<tr class=\'data-row\' data-rid=\'"+r.id+"\' onclick=\'toggleExpand("+r.id+")\'>"\n' +
'        +"<td class=\'td-date"+ed+"\' data-id=\'"+r.id+"\' data-field=\'date\'>"+(r.date||"")+"</td>"\n' +
'        +"<td class=\'td-cell"+ed+"\' data-id=\'"+r.id+"\' data-field=\'done\'>"+trunc(r.done)+"</td>"\n' +
'        +"<td class=\'td-cell"+ed+"\' data-id=\'"+r.id+"\' data-field=\'plan\'>"+trunc(r.plan)+"</td>"\n' +
'        +"<td class=\'td-cell"+ed+"\' data-id=\'"+r.id+"\' data-field=\'problem\'>"+trunc(r.problem)+"</td>"\n' +
'        +"<td class=\'td-cell"+ed+"\' data-id=\'"+r.id+"\' data-field=\'thinking\'>"+trunc(r.thinking)+"</td>"\n' +
'        +"<td class=\'td-cell"+ed+"\' data-id=\'"+r.id+"\' data-field=\'important\'>"+trunc(r.important)+"</td>"\n' +
'        +"<td class=\'td-sub\'>"+(r.author_name||"")+"</td>"\n' +
'        +"<td class=\'td-act\' onclick=\'event.stopPropagation()\'>"\n' +
'        +"<button class=\'btn-comment\' onclick=\'toggleExpand("+r.id+")\'>&#128172; "+cnt+"</button>"\n' +
'        +(canEdit?"<button class=\'btn-del\' onclick=\'delRecord("+r.id+")\'>\u5220\u9664</button>":"")\n' +
'        +"</td></tr>"\n' +
'        +"<tr class=\'expand-row\' id=\'er_"+r.id+"\' style=\'display:none\'>"\n' +
'        +"<td colspan=\'8\' class=\'expand-panel\'>"\n' +
'        +"<div class=\'expand-fields\'>"\n' +
'        +(r.done?"<div class=\'ef-item\'><span class=\'ef-label\'>\u4ECA\u65E5\u5B8C\u6210</span><span class=\'ef-val\'>"+r.done+"</span></div>":"")\n' +
'        +(r.plan?"<div class=\'ef-item\'><span class=\'ef-label\'>\u660E\u65E5\u8BA1\u5212</span><span class=\'ef-val\'>"+r.plan+"</span></div>":"")\n' +
'        +(r.problem?"<div class=\'ef-item\'><span class=\'ef-label\'>\u9047\u5230\u95EE\u9898</span><span class=\'ef-val\'>"+r.problem+"</span></div>":"")\n' +
'        +(r.thinking?"<div class=\'ef-item\'><span class=\'ef-label\'>\u611F\u609F\u601D\u8003</span><span class=\'ef-val\'>"+r.thinking+"</span></div>":"")\n' +
'        +(r.important?"<div class=\'ef-item\'><span class=\'ef-label\'>\u91CD\u8981\u5907\u6CE8</span><span class=\'ef-val\'>"+r.important+"</span></div>":"")\n' +
'        +"</div><div class=\'expand-divider\'></div>"\n' +
'        +"<div class=\'comment-list\' id=\'cl_"+r.id+"\'></div>"\n' +
'        +"<div class=\'comment-input-row\' id=\'cbox_"+r.id+"\' style=\'display:none\'>"\n' +
'        +"<div class=\'comment-avatar\'>"+(currentUser&&currentUser.name?currentUser.name[0].toUpperCase():"?")+"</div>"\n' +
'        +"<input class=\'comment-inp\' id=\'ci_"+r.id+"\' placeholder=\'\u5199\u4E0B\u4F60\u7684\u7591\u95EE\u6216\u56DE\u590D\u2026\' onkeydown=\'if(event.key==&quot;Enter&quot;)submitComment("+r.id+")\'/>" +
'        +"<button class=\'comment-send\' onclick=\'submitComment("+r.id+")\'>&#x53D1;&#x9001;</button>"\n' +
'        +"<button class=\'btn-cancel-comment\' onclick=\'toggleReplyBox("+r.id+")\'>&#x53D6;&#x6D88;</button>"\n' +
'        +"</div></td></tr>";\n' +
'    });\n' +
'  }\n' +
'  tbody.innerHTML=html;\n' +
'  document.querySelectorAll("td.ed").forEach(function(td){\n' +
'    td.addEventListener("click",function(e){\n' +
'      e.stopPropagation();\n' +
'      document.querySelectorAll(".data-row").forEach(function(r){r.classList.remove("row-expanded");});\n' +
'      td.closest("tr").classList.add("row-expanded");\n' +
'      startEdit(td);\n' +
'    });\n' +
'  });\n' +
'  if(newRowActive) setTimeout(function(){var el=document.getElementById("nr_done");if(el)el.focus();},30);\n' +
'}\n' +
'\n' +
'function startEdit(td){\n' +
'  if(td.dataset.editing) return;\n' +
'  td.dataset.editing="1";\n' +
'  const id=parseInt(td.dataset.id), field=td.dataset.field;\n' +
'  const rec=allRecords.find(function(r){return r.id===id;});\n' +
'  if(!rec) return;\n' +
'  const origVal=rec[field]||"", origText=td.textContent;\n' +
'  td.classList.add("active-cell");\n' +
'  td.innerHTML="<input class=\'ghost-input\' type=\'"+(field==="date"?"date":"text")+"\' value=\'"+origVal+"\'/>";\n' +
'  const inp=td.querySelector("input");\n' +
'  inp.focus();\n' +
'  if(field!=="date"){inp.selectionStart=inp.selectionEnd=inp.value.length;}\n' +
'  const allEd=function(){return Array.from(document.querySelectorAll("td.ed"));};\n' +
'  const commit=async function(){\n' +
'    const newVal=inp.value.trim();\n' +
'    delete td.dataset.editing; td.classList.remove("active-cell"); td.textContent=newVal;\n' +
'    td.addEventListener("click",function(e){e.stopPropagation();startEdit(td);},{once:true});\n' +
'    if(newVal===origVal) return;\n' +
'    const body=Object.assign({},rec); body[field]=newVal;\n' +
'    const res=await fetch(API+"/api/worklogs/"+id,{method:"PUT",headers:authHeaders(),body:JSON.stringify(body)});\n' +
'    if(res.ok){rec[field]=newVal;showToast("\u5DF2\u4FDD\u5B58 \u2713");}else{showToast("\u4FDD\u5B58\u5931\u8D25");td.textContent=origText;}\n' +
'  };\n' +
'  inp.addEventListener("blur",commit);\n' +
'  inp.addEventListener("keydown",function(e){\n' +
'    if(e.key==="Enter"){e.preventDefault();inp.blur();}\n' +
'    if(e.key==="Escape"){inp.removeEventListener("blur",commit);delete td.dataset.editing;td.classList.remove("active-cell");td.textContent=origText;td.addEventListener("click",function(e){e.stopPropagation();startEdit(td);},{once:true});}\n' +
'    if(e.key==="Tab"){e.preventDefault();const eds=allEd();const idx=eds.indexOf(td);inp.removeEventListener("blur",commit);commit().then(function(){const next=eds[e.shiftKey?idx-1:idx+1];if(next)next.click();});}\n' +
'  });\n' +
'}\n' +
'\n' +
'function addNewRow(){if(newRowActive){var el=document.getElementById("nr_done");if(el)el.focus();return;}newRowActive=true;renderTable();}\n' +
'function cancelNewRow(){newRowActive=false;renderTable();}\n' +
'async function saveNewRow(){\n' +
'  const date=document.getElementById("nr_date")&&document.getElementById("nr_date").value||"";\n' +
'  const done=(document.getElementById("nr_done")&&document.getElementById("nr_done").value||"").trim();\n' +
'  const plan=(document.getElementById("nr_plan")&&document.getElementById("nr_plan").value||"").trim();\n' +
'  const problem=(document.getElementById("nr_problem")&&document.getElementById("nr_problem").value||"").trim();\n' +
'  const thinking=(document.getElementById("nr_thinking")&&document.getElementById("nr_thinking").value||"").trim();\n' +
'  const important=(document.getElementById("nr_important")&&document.getElementById("nr_important").value||"").trim();\n' +
'  if(!date){showToast("\u8BF7\u9009\u62E9\u65E5\u671F");return;}\n' +
'  if(!done&&!plan){showToast("\u8BF7\u81F3\u5C11\u586B\u5199\u4ECA\u65E5\u5B8C\u6210\u6216\u660E\u65E5\u8BA1\u5212");return;}\n' +
'  const res=await fetch(API+"/api/worklogs",{method:"POST",headers:authHeaders(),body:JSON.stringify({date,done,plan,problem,thinking,important})});\n' +
'  if(res.ok){newRowActive=false;showToast("\u63D0\u4EA4\u6210\u529F \u2713");await loadRecords();}else{showToast("\u63D0\u4EA4\u5931\u8D25");}\n' +
'}\n' +
'\n' +
'async function delRecord(id){\n' +
'  if(!confirm("\u786E\u5B9A\u5220\u9664\u8FD9\u6761\u8BB0\u5F55\uFF1F")) return;\n' +
'  const res=await fetch(API+"/api/worklogs/"+id,{method:"DELETE",headers:authHeaders()});\n' +
'  if(res.ok){showToast("\u5DF2\u5220\u9664");await loadRecords();}else showToast("\u5220\u9664\u5931\u8D25");\n' +
'}\n' +
'\n' +
'async function toggleExpand(id){\n' +
'  const row=document.getElementById("er_"+id);\n' +
'  if(!row) return;\n' +
'  const isOpen=row.style.display!=="none";\n' +
'  document.querySelectorAll(".expand-row").forEach(function(r){r.style.display="none";});\n' +
'  document.querySelectorAll(".data-row").forEach(function(r){r.classList.remove("row-expanded");});\n' +
'  if(isOpen) return;\n' +
'  row.style.display="table-row";\n' +
'  const dataRow=document.querySelector("tr[data-rid=\'"+id+"\']");\n' +
'  if(dataRow) dataRow.classList.add("row-expanded");\n' +
'  await loadComments(id);\n' +
'}\n' +
'\n' +
'async function loadComments(id){\n' +
'  const res=await fetch(API+"/api/worklogs/"+id+"/comments",{headers:authHeaders()});\n' +
'  if(!res.ok) return;\n' +
'  const comments=await res.json();\n' +
'  renderComments(id,comments);\n' +
'}\n' +
'\n' +
'function renderComments(id,comments){\n' +
'  const el=document.getElementById("cl_"+id);\n' +
'  if(!el) return;\n' +
'  const replyBtn="<button class=\'btn-reply-sm\' onclick=\'toggleReplyBox("+id+")\'>\u270F\uFE0F \u56DE\u590D</button>";\n' +
'  if(!comments.length){el.innerHTML="<div class=\'no-comment\'>\u8FD8\u6CA1\u6709\u8BC4\u8BBA\uFF0C\u6765\u7B2C\u4E00\u4E2A\u63D0\u95EE\u5427 &nbsp;"+replyBtn+"</div>";return;}\n' +
'  el.innerHTML=comments.map(function(c,i){\n' +
'    const t=c.created_at?new Date(c.created_at*1000).toLocaleDateString("zh-CN",{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}):"";\n' +
'    const isMe=currentUser&&c.author_id===currentUser.id;\n' +
'    const isAdm=currentUser&&currentUser.email===ADMIN_EMAIL;\n' +
'    const isLast=i===comments.length-1;\n' +
'    return "<div class=\'comment-item\'>"\n' +
'      +"<div class=\'comment-avatar-sm\'>"+(c.author_name?c.author_name[0].toUpperCase():"?")+"</div>"\n' +
'      +"<div class=\'comment-body\'>"\n' +
'      +"<div class=\'comment-meta\'>"\n' +
'      +"<span class=\'comment-name\'>"+(c.author_name||"")+"</span>"\n' +
'      +"<span class=\'comment-time\'>"+t+"</span>"\n' +
'      +((isMe||isAdm)?"<button class=\'btn-del-comment\' onclick=\'delComment("+id+","+c.id+")\'>\u5220\u9664</button>":"")\n' +
'      +(isLast?replyBtn:"")\n' +
'      +"</div>"\n' +
'      +"<div class=\'comment-text\'>"+(c.text||"")+"</div>"\n' +
'      +"</div></div>";\n' +
'  }).join("");\n' +
'}\n' +
'\n' +
'function toggleReplyBox(id){\n' +
'  const box=document.getElementById("cbox_"+id);\n' +
'  if(!box) return;\n' +
'  const isOpen=box.style.display!=="none";\n' +
'  box.style.display=isOpen?"none":"flex";\n' +
'  if(!isOpen) setTimeout(function(){var el=document.getElementById("ci_"+id);if(el)el.focus();},30);\n' +
'}\n' +
'\n' +
'async function submitComment(id){\n' +
'  const inp=document.getElementById("ci_"+id);\n' +
'  const text=inp&&inp.value.trim();\n' +
'  if(!text) return;\n' +
'  inp.value="";\n' +
'  const res=await fetch(API+"/api/worklogs/"+id+"/comments",{method:"POST",headers:authHeaders(),body:JSON.stringify({text:text})});\n' +
'  if(res.ok){\n' +
'    const box=document.getElementById("cbox_"+id);\n' +
'    if(box) box.style.display="none";\n' +
'    await loadComments(id);\n' +
'    commentCounts[id]=(commentCounts[id]||0)+1;\n' +
'    const cc=document.querySelector("tr[data-rid=\'"+id+"\'] .btn-comment");\n' +
'    if(cc) cc.textContent="\uD83D\uDCAC "+commentCounts[id];\n' +
'    await checkNotifications();\n' +
'  }\n' +
'}\n' +
'\n' +
'async function delComment(wid,cid){\n' +
'  if(!confirm("\u5220\u9664\u8FD9\u6761\u8BC4\u8BBA\uFF1F")) return;\n' +
'  const res=await fetch(API+"/api/comments/"+cid,{method:"DELETE",headers:authHeaders()});\n' +
'  if(res.ok) await loadComments(wid);\n' +
'}\n' +
'\n' +
'async function checkNotifications(){\n' +
'  if(!currentUser) return;\n' +
'  const seenRaw=localStorage.getItem("notif_seen_"+currentUser.id)||"{}";\n' +
'  const seen=JSON.parse(seenRaw);\n' +
'  const notifs=[];\n' +
'  for(const r of allRecords){\n' +
'    if(r.author_id!==currentUser.id) continue;\n' +
'    try{\n' +
'      const res=await fetch(API+"/api/worklogs/"+r.id+"/comments",{headers:authHeaders()});\n' +
'      if(!res.ok) continue;\n' +
'      const comments=await res.json();\n' +
'      for(const c of comments){\n' +
'        if(c.author_id===currentUser.id) continue;\n' +
'        const key=r.id+"_"+c.id;\n' +
'        notifs.push({key:key,rid:r.id,comment:c,record:r,isNew:!seen[key]});\n' +
'      }\n' +
'    }catch(e){}\n' +
'  }\n' +
'  const newCount=notifs.filter(function(n){return n.isNew;}).length;\n' +
'  const btn=document.getElementById("notifBtn");\n' +
'  const badge=document.getElementById("notifCount");\n' +
'  if(notifs.length>0){btn.style.display="inline-flex";badge.textContent=newCount;badge.style.display=newCount>0?"inline":"none";}\n' +
'  const list=document.getElementById("notifList");\n' +
'  if(!notifs.length){list.innerHTML="<div class=\'notif-empty\'>\u6682\u65E0\u65B0\u56DE\u590D</div>";return;}\n' +
'  list.innerHTML=notifs.reverse().map(function(n){\n' +
'    const t=n.comment.created_at?new Date(n.comment.created_at*1000).toLocaleDateString("zh-CN",{month:"short",day:"numeric",hour:"2-digit",minute:"2-digit"}):"";\n' +
'    return "<div class=\'notif-item "+(n.isNew?"unread":"")+"\'  onclick=\'goToNotif("+n.rid+")\'>"  \n' +
'      +"<div class=\'notif-who\'><span>"+(n.comment.author_name||"")+"</span> \u56DE\u590D\u4E86\u4F60\u7684\u8BB0\u5F55\u300C"+(n.record.date||"")+"\u300D</div>"\n' +
'      +"<div class=\'notif-time\'>"+t+"</div></div>";\n' +
'  }).join("");\n' +
'  window._notifs=notifs;\n' +
'}\n' +
'\n' +
'function toggleNotif(){\n' +
'  const panel=document.getElementById("notifPanel");\n' +
'  const isOpen=panel.style.display!=="none";\n' +
'  panel.style.display=isOpen?"none":"block";\n' +
'  if(!isOpen){\n' +
'    const seen=JSON.parse(localStorage.getItem("notif_seen_"+(currentUser&&currentUser.id))||"{}");\n' +
'    (window._notifs||[]).forEach(function(n){seen[n.key]=true;});\n' +
'    localStorage.setItem("notif_seen_"+(currentUser&&currentUser.id),JSON.stringify(seen));\n' +
'    document.getElementById("notifCount").style.display="none";\n' +
'    document.querySelectorAll(".notif-item").forEach(function(el){el.classList.remove("unread");});\n' +
'  }\n' +
'}\n' +
'\n' +
'async function goToNotif(rid){\n' +
'  document.getElementById("notifPanel").style.display="none";\n' +
'  await toggleExpand(rid);\n' +
'  const row=document.querySelector("tr[data-rid=\'"+rid+"\']");\n' +
'  if(row) row.scrollIntoView({behavior:"smooth",block:"center"});\n' +
'}\n' +
'\n' +
'document.addEventListener("click",function(e){\n' +
'  const panel=document.getElementById("notifPanel");\n' +
'  const btn=document.getElementById("notifBtn");\n' +
'  if(panel&&!panel.contains(e.target)&&btn&&!btn.contains(e.target)) panel.style.display="none";\n' +
'});\n' +
'\n' +
'// \u7BA1\u7406\u9762\u677F\n' +
'async function showAdminPanel(){\n' +
'  showModal("adminModal");\n' +
'  const res=await fetch("/api/admin/users",{headers:authHeaders()});\n' +
'  const users=await res.json();\n' +
'  var html="";\n' +
'  users.forEach(function(u){\n' +
'    html+="<div style=\'display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #e0e4eb;\'>"\n' +
'      +"<div>"\n' +
'      +"<div style=\'font-size:.84rem;font-weight:600;color:#1a2030;\'>"+u.name+"</div>"\n' +
'      +"<div style=\'font-size:.75rem;color:#8a94a6;\'>"+u.email+"</div>"\n' +
'      +"</div>"\n' +
'      +"<button class=\'btn-logout\' onclick=\'showResetModal("+u.id+",\""+u.name+"\")\'>\\u91CD\\u7F6E\\u5BC6\\u7801</button>"\n' +
'      +"</div>";\n' +
'  });\n' +
'  document.getElementById("adminUserList").innerHTML=html;\n' +
'}\n' +
'function hideAdminPanel(){ hideModal("adminModal"); }\n' +
'\n' +
'function showResetModal(uid,uname){\n' +
'  resetTargetId=uid;\n' +
'  document.getElementById("resetTargetName").textContent="\u4E3A\u300C"+uname+"\u300D\u91CD\u7F6E\u5BC6\u7801";\n' +
'  document.getElementById("reset_new").value="";\n' +
'  document.getElementById("reset_error").textContent="";\n' +
'  showModal("resetModal");\n' +
'}\n' +
'function hideResetModal(){ hideModal("resetModal"); }\n' +
'\n' +
'async function doResetPwd(){\n' +
'  const newP=document.getElementById("reset_new").value;\n' +
'  const errEl=document.getElementById("reset_error");\n' +
'  errEl.textContent="";\n' +
'  if(!newP){errEl.textContent="\u8BF7\u586B\u5199\u65B0\u5BC6\u7801";return;}\n' +
'  if(newP.length<6){errEl.textContent="\u5BC6\u7801\u81F3\u5C116\u4F4D";return;}\n' +
'  const res=await fetch("/api/admin/reset-password",{method:"POST",headers:authHeaders(),body:JSON.stringify({userId:resetTargetId,newPassword:newP})});\n' +
'  const data=await res.json();\n' +
'  if(!res.ok){errEl.textContent=data.error;return;}\n' +
'  hideResetModal(); hideAdminPanel();\n' +
'  showToast("\u5BC6\u7801\u5DF2\u91CD\u7F6E \u2713");\n' +
'}\n' +
'\n' +
'// \u6539\u5BC6\u7801\n' +
'function showChangePwd(){\n' +
'  document.getElementById("pwd_old").value="";\n' +
'  document.getElementById("pwd_new").value="";\n' +
'  document.getElementById("pwd_confirm").value="";\n' +
'  document.getElementById("pwd_error").textContent="";\n' +
'  showModal("pwdModal");\n' +
'}\n' +
'function hideChangePwd(){ hideModal("pwdModal"); }\n' +
'\n' +
'async function doChangePwd(){\n' +
'  const oldP=document.getElementById("pwd_old").value;\n' +
'  const newP=document.getElementById("pwd_new").value;\n' +
'  const cfm=document.getElementById("pwd_confirm").value;\n' +
'  const errEl=document.getElementById("pwd_error");\n' +
'  errEl.textContent="";\n' +
'  if(!oldP||!newP||!cfm){errEl.textContent="\u8BF7\u586B\u5199\u6240\u6709\u5B57\u6BB5";return;}\n' +
'  if(newP!==cfm){errEl.textContent="\u4E24\u6B21\u65B0\u5BC6\u7801\u4E0D\u4E00\u81F4";return;}\n' +
'  if(newP.length<6){errEl.textContent="\u65B0\u5BC6\u7801\u81F3\u5C116\u4F4D";return;}\n' +
'  const res=await fetch("/api/change-password",{method:"POST",headers:authHeaders(),body:JSON.stringify({oldPassword:oldP,newPassword:newP})});\n' +
'  const data=await res.json();\n' +
'  if(!res.ok){errEl.textContent=data.error;return;}\n' +
'  hideChangePwd();\n' +
'  showToast("\u5BC6\u7801\u4FEE\u6539\u6210\u529F \u2713");\n' +
'}\n' +
'\n' +
'function showToast(msg){\n' +
'  const t=document.getElementById("toast");\n' +
'  t.textContent=msg;t.classList.add("show");\n' +
'  clearTimeout(window._tt);window._tt=setTimeout(function(){t.classList.remove("show");},2200);\n' +
'}\n' +
'<\/script>\n' +
'</body>\n' +
'</html>';
}
__name(getHTML, "getHTML");
export {
  index_default as default
};
