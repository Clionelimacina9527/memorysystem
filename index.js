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
  return "<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>个人数字记忆系统</title>\n<link href=\"https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;600&display=swap\" rel=\"stylesheet\">\n<style>\n:root{--white:#fff;--border:#e0e4eb;--text:#1a2030;--muted:#8a94a6;--accent:#2f6be8;--accent-light:#edf2fd;--red:#e84040;--header-bg:#f4f6fa;--row-sel:#ddeeff;--row-h:36px;}\n*{margin:0;padding:0;box-sizing:border-box;}\nbody{background:#f0f3f7;color:var(--text);font-family:'Noto Sans SC',sans-serif;font-size:13px;min-height:100vh;}\n#loadingScreen{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);flex-direction:column;gap:14px;}\n.loading-logo{font-size:1.2rem;font-weight:700;color:var(--accent);}\n.loading-spinner{width:28px;height:28px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;}\n@keyframes spin{to{transform:rotate(360deg);}}\n#authScreen{display:none;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);}\n.auth-card{background:var(--white);border-radius:14px;padding:36px 32px;width:100%;max-width:360px;box-shadow:0 4px 20px rgba(0,0,0,.09);}\n.auth-logo{font-size:1.2rem;font-weight:700;color:var(--accent);text-align:center;margin-bottom:4px;}\n.auth-sub{font-size:.78rem;color:var(--muted);text-align:center;margin-bottom:22px;}\n.auth-tabs{display:flex;background:#f0f3f7;border-radius:7px;padding:3px;margin-bottom:18px;}\n.auth-tab{flex:1;padding:7px;text-align:center;border-radius:5px;cursor:pointer;font-size:.82rem;color:var(--muted);transition:all .15s;}\n.auth-tab.active{background:var(--white);color:var(--text);font-weight:500;box-shadow:0 1px 4px rgba(0,0,0,.07);}\n.auth-form{display:none;flex-direction:column;gap:11px;}\n.auth-form.active{display:flex;}\n.field{display:flex;flex-direction:column;gap:4px;}\n.field label{font-size:.72rem;color:var(--muted);font-weight:500;}\n.field input{border:1px solid var(--border);border-radius:7px;padding:9px 11px;font-size:.86rem;font-family:'Noto Sans SC',sans-serif;outline:none;transition:border-color .15s;}\n.field input:focus{border-color:var(--accent);}\n.auth-error{color:var(--red);font-size:.76rem;text-align:center;min-height:15px;}\n.btn-auth{background:var(--accent);border:none;border-radius:7px;padding:11px;color:white;font-size:.86rem;font-family:'Noto Sans SC',sans-serif;font-weight:500;cursor:pointer;}\n.btn-auth:hover{opacity:.88;}\n#appScreen{display:none;}\n.topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 20px;height:48px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,.04);}\n.topbar-title{font-size:.95rem;font-weight:700;color:var(--text);flex:1;}\n.topbar-user{font-size:.78rem;color:var(--muted);}\n.btn-logout{background:none;border:1px solid var(--border);border-radius:5px;padding:4px 11px;font-size:.75rem;color:var(--muted);cursor:pointer;font-family:'Noto Sans SC',sans-serif;}\n.btn-notif{background:none;border:1px solid var(--border);border-radius:6px;padding:4px 11px;font-size:.78rem;color:var(--text);cursor:pointer;font-family:'Noto Sans SC',sans-serif;display:none;}\n.notif-badge{background:var(--red);color:white;border-radius:10px;padding:1px 6px;font-size:.68rem;font-weight:700;margin-left:3px;}\n.toolbar{padding:9px 20px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--white);border-bottom:1px solid var(--border);}\n.filter-label{font-size:.75rem;color:var(--muted);white-space:nowrap;}\n.filter-select{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;outline:none;width:180px;background:white;cursor:pointer;color:var(--text);}\n.filter-select:focus{border-color:var(--accent);}\n.filter-input{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;outline:none;width:130px;}\n.filter-input:focus{border-color:var(--accent);}\n.btn-add{background:var(--accent);border:none;border-radius:6px;padding:7px 16px;color:white;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;font-weight:500;cursor:pointer;margin-left:auto;}\n.btn-add:hover{opacity:.88;}\n.table-wrap{overflow-x:auto;padding:14px 20px 60px;}\ntable{width:100%;border-collapse:collapse;background:var(--white);border-radius:8px;overflow:hidden;box-shadow:0 1px 5px rgba(0,0,0,.06);min-width:1000px;}\nthead tr{background:var(--header-bg);}\nth{padding:9px 12px;text-align:left;font-size:.73rem;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;}\ntbody tr{border-bottom:1px solid var(--border);height:var(--row-h);background:var(--white);}\ntbody tr:last-child{border-bottom:none;}\n.data-row{cursor:pointer;}\n.data-row:hover{background:var(--accent-light)!important;}\n.data-row.row-expanded{background:var(--accent-light)!important;}\n.expand-row{background:#f7faff!important;}\n.expand-panel{padding:16px 24px 18px!important;border-top:2px solid var(--accent);}\n.expand-fields{display:flex;flex-wrap:wrap;gap:12px 24px;margin-bottom:14px;}\n.ef-item{display:flex;flex-direction:column;gap:3px;min-width:160px;max-width:320px;}\n.ef-label{font-size:.7rem;font-weight:600;color:var(--muted);letter-spacing:.04em;}\n.ef-val{font-size:.84rem;color:var(--text);line-height:1.6;white-space:pre-wrap;}\n.expand-divider{height:1px;background:var(--border);margin-bottom:14px;}\n.td-date{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--accent);font-weight:600;white-space:nowrap;min-width:95px;}\n.td-cell{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--text);min-width:140px;max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}\n.td-sub{padding:0 12px;height:var(--row-h);font-size:.76rem;color:var(--muted);white-space:nowrap;}\n.td-act{padding:0 10px;height:var(--row-h);white-space:nowrap;}\ntd.ed{cursor:cell;}\ntd.active-cell{padding:0!important;background:#fff!important;outline:2px solid var(--accent);outline-offset:-2px;}\n.ghost-input{display:block;width:100%;height:var(--row-h);padding:0 12px;border:none;outline:none;background:transparent;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;color:var(--text);}\n.new-row{background:#f0f7ff!important;}\n.new-row td{border-top:1px solid #aac8f0;border-bottom:1px solid #aac8f0;height:var(--row-h);}\n.nc{padding:0 4px;}\n.nr-inp{display:block;width:100%;height:var(--row-h);border:none;border-bottom:1px solid transparent;padding:0 8px;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;outline:none;background:transparent;color:var(--text);}\n.nr-inp:focus{border-bottom-color:var(--accent);}\n.nr-inp::placeholder{color:#bcc4d0;}\n.btn-sv{background:var(--accent);border:none;border-radius:3px;padding:3px 9px;color:white;font-size:.74rem;cursor:pointer;margin-right:3px;}\n.btn-cx{background:none;border:1px solid var(--border);border-radius:3px;padding:2px 8px;color:var(--muted);font-size:.74rem;cursor:pointer;}\n.btn-del{background:none;border:none;font-size:.74rem;color:var(--red);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.7;}\n.btn-del:hover{opacity:1;}\n.btn-comment{background:none;border:none;font-size:.74rem;color:var(--accent);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.8;margin-right:4px;}\n.comment-list{display:flex;flex-direction:column;gap:10px;margin-bottom:8px;}\n.no-comment{font-size:.78rem;color:var(--muted);padding:6px 0;}\n.comment-item{display:flex;gap:9px;align-items:flex-start;}\n.comment-avatar-sm{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6ea8fe,#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}\n.comment-body{flex:1;}\n.comment-meta{display:flex;align-items:center;gap:8px;margin-bottom:3px;}\n.comment-name{font-size:.78rem;font-weight:600;color:var(--text);}\n.comment-time{font-size:.7rem;color:var(--muted);}\n.btn-del-comment{background:none;border:none;font-size:.7rem;color:var(--red);cursor:pointer;opacity:.6;font-family:'Noto Sans SC',sans-serif;}\n.btn-reply-sm{background:none;border:none;font-size:.72rem;color:var(--accent);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.75;margin-left:4px;}\n.comment-text{font-size:.82rem;color:var(--text);line-height:1.6;}\n.comment-input-row{display:flex;align-items:center;gap:8px;padding-top:10px;border-top:1px solid var(--border);}\n.comment-avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}\n.comment-inp{flex:1;border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:.82rem;font-family:'Noto Sans SC',sans-serif;outline:none;}\n.comment-inp:focus{border-color:var(--accent);}\n.comment-send{background:var(--accent);border:none;border-radius:6px;padding:7px 14px;color:white;font-size:.78rem;cursor:pointer;font-family:'Noto Sans SC',sans-serif;}\n.btn-cancel-comment{background:none;border:1px solid var(--border);border-radius:6px;padding:7px 12px;color:var(--muted);font-size:.78rem;cursor:pointer;font-family:'Noto Sans SC',sans-serif;}\n.notif-panel{position:fixed;top:54px;right:20px;width:320px;background:white;border:1px solid var(--border);border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12);z-index:200;display:none;}\n.notif-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);font-size:.85rem;font-weight:600;}\n.notif-close{background:none;border:none;font-size:1.1rem;color:var(--muted);cursor:pointer;}\n.notif-list{max-height:340px;overflow-y:auto;}\n.notif-item{padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;}\n.notif-item:last-child{border-bottom:none;}\n.notif-item:hover{background:var(--accent-light);}\n.notif-item.unread{background:#fff8f0;}\n.notif-who{font-size:.8rem;font-weight:600;color:var(--text);margin-bottom:3px;}\n.notif-who span{color:var(--accent);}\n.notif-time{font-size:.7rem;color:#bbb;margin-top:3px;}\n.notif-empty{padding:24px 16px;text-align:center;color:var(--muted);font-size:.82rem;}\n.empty-msg{text-align:center;padding:50px;color:var(--muted);font-size:.86rem;}\n.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:300;align-items:center;justify-content:center;}\n.modal-box{background:white;border-radius:14px;padding:28px;width:100%;max-width:360px;box-shadow:0 4px 24px rgba(0,0,0,.15);}\n.modal-title{font-size:.95rem;font-weight:700;color:#1a2030;margin-bottom:18px;}\n.modal-error{color:#e84040;font-size:.76rem;min-height:15px;margin-bottom:10px;text-align:center;}\n.modal-btns{display:flex;gap:8px;}\n.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(14px);background:#1a2030;color:white;padding:8px 20px;border-radius:18px;font-size:.8rem;opacity:0;transition:all .25s;z-index:999;white-space:nowrap;}\n.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}\n</style>\n</head>\n<body>\n<div id=\"loadingScreen\"><div class=\"loading-logo\">🧠 个人数字记忆系统</div><div class=\"loading-spinner\"></div></div>\n<div id=\"authScreen\">\n  <div class=\"auth-card\">\n    <div class=\"auth-logo\">🧠 个人数字记忆系统</div>\n    <div class=\"auth-sub\">团队每日记忆记录系统</div>\n    <div class=\"auth-tabs\">\n      <div class=\"auth-tab active\" onclick=\"switchTab('login')\">登录</div>\n      <div class=\"auth-tab\" onclick=\"switchTab('register')\">注册</div>\n    </div>\n    <div class=\"auth-form active\" id=\"loginForm\">\n      <div class=\"field\"><label>邮箱</label><input type=\"email\" id=\"loginEmail\" placeholder=\"your@email.com\" onkeydown=\"if(event.key==='Enter')doLogin()\"/></div>\n      <div class=\"field\"><label>密码</label><input type=\"password\" id=\"loginPass\" placeholder=\"••••••\" onkeydown=\"if(event.key==='Enter')doLogin()\"/></div>\n      <div class=\"auth-error\" id=\"authError\"></div>\n      <button class=\"btn-auth\" onclick=\"doLogin()\">登录</button>\n    </div>\n    <div class=\"auth-form\" id=\"registerForm\">\n      <div class=\"field\"><label>姓名</label><input type=\"text\" id=\"regName\" placeholder=\"你的姓名\"/></div>\n      <div class=\"field\"><label>邮箱</label><input type=\"email\" id=\"regEmail\" placeholder=\"your@email.com\"/></div>\n      <div class=\"field\"><label>密码（至少6位）</label><input type=\"password\" id=\"regPass\" placeholder=\"••••••\"/></div>\n      <div class=\"field\"><label>邀请码</label><input type=\"text\" id=\"regInvite\" placeholder=\"请输入团队邀请码\"/></div>\n      <div class=\"auth-error\" id=\"regError\"></div>\n      <button class=\"btn-auth\" id=\"regBtn\" onclick=\"doRegister()\">注册</button>\n    </div>\n  </div>\n</div>\n<div id=\"appScreen\">\n  <div class=\"topbar\">\n    <div class=\"topbar-title\">🧠 个人数字记忆系统</div>\n    <div class=\"topbar-user\" id=\"topUser\"></div>\n    <button class=\"btn-notif\" id=\"notifBtn\" onclick=\"toggleNotif()\">🔔 <span class=\"notif-badge\" id=\"notifCount\">0</span></button>\n    <button class=\"btn-logout\" id=\"adminBtn\" onclick=\"showAdminPanel()\" style=\"display:none\">管理</button>\n    <button class=\"btn-logout\" onclick=\"showChangePwd()\">改密码</button>\n    <button class=\"btn-logout\" onclick=\"doLogout()\">退出</button>\n  </div>\n  <div class=\"toolbar\">\n    <span class=\"filter-label\">筛选成员：</span>\n    <select class=\"filter-select\" id=\"filterUser\" onchange=\"renderTable()\"><option value=\"\">全部成员</option></select>\n    <span class=\"filter-label\">日期从：</span>\n    <input class=\"filter-input\" type=\"date\" id=\"filterDateFrom\" onchange=\"renderTable()\"/>\n    <span class=\"filter-label\">到：</span>\n    <input class=\"filter-input\" type=\"date\" id=\"filterDateTo\" onchange=\"renderTable()\"/>\n    <button class=\"btn-add\" onclick=\"addNewRow()\">＋ 新增记录</button>\n  </div>\n  <div class=\"table-wrap\">\n    <table>\n      <thead><tr><th>日期</th><th>今日完成</th><th>明日计划</th><th>遇到问题</th><th>感悟思考</th><th>重要备注</th><th>提交者</th><th>操作</th></tr></thead>\n      <tbody id=\"tableBody\"><tr><td colspan=\"8\" class=\"empty-msg\">加载中…</td></tr></tbody>\n    </table>\n  </div>\n</div>\n<div class=\"notif-panel\" id=\"notifPanel\">\n  <div class=\"notif-header\"><span>新回复通知</span><button class=\"notif-close\" onclick=\"toggleNotif()\">&times;</button></div>\n  <div class=\"notif-list\" id=\"notifList\"></div>\n</div>\n<div class=\"modal-overlay\" id=\"adminModal\">\n  <div class=\"modal-box\" style=\"max-width:420px;max-height:80vh;overflow-y:auto;\">\n    <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;\">\n      <div class=\"modal-title\" style=\"margin-bottom:0\">用户管理</div>\n      <button class=\"btn-logout\" onclick=\"hideAdminPanel()\">关闭</button>\n    </div>\n    <div id=\"adminUserList\"></div>\n  </div>\n</div>\n<div class=\"modal-overlay\" id=\"resetModal\" style=\"z-index:400\">\n  <div class=\"modal-box\">\n    <div class=\"modal-title\">重置密码</div>\n    <div id=\"resetTargetName\" style=\"font-size:.84rem;color:#8a94a6;margin-bottom:12px;\"></div>\n    <div class=\"field\" style=\"margin-bottom:14px;\"><label>新密码</label><input type=\"password\" id=\"reset_new\" placeholder=\"至少6位\"/></div>\n    <div class=\"modal-error\" id=\"reset_error\"></div>\n    <div class=\"modal-btns\">\n      <button class=\"btn-auth\" style=\"flex:1\" onclick=\"doResetPwd()\">确认重置</button>\n      <button class=\"btn-logout\" style=\"flex:1;padding:11px\" onclick=\"hideResetModal()\">取消</button>\n    </div>\n  </div>\n</div>\n<div class=\"modal-overlay\" id=\"pwdModal\">\n  <div class=\"modal-box\">\n    <div class=\"modal-title\">修改密码</div>\n    <div class=\"field\" style=\"margin-bottom:10px;\"><label>旧密码</label><input type=\"password\" id=\"pwd_old\" placeholder=\"输入旧密码\"/></div>\n    <div class=\"field\" style=\"margin-bottom:10px;\"><label>新密码</label><input type=\"password\" id=\"pwd_new\" placeholder=\"至少6位\"/></div>\n    <div class=\"field\" style=\"margin-bottom:14px;\"><label>确认新密码</label><input type=\"password\" id=\"pwd_confirm\" placeholder=\"再输一次\"/></div>\n    <div class=\"modal-error\" id=\"pwd_error\"></div>\n    <div class=\"modal-btns\">\n      <button class=\"btn-auth\" style=\"flex:1\" onclick=\"doChangePwd()\">确认修改</button>\n      <button class=\"btn-logout\" style=\"flex:1;padding:11px\" onclick=\"hideChangePwd()\">取消</button>\n    </div>\n  </div>\n</div>\n<div class=\"toast\" id=\"toast\"></div>\n<script>\nconst API = \"\";\nlet currentUser = null;\nlet allRecords = [];\nlet newRowActive = false;\nlet commentCounts = {};\nlet resetTargetId = null;\nconst ADMIN_EMAIL = \"1065857324@qq.com\";\n\nfunction show(id){ document.getElementById(id).style.display = id===\"authScreen\"?\"flex\":\"block\"; }\nfunction hide(id){ document.getElementById(id).style.display = \"none\"; }\nfunction showModal(id){ document.getElementById(id).style.display = \"flex\"; }\nfunction hideModal(id){ document.getElementById(id).style.display = \"none\"; }\n\nconst saved = localStorage.getItem(\"memory_user\");\nif (saved) {\n  currentUser = JSON.parse(saved);\n  show(\"appScreen\"); hide(\"loadingScreen\");\n  document.getElementById(\"topUser\").textContent = currentUser.name;\n  if(currentUser.email===ADMIN_EMAIL) document.getElementById(\"adminBtn\").style.display=\"inline-block\";\n  loadRecords();\n} else {\n  hide(\"loadingScreen\"); show(\"authScreen\");\n}\n\nfunction switchTab(tab){\n  document.querySelectorAll(\".auth-tab\").forEach((b,i)=>b.classList.toggle(\"active\",(i===0)===(tab===\"login\")));\n  document.getElementById(\"loginForm\").classList.toggle(\"active\",tab===\"login\");\n  document.getElementById(\"registerForm\").classList.toggle(\"active\",tab===\"register\");\n  document.getElementById(\"authError\").textContent=\"\";\n}\n\nasync function doLogin(){\n  const email=document.getElementById(\"loginEmail\").value.trim();\n  const pass=document.getElementById(\"loginPass\").value;\n  document.getElementById(\"authError\").textContent=\"\";\n  if(!email||!pass){document.getElementById(\"authError\").textContent=\"请填写邮箱和密码\";return;}\n  const res=await fetch(\"/api/login\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({email,password:pass})});\n  const data=await res.json();\n  if(!res.ok){document.getElementById(\"authError\").textContent=data.error;return;}\n  localStorage.setItem(\"memory_token\",data.token);\n  localStorage.setItem(\"memory_user\",JSON.stringify(data.user));\n  currentUser=data.user;\n  hide(\"authScreen\"); show(\"appScreen\");\n  document.getElementById(\"topUser\").textContent=currentUser.name;\n  if(currentUser.email===ADMIN_EMAIL) document.getElementById(\"adminBtn\").style.display=\"inline-block\";\n  loadRecords();\n}\n\nasync function doRegister(){\n  const name=document.getElementById(\"regName\").value.trim();\n  const email=document.getElementById(\"regEmail\").value.trim();\n  const pass=document.getElementById(\"regPass\").value;\n  const invite=document.getElementById(\"regInvite\").value.trim();\n  const errEl=document.getElementById(\"regError\");\n  const btn=document.getElementById(\"regBtn\");\n  errEl.textContent=\"\";\n  if(!name||!email||!pass||!invite){errEl.textContent=\"请填写所有字段\";return;}\n  btn.textContent=\"注册中…\";btn.disabled=true;\n  const res=await fetch(\"/api/register\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({name,email,password:pass,inviteCode:invite})});\n  const data=await res.json();\n  if(!res.ok){errEl.textContent=data.error;btn.textContent=\"注册\";btn.disabled=false;return;}\n  localStorage.setItem(\"memory_token\",data.token);\n  localStorage.setItem(\"memory_user\",JSON.stringify(data.user));\n  currentUser=data.user;\n  hide(\"authScreen\"); show(\"appScreen\");\n  document.getElementById(\"topUser\").textContent=currentUser.name;\n  if(currentUser.email===ADMIN_EMAIL) document.getElementById(\"adminBtn\").style.display=\"inline-block\";\n  loadRecords();\n}\n\nfunction doLogout(){\n  localStorage.removeItem(\"memory_token\");\n  localStorage.removeItem(\"memory_user\");\n  currentUser=null; allRecords=[];\n  hide(\"appScreen\"); show(\"authScreen\");\n}\n\nfunction authHeaders(){\n  return {\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer \"+localStorage.getItem(\"memory_token\")};\n}\n\nasync function loadRecords(){\n  const res=await fetch(\"/api/worklogs\",{headers:authHeaders()});\n  if(!res.ok){if(res.status===401)doLogout();return;}\n  allRecords=await res.json();\n  const cRes=await fetch(\"/api/comment-counts\",{headers:authHeaders()});\n  commentCounts=cRes.ok?await cRes.json():{};\n  updateMemberDropdown();\n  renderTable();\n  checkNotifications();\n}\n\nfunction updateMemberDropdown(){\n  const sel=document.getElementById(\"filterUser\");\n  const cur=sel.value;\n  const names=[...new Set(allRecords.map(r=>r.author_name).filter(Boolean))].sort();\n  sel.innerHTML=\"<option value=''>全部成员</option>\"+names.map(n=>\"<option value='\"+n+\"' \"+(n===cur?\"selected\":\"\")+\">\"+n+\"</option>\").join(\"\");\n}\n\nfunction renderTable(){\n  const fu=document.getElementById(\"filterUser\").value;\n  const df=document.getElementById(\"filterDateFrom\").value;\n  const dt=document.getElementById(\"filterDateTo\").value;\n  let list=allRecords;\n  if(fu) list=list.filter(r=>r.author_name===fu);\n  if(df) list=list.filter(r=>r.date>=df);\n  if(dt) list=list.filter(r=>r.date<=dt);\n  const tbody=document.getElementById(\"tableBody\");\n  const isAdmin=currentUser&&currentUser.email===ADMIN_EMAIL;\n  const trunc=(s,n=28)=>s&&s.length>n?s.substring(0,n)+\"…\":(s||\"\");\n  let rows=[];\n  if(newRowActive){\n    const today=new Date().toISOString().split(\"T\")[0];\n    rows.push(\"<tr class='new-row'>\"\n      +\"<td class='nc'><input class='nr-inp' type='date' id='nr_date' value='\"+today+\"'/></td>\"\n      +\"<td class='nc'><input class='nr-inp' type='text' id='nr_done' placeholder='今日完成…'/></td>\"\n      +\"<td class='nc'><input class='nr-inp' type='text' id='nr_plan' placeholder='明日计划…'/></td>\"\n      +\"<td class='nc'><input class='nr-inp' type='text' id='nr_problem' placeholder='遇到问题…'/></td>\"\n      +\"<td class='nc'><input class='nr-inp' type='text' id='nr_thinking' placeholder='感悟思考…'/></td>\"\n      +\"<td class='nc'><input class='nr-inp' type='text' id='nr_important' placeholder='重要备注…'/></td>\"\n      +\"<td class='td-sub'>\"+(currentUser?currentUser.name:\"\")+\"</td>\"\n      +\"<td class='td-act'><button class='btn-sv' onclick='saveNewRow()'>✓</button><button class='btn-cx' onclick='cancelNewRow()'>✕</button></td>\"\n      +\"</tr>\");\n  }\n  if(!list.length){\n    rows.push(\"<tr><td colspan='8' class='empty-msg'>暂无记录</td></tr>\");\n  } else {\n    list.forEach(function(r){\n      const own=currentUser&&r.author_id===currentUser.id;\n      const canEdit=own||isAdmin;\n      const cnt=commentCounts[r.id]||0;\n      const ed=canEdit?\" ed\":\"\";\n      rows.push(\n        \"<tr class='data-row' data-rid='\"+r.id+\"' onclick='toggleExpand(\"+r.id+\")'>\"\n        +\"<td class='td-date\"+ed+\"' data-id='\"+r.id+\"' data-field='date'>\"+(r.date||\"\")+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='done'>\"+trunc(r.done)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='plan'>\"+trunc(r.plan)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='problem'>\"+trunc(r.problem)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='thinking'>\"+trunc(r.thinking)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='important'>\"+trunc(r.important)+\"</td>\"\n        +\"<td class='td-sub'>\"+(r.author_name||\"\")+\"</td>\"\n        +\"<td class='td-act' onclick='event.stopPropagation()'>\"\n        +\"<button class='btn-comment' onclick='toggleExpand(\"+r.id+\")'>💬 \"+cnt+\"</button>\"\n        +(canEdit?\"<button class='btn-del' onclick='delRecord(\"+r.id+\")'>删除</button>\":\"\")\n        +\"</td></tr>\"\n        +\"<tr class='expand-row' id='er_\"+r.id+\"' style='display:none'>\"\n        +\"<td colspan='8' class='expand-panel'>\"\n        +\"<div class='expand-fields'>\"\n        +(r.done?\"<div class='ef-item'><span class='ef-label'>今日完成</span><span class='ef-val'>\"+r.done+\"</span></div>\":\"\")\n        +(r.plan?\"<div class='ef-item'><span class='ef-label'>明日计划</span><span class='ef-val'>\"+r.plan+\"</span></div>\":\"\")\n        +(r.problem?\"<div class='ef-item'><span class='ef-label'>遇到问题</span><span class='ef-val'>\"+r.problem+\"</span></div>\":\"\")\n        +(r.thinking?\"<div class='ef-item'><span class='ef-label'>感悟思考</span><span class='ef-val'>\"+r.thinking+\"</span></div>\":\"\")\n        +(r.important?\"<div class='ef-item'><span class='ef-label'>重要备注</span><span class='ef-val'>\"+r.important+\"</span></div>\":\"\")\n        +\"</div><div class='expand-divider'></div>\"\n        +\"<div class='comment-list' id='cl_\"+r.id+\"'></div>\"\n        +\"<div class='comment-input-row' id='cbox_\"+r.id+\"' style='display:none'>\"\n        +\"<div class='comment-avatar'>\"+(currentUser&&currentUser.name?currentUser.name[0].toUpperCase():\"?\")+\"</div>\"\n        +\"<input class='comment-inp' id='ci_\"+r.id+\"' placeholder='写下你的疑问或回复…' onkeydown='if(event.key==String.fromCharCode(13))submitComment(\"+r.id+\")'/>\"\n        +\"<button class='comment-send' onclick='submitComment(\"+r.id+\")'>发送</button>\"\n        +\"<button class='btn-cancel-comment' onclick='toggleReplyBox(\"+r.id+\")'>取消</button>\"\n        +\"</div></td></tr>\"\n      );\n    });\n  }\n  tbody.innerHTML=rows.join(\"\");\n  document.querySelectorAll(\"td.ed\").forEach(function(td){\n    td.addEventListener(\"click\",function(e){\n      e.stopPropagation();\n      document.querySelectorAll(\".data-row\").forEach(function(r){r.classList.remove(\"row-expanded\");});\n      td.closest(\"tr\").classList.add(\"row-expanded\");\n      startEdit(td);\n    });\n  });\n  if(newRowActive) setTimeout(function(){var el=document.getElementById(\"nr_done\");if(el)el.focus();},30);\n}\n\nfunction startEdit(td){\n  if(td.dataset.editing) return;\n  td.dataset.editing=\"1\";\n  const id=parseInt(td.dataset.id), field=td.dataset.field;\n  const rec=allRecords.find(function(r){return r.id===id;});\n  if(!rec) return;\n  const origVal=rec[field]||\"\", origText=td.textContent;\n  td.classList.add(\"active-cell\");\n  td.innerHTML=\"<input class='ghost-input' type='\"+(field===\"date\"?\"date\":\"text\")+\"' value='\"+origVal+\"'/>\";\n  const inp=td.querySelector(\"input\");\n  inp.focus();\n  if(field!==\"date\"){inp.selectionStart=inp.selectionEnd=inp.value.length;}\n  const allEd=function(){return Array.from(document.querySelectorAll(\"td.ed\"));};\n  const commit=async function(){\n    const newVal=inp.value.trim();\n    delete td.dataset.editing; td.classList.remove(\"active-cell\"); td.textContent=newVal;\n    td.addEventListener(\"click\",function(e){e.stopPropagation();startEdit(td);},{once:true});\n    if(newVal===origVal) return;\n    const body=Object.assign({},rec); body[field]=newVal;\n    const res=await fetch(\"/api/worklogs/\"+id,{method:\"PUT\",headers:authHeaders(),body:JSON.stringify(body)});\n    if(res.ok){rec[field]=newVal;showToast(\"已保存 ✓\");}else{showToast(\"保存失败\");td.textContent=origText;}\n  };\n  inp.addEventListener(\"blur\",commit);\n  inp.addEventListener(\"keydown\",function(e){\n    if(e.key===\"Enter\"){e.preventDefault();inp.blur();}\n    if(e.key===\"Escape\"){inp.removeEventListener(\"blur\",commit);delete td.dataset.editing;td.classList.remove(\"active-cell\");td.textContent=origText;td.addEventListener(\"click\",function(e){e.stopPropagation();startEdit(td);},{once:true});}\n    if(e.key===\"Tab\"){e.preventDefault();const eds=allEd();const idx=eds.indexOf(td);inp.removeEventListener(\"blur\",commit);commit().then(function(){const next=eds[e.shiftKey?idx-1:idx+1];if(next)next.click();});}\n  });\n}\n\nfunction addNewRow(){if(newRowActive){var el=document.getElementById(\"nr_done\");if(el)el.focus();return;}newRowActive=true;renderTable();}\nfunction cancelNewRow(){newRowActive=false;renderTable();}\nasync function saveNewRow(){\n  const date=(document.getElementById(\"nr_date\")||{}).value||\"\";\n  const done=((document.getElementById(\"nr_done\")||{}).value||\"\").trim();\n  const plan=((document.getElementById(\"nr_plan\")||{}).value||\"\").trim();\n  const problem=((document.getElementById(\"nr_problem\")||{}).value||\"\").trim();\n  const thinking=((document.getElementById(\"nr_thinking\")||{}).value||\"\").trim();\n  const important=((document.getElementById(\"nr_important\")||{}).value||\"\").trim();\n  if(!date){showToast(\"请选择日期\");return;}\n  if(!done&&!plan){showToast(\"请至少填写今日完成或明日计划\");return;}\n  const res=await fetch(\"/api/worklogs\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({date,done,plan,problem,thinking,important})});\n  if(res.ok){newRowActive=false;showToast(\"提交成功 ✓\");await loadRecords();}else{showToast(\"提交失败\");}\n}\n\nasync function delRecord(id){\n  if(!confirm(\"确定删除这条记录？\")) return;\n  const res=await fetch(\"/api/worklogs/\"+id,{method:\"DELETE\",headers:authHeaders()});\n  if(res.ok){showToast(\"已删除\");await loadRecords();}else showToast(\"删除失败\");\n}\n\nasync function toggleExpand(id){\n  const row=document.getElementById(\"er_\"+id);\n  if(!row) return;\n  const isOpen=row.style.display!==\"none\";\n  document.querySelectorAll(\".expand-row\").forEach(function(r){r.style.display=\"none\";});\n  document.querySelectorAll(\".data-row\").forEach(function(r){r.classList.remove(\"row-expanded\");});\n  if(isOpen) return;\n  row.style.display=\"table-row\";\n  const dr=document.querySelector(\"tr[data-rid='\"+id+\"']\");\n  if(dr) dr.classList.add(\"row-expanded\");\n  await loadComments(id);\n}\n\nasync function loadComments(id){\n  const res=await fetch(\"/api/worklogs/\"+id+\"/comments\",{headers:authHeaders()});\n  if(!res.ok) return;\n  renderComments(id,await res.json());\n}\n\nfunction renderComments(id,comments){\n  const el=document.getElementById(\"cl_\"+id);\n  if(!el) return;\n  const replyBtn=\"<button class='btn-reply-sm' onclick='toggleReplyBox(\"+id+\")'>✏️ 回复</button>\";\n  if(!comments.length){el.innerHTML=\"<div class='no-comment'>还没有评论，来第一个提问吧 \"+replyBtn+\"</div>\";return;}\n  el.innerHTML=comments.map(function(c,i){\n    const t=c.created_at?new Date(c.created_at*1000).toLocaleDateString(\"zh-CN\",{month:\"short\",day:\"numeric\",hour:\"2-digit\",minute:\"2-digit\"}):\"\";\n    const isMe=currentUser&&c.author_id===currentUser.id;\n    const isAdm=currentUser&&currentUser.email===ADMIN_EMAIL;\n    const isLast=i===comments.length-1;\n    return \"<div class='comment-item'>\"\n      +\"<div class='comment-avatar-sm'>\"+(c.author_name?c.author_name[0].toUpperCase():\"?\")+\"</div>\"\n      +\"<div class='comment-body'>\"\n      +\"<div class='comment-meta'>\"\n      +\"<span class='comment-name'>\"+(c.author_name||\"\")+\"</span>\"\n      +\"<span class='comment-time'>\"+t+\"</span>\"\n      +((isMe||isAdm)?\"<button class='btn-del-comment' onclick='delComment(\"+id+\",\"+c.id+\")'>删除</button>\":\"\")\n      +(isLast?replyBtn:\"\")\n      +\"</div>\"\n      +\"<div class='comment-text'>\"+(c.text||\"\")+\"</div>\"\n      +\"</div></div>\";\n  }).join(\"\");\n}\n\nfunction toggleReplyBox(id){\n  const box=document.getElementById(\"cbox_\"+id);\n  if(!box) return;\n  const isOpen=box.style.display!==\"none\";\n  box.style.display=isOpen?\"none\":\"flex\";\n  if(!isOpen) setTimeout(function(){var el=document.getElementById(\"ci_\"+id);if(el)el.focus();},30);\n}\n\nasync function submitComment(id){\n  const inp=document.getElementById(\"ci_\"+id);\n  const text=inp&&inp.value.trim();\n  if(!text) return;\n  inp.value=\"\";\n  const res=await fetch(\"/api/worklogs/\"+id+\"/comments\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({text:text})});\n  if(res.ok){\n    const box=document.getElementById(\"cbox_\"+id);\n    if(box) box.style.display=\"none\";\n    await loadComments(id);\n    commentCounts[id]=(commentCounts[id]||0)+1;\n    const cc=document.querySelector(\"tr[data-rid='\"+id+\"'] .btn-comment\");\n    if(cc) cc.textContent=\"💬 \"+commentCounts[id];\n    await checkNotifications();\n  }\n}\n\nasync function delComment(wid,cid){\n  if(!confirm(\"删除这条评论？\")) return;\n  const res=await fetch(\"/api/comments/\"+cid,{method:\"DELETE\",headers:authHeaders()});\n  if(res.ok) await loadComments(wid);\n}\n\nasync function checkNotifications(){\n  if(!currentUser) return;\n  const seenRaw=localStorage.getItem(\"notif_seen_\"+currentUser.id)||\"{}\";\n  const seen=JSON.parse(seenRaw);\n  const notifs=[];\n  for(const r of allRecords){\n    if(r.author_id!==currentUser.id) continue;\n    try{\n      const res=await fetch(\"/api/worklogs/\"+r.id+\"/comments\",{headers:authHeaders()});\n      if(!res.ok) continue;\n      const comments=await res.json();\n      for(const c of comments){\n        if(c.author_id===currentUser.id) continue;\n        const key=r.id+\"_\"+c.id;\n        notifs.push({key:key,rid:r.id,comment:c,record:r,isNew:!seen[key]});\n      }\n    }catch(e){}\n  }\n  const newCount=notifs.filter(function(n){return n.isNew;}).length;\n  const btn=document.getElementById(\"notifBtn\");\n  const badge=document.getElementById(\"notifCount\");\n  if(notifs.length>0){btn.style.display=\"inline-flex\";badge.textContent=newCount;badge.style.display=newCount>0?\"inline\":\"none\";}\n  const list=document.getElementById(\"notifList\");\n  if(!notifs.length){list.innerHTML=\"<div class='notif-empty'>暂无新回复</div>\";return;}\n  list.innerHTML=notifs.reverse().map(function(n){\n    const t=n.comment.created_at?new Date(n.comment.created_at*1000).toLocaleDateString(\"zh-CN\",{month:\"short\",day:\"numeric\",hour:\"2-digit\",minute:\"2-digit\"}):\"\";\n    return \"<div class='notif-item \"+(n.isNew?\"unread\":\"\")+\"' onclick='goToNotif(\"+n.rid+\")'>\"\n      +\"<div class='notif-who'><span>\"+(n.comment.author_name||\"\")+\"</span> 回复了你的记录「\"+(n.record.date||\"\")+\"」</div>\"\n      +\"<div class='notif-time'>\"+t+\"</div></div>\";\n  }).join(\"\");\n  window._notifs=notifs;\n}\n\nfunction toggleNotif(){\n  const panel=document.getElementById(\"notifPanel\");\n  const isOpen=panel.style.display!==\"none\";\n  panel.style.display=isOpen?\"none\":\"block\";\n  if(!isOpen){\n    const seen=JSON.parse(localStorage.getItem(\"notif_seen_\"+(currentUser&&currentUser.id))||\"{}\");\n    (window._notifs||[]).forEach(function(n){seen[n.key]=true;});\n    localStorage.setItem(\"notif_seen_\"+(currentUser&&currentUser.id),JSON.stringify(seen));\n    document.getElementById(\"notifCount\").style.display=\"none\";\n    document.querySelectorAll(\".notif-item\").forEach(function(el){el.classList.remove(\"unread\");});\n  }\n}\n\nasync function goToNotif(rid){\n  document.getElementById(\"notifPanel\").style.display=\"none\";\n  await toggleExpand(rid);\n  const row=document.querySelector(\"tr[data-rid='\"+rid+\"']\");\n  if(row) row.scrollIntoView({behavior:\"smooth\",block:\"center\"});\n}\n\ndocument.addEventListener(\"click\",function(e){\n  const panel=document.getElementById(\"notifPanel\");\n  const btn=document.getElementById(\"notifBtn\");\n  if(panel&&!panel.contains(e.target)&&btn&&!btn.contains(e.target)) panel.style.display=\"none\";\n});\n\nasync function showAdminPanel(){\n  showModal(\"adminModal\");\n  const res=await fetch(\"/api/admin/users\",{headers:authHeaders()});\n  const users=await res.json();\n  var rows=[];\n  users.forEach(function(u){\n    rows.push(\"<div style='display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #e0e4eb;'>\"\n      +\"<div><div style='font-size:.84rem;font-weight:600;color:#1a2030;'>\"+u.name+\"</div>\"\n      +\"<div style='font-size:.75rem;color:#8a94a6;'>\"+u.email+\"</div></div>\"\n      +\"<button class='btn-logout' onclick='showResetModal(\"+u.id+\",this.dataset.name)' data-name='\"+u.name+\"'>重置密码</button>\"\n      +\"</div>\");\n  });\n  document.getElementById(\"adminUserList\").innerHTML=rows.join(\"\");\n}\nfunction hideAdminPanel(){ hideModal(\"adminModal\"); }\n\nfunction showResetModal(uid,uname){\n  resetTargetId=uid;\n  document.getElementById(\"resetTargetName\").textContent=\"为「\"+uname+\"」重置密码\";\n  document.getElementById(\"reset_new\").value=\"\";\n  document.getElementById(\"reset_error\").textContent=\"\";\n  showModal(\"resetModal\");\n}\nfunction hideResetModal(){ hideModal(\"resetModal\"); }\n\nasync function doResetPwd(){\n  const newP=document.getElementById(\"reset_new\").value;\n  const errEl=document.getElementById(\"reset_error\");\n  errEl.textContent=\"\";\n  if(!newP){errEl.textContent=\"请填写新密码\";return;}\n  if(newP.length<6){errEl.textContent=\"密码至少6位\";return;}\n  const res=await fetch(\"/api/admin/reset-password\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({userId:resetTargetId,newPassword:newP})});\n  const data=await res.json();\n  if(!res.ok){errEl.textContent=data.error;return;}\n  hideResetModal(); hideAdminPanel();\n  showToast(\"密码已重置 ✓\");\n}\n\nfunction showChangePwd(){\n  document.getElementById(\"pwd_old\").value=\"\";\n  document.getElementById(\"pwd_new\").value=\"\";\n  document.getElementById(\"pwd_confirm\").value=\"\";\n  document.getElementById(\"pwd_error\").textContent=\"\";\n  showModal(\"pwdModal\");\n}\nfunction hideChangePwd(){ hideModal(\"pwdModal\"); }\n\nasync function doChangePwd(){\n  const oldP=document.getElementById(\"pwd_old\").value;\n  const newP=document.getElementById(\"pwd_new\").value;\n  const cfm=document.getElementById(\"pwd_confirm\").value;\n  const errEl=document.getElementById(\"pwd_error\");\n  errEl.textContent=\"\";\n  if(!oldP||!newP||!cfm){errEl.textContent=\"请填写所有字段\";return;}\n  if(newP!==cfm){errEl.textContent=\"两次新密码不一致\";return;}\n  if(newP.length<6){errEl.textContent=\"新密码至少6位\";return;}\n  const res=await fetch(\"/api/change-password\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({oldPassword:oldP,newPassword:newP})});\n  const data=await res.json();\n  if(!res.ok){errEl.textContent=data.error;return;}\n  hideChangePwd();\n  showToast(\"密码修改成功 ✓\");\n}\n\nfunction showToast(msg){\n  const t=document.getElementById(\"toast\");\n  t.textContent=msg;t.classList.add(\"show\");\n  clearTimeout(window._tt);window._tt=setTimeout(function(){t.classList.remove(\"show\");},2200);\n}\n</script>\n</body>\n</html>";
}

__name(getHTML, "getHTML");
export {
  index_default as default
};
