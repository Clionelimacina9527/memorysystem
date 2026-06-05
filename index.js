var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var SITE_URL = "https://memory.mizuflow.net";
async function signJWT(payload, JWT_SECRET) {
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
async function verifyJWT(token, JWT_SECRET) {
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
async function getUser(req, JWT_SECRET) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "");
  if (!token) return null;
  return verifyJWT(token, JWT_SECRET);
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
  await db.prepare(`CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    author_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(author_id) REFERENCES users(id)
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS project_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worklog_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    progress TEXT DEFAULT '',
    author_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    UNIQUE(worklog_id, project_id),
    FOREIGN KEY(worklog_id) REFERENCES worklogs(id) ON DELETE CASCADE,
    FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
    FOREIGN KEY(author_id) REFERENCES users(id)
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    ip TEXT DEFAULT '',
    attempted_at INTEGER DEFAULT (strftime('%s','now'))
  )`).run();
}
__name(initDB, "initDB");
async function setWorklogTag(db, worklogId, tagName, user) {
  await db.prepare("DELETE FROM project_entries WHERE worklog_id=?").bind(worklogId).run();
  const tagNameClean = (tagName || "").trim();
  if (!tagNameClean) return;
  await db.prepare("INSERT OR IGNORE INTO projects(name,author_id) VALUES(?,?)").bind(tagNameClean, user.id).run();
  const tag = await db.prepare("SELECT id FROM projects WHERE name=?").bind(tagNameClean).first();
  if (tag) {
    await db.prepare("INSERT INTO project_entries(worklog_id,project_id,progress,author_id) VALUES(?,?,?,?)").bind(worklogId, tag.id, "", user.id).run();
  }
}
__name(setWorklogTag, "setWorklogTag");
async function hashPassword(password, HASH_SECRET) {
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, "0")).join("");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt + HASH_SECRET), iterations: 100000, hash: "SHA-256" }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2:${salt}:${hash}`;
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, stored, HASH_SECRET, legacySecret) {
  if (stored.startsWith("pbkdf2:")) {
    const parts = stored.split(":");
    const salt = parts[1], hash = parts[2];
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt + HASH_SECRET), iterations: 100000, hash: "SHA-256" }, key, 256);
    const newHash = Array.from(new Uint8Array(bits)).map((b) => b.toString(16).padStart(2, "0")).join("");
    return newHash === hash;
  }
  const sha256hex = async (s) => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  };
  if (await sha256hex(password + HASH_SECRET) === stored) return true;
  if (legacySecret && legacySecret !== HASH_SECRET) return await sha256hex(password + legacySecret) === stored;
  return false;
}
__name(verifyPassword, "verifyPassword");
async function checkLoginRateLimit(db, email) {
  const since = Math.floor(Date.now() / 1000) - 900;
  const r = await db.prepare("SELECT COUNT(*) as cnt FROM login_attempts WHERE email=? AND attempted_at > ?").bind(email, since).first();
  return (r?.cnt || 0) < 5;
}
__name(checkLoginRateLimit, "checkLoginRateLimit");
async function recordLoginFailure(db, email, ip) {
  await db.prepare("INSERT INTO login_attempts(email,ip) VALUES(?,?)").bind(email, ip || "").run();
  await db.prepare("DELETE FROM login_attempts WHERE attempted_at < ?").bind(Math.floor(Date.now() / 1000) - 3600).run();
}
__name(recordLoginFailure, "recordLoginFailure");
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
    const { ADMIN_EMAIL, INVITE_CODE, JWT_SECRET, HASH_SECRET, FEISHU_HOOK } = env;
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
      const hash = await hashPassword(password, HASH_SECRET);
      try {
        const r = await env.DB.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").bind(name, email, hash).run();
        const token = await signJWT({ id: r.meta.last_row_id, name, email }, JWT_SECRET);
        return json({ token, user: { id: r.meta.last_row_id, name, email, isAdmin: email === ADMIN_EMAIL } });
      } catch {
        return json({ error: "\u8BE5\u90AE\u7BB1\u5DF2\u88AB\u6CE8\u518C" }, 400);
      }
    }
    if (path === "/api/login" && method === "POST") {
      const { email, password } = await req.json();
      const ip = req.headers.get("CF-Connecting-IP") || "";
      if (!await checkLoginRateLimit(env.DB, email)) return json({ error: "\u767B\u5F55\u5C1D\u8BD5\u8FC7\u4E8E\u9891\u7E41\uFF0C\u8BF715\u5206\u949F\u540E\u518D\u8BD5" }, 429);
      const user2 = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
      if (!user2 || !await verifyPassword(password, user2.password, HASH_SECRET, JWT_SECRET)) {
        if (user2) await recordLoginFailure(env.DB, email, ip);
        return json({ error: "\u90AE\u7BB1\u6216\u5BC6\u7801\u9519\u8BEF" }, 401);
      }
      if (!user2.password.startsWith("pbkdf2:")) {
        const newHash = await hashPassword(password, HASH_SECRET);
        await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, user2.id).run();
      }
      const token = await signJWT({ id: user2.id, name: user2.name, email: user2.email }, JWT_SECRET);
      return json({ token, user: { id: user2.id, name: user2.name, email: user2.email, isAdmin: user2.email === ADMIN_EMAIL } });
    }
    const user = await getUser(req, JWT_SECRET);
    if (!user && path.startsWith("/api/")) return json({ error: "\u8BF7\u5148\u767B\u5F55" }, 401);
    const isAdmin = user?.email === ADMIN_EMAIL;
    if (path === "/api/worklogs" && method === "GET") {
      const rows = await env.DB.prepare("SELECT w.*, p.id as project_id, p.name as project_name, pe.progress as project_progress, p.id as tag_id, p.name as tag_name, pe.progress as tag_note FROM worklogs w LEFT JOIN project_entries pe ON pe.worklog_id=w.id LEFT JOIN projects p ON p.id=pe.project_id ORDER BY w.date DESC, w.created_at DESC").all();
      return json(rows.results);
    }
    if (path === "/api/worklogs" && method === "POST") {
      const { date, done, plan, problem, thinking, important, projectName, projectProgress, tagName } = await req.json();
      if (!date) return json({ error: "\u8BF7\u9009\u62E9\u65E5\u671F" }, 400);
      const r = await env.DB.prepare(
        "INSERT INTO worklogs(date,done,plan,problem,thinking,important,author_id,author_name) VALUES(?,?,?,?,?,?,?,?)"
      ).bind(date, done || "", plan || "", problem || "", thinking || "", important || "", user.id, user.name).run();
      await setWorklogTag(env.DB, r.meta.last_row_id, tagName || projectName || "", user);
      return json({ id: r.meta.last_row_id });
    }
    if ((path === "/api/projects" || path === "/api/tags") && method === "GET") {
      const rows = await env.DB.prepare("SELECT p.id, p.name, COUNT(pe.id) as entry_count, (SELECT pe2.progress FROM project_entries pe2 JOIN worklogs w2 ON w2.id=pe2.worklog_id WHERE pe2.project_id=p.id ORDER BY w2.date DESC, pe2.created_at DESC LIMIT 1) as latest_progress, (SELECT w2.date FROM project_entries pe2 JOIN worklogs w2 ON w2.id=pe2.worklog_id WHERE pe2.project_id=p.id ORDER BY w2.date DESC, pe2.created_at DESC LIMIT 1) as latest_date FROM projects p LEFT JOIN project_entries pe ON pe.project_id=p.id GROUP BY p.id, p.name ORDER BY latest_date DESC, p.created_at DESC").all();
      return json(rows.results);
    }
    if (path === "/api/tags" && method === "POST") {
      const { name } = await req.json();
      const tagName = (name || "").trim();
      if (!tagName) return json({ error: "\u6807\u7B7E\u540D\u4E0D\u80FD\u4E3A\u7A7A" }, 400);
      try {
        const r = await env.DB.prepare("INSERT INTO projects(name,author_id) VALUES(?,?)").bind(tagName, user.id).run();
        return json({ id: r.meta.last_row_id, name: tagName });
      } catch {
        return json({ error: "\u6807\u7B7E\u5DF2\u5B58\u5728" }, 400);
      }
    }
    const tagMatch = path.match(/^\/api\/tags\/(\d+)$/);
    if (tagMatch) {
      const tid = parseInt(tagMatch[1]);
      if (method === "PUT") {
        const { name } = await req.json();
        const tagName = (name || "").trim();
        if (!tagName) return json({ error: "\u6807\u7B7E\u540D\u4E0D\u80FD\u4E3A\u7A7A" }, 400);
        try {
          await env.DB.prepare("UPDATE projects SET name=? WHERE id=?").bind(tagName, tid).run();
          return json({ ok: true });
        } catch {
          return json({ error: "\u6807\u7B7E\u5DF2\u5B58\u5728" }, 400);
        }
      }
      if (method === "DELETE") {
        await env.DB.prepare("DELETE FROM project_entries WHERE project_id=?").bind(tid).run();
        await env.DB.prepare("DELETE FROM projects WHERE id=?").bind(tid).run();
        return json({ ok: true });
      }
    }
    const projectEntriesMatch = path.match(/^\/api\/(?:projects|tags)\/(\d+)\/entries$/);
    if (projectEntriesMatch && method === "GET") {
      const pid = parseInt(projectEntriesMatch[1]);
      const rows = await env.DB.prepare("SELECT pe.id, pe.progress, w.id as worklog_id, w.date, w.done, w.plan, w.problem, w.thinking, w.important, w.author_name FROM project_entries pe JOIN worklogs w ON w.id=pe.worklog_id WHERE pe.project_id=? ORDER BY w.date DESC, pe.created_at DESC").bind(pid).all();
      return json(rows.results);
    }
    const wlogMatch = path.match(/^\/api\/worklogs\/(\d+)$/);
    if (wlogMatch) {
      const wid = parseInt(wlogMatch[1]);
      const log = await env.DB.prepare("SELECT * FROM worklogs WHERE id=?").bind(wid).first();
      if (!log) return json({ error: "\u8BB0\u5F55\u4E0D\u5B58\u5728" }, 404);
      const canEdit = isAdmin || log.author_id === user.id;
      if (method === "PUT") {
        if (!canEdit) return json({ error: "\u65E0\u6743\u9650" }, 403);
        const { date, done, plan, problem, thinking, important, tagName } = await req.json();
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
        if (tagName !== void 0) {
          await setWorklogTag(env.DB, wid, tagName, user);
        }
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
      const newHash = await hashPassword(newPassword, HASH_SECRET);
      await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, userId).run();
      return json({ ok: true });
    }
    if (path === "/api/change-password" && method === "POST") {
      const { oldPassword, newPassword } = await req.json();
      if (!oldPassword || !newPassword) return json({ error: "\u8BF7\u586B\u5199\u5B8C\u6574" }, 400);
      if (newPassword.length < 6) return json({ error: "\u65B0\u5BC6\u7801\u81F3\u5C116\u4F4D" }, 400);
      const dbUser = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(user.id).first();
      if (!dbUser || !await verifyPassword(oldPassword, dbUser.password, HASH_SECRET, JWT_SECRET)) return json({ error: "\u65E7\u5BC6\u7801\u4E0D\u6B63\u786E" }, 400);
      const newHash = await hashPassword(newPassword, HASH_SECRET);
      await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, user.id).run();
      return json({ ok: true });
    }
    if (path === "/api/my-comment-notifications" && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT c.id, c.worklog_id, c.text, c.author_id, c.author_name, c.created_at, w.date as worklog_date FROM comments c JOIN worklogs w ON w.id=c.worklog_id WHERE w.author_id=? AND c.author_id!=? ORDER BY c.created_at DESC"
      ).bind(user.id, user.id).all();
      return json(rows.results);
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
  return "<!DOCTYPE html>\n<html lang=\"zh\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n<title>个人数字记忆系统</title>\n<link href=\"https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;600&display=swap\" rel=\"stylesheet\">\n<style>\n:root{--white:#fff;--border:#e0e4eb;--text:#1a2030;--muted:#8a94a6;--accent:#2f6be8;--accent-light:#edf2fd;--red:#e84040;--header-bg:#f4f6fa;--row-sel:#ddeeff;--row-h:36px;}\n*{margin:0;padding:0;box-sizing:border-box;}\nbody{background:#f0f3f7;color:var(--text);font-family:'Noto Sans SC',sans-serif;font-size:13px;min-height:100vh;}\n#loadingScreen{display:flex;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);flex-direction:column;gap:14px;}\n.loading-logo{font-size:1.2rem;font-weight:700;color:var(--accent);}\n.loading-spinner{width:28px;height:28px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;}\n@keyframes spin{to{transform:rotate(360deg);}}\n#authScreen{display:none;align-items:center;justify-content:center;min-height:100vh;background:linear-gradient(135deg,#e4ebf8,#f0f3f7);}\n.auth-card{background:var(--white);border-radius:14px;padding:36px 32px;width:100%;max-width:360px;box-shadow:0 4px 20px rgba(0,0,0,.09);}\n.auth-logo{font-size:1.2rem;font-weight:700;color:var(--accent);text-align:center;margin-bottom:4px;}\n.auth-sub{font-size:.78rem;color:var(--muted);text-align:center;margin-bottom:22px;}\n.auth-tabs{display:flex;background:#f0f3f7;border-radius:7px;padding:3px;margin-bottom:18px;}\n.auth-tab{flex:1;padding:7px;text-align:center;border-radius:5px;cursor:pointer;font-size:.82rem;color:var(--muted);transition:all .15s;}\n.auth-tab.active{background:var(--white);color:var(--text);font-weight:500;box-shadow:0 1px 4px rgba(0,0,0,.07);}\n.auth-form{display:none;flex-direction:column;gap:11px;}\n.auth-form.active{display:flex;}\n.field{display:flex;flex-direction:column;gap:4px;}\n.field label{font-size:.72rem;color:var(--muted);font-weight:500;}\n.field input{border:1px solid var(--border);border-radius:7px;padding:9px 11px;font-size:.86rem;font-family:'Noto Sans SC',sans-serif;outline:none;transition:border-color .15s;}\n.field input:focus{border-color:var(--accent);}\n.auth-error{color:var(--red);font-size:.76rem;text-align:center;min-height:15px;}\n.btn-auth{background:var(--accent);border:none;border-radius:7px;padding:11px;color:white;font-size:.86rem;font-family:'Noto Sans SC',sans-serif;font-weight:500;cursor:pointer;}\n.btn-auth:hover{opacity:.88;}\n#appScreen{display:none;}\n.topbar{background:var(--white);border-bottom:1px solid var(--border);padding:0 20px;height:48px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50;box-shadow:0 1px 3px rgba(0,0,0,.04);}\n.topbar-title{font-size:.95rem;font-weight:700;color:var(--text);flex:1;}\n.topbar-user{font-size:.78rem;color:var(--muted);}\n.btn-logout{background:none;border:1px solid var(--border);border-radius:5px;padding:4px 11px;font-size:.75rem;color:var(--muted);cursor:pointer;font-family:'Noto Sans SC',sans-serif;}\n.btn-notif{background:none;border:1px solid var(--border);border-radius:6px;padding:4px 11px;font-size:.78rem;color:var(--text);cursor:pointer;font-family:'Noto Sans SC',sans-serif;display:none;}\n.notif-badge{background:var(--red);color:white;border-radius:10px;padding:1px 6px;font-size:.68rem;font-weight:700;margin-left:3px;}\n.toolbar{padding:9px 20px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;background:var(--white);border-bottom:1px solid var(--border);}\n.filter-label{font-size:.75rem;color:var(--muted);white-space:nowrap;}\n.filter-select{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;outline:none;width:180px;background:white;cursor:pointer;color:var(--text);}\n.filter-select:focus{border-color:var(--accent);}\n.filter-input{border:1px solid var(--border);border-radius:5px;padding:5px 9px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;outline:none;width:130px;}\n.filter-input:focus{border-color:var(--accent);}\n.btn-export,.btn-add{background:var(--accent);border:none;border-radius:6px;padding:7px 16px;color:white;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;font-weight:500;cursor:pointer;}\n.btn-add{margin-left:auto;}\n.btn-export:hover,.btn-add:hover{opacity:.88;}\n.btn-export:disabled{opacity:.5;cursor:not-allowed;}\n.table-wrap{overflow-x:auto;padding:14px 20px 60px;}\ntable{width:100%;border-collapse:collapse;background:var(--white);border-radius:8px;overflow:hidden;box-shadow:0 1px 5px rgba(0,0,0,.06);min-width:1000px;}\nthead tr{background:var(--header-bg);}\nth{padding:9px 12px;text-align:left;font-size:.73rem;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;}\n.th-select,.td-select{width:36px;min-width:36px;padding:0 8px;text-align:center;}\ntbody tr{border-bottom:1px solid var(--border);height:var(--row-h);background:var(--white);}\ntbody tr:last-child{border-bottom:none;}\n.data-row{cursor:pointer;}\n.data-row:hover{background:var(--accent-light)!important;}\n.data-row.row-expanded{background:var(--accent-light)!important;}\n.expand-row{background:#f7faff!important;}\n.expand-panel{padding:16px 24px 18px!important;border-top:2px solid var(--accent);}\n.expand-fields{display:flex;flex-wrap:wrap;gap:12px 24px;margin-bottom:14px;}\n.ef-item{display:flex;flex-direction:column;gap:3px;min-width:160px;max-width:320px;}\n.ef-label{font-size:.7rem;font-weight:600;color:var(--muted);letter-spacing:.04em;}\n.ef-val{font-size:.84rem;color:var(--text);line-height:1.6;white-space:pre-wrap;}\n.ef-editable{cursor:text;}\n.ef-edit-ta{display:block;width:100%;border:none;outline:2px solid var(--accent);outline-offset:-1px;background:white;font-size:.84rem;color:var(--text);font-family:'Noto Sans SC',sans-serif;line-height:1.6;resize:none;padding:0;white-space:pre-wrap;box-sizing:border-box;}\n.expand-divider{height:1px;background:var(--border);margin-bottom:14px;}\n.td-date{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--accent);font-weight:600;white-space:nowrap;min-width:95px;}\n.td-cell{padding:0 12px;height:var(--row-h);font-size:.8rem;color:var(--text);min-width:140px;max-width:200px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;}\n.td-sub{padding:0 12px;height:var(--row-h);font-size:.76rem;color:var(--muted);white-space:nowrap;}\n.td-act{padding:0 10px;height:var(--row-h);white-space:nowrap;}\ntd.ed{cursor:cell;}\ntd.active-cell{padding:0!important;background:#fff!important;outline:2px solid var(--accent);outline-offset:-2px;}\n.ghost-input{display:block;width:100%;height:var(--row-h);padding:0 12px;border:none;outline:none;background:transparent;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;color:var(--text);}\ntextarea.ghost-input{height:80px;resize:none;overflow-y:auto;vertical-align:top;padding:4px 12px;}\n.new-row{background:#f0f7ff!important;}\n.new-row td{border-top:1px solid #aac8f0;border-bottom:1px solid #aac8f0;height:var(--row-h);}\n.nc{padding:0 4px;}\n.nr-inp{display:block;width:100%;height:var(--row-h);border:none;border-bottom:1px solid transparent;padding:0 8px;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;outline:none;background:transparent;color:var(--text);}\n.nr-inp:focus{border-bottom-color:var(--accent);}\ntextarea.nr-inp{height:72px;resize:none;padding:6px 8px;line-height:1.5;vertical-align:top;overflow-y:auto;}\n.nr-inp::placeholder{color:#bcc4d0;}\n.btn-sv{background:var(--accent);border:none;border-radius:3px;padding:3px 9px;color:white;font-size:.74rem;cursor:pointer;margin-right:3px;}\n.btn-cx{background:none;border:1px solid var(--border);border-radius:3px;padding:2px 8px;color:var(--muted);font-size:.74rem;cursor:pointer;}\n.btn-del{background:none;border:none;font-size:.74rem;color:var(--red);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.7;}\n.btn-del:hover{opacity:1;}\n.btn-comment{background:none;border:none;font-size:.74rem;color:var(--accent);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.8;margin-right:4px;}\n.tag-chip{display:inline-flex;align-items:center;max-width:100%;border:1px solid #b9d2ff;background:#eef5ff;color:#2258c8;border-radius:5px;padding:2px 7px;margin-right:6px;font-size:.72rem;font-family:'Noto Sans SC',sans-serif;cursor:pointer;vertical-align:middle;white-space:nowrap;}\n.tag-chip:hover{background:#dfeeff;}\n.nr-stack{display:flex;flex-direction:column;gap:4px;padding:4px 0;}\n.nr-tag-row{display:flex;gap:4px;}\n.nr-tag{height:24px;border:1px solid var(--border);border-radius:4px;padding:0 7px;font-size:.74rem;font-family:'Noto Sans SC',sans-serif;outline:none;background:white;min-width:0;}\n.nr-tag.name{flex:1;}\n.tag-summary{display:inline-flex;align-items:center;gap:8px;border:1px solid #b9d2ff;background:#eef5ff;color:#2258c8;border-radius:6px;padding:6px 10px;margin-bottom:12px;cursor:pointer;font-size:.8rem;}\n.tag-summary:hover{background:#dfeeff;}\n.tag-modal{max-width:520px;max-height:80vh;overflow-y:auto;}\n.tag-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}\n.tag-meta{font-size:.78rem;color:var(--muted);margin-bottom:12px;}\n.tag-timeline{display:flex;flex-direction:column;gap:8px;}\n.tag-entry{display:grid;grid-template-columns:86px 1fr;gap:10px;border-top:1px solid var(--border);padding-top:9px;}\n.tag-date{font-size:.78rem;color:var(--accent);font-weight:600;}\n.tag-title{font-size:.82rem;font-weight:600;color:var(--text);margin-bottom:2px;}\n.tag-note{font-size:.78rem;color:var(--muted);line-height:1.5;white-space:pre-wrap;}\n.tag-manage-row{display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid var(--border);}\n.tag-manage-row input{flex:1;border:1px solid var(--border);border-radius:5px;padding:6px 8px;font-size:.8rem;font-family:'Noto Sans SC',sans-serif;}\n.tag-manage-actions{display:flex;gap:5px;}\n.tag-manage-empty{padding:18px 0;color:var(--muted);font-size:.82rem;text-align:center;}\n.tag-edit-row{display:flex;align-items:center;gap:8px;margin-bottom:12px;}\n.tag-edit-row label{font-size:.74rem;color:var(--muted);font-weight:600;}\n.tag-edit-select{border:1px solid var(--border);border-radius:5px;padding:5px 8px;font-size:.78rem;font-family:'Noto Sans SC',sans-serif;min-width:180px;background:white;color:var(--text);}\n.comment-list{display:flex;flex-direction:column;gap:10px;margin-bottom:8px;}\n.no-comment{font-size:.78rem;color:var(--muted);padding:6px 0;}\n.comment-item{display:flex;gap:9px;align-items:flex-start;}\n.comment-avatar-sm{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,#6ea8fe,#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}\n.comment-body{flex:1;}\n.comment-meta{display:flex;align-items:center;gap:8px;margin-bottom:3px;}\n.comment-name{font-size:.78rem;font-weight:600;color:var(--text);}\n.comment-time{font-size:.7rem;color:var(--muted);}\n.btn-del-comment{background:none;border:none;font-size:.7rem;color:var(--red);cursor:pointer;opacity:.6;font-family:'Noto Sans SC',sans-serif;}\n.btn-reply-sm{background:none;border:none;font-size:.72rem;color:var(--accent);cursor:pointer;font-family:'Noto Sans SC',sans-serif;opacity:.75;margin-left:4px;}\n.comment-text{font-size:.82rem;color:var(--text);line-height:1.6;}\n.comment-input-row{display:flex;align-items:center;gap:8px;padding-top:10px;border-top:1px solid var(--border);}\n.comment-avatar{width:26px;height:26px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#a78bfa);display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:white;flex-shrink:0;}\n.comment-inp{flex:1;border:1px solid var(--border);border-radius:6px;padding:7px 10px;font-size:.82rem;font-family:'Noto Sans SC',sans-serif;outline:none;}\n.comment-inp:focus{border-color:var(--accent);}\n.comment-send{background:var(--accent);border:none;border-radius:6px;padding:7px 14px;color:white;font-size:.78rem;cursor:pointer;font-family:'Noto Sans SC',sans-serif;}\n.btn-cancel-comment{background:none;border:1px solid var(--border);border-radius:6px;padding:7px 12px;color:var(--muted);font-size:.78rem;cursor:pointer;font-family:'Noto Sans SC',sans-serif;}\n.notif-panel{position:fixed;top:54px;right:20px;width:320px;background:white;border:1px solid var(--border);border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.12);z-index:200;display:none;}\n.notif-header{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);font-size:.85rem;font-weight:600;}\n.notif-close{background:none;border:none;font-size:1.1rem;color:var(--muted);cursor:pointer;}\n.notif-list{max-height:340px;overflow-y:auto;}\n.notif-item{padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;}\n.notif-item:last-child{border-bottom:none;}\n.notif-item:hover{background:var(--accent-light);}\n.notif-item.unread{background:#fff8f0;}\n.notif-who{font-size:.8rem;font-weight:600;color:var(--text);margin-bottom:3px;}\n.notif-who span{color:var(--accent);}\n.notif-time{font-size:.7rem;color:#bbb;margin-top:3px;}\n.notif-empty{padding:24px 16px;text-align:center;color:var(--muted);font-size:.82rem;}\n.empty-msg{text-align:center;padding:50px;color:var(--muted);font-size:.86rem;}\n.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:300;align-items:center;justify-content:center;}\n.modal-box{background:white;border-radius:14px;padding:28px;width:100%;max-width:360px;box-shadow:0 4px 24px rgba(0,0,0,.15);}\n.modal-title{font-size:.95rem;font-weight:700;color:#1a2030;margin-bottom:18px;}\n.modal-error{color:#e84040;font-size:.76rem;min-height:15px;margin-bottom:10px;text-align:center;}\n.modal-btns{display:flex;gap:8px;}\n.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(14px);background:#1a2030;color:white;padding:8px 20px;border-radius:18px;font-size:.8rem;opacity:0;transition:all .25s;z-index:999;white-space:nowrap;}\n.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}\n</style>\n</head>\n<body>\n<div id=\"loadingScreen\"><div class=\"loading-logo\">🧠 个人数字记忆系统</div><div class=\"loading-spinner\"></div></div>\n<div id=\"authScreen\">\n  <div class=\"auth-card\">\n    <div class=\"auth-logo\">🧠 个人数字记忆系统</div>\n    <div class=\"auth-sub\">团队每日记忆记录系统</div>\n    <div class=\"auth-tabs\">\n      <div class=\"auth-tab active\" onclick=\"switchTab('login')\">登录</div>\n      <div class=\"auth-tab\" onclick=\"switchTab('register')\">注册</div>\n    </div>\n    <div class=\"auth-form active\" id=\"loginForm\">\n      <div class=\"field\"><label>邮箱</label><input type=\"email\" id=\"loginEmail\" placeholder=\"your@email.com\" onkeydown=\"if(event.key==='Enter')doLogin()\"/></div>\n      <div class=\"field\"><label>密码</label><input type=\"password\" id=\"loginPass\" placeholder=\"••••••\" onkeydown=\"if(event.key==='Enter')doLogin()\"/></div>\n      <div class=\"auth-error\" id=\"authError\"></div>\n      <button class=\"btn-auth\" onclick=\"doLogin()\">登录</button>\n    </div>\n    <div class=\"auth-form\" id=\"registerForm\">\n      <div class=\"field\"><label>姓名</label><input type=\"text\" id=\"regName\" placeholder=\"你的姓名\"/></div>\n      <div class=\"field\"><label>邮箱</label><input type=\"email\" id=\"regEmail\" placeholder=\"your@email.com\"/></div>\n      <div class=\"field\"><label>密码（至少6位）</label><input type=\"password\" id=\"regPass\" placeholder=\"••••••\"/></div>\n      <div class=\"field\"><label>邀请码</label><input type=\"text\" id=\"regInvite\" placeholder=\"请输入团队邀请码\"/></div>\n      <div class=\"auth-error\" id=\"regError\"></div>\n      <button class=\"btn-auth\" id=\"regBtn\" onclick=\"doRegister()\">注册</button>\n    </div>\n  </div>\n</div>\n<div id=\"appScreen\">\n  <div class=\"topbar\">\n    <div class=\"topbar-title\">🧠 个人数字记忆系统</div>\n    <div class=\"topbar-user\" id=\"topUser\"></div>\n    <button class=\"btn-notif\" id=\"notifBtn\" onclick=\"toggleNotif()\">🔔 <span class=\"notif-badge\" id=\"notifCount\">0</span></button>\n    <button class=\"btn-logout\" id=\"adminBtn\" onclick=\"showAdminPanel()\" style=\"display:none\">管理</button>\n    <button class=\"btn-logout\" onclick=\"showChangePwd()\">改密码</button>\n    <button class=\"btn-logout\" onclick=\"doLogout()\">退出</button>\n  </div>\n  <div class=\"toolbar\">\n    <span class=\"filter-label\">筛选成员：</span>\n    <select class=\"filter-select\" id=\"filterUser\" onchange=\"renderTable()\"><option value=\"\">全部成员</option></select>\n    <span class=\"filter-label\">日期从：</span>\n    <input class=\"filter-input\" type=\"date\" id=\"filterDateFrom\" onchange=\"renderTable()\"/>\n    <span class=\"filter-label\">到：</span>\n    <input class=\"filter-input\" type=\"date\" id=\"filterDateTo\" onchange=\"renderTable()\"/>\n    <span class=\"filter-label\">搜索：</span>\n    <input class=\"filter-input\" type=\"text\" id=\"filterKeyword\" placeholder=\"关键词…\" oninput=\"renderTable()\"/>\n    <button class=\"btn-export\" id=\"exportBtn\" onclick=\"exportSelected()\">&#23548;&#20986;</button>\n    <button class=\"btn-export\" onclick=\"showTagManage()\">标签分类</button>\n    <button class=\"btn-add\" onclick=\"addNewRow()\">＋ 新增记录</button>\n  </div>\n  <div class=\"table-wrap\">\n    <table>\n      <thead><tr><th class=\"th-select\"><input type=\"checkbox\" id=\"selectAll\"/></th><th>日期</th><th>今日完成</th><th>明日计划</th><th>遇到问题</th><th>感悟思考</th><th>重要备注</th><th>提交者</th><th>操作</th></tr></thead>\n      <tbody id=\"tableBody\"><tr><td colspan=\"9\" class=\"empty-msg\">加载中…</td></tr></tbody>\n    </table>\n  </div>\n</div>\n<div class=\"notif-panel\" id=\"notifPanel\">\n  <div class=\"notif-header\"><span>新回复通知</span><button class=\"notif-close\" onclick=\"toggleNotif()\">&times;</button></div>\n  <div class=\"notif-list\" id=\"notifList\"></div>\n</div>\n<div class=\"modal-overlay\" id=\"tagModal\">\n  <div class=\"modal-box tag-modal\">\n    <div class=\"tag-head\"><div class=\"modal-title\" id=\"tagTitle\" style=\"margin-bottom:0\">标签时间树</div><button class=\"btn-logout\" onclick=\"hideTagModal()\">关闭</button></div>\n    <div class=\"tag-meta\" id=\"tagMeta\"></div>\n    <div class=\"tag-timeline\" id=\"tagTimeline\"></div>\n  </div>\n</div>\n<div class=\"modal-overlay\" id=\"tagManageModal\">\n  <div class=\"modal-box tag-modal\">\n    <div class=\"tag-head\"><div class=\"modal-title\" style=\"margin-bottom:0\">标签分类</div><button class=\"btn-logout\" onclick=\"hideTagManage()\">关闭</button></div>\n    <div class=\"field\" style=\"margin-bottom:12px;\"><label>标签名</label><div style=\"display:flex;gap:8px;\"><input id=\"newTagName\" placeholder=\"标签名\"/><button class=\"btn-auth\" style=\"padding:8px 14px\" onclick=\"addTag()\">添加</button></div></div>\n    <div id=\"tagManageList\"></div>\n  </div>\n</div>\n<div class=\"modal-overlay\" id=\"adminModal\">\n  <div class=\"modal-box\" style=\"max-width:420px;max-height:80vh;overflow-y:auto;\">\n    <div style=\"display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;\">\n      <div class=\"modal-title\" style=\"margin-bottom:0\">用户管理</div>\n      <button class=\"btn-logout\" onclick=\"hideAdminPanel()\">关闭</button>\n    </div>\n    <div id=\"adminUserList\"></div>\n  </div>\n</div>\n<div class=\"modal-overlay\" id=\"resetModal\" style=\"z-index:400\">\n  <div class=\"modal-box\">\n    <div class=\"modal-title\">重置密码</div>\n    <div id=\"resetTargetName\" style=\"font-size:.84rem;color:#8a94a6;margin-bottom:12px;\"></div>\n    <div class=\"field\" style=\"margin-bottom:14px;\"><label>新密码</label><input type=\"password\" id=\"reset_new\" placeholder=\"至少6位\"/></div>\n    <div class=\"modal-error\" id=\"reset_error\"></div>\n    <div class=\"modal-btns\">\n      <button class=\"btn-auth\" style=\"flex:1\" onclick=\"doResetPwd()\">确认重置</button>\n      <button class=\"btn-logout\" style=\"flex:1;padding:11px\" onclick=\"hideResetModal()\">取消</button>\n    </div>\n  </div>\n</div>\n<div class=\"modal-overlay\" id=\"pwdModal\">\n  <div class=\"modal-box\">\n    <div class=\"modal-title\">修改密码</div>\n    <div class=\"field\" style=\"margin-bottom:10px;\"><label>旧密码</label><input type=\"password\" id=\"pwd_old\" placeholder=\"输入旧密码\"/></div>\n    <div class=\"field\" style=\"margin-bottom:10px;\"><label>新密码</label><input type=\"password\" id=\"pwd_new\" placeholder=\"至少6位\"/></div>\n    <div class=\"field\" style=\"margin-bottom:14px;\"><label>确认新密码</label><input type=\"password\" id=\"pwd_confirm\" placeholder=\"再输一次\"/></div>\n    <div class=\"modal-error\" id=\"pwd_error\"></div>\n    <div class=\"modal-btns\">\n      <button class=\"btn-auth\" style=\"flex:1\" onclick=\"doChangePwd()\">确认修改</button>\n      <button class=\"btn-logout\" style=\"flex:1;padding:11px\" onclick=\"hideChangePwd()\">取消</button>\n    </div>\n  </div>\n</div>\n<div class=\"toast\" id=\"toast\"></div>\n<script>\nconst API = \"\";\nlet currentUser = null;\nlet allRecords = [];\nlet newRowActive = false;\nlet commentCounts = {};\nlet allTags = [];\nlet selectedIds = new Set();\nlet resetTargetId = null;\nvar _esc=document.createElement('div');\nfunction escapeHTML(s){_esc.textContent=(s||'');return _esc.innerHTML;}\nfunction displayText(s){return (s||'').split(String.fromCharCode(10)).map(function(l){return escapeHTML(l);}).join('<br>');}\nfunction firstLine(s){return escapeHTML((s||'').split(String.fromCharCode(10))[0]);}\nfunction _nrTagChange(){var sel=document.getElementById('nr_tag'),inp=document.getElementById('nr_tag_new'),btn=document.getElementById('nr_tag_btn');if(!sel||!inp) return;var isNew=sel.value==='__new__';inp.style.display=isNew?'inline-block':'none';if(btn)btn.style.display=isNew?'inline-block':'none';if(isNew){sel.value='';inp.value='';inp.focus();}}\nasync function _nrTagConfirm(e){if(e&&e.keyCode!==13)return;if(e)e.preventDefault();var inp=document.getElementById('nr_tag_new');var name=(inp&&inp.value||'').trim();if(!name)return;var res=await fetch('/api/tags',{method:'POST',headers:authHeaders(),body:JSON.stringify({name:name})});var data=await res.json();if(!res.ok){showToast(data.error||'创建失败');return;}allTags.push({id:data.id,name:name});updateTagOptions();var sel=document.getElementById('nr_tag');if(sel)sel.value=name;inp.style.display='none';var btn=document.getElementById('nr_tag_btn');if(btn)btn.style.display='none';inp.value='';showToast('标签已创建 ✓');}\nfunction _nrkd(e){if(e.keyCode===13){e.preventDefault();if(e.shiftKey){var t=e.target,s=t.selectionStart;t.value=t.value.slice(0,s)+String.fromCharCode(10)+t.value.slice(t.selectionEnd);t.selectionStart=t.selectionEnd=s+1;}else{saveNewRow();}}}\n\nfunction show(id){ document.getElementById(id).style.display = id===\"authScreen\"?\"flex\":\"block\"; }\nfunction hide(id){ document.getElementById(id).style.display = \"none\"; }\nfunction showModal(id){ document.getElementById(id).style.display = \"flex\"; }\nfunction hideModal(id){ document.getElementById(id).style.display = \"none\"; }\n\nconst saved = localStorage.getItem(\"memory_user\");\nif (saved) {\n  currentUser = JSON.parse(saved);\n  show(\"appScreen\"); hide(\"loadingScreen\");\n  document.getElementById(\"topUser\").textContent = currentUser.name;\n  if(currentUser.isAdmin) document.getElementById(\"adminBtn\").style.display=\"inline-block\";\n  loadRecords();\n} else {\n  hide(\"loadingScreen\"); show(\"authScreen\");\n}\n\nfunction switchTab(tab){\n  document.querySelectorAll(\".auth-tab\").forEach((b,i)=>b.classList.toggle(\"active\",(i===0)===(tab===\"login\")));\n  document.getElementById(\"loginForm\").classList.toggle(\"active\",tab===\"login\");\n  document.getElementById(\"registerForm\").classList.toggle(\"active\",tab===\"register\");\n  document.getElementById(\"authError\").textContent=\"\";\n}\n\nasync function doLogin(){\n  const email=document.getElementById(\"loginEmail\").value.trim();\n  const pass=document.getElementById(\"loginPass\").value;\n  document.getElementById(\"authError\").textContent=\"\";\n  if(!email||!pass){document.getElementById(\"authError\").textContent=\"请填写邮箱和密码\";return;}\n  const res=await fetch(\"/api/login\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({email,password:pass})});\n  const data=await res.json();\n  if(!res.ok){document.getElementById(\"authError\").textContent=data.error;return;}\n  localStorage.setItem(\"memory_token\",data.token);\n  localStorage.setItem(\"memory_user\",JSON.stringify(data.user));\n  currentUser=data.user;\n  hide(\"authScreen\"); show(\"appScreen\");\n  document.getElementById(\"topUser\").textContent=currentUser.name;\n  if(currentUser.isAdmin) document.getElementById(\"adminBtn\").style.display=\"inline-block\";\n  loadRecords();\n}\n\nasync function doRegister(){\n  const name=document.getElementById(\"regName\").value.trim();\n  const email=document.getElementById(\"regEmail\").value.trim();\n  const pass=document.getElementById(\"regPass\").value;\n  const invite=document.getElementById(\"regInvite\").value.trim();\n  const errEl=document.getElementById(\"regError\");\n  const btn=document.getElementById(\"regBtn\");\n  errEl.textContent=\"\";\n  if(!name||!email||!pass||!invite){errEl.textContent=\"请填写所有字段\";return;}\n  btn.textContent=\"注册中…\";btn.disabled=true;\n  const res=await fetch(\"/api/register\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({name,email,password:pass,inviteCode:invite})});\n  const data=await res.json();\n  if(!res.ok){errEl.textContent=data.error;btn.textContent=\"注册\";btn.disabled=false;return;}\n  localStorage.setItem(\"memory_token\",data.token);\n  localStorage.setItem(\"memory_user\",JSON.stringify(data.user));\n  currentUser=data.user;\n  hide(\"authScreen\"); show(\"appScreen\");\n  document.getElementById(\"topUser\").textContent=currentUser.name;\n  if(currentUser.isAdmin) document.getElementById(\"adminBtn\").style.display=\"inline-block\";\n  loadRecords();\n}\n\nfunction doLogout(){\n  localStorage.removeItem(\"memory_token\");\n  localStorage.removeItem(\"memory_user\");\n  currentUser=null; allRecords=[]; selectedIds.clear();\n  hide(\"appScreen\"); show(\"authScreen\");\n}\n\nfunction authHeaders(){\n  return {\"Content-Type\":\"application/json\",\"Authorization\":\"Bearer \"+localStorage.getItem(\"memory_token\")};\n}\n\nasync function loadRecords(){\n  const res=await fetch(\"/api/worklogs\",{headers:authHeaders()});\n  if(!res.ok){if(res.status===401)doLogout();return;}\n  allRecords=await res.json();\n  selectedIds = new Set(Array.from(selectedIds).filter(function(id){return allRecords.some(function(r){return r.id===id;});}));\n  const cRes=await fetch(\"/api/comment-counts\",{headers:authHeaders()});\n  commentCounts=cRes.ok?await cRes.json():{};\n  await loadTags();\n  updateMemberDropdown();\n  renderTable();\n  checkNotifications();\n}\n\nasync function loadTags(){\n  const res=await fetch(\"/api/tags\",{headers:authHeaders()});\n  allTags=res.ok?await res.json():[];\n  updateTagOptions();\n}\n\nfunction parseTagFromText(text){\n  return null;\n}\n\nfunction getRecordTag(r){\n  if(r.tag_name) return {id:r.tag_id,name:r.tag_name,note:r.tag_note||\"\"};\n  return null;\n}\n\nfunction displayDoneText(r){\n  return r.done;\n}\n\nfunction tagOptionsHtml(selected,allowNew){\n  return \"<option value=''>不添加标签</option>\"+(allTags||[]).map(function(t){return \"<option value='\"+t.name+\"' \"+(t.name===selected?\"selected\":\"\")+\">\"+t.name+\"</option>\";}).join(\"\")+(allowNew?\"<option value='__new__'>＋ 新建标签…</option>\":\"\");\n}\n\nfunction updateTagOptions(){\n  const el=document.getElementById(\"nr_tag\");\n  if(el) el.innerHTML=tagOptionsHtml(el.value,true);\n  document.querySelectorAll(\".record-tag-select\").forEach(function(sel){\n    sel.innerHTML=tagOptionsHtml(sel.dataset.current||\"\");\n  });\n}\n\nfunction tagBadge(r){\n  const p=getRecordTag(r);\n  if(!p||!p.name) return \"\";\n  return \"<button class='tag-chip' data-pid='\"+(p.id||\"\")+\"' data-project='\"+encodeURIComponent(p.name)+\"'>\"+escapeHTML(p.name)+\"</button>\";\n}\n\nfunction startExpandEdit(el){\n  if(el.dataset.editing) return;\n  el.dataset.editing='1';\n  var wid=parseInt(el.dataset.wid),field=el.dataset.field;\n  var rec=allRecords.find(function(r){return r.id===wid;});\n  if(!rec) return;\n  var origVal=rec[field]||'';\n  var efItem=el.closest?el.closest('.ef-item'):el.parentElement;\n  var lockW=efItem?efItem.offsetWidth:0;\n  if(efItem&&lockW) efItem.style.width=lockW+'px';\n  var ta=document.createElement('textarea');\n  ta.className='ef-edit-ta';\n  ta.value=origVal;\n  el.innerHTML='';\n  el.appendChild(ta);\n  ta.style.height='1px';\n  ta.style.height=Math.max(ta.scrollHeight,28)+'px';\n  ta.focus();\n  ta.selectionStart=ta.selectionEnd=ta.value.length;\n  var saved=false;\n  var unlock=function(){if(efItem) efItem.style.width='';};\n  var commit=function(){\n    if(saved) return; saved=true;\n    var newVal=ta.value;\n    delete el.dataset.editing;\n    unlock();\n    if(newVal===origVal){el.innerHTML=displayText(origVal);return;}\n    fetch('/api/worklogs/'+wid,{method:'PUT',headers:authHeaders(),body:JSON.stringify(Object.assign({},rec,{[field]:newVal}))})\n      .then(function(res){\n        if(res.ok){rec[field]=newVal;showToast('已保存 ✓');}else{showToast('保存失败');}\n        el.innerHTML=displayText(rec[field]||'');\n      });\n  };\n  ta.addEventListener('blur',commit);\n  ta.addEventListener('keydown',function(e){\n    if(e.keyCode===13&&!e.shiftKey){e.preventDefault();ta.blur();}\n    if(e.keyCode===13&&e.shiftKey){e.preventDefault();var s=ta.selectionStart;ta.value=ta.value.slice(0,s)+String.fromCharCode(10)+ta.value.slice(ta.selectionEnd);ta.selectionStart=ta.selectionEnd=s+1;}\n    if(e.key==='Escape'){saved=true;delete el.dataset.editing;unlock();el.innerHTML=displayText(origVal);}\n  });\n}\nfunction bindTagChips(){\n  document.querySelectorAll(\".tag-chip\").forEach(function(btn){\n    btn.onclick=function(e){\n      e.stopPropagation();\n      const name=decodeURIComponent(btn.dataset.project||\"\");\n      showTagByName(name);\n    };\n  });\n}\n\nfunction updateMemberDropdown(){\n  const sel=document.getElementById(\"filterUser\");\n  const cur=sel.value;\n  const names=[...new Set(allRecords.map(r=>r.author_name).filter(Boolean))].sort();\n  sel.innerHTML=\"<option value=''>全部成员</option>\"+names.map(n=>\"<option value='\"+n+\"' \"+(n===cur?\"selected\":\"\")+\">\"+n+\"</option>\").join(\"\");\n}\n\nfunction getFilteredRecords(){\n  const fu=document.getElementById(\"filterUser\").value;\n  const df=document.getElementById(\"filterDateFrom\").value;\n  const dt=document.getElementById(\"filterDateTo\").value;\n  const kwEl=document.getElementById(\"filterKeyword\");\n  const kw=kwEl?(kwEl.value||'').trim().toLowerCase():'';\n  let list=allRecords;\n  if(fu) list=list.filter(r=>r.author_name===fu);\n  if(df) list=list.filter(r=>r.date>=df);\n  if(dt) list=list.filter(r=>r.date<=dt);\n  if(kw) list=list.filter(r=>\n    (r.done||'').toLowerCase().includes(kw)||\n    (r.plan||'').toLowerCase().includes(kw)||\n    (r.problem||'').toLowerCase().includes(kw)||\n    (r.thinking||'').toLowerCase().includes(kw)||\n    (r.important||'').toLowerCase().includes(kw)||\n    (r.author_name||'').toLowerCase().includes(kw)||\n    (r.tag_name||'').toLowerCase().includes(kw)||\n    (r.date||'').includes(kw)\n  );\n  return list;\n}\n\nfunction updateExportButton(){\n  const btn=document.getElementById(\"exportBtn\");\n  if(!btn) return;\n  const selectedCount=getFilteredRecords().filter(function(r){return selectedIds.has(r.id);}).length;\n  btn.disabled=selectedCount===0;\n}\n\nfunction syncSelectAllCheckbox(){\n  const allBox=document.getElementById(\"selectAll\");\n  if(!allBox) return;\n  const list=getFilteredRecords();\n  const selectedCount=list.filter(function(r){return selectedIds.has(r.id);}).length;\n  allBox.checked=list.length>0&&selectedCount===list.length;\n  allBox.indeterminate=selectedCount>0&&selectedCount<list.length;\n}\n\nfunction toggleRowSelect(id,checked){\n  if(checked) selectedIds.add(id);\n  else selectedIds.delete(id);\n  syncSelectAllCheckbox();\n  updateExportButton();\n}\n\nfunction toggleSelectAll(checked){\n  getFilteredRecords().forEach(function(r){\n    if(checked) selectedIds.add(r.id);\n    else selectedIds.delete(r.id);\n  });\n  renderTable();\n}\n\nfunction escapeCSV(value){\n  const v=value==null?\"\":String(value);\n  return '\"'+v.replace(/\"/g,'\"\"')+'\"';\n}\n\nfunction exportSelected(){\n  const rows=getFilteredRecords().filter(function(r){return selectedIds.has(r.id);});\n  if(!rows.length){showToast(\"Please select records first\");return;}\n  const header=[\"Date\",\"Done\",\"Tag\",\"Plan\",\"Problem\",\"Thinking\",\"Important\",\"Author\"];\n  const lines=[header.map(escapeCSV).join(\",\")];\n  rows.forEach(function(r){\n    const p=getRecordTag(r)||{};\n    lines.push([r.date,r.done,p.name||\"\",r.plan,r.problem,r.thinking,r.important,r.author_name].map(escapeCSV).join(\",\"));\n  });\n  const blob=new Blob([\"\\uFEFF\"+lines.join(\"\\r\\n\")],{type:\"text/csv;charset=utf-8;\"});\n  const link=document.createElement(\"a\");\n  const today=new Date().toISOString().slice(0,10);\n  link.href=URL.createObjectURL(blob);\n  link.download=\"worklogs-\"+today+\".csv\";\n  document.body.appendChild(link);\n  link.click();\n  document.body.removeChild(link);\n  URL.revokeObjectURL(link.href);\n}\n\nfunction renderTable(){\n  const fu=document.getElementById(\"filterUser\").value;\n  const df=document.getElementById(\"filterDateFrom\").value;\n  const dt=document.getElementById(\"filterDateTo\").value;\n  let list=getFilteredRecords();\n  const tbody=document.getElementById(\"tableBody\");\n  const isAdmin=currentUser&&currentUser.isAdmin;\n  const trunc=(s,n=28)=>escapeHTML(s&&s.length>n?s.substring(0,n)+\"…\":(s||\"\"));\n  let rows=[];\n  if(newRowActive){\n    const today=new Date().toISOString().split(\"T\")[0];\n    rows.push(\"<tr class='new-row'>\"\n      +\"<td class='td-select'></td>\"\n      +\"<td class='nc'><input class='nr-inp' type='date' id='nr_date' value='\"+today+\"'/></td>\"\n      +\"<td class='nc'><div class='nr-stack'><textarea class='nr-inp' id='nr_done' placeholder='今日完成...' onkeydown='_nrkd(event)'></textarea><div class='nr-tag-row'><select class='nr-tag name' id='nr_tag' onchange='_nrTagChange()'><option value=''>不添加标签</option></select><input class='nr-tag' id='nr_tag_new' placeholder='新标签名…' style='display:none;flex:1' onkeydown='_nrTagConfirm(event)'/><button class='btn-sv' id='nr_tag_btn' onclick='_nrTagConfirm(null)' style='display:none;padding:3px 7px'>✓</button></div></div></td>\"\n      +\"<td class='nc'><textarea class='nr-inp' id='nr_plan' placeholder='明日计划…' onkeydown='_nrkd(event)'></textarea></td>\"\n      +\"<td class='nc'><textarea class='nr-inp' id='nr_problem' placeholder='遇到问题…' onkeydown='_nrkd(event)'></textarea></td>\"\n      +\"<td class='nc'><textarea class='nr-inp' id='nr_thinking' placeholder='感悟思考…' onkeydown='_nrkd(event)'></textarea></td>\"\n      +\"<td class='nc'><textarea class='nr-inp' id='nr_important' placeholder='重要备注…' onkeydown='_nrkd(event)'></textarea></td>\"\n      +\"<td class='td-sub'>\"+(currentUser?currentUser.name:\"\")+\"</td>\"\n      +\"<td class='td-act'><button class='btn-sv' onclick='saveNewRow()'>✓</button><button class='btn-cx' onclick='cancelNewRow()'>✕</button></td>\"\n      +\"</tr>\");\n  }\n  if(!list.length){\n    rows.push(\"<tr><td colspan='9' class='empty-msg'>暂无记录</td></tr>\");\n  } else {\n    list.forEach(function(r){\n      const own=currentUser&&r.author_id===currentUser.id;\n      const canEdit=own||isAdmin;\n      const cnt=commentCounts[r.id]||0;\n      const ed=canEdit?\" ed\":\"\";\n      rows.push(\n        \"<tr class='data-row' data-rid='\"+r.id+\"' onclick='toggleExpand(\"+r.id+\")'>\"\n        +\"<td class='td-select' onclick='event.stopPropagation()'><input class='row-select' type='checkbox' data-id='\"+r.id+\"' \"+(selectedIds.has(r.id)?\"checked\":\"\")+\"/></td>\"\n        +\"<td class='td-date\"+ed+\"' data-id='\"+r.id+\"' data-field='date'>\"+escapeHTML(r.date)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='done'>\"+tagBadge(r)+firstLine(displayDoneText(r))+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='plan'>\"+trunc(r.plan)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='problem'>\"+trunc(r.problem)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='thinking'>\"+trunc(r.thinking)+\"</td>\"\n        +\"<td class='td-cell\"+ed+\"' data-id='\"+r.id+\"' data-field='important'>\"+trunc(r.important)+\"</td>\"\n        +\"<td class='td-sub'>\"+escapeHTML(r.author_name)+\"</td>\"\n        +\"<td class='td-act' onclick='event.stopPropagation()'>\"\n        +\"<button class='btn-comment' onclick='toggleExpand(\"+r.id+\")'>💬 \"+cnt+\"</button>\"\n        +(canEdit?\"<button class='btn-del' onclick='delRecord(\"+r.id+\")'>删除</button>\":\"\")\n        +\"</td></tr>\"\n        +\"<tr class='expand-row' id='er_\"+r.id+\"' style='display:none'>\"\n        +\"<td colspan='9' class='expand-panel'>\"\n+\"<div class='tag-edit-row' onclick='event.stopPropagation()'><label>标签</label><select class='tag-edit-select record-tag-select' id='tag_sel_\"+r.id+\"' data-current='\"+((getRecordTag(r)||{}).name||\"\")+\"'></select><button class='btn-sv' onclick='saveRecordTag(\"+r.id+\")'>保存</button>\"+(getRecordTag(r)?\"<button class='tag-chip' data-pid='\"+(getRecordTag(r).id||\"\")+\"' data-project='\"+encodeURIComponent(getRecordTag(r).name)+\"'>查看时间树</button>\":\"\")+\"</div>\"\n+\"<div class='expand-fields'>\"\n        +(r.done?\"<div class='ef-item'><span class='ef-label'>今日完成</span><span class='ef-val\"+(canEdit?\" ef-editable' data-wid='\"+r.id+\"' data-field='done\":\"\")+\"'>\"+displayText(r.done)+\"</span></div>\":\"\")\n        +(r.plan?\"<div class='ef-item'><span class='ef-label'>明日计划</span><span class='ef-val\"+(canEdit?\" ef-editable' data-wid='\"+r.id+\"' data-field='plan\":\"\")+\"'>\"+displayText(r.plan)+\"</span></div>\":\"\")\n        +(r.problem?\"<div class='ef-item'><span class='ef-label'>遇到问题</span><span class='ef-val\"+(canEdit?\" ef-editable' data-wid='\"+r.id+\"' data-field='problem\":\"\")+\"'>\"+displayText(r.problem)+\"</span></div>\":\"\")\n        +(r.thinking?\"<div class='ef-item'><span class='ef-label'>感悟思考</span><span class='ef-val\"+(canEdit?\" ef-editable' data-wid='\"+r.id+\"' data-field='thinking\":\"\")+\"'>\"+displayText(r.thinking)+\"</span></div>\":\"\")\n        +(r.important?\"<div class='ef-item'><span class='ef-label'>重要备注</span><span class='ef-val\"+(canEdit?\" ef-editable' data-wid='\"+r.id+\"' data-field='important\":\"\")+\"'>\"+displayText(r.important)+\"</span></div>\":\"\")\n        +\"</div><div class='expand-divider'></div>\"\n        +\"<div class='comment-list' id='cl_\"+r.id+\"'></div>\"\n        +\"<div class='comment-input-row' id='cbox_\"+r.id+\"' style='display:none'>\"\n        +\"<div class='comment-avatar'>\"+(currentUser&&currentUser.name?currentUser.name[0].toUpperCase():\"?\")+\"</div>\"\n        +\"<input class='comment-inp' id='ci_\"+r.id+\"' placeholder='写下你的疑问或回复…' onkeydown='if(event.key==String.fromCharCode(13))submitComment(\"+r.id+\")'/>\"\n        +\"<button class='comment-send' onclick='submitComment(\"+r.id+\")'>发送</button>\"\n        +\"<button class='btn-cancel-comment' onclick='toggleReplyBox(\"+r.id+\")'>取消</button>\"\n        +\"</div></td></tr>\"\n      );\n    });\n  }\n  tbody.innerHTML=rows.join(\"\");\n  updateTagOptions();\n  document.querySelectorAll(\"td.ed\").forEach(function(td){\n    td.addEventListener(\"click\",function(e){\n      e.stopPropagation();\n      document.querySelectorAll(\".data-row\").forEach(function(r){r.classList.remove(\"row-expanded\");});\n      td.closest(\"tr\").classList.add(\"row-expanded\");\n      startEdit(td);\n    });\n  });\n  const allBox=document.getElementById(\"selectAll\");\n  if(allBox){\n    allBox.onchange=function(){ toggleSelectAll(allBox.checked); };\n  }\n  document.querySelectorAll(\".row-select\").forEach(function(box){\n    box.onchange=function(e){\n      e.stopPropagation();\n      toggleRowSelect(parseInt(box.dataset.id), box.checked);\n    };\n    box.onclick=function(e){ e.stopPropagation(); };\n  });\n  bindTagChips();\n  document.querySelectorAll('.ef-editable').forEach(function(el){el.addEventListener('click',function(e){e.stopPropagation();startExpandEdit(el);});});\n  syncSelectAllCheckbox();\n  updateExportButton();\n  if(newRowActive) setTimeout(function(){var el=document.getElementById(\"nr_done\");if(el)el.focus();},30);\n}\n\nfunction startEdit(td){\n  if(td.dataset.editing) return;\n  td.dataset.editing=\"1\";\n  const id=parseInt(td.dataset.id), field=td.dataset.field;\n  const rec=allRecords.find(function(r){return r.id===id;});\n  if(!rec) return;\n  const origVal=rec[field]||\"\", origText=td.textContent;\n  td.classList.add(\"active-cell\");\n  if(field===\"date\"){td.innerHTML=\"<input class='ghost-input' type='date' value='\"+origVal+\"'/>\";} else {td.innerHTML=\"<textarea class='ghost-input'></textarea>\";}\n  const inp=td.querySelector(\"input,textarea\");\n  if(field!==\"date\"){inp.value=origVal;}\n  inp.focus();\n  if(field!==\"date\"){inp.selectionStart=inp.selectionEnd=(inp.value||'').length;}\n  const allEd=function(){return Array.from(document.querySelectorAll(\"td.ed\"));};\n  const commit=async function(){\n    const newVal=inp.value.trim();\n    delete td.dataset.editing; td.classList.remove(\"active-cell\"); td.textContent=newVal;\n    td.addEventListener(\"click\",function(e){e.stopPropagation();startEdit(td);},{once:true});\n    if(newVal===origVal) return;\n    const body=Object.assign({},rec); body[field]=newVal;\n    const res=await fetch(\"/api/worklogs/\"+id,{method:\"PUT\",headers:authHeaders(),body:JSON.stringify(body)});\n    if(res.ok){rec[field]=newVal;showToast(\"已保存 ✓\");}else{showToast(\"保存失败\");td.textContent=origText;}\n  };\n  inp.addEventListener(\"blur\",commit);\n  inp.addEventListener(\"keydown\",function(e){\n    if(e.key===\"Enter\"&&!e.shiftKey){e.preventDefault();inp.blur();}\n    if(e.key===\"Enter\"&&e.shiftKey&&inp.tagName===\"TEXTAREA\"){e.preventDefault();var s2=inp.selectionStart;inp.value=inp.value.slice(0,s2)+String.fromCharCode(10)+inp.value.slice(inp.selectionEnd);inp.selectionStart=inp.selectionEnd=s2+1;}\n    if(e.key===\"Escape\"){inp.removeEventListener(\"blur\",commit);delete td.dataset.editing;td.classList.remove(\"active-cell\");td.textContent=origText;td.addEventListener(\"click\",function(e){e.stopPropagation();startEdit(td);},{once:true});}\n    if(e.key===\"Tab\"){e.preventDefault();const eds=allEd();const idx=eds.indexOf(td);inp.removeEventListener(\"blur\",commit);commit().then(function(){const next=eds[e.shiftKey?idx-1:idx+1];if(next)next.click();});}\n  });\n}\n\nasync function saveRecordTag(id){\n  const sel=document.getElementById(\"tag_sel_\"+id);\n  const rec=allRecords.find(function(r){return r.id===id;});\n  if(!sel||!rec) return;\n  const body=Object.assign({},rec,{tagName:sel.value||\"\"});\n  const res=await fetch(\"/api/worklogs/\"+id,{method:\"PUT\",headers:authHeaders(),body:JSON.stringify(body)});\n  if(res.ok){showToast(\"标签已保存 ?\");await loadRecords();await toggleExpand(id);}else{showToast(\"标签保存失败\");}\n}\n\nfunction addNewRow(){if(newRowActive){var el=document.getElementById(\"nr_done\");if(el)el.focus();return;}newRowActive=true;renderTable();}\nfunction cancelNewRow(){newRowActive=false;renderTable();}\nasync function saveNewRow(){\n  const date=(document.getElementById(\"nr_date\")||{}).value||\"\";\n  const done=((document.getElementById(\"nr_done\")||{}).value||\"\").trim();\n  const plan=((document.getElementById(\"nr_plan\")||{}).value||\"\").trim();\n  const problem=((document.getElementById(\"nr_problem\")||{}).value||\"\").trim();\n  const thinking=((document.getElementById(\"nr_thinking\")||{}).value||\"\").trim();\n  const important=((document.getElementById(\"nr_important\")||{}).value||\"\").trim();\n  const tagName=((document.getElementById(\"nr_tag\")||{}).value||\"\").trim();\n  const tagNote=\"\";\n  if(!date){showToast(\"请选择日期\");return;}\n  if(!done&&!plan&&!tagName){showToast(\"请至少填写今日完成、明日计划或标签\");return;}\n  const res=await fetch(\"/api/worklogs\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({date,done,plan,problem,thinking,important,tagName})});\n  if(res.ok){newRowActive=false;showToast(\"提交成功 ✓\");await loadRecords();}else{showToast(\"提交失败\");}\n}\n\n\nfunction renderTagManage(){\n  const list=document.getElementById(\"tagManageList\");\n  if(!list) return;\n  if(!allTags.length){list.innerHTML=\"<div class='tag-manage-empty'>暂无标签</div>\";return;}\n  list.innerHTML=allTags.map(function(t){\n    return \"<div class='tag-manage-row'><input id='tag_edit_\"+t.id+\"' value='\"+escapeHTML(t.name)+\"'/><div class='tag-manage-actions'><button class='btn-sv' onclick='renameTag(\"+t.id+\")'>保存</button><button class='btn-del' onclick='deleteTag(\"+t.id+\")'>删除</button></div></div>\";\n  }).join(\"\");\n}\n\nasync function showTagManage(){\n  showModal(\"tagManageModal\");\n  await loadTags();\n  renderTagManage();\n}\nfunction hideTagManage(){hideModal(\"tagManageModal\");}\nasync function addTag(){\n  const input=document.getElementById(\"newTagName\");\n  const name=(input&&input.value||\"\").trim();\n  if(!name){showToast(\"标签名\");return;}\n  const res=await fetch(\"/api/tags\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({name:name})});\n  const data=await res.json();\n  if(!res.ok){showToast(data.error||\"添加失败\");return;}\n  input.value=\"\";\n  await loadTags();\n  renderTagManage();\n  renderTable();\n}\nasync function renameTag(id){\n  const input=document.getElementById(\"tag_edit_\"+id);\n  const name=(input&&input.value||\"\").trim();\n  if(!name){showToast(\"标签名\");return;}\n  const res=await fetch(\"/api/tags/\"+id,{method:\"PUT\",headers:authHeaders(),body:JSON.stringify({name:name})});\n  const data=await res.json();\n  if(!res.ok){showToast(data.error||\"保存失败\");return;}\n  await loadRecords();\n  renderTagManage();\n}\nasync function deleteTag(id){\n  if(!confirm(\"确定删除这个标签？相关记录会取消标签关联\")) return;\n  const res=await fetch(\"/api/tags/\"+id,{method:\"DELETE\",headers:authHeaders()});\n  if(!res.ok){showToast(\"删除失败\");return;}\n  await loadRecords();\n  renderTagManage();\n}\n\nfunction renderTagEntries(name,entries){\n  entries.sort(function(a,b){return String(b.date||\"\").localeCompare(String(a.date||\"\"));});\n  document.getElementById(\"tagTitle\").textContent=name;\n  document.getElementById(\"tagMeta\").textContent=entries.length?\"共 \"+entries.length+\" 条相关记录\":\"还没有相关记录\";\n  document.getElementById(\"tagTimeline\").innerHTML=entries.length?entries.map(function(e){\n    const note=e.done||e.plan||e.thinking||\"\";\n    return \"<div class='tag-entry'><div class='tag-date'>\"+escapeHTML(e.date)+\"</div><div><div class='tag-note'>\"+escapeHTML(note)+\"</div></div></div>\";\n  }).join(\"\"):\"<div class='notif-empty'>暂无相关记录</div>\";\n}\n\nasync function showTagByName(name){\n  if(!name) return;\n  showModal(\"tagModal\");\n  document.getElementById(\"tagTitle\").textContent=name;\n  document.getElementById(\"tagMeta\").textContent=\"加载中...\";\n  document.getElementById(\"tagTimeline\").innerHTML=\"\";\n  const entries=[];\n  const seen={};\n  const project=(allTags||[]).find(function(p){return p.name===name;});\n  if(project){\n    const res=await fetch(\"/api/tags/\"+project.id+\"/entries\",{headers:authHeaders()});\n    if(res.ok){\n      (await res.json()).forEach(function(e){entries.push(e);seen[e.worklog_id]=true;});\n    }\n  }\n  allRecords.forEach(function(r){\n    const p=getRecordTag(r);\n    if(p&&p.name===name&&!seen[r.id]) entries.push({worklog_id:r.id,date:r.date,done:r.done,plan:r.plan,thinking:r.thinking});\n  });\n  renderTagEntries(name,entries);\n}\n\nfunction hideTagModal(){hideModal(\"tagModal\");}\n\nasync function delRecord(id){\n  if(!confirm(\"确定删除这条记录？\")) return;\n  const res=await fetch(\"/api/worklogs/\"+id,{method:\"DELETE\",headers:authHeaders()});\n  if(res.ok){showToast(\"已删除\");await loadRecords();}else showToast(\"删除失败\");\n}\n\nasync function toggleExpand(id){\n  const row=document.getElementById(\"er_\"+id);\n  if(!row) return;\n  const isOpen=row.style.display!==\"none\";\n  document.querySelectorAll(\".expand-row\").forEach(function(r){r.style.display=\"none\";});\n  document.querySelectorAll(\".data-row\").forEach(function(r){r.classList.remove(\"row-expanded\");});\n  if(isOpen) return;\n  row.style.display=\"table-row\";\n  const dr=document.querySelector(\"tr[data-rid='\"+id+\"']\");\n  if(dr) dr.classList.add(\"row-expanded\");\n  await loadComments(id);\n}\n\nasync function loadComments(id){\n  const res=await fetch(\"/api/worklogs/\"+id+\"/comments\",{headers:authHeaders()});\n  if(!res.ok) return;\n  renderComments(id,await res.json());\n}\n\nfunction renderComments(id,comments){\n  const el=document.getElementById(\"cl_\"+id);\n  if(!el) return;\n  const replyBtn=\"<button class='btn-reply-sm' onclick='toggleReplyBox(\"+id+\")'>✏️ 回复</button>\";\n  if(!comments.length){el.innerHTML=\"<div class='no-comment'>还没有评论，来第一个提问吧 \"+replyBtn+\"</div>\";return;}\n  el.innerHTML=comments.map(function(c,i){\n    const t=c.created_at?new Date(c.created_at*1000).toLocaleDateString(\"zh-CN\",{month:\"short\",day:\"numeric\",hour:\"2-digit\",minute:\"2-digit\"}):\"\";\n    const isMe=currentUser&&c.author_id===currentUser.id;\n    const isAdm=currentUser&&currentUser.isAdmin;\n    return \"<div class='comment-item'>\"\n      +\"<div class='comment-avatar-sm'>\"+(c.author_name?c.author_name[0].toUpperCase():\"?\")+\"</div>\"\n      +\"<div class='comment-body'>\"\n      +\"<div class='comment-meta'>\"\n      +\"<span class='comment-name'>\"+escapeHTML(c.author_name)+\"</span>\"\n      +\"<span class='comment-time'>\"+t+\"</span>\"\n      +((isMe||isAdm)?\"<button class='btn-del-comment' onclick='delComment(\"+id+\",\"+c.id+\")'>删除</button>\":\"\")\n      +replyBtn\n      +\"</div>\"\n      +\"<div class='comment-text'>\"+escapeHTML(c.text)+\"</div>\"\n      +\"</div></div>\";\n  }).join(\"\");\n}\n\nfunction toggleReplyBox(id){\n  const box=document.getElementById(\"cbox_\"+id);\n  if(!box) return;\n  const isOpen=box.style.display!==\"none\";\n  box.style.display=isOpen?\"none\":\"flex\";\n  if(!isOpen) setTimeout(function(){var el=document.getElementById(\"ci_\"+id);if(el)el.focus();},30);\n}\n\nasync function submitComment(id){\n  const inp=document.getElementById(\"ci_\"+id);\n  const text=inp&&inp.value.trim();\n  if(!text) return;\n  inp.value=\"\";\n  const res=await fetch(\"/api/worklogs/\"+id+\"/comments\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({text:text})});\n  if(res.ok){\n    const box=document.getElementById(\"cbox_\"+id);\n    if(box) box.style.display=\"none\";\n    await loadComments(id);\n    commentCounts[id]=(commentCounts[id]||0)+1;\n    const cc=document.querySelector(\"tr[data-rid='\"+id+\"'] .btn-comment\");\n    if(cc) cc.textContent=\"💬 \"+commentCounts[id];\n    await checkNotifications();\n  }\n}\n\nasync function delComment(wid,cid){\n  if(!confirm(\"删除这条评论？\")) return;\n  const res=await fetch(\"/api/comments/\"+cid,{method:\"DELETE\",headers:authHeaders()});\n  if(res.ok) await loadComments(wid);\n}\n\nasync function checkNotifications(){\n  if(!currentUser) return;\n  const seenRaw=localStorage.getItem(\"notif_seen_\"+currentUser.id)||\"{}\";\n  const seen=JSON.parse(seenRaw);\n  const notifs=[];\n  try{\n    const res=await fetch(\"/api/my-comment-notifications\",{headers:authHeaders()});\n    if(res.ok){\n      const items=await res.json();\n      items.forEach(function(c){\n        const record=allRecords.find(function(r){return r.id===c.worklog_id;});\n        if(!record) return;\n        const key=c.worklog_id+\"_\"+c.id;\n        notifs.push({key:key,rid:c.worklog_id,comment:c,record:record,isNew:!seen[key]});\n      });\n    }\n  }catch(e){}\n  const newCount=notifs.filter(function(n){return n.isNew;}).length;\n  const btn=document.getElementById(\"notifBtn\");\n  const badge=document.getElementById(\"notifCount\");\n  if(notifs.length>0){btn.style.display=\"inline-flex\";badge.textContent=newCount;badge.style.display=newCount>0?\"inline\":\"none\";}\n  const list=document.getElementById(\"notifList\");\n  if(!notifs.length){list.innerHTML=\"<div class='notif-empty'>暂无新回复</div>\";return;}\n  list.innerHTML=notifs.reverse().map(function(n){\n    const t=n.comment.created_at?new Date(n.comment.created_at*1000).toLocaleDateString(\"zh-CN\",{month:\"short\",day:\"numeric\",hour:\"2-digit\",minute:\"2-digit\"}):\"\";\n    return \"<div class='notif-item \"+(n.isNew?\"unread\":\"\")+\"' onclick='goToNotif(\"+n.rid+\")'>\"\n      +\"<div class='notif-who'><span>\"+escapeHTML(n.comment.author_name)+\"</span> 回复了你的记录「\"+escapeHTML(n.record.date)+\"」</div>\"\n      +\"<div class='notif-time'>\"+t+\"</div></div>\";\n  }).join(\"\");\n  window._notifs=notifs;\n}\n\nfunction toggleNotif(){\n  const panel=document.getElementById(\"notifPanel\");\n  const isOpen=panel.style.display!==\"none\";\n  panel.style.display=isOpen?\"none\":\"block\";\n  if(!isOpen){\n    const seen=JSON.parse(localStorage.getItem(\"notif_seen_\"+(currentUser&&currentUser.id))||\"{}\");\n    (window._notifs||[]).forEach(function(n){seen[n.key]=true;});\n    localStorage.setItem(\"notif_seen_\"+(currentUser&&currentUser.id),JSON.stringify(seen));\n    document.getElementById(\"notifCount\").style.display=\"none\";\n    document.querySelectorAll(\".notif-item\").forEach(function(el){el.classList.remove(\"unread\");});\n  }\n}\n\nasync function goToNotif(rid){\n  document.getElementById(\"notifPanel\").style.display=\"none\";\n  await toggleExpand(rid);\n  const row=document.querySelector(\"tr[data-rid='\"+rid+\"']\");\n  if(row) row.scrollIntoView({behavior:\"smooth\",block:\"center\"});\n}\n\ndocument.addEventListener(\"click\",function(e){\n  const panel=document.getElementById(\"notifPanel\");\n  const btn=document.getElementById(\"notifBtn\");\n  if(panel&&!panel.contains(e.target)&&btn&&!btn.contains(e.target)) panel.style.display=\"none\";\n});\n\nasync function showAdminPanel(){\n  showModal(\"adminModal\");\n  const res=await fetch(\"/api/admin/users\",{headers:authHeaders()});\n  const users=await res.json();\n  var rows=[];\n  users.forEach(function(u){\n    rows.push(\"<div style='display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #e0e4eb;'>\"\n      +\"<div><div style='font-size:.84rem;font-weight:600;color:#1a2030;'>\"+escapeHTML(u.name)+\"</div>\"\n      +\"<div style='font-size:.75rem;color:#8a94a6;'>\"+escapeHTML(u.email)+\"</div></div>\"\n      +\"<button class='btn-logout' onclick='showResetModal(\"+u.id+\",this.dataset.name)' data-name='\"+u.name+\"'>重置密码</button>\"\n      +\"</div>\");\n  });\n  document.getElementById(\"adminUserList\").innerHTML=rows.join(\"\");\n}\nfunction hideAdminPanel(){ hideModal(\"adminModal\"); }\n\nfunction showResetModal(uid,uname){\n  resetTargetId=uid;\n  document.getElementById(\"resetTargetName\").textContent=\"为「\"+uname+\"」重置密码\";\n  document.getElementById(\"reset_new\").value=\"\";\n  document.getElementById(\"reset_error\").textContent=\"\";\n  showModal(\"resetModal\");\n}\nfunction hideResetModal(){ hideModal(\"resetModal\"); }\n\nasync function doResetPwd(){\n  const newP=document.getElementById(\"reset_new\").value;\n  const errEl=document.getElementById(\"reset_error\");\n  errEl.textContent=\"\";\n  if(!newP){errEl.textContent=\"请填写新密码\";return;}\n  if(newP.length<6){errEl.textContent=\"密码至少6位\";return;}\n  const res=await fetch(\"/api/admin/reset-password\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({userId:resetTargetId,newPassword:newP})});\n  const data=await res.json();\n  if(!res.ok){errEl.textContent=data.error;return;}\n  hideResetModal(); hideAdminPanel();\n  showToast(\"密码已重置 ✓\");\n}\n\nfunction showChangePwd(){\n  document.getElementById(\"pwd_old\").value=\"\";\n  document.getElementById(\"pwd_new\").value=\"\";\n  document.getElementById(\"pwd_confirm\").value=\"\";\n  document.getElementById(\"pwd_error\").textContent=\"\";\n  showModal(\"pwdModal\");\n}\nfunction hideChangePwd(){ hideModal(\"pwdModal\"); }\n\nasync function doChangePwd(){\n  const oldP=document.getElementById(\"pwd_old\").value;\n  const newP=document.getElementById(\"pwd_new\").value;\n  const cfm=document.getElementById(\"pwd_confirm\").value;\n  const errEl=document.getElementById(\"pwd_error\");\n  errEl.textContent=\"\";\n  if(!oldP||!newP||!cfm){errEl.textContent=\"请填写所有字段\";return;}\n  if(newP!==cfm){errEl.textContent=\"两次新密码不一致\";return;}\n  if(newP.length<6){errEl.textContent=\"新密码至少6位\";return;}\n  const res=await fetch(\"/api/change-password\",{method:\"POST\",headers:authHeaders(),body:JSON.stringify({oldPassword:oldP,newPassword:newP})});\n  const data=await res.json();\n  if(!res.ok){errEl.textContent=data.error;return;}\n  hideChangePwd();\n  showToast(\"密码修改成功 ✓\");\n}\n\nfunction showToast(msg){\n  const t=document.getElementById(\"toast\");\n  t.textContent=msg;t.classList.add(\"show\");\n  clearTimeout(window._tt);window._tt=setTimeout(function(){t.classList.remove(\"show\");},2200);\n}\n</script>\n</body>\n</html>";
}

__name(getHTML, "getHTML");
export {
  index_default as default
};
