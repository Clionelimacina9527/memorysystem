// HTML_CONTENT is injected at build time by build.js
const SITE_URL = "https://memory.mizuflow.net";

async function signJWT(payload, JWT_SECRET) {
  const header = btoa(unescape(encodeURIComponent(JSON.stringify({ alg: "HS256", typ: "JWT" }))));
  const body = btoa(unescape(encodeURIComponent(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 3600 * 1e3 }))));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function verifyJWT(token, JWT_SECRET) {
  try {
    const [header, body, sig] = token.split(".");
    const data = `${header}.${body}`;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(JWT_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const sigBytes = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(decodeURIComponent(escape(atob(body))));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function getUser(req, JWT_SECRET) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.replace("Bearer ", "");
  if (!token) return null;
  return verifyJWT(token, JWT_SECRET);
}

async function hashPassword(password, HASH_SECRET) {
  const salt = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt + HASH_SECRET), iterations: 100000, hash: "SHA-256" }, key, 256);
  const hash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2:${salt}:${hash}`;
}

async function verifyPassword(password, stored, HASH_SECRET, legacySecret) {
  if (stored.startsWith("pbkdf2:")) {
    const [, salt, hash] = stored.split(":");
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: new TextEncoder().encode(salt + HASH_SECRET), iterations: 100000, hash: "SHA-256" }, key, 256);
    const newHash = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
    return newHash === hash;
  }
  const sha256hex = async s => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  };
  if (await sha256hex(password + HASH_SECRET) === stored) return true;
  if (legacySecret && legacySecret !== HASH_SECRET) return await sha256hex(password + legacySecret) === stored;
  return false;
}

async function checkLoginRateLimit(db, email) {
  const since = Math.floor(Date.now() / 1000) - 900;
  const r = await db.prepare("SELECT COUNT(*) as cnt FROM login_attempts WHERE email=? AND attempted_at > ?").bind(email, since).first();
  return (r?.cnt || 0) < 5;
}

async function recordLoginFailure(db, email, ip) {
  await db.prepare("INSERT INTO login_attempts(email,ip) VALUES(?,?)").bind(email, ip || "").run();
  await db.prepare("DELETE FROM login_attempts WHERE attempted_at < ?").bind(Math.floor(Date.now() / 1000) - 3600).run();
}

// Resolves and validates a candidate parent tag id (max 2 levels deep, no cycles).
async function resolveParentId(db, parentId, selfId) {
  if (!parentId) return null;
  if (selfId && parentId === selfId) throw new Error("不能将自己设为父标签");
  const parent = await db.prepare("SELECT id, parent_id FROM projects WHERE id=?").bind(parentId).first();
  if (!parent) throw new Error("父标签不存在");
  if (parent.parent_id) throw new Error("最多支持二级标签，请选择一级标签作为父标签");
  if (selfId) {
    const childCount = await db.prepare("SELECT COUNT(*) as cnt FROM projects WHERE parent_id=?").bind(selfId).first();
    if (childCount?.cnt) throw new Error("该标签下还有子标签，无法再设置父标签");
  }
  return parentId;
}

async function setWorklogTag(db, worklogId, tagName, user) {
  await db.prepare("DELETE FROM project_entries WHERE worklog_id=?").bind(worklogId).run();
  const name = (tagName || "").trim();
  if (!name) return;
  await db.prepare("INSERT OR IGNORE INTO projects(name,author_id) VALUES(?,?)").bind(name, user.id).run();
  const tag = await db.prepare("SELECT id FROM projects WHERE name=?").bind(name).first();
  if (tag) {
    await db.prepare("INSERT INTO project_entries(worklog_id,project_id,progress,author_id) VALUES(?,?,?,?)").bind(worklogId, tag.id, "", user.id).run();
  }
}

async function initDB(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    notif_last_seen INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )`).run();
  // Migrate existing tables that may not have notif_last_seen
  await db.prepare("ALTER TABLE users ADD COLUMN notif_last_seen INTEGER DEFAULT 0").run().catch(() => {});

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
    parent_id INTEGER,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(author_id) REFERENCES users(id),
    FOREIGN KEY(parent_id) REFERENCES projects(id)
  )`).run();
  // Migrate existing tables that may not have parent_id
  await db.prepare("ALTER TABLE projects ADD COLUMN parent_id INTEGER REFERENCES projects(id)").run().catch(() => {});
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
  await db.prepare(`CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worklog_id INTEGER NOT NULL,
    file_key TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    file_type TEXT NOT NULL,
    author_id INTEGER NOT NULL,
    author_name TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    FOREIGN KEY(worklog_id) REFERENCES worklogs(id) ON DELETE CASCADE
  )`).run();
}

const CORS = {
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

export default {
  async fetch(req, env) {
    const { ADMIN_EMAIL, INVITE_CODE, JWT_SECRET, HASH_SECRET, FEISHU_HOOK } = env;
    await initDB(env.DB);
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    if (method === "OPTIONS") return new Response(null, { headers: CORS });

    if (method === "GET" && (path === "/" || path === "/index.html")) {
      return new Response(HTML_CONTENT, { headers: { "Content-Type": "text/html;charset=utf-8" } });
    }

    // --- Auth (no login required) ---
    if (path === "/api/register" && method === "POST") {
      const { name, email, password, inviteCode } = await req.json();
      if (inviteCode !== INVITE_CODE) return json({ error: "邀请码不正确" }, 400);
      if (!name || !email || !password) return json({ error: "请填写所有字段" }, 400);
      if (password.length < 6) return json({ error: "密码至少6位" }, 400);
      const hash = await hashPassword(password, HASH_SECRET);
      try {
        const r = await env.DB.prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)").bind(name, email, hash).run();
        const token = await signJWT({ id: r.meta.last_row_id, name, email }, JWT_SECRET);
        return json({ token, user: { id: r.meta.last_row_id, name, email, isAdmin: email === ADMIN_EMAIL } });
      } catch {
        return json({ error: "该邮箱已被注册" }, 400);
      }
    }

    if (path === "/api/login" && method === "POST") {
      const { email, password } = await req.json();
      const ip = req.headers.get("CF-Connecting-IP") || "";
      if (!await checkLoginRateLimit(env.DB, email)) return json({ error: "登录尝试过于频繁，请15分钟后再试" }, 429);
      const dbUser = await env.DB.prepare("SELECT * FROM users WHERE email=?").bind(email).first();
      if (!dbUser || !await verifyPassword(password, dbUser.password, HASH_SECRET, JWT_SECRET)) {
        if (dbUser) await recordLoginFailure(env.DB, email, ip);
        return json({ error: "邮箱或密码错误" }, 401);
      }
      if (!dbUser.password.startsWith("pbkdf2:")) {
        const newHash = await hashPassword(password, HASH_SECRET);
        await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, dbUser.id).run();
      }
      const token = await signJWT({ id: dbUser.id, name: dbUser.name, email: dbUser.email }, JWT_SECRET);
      return json({ token, user: { id: dbUser.id, name: dbUser.name, email: dbUser.email, isAdmin: dbUser.email === ADMIN_EMAIL } });
    }

    // --- File serving (capability URL, no auth required) ---
    const fileMatch = path.match(/^\/api\/files\/([a-zA-Z0-9_-]+)$/);
    if (fileMatch && method === "GET") {
      const key = fileMatch[1];
      const result = await env.KV.getWithMetadata(key, "arrayBuffer");
      if (!result.value) return json({ error: "文件不存在" }, 404);
      const { filename, type } = result.metadata || {};
      return new Response(result.value, {
        headers: {
          ...CORS,
          "Content-Type": type || "application/octet-stream",
          "Content-Disposition": `inline; filename="${filename || key}"`,
          "Cache-Control": "private, max-age=86400",
        }
      });
    }

    // --- All routes below require auth ---
    const user = await getUser(req, JWT_SECRET);
    if (!user && path.startsWith("/api/")) return json({ error: "请先登录" }, 401);
    const isAdmin = user?.email === ADMIN_EMAIL;

    // --- Worklogs (paginated + server-side filtered) ---
    if (path === "/api/worklogs" && method === "GET") {
      const page = Math.max(1, parseInt(url.searchParams.get("page") || "1"));
      const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get("pageSize") || "50")));
      const author = url.searchParams.get("author") || "";
      const dateFrom = url.searchParams.get("dateFrom") || "";
      const dateTo = url.searchParams.get("dateTo") || "";
      const tag = url.searchParams.get("tag") || "";
      const keyword = (url.searchParams.get("keyword") || "").trim();

      const conditions = [];
      const params = [];
      if (author) { conditions.push("w.author_name = ?"); params.push(author); }
      if (dateFrom) { conditions.push("w.date >= ?"); params.push(dateFrom); }
      if (dateTo) { conditions.push("w.date <= ?"); params.push(dateTo); }
      if (tag) {
        const tagRow = await env.DB.prepare("SELECT id FROM projects WHERE name=?").bind(tag).first();
        if (tagRow) {
          const childRows = await env.DB.prepare("SELECT id FROM projects WHERE parent_id=?").bind(tagRow.id).all();
          const tagIds = [tagRow.id, ...childRows.results.map(r => r.id)];
          conditions.push(`p.id IN (${tagIds.map(() => "?").join(",")})`);
          params.push(...tagIds);
        } else {
          conditions.push("1=0");
        }
      }
      if (keyword) {
        const kw = `%${keyword}%`;
        conditions.push("(w.done LIKE ? OR w.plan LIKE ? OR w.problem LIKE ? OR w.thinking LIKE ? OR w.important LIKE ? OR w.author_name LIKE ? OR p.name LIKE ? OR w.date LIKE ?)");
        params.push(kw, kw, kw, kw, kw, kw, kw, kw);
      }
      const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const offset = (page - 1) * pageSize;

      const countSQL = `SELECT COUNT(DISTINCT w.id) as total FROM worklogs w LEFT JOIN project_entries pe ON pe.worklog_id=w.id LEFT JOIN projects p ON p.id=pe.project_id ${where}`;
      const dataSQL = `SELECT w.*, p.id as tag_id, p.name as tag_name, pe.progress as tag_note FROM worklogs w LEFT JOIN project_entries pe ON pe.worklog_id=w.id LEFT JOIN projects p ON p.id=pe.project_id ${where} ORDER BY w.date DESC, w.created_at DESC LIMIT ? OFFSET ?`;

      // Export mode: return all matching records without pagination (max 5000)
      if (url.searchParams.get("export") === "1") {
        const exportSQL = `SELECT w.*, p.id as tag_id, p.name as tag_name, pe.progress as tag_note FROM worklogs w LEFT JOIN project_entries pe ON pe.worklog_id=w.id LEFT JOIN projects p ON p.id=pe.project_id ${where} ORDER BY w.date DESC, w.created_at DESC LIMIT 5000`;
        const rows = await env.DB.prepare(exportSQL).bind(...params).all();
        return json({ results: rows.results });
      }

      const countRow = await env.DB.prepare(countSQL).bind(...params).first();
      const total = countRow?.total || 0;
      const rows = await env.DB.prepare(dataSQL).bind(...params, pageSize, offset).all();

      // Return all member names for filter dropdown (unaffected by current filters)
      const authorsRows = await env.DB.prepare("SELECT DISTINCT author_name FROM worklogs ORDER BY author_name").all();
      const authors = authorsRows.results.map(r => r.author_name);

      return json({ results: rows.results, total, page, pageSize, authors });
    }

    if (path === "/api/worklogs" && method === "POST") {
      const { date, done, plan, problem, thinking, important, tagName } = await req.json();
      if (!date) return json({ error: "请选择日期" }, 400);
      const r = await env.DB.prepare(
        "INSERT INTO worklogs(date,done,plan,problem,thinking,important,author_id,author_name) VALUES(?,?,?,?,?,?,?,?)"
      ).bind(date, done || "", plan || "", problem || "", thinking || "", important || "", user.id, user.name).run();
      await setWorklogTag(env.DB, r.meta.last_row_id, tagName || "", user);
      return json({ id: r.meta.last_row_id });
    }

    // --- Personal stats ---
    if (path === "/api/my-stats" && method === "GET") {
      const totalRow = await env.DB.prepare("SELECT COUNT(*) as cnt FROM worklogs WHERE author_id=?").bind(user.id).first();
      const monthRow = await env.DB.prepare(
        "SELECT COUNT(*) as cnt FROM worklogs WHERE author_id=? AND strftime('%Y-%m', date) = strftime('%Y-%m','now')"
      ).bind(user.id).first();
      const dateRows = await env.DB.prepare("SELECT DISTINCT date FROM worklogs WHERE author_id=? ORDER BY date DESC").bind(user.id).all();
      const dateSet = new Set(dateRows.results.map(r => r.date));
      const toDateStr = d => d.toISOString().split("T")[0];
      const cursor = new Date();
      if (!dateSet.has(toDateStr(cursor))) cursor.setUTCDate(cursor.getUTCDate() - 1);
      let streak = 0;
      while (dateSet.has(toDateStr(cursor))) { streak++; cursor.setUTCDate(cursor.getUTCDate() - 1); }
      return json({ total: totalRow?.cnt || 0, month: monthRow?.cnt || 0, streak });
    }

    // --- Tags ---
    if ((path === "/api/projects" || path === "/api/tags") && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT p.id, p.name, p.parent_id, par.name as parent_name, COUNT(pe.id) as entry_count, " +
        "(SELECT pe2.progress FROM project_entries pe2 JOIN worklogs w2 ON w2.id=pe2.worklog_id WHERE pe2.project_id=p.id ORDER BY w2.date DESC, pe2.created_at DESC LIMIT 1) as latest_progress, " +
        "(SELECT w2.date FROM project_entries pe2 JOIN worklogs w2 ON w2.id=pe2.worklog_id WHERE pe2.project_id=p.id ORDER BY w2.date DESC, pe2.created_at DESC LIMIT 1) as latest_date " +
        "FROM projects p LEFT JOIN project_entries pe ON pe.project_id=p.id LEFT JOIN projects par ON par.id=p.parent_id " +
        "GROUP BY p.id, p.name ORDER BY latest_date DESC, p.created_at DESC"
      ).all();
      return json(rows.results);
    }

    if (path === "/api/tags" && method === "POST") {
      const { name, parentId } = await req.json();
      const tagName = (name || "").trim();
      if (!tagName) return json({ error: "标签名不能为空" }, 400);
      let pid;
      try {
        pid = await resolveParentId(env.DB, parentId ? parseInt(parentId) : null, null);
      } catch (e) {
        return json({ error: e.message }, 400);
      }
      try {
        const r = await env.DB.prepare("INSERT INTO projects(name,author_id,parent_id) VALUES(?,?,?)").bind(tagName, user.id, pid).run();
        return json({ id: r.meta.last_row_id, name: tagName, parent_id: pid });
      } catch {
        return json({ error: "标签已存在" }, 400);
      }
    }

    const tagMatch = path.match(/^\/api\/tags\/(\d+)$/);
    if (tagMatch) {
      const tid = parseInt(tagMatch[1]);
      if (method === "PUT") {
        const { name, parentId } = await req.json();
        const tagName = (name || "").trim();
        if (!tagName) return json({ error: "标签名不能为空" }, 400);
        let pid;
        try {
          pid = await resolveParentId(env.DB, parentId ? parseInt(parentId) : null, tid);
        } catch (e) {
          return json({ error: e.message }, 400);
        }
        try {
          await env.DB.prepare("UPDATE projects SET name=?, parent_id=? WHERE id=?").bind(tagName, pid, tid).run();
          return json({ ok: true });
        } catch {
          return json({ error: "标签已存在" }, 400);
        }
      }
      if (method === "DELETE") {
        await env.DB.prepare("UPDATE projects SET parent_id=NULL WHERE parent_id=?").bind(tid).run();
        await env.DB.prepare("DELETE FROM project_entries WHERE project_id=?").bind(tid).run();
        await env.DB.prepare("DELETE FROM projects WHERE id=?").bind(tid).run();
        return json({ ok: true });
      }
    }

    const projectEntriesMatch = path.match(/^\/api\/(?:projects|tags)\/(\d+)\/entries$/);
    if (projectEntriesMatch && method === "GET") {
      const pid = parseInt(projectEntriesMatch[1]);
      const rows = await env.DB.prepare(
        "SELECT pe.id, pe.progress, w.id as worklog_id, w.date, w.done, w.plan, w.problem, w.thinking, w.important, w.author_name " +
        "FROM project_entries pe JOIN worklogs w ON w.id=pe.worklog_id " +
        "WHERE pe.project_id=? OR pe.project_id IN (SELECT id FROM projects WHERE parent_id=?) " +
        "ORDER BY w.date DESC, pe.created_at DESC"
      ).bind(pid, pid).all();
      return json(rows.results);
    }

    // --- Single worklog CRUD ---
    const wlogMatch = path.match(/^\/api\/worklogs\/(\d+)$/);
    if (wlogMatch) {
      const wid = parseInt(wlogMatch[1]);
      const log = await env.DB.prepare("SELECT * FROM worklogs WHERE id=?").bind(wid).first();
      if (!log) return json({ error: "记录不存在" }, 404);
      const canEdit = isAdmin || log.author_id === user.id;

      if (method === "PUT") {
        if (!canEdit) return json({ error: "无权限" }, 403);
        const { date, done, plan, problem, thinking, important, tagName } = await req.json();
        await env.DB.prepare(
          "UPDATE worklogs SET date=?,done=?,plan=?,problem=?,thinking=?,important=? WHERE id=?"
        ).bind(date || log.date, done ?? log.done, plan ?? log.plan, problem ?? log.problem, thinking ?? log.thinking, important ?? log.important, wid).run();
        if (tagName !== undefined) await setWorklogTag(env.DB, wid, tagName, user);
        return json({ ok: true });
      }

      if (method === "DELETE") {
        if (!canEdit) return json({ error: "无权限" }, 403);
        // Clean up KV files before deleting worklog
        const attachRows = await env.DB.prepare("SELECT file_key FROM attachments WHERE worklog_id=?").bind(wid).all();
        await Promise.all(attachRows.results.map(a => env.KV.delete(a.file_key)));
        await env.DB.prepare("DELETE FROM worklogs WHERE id=?").bind(wid).run();
        return json({ ok: true });
      }
    }

    // --- Attachments ---
    const attachListMatch = path.match(/^\/api\/worklogs\/(\d+)\/attachments$/);
    if (attachListMatch) {
      const wid = parseInt(attachListMatch[1]);
      if (method === "GET") {
        const rows = await env.DB.prepare("SELECT id, file_key, file_name, file_size, file_type, author_id, author_name, created_at FROM attachments WHERE worklog_id=? ORDER BY created_at ASC").bind(wid).all();
        return json(rows.results);
      }
      if (method === "POST") {
        const formData = await req.formData();
        const file = formData.get("file");
        if (!file) return json({ error: "没有文件" }, 400);
        const allowed = ["image/jpeg", "image/png", "image/gif", "image/webp", "application/pdf"];
        if (!allowed.includes(file.type)) return json({ error: "仅支持图片（JPG/PNG/GIF/WebP）和PDF" }, 400);
        if (file.size > 5 * 1024 * 1024) return json({ error: "文件不能超过5MB" }, 400);
        const key = crypto.randomUUID();
        const buf = await file.arrayBuffer();
        await env.KV.put(key, buf, { metadata: { filename: file.name, type: file.type } });
        const r = await env.DB.prepare(
          "INSERT INTO attachments(worklog_id,file_key,file_name,file_size,file_type,author_id,author_name) VALUES(?,?,?,?,?,?,?)"
        ).bind(wid, key, file.name, file.size, file.type, user.id, user.name).run();
        return json({ id: r.meta.last_row_id, file_key: key, file_name: file.name, file_type: file.type, file_size: file.size });
      }
    }

    const delAttachMatch = path.match(/^\/api\/attachments\/(\d+)$/);
    if (delAttachMatch && method === "DELETE") {
      const aid = parseInt(delAttachMatch[1]);
      const att = await env.DB.prepare("SELECT * FROM attachments WHERE id=?").bind(aid).first();
      if (!att) return json({ error: "不存在" }, 404);
      if (!isAdmin && att.author_id !== user.id) return json({ error: "无权限" }, 403);
      await env.KV.delete(att.file_key);
      await env.DB.prepare("DELETE FROM attachments WHERE id=?").bind(aid).run();
      return json({ ok: true });
    }

    // --- Comments ---
    const cmtMatch = path.match(/^\/api\/worklogs\/(\d+)\/comments$/);
    if (cmtMatch) {
      const wid = parseInt(cmtMatch[1]);
      if (method === "GET") {
        const rows = await env.DB.prepare("SELECT * FROM comments WHERE worklog_id=? ORDER BY created_at ASC").bind(wid).all();
        return json(rows.results);
      }
      if (method === "POST") {
        const { text } = await req.json();
        if (!text) return json({ error: "评论不能为空" }, 400);
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
                header: { title: { tag: "plain_text", content: "💬 个人数字记忆系统新回复" }, template: "green" },
                elements: [{
                  tag: "div",
                  text: { tag: "lark_md", content: `**${user.name}** 回复了 **${log.author_name} ${log.date}** 的记录，快去看看吧 👀` }
                }, {
                  tag: "action",
                  actions: [{ tag: "button", text: { tag: "plain_text", content: "👉 查看记录" }, type: "primary", url: SITE_URL }]
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
      if (!cmt) return json({ error: "不存在" }, 404);
      if (!isAdmin && cmt.author_id !== user.id) return json({ error: "无权限" }, 403);
      await env.DB.prepare("DELETE FROM comments WHERE id=?").bind(cid).run();
      return json({ ok: true });
    }

    // --- Notifications (DB-persisted read state) ---
    if (path === "/api/my-comment-notifications" && method === "GET") {
      const dbUser = await env.DB.prepare("SELECT notif_last_seen FROM users WHERE id=?").bind(user.id).first();
      const lastSeen = dbUser?.notif_last_seen || 0;
      const rows = await env.DB.prepare(
        "SELECT c.id, c.worklog_id, c.text, c.author_id, c.author_name, c.created_at, w.date as worklog_date " +
        "FROM comments c JOIN worklogs w ON w.id=c.worklog_id " +
        "WHERE w.author_id=? AND c.author_id!=? ORDER BY c.created_at DESC"
      ).bind(user.id, user.id).all();
      const items = rows.results.map(r => ({ ...r, is_new: r.created_at > lastSeen }));
      return json({ items, unread_count: items.filter(r => r.is_new).length });
    }

    if (path === "/api/notifications/mark-read" && method === "POST") {
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare("UPDATE users SET notif_last_seen=? WHERE id=?").bind(now, user.id).run();
      return json({ ok: true });
    }

    // --- Comment counts ---
    if (path === "/api/comment-counts" && method === "GET") {
      const rows = await env.DB.prepare("SELECT worklog_id, COUNT(*) as cnt FROM comments GROUP BY worklog_id").all();
      const map = {};
      rows.results.forEach(r => map[r.worklog_id] = r.cnt);
      return json(map);
    }

    // --- Admin ---
    if (path === "/api/admin/users" && method === "GET") {
      if (!isAdmin) return json({ error: "无权限" }, 403);
      const rows = await env.DB.prepare("SELECT id, name, email, created_at FROM users").all();
      return json(rows.results);
    }

    if (path === "/api/admin/reset-password" && method === "POST") {
      if (!isAdmin) return json({ error: "无权限" }, 403);
      const { userId, newPassword } = await req.json();
      if (!userId || !newPassword) return json({ error: "参数缺失" }, 400);
      if (newPassword.length < 6) return json({ error: "密码至少6位" }, 400);
      const newHash = await hashPassword(newPassword, HASH_SECRET);
      await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, userId).run();
      return json({ ok: true });
    }

    if (path === "/api/change-password" && method === "POST") {
      const { oldPassword, newPassword } = await req.json();
      if (!oldPassword || !newPassword) return json({ error: "请填写完整" }, 400);
      if (newPassword.length < 6) return json({ error: "新密码至少6位" }, 400);
      const dbUser = await env.DB.prepare("SELECT * FROM users WHERE id=?").bind(user.id).first();
      if (!dbUser || !await verifyPassword(oldPassword, dbUser.password, HASH_SECRET, JWT_SECRET)) return json({ error: "旧密码不正确" }, 400);
      const newHash = await hashPassword(newPassword, HASH_SECRET);
      await env.DB.prepare("UPDATE users SET password=? WHERE id=?").bind(newHash, user.id).run();
      return json({ ok: true });
    }

    return json({ error: "Not found" }, 404);
  }
};
