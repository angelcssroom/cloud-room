const MEMBER_COOKIE = "cr_session";
const DEVICE_COOKIE = "cr_device";
const ADMIN_COOKIE = "cr_admin";

const MEMBER_SESSION_SECONDS = 180 * 24 * 60 * 60;
const DEVICE_COOKIE_SECONDS = 2 * 365 * 24 * 60 * 60;
const ADMIN_SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const LOGIN_BLOCK_SECONDS = 30 * 60;
const LOGIN_MAX_FAILURES = 8;
const MAX_JSON_BYTES = 8192;

const ACCESS_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
let schemaReady = false;

class SetupError extends Error {}

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = normalizePath(url.pathname);

      if (path.startsWith("/api/")) {
        return secureResponse(await handleApi(request, env, path), "api");
      }

      if (path === "/login" || path === "/login.html") {
        const member = await tryGetMemberSession(request, env);
        if (member) return redirectResponse("/");
        return secureResponse(await serveAsset(request, env, "/login.html"), "public");
      }

      if (path === "/admin" || path === "/admin.html") {
        return secureResponse(await serveAsset(request, env, "/admin.html"), "public");
      }

      const member = await getMemberSession(request, env);
      if (!member) {
        const next = safeNextPath(url.pathname + url.search);
        return redirectResponse(`/login?next=${encodeURIComponent(next)}`);
      }

      const assetPath = mapFriendlyPath(path);
      return secureResponse(await serveAsset(request, env, assetPath), "protected");
    } catch (error) {
      console.error("Cloud Room request failed", error);
      if (error instanceof SetupError) {
        return secureResponse(
          htmlResponse(setupErrorHtml(), 503),
          "public"
        );
      }
      return secureResponse(
        htmlResponse("<!doctype html><meta charset=\"utf-8\"><title>Cloud Room</title><p style=\"font-family:system-ui;padding:32px\">页面暂时无法打开，请稍后重试。</p>", 500),
        "public"
      );
    }
  },
};

async function handleApi(request, env, path) {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204 });
  }

  if (["POST", "PUT", "PATCH", "DELETE"].includes(request.method) && !isSameOriginRequest(request)) {
    return jsonResponse({ ok: false, error: "请求来源无效。" }, 403);
  }

  if (path === "/api/login") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return memberLogin(request, env);
  }

  if (path === "/api/logout") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return memberLogout(request, env);
  }

  if (path === "/api/session") {
    if (request.method !== "GET") return methodNotAllowed(["GET"]);
    const member = await getMemberSession(request, env);
    if (!member) return jsonResponse({ ok: false, authenticated: false }, 401);
    return jsonResponse({ ok: true, authenticated: true, member: { qq: member.qq } });
  }

  if (path === "/api/admin/login") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return adminLogin(request, env);
  }

  if (path === "/api/admin/logout") {
    if (request.method !== "POST") return methodNotAllowed(["POST"]);
    return adminLogout(request, env);
  }

  if (path === "/api/admin/session") {
    if (request.method !== "GET") return methodNotAllowed(["GET"]);
    const admin = await getAdminSession(request, env);
    if (!admin) return jsonResponse({ ok: true, authenticated: false });
    return jsonResponse({ ok: true, authenticated: true });
  }

  if (path === "/api/admin/members") {
    const admin = await getAdminSession(request, env);
    if (!admin) return jsonResponse({ ok: false, error: "管理员登录已失效。" }, 401);
    if (request.method === "GET") return listMembers(request, env);
    if (request.method === "POST") return addMember(request, env);
    return methodNotAllowed(["GET", "POST"]);
  }

  if (path.startsWith("/api/admin/members/")) {
    const admin = await getAdminSession(request, env);
    if (!admin) return jsonResponse({ ok: false, error: "管理员登录已失效。" }, 401);
    if (request.method !== "DELETE") return methodNotAllowed(["DELETE"]);
    const qq = decodeURIComponent(path.slice("/api/admin/members/".length));
    return deleteMember(env, qq);
  }

  return jsonResponse({ ok: false, error: "接口不存在。" }, 404);
}

async function memberLogin(request, env) {
  requireRuntimeConfig(env);
  await ensureSchema(env.DB);

  const body = await readJson(request);
  const qq = normalizeQq(body.qq);
  const accessCode = normalizeAccessCode(body.accessCode);
  if (!qq || !accessCode) {
    return jsonResponse({ ok: false, error: "请填写正确的 QQ 号和访问码。" }, 400);
  }

  const attemptKey = await attemptHash(env.AUTH_SECRET, request, `member:${qq}`);
  const blockedFor = await getBlockedSeconds(env.DB, attemptKey);
  if (blockedFor > 0) {
    return jsonResponse({ ok: false, error: `尝试次数过多，请 ${Math.ceil(blockedFor / 60)} 分钟后再试。` }, 429);
  }

  const member = await env.DB.prepare(
    "SELECT id, qq, access_code_hash, device_hash FROM members WHERE qq = ? LIMIT 1"
  ).bind(qq).first();

  const suppliedHash = await hmacHex(env.AUTH_SECRET, `access:${qq}:${accessCode}`);
  const expectedHash = member?.access_code_hash || await hmacHex(env.AUTH_SECRET, `access:${qq}:invalid`);
  const validCode = member && timingSafeEqual(suppliedHash, expectedHash);

  if (!validCode) {
    await recordFailure(env.DB, attemptKey);
    return jsonResponse({ ok: false, error: "QQ 号或访问码不正确。" }, 401);
  }

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  let deviceToken = cookies[DEVICE_COOKIE];
  let newDeviceCookie = false;
  if (!isValidToken(deviceToken)) {
    deviceToken = randomToken(32);
    newDeviceCookie = true;
  }
  const deviceHash = await hmacHex(env.AUTH_SECRET, `device:${deviceToken}`);

  if (!member.device_hash) {
    await env.DB.prepare(
      "UPDATE members SET device_hash = ? WHERE id = ? AND device_hash IS NULL"
    ).bind(deviceHash, member.id).run();
  }

  const bound = await env.DB.prepare(
    "SELECT device_hash FROM members WHERE id = ? LIMIT 1"
  ).bind(member.id).first();

  if (!bound?.device_hash || !timingSafeEqual(bound.device_hash, deviceHash)) {
    await recordFailure(env.DB, attemptKey);
    return jsonResponse(
      { ok: false, code: "DEVICE_MISMATCH", error: "该 QQ 号已经绑定其他设备。需要换设备时，请联系管理员删除后重新添加。" },
      409
    );
  }

  const now = unixNow();
  const sessionToken = randomToken(32);
  const sessionHash = await hmacHex(env.AUTH_SECRET, `member-session:${sessionToken}`);

  await env.DB.batch([
    env.DB.prepare("DELETE FROM member_sessions WHERE member_id = ?").bind(member.id),
    env.DB.prepare(
      "INSERT INTO member_sessions (token_hash, member_id, device_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)"
    ).bind(sessionHash, member.id, deviceHash, now + MEMBER_SESSION_SECONDS, now),
    env.DB.prepare("UPDATE members SET last_login_at = ? WHERE id = ?").bind(now, member.id),
    env.DB.prepare("DELETE FROM login_attempts WHERE attempt_key = ?").bind(attemptKey),
  ]);

  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  headers.append("Set-Cookie", makeCookie(MEMBER_COOKIE, sessionToken, MEMBER_SESSION_SECONDS, request));
  if (newDeviceCookie) {
    headers.append("Set-Cookie", makeCookie(DEVICE_COOKIE, deviceToken, DEVICE_COOKIE_SECONDS, request));
  }

  return new Response(JSON.stringify({ ok: true, member: { qq } }), { status: 200, headers });
}

async function memberLogout(request, env) {
  if (env.DB && env.AUTH_SECRET) {
    await ensureSchema(env.DB);
    const token = parseCookies(request.headers.get("Cookie") || "")[MEMBER_COOKIE];
    if (isValidToken(token)) {
      const hash = await hmacHex(env.AUTH_SECRET, `member-session:${token}`);
      await env.DB.prepare("DELETE FROM member_sessions WHERE token_hash = ?").bind(hash).run();
    }
  }
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  headers.append("Set-Cookie", clearCookie(MEMBER_COOKIE, request));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function adminLogin(request, env) {
  requireRuntimeConfig(env);
  await ensureSchema(env.DB);

  const body = await readJson(request);
  const password = typeof body.password === "string" ? body.password : "";
  const attemptKey = await attemptHash(env.AUTH_SECRET, request, "admin");
  const blockedFor = await getBlockedSeconds(env.DB, attemptKey);
  if (blockedFor > 0) {
    return jsonResponse({ ok: false, error: `尝试次数过多，请 ${Math.ceil(blockedFor / 60)} 分钟后再试。` }, 429);
  }

  const supplied = await sha256Hex(password);
  const expected = await sha256Hex(env.ADMIN_PASSWORD);
  if (!password || !timingSafeEqual(supplied, expected)) {
    await recordFailure(env.DB, attemptKey);
    return jsonResponse({ ok: false, error: "管理员密码不正确。" }, 401);
  }

  const now = unixNow();
  const token = randomToken(32);
  const tokenHash = await hmacHex(env.AUTH_SECRET, `admin-session:${token}`);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO admin_sessions (token_hash, expires_at, created_at) VALUES (?, ?, ?)"
    ).bind(tokenHash, now + ADMIN_SESSION_SECONDS, now),
    env.DB.prepare("DELETE FROM login_attempts WHERE attempt_key = ?").bind(attemptKey),
    env.DB.prepare("DELETE FROM admin_sessions WHERE expires_at <= ?").bind(now),
  ]);

  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  headers.append("Set-Cookie", makeCookie(ADMIN_COOKIE, token, ADMIN_SESSION_SECONDS, request));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function adminLogout(request, env) {
  if (env.DB && env.AUTH_SECRET) {
    await ensureSchema(env.DB);
    const token = parseCookies(request.headers.get("Cookie") || "")[ADMIN_COOKIE];
    if (isValidToken(token)) {
      const hash = await hmacHex(env.AUTH_SECRET, `admin-session:${token}`);
      await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(hash).run();
    }
  }
  const headers = new Headers({ "Content-Type": "application/json; charset=utf-8" });
  headers.append("Set-Cookie", clearCookie(ADMIN_COOKIE, request));
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

async function listMembers(request, env) {
  await ensureSchema(env.DB);
  const url = new URL(request.url);
  const q = normalizeQqSearch(url.searchParams.get("q") || "");

  let statement;
  if (q) {
    statement = env.DB.prepare(
      "SELECT id, qq, device_hash, created_at, last_login_at FROM members WHERE qq LIKE ? ORDER BY created_at DESC LIMIT 100"
    ).bind(`%${q}%`);
  } else {
    statement = env.DB.prepare(
      "SELECT id, qq, device_hash, created_at, last_login_at FROM members ORDER BY created_at DESC LIMIT 100"
    );
  }

  const [rows, countRow] = await Promise.all([
    statement.all(),
    env.DB.prepare("SELECT COUNT(*) AS total FROM members").first(),
  ]);

  const members = (rows.results || []).map((row) => ({
    id: row.id,
    qq: row.qq,
    deviceBound: Boolean(row.device_hash),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  }));

  return jsonResponse({ ok: true, total: Number(countRow?.total || 0), members });
}

async function addMember(request, env) {
  await ensureSchema(env.DB);
  const body = await readJson(request);
  const qq = normalizeQq(body.qq);
  if (!qq) return jsonResponse({ ok: false, error: "请输入正确的 QQ 号。" }, 400);

  const existing = await env.DB.prepare("SELECT id FROM members WHERE qq = ? LIMIT 1").bind(qq).first();
  if (existing) return jsonResponse({ ok: false, error: "这个 QQ 号已经存在。" }, 409);

  const rawCode = randomAccessCode(10);
  const displayCode = formatAccessCode(rawCode);
  const codeHash = await hmacHex(env.AUTH_SECRET, `access:${qq}:${rawCode}`);
  const now = unixNow();

  await env.DB.prepare(
    "INSERT INTO members (qq, access_code_hash, device_hash, created_at, last_login_at) VALUES (?, ?, NULL, ?, NULL)"
  ).bind(qq, codeHash, now).run();

  return jsonResponse({
    ok: true,
    member: { qq, accessCode: displayCode, deviceBound: false, createdAt: now },
  }, 201);
}

async function deleteMember(env, rawQq) {
  await ensureSchema(env.DB);
  const qq = normalizeQq(rawQq);
  if (!qq) return jsonResponse({ ok: false, error: "QQ 号无效。" }, 400);

  const member = await env.DB.prepare("SELECT id FROM members WHERE qq = ? LIMIT 1").bind(qq).first();
  if (!member) return jsonResponse({ ok: false, error: "没有找到这个成员。" }, 404);

  await env.DB.batch([
    env.DB.prepare("DELETE FROM member_sessions WHERE member_id = ?").bind(member.id),
    env.DB.prepare("DELETE FROM members WHERE id = ?").bind(member.id),
  ]);
  return jsonResponse({ ok: true, deletedQq: qq });
}

async function getMemberSession(request, env) {
  requireRuntimeConfig(env);
  await ensureSchema(env.DB);

  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const sessionToken = cookies[MEMBER_COOKIE];
  const deviceToken = cookies[DEVICE_COOKIE];
  if (!isValidToken(sessionToken) || !isValidToken(deviceToken)) return null;

  const sessionHash = await hmacHex(env.AUTH_SECRET, `member-session:${sessionToken}`);
  const deviceHash = await hmacHex(env.AUTH_SECRET, `device:${deviceToken}`);
  const now = unixNow();

  const row = await env.DB.prepare(
    `SELECT s.member_id, s.device_hash AS session_device_hash, s.expires_at,
            m.qq, m.device_hash AS member_device_hash
       FROM member_sessions s
       JOIN members m ON m.id = s.member_id
      WHERE s.token_hash = ?
      LIMIT 1`
  ).bind(sessionHash).first();

  if (!row) return null;
  if (Number(row.expires_at) <= now) {
    await env.DB.prepare("DELETE FROM member_sessions WHERE token_hash = ?").bind(sessionHash).run();
    return null;
  }
  if (!timingSafeEqual(row.session_device_hash, deviceHash)) return null;
  if (!timingSafeEqual(row.member_device_hash, deviceHash)) return null;

  return { id: row.member_id, qq: row.qq };
}

async function tryGetMemberSession(request, env) {
  if (!env.DB || !env.AUTH_SECRET || !env.ADMIN_PASSWORD) return null;
  try {
    return await getMemberSession(request, env);
  } catch (error) {
    console.error("Member session check failed", error);
    return null;
  }
}

async function getAdminSession(request, env) {
  requireRuntimeConfig(env);
  await ensureSchema(env.DB);

  const token = parseCookies(request.headers.get("Cookie") || "")[ADMIN_COOKIE];
  if (!isValidToken(token)) return null;
  const tokenHash = await hmacHex(env.AUTH_SECRET, `admin-session:${token}`);
  const now = unixNow();
  const row = await env.DB.prepare(
    "SELECT expires_at FROM admin_sessions WHERE token_hash = ? LIMIT 1"
  ).bind(tokenHash).first();
  if (!row) return null;
  if (Number(row.expires_at) <= now) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token_hash = ?").bind(tokenHash).run();
    return null;
  }
  return { authenticated: true };
}

function requireRuntimeConfig(env) {
  if (!env.DB) throw new SetupError("Missing D1 binding DB");
  if (typeof env.AUTH_SECRET !== "string" || env.AUTH_SECRET.length < 32) {
    throw new SetupError("Missing or short AUTH_SECRET");
  }
  if (typeof env.ADMIN_PASSWORD !== "string" || env.ADMIN_PASSWORD.length < 8) {
    throw new SetupError("Missing or short ADMIN_PASSWORD");
  }
}

async function ensureSchema(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      qq TEXT NOT NULL UNIQUE,
      access_code_hash TEXT NOT NULL,
      device_hash TEXT,
      created_at INTEGER NOT NULL,
      last_login_at INTEGER
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS member_sessions (
      token_hash TEXT PRIMARY KEY,
      member_id INTEGER NOT NULL,
      device_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS admin_sessions (
      token_hash TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (
      attempt_key TEXT PRIMARY KEY,
      first_attempt_at INTEGER NOT NULL,
      attempt_count INTEGER NOT NULL,
      blocked_until INTEGER NOT NULL DEFAULT 0
    )`),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_member_sessions_member_id ON member_sessions(member_id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_member_sessions_expires_at ON member_sessions(expires_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_members_created_at ON members(created_at)"),
  ]);
  schemaReady = true;
}

async function getBlockedSeconds(db, key) {
  const now = unixNow();
  const row = await db.prepare(
    "SELECT first_attempt_at, attempt_count, blocked_until FROM login_attempts WHERE attempt_key = ? LIMIT 1"
  ).bind(key).first();
  if (!row) return 0;
  if (Number(row.blocked_until) > now) return Number(row.blocked_until) - now;
  if (now - Number(row.first_attempt_at) > LOGIN_WINDOW_SECONDS) {
    await db.prepare("DELETE FROM login_attempts WHERE attempt_key = ?").bind(key).run();
  }
  return 0;
}

async function recordFailure(db, key) {
  const now = unixNow();
  const row = await db.prepare(
    "SELECT first_attempt_at, attempt_count FROM login_attempts WHERE attempt_key = ? LIMIT 1"
  ).bind(key).first();

  if (!row || now - Number(row.first_attempt_at) > LOGIN_WINDOW_SECONDS) {
    await db.prepare(
      "INSERT INTO login_attempts (attempt_key, first_attempt_at, attempt_count, blocked_until) VALUES (?, ?, 1, 0) ON CONFLICT(attempt_key) DO UPDATE SET first_attempt_at = excluded.first_attempt_at, attempt_count = 1, blocked_until = 0"
    ).bind(key, now).run();
    return;
  }

  const count = Number(row.attempt_count) + 1;
  const blockedUntil = count >= LOGIN_MAX_FAILURES ? now + LOGIN_BLOCK_SECONDS : 0;
  await db.prepare(
    "UPDATE login_attempts SET attempt_count = ?, blocked_until = ? WHERE attempt_key = ?"
  ).bind(count, blockedUntil, key).run();
}

async function attemptHash(secret, request, scope) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return hmacHex(secret, `attempt:${scope}:${ip}`);
}

async function readJson(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > MAX_JSON_BYTES) throw new Error("Request body too large");
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_JSON_BYTES) throw new Error("Request body too large");
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

function normalizeQq(value) {
  const qq = String(value ?? "").trim();
  return /^\d{4,12}$/.test(qq) ? qq : "";
}

function normalizeQqSearch(value) {
  return String(value ?? "").replace(/\D/g, "").slice(0, 12);
}

function normalizeAccessCode(value) {
  const code = String(value ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  return code.length >= 8 && code.length <= 16 ? code : "";
}

function randomAccessCode(length) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = "";
  for (const byte of bytes) out += ACCESS_ALPHABET[byte % ACCESS_ALPHABET.length];
  return out;
}

function formatAccessCode(code) {
  return `${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8)}`;
}

function randomToken(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function isValidToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(signature));
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value)));
  return bytesToHex(new Uint8Array(digest));
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  const left = String(a ?? "");
  const right = String(b ?? "");
  if (left.length !== right.length) return false;
  let mismatch = 0;
  for (let i = 0; i < left.length; i += 1) mismatch |= left.charCodeAt(i) ^ right.charCodeAt(i);
  return mismatch === 0;
}

function parseCookies(header) {
  const cookies = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) cookies[name] = value;
  }
  return cookies;
}

function makeCookie(name, value, maxAge, request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${name}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${secure}`;
}

function clearCookie(name, request) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict${secure}`;
}

function isSameOriginRequest(request) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) return false;
  const fetchSite = request.headers.get("Sec-Fetch-Site");
  return fetchSite !== "cross-site";
}

function normalizePath(pathname) {
  if (!pathname) return "/";
  const collapsed = pathname.replace(/\/{2,}/g, "/");
  return collapsed.length > 1 && collapsed.endsWith("/") ? collapsed.slice(0, -1) : collapsed;
}

function mapFriendlyPath(path) {
  const routes = {
    "/": "/index.html",
    "/archive": "/archive.html",
    "/community": "/community.html",
    "/favorites": "/favorites.html",
    "/bubble-studio": "/bubble-studio.html",
  };
  return routes[path] || path;
}

function safeNextPath(value) {
  const next = String(value || "/");
  if (!next.startsWith("/") || next.startsWith("//")) return "/";
  if (next.startsWith("/login") || next.startsWith("/admin") || next.startsWith("/api/")) return "/";
  return next;
}

async function serveAsset(originalRequest, env, pathname) {
  if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") {
    throw new SetupError("Missing ASSETS binding");
  }
  const url = new URL(originalRequest.url);
  url.pathname = pathname;
  const assetRequest = new Request(url.toString(), {
    method: originalRequest.method === "HEAD" ? "HEAD" : "GET",
    headers: originalRequest.headers,
  });
  return env.ASSETS.fetch(assetRequest);
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function methodNotAllowed(allowed) {
  return new Response(JSON.stringify({ ok: false, error: "请求方式不支持。" }), {
    status: 405,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Allow: allowed.join(", "),
    },
  });
}

function redirectResponse(location) {
  return secureResponse(new Response(null, {
    status: 302,
    headers: { Location: location },
  }), "public");
}

function secureResponse(response, mode) {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "no-referrer");
  headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  headers.set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet");
  headers.set("Cache-Control", "private, no-store, max-age=0");
  headers.set("Pragma", "no-cache");
  headers.set(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data: blob: https://cdn.jsdelivr.net https://raw.githubusercontent.com https://i.postimg.cc; media-src 'self' blob:; connect-src 'self' https://api.github.com https://data.jsdelivr.com https://cdn.jsdelivr.net https://raw.githubusercontent.com; worker-src 'self' blob:"
  );
  if (mode === "api") headers.set("Content-Type", headers.get("Content-Type") || "application/json; charset=utf-8");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function setupErrorHtml() {
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cloud Room</title>
<style>body{margin:0;background:#fff;color:#171717;font-family:-apple-system,BlinkMacSystemFont,"PingFang SC",sans-serif;padding:44px 22px}.box{max-width:520px;margin:auto;border:1px solid #ececec;border-radius:16px;padding:24px}.box h1{font-size:18px;margin:0 0 12px}.box p{font-size:13px;line-height:1.8;color:#666;margin:0}</style></head>
<body><div class="box"><h1>Cloud Room 尚未完成初始化</h1><p>请先在 Cloudflare 为项目绑定名为 DB 的 D1 数据库，并添加 AUTH_SECRET 与 ADMIN_PASSWORD 两个加密变量，然后重新部署。</p></div></body></html>`;
}

function unixNow() {
  return Math.floor(Date.now() / 1000);
}
