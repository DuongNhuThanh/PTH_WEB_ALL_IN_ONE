"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { promisify } = require("node:util");
const { DatabaseSync } = require("node:sqlite");

const ROOT = __dirname;
const DEFAULT_DB = path.join(ROOT, "data", "pth-dashboard.sqlite3");
const COOKIE_NAME = "pth_session";
const SESSION_DAYS = 30;
const MAX_REQUEST_BYTES = 6 * 1024 * 1024;
const MAX_EXCEL_BYTES = 5 * 1024 * 1024;
const PASSWORD_ITERATIONS = 310_000;
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$/;
const pbkdf2 = promisify(crypto.pbkdf2);
const loginFailures = new Map();

class APIError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function nowMs() {
  return Date.now();
}

function databasePath() {
  return path.resolve(process.env.PTH_DB_PATH || DEFAULT_DB);
}

function openDatabase(filePath = databasePath()) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const db = new DatabaseSync(filePath);
  db.exec("PRAGMA foreign_keys = ON");
  db.exec("PRAGMA busy_timeout = 10000");
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      is_admin INTEGER NOT NULL DEFAULT 0,
      approved INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
    CREATE TABLE IF NOT EXISTS dashboard_data (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      production_json TEXT,
      file_name TEXT,
      excel_content TEXT,
      uploaded_by TEXT,
      uploaded_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS ipqc_issues (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      process TEXT NOT NULL,
      detected_at TEXT NOT NULL,
      improvement TEXT NOT NULL DEFAULT '',
      confirmed INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS changes (
      revision INTEGER PRIMARY KEY AUTOINCREMENT,
      change_type TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO dashboard_data (id) VALUES (1);
  `);
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowMs());
  return db;
}

function transaction(db, callback, immediate = false) {
  db.exec(immediate ? "BEGIN IMMEDIATE" : "BEGIN");
  try {
    const result = callback();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
}

function passwordDigest(password, salt) {
  return pbkdf2(password, salt, PASSWORD_ITERATIONS, 32, "sha256").then((digest) =>
    digest.toString("hex"),
  );
}

function validatePassword(password) {
  if (typeof password !== "string" || password.length < 10 || password.length > 256) {
    throw new APIError(400, "Mật khẩu phải có từ 10 đến 256 ký tự.");
  }
  return password;
}

function validateEmail(email) {
  if (typeof email !== "string") {
    throw new APIError(400, "Email không hợp lệ.");
  }
  const normalized = email.trim().toLowerCase();
  if (normalized.length > 254 || !EMAIL_RE.test(normalized)) {
    throw new APIError(400, "Email không hợp lệ.");
  }
  return normalized;
}

function validateProduction(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new APIError(400, "Dữ liệu sản xuất không hợp lệ.");
  }
  const { processes, hours, totals } = value;
  if (
    !Array.isArray(processes) ||
    processes.length < 1 ||
    processes.length > 100 ||
    !processes.every((item) => typeof item === "string" && item.length <= 120) ||
    !Array.isArray(hours) ||
    hours.length > 2000 ||
    !Array.isArray(totals) ||
    totals.length !== processes.length
  ) {
    throw new APIError(400, "Cấu trúc dữ liệu sản xuất không hợp lệ.");
  }
  for (const row of hours) {
    if (
      !Array.isArray(row) ||
      row.length !== processes.length + 1 ||
      typeof row[0] !== "string" ||
      row.slice(1).some((item) => item !== null && !Number.isFinite(item))
    ) {
      throw new APIError(400, "Một dòng dữ liệu sản xuất không hợp lệ.");
    }
  }
  if (totals.some((item) => item !== null && !Number.isFinite(item))) {
    throw new APIError(400, "Tổng sản lượng không hợp lệ.");
  }
  const source = value.source === undefined ? "" : value.source;
  if (typeof source !== "string" || source.length > 255) {
    throw new APIError(400, "Tên nguồn dữ liệu không hợp lệ.");
  }
  return { source, processes, hours, totals };
}

function issueFromPayload(value, issueId) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new APIError(400, "Thông tin IPQC không hợp lệ.");
  }
  const {
    title,
    process,
    detectedAt,
    improvement = "",
    confirmed = false,
  } = value;
  if (
    typeof title !== "string" ||
    !title.trim() ||
    title.length > 140 ||
    typeof process !== "string" ||
    process.length > 120 ||
    typeof detectedAt !== "string" ||
    detectedAt.length > 40 ||
    typeof improvement !== "string" ||
    improvement.length > 1200 ||
    typeof confirmed !== "boolean"
  ) {
    throw new APIError(400, "Thông tin IPQC không hợp lệ.");
  }
  return {
    id: issueId,
    title: title.trim(),
    process,
    detectedAt,
    improvement: improvement.trim(),
    confirmed,
  };
}

function addChange(db, changeType) {
  db.prepare("INSERT INTO changes (change_type, created_at) VALUES (?, ?)").run(
    changeType,
    nowMs(),
  );
  db.exec(
    "DELETE FROM changes WHERE revision < (SELECT MAX(revision) - 500 FROM changes)",
  );
}

function userJson(row) {
  return {
    id: row.id,
    email: row.email,
    isAdmin: Boolean(row.is_admin),
    approved: Boolean(row.approved),
    createdAt: row.created_at,
  };
}

async function createAccount(db, email, password) {
  const salt = crypto.randomBytes(16);
  const hash = await passwordDigest(password, salt);
  try {
    db.prepare(
      `INSERT INTO users (email, password_hash, password_salt, created_at)
       VALUES (?, ?, ?, ?)`,
    ).run(email, hash, salt.toString("hex"), nowMs());
  } catch (error) {
    if (error.errcode === 2067 || error.errcode === 1555) {
      throw new APIError(409, "Email này đã có tài khoản.");
    }
    throw error;
  }
}

function checkLoginLimit(address, timestamp) {
  if (loginFailures.size > 10_000) {
    for (const [failedAddress, stamps] of loginFailures) {
      if (!stamps.some((stamp) => timestamp - stamp < 900_000)) {
        loginFailures.delete(failedAddress);
      }
    }
  }
  const failures = (loginFailures.get(address) || []).filter(
    (stamp) => timestamp - stamp < 900_000,
  );
  loginFailures.set(address, failures);
  if (failures.length >= 10) {
    throw new APIError(
      429,
      "Đăng nhập tạm thời bị giới hạn. Hãy thử lại sau 15 phút.",
    );
  }
}

async function verifyAccountPassword(row, password) {
  const salt = row ? Buffer.from(row.password_salt, "hex") : Buffer.alloc(16);
  const calculated = Buffer.from(await passwordDigest(password, salt), "hex");
  const expected = row ? Buffer.from(row.password_hash, "hex") : Buffer.alloc(32);
  return (
    calculated.length === expected.length &&
    crypto.timingSafeEqual(calculated, expected) &&
    row !== undefined
  );
}

function createUserSession(db, userId) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const expiresAt = nowMs() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(nowMs());
  db.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
  ).run(tokenHash, userId, expiresAt);
  return rawToken;
}

function setAccountApproval(db, userId, approved) {
  transaction(
    db,
    () => {
      const target = db
        .prepare("SELECT id, is_admin FROM users WHERE id = ?")
        .get(userId);
      if (!target) throw new APIError(404, "Không tìm thấy tài khoản.");
      if (target.is_admin && !approved) {
        const remaining = db
          .prepare(
            "SELECT COUNT(*) AS count FROM users WHERE is_admin = 1 AND approved = 1",
          )
          .get().count;
        if (remaining <= 1) {
          throw new APIError(
            409,
            "Không thể thu hồi quyền của quản trị viên cuối cùng.",
          );
        }
      }
      db.prepare("UPDATE users SET approved = ? WHERE id = ?").run(
        Number(approved),
        userId,
      );
      if (!approved) db.prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
      addChange(db, "users");
    },
    true,
  );
}

function parseCookies(header = "") {
  const cookies = new Map();
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try {
      cookies.set(key, decodeURIComponent(value));
    } catch {
      cookies.set(key, value);
    }
  }
  return cookies;
}

function sessionUser(db, request, requireApproved = true) {
  const rawToken = parseCookies(request.headers.cookie).get(COOKIE_NAME);
  if (!rawToken || rawToken.length !== 64) return null;
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const row = db
    .prepare(
      `SELECT users.* FROM sessions
       JOIN users ON users.id = sessions.user_id
       WHERE sessions.token_hash = ? AND sessions.expires_at > ?`,
    )
    .get(tokenHash, nowMs());
  if (!row || (requireApproved && !row.approved)) return null;
  return row;
}

function requireUser(db, request, admin = false) {
  const user = sessionUser(db, request);
  if (!user) {
    throw new APIError(401, "Vui lòng đăng nhập bằng tài khoản đã được duyệt.");
  }
  if (admin && !user.is_admin) {
    throw new APIError(
      403,
      "Chỉ quản trị viên mới có quyền thực hiện thao tác này.",
    );
  }
  return user;
}

function sessionCookie(token, maxAge) {
  const attributes = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${maxAge}`,
  ];
  if (process.env.PTH_COOKIE_SECURE === "1") attributes.push("Secure");
  return attributes.join("; ");
}

function sendJson(response, status, value, headers = {}) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": body.length,
    ...headers,
  });
  response.end(body);
}

async function readJson(request) {
  const rawLength = request.headers["content-length"];
  if (rawLength === undefined) throw new APIError(411, "Thiếu Content-Length.");
  const length = Number(rawLength);
  if (!Number.isSafeInteger(length)) {
    throw new APIError(400, "Content-Length không hợp lệ.");
  }
  if (length < 0 || length > MAX_REQUEST_BYTES) {
    throw new APIError(413, "Yêu cầu vượt quá giới hạn 6 MB.");
  }
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] || "")) {
    throw new APIError(415, "Yêu cầu phải dùng application/json.");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_REQUEST_BYTES || total > length) {
      throw new APIError(413, "Yêu cầu vượt quá giới hạn 6 MB.");
    }
    chunks.push(chunk);
  }
  if (total !== length) throw new APIError(400, "Nội dung yêu cầu không đầy đủ.");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new APIError(400, "JSON không hợp lệ.");
  }
}

function checkOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return;
  let originHost;
  try {
    originHost = new URL(origin).host.toLowerCase();
  } catch {
    throw new APIError(403, "Nguồn yêu cầu không được phép.");
  }
  if (!originHost || originHost !== (request.headers.host || "").toLowerCase()) {
    throw new APIError(403, "Nguồn yêu cầu không được phép.");
  }
}

function addSecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  response.setHeader("X-Frame-Options", "DENY");
}

function sendApiError(response, error) {
  if (response.headersSent) {
    response.end();
    return;
  }
  if (error instanceof APIError) {
    sendJson(response, error.status, { error: error.message });
  } else {
    console.error(error);
    sendJson(response, 500, { error: "Lỗi máy chủ." });
  }
}

function serveStatic(response, requestPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(requestPath);
  } catch {
    throw new APIError(404, "Không tìm thấy trang.");
  }
  let target;
  if (decoded === "" || decoded === "/") {
    target = path.join(ROOT, "index.html");
  } else {
    const segments = decoded.replace(/^\/+/, "").split("/");
    if (
      segments[0] !== "assets" ||
      segments.some((segment) => !segment || segment === "." || segment === "..")
    ) {
      throw new APIError(404, "Không tìm thấy trang.");
    }
    target = path.join(ROOT, ...segments);
  }
  const resolved = path.resolve(target);
  if (resolved !== ROOT && !resolved.startsWith(`${ROOT}${path.sep}`)) {
    throw new APIError(404, "Không tìm thấy tệp.");
  }
  let content;
  try {
    if (!fs.statSync(resolved).isFile()) throw new Error("Not a file");
    content = fs.readFileSync(resolved);
  } catch {
    throw new APIError(404, "Không tìm thấy tệp.");
  }
  const contentTypes = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
  };
  response.writeHead(200, {
    "Content-Type": contentTypes[path.extname(resolved).toLowerCase()] ||
      "application/octet-stream",
    "Cache-Control": "no-store",
    "Content-Length": content.length,
  });
  response.end(content);
}

async function handleRegister(db, response, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new APIError(400, "Thông tin tài khoản không hợp lệ.");
  }
  const email = validateEmail(payload.email);
  await createAccount(db, email, validatePassword(payload.password));
  sendJson(response, 201, {
    message: "Tạo tài khoản thành công. Hãy chờ quản trị viên cấp quyền.",
  });
}

async function handleLogin(db, request, response, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new APIError(400, "Thông tin đăng nhập không hợp lệ.");
  }
  const email = validateEmail(payload.email);
  const password = payload.password;
  if (typeof password !== "string" || password.length > 256) {
    throw new APIError(401, "Email hoặc mật khẩu không chính xác.");
  }
  const address = request.socket.remoteAddress || "unknown";
  const timestamp = nowMs();
  checkLoginLimit(address, timestamp);
  const row = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!row || !(await verifyAccountPassword(row, password))) {
    loginFailures.set(address, [...(loginFailures.get(address) || []), timestamp]);
    throw new APIError(401, "Email hoặc mật khẩu không chính xác.");
  }
  loginFailures.delete(address);
  if (!row.approved) {
    throw new APIError(403, "Tài khoản đang chờ quản trị viên cấp quyền.");
  }
  const token = createUserSession(db, row.id);
  sendJson(
    response,
    200,
    { user: userJson(row) },
    { "Set-Cookie": sessionCookie(token, SESSION_DAYS * 24 * 60 * 60) },
  );
}

function handleLogout(db, request, response) {
  const token = parseCookies(request.headers.cookie).get(COOKIE_NAME);
  if (token) {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
  }
  sendJson(response, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) });
}

function sendState(db, response) {
  const data = db.prepare("SELECT * FROM dashboard_data WHERE id = 1").get();
  const issues = db
    .prepare(
      `SELECT id, title, process, detected_at, improvement, confirmed
       FROM ipqc_issues ORDER BY rowid DESC`,
    )
    .all();
  const revision = db
    .prepare("SELECT COALESCE(MAX(revision), 0) AS revision FROM changes")
    .get().revision;
  sendJson(response, 200, {
    revision,
    production: data.production_json ? JSON.parse(data.production_json) : null,
    latestExcel: data.file_name
      ? {
          fileName: data.file_name,
          uploadedBy: data.uploaded_by,
          uploadedAt: data.uploaded_at,
        }
      : null,
    ipqcIssues: issues.map((row) => ({
      id: row.id,
      title: row.title,
      process: row.process,
      detectedAt: row.detected_at,
      improvement: row.improvement,
      confirmed: Boolean(row.confirmed),
    })),
  });
}

function sendLatestExcel(db, response) {
  const row = db
    .prepare(
      "SELECT file_name, excel_content, uploaded_at FROM dashboard_data WHERE id = 1",
    )
    .get();
  if (!row || !row.file_name) {
    throw new APIError(404, "Chưa có file Excel chung.");
  }
  sendJson(response, 200, {
    fileName: row.file_name,
    content: row.excel_content,
    uploadedAt: row.uploaded_at,
  });
}

function bootstrap(db, request, response, payload) {
  requireUser(db, request);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new APIError(400, "Dữ liệu khởi tạo không hợp lệ.");
  }
  const production = validateProduction(payload.production);
  const rawIssues = payload.ipqcIssues === undefined ? [] : payload.ipqcIssues;
  if (!Array.isArray(rawIssues) || rawIssues.length > 5000) {
    throw new APIError(400, "Danh sách IPQC khởi tạo không hợp lệ.");
  }
  const seenIds = new Set();
  const issues = rawIssues.map((rawIssue) => {
    if (
      !rawIssue ||
      typeof rawIssue !== "object" ||
      typeof rawIssue.id !== "string"
    ) {
      throw new APIError(400, "Ghi nhận IPQC khởi tạo không hợp lệ.");
    }
    const issueId = rawIssue.id;
    if (!/^[A-Za-z0-9_-]{1,80}$/.test(issueId) || seenIds.has(issueId)) {
      throw new APIError(400, "Mã ghi nhận IPQC khởi tạo không hợp lệ.");
    }
    seenIds.add(issueId);
    return issueFromPayload(rawIssue, issueId);
  });
  transaction(db, () => {
    const current = db
      .prepare("SELECT production_json FROM dashboard_data WHERE id = 1")
      .get();
    if (current.production_json === null) {
      db.prepare(
        "UPDATE dashboard_data SET production_json = ? WHERE id = 1",
      ).run(JSON.stringify(production));
      const insert = db.prepare(
        `INSERT OR IGNORE INTO ipqc_issues
         (id, title, process, detected_at, improvement, confirmed)
         VALUES (?, ?, ?, ?, ?, ?)`,
      );
      for (const issue of issues) {
        insert.run(
          issue.id,
          issue.title,
          issue.process,
          issue.detectedAt,
          issue.improvement,
          Number(issue.confirmed),
        );
      }
      addChange(db, "production");
      if (issues.length) addChange(db, "ipqc");
    }
  });
  sendJson(response, 200, { ok: true });
}

function uploadExcel(db, request, response, payload) {
  const user = requireUser(db, request);
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new APIError(400, "Thông tin file Excel không hợp lệ.");
  }
  const { fileName, content } = payload;
  if (
    typeof fileName !== "string" ||
    !fileName.trim() ||
    fileName.length > 255 ||
    path.posix.basename(fileName.replace(/\\/g, "/")) !== fileName ||
    typeof content !== "string" ||
    Buffer.byteLength(content, "utf8") > MAX_EXCEL_BYTES
  ) {
    throw new APIError(
      400,
      "Tên hoặc dung lượng file không hợp lệ (tối đa 5 MB).",
    );
  }
  const production = validateProduction(payload.production);
  transaction(db, () => {
    db.prepare(
      `UPDATE dashboard_data
       SET production_json = ?, file_name = ?, excel_content = ?,
           uploaded_by = ?, uploaded_at = ?
       WHERE id = 1`,
    ).run(
      JSON.stringify(production),
      fileName.trim(),
      content,
      user.email,
      nowMs(),
    );
    addChange(db, "production");
  });
  sendJson(response, 200, { ok: true });
}

function createIssue(db, request, response, payload) {
  requireUser(db, request);
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    typeof payload.id !== "string" ||
    !/^[A-Za-z0-9_-]{1,80}$/.test(payload.id)
  ) {
    throw new APIError(400, "Mã ghi nhận IPQC không hợp lệ.");
  }
  const issue = issueFromPayload(payload, payload.id);
  try {
    transaction(db, () => {
      db.prepare(
        `INSERT INTO ipqc_issues
         (id, title, process, detected_at, improvement, confirmed)
         VALUES (?, ?, ?, ?, ?, ?)`,
      ).run(
        issue.id,
        issue.title,
        issue.process,
        issue.detectedAt,
        issue.improvement,
        Number(issue.confirmed),
      );
      addChange(db, "ipqc");
    });
  } catch (error) {
    if (error.errcode === 1555 || error.errcode === 2067) {
      throw new APIError(409, "Mã ghi nhận IPQC đã tồn tại.");
    }
    throw error;
  }
  sendJson(response, 201, { ok: true });
}

function updateIssue(db, request, response, issueId, payload) {
  requireUser(db, request);
  const row = db.prepare("SELECT * FROM ipqc_issues WHERE id = ?").get(issueId);
  if (!row) throw new APIError(404, "Không tìm thấy ghi nhận IPQC.");
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new APIError(400, "Thông tin IPQC không hợp lệ.");
  }
  const issue = issueFromPayload(
    {
      id: row.id,
      title: row.title,
      process: row.process,
      detectedAt: row.detected_at,
      improvement: row.improvement,
      confirmed: Boolean(row.confirmed),
      ...payload,
    },
    issueId,
  );
  transaction(db, () => {
    db.prepare(
      `UPDATE ipqc_issues SET title = ?, process = ?, detected_at = ?,
       improvement = ?, confirmed = ? WHERE id = ?`,
    ).run(
      issue.title,
      issue.process,
      issue.detectedAt,
      issue.improvement,
      Number(issue.confirmed),
      issueId,
    );
    addChange(db, "ipqc");
  });
  sendJson(response, 200, { ok: true });
}

function deleteIssue(db, request, response, issueId) {
  requireUser(db, request);
  transaction(db, () => {
    const result = db.prepare("DELETE FROM ipqc_issues WHERE id = ?").run(issueId);
    if (result.changes === 0) {
      throw new APIError(404, "Không tìm thấy ghi nhận IPQC.");
    }
    addChange(db, "ipqc");
  });
  sendJson(response, 200, { ok: true });
}

function sendAdminUsers(db, response) {
  const rows = db
    .prepare(
      `SELECT id, email, is_admin, approved, created_at
       FROM users ORDER BY created_at DESC, id DESC`,
    )
    .all();
  sendJson(response, 200, { users: rows.map(userJson) });
}

function updateUserApproval(db, request, response, userId, payload) {
  requireUser(db, request, true);
  if (
    !payload ||
    typeof payload !== "object" ||
    typeof payload.approved !== "boolean"
  ) {
    throw new APIError(400, "Trạng thái cấp quyền không hợp lệ.");
  }
  setAccountApproval(db, userId, payload.approved);
  sendJson(response, 200, { ok: true });
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function sendEvents(db, request, response, url) {
  requireUser(db, request);
  const after = url.searchParams.get("after");
  let revision = Math.max(0, Number.parseInt(after || "0", 10) || 0);
  const lastEventId = request.headers["last-event-id"];
  if (lastEventId) {
    revision = Math.max(revision, Number.parseInt(lastEventId, 10) || 0);
  }
  response.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  response.flushHeaders();
  let closed = false;
  let lastPing = Date.now();
  response.on("close", () => {
    closed = true;
  });
  while (!closed) {
    if (!sessionUser(db, request)) {
      response.write("event: access-revoked\ndata: {}\n\n");
      response.end();
      return;
    }
    const changes = db
      .prepare(
        "SELECT revision, change_type FROM changes WHERE revision > ? ORDER BY revision LIMIT 100",
      )
      .all(revision);
    for (const change of changes) {
      revision = change.revision;
      response.write(
        `id: ${revision}\nevent: change\ndata: ${JSON.stringify({ type: change.change_type })}\n\n`,
      );
    }
    if (Date.now() - lastPing >= 15_000) {
      response.write(": keep-alive\n\n");
      lastPing = Date.now();
    }
    await sleep(500);
  }
}

function createHandler(db) {
  return async (request, response) => {
    addSecurityHeaders(response);
    try {
      const url = new URL(
        request.url,
        `http://${request.headers.host || "localhost"}`,
      );
      if (request.method === "GET") {
        if (url.pathname === "/api/health") {
          sendJson(response, 200, { status: "ok" });
        } else if (url.pathname === "/api/me") {
          const user = sessionUser(db, request, false);
          sendJson(response, 200, { user: user ? userJson(user) : null });
        } else if (url.pathname === "/api/state") {
          requireUser(db, request);
          sendState(db, response);
        } else if (url.pathname === "/api/latest-excel") {
          requireUser(db, request);
          sendLatestExcel(db, response);
        } else if (url.pathname === "/api/admin/users") {
          requireUser(db, request, true);
          sendAdminUsers(db, response);
        } else if (url.pathname === "/api/events") {
          await sendEvents(db, request, response, url);
        } else {
          serveStatic(response, url.pathname);
        }
        return;
      }

      if (request.method === "POST") {
        checkOrigin(request);
        const payload = await readJson(request);
        if (url.pathname === "/api/register") {
          await handleRegister(db, response, payload);
        } else if (url.pathname === "/api/login") {
          await handleLogin(db, request, response, payload);
        } else if (url.pathname === "/api/logout") {
          handleLogout(db, request, response);
        } else if (url.pathname === "/api/bootstrap") {
          bootstrap(db, request, response, payload);
        } else if (url.pathname === "/api/ipqc") {
          createIssue(db, request, response, payload);
        } else if (url.pathname === "/api/excel") {
          uploadExcel(db, request, response, payload);
        } else {
          sendJson(response, 404, { error: "Không tìm thấy API." });
        }
        return;
      }

      if (request.method === "PATCH") {
        checkOrigin(request);
        const payload = await readJson(request);
        const issueMatch = url.pathname.match(/^\/api\/ipqc\/([^/]+)$/);
        const adminMatch = url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
        if (issueMatch) {
          updateIssue(db, request, response, decodeURIComponent(issueMatch[1]), payload);
        } else if (adminMatch) {
          updateUserApproval(db, request, response, Number(adminMatch[1]), payload);
        } else {
          sendJson(response, 404, { error: "Không tìm thấy API." });
        }
        return;
      }

      if (request.method === "DELETE") {
        checkOrigin(request);
        const issueMatch = url.pathname.match(/^\/api\/ipqc\/([^/]+)$/);
        if (!issueMatch) {
          sendJson(response, 404, { error: "Không tìm thấy API." });
          return;
        }
        deleteIssue(db, request, response, decodeURIComponent(issueMatch[1]));
        return;
      }

      sendJson(response, 405, { error: "Phương thức không được hỗ trợ." }, {
        Allow: "GET, POST, PATCH, DELETE",
      });
    } catch (error) {
      sendApiError(response, error);
    }
  };
}

function createApplication(options = {}) {
  const db = openDatabase(options.dbPath || databasePath());
  return {
    db,
    server: options.tls
      ? https.createServer(options.tls, createHandler(db))
      : http.createServer(createHandler(db)),
  };
}

function safePasswordEqual(left, right) {
  const leftBuffer = Buffer.from(left || "", "utf8");
  const rightBuffer = Buffer.from(right || "", "utf8");
  return leftBuffer.length === rightBuffer.length &&
    crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

async function createFirstAdmin(email, password, confirmation, dbPath = databasePath()) {
  const normalized = validateEmail(email);
  validatePassword(password);
  if (!safePasswordEqual(password, confirmation)) {
    throw new Error("Mật khẩu nhập lại không khớp.");
  }
  const db = openDatabase(dbPath);
  try {
    const salt = crypto.randomBytes(16);
    const hash = await passwordDigest(password, salt);
    transaction(
      db,
      () => {
        const existing = db
          .prepare("SELECT COUNT(*) AS count FROM users WHERE is_admin = 1")
          .get().count;
        if (existing) {
          throw new Error(
            "Đã có quản trị viên. Không thể dùng lệnh tạo quản trị viên đầu tiên.",
          );
        }
        db.prepare(
          `INSERT INTO users
           (email, password_hash, password_salt, is_admin, approved, created_at)
           VALUES (?, ?, ?, 1, 1, ?)`,
        ).run(normalized, hash, salt.toString("hex"), nowMs());
      },
      true,
    );
  } finally {
    db.close();
  }
}

function readSecret(promptText) {
  return new Promise((resolve, reject) => {
    const input = process.stdin;
    if (!input.isTTY || typeof input.setRawMode !== "function") {
      reject(new Error("Lệnh tạo admin cần được chạy trong terminal tương tác."));
      return;
    }
    let value = "";
    const onData = (chunk) => {
      for (const character of chunk.toString("utf8")) {
        if (character === "\u0003") {
          input.setRawMode(false);
          input.pause();
          input.removeListener("data", onData);
          reject(new Error("Đã hủy."));
          return;
        }
        if (character === "\r" || character === "\n") {
          input.setRawMode(false);
          input.pause();
          input.removeListener("data", onData);
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (character === "\u007f" || character === "\b") {
          value = value.slice(0, -1);
        } else if (character >= " ") {
          value += character;
        }
      }
    };
    process.stdout.write(promptText);
    input.setRawMode(true);
    input.resume();
    input.on("data", onData);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) => {
    const index = args.indexOf(name);
    return index >= 0 ? args[index + 1] : fallback;
  };
  const adminIndex = args.indexOf("--create-admin");
  if (adminIndex >= 0) {
    const email = args[adminIndex + 1];
    if (!email || email.startsWith("--")) {
      throw new Error("Cần cung cấp email sau --create-admin.");
    }
    const password = await readSecret("Mật khẩu quản trị viên (ít nhất 10 ký tự): ");
    const confirmation = await readSecret("Nhập lại mật khẩu: ");
    await createFirstAdmin(email, password, confirmation);
    console.log(`Đã tạo quản trị viên ${validateEmail(email)} trong ${databasePath()}`);
    return;
  }

  const host = option("--host", process.env.HOST || "0.0.0.0");
  const port = Number(option("--port", process.env.PORT || "8000"));
  const certFile = option("--certfile", null);
  const keyFile = option("--keyfile", null);
  if (Boolean(certFile) !== Boolean(keyFile)) {
    throw new Error("--certfile và --keyfile phải được dùng cùng nhau.");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("--port phải nằm trong khoảng 1 đến 65535.");
  }
  const tls = certFile
    ? {
        cert: fs.readFileSync(path.resolve(certFile)),
        key: fs.readFileSync(path.resolve(keyFile)),
      }
    : null;
  if (tls) process.env.PTH_COOKIE_SECURE ||= "1";
  const { db, server } = createApplication({ tls });
  const scheme = tls ? "https" : "http";
  server.listen(port, host, () => {
    console.log(`PTH dashboard: ${scheme}://${host}:${port}/`);
    console.log(`SQLite database: ${databasePath()}`);
  });
  const shutdown = () => {
    server.close(() => {
      db.close();
      process.exit(0);
    });
    server.closeAllConnections();
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  createApplication,
  createFirstAdmin,
  databasePath,
  openDatabase,
  passwordDigest,
  validateEmail,
  validatePassword,
  validateProduction,
};
