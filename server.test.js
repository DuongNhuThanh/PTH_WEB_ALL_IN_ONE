"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { after, before, test } = require("node:test");
const {
  createApplication,
  createAdminFromEnvironment,
  createFirstAdmin,
  openDatabase,
  passwordDigest,
} = require("./server");

const ADMIN_EMAIL = "admin@example.com";
const ADMIN_PASSWORD = "AdminPassword!234";
const USER_EMAIL = "worker@example.com";
const USER_PASSWORD = "WorkerPassword!234";
const PRODUCTION = {
  source: "test.xls",
  processes: ["SMT_WIP", "ELECTRICAL_TEST"],
  hours: [["07:30-08:30", 25, 20]],
  totals: [25, 20],
};

let tempDir;
let db;
let server;
let baseUrl;
let admin;

function createClient() {
  return { cookie: "" };
}

async function request(client, method, route, payload) {
  const headers = {};
  if (payload !== undefined) headers["Content-Type"] = "application/json";
  if (client.cookie) headers.Cookie = client.cookie;
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  const cookie = response.headers.get("set-cookie");
  if (cookie) client.cookie = cookie.split(";", 1)[0];
  const body = await response.text();
  return {
    status: response.status,
    payload: body ? JSON.parse(body) : {},
    response,
  };
}

async function login(client, email, password) {
  const result = await request(client, "POST", "/api/login", { email, password });
  return { status: result.status, payload: result.payload };
}

async function registerAndApprove(email, password = USER_PASSWORD) {
  const registration = await request(admin, "POST", "/api/register", {
    email,
    password,
  });
  assert.equal(registration.status, 201);
  const listing = await request(admin, "GET", "/api/admin/users");
  assert.equal(listing.status, 200);
  const user = listing.payload.users.find((item) => item.email === email);
  assert.ok(user);
  assert.equal(
    (await request(admin, "PATCH", `/api/admin/users/${user.id}`, {
      approved: true,
    })).status,
    200,
  );
  const client = createClient();
  assert.equal((await login(client, email, password)).status, 200);
  return { client, user };
}

before(async () => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pth-dashboard-"));
  const dbPath = path.join(tempDir, "test.sqlite3");
  await createFirstAdmin(ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_PASSWORD, dbPath);
  const application = createApplication({ dbPath });
  db = application.db;
  server = application.server;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  admin = createClient();
  assert.equal((await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD)).status, 200);
});

after(async () => {
  if (server) {
    await new Promise((resolve) => {
      server.close(resolve);
      server.closeAllConnections();
    });
  }
  if (db) db.close();
  if (tempDir) fs.rmSync(tempDir, { recursive: true, force: true });
});

test("auth and approval protect shared data", async () => {
  assert.equal((await request(createClient(), "GET", "/api/state")).status, 401);

  assert.equal(
    (await request(admin, "POST", "/api/register", {
      email: USER_EMAIL,
      password: USER_PASSWORD,
    })).status,
    201,
  );
  const pending = await login(createClient(), USER_EMAIL, USER_PASSWORD);
  assert.equal(pending.status, 403);
  assert.match(pending.payload.error, /chờ/);

  const signedIn = await login(admin, ADMIN_EMAIL, ADMIN_PASSWORD);
  assert.equal(signedIn.status, 200);
  assert.equal(signedIn.payload.user.isAdmin, true);
});

test("account management enforces admin access and revokes sessions", async () => {
  const { client: worker, user } = await registerAndApprove("worker2@example.com");
  const listing = await request(admin, "GET", "/api/admin/users");
  const publicUser = listing.payload.users.find((item) => item.id === user.id);
  assert.ok(publicUser);
  assert.equal("password_hash" in publicUser, false);
  assert.equal("password_salt" in publicUser, false);
  assert.equal(
    (await request(createClient(), "PATCH", `/api/admin/users/${user.id}`, {
      approved: false,
    })).status,
    401,
  );
  assert.equal(
    (await request(worker, "PATCH", `/api/admin/users/${user.id}`, {
      approved: false,
    })).status,
    403,
  );
  assert.equal(
    (await request(admin, "PATCH", `/api/admin/users/${user.id}`, {
      approved: false,
    })).status,
    200,
  );
  assert.equal((await request(worker, "GET", "/api/me")).payload.user, null);
  assert.equal((await request(worker, "GET", "/api/state")).status, 401);

  const lastAdmin = await request(admin, "PATCH", "/api/admin/users/1", {
    approved: false,
  });
  assert.equal(lastAdmin.status, 409);
  assert.match(lastAdmin.payload.error, /cuối cùng/);
});

test("account endpoints reject duplicate and invalid updates", async () => {
  const email = "duplicate@example.com";
  assert.equal(
    (await request(admin, "POST", "/api/register", {
      email,
      password: USER_PASSWORD,
    })).status,
    201,
  );
  assert.equal(
    (await request(admin, "POST", "/api/register", {
      email,
      password: USER_PASSWORD,
    })).status,
    409,
  );
  assert.equal(
    (await request(admin, "PATCH", "/api/admin/users/1", {
      approved: "false",
    })).status,
    400,
  );
  assert.equal(
    (await request(admin, "PATCH", "/api/admin/users/9999", {
      approved: false,
    })).status,
    404,
  );
});

test("bootstrap, IPQC and Excel updates persist in SQLite", async () => {
  const { client } = await registerAndApprove("data-worker@example.com");
  const issue = {
    id: "test-issue-1",
    title: "Kiểm tra mối hàn",
    process: "SMT_WIP",
    detectedAt: "2026-10-27T09:00",
    improvement: "Kiểm tra lại",
    confirmed: false,
  };
  assert.equal(
    (await request(client, "POST", "/api/bootstrap", {
      production: PRODUCTION,
      ipqcIssues: [issue],
    })).status,
    200,
  );
  let state = await request(client, "GET", "/api/state");
  assert.equal(state.status, 200);
  assert.deepEqual(state.payload.production, PRODUCTION);
  assert.deepEqual(state.payload.ipqcIssues, [issue]);

  await request(client, "POST", "/api/bootstrap", {
    production: { ...PRODUCTION, source: "do-not-overwrite.xls" },
    ipqcIssues: [],
  });
  state = await request(client, "GET", "/api/state");
  assert.deepEqual(state.payload.production, PRODUCTION);

  assert.equal(
    (await request(client, "PATCH", `/api/ipqc/${issue.id}`, {
      confirmed: true,
    })).status,
    200,
  );
  state = await request(client, "GET", "/api/state");
  assert.equal(state.payload.ipqcIssues[0].confirmed, true);

  assert.equal(
    (await request(client, "POST", "/api/excel", {
      fileName: "today.xls",
      content: "<table>test</table>",
      production: PRODUCTION,
    })).status,
    200,
  );
  const latest = await request(client, "GET", "/api/latest-excel");
  assert.equal(latest.status, 200);
  assert.equal(latest.payload.content, "<table>test</table>");
  assert.equal((await request(client, "DELETE", `/api/ipqc/${issue.id}`)).status, 200);
  state = await request(client, "GET", "/api/state");
  assert.deepEqual(state.payload.ipqcIssues, []);
});

test("SSE announces shared updates and private files stay unavailable", async () => {
  const { client } = await registerAndApprove("sse-worker@example.com");
  assert.equal(
    (await request(client, "POST", "/api/bootstrap", {
      production: PRODUCTION,
      ipqcIssues: [],
    })).status,
    200,
  );
  const initialState = await request(client, "GET", "/api/state");
  const streamResponse = await fetch(
    `${baseUrl}/api/events?after=${initialState.payload.revision}`,
    { headers: { Cookie: client.cookie } },
  );
  const reader = streamResponse.body.getReader();
  const pendingRead = reader.read();
  await request(client, "POST", "/api/excel", {
    fileName: "update.xls",
    content: "<table>update</table>",
    production: PRODUCTION,
  });
  const readResult = await Promise.race([
    pendingRead,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timed out waiting for SSE event.")), 4000),
    ),
  ]);
  const eventText = new TextDecoder().decode(readResult.value);
  assert.match(eventText, /event: change/);
  await reader.cancel();

  assert.equal((await request(createClient(), "GET", "/server.js")).status, 404);
  const health = await request(createClient(), "GET", "/api/health");
  assert.deepEqual(health.payload, { status: "ok" });
});

test("database schema and password hashes remain compatible with existing SQLite data", async () => {
  const salt = Buffer.from("t".repeat(16));
  const hash = await passwordDigest(ADMIN_PASSWORD, salt);
  assert.equal(
    hash,
    "9ccea834ed7a49ba5facc54e67bdfa4cedd04a7d59b93fc4c129d32f41f4e862",
  );
  const row = db
    .prepare("SELECT id, email, password_hash, password_salt FROM users WHERE email = ?")
    .get(ADMIN_EMAIL);
  assert.ok(row);
  assert.equal(
    await passwordDigest(ADMIN_PASSWORD, Buffer.from(row.password_salt, "hex")),
    row.password_hash,
  );
  assert.equal(db.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM dashboard_data").get().count, 1);
});

test("first-admin creation requires matching passwords and allows only one admin", async () => {
  const dbPath = path.join(tempDir, "first-admin.sqlite3");
  await assert.rejects(
    createFirstAdmin("first@example.com", ADMIN_PASSWORD, "DifferentPassword!234", dbPath),
    /không khớp/,
  );
  await createFirstAdmin("first@example.com", ADMIN_PASSWORD, ADMIN_PASSWORD, dbPath);
  await assert.rejects(
    createFirstAdmin("second@example.com", ADMIN_PASSWORD, ADMIN_PASSWORD, dbPath),
    /Đã có quản trị viên/,
  );
  const firstAdminDb = openDatabase(dbPath);
  assert.equal(
    firstAdminDb.prepare("SELECT COUNT(*) AS count FROM users WHERE is_admin = 1").get().count,
    1,
  );
  firstAdminDb.close();
});

test("Render environment bootstraps only the first admin", async () => {
  const dbPath = path.join(tempDir, "environment-admin.sqlite3");
  const application = createApplication({ dbPath });
  const { db: setupDb } = application;
  const setupServer = application.server;
  await new Promise((resolve) => setupServer.listen(0, "127.0.0.1", resolve));
  try {
    const obsoleteSetup = await fetch(
      `http://127.0.0.1:${setupServer.address().port}/api/setup-admin`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      },
    );
    assert.equal(obsoleteSetup.status, 404);

    assert.equal(
      await createAdminFromEnvironment(setupDb, {}),
      false,
    );
    await assert.rejects(
      createAdminFromEnvironment(setupDb, {
        PTH_ADMIN_EMAIL: "setup-admin@example.com",
      }),
      /cả PTH_ADMIN_EMAIL và PTH_ADMIN_PASSWORD/,
    );
    assert.equal(
      await createAdminFromEnvironment(setupDb, {
        PTH_ADMIN_EMAIL: "setup-admin@example.com",
        PTH_ADMIN_PASSWORD: ADMIN_PASSWORD,
      }),
      true,
    );
    assert.equal(
      await createAdminFromEnvironment(setupDb, {
        PTH_ADMIN_EMAIL: "another-admin@example.com",
        PTH_ADMIN_PASSWORD: ADMIN_PASSWORD,
      }),
      false,
    );

    const registration = await fetch(
      `http://127.0.0.1:${setupServer.address().port}/api/register`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "regular-user@example.com",
          password: USER_PASSWORD,
        }),
      },
    );
    assert.equal(registration.status, 201);
    const accounts = setupDb
      .prepare("SELECT email, is_admin, approved FROM users ORDER BY id")
      .all()
      .map((row) => ({ ...row }));
    assert.deepEqual(accounts, [
      { email: "setup-admin@example.com", is_admin: 1, approved: 1 },
      { email: "regular-user@example.com", is_admin: 0, approved: 0 },
    ]);
  } finally {
    await new Promise((resolve) => {
      setupServer.close(resolve);
      setupServer.closeAllConnections();
    });
    setupDb.close();
  }
});
