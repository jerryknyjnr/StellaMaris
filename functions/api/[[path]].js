// Stella Maris portal API (Cloudflare Pages Function). Served at /api/*
const ITER = 100000;            // PBKDF2 iterations (Workers maximum)
const SESSION_HOURS = 12;
const enc = new TextEncoder();

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...extra }
  });
const fail = (msg, status = 400) => json({ error: msg }, status);
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const unhex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
const uid = () => hex(crypto.getRandomValues(new Uint8Array(12)));
const now = () => Date.now();

async function hashPassword(password, saltHex) {
  const salt = saltHex ? unhex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, key, 256);
  return { salt: hex(salt), hash: hex(bits) };
}
async function checkPassword(password, salt, storedHash) {
  const { hash } = await hashPassword(password, salt);
  return hash === storedHash;
}

const cookie = (token, maxAge) =>
  `smc_session=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
function readToken(request) {
  const m = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)smc_session=([a-f0-9]{64})/);
  return m ? m[1] : null;
}
async function currentUser(request, db) {
  const token = readToken(request);
  if (!token) return null;
  const s = await db.prepare("SELECT account_type, account_id, expires_at FROM sessions WHERE token = ?").bind(token).first();
  if (!s || s.expires_at < now()) return null;
  if (s.account_type === "user") {
    const u = await db.prepare("SELECT id, role, username, name FROM users WHERE id = ?").bind(s.account_id).first();
    if (!u) return null;
    const subs = await db.prepare("SELECT subject_id FROM teacher_subjects WHERE user_id = ?").bind(u.id).all();
    return { ...u, subjectIds: subs.results.map(r => r.subject_id) };
  }
  const st = await db.prepare("SELECT id, adm, name, class_id FROM students WHERE id = ?").bind(s.account_id).first();
  if (!st) return null;
  return { id: st.id, role: "student", username: st.adm, name: st.name, classId: st.class_id };
}

export async function onRequest({ request, env, params }) {
  if (!env.DB) return fail("The database is not connected yet. See the setup notes.", 500);
  const route = [].concat(params.path || []).map(p => decodeURIComponent(p)).join("/");
  try {
    return await handle(route, request, env.DB);
  } catch (e) {
    console.error(e);
    if (String(e && e.message).includes("UNIQUE")) return fail("That record already exists.", 409);
    return fail("Something went wrong. Please try again.", 500);
  }
}

async function handle(route, request, db) {
  const method = request.method;
  const [head, id] = route.split("/");
  const body = method === "POST" ? await request.json().catch(() => ({})) : {};
  const search = new URL(request.url).searchParams;

  /* ---------- Public ---------- */
  if (route === "status" && method === "GET") {
    const r = await db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").first();
    return json({ needsSetup: r.n === 0 });
  }
  if (route === "setup" && method === "POST") {
    const r = await db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").first();
    if (r.n > 0) return fail("Setup is already complete.", 403);
    const name = (body.name || "").trim(), username = (body.username || "").trim(), password = body.password || "";
    if (!name || !username || password.length < 8) return fail("Name, username and a password of at least 8 characters are required.");
    const { salt, hash } = await hashPassword(password);
    await db.prepare("INSERT INTO users (id, role, username, name, password_hash, salt) VALUES (?, 'admin', ?, ?, ?, ?)")
      .bind(uid(), username, name, hash, salt).run();
    return json({ ok: true }, 201);
  }
  if (route === "login" && method === "POST") {
    const username = (body.username || "").trim(), password = body.password || "";
    let acct = await db.prepare("SELECT id, password_hash, salt FROM users WHERE username = ?").bind(username).first();
    let type = "user";
    if (!acct) {
      acct = await db.prepare("SELECT id, password_hash, salt FROM students WHERE adm = ?").bind(username).first();
      type = "student";
    }
    if (!acct || !(await checkPassword(password, acct.salt, acct.password_hash)))
      return fail("Incorrect username or password.", 401);
    const token = hex(crypto.getRandomValues(new Uint8Array(32)));
    await db.batch([
      db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now()),
      db.prepare("INSERT INTO sessions (token, account_type, account_id, expires_at) VALUES (?, ?, ?, ?)")
        .bind(token, type, acct.id, now() + SESSION_HOURS * 3600000)
    ]);
    return json({ ok: true }, 200, { "Set-Cookie": cookie(token, SESSION_HOURS * 3600) });
  }
  if (route === "logout" && method === "POST") {
    const token = readToken(request);
    if (token) await db.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
  }

  /* ---------- Signed-in users ---------- */
  const me = await currentUser(request, db);
  if (!me) return fail("Please sign in.", 401);
  const isAdmin = me.role === "admin";
  const forbid = () => fail("You do not have permission to do that.", 403);
  const canTeach = subjectId => isAdmin || (me.subjectIds || []).includes(subjectId);

  if (route === "me" && method === "GET") return json({ user: me });

  if (route === "meta" && method === "GET") {
    const [c, s, t] = await Promise.all([
      db.prepare("SELECT id, name FROM classes ORDER BY name").all(),
      db.prepare("SELECT id, name FROM subjects ORDER BY name").all(),
      db.prepare("SELECT name FROM terms ORDER BY rowid").all()
    ]);
    return json({ classes: c.results, subjects: s.results, terms: t.results.map(r => r.name) });
  }

  if (route === "results" && method === "GET") {
    if (me.role !== "student") return forbid();
    const rows = await db.prepare(
      "SELECT sub.name AS subject, m.score FROM marks m JOIN subjects sub ON sub.id = m.subject_id " +
      "WHERE m.student_id = ? AND m.term = ? ORDER BY sub.name"
    ).bind(me.id, search.get("term") || "").all();
    return json({ results: rows.results });
  }

  /* ---------- Admin: teachers ---------- */
  if (head === "teachers") {
    if (!isAdmin) return forbid();
    if (method === "GET") {
      const [t, ts] = await Promise.all([
        db.prepare("SELECT id, username, name FROM users WHERE role = 'teacher' ORDER BY name").all(),
        db.prepare("SELECT user_id, subject_id FROM teacher_subjects").all()
      ]);
      return json({
        teachers: t.results.map(u => ({
          ...u,
          subjectIds: ts.results.filter(x => x.user_id === u.id).map(x => x.subject_id)
        }))
      });
    }
    if (method === "POST") {
      const name = (body.name || "").trim(), username = (body.username || "").trim(), password = body.password || "";
      const subjectIds = Array.isArray(body.subjectIds) ? body.subjectIds : [];
      if (!name || !username || password.length < 6) return fail("Name, username and a password of at least 6 characters are required.");
      const { salt, hash } = await hashPassword(password);
      const userId = uid();
      await db.batch([
        db.prepare("INSERT INTO users (id, role, username, name, password_hash, salt) VALUES (?, 'teacher', ?, ?, ?, ?)")
          .bind(userId, username, name, hash, salt),
        ...subjectIds.map(sid => db.prepare("INSERT INTO teacher_subjects (user_id, subject_id) VALUES (?, ?)").bind(userId, sid))
      ]);
      return json({ ok: true, id: userId }, 201);
    }
    if (method === "DELETE" && id) {
      await db.batch([
        db.prepare("DELETE FROM teacher_subjects WHERE user_id = ?").bind(id),
        db.prepare("DELETE FROM sessions WHERE account_type = 'user' AND account_id = ?").bind(id),
        db.prepare("DELETE FROM users WHERE id = ? AND role = 'teacher'").bind(id)
      ]);
      return json({ ok: true });
    }
  }

  /* ---------- Admin: classes ---------- */
  if (head === "classes") {
    if (!isAdmin) return forbid();
    if (method === "POST") {
      const name = (body.name || "").trim();
      if (!name) return fail("Enter a class name.");
      await db.prepare("INSERT INTO classes (id, name) VALUES (?, ?)").bind(uid(), name).run();
      return json({ ok: true }, 201);
    }
    if (method === "DELETE" && id) {
      const n = await db.prepare("SELECT COUNT(*) AS n FROM students WHERE class_id = ?").bind(id).first();
      if (n.n > 0) return fail("This class still has students. Move or remove them first.", 409);
      await db.prepare("DELETE FROM classes WHERE id = ?").bind(id).run();
      return json({ ok: true });
    }
  }

  /* ---------- Admin: subjects ---------- */
  if (head === "subjects") {
    if (!isAdmin) return forbid();
    if (method === "POST") {
      const name = (body.name || "").trim();
      if (!name) return fail("Enter a subject name.");
      await db.prepare("INSERT INTO subjects (id, name) VALUES (?, ?)").bind(uid(), name).run();
      return json({ ok: true }, 201);
    }
    if (method === "DELETE" && id) {
      await db.batch([
        db.prepare("DELETE FROM marks WHERE subject_id = ?").bind(id),
        db.prepare("DELETE FROM teacher_subjects WHERE subject_id = ?").bind(id),
        db.prepare("DELETE FROM subjects WHERE id = ?").bind(id)
      ]);
      return json({ ok: true });
    }
  }

  /* ---------- Admin: terms ---------- */
  if (head === "terms") {
    if (!isAdmin) return forbid();
    if (method === "POST") {
      const name = (body.name || "").trim();
      if (!name) return fail("Enter a term name.");
      await db.prepare("INSERT INTO terms (name) VALUES (?)").bind(name).run();
      return json({ ok: true }, 201);
    }
    if (method === "DELETE" && id) {
      const n = await db.prepare("SELECT COUNT(*) AS n FROM marks WHERE term = ?").bind(id).first();
      if (n.n > 0) return fail("This term has marks recorded and cannot be removed.", 409);
      await db.prepare("DELETE FROM terms WHERE name = ?").bind(id).run();
      return json({ ok: true });
    }
  }

  /* ---------- Admin: students ---------- */
  if (head === "students") {
    if (!isAdmin) return forbid();
    if (method === "GET") {
      const r = await db.prepare("SELECT id, adm, name, class_id AS classId FROM students ORDER BY name").all();
      return json({ students: r.results });
    }
    if (method === "POST") {
      const name = (body.name || "").trim(), adm = (body.adm || "").trim(), classId = body.classId, password = body.password || "";
      if (!name || !adm || !classId || password.length < 6) return fail("Name, admission number, class and a password of at least 6 characters are required.");
      const cls = await db.prepare("SELECT 1 FROM classes WHERE id = ?").bind(classId).first();
      if (!cls) return fail("Choose a valid class.");
      const { salt, hash } = await hashPassword(password);
      await db.prepare("INSERT INTO students (id, adm, name, class_id, password_hash, salt) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(uid(), adm, name, classId, hash, salt).run();
      return json({ ok: true }, 201);
    }
    if (method === "DELETE" && id) {
      await db.batch([
        db.prepare("DELETE FROM marks WHERE student_id = ?").bind(id),
        db.prepare("DELETE FROM sessions WHERE account_type = 'student' AND account_id = ?").bind(id),
        db.prepare("DELETE FROM students WHERE id = ?").bind(id)
      ]);
      return json({ ok: true });
    }
  }

  /* ---------- Teacher and admin: marks ---------- */
  if (head === "marks") {
    if (me.role === "student") return forbid();
    if (method === "GET") {
      const classId = search.get("classId"), subjectId = search.get("subjectId"), term = search.get("term");
      if (!classId || !subjectId || !term) return fail("classId, subjectId and term are required.");
      if (!canTeach(subjectId)) return forbid();
      const rows = await db.prepare(
        "SELECT s.id, s.adm, s.name, m.score FROM students s " +
        "LEFT JOIN marks m ON m.student_id = s.id AND m.subject_id = ? AND m.term = ? " +
        "WHERE s.class_id = ? ORDER BY s.name"
      ).bind(subjectId, term, classId).all();
      return json({ students: rows.results });
    }
    if (method === "POST") {
      const { classId, subjectId, term } = body;
      const scores = Array.isArray(body.scores) ? body.scores : [];
      if (!classId || !subjectId || !term) return fail("Class, subject and term are required.");
      if (!canTeach(subjectId)) return forbid();
      const t = await db.prepare("SELECT 1 FROM terms WHERE name = ?").bind(term).first();
      if (!t) return fail("Unknown term.");
      const roster = new Set((await db.prepare("SELECT id FROM students WHERE class_id = ?").bind(classId).all()).results.map(r => r.id));
      const stmts = [];
      for (const { studentId, score } of scores) {
        if (!roster.has(studentId)) return fail("One of the students is not in this class.");
        if (score === null || score === undefined || score === "") {
          stmts.push(db.prepare("DELETE FROM marks WHERE student_id = ? AND subject_id = ? AND term = ?").bind(studentId, subjectId, term));
          continue;
        }
        const n = Number(score);
        if (!Number.isInteger(n) || n < 0 || n > 100) return fail("Scores must be whole numbers from 0 to 100.");
        stmts.push(db.prepare(
          "INSERT INTO marks (student_id, subject_id, term, class_id, score, teacher_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) " +
          "ON CONFLICT(student_id, subject_id, term) DO UPDATE SET score = excluded.score, teacher_id = excluded.teacher_id, updated_at = excluded.updated_at"
        ).bind(studentId, subjectId, term, classId, n, me.id, now()));
      }
      if (stmts.length) await db.batch(stmts);
      return json({ ok: true, saved: stmts.length });
    }
  }

  return fail("Not found.", 404);
}
