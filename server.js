import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, "public")));

const db = new sqlite3.Database("./database.sqlite");

// ----------------------
// Создание таблиц
// ----------------------
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE,
      password_hash TEXT
    )
  `);

  // Таблицы на будущее (пока не используем, можно оставить)
  db.run(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      name TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS groups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      folder_id INTEGER,
      name TEXT,
      schedule_type TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      group_id INTEGER,
      name TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      group_id INTEGER,
      student_id INTEGER,
      date TEXT,
      mark TEXT
    )
  `);

  // Главное: JSON-состояние журнала на пользователя
  db.run(`
    CREATE TABLE IF NOT EXISTS user_states (
      user_id INTEGER PRIMARY KEY,
      data TEXT
    )
  `);
});

// ----------------------
// JWT middleware
// ----------------------
const SECRET = "SUPER_SECRET_KEY";

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "No token" });
  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET);
    req.userId = decoded.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ----------------------
// AUTH
// ----------------------
app.post("/api/register", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  const hash = bcrypt.hashSync(password, 10);

  db.run(
    `INSERT INTO users (email, password_hash) VALUES (?, ?)`,
    [email, hash],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(400).json({ error: "Email already exists" });
      }
      const token = jwt.sign({ id: this.lastID }, SECRET);
      res.json({ token });
    }
  );
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "DB error" });
    }
    if (!user) return res.status(400).json({ error: "User not found" });

    if (!bcrypt.compareSync(password, user.password_hash)) {
      return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign({ id: user.id }, SECRET);
    res.json({ token });
  });
});

// ----------------------
// STATE (главное API)
// ----------------------
// Получить состояние журнала текущего пользователя
app.get("/api/state", auth, (req, res) => {
  db.get(
    `SELECT data FROM user_states WHERE user_id = ?`,
    [req.userId],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "DB error" });
      }
      if (!row) {
        return res.json({ data: null });
      }
      let parsed = null;
      try {
        parsed = JSON.parse(row.data);
      } catch {
        parsed = null;
      }
      res.json({ data: parsed });
    }
  );
});

// Сохранить состояние журнала
app.post("/api/state", auth, (req, res) => {
  const data = req.body.data || {};
  const dataStr = JSON.stringify(data);

  db.run(
    `
    INSERT INTO user_states (user_id, data)
    VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET data = excluded.data
  `,
    [req.userId, dataStr],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "DB error" });
      }
      res.json({ ok: true });
    }
  );
});

// ----------------------
// Static + fallback
// ----------------------
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("SERVER STARTED on port", PORT);
});
