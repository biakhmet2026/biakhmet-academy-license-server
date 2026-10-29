import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";
import fs from "fs";
import https from "https";
import path from "path";
import { fileURLToPath } from "url";
import { GoogleGenAI } from "@google/genai";
import { Pool } from "pg";
import {
  Document,
  Packer,
  Paragraph,
  HeadingLevel,
  TextRun,
  Table,
  TableRow,
  TableCell,
  WidthType,
  AlignmentType,
  PageBreak,
  BorderStyle,
  VerticalAlign
} from "docx";

dotenv.config();

const app = express();

// ===============================================================
// BMA V58 PRODUCTION SECURITY
// ===============================================================
app.disable("x-powered-by");
app.set("trust proxy", 1);

const allowedOrigins = String(process.env.BMA_ALLOWED_ORIGINS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Windows desktop requests may not send a browser Origin header.
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("CORS origin is not allowed."));
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-bma-admin"],
  }),
);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

app.use(express.json({ limit: "2mb" }));


// ===============================================================
// BMA ЛИЦЕНЗИЯ ЖҮЙЕСІ — POSTGRESQL
// ===============================================================

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL environment variable is missing.");
}

const licensePool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

async function initLicenseDatabase() {
  await licensePool.query(`
    CREATE TABLE IF NOT EXISTS license_users (
      id TEXT PRIMARY KEY,
      login TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      client_name TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      license_until TIMESTAMPTZ NOT NULL,
      max_devices INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ NULL
    );
  `);

  await licensePool.query(`
    CREATE TABLE IF NOT EXISTS license_devices (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES license_users(id) ON DELETE CASCADE,
      device_hash TEXT NOT NULL,
      label TEXT NOT NULL DEFAULT 'Windows PC',
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, device_hash)
    );
  `);

  await licensePool.query(`
    CREATE TABLE IF NOT EXISTS license_sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES license_users(id) ON DELETE CASCADE,
      device_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL
    );
  `);

  await licensePool.query(`
    CREATE INDEX IF NOT EXISTS idx_license_sessions_user
    ON license_sessions(user_id);
  `);

  await licensePool.query(`
    CREATE INDEX IF NOT EXISTS idx_license_sessions_expiry
    ON license_sessions(expires_at);
  `);

  console.log("PostgreSQL license database ready.");
}

function verifyPassword(password, passwordHash) {
  try {
    const [saltHex, hashHex] = String(passwordHash || "").split(":");
    if (!saltHex || !hashHex) return false;
    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");
    const actual = crypto.scryptSync(String(password), salt, 64);
    return expected.length === actual.length &&
      crypto.timingSafeEqual(expected, actual);
  } catch (_) {
    return false;
  }
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64);
  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

function hashDeviceId(deviceId) {
  return crypto
    .createHash("sha256")
    .update(String(deviceId || "unknown-device"))
    .digest("hex");
}

function pgUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    login: row.login,
    passwordHash: row.password_hash,
    clientName: row.client_name,
    active: row.active,
    licenseUntil: row.license_until,
    maxDevices: Number(row.max_devices || 1),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

function licenseState(user) {
  if (!user || user.active === false) {
    return { ok: false, error: "Лицензия белсенді емес." };
  }

  const until = new Date(user.licenseUntil || 0);
  if (!Number.isFinite(until.getTime())) {
    return { ok: false, error: "Лицензия мерзімі дұрыс орнатылмаған." };
  }

  if (until.getTime() < Date.now()) {
    return { ok: false, error: "Лицензия мерзімі аяқталған." };
  }

  return { ok: true, until };
}

async function deleteExpiredSessions() {
  await licensePool.query(
    `DELETE FROM license_sessions WHERE expires_at <= NOW()`
  );
}

async function deviceCount(userId) {
  const result = await licensePool.query(
    `SELECT COUNT(*)::int AS count
     FROM license_devices
     WHERE user_id = $1`,
    [userId],
  );
  return Number(result.rows[0]?.count || 0);
}

app.post("/api/auth/login", async (req, res) => {
  const client = await licensePool.connect();
  try {
    const {
      login = "",
      password = "",
      deviceId = "",
      deviceLabel = "Windows PC",
    } = req.body || {};

    const normalizedLogin = String(login).trim().toLowerCase();
    if (!normalizedLogin || !password) {
      return res.status(400).json({
        ok: false,
        error: "Логин мен парольді енгізіңіз.",
      });
    }

    await client.query("BEGIN");
    await client.query(
      `DELETE FROM license_sessions WHERE expires_at <= NOW()`
    );

    const userResult = await client.query(
      `SELECT *
       FROM license_users
       WHERE LOWER(login) = $1
       LIMIT 1
       FOR UPDATE`,
      [normalizedLogin],
    );

    const user = pgUser(userResult.rows[0]);

    if (!user || !verifyPassword(password, user.passwordHash)) {
      await client.query("ROLLBACK");
      return res.status(401).json({
        ok: false,
        error: "Логин немесе пароль қате.",
      });
    }

    const state = licenseState(user);
    if (!state.ok) {
      await client.query("ROLLBACK");
      return res.status(403).json(state);
    }

    const deviceHash = hashDeviceId(deviceId);

    const deviceResult = await client.query(
      `SELECT *
       FROM license_devices
       WHERE user_id = $1 AND device_hash = $2
       LIMIT 1`,
      [user.id, deviceHash],
    );

    if (deviceResult.rowCount === 0) {
      const countResult = await client.query(
        `SELECT COUNT(*)::int AS count
         FROM license_devices
         WHERE user_id = $1`,
        [user.id],
      );
      const used = Number(countResult.rows[0]?.count || 0);
      const maxDevices = Math.max(1, Number(user.maxDevices || 1));

      if (used >= maxDevices) {
        await client.query("ROLLBACK");
        return res.status(403).json({
          ok: false,
          error: `Құрылғы лимиті толды (${used}/${maxDevices}).`,
        });
      }

      await client.query(
        `INSERT INTO license_devices
          (user_id, device_hash, label, first_seen_at, last_seen_at)
         VALUES ($1, $2, $3, NOW(), NOW())`,
        [
          user.id,
          deviceHash,
          String(deviceLabel || "Windows PC"),
        ],
      );
    } else {
      await client.query(
        `UPDATE license_devices
         SET label = $3, last_seen_at = NOW()
         WHERE user_id = $1 AND device_hash = $2`,
        [
          user.id,
          deviceHash,
          String(deviceLabel || "Windows PC"),
        ],
      );
    }

    const token = crypto.randomBytes(32).toString("hex");
    const sessionExpiresAt = new Date(
      Math.min(
        state.until.getTime(),
        Date.now() + 30 * 24 * 60 * 60 * 1000,
      ),
    );

    await client.query(
      `DELETE FROM license_sessions
       WHERE user_id = $1 AND device_hash = $2`,
      [user.id, deviceHash],
    );

    await client.query(
      `INSERT INTO license_sessions
        (token, user_id, device_hash, created_at, expires_at)
       VALUES ($1, $2, $3, NOW(), $4)`,
      [token, user.id, deviceHash, sessionExpiresAt],
    );

    await client.query(
      `UPDATE license_users
       SET last_login_at = NOW()
       WHERE id = $1`,
      [user.id],
    );

    const usedResult = await client.query(
      `SELECT COUNT(*)::int AS count
       FROM license_devices
       WHERE user_id = $1`,
      [user.id],
    );

    await client.query("COMMIT");

    return res.json({
      ok: true,
      token,
      clientName: user.clientName || user.login,
      login: user.login,
      licenseUntil: user.licenseUntil,
      maxDevices: Number(user.maxDevices || 1),
      usedDevices: Number(usedResult.rows[0]?.count || 0),
    });
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}
    console.error("LICENSE LOGIN ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: "Лицензия серверінде қате пайда болды.",
    });
  } finally {
    client.release();
  }
});

app.post("/api/auth/check", async (req, res) => {
  try {
    const { token = "", deviceId = "" } = req.body || {};
    if (!token) {
      return res.status(401).json({
        ok: false,
        error: "Сессия табылмады.",
      });
    }

    await deleteExpiredSessions();

    const deviceHash = hashDeviceId(deviceId);

    const result = await licensePool.query(
      `SELECT
         s.token,
         s.user_id,
         s.device_hash,
         s.expires_at,
         u.*
       FROM license_sessions s
       JOIN license_users u ON u.id = s.user_id
       WHERE s.token = $1
         AND s.device_hash = $2
         AND s.expires_at > NOW()
       LIMIT 1`,
      [token, deviceHash],
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        ok: false,
        error: "Сессия жарамсыз немесе аяқталған.",
      });
    }

    const user = pgUser(result.rows[0]);
    const state = licenseState(user);

    if (!state.ok) {
      await licensePool.query(
        `DELETE FROM license_sessions WHERE token = $1`,
        [token],
      );
      return res.status(403).json(state);
    }

    await licensePool.query(
      `UPDATE license_devices
       SET last_seen_at = NOW()
       WHERE user_id = $1 AND device_hash = $2`,
      [user.id, deviceHash],
    );

    return res.json({
      ok: true,
      clientName: user.clientName || user.login,
      login: user.login,
      licenseUntil: user.licenseUntil,
      maxDevices: Number(user.maxDevices || 1),
      usedDevices: await deviceCount(user.id),
    });
  } catch (error) {
    console.error("LICENSE CHECK ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: "Лицензияны тексеру қатесі.",
    });
  }
});


// ===============================================================
// BMA ADMIN API — POSTGRESQL
// ===============================================================

const BMA_ADMIN_SECRET = String(process.env.BMA_ADMIN_SECRET || "").trim();

if (!BMA_ADMIN_SECRET) {
  console.error("BMA_ADMIN_SECRET environment variable is missing.");
}

function requireAdmin(req, res, next) {
  const secret = String(req.headers["x-bma-admin"] || "");
  if (!BMA_ADMIN_SECRET) {
    return res.status(503).json({
      ok: false,
      error: "Admin қызметі серверде бапталмаған.",
    });
  }
  if (!secret || secret !== BMA_ADMIN_SECRET) {
    return res.status(401).json({
      ok: false,
      error: "Admin құпиясөзі қате.",
    });
  }
  next();
}

app.get("/api/admin/clients", requireAdmin, async (req, res) => {
  try {
    await deleteExpiredSessions();

    const usersResult = await licensePool.query(
      `SELECT *
       FROM license_users
       ORDER BY LOWER(client_name), LOWER(login)`,
    );

    const devicesResult = await licensePool.query(
      `SELECT user_id, label, first_seen_at, last_seen_at
       FROM license_devices
       ORDER BY first_seen_at`,
    );

    const byUser = new Map();
    for (const d of devicesResult.rows) {
      if (!byUser.has(d.user_id)) byUser.set(d.user_id, []);
      byUser.get(d.user_id).push({
        label: d.label || "Windows PC",
        firstSeenAt: d.first_seen_at || null,
        lastSeenAt: d.last_seen_at || null,
      });
    }

    const clients = usersResult.rows.map((row) => {
      const u = pgUser(row);
      const devices = byUser.get(u.id) || [];
      return {
        id: u.id,
        login: u.login,
        clientName: u.clientName || u.login,
        active: u.active !== false,
        licenseUntil: u.licenseUntil,
        maxDevices: Number(u.maxDevices || 1),
        usedDevices: devices.length,
        devices,
        createdAt: u.createdAt || null,
        lastLoginAt: u.lastLoginAt || null,
      };
    });

    return res.json({ ok: true, clients });
  } catch (error) {
    console.error("ADMIN CLIENT LIST ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: "Клиенттер тізімін оқу қатесі.",
    });
  }
});

app.post("/api/admin/clients", requireAdmin, async (req, res) => {
  try {
    const {
      login = "",
      password = "",
      clientName = "",
      days = 365,
      maxDevices = 1,
    } = req.body || {};

    const normalizedLogin = String(login).trim().toLowerCase();
    if (!normalizedLogin || !String(password)) {
      return res.status(400).json({
        ok: false,
        error: "Логин мен пароль міндетті.",
      });
    }

    const exists = await licensePool.query(
      `SELECT id FROM license_users
       WHERE LOWER(login) = $1
       LIMIT 1`,
      [normalizedLogin],
    );

    if (exists.rowCount > 0) {
      return res.status(409).json({
        ok: false,
        error: "Бұл логин бұрыннан бар.",
      });
    }

    const durationDays = Math.max(1, Number(days || 365));
    const deviceLimit = Math.max(1, Number(maxDevices || 1));
    const id = crypto.randomUUID();
    const licenseUntil = new Date(
      Date.now() + durationDays * 86400000,
    );

    await licensePool.query(
      `INSERT INTO license_users
        (
          id,
          login,
          password_hash,
          client_name,
          active,
          license_until,
          max_devices,
          created_at,
          last_login_at
        )
       VALUES ($1, $2, $3, $4, TRUE, $5, $6, NOW(), NULL)`,
      [
        id,
        normalizedLogin,
        hashPassword(password),
        String(clientName || normalizedLogin).trim(),
        licenseUntil,
        deviceLimit,
      ],
    );

    return res.json({
      ok: true,
      client: {
        id,
        login: normalizedLogin,
        clientName: String(clientName || normalizedLogin).trim(),
        active: true,
        licenseUntil,
        maxDevices: deviceLimit,
        usedDevices: 0,
      },
    });
  } catch (error) {
    console.error("ADMIN ADD CLIENT ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: "Клиент қосу қатесі.",
    });
  }
});

app.post(
  "/api/admin/clients/:id/extend",
  requireAdmin,
  async (req, res) => {
    try {
      const days = Math.max(1, Number(req.body?.days || 365));

      const result = await licensePool.query(
        `UPDATE license_users
         SET license_until =
           GREATEST(license_until, NOW()) +
           ($2::text || ' days')::interval
         WHERE id = $1
         RETURNING license_until`,
        [req.params.id, days],
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          ok: false,
          error: "Клиент табылмады.",
        });
      }

      return res.json({
        ok: true,
        licenseUntil: result.rows[0].license_until,
      });
    } catch (error) {
      console.error("ADMIN EXTEND ERROR:", error);
      return res.status(500).json({
        ok: false,
        error: "Лицензияны ұзарту қатесі.",
      });
    }
  },
);

app.post(
  "/api/admin/clients/:id/status",
  requireAdmin,
  async (req, res) => {
    const client = await licensePool.connect();
    try {
      const active = req.body?.active === true;

      await client.query("BEGIN");

      const result = await client.query(
        `UPDATE license_users
         SET active = $2
         WHERE id = $1
         RETURNING id`,
        [req.params.id, active],
      );

      if (result.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          ok: false,
          error: "Клиент табылмады.",
        });
      }

      if (!active) {
        await client.query(
          `DELETE FROM license_sessions WHERE user_id = $1`,
          [req.params.id],
        );
      }

      await client.query("COMMIT");
      return res.json({ ok: true, active });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}
      console.error("ADMIN STATUS ERROR:", error);
      return res.status(500).json({
        ok: false,
        error: "Статусты өзгерту қатесі.",
      });
    } finally {
      client.release();
    }
  },
);

app.post(
  "/api/admin/clients/:id/password",
  requireAdmin,
  async (req, res) => {
    const client = await licensePool.connect();
    try {
      const password = String(req.body?.password || "");
      if (!password) {
        return res.status(400).json({
          ok: false,
          error: "Жаңа пароль бос болмауы керек.",
        });
      }

      await client.query("BEGIN");

      const result = await client.query(
        `UPDATE license_users
         SET password_hash = $2
         WHERE id = $1
         RETURNING id`,
        [req.params.id, hashPassword(password)],
      );

      if (result.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          ok: false,
          error: "Клиент табылмады.",
        });
      }

      await client.query(
        `DELETE FROM license_sessions WHERE user_id = $1`,
        [req.params.id],
      );

      await client.query("COMMIT");
      return res.json({ ok: true });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}
      console.error("ADMIN PASSWORD ERROR:", error);
      return res.status(500).json({
        ok: false,
        error: "Парольді өзгерту қатесі.",
      });
    } finally {
      client.release();
    }
  },
);

app.post(
  "/api/admin/clients/:id/reset-devices",
  requireAdmin,
  async (req, res) => {
    const client = await licensePool.connect();
    try {
      await client.query("BEGIN");

      const exists = await client.query(
        `SELECT id FROM license_users WHERE id = $1`,
        [req.params.id],
      );

      if (exists.rowCount === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          ok: false,
          error: "Клиент табылмады.",
        });
      }

      await client.query(
        `DELETE FROM license_devices WHERE user_id = $1`,
        [req.params.id],
      );
      await client.query(
        `DELETE FROM license_sessions WHERE user_id = $1`,
        [req.params.id],
      );

      await client.query("COMMIT");
      return res.json({ ok: true });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch (_) {}
      console.error("ADMIN RESET DEVICES ERROR:", error);
      return res.status(500).json({
        ok: false,
        error: "Құрылғыларды босату қатесі.",
      });
    } finally {
      client.release();
    }
  },
);


// ===============================================================
// BMA POSTGRES DIAGNOSTIC
// ===============================================================

app.get("/api/db/health", async (_req, res) => {
  try {
    const result = await licensePool.query(
      `SELECT NOW() AS now,
              (SELECT COUNT(*)::int FROM license_users) AS users`,
    );
    return res.json({
      ok: true,
      database: "postgresql",
      time: result.rows[0].now,
      users: result.rows[0].users,
    });
  } catch (error) {
    console.error("POSTGRES HEALTH ERROR:", error);
    return res.status(500).json({
      ok: false,
      database: "postgresql",
      error: error.message,
    });
  }
});



const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY
});

// Бұрын сізде жұмыс істеген Gemini моделінің атауын осында қалдырамыз.
// Егер модель қатесі шықса, оны бөлек тексереміз.
const MODEL = "gemini-3.5-flash-lite";

function normalizeLanguage(value) {
  return String(value || "kk").toLowerCase().startsWith("ru") ? "ru" : "kk";
}

function languageInstruction(language) {
  return normalizeLanguage(language) === "ru"
    ? "Все текстовые поля ответа пиши полностью на русском языке. Математические формулы и обозначения не переводи."
    : "Барлық мәтіндік өрістерді толық қазақ тілінде жаз. Математикалық формулалар мен белгіленулерді өзгертпе.";
}

function parseJson(text) {
  let value = text;

  // Gemini кейде JSON объектісін JSON-string ретінде қайтарады.
  // Мысалы: "{\\"problems\\":[...]}". Оны бірнеше рет ашамыз.
  for (let i = 0; i < 3; i++) {
    if (typeof value !== "string") break;
    const cleaned = value
      .trim()
      .replace(/^```json\s*/i, "")
      .replace(/^```\s*/, "")
      .replace(/```$/, "")
      .trim();

    try {
      value = JSON.parse(cleaned);
      continue;
    } catch (_) {
      const start = cleaned.indexOf("{");
      const end = cleaned.lastIndexOf("}");
      if (start >= 0 && end >= start) {
        value = JSON.parse(cleaned.slice(start, end + 1));
        continue;
      }
      throw new Error("AI жауабын JSON ретінде оқу мүмкін болмады.");
    }
  }

  return value;
}

// ========================================
// WORD ҮШІН МАТЕМАТИКАЛЫҚ ФОРМАТТАУ
// Дәреже, индекс, түбір, π, көбейту/бөлу,
// теңсіздік және LaTeX-тегі қарапайым бөлшектерді
// Word-та көрнекі етіп шығарады.
// ========================================

function normalizeMathText(input) {
  if (input === null || input === undefined) return "";

  let text = String(input);

  // LaTeX wrappers
  text = text
    .replace(/\$\$/g, "")
    .replace(/\$/g, "")
    .replace(/\\\(/g, "")
    .replace(/\\\)/g, "")
    .replace(/\\\[/g, "")
    .replace(/\\\]/g, "");

  // Common LaTeX commands and symbols
  const replacements = [
    [/\\cdot/g, "×"],
    [/\\times/g, "×"],
    [/\\div/g, "÷"],
    [/\\leq?/g, "≤"],
    [/\\geq?/g, "≥"],
    [/\\neq/g, "≠"],
    [/\\approx/g, "≈"],
    [/\\pm/g, "±"],
    [/\\pi/g, "π"],
    [/\\infty/g, "∞"],
    [/\\sqrt\s*\{([^{}]+)\}/g, "√($1)"],
    [/sqrt\s*\(([^()]+)\)/gi, "√($1)"],
    [/\bpi\b/gi, "π"],
    [/\s\*\s/g, " × "],
    [/\s\/\s/g, " ÷ "],
    [/<=/g, "≤"],
    [/>=/g, "≥"],
    [/!=/g, "≠"],
    [/->/g, "→"],
    [/<-/g, "←"],
  ];

  for (const [pattern, value] of replacements) {
    text = text.replace(pattern, value);
  }

  // \frac{a}{b} -> a⁄b.
  // Word-та көлденең slash-пен болса да математикалық бөлшек ретінде анық көрінеді.
  for (let i = 0; i < 5; i++) {
    const next = text.replace(
      /\\frac\s*\{([^{}]+)\}\s*\{([^{}]+)\}/g,
      "($1)⁄($2)"
    );
    if (next === text) break;
    text = next;
  }

  // \text{...} және қалған қарапайым жақшалар
  text = text
    .replace(/\\text\s*\{([^{}]*)\}/g, "$1")
    .replace(/\\left/g, "")
    .replace(/\\right/g, "")
    .replace(/\\,/g, " ")
    .replace(/\\;/g, " ")
    .replace(/\{([^{}]*)\}/g, "$1");

  return text;
}

function mathTextRuns(input, options = {}) {
  const {
    bold = false,
    size = 22,
    color,
  } = options;

  const text = normalizeMathText(input);
  const runs = [];

  // ^{...}, ^abc, _{...}, _abc форматтарын бөлек TextRun ретінде шығарамыз.
  const tokenRegex = /(\^\{[^{}]+\}|\^[A-Za-zА-Яа-яӘәҒғҚқҢңӨөҰұҮүҺһ0-9+\-]+|_\{[^{}]+\}|_[A-Za-zА-Яа-яӘәҒғҚқҢңӨөҰұҮүҺһ0-9+\-]+)/g;

  let last = 0;
  let match;

  while ((match = tokenRegex.exec(text)) !== null) {
    if (match.index > last) {
      runs.push(
        new TextRun({
          text: text.slice(last, match.index),
          bold,
          size,
          ...(color ? { color } : {}),
        })
      );
    }

    const token = match[0];
    const isSuper = token.startsWith("^");
    let value = token.slice(1);

    if (value.startsWith("{") && value.endsWith("}")) {
      value = value.slice(1, -1);
    }

    runs.push(
      new TextRun({
        text: value,
        bold,
        size: Math.max(16, size - 2),
        superScript: isSuper,
        subScript: !isSuper,
        ...(color ? { color } : {}),
      })
    );

    last = tokenRegex.lastIndex;
  }

  if (last < text.length) {
    runs.push(
      new TextRun({
        text: text.slice(last),
        bold,
        size,
        ...(color ? { color } : {}),
      })
    );
  }

  return runs.length
    ? runs
    : [
        new TextRun({
          text,
          bold,
          size,
          ...(color ? { color } : {}),
        }),
      ];
}

function mathParagraph(text, options = {}) {
  const {
    bold = false,
    size = 22,
    alignment,
    spacingAfter = 80,
    color,
  } = options;

  return new Paragraph({
    ...(alignment ? { alignment } : {}),
    spacing: { after: spacingAfter },
    children: mathTextRuns(text, { bold, size, color }),
  });
}

function mathCell(text, bold = false) {
  return new TableCell({
    margins: { top: 90, bottom: 90, left: 100, right: 100 },
    children: [
      mathParagraph(text, {
        bold,
        size: 21,
        spacingAfter: 40,
      }),
    ],
  });
}

// Серверді тексеру
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    app: "Biakhmet Math Academy"
  });
});

// ========================================
// BMA UI TRANSLATION — ҚАЗ / РУС
// UI мәтіндерін ғана аударады. Лицензия жүйесіне қатысы жоқ.
// ========================================

const uiTranslationCache = new Map();

app.post("/api/ui-translations", async (req, res) => {
  try {
    const language = String(req.body?.language || "ru").toLowerCase();
    const inputTexts = Array.isArray(req.body?.texts)
      ? req.body.texts.map((x) => String(x ?? "")).filter(Boolean)
      : [];

    if (language !== "ru") {
      return res.json({
        ok: true,
        translations: Object.fromEntries(inputTexts.map((t) => [t, t]))
      });
    }

    const unique = [...new Set(inputTexts)].slice(0, 80);
    const translations = {};
    const missing = [];

    for (const text of unique) {
      const key = `ru:${text}`;
      if (uiTranslationCache.has(key)) {
        translations[text] = uiTranslationCache.get(key);
      } else {
        missing.push(text);
      }
    }

    if (missing.length > 0) {
      const prompt = `
Сен кәсіби қазақша → орысша интерфейс аудармашысысың.
Biakhmet Math Academy математика бағдарламасының UI мәтіндерін орыс тіліне аудар.

ҚАТАҢ ТАЛАПТАР:
1. Тек берілген мәтіндерді аудар.
2. Математикалық формулаларды, сандарды, кодтарды, URL, файл аттарын өзгертпе.
3. Biakhmet Math Academy, AI, Word, Windows, 3D, PISA, QR атауларын өзгертпе.
4. Оқу терминдерін Қазақстан мектебінде қолданылатын табиғи орысша терминдермен бер.
5. ҚМЖ → КСП, ҰБТ → ЕНТ, БЖБ → СОР, ТЖБ → СОЧ мағынасында аудар.
6. Егер мәтіннің өзі орысша немесе аударуды қажет етпесе, сол күйінде қалдыр.
7. \\n жол ауыстыруларын және % сияқты белгілерді сақта.
8. JSON кілттері ретінде бастапқы мәтінді ДӘЛ сақта.
9. ТЕК JSON қайтар.

Мәтіндер:
${JSON.stringify(missing)}

Формат:
{
  "translations": {
    "бастапқы мәтін": "орысша аударма"
  }
}
`;

      const response = await ai.models.generateContent({
        model: MODEL,
        contents: prompt,
        config: { responseMimeType: "application/json" }
      });

      if (!response.text) {
        throw new Error("Gemini UI аудармасына бос жауап қайтарды.");
      }

      const data = parseJson(response.text);
      const translated =
        data?.translations && typeof data.translations === "object"
          ? data.translations
          : {};

      for (const text of missing) {
        const value = String(translated[text] ?? text).trim() || text;
        translations[text] = value;
        uiTranslationCache.set(`ru:${text}`, value);
      }
    }

    return res.json({ ok: true, translations });
  } catch (error) {
    console.error("UI TRANSLATION ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: error.message,
      translations: {}
    });
  }
});



// ============================================================================
// BMA VIRTUAL AI TEACHER
// Returns a spoken explanation plus structured virtual-board content.
// Does not modify authentication or license data.
// ============================================================================

// ============================================================================
// BMA AI TEACHER — AZURE KAZAKH NEURAL VOICE (REST + IPv4)
// Uses native Node https because it is more reliable on this Windows/network.
// ============================================================================
function bmaXmlEscape(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function normalizeKazakhForSpeech(text) {
  let s = String(text || "")
    .replace(/\r/g, " ")
    .replace(/[•●▪◦]/g, ". ")
    .replace(/\s+/g, " ")
    .trim();

  // Common formulas/signs -> natural spoken Kazakh.
  s = s
    .replace(/²/g, " квадраты")
    .replace(/³/g, " кубы")
    .replace(/√/g, " түбір ")
    .replace(/≠/g, " тең емес ")
    .replace(/≥/g, " үлкен немесе тең ")
    .replace(/≤/g, " кіші немесе тең ")
    .replace(/=/g, " тең ")
    .replace(/\+/g, " қосу ")
    .replace(/−|–/g, " азайту ")
    .replace(/\*/g, " көбейту ")
    .replace(/\//g, " бөлу ");

  // Make common abbreviations less robotic.
  s = s
    .replace(/\bAI\b/gi, "жасанды интеллект")
    .replace(/\bBMA\b/g, "Би Әм Әй")
    .replace(/\s+/g, " ")
    .replace(/\s+([,.!?;:])/g, "$1");

  return s.trim();
}

function azureSpeechRequest({ key, region, ssml, outputFormat }) {
  return new Promise((resolve, reject) => {
    const options = {
      hostname: `${region}.tts.speech.microsoft.com`,
      port: 443,
      path: "/cognitiveservices/v1",
      method: "POST",
      family: 4,
      headers: {
        "Ocp-Apim-Subscription-Key": key,
        "Content-Type": "application/ssml+xml",
        "X-Microsoft-OutputFormat": outputFormat,
        "User-Agent": "BiakhmetMathAcademy",
        "Content-Length": Buffer.byteLength(ssml, "utf8")
      },
      timeout: 45000
    };

    const req = https.request(options, (response) => {
      const chunks = [];

      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const body = Buffer.concat(chunks);

        if (response.statusCode !== 200) {
          return reject(
            new Error(
              `Azure Speech HTTP ${response.statusCode}: ${body.toString("utf8").slice(0, 300)}`
            )
          );
        }

        resolve(body);
      });
    });

    req.on("timeout", () => {
      req.destroy(new Error("Azure Speech connection timeout"));
    });

    req.on("error", reject);
    req.write(ssml);
    req.end();
  });
}

async function synthesizeBmaSpeech(text, language = "kk") {
  const key = String(process.env.AZURE_SPEECH_KEY || "").trim();
  const region = String(process.env.AZURE_SPEECH_REGION || "").trim();

  // If Azure is not configured, Flutter automatically falls back to Windows TTS.
  if (!key || !region || !String(text || "").trim()) return null;

  const isKk = language === "kk";
  const voice = isKk
    ? String(process.env.AZURE_SPEECH_VOICE_KK || "kk-KZ-AigulNeural")
    : String(process.env.AZURE_SPEECH_VOICE_RU || "ru-RU-SvetlanaNeural");

  const locale = isKk ? "kk-KZ" : "ru-RU";
  const spokenText = isKk
    ? normalizeKazakhForSpeech(text)
    : String(text).trim();

  const ssml = `<speak version="1.0"
    xmlns="http://www.w3.org/2001/10/synthesis"
    xml:lang="${locale}">
    <voice name="${bmaXmlEscape(voice)}">
      <prosody rate="${isKk ? "-8%" : "-4%"}" pitch="0%">
        ${bmaXmlEscape(spokenText)}
      </prosody>
    </voice>
  </speak>`;

  const audio = await azureSpeechRequest({
    key,
    region,
    ssml,
    outputFormat: "audio-24khz-48kbitrate-mono-mp3"
  });

  return {
    audioBase64: audio.toString("base64"),
    mimeType: "audio/mpeg",
    voice,
    spokenText
  };
}

// Optional direct TTS endpoint for diagnostics/retry.
app.post("/api/virtual-teacher/tts", async (req, res) => {
  try {
    const language = normalizeLanguage(req.body?.language);
    const text = String(req.body?.text || "").trim();

    if (!text) {
      return res.status(400).json({ ok: false, error: "text is required" });
    }

    const audio = await synthesizeBmaSpeech(text, language);
    if (!audio) {
      return res.status(503).json({
        ok: false,
        code: "AZURE_SPEECH_NOT_CONFIGURED",
        error: "Azure Speech is not configured"
      });
    }

    return res.json({ ok: true, ...audio });
  } catch (error) {
    console.error("BMA AZURE TTS ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: error.message || "Azure Speech error"
    });
  }
});


// ============================================================================
// BMA AZURE SPEECH-TO-TEXT — direct microphone WAV -> Kazakh/Russian text
// Uses native Node https + IPv4, same reliable approach as Azure TTS.
// ============================================================================
function azureSpeechToTextRequest({ key, region, audio, locale }) {
  return new Promise((resolve, reject) => {
    const requestPath =
      `/speech/recognition/conversation/cognitiveservices/v1` +
      `?language=${encodeURIComponent(locale)}&format=detailed`;

    const options = {
      hostname: `${region}.stt.speech.microsoft.com`,
      port: 443,
      path: requestPath,
      method: "POST",
      family: 4,
      headers: {
        "Ocp-Apim-Subscription-Key": key,
        "Content-Type": "audio/wav; codecs=audio/pcm; samplerate=16000",
        "Accept": "application/json",
        "User-Agent": "BiakhmetMathAcademy",
        "Content-Length": audio.length
      },
      timeout: 45000
    };

    const request = https.request(options, (response) => {
      const chunks = [];

      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");

        let parsed = null;
        try {
          parsed = body ? JSON.parse(body) : {};
        } catch (_) {}

        if (response.statusCode !== 200) {
          return reject(
            new Error(
              `Azure STT HTTP ${response.statusCode}: ${body.slice(0, 500)}`
            )
          );
        }

        resolve(parsed || {});
      });
    });

    request.on("timeout", () => {
      request.destroy(new Error("Azure STT connection timeout"));
    });

    request.on("error", reject);
    request.write(audio);
    request.end();
  });
}

app.post(
  "/api/virtual-teacher/stt",
  express.raw({ type: ["audio/wav", "audio/x-wav"], limit: "20mb" }),
  async (req, res) => {
    try {
      const key = String(process.env.AZURE_SPEECH_KEY || "").trim();
      const region = String(process.env.AZURE_SPEECH_REGION || "").trim();

      if (!key || !region) {
        return res.status(503).json({
          ok: false,
          code: "AZURE_SPEECH_NOT_CONFIGURED",
          error: "AZURE_SPEECH_KEY немесе AZURE_SPEECH_REGION орнатылмаған."
        });
      }

      const language = normalizeLanguage(req.query?.language);
      const locale = language === "ru" ? "ru-RU" : "kk-KZ";
      const audio = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);

      if (audio.length < 1000) {
        return res.status(400).json({
          ok: false,
          error: "Микрофон аудиосы бос немесе тым қысқа."
        });
      }

      const result = await azureSpeechToTextRequest({
        key,
        region,
        audio,
        locale
      });

      const nBestText =
        Array.isArray(result?.NBest) && result.NBest.length > 0
          ? String(
              result.NBest[0]?.Display ||
              result.NBest[0]?.Lexical ||
              result.NBest[0]?.ITN ||
              ""
            ).trim()
          : "";

      const text =
        nBestText ||
        String(result?.DisplayText || result?.Text || "").trim();

      if (!text) {
        return res.json({
          ok: true,
          text: "",
          locale,
          reason: result?.RecognitionStatus || "NoMatch"
        });
      }

      return res.json({
        ok: true,
        text,
        locale,
        reason: result?.RecognitionStatus || "Success"
      });
    } catch (error) {
      console.error("BMA AZURE STT ERROR:", error);
      return res.status(500).json({
        ok: false,
        error: error.message || "Azure Speech-to-Text error"
      });
    }
  }
);


app.post("/api/virtual-teacher", async (req, res) => {
  try {
    const question = String(req.body?.question || "").trim();
    const language = normalizeLanguage(req.body?.language);
    const lessonMode = String(req.body?.lessonMode || "full") === "short" ? "short" : "full";

    if (!question) {
      return res.status(400).json({
        ok: false,
        error: language === "ru"
          ? "Введите вопрос."
          : "Сұрақты енгізіңіз."
      });
    }

    const langRule = language === "ru"
      ? "Отвечай полностью на русском языке."
      : "Толық қазақ тілінде жауап бер.";

    const prompt = `
Сен Biakhmet Math Academy платформасындағы виртуалды AI мұғалімсің.
Оқушы кез келген мектеп пәнінен сұрақ қоя алады: математика, тарих, физика,
химия, биология, география, информатика, тілдер және басқа пәндер.

${langRule}

ҚАЗАҚ ТІЛІНЕ АРНАЛҒАН ҚАТАҢ ЕРЕЖЕ:
${language === "kk" ? `
- Жауап әдеби, табиғи және түсінікті қазақ тілінде болсын.
- Орысша сөздерді, калька тіркестерді және аралас сөйлемдерді қолданба.
- Күрделі термин кездессе, бірден қарапайым қазақша мағынасын түсіндір.
- Әр ойды қысқа, анық сөйлеммен жеткіз.
- Алдымен "Бұл не?" деген сұраққа жауап бер, содан кейін "Неге маңызды?", "Қалай жұмыс істейді?", "Мысал" ретімен түсіндір.
- Оқушыға тікелей сөйлегендей жаз: "Енді мынаған назар аударайық", "Мысалды бірге қарайық", "Есте сақтайтын негізгі ой".
- Сандарды, даталарды, формулаларды жай тізіп шықпай, олардың мағынасын түсіндір.
- Тарихи тақырыпта: кезеңі → негізгі тұлғалар → не болды → себебі → салдары → тарихи маңызы.
- Математикада: анықтама → формула → әр таңбаның мағынасы → бір жеңіл мысал → қадамдық шешу → тексеру.
- Физикада: құбылыс → формула → өлшем бірліктері → өмірлік мысал.
- Биологияда: құрылым → қызметі → процесс → мысал.
- Географияда: орналасуы → ерекшелігі → себептері → әсері → мысал.
- Информатикада: ұғым → не үшін керек → қалай жұмыс істейді → шағын мысал.
- speech мәтіні дауыстап оқуға ыңғайлы болсын: өте ұзын сөйлем жасама, тыныс белгілерін дұрыс қой.
- Қысқартуларды алғаш айтқанда толық атауын бер.
- "қорытындылай келе" сияқты бос сөзді көп қайталама; нақты мазмұн айт.
` : `
- Пиши естественным, понятным русским языком.
- Сложные термины сразу объясняй простыми словами.
`}

Оқушы сұрағы:
${question}

САБАҚ РЕЖИМІ: ${lessonMode === "full" ? "ТОЛЫҚ САБАҚ" : "ҚЫСҚА ТҮСІНДІРУ"}.

МІНДЕТ:
1. Жай жалпы жауап берме. Нақты мұғалім сияқты сабақ өткіз.
2. Алдымен сұрақтың нақты мағынасын анықта. Атауы екіұшты болса, оны ашық айт;
   сенімсіз фактіні ойдан шығарма.
3. ТОЛЫҚ САБАҚ режимінде түсіндіру құрылымы:
   а) қысқа анықтама/кіріспе;
   ә) 3–6 негізгі нақты тармақ;
   б) себеп-салдар немесе қалай жұмыс істейтіні;
   в) кемінде бір нақты мысал;
   г) тақырыптың маңызы;
   ғ) 2–3 сөйлемдік қорытынды.
   Математика/физикада: анықтама → формула → әр таңбаның мағынасы →
   қадамдық мысал → жауапты тексеру.
4. ҚЫСҚА режимде де кемінде анықтама + 3 нақты факт/қадам + қорытынды бер.
5. Тарих/қоғам/саясат тақырыбында даталар, тұлғалар, ұйымдар мен оқиғаларды
   шатастырма. Нақты білмейтін немесе атауы екіұшты нәрсені факт ретінде жазба.
   Саяси тақырыпта бейтарап, оқу-ағартушылық стиль сақта.
6. "speech" — тақтадағы материалмен синхронды, мұғалімнің ауызша сабағы сияқты болсын.
   Құр тізім оқыма. Әр бөлімді бір-бірімен байланыстырып түсіндір.
   Қазақша режимде сөйлеу үлгісі:
   "Алдымен негізгі ұғымды түсініп алайық." →
   "Енді оның не үшін маңызды екенін қарайық." →
   "Мысалды бірге талдайық." →
   "Есте сақтайтын негізгі ой мынау..."
   Формуланы экранда символмен көрсет, ал speech ішінде оны адамға түсінікті сөзбен оқы.
   Бір сөйлемде бір негізгі ой ғана болсын.
   Толық режимде шамамен 300–500 сөз, қысқа режимде 100–180 сөз мақсат ет.
7. "board" — виртуалды тақтада көрсетілетін блоктар. Тақта speech мәтінін
   қайталамай, оны көрнекі түрде толықтырсын.
8. Сұраққа қарай блок түрін ӨЗІҢ таңда:
   - text: анықтама, негізгі ой, қадамдар;
   - formula: математикалық/физикалық формула, content ішінде LaTeX;
   - table: салыстыру немесе деректер; headers және rows міндетті;
   - chart: сандық салыстыру; labels және values міндетті;
   - diagram: процесс/байланыс; nodes массиві міндетті;
   - image: тақырыпты көрнекі көрсету қажет болса SVG иллюстрация.
9. Егер тарихи тұлға (мысалы Абылай хан) сұралса, image блогын міндетті түрде
   қос. SVG — оқу мақсатына арналған стильденген иллюстрация екенін ескер:
   фотосурет деп көрсетпе. Тұлғаның атын SVG ішінде жазуға болады.
10. Геометрия, биология, физика, география сияқты визуалды тақырыпта diagram
   немесе image қолдан.
11. Кесте керек болса table, сандық салыстыру керек болса chart қолдан.
12. Бір жауапта бірнеше түрлі блок қолдануға болады.
13. SVG қауіпсіз болсын: тек <svg>, basic shapes/path/text; script, foreignObject,
   external URL, image href қолданба. viewBox="0 0 800 450" қолдан.
14. Тек JSON қайтар. Markdown code fence қолданба.

JSON форматы:
{
  "speech": "мұғалімнің дауыстап айтатын түсіндірмесі",
  "board": [
    {
      "type": "text",
      "title": "тақырып",
      "content": "мәтін"
    },
    {
      "type": "formula",
      "title": "формула",
      "content": "a^2+b^2=c^2"
    },
    {
      "type": "table",
      "title": "кесте",
      "headers": ["A","B"],
      "rows": [["1","2"],["3","4"]]
    },
    {
      "type": "chart",
      "title": "диаграмма",
      "labels": ["A","B"],
      "values": [10,20]
    },
    {
      "type": "diagram",
      "title": "сызба",
      "nodes": ["1-қадам","2-қадам","3-қадам"]
    },
    {
      "type": "image",
      "title": "иллюстрация",
      "content": "Қысқа сипаттама",
      "svg": "<svg viewBox=\\"0 0 800 450\\" xmlns=\\"http://www.w3.org/2000/svg\\">...</svg>"
    }
  ]
}
`;

    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });

    if (!response.text) {
      throw new Error("AI мұғалім бос жауап қайтарды.");
    }

    const parsed = parseJson(response.text);
    const board = Array.isArray(parsed?.board) ? parsed.board.slice(0, 10) : [];

    // Basic SVG safety filter: never allow active/external content.
    for (const item of board) {
      if (item && item.type === "image" && typeof item.svg === "string") {
        let svg = item.svg.trim();
        svg = svg
          .replace(/<script[\s\S]*?<\/script>/gi, "")
          .replace(/<foreignObject[\s\S]*?<\/foreignObject>/gi, "")
          .replace(/\son\w+\s*=\s*["'][^"']*["']/gi, "")
          .replace(/\s(?:href|xlink:href)\s*=\s*["'][^"']*["']/gi, "");
        if (!svg.startsWith("<svg") || svg.length > 120000) {
          svg = "";
        }
        item.svg = svg;
      }
    }

    const speech = String(parsed?.speech || "");

    let neuralAudio = null;
    try {
      neuralAudio = await synthesizeBmaSpeech(speech, language);
    } catch (ttsError) {
      // Lesson itself must still work if the free Azure voice is temporarily unavailable.
      console.warn("AZURE SPEECH FALLBACK:", ttsError?.message || ttsError);
    }

    return res.json({
      ok: true,
      speech,
      board,
      audioBase64: neuralAudio?.audioBase64 || null,
      audioMimeType: neuralAudio?.mimeType || null,
      voice: neuralAudio?.voice || null,
      spokenText: neuralAudio?.spokenText || speech
    });
  } catch (error) {
    console.error("VIRTUAL TEACHER ERROR:", error);
    return res.status(500).json({
      ok: false,
      error: error.message || "Virtual teacher error"
    });
  }
});


app.get("/api/app-version", (req, res) => {
  const latestVersion = String(
    process.env.BMA_LATEST_VERSION || "1.0.1"
  ).trim();

  const minVersion = String(
    process.env.BMA_MIN_VERSION || "1.0.0"
  ).trim();

  const forceUpdate =
    String(process.env.BMA_FORCE_UPDATE || "false")
      .trim()
      .toLowerCase() === "true";

  const title = String(
    process.env.BMA_UPDATE_TITLE ||
      "Biakhmet Math Academy жаңартуы"
  ).trim();

  const message = String(
    process.env.BMA_UPDATE_MESSAGE ||
      "Жаңа нұсқа қолжетімді. Жаңартуды орнатыңыз."
  ).trim();

  const downloadUrl = String(
    process.env.BMA_UPDATE_URL ||
      "https://github.com/biakhmet2026/biakhmet-math-academy-backend/releases/download/v1.0.1/BiakhmetMathAcademy_Setup_1.0.1.exe"
  ).trim();

  res.set("Cache-Control", "no-store, no-cache, must-revalidate");
  res.json({
    ok: true,
    latestVersion,
    minVersion,
    forceUpdate,
    title,
    message,
    downloadUrl
  });
});

// ========================================
// AI ЕСЕП ҚҰРАСТЫРУ
// ========================================

app.post("/api/generate", async (req, res) => {
  try {
    const {
      grade = 7,
      topic = "Математика",
      count = 5,
      level = "Орташа",
      request = "",
      language = "kk"
    } = req.body;

    const outputLanguage = normalizeLanguage(language);
    const prompt = `
${outputLanguage === "ru" ? "Ты учитель математики школы Казахстана." : "Сен Қазақстан мектебінің математика мұғалімісің."}

Сынып: ${grade}-сынып
Тақырып: ${topic}
Деңгей: ${level}
Есеп саны: ${count}

Оқушының қосымша сұранысы:
${request || "Жоқ"}

Осы талаптарға сәйкес ${count} есеп құрастыр.

Міндетті талаптар:

1. ${languageInstruction(outputLanguage)}
2. Есептер ${grade}-сынып деңгейіне сәйкес болсын.
3. Әр есеп әртүрлі болсын.
4. Математикалық есептеулер дұрыс болсын.
5. Әр есептің нақты жауабы болсын.
6. Әр есепке қадамдық шешу жолын жаз.
7. Оқушыға түсінікті тіл қолдан.
8. Барлық математикалық өрнектерді бірізді форматта жаз:
   - дәреже: x^2, a^n, 10^5;
   - индекс: a_1, x_n;
   - түбір: sqrt(49), sqrt(x+1);
   - π үшін pi;
   - көбейту үшін *;
   - бөлу үшін /;
   - теңсіздік үшін <= және >=;
   - күрделі бөлшек керек болса \frac{a}{b} түрін қолдан.
9. Формуланы жай сөзбен алмастырма. Формула бар жерде формуланың өзін міндетті түрде көрсет.

ТЕК JSON форматында жауап бер.

{
  "problems": [
    {
      "question": "есеп",
      "answer": "жауап",
      "solution": "қадамдық шешу жолы"
    }
  ]
}
`;

    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });

    const text = response.text;

    if (!text) {
      throw new Error("Gemini бос жауап қайтарды.");
    }

    const data = parseJson(text);
    const problems = Array.isArray(data?.problems)
      ? data.problems
          .filter((p) => p && typeof p === "object")
          .map((p) => ({
            question: String(p.question ?? ""),
            answer: String(p.answer ?? ""),
            solution: String(p.solution ?? "")
          }))
      : [];

    if (problems.length === 0) {
      throw new Error("AI есептер тізімін дұрыс форматта қайтармады.");
    }

    res.json({ problems });

  } catch (error) {
    console.error("GENERATE ERROR:", error);

    res.status(500).json({
      error: error.message
    });
  }
});

// ========================================
// ТҮСІНБЕДІМ — AI ТҮСІНДІР
// ========================================

app.post("/api/explain", async (req, res) => {
  try {
    const {
      grade = 7,
      topic = "Математика",
      theory = "",
      formula = "",
      example = "",
      question = "",
      language = "kk"
    } = req.body;

    const outputLanguage = normalizeLanguage(language);
    const prompt = `
${outputLanguage === "ru" ? `Ты учитель математики, объясняющий тему ученику ${grade} класса.` : `Сен ${grade}-сынып оқушысына математика түсіндіретін мұғалімсің.`}
${languageInstruction(outputLanguage)}

Тақырып:
${topic}

Теория:
${theory}

Формула немесе ереже:
${formula}

Мысал:
${example}

Оқушы түсінбеген жері:
${question || "Осы тақырыпты түсінбедім."}

${outputLanguage === "ru" ? "Объясни эту тему ученику ОЧЕНЬ ПРОСТЫМ русским языком." : "Осы тақырыпты оқушыға ӨТЕ ҚАРАПАЙЫМ қазақ тілінде қайта түсіндір."}

Түсіндіру реті:

1. Бұл тақырып не туралы?
2. Негізгі ереже.
3. Формула болса, формуланы түсіндір.
4. Өте жеңіл мысал көрсет.
5. Мысалды қадам-қадаммен шығар.
6. Неліктен дәл солай шығарғаныңды түсіндір.
7. Соңында "Есте сақта" деген қысқа қорытынды жаз.

Күрделі ғылыми сөздерді мүмкіндігінше аз қолдан.

ТЕК JSON қайтар:

{
  "explanation": "толық түсіндіру"
}
`;

    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });

    const text = response.text;

    if (!text) {
      throw new Error("Gemini бос жауап қайтарды.");
    }

    const data = parseJson(text);

    res.json({
      explanation: data.explanation || ""
    });

  } catch (error) {
    console.error("EXPLAIN ERROR:", error);

    res.status(500).json({
      error: error.message
    });
  }
});


// ========================================
// ҚМЖ — AI ГЕНЕРАТОР
// №130 бұйрықтағы міндетті құрылымға негізделген
// ========================================

app.post("/api/generate-kmj", async (req, res) => {
  try {
    const {
      grade = 7,
      classSection = "А",
      subject = "Математика",
      school = "",
      section = "",
      teacher = "",
      date = "",
      topic = "",
      learningObjectiveCode = "",
      learningObjective = "",
      duration = 45,
      lessonType = "Аралас сабақ",
      methods = ["AI өзі таңдасын"],
      customMethods = "",
      extra = "",
      language = "kk"
    } = req.body;

    if (!topic || !learningObjectiveCode || !learningObjective) {
      return res.status(400).json({
        error: "Сабақ тақырыбы, оқу мақсатының коды және оқу мақсаты міндетті."
      });
    }

    const requestedMethods = Array.isArray(methods)
      ? methods.map((m) => String(m)).filter(Boolean)
      : [String(methods || "")].filter(Boolean);

    const methodsText = [
      ...requestedMethods,
      String(customMethods || "").trim()
    ].filter(Boolean).join(", ");

    const outputLanguage = normalizeLanguage(language);
    const prompt = `
${outputLanguage === "ru" ? "Ты опытный учитель математики школы Казахстана." : "Сен Қазақстан мектебіндегі тәжірибелі математика мұғалімісің."}
${outputLanguage === "ru" ? `Составь для ${grade}${classSection} класса ПОЛНЫЙ, ПРАКТИЧЕСКИЙ краткосрочный план урока (КСП), который учитель может сразу использовать на уроке.` : `${grade}${classSection} сыныпқа ТОЛЫҚ, ПРАКТИКАЛЫҚ және МҰҒАЛІМ САБАҚТА ДЕРЕУ ҚОЛДАНА АЛАТЫН\nқысқа мерзімді сабақ жоспарын (ҚМЖ) қазақ тілінде құрастыр.`}
${languageInstruction(outputLanguage)}

НЕГІЗГІ ТАЛАП:
1. ҚМЖ Қазақстандағы №130 бұйрықтағы міндетті нысан логикасын сақтасын:
   - Бөлім
   - Педагогтің Т.А.Ә.
   - Күні
   - Сынып, қатысушылар/қатыспағандар саны
   - Сабақтың тақырыбы
   - Оқу бағдарламасына сәйкес оқыту мақсаттары
   - Сабақтың мақсаты
   - Сабақтың барысы: кезеңі/уақыт | педагогтің әрекеті | оқушының әрекеті | бағалау | ресурстар.
2. Мұғалім енгізген оқу мақсатының кодын және мәтінін ЕШҚАШАН өзгертпе.
3. Жаңа оқу мақсаты кодын ойдан шығарма.
4. Сабақ мақсаты оқу мақсатына тікелей сәйкес, өлшенетін 2–3 нәтиже түрінде жазылсын.
5. Сабақ уақыты дәл ${duration} минут болсын. Барлық кезең минуттарының қосындысы дәл ${duration}.
6. Жоспар жай жалпы сөздерден тұрмасын. Әр кезеңде:
   - мұғалімнің нақты сөзі/нұсқауы;
   - нақты математикалық тапсырмалар немесе есептер;
   - оқушының нақты әрекеті;
   - нақты дескриптор;
   - нақты қалыптастырушы бағалау тәсілі;
   - қолданылатын ресурс болсын.
7. Кемінде:
   - ұйымдастыру/қызығушылықты ояту;
   - алдыңғы білімді тексеру;
   - жаңа білімді түсіндіру немесе еске түсіру;
   - жұптық не топтық жұмыс;
   - жеке жұмыс;
   - бекіту;
   - рефлексия кезеңдері қамтылсын.
8. Тапсырмалар ${grade}-сынып деңгейіне сәйкес болсын. Формулалар мен мысалдар нақты болсын.
9. Саралау үш деңгейде көрінсін: қолдау қажет оқушы, негізгі деңгей, қабілеті жоғары оқушы.
10. ЕБҚ оқушыға нақты қолдау ұсын.
11. Қауіпсіздік, құндылық, пәнаралық байланыс тек орынсыз болса ойдан шығарылмасын; орынды, қысқа жазылсын.
12. Үй тапсырмасы нақты болсын: 3–5 тапсырма немесе нақты нұсқа.
13. Бағалау критерийлері оқу мақсатына сәйкес 2–4 тармақтан тұрсын.
14. Рефлексия нақты әдіспен берілсін.
15. ҚМЖ көлемі қысқа болмауы керек: Word-қа шыққанда шамамен 3–5 бет мазмұн беретіндей толық жаз.
16. ҮЛГІ СТИЛІ:
   - сабақ басында психологиялық ахуал/дәйек сөз немесе қысқа мотивация орынды болса қолдан;
   - «Жылдам есепте» сияқты қысқа бастапқы тапсырма бер;
   - жаңа тақырыпта анықтама + негізгі формула(лар) + кемінде 1 толық мысал көрсет;
   - сабақ ортасында кемінде 3 мазмұнды тапсырма болсын: жұптық/топтық, жеке, өмірмен байланысты немесе функционалдық сауаттылық;
   - әр тапсырмадан кейін 1–4 нақты дескриптор және балл көрсет;
   - сабақ соңында 1–10 балдық қорытынды бағалауға негіз болатын жинақ ұпайын көрсет;
   - кері байланысқа нақты әдіс қолдан: «Түсіндім / Сұрағым бар / Түсінбедім», Exit ticket, Бағдаршам және т.б.
17. ӘДІС-ТӘСІЛДЕР:
   - Мұғалім таңдаған әдістер: ${methodsText || "AI өзі таңдасын"}.
   - Егер «AI өзі таңдасын» бар болса, тақырыпқа сай 3–6 әдісті өзің таңда.
   - Таңдалған әдісті жай атаумен қалдырма: қай кезеңде, қандай тапсырмамен және қалай орындалатынын нақты жаз.
   - Бір әдісті орынсыз қайталама.
18. ФОРМУЛАЛАР МЕН ЕСЕПТЕР:
   - барлық математикалық өрнектерді формула түрінде міндетті түрде көрсет;
   - Word экспорты дұрыс форматтауы үшін мына синтаксисті қолдан:
     дәреже: x^2, a^n, 10^5;
     индекс: a_1, x_n;
     түбір: sqrt(49), sqrt(x+1);
     π: pi;
     көбейту: *;
     бөлу: /;
     теңсіздік: <=, >=, !=;
     күрделі бөлшек: \frac{a}{b};
   - формуланы «икстің квадраты» деп қана жазба, x^2 түрін де бер;
   - әр негізгі формулаға анықтама, белгіленулердің мағынасы және кемінде 1 толық шығарылған мысал бер;
   - тапсырмалардағы есептердің өзінде де формулаларды осы форматпен жаз;
   - геометрияда аудан/көлем/периметр формулаларын, алгебрада теңдеу/дәреже/түбір формулаларын көрнекі бер.
19. КӨРНЕКІЛІК:
   - сурет пайдалы болатын кезеңдерде "visualAid" өрісіне нақты қандай сурет/сызба/кесте керек екенін жаз;
   - мысалы: координаталық жазықтық, геометриялық сызба, статистикалық кесте, қала/ауа райы иллюстрациясы, формула схемасы;
   - сурет қажет емес болса бос жол бер.
20. Markdown, түсіндірме, кіріспе мәтін қоспа. ТЕК JSON қайтар.
21. ${languageInstruction(outputLanguage)}

ДЕРЕКТЕР:
Білім беру ұйымы: ${school}
Пән: ${subject}
Сынып: ${grade}${classSection}
Бөлім: ${section}
Педагог: ${teacher}
Күні: ${date}
Сабақ тақырыбы: ${topic}
Оқу мақсатының коды: ${learningObjectiveCode}
Оқу мақсаты: ${learningObjective}
Сабақ ұзақтығы: ${duration} минут
Сабақ түрі: ${lessonType}
Мұғалім таңдаған әдіс-тәсілдер: ${methodsText || "AI өзі таңдасын"}
Қосымша талап: ${extra}

JSON ФОРМАТЫ:
{
  "lessonGoal": "2–3 өлшенетін сабақ мақсаты",
  "assessmentCriteria": [
    "критерий 1",
    "критерий 2"
  ],
  "values": "сабаққа сәйкес құндылықтар",
  "interdisciplinary": "пәнаралық байланыс",
  "previousKnowledge": "алдыңғы білім",
  "stages": [
    {
      "stage": "Сабақтың басы",
      "minutes": 5,
      "method": "осы кезеңдегі әдіс-тәсіл",
      "theoryFormula": "осы кезеңге қажет анықтама, формула немесе толық мысал",
      "visualAid": "сурет/сызба/кесте ұсынысы немесе бос жол",
      "teacherAction": "мұғалімнің нақты әрекеті, сұрақтары және нақты тапсырма",
      "studentAction": "оқушының нақты әрекеті",
      "assessment": "бағалау тәсілі және нақты дескрипторлар",
      "resources": "нақты ресурстар"
    }
  ],
  "differentiation": {
    "support": "қолдауды қажет ететін оқушыларға",
    "core": "негізгі деңгейге",
    "advanced": "қабілеті жоғары оқушыларға"
  },
  "specialNeedsSupport": "ЕБҚ оқушыға нақты қолдау",
  "safety": "қауіпсіздік/денсаулық сақтау",
  "homework": "нақты үй тапсырмасы",
  "reflection": "нақты рефлексия әдісі және сұрақтары"
}
`;

    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: { responseMimeType: "application/json" }
    });

    if (!response.text) throw new Error("Gemini бос жауап қайтарды.");

    const data = parseJson(response.text);

    const stages = Array.isArray(data?.stages)
      ? data.stages.map((s) => ({
          stage: String(s?.stage ?? ""),
          minutes: Number(s?.minutes ?? 0),
          method: String(s?.method ?? ""),
          theoryFormula: String(s?.theoryFormula ?? ""),
          visualAid: String(s?.visualAid ?? ""),
          teacherAction: String(s?.teacherAction ?? ""),
          studentAction: String(s?.studentAction ?? ""),
          assessment: String(s?.assessment ?? ""),
          resources: String(s?.resources ?? "")
        }))
      : [];

    const criteria = Array.isArray(data?.assessmentCriteria)
      ? data.assessmentCriteria.map((x) => String(x))
      : [];

    const diff = data?.differentiation && typeof data.differentiation === "object"
      ? {
          support: String(data.differentiation.support ?? ""),
          core: String(data.differentiation.core ?? ""),
          advanced: String(data.differentiation.advanced ?? "")
        }
      : { support: "", core: "", advanced: "" };

    if (!data?.lessonGoal || stages.length === 0) {
      throw new Error("AI ҚМЖ-ны толық форматта қайтармады.");
    }

    const totalMinutes = stages.reduce((sum, s) => sum + Number(s.minutes || 0), 0);

    res.json({
      meta: {
        grade,
        classSection,
        subject,
        school,
        section,
        teacher,
        date,
        topic,
        learningObjectiveCode,
        learningObjective,
        duration,
        lessonType,
        methods: methodsText,
        language: outputLanguage
      },
      lessonGoal: String(data.lessonGoal),
      assessmentCriteria: criteria,
      values: String(data.values ?? ""),
      interdisciplinary: String(data.interdisciplinary ?? ""),
      previousKnowledge: String(data.previousKnowledge ?? ""),
      stages,
      differentiation: diff,
      specialNeedsSupport: String(data.specialNeedsSupport ?? ""),
      safety: String(data.safety ?? ""),
      homework: String(data.homework ?? ""),
      reflection: String(data.reflection ?? ""),
      totalMinutes
    });
  } catch (error) {
    console.error("KMJ GENERATE ERROR:", error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// ҚМЖ — WORD
// ========================================

app.post("/api/export-kmj-word", async (req, res) => {
  try {
    const {
      meta = {},
      lessonGoal = "",
      assessmentCriteria = [],
      values = "",
      interdisciplinary = "",
      previousKnowledge = "",
      stages = [],
      differentiation = {},
      specialNeedsSupport = "",
      safety = "",
      homework = "",
      reflection = "",
      language = meta?.language || "kk"
    } = req.body;

    const ru = normalizeLanguage(language) === "ru";
    const w = (kk, ruText) => ru ? ruText : kk;

    const p = (text, bold = false) =>
      mathParagraph(text, { bold, size: 22, spacingAfter: 80 });

    const cell = (text, bold = false) =>
      mathCell(text, bold);

    const schoolName = String(meta.school || "").trim();

    const infoRows = [
      [w("Бөлім", "Раздел"), meta.section || ""],
      [w("Педагогтің Т.А.Ә. (болған жағдайда)", "Ф.И.О. педагога"), meta.teacher || ""],
      [w("Күні", "Дата"), meta.date || ""],
      [
        w("Сынып", "Класс"),
        `${meta.grade || ""}${meta.classSection || ""}    ${w("Қатысушылар саны", "Присутствуют")}: ____    ${w("Қатыспағандар саны", "Отсутствуют")}: ____`
      ],
      [w("Сабақтың тақырыбы", "Тема урока"), meta.topic || ""],
      [
        w("Оқу бағдарламасына сәйкес оқыту мақсаттары", "Цели обучения по учебной программе"),
        `${meta.learningObjectiveCode || ""} ${meta.learningObjective || ""}`
      ],
      [w("Сабақтың мақсаты", "Цель урока"), lessonGoal || ""],
      [w("Қолданылатын әдіс-тәсілдер", "Методы и приёмы"), meta.methods || ""]
    ];

    const infoTable = new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: infoRows.map(([a, b]) =>
        new TableRow({
          children: [cell(a, true), cell(b)]
        })
      )
    });

    const stageRows = [
      new TableRow({
        children: [
          cell(w("Сабақтың кезеңі/уақыт", "Этап урока/время"), true),
          cell(w("Педагогтің әрекеті", "Действия педагога"), true),
          cell(w("Оқушының әрекеті", "Действия ученика"), true),
          cell(w("Бағалау", "Оценивание"), true),
          cell(w("Ресурстар", "Ресурсы"), true)
        ]
      }),
      ...stages.map((s) =>
        new TableRow({
          children: [
            cell(`${s.stage || ""}\n${s.minutes || 0} минут`, true),
            cell(
              [
                s.method ? `${w("Әдіс", "Метод")}: ${s.method}` : "",
                s.theoryFormula ? `${w("Теория/формула", "Теория/формула")}:\n${s.theoryFormula}` : "",
                s.teacherAction || "",
                s.visualAid ? `${w("Көрнекілік/сурет идеясы", "Наглядность/идея изображения")}:\n${s.visualAid}` : ""
              ].filter(Boolean).join("\n\n")
            ),
            cell(s.studentAction || ""),
            cell(s.assessment || ""),
            cell(s.resources || "")
          ]
        })
      )
    ];

    const stageTable = new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: stageRows
    });

    const criteriaText = Array.isArray(assessmentCriteria)
      ? assessmentCriteria.map((x, i) => `${i + 1}. ${x}`).join("\n")
      : String(assessmentCriteria || "");

    const methodRows = [
      [w("Бағалау критерийлері", "Критерии оценивания"), criteriaText],
      [w("Алдыңғы білім", "Предыдущие знания"), previousKnowledge || ""],
      [w("Құндылықтарды дарыту", "Ценности"), values || ""],
      [w("Пәнаралық байланыс", "Межпредметные связи"), interdisciplinary || ""],
      [
        w("Саралау", "Дифференциация"),
        `${w("Қолдау", "Поддержка")}: ${differentiation?.support || ""}\n${w("Негізгі деңгей", "Основной уровень")}: ${differentiation?.core || ""}\n${w("Қабілеті жоғары", "Высокий уровень")}: ${differentiation?.advanced || ""}`
      ],
      [w("ЕБҚ оқушыға қолдау", "Поддержка ученика с ООП"), specialNeedsSupport || ""],
      [w("Қауіпсіздік және денсаулық", "Безопасность и здоровье"), safety || ""],
      [w("Үй тапсырмасы", "Домашнее задание"), homework || ""],
      [w("Рефлексия", "Рефлексия"), reflection || ""],
      [
        "ҚМЖ дизайнына ескерту",
        "Көрнекілік/сурет идеялары сабақ барысындағы сәйкес кезеңдерде берілді. Word-та мұғалім қалаған нақты суретті сол орынға қоса алады. Математикалық өрнектер Word-та дәреже, индекс, түбір, π, ×, ÷, ≤, ≥ белгілерімен автоматты форматталады."
      ]
    ];

    const methodTable = new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: methodRows.map(([a, b]) =>
        new TableRow({
          children: [cell(a, true), cell(b)]
        })
      )
    });

    const children = [];

    if (schoolName) {
      children.push(
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [
            new TextRun({
              text: w("Қазақстан Республикасы Оқу-ағарту министрлігі", "Министерство просвещения Республики Казахстан"),
              bold: true,
              size: 20
            })
          ]
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [new TextRun({ text: schoolName, bold: true, size: 22 })]
        })
      );
    }

    children.push(
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 120, after: 100 },
        children: [
          new TextRun({
            text: w("Қысқа мерзімді (сабақ) жоспары", "Краткосрочный план урока"),
            bold: true,
            size: 30
          })
        ]
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 180 },
        children: [
          new TextRun({
            text: String(meta.topic || ""),
            bold: true,
            size: 24
          })
        ]
      }),
      infoTable,
      new Paragraph({ text: "" }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 120, after: 100 },
        children: [
          new TextRun({ text: w("Сабақтың барысы", "Ход урока"), bold: true, size: 26 })
        ]
      }),
      stageTable,
      new Paragraph({ text: "" }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { before: 120, after: 100 },
        children: [
          new TextRun({
            text: w("Қосымша әдістемелік бөлім", "Дополнительный методический раздел"),
            bold: true,
            size: 24
          })
        ]
      }),
      methodTable
    );

    const doc = new Document({
      sections: [{ children }]
    });

    const buffer = await Packer.toBuffer(doc);
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    res.setHeader("Content-Disposition", 'attachment; filename="KMJ.docx"');
    res.send(buffer);
  } catch (error) {
    console.error("KMJ WORD ERROR:", error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// WORD ФАЙЛ
// ========================================

app.post("/api/export-word", async (req, res) => {
  try {
    const {
      grade = 7,
      topic = "Математика",
      problems = [],
      classSection = "",
      variant = 1,
      language = "kk"
    } = req.body || {};

    const isEntranceTest =
      String(topic).toLowerCase().includes("кіріс") &&
      String(topic).toLowerCase().includes("тест");

    // ======================================================
    // КІРІС ДИАГНОСТИКАЛЫҚ ТЕСТ — ӘДЕМІ WORD БЛАНК
    // ======================================================
    if (isEntranceTest) {
      const BLUE = "173F7A";
      const BLUE2 = "2E5FA8";
      const LIGHT = "F4F8FF";
      const BORDER = "A9C3E8";
      const TEXT = "172554";

      const noBorder = {
        top: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
        bottom: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
        left: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
        right: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
        insideHorizontal: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
        insideVertical: { style: BorderStyle.NONE, size: 0, color: "FFFFFF" },
      };

      const thinBlue = {
        top: { style: BorderStyle.SINGLE, size: 8, color: BORDER },
        bottom: { style: BorderStyle.SINGLE, size: 8, color: BORDER },
        left: { style: BorderStyle.SINGLE, size: 8, color: BORDER },
        right: { style: BorderStyle.SINGLE, size: 8, color: BORDER },
        insideHorizontal: { style: BorderStyle.SINGLE, size: 6, color: "D8E6F8" },
        insideVertical: { style: BorderStyle.SINGLE, size: 6, color: "D8E6F8" },
      };

      const classMatch = String(topic).match(/(\d+)\s*([АӘБВГ])?/i);
      const section = String(classSection || classMatch?.[2] || "").trim().toUpperCase();
      const classLabel = `${grade}${section}`;

      const para = (text, opts = {}) =>
        mathParagraph(text, {
          bold: opts.bold ?? false,
          size: opts.size ?? 22,
          alignment: opts.alignment,
          spacingAfter: opts.spacingAfter ?? 60,
          color: opts.color,
        });

      const plainCell = (children, opts = {}) =>
        new TableCell({
          width: opts.width
            ? { size: opts.width, type: WidthType.PERCENTAGE }
            : undefined,
          columnSpan: opts.columnSpan,
          verticalAlign: opts.verticalAlign ?? VerticalAlign.CENTER,
          shading: opts.fill ? { fill: opts.fill } : undefined,
          borders: opts.borders ?? thinBlue,
          margins: {
            top: opts.margin ?? 90,
            bottom: opts.margin ?? 90,
            left: opts.margin ?? 110,
            right: opts.margin ?? 110,
          },
          children: Array.isArray(children) ? children : [children],
        });

      const titleBlock = () => [
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 70 },
          children: [
            new TextRun({
              text: "Biakhmet Math Academy",
              bold: true,
              size: 38,
              color: BLUE,
              font: "Times New Roman",
            }),
          ],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 60 },
          children: [
            new TextRun({
              text: `${grade}-сынып | ${classLabel} сыныбы`,
              bold: true,
              size: 23,
              color: BLUE2,
              font: "Times New Roman",
            }),
          ],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 170 },
          children: [
            new TextRun({
              text: "КІРІС ДИАГНОСТИКАЛЫҚ ТЕСТ",
              bold: true,
              size: 30,
              color: BLUE,
              font: "Times New Roman",
            }),
          ],
        }),
        new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          borders: thinBlue,
          rows: [
            new TableRow({
              children: [
                plainCell(
                  para(
                    "Оқушының аты-жөні: ______________________________________________",
                    { bold: true, size: 21, color: TEXT, spacingAfter: 0 }
                  ),
                  { width: 70, fill: "FFFFFF" }
                ),
                plainCell(
                  para("Нұсқа: 1", {
                    bold: true,
                    size: 21,
                    color: TEXT,
                    alignment: AlignmentType.CENTER,
                    spacingAfter: 0,
                  }),
                  { width: 30, fill: LIGHT }
                ),
              ],
            }),
            new TableRow({
              children: [
                plainCell(
                  para("Күні: ____________________", {
                    bold: true,
                    size: 21,
                    color: TEXT,
                    spacingAfter: 0,
                  }),
                  { width: 70 }
                ),
                plainCell(
                  para(`Сынып: ${classLabel}`, {
                    bold: true,
                    size: 21,
                    color: TEXT,
                    alignment: AlignmentType.CENTER,
                    spacingAfter: 0,
                  }),
                  { width: 30 }
                ),
              ],
            }),
          ],
        }),
        new Paragraph({ text: "", spacing: { after: 50 } }),
        new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          borders: thinBlue,
          rows: [
            new TableRow({
              children: [
                plainCell(
                  para(
                    "ⓘ Нұсқау: Төмендегі тапсырмалардан дұрыс жауаптың біреуін таңдап, белгілеңіз.",
                    { bold: true, size: 20, color: BLUE, spacingAfter: 0 }
                  ),
                  { fill: LIGHT }
                ),
              ],
            }),
          ],
        }),
        new Paragraph({ text: "", spacing: { after: 100 } }),
      ];

      function parseProblem(problem, index) {
        const structuredQuestion = String(
          problem?.question ?? problem?.text ?? problem?.task ?? problem?.prompt ?? ""
        ).trim();

        const structuredOptions = Array.isArray(problem?.options)
          ? problem.options.slice(0, 4).map((x, i) => ({
              letter: String.fromCharCode(65 + i),
              text: String(x ?? "").trim(),
            }))
          : [];

        if (structuredQuestion && structuredOptions.length === 4) {
          return {
            number: Number(problem?.number) || index + 1,
            question: structuredQuestion.replace(/^\s*\d+\.\s*/, ""),
            options: structuredOptions,
            correctAnswer: String(problem?.correctAnswer ?? "").trim().toUpperCase(),
            skill: String(problem?.skill ?? "").trim(),
          };
        }

        const raw = String(
          problem?.problem ?? problem?.question ?? problem?.text ??
          problem?.task ?? problem?.prompt ?? ""
        ).trim();

        const lines = raw.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
        let question = lines.shift() || "";
        question = question.replace(/^\s*\d+\.\s*/, "");

        const options = [];
        for (const line of lines) {
          const m = line.match(/^([ABCDАВСД])\)\s*(.*)$/i);
          if (m) {
            const latinMap = { "А": "A", "В": "B", "С": "C", "Д": "D" };
            const letter = latinMap[m[1].toUpperCase()] || m[1].toUpperCase();
            options.push({ letter, text: m[2] });
          } else if (options.length < 4) {
            options.push({
              letter: String.fromCharCode(65 + options.length),
              text: line,
            });
          }
        }

        return {
          number: index + 1,
          question,
          options: options.slice(0, 4),
          correctAnswer: String(problem?.correctAnswer ?? "").trim().toUpperCase(),
          skill: String(problem?.skill ?? "").trim(),
        };
      }
      const parsed = problems.map(parseProblem);
      const children = [];

      children.push(...titleBlock());

      parsed.forEach((q, idx) => {
        // 3 content pages: 1-7, 8-14, 15-20.
        if (idx === 7 || idx === 14) {
          children.push(
            new Paragraph({
              children: [new PageBreak()],
            })
          );
        }

        const numberCell = plainCell(
          para(String(q.number), {
            bold: true,
            size: 22,
            color: "FFFFFF",
            alignment: AlignmentType.CENTER,
            spacingAfter: 0,
          }),
          {
            width: 8,
            fill: BLUE2,
            margin: 80,
          }
        );

        const questionCell = plainCell(
          para(q.question, {
            bold: true,
            size: 22,
            color: TEXT,
            spacingAfter: 0,
          }),
          {
            width: 92,
            fill: "FFFFFF",
          }
        );

        children.push(
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            borders: noBorder,
            rows: [
              new TableRow({
                children: [numberCell, questionCell],
              }),
            ],
          })
        );

        const opts = [...q.options];
        while (opts.length < 4) {
          opts.push({
            letter: String.fromCharCode(65 + opts.length),
            text: "",
          });
        }

        const optionCell = (opt) =>
          plainCell(
            new Paragraph({
              spacing: { after: 0 },
              children: [
                new TextRun({
                  text: `☐ ${opt.letter}) `,
                  bold: true,
                  size: 20,
                  color: TEXT,
                  font: "Times New Roman",
                }),
                ...mathTextRuns(opt.text, {
                  bold: false,
                  size: 20,
                  color: TEXT,
                }),
              ],
            }),
            {
              width: 50,
              fill: "FFFFFF",
              margin: 75,
            }
          );

        children.push(
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            borders: thinBlue,
            rows: [
              new TableRow({
                children: [optionCell(opts[0]), optionCell(opts[1])],
              }),
              new TableRow({
                children: [optionCell(opts[2]), optionCell(opts[3])],
              }),
            ],
          }),
          new Paragraph({
            text: "",
            spacing: { after: 85 },
          })
        );
      });

      // Teacher answer key on a separate final page.
      const hasKey = parsed.some((q) => q.correctAnswer);

      if (hasKey) {
        children.push(
          new Paragraph({
            children: [new PageBreak()],
          }),
          new Paragraph({
            alignment: AlignmentType.CENTER,
            spacing: { after: 180 },
            children: [
              new TextRun({
                text: "🔑 ЖАУАП КІЛТІ",
                bold: true,
                size: 32,
                color: BLUE,
                font: "Times New Roman",
              }),
            ],
          })
        );

        const groups = [];
        for (let start = 0; start < parsed.length; start += 10) {
          groups.push(parsed.slice(start, start + 10));
        }

        for (const group of groups) {
          children.push(
            new Table({
              width: { size: 100, type: WidthType.PERCENTAGE },
              borders: thinBlue,
              rows: [
                new TableRow({
                  children: group.map((q) =>
                    plainCell(
                      para(String(q.number), {
                        bold: true,
                        size: 19,
                        color: "FFFFFF",
                        alignment: AlignmentType.CENTER,
                        spacingAfter: 0,
                      }),
                      {
                        fill: BLUE2,
                        width: 10,
                        margin: 70,
                      }
                    )
                  ),
                }),
                new TableRow({
                  children: group.map((q) =>
                    plainCell(
                      para(q.correctAnswer || "—", {
                        bold: true,
                        size: 21,
                        color: TEXT,
                        alignment: AlignmentType.CENTER,
                        spacingAfter: 0,
                      }),
                      {
                        width: 10,
                        margin: 70,
                      }
                    )
                  ),
                }),
              ],
            }),
            new Paragraph({ text: "", spacing: { after: 140 } })
          );
        }

        children.push(
          new Table({
            width: { size: 100, type: WidthType.PERCENTAGE },
            borders: thinBlue,
            rows: [
              new TableRow({
                children: [
                  plainCell(
                    para(
                      "★ Есіңе сен! Білім — сенің ең үлкен күшің! Сәттілік!",
                      {
                        bold: true,
                        size: 22,
                        color: BLUE,
                        alignment: AlignmentType.CENTER,
                        spacingAfter: 0,
                      }
                    ),
                    { fill: LIGHT, margin: 130 }
                  ),
                ],
              }),
            ],
          })
        );
      }

      const doc = new Document({
        sections: [
          {
            properties: {
              page: {
                margin: {
                  top: 850,
                  right: 850,
                  bottom: 800,
                  left: 850,
                },
              },
            },
            children,
          },
        ],
      });

      const buffer = await Packer.toBuffer(doc);

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${grade}_Entrance_Diagnostic_Test.docx"`
      );
      return res.send(buffer);
    }

    // ======================================================
    // КӘДІМГІ AI ЕСЕПТЕР — бұрынғы Word экспорты
    // ======================================================
    const children = [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 100 },
        children: [
          new TextRun({
            text: "Biakhmet Math Academy",
            bold: true,
            size: 34,
          }),
        ],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 180 },
        children: [
          ...mathTextRuns(`${grade}-сынып | ${topic}`, {
            bold: true,
            size: 24,
          }),
        ],
      }),
    ];

    problems.forEach((problem, index) => {
      let question = String(
        problem?.question ??
        problem?.problem ??
        problem?.text ??
        problem?.task ??
        problem?.prompt ??
        ""
      ).trim();

      question = question.replace(/^\s*\d+\.\s*/, "");

      const answer = String(
        problem?.answer ??
        problem?.correctAnswer ??
        ""
      ).trim();

      const solution = String(
        problem?.solution ??
        problem?.solutionText ??
        problem?.explanation ??
        ""
      ).trim();

      children.push(
        new Paragraph({
          spacing: { before: 160, after: 80 },
          children: [
            new TextRun({
              text: `${index + 1}. `,
              bold: true,
              size: 24,
            }),
            ...mathTextRuns(question || "Сұрақ мәтіні табылмады", {
              bold: true,
              size: 24,
            }),
          ],
        })
      );

      if (answer) {
        children.push(
          new Paragraph({
            spacing: { after: 70 },
            children: [
              new TextRun({
                text: "Жауабы: ",
                bold: true,
                size: 22,
              }),
              ...mathTextRuns(answer, {
                bold: true,
                size: 22,
              }),
            ],
          })
        );
      }

      if (solution) {
        children.push(
          new Paragraph({
            spacing: { after: 110 },
            children: [
              new TextRun({
                text: "Шешу жолы: ",
                bold: true,
                size: 22,
              }),
              ...mathTextRuns(solution, {
                size: 22,
              }),
            ],
          })
        );
      }
    });

    const doc = new Document({
      sections: [{ children }],
    });

    const buffer = await Packer.toBuffer(doc);

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="Biakhmet_Math_Academy.docx"'
    );

    res.send(buffer);
  } catch (error) {
    console.error("WORD EXPORT ERROR:", error);
    res.status(500).json({
      error: error.message,
    });
  }
});


// ========================================
// КІРІС ДИАГНОСТИКАСЫ: ТАЛДАУ + ОЛҚЫЛЫҚ ЖОСПАРЫ WORD
// ========================================

app.post("/api/export-analysis-word", async (req, res) => {
  try {
    const {
      grade = 7,
      classSection = "",
      studentCount = 0,
      students = [],
      gaps = [],
    } = req.body || {};

    const classLabel = `${grade}${String(classSection || "").trim().toUpperCase()}`;

    const thin = { style: BorderStyle.SINGLE, size: 4, color: "D8DEEA" };
    const cellBorders = { top: thin, bottom: thin, left: thin, right: thin };

    const title = new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 90 },
      children: [
        new TextRun({
          text: "BIAKHMET MATH ACADEMY",
          bold: true,
          size: 32,
          color: "253AA5",
        }),
      ],
    });

    const subtitle = new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 80 },
      children: [
        new TextRun({
          text: `${classLabel}-СЫНЫП • КІРІС ДИАГНОСТИКАСЫН ТАЛДАУ`,
          bold: true,
          size: 26,
          color: "172554",
        }),
      ],
    });

    const summary = new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 260 },
      children: [
        new TextRun({
          text: `Бағаланған оқушылар: ${studentCount}`,
          size: 22,
          color: "475569",
        }),
      ],
    });

    const resultRows = [
      new TableRow({
        tableHeader: true,
        children: ["Оқушы", "Нәтиже", "10 балл", "Қате тапсырмалар"].map(
          (text) =>
            new TableCell({
              borders: cellBorders,
              shading: { fill: "E9EDFF" },
              verticalAlign: VerticalAlign.CENTER,
              children: [
                new Paragraph({
                  alignment: AlignmentType.CENTER,
                  children: [new TextRun({ text, bold: true, size: 20 })],
                }),
              ],
            })
        ),
      }),
      ...students.map((s) => {
        const wrong = Array.isArray(s.wrongTasks) && s.wrongTasks.length
          ? s.wrongTasks
              .map((w) => `${w.number} (${w.skill || "дағды"})`)
              .join(", ")
          : "Қате жоқ";

        return new TableRow({
          children: [
            String(s.name || ""),
            `${s.correct ?? 0}/${s.total ?? 20}`,
            `${s.score10 ?? 0}/10`,
            wrong,
          ].map(
            (text, i) =>
              new TableCell({
                borders: cellBorders,
                verticalAlign: VerticalAlign.CENTER,
                children: [
                  new Paragraph({
                    alignment: i === 0 ? AlignmentType.LEFT : AlignmentType.CENTER,
                    children: [new TextRun({ text: String(text), size: 19 })],
                  }),
                ],
              })
          ),
        });
      }),
    ];

    const gapRows = [
      new TableRow({
        tableHeader: true,
        children: ["№", "Тақырып / дағды", "Қате саны", "Қажет оқушылар", "Ұсынылатын жұмыс", "Бақылау"].map(
          (text) =>
            new TableCell({
              borders: cellBorders,
              shading: { fill: "E9EDFF" },
              verticalAlign: VerticalAlign.CENTER,
              children: [
                new Paragraph({
                  alignment: AlignmentType.CENTER,
                  children: [new TextRun({ text, bold: true, size: 18 })],
                }),
              ],
            })
        ),
      }),
      ...gaps.slice(0, 10).map((g, index) =>
        new TableRow({
          children: [
            String(index + 1),
            String(g.skill || ""),
            String(g.errorCount ?? 0),
            Array.isArray(g.students) ? g.students.join(", ") : "",
            String(g.work || ""),
            String(g.control || "Қайта тексеру"),
          ].map(
            (text, i) =>
              new TableCell({
                borders: cellBorders,
                verticalAlign: VerticalAlign.CENTER,
                children: [
                  new Paragraph({
                    alignment: i === 0 || i === 2
                      ? AlignmentType.CENTER
                      : AlignmentType.LEFT,
                    children: [new TextRun({ text, size: 18 })],
                  }),
                ],
              })
          ),
        })
      ),
    ];

    const children = [
      title,
      subtitle,
      summary,
      new Paragraph({
        spacing: { before: 100, after: 100 },
        children: [
          new TextRun({
            text: "1. ОҚУШЫ НӘТИЖЕЛЕРІ",
            bold: true,
            size: 24,
            color: "172554",
          }),
        ],
      }),
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: resultRows,
      }),
      new Paragraph({
        spacing: { before: 260, after: 100 },
        children: [
          new TextRun({
            text: "2. СЫНЫП БОЙЫНША ОЛҚЫЛЫҚТАР ЖӘНЕ ЖҰМЫС ЖОСПАРЫ",
            bold: true,
            size: 24,
            color: "172554",
          }),
        ],
      }),
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: gapRows,
      }),
      new Paragraph({
        spacing: { before: 260, after: 80 },
        children: [
          new TextRun({
            text: "Мұғалім қорытындысы:",
            bold: true,
            size: 22,
          }),
        ],
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: "________________________________________________________________________________",
            size: 20,
            color: "94A3B8",
          }),
        ],
      }),
      new Paragraph({
        spacing: { before: 80 },
        children: [
          new TextRun({
            text: "________________________________________________________________________________",
            size: 20,
            color: "94A3B8",
          }),
        ],
      }),
    ];

    const doc = new Document({
      sections: [{
        properties: {
          page: {
            margin: { top: 700, right: 650, bottom: 700, left: 650 },
          },
        },
        children,
      }],
    });

    const buffer = await Packer.toBuffer(doc);
    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    // HTTP header ішінде тек ASCII қолданамыз.
    // Параллель әріптері кирилл болса, оларды латыншаға ауыстырамыз.
    const sectionAsciiMap = {
      "А": "A",
      "Ә": "AE",
      "Б": "B",
      "В": "V",
      "Г": "G",
      "A": "A",
      "B": "B",
      "V": "V",
      "G": "G"
    };
    const sectionRaw = String(classSection || "").trim().toUpperCase();
    const sectionAscii = sectionAsciiMap[sectionRaw] || "CLASS";
    const safeFileName = `BMA_${grade}_${sectionAscii}_diagnostic_analysis.docx`;

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeFileName}"`
    );
    res.send(buffer);
  } catch (error) {
    console.error("ANALYSIS WORD EXPORT ERROR:", error);
    res.status(500).json({ error: error.message });
  }
});

// ========================================
// ҰБТ — МАТЕМАТИКАЛЫҚ САУАТТЫЛЫҚ
// 2026 формат: 10 тапсырма
// Әр шақырғанда жаңа nonce → жаңа нұсқа
// ========================================

const LITERACY_TOPIC_MAP = {
  percent: "Пайыз және пропорция",
  text_equations: "Мәтіндік есептер және теңдеу",
  charts: "Диаграмма, график және кесте",
  statistics: "Орташа, медиана, мода, құлаш",
  sets_logic: "Жиындар және логика",
  combinatorics: "Комбинаторика",
  probability: "Ықтималдық",
  dependencies: "Шамалар арасындағы тәуелділік",
  sequences: "Тізбектер және заңдылықтар",
  geometry: "Периметр, аудан және кеңістік",
  solids: "Көлем және бет ауданы",
  units: "Өлшем бірліктері және масштаб"
};

app.post("/api/generate-literacy-practice", async (req, res) => {
  try {
    const {
      topicId = "percent",
      topic = "Математикалық сауаттылық",
      count = 5,
      level = "Орташа",
      language = "kk"
    } = req.body;

    const outputLanguage = normalizeLanguage(language);
    const prompt = `
${outputLanguage === "ru" ? "Ты опытный преподаватель математической грамотности для ЕНТ." : "Сен ҰБТ математикалық сауаттылық бойынша тәжірибелі мұғалімсің."}
${languageInstruction(outputLanguage)}

Тақырып: ${topic}
Тақырып ID: ${topicId}
Деңгей: ${level}
Есеп саны: ${count}

${outputLanguage === "ru" ? `Составь ${count} разных тренировочных задач в стиле ЕНТ на русском языке.` : `${count} түрлі ҰБТ стиліндегі жаттығу есебін қазақ тілінде құрастыр.`}
Талаптар:
- есептер өмірлік немесе практикалық контекстте болсын;
- әр есептің нақты жауабы және толық шешуі болсын;
- бір-біріне ұқсамасын;
- математикалық өрнектерді: x^2, sqrt(49), pi, *, /, <=, >= форматында жаз;
- деңгейге сай күрделілік сақталсын;
- қате немесе екіұшты шарт болмасын.

ТЕК JSON:
{
  "problems": [
    {
      "question": "есеп",
      "answer": "жауап",
      "solution": "толық шешу жолы"
    }
  ]
}
`;

    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: { responseMimeType: "application/json" }
    });

    if (!response.text) throw new Error("AI бос жауап қайтарды.");
    const data = parseJson(response.text);

    if (!Array.isArray(data?.problems)) {
      throw new Error("AI есептерді дұрыс форматта қайтармады.");
    }

    res.json({
      problems: data.problems.slice(0, Number(count) || 5)
    });
  } catch (error) {
    console.error("LITERACY PRACTICE ERROR:", error);
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/generate-literacy-test", async (req, res) => {
  try {
    const {
      focusTopicId = null,
      nonce = Date.now(),
      language = "kk"
    } = req.body;

    const focusText = focusTopicId && LITERACY_TOPIC_MAP[focusTopicId]
      ? `Барлық 10 тапсырма "${LITERACY_TOPIC_MAP[focusTopicId]}" тақырыбы аясында әртүрлі типтен болсын.`
      : `
10 тапсырма ресми математикалық сауаттылық мазмұнының төрт бағытын қамтысын:
1) Сандық талқылау;
2) Анықсыздық;
3) Өзгерістер мен тәуелділіктер;
4) Кеңістік пен форма.

Тақырыптарды араластыр:
пайыз/пропорция, мәтіндік теңдеу, диаграмма/кесте,
статистика, жиын/логика, комбинаторика, ықтималдық,
тәуелділік, тізбек, периметр/аудан, көлем/бет ауданы, масштаб.
`;

    const outputLanguage = normalizeLanguage(language);
    const prompt = `
${outputLanguage === "ru" ? "Ты специалист по составлению тестов математической грамотности ЕНТ в Казахстане." : "Сен Қазақстандағы ҰБТ математикалық сауаттылық тестін құрастырушы мамансың."}
${languageInstruction(outputLanguage)}

Нұсқаның кездейсоқ кілті: ${nonce}
ӘР ШАҚЫРУДА алдыңғы нұсқадан өзгеше 10 жаңа тапсырма құрастыр.
${focusText}

Міндетті талап:
- дәл 10 тапсырма;
- әр тапсырмада 4 жауап нұсқасы A/B/C/D және тек 1 дұрыс жауап;
- жалпы сынақта күрделілік балансы шамамен: 5 базалық, 3 орташа, 2 жоғары;
- сұрақтар ҰБТ стилінде, қысқа бірақ ойлануды қажет ететін болсын;
- өмірлік контекст, кестелік/сандық ақпарат, логика және геометрия аралассын;
- есептер бір нұсқаның ішінде қайталанбасын;
- бірдей nonce болса да сандық мәндерді әртараптандыр;
- математикалық өрнектерді x^2, sqrt(49), pi, *, / форматында жаз;
- correctIndex 0..3 аралығында болсын;
- explanation қысқа, нақты шешу логикасын түсіндірсін;
- topicId тек мына ID-лардың бірі болсын:
  percent, text_equations, charts, statistics, sets_logic,
  combinatorics, probability, dependencies, sequences,
  geometry, solids, units.

ТЕК JSON:
{
  "questions": [
    {
      "topicId": "percent",
      "difficulty": "Базалық",
      "question": "сұрақ",
      "options": ["A мәні", "B мәні", "C мәні", "D мәні"],
      "correctIndex": 0,
      "explanation": "неге осы жауап дұрыс"
    }
  ]
}
`;

    const response = await ai.models.generateContent({
      model: MODEL,
      contents: prompt,
      config: {
        responseMimeType: "application/json",
        temperature: 1.0
      }
    });

    if (!response.text) throw new Error("AI бос жауап қайтарды.");

    const data = parseJson(response.text);
    const questions = Array.isArray(data?.questions)
      ? data.questions.slice(0, 10).map((q) => ({
          topicId: String(q?.topicId ?? "percent"),
          difficulty: String(q?.difficulty ?? "Орташа"),
          question: String(q?.question ?? ""),
          options: Array.isArray(q?.options)
            ? q.options.slice(0, 4).map((x) => String(x))
            : [],
          correctIndex: Number(q?.correctIndex ?? -1),
          explanation: String(q?.explanation ?? "")
        }))
      : [];

    if (
      questions.length !== 10 ||
      questions.some(
        (q) =>
          q.options.length !== 4 ||
          q.correctIndex < 0 ||
          q.correctIndex > 3 ||
          !q.question
      )
    ) {
      throw new Error("AI 10 тапсырмалық тестті дұрыс форматта қайтармады.");
    }

    res.json({
      variant: Number(String(nonce).slice(-6)),
      questions
    });
  } catch (error) {
    console.error("LITERACY TEST ERROR:", error);
    res.status(500).json({ error: error.message });
  }
});


// ========================================
// БЖБ / ТЖБ ТАЛДАУЫН WORD-ҚА ШЫҒАРУ
// ========================================

app.post("/api/export-assessment-analysis-word", async (req, res) => {
  try {
    const {
      grade = 7,
      classSection = "",
      assessmentType = "БЖБ",
      quarter = 1,
      subject = "Математика",
      school = "",
      teacher = "",
      title = "",
      date = "",
      studentCount = 0,
      totalMaxScore = 0,
      classAveragePercent = 0,
      achievementPercent = 0,
      qualityPercent = 0,
      passThreshold = 40,
      qualityThreshold = 65,
      tasks = [],
      students = [],
      objectives = [],
      weakObjectives = [],
    } = req.body || {};

    const sectionAsciiMap = {
      "А": "A",
      "Ә": "AE",
      "Б": "B",
      "В": "V",
      "Г": "G",
      "A": "A",
      "B": "B",
      "V": "V",
      "G": "G",
    };
    const sectionRaw = String(classSection || "").trim().toUpperCase();
    const sectionAscii = sectionAsciiMap[sectionRaw] || "CLASS";
    const typeAscii = assessmentType === "ТЖБ" ? "TZHB" : "BZHB";
    const safeFileName =
      `BMA_${grade}_${sectionAscii}_Q${quarter}_${typeAscii}_analysis.docx`;

    const thin = {
      style: BorderStyle.SINGLE,
      size: 4,
      color: "D8DEEA",
    };
    const borders = {
      top: thin,
      bottom: thin,
      left: thin,
      right: thin,
    };

    const cell = (
      text,
      {
        bold = false,
        center = false,
        fill = null,
        size = 18,
      } = {}
    ) =>
      new TableCell({
        borders,
        verticalAlign: VerticalAlign.CENTER,
        ...(fill ? { shading: { fill } } : {}),
        children: [
          new Paragraph({
            alignment: center ? AlignmentType.CENTER : AlignmentType.LEFT,
            children: [
              new TextRun({
                text: String(text ?? ""),
                bold,
                size,
              }),
            ],
          }),
        ],
      });

    const heading = (text) =>
      new Paragraph({
        spacing: { before: 220, after: 100 },
        children: [
          new TextRun({
            text,
            bold: true,
            size: 24,
            color: "172554",
          }),
        ],
      });

    const classLabel = `${grade}${classSection}`;

    const children = [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 80 },
        children: [
          new TextRun({
            text: "BIAKHMET MATH ACADEMY",
            bold: true,
            size: 32,
            color: "2945B8",
          }),
        ],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 70 },
        children: [
          new TextRun({
            text: `${classLabel}-СЫНЫП • ${quarter}-ТОҚСАН • ${assessmentType} ТАЛДАУЫ`,
            bold: true,
            size: 27,
            color: "172554",
          }),
        ],
      }),
      new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 220 },
        children: [
          new TextRun({
            text: String(title || subject),
            size: 22,
            color: "475569",
          }),
        ],
      }),
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          new TableRow({
            children: [
              cell("Мектеп", { bold: true, fill: "EEF2FF" }),
              cell(school || "—"),
              cell("Педагог", { bold: true, fill: "EEF2FF" }),
              cell(teacher || "—"),
            ],
          }),
          new TableRow({
            children: [
              cell("Пән", { bold: true, fill: "EEF2FF" }),
              cell(subject),
              cell("Күні", { bold: true, fill: "EEF2FF" }),
              cell(date || "—"),
            ],
          }),
        ],
      }),

      heading("1. ЖАЛПЫ НӘТИЖЕ"),

      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          new TableRow({
            children: [
              cell("Оқушы саны", {
                bold: true,
                center: true,
                fill: "EEF2FF",
              }),
              cell("Макс. балл", {
                bold: true,
                center: true,
                fill: "EEF2FF",
              }),
              cell("Сынып орташа", {
                bold: true,
                center: true,
                fill: "EEF2FF",
              }),
              cell("Үлгерім", {
                bold: true,
                center: true,
                fill: "EEF2FF",
              }),
              cell("Білім сапасы", {
                bold: true,
                center: true,
                fill: "EEF2FF",
              }),
            ],
          }),
          new TableRow({
            children: [
              cell(studentCount, { center: true, size: 22 }),
              cell(totalMaxScore, { center: true, size: 22 }),
              cell(`${Number(classAveragePercent).toFixed(1)}%`, {
                center: true,
                size: 22,
              }),
              cell(`${Number(achievementPercent).toFixed(1)}%`, {
                center: true,
                size: 22,
              }),
              cell(`${Number(qualityPercent).toFixed(1)}%`, {
                center: true,
                size: 22,
              }),
            ],
          }),
        ],
      }),

      new Paragraph({
        spacing: { before: 80, after: 70 },
        children: [
          new TextRun({
            text:
              `Есептеу шектері: үлгерім ≥ ${passThreshold}%, білім сапасы ≥ ${qualityThreshold}%.`,
            size: 18,
            color: "64748B",
          }),
        ],
      }),

      heading("2. ОҚУШЫЛАРДЫҢ ЖЕКЕ НӘТИЖЕЛЕРІ"),
    ];

    const studentHeader = [
      "№",
      "Оқушы",
      ...tasks.map((t) => `${t.number}-тапс.`),
      "Жалпы",
      "%",
      "Деңгей",
    ];

    const studentRows = [
      new TableRow({
        tableHeader: true,
        children: studentHeader.map((text) =>
          cell(text, {
            bold: true,
            center: true,
            fill: "E9EDFF",
            size: 16,
          })
        ),
      }),
      ...students.map((s, index) =>
        new TableRow({
          children: [
            cell(index + 1, { center: true, size: 16 }),
            cell(s.name || "", { size: 16 }),
            ...(Array.isArray(s.scores) ? s.scores : []).map((score) =>
              cell(score ?? "—", { center: true, size: 16 })
            ),
            cell(
              `${Number(s.total || 0).toFixed(1)}/${Number(s.max || 0).toFixed(1)}`,
              { center: true, size: 16 }
            ),
            cell(`${Number(s.percent || 0).toFixed(1)}%`, {
              center: true,
              size: 16,
            }),
            cell(s.level || "", { center: true, size: 16 }),
          ],
        })
      ),
    ];

    children.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: studentRows,
      })
    );

    children.push(heading("3. ТАПСЫРМАЛАР БОЙЫНША ТАЛДАУ"));

    const taskRows = [
      new TableRow({
        tableHeader: true,
        children: [
          "Тапсырма",
          "Макс. балл",
          "Оқу мақсаты",
          "Оқу мақсатының мазмұны",
          "Орташа меңгеру",
        ].map((text) =>
          cell(text, {
            bold: true,
            center: true,
            fill: "E9EDFF",
          })
        ),
      }),
      ...tasks.map((t) =>
        new TableRow({
          children: [
            cell(t.number, { center: true }),
            cell(t.maxScore, { center: true }),
            cell(t.objectiveCode || "—", { center: true }),
            cell(t.objective || "—"),
            cell(`${Number(t.averagePercent || 0).toFixed(1)}%`, {
              center: true,
            }),
          ],
        })
      ),
    ];

    children.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: taskRows,
      })
    );

    children.push(heading("4. ОҚУ МАҚСАТТАРЫ БОЙЫНША ТАЛДАУ"));

    const objectiveRows = [
      new TableRow({
        tableHeader: true,
        children: [
          "Оқу мақсаты",
          "Мазмұны",
          "Тапсырмалар",
          "Меңгеру %",
          "Қорытынды",
        ].map((text) =>
          cell(text, {
            bold: true,
            center: true,
            fill: "E9EDFF",
          })
        ),
      }),
      ...objectives.map((o) => {
        const pct = Number(o.percent || 0);
        return new TableRow({
          children: [
            cell(o.code || "—", { center: true }),
            cell(o.objective || "—"),
            cell(
              Array.isArray(o.tasks) ? o.tasks.join(", ") : "",
              { center: true }
            ),
            cell(`${pct.toFixed(1)}%`, { center: true }),
            cell(
              pct >= qualityThreshold
                ? "Меңгерілген"
                : "Қосымша жұмыс қажет",
              { center: true }
            ),
          ],
        });
      }),
    ];

    children.push(
      new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: objectiveRows,
      })
    );

    children.push(heading("5. ОЛҚЫЛЫҚТАР ЖӘНЕ ЖҰМЫС ЖОСПАРЫ"));

    if (!Array.isArray(weakObjectives) || weakObjectives.length === 0) {
      children.push(
        new Paragraph({
          children: [
            new TextRun({
              text:
                "Меңгерілуі белгіленген шектен төмен оқу мақсаты анықталған жоқ.",
              size: 20,
              color: "15803D",
              bold: true,
            }),
          ],
        })
      );
    } else {
      const planRows = [
        new TableRow({
          tableHeader: true,
          children: [
            "№",
            "Оқу мақсаты",
            "Меңгеру",
            "Ұсынылатын жұмыс",
            "Бақылау",
          ].map((text) =>
            cell(text, {
              bold: true,
              center: true,
              fill: "FFF3E6",
            })
          ),
        }),
        ...weakObjectives.map((o, index) => {
          const pct = Number(o.percent || 0);
          const work =
            pct < passThreshold
              ? "Қайта түсіндіру; үлгі есеп; мұғаліммен бірге орындау; жеке түзету тапсырмасы"
              : "Қысқа қайталау; деңгейлік жаттығу; жұптық/шағын топтық жұмыс";
          return new TableRow({
            children: [
              cell(index + 1, { center: true }),
              cell(`${o.code || "—"} ${o.objective || ""}`),
              cell(`${pct.toFixed(1)}%`, { center: true }),
              cell(work),
              cell("Қайта тексеру", { center: true }),
            ],
          });
        }),
      ];

      children.push(
        new Table({
          width: { size: 100, type: WidthType.PERCENTAGE },
          rows: planRows,
        })
      );
    }

    children.push(
      heading("6. ПЕДАГОГ ҚОРЫТЫНДЫСЫ"),
      new Paragraph({
        spacing: { after: 80 },
        children: [
          new TextRun({
            text:
              "________________________________________________________________________________",
            size: 20,
            color: "94A3B8",
          }),
        ],
      }),
      new Paragraph({
        spacing: { after: 80 },
        children: [
          new TextRun({
            text:
              "________________________________________________________________________________",
            size: 20,
            color: "94A3B8",
          }),
        ],
      }),
      new Paragraph({
        children: [
          new TextRun({
            text:
              "________________________________________________________________________________",
            size: 20,
            color: "94A3B8",
          }),
        ],
      })
    );

    const doc = new Document({
      sections: [
        {
          properties: {
            page: {
              margin: {
                top: 650,
                right: 550,
                bottom: 650,
                left: 550,
              },
            },
          },
          children,
        },
      ],
    });

    const buffer = await Packer.toBuffer(doc);

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${safeFileName}"`
    );
    res.send(buffer);
  } catch (error) {
    console.error("ASSESSMENT ANALYSIS WORD ERROR:", error);
    res.status(500).json({
      error: error.message,
    });
  }
});


// ========================================
// SERVER
// ========================================


// ===============================================================
// BI AKHMET ACADEMY (BA) LICENSES — separate from existing BMA users
// ===============================================================
async function initBaLicenseDatabase() {
  await licensePool.query(`CREATE TABLE IF NOT EXISTS ba_license_users (
    id TEXT PRIMARY KEY, login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, client_name TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    license_until TIMESTAMPTZ NOT NULL,
    max_devices INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
  )`);
  await licensePool.query(`CREATE TABLE IF NOT EXISTS ba_license_devices (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ba_license_users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL, label TEXT NOT NULL DEFAULT 'Windows PC',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, device_hash)
  )`);
  await licensePool.query(`CREATE TABLE IF NOT EXISTS ba_license_sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES ba_license_users(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
  )`);
  await licensePool.query(`CREATE INDEX IF NOT EXISTS idx_ba_sessions_expiry ON ba_license_sessions(expires_at)`);
  console.log('BA license tables ready (BMA unchanged).');
}

app.post('/api/ba/auth/login', async (req, res) => {
  const {login='',password='',deviceId='',deviceLabel='Windows PC'}=req.body||{};
  if(!String(login).trim() || !String(password) || !String(deviceId).trim())
    return res.status(400).json({ok:false,error:'Логин, пароль және құрылғы идентификаторы міндетті.'});
  let client;
  try {
    client=await licensePool.connect();
    await client.query('BEGIN');
    const result=await client.query('SELECT * FROM ba_license_users WHERE LOWER(login)=$1 FOR UPDATE',[String(login).trim().toLowerCase()]);
    const user=pgUser(result.rows[0]);
    if(!user || !verifyPassword(password,user.passwordHash)) {
      await client.query('ROLLBACK');
      return res.status(401).json({ok:false,error:'Логин немесе пароль қате.'});
    }
    const state=licenseState(user);
    if(!state.ok) {await client.query('ROLLBACK');return res.status(403).json(state);}
    const deviceHash=hashDeviceId(deviceId);
    const devices=await client.query('SELECT device_hash FROM ba_license_devices WHERE user_id=$1',[user.id]);
    if(!devices.rows.some(x=>x.device_hash===deviceHash) && devices.rowCount>=user.maxDevices) {
      await client.query('ROLLBACK');
      return res.status(403).json({ok:false,error:'Құрылғы лимиті толды.'});
    }
    await client.query(`INSERT INTO ba_license_devices(user_id,device_hash,label) VALUES($1,$2,$3)
      ON CONFLICT(user_id,device_hash) DO UPDATE SET label=EXCLUDED.label,last_seen_at=NOW()`,
      [user.id,deviceHash,String(deviceLabel).slice(0,120)]);
    await client.query('DELETE FROM ba_license_sessions WHERE user_id=$1 AND device_hash=$2',[user.id,deviceHash]);
    const token=crypto.randomBytes(32).toString('hex');
    const expiresAt=new Date(Math.min(state.until.getTime(),Date.now()+30*86400000));
    await client.query('INSERT INTO ba_license_sessions(token,user_id,device_hash,expires_at) VALUES($1,$2,$3,$4)',[token,user.id,deviceHash,expiresAt]);
    await client.query('UPDATE ba_license_users SET last_login_at=NOW() WHERE id=$1',[user.id]);
    await client.query('COMMIT');
    return res.json({ok:true,product:'BA',token,login:user.login,clientName:user.clientName,licenseUntil:user.licenseUntil,maxDevices:user.maxDevices,usedDevices:devices.rowCount+(devices.rows.some(x=>x.device_hash===deviceHash)?0:1)});
  } catch(error) {
    if(client) try{await client.query('ROLLBACK');}catch(_){}
    console.error('BA LOGIN ERROR:',error);
    return res.status(500).json({ok:false,error:'BA лицензия серверінің қатесі.'});
  } finally {if(client)client.release();}
});

app.post('/api/ba/auth/check',async(req,res)=>{
  const {token='',deviceId=''}=req.body||{};
  if(!token || !deviceId) return res.status(401).json({ok:false,error:'Сессия немесе құрылғы жоқ.'});
  try {
    const result=await licensePool.query(`SELECT u.* FROM ba_license_sessions s
      JOIN ba_license_users u ON u.id=s.user_id
      WHERE s.token=$1 AND s.device_hash=$2 AND s.expires_at>NOW() LIMIT 1`,[token,hashDeviceId(deviceId)]);
    if(!result.rowCount)return res.status(401).json({ok:false,error:'Сессия жарамсыз немесе аяқталған.'});
    const user=pgUser(result.rows[0]);
    const state=licenseState(user);
    if(!state.ok)return res.status(403).json(state);
    return res.json({ok:true,product:'BA',login:user.login,clientName:user.clientName,licenseUntil:user.licenseUntil,maxDevices:user.maxDevices});
  }catch(error){console.error('BA CHECK ERROR:',error);return res.status(500).json({ok:false,error:'BA лицензиясын тексеру қатесі.'});}
});

app.get('/api/ba/admin/clients',requireAdmin,async(req,res)=>{
  try {
    const r=await licensePool.query(`SELECT u.id,u.login,u.client_name AS "clientName",u.active,u.license_until AS "licenseUntil",
      u.max_devices AS "maxDevices",u.created_at AS "createdAt",u.last_login_at AS "lastLoginAt",
      (SELECT COUNT(*)::int FROM ba_license_devices d WHERE d.user_id=u.id) AS "usedDevices"
      FROM ba_license_users u ORDER BY u.created_at DESC`);
    res.json({ok:true,clients:r.rows});
  }catch(error){console.error('BA ADMIN LIST ERROR:',error);res.status(500).json({ok:false,error:'Тізімді алу қатесі.'});}
});

app.post('/api/ba/admin/clients',requireAdmin,async(req,res)=>{
  const {login='',password='',clientName='',maxDevices=1}=req.body||{};
  const name=String(login).trim().toLowerCase();
  if(!/^[a-z0-9._-]{3,80}$/.test(name) || String(password).length<8)
    return res.status(400).json({ok:false,error:'Логин 3–80 таңба, пароль кемінде 8 таңба болуы керек.'});
  const devices=Number(maxDevices);
  if(!Number.isInteger(devices)||devices<1||devices>20)return res.status(400).json({ok:false,error:'Құрылғы лимиті 1–20 аралығында.'});
  try {
    const id=crypto.randomUUID();
    // One-time purchase: license valid for 100 years, with no recurring payment.
    const until=new Date();until.setUTCFullYear(until.getUTCFullYear()+100);
    const r=await licensePool.query(`INSERT INTO ba_license_users(id,login,password_hash,client_name,license_until,max_devices)
      VALUES($1,$2,$3,$4,$5,$6) RETURNING id,login,client_name AS "clientName",license_until AS "licenseUntil",max_devices AS "maxDevices"`,
      [id,name,hashPassword(password),String(clientName||name).slice(0,160),until,devices]);
    res.status(201).json({ok:true,product:'BA',client:r.rows[0]});
  }catch(error){if(error.code==='23505')return res.status(409).json({ok:false,error:'Бұл BA логині бұрыннан бар.'});console.error('BA CREATE ERROR:',error);res.status(500).json({ok:false,error:'BA клиентін қосу қатесі.'});}
});

app.post('/api/ba/admin/clients/:id/status',requireAdmin,async(req,res)=>{
  if(typeof req.body?.active!=='boolean')return res.status(400).json({ok:false,error:'active мәні true немесе false болуы керек.'});
  const client=await licensePool.connect();
  try {
    await client.query('BEGIN');
    const r=await client.query('UPDATE ba_license_users SET active=$2 WHERE id=$1 RETURNING id',[req.params.id,req.body.active]);
    if(!r.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,error:'BA клиенті табылмады.'});}
    if(!req.body.active)await client.query('DELETE FROM ba_license_sessions WHERE user_id=$1',[req.params.id]);
    await client.query('COMMIT');res.json({ok:true,active:req.body.active});
  }catch(error){try{await client.query('ROLLBACK');}catch(_){}console.error('BA STATUS ERROR:',error);res.status(500).json({ok:false,error:'Статусты өзгерту қатесі.'});}finally{client.release();}
});

app.post('/api/ba/admin/clients/:id/device-limit',requireAdmin,async(req,res)=>{
  const maxDevices=Number(req.body?.maxDevices);
  if(!Number.isInteger(maxDevices)||maxDevices<1||maxDevices>20)
    return res.status(400).json({ok:false,error:'Құрылғы лимиті 1–20 аралығында.'});
  try {
    const r=await licensePool.query(
      `UPDATE ba_license_users SET max_devices=$2 WHERE id=$1
       RETURNING id,max_devices AS "maxDevices"`,
      [req.params.id,maxDevices]);
    if(!r.rowCount)return res.status(404).json({ok:false,error:'BA клиенті табылмады.'});
    res.json({ok:true,client:r.rows[0]});
  }catch(error){
    console.error('BA LIMIT ERROR:',error);
    res.status(500).json({ok:false,error:'Құрылғы лимитін өзгерту қатесі.'});
  }
});

app.post('/api/ba/admin/clients/:id/reset-devices',requireAdmin,async(req,res)=>{
  const client=await licensePool.connect();
  try {
    await client.query('BEGIN');
    const r=await client.query('SELECT id FROM ba_license_users WHERE id=$1 FOR UPDATE',[req.params.id]);
    if(!r.rowCount){await client.query('ROLLBACK');return res.status(404).json({ok:false,error:'BA клиенті табылмады.'});}
    await client.query('DELETE FROM ba_license_sessions WHERE user_id=$1',[req.params.id]);
    await client.query('DELETE FROM ba_license_devices WHERE user_id=$1',[req.params.id]);
    await client.query('COMMIT');res.json({ok:true});
  }catch(error){try{await client.query('ROLLBACK');}catch(_){}console.error('BA RESET ERROR:',error);res.status(500).json({ok:false,error:'Құрылғыны босату қатесі.'});}finally{client.release();}
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    const requiredEnv = ["DATABASE_URL", "GEMINI_API_KEY", "BMA_ADMIN_SECRET"];
    const missingEnv = requiredEnv.filter(
      (name) => !String(process.env[name] || "").trim(),
    );

    if (missingEnv.length > 0) {
      throw new Error(
        `Required environment variables are missing: ${missingEnv.join(", ")}`,
      );
    }

    await initLicenseDatabase();
    await initBaLicenseDatabase();

    app.listen(PORT, () => {
      console.log("======================================");
      console.log("Biakhmet Math Academy backend started");
      console.log(`Server: http://localhost:${PORT}`);
      console.log("License DB: PostgreSQL");
      console.log("======================================");
    });
  } catch (error) {
    console.error("SERVER START ERROR:", error);
    process.exit(1);
  }
}

startServer();