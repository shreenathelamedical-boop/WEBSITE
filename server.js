require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const multer = require("multer");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const AUTO_BACKUP_HOURS = Math.max(0, Number(process.env.AUTO_BACKUP_HOURS || 24));
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 6);
const SESSION_MS = SESSION_HOURS * 60 * 60 * 1000;
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE-ME-IN-.env";

if (SESSION_SECRET === "CHANGE-ME-IN-.env") {
  console.warn("WARNING: Set SESSION_SECRET in .env before using this beyond local testing.");
}

const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");
const purchaseBillDir = path.join(uploadDir, "purchase-bills");
const backupDir = path.join(dataDir, "backups");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(purchaseBillDir, { recursive: true });
fs.mkdirSync(backupDir, { recursive: true });

const db = new Database(path.join(dataDir, "stock.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'staff' CHECK(role IN ('admin','staff')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS medicines (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  generic_name TEXT,
  company TEXT,
  strength TEXT,
  dosage_form TEXT,
  pack_size TEXT,
  units_per_pack INTEGER NOT NULL DEFAULT 1 CHECK(units_per_pack >= 1),
  image_path TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS batches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE CASCADE,
  batch_no TEXT NOT NULL,
  mfd_date TEXT,
  expiry_date TEXT NOT NULL,
  quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),
  loose_quantity INTEGER NOT NULL DEFAULT 0 CHECK(loose_quantity >= 0),
  cost_price REAL NOT NULL DEFAULT 0 CHECK(cost_price >= 0),
  selling_price_1 REAL NOT NULL DEFAULT 0 CHECK(selling_price_1 >= 0),
  selling_price_2 REAL NOT NULL DEFAULT 0 CHECK(selling_price_2 >= 0),
  selling_price_3 REAL NOT NULL DEFAULT 0 CHECK(selling_price_3 >= 0),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(medicine_id, batch_no)
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_medicines_name ON medicines(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_batches_expiry ON batches(expiry_date);
CREATE INDEX IF NOT EXISTS idx_batches_medicine ON batches(medicine_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_no TEXT NOT NULL UNIQUE,
  customer_name TEXT,
  customer_phone TEXT,
  sale_date TEXT NOT NULL,
  total_amount REAL NOT NULL DEFAULT 0 CHECK(total_amount >= 0),
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS sale_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE CASCADE,
  medicine_id INTEGER NOT NULL REFERENCES medicines(id) ON DELETE RESTRICT,
  batch_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE RESTRICT,
  medicine_name TEXT NOT NULL,
  batch_no TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity > 0),
  sale_unit TEXT NOT NULL DEFAULT 'strip' CHECK(sale_unit IN ('strip','piece')),
  units_per_pack INTEGER NOT NULL DEFAULT 1 CHECK(units_per_pack >= 1),
  unit_price REAL NOT NULL CHECK(unit_price >= 0),
  amount REAL NOT NULL CHECK(amount >= 0)
);

CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(sale_date);
CREATE INDEX IF NOT EXISTS idx_sale_items_sale ON sale_items(sale_id);
CREATE INDEX IF NOT EXISTS idx_sale_items_batch ON sale_items(batch_id);

CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  supplier_name TEXT NOT NULL,
  invoice_no TEXT,
  purchase_date TEXT NOT NULL,
  notes TEXT,
  bill_original_name TEXT NOT NULL,
  bill_file_name TEXT NOT NULL UNIQUE,
  bill_mime TEXT NOT NULL,
  bill_size INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'uploaded' CHECK(status IN ('uploaded','reviewed','confirmed')),
  uploaded_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_purchases_date ON purchases(purchase_date);
CREATE INDEX IF NOT EXISTS idx_purchases_supplier ON purchases(supplier_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS purchase_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  purchase_id INTEGER NOT NULL REFERENCES purchases(id) ON DELETE CASCADE,
  medicine_name TEXT NOT NULL,
  company TEXT,
  batch_no TEXT,
  mfd_date TEXT,
  expiry_date TEXT,
  quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),
  scheme_quantity INTEGER NOT NULL DEFAULT 0 CHECK(scheme_quantity >= 0),
  purchase_rate REAL NOT NULL DEFAULT 0 CHECK(purchase_rate >= 0),
  discount_percent REAL NOT NULL DEFAULT 0 CHECK(discount_percent >= 0),
  gst_percent REAL NOT NULL DEFAULT 0 CHECK(gst_percent >= 0),
  mrp REAL NOT NULL DEFAULT 0 CHECK(mrp >= 0),
  net_rate REAL NOT NULL DEFAULT 0 CHECK(net_rate >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_purchase_items_purchase ON purchase_items(purchase_id);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id INTEGER,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS sale_returns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  return_no TEXT NOT NULL UNIQUE,
  sale_id INTEGER NOT NULL REFERENCES sales(id) ON DELETE RESTRICT,
  return_date TEXT NOT NULL,
  total_amount REAL NOT NULL DEFAULT 0 CHECK(total_amount >= 0),
  reason TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sale_return_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  return_id INTEGER NOT NULL REFERENCES sale_returns(id) ON DELETE CASCADE,
  sale_item_id INTEGER NOT NULL REFERENCES sale_items(id) ON DELETE RESTRICT,
  batch_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE RESTRICT,
  medicine_name TEXT NOT NULL,
  batch_no TEXT NOT NULL,
  quantity INTEGER NOT NULL CHECK(quantity > 0),
  sale_unit TEXT NOT NULL DEFAULT 'strip' CHECK(sale_unit IN ('strip','piece')),
  units_per_pack INTEGER NOT NULL DEFAULT 1 CHECK(units_per_pack >= 1),
  unit_price REAL NOT NULL CHECK(unit_price >= 0),
  amount REAL NOT NULL CHECK(amount >= 0)
);
CREATE INDEX IF NOT EXISTS idx_return_sale ON sale_returns(sale_id);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

function hasColumn(table, column) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === column);
}
function addColumn(table, column, definition) {
  if (!hasColumn(table, column)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
addColumn('medicines', 'reorder_level', 'INTEGER NOT NULL DEFAULT 10');
addColumn('medicines', 'units_per_pack', 'INTEGER NOT NULL DEFAULT 1');
addColumn('batches', 'loose_quantity', 'INTEGER NOT NULL DEFAULT 0');
addColumn('batches', 'selling_price_3', 'REAL NOT NULL DEFAULT 0');
addColumn('sale_items', 'sale_unit', "TEXT NOT NULL DEFAULT 'strip'");
addColumn('sale_items', 'units_per_pack', 'INTEGER NOT NULL DEFAULT 1');
addColumn('purchase_items', 'units_per_pack', 'INTEGER NOT NULL DEFAULT 1');
addColumn('sales', 'payment_method', "TEXT NOT NULL DEFAULT 'Cash'");
addColumn('sales', 'discount_amount', 'REAL NOT NULL DEFAULT 0');
addColumn('sales', 'notes', 'TEXT');
addColumn('sale_items', 'cost_price', 'REAL NOT NULL DEFAULT 0');
addColumn('sale_items', 'strip_quantity', 'INTEGER NOT NULL DEFAULT 0');
addColumn('sale_items', 'loose_piece_quantity', 'INTEGER NOT NULL DEFAULT 0');
addColumn('sale_items', 'cost_total', 'REAL NOT NULL DEFAULT 0');
addColumn('sale_items', 'price_type', "TEXT NOT NULL DEFAULT 'selling_price_1'");
addColumn('purchase_items', 'line_total', 'REAL NOT NULL DEFAULT 0');
addColumn('purchase_items', 'mrp3', 'REAL NOT NULL DEFAULT 0');
addColumn('purchases', 'payment_method', "TEXT NOT NULL DEFAULT 'Cash'");
addColumn('purchases', 'due_days', 'INTEGER NOT NULL DEFAULT 0');
addColumn('purchases', 'due_date', 'TEXT');
addColumn('users', 'access_role', "TEXT NOT NULL DEFAULT 'staff'");
db.prepare("UPDATE medicines SET units_per_pack = CASE WHEN units_per_pack > 1 THEN units_per_pack ELSE 1 END").run();
db.prepare("UPDATE sale_items SET strip_quantity=CASE WHEN sale_unit='strip' THEN quantity ELSE 0 END, loose_piece_quantity=CASE WHEN sale_unit='piece' THEN quantity ELSE 0 END, cost_total=CASE WHEN cost_total>0 THEN cost_total ELSE cost_price*quantity END WHERE strip_quantity=0 AND loose_piece_quantity=0").run();
db.prepare("UPDATE sale_items SET price_type='selling_price_2' WHERE price_type='selling_price_1' AND sale_unit='strip' AND EXISTS (SELECT 1 FROM batches b WHERE b.id=sale_items.batch_id AND ABS(b.selling_price_2-sale_items.unit_price)<0.01)").run();
db.prepare("UPDATE sale_items SET price_type='selling_price_3' WHERE price_type='selling_price_1' AND sale_unit='strip' AND EXISTS (SELECT 1 FROM batches b WHERE b.id=sale_items.batch_id AND ABS(b.selling_price_3-sale_items.unit_price)<0.01 AND b.selling_price_3>0)").run();
db.prepare("UPDATE users SET access_role='owner' WHERE role='admin' AND (access_role IS NULL OR access_role='staff')").run();
db.prepare("UPDATE users SET access_role='staff' WHERE access_role IS NULL OR access_role NOT IN ('owner','authorized_staff','staff')").run();
// MRP 2 is derived from original MRP: <= 200 => 5% off; > 200 => 3% off.
db.prepare("UPDATE batches SET selling_price_2 = ROUND(selling_price_1 * CASE WHEN selling_price_1 <= 200 THEN 0.95 ELSE 0.97 END, 2) WHERE selling_price_1 > 0").run();


const userCount = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
if (userCount === 0) {
  const initialUsers = [
    ["owner", "1234", "owner"],
    ["auth01", "Auth01@SNMS2026!", "authorized_staff"],
    ["auth02", "Auth02@SNMS2026!", "authorized_staff"],
    ["staff01", "Staff01@SNMS2026!", "staff"],
    ["staff02", "Staff02@SNMS2026!", "staff"]
  ];
  const insert = db.prepare("INSERT INTO users (username, password_hash, role, access_role) VALUES (?, ?, ?, ?)");
  const seed = db.transaction(() => {
    for (const [username, password, accessRole] of initialUsers) {
      const hash = bcrypt.hashSync(password, 12);
      insert.run(username, hash, accessRole === "owner" ? "admin" : "staff", accessRole);
    }
  });
  seed();
  console.log("Initial SNMS accounts created. Change all temporary passwords before real use.");
  for (const [username, password, accessRole] of initialUsers) console.log(`${accessRole}: ${username} / ${password}`);
}

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp", "image/gif"];
    cb(null, allowed.includes(file.mimetype));
  }
});

const billStorage = multer.diskStorage({
  destination: purchaseBillDir,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const billUpload = multer({
  storage: billStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ["application/pdf", "image/jpeg", "image/png", "image/webp"];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error("Supplier bill must be a PDF, JPG, PNG or WEBP file."));
    }
    cb(null, true);
  }
});

function handleBillUpload(req, res, next) {
  billUpload.single("bill_file")(req, res, (err) => {
    if (!err) return next();
    if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "Supplier bill is too large. Maximum size is 10 MB." });
    }
    return res.status(400).json({ error: err.message || "Could not upload supplier bill." });
  });
}

app.use(helmet({
  crossOriginResourcePolicy: { policy: "same-site" },
  contentSecurityPolicy: {
    directives: {
      "script-src": ["'self'"],
      "script-src-attr": ["'unsafe-inline'"]
    }
  }
}));
app.use(cookieParser());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if (origin) {
      try { if (new URL(origin).host !== req.get('host')) return res.status(403).json({error:'Cross-site request blocked.'}); } catch { return res.status(403).json({error:'Invalid request origin.'}); }
    }
  }
  next();
});
app.use(express.static(path.join(__dirname, "public")));

function hashToken(token) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(token).digest("hex");
}

function createSession(userId, res) {
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(Date.now());

  const rawToken = crypto.randomBytes(48).toString("hex");
  const tokenHash = hashToken(rawToken);
  const expiresAt = Date.now() + SESSION_MS;

  db.prepare("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)")
    .run(tokenHash, userId, expiresAt);

  res.cookie("session", rawToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: SESSION_MS,
    path: "/"
  });

  return expiresAt;
}

function clearSession(req, res) {
  const token = req.cookies?.session;
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
  res.clearCookie("session", { path: "/" });
}

function getUser(req) {
  const token = req.cookies?.session;
  if (!token) return null;

  const row = db.prepare(`
    SELECT u.id, u.username, u.access_role AS role, s.expires_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND u.active = 1
  `).get(hashToken(token), Date.now());

  return row || null;
}

function requireAuth(req, res, next) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: "Login required." });
  req.user = user;
  next();
}

const ROLES = Object.freeze({
  OWNER: "owner",
  AUTHORIZED: "authorized_staff",
  STAFF: "staff"
});

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: "You do not have permission to perform this action." });
    }
    next();
  };
}

const requireOwner = requireRole(ROLES.OWNER);
const requireOperations = requireRole(ROLES.OWNER, ROLES.AUTHORIZED);

function can(req, role) {
  return req.user?.role === role;
}

function requireOwnerOrPurchaseOperator(req, res, next) {
  if (req.user.role === ROLES.OWNER) return next();
  const purchaseId = Number(req.params.id);
  const purchase = db.prepare("SELECT uploaded_by, status FROM purchases WHERE id=?").get(purchaseId);
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });
  if (req.user.role === ROLES.AUTHORIZED && purchase.uploaded_by === req.user.id) return next();
  return res.status(403).json({ error: "Purchase records are confidential." });
}

function clean(value) {
  return value === undefined || value === null ? "" : String(value).trim();
}

function inferUnitsPerPack(packSize) {
  const text = clean(packSize).toLowerCase();
  const labeled = text.match(/(\d+)\s*(?:tablets?|tabs?|capsules?|caps?|pieces?|pcs?)/i);
  if (labeled) return Math.max(1, parseInt(labeled[1], 10));
  const x = text.match(/(?:x|×)\s*(\d+)/i);
  if (x) return Math.max(1, parseInt(x[1], 10));
  return 1;
}
function unitsForMedicine(medicine) { return Math.max(1, Number(medicine.units_per_pack || inferUnitsPerPack(medicine.pack_size) || 1)); }
db.prepare("SELECT id, pack_size, units_per_pack FROM medicines").all().forEach(m => { const inferred = inferUnitsPerPack(m.pack_size); if (Number(m.units_per_pack) <= 1 && inferred > 1) db.prepare("UPDATE medicines SET units_per_pack=? WHERE id=?").run(inferred, m.id); });

function validISODate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [y,m,d] = value.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  return dt.getFullYear() === y && dt.getMonth() === m - 1 && dt.getDate() === d;
}

function numberValue(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function mrp2FromOriginal(original) {
  const mrp = Math.max(0, Number(original) || 0);
  if (!mrp) return 0;
  return Math.round((mrp * (mrp <= 200 ? 0.95 : 0.97)) * 100) / 100;
}

function audit(req, action, entityType, entityId, details = '') {
  try { db.prepare("INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details) VALUES (?, ?, ?, ?, ?)").run(req.user?.id || null, action, entityType, entityId || null, details); } catch {}
}

app.get("/api/medicine-image/:filename", requireAuth, (req, res) => {
  const fileName = path.basename(req.params.filename);
  const filePath = path.join(uploadDir, fileName);
  if (!fs.existsSync(filePath)) return res.status(404).end();
  res.sendFile(filePath);
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role
    },
    sessionExpiresAt: req.user.expires_at
  });
});

const loginAttempts = new Map();
function loginRateLimited(ip) {
  const now = Date.now(), key = ip || 'unknown', item = loginAttempts.get(key);
  if (!item || now - item.started > 15*60*1000) { loginAttempts.set(key,{started:now,count:0}); return false; }
  return item.count >= 8;
}

app.post("/api/login", (req, res) => {
  const attemptKey = req.ip;
  if (loginRateLimited(attemptKey)) return res.status(429).json({error:'Too many login attempts. Try again in a few minutes.'});
  const username = clean(req.body.username);
  const password = String(req.body.password || "");

  const user = db.prepare("SELECT * FROM users WHERE username = ? AND active = 1").get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    const item=loginAttempts.get(attemptKey)||{started:Date.now(),count:0}; item.count++; loginAttempts.set(attemptKey,item);
    return res.status(401).json({ error: "Invalid username or password." });
  }
  loginAttempts.delete(attemptKey);

  const expiresAt = createSession(user.id, res);
  res.json({
    ok: true,
    user: { id: user.id, username: user.username, role: user.access_role || (user.role === 'admin' ? 'owner' : 'staff') },
    sessionExpiresAt: expiresAt
  });
});

app.post("/api/me/password", requireAuth, (req, res) => {
  const current = String(req.body.current_password || "");
  const next = String(req.body.new_password || "");
  if (next.length < 10) return res.status(400).json({ error: "New password must be at least 10 characters." });
  const user = db.prepare("SELECT password_hash FROM users WHERE id=? AND active=1").get(req.user.id);
  if (!user || !bcrypt.compareSync(current, user.password_hash)) return res.status(401).json({ error: "Current password is incorrect." });
  db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(bcrypt.hashSync(next, 12), req.user.id);
  audit(req, "update", "user", req.user.id, "Changed own password");
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies?.session;
  if (token) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
  res.clearCookie("session", { path: "/" });
  res.json({ ok: true });
});

app.get("/api/medicines", requireAuth, (req, res) => {
  const search = clean(req.query.search);
  const company = clean(req.query.company);
  const sort = req.query.sort === "newest" ? "m.id DESC" : "m.name COLLATE NOCASE ASC, m.id ASC";

  const rows = db.prepare(`
    SELECT
      m.id, m.name, m.generic_name, m.company, m.strength, m.dosage_form,
      m.pack_size, m.units_per_pack, m.reorder_level, m.image_path, m.notes,
      COALESCE(SUM(b.quantity), 0) AS total_quantity,
      COALESCE(SUM(b.loose_quantity), 0) AS total_loose_quantity,
      COUNT(b.id) AS batch_count,
      MIN(CASE WHEN b.quantity > 0 THEN b.expiry_date END) AS nearest_expiry
    FROM medicines m
    LEFT JOIN batches b ON b.medicine_id = m.id
    WHERE (? = '' OR m.name LIKE '%' || ? || '%' OR m.generic_name LIKE '%' || ? || '%' OR m.company LIKE '%' || ? || '%')
      AND (? = '' OR m.company = ?)
    GROUP BY m.id
    ORDER BY ${sort}
  `).all(search, search, search, search, company, company);

  res.json(rows);
});

app.get("/api/companies", requireAuth, (req, res) => {
  res.json(db.prepare(`
    SELECT DISTINCT company
    FROM medicines
    WHERE company IS NOT NULL AND TRIM(company) <> ''
    ORDER BY company COLLATE NOCASE
  `).all().map(r => r.company));
});

app.get("/api/medicine-memory", requireAuth, (req, res) => {
  const name = clean(req.query.name);
  const company = clean(req.query.company);
  const batch = clean(req.query.batch);
  if (!name) return res.json(null);

  // First remember the medicine itself. This lets a repeated medicine name
  // recall the company and units-per-strip even before a batch is entered.
  const medicine = db.prepare(`
    SELECT id, name, company, units_per_pack, pack_size, strength, dosage_form
    FROM medicines
    WHERE lower(name)=lower(?)
      AND (? = '' OR lower(coalesce(company,''))=lower(?))
    ORDER BY id DESC
    LIMIT 1
  `).get(name, company, company);

  if (!medicine) return res.json(null);

  let row = null;
  if (batch) {
    // If the batch matches, recall its exact batch memory.
    row = db.prepare(`
      SELECT m.name, m.company, m.units_per_pack, m.pack_size, m.strength, m.dosage_form,
             b.batch_no, b.mfd_date, b.expiry_date, b.cost_price,
             b.selling_price_1 AS mrp, b.selling_price_2 AS mrp2, b.selling_price_3 AS mrp3
      FROM batches b JOIN medicines m ON m.id=b.medicine_id
      WHERE lower(m.name)=lower(?)
        AND lower(coalesce(m.company,''))=lower(?)
        AND lower(b.batch_no)=lower(?)
      LIMIT 1
    `).get(name, medicine.company || '', batch);
  }

  const result = row || {
    name: medicine.name, company: medicine.company || '', units_per_pack: medicine.units_per_pack,
    pack_size: medicine.pack_size || '', strength: medicine.strength || '', dosage_form: medicine.dosage_form || '',
    batch_no: '', mfd_date: '', expiry_date: '', cost_price: 0, mrp: 0, mrp2: 0, mrp3: 0
  };

  if (req.user.role !== ROLES.OWNER && req.user.role !== ROLES.AUTHORIZED) delete result.cost_price;
  res.json(result);
});

app.get("/api/medicines/:id", requireAuth, (req, res) => {
  const medicine = db.prepare("SELECT * FROM medicines WHERE id = ?").get(Number(req.params.id));
  if (!medicine) return res.status(404).json({ error: "Medicine not found." });

  const batches = db.prepare(`
    SELECT * FROM batches
    WHERE medicine_id = ?
    ORDER BY expiry_date ASC, batch_no ASC
  `).all(medicine.id);

  const safeBatches = req.user.role === ROLES.OWNER
    ? batches
    : batches.map(({ cost_price, ...b }) => b);
  res.json({ medicine, batches: safeBatches });
});

app.post("/api/medicines", requireAuth, requireOperations, upload.single("image"), (req, res) => {
  const name = clean(req.body.name);
  if (!name) return res.status(400).json({ error: "Medicine name is required." });

  const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

  const result = db.prepare(`
    INSERT INTO medicines
    (name, generic_name, company, strength, dosage_form, pack_size, units_per_pack, reorder_level, image_path, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    name,
    clean(req.body.generic_name),
    clean(req.body.company),
    clean(req.body.strength),
    clean(req.body.dosage_form),
    clean(req.body.pack_size),
    Math.max(1, Math.floor(numberValue(req.body.units_per_pack, inferUnitsPerPack(req.body.pack_size)))),
    Math.max(0, Math.floor(numberValue(req.body.reorder_level, 10))),
    imagePath,
    clean(req.body.notes)
  );
  audit(req, 'create', 'medicine', result.lastInsertRowid, `Created medicine ${name}`);

  res.status(201).json({ id: result.lastInsertRowid });
});

app.put("/api/medicines/:id", requireAuth, requireOperations, upload.single("image"), (req, res) => {
  const id = Number(req.params.id);
  const current = db.prepare("SELECT * FROM medicines WHERE id = ?").get(id);
  if (!current) return res.status(404).json({ error: "Medicine not found." });

  const imagePath = req.file ? `/uploads/${req.file.filename}` : current.image_path;

  db.prepare(`
    UPDATE medicines
    SET name=?, generic_name=?, company=?, strength=?, dosage_form=?,
        pack_size=?, units_per_pack=?, reorder_level=?, image_path=?, notes=?, updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(
    clean(req.body.name),
    clean(req.body.generic_name),
    clean(req.body.company),
    clean(req.body.strength),
    clean(req.body.dosage_form),
    clean(req.body.pack_size),
    Math.max(1, Math.floor(numberValue(req.body.units_per_pack, inferUnitsPerPack(req.body.pack_size) || current.units_per_pack || 1))),
    Math.max(0, Math.floor(numberValue(req.body.reorder_level, current.reorder_level || 10))),
    imagePath,
    clean(req.body.notes),
    id
  );
  audit(req, 'update', 'medicine', id, `Updated medicine ${clean(req.body.name)}`);

  res.json({ ok: true });
});

app.delete("/api/medicines/:id", requireAuth, requireOwner, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("DELETE FROM medicines WHERE id = ?").run(id);
  res.json({ ok: true });
});

app.post("/api/batches", requireAuth, requireOperations, (req, res) => {
  const medicineId = Number(req.body.medicine_id);
  const batchNo = clean(req.body.batch_no);
  const expiry = clean(req.body.expiry_date);

  if (!medicineId || !batchNo || !expiry) {
    return res.status(400).json({ error: "Medicine, batch number and expiry date are required." });
  }

  try {
    const result = db.prepare(`
      INSERT INTO batches
      (medicine_id, batch_no, mfd_date, expiry_date, quantity, cost_price, selling_price_1, selling_price_2, selling_price_3)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      medicineId,
      batchNo,
      clean(req.body.mfd_date) || null,
      expiry,
      Math.floor(numberValue(req.body.quantity)),
      numberValue(req.body.cost_price),
      numberValue(req.body.selling_price_1),
      mrp2FromOriginal(numberValue(req.body.selling_price_1)),
      numberValue(req.body.selling_price_3)
    );

    audit(req, 'create', 'batch', result.lastInsertRowid, `Created batch ${batchNo}`);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "That batch number already exists for this medicine." });
    }
    throw e;
  }
});

app.put("/api/batches/:id", requireAuth, requireOperations, (req, res) => {
  const id = Number(req.params.id);
  const current = db.prepare("SELECT * FROM batches WHERE id=?").get(id);
  if (!current) return res.status(404).json({error:"Batch not found."});
  const sold = db.prepare("SELECT COALESCE(SUM(quantity),0) n FROM sale_items WHERE batch_id=?").get(id).n;
  const returned = db.prepare("SELECT COALESCE(SUM(quantity),0) n FROM sale_return_items WHERE batch_id=?").get(id).n;
  const newQty = Math.floor(numberValue(req.body.quantity));
  const minSafe = Math.max(0, sold - returned);
  if (newQty < minSafe) return res.status(409).json({error:`Stock cannot be reduced below ${minSafe}. This batch has recorded sales.`});
  db.prepare(`
    UPDATE batches
    SET batch_no=?, mfd_date=?, expiry_date=?, quantity=?,
        cost_price=?, selling_price_1=?, selling_price_2=?, selling_price_3=?, updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(
    clean(req.body.batch_no),
    clean(req.body.mfd_date) || null,
    clean(req.body.expiry_date),
    Math.floor(numberValue(req.body.quantity)),
    numberValue(req.body.cost_price),
    numberValue(req.body.selling_price_1),
    mrp2FromOriginal(numberValue(req.body.selling_price_1)),
    numberValue(req.body.selling_price_3),
    id
  );
  audit(req, 'update', 'batch', id, `Updated batch ${clean(req.body.batch_no)}`);
  res.json({ ok: true });
});

app.delete("/api/batches/:id", requireAuth, requireOwner, (req, res) => {
  const id=Number(req.params.id); const sold=db.prepare("SELECT COALESCE(SUM(quantity),0) n FROM sale_items WHERE batch_id=?").get(id).n;
  if(sold>0) return res.status(409).json({error:'A batch with recorded sales cannot be deleted.'});
  db.prepare("DELETE FROM batches WHERE id = ?").run(id); audit(req,'delete','batch',id,'Deleted batch'); res.json({ ok: true });
});

app.get("/api/expiry", requireAuth, (req, res) => {
  const mode = req.query.mode || "under3";
  let where = "";

  if (mode === "month") {
    where = "date(b.expiry_date) >= date('now','start of month') AND date(b.expiry_date) < date('now','start of month','+1 month')";
  } else if (mode === "under3") {
    where = "date(b.expiry_date) >= date('now') AND date(b.expiry_date) < date('now','+3 months')";
  } else if (mode === "expired") {
    where = "date(b.expiry_date) < date('now')";
  } else {
    return res.status(400).json({ error: "Unknown expiry mode." });
  }

  const rows = db.prepare(`
    SELECT b.id, b.medicine_id, b.batch_no, b.mfd_date, b.expiry_date, b.quantity,
           ${req.user.role === ROLES.OWNER ? "b.cost_price," : ""}
           b.selling_price_1, b.selling_price_2, b.selling_price_3, b.updated_at,
           m.name, m.company, m.strength, m.dosage_form
    FROM batches b
    JOIN medicines m ON m.id = b.medicine_id
    WHERE ${where}
    ORDER BY date(b.expiry_date) ASC, m.name COLLATE NOCASE ASC
  `).all();

  res.json(rows);
});

app.get("/api/dashboard", requireAuth, (req, res) => {
  const today = db.prepare("SELECT date('now') AS today").get().today;
  const stats = {
    medicines: db.prepare("SELECT COUNT(*) AS n FROM medicines").get().n,
    batches: db.prepare("SELECT COUNT(*) AS n FROM batches").get().n,
    units: db.prepare("SELECT COALESCE(SUM(quantity),0) AS n FROM batches").get().n,
    loosePieces: db.prepare("SELECT COALESCE(SUM(loose_quantity),0) AS n FROM batches").get().n,
    under3: db.prepare(`
      SELECT COUNT(*) AS n FROM batches
      WHERE date(expiry_date) >= date('now') AND date(expiry_date) < date('now','+3 months')
    `).get().n,
    expired: db.prepare(`
      SELECT COUNT(*) AS n FROM batches
      WHERE date(expiry_date) < date('now')
    `).get().n,
    lowStock: db.prepare(`
      SELECT COUNT(*) AS n FROM (
        SELECT m.id, COALESCE(SUM(b.quantity),0) AS qty, m.reorder_level
        FROM medicines m LEFT JOIN batches b ON b.medicine_id=m.id
        GROUP BY m.id HAVING qty <= m.reorder_level
      )
    `).get().n,
    today
  };
  if (req.user.role === ROLES.OWNER) {
    stats.financial = {
      salesToday: db.prepare("SELECT COALESCE(SUM(total_amount),0) AS n FROM sales WHERE sale_date = ?").get(today).n,
      salesMonth: db.prepare("SELECT COALESCE(SUM(total_amount),0) AS n FROM sales WHERE strftime('%Y-%m',sale_date)=strftime('%Y-%m','now')").get().n,
      purchaseMonth: db.prepare("SELECT COALESCE(SUM(line_total),0) AS n FROM purchase_items pi JOIN purchases p ON p.id=pi.purchase_id WHERE p.status='confirmed' AND strftime('%Y-%m',p.purchase_date)=strftime('%Y-%m','now')").get().n,
      profitMonth: db.prepare("SELECT COALESCE(SUM(si.amount-COALESCE(si.cost_total,si.cost_price*si.quantity)),0) AS n FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE strftime('%Y-%m',s.sale_date)=strftime('%Y-%m','now')").get().n,
      stockValue: db.prepare("SELECT COALESCE(SUM(quantity*cost_price + loose_quantity*(cost_price/CASE WHEN (SELECT units_per_pack FROM medicines m WHERE m.id=batches.medicine_id)>0 THEN (SELECT units_per_pack FROM medicines m2 WHERE m2.id=batches.medicine_id) ELSE 1 END)),0) AS n FROM batches").get().n
    };
  }
  res.json(stats);
});

app.get("/api/sales", requireAuth, requireOperations, (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.invoice_no, s.customer_name, s.customer_phone, s.sale_date,
           s.total_amount, u.username AS created_by, COUNT(si.id) AS item_count
    FROM sales s
    LEFT JOIN users u ON u.id = s.created_by
    LEFT JOIN sale_items si ON si.sale_id = s.id
    GROUP BY s.id
    ORDER BY s.id DESC
    LIMIT 100
  `).all();
  res.json(rows);
});

app.get("/api/sales/:id", requireAuth, requireOperations, (req, res) => {
  const sale = db.prepare(`
    SELECT s.*, u.username AS created_by
    FROM sales s LEFT JOIN users u ON u.id = s.created_by
    WHERE s.id = ?
  `).get(Number(req.params.id));
  if (!sale) return res.status(404).json({ error: "Sale not found." });
  const items = db.prepare(`SELECT * FROM sale_items WHERE sale_id = ? ORDER BY id ASC`).all(sale.id);
  res.json({ sale, items });
});

app.get("/api/sale-batches", requireAuth, requireOperations, (req, res) => {
  const search = clean(req.query.search);
  const rows = db.prepare(`
    SELECT b.id AS batch_id, b.medicine_id, b.batch_no, b.quantity, b.loose_quantity,
           (b.quantity * m.units_per_pack + b.loose_quantity) AS available_pieces,
           b.expiry_date, b.selling_price_1, b.selling_price_2, b.selling_price_3,
           m.name, m.company, m.strength, m.dosage_form, m.pack_size, m.units_per_pack
    FROM batches b
    JOIN medicines m ON m.id = b.medicine_id
    WHERE (b.quantity > 0 OR b.loose_quantity > 0)
      AND date(b.expiry_date) >= date('now')
      AND (? = '' OR m.name LIKE '%' || ? || '%' OR m.company LIKE '%' || ? || '%' OR b.batch_no LIKE '%' || ? || '%')
    ORDER BY m.name COLLATE NOCASE ASC, date(b.expiry_date) ASC, b.batch_no ASC
    LIMIT 250
  `).all(search, search, search, search);
  res.json(rows);
});



app.get("/api/purchases", requireAuth, requireOwner, (req, res) => {
  const rows = db.prepare(`
    SELECT p.id, p.supplier_name, p.invoice_no, p.purchase_date, p.payment_method, p.due_days, p.due_date, p.notes,
           p.bill_original_name, p.bill_mime, p.bill_size, p.status,
           (SELECT COUNT(*) FROM purchase_items pi WHERE pi.purchase_id = p.id) AS item_count,
           (SELECT COALESCE(SUM(CASE WHEN pi.line_total > 0 THEN pi.line_total ELSE pi.quantity * pi.net_rate * (1 + pi.gst_percent / 100) END),0) FROM purchase_items pi WHERE pi.purchase_id = p.id) AS total_amount,
           u.username AS uploaded_by, p.created_at
    FROM purchases p
    LEFT JOIN users u ON u.id = p.uploaded_by
    ORDER BY p.id DESC
    LIMIT 100
  `).all();
  res.json(rows);
});

app.get("/api/purchases/:id", requireAuth, requireOwnerOrPurchaseOperator, (req, res) => {
  const purchase = db.prepare(`
    SELECT p.id, p.supplier_name, p.invoice_no, p.purchase_date, p.payment_method, p.due_days, p.due_date, p.notes,
           p.bill_original_name, p.bill_file_name, p.bill_mime, p.bill_size, p.status,
           u.username AS uploaded_by, p.created_at
    FROM purchases p
    LEFT JOIN users u ON u.id = p.uploaded_by
    WHERE p.id = ?
  `).get(Number(req.params.id));
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });
  res.json(purchase);
});

app.get("/api/purchases/:id/file", requireAuth, requireOwnerOrPurchaseOperator, (req, res) => {
  const purchase = db.prepare("SELECT bill_file_name, bill_original_name, bill_mime FROM purchases WHERE id = ?").get(Number(req.params.id));
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });

  const fileName = path.basename(purchase.bill_file_name);
  const filePath = path.join(purchaseBillDir, fileName);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Original supplier bill file is missing." });

  res.type(purchase.bill_mime);
  res.sendFile(filePath, { headers: { "Content-Disposition": `inline; filename="${purchase.bill_original_name.replace(/"/g, "")}"` } });
});


app.get("/api/purchases/:id/items", requireAuth, requireOwnerOrPurchaseOperator, (req, res) => {
  const id = Number(req.params.id);
  const purchase = db.prepare("SELECT id, status FROM purchases WHERE id = ?").get(id);
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });
  const items = db.prepare("SELECT * FROM purchase_items WHERE purchase_id = ? ORDER BY id ASC").all(id);
  res.json({ purchase, items });
});

app.put("/api/purchases/:id/items", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const purchase = db.prepare("SELECT id FROM purchases WHERE id = ?").get(id);
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });
  const items = Array.isArray(req.body.items) ? req.body.items : [];
  if (!items.length) return res.status(400).json({ error: "Add at least one purchase item." });
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM purchase_items WHERE purchase_id = ?").run(id);
    const insert = db.prepare(`INSERT INTO purchase_items (purchase_id, medicine_name, company, batch_no, mfd_date, expiry_date, quantity, scheme_quantity, purchase_rate, discount_percent, gst_percent, mrp, mrp3, units_per_pack, net_rate, line_total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    for (const raw of items) {
      const name = clean(raw.medicine_name);
      if (!name) throw new Error("Every purchase item needs a medicine name.");
      const quantity = Math.max(0, Math.floor(Number(raw.quantity) || 0));
      if (quantity <= 0) throw new Error(`Quantity must be greater than 0 for ${name}.`);
      const rate = Math.max(0, Number(raw.purchase_rate) || 0);
      const discount = Math.max(0, Number(raw.discount_percent) || 0);
      const net = Math.max(0, Number(raw.net_rate) || rate * (1 - discount / 100));
      const scheme=Math.max(0, Math.floor(Number(raw.scheme_quantity)||0)); const gst=Math.max(0, Number(raw.gst_percent)||0); const lineTotal=Math.max(0,(quantity*net)*(1+gst/100)); insert.run(id,name,clean(raw.company)||null,clean(raw.batch_no)||null,clean(raw.mfd_date)||null,clean(raw.expiry_date)||null,quantity,scheme,rate,discount,gst,Math.max(0,Number(raw.mrp)||0),Math.max(0,Number(raw.mrp3)||0),Math.max(1,Math.floor(Number(raw.units_per_pack)||inferUnitsPerPack(raw.pack_size)||1)),net,lineTotal);
    }
    db.prepare("UPDATE purchases SET status = 'reviewed' WHERE id = ?").run(id);
  });
  try {
    tx();
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.message || "Could not save reviewed items." }); }
});

app.post("/api/purchases", requireAuth, requireOperations, handleBillUpload, (req, res) => {
  const supplierName = clean(req.body.supplier_name);
  const invoiceNo = clean(req.body.invoice_no) || null;
  const purchaseDate = clean(req.body.purchase_date) || new Date().toISOString().slice(0, 10);
  const notes = clean(req.body.notes) || null;
  const paymentMethod = clean(req.body.payment_method) === 'Credit' ? 'Credit' : 'Cash';
  const dueDays = paymentMethod === 'Credit' ? Math.max(0, Math.floor(Number(req.body.due_days) || 0)) : 0;
  const dueDate = paymentMethod === 'Credit' && dueDays > 0 ? new Date(new Date(purchaseDate + 'T00:00:00').getTime() + dueDays*86400000).toISOString().slice(0,10) : null;
  let items = [];
  try { items = req.body.items_json ? JSON.parse(req.body.items_json) : []; }
  catch { if (req.file) fs.rmSync(req.file.path, { force: true }); return res.status(400).json({ error: "Invalid purchase items data." }); }

  if (!supplierName) {
    if (req.file) fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Supplier name is required." });
  }
  if (!validISODate(purchaseDate)) {
    if (req.file) fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Invalid purchase date." });
  }
  if (!Array.isArray(items) || !items.length) {
    if (req.file) fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Add at least one medicine to the purchase." });
  }

  try {
    const tx = db.transaction(() => {
      const result = db.prepare(`
        INSERT INTO purchases
        (supplier_name, invoice_no, purchase_date, payment_method, due_days, due_date, notes, bill_original_name, bill_file_name, bill_mime, bill_size, status, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reviewed', ?)
      `).run(
        supplierName, invoiceNo, purchaseDate, paymentMethod, dueDays, dueDate, notes,
        req.file ? req.file.originalname : 'No file attached',
        req.file ? req.file.filename : `manual-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.txt`,
        req.file ? req.file.mimetype : 'text/plain',
        req.file ? req.file.size : 0, req.user.id
      );
      const purchaseId = Number(result.lastInsertRowid);
      const insert = db.prepare(`INSERT INTO purchase_items (purchase_id, medicine_name, company, batch_no, mfd_date, expiry_date, quantity, scheme_quantity, purchase_rate, discount_percent, gst_percent, mrp, mrp3, units_per_pack, net_rate, line_total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      for (const raw of items) {
        const name = clean(raw.medicine_name);
        const batch = clean(raw.batch_no);
        const expiry = clean(raw.expiry_date);
        const quantity = Math.max(0, Math.floor(Number(raw.quantity) || 0));
        if (!name) throw new Error("Every purchase row needs a medicine name.");
        if (!batch) throw new Error(`Batch number is required for ${name}.`);
        if (!expiry) throw new Error(`Expiry date is required for ${name}.`);
        if (!validISODate(expiry)) throw new Error(`Invalid expiry date for ${name}.`);
        if (quantity <= 0) throw new Error(`Quantity must be greater than 0 for ${name}.`);
        const rate = Math.max(0, Number(raw.purchase_rate) || 0);
        const discount = Math.max(0, Number(raw.discount_percent) || 0);
        const net = Math.max(0, Number(raw.net_rate) || rate * (1 - discount / 100));
        const scheme = Math.max(0, Math.floor(Number(raw.scheme_quantity) || 0));
        const gst = Math.max(0, Number(raw.gst_percent) || 0);
        const lineTotal = Math.max(0, (quantity * net) * (1 + gst / 100));
        insert.run(purchaseId, name, clean(raw.company) || null, batch, clean(raw.mfd_date) || null, expiry, quantity, scheme, rate, discount, gst, Math.max(0, Number(raw.mrp) || 0), Math.max(0, Number(raw.mrp3) || 0), Math.max(1, Math.floor(Number(raw.units_per_pack) || inferUnitsPerPack(raw.pack_size) || 1)), net, lineTotal);
      }
      return purchaseId;
    });
    const purchase = db.prepare("SELECT * FROM purchases WHERE id = ?").get(tx());
    audit(req, 'create', 'purchase', purchase.id, `Created purchase ${invoiceNo || purchase.id}`);
    res.status(201).json({ purchase });
  } catch (e) {
    if (req.file) fs.rmSync(req.file.path, { force: true });
    res.status(400).json({ error: e.message || "Could not save purchase record." });
  }
});

app.put("/api/purchases/:id/manual", requireAuth, requireOwnerOrPurchaseOperator, handleBillUpload, (req, res) => {
  const id = Number(req.params.id);
  const purchase = db.prepare("SELECT * FROM purchases WHERE id = ?").get(id);
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });
  
  let items = [];
  try { items = req.body.items_json ? JSON.parse(req.body.items_json) : []; }
  catch { if (req.file) fs.rmSync(req.file.path, { force: true }); return res.status(400).json({ error: "Invalid purchase items data." }); }
  if (!Array.isArray(items) || !items.length) { if (req.file) fs.rmSync(req.file.path, { force: true }); return res.status(400).json({ error: "Add at least one medicine to the purchase." }); }
  const supplierName = clean(req.body.supplier_name);
  const invoiceNo = clean(req.body.invoice_no) || null;
  const purchaseDate = clean(req.body.purchase_date);
  const notes = clean(req.body.notes) || null;
  const paymentMethod = clean(req.body.payment_method) === 'Credit' ? 'Credit' : 'Cash';
  const dueDays = paymentMethod === 'Credit' ? Math.max(0, Math.floor(Number(req.body.due_days) || 0)) : 0;
  const dueDate = paymentMethod === 'Credit' && dueDays > 0 ? new Date(new Date(purchaseDate + 'T00:00:00').getTime() + dueDays*86400000).toISOString().slice(0,10) : null;
  if (!supplierName) { if (req.file) fs.rmSync(req.file.path, { force: true }); return res.status(400).json({ error: "Supplier name is required." }); }
  if (!validISODate(purchaseDate)) { if (req.file) fs.rmSync(req.file.path, { force: true }); return res.status(400).json({ error: "Invalid purchase date." }); }
  try {
    const tx = db.transaction(() => {
      if (purchase.status === 'confirmed') {
        const oldItems = db.prepare('SELECT * FROM purchase_items WHERE purchase_id=?').all(id);
        for (const old of oldItems) {
          const med = db.prepare("SELECT id FROM medicines WHERE lower(name)=lower(?) AND lower(coalesce(company,''))=lower(coalesce(?,'')) ORDER BY id LIMIT 1").get(old.medicine_name, old.company || '');
          if (!med) throw new Error(`Cannot reverse confirmed purchase: medicine ${old.medicine_name} was not found.`);
          const batch = db.prepare('SELECT * FROM batches WHERE medicine_id=? AND batch_no=?').get(med.id, old.batch_no);
          const qty = Number(old.quantity||0) + Number(old.scheme_quantity||0);
          if (!batch || Number(batch.quantity) < qty) throw new Error(`Cannot modify this confirmed purchase because ${old.medicine_name} batch ${old.batch_no} no longer has enough stock to safely reverse the original receipt. Reverse related sales first.`);
          db.prepare('UPDATE batches SET quantity=quantity-?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(qty, batch.id);
        }
      }
      if (req.file) {
        db.prepare(`UPDATE purchases SET supplier_name=?, invoice_no=?, purchase_date=?, payment_method=?, due_days=?, due_date=?, notes=?, bill_original_name=?, bill_file_name=?, bill_mime=?, bill_size=?, status='reviewed' WHERE id=?`).run(supplierName, invoiceNo, purchaseDate, paymentMethod, dueDays, dueDate, notes, req.file.originalname, req.file.filename, req.file.mimetype, req.file.size, id);
      } else {
        db.prepare(`UPDATE purchases SET supplier_name=?, invoice_no=?, purchase_date=?, payment_method=?, due_days=?, due_date=?, notes=?, status='reviewed' WHERE id=?`).run(supplierName, invoiceNo, purchaseDate, paymentMethod, dueDays, dueDate, notes, id);
      }
      db.prepare("DELETE FROM purchase_items WHERE purchase_id=?").run(id);
      const insert = db.prepare(`INSERT INTO purchase_items (purchase_id, medicine_name, company, batch_no, mfd_date, expiry_date, quantity, scheme_quantity, purchase_rate, discount_percent, gst_percent, mrp, mrp3, units_per_pack, net_rate, line_total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      for (const raw of items) {
        const name=clean(raw.medicine_name), batch=clean(raw.batch_no), expiry=clean(raw.expiry_date);
        const quantity=Math.max(0,Math.floor(Number(raw.quantity)||0));
        if(!name) throw new Error("Every purchase row needs a medicine name.");
        if(!batch) throw new Error(`Batch number is required for ${name}.`);
        if(!expiry) throw new Error(`Expiry date is required for ${name}.`);
        if(quantity<=0) throw new Error(`Quantity must be greater than 0 for ${name}.`);
        const rate=Math.max(0,Number(raw.purchase_rate)||0), discount=Math.max(0,Number(raw.discount_percent)||0);
        const net=Math.max(0,Number(raw.net_rate)||rate*(1-discount/100));
        const scheme = Math.max(0, Math.floor(Number(raw.scheme_quantity)||0));
        const gst = Math.max(0, Number(raw.gst_percent)||0);
        const lineTotal = Math.max(0, (quantity * net) * (1 + gst / 100));
        insert.run(id,name,clean(raw.company)||null,batch,clean(raw.mfd_date)||null,expiry,quantity,scheme,rate,discount,gst,Math.max(0,Number(raw.mrp)||0),Math.max(0,Number(raw.mrp3)||0),Math.max(1,Math.floor(Number(raw.units_per_pack)||inferUnitsPerPack(raw.pack_size)||1)),net,lineTotal);
      }
    });
    tx();
    res.json({ok:true,purchase:db.prepare("SELECT * FROM purchases WHERE id=?").get(id)});
  } catch(e) { if(req.file) fs.rmSync(req.file.path,{force:true}); res.status(400).json({error:e.message||"Could not update purchase."}); }
});

app.post("/api/purchases/:id/confirm", requireAuth, requireOwnerOrPurchaseOperator, (req, res) => {
  const id = Number(req.params.id);
  const purchase = db.prepare("SELECT * FROM purchases WHERE id = ?").get(id);
  if (!purchase) return res.status(404).json({ error: "Purchase record not found." });
  if (purchase.status === "confirmed") return res.status(400).json({ error: "This purchase has already been confirmed." });
  const items = db.prepare("SELECT * FROM purchase_items WHERE purchase_id = ? ORDER BY id ASC").all(id);
  if (!items.length) return res.status(400).json({ error: "Add purchase items before confirming." });

  try {
    const tx = db.transaction(() => {
      for (const item of items) {
        const company = clean(item.company);
        let medicine = company
          ? db.prepare("SELECT * FROM medicines WHERE lower(name)=lower(?) AND lower(coalesce(company,''))=lower(?) ORDER BY id LIMIT 1").get(item.medicine_name, company)
          : db.prepare("SELECT * FROM medicines WHERE lower(name)=lower(?) ORDER BY id LIMIT 1").get(item.medicine_name);
        if (!medicine) {
          const result = db.prepare(`INSERT INTO medicines (name, company, units_per_pack) VALUES (?, ?, ?)`).run(item.medicine_name, company || null, Math.max(1, Number(item.units_per_pack) || 1));
          medicine = db.prepare("SELECT * FROM medicines WHERE id = ?").get(result.lastInsertRowid);
        }

        const itemUnitsPerPack = Math.max(1, Number(item.units_per_pack) || Number(medicine.units_per_pack) || 1);
        if (itemUnitsPerPack > 1 && itemUnitsPerPack !== Number(medicine.units_per_pack || 1)) db.prepare('UPDATE medicines SET units_per_pack=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(itemUnitsPerPack, medicine.id);
        const totalQty = item.quantity + item.scheme_quantity;
        const cost = item.net_rate > 0 ? item.net_rate : item.purchase_rate * (1 - item.discount_percent / 100);
        const existing = db.prepare("SELECT * FROM batches WHERE medicine_id = ? AND batch_no = ?").get(medicine.id, item.batch_no);
        if (existing) {
          db.prepare(`UPDATE batches SET mfd_date=?, expiry_date=?, quantity=quantity+?, cost_price=?, selling_price_1=?, selling_price_2=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`).run(
            item.mfd_date || existing.mfd_date, item.expiry_date || existing.expiry_date, totalQty, cost,
            item.mrp > 0 ? item.mrp : existing.selling_price_1,
            item.mrp > 0 ? mrp2FromOriginal(item.mrp) : mrp2FromOriginal(existing.selling_price_1),
            item.mrp3 > 0 ? item.mrp3 : existing.selling_price_3, existing.id
          );
        } else {
          db.prepare(`INSERT INTO batches (medicine_id, batch_no, mfd_date, expiry_date, quantity, cost_price, selling_price_1, selling_price_2, selling_price_3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
            medicine.id, item.batch_no, item.mfd_date || null, item.expiry_date, totalQty, cost, item.mrp,
            mrp2FromOriginal(item.mrp), item.mrp3
          );
        }
      }
      db.prepare("UPDATE purchases SET status='confirmed' WHERE id=?").run(id);
      audit(req, 'confirm', 'purchase', id, `Confirmed purchase ${purchase.invoice_no || id}`);
    });
    tx();
    res.json({ ok: true, purchaseId: id });
  } catch (e) {
    res.status(400).json({ error: e.message || "Could not confirm purchase." });
  }
});

function normalizeSaleItems(items) {
  return items.map(item => {
    const strips = Math.max(0, Math.floor(Number(item.strip_quantity ?? (item.sale_unit === 'strip' ? item.quantity : 0)) || 0));
    const pieces = Math.max(0, Math.floor(Number(item.loose_piece_quantity ?? (item.sale_unit === 'piece' ? item.quantity : 0)) || 0));
    return {
      batchId: Number(item.batch_id), stripQuantity: strips, loosePieceQuantity: pieces,
      priceType: ["selling_price_1","selling_price_2","selling_price_3"].includes(item.price_type) ? item.price_type : "selling_price_1"
    };
  });
}
function restoreSaleStock(saleId) {
  const items = db.prepare("SELECT * FROM sale_items WHERE sale_id=? ORDER BY id").all(saleId);
  for (const item of items) {
    const batch = db.prepare("SELECT * FROM batches WHERE id=?").get(item.batch_id);
    if (!batch) throw new Error(`Batch ${item.batch_no} no longer exists; this sale cannot be safely modified.`);
    const strips = Number(item.strip_quantity || (item.sale_unit === 'strip' ? item.quantity : 0));
    const pieces = Number(item.loose_piece_quantity || (item.sale_unit === 'piece' ? item.quantity : 0));
    db.prepare("UPDATE batches SET quantity=quantity+?, loose_quantity=loose_quantity+?, updated_at=CURRENT_TIMESTAMP WHERE id=?").run(strips, pieces, batch.id);
  }
}
function applySaleItems(items, saleId) {
  const resolved = items.map(item => {
    const row = db.prepare(`SELECT b.*, m.name, m.units_per_pack, m.pack_size FROM batches b JOIN medicines m ON m.id=b.medicine_id WHERE b.id=?`).get(item.batchId);
    if (!row) throw new Error(`Batch ${item.batchId} was not found.`);
    if (new Date(row.expiry_date) < new Date(new Date().toISOString().slice(0,10))) throw new Error(`${row.name} batch ${row.batch_no} is expired.`);
    const unitsPerPack = Math.max(1, Number(row.units_per_pack || inferUnitsPerPack(row.pack_size) || 1));
    if (unitsPerPack <= 1 && item.loosePieceQuantity > 0) throw new Error(`${row.name} is not configured for loose-piece sales.`);
    const strips = item.stripQuantity;
    const pieces = item.loosePieceQuantity;
    if (strips <= 0 && pieces <= 0) throw new Error(`Enter a strip or loose-piece quantity for ${row.name}.`);
    if (Number(row.quantity) < strips) throw new Error(`Not enough strip stock for ${row.name} (batch ${row.batch_no}). Available: ${row.quantity} strips.`);
    const availablePieces = Number(row.quantity) * unitsPerPack + Number(row.loose_quantity || 0);
    if (strips * unitsPerPack + pieces > availablePieces) throw new Error(`Not enough total stock for ${row.name} (batch ${row.batch_no}).`);
    // Selling loose pieces may require opening a strip. Consume existing loose first, then open strips.
    let packs = Number(row.quantity) - strips;
    let loose = Number(row.loose_quantity || 0);
    let remainingPieces = pieces;
    const fromLoose = Math.min(loose, remainingPieces); loose -= fromLoose; remainingPieces -= fromLoose;
    if (remainingPieces > 0) {
      const opened = Math.ceil(remainingPieces / unitsPerPack);
      if (packs < opened) throw new Error(`Not enough unopened strips to create ${pieces} loose pieces of ${row.name}.`);
      packs -= opened;
      loose += opened * unitsPerPack - remainingPieces;
    }
    const stripPrice = Number(row[item.priceType] || 0);
    if (strips > 0 && stripPrice <= 0) throw new Error(`Selected selling price is not configured for ${row.name}.`);
    const piecePrice = unitsPerPack > 1 ? (Number(row.selling_price_1 || 0) / unitsPerPack) * 1.10 : 0;
    if (pieces > 0 && piecePrice <= 0) throw new Error(`MRP is not configured for loose sales of ${row.name}.`);
    const amount = strips * stripPrice + pieces * piecePrice;
    const costTotal = strips * Number(row.cost_price || 0) + pieces * (Number(row.cost_price || 0) / unitsPerPack);
    return {...item, row, unitsPerPack, amount, costTotal, stripStockAfter:packs, looseStockAfter:loose};
  });
  const seen = new Set();
  if (resolved.some(i => seen.has(i.batchId) || !seen.add(i.batchId))) throw new Error("A batch can only appear once in an invoice.");
  const insertItem = db.prepare(`INSERT INTO sale_items (sale_id, medicine_id, batch_id, medicine_name, batch_no, quantity, sale_unit, units_per_pack, unit_price, amount, cost_price, strip_quantity, loose_piece_quantity, cost_total, price_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  const updateBatch = db.prepare("UPDATE batches SET quantity=?, loose_quantity=?, updated_at=CURRENT_TIMESTAMP WHERE id=?");
  for (const item of resolved) {
    const displayQuantity = item.stripQuantity + item.loosePieceQuantity;
    const primaryPrice = item.stripQuantity > 0 ? Number(item.row[item.priceType]||0) : (Number(item.row.selling_price_1||0)/item.unitsPerPack)*1.10;
    const primaryUnit = item.stripQuantity > 0 ? 'strip' : 'piece';
    insertItem.run(saleId,item.row.medicine_id,item.row.id,item.row.name,item.row.batch_no,displayQuantity,primaryUnit,item.unitsPerPack,primaryPrice,item.amount,primaryUnit==='strip'?Number(item.row.cost_price||0):Number(item.row.cost_price||0)/item.unitsPerPack,item.stripQuantity,item.loosePieceQuantity,item.costTotal,item.priceType);
    updateBatch.run(item.stripStockAfter,item.looseStockAfter,item.row.id);
  }
  return resolved.reduce((sum,i)=>sum+i.amount,0);
}
app.post("/api/sales", requireAuth, requireOperations, (req, res) => {
  const customerName = clean(req.body.customer_name) || null, customerPhone = clean(req.body.customer_phone) || null;
  const saleDate = clean(req.body.sale_date) || new Date().toISOString().slice(0,10), items = normalizeSaleItems(Array.isArray(req.body.items)?req.body.items:[]);
  if (!items.length) return res.status(400).json({error:"Add at least one medicine to the sale."});
  if (!validISODate(saleDate)) return res.status(400).json({error:"Invalid sale date."});
  try {
    const saleId=db.transaction(()=>{
      const saleResult=db.prepare(`INSERT INTO sales (invoice_no, customer_name, customer_phone, sale_date, total_amount, payment_method, discount_amount, notes, created_by) VALUES ('PENDING',?,?,?,?,?,?,?,?)`).run(customerName,customerPhone,saleDate,0,clean(req.body.payment_method)||'Cash',0,clean(req.body.notes)||null,req.user.id);
      const id=Number(saleResult.lastInsertRowid); const subtotal=applySaleItems(items,id); const discount=Math.min(subtotal,numberValue(req.body.discount_amount));
      const total=Math.max(0,subtotal-discount); const invoiceNo=`SNMS-${saleDate.replaceAll('-','')}-${String(id).padStart(6,'0')}`;
      db.prepare("UPDATE sales SET invoice_no=?, total_amount=?, discount_amount=? WHERE id=?").run(invoiceNo,total,discount,id); audit(req,'create','sale',id,`Created sale ${invoiceNo}`); return id;
    })();
    res.status(201).json({sale:db.prepare("SELECT * FROM sales WHERE id=?").get(saleId),items:db.prepare("SELECT * FROM sale_items WHERE sale_id=? ORDER BY id").all(saleId)});
  } catch(e){res.status(400).json({error:e.message||"Could not create sale."});}
});
app.put("/api/sales/:id", requireAuth, requireOperations, (req,res)=>{
  const id=Number(req.params.id), sale=db.prepare("SELECT * FROM sales WHERE id=?").get(id); if(!sale)return res.status(404).json({error:"Sale not found."});
  const items=normalizeSaleItems(Array.isArray(req.body.items)?req.body.items:[]); if(!items.length)return res.status(400).json({error:"Add at least one medicine to the sale."});
  if(!validISODate(clean(req.body.sale_date)))return res.status(400).json({error:"Invalid sale date."});
  const hasReturns=db.prepare("SELECT COUNT(*) n FROM sale_return_items sri JOIN sale_items si ON si.id=sri.sale_item_id WHERE si.sale_id=?").get(id).n; if(hasReturns)return res.status(400).json({error:"This sale has a return recorded and cannot be modified safely. Use a new sale/return instead."});
  try { db.transaction(()=>{restoreSaleStock(id); db.prepare("DELETE FROM sale_items WHERE sale_id=?").run(id); const subtotal=applySaleItems(items,id); const discount=Math.min(subtotal,numberValue(req.body.discount_amount)); const total=Math.max(0,subtotal-discount); db.prepare("UPDATE sales SET customer_name=?,customer_phone=?,sale_date=?,total_amount=?,payment_method=?,discount_amount=?,notes=? WHERE id=?").run(clean(req.body.customer_name)||null,clean(req.body.customer_phone)||null,clean(req.body.sale_date),total,clean(req.body.payment_method)||'Cash',discount,clean(req.body.notes)||null,id); audit(req,'update','sale',id,`Modified sale ${sale.invoice_no}`); })(); res.json({sale:db.prepare("SELECT * FROM sales WHERE id=?").get(id),items:db.prepare("SELECT * FROM sale_items WHERE sale_id=? ORDER BY id").all(id)}); } catch(e){res.status(400).json({error:e.message||"Could not modify sale."});}
});

app.get("/api/insights", requireAuth, requireOwner, (req, res) => {
  const today = db.prepare("SELECT date('now') AS d").get().d;
  const salesToday = db.prepare("SELECT COALESCE(SUM(total_amount),0) AS n FROM sales WHERE sale_date = ?").get(today).n;
  const salesMonth = db.prepare("SELECT COALESCE(SUM(total_amount),0) AS n FROM sales WHERE strftime('%Y-%m',sale_date)=strftime('%Y-%m','now')").get().n;
  const purchaseMonth = db.prepare("SELECT COALESCE(SUM(line_total),0) AS n FROM purchase_items pi JOIN purchases p ON p.id=pi.purchase_id WHERE p.status='confirmed' AND strftime('%Y-%m',p.purchase_date)=strftime('%Y-%m','now')").get().n;
  const profitMonth = db.prepare("SELECT COALESCE(SUM(si.amount-COALESCE(si.cost_total,si.cost_price*si.quantity)),0) AS n FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE strftime('%Y-%m',s.sale_date)=strftime('%Y-%m','now')").get().n;
  const stockValue = db.prepare("SELECT COALESCE(SUM(quantity*cost_price + loose_quantity*(cost_price/CASE WHEN (SELECT units_per_pack FROM medicines m WHERE m.id=batches.medicine_id)>0 THEN (SELECT units_per_pack FROM medicines m2 WHERE m2.id=batches.medicine_id) ELSE 1 END)),0) AS n FROM batches").get().n;
  const expiring = db.prepare("SELECT m.name,b.batch_no,b.expiry_date,b.quantity FROM batches b JOIN medicines m ON m.id=b.medicine_id WHERE b.quantity>0 AND date(b.expiry_date)>=date('now') AND date(b.expiry_date)<date('now','+90 days') ORDER BY date(b.expiry_date) LIMIT 8").all();
  const fast = db.prepare("SELECT si.medicine_name, SUM(si.quantity) qty, SUM(si.amount) revenue, SUM(si.amount-COALESCE(si.cost_total,si.cost_price*si.quantity)) profit FROM sale_items si JOIN sales s ON s.id=si.sale_id WHERE date(s.sale_date)>=date('now','-30 days') GROUP BY si.medicine_id ORDER BY qty DESC LIMIT 8").all();
  const suppliers = db.prepare("SELECT supplier_name, COUNT(*) invoices, COALESCE(SUM((SELECT COALESCE(SUM(line_total),0) FROM purchase_items pi WHERE pi.purchase_id=p.id)),0) total FROM purchases p WHERE p.status='confirmed' GROUP BY supplier_name ORDER BY total DESC LIMIT 8").all();
  res.json({today,salesToday,salesMonth,purchaseMonth,profitMonth,stockValue,expiring,fast,suppliers});
});

app.get("/api/customers", requireAuth, requireOwner, (req, res) => {
  res.json(db.prepare("SELECT COALESCE(NULLIF(TRIM(customer_name),''),'Walk-in customer') name, MAX(customer_phone) phone, COUNT(*) invoices, COALESCE(SUM(total_amount),0) total_spent, MAX(sale_date) last_sale FROM sales GROUP BY COALESCE(NULLIF(TRIM(customer_name),''),'Walk-in customer') ORDER BY total_spent DESC LIMIT 200").all());
});

app.get("/api/suppliers/search", requireAuth, requireOwner, (req,res)=>{ const q=clean(req.query.q); const rows=db.prepare(`SELECT supplier_name name, COUNT(*) invoices, MAX(purchase_date) last_purchase, COALESCE(SUM((SELECT COALESCE(SUM(line_total),0) FROM purchase_items pi WHERE pi.purchase_id=p.id)),0) total_purchased, SUM(CASE WHEN p.payment_method='Credit' AND p.due_date IS NOT NULL AND date(p.due_date)>=date('now') THEN 1 ELSE 0 END) credit_bills FROM purchases p WHERE p.status='confirmed' AND (?='' OR supplier_name LIKE '%'||?||'%') GROUP BY supplier_name ORDER BY supplier_name COLLATE NOCASE`).all(q,q); res.json(rows); });
app.get("/api/suppliers/:name/bills", requireAuth, requireOwner, (req,res)=>{ const name=clean(req.params.name); const rows=db.prepare(`SELECT p.id,p.supplier_name,p.invoice_no,p.purchase_date,p.payment_method,p.due_days,p.due_date,p.status,(SELECT COALESCE(SUM(line_total),0) FROM purchase_items pi WHERE pi.purchase_id=p.id) total_amount FROM purchases p WHERE p.status='confirmed' AND lower(p.supplier_name)=lower(?) ORDER BY p.purchase_date DESC,p.id DESC`).all(name); res.json(rows); });
app.get("/api/suppliers", requireAuth, requireOwner, (req, res) => {
  res.json(db.prepare("SELECT supplier_name name, COUNT(*) invoices, MAX(purchase_date) last_purchase, COALESCE(SUM((SELECT COALESCE(SUM(line_total),0) FROM purchase_items pi WHERE pi.purchase_id=p.id)),0) total_purchased FROM purchases p WHERE p.status='confirmed' GROUP BY supplier_name ORDER BY total_purchased DESC LIMIT 200").all());
});

app.get("/api/audit", requireAuth, requireOwner, (req, res) => {
  res.json(db.prepare("SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200").all());
});

app.post("/api/sales/:id/return", requireAuth, requireOperations, (req, res) => {
  const saleId=Number(req.params.id), sale=db.prepare("SELECT * FROM sales WHERE id=?").get(saleId);
  if(!sale)return res.status(404).json({error:"Sale not found."});
  const items=Array.isArray(req.body.items)?req.body.items:[]; if(!items.length)return res.status(400).json({error:"Select at least one item to return."});
  const tx=db.transaction(()=>{
    const resolved=[];
    for(const raw of items){
      const saleItem=db.prepare("SELECT si.*, b.quantity stock_qty, b.loose_quantity FROM sale_items si JOIN batches b ON b.id=si.batch_id WHERE si.id=? AND si.sale_id=?").get(Number(raw.sale_item_id),saleId);
      const qty=Math.floor(Number(raw.quantity)); if(!saleItem||!Number.isInteger(qty)||qty<1||qty>saleItem.quantity)throw new Error("Invalid return quantity.");
      const already=db.prepare("SELECT COALESCE(SUM(quantity),0) n FROM sale_return_items sri JOIN sale_returns sr ON sr.id=sri.return_id WHERE sri.sale_item_id=?").get(saleItem.id).n;
      if(qty+already>saleItem.quantity)throw new Error(`Return quantity exceeds sold quantity for ${saleItem.medicine_name}.`);
      resolved.push({...saleItem,qty});
    }
    const total=resolved.reduce((n,x)=>n+x.qty*x.unit_price,0);
    const rr=db.prepare("INSERT INTO sale_returns (return_no,sale_id,return_date,total_amount,reason,created_by) VALUES (?,?,?,?,?,?)").run(`PENDING-${Date.now()}`,saleId,clean(req.body.return_date)||new Date().toISOString().slice(0,10),total,clean(req.body.reason)||null,req.user.id);
    const rid=Number(rr.lastInsertRowid),returnNo=`SNR-${new Date().toISOString().slice(0,10).replaceAll('-','')}-${String(rid).padStart(5,'0')}`; db.prepare("UPDATE sale_returns SET return_no=? WHERE id=?").run(returnNo,rid);
    const ins=db.prepare("INSERT INTO sale_return_items (return_id,sale_item_id,batch_id,medicine_name,batch_no,quantity,sale_unit,units_per_pack,unit_price,amount) VALUES (?,?,?,?,?,?,?,?,?,?)");
    for(const x of resolved){
      ins.run(rid,x.id,x.batch_id,x.medicine_name,x.batch_no,x.qty,x.sale_unit||'strip',x.units_per_pack||1,x.unit_price,x.qty*x.unit_price);
      if(x.sale_unit==='strip') db.prepare("UPDATE batches SET quantity=quantity+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(x.qty,x.batch_id);
      else db.prepare("UPDATE batches SET loose_quantity=loose_quantity+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(x.qty,x.batch_id);
    }
    audit(req,'create','sale_return',rid,`Return ${returnNo} against ${sale.invoice_no}`); return rid;
  });
  try{const id=tx();res.status(201).json({return:db.prepare("SELECT * FROM sale_returns WHERE id=?").get(id)});}catch(e){res.status(400).json({error:e.message||"Could not process return."});}
});


function validAccessRole(role) {
  return [ROLES.OWNER, ROLES.AUTHORIZED, ROLES.STAFF].includes(role);
}

app.get("/api/users", requireAuth, requireOwner, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, access_role AS role, active, created_at
    FROM users ORDER BY id ASC
  `).all();
  res.json(users);
});

app.post("/api/users", requireAuth, requireOwner, (req, res) => {
  const username = clean(req.body.username);
  const password = String(req.body.password || "");
  const role = clean(req.body.role);
  if (!/^[A-Za-z0-9._-]{3,40}$/.test(username)) return res.status(400).json({ error: "Username must be 3-40 characters and use letters, numbers, dot, underscore or hyphen." });
  if (password.length < 10) return res.status(400).json({ error: "Password must be at least 10 characters." });
  if (!validAccessRole(role)) return res.status(400).json({ error: "Invalid user role." });
  try {
    const hash = bcrypt.hashSync(password, 12);
    const result = db.prepare(`
      INSERT INTO users (username, password_hash, role, access_role, active)
      VALUES (?, ?, ?, ?, 1)
    `).run(username, hash, role === ROLES.OWNER ? "admin" : "staff", role);
    audit(req, "create", "user", result.lastInsertRowid, `Created ${role} user ${username}`);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error: "That username already exists." });
    res.status(400).json({ error: "Could not create user." });
  }
});

app.patch("/api/users/:id", requireAuth, requireOwner, (req, res) => {
  const id = Number(req.params.id);
  const user = db.prepare("SELECT id, username, access_role FROM users WHERE id=?").get(id);
  if (!user) return res.status(404).json({ error: "User not found." });
  if (id === req.user.id && req.body.active === false) return res.status(400).json({ error: "You cannot deactivate your own account." });
  const updates = [];
  const params = [];
  if (req.body.role !== undefined) {
    const role = clean(req.body.role);
    if (!validAccessRole(role)) return res.status(400).json({ error: "Invalid user role." });
    if (id === req.user.id && role !== ROLES.OWNER) return res.status(400).json({ error: "The current owner account cannot be changed to a lower access level." });
    if (user.access_role === ROLES.OWNER && role !== ROLES.OWNER) {
      const owners = db.prepare("SELECT COUNT(*) AS n FROM users WHERE access_role=? AND active=1").get(ROLES.OWNER).n;
      if (owners <= 1) return res.status(400).json({ error: "At least one active owner account must remain." });
    }
    updates.push("access_role=?", "role=?");
    params.push(role, role === ROLES.OWNER ? "admin" : "staff");
  }
  if (req.body.active !== undefined) {
    if (!req.body.active && user.access_role === ROLES.OWNER) {
      const owners = db.prepare("SELECT COUNT(*) AS n FROM users WHERE access_role=? AND active=1").get(ROLES.OWNER).n;
      if (owners <= 1) return res.status(400).json({ error: "At least one active owner account must remain." });
    }
    updates.push("active=?");
    params.push(req.body.active ? 1 : 0);
  }
  if (req.body.password !== undefined) {
    const password = String(req.body.password || "");
    if (password.length < 10) return res.status(400).json({ error: "Password must be at least 10 characters." });
    updates.push("password_hash=?");
    params.push(bcrypt.hashSync(password, 12));
  }
  if (!updates.length) return res.status(400).json({ error: "No changes supplied." });
  params.push(id);
  db.prepare(`UPDATE users SET ${updates.join(", ")} WHERE id=?`).run(...params);
  if (req.body.active === false) db.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
  audit(req, "update", "user", id, `Updated user ${user.username}`);
  res.json({ ok: true });
});

async function createBackupBundle() {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const tempDb = path.join(backupDir, `stock-${stamp}.db`);
  const bundlePath = path.join(backupDir, `SNMS-backup-${stamp}.snmsbackup`);
  await db.backup(tempDb);
  const files = [];
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else {
        const rel = path.relative(uploadDir, full).replaceAll(path.sep, "/");
        files.push({
          path: rel,
          data_base64: fs.readFileSync(full).toString("base64")
        });
      }
    }
  }
  walk(uploadDir);
  const bundle = {
    format: "SNMS-FULL-BACKUP",
    version: 1,
    created_at: new Date().toISOString(),
    warning: "Contains confidential pharmacy data. Store securely.",
    database_base64: fs.readFileSync(tempDb).toString("base64"),
    uploaded_files: files
  };
  fs.writeFileSync(bundlePath, JSON.stringify(bundle));
  fs.rmSync(tempDb, { force: true });

  const old = fs.readdirSync(backupDir)
    .filter(n => n.endsWith(".snmsbackup"))
    .sort()
    .reverse();
  for (const name of old.slice(7)) fs.rmSync(path.join(backupDir, name), { force: true });
  return bundlePath;
}

app.get("/api/backup", requireAuth, requireOwner, async (req, res) => {
  try {
    const filePath = await createBackupBundle();
    audit(req, "backup", "system", null, `Created full backup ${path.basename(filePath)}`);
    res.download(filePath, path.basename(filePath));
  } catch (e) {
    res.status(500).json({ error: "Could not create the full backup." });
  }
});

if (AUTO_BACKUP_HOURS > 0) {
  setTimeout(() => { createBackupBundle().catch(() => {}); }, 30000);
  setInterval(() => { createBackupBundle().catch(() => {}); }, AUTO_BACKUP_HOURS * 60 * 60 * 1000);
}

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Shree Nathela Medical Stores running at http://localhost:${PORT}`);
});
