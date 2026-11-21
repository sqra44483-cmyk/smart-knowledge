require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET || !DATABASE_URL) {
  throw new Error('Missing required environment variables');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || false
}));
app.use(express.json({ limit: '20kb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'student',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS manager_cards (
      id SERIAL PRIMARY KEY,
      card_hash TEXT NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({
      message: 'يرجى تسجيل الدخول'
    });
  }

  try {
    req.user = jwt.verify(
      header.substring(7),
      JWT_SECRET
    );
    next();
  } catch {
    return res.status(401).json({
      message: 'جلسة الدخول غير صالحة'
    });
  }
}

function managerOnly(req, res, next) {
  if (req.user.role !== 'manager') {
    return res.status(403).json({
      message: 'غير مصرح لك بالدخول'
    });
  }

  next();
}

app.get('/', (req, res) => {
  res.json({
    name: 'Smart Knowledge',
    status: 'running',
    version: '2.0.0'
  });
});

// تسجيل طالب جديد
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: 'جميع الحقول مطلوبة'
      });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({
        message: 'البريد الإلكتروني غير صحيح'
      });
    }

    if (String(password).length < 10) {
      return res.status(400).json({
        message: 'كلمة المرور يجب ألا تقل عن 10 أحرف'
      });
    }

    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [normalizedEmail]
    );

    if (existing.rows.length) {
      return res.status(409).json({
        message: 'البريد الإلكتروني مسجل مسبقاً'
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES ($1, $2, $3, 'student')
       RETURNING id, name, email, role`,
      [String(name).trim(), normalizedEmail, passwordHash]
    );

    res.status(201).json({
      message: 'تم إنشاء حساب الطالب بنجاح',
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Registration error:', error.message);

    res.status(500).json({
      message: 'حدث خطأ أثناء التسجيل'
    });
  }
});

// تسجيل الدخول
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: 'البريد الإلكتروني وكلمة المرور مطلوبان'
      });
    }

    const result = await pool.query(
      `SELECT id, name, email, password_hash, role
       FROM users WHERE email = $1`,
      [String(email).trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة'
      });
    }

    const token = createToken(user);

    res.json({
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error.message);

    res.status(500).json({
      message: 'حدث خطأ أثناء تسجيل الدخول'
    });
  }
});

// بيانات المستخدم الحالي
app.get('/api/auth/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, role
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        message: 'الحساب غير موجود'
      });
    }

    res.json({ user: result.rows[0] });

  } catch (error) {
    res.status(500).json({
      message: 'تعذر جلب بيانات الحساب'
    });
  }
});

// لوحة تحكم المدير
app.get(
  '/api/admin/dashboard',
  authenticate,
  managerOnly,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT
          COUNT(*) AS total_students
         FROM users
         WHERE role = 'student'`
      );

      res.json({
        message: 'مرحباً بك في لوحة تحكم المدير',
        totalStudents: Number(result.rows[0].total_students)
      });

    } catch (error) {
      res.status(500).json({
        message: 'تعذر تحميل لوحة التحكم'
      });
    }
  }
);

// فحص حالة الخادم
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'Smart Knowledge'
  });
});

async function startServer() {
  await initializeDatabase();

  app.listen(PORT, () => {
    console.log(`Smart Knowledge running on port ${PORT}`);
  });
}

startServer().catch(error => {
  console.error('Server startup failed:', error);
  process.exit(1);
});
