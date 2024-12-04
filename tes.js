const express = require('express');
const multer = require('multer');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
const port = 1000;

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Swagger configuration
const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'GPS Tracking API',
      version: '1.0.0',
      description: 'API documentation for GPS Tracking system',
    },
    servers: [{ url: `http://localhost:${port}` }],
  },
  apis: ['./app.js'],
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// Database configuration
const dbConfig = {
  user: 'postgres',
  host: 'localhost',
  database: 'gps_tracking',
  password: '123',
  port: 5432,
};

const pool = new Pool(dbConfig);

// JWT Authentication middleware
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.sendStatus(403);
  }

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

/**
 * @swagger
 * /api/register:
 *   post:
 *     summary: Register a new company
 *     tags: [Companies]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               companyName:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               features:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: Company registered successfully
 *       400:
 *         description: Bad request
 *       500:
 *         description: Internal server error
 */
app.post('/api/register', async (req, res) => {
  const { companyName, username, password, features } = req.body;

  if (!companyName || !username || !password) {
    return res.status(400).json({ error: 'Company name, username, and password are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO companies (name, username, password, features) VALUES ($1, $2, $3, $4) RETURNING id',
      [companyName, username, hashedPassword, features]
    );

    res.status(201).json({ id: result.rows[0].id, companyName });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/login:
 *   post:
 *     summary: Login a user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login
 *       400:
 *         description: Bad request
 *       401:
 *         description: Invalid credentials
 *       500:
 *         description: Internal server error
 */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM companies WHERE username = $1', [username]);
    const company = result.rows[0];

    if (!company) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, company.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: company.id, role: 'company' }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token, company: { id: company.id, companyName: company.name, features: company.features } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/features:
 *   get:
 *     summary: Get features accessible by the logged-in company
 *     tags: [Features]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: A list of features
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */
app.get('/api/features', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query('SELECT features FROM companies WHERE id = $1', [req.user.id]);
    const features = result.rows[0]?.features || [];
    res.json({ features });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin functionality for managing companies
/**
 * @swagger
 * /api/admin/register:
 *   post:
 *     summary: Admin registers a new company
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               companyName:
 *                 type: string
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               features:
 *                 type: array
 *                 items:
 *                   type: string
 *     responses:
 *       201:
 *         description: Company registered successfully by admin
 *       400:
 *         description: Bad request
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */
app.post('/api/admin/register', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }

  const { companyName, username, password, features } = req.body;

  if (!companyName || !username || !password) {
    return res.status(400).json({ error: 'Company name, username, and password are required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO companies (name, username, password, features) VALUES ($1, $2, $3, $4) RETURNING id',
      [companyName, username, hashedPassword, features]
    );

    res.status(201).json({ id: result.rows[0].id, companyName });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
