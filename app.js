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

const swaggerOptions = {
  swaggerDefinition: {
    openapi: '3.0.0',
    info: {
      title: 'GPS Tracking API',
      version: '1.0.0',
      description: 'API documentation for GPS Tracking system',
    },
    servers: [
      {
        url: `http://localhost:${port}`,
      },
    ],
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


const dbConfig = {
  user: 'postgres',
  host: 'localhost',
  database: 'gps_tracking',
  password: '123',
  port: 5432,
};

const pool = new Pool(dbConfig);


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
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     username:
 *                       type: string
 *                     role:
 *                       type: string
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
    return res.status(400).json({ error: 'Username dan password harus diisi' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: 'Username atau password tidak valid' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Username atau password tidak valid' });
    }

    const token = jwt.sign({ id: user.id, role: user.role }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
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
/**
 * @swagger
 * /api/drivers:
 *   get:
 *     summary: Retrieve a list of drivers
 *     tags: [Drivers]
 *     parameters:
 *       - in: query
 *         name: jenis_kendaraan
 *         required: false
 *         description: The type of vehicle to filter drivers
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: A list of drivers
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   name:
 *                     type: string
 *                   vehicle_number:
 *                     type: string
 *                   phone:
 *                     type: string
 *                   status:
 *                     type: string
 *                   vehicle_type:
 *                     type: string
 *                   ktp_url:
 *                     type: string
 *                   sim_url:
 *                     type: string
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */
app.get('/api/drivers', authenticateJWT, async (req, res) => {
  const { jenis_kendaraan } = req.query;
  let query = 'SELECT * FROM drivers';
  const params = [];

  if (jenis_kendaraan) {
    query += ' WHERE vehicle_type = $1';
    params.push(jenis_kendaraan);
  }

  try {
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * @swagger
 * /api/drivers:
 *   post:
 *     summary: Add a new driver
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               phone:
 *                 type: string
 *               status:
 *                 type: string
 *               vehicleType:
 *                 type: string
 *               ktp:
 *                 type: string
 *                 format: binary
 *               sim:
 *                 type: string
 *                 format: binary
 *     responses:
 *       201:
 *         description: Driver created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 name:
 *                   type: string
 *                 vehicleNumber:
 *                   type: string
 *                 phone:
 *                   type: string
 *                 status:
 *                   type: string
 *                 vehicle_type:
 *                   type: string
 *                 ktp:
 *                   type: string
 *                 sim:
 *                   type: string
 *       403:
 *         description: Forbidden
 *       500:
 *         description: Internal server error
 */
app.post('/api/drivers', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }

  upload.fields([{ name: 'ktp' }, { name: 'sim' }])(req, res, async (err) => {
    if (err) return res.status(500).send(err);

    const { name, vehicleNumber, phone, status, vehicleType } = req.body;
    const ktpFile = req.files['ktp'] ? req.files['ktp'][0].filename : null;
    const simFile = req.files['sim'] ? req.files['sim'][0].filename : null;

    try {
      const result = await pool.query(
        'INSERT INTO drivers (name, vehicle_number, phone, status, vehicle_type, ktp_url, sim_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id',
        [name, vehicleNumber, phone, status, vehicleType, ktpFile, simFile]
      );
      res.status(201).json({ id: result.rows[0].id, name, vehicleNumber, phone, status, vehicle_type: vehicleType, ktp: ktpFile, sim: simFile });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
});
// Mengupdate Driver
/**
 * @swagger
 * /api/drivers/{id}:
 *   put:
 *     summary: Update a driver
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID driver yang ingin diperbarui
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               phone:
 *                 type: string
 *               status:
 *                 type: string
 *               vehicleType:
 *                 type: string
 *               ktp:
 *                 type: string
 *                 format: binary
 *               sim:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Driver updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 name:
 *                   type: string
 *                 vehicleNumber:
 *                   type: string
 *                 phone:
 *                   type: string
 *                 status:
 *                   type: string
 *                 vehicle_type:
 *                   type: string
 *                 ktp:
 *                   type: string
 *                 sim:
 *                   type: string
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Driver not found
 *       500:
 *         description: Internal server error
 */
app.put('/api/drivers/:id', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }

  const driverId = req.params.id;

  upload.fields([{ name: 'ktp' }, { name: 'sim' }])(req, res, async (err) => {
    if (err) return res.status(500).send(err);

    const { name, vehicleNumber, phone, status, vehicleType } = req.body;
    const ktpFile = req.files['ktp'] ? req.files['ktp'][0].filename : null;
    const simFile = req.files['sim'] ? req.files['sim'][0].filename : null;

    try {
      const result = await pool.query(
        'UPDATE drivers SET name = $1, vehicle_number = $2, phone = $3, status = $4, vehicle_type = $5, ktp_url = $6, sim_url = $7 WHERE id = $8 RETURNING id',
        [name, vehicleNumber, phone, status, vehicleType, ktpFile, simFile, driverId]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({ error: 'Driver tidak ditemukan' });
      }

      res.json({
        id: result.rows[0].id,
        name,
        vehicleNumber,
        phone,
        status,
        vehicle_type: vehicleType,
        ktp: ktpFile,
        sim: simFile,
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
});

// Menghapus Driver
/**
 * @swagger
 * /api/drivers/{id}:
 *   delete:
 *     summary: Delete a driver
 *     tags: [Drivers]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID driver yang ingin dihapus
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Driver deleted
 *       403:
 *         description: Forbidden
 *       404:
 *         description: Driver not found
 *       500:
 *         description: Internal server error
 */
app.delete('/api/drivers/:id', authenticateJWT, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }

  const driverId = req.params.id;

  try {
    const result = await pool.query('DELETE FROM drivers WHERE id = $1', [driverId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Driver tidak ditemukan' });
    }

    res.sendStatus(204);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mendapatkan Detail Driver
/**
 * @swagger
 * /api/drivers/{id}:
 *   get:
 *     summary: Retrieve a driver by ID
 *     tags: [Drivers]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID driver yang ingin diambil
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Driver details
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 name:
 *                   type: string
 *                 vehicle_number:
 *                   type: string
 *                 phone:
 *                   type: string
 *                 status:
 *                   type: string
 *                 vehicle_type:
 *                   type: string
 *                 ktp_url:
 *                   type: string
 *                 sim_url:
 *                   type: string
 *       404:
 *         description: Driver not found
 *       500:
 *         description: Internal server error
 */
app.get('/api/drivers/:id', authenticateJWT, async (req, res) => {
  const driverId = req.params.id;

  try {
    const result = await pool.query('SELECT * FROM drivers WHERE id = $1', [driverId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Driver tidak ditemukan' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mendapatkan daftar kendaraan (Contoh)
// Endpoint ini hanya sebagai contoh, silakan sesuaikan dengan kebutuhan
/**
 * @swagger
 * /api/vehicles:
 *   get:
 *     summary: Retrieve a list of vehicles
 *     tags: [Vehicles]
 *     responses:
 *       200:
 *         description: A list of vehicles
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   vehicle_number:
 *                     type: string
 *                   vehicle_type:
 *                     type: string
 *       500:
 *         description: Internal server error
 */
app.get('/api/vehicles', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM vehicles');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Menjalankan server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
