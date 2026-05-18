// ================================================================
// server.js — Booking & Service Management System
// ລະບົບຈອງຕ໋ວ/ບໍລິການ — Complete REST API
// ================================================================
// npm install express mysql2 dotenv bcrypt jsonwebtoken

const express  = require('express');
const db       = require('./db');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
require('dotenv').config();

const app  = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

app.use(express.json());

// ----------------------------------------------------------------
// MIDDLEWARE — ກວດ Token (auth)
// ----------------------------------------------------------------
function auth(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'ບໍ່ມີ Token' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ success: false, message: 'Token ບໍ່ຖືກຕ້ອງ' });
    }
}

// ----------------------------------------------------------------
// ROOT
// ----------------------------------------------------------------
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: 'Booking API ກຳລັງເຮັດວຽກ ✅',
        version: '1.0.0'
    });
});

// ================================================================
// 1. ROLES API
// ================================================================

// GET /api/roles — ດຶງ roles ທັງໝົດ
app.get('/api/roles', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM roles');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/roles/:id — ດຶງ role ຕາມ ID
app.get('/api/roles/:id', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM roles WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ Role' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/roles — ສ້າງ role ໃໝ່
app.post('/api/roles', auth, async (req, res) => {
    try {
        const { name, permissions } = req.body;
        if (!name) return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຊື່ Role' });
        const [result] = await db.query(
            'INSERT INTO roles (name, permissions) VALUES (?, ?)',
            [name, JSON.stringify(permissions || [])]
        );
        res.status(201).json({ success: true, message: 'ສ້າງ Role ສຳເລັດ', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 2. AUTH API (Register / Login)
// ================================================================

// POST /api/register — ລົງທະບຽນ
app.post('/api/register', async (req, res) => {
    try {
        const { role_id, name, email, password, phone } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຂໍ້ມູນໃຫ້ຄົບ' });
        }
        // ກວດ email ຊ້ຳ
        const [exist] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
        if (exist.length) return res.status(409).json({ success: false, message: 'Email ນີ້ຖືກໃຊ້ແລ້ວ' });

        const hashed = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            'INSERT INTO users (role_id, name, email, password_hash, phone) VALUES (?, ?, ?, ?, ?)',
            [role_id || 3, name, email, hashed, phone || null]
        );
        res.status(201).json({ success: true, message: 'ລົງທະບຽນສຳເລັດ!', userId: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/login — ເຂົ້າລະບົບ
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ Email ແລະ Password' });
        }
        const [rows] = await db.query(
            'SELECT u.*, r.name AS role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE u.email = ? AND u.is_active = 1',
            [email]
        );
        if (!rows.length) return res.status(401).json({ success: false, message: 'Email ຫຼື Password ບໍ່ຖືກຕ້ອງ' });

        const user = rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ success: false, message: 'Email ຫຼື Password ບໍ່ຖືກຕ້ອງ' });

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role_name },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        res.json({
            success: true,
            message: 'ເຂົ້າລະບົບສຳເລັດ',
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role_name }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 3. USERS API
// ================================================================

// GET /api/users — ດຶງ users ທັງໝົດ
app.get('/api/users', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT u.id, u.name, u.email, u.phone, u.is_active, u.created_at, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id'
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/users/:id — ດຶງ user ຕາມ ID
app.get('/api/users/:id', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT u.id, u.name, u.email, u.phone, u.is_active, u.created_at, r.name AS role FROM users u JOIN roles r ON u.role_id = r.id WHERE u.id = ?',
            [req.params.id]
        );
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ User' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/users/:id — ອັບເດດ user
app.put('/api/users/:id', auth, async (req, res) => {
    try {
        const { name, phone, is_active } = req.body;
        await db.query(
            'UPDATE users SET name = COALESCE(?, name), phone = COALESCE(?, phone), is_active = COALESCE(?, is_active) WHERE id = ?',
            [name, phone, is_active, req.params.id]
        );
        res.json({ success: true, message: 'ອັບເດດ User ສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// DELETE /api/users/:id — ລົບ user (soft delete)
app.delete('/api/users/:id', auth, async (req, res) => {
    try {
        await db.query('UPDATE users SET is_active = 0 WHERE id = ?', [req.params.id]);
        res.json({ success: true, message: 'ປິດການໃຊ້ງານ User ສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 4. ANIMALS API
// ================================================================

// GET /api/animals — ດຶງສັດທັງໝົດ
app.get('/api/animals', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT a.*, u.name AS owner_name FROM animals a JOIN users u ON a.owner_id = u.id'
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/animals/:id — ດຶງສັດຕາມ ID
app.get('/api/animals/:id', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT a.*, u.name AS owner_name FROM animals a JOIN users u ON a.owner_id = u.id WHERE a.id = ?',
            [req.params.id]
        );
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ Animal' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/users/:userId/animals — ດຶງສັດຂອງ user ນີ້
app.get('/api/users/:userId/animals', auth, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM animals WHERE owner_id = ?', [req.params.userId]);
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/animals — ເພີ່ມສັດໃໝ່
app.post('/api/animals', auth, async (req, res) => {
    try {
        const { owner_id, name, species, breed, age } = req.body;
        if (!owner_id || !name || !species) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຂໍ້ມູນໃຫ້ຄົບ' });
        }
        const [result] = await db.query(
            'INSERT INTO animals (owner_id, name, species, breed, age) VALUES (?, ?, ?, ?, ?)',
            [owner_id, name, species, breed || null, age || null]
        );
        res.status(201).json({ success: true, message: 'ເພີ່ມສັດສຳເລັດ', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/animals/:id — ອັບເດດສັດ
app.put('/api/animals/:id', auth, async (req, res) => {
    try {
        const { name, species, breed, age } = req.body;
        await db.query(
            'UPDATE animals SET name = COALESCE(?, name), species = COALESCE(?, species), breed = COALESCE(?, breed), age = COALESCE(?, age) WHERE id = ?',
            [name, species, breed, age, req.params.id]
        );
        res.json({ success: true, message: 'ອັບເດດສັດສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// DELETE /api/animals/:id — ລົບສັດ
app.delete('/api/animals/:id', auth, async (req, res) => {
    try {
        await db.query('DELETE FROM animals WHERE id = ?', [req.params.id]);
        res.json({ success: true, message: 'ລົບສັດສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 5. SERVICES API
// ================================================================

// GET /api/services — ດຶງ services ທັງໝົດ
app.get('/api/services', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM services WHERE is_active = 1');
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/services/:id — ດຶງ service ຕາມ ID
app.get('/api/services/:id', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM services WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ Service' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/services — ສ້າງ service ໃໝ່
app.post('/api/services', auth, async (req, res) => {
    try {
        const { name, description, price } = req.body;
        if (!name || !price) return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຊື່ ແລະ ລາຄາ' });
        const [result] = await db.query(
            'INSERT INTO services (name, description, price) VALUES (?, ?, ?)',
            [name, description || null, price]
        );
        res.status(201).json({ success: true, message: 'ສ້າງ Service ສຳເລັດ', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/services/:id — ອັບເດດ service
app.put('/api/services/:id', auth, async (req, res) => {
    try {
        const { name, description, price, is_active } = req.body;
        await db.query(
            'UPDATE services SET name = COALESCE(?, name), description = COALESCE(?, description), price = COALESCE(?, price), is_active = COALESCE(?, is_active) WHERE id = ?',
            [name, description, price, is_active, req.params.id]
        );
        res.json({ success: true, message: 'ອັບເດດ Service ສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// DELETE /api/services/:id — ປິດ service
app.delete('/api/services/:id', auth, async (req, res) => {
    try {
        await db.query('UPDATE services SET is_active = 0 WHERE id = ?', [req.params.id]);
        res.json({ success: true, message: 'ປິດ Service ສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 6. BOOKINGS API
// ================================================================

// GET /api/bookings — ດຶງການຈອງທັງໝົດ
app.get('/api/bookings', auth, async (req, res) => {
    try {
        const { status } = req.query;
        let sql = `SELECT b.*, u.name AS user_name, a.name AS animal_name, s.name AS service_name
                   FROM bookings b
                   JOIN users u ON b.user_id = u.id
                   JOIN animals a ON b.animal_id = a.id
                   JOIN services s ON b.service_id = s.id`;
        const params = [];
        if (status) { sql += ' WHERE b.status = ?'; params.push(status); }
        sql += ' ORDER BY b.created_at DESC';
        const [rows] = await db.query(sql, params);
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/bookings/:id — ດຶງການຈອງຕາມ ID
app.get('/api/bookings/:id', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT b.*, u.name AS user_name, a.name AS animal_name, s.name AS service_name
             FROM bookings b
             JOIN users u ON b.user_id = u.id
             JOIN animals a ON b.animal_id = a.id
             JOIN services s ON b.service_id = s.id
             WHERE b.id = ?`,
            [req.params.id]
        );
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ Booking' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/users/:userId/bookings — ການຈອງຂອງ user
app.get('/api/users/:userId/bookings', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT b.*, a.name AS animal_name, s.name AS service_name
             FROM bookings b
             JOIN animals a ON b.animal_id = a.id
             JOIN services s ON b.service_id = s.id
             WHERE b.user_id = ? ORDER BY b.created_at DESC`,
            [req.params.userId]
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/bookings — ສ້າງການຈອງ
app.post('/api/bookings', auth, async (req, res) => {
    try {
        const { user_id, animal_id, service_id, scheduled_date, note } = req.body;
        if (!user_id || !animal_id || !service_id || !scheduled_date) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຂໍ້ມູນໃຫ້ຄົບ' });
        }
        const [result] = await db.query(
            'INSERT INTO bookings (user_id, animal_id, service_id, scheduled_date, note) VALUES (?, ?, ?, ?, ?)',
            [user_id, animal_id, service_id, scheduled_date, note || null]
        );
        res.status(201).json({ success: true, message: 'ຈອງສຳເລັດ!', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/bookings/:id/status — ອັບເດດສະຖານະ
app.put('/api/bookings/:id/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        const allowed = ['pending','confirmed','in_progress','completed','cancelled'];
        if (!allowed.includes(status)) {
            return res.status(400).json({ success: false, message: 'Status ບໍ່ຖືກຕ້ອງ' });
        }
        await db.query('UPDATE bookings SET status = ? WHERE id = ?', [status, req.params.id]);
        res.json({ success: true, message: 'ອັບເດດສະຖານະສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// DELETE /api/bookings/:id — ຍົກເລີກການຈອງ
app.delete('/api/bookings/:id', auth, async (req, res) => {
    try {
        await db.query('UPDATE bookings SET status = "cancelled" WHERE id = ?', [req.params.id]);
        res.json({ success: true, message: 'ຍົກເລີກການຈອງສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 7. PAYMENTS API
// ================================================================

// GET /api/payments — ດຶງ payments ທັງໝົດ
app.get('/api/payments', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT p.*, b.scheduled_date, u.name AS user_name
             FROM payments p
             JOIN bookings b ON p.booking_id = b.id
             JOIN users u ON b.user_id = u.id
             ORDER BY p.created_at DESC`
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/payments/:id — ດຶງ payment ຕາມ ID
app.get('/api/payments/:id', auth, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM payments WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ Payment' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/payments — ສ້າງ payment (upload slip)
app.post('/api/payments', auth, async (req, res) => {
    try {
        const { booking_id, type, amount, slip_url } = req.body;
        if (!booking_id || !amount) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຂໍ້ມູນໃຫ້ຄົບ' });
        }
        const [result] = await db.query(
            'INSERT INTO payments (booking_id, type, amount, slip_url) VALUES (?, ?, ?, ?)',
            [booking_id, type || 'full', amount, slip_url || null]
        );
        res.status(201).json({ success: true, message: 'ສ້າງ Payment ສຳເລັດ', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/payments/:id/approve — admin ອະນຸມັດ payment
app.put('/api/payments/:id/approve', auth, async (req, res) => {
    try {
        await db.query(
            'UPDATE payments SET status = "approved", approved_by = ?, paid_at = NOW() WHERE id = ?',
            [req.user.id, req.params.id]
        );
        res.json({ success: true, message: 'ອະນຸມັດ Payment ສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/payments/:id/reject — admin ປະຕິເສດ payment
app.put('/api/payments/:id/reject', auth, async (req, res) => {
    try {
        await db.query(
            'UPDATE payments SET status = "rejected", approved_by = ? WHERE id = ?',
            [req.user.id, req.params.id]
        );
        res.json({ success: true, message: 'ປະຕິເສດ Payment ສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 8. RECEIPTS API
// ================================================================

// GET /api/receipts — ດຶງ receipts ທັງໝົດ
app.get('/api/receipts', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT r.*, u.name AS user_name, a.name AS animal_name, s.name AS service_name
             FROM receipts r
             JOIN bookings b ON r.booking_id = b.id
             JOIN users u ON b.user_id = u.id
             JOIN animals a ON b.animal_id = a.id
             JOIN services s ON b.service_id = s.id
             ORDER BY r.issued_at DESC`
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// GET /api/receipts/:id — ດຶງ receipt ຕາມ ID
app.get('/api/receipts/:id', auth, async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM receipts WHERE id = ?', [req.params.id]);
        if (!rows.length) return res.status(404).json({ success: false, message: 'ບໍ່ພົບ Receipt' });
        res.json({ success: true, data: rows[0] });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/receipts — ອອກໃບບໍລິ
app.post('/api/receipts', auth, async (req, res) => {
    try {
        const { booking_id, total_amount, deposit_paid } = req.body;
        if (!booking_id || !total_amount) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຂໍ້ມູນໃຫ້ຄົບ' });
        }
        const [result] = await db.query(
            'INSERT INTO receipts (booking_id, total_amount, deposit_paid) VALUES (?, ?, ?)',
            [booking_id, total_amount, deposit_paid || 0]
        );
        res.status(201).json({ success: true, message: 'ອອກໃບບໍລິສຳເລັດ', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 9. NOTIFICATIONS API
// ================================================================

// GET /api/notifications — ດຶງແຈ້ງເຕືອນຂອງ user
app.get('/api/notifications', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/notifications/:id/read — ອ່ານແຈ້ງເຕືອນ
app.put('/api/notifications/:id/read', auth, async (req, res) => {
    try {
        await db.query('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
        res.json({ success: true, message: 'ອ່ານແຈ້ງເຕືອນສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// PUT /api/notifications/read-all — ອ່ານທັງໝົດ
app.put('/api/notifications/read-all', auth, async (req, res) => {
    try {
        await db.query('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.user.id]);
        res.json({ success: true, message: 'ອ່ານທັງໝົດສຳເລັດ' });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/notifications — ສ້າງແຈ້ງເຕືອນ (admin/staff)
app.post('/api/notifications', auth, async (req, res) => {
    try {
        const { user_id, booking_id, message, type } = req.body;
        if (!user_id || !message) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຂໍ້ມູນໃຫ້ຄົບ' });
        }
        const [result] = await db.query(
            'INSERT INTO notifications (user_id, booking_id, message, type) VALUES (?, ?, ?, ?)',
            [user_id, booking_id || null, message, type || 'info']
        );
        res.status(201).json({ success: true, message: 'ສ້າງແຈ້ງເຕືອນສຳເລັດ', id: result.insertId });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// 10. REPORTS API
// ================================================================

// GET /api/reports — ດຶງ reports ທັງໝົດ
app.get('/api/reports', auth, async (req, res) => {
    try {
        const [rows] = await db.query(
            `SELECT r.*, u.name AS generated_by_name
             FROM reports r JOIN users u ON r.generated_by = u.id
             ORDER BY r.created_at DESC`
        );
        res.json({ success: true, data: rows });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// POST /api/reports — ສ້າງ report
app.post('/api/reports', auth, async (req, res) => {
    try {
        const { report_type, period_start, period_end } = req.body;
        if (!period_start || !period_end) {
            return res.status(400).json({ success: false, message: 'ກະລຸນາໃສ່ຊ່ວງວັນທີ' });
        }
        // ດຶງຂໍ້ມູນສະຫຼຸບ
        const [bookings] = await db.query(
            'SELECT COUNT(*) AS total, status FROM bookings WHERE scheduled_date BETWEEN ? AND ? GROUP BY status',
            [period_start, period_end]
        );
        const [payments] = await db.query(
            'SELECT SUM(amount) AS total_income FROM payments WHERE status = "approved" AND paid_at BETWEEN ? AND ?',
            [period_start, period_end]
        );
        const reportData = { bookings, income: payments[0].total_income || 0 };

        const [result] = await db.query(
            'INSERT INTO reports (generated_by, report_type, period_start, period_end, data) VALUES (?, ?, ?, ?, ?)',
            [req.user.id, report_type || 'custom', period_start, period_end, JSON.stringify(reportData)]
        );
        res.status(201).json({ success: true, message: 'ສ້າງ Report ສຳເລັດ', id: result.insertId, data: reportData });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ================================================================
// START SERVER
// ================================================================
app.listen(PORT, () => {
    console.log(`✅ Server running → http://localhost:${PORT}`);
});