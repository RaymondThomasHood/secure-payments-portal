const express = require('express');
const bcrypt = require('bcrypt');
const db = require('./database');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const https = require('https');
const fs = require('fs');

const app = express();
const PORT = 5001;
const SECRET_KEY = 'Mielie123**';

// Middleware
app.use(helmet());
app.use(bodyParser.json());
app.use(cors({ origin: 'https://localhost:3000', credentials: true }));

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests, try again later'
});
app.use(limiter);

// Regex for input validation
const nameRegex = /^[a-zA-Z\s]{2,50}$/;
const idRegex = /^\d{13}$/;
const accountRegex = /^\d{10,12}$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_]).{8,}$/;
const amountRegex = /^\d+(\.\d{1,2})?$/;
const currencyRegex = /^[A-Z]{3}$/;
const recipientRegex = /^\d{10,12}$/;

// Validation helpers
function validateInput(fullName, idNumber, accountNumber, password) {
  if (!nameRegex.test(fullName)) return 'Invalid full name';
  if (!idRegex.test(idNumber)) return 'Invalid ID number';
  if (!accountRegex.test(accountNumber)) return 'Invalid account number';
  if (password && !passwordRegex.test(password)) return 'Weak password';
  return null;
}

function validatePayment(amount, currency, recipient) {
  if (!amountRegex.test(amount)) return 'Invalid amount';
  if (!currencyRegex.test(currency)) return 'Invalid currency';
  if (!recipientRegex.test(recipient)) return 'Invalid recipient';
  return null;
}

// Create payments table
db.run(`CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  amount REAL NOT NULL,
  currency TEXT NOT NULL,
  recipient TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  userId INTEGER NOT NULL
)`);


// Customer Routes

app.post('/register', async (req, res) => {
  const { fullName, idNumber, accountNumber, password } = req.body;
  const error = validateInput(fullName, idNumber, accountNumber, password);
  if (error) return res.status(400).json({ error });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (fullName, idNumber, accountNumber, password) VALUES (?, ?, ?, ?)`,
      [fullName, idNumber, accountNumber, hashedPassword],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
        res.json({ message: 'Registered successfully' });
      }
    );
  } catch (err) {
    res.status(500).json({ error: 'Server error: ' + err.message });
  }
});

app.post('/login', (req, res) => {
  const { accountNumber, password } = req.body;
  db.get(`SELECT * FROM users WHERE accountNumber = ?`, [accountNumber], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'Invalid credentials' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, role: user.role || 'customer' }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});

app.post('/payment', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    const { amount, currency, recipient } = req.body;
    const error = validatePayment(amount, currency, recipient);
    if (error) return res.status(400).json({ error });
    db.run(
      `INSERT INTO payments (amount, currency, recipient, userId) VALUES (?, ?, ?, ?)`,
      [amount, currency, recipient, decoded.id],
      (err) => {
        if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
        res.json({ message: 'Payment submitted for approval' });
      }
    );
  });
});


// Employee Routes

app.post('/employee/create-user', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'employee') return res.status(401).json({ error: 'Unauthorized' });

    const { fullName, idNumber, accountNumber, password } = req.body;
    const error = validateInput(fullName, idNumber, accountNumber, password);
    if (error) return res.status(400).json({ error });

    try {
      const hashedPassword = bcrypt.hashSync(password, 10);
      db.run(
        `INSERT INTO users (fullName, idNumber, accountNumber, password, role) VALUES (?, ?, ?, ?, 'customer')`,
        [fullName, idNumber, accountNumber, hashedPassword],
        (err) => {
          if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
              return res.status(400).json({ error: 'Account number already exists' });
            }
            return res.status(500).json({ error: 'Database error: ' + err.message });
          }
          res.json({ message: 'User created successfully' });
        }
      );
    } catch (err) {
      res.status(500).json({ error: 'Server error: ' + err.message });
    }
  });
});

app.get('/employee/payments', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'employee') return res.status(401).json({ error: 'Unauthorized' });
    db.all(`SELECT * FROM payments WHERE status = 'pending'`, [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
      res.json(rows);
    });
  });
});

app.post('/employee/payment/update', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'employee') return res.status(401).json({ error: 'Unauthorized' });
    const { id, status } = req.body;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    db.run(`UPDATE payments SET status = ? WHERE id = ?`, [status, id], (err) => {
      if (err) return res.status(500).json({ error: 'Database error: ' + err.message });
      res.json({ message: 'Payment updated' });
    });
  });
});


// Employee Reports Route

app.get('/employee/reports', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'employee') {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    db.all(
      `SELECT status, COUNT(*) as count, SUM(amount) as total
       FROM payments
       GROUP BY status`,
      [],
      (err, rows) => {
        if (err) {
          console.error("Error generating report:", err.message);
          return res.status(500).json({ error: 'Database error: ' + err.message });
        }
        res.json(rows);
      }
    );
  });
});


// Start HTTPS server

try {
  const options = {
    key: fs.readFileSync('./localhost-key.pem'),   // private key file
    cert: fs.readFileSync('./localhost.pem')       // certificate file
  };

  https.createServer(options, app).listen(PORT, () => {
    console.log(`HTTPS server running on https://localhost:${PORT}`);
  });
} catch (err) {
  console.error('Failed to start HTTPS server:', err.message);
  // Fallback to HTTP for testing
  app.listen(PORT, () => {
    console.log(`HTTP fallback server running on http://localhost:${PORT}`);
  });
}
