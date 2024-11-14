const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 8080;

// Create a connection pool for MySQL
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'tiger', 
    database: 'mini_project' 
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'your_secret_key', 
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } 
}));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// User registration route
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    pool.query('SELECT * FROM users WHERE username = ?', [username], (err, result) => {
        if (err) {
            return res.status(500).send('Server error: ' + err.message);
        }
        if (result.length > 0) {
            return res.status(400).send('User already exists');
        }

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.status(500).send('Server error: ' + err.message);
            }
            const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
            pool.query(sql, [username, hash], (err, result) => {
                if (err) {
                    return res.status(500).send('Server error: ' + err.message);
                }
                res.send('User registered successfully');
            });
        });
    });
});

// User login route
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    pool.query('SELECT * FROM users WHERE username = ?', [username], (err, result) => {
        if (err) {
            return res.status(500).send('Server error: ' + err.message);
        }
        if (result.length === 0) {
            return res.status(400).send('User does not exist');
        }

        bcrypt.compare(password, result[0].password, (err, match) => {
            if (err) {
                return res.status(500).send('Server error: ' + err.message);
            }
            if (!match) {
                return res.status(400).send('Incorrect password');
            }

            req.session.user = result[0];
            res.redirect('/index.html'); 
        });
    });
});

// Logout route
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Server error: ' + err.message);
        }
        res.redirect('/login.html'); 
    });
});

// Check if the user is authenticated
app.get('/checkAuth', (req, res) => {
    if (req.session.user) {
        res.sendStatus(200);
    } else {
        res.sendStatus(401);
    }
});

// Retrieve all subscribers
app.get('/subscribers', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    pool.query('SELECT * FROM subscribers', (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(results);
    });
});

// Retrieve a specific subscriber by ID
app.get('/subscribers/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    const { id } = req.params;
    pool.query('SELECT * FROM subscribers WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) {
            return res.status(404).json({ message: 'Subscriber not found' });
        }
        res.json(results[0]);
    });
});

// Create a new subscriber
app.post('/subscribers', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    const { subscription_type, subscription_start_date, subscription_end_date, payment_status, last_payment_date } = req.body;
    const query = 'INSERT INTO subscribers (subscription_type, subscription_start_date, subscription_end_date, payment_status, last_payment_date) VALUES (?, ?, ?, ?, ?)';
    const values = [subscription_type, subscription_start_date, subscription_end_date, payment_status, last_payment_date];
    pool.query(query, values, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.status(201).json({
            message: 'Subscriber created successfully',
            subscriberId: results.insertId
        });
    });
});

// Update a subscriber by ID
app.put('/subscribers/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    const { id } = req.params;
    const { subscription_type, subscription_start_date, subscription_end_date, payment_status, last_payment_date } = req.body;
    const query = 'UPDATE subscribers SET subscription_type = ?, subscription_start_date = ?, subscription_end_date = ?, payment_status = ?, last_payment_date = ? WHERE id = ?';
    const values = [subscription_type, subscription_start_date, subscription_end_date, payment_status, last_payment_date, id];
    pool.query(query, values, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Subscriber not found' });
        }
        res.json({ message: 'Subscriber updated successfully' });
    });
});

// Delete a subscriber by ID
app.delete('/subscribers/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }
    const { id } = req.params;
    pool.query('DELETE FROM subscribers WHERE id = ?', [id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Subscriber not found' });
        }
        res.json({ message: 'Subscriber deleted successfully' });
    });
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/index.html', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login.html'); 
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
